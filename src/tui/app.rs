//! State and logic of the TUI – deliberately without any rendering.
//!
//! # Elm-style architecture
//!
//! The TUI follows a simple cycle:
//!
//! ```text
//!   key press ──(event.rs)──▶ Action ──(App::update)──▶ new state
//!                                                          │
//!                                        (ui.rs, read-only) ▼
//!                                                         screen
//! ```
//!
//! * **State** is the struct [`App`]: everything needed for drawing.
//! * **Actions** ([`Action`]) describe *what* the user wants – independent
//!   of the key. `App::update` is the only place that changes the state.
//! * **View** is `ui::draw`: a function that only *reads* the state.
//!
//! Because this module knows neither the terminal nor ratatui widgets, it can
//! be checked with ordinary unit tests (see below).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use ratatui::widgets::ListState;

use super::form::{FormEvent, FormResult, FormState, complete_tag};
use super::input::TextInput;
use super::secret::{DialogEvent, Intent, SecretDialog, Step};
use crate::commands::sort_hosts;
// `as AppConfig`: `nucleo_matcher` already ships its own `Config`.
use crate::config::{Config as AppConfig, DefaultSort};
use crate::connect::{self, MountTarget, Programs, Session};
use crate::secrets::{self, LockState, SecretError, SecretStore, SecretString, check_new_master};
use crate::store::{Connection, Host, HostSource, HostStats, Store, StoreError, now_ms};
use crate::timefmt;
use crate::validate::{Field, parse_tags};

/// How many days the bar chart in the detail panel shows.
pub const SPARK_DAYS: usize = 14;
/// How many connections the mini history shows.
pub const HISTORY_LEN: usize = 8;
/// How long a status message stays visible.
const STATUS_TTL: Duration = Duration::from_secs(8);

/// Which mode the UI is currently in.
///
/// An `enum` instead of several `bool` fields: only *one* mode can be
/// active at a time, invalid combinations ("search and help at the same
/// time") cannot even be represented.
///
/// The variants deliberately carry *no* data here, so that `Mode` stays cheap
/// to copy (`Copy`) and `event.rs` can simply receive it by value.
/// The data belonging to a mode lives in separate fields of [`App`]
/// (`form`, `confirm`, `tag_dialog`, `tag_filter`); the mode only says which
/// of them currently receives the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Normal navigation.
    Normal,
    /// The search field is active, keys go into the search text.
    Search,
    /// The help overlay is open.
    Help,
    /// The host form (create/edit) is open.
    Form,
    /// A yes/no confirmation prompt is open.
    Confirm,
    /// The quick tag dialog is open.
    TagEdit,
    /// The password dialog (`p`) or the master password prompt is open.
    Secret,
    /// The tag filter picker is open.
    TagFilter,
}

/// An open confirmation prompt. The variants carry the data needed for
/// execution – here the ID *and* the alias (for the text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirm {
    /// Permanently delete a manual host.
    DeleteHost { id: i64, alias: String },
    /// Discard the form with unsaved changes.
    DiscardForm,
}

/// State of the quick tag dialog (`t`).
#[derive(Debug, Clone, PartialEq)]
pub struct TagDialog {
    pub host_id: i64,
    pub alias: String,
    /// Comma-separated tags.
    pub input: TextInput,
    /// Error message (e.g. tag with spaces).
    pub error: Option<String>,
    known_tags: Vec<String>,
}

/// State of the tag filter picker (`T`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    /// Tag name and number of hosts (among the loaded hosts).
    pub entries: Vec<(String, usize)>,
    pub selected: usize,
}

/// Sort order of the host list (favorites always come first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    /// Alphabetical by alias.
    Name,
    /// Most recently connected successfully first.
    Recent,
    /// Most frequently connected first.
    Frequent,
}

impl SortMode {
    /// Next sort order in the cycle name → recent → frequent → name.
    pub fn next(self) -> Self {
        match self {
            Self::Name => Self::Recent,
            Self::Recent => Self::Frequent,
            Self::Frequent => Self::Name,
        }
    }

    /// Translates the initial sort order from the configuration.
    pub fn from_config(sort: DefaultSort) -> Self {
        match sort {
            DefaultSort::Name => Self::Name,
            DefaultSort::Recent => Self::Recent,
            DefaultSort::Frequent => Self::Frequent,
        }
    }

    /// Display name for the header line.
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Recent => "recent",
            Self::Frequent => "frequent",
        }
    }
}

/// What the user wants to do – the result of key evaluation (`event.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Quit the program.
    Quit,
    /// Move the selection one up / down.
    Up,
    Down,
    /// One page up / down.
    PageUp,
    PageDown,
    /// To the first / last entry.
    First,
    Last,
    /// Connect to the selected host.
    Connect,
    /// Open an SFTP session to the selected host.
    Sftp,
    /// Mount the selected host with sshfs, or unmount it if it is mounted.
    ToggleMount,
    /// Toggle favorite of the selected host.
    ToggleFavorite,
    /// Next sort order.
    CycleSort,
    /// Open the search field.
    OpenSearch,
    /// Close the search and discard the search text.
    CancelSearch,
    /// Close the search but keep the filter.
    CommitSearch,
    /// Append a character to the search text (enum variants may carry data).
    SearchChar(char),
    /// Delete the last character of the search text.
    SearchBackspace,
    /// Delete the entire search text.
    SearchClear,
    /// Open help.
    OpenHelp,
    /// Close help.
    CloseHelp,
    /// Open the form for a new manual host.
    NewHost,
    /// Edit the selected host.
    EditHost,
    /// Quick tag dialog for the selected host.
    EditTags,
    /// Set, change or remove the password of the selected host.
    EditPassword,
    /// Delete the selected host (with confirmation).
    DeleteHost,
    /// Archive or restore the selected host.
    ToggleArchive,
    /// Show/hide archived hosts.
    ToggleShowArchived,
    /// Open the tag filter picker.
    OpenTagFilter,
    /// A raw key for modes with their own key logic (form, dialogs).
    Key(KeyEvent),
    /// Answer the confirmation prompt with "yes".
    ConfirmYes,
    /// Cancel the confirmation prompt.
    ConfirmNo,
}

/// What the event loop has to do *outside* the state after an action.
///
/// `App::update` must not touch the terminal. It therefore only reports
/// that, e.g., a connection should be made – the loop in `mod.rs` does that.
///
/// No `Clone`: the password in `Connect` must not be copyable.
#[derive(Debug, PartialEq)]
pub enum Effect {
    /// Nothing more to do.
    None,
    /// Programm beenden.
    Quit,
    /// Release the terminal and connect to this host. The password (if
    /// stored) has already been fetched, while there was still room for the
    /// master password prompt in the TUI.
    Connect {
        host: Box<Host>,
        password: Option<SecretString>,
        /// Shell, SFTP or mount.
        session: Session,
    },
    /// Unmount the host mounted at `mountpoint` (no terminal needed).
    Unmount {
        alias: String,
        mountpoint: std::path::PathBuf,
    },
}

/// Kind of a status message (determines the color).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Success,
    Error,
    Warning,
}

/// A time-limited message in the status bar ("toast").
#[derive(Debug, Clone)]
pub struct Status {
    pub kind: StatusKind,
    pub text: String,
    created: Instant,
}

/// A visible row of the host list: reference to a host plus match info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Index in [`App::hosts`].
    pub host_index: usize,
    /// Character positions (not bytes) in the alias that match the search.
    pub alias_matches: Vec<u32>,
}

/// Details of the selected host (history and daily counters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {
    pub host_id: i64,
    /// The latest connections, newest first (at most [`HISTORY_LEN`]).
    pub history: Vec<Connection>,
    /// Connections per day; index 0 = 13 days ago, last index = today.
    pub per_day: [u32; SPARK_DAYS],
}

/// Parsed search text: `#tag` filters and the rest as a fuzzy pattern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedQuery {
    /// Lowercase tag prefixes; a host must satisfy *all* of them.
    pub tags: Vec<String>,
    /// Remaining text for the fuzzy search.
    pub fuzzy: String,
}

/// Splits the search text into tag filters (`#prod`) and fuzzy text.
///
/// A lone `#` without a name is ignored (the user is still typing).
pub fn parse_query(query: &str) -> ParsedQuery {
    let mut parsed = ParsedQuery::default();
    let mut words = Vec::new();
    for word in query.split_whitespace() {
        // `strip_prefix` returns the rest if the prefix matches.
        match word.strip_prefix('#') {
            Some("") => {}
            Some(tag) => parsed.tags.push(tag.to_lowercase()),
            None => words.push(word),
        }
    }
    parsed.fuzzy = words.join(" ");
    parsed
}

/// The entire state of the application.
pub struct App {
    store: Store,
    /// Password storage (Keychain or encrypted). `Box<dyn …>`: a pointer
    /// to any type that implements `SecretStore` – the choice was made at startup.
    secrets: Box<dyn SecretStore>,
    /// Current mode.
    pub mode: Mode,
    /// Active sort order.
    pub sort: SortMode,
    /// All displayed hosts in sort order (archived ones only with [`App::show_archived`]).
    pub hosts: Vec<Host>,
    stats: HashMap<i64, HostStats>,
    /// Currently visible rows (after filter and search).
    pub rows: Vec<Row>,
    /// Index of the selection in [`App::rows`].
    pub selected: usize,
    /// Search text (live while search mode is open, afterwards as a filter).
    pub query: String,
    /// Details of the selected host.
    pub detail: Option<Detail>,
    /// Current status message.
    pub status: Option<Status>,
    /// Show archived hosts in the list?
    pub show_archived: bool,
    /// Symbol for hosts without their own icon (from the configuration).
    pub icon_fallback: String,
    /// `[ssh]`, `[sftp]` and `[mount]` settings of the configuration.
    programs: Programs,
    /// Open host form (mode [`Mode::Form`]).
    pub form: Option<FormState>,
    /// Open confirmation prompt (mode [`Mode::Confirm`]).
    pub confirm: Option<Confirm>,
    /// Open tag dialog (mode [`Mode::TagEdit`]).
    pub tag_dialog: Option<TagDialog>,
    /// Open tag filter picker (mode [`Mode::TagFilter`]).
    pub tag_filter: Option<TagFilter>,
    /// Open password dialog (mode [`Mode::Secret`]).
    pub secret_dialog: Option<SecretDialog>,
    /// Scroll state of the list; `ui` updates it while drawing.
    pub list_state: ListState,
    /// Visible rows of the list (for PgUp/PgDn); `ui` sets the value.
    pub page_size: usize,
    // The matcher holds buffers that are reused between searches.
    matcher: Matcher,
}

impl App {
    /// Test shorthand: app with an in-memory password storage.
    #[cfg(test)]
    pub fn new(store: Store, warnings: &[String]) -> anyhow::Result<Self> {
        Self::with_secrets(
            store,
            Box::new(secrets::MemoryStore::default()),
            AppConfig::default(),
            warnings,
        )
    }

    /// Builds the app and loads the data. `config` determines the initial sort,
    /// archive display, fallback icon and ssh program; `warnings` (e.g. from the
    /// ssh_config sync) appear as a status message.
    pub fn with_secrets(
        store: Store,
        secrets: Box<dyn SecretStore>,
        config: AppConfig,
        warnings: &[String],
    ) -> anyhow::Result<Self> {
        let mut app = Self {
            store,
            secrets,
            mode: Mode::Normal,
            sort: SortMode::from_config(config.default_sort),
            hosts: Vec::new(),
            stats: HashMap::new(),
            rows: Vec::new(),
            selected: 0,
            query: String::new(),
            detail: None,
            status: None,
            show_archived: config.show_archived,
            icon_fallback: config.icon_fallback,
            programs: Programs {
                ssh: config.ssh,
                sftp: config.sftp,
                mount: config.mount,
            },
            form: None,
            confirm: None,
            tag_dialog: None,
            tag_filter: None,
            secret_dialog: None,
            list_state: ListState::default(),
            page_size: 10,
            matcher: Matcher::new(Config::DEFAULT),
        };
        app.reload()?;
        if let Some(first) = warnings.first() {
            let more = if warnings.len() > 1 {
                format!(" (+{} more)", warnings.len() - 1)
            } else {
                String::new()
            };
            app.set_status(StatusKind::Warning, format!("⚠ {first}{more}"));
        }
        Ok(app)
    }

    /// The selected host, if the list is not empty.
    pub fn selected_host(&self) -> Option<&Host> {
        self.rows
            .get(self.selected)
            .map(|row| &self.hosts[row.host_index])
    }

    /// Statistics of a host (absent if it has never been connected).
    pub fn stats_for(&self, host_id: i64) -> Option<&HostStats> {
        self.stats.get(&host_id)
    }

    /// Sets the status message (and starts its expiry timer).
    pub fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status = Some(Status {
            kind,
            text: text.into(),
            created: Instant::now(),
        });
    }

    /// Removes expired status messages; called regularly from the event loop.
    pub fn tick(&mut self) {
        if self
            .status
            .as_ref()
            .is_some_and(|s| s.created.elapsed() > STATUS_TTL)
        {
            self.status = None;
        }
    }

    /// Reloads hosts and statistics and keeps the selection on the same host.
    pub fn reload(&mut self) -> anyhow::Result<()> {
        let keep = self.selected_host().map(|h| h.id);
        self.reload_keeping(keep)
    }

    /// Like [`App::reload`], but the selection should land on host `keep`.
    fn reload_keeping(&mut self, keep: Option<i64>) -> anyhow::Result<()> {
        let mut hosts = self.store.list_hosts(self.show_archived)?;
        self.stats = self.store.host_stats()?;
        sort_hosts_by(&mut hosts, self.sort, &self.stats);
        self.hosts = hosts;
        self.apply_filter(keep);
        Ok(())
    }

    /// Recomputes [`App::rows`] from the search text and hosts.
    ///
    /// `keep` is the host ID the selection should preferably end up on.
    fn apply_filter(&mut self, keep: Option<i64>) {
        let parsed = parse_query(&self.query);
        let pattern = Pattern::parse(&parsed.fuzzy, CaseMatching::Smart, Normalization::Smart);
        let mut scored: Vec<(u32, Row)> = Vec::new();
        let mut buf = Vec::new();

        for (index, host) in self.hosts.iter().enumerate() {
            // Tag filter: every `#tag` must match at least one tag of the host.
            let tags_ok = parsed.tags.iter().all(|wanted| {
                host.tags
                    .iter()
                    .any(|t| t.name.to_lowercase().starts_with(wanted.as_str()))
            });
            if !tags_ok {
                continue;
            }
            if parsed.fuzzy.is_empty() {
                scored.push((
                    0,
                    Row {
                        host_index: index,
                        alias_matches: Vec::new(),
                    },
                ));
                continue;
            }
            // All searchable fields in one text, so that a pattern like
            // "web prod" can also match across several fields (alias + tag).
            let haystack = searchable_text(host);
            let Some(base) = pattern.score(Utf32Str::new(&haystack, &mut buf), &mut self.matcher)
            else {
                continue;
            };
            // Matches in the alias count double and provide the highlighting.
            let mut matches = Vec::new();
            let alias_score = pattern.indices(
                Utf32Str::new(&host.alias, &mut buf),
                &mut self.matcher,
                &mut matches,
            );
            matches.sort_unstable();
            matches.dedup();
            if alias_score.is_none() {
                matches.clear();
            }
            scored.push((
                base + 2 * alias_score.unwrap_or(0),
                Row {
                    host_index: index,
                    alias_matches: matches,
                },
            ));
        }

        // With search text: best matches first. `sort_by` is *stable*: with
        // equal scores the order of the chosen sort is kept.
        // `Reverse` flips the direction to "descending".
        if !parsed.fuzzy.is_empty() {
            scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        }
        self.rows = scored.into_iter().map(|(_, row)| row).collect();

        self.selected = keep
            .and_then(|id| {
                self.rows
                    .iter()
                    .position(|row| self.hosts[row.host_index].id == id)
            })
            .unwrap_or(0);
        self.refresh_detail();
    }

    /// Loads the history and daily counters of the selected host.
    fn refresh_detail(&mut self) {
        let Some(id) = self.selected_host().map(|h| h.id) else {
            self.detail = None;
            return;
        };
        // More than the history shows, so the 14-day counters are correct.
        match self.store.recent_connections(Some(id), 1000) {
            Ok(all) => {
                let mut per_day = [0_u32; SPARK_DAYS];
                if let Some(today) = timefmt::local_day_number(now_ms()) {
                    for conn in &all {
                        let Some(day) = timefmt::local_day_number(conn.started_at) else {
                            continue;
                        };
                        // `age` = days since the connection; only 0..14 count.
                        let age = usize::try_from(today - day).ok();
                        if let Some(age) = age.filter(|a| *a < SPARK_DAYS) {
                            per_day[SPARK_DAYS - 1 - age] += 1;
                        }
                    }
                }
                self.detail = Some(Detail {
                    host_id: id,
                    history: all.into_iter().take(HISTORY_LEN).collect(),
                    per_day,
                });
            }
            Err(err) => {
                self.detail = None;
                self.set_status(StatusKind::Error, format!("Could not read history: {err}"));
            }
        }
    }

    /// Sets the selection and reloads the details if it changed.
    fn select(&mut self, index: usize) {
        let last = self.rows.len().saturating_sub(1);
        let index = index.min(last);
        if index != self.selected {
            self.selected = index;
            self.refresh_detail();
        }
    }

    /// Applies an action and reports what the event loop still has to do.
    ///
    /// `&mut self`: this method changes the state (exclusive borrow). Rendering,
    /// on the other hand, only gets `&App` or – for the scroll state –
    /// `&mut App`, see `ui.rs`.
    pub fn update(&mut self, action: Action) -> Effect {
        match action {
            Action::Quit => return Effect::Quit,
            Action::Up => self.select(self.selected.saturating_sub(1)),
            Action::Down => self.select(self.selected.saturating_add(1)),
            Action::PageUp => self.select(self.selected.saturating_sub(self.page_size.max(1))),
            Action::PageDown => self.select(self.selected.saturating_add(self.page_size.max(1))),
            Action::First => self.select(0),
            Action::Last => self.select(usize::MAX),
            Action::Connect => {
                if let Some(host) = self.selected_host().cloned() {
                    return self.begin_connect(host, Session::Shell);
                }
            }
            Action::Sftp => {
                if let Some(host) = self.selected_host().cloned() {
                    return self.begin_connect(host, Session::Sftp);
                }
            }
            Action::ToggleMount => {
                if let Some(host) = self.selected_host().cloned() {
                    return self.toggle_mount(host);
                }
            }
            Action::ToggleFavorite => self.toggle_favorite(),
            Action::CycleSort => {
                self.sort = self.sort.next();
                let label = self.sort.label();
                self.reload_or_report();
                self.set_status(StatusKind::Info, format!("Sort: {label}"));
            }
            Action::OpenSearch => self.mode = Mode::Search,
            Action::CancelSearch => {
                self.mode = Mode::Normal;
                self.set_query(String::new());
            }
            Action::CommitSearch => self.mode = Mode::Normal,
            Action::SearchChar(c) => {
                let mut query = self.query.clone();
                query.push(c);
                self.set_query(query);
            }
            Action::SearchBackspace => {
                let mut query = self.query.clone();
                query.pop();
                self.set_query(query);
            }
            Action::SearchClear => self.set_query(String::new()),
            Action::OpenHelp => self.mode = Mode::Help,
            Action::CloseHelp => self.mode = Mode::Normal,
            Action::NewHost => self.open_new_form(),
            Action::EditHost => self.open_edit_form(),
            Action::EditTags => self.open_tag_dialog(),
            Action::EditPassword => self.open_password_dialog(),
            Action::DeleteHost => self.ask_delete(),
            Action::ToggleArchive => self.toggle_archive(),
            Action::ToggleShowArchived => self.toggle_show_archived(),
            Action::OpenTagFilter => self.open_tag_filter(),
            Action::Key(key) => match self.mode {
                Mode::Form => self.form_key(key),
                Mode::TagEdit => self.tag_dialog_key(key),
                Mode::TagFilter => self.tag_filter_key(key),
                Mode::Secret => return self.secret_key(key),
                // In the remaining modes `event.rs` does the translation itself.
                Mode::Normal | Mode::Search | Mode::Help | Mode::Confirm => {}
            },
            Action::ConfirmYes => self.answer_confirm(true),
            Action::ConfirmNo => self.answer_confirm(false),
        }
        Effect::None
    }

    // ---- Management: form -----------------------------------------------

    /// All existing tag names (for tab completion).
    fn known_tag_names(&self) -> Vec<String> {
        // Errors here are harmless: everything keeps working without suggestions.
        self.store
            .list_tags()
            .map(|tags| tags.into_iter().map(|t| t.name).collect())
            .unwrap_or_default()
    }

    fn open_new_form(&mut self) {
        self.form = Some(FormState::new_host(self.known_tag_names()));
        self.mode = Mode::Form;
    }

    fn open_edit_form(&mut self) {
        let Some(host) = self.selected_host().cloned() else {
            return;
        };
        self.form = Some(FormState::edit(&host, self.known_tag_names()));
        self.mode = Mode::Form;
    }

    fn close_form(&mut self) {
        self.form = None;
        self.mode = Mode::Normal;
    }

    fn form_key(&mut self, key: KeyEvent) {
        let Some(form) = self.form.as_mut() else {
            self.mode = Mode::Normal;
            return;
        };
        match form.handle_key(key) {
            FormEvent::None => {}
            FormEvent::Cancel => self.close_form(),
            FormEvent::ConfirmDiscard => {
                self.confirm = Some(Confirm::DiscardForm);
                self.mode = Mode::Confirm;
            }
            FormEvent::Submit(result) => self.save_form(*result),
        }
    }

    /// Writes a validated form to the database. On a duplicate
    /// alias the form stays open and shows the message at the field.
    fn save_form(&mut self, result: FormResult) {
        let outcome = match result {
            FormResult::Create { host, tags } => self
                .store
                .insert_host_with_tags(&host, &tags)
                .map(|id| (id, format!("✔ Host \"{}\" created", host.alias))),
            FormResult::Update { id, update, tags } => self
                .store
                .update_host_with_tags(id, &update, &tags)
                .map(|()| (id, format!("✔ Host \"{}\" saved", update.alias))),
        };
        match outcome {
            Ok((id, text)) => {
                self.close_form();
                if let Err(err) = self.reload_keeping(Some(id)) {
                    self.set_status(StatusKind::Error, format!("Reload failed: {err:#}"));
                } else {
                    self.set_status(StatusKind::Success, text);
                }
            }
            // An alias conflict belongs at the field, not in the status bar.
            Err(StoreError::DuplicateAlias(alias)) => {
                if let Some(form) = self.form.as_mut() {
                    form.set_error(
                        Field::Alias,
                        format!("Alias \"{alias}\" is already taken – please choose another one"),
                    );
                }
            }
            Err(err) => self.set_status(StatusKind::Error, format!("Save failed: {err}")),
        }
    }

    // ---- Management: confirmation prompts -------------------------------

    fn ask_delete(&mut self) {
        let Some((id, alias, source)) = self
            .selected_host()
            .map(|h| (h.id, h.alias.clone(), h.source))
        else {
            return;
        };
        if source == HostSource::SshConfig {
            self.set_status(
                StatusKind::Warning,
                format!(
                    "\"{alias}\" is managed in ~/.ssh/config and cannot be deleted here – archive it with x"
                ),
            );
            return;
        }
        self.confirm = Some(Confirm::DeleteHost { id, alias });
        self.mode = Mode::Confirm;
    }

    fn answer_confirm(&mut self, yes: bool) {
        let Some(confirm) = self.confirm.take() else {
            self.mode = Mode::Normal;
            return;
        };
        match (confirm, yes) {
            (Confirm::DeleteHost { id, alias }, true) => {
                self.mode = Mode::Normal;
                self.delete_host(id, &alias);
            }
            (Confirm::DeleteHost { .. }, false) => {
                self.mode = Mode::Normal;
                self.set_status(StatusKind::Info, "Delete cancelled");
            }
            (Confirm::DiscardForm, true) => self.close_form(),
            // Back to the form: nothing is lost.
            (Confirm::DiscardForm, false) => self.mode = Mode::Form,
        }
    }

    fn delete_host(&mut self, id: i64, alias: &str) {
        // Safety net: ssh_config hosts are never deleted, even if
        // someone builds `Confirm::DeleteHost` by hand.
        // The database is the source of truth, not the (possibly stale) display list.
        let is_ssh_config = matches!(
            self.store.get_host(id),
            Ok(Some(host)) if host.source == HostSource::SshConfig
        );
        if is_ssh_config {
            self.set_status(
                StatusKind::Warning,
                format!("\"{alias}\" is managed in ~/.ssh/config"),
            );
            return;
        }
        // Password first, then the host: the Keychain has no CASCADE, so an
        // orphaned password must not be left behind. If deleting the password
        // fails, the host stays and the error is reported.
        match secrets::delete_host_with_secret(self.secrets.as_mut(), &self.store, id) {
            Ok(()) => {
                self.reload_near_selection();
                self.set_status(StatusKind::Success, format!("✔ Host \"{alias}\" deleted"));
            }
            Err(err) => self.set_status(StatusKind::Error, format!("Delete failed: {err:#}")),
        }
    }

    /// Reloads and keeps the selection at the same *position* if the
    /// previous host has disappeared (deleted/hidden).
    fn reload_near_selection(&mut self) {
        let position = self.selected;
        self.reload_or_report();
        self.select(position);
    }

    // ---- Management: archive --------------------------------------------

    fn toggle_archive(&mut self) {
        let Some((id, alias, archived)) = self
            .selected_host()
            .map(|h| (h.id, h.alias.clone(), h.archived))
        else {
            return;
        };
        match self.store.set_archived(id, !archived) {
            Ok(()) => {
                self.reload_near_selection();
                let text = if archived {
                    format!("📦 \"{alias}\" restored")
                } else {
                    format!("📦 \"{alias}\" archived (A shows archive)")
                };
                self.set_status(StatusKind::Info, text);
            }
            Err(err) => self.set_status(StatusKind::Error, format!("Archiving failed: {err}")),
        }
    }

    fn toggle_show_archived(&mut self) {
        self.show_archived = !self.show_archived;
        self.reload_or_report();
        let text = if self.show_archived {
            "Showing archived hosts"
        } else {
            "Archived hosts hidden"
        };
        self.set_status(StatusKind::Info, text);
    }

    // ---- Passwords and connecting ---------------------------------------

    /// Starts the connection: if the host has a password, it is fetched *now* –
    /// while we are still in the TUI and can ask for the master password
    /// if needed. Only the event loop releases the terminal.
    fn begin_connect(&mut self, host: Host, session: Session) -> Effect {
        if !host.has_password {
            return Effect::Connect {
                host: Box::new(host),
                password: None,
                session,
            };
        }
        match self.secrets.lock_state() {
            Ok(LockState::Ready) => self.connect_with_password(host, session),
            Ok(LockState::Locked) => {
                self.open_secret_dialog(SecretDialog::for_connect(host, session));
                Effect::None
            }
            Ok(LockState::NeedsInit) => {
                self.set_status(
                    StatusKind::Error,
                    "Password stored, but no master password exists – set it again with p",
                );
                Effect::None
            }
            Err(err) => {
                self.set_status(StatusKind::Error, format!("Password storage: {err}"));
                Effect::None
            }
        }
    }

    /// Fetches the password from the (unlocked) storage and returns the connect effect.
    fn connect_with_password(&mut self, host: Host, session: Session) -> Effect {
        match secrets::fetch_host_password(self.secrets.as_mut(), &self.store, &host) {
            Ok(password) => {
                if password.is_none() {
                    // The flag was stale and has been repaired: refresh the display.
                    self.reload_or_report();
                }
                Effect::Connect {
                    host: Box::new(host),
                    password,
                    session,
                }
            }
            Err(err) => {
                self.set_status(
                    StatusKind::Error,
                    format!("Could not read password: {err:#}"),
                );
                Effect::None
            }
        }
    }

    /// `m`: mounts the host at its default mount point, or unmounts it if
    /// something is mounted there already.
    fn toggle_mount(&mut self, host: Host) -> Effect {
        let mountpoint = match connect::mount::default_mountpoint(&self.programs.mount, &host.alias)
        {
            Ok(path) => path,
            Err(err) => {
                self.set_status(StatusKind::Error, format!("Mount point: {err:#}"));
                return Effect::None;
            }
        };
        if connect::mount::is_mounted(&mountpoint) {
            return Effect::Unmount {
                alias: host.alias,
                mountpoint,
            };
        }
        let target = MountTarget {
            mountpoint,
            remote_path: None,
        };
        self.begin_connect(host, Session::Mount(target))
    }

    fn open_password_dialog(&mut self) {
        let Some(host) = self.selected_host() else {
            return;
        };
        let dialog = SecretDialog::for_password(host);
        self.open_secret_dialog(dialog);
    }

    fn open_secret_dialog(&mut self, dialog: SecretDialog) {
        self.secret_dialog = Some(dialog);
        self.mode = Mode::Secret;
    }

    /// Closes the password dialog; its inputs are overwritten in the process.
    fn close_secret_dialog(&mut self) {
        self.secret_dialog = None;
        self.mode = Mode::Normal;
    }

    /// Accepts a key for the password dialog.
    ///
    /// The dialog is briefly *taken out* of `self` (`take`) so that we may
    /// use `self.secrets` and `self.store` at the same time
    /// (the borrow checker only allows one mutable borrow at a time).
    fn secret_key(&mut self, key: KeyEvent) -> Effect {
        let Some(mut dialog) = self.secret_dialog.take() else {
            self.mode = Mode::Normal;
            return Effect::None;
        };
        match dialog.handle_key(key) {
            DialogEvent::None => {
                self.secret_dialog = Some(dialog);
                Effect::None
            }
            DialogEvent::Cancel => {
                self.mode = Mode::Normal;
                let text = match dialog.intent {
                    Intent::SetPassword => "Cancelled – password unchanged",
                    Intent::Connect(..) => "Connection cancelled",
                };
                self.set_status(StatusKind::Info, text);
                Effect::None
            }
            DialogEvent::Submit => self.secret_submit(dialog),
        }
    }

    /// Evaluates the confirmation of a step and moves on to the next one.
    fn secret_submit(&mut self, mut dialog: SecretDialog) -> Effect {
        match dialog.step {
            Step::EnterPassword => {
                if !dialog.input.is_empty() {
                    let password = dialog.take_input();
                    dialog.remember_first(password);
                    dialog.goto(Step::RepeatPassword);
                } else if dialog.has_password {
                    dialog.goto(Step::ConfirmRemove);
                } else {
                    dialog.fail("The password must not be empty");
                }
                self.keep_dialog(dialog)
            }
            Step::RepeatPassword => {
                let second = dialog.take_input();
                match dialog.take_first() {
                    // `==` on `SecretString` compares in constant time.
                    Some(first) if first == second => {
                        dialog.set_pending(first);
                        self.continue_after_password(dialog)
                    }
                    _ => {
                        dialog.goto(Step::EnterPassword);
                        dialog.fail("The two entries do not match");
                        self.keep_dialog(dialog)
                    }
                }
            }
            Step::ConfirmRemove => self.finish_remove(&dialog),
            Step::Unlock => {
                let master = dialog.take_input();
                match self.secrets.unlock(master.expose()) {
                    Ok(()) => self.after_unlock(dialog),
                    Err(SecretError::WrongMasterPassword) => {
                        dialog.fail("Wrong master password");
                        self.keep_dialog(dialog)
                    }
                    Err(err) => self.abort_dialog(format!("Unlock failed: {err}")),
                }
            }
            Step::NewMaster => {
                let master = dialog.take_input();
                match check_new_master(master.expose()) {
                    Ok(()) => {
                        dialog.remember_first(master);
                        dialog.goto(Step::RepeatMaster);
                    }
                    Err(message) => dialog.fail(message),
                }
                self.keep_dialog(dialog)
            }
            Step::RepeatMaster => {
                let second = dialog.take_input();
                match dialog.take_first() {
                    Some(first) if first == second => {
                        match self.secrets.initialize(first.expose()) {
                            Ok(()) => self.after_unlock(dialog),
                            Err(err) => {
                                self.abort_dialog(format!("Master password not saved: {err}"))
                            }
                        }
                    }
                    _ => {
                        dialog.goto(Step::NewMaster);
                        dialog.fail("The two entries do not match");
                        self.keep_dialog(dialog)
                    }
                }
            }
        }
    }

    fn keep_dialog(&mut self, dialog: SecretDialog) -> Effect {
        self.secret_dialog = Some(dialog);
        Effect::None
    }

    /// Closes the dialog with an error message.
    fn abort_dialog(&mut self, message: String) -> Effect {
        self.close_secret_dialog();
        self.set_status(StatusKind::Error, message);
        Effect::None
    }

    /// The host password is settled: if the storage is ready, save it – otherwise
    /// first ask for or set the master password.
    fn continue_after_password(&mut self, mut dialog: SecretDialog) -> Effect {
        match self.secrets.lock_state() {
            Ok(LockState::Ready) => self.finish_set(dialog),
            Ok(LockState::Locked) => {
                dialog.goto(Step::Unlock);
                self.keep_dialog(dialog)
            }
            Ok(LockState::NeedsInit) => {
                dialog.goto(Step::NewMaster);
                self.keep_dialog(dialog)
            }
            Err(err) => self.abort_dialog(format!("Password storage: {err}")),
        }
    }

    /// The storage is now unlocked: continue with what the dialog was opened for.
    fn after_unlock(&mut self, mut dialog: SecretDialog) -> Effect {
        // `mem::replace` takes the intent out and leaves a placeholder behind.
        match std::mem::replace(&mut dialog.intent, Intent::SetPassword) {
            Intent::SetPassword => self.finish_set(dialog),
            Intent::Connect(host, session) => {
                self.close_secret_dialog();
                self.connect_with_password(*host, session)
            }
        }
    }

    /// Saves the confirmed password and closes the dialog.
    fn finish_set(&mut self, mut dialog: SecretDialog) -> Effect {
        let Some(password) = dialog.take_pending() else {
            return self.abort_dialog("Internal error: no password to save".to_owned());
        };
        self.close_secret_dialog();
        let result = secrets::save_host_password(
            self.secrets.as_mut(),
            &self.store,
            dialog.host_id,
            password.expose(),
        );
        match result {
            Ok(()) => {
                self.reload_or_report();
                let label = self.secret_backend_label();
                self.set_status(
                    StatusKind::Success,
                    format!("🔑 Password for \"{}\" saved ({label})", dialog.alias),
                );
            }
            Err(err) => self.set_status(
                StatusKind::Error,
                format!("Saving password failed: {err:#}"),
            ),
        }
        Effect::None
    }

    /// Removes the password (needs no master password) and closes the dialog.
    fn finish_remove(&mut self, dialog: &SecretDialog) -> Effect {
        self.close_secret_dialog();
        match secrets::remove_host_password(self.secrets.as_mut(), &self.store, dialog.host_id) {
            Ok(()) => {
                self.reload_or_report();
                self.set_status(
                    StatusKind::Success,
                    format!("🔑 Password for \"{}\" removed", dialog.alias),
                );
            }
            Err(err) => self.set_status(
                StatusKind::Error,
                format!("Removing password failed: {err:#}"),
            ),
        }
        Effect::None
    }

    // ---- Management: tags ------------------------------------------------

    fn open_tag_dialog(&mut self) {
        let Some(host) = self.selected_host() else {
            return;
        };
        let names: Vec<&str> = host.tags.iter().map(|t| t.name.as_str()).collect();
        let dialog = TagDialog {
            host_id: host.id,
            alias: host.alias.clone(),
            input: TextInput::with_value(names.join(", ")),
            error: None,
            known_tags: self.known_tag_names(),
        };
        self.tag_dialog = Some(dialog);
        self.mode = Mode::TagEdit;
    }

    fn close_tag_dialog(&mut self) {
        self.tag_dialog = None;
        self.mode = Mode::Normal;
    }

    fn tag_dialog_key(&mut self, key: KeyEvent) {
        let Some(dialog) = self.tag_dialog.as_mut() else {
            self.mode = Mode::Normal;
            return;
        };
        match key.code {
            KeyCode::Esc => self.close_tag_dialog(),
            KeyCode::Enter => self.save_tag_dialog(),
            KeyCode::Tab => {
                if let Some(text) = complete_tag(dialog.input.value(), &dialog.known_tags) {
                    dialog.input.set_value(text);
                }
            }
            _ => {
                if dialog.input.handle_key(key) {
                    dialog.error = None;
                }
            }
        }
    }

    fn save_tag_dialog(&mut self) {
        let Some(dialog) = self.tag_dialog.as_mut() else {
            return;
        };
        let tags = match parse_tags(dialog.input.value()) {
            Ok(tags) => tags,
            Err(message) => {
                dialog.error = Some(message);
                return;
            }
        };
        let (id, alias) = (dialog.host_id, dialog.alias.clone());
        match self.store.set_host_tags(id, &tags) {
            Ok(()) => {
                self.close_tag_dialog();
                if let Err(err) = self.reload_keeping(Some(id)) {
                    self.set_status(StatusKind::Error, format!("Reload failed: {err:#}"));
                } else {
                    self.set_status(StatusKind::Success, format!("✔ Tags of \"{alias}\" saved"));
                }
            }
            Err(err) => {
                if let Some(dialog) = self.tag_dialog.as_mut() {
                    dialog.error = Some(format!("Save failed: {err}"));
                }
            }
        }
    }

    fn open_tag_filter(&mut self) {
        // Count hosts per tag across the currently loaded hosts.
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for host in &self.hosts {
            for tag in &host.tags {
                *counts.entry(tag.name.as_str()).or_default() += 1;
            }
        }
        if counts.is_empty() {
            self.set_status(StatusKind::Info, "No tags assigned yet (t assigns tags)");
            return;
        }
        let mut entries: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(name, count)| (name.to_owned(), count))
            .collect();
        entries.sort_by_key(|(name, _)| name.to_lowercase());
        self.tag_filter = Some(TagFilter {
            entries,
            selected: 0,
        });
        self.mode = Mode::TagFilter;
    }

    fn tag_filter_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return;
        }
        let Some(filter) = self.tag_filter.as_mut() else {
            self.mode = Mode::Normal;
            return;
        };
        let last = filter.entries.len().saturating_sub(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.tag_filter = None;
                self.mode = Mode::Normal;
            }
            KeyCode::Up | KeyCode::Char('k') => filter.selected = filter.selected.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => filter.selected = (filter.selected + 1).min(last),
            KeyCode::Home | KeyCode::Char('g') => filter.selected = 0,
            KeyCode::End | KeyCode::Char('G') => filter.selected = last,
            KeyCode::Enter => {
                let chosen = filter.entries.get(filter.selected).map(|(n, _)| n.clone());
                self.tag_filter = None;
                self.mode = Mode::Normal;
                if let Some(tag) = chosen {
                    self.filter_by_tag(&tag);
                }
            }
            _ => {}
        }
    }

    /// Puts `#tag` into the search; other `#` filters are dropped, normal
    /// search text is kept.
    fn filter_by_tag(&mut self, tag: &str) {
        let mut words: Vec<&str> = self
            .query
            .split_whitespace()
            .filter(|w| !w.starts_with('#'))
            .collect();
        let tag_word = format!("#{tag}");
        words.push(&tag_word);
        let query = words.join(" ");
        self.set_query(query);
    }

    /// Changes the search text and filters again (selection stays if possible).
    fn set_query(&mut self, query: String) {
        let keep = self.selected_host().map(|h| h.id);
        self.query = query;
        self.apply_filter(keep);
    }

    fn toggle_favorite(&mut self) {
        let Some((id, alias, now_fav)) = self
            .selected_host()
            .map(|h| (h.id, h.alias.clone(), !h.favorite))
        else {
            return;
        };
        match self.store.set_favorite(id, now_fav) {
            Ok(()) => {
                // `reload` keeps the selection on the host, even if it is sorted away.
                self.reload_or_report();
                let text = if now_fav {
                    format!("★ {alias} is now a favorite")
                } else {
                    format!("{alias} is no longer a favorite")
                };
                self.set_status(StatusKind::Info, text);
            }
            Err(err) => self.set_status(StatusKind::Error, format!("Save failed: {err}")),
        }
    }

    fn reload_or_report(&mut self) {
        if let Err(err) = self.reload() {
            self.set_status(StatusKind::Error, format!("Reload failed: {err:#}"));
        }
    }

    /// Called after a connection: reloads (selection stays) and shows
    /// the result as a status message. Rendering/describing is up to the caller.
    pub fn finish_connect(&mut self, status: StatusKind, text: String) {
        self.reload_or_report();
        self.set_status(status, text);
    }

    /// Starts the session with `host` (the terminal must be released beforehand).
    ///
    /// The store belongs to the `App`; this way it doesn't have to be handed out.
    pub fn run_connect(
        &self,
        host: &Host,
        password: Option<SecretString>,
        session: &Session,
    ) -> anyhow::Result<crate::connect::ConnectOutcome> {
        crate::connect::run(&self.store, host, password, &self.programs, session)
    }

    /// Short name of the active password storage ("Keychain" / "encrypted").
    pub fn secret_backend_label(&self) -> &'static str {
        self.secrets.kind().label()
    }

    /// For tests and loading code: the store, e.g. to create connections.
    #[cfg(test)]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Sets the search text directly (tests).
    #[cfg(test)]
    pub fn set_query_for_test(&mut self, query: &str) {
        self.set_query(query.to_owned());
    }
}

/// All searchable fields of a host in one text.
fn searchable_text(host: &Host) -> String {
    let mut parts: Vec<&str> = vec![&host.alias];
    parts.extend(host.hostname.as_deref());
    parts.extend(host.user.as_deref());
    parts.extend(host.tags.iter().map(|t| t.name.as_str()));
    parts.extend(host.notes.as_deref());
    parts.join(" ")
}

/// Sorts hosts by `mode`; favorites always come first.
///
/// `sort_by` takes a *closure* (anonymous function `|a, b| …`) that compares
/// two elements and returns a [`std::cmp::Ordering`]. `then_with` chains
/// several criteria: it evaluates the next criterion (again a closure) only
/// if the previous one yielded `Equal`.
fn sort_hosts_by(hosts: &mut [Host], mode: SortMode, stats: &HashMap<i64, HostStats>) {
    match mode {
        SortMode::Name => sort_hosts(hosts),
        SortMode::Recent => {
            let last = |h: &Host| stats.get(&h.id).and_then(|s| s.last_success_at);
            hosts.sort_by(|a, b| {
                b.favorite
                    .cmp(&a.favorite)
                    // `Option` is ordered (`None < Some`): `last(b).cmp(&last(a))`
                    // sorts newest first, never-connected ones at the end.
                    .then_with(|| last(b).cmp(&last(a)))
                    .then_with(|| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()))
            });
        }
        SortMode::Frequent => {
            let count = |h: &Host| stats.get(&h.id).map_or(0, |s| s.total_connections);
            hosts.sort_by(|a, b| {
                b.favorite
                    .cmp(&a.favorite)
                    .then_with(|| count(b).cmp(&count(a)))
                    .then_with(|| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ConnectionStatus, NewHost};

    /// Builds an app with five hosts: alpha (prod, web), beta (prod), gamma, delta (notes), eps.
    fn app() -> App {
        let mut store = Store::open_in_memory().unwrap();
        let mut ids = Vec::new();
        for (alias, hostname, notes) in [
            ("alpha", "a.example.invalid", None),
            ("beta", "b.example.invalid", None),
            ("gamma", "g.example.invalid", None),
            ("delta", "d.example.invalid", Some("Database server")),
            ("eps", "e.example.invalid", None),
        ] {
            let mut host = NewHost::new(alias);
            host.hostname = Some(hostname.into());
            host.notes = notes.map(str::to_owned);
            ids.push(store.insert_host(&host).unwrap());
        }
        store.set_host_tags(ids[0], &["prod", "web"]).unwrap();
        store.set_host_tags(ids[1], &["prod"]).unwrap();
        // An archived host must never show up.
        let hidden = store.insert_host(&NewHost::new("hidden")).unwrap();
        store.set_archived(hidden, true).unwrap();
        App::new(store, &[]).unwrap()
    }

    fn aliases(app: &App) -> Vec<&str> {
        app.rows
            .iter()
            .map(|r| app.hosts[r.host_index].alias.as_str())
            .collect()
    }

    fn selected_alias(app: &App) -> &str {
        &app.selected_host().unwrap().alias
    }

    /// Logs `n` successful connections to `alias`.
    fn log_connections(app: &App, alias: &str, n: usize) {
        let id = app.store().get_host_by_alias(alias).unwrap().unwrap().id;
        for _ in 0..n {
            let log = app.store().start_connection(id).unwrap();
            app.store()
                .finish_connection(log, Some(0), ConnectionStatus::Success)
                .unwrap();
        }
    }

    #[test]
    fn archived_hosts_are_hidden() {
        let app = app();
        assert_eq!(aliases(&app), ["alpha", "beta", "delta", "eps", "gamma"]);
    }

    #[test]
    fn navigation_respects_bounds() {
        let mut app = app();
        app.update(Action::Up);
        assert_eq!(app.selected, 0);
        app.update(Action::Down);
        assert_eq!(selected_alias(&app), "beta");
        app.update(Action::Last);
        assert_eq!(selected_alias(&app), "gamma");
        app.update(Action::Down);
        assert_eq!(selected_alias(&app), "gamma");
        app.update(Action::First);
        assert_eq!(selected_alias(&app), "alpha");
    }

    #[test]
    fn paging_moves_by_page_size_and_clamps() {
        let mut app = app();
        app.page_size = 3;
        app.update(Action::PageDown);
        assert_eq!(app.selected, 3);
        app.update(Action::PageDown);
        assert_eq!(app.selected, 4);
        app.update(Action::PageUp);
        assert_eq!(app.selected, 1);
        app.update(Action::PageUp);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn detail_follows_selection() {
        let mut app = app();
        assert_eq!(app.detail.as_ref().unwrap().host_id, app.hosts[0].id);
        app.update(Action::Down);
        assert_eq!(app.detail.as_ref().unwrap().host_id, app.hosts[1].id);
    }

    #[test]
    fn fuzzy_search_filters_and_sorts_by_score() {
        let mut app = app();
        app.set_query_for_test("gam");
        assert_eq!(aliases(&app), ["gamma"]);
        assert_eq!(app.rows[0].alias_matches, vec![0, 1, 2]);
        // "eps" also fuzzy-matches "delta" (hostname + note), but the
        // exact alias match must rank on top by score.
        app.set_query_for_test("eps");
        assert_eq!(aliases(&app)[0], "eps");
    }

    #[test]
    fn search_covers_hostname_and_notes() {
        let mut app = app();
        app.set_query_for_test("database");
        assert_eq!(aliases(&app), ["delta"]);
        app.set_query_for_test("g.example");
        assert_eq!(aliases(&app), ["gamma"]);
    }

    #[test]
    fn search_covers_tags_across_fields() {
        let mut app = app();
        app.set_query_for_test("alpha web");
        assert_eq!(aliases(&app), ["alpha"]);
    }

    #[test]
    fn tag_filter_and_combination() {
        let mut app = app();
        app.set_query_for_test("#prod");
        assert_eq!(aliases(&app), ["alpha", "beta"]);
        app.set_query_for_test("#PRO #web");
        assert_eq!(aliases(&app), ["alpha"]);
        app.set_query_for_test("#prod bet");
        assert_eq!(aliases(&app), ["beta"]);
        app.set_query_for_test("#nope");
        assert!(app.rows.is_empty());
        assert!(app.selected_host().is_none());
        // A lone "#" filters nothing.
        app.set_query_for_test("#");
        assert_eq!(app.rows.len(), 5);
    }

    #[test]
    fn search_modes_and_cancel() {
        let mut app = app();
        app.update(Action::OpenSearch);
        assert_eq!(app.mode, Mode::Search);
        app.update(Action::SearchChar('g'));
        app.update(Action::SearchChar('a'));
        app.update(Action::SearchChar('m'));
        assert_eq!(aliases(&app), ["gamma"]);
        app.update(Action::SearchBackspace);
        app.update(Action::SearchBackspace);
        app.update(Action::SearchBackspace);
        assert_eq!(app.rows.len(), 5);
        app.update(Action::SearchChar('d'));
        // Enter commits: the filter stays.
        app.update(Action::CommitSearch);
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.query.is_empty());
        // Esc clears.
        app.update(Action::OpenSearch);
        app.update(Action::CancelSearch);
        assert!(app.query.is_empty());
        assert_eq!(app.rows.len(), 5);
    }

    #[test]
    fn parse_query_splits_tags_and_text() {
        let p = parse_query("  web  #Prod  #  db ");
        assert_eq!(p.tags, ["prod"]);
        assert_eq!(p.fuzzy, "web db");
    }

    #[test]
    fn sort_cycle_name_recent_frequent() {
        let mut app = app();
        log_connections(&app, "gamma", 1);
        log_connections(&app, "delta", 3);
        app.update(Action::CycleSort);
        assert_eq!(app.sort, SortMode::Recent);
        // gamma and delta connected; "Recent" uses the newest timestamp,
        // on a tie (same millisecond) the alias decides.
        let names = aliases(&app);
        assert!(names[..2].contains(&"gamma") && names[..2].contains(&"delta"));
        app.update(Action::CycleSort);
        assert_eq!(app.sort, SortMode::Frequent);
        assert_eq!(aliases(&app)[0], "delta");
        assert_eq!(aliases(&app)[1], "gamma");
        app.update(Action::CycleSort);
        assert_eq!(app.sort, SortMode::Name);
        assert_eq!(aliases(&app)[0], "alpha");
    }

    #[test]
    fn recent_sort_puts_never_connected_last() {
        let mut app = app();
        log_connections(&app, "eps", 1);
        app.update(Action::CycleSort);
        assert_eq!(aliases(&app)[0], "eps");
    }

    #[test]
    fn favorite_toggle_moves_host_to_top_and_keeps_selection() {
        let mut app = app();
        app.update(Action::Last);
        assert_eq!(selected_alias(&app), "gamma");
        app.update(Action::ToggleFavorite);
        assert_eq!(aliases(&app)[0], "gamma");
        assert_eq!(selected_alias(&app), "gamma");
        assert_eq!(app.selected, 0);
        app.update(Action::ToggleFavorite);
        assert_eq!(aliases(&app)[0], "alpha");
        assert_eq!(selected_alias(&app), "gamma");
    }

    #[test]
    fn selection_stays_on_same_host_after_reload() {
        let mut app = app();
        app.update(Action::Down);
        app.update(Action::Down);
        assert_eq!(selected_alias(&app), "delta");
        // New host sorted in before it (alphabetically before "delta").
        app.store().insert_host(&NewHost::new("aaa")).unwrap();
        app.reload().unwrap();
        assert_eq!(selected_alias(&app), "delta");
    }

    #[test]
    fn connect_action_yields_effect_and_empty_list_does_nothing() {
        let mut app = app();
        match app.update(Action::Connect) {
            Effect::Connect {
                host,
                password,
                session,
            } => {
                assert_eq!(host.alias, "alpha");
                // alpha has no password stored.
                assert!(password.is_none());
                assert_eq!(session, Session::Shell);
            }
            other => panic!("unexpected: {other:?}"),
        }
        app.set_query_for_test("#nope");
        assert_eq!(app.update(Action::Connect), Effect::None);
        assert_eq!(app.update(Action::Quit), Effect::Quit);
    }

    #[test]
    fn sftp_and_mount_actions_yield_their_session() {
        let mut app = app();
        match app.update(Action::Sftp) {
            Effect::Connect { host, session, .. } => {
                assert_eq!(host.alias, "alpha");
                assert_eq!(session, Session::Sftp);
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Nothing is mounted at the default mount point: mount.
        match app.update(Action::ToggleMount) {
            Effect::Connect {
                session: Session::Mount(target),
                ..
            } => {
                assert!(target.mountpoint.ends_with("mnt/alpha"));
                assert_eq!(target.remote_path, None);
            }
            other => panic!("unexpected: {other:?}"),
        }
        app.set_query_for_test("#nope");
        assert_eq!(app.update(Action::Sftp), Effect::None);
        assert_eq!(app.update(Action::ToggleMount), Effect::None);
    }

    #[test]
    fn detail_counts_connections_per_day() {
        let mut app = app();
        log_connections(&app, "alpha", 3);
        app.reload().unwrap();
        let detail = app.detail.as_ref().unwrap();
        assert_eq!(detail.per_day[SPARK_DAYS - 1], 3);
        assert_eq!(detail.history.len(), 3);
    }

    #[test]
    fn config_sets_start_sort_archive_and_icon() {
        let config = AppConfig {
            default_sort: DefaultSort::Frequent,
            show_archived: true,
            icon_fallback: "*".to_owned(),
            ..AppConfig::default()
        };
        let store = Store::open_in_memory().unwrap();
        let secrets = Box::new(secrets::MemoryStore::default());
        let app = App::with_secrets(store, secrets, config, &[]).unwrap();
        assert_eq!(app.sort, SortMode::Frequent);
        assert!(app.show_archived);
        assert_eq!(app.icon_fallback, "*");
    }

    #[test]
    fn warnings_become_status() {
        let store = Store::open_in_memory().unwrap();
        let app = App::new(store, &["first".into(), "second".into()]).unwrap();
        let status = app.status.unwrap();
        assert_eq!(status.kind, StatusKind::Warning);
        assert!(status.text.contains("first") && status.text.contains("+1"));
    }

    // ---- Management ------------------------------------------------------

    use crate::store::SshConfigHost;
    use crate::tui::event::key_to_action;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// Sends a key through the same path as the event loop.
    fn send(app: &mut App, code: KeyCode) {
        send_mod(app, code, KeyModifiers::NONE);
    }

    fn send_mod(app: &mut App, code: KeyCode, mods: KeyModifiers) {
        let key = KeyEvent::new(code, mods);
        let has_filter = !app.query.is_empty();
        if let Some(action) = key_to_action(app.mode, has_filter, key) {
            app.update(action);
        }
    }

    fn type_str(app: &mut App, text: &str) {
        for c in text.chars() {
            send(app, KeyCode::Char(c));
        }
    }

    /// Adds an ssh_config host and reloads.
    fn add_ssh_config_host(app: &mut App, alias: &str) {
        let host = SshConfigHost {
            alias: alias.into(),
            hostname: Some("cfg.example.invalid".into()),
            ..SshConfigHost::default()
        };
        app.store().upsert_ssh_config_host(&host).unwrap();
        app.reload().unwrap();
    }

    fn select_alias(app: &mut App, alias: &str) {
        let pos = aliases(app).iter().position(|a| *a == alias).unwrap();
        app.update(Action::First);
        for _ in 0..pos {
            app.update(Action::Down);
        }
        assert_eq!(selected_alias(app), alias);
    }

    #[test]
    fn new_host_flow_creates_host_with_tags_and_selects_it() {
        let mut app = app();
        send(&mut app, KeyCode::Char('a'));
        assert_eq!(app.mode, Mode::Form);
        type_str(&mut app, "newbie");
        send(&mut app, KeyCode::Tab);
        type_str(&mut app, "n.example.invalid");
        // Continue to tags (Hostname → User → Port → Identity → Jump → Extra → Auth → Icon → Tags).
        for _ in 0..8 {
            send(&mut app, KeyCode::Tab);
        }
        type_str(&mut app, "fresh, prod");
        send_mod(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.form.is_none());
        assert_eq!(selected_alias(&app), "newbie");
        let host = app.selected_host().unwrap();
        assert_eq!(host.source, HostSource::Manual);
        assert_eq!(host.hostname.as_deref(), Some("n.example.invalid"));
        let tags: Vec<_> = host.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tags, ["fresh", "prod"]);
        assert_eq!(app.status.as_ref().unwrap().kind, StatusKind::Success);
    }

    #[test]
    fn duplicate_alias_keeps_form_open_with_field_error() {
        let mut app = app();
        send(&mut app, KeyCode::Char('a'));
        type_str(&mut app, "alpha");
        send_mod(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.mode, Mode::Form);
        let form = app.form.as_ref().unwrap();
        assert!(form.error_for(Field::Alias).unwrap().contains("taken"));
        assert_eq!(form.focus, Field::Alias);
        assert_eq!(app.rows.len(), 5);
    }

    #[test]
    fn invalid_input_keeps_form_open() {
        let mut app = app();
        send(&mut app, KeyCode::Char('a'));
        send_mod(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.mode, Mode::Form);
        assert!(app.form.as_ref().unwrap().error_for(Field::Alias).is_some());
    }

    #[test]
    fn edit_manual_host_updates_it() {
        let mut app = app();
        select_alias(&mut app, "gamma");
        send(&mut app, KeyCode::Char('e'));
        assert_eq!(app.mode, Mode::Form);
        // Change alias: the cursor is at the end of the field.
        send(&mut app, KeyCode::Backspace);
        type_str(&mut app, "x");
        send_mod(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(selected_alias(&app), "gammx");
        assert_eq!(
            app.selected_host().unwrap().hostname.as_deref(),
            Some("g.example.invalid")
        );
    }

    #[test]
    fn edit_ssh_config_host_only_changes_metadata() {
        let mut app = app();
        add_ssh_config_host(&mut app, "cfg");
        select_alias(&mut app, "cfg");
        send(&mut app, KeyCode::Char('e'));
        assert!(app.form.as_ref().unwrap().is_ssh_config());
        assert_eq!(app.form.as_ref().unwrap().focus, Field::Icon);
        type_str(&mut app, "🔥");
        send(&mut app, KeyCode::Tab);
        type_str(&mut app, "infra");
        send_mod(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.mode, Mode::Normal);
        let host = app.selected_host().unwrap();
        assert_eq!(host.alias, "cfg");
        assert_eq!(host.source, HostSource::SshConfig);
        assert_eq!(host.hostname.as_deref(), Some("cfg.example.invalid"));
        assert_eq!(host.icon.as_deref(), Some("🔥"));
        assert_eq!(host.tags[0].name, "infra");
    }

    #[test]
    fn discard_confirmation_flow() {
        let mut app = app();
        send(&mut app, KeyCode::Char('a'));
        // Unchanged: Esc closes immediately.
        send(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
        // With changes: confirmation prompt; "no" leads back to the form.
        send(&mut app, KeyCode::Char('a'));
        type_str(&mut app, "abc");
        send(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Confirm);
        assert_eq!(app.confirm, Some(Confirm::DiscardForm));
        send(&mut app, KeyCode::Char('n'));
        assert_eq!(app.mode, Mode::Form);
        assert_eq!(app.form.as_ref().unwrap().value(Field::Alias), "abc");
        // "yes" discards.
        send(&mut app, KeyCode::Esc);
        send(&mut app, KeyCode::Char('y'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.form.is_none() && app.confirm.is_none());
        assert_eq!(app.rows.len(), 5);
    }

    #[test]
    fn delete_requires_confirmation() {
        let mut app = app();
        select_alias(&mut app, "eps");
        send(&mut app, KeyCode::Char('d'));
        assert_eq!(app.mode, Mode::Confirm);
        // Any other key cancels, the host stays.
        send(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.rows.len(), 5);
        // With "y" it is deleted; the selection stays nearby.
        send(&mut app, KeyCode::Char('d'));
        send(&mut app, KeyCode::Char('y'));
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(aliases(&app), ["alpha", "beta", "delta", "gamma"]);
        assert!(app.store().get_host_by_alias("eps").unwrap().is_none());
        assert_eq!(selected_alias(&app), "gamma");
    }

    #[test]
    fn ssh_config_host_cannot_be_deleted() {
        let mut app = app();
        add_ssh_config_host(&mut app, "cfg");
        select_alias(&mut app, "cfg");
        send(&mut app, KeyCode::Char('d'));
        // No confirmation dialog, but a notice.
        assert_eq!(app.mode, Mode::Normal);
        let status = app.status.as_ref().unwrap();
        assert_eq!(status.kind, StatusKind::Warning);
        assert!(status.text.contains("~/.ssh/config") && status.text.contains('x'));
        // Even a hand-built delete command has no effect.
        let id = app.selected_host().unwrap().id;
        app.delete_host(id, "cfg");
        assert!(app.store().get_host_by_alias("cfg").unwrap().is_some());
    }

    #[test]
    fn tag_dialog_replaces_tags_for_manual_and_ssh_config_hosts() {
        let mut app = app();
        add_ssh_config_host(&mut app, "cfg");
        for alias in ["alpha", "cfg"] {
            select_alias(&mut app, alias);
            send(&mut app, KeyCode::Char('t'));
            assert_eq!(app.mode, Mode::TagEdit);
            // Prefilled with the existing tags; clear and set anew.
            send_mod(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
            type_str(&mut app, "new, #two");
            send(&mut app, KeyCode::Enter);
            assert_eq!(app.mode, Mode::Normal);
            let tags: Vec<_> = app
                .selected_host()
                .unwrap()
                .tags
                .iter()
                .map(|t| t.name.clone())
                .collect();
            assert_eq!(tags, ["new", "two"], "{alias}");
        }
    }

    #[test]
    fn tag_dialog_prefills_validates_completes_and_cancels() {
        let mut app = app();
        select_alias(&mut app, "alpha");
        send(&mut app, KeyCode::Char('t'));
        assert_eq!(app.tag_dialog.as_ref().unwrap().input.value(), "prod, web");
        // Invalid (space in tag): error, dialog stays.
        type_str(&mut app, ", two words");
        send(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::TagEdit);
        assert!(app.tag_dialog.as_ref().unwrap().error.is_some());
        // Tab completion with the known tag "prod".
        send_mod(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        type_str(&mut app, "pr");
        send(&mut app, KeyCode::Tab);
        assert_eq!(app.tag_dialog.as_ref().unwrap().input.value(), "prod");
        // Esc discards without saving.
        send_mod(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        send(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.selected_host().unwrap().tags.len(), 2);
    }

    #[test]
    fn archive_toggle_hides_and_restores() {
        let mut app = app();
        select_alias(&mut app, "beta");
        send(&mut app, KeyCode::Char('x'));
        assert_eq!(aliases(&app), ["alpha", "delta", "eps", "gamma"]);
        // The selection stays at the same position (now "delta").
        assert_eq!(selected_alias(&app), "delta");
        // Show archive: "beta" appears archived.
        send(&mut app, KeyCode::Char('A'));
        assert!(app.show_archived);
        assert!(aliases(&app).contains(&"beta") && aliases(&app).contains(&"hidden"));
        select_alias(&mut app, "beta");
        assert!(app.selected_host().unwrap().archived);
        // Restore.
        send(&mut app, KeyCode::Char('x'));
        assert!(
            !app.store()
                .get_host_by_alias("beta")
                .unwrap()
                .unwrap()
                .archived
        );
        // Hide: "hidden" disappears again.
        send(&mut app, KeyCode::Char('A'));
        assert!(!app.show_archived);
        assert!(!aliases(&app).contains(&"hidden"));
    }

    #[test]
    fn tag_filter_lists_counts_and_sets_query() {
        let mut app = app();
        send(&mut app, KeyCode::Char('T'));
        assert_eq!(app.mode, Mode::TagFilter);
        let entries = app.tag_filter.as_ref().unwrap().entries.clone();
        assert_eq!(entries, [("prod".to_owned(), 2), ("web".to_owned(), 1)]);
        send(&mut app, KeyCode::Down);
        send(&mut app, KeyCode::Enter);
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.query, "#web");
        assert_eq!(aliases(&app), ["alpha"]);
        // A second filter replaces the first, search text stays.
        app.set_query_for_test("alp #web");
        send(&mut app, KeyCode::Char('T'));
        send(&mut app, KeyCode::Enter);
        assert_eq!(app.query, "alp #prod");
    }

    #[test]
    fn tag_filter_esc_and_empty_tag_list() {
        let mut app = app();
        send(&mut app, KeyCode::Char('T'));
        send(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.query.is_empty());
        // Without tags nothing opens.
        let mut empty = App::new(Store::open_in_memory().unwrap(), &[]).unwrap();
        send(&mut empty, KeyCode::Char('T'));
        assert_eq!(empty.mode, Mode::Normal);
        assert!(empty.status.is_some());
    }

    #[test]
    fn management_keys_do_nothing_on_empty_selection() {
        let mut app = app();
        app.set_query_for_test("#nope");
        for c in ['e', 't', 'd', 'x'] {
            send(&mut app, KeyCode::Char(c));
            assert_eq!(app.mode, Mode::Normal, "{c}");
        }
    }

    // ---- Passwords --------------------------------------------------------

    /// Like `send`, but returns the effect (for connecting).
    fn send_effect(app: &mut App, code: KeyCode) -> Effect {
        let key = KeyEvent::new(code, KeyModifiers::NONE);
        let has_filter = !app.query.is_empty();
        match key_to_action(app.mode, has_filter, key) {
            Some(action) => app.update(action),
            None => Effect::None,
        }
    }

    fn type_and_enter(app: &mut App, text: &str) -> Effect {
        for c in text.chars() {
            send(app, KeyCode::Char(c));
        }
        send_effect(app, KeyCode::Enter)
    }

    fn host_id(app: &App, alias: &str) -> i64 {
        app.store().get_host_by_alias(alias).unwrap().unwrap().id
    }

    fn has_password(app: &App, alias: &str) -> bool {
        app.store()
            .get_host_by_alias(alias)
            .unwrap()
            .unwrap()
            .has_password
    }

    fn stored(app: &mut App, alias: &str) -> Option<String> {
        let id = host_id(app, alias);
        app.secrets.get(id).unwrap().map(|s| s.expose().to_owned())
    }

    /// Sets a password for the selected host via the UI.
    fn set_password_via_ui(app: &mut App, pw: &str) {
        send(app, KeyCode::Char('p'));
        type_and_enter(app, pw);
        type_and_enter(app, pw);
    }

    #[test]
    fn p_sets_password_after_two_matching_entries() {
        let mut app = app();
        send(&mut app, KeyCode::Char('p'));
        assert_eq!(app.mode, Mode::Secret);
        type_and_enter(&mut app, "hunter2");
        assert_eq!(
            app.secret_dialog.as_ref().unwrap().step,
            Step::RepeatPassword
        );
        type_and_enter(&mut app, "hunter2");
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.secret_dialog.is_none());
        assert!(has_password(&app, "alpha"));
        assert_eq!(stored(&mut app, "alpha").as_deref(), Some("hunter2"));
        assert!(app.selected_host().unwrap().has_password);
        assert_eq!(app.status.as_ref().unwrap().kind, StatusKind::Success);
        // The status message never mentions the password.
        assert!(!app.status.as_ref().unwrap().text.contains("hunter2"));
    }

    #[test]
    fn mismatching_repeat_starts_over_and_stores_nothing() {
        let mut app = app();
        send(&mut app, KeyCode::Char('p'));
        type_and_enter(&mut app, "one");
        type_and_enter(&mut app, "two");
        let dialog = app.secret_dialog.as_ref().unwrap();
        assert_eq!(dialog.step, Step::EnterPassword);
        assert!(dialog.error.as_deref().unwrap().contains("do not match"));
        assert!(!has_password(&app, "alpha"));
        assert_eq!(stored(&mut app, "alpha"), None);
    }

    #[test]
    fn empty_password_is_refused_when_none_exists_and_esc_cancels() {
        let mut app = app();
        send(&mut app, KeyCode::Char('p'));
        send(&mut app, KeyCode::Enter);
        assert_eq!(
            app.secret_dialog.as_ref().unwrap().step,
            Step::EnterPassword
        );
        assert!(app.secret_dialog.as_ref().unwrap().error.is_some());
        send(&mut app, KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.secret_dialog.is_none());
        assert!(!has_password(&app, "alpha"));
    }

    #[test]
    fn empty_input_with_existing_password_asks_to_remove() {
        let mut app = app();
        set_password_via_ui(&mut app, "pw");
        assert!(has_password(&app, "alpha"));
        // Cancelling the prompt leaves everything unchanged.
        send(&mut app, KeyCode::Char('p'));
        send(&mut app, KeyCode::Enter);
        assert_eq!(
            app.secret_dialog.as_ref().unwrap().step,
            Step::ConfirmRemove
        );
        send(&mut app, KeyCode::Char('n'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(has_password(&app, "alpha"));
        // With "y" it is removed.
        send(&mut app, KeyCode::Char('p'));
        send(&mut app, KeyCode::Enter);
        send(&mut app, KeyCode::Char('y'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!has_password(&app, "alpha"));
        assert_eq!(stored(&mut app, "alpha"), None);
    }

    #[test]
    fn connect_carries_the_password_into_the_effect() {
        let mut app = app();
        set_password_via_ui(&mut app, "pw-for-alpha");
        match app.update(Action::Connect) {
            Effect::Connect { host, password, .. } => {
                assert_eq!(host.alias, "alpha");
                assert_eq!(password.unwrap().expose(), "pw-for-alpha");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // The debug format of the effect does not reveal the password.
        let effect = app.update(Action::Connect);
        assert!(!format!("{effect:?}").contains("pw-for-alpha"));
    }

    #[test]
    fn stale_flag_is_healed_and_connect_continues_without_password() {
        let mut app = app();
        let id = host_id(&app, "alpha");
        app.store().set_has_password(id, true).unwrap();
        app.reload().unwrap();
        match app.update(Action::Connect) {
            Effect::Connect { password, .. } => assert!(password.is_none()),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!has_password(&app, "alpha"));
    }

    #[test]
    fn deleting_a_host_deletes_its_secret_first() {
        let mut app = app();
        set_password_via_ui(&mut app, "pw");
        let id = host_id(&app, "alpha");
        send(&mut app, KeyCode::Char('d'));
        send(&mut app, KeyCode::Char('y'));
        assert!(app.store().get_host(id).unwrap().is_none());
        assert!(app.secrets.get(id).unwrap().is_none());
    }

    #[test]
    fn host_survives_when_its_secret_cannot_be_deleted() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("solo")).unwrap();
        let mut failing = secrets::MemoryStore::default();
        failing.fail_delete = true;
        let mut app =
            App::with_secrets(store, Box::new(failing), AppConfig::default(), &[]).unwrap();
        send(&mut app, KeyCode::Char('d'));
        send(&mut app, KeyCode::Char('y'));
        assert!(app.store().get_host(id).unwrap().is_some());
        assert_eq!(app.status.as_ref().unwrap().kind, StatusKind::Error);
    }

    #[test]
    fn detail_panel_names_the_backend_when_a_password_exists() {
        let mut app = app();
        set_password_via_ui(&mut app, "pw");
        assert_eq!(app.secret_backend_label(), "Keychain");
        assert!(app.selected_host().unwrap().has_password);
    }

    /// App with a real encrypted storage (fast KDF) in a temp directory.
    fn encrypted_app(dir: &std::path::Path) -> App {
        let path = dir.join("sshire.db");
        let store = Store::open(&path).unwrap();
        if store.get_host_by_alias("alpha").unwrap().is_none() {
            store.insert_host(&NewHost::new("alpha")).unwrap();
        }
        let enc =
            secrets::EncryptedStore::open_with_params(&path, secrets::KdfParams::FAST).unwrap();
        App::with_secrets(store, Box::new(enc), AppConfig::default(), &[]).unwrap()
    }

    #[test]
    fn first_password_on_encrypted_backend_sets_a_master_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = encrypted_app(dir.path());
        assert_eq!(app.secret_backend_label(), "encrypted");
        send(&mut app, KeyCode::Char('p'));
        type_and_enter(&mut app, "host-pw");
        type_and_enter(&mut app, "host-pw");
        // Now the dialog asks for a *new* master password.
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::NewMaster);
        // Too short: error, no progress.
        type_and_enter(&mut app, "short");
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::NewMaster);
        assert!(app.secret_dialog.as_ref().unwrap().error.is_some());
        type_and_enter(&mut app, "long enough master");
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::RepeatMaster);
        // Mismatching repeat: back to the start of the master step.
        type_and_enter(&mut app, "long enough MASTER");
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::NewMaster);
        type_and_enter(&mut app, "long enough master");
        type_and_enter(&mut app, "long enough master");
        assert_eq!(app.mode, Mode::Normal);
        assert!(has_password(&app, "alpha"));
        assert_eq!(stored(&mut app, "alpha").as_deref(), Some("host-pw"));
    }

    #[test]
    fn locked_backend_asks_for_master_before_connecting() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut app = encrypted_app(dir.path());
            send(&mut app, KeyCode::Char('p'));
            type_and_enter(&mut app, "host-pw");
            type_and_enter(&mut app, "host-pw");
            type_and_enter(&mut app, "long enough master");
            type_and_enter(&mut app, "long enough master");
        }
        // New process (new app): the storage is locked again.
        let mut app = encrypted_app(dir.path());
        assert!(app.selected_host().unwrap().has_password);
        // SFTP: the session kind must survive the unlock dialog.
        assert_eq!(app.update(Action::Sftp), Effect::None);
        assert_eq!(app.mode, Mode::Secret);
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::Unlock);
        // Wrong master password: error message, dialog stays, no connect.
        assert_eq!(type_and_enter(&mut app, "wrong master"), Effect::None);
        assert!(
            app.secret_dialog
                .as_ref()
                .unwrap()
                .error
                .as_deref()
                .unwrap()
                .contains("Wrong")
        );
        match type_and_enter(&mut app, "long enough master") {
            Effect::Connect {
                host,
                password,
                session,
            } => {
                assert_eq!(host.alias, "alpha");
                assert_eq!(password.unwrap().expose(), "host-pw");
                assert_eq!(session, Session::Sftp);
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn changing_a_password_on_a_locked_backend_unlocks_first() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut app = encrypted_app(dir.path());
            set_password_via_ui(&mut app, "old-pw");
            type_and_enter(&mut app, "long enough master");
            type_and_enter(&mut app, "long enough master");
        }
        let mut app = encrypted_app(dir.path());
        set_password_via_ui(&mut app, "new-pw");
        assert_eq!(app.secret_dialog.as_ref().unwrap().step, Step::Unlock);
        type_and_enter(&mut app, "long enough master");
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(stored(&mut app, "alpha").as_deref(), Some("new-pw"));
    }

    #[test]
    fn removing_a_password_needs_no_master_password() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut app = encrypted_app(dir.path());
            set_password_via_ui(&mut app, "pw");
            type_and_enter(&mut app, "long enough master");
            type_and_enter(&mut app, "long enough master");
        }
        let mut app = encrypted_app(dir.path());
        send(&mut app, KeyCode::Char('p'));
        send(&mut app, KeyCode::Enter);
        send(&mut app, KeyCode::Char('y'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!has_password(&app, "alpha"));
    }
}
