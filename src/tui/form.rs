//! State of the host form (create and edit), without a terminal.
//!
//! [`FormState`] is a small *state machine*: it knows which field has focus,
//! what is in the fields, which errors to show and whether the icon picker is
//! currently open. [`FormState::handle_key`] takes a key press and reports as
//! a [`FormEvent`] what the app should do (save, cancel, ask for
//! confirmation). Drawing and database access happen elsewhere, so
//! everything here can be checked with ordinary unit tests.
//!
//! # `ssh_config`-Hosts
//!
//! `~/.ssh/config` is the source of truth and is never written by sshire.
//! For hosts with `source = ssh_config`, the fields from alias through auth
//! are therefore read-only (focus skips them); icon, tags and notes remain
//! editable, since they are sshire's own metadata.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::emoji::{IconPicker, PickerEvent};
use super::input::TextInput;
use crate::store::{AuthMethod, Host, HostSource, HostUpdate, NewHost};
use crate::validate::{Field, FieldError, RawHost, validate_host, validate_metadata};

/// Why the form was opened.
///
/// An `enum` may carry *data* in its variants: `New` needs none, `Edit`
/// brings the previous host along. This makes it impossible to even
/// represent "editing without a host". `Box` puts the (large) `Host` on the
/// heap so the enum variant stays small.
#[derive(Debug, Clone, PartialEq)]
pub enum FormKind {
    /// New manual host.
    New,
    /// Edit an existing host.
    Edit { original: Box<Host> },
}

/// The validated result of a saved form.
#[derive(Debug, Clone, PartialEq)]
pub enum FormResult {
    /// Create a new host and assign the tags to it.
    Create { host: NewHost, tags: Vec<String> },
    /// Update an existing host and replace its tags.
    Update {
        id: i64,
        update: HostUpdate,
        tags: Vec<String>,
    },
}

/// What the app has to do after a key press in the form.
#[derive(Debug, Clone, PartialEq)]
pub enum FormEvent {
    /// Nothing further.
    None,
    /// Valid input: save. (`Box`, so the variant isn't much larger than the
    /// data-less ones; otherwise every `FormEvent` would reserve that space.)
    Submit(Box<FormResult>),
    /// Close the form (no changes present).
    Cancel,
    /// There are unsaved changes: ask for confirmation.
    ConfirmDiscard,
}

/// The entire form state.
///
/// `#[derive(Clone, PartialEq)]` makes the state cloneable and comparable,
/// so tests can check it directly.
#[derive(Debug, Clone, PartialEq)]
pub struct FormState {
    pub kind: FormKind,
    /// All text fields (`Field::Auth` is not a text field and is missing here).
    inputs: Vec<(Field, TextInput)>,
    /// Chosen auth method.
    pub auth: AuthMethod,
    /// Field with focus.
    pub focus: Field,
    /// Errors currently shown.
    pub errors: Vec<FieldError>,
    /// Open icon picker, if any.
    pub picker: Option<IconPicker>,
    /// Existing tag names for Tab completion.
    known_tags: Vec<String>,
    /// Initial values, to detect "unsaved changes".
    initial: (Vec<String>, AuthMethod),
}

impl FormState {
    /// Empty form for a new manual host.
    pub fn new_host(known_tags: Vec<String>) -> Self {
        Self::build(FormKind::New, &RawHost::default(), known_tags)
    }

    /// Form for editing `host`.
    pub fn edit(host: &Host, known_tags: Vec<String>) -> Self {
        let raw = RawHost {
            alias: host.alias.clone(),
            hostname: host.hostname.clone().unwrap_or_default(),
            user: host.user.clone().unwrap_or_default(),
            port: host.port.map(|p| p.to_string()).unwrap_or_default(),
            identity_file: host.identity_file.clone().unwrap_or_default(),
            proxy_jump: host.proxy_jump.clone().unwrap_or_default(),
            extra_args: host.extra_args.clone().unwrap_or_default(),
            icon: host.icon.clone().unwrap_or_default(),
            tags: host
                .tags
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            notes: host.notes.clone().unwrap_or_default(),
            auth: host.auth_method,
        };
        let kind = FormKind::Edit {
            original: Box::new(host.clone()),
        };
        Self::build(kind, &raw, known_tags)
    }

    fn build(kind: FormKind, raw: &RawHost, known_tags: Vec<String>) -> Self {
        let text = |field: Field| -> String {
            match field {
                Field::Alias => raw.alias.clone(),
                Field::Hostname => raw.hostname.clone(),
                Field::User => raw.user.clone(),
                Field::Port => raw.port.clone(),
                Field::IdentityFile => raw.identity_file.clone(),
                Field::ProxyJump => raw.proxy_jump.clone(),
                Field::ExtraArgs => raw.extra_args.clone(),
                Field::Icon => raw.icon.clone(),
                Field::Tags => raw.tags.clone(),
                Field::Notes => raw.notes.clone(),
                Field::Auth => String::new(),
            }
        };
        let inputs: Vec<(Field, TextInput)> = Field::ALL
            .iter()
            .filter(|f| **f != Field::Auth)
            .map(|f| (*f, TextInput::with_value(text(*f))))
            .collect();
        let mut form = Self {
            kind,
            inputs,
            auth: raw.auth,
            focus: Field::Alias,
            errors: Vec::new(),
            picker: None,
            known_tags,
            initial: (Vec::new(), raw.auth),
        };
        form.initial = form.snapshot();
        form.focus = form.editable_fields()[0];
        form
    }

    /// Text of all fields (to detect changes).
    fn snapshot(&self) -> (Vec<String>, AuthMethod) {
        (
            self.inputs
                .iter()
                .map(|(_, i)| i.value().to_owned())
                .collect(),
            self.auth,
        )
    }

    /// `true` if anything has changed since opening.
    pub fn is_dirty(&self) -> bool {
        self.snapshot() != self.initial
    }

    /// The previous host when editing.
    pub fn original(&self) -> Option<&Host> {
        match &self.kind {
            FormKind::New => None,
            FormKind::Edit { original } => Some(original),
        }
    }

    /// `true` for `ssh_config` hosts: connection fields are read-only.
    pub fn is_ssh_config(&self) -> bool {
        // `matches!` checks whether a value fits a pattern and returns a `bool`.
        matches!(self.original(), Some(h) if h.source == HostSource::SshConfig)
    }

    /// Is this field currently not editable?
    pub fn is_readonly(&self, field: Field) -> bool {
        self.is_ssh_config() && field.is_connection_field()
    }

    /// All fields the focus may move to (in order).
    pub fn editable_fields(&self) -> Vec<Field> {
        Field::ALL
            .iter()
            .copied()
            .filter(|f| !self.is_readonly(*f))
            .collect()
    }

    /// Text field for `field` (`None` for `Field::Auth`).
    pub fn input(&self, field: Field) -> Option<&TextInput> {
        self.inputs
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, i)| i)
    }

    fn input_mut(&mut self, field: Field) -> Option<&mut TextInput> {
        self.inputs
            .iter_mut()
            .find(|(f, _)| *f == field)
            .map(|(_, i)| i)
    }

    /// Text of a field (empty for `Field::Auth`).
    pub fn value(&self, field: Field) -> &str {
        self.input(field).map_or("", TextInput::value)
    }

    /// Sets the text of a field (tests and picker).
    pub fn set_value(&mut self, field: Field, text: &str) {
        if let Some(input) = self.input_mut(field) {
            input.set_value(text);
        }
    }

    /// Error message for a field.
    pub fn error_for(&self, field: Field) -> Option<&str> {
        self.errors
            .iter()
            .find(|e| e.field == field)
            .map(|e| e.message.as_str())
    }

    /// Sets (replaces) the error message of a field, e.g. "Alias already taken".
    pub fn set_error(&mut self, field: Field, message: impl Into<String>) {
        self.errors.retain(|e| e.field != field);
        self.errors.push(FieldError {
            field,
            message: message.into(),
        });
        if !self.is_readonly(field) {
            self.focus = field;
        }
    }

    /// Hint about the auth method (currently only for password).
    pub fn auth_hint(&self) -> Option<&'static str> {
        (self.auth == AuthMethod::Password && !self.is_readonly(Field::Auth))
            .then_some("Set the password with p in the list")
    }

    /// Title for the border.
    pub fn title(&self) -> String {
        match self.original() {
            None => "New host".to_owned(),
            Some(host) => format!("Edit host: {}", host.alias),
        }
    }

    // ---- Focus -----------------------------------------------------------

    fn move_focus(&mut self, delta: isize) {
        let fields = self.editable_fields();
        let pos = fields.iter().position(|f| *f == self.focus).unwrap_or(0);
        // With wraparound: after the last field comes the first again.
        let len = fields.len().cast_signed();
        let next = (pos.cast_signed() + delta).rem_euclid(len);
        self.focus = fields[next.cast_unsigned()];
    }

    /// Focus the next editable field.
    pub fn focus_next(&mut self) {
        self.move_focus(1);
    }

    /// Focus the previous editable field.
    pub fn focus_prev(&mut self) {
        self.move_focus(-1);
    }

    fn is_last_field(&self) -> bool {
        self.editable_fields().last() == Some(&self.focus)
    }

    // ---- Input ---------------------------------------------------------

    fn cycle_auth(&mut self, forward: bool) {
        self.auth = match (self.auth, forward) {
            (AuthMethod::Agent, true) | (AuthMethod::Password, false) => AuthMethod::Key,
            (AuthMethod::Key, true) | (AuthMethod::Agent, false) => AuthMethod::Password,
            (AuthMethod::Password, true) | (AuthMethod::Key, false) => AuthMethod::Agent,
        };
    }

    /// Evaluates a key press.
    pub fn handle_key(&mut self, key: KeyEvent) -> FormEvent {
        // 1. If the picker is open, it owns the input.
        if let Some(picker) = self.picker.as_mut() {
            match picker.handle_key(key) {
                PickerEvent::None => {}
                PickerEvent::Cancel => self.picker = None,
                PickerEvent::Picked(symbol) => {
                    self.picker = None;
                    self.set_value(Field::Icon, symbol);
                    self.errors.retain(|e| e.field != Field::Icon);
                }
            }
            return FormEvent::None;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            KeyCode::Char('s') if ctrl => return self.submit_event(),
            KeyCode::Char('e') if ctrl && self.focus == Field::Icon => {
                self.picker = Some(IconPicker::new());
            }
            KeyCode::Esc => {
                return if self.is_dirty() {
                    FormEvent::ConfirmDiscard
                } else {
                    FormEvent::Cancel
                };
            }
            KeyCode::BackTab | KeyCode::Up => self.focus_prev(),
            KeyCode::Tab if shift => self.focus_prev(),
            KeyCode::Tab => {
                // In the tags field Tab completes first; if nothing fits, it moves on.
                if !(self.focus == Field::Tags && self.complete_tags()) {
                    self.focus_next();
                }
            }
            KeyCode::Down => self.focus_next(),
            KeyCode::Enter => match self.focus {
                Field::Icon => self.picker = Some(IconPicker::new()),
                _ if self.is_last_field() => return self.submit_event(),
                _ => self.focus_next(),
            },
            _ if self.focus == Field::Auth => match key.code {
                KeyCode::Left => self.cycle_auth(false),
                KeyCode::Right | KeyCode::Char(' ') => self.cycle_auth(true),
                _ => {}
            },
            _ => {
                let focus = self.focus;
                if let Some(input) = self.input_mut(focus)
                    && input.handle_key(key)
                {
                    // Whoever edits a field has seen the error: hide the message.
                    self.errors.retain(|e| e.field != focus);
                }
            }
        }
        FormEvent::None
    }

    /// Completes the last tag in the tags field; `true` if something changed.
    fn complete_tags(&mut self) -> bool {
        let Some(completed) = complete_tag(self.value(Field::Tags), &self.known_tags) else {
            return false;
        };
        self.set_value(Field::Tags, &completed);
        true
    }

    fn submit_event(&mut self) -> FormEvent {
        match self.submit() {
            Some(result) => FormEvent::Submit(Box::new(result)),
            None => FormEvent::None,
        }
    }

    /// Validates the inputs. On errors they are stored in
    /// [`FormState::errors`] and the focus jumps to the first faulty field.
    pub fn submit(&mut self) -> Option<FormResult> {
        self.errors.clear();
        let result = match &self.kind {
            FormKind::Edit { original } if original.source == HostSource::SshConfig => {
                self.submit_metadata_only(original)
            }
            _ => self.submit_full(),
        };
        match result {
            Ok(result) => Some(result),
            Err(errors) => {
                if let Some(first) = errors.iter().find(|e| !self.is_readonly(e.field)) {
                    self.focus = first.field;
                }
                self.errors = errors;
                None
            }
        }
    }

    /// `ssh_config` host: validate only icon, tags and notes; the rest stays as it was.
    fn submit_metadata_only(&self, original: &Host) -> Result<FormResult, Vec<FieldError>> {
        let meta = validate_metadata(
            self.value(Field::Icon),
            self.value(Field::Tags),
            self.value(Field::Notes),
        )?;
        let update = HostUpdate {
            alias: original.alias.clone(),
            hostname: original.hostname.clone(),
            user: original.user.clone(),
            port: original.port,
            identity_file: original.identity_file.clone(),
            proxy_jump: original.proxy_jump.clone(),
            extra_args: original.extra_args.clone(),
            icon: meta.icon,
            color: original.color.clone(),
            notes: meta.notes,
            auth_method: original.auth_method,
        };
        Ok(FormResult::Update {
            id: original.id,
            update,
            tags: meta.tags,
        })
    }

    /// Manual host: validate all fields.
    fn submit_full(&self) -> Result<FormResult, Vec<FieldError>> {
        let raw = RawHost {
            alias: self.value(Field::Alias).to_owned(),
            hostname: self.value(Field::Hostname).to_owned(),
            user: self.value(Field::User).to_owned(),
            port: self.value(Field::Port).to_owned(),
            identity_file: self.value(Field::IdentityFile).to_owned(),
            proxy_jump: self.value(Field::ProxyJump).to_owned(),
            extra_args: self.value(Field::ExtraArgs).to_owned(),
            icon: self.value(Field::Icon).to_owned(),
            tags: self.value(Field::Tags).to_owned(),
            notes: self.value(Field::Notes).to_owned(),
            auth: self.auth,
        };
        let valid = validate_host(&raw)?;
        Ok(match &self.kind {
            FormKind::New => FormResult::Create {
                // `From<&ValidHost> for NewHost` from `validate.rs`; `.into()` applies it.
                host: (&valid).into(),
                tags: valid.tags,
            },
            FormKind::Edit { original } => FormResult::Update {
                id: original.id,
                update: valid.to_update(original.color.clone()),
                tags: valid.tags,
            },
        })
    }
}

/// Completes the *last* comma-separated entry with the first known tag that
/// starts with it (case-insensitively).
///
/// Tags already present in the field are skipped, so repeated Tab doesn't
/// insert the same tag twice. Returns `None` if there is nothing to
/// complete.
pub fn complete_tag(text: &str, known: &[String]) -> Option<String> {
    // `rfind` returns the *byte* offset of the last comma; a comma is an
    // ASCII character (1 byte), so `idx + 1` is safely a character boundary.
    let (head, rest) = match text.rfind(',') {
        Some(idx) => text.split_at(idx + 1),
        None => ("", text),
    };
    let fragment = rest.trim().trim_start_matches('#');
    if fragment.is_empty() {
        return None;
    }
    let lower = fragment.to_lowercase();
    let already: Vec<String> = head
        .split(',')
        .map(|t| t.trim().trim_start_matches('#').to_lowercase())
        .collect();
    let tag = known.iter().find(|tag| {
        let tag_lower = tag.to_lowercase();
        tag_lower.starts_with(&lower) && tag_lower != lower && !already.contains(&tag_lower)
    })?;
    let lead = &rest[..rest.len() - rest.trim_start().len()];
    Some(format!("{head}{lead}{tag}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Tag;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn type_text(form: &mut FormState, text: &str) {
        for c in text.chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
    }

    fn host(source: HostSource) -> Host {
        Host {
            id: 7,
            alias: "web".into(),
            hostname: Some("web.example.invalid".into()),
            user: Some("admin".into()),
            port: Some(2222),
            identity_file: None,
            proxy_jump: None,
            extra_args: Some("-v".into()),
            icon: Some("🚀".into()),
            color: Some("#ff0000".into()),
            notes: Some("old".into()),
            source,
            favorite: false,
            archived: false,
            auth_method: AuthMethod::Key,
            has_password: false,
            created_at: 0,
            updated_at: 0,
            tags: vec![Tag {
                id: 1,
                name: "prod".into(),
                color: None,
                icon: None,
            }],
        }
    }

    #[test]
    fn tab_and_arrows_move_focus_with_wraparound() {
        let mut form = FormState::new_host(vec![]);
        assert_eq!(form.focus, Field::Alias);
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus, Field::Hostname);
        form.handle_key(key(KeyCode::Down));
        assert_eq!(form.focus, Field::User);
        form.handle_key(key(KeyCode::Up));
        form.handle_key(key(KeyCode::BackTab));
        assert_eq!(form.focus, Field::Alias);
        // Going back from the first field lands on the last one.
        form.handle_key(key(KeyCode::BackTab));
        assert_eq!(form.focus, Field::Notes);
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus, Field::Alias);
        // Shift+Tab as the modifier variant.
        form.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
        assert_eq!(form.focus, Field::Notes);
    }

    #[test]
    fn ssh_config_host_skips_readonly_fields() {
        let mut form = FormState::edit(&host(HostSource::SshConfig), vec![]);
        assert!(form.is_readonly(Field::Alias));
        assert!(form.is_readonly(Field::Auth));
        assert!(!form.is_readonly(Field::Icon));
        assert_eq!(
            form.editable_fields(),
            [Field::Icon, Field::Tags, Field::Notes]
        );
        assert_eq!(form.focus, Field::Icon);
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus, Field::Tags);
        form.handle_key(key(KeyCode::Tab));
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus, Field::Icon);
        // Typing does not change the connection fields.
        assert_eq!(form.value(Field::Alias), "web");
        form.handle_key(key(KeyCode::BackTab));
        assert_eq!(form.focus, Field::Notes);
    }

    #[test]
    fn manual_host_has_all_fields_editable() {
        let form = FormState::edit(&host(HostSource::Manual), vec![]);
        assert_eq!(form.editable_fields().len(), Field::ALL.len());
        assert_eq!(form.value(Field::Port), "2222");
        assert_eq!(form.value(Field::Tags), "prod");
        assert_eq!(form.auth, AuthMethod::Key);
    }

    #[test]
    fn typing_and_cursor_editing_in_a_field() {
        let mut form = FormState::new_host(vec![]);
        type_text(&mut form, "wbe");
        form.handle_key(key(KeyCode::Left));
        form.handle_key(key(KeyCode::Left));
        form.handle_key(key(KeyCode::Char('e')));
        assert_eq!(form.value(Field::Alias), "webe");
        form.handle_key(key(KeyCode::End));
        form.handle_key(key(KeyCode::Backspace));
        assert_eq!(form.value(Field::Alias), "web");
        form.handle_key(key(KeyCode::Home));
        form.handle_key(key(KeyCode::Delete));
        assert_eq!(form.value(Field::Alias), "eb");
        // Input only lands in the focused field.
        assert_eq!(form.value(Field::Hostname), "");
    }

    #[test]
    fn auth_field_cycles_with_arrows_and_shows_password_hint() {
        let mut form = FormState::new_host(vec![]);
        while form.focus != Field::Auth {
            form.focus_next();
        }
        assert_eq!(form.auth, AuthMethod::Agent);
        assert_eq!(form.auth_hint(), None);
        form.handle_key(key(KeyCode::Right));
        assert_eq!(form.auth, AuthMethod::Key);
        form.handle_key(key(KeyCode::Right));
        assert_eq!(form.auth, AuthMethod::Password);
        assert!(form.auth_hint().unwrap().contains("with p"));
        form.handle_key(key(KeyCode::Right));
        assert_eq!(form.auth, AuthMethod::Agent);
        form.handle_key(key(KeyCode::Left));
        assert_eq!(form.auth, AuthMethod::Password);
        // Letters don't change the selection.
        form.handle_key(key(KeyCode::Char('x')));
        assert_eq!(form.auth, AuthMethod::Password);
    }

    #[test]
    fn empty_alias_is_reported_and_focused() {
        let mut form = FormState::new_host(vec![]);
        form.focus = Field::Notes;
        assert!(form.submit().is_none());
        assert!(form.error_for(Field::Alias).unwrap().contains("required"));
        assert_eq!(form.focus, Field::Alias);
        // Typing on hides the message.
        type_text(&mut form, "a");
        assert!(form.error_for(Field::Alias).is_none());
    }

    #[test]
    fn invalid_fields_produce_messages_per_field() {
        let mut form = FormState::new_host(vec![]);
        form.set_value(Field::Alias, "-x");
        form.set_value(Field::Hostname, "-h");
        form.set_value(Field::Port, "70000");
        form.set_value(Field::ExtraArgs, "'open");
        form.set_value(Field::Icon, "ab");
        assert!(form.submit().is_none());
        for field in [
            Field::Alias,
            Field::Hostname,
            Field::Port,
            Field::ExtraArgs,
            Field::Icon,
        ] {
            assert!(form.error_for(field).is_some(), "{field:?}");
        }
        assert!(form.error_for(Field::User).is_none());
    }

    #[test]
    fn valid_new_host_becomes_create_result() {
        let mut form = FormState::new_host(vec![]);
        form.set_value(Field::Alias, "db1");
        form.set_value(Field::Hostname, "db.example.invalid");
        form.set_value(Field::Port, "5432");
        form.set_value(Field::Tags, "prod, db");
        form.auth = AuthMethod::Key;
        let Some(FormResult::Create { host, tags }) = form.submit() else {
            panic!("expected Create");
        };
        assert_eq!(host.alias, "db1");
        assert_eq!(host.port, Some(5432));
        assert_eq!(host.auth_method, AuthMethod::Key);
        assert_eq!(host.source, HostSource::Manual);
        assert_eq!(tags, ["prod", "db"]);
    }

    #[test]
    fn manual_edit_becomes_update_keeping_color() {
        let mut form = FormState::edit(&host(HostSource::Manual), vec![]);
        form.set_value(Field::Alias, "web2");
        let Some(FormResult::Update { id, update, tags }) = form.submit() else {
            panic!("expected Update");
        };
        assert_eq!(id, 7);
        assert_eq!(update.alias, "web2");
        assert_eq!(update.color.as_deref(), Some("#ff0000"));
        assert_eq!(update.extra_args.as_deref(), Some("-v"));
        assert_eq!(tags, ["prod"]);
    }

    #[test]
    fn ssh_config_edit_keeps_connection_fields_and_updates_metadata() {
        let original = host(HostSource::SshConfig);
        let mut form = FormState::edit(&original, vec![]);
        // Even if someone tampered with the (locked) fields: the original value counts.
        form.set_value(Field::Alias, "tampered");
        form.set_value(Field::Icon, "🔥");
        form.set_value(Field::Tags, "new");
        form.set_value(Field::Notes, "Note");
        let Some(FormResult::Update { id, update, tags }) = form.submit() else {
            panic!("expected Update");
        };
        assert_eq!(id, 7);
        assert_eq!(update.alias, "web");
        assert_eq!(update.hostname, original.hostname);
        assert_eq!(update.port, Some(2222));
        assert_eq!(update.auth_method, AuthMethod::Key);
        assert_eq!(update.icon.as_deref(), Some("🔥"));
        assert_eq!(update.notes.as_deref(), Some("Note"));
        assert_eq!(tags, ["new"]);
    }

    #[test]
    fn ssh_config_edit_with_invalid_icon_reports_error() {
        let mut form = FormState::edit(&host(HostSource::SshConfig), vec![]);
        form.set_value(Field::Icon, "too long");
        assert!(form.submit().is_none());
        assert!(form.error_for(Field::Icon).is_some());
        assert_eq!(form.focus, Field::Icon);
    }

    #[test]
    fn ctrl_s_and_enter_on_last_field_submit() {
        let mut form = FormState::new_host(vec![]);
        form.set_value(Field::Alias, "x");
        // `Box<FormResult>`: `*` takes the contents out of the box for the pattern.
        let FormEvent::Submit(result) = form.handle_key(ctrl('s')) else {
            panic!("expected Submit");
        };
        assert!(matches!(*result, FormResult::Create { .. }));
        // Enter in a middle field just moves on.
        form.focus = Field::Hostname;
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormEvent::None);
        assert_eq!(form.focus, Field::User);
        // Enter in the last field saves.
        form.focus = Field::Notes;
        assert!(matches!(
            form.handle_key(key(KeyCode::Enter)),
            FormEvent::Submit(_)
        ));
        // With an error: no submit.
        form.set_value(Field::Alias, "");
        assert_eq!(form.handle_key(ctrl('s')), FormEvent::None);
        assert!(form.error_for(Field::Alias).is_some());
    }

    #[test]
    fn esc_cancels_directly_when_clean_and_asks_when_dirty() {
        let mut form = FormState::new_host(vec![]);
        assert!(!form.is_dirty());
        assert_eq!(form.handle_key(key(KeyCode::Esc)), FormEvent::Cancel);
        type_text(&mut form, "a");
        assert!(form.is_dirty());
        assert_eq!(
            form.handle_key(key(KeyCode::Esc)),
            FormEvent::ConfirmDiscard
        );
        // Change undone: clean again.
        form.handle_key(key(KeyCode::Backspace));
        assert!(!form.is_dirty());
        // A changed auth method counts as a change too.
        form.auth = AuthMethod::Key;
        assert!(form.is_dirty());
    }

    #[test]
    fn icon_picker_opens_with_ctrl_e_or_enter_and_fills_the_field() {
        let mut form = FormState::new_host(vec![]);
        // Ctrl-E only works in the icon field.
        form.handle_key(ctrl('e'));
        assert!(form.picker.is_none());
        form.focus = Field::Icon;
        form.handle_key(ctrl('e'));
        assert!(form.picker.is_some());
        for c in "docker".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        // While the picker is open, keys don't land in the form.
        assert_eq!(form.value(Field::Icon), "");
        form.handle_key(key(KeyCode::Enter));
        assert!(form.picker.is_none());
        assert_eq!(form.value(Field::Icon), "🐳");
        // Esc closes only the picker, not the form.
        form.handle_key(key(KeyCode::Enter));
        assert!(form.picker.is_some());
        assert_eq!(form.handle_key(key(KeyCode::Esc)), FormEvent::None);
        assert!(form.picker.is_none());
        assert_eq!(form.value(Field::Icon), "🐳");
    }

    #[test]
    fn icon_free_text_is_still_possible() {
        let mut form = FormState::new_host(vec![]);
        form.focus = Field::Icon;
        form.handle_key(key(KeyCode::Char('\u{f120}')));
        assert_eq!(form.value(Field::Icon), "\u{f120}");
        form.set_value(Field::Alias, "x");
        assert!(form.submit().is_some());
    }

    #[test]
    fn tab_completes_tags_then_moves_on() {
        let known = vec!["prod".to_owned(), "production".to_owned(), "web".to_owned()];
        let mut form = FormState::new_host(known);
        form.focus = Field::Tags;
        type_text(&mut form, "db, pr");
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.value(Field::Tags), "db, prod");
        assert_eq!(form.focus, Field::Tags);
        // "prod" is itself a prefix of "production": the second Tab takes the next candidate.
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.value(Field::Tags), "db, production");
        // Nothing left to complete: the next Tab moves to the next field.
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus, Field::Notes);
    }

    #[test]
    fn complete_tag_rules() {
        let known = vec!["Prod".to_owned(), "web".to_owned()];
        assert_eq!(complete_tag("pr", &known).as_deref(), Some("Prod"));
        assert_eq!(complete_tag("a,  w", &known).as_deref(), Some("a,  web"));
        // Empty fragment, no match, already complete, already used:
        assert_eq!(complete_tag("a, ", &known), None);
        assert_eq!(complete_tag("zz", &known), None);
        assert_eq!(complete_tag("web", &known), None);
        assert_eq!(complete_tag("prod, pr", &known), None);
        assert_eq!(complete_tag("#we", &known).as_deref(), Some("web"));
    }

    #[test]
    fn set_error_focuses_editable_field_only() {
        let mut form = FormState::new_host(vec![]);
        form.focus = Field::Notes;
        form.set_error(Field::Alias, "already taken");
        assert_eq!(form.focus, Field::Alias);
        assert_eq!(form.error_for(Field::Alias), Some("already taken"));
        let mut ro = FormState::edit(&host(HostSource::SshConfig), vec![]);
        ro.set_error(Field::Alias, "x");
        assert_eq!(ro.focus, Field::Icon);
    }
}
