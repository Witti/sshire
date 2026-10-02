//! Rendering: draws the [`App`] state into a ratatui `Frame`.
//!
//! # Ownership while rendering
//!
//! Almost all functions here receive `&App` (a shared, read-only borrow):
//! drawing must not change the state. The only exception is [`draw`] itself
//! with `&mut App`: for scrolling lists ratatui needs a mutable scroll state
//! (`ListState`), and we remember the visible list height for PgUp/PgDn.
//!
//! # Lifetimes in widgets
//!
//! `Line<'a>` and `Span<'a>` can *borrow* text instead of copying it:
//! `Span::raw(&host.alias)` points to the string inside the `App`. The `'a`
//! is the lifetime of that borrow: the lines must not outlive the `App` they
//! come from. The compiler checks this. Where we build text anew with
//! `format!`, the span owns the `String` itself.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::app::{App, Mode, Row, SPARK_DAYS, StatusKind};
use super::{overlays, theme};
use crate::commands::target_label;
use crate::store::{ConnectionStatus, Host, HostSource, now_ms};
use crate::timefmt;

/// From this terminal width on, list and detail sit side by side.
const WIDE_LAYOUT_MIN_WIDTH: u16 = 100;

/// Draws the whole interface.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    // `areas` splits the space into a fixed-size array (here 3 parts).
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);

    let [list_area, detail_area] = if area.width < WIDE_LAYOUT_MIN_WIDTH {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body)
    } else {
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body)
    };

    draw_header(frame, app, header);
    draw_list(frame, app, list_area);
    draw_detail(frame, app, detail_area);
    draw_footer(frame, app, footer);
    // Overlays: one per mode; the confirmation prompt sits on top of an open form.
    match app.mode {
        Mode::Normal | Mode::Search => {}
        Mode::Help => draw_help(frame, area),
        Mode::Form => {
            if let Some(form) = &app.form {
                overlays::draw_form(frame, form, area);
            }
        }
        Mode::Confirm => {
            if let Some(form) = &app.form {
                overlays::draw_form(frame, form, area);
            }
            if let Some(confirm) = &app.confirm {
                overlays::draw_confirm(frame, confirm, area);
            }
        }
        Mode::TagEdit => {
            if let Some(dialog) = &app.tag_dialog {
                overlays::draw_tag_dialog(frame, dialog, area);
            }
        }
        Mode::TagFilter => {
            if let Some(filter) = &app.tag_filter {
                overlays::draw_tag_filter(frame, filter, area);
            }
        }
        Mode::Secret => {
            if let Some(dialog) = &app.secret_dialog {
                overlays::draw_secret_dialog(frame, dialog, app.secret_backend_label(), area);
            }
        }
    }
}

/// Block with a rounded border and title.
pub(super) fn panel(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title(Span::styled(format!(" {title} "), theme::accent()))
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let archive = if app.show_archived {
        " · 📦 archived shown"
    } else {
        ""
    };
    let info = format!(
        "{}/{} hosts · Sort: {}{archive} ",
        app.rows.len(),
        app.hosts.len(),
        app.sort.label()
    );
    let [title_area, search_area, info_area] = Layout::horizontal([
        Constraint::Length(12),
        Constraint::Min(8),
        // `width()` from `UnicodeWidthStr` counts terminal columns, not bytes.
        Constraint::Length(u16::try_from(info.width()).unwrap_or(u16::MAX)),
    ])
    .areas(inner);

    frame.render_widget(
        Paragraph::new(Span::styled(" sshire 🏡", theme::accent())),
        title_area,
    );

    let search = if app.mode == Mode::Search {
        Line::from(vec![
            Span::styled("/ ", theme::accent()),
            Span::styled(app.query.as_str(), theme::text()),
            Span::styled("▏", theme::accent()),
        ])
    } else if app.query.is_empty() {
        Line::from(Span::styled("/ to search · #tag to filter", theme::dim()))
    } else {
        Line::from(vec![
            Span::styled("/ ", theme::dim()),
            Span::styled(app.query.as_str(), theme::text()),
        ])
    };
    frame.render_widget(Paragraph::new(search), search_area);
    frame.render_widget(
        Paragraph::new(Span::styled(info, theme::dim())).alignment(Alignment::Right),
        info_area,
    );
}

fn draw_list(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = panel("Hosts");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.page_size = usize::from(inner.height);

    if app.hosts.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from("No hosts yet."),
            Line::from(Span::styled(
                "Hosts from ~/.ssh/config appear here automatically.",
                theme::dim(),
            )),
            Line::from(Span::styled("Press a to add a new host.", theme::dim())),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .alignment(Alignment::Center)
                .style(theme::text()),
            inner,
        );
        return;
    }
    if app.rows.is_empty() {
        let text = vec![
            Line::from(""),
            Line::from(format!("No matches for \"{}\".", app.query)),
            Line::from(Span::styled("Esc clears the search.", theme::dim())),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .alignment(Alignment::Center)
                .style(theme::text()),
            inner,
        );
        return;
    }

    // Borrow checker: `items` below borrows text from `app` for as long as it
    // lives. Requesting `&mut app.list_state` at the same time wouldn't work.
    // So take the scroll state out beforehand (`mem::take` leaves a default
    // behind) and put it back after drawing.
    let mut state = std::mem::take(&mut app.list_state);
    state.select(Some(app.selected));
    let now = now_ms();
    // One column belongs to the selection bar ("▌").
    let width = usize::from(inner.width).saturating_sub(1);
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|row| ListItem::new(host_line(app, row, width, now)))
        .collect();
    let list = List::new(items)
        .highlight_symbol("▌")
        .highlight_style(Style::default().bg(theme::selection_bg()));
    // `render_stateful_widget` reads and modifies the scroll state.
    frame.render_stateful_widget(list, inner, &mut state);
    // `list` (and with it the borrow of `app`) is consumed: writing back works.
    app.list_state = state;
}

/// Builds a list row: `★ 🚀 alias  user@host:22  #tag #tag     3 days ago`.
fn host_line<'a>(app: &'a App, row: &'a Row, width: usize, now: i64) -> Line<'a> {
    let host: &'a Host = &app.hosts[row.host_index];

    let last = app
        .stats_for(host.id)
        .and_then(|s| s.last_success_at)
        .map_or_else(|| "never".to_owned(), |ts| timefmt::relative_time(ts, now));
    let last_width = last.width();
    // Room to the left of the timestamp (one column of spacing).
    let budget = width.saturating_sub(last_width + 1);

    // Archived hosts: 📦 instead of the star, everything dimmed.
    let star = if host.archived {
        Span::raw("📦")
    } else if host.favorite {
        Span::styled("★ ", Style::default().fg(theme::warning()))
    } else {
        Span::raw("  ")
    };
    let alias_style = if host.archived {
        theme::dim()
    } else {
        theme::bold()
    };
    let mut spans = vec![star, icon_span(host, &app.icon_fallback)];
    // Alias: search matches highlighted, length limited.
    let used_before = 4;
    // 🔑 (space + 2 columns) marks hosts with a stored password.
    let key_width = if host.has_password { 3 } else { 0 };
    let alias_room = budget.saturating_sub(used_before + key_width).max(1);
    if host.alias.width() <= alias_room {
        spans.extend(highlight_spans(
            &host.alias,
            &row.alias_matches,
            alias_style,
            theme::highlight(),
        ));
    } else {
        spans.push(Span::styled(truncate(&host.alias, alias_room), alias_style));
    }

    if host.has_password {
        spans.push(Span::raw(" 🔑"));
    }

    let mut used: usize = spans.iter().map(Span::width).sum();
    // Target (user@host:port), only if at least a few characters fit.
    let room = budget.saturating_sub(used + 2);
    if room >= 6 {
        let target = truncate(&target_label(host), room);
        used += 2 + target.width();
        spans.push(Span::raw("  "));
        spans.push(Span::styled(target, theme::dim()));
    }
    // Tag chips, as long as they still fit.
    for tag in &host.tags {
        let chip = format!(" #{} ", tag.name);
        if used + 1 + chip.width() > budget {
            break;
        }
        used += 1 + chip.width();
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            chip,
            theme::chip(&tag.name, tag.color.as_deref()),
        ));
    }
    spans.push(Span::raw(
        " ".repeat(width.saturating_sub(used + last_width)),
    ));
    spans.push(Span::styled(last, theme::dim()));
    Line::from(spans)
}

/// The host's icon, padded to a width of two columns (emojis are mostly 2 wide).
fn icon_span(host: &Host, fallback: &str) -> Span<'static> {
    let icon = host
        .icon
        .as_deref()
        .map(str::trim)
        .filter(|i| !i.is_empty())
        .unwrap_or(fallback);
    let pad = 3_usize.saturating_sub(icon.width());
    let style = if host.archived {
        theme::dim()
    } else {
        theme::text()
    };
    Span::styled(format!("{icon}{}", " ".repeat(pad)), style)
}

/// Splits `text` into spans; characters at the positions in `matches` get `hl`.
///
/// The return value borrows slices of `text` (`&'a str`), so it doesn't copy:
/// `Span<'a>` must not outlive `text`.
fn highlight_spans<'a>(text: &'a str, matches: &[u32], base: Style, hl: Style) -> Vec<Span<'a>> {
    if matches.is_empty() {
        return vec![Span::styled(text, base)];
    }
    let mut spans = Vec::new();
    let mut run_start = 0; // byte position where the current run begins
    let mut run_hl = false;
    // `char_indices` yields (byte position, character); `enumerate` counts the
    // characters; nucleo reports matches as character positions, not byte positions.
    for (char_pos, (byte_pos, _)) in text.char_indices().enumerate() {
        let is_hl = u32::try_from(char_pos).is_ok_and(|p| matches.contains(&p));
        if is_hl != run_hl && byte_pos > run_start {
            spans.push(Span::styled(
                &text[run_start..byte_pos],
                if run_hl { hl } else { base },
            ));
            run_start = byte_pos;
        }
        run_hl = is_hl;
    }
    spans.push(Span::styled(
        &text[run_start..],
        if run_hl { hl } else { base },
    ));
    spans
}

/// Shortens `text` to at most `max` terminal columns and appends "…".
pub(super) fn truncate(text: &str, max: usize) -> String {
    if text.width() <= max {
        return text.to_owned();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w + 1 > max {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let block = panel("Details");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(host) = app.selected_host() else {
        frame.render_widget(
            Paragraph::new(Span::styled("No host selected.", theme::dim()))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    };
    let lines = detail_lines(app, host, now_ms());
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// A "name: value" line with a dimmed name.
fn field<'a>(name: &'a str, value: impl Into<Span<'a>>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{name:<13}"), theme::dim()),
        value.into(),
    ])
}

fn detail_lines<'a>(app: &'a App, host: &'a Host, now: i64) -> Vec<Line<'a>> {
    let mut lines: Vec<Line> = Vec::new();

    let mut title = vec![icon_span(host, &app.icon_fallback)];
    title.push(Span::styled(host.alias.as_str(), theme::bold()));
    if host.favorite {
        title.push(Span::styled(" ★", Style::default().fg(theme::warning())));
    }
    lines.push(Line::from(title));
    lines.push(Line::from(""));

    lines.push(field(
        "Target",
        Span::styled(target_label(host), theme::text()),
    ));
    let source = match host.source {
        HostSource::SshConfig => "ssh_config",
        HostSource::Manual => "manual",
    };
    lines.push(field("Source", Span::styled(source, theme::text())));
    if host.archived {
        lines.push(field("Status", Span::styled("📦 archived", theme::dim())));
    }
    lines.push(field(
        "Auth",
        Span::styled(host.auth_method.as_str(), theme::text()),
    ));
    if host.has_password {
        // Only the flag from the database; the password itself is never loaded.
        lines.push(field(
            "",
            Span::styled(
                format!("🔑 Password stored ({})", app.secret_backend_label()),
                theme::text(),
            ),
        ));
    }
    if let Some(jump) = host.proxy_jump.as_deref() {
        lines.push(field("ProxyJump", Span::styled(jump, theme::text())));
    }
    if let Some(identity) = host.identity_file.as_deref() {
        lines.push(field("IdentityFile", Span::styled(identity, theme::text())));
    }
    if !host.tags.is_empty() {
        let mut chips = vec![Span::styled(format!("{:<13}", "Tags"), theme::dim())];
        for tag in &host.tags {
            chips.push(Span::styled(
                format!(" #{} ", tag.name),
                theme::chip(&tag.name, tag.color.as_deref()),
            ));
            chips.push(Span::raw(" "));
        }
        lines.push(Line::from(chips));
    }
    if let Some(notes) = host.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        lines.push(field("Notes", Span::styled(notes, theme::text())));
    }

    lines.push(Line::from(""));
    let stats = app.stats_for(host.id);
    lines.push(connection_line(
        "✔ Last success",
        stats.and_then(|s| s.last_success_at),
        now,
        theme::success(),
    ));
    lines.push(connection_line(
        "✘ Last failure",
        stats.and_then(|s| s.last_failure_at),
        now,
        theme::error(),
    ));
    lines.push(field(
        "Connections",
        Span::styled(
            stats.map_or(0, |s| s.total_connections).to_string(),
            theme::text(),
        ),
    ));

    // History and chart only if the details belong to the selected host.
    if let Some(detail) = app.detail.as_ref().filter(|d| d.host_id == host.id) {
        if !detail.history.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Recent connections",
                theme::accent(),
            )));
            for conn in &detail.history {
                let (symbol, color) = match conn.status {
                    Some(ConnectionStatus::Success) => ("✔", theme::success()),
                    Some(ConnectionStatus::Failed) => ("✘", theme::error()),
                    None => ("…", theme::warning()),
                };
                let duration = conn
                    .duration_ms
                    .map_or_else(|| "-".to_owned(), timefmt::format_duration);
                lines.push(Line::from(vec![
                    Span::styled(format!("{symbol} "), Style::default().fg(color)),
                    Span::styled(timefmt::format_local(conn.started_at), theme::text()),
                    Span::styled(format!("  {duration}"), theme::dim()),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<13}", format!("{SPARK_DAYS} days")),
                theme::dim(),
            ),
            Span::styled(
                sparkline(&detail.per_day),
                Style::default().fg(theme::accent_color()),
            ),
        ]));
    }
    lines
}

/// Line "✔ Last success: 2026-10-01 14:30 (3 days ago)".
fn connection_line(
    label: &str,
    ts: Option<i64>,
    now: i64,
    color: ratatui::style::Color,
) -> Line<'static> {
    let value = ts.map_or_else(
        || "never".to_owned(),
        |ts| {
            format!(
                "{} ({})",
                timefmt::format_local(ts),
                timefmt::relative_time(ts, now)
            )
        },
    );
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(color)),
        Span::styled(value, theme::text()),
    ])
}

/// Bars made of block characters; the highest number gets the tallest bar.
fn sparkline(values: &[u32]) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = values.iter().copied().max().unwrap_or(0);
    values
        .iter()
        .map(|&v| {
            if v == 0 {
                '·'
            } else {
                // Scales 1..=max to index 0..=7 (purely integer, no floats).
                let level = (v as usize * (BARS.len() - 1)) / max as usize;
                BARS[level]
            }
        })
        .collect()
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let line = if let Some(status) = &app.status {
        let color = match status.kind {
            StatusKind::Info => theme::accent_color(),
            StatusKind::Success => theme::success(),
            StatusKind::Error => theme::error(),
            StatusKind::Warning => theme::warning(),
        };
        Line::from(Span::styled(
            format!(" {}", status.text),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ))
    } else {
        let hints: &[(&str, &str)] = match app.mode {
            Mode::Search => &[
                ("Type", "filter"),
                ("#tag", "tag filter"),
                ("⏎", "accept"),
                ("Esc", "cancel"),
            ],
            Mode::Form => &[("Tab", "next field"), ("Ctrl-S", "save"), ("Esc", "cancel")],
            Mode::Confirm => &[("y", "confirm"), ("any other key", "cancel")],
            Mode::TagEdit => &[("Tab", "complete"), ("⏎", "save"), ("Esc", "cancel")],
            Mode::TagFilter => &[("↑↓", "select"), ("⏎", "filter"), ("Esc", "close")],
            Mode::Secret => &[("⏎", "next"), ("Esc", "cancel")],
            Mode::Normal | Mode::Help => &[
                ("↑↓/jk", "select"),
                ("⏎", "connect"),
                ("/", "search"),
                ("a", "new"),
                ("e", "edit"),
                ("t", "tags"),
                ("p", "password"),
                ("d", "delete"),
                ("x", "archive"),
                ("f", "favorite"),
                ("?", "help"),
                ("q", "quit"),
            ],
        };
        let mut spans = vec![Span::raw(" ")];
        for (key, what) in hints {
            spans.push(Span::styled(*key, theme::accent()));
            spans.push(Span::styled(format!(" {what}  "), theme::dim()));
        }
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// All keys of the help as (key, description).
///
/// A module-level `const` so a test can check that every key bound in
/// `event.rs` appears here. In the key column, `" / "` separates
/// alternatives, and spaces separate the keys within one alternative.
pub(super) const HELP: &[(&str, &str)] = &[
    ("↑ ↓ / j k", "move selection"),
    ("PgUp / PgDn", "scroll page by page"),
    ("g / Home", "jump to the start"),
    ("G / End", "jump to the end"),
    ("Enter", "connect to the host"),
    ("F", "open an SFTP session"),
    ("m", "mount with sshfs / unmount again"),
    ("/", "search (fuzzy; #tag filters by tag)"),
    ("Esc", "clear / close the search"),
    ("f", "toggle favorite"),
    ("s", "Sort: name → recent → frequent"),
    ("a", "add a new manual host"),
    ("e", "edit host (ssh_config: only icon/tags/notes)"),
    ("t", "edit the host's tags (comma-separated)"),
    ("T", "filter by tag (list of all tags)"),
    ("p", "set / change / remove password (empty = remove)"),
    ("d", "delete manual host (asks first)"),
    ("x", "archive / restore"),
    ("A", "show / hide archived hosts"),
    ("", "In the form: Tab/↑↓ field · Ctrl-S save · Esc back"),
    ("", "Icon field: Enter or Ctrl-E opens the symbol picker"),
    ("", "🔑 after the alias: password stored"),
    ("?", "this help"),
    ("q / Ctrl-C", "quit"),
    ("", ""),
    ("", "Any key closes the help."),
];

/// Help overlay: `Clear` wipes the area beneath, then the popup is drawn.
fn draw_help(frame: &mut Frame, area: Rect) {
    let lines: Vec<Line> = HELP
        .iter()
        .map(|(key, what)| {
            Line::from(vec![
                Span::styled(format!(" {key:<13}"), theme::accent()),
                Span::styled(*what, theme::text()),
            ])
        })
        .collect();
    let popup = centered(area, 76, u16::try_from(lines.len() + 2).unwrap_or(14));
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("Help").border_style(theme::accent()))
            .style(Style::default().bg(theme::base())),
        popup,
    );
}

/// A rectangle of size `width` × `height` in the middle of `area` (clamped at the edges).
pub(super) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::store::{NewHost, Store};
    use crate::tui::app::Action;

    fn app_with_hosts() -> App {
        let mut store = Store::open_in_memory().unwrap();
        let mut host = NewHost::new("webserver");
        host.hostname = Some("web.example.invalid".into());
        host.user = Some("admin".into());
        host.icon = Some("🚀".into());
        let id = store.insert_host(&host).unwrap();
        store.set_host_tags(id, &["prod"]).unwrap();
        store.insert_host(&NewHost::new("db")).unwrap();
        App::new(store, &[]).unwrap()
    }

    /// Renders into a test buffer and returns its text line by line.
    fn render(app: &mut App, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_title_hosts_and_details() {
        let mut app = app_with_hosts();
        let out = render(&mut app, 120, 30);
        assert!(out.contains("sshire"));
        assert!(out.contains("webserver"));
        assert!(out.contains("#prod"));
        assert!(out.contains("admin@web.example.invalid"));
        assert!(out.contains("Last success"));
        assert!(out.contains("2/2 hosts"));
    }

    #[test]
    fn password_hosts_get_a_key_marker() {
        let mut app = app_with_hosts();
        assert!(!render(&mut app, 120, 30).contains('🔑'));
        let id = app.hosts[0].id;
        app.store().set_has_password(id, true).unwrap();
        app.reload().unwrap();
        assert!(render(&mut app, 120, 30).contains('🔑'));
    }

    #[test]
    fn narrow_terminal_stacks_panels() {
        let mut app = app_with_hosts();
        let out = render(&mut app, 80, 30);
        assert!(out.contains("webserver"));
        assert!(out.contains("Details"));
    }

    #[test]
    fn empty_states_are_friendly() {
        let mut app = App::new(Store::open_in_memory().unwrap(), &[]).unwrap();
        assert!(render(&mut app, 100, 20).contains("No hosts yet"));
        let mut app = app_with_hosts();
        app.update(Action::OpenSearch);
        for c in "zzzq".chars() {
            app.update(Action::SearchChar(c));
        }
        assert!(render(&mut app, 100, 20).contains("No matches"));
    }

    #[test]
    fn help_overlay_and_status_render() {
        let mut app = app_with_hosts();
        app.update(Action::OpenHelp);
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Help"));
        assert!(out.contains("toggle favorite"));
        app.update(Action::CloseHelp);
        app.update(Action::ToggleFavorite);
        assert!(render(&mut app, 100, 30).contains("favorite"));
    }

    /// All key alternatives of the help (e.g. `["↑", "↓", "j", "k"]`).
    fn help_tokens() -> Vec<String> {
        HELP.iter()
            .flat_map(|(keys, _)| keys.split(" / "))
            .flat_map(str::split_whitespace)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn help_lists_every_key_bound_in_normal_mode() {
        use crate::tui::app::Mode;
        use crate::tui::event::key_to_action;

        let help = help_tokens();
        // Try all printable ASCII characters plus the special keys.
        let mut candidates: Vec<(KeyCode, String)> = (0x20_u8..0x7f)
            .map(|b| (KeyCode::Char(char::from(b)), char::from(b).to_string()))
            .collect();
        candidates.extend([
            (KeyCode::Up, "↑".to_owned()),
            (KeyCode::Down, "↓".to_owned()),
            (KeyCode::PageUp, "PgUp".to_owned()),
            (KeyCode::PageDown, "PgDn".to_owned()),
            (KeyCode::Home, "Home".to_owned()),
            (KeyCode::End, "End".to_owned()),
            (KeyCode::Enter, "Enter".to_owned()),
            (KeyCode::Esc, "Esc".to_owned()),
        ]);
        let mut checked = 0;
        for (code, label) in candidates {
            let event = KeyEvent::new(code, KeyModifiers::NONE);
            // Esc only works with an active filter; there it is bound.
            let bound = key_to_action(Mode::Normal, true, event).is_some();
            if bound {
                checked += 1;
                assert!(
                    help.contains(&label),
                    "Key \"{label}\" is bound but missing from the help"
                );
            }
        }
        // Sanity check: the test really checked something.
        assert!(checked >= 20, "only {checked} keys checked");
        // Ctrl-C is in the help as well.
        assert!(help.contains(&"Ctrl-C".to_owned()));
    }

    #[test]
    fn highlight_splits_runs() {
        let spans = highlight_spans("abcd", &[1, 2], theme::text(), theme::highlight());
        let parts: Vec<_> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(parts, ["a", "bc", "d"]);
        let all = highlight_spans("äö", &[0, 1], theme::text(), theme::highlight());
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn truncate_respects_width() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
        assert!(truncate("🚀🚀🚀", 4).width() <= 4);
    }

    #[test]
    fn sparkline_scales() {
        assert_eq!(sparkline(&[0, 1, 8]), "·▁█");
    }

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn press(app: &mut App, code: KeyCode) {
        let key = KeyEvent::new(code, KeyModifiers::NONE);
        if let Some(action) = crate::tui::event::key_to_action(app.mode, false, key) {
            app.update(action);
        }
    }

    fn type_str(app: &mut App, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    #[test]
    fn form_renders_all_fields_and_hints() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('a'));
        let out = render(&mut app, 100, 30);
        assert!(out.contains("New host"));
        for label in [
            "Alias",
            "Hostname",
            "User",
            "Port",
            "IdentityFile",
            "ProxyJump",
            "Extra-Args",
            "Auth",
            "Icon",
            "Tags",
            "Notes",
        ] {
            assert!(out.contains(label), "{label} missing");
        }
        assert!(out.contains("Ctrl-S"));
        assert!(out.contains("agent"));
    }

    #[test]
    fn form_shows_field_error_and_typed_text() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('a'));
        type_str(&mut app, "bad alias");
        let key = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        app.update(crate::tui::app::Action::Key(key));
        let out = render(&mut app, 100, 34);
        assert!(out.contains("bad alias"));
        assert!(out.contains("spaces"));
    }

    #[test]
    fn form_shows_duplicate_alias_and_password_hint() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('a'));
        type_str(&mut app, "db");
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        app.update(crate::tui::app::Action::Key(ctrl_s));
        assert!(render(&mut app, 110, 34).contains("already taken"));
        // Set auth to "password": hint about `p`, no password field in the form.
        while app.form.as_ref().unwrap().focus != crate::validate::Field::Auth {
            press(&mut app, KeyCode::Tab);
        }
        press(&mut app, KeyCode::Right);
        press(&mut app, KeyCode::Right);
        let out = render(&mut app, 110, 34);
        assert!(out.contains("Set the password with p in the list"));
        assert!(!out.contains("Password:"));
    }

    #[test]
    fn ssh_config_form_marks_readonly_fields() {
        let mut app = app_with_hosts();
        let host = crate::store::SshConfigHost {
            alias: "cfg".into(),
            hostname: Some("cfg.example.invalid".into()),
            ..Default::default()
        };
        app.store().upsert_ssh_config_host(&host).unwrap();
        app.reload().unwrap();
        app.update(Action::Down);
        app.update(Action::Down);
        assert_eq!(app.selected_host().unwrap().alias, "webserver");
        app.update(Action::Up);
        app.update(Action::Up);
        assert_eq!(app.selected_host().unwrap().alias, "cfg");
        press(&mut app, KeyCode::Char('e'));
        let out = render(&mut app, 110, 30);
        assert!(out.contains("Edit host: cfg"));
        assert!(out.contains("only icon, tags and notes"));
        assert!(out.contains("cfg.example.invalid"));
    }

    #[test]
    fn icon_picker_renders_grid_and_filters() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('a'));
        while app.form.as_ref().unwrap().focus != crate::validate::Field::Icon {
            press(&mut app, KeyCode::Tab);
        }
        press(&mut app, KeyCode::Enter);
        let out = render(&mut app, 100, 40);
        assert!(out.contains("Pick icon"));
        assert!(out.contains("🐳") && out.contains("🚀") && out.contains("🍓"));
        assert!(out.contains("server computer"));
        type_str(&mut app, "raspberry");
        let out = render(&mut app, 100, 40);
        assert!(out.contains("🍓"));
        assert!(!out.contains("🐳"));
        assert!(out.contains("Device"));
        type_str(&mut app, "zzz");
        assert!(render(&mut app, 100, 40).contains("No matches"));
    }

    #[test]
    fn confirm_dialog_renders_for_delete_and_discard() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('d'));
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Really delete"));
        assert!(out.contains("any other key"));
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('a'));
        type_str(&mut app, "x");
        press(&mut app, KeyCode::Esc);
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Discard unsaved changes"));
        // The form stays visible behind it.
        assert!(out.contains("New host"));
    }

    #[test]
    fn tag_dialog_and_tag_filter_render() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('T'));
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Filter by tag"));
        assert!(out.contains("#prod"));
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('t'));
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Tags for \"db\""));
        assert!(out.contains("comma-separated"));
    }

    #[test]
    fn archived_hosts_are_marked_and_new_keys_are_in_help() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('x'));
        press(&mut app, KeyCode::Char('A'));
        // "db" comes first alphabetically and is now visible as archived.
        app.update(Action::First);
        let out = render(&mut app, 120, 30);
        assert!(out.contains("📦"));
        assert!(out.contains("archived shown"));
        assert!(out.contains("archived"));
        app.update(Action::OpenHelp);
        let out = render(&mut app, 120, 34);
        for text in [
            "add a new manual host",
            "edit host",
            "edit the host's tags",
            "filter by tag",
            "delete manual host",
            "show / hide archived hosts",
        ] {
            assert!(out.contains(text), "{text}");
        }
    }

    #[test]
    fn centered_stays_inside() {
        let r = centered(Rect::new(0, 0, 20, 10), 100, 100);
        assert_eq!((r.width, r.height), (20, 10));
    }

    #[test]
    fn password_dialog_shows_only_dots_never_the_text() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('p'));
        type_str(&mut app, "hunter2xyz");
        let out = render(&mut app, 100, 30);
        assert!(out.contains("Password for \"db\"") || out.contains("Password for"));
        assert!(out.contains("••••••••••"));
        assert!(!out.contains("hunter2xyz"));
        assert!(!out.contains("hunter"));
    }

    #[test]
    fn detail_panel_shows_password_marker_and_help_lists_p() {
        let mut app = app_with_hosts();
        press(&mut app, KeyCode::Char('p'));
        type_str(&mut app, "pw");
        press(&mut app, KeyCode::Enter);
        type_str(&mut app, "pw");
        press(&mut app, KeyCode::Enter);
        let out = render(&mut app, 120, 40);
        // (The test buffer inserts a space after wide characters like 🔑.)
        assert!(out.contains("Password stored (Keychain)"));
        press(&mut app, KeyCode::Char('?'));
        let help = render(&mut app, 120, 40);
        assert!(help.contains("set / change / remove password"));
    }
}
