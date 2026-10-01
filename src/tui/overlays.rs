//! Rendering of the overlays: host form, icon picker, confirmation prompts,
//! tag dialog and tag filter selection.
//!
//! As in `ui.rs`: the functions *read* the state (`&FormState` etc.) and only
//! draw. Each overlay clears the area beneath it with `Clear` and then draws
//! a popup in the center of the screen.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph};
use unicode_width::UnicodeWidthStr;

use super::app::{Confirm, TagDialog, TagFilter};
use super::emoji::{IconPicker, PICKER_COLUMNS};
use super::form::FormState;
use super::input::TextInput;
use super::secret::{SecretDialog, Step};
use super::theme;
use super::ui::{centered, panel, truncate};
use crate::store::AuthMethod;
use crate::validate::Field;

/// Width of the label column in the form.
const LABEL_WIDTH: usize = 14;
/// Width of a grid cell in the picker (space, symbol in 2 columns, space).
const CELL_WIDTH: usize = 4;

/// Draws a popup with a border and returns the inner area.
fn popup(frame: &mut Frame, area: Rect, title: &str, width: u16, height: u16) -> Rect {
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    let block = panel(title)
        .border_style(theme::accent())
        .style(Style::default().bg(theme::base()));
    let inner = ratatui::widgets::Block::inner(&block, rect);
    frame.render_widget(block, rect);
    inner
}

/// Pads text with spaces to `width` columns (for field backgrounds).
fn pad_to(text: &str, width: usize) -> String {
    let missing = width.saturating_sub(text.width());
    format!("{text}{}", " ".repeat(missing))
}

/// The display of a text field: text with a background and, when focused,
/// the cursor column. Returns the span and (if focused) the cursor column.
fn field_value(
    input: &TextInput,
    width: usize,
    focused: bool,
    readonly: bool,
) -> (Span<'static>, Option<usize>) {
    if focused {
        let (text, col) = input.window(width);
        let style = Style::default()
            .fg(theme::text_color())
            .bg(theme::selection_bg());
        (Span::styled(pad_to(&text, width), style), Some(col))
    } else if readonly {
        (
            Span::styled(truncate(input.value(), width), theme::dim()),
            None,
        )
    } else {
        (
            Span::styled(truncate(input.value(), width), theme::text()),
            None,
        )
    }
}

/// The host form together with the icon picker (if open).
pub fn draw_form(frame: &mut Frame, form: &FormState, area: Rect) {
    let width = 78.min(area.width);
    // Room for the label, marker ("▸ ") and border.
    let value_width = usize::from(width).saturating_sub(LABEL_WIDTH + 4).max(4);

    let mut lines: Vec<Line> = Vec::new();
    let mut cursor: Option<(usize, usize)> = None; // (line, column in the popup)
    for field in Field::ALL {
        let focused = form.focus == field;
        let readonly = form.is_readonly(field);
        let marker = if focused { "▸ " } else { "  " };
        let label_style = if focused {
            theme::accent()
        } else if readonly {
            theme::dim()
        } else {
            theme::text()
        };
        let mut spans = vec![
            Span::styled(marker, theme::accent()),
            Span::styled(
                format!("{:<width$}", field.label(), width = LABEL_WIDTH),
                label_style,
            ),
        ];
        if field == Field::Auth {
            spans.push(auth_span(form.auth, focused, readonly));
        } else if let Some(input) = form.input(field) {
            let (span, col) = field_value(input, value_width, focused, readonly);
            if let Some(col) = col {
                cursor = Some((lines.len(), 2 + LABEL_WIDTH + col));
            }
            spans.push(span);
        }
        lines.push(Line::from(spans));
        if let Some(message) = form.error_for(field) {
            lines.push(Line::from(Span::styled(
                format!("{}↳ {message}", " ".repeat(2 + LABEL_WIDTH)),
                Style::default().fg(theme::error()),
            )));
        }
    }

    lines.push(Line::from(""));
    if let Some(hint) = form.auth_hint() {
        lines.push(Line::from(Span::styled(
            format!("  ⓘ {hint}"),
            Style::default().fg(theme::warning()),
        )));
    }
    if form.is_ssh_config() {
        lines.push(Line::from(Span::styled(
            "  🔒 From ~/.ssh/config – only icon, tags and notes are editable",
            theme::dim(),
        )));
    }
    lines.push(Line::from(vec![
        Span::styled("  Tab/↑↓", theme::accent()),
        Span::styled(" field  ", theme::dim()),
        Span::styled("Ctrl-S", theme::accent()),
        Span::styled(" save  ", theme::dim()),
        Span::styled("Esc", theme::accent()),
        Span::styled(" cancel  ", theme::dim()),
        Span::styled("Ctrl-E", theme::accent()),
        Span::styled(" pick icon", theme::dim()),
    ]));

    let height = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let inner = popup(frame, area, &form.title(), width, height);
    frame.render_widget(Paragraph::new(lines), inner);

    if let Some(picker) = &form.picker {
        draw_picker(frame, picker, area);
    } else if let Some((line, col)) = cursor {
        // Set the real terminal cursor (it blinks and shows the insertion point).
        let x = inner.x + u16::try_from(col).unwrap_or(0);
        let y = inner.y + u16::try_from(line).unwrap_or(0);
        if x < inner.right() && y < inner.bottom() {
            frame.set_cursor_position((x, y));
        }
    }
}

/// `◂ agent ▸` selector for the auth method.
fn auth_span(auth: AuthMethod, focused: bool, readonly: bool) -> Span<'static> {
    let style = if readonly {
        theme::dim()
    } else if focused {
        Style::default()
            .fg(theme::text_color())
            .bg(theme::selection_bg())
            .add_modifier(Modifier::BOLD)
    } else {
        theme::text()
    };
    let text = if readonly || !focused {
        auth.as_str().to_owned()
    } else {
        format!("◂ {} ▸", auth.as_str())
    };
    Span::styled(text, style)
}

/// The picker's symbol grid.
fn draw_picker(frame: &mut Frame, picker: &IconPicker, area: Rect) {
    let entries = picker.visible();
    let rows = entries.len().div_ceil(PICKER_COLUMNS).max(1);
    let width = u16::try_from(PICKER_COLUMNS * CELL_WIDTH + 4).unwrap_or(44);
    // Search, blank line, grid, blank line, detail, hint.
    let height = u16::try_from(rows + 6 + 2).unwrap_or(u16::MAX);
    let inner = popup(frame, area, "Pick icon", width, height);

    let search_width = usize::from(inner.width).saturating_sub(9).max(2);
    let (text, col) = picker.query.window(search_width);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(" Search: ", theme::dim()),
            Span::styled(text, theme::text()),
        ]),
        Line::from(""),
    ];
    if entries.is_empty() {
        lines.push(Line::from(Span::styled(
            " No matches – change the search text",
            theme::dim(),
        )));
    }
    for (row_index, chunk) in entries.chunks(PICKER_COLUMNS).enumerate() {
        let spans: Vec<Span> = chunk
            .iter()
            .enumerate()
            .map(|(col_index, entry)| {
                let index = row_index * PICKER_COLUMNS + col_index;
                let pad = 2usize.saturating_sub(entry.symbol.width());
                let cell = format!(" {}{} ", entry.symbol, " ".repeat(pad));
                let style = if index == picker.selected {
                    Style::default().fg(theme::base()).bg(theme::accent_color())
                } else {
                    theme::text()
                };
                Span::styled(cell, style)
            })
            .collect();
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(match picker.current() {
        Some(entry) => Line::from(vec![
            Span::styled(format!(" {} ", entry.symbol), theme::text()),
            Span::styled(entry.keywords, theme::text()),
            Span::styled(format!(" · {}", entry.category), theme::dim()),
        ]),
        None => Line::from(""),
    });
    lines.push(Line::from(vec![
        Span::styled(" ←↑↓→", theme::accent()),
        Span::styled(" select  ", theme::dim()),
        Span::styled("⏎", theme::accent()),
        Span::styled(" accept  ", theme::dim()),
        Span::styled("Esc", theme::accent()),
        Span::styled(" back", theme::dim()),
    ]));
    frame.render_widget(Paragraph::new(lines), inner);
    let x = inner.x + 8 + u16::try_from(col).unwrap_or(0);
    if x < inner.right() {
        frame.set_cursor_position((x, inner.y));
    }
}

/// Yes/no confirmation prompt.
pub fn draw_confirm(frame: &mut Frame, confirm: &Confirm, area: Rect) {
    let (title, question, detail) = match confirm {
        Confirm::DeleteHost { alias, .. } => (
            "Delete host",
            format!("Really delete host \"{alias}\"?"),
            "Tags, connection log and any stored password will be lost.",
        ),
        Confirm::DiscardForm => (
            "Discard changes",
            "Discard unsaved changes?".to_owned(),
            "The form will be closed.",
        ),
    };
    let lines = vec![
        Line::from(Span::styled(format!(" {question}"), theme::bold())),
        Line::from(Span::styled(format!(" {detail}"), theme::dim())),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " y",
                Style::default()
                    .fg(theme::error())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" yes  ·  any other key: cancel", theme::dim()),
        ]),
    ];
    let inner = popup(frame, area, title, 58, 6);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Quick tag dialog.
pub fn draw_tag_dialog(frame: &mut Frame, dialog: &TagDialog, area: Rect) {
    let width = 64.min(area.width);
    let value_width = usize::from(width).saturating_sub(6).max(4);
    let (input_span, col) = field_value(&dialog.input, value_width, true, false);
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" Tags for \"{}\" (comma-separated)", dialog.alias),
            theme::text(),
        )),
        Line::from(vec![Span::raw(" "), input_span]),
    ];
    lines.push(match &dialog.error {
        Some(message) => Line::from(Span::styled(
            format!(" ↳ {message}"),
            Style::default().fg(theme::error()),
        )),
        None => Line::from(""),
    });
    lines.push(Line::from(vec![
        Span::styled(" Tab", theme::accent()),
        Span::styled(" complete  ", theme::dim()),
        Span::styled("⏎", theme::accent()),
        Span::styled(" save  ", theme::dim()),
        Span::styled("Esc", theme::accent()),
        Span::styled(" abbrechen", theme::dim()),
    ]));
    let inner = popup(frame, area, "Edit tags", width, 8);
    frame.render_widget(Paragraph::new(lines), inner);
    if let Some(col) = col {
        let x = inner.x + 1 + u16::try_from(col).unwrap_or(0);
        if x < inner.right() {
            frame.set_cursor_position((x, inner.y + 1));
        }
    }
}

/// Tag filter selection: list of all tags with their counts.
pub fn draw_tag_filter(frame: &mut Frame, filter: &TagFilter, area: Rect) {
    let rows = filter.entries.len().min(14);
    let height = u16::try_from(rows + 4).unwrap_or(u16::MAX);
    let inner = popup(frame, area, "Filter by tag", 40, height);
    let [list_area, hint_area] = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Min(1),
        ratatui::layout::Constraint::Length(2),
    ])
    .areas(inner);

    let items: Vec<ListItem> = filter
        .entries
        .iter()
        .map(|(name, count)| {
            Line::from(vec![
                Span::styled(format!(" #{name} "), theme::chip(name, None)),
                Span::styled(format!("  {count}"), theme::dim()),
            ])
            .into()
        })
        .collect();
    let list = List::new(items)
        .highlight_symbol("▌")
        .highlight_style(Style::default().bg(theme::selection_bg()));
    let mut state = ListState::default();
    state.select(Some(filter.selected));
    frame.render_stateful_widget(list, list_area, &mut state);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(" ⏎", theme::accent()),
                Span::styled(" filter  ", theme::dim()),
                Span::styled("Esc", theme::accent()),
                Span::styled(" close", theme::dim()),
            ]),
        ]),
        hint_area,
    );
}

/// Password dialog: masked field (only `•`), error message and hints.
///
/// Deliberately shows only the *number* of characters as dots, never the contents.
pub fn draw_secret_dialog(frame: &mut Frame, dialog: &SecretDialog, backend: &str, area: Rect) {
    let width = 66.min(area.width);
    let inner_width = usize::from(width).saturating_sub(4).max(8);
    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        format!(" Vault: {backend}"),
        theme::dim(),
    ))];

    let mut cursor: Option<(u16, u16)> = None;
    if dialog.step == Step::ConfirmRemove {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" Really remove the password for \"{}\"?", dialog.alias),
            theme::bold(),
        )));
        lines.push(Line::from(vec![
            Span::styled(
                " y",
                Style::default()
                    .fg(theme::error())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" yes  ·  any other key: cancel", theme::dim()),
        ]));
    } else {
        let label = format!(" {}: ", dialog.prompt());
        let field_width = inner_width.saturating_sub(label.width()).max(4);
        // At most as many dots as fit into the field (one column stays free for the cursor).
        let dots = dialog.input.char_count().min(field_width - 1);
        let style = Style::default()
            .fg(theme::text_color())
            .bg(theme::selection_bg());
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(label.clone(), theme::text()),
            Span::styled(pad_to(&"•".repeat(dots), field_width), style),
        ]));
        // Line 2 in the popup (index 2), column right after the dots.
        let col = label.width() + dots;
        cursor = Some((u16::try_from(col).unwrap_or(0), 2));
        if let Some(message) = &dialog.error {
            lines.push(Line::from(Span::styled(
                format!(" ↳ {message}"),
                Style::default().fg(theme::error()),
            )));
        } else {
            lines.push(Line::from(""));
        }
        if let Some(text) = dialog.explanation() {
            lines.push(Line::from(Span::styled(format!(" ⓘ {text}"), theme::dim())));
        }
        lines.push(Line::from(vec![
            Span::styled(" ⏎", theme::accent()),
            Span::styled(" next  ", theme::dim()),
            Span::styled("Esc", theme::accent()),
            Span::styled(" abbrechen", theme::dim()),
        ]));
    }

    let height = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let inner = popup(frame, area, &dialog.title(), width, height);
    // Wrap lines in case a hint text is longer than the popup.
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
        inner,
    );
    if let Some((col, line)) = cursor {
        let x = inner.x + col;
        let y = inner.y + line;
        if x < inner.right() && y < inner.bottom() {
            frame.set_cursor_position((x, y));
        }
    }
}
