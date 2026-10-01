//! Small text table for CLI output (without an extra crate).
//!
//! Column widths are computed in *display width*, not in bytes or `char`s:
//! emojis occupy two terminal columns, accented letters one.
//! The `unicode-width` crate is used for this.

use std::fmt;

use unicode_width::UnicodeWidthStr;

/// ANSI escape sequences for colors and style.
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Display width of a text in terminal columns.
pub fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

/// A table cell: text plus optional ANSI color.
#[derive(Debug, Clone)]
pub struct Cell {
    text: String,
    style: Option<&'static str>,
}

impl Cell {
    /// Cell without color.
    // `impl Into<String>` in the argument: callers may pass `&str` *or*
    // `String`; `into()` turns it into an owned `String`.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            style: None,
        }
    }

    /// Cell with ANSI style (only emitted if the table uses color).
    pub fn styled(text: impl Into<String>, style: &'static str) -> Self {
        Self {
            text: text.into(),
            style: Some(style),
        }
    }
}

/// Table with a header row; `Display` renders it to text.
#[derive(Debug)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<Cell>>,
    color: bool,
}

impl Table {
    /// New, empty table. `color` enables ANSI output.
    pub fn new(headers: &[&str], color: bool) -> Self {
        Self {
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
            color,
        }
    }

    /// Appends a row. Missing cells are treated as empty.
    pub fn push_row(&mut self, row: Vec<Cell>) {
        self.rows.push(row);
    }

    /// Width of each column = widest cell (including the header).
    fn column_widths(&self) -> Vec<usize> {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if let Some(w) = widths.get_mut(i) {
                    *w = (*w).max(display_width(&cell.text));
                }
            }
        }
        widths
    }

    /// Writes a row; the last column is not padded.
    fn write_row(
        &self,
        f: &mut fmt::Formatter<'_>,
        widths: &[usize],
        cells: &[(&str, Option<&'static str>)],
    ) -> fmt::Result {
        let last = widths.len().saturating_sub(1);
        for (i, width) in widths.iter().enumerate() {
            let (text, style) = cells.get(i).copied().unwrap_or(("", None));
            let style = if self.color { style } else { None };
            if let Some(code) = style {
                write!(f, "{code}{text}{}", ansi::RESET)?;
            } else {
                write!(f, "{text}")?;
            }
            if i != last {
                // Pad with spaces up to the column width + 2 spacing.
                // `{:pad$}` formats the empty text `""` to a width of `pad` characters.
                let pad = width.saturating_sub(display_width(text)) + 2;
                write!(f, "{:pad$}", "")?;
            }
        }
        writeln!(f)
    }
}

// `Display` makes the type usable with `{}` / `to_string()`.
impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let widths = self.column_widths();
        let header: Vec<(&str, Option<&'static str>)> = self
            .headers
            .iter()
            .map(|h| (h.as_str(), Some(ansi::DIM)))
            .collect();
        self.write_row(f, &widths, &header)?;
        for row in &self.rows {
            let cells: Vec<(&str, Option<&'static str>)> =
                row.iter().map(|c| (c.text.as_str(), c.style)).collect();
            self.write_row(f, &widths, &cells)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_counts_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("🚀"), 2);
        assert_eq!(display_width("äö"), 2);
    }

    #[test]
    fn columns_align_with_emoji() {
        let mut t = Table::new(&["Icon", "Alias"], false);
        t.push_row(vec![Cell::plain("🚀"), Cell::plain("a")]);
        t.push_row(vec![Cell::plain("x"), Cell::plain("b")]);
        let out = t.to_string();
        // Column 1 is 4 wide (header) + 2 spacing: the second column starts at
        // display position 6 in every row, no matter how wide the emoji is.
        for (line, second) in out.lines().zip(["Alias", "a", "b"]) {
            let idx = line.find(second).unwrap();
            assert_eq!(display_width(&line[..idx]), 6, "Line: {line:?}");
        }
    }

    #[test]
    fn no_ansi_without_color_and_no_trailing_padding() {
        let mut t = Table::new(&["A", "B"], false);
        t.push_row(vec![Cell::styled("x", ansi::RED), Cell::plain("y")]);
        let out = t.to_string();
        assert!(!out.contains('\x1b'));
        assert!(out.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn ansi_with_color() {
        let mut t = Table::new(&["A"], true);
        t.push_row(vec![Cell::styled("x", ansi::RED)]);
        assert!(t.to_string().contains(ansi::RED));
    }

    #[test]
    fn short_rows_do_not_panic() {
        let mut t = Table::new(&["A", "B", "C"], false);
        t.push_row(vec![Cell::plain("only")]);
        let _ = t.to_string();
    }
}
