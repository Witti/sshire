//! Single-line text input field without any terminal dependency.
//!
//! [`TextInput`] stores the text and the cursor position and understands the
//! usual editing keys. It draws nothing; rendering is done by `overlays.rs`,
//! which uses [`TextInput::window`] for the visible slice.
//!
//! # The cursor is a byte offset, but always on a grapheme boundary
//!
//! `String` indices are **byte** offsets: in `"äb"` the `b` sits at byte 2,
//! not at position 1, because `ä` takes two bytes in UTF-8. If you cut in the
//! middle of a character, Rust's slice operations panic. That is why the
//! cursor never moves byte by byte, but always from one *grapheme cluster*
//! (one visible character, see `validate.rs`) to the next. This way
//! Backspace can delete a "🖥️" (two `char`s) completely instead of tearing it apart.

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;
use zeroize::Zeroizing;

use crate::secrets::{MAX_SECRET_LEN, SecretString};

/// Text plus cursor. `#[derive(Clone, PartialEq)]` makes the state
/// cloneable and comparable, so tests can check whole fields with `assert_eq!`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TextInput {
    value: String,
    /// Byte offset of the cursor in `value` (always on a grapheme boundary).
    cursor: usize,
}

impl TextInput {
    /// Field with an initial value; the cursor sits at the end.
    pub fn with_value(value: impl Into<String>) -> Self {
        let value = value.into();
        let cursor = value.len();
        Self { value, cursor }
    }

    /// The current text.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Cursor position as a byte offset (for tests and debugging).
    #[cfg(test)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Replaces the text; the cursor jumps to the end.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.len();
    }

    /// Inserts a character at the cursor position.
    pub fn insert(&mut self, c: char) {
        // Control characters (tab, newline, …) don't belong in the field.
        if c.is_control() {
            return;
        }
        self.value.insert(self.cursor, c);
        // `len_utf8` = how many bytes this `char` occupies; the cursor advances by exactly that much.
        self.cursor += c.len_utf8();
    }

    /// Byte offset of the grapheme *before* the cursor (or 0).
    fn prev_boundary(&self) -> usize {
        self.value[..self.cursor]
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(index, _)| index)
    }

    /// Byte offset of the grapheme *after* the cursor (or the end of the text).
    fn next_boundary(&self) -> usize {
        self.cursor
            + self.value[self.cursor..]
                .graphemes(true)
                .next()
                .map_or(0, str::len)
    }

    /// Moves the cursor one character to the left.
    pub fn move_left(&mut self) {
        self.cursor = self.prev_boundary();
    }

    /// Moves the cursor one character to the right.
    pub fn move_right(&mut self) {
        self.cursor = self.next_boundary();
    }

    /// Moves the cursor to the start.
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /// Moves the cursor to the end.
    pub fn end(&mut self) {
        self.cursor = self.value.len();
    }

    /// Deletes the character to the left of the cursor.
    pub fn backspace(&mut self) {
        let start = self.prev_boundary();
        // `replace_range` replaces a byte range; here with "nothing".
        self.value.replace_range(start..self.cursor, "");
        self.cursor = start;
    }

    /// Deletes the character under the cursor.
    pub fn delete(&mut self) {
        let end = self.next_boundary();
        self.value.replace_range(self.cursor..end, "");
    }

    /// Clears the field.
    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }

    /// Evaluates an editing key. Returns `true` if the key was consumed
    /// (the caller then doesn't need to handle it any further).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('u') if ctrl => self.clear(),
            // Other Ctrl/Alt combinations are commands, not input.
            KeyCode::Char(_) if ctrl || alt => return false,
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.move_left(),
            KeyCode::Right => self.move_right(),
            KeyCode::Home => self.home(),
            KeyCode::End => self.end(),
            _ => return false,
        }
        true
    }

    /// The visible slice for a field of width `width` (terminal columns)
    /// and the cursor column within it.
    ///
    /// If the text is longer than the field, the slice scrolls so that the
    /// cursor stays visible (one column at the end is reserved for it).
    pub fn window(&self, width: usize) -> (String, usize) {
        let width = width.max(2);
        let before = &self.value[..self.cursor];
        // Cut graphemes off the front until the cursor fits into the field.
        let mut cursor_cols = before.width();
        let mut start = 0;
        if cursor_cols >= width {
            for (index, grapheme) in before.grapheme_indices(true) {
                if cursor_cols < width {
                    break;
                }
                let w = grapheme.width();
                cursor_cols -= w;
                start = index + grapheme.len();
            }
        }
        // Then take as many graphemes as fit into `width`.
        let mut out = String::new();
        let mut used = 0;
        for grapheme in self.value[start..].graphemes(true) {
            let w = grapheme.width();
            if used + w > width {
                break;
            }
            out.push_str(grapheme);
            used += w;
        }
        (out, cursor_cols)
    }
}

/// Input field for passwords: shows only dots and overwrites its contents.
///
/// Unlike [`TextInput`], the cursor cannot move; there is only appending
/// and Backspace. The buffer is allocated once at full size and never
/// grows, so typing leaves no scattered copies in memory that would not be
/// overwritten. `Zeroizing` overwrites the contents on drop.
pub struct MaskedInput {
    value: Zeroizing<String>,
}

impl Default for MaskedInput {
    fn default() -> Self {
        Self::new()
    }
}

impl MaskedInput {
    /// Empty field.
    pub fn new() -> Self {
        Self {
            value: Zeroizing::new(String::with_capacity(MAX_SECRET_LEN)),
        }
    }

    /// Number of typed characters (for the dots display).
    pub fn char_count(&self) -> usize {
        self.value.chars().count()
    }

    /// Is nothing entered?
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Appends a character; input that is too long and control characters are ignored.
    pub fn insert(&mut self, c: char) {
        if c.is_control() || self.value.len() + c.len_utf8() > MAX_SECRET_LEN {
            return;
        }
        self.value.push(c);
    }

    /// Deletes the last character.
    pub fn backspace(&mut self) {
        // `pop` removes the last `char`; the memory behind it stays in the
        // buffer, but is completely overwritten on drop.
        self.value.pop();
    }

    /// Clears the field (overwrites the previous contents).
    pub fn clear(&mut self) {
        // `Zeroizing<String>` only zeroizes on drop. So allocate a new
        // buffer and *drop* the old one (which overwrites it).
        self.value = Zeroizing::new(String::with_capacity(MAX_SECRET_LEN));
    }

    /// Takes out the contents (the field is empty afterwards).
    pub fn take(&mut self) -> SecretString {
        let fresh = Zeroizing::new(String::with_capacity(MAX_SECRET_LEN));
        let mut old = std::mem::replace(&mut self.value, fresh);
        // `Zeroizing` has a `Drop`, so you can't simply move the string out.
        // `mem::take` does move it out of `old` (leaving an empty string
        // behind) without copying. The buffer afterwards belongs to the
        // `SecretString`, which overwrites it.
        SecretString::new(std::mem::take(&mut *old))
    }

    /// Evaluates a key press (only characters, Backspace, Ctrl-U). `true` = consumed.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('u') if ctrl => self.clear(),
            KeyCode::Char(_) if ctrl || alt => return false,
            KeyCode::Char(c) => self.insert(c),
            KeyCode::Backspace => self.backspace(),
            _ => return false,
        }
        true
    }
}

impl fmt::Debug for MaskedInput {
    // Never print the contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaskedInput({} chars)", self.char_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_input_edits_and_hides_value_in_debug() {
        let mut input = MaskedInput::new();
        assert!(input.is_empty());
        for c in "pä🔑".chars() {
            input.insert(c);
        }
        assert_eq!(input.char_count(), 3);
        assert_eq!(format!("{input:?}"), "MaskedInput(3 chars)");
        input.backspace();
        assert_eq!(input.char_count(), 2);
        input.insert('\n');
        input.insert('\t');
        assert_eq!(input.char_count(), 2);
        let secret = input.take();
        assert_eq!(secret.expose(), "pä");
        assert!(input.is_empty());
    }

    #[test]
    fn masked_input_handles_keys_and_never_exceeds_capacity() {
        let mut input = MaskedInput::new();
        assert!(input.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)));
        assert!(!input.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)));
        assert!(!input.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)));
        assert!(input.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
        assert!(input.is_empty());
        for _ in 0..(MAX_SECRET_LEN + 50) {
            input.insert('x');
        }
        assert_eq!(input.char_count(), MAX_SECRET_LEN);
        // A multi-byte character that no longer fits is not inserted halfway.
        input.insert('🔑');
        assert_eq!(input.char_count(), MAX_SECRET_LEN);
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn insert_and_move_with_multibyte_text() {
        let mut input = TextInput::default();
        for c in "aäb".chars() {
            input.insert(c);
        }
        assert_eq!(input.value(), "aäb");
        // "ä" takes 2 bytes: the cursor is at byte 4 (1 + 2 + 1).
        assert_eq!(input.cursor(), 4);
        input.move_left();
        assert_eq!(input.cursor(), 3);
        input.move_left();
        assert_eq!(input.cursor(), 1);
        input.insert('X');
        assert_eq!(input.value(), "aXäb");
        input.home();
        assert_eq!(input.cursor(), 0);
        input.move_left();
        assert_eq!(input.cursor(), 0);
        input.end();
        input.move_right();
        assert_eq!(input.cursor(), input.value().len());
    }

    #[test]
    fn backspace_and_delete_remove_whole_graphemes() {
        // "🖥️" = two `char`s, one grapheme.
        let mut input = TextInput::with_value("a🖥️b");
        input.move_left();
        input.backspace();
        assert_eq!(input.value(), "ab");
        assert_eq!(input.cursor(), 1);
        input.home();
        input.delete();
        assert_eq!(input.value(), "b");
        // At the edges nothing happens (and no slices panic).
        input.home();
        input.backspace();
        input.end();
        input.delete();
        assert_eq!(input.value(), "b");
    }

    #[test]
    fn control_characters_are_not_inserted() {
        let mut input = TextInput::default();
        input.insert('\t');
        input.insert('\n');
        assert_eq!(input.value(), "");
    }

    #[test]
    fn handle_key_edits_and_reports_consumption() {
        let mut input = TextInput::default();
        assert!(input.handle_key(key(KeyCode::Char('h'))));
        assert!(input.handle_key(key(KeyCode::Char('i'))));
        assert!(input.handle_key(key(KeyCode::Left)));
        assert!(input.handle_key(key(KeyCode::Backspace)));
        assert_eq!(input.value(), "i");
        assert!(input.handle_key(key(KeyCode::Delete)));
        assert_eq!(input.value(), "");
        // Unknown keys and Ctrl commands are not consumed.
        assert!(!input.handle_key(key(KeyCode::Tab)));
        let ctrl_s = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert!(!input.handle_key(ctrl_s));
        let ctrl_u = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
        input.set_value("abc");
        assert!(input.handle_key(ctrl_u));
        assert_eq!(input.value(), "");
    }

    #[test]
    fn window_scrolls_to_keep_cursor_visible() {
        let input = TextInput::with_value("abcdefghij");
        let (text, col) = input.window(5);
        // Cursor at the end: the slice ends at the cursor, room for it remains.
        assert_eq!(col, 4);
        assert_eq!(text, "ghij");
        let mut input = input;
        input.home();
        let (text, col) = input.window(5);
        assert_eq!((text.as_str(), col), ("abcde", 0));
        // Short text: unchanged.
        let short = TextInput::with_value("ab");
        assert_eq!(short.window(10), ("ab".to_owned(), 2));
    }

    #[test]
    fn window_handles_wide_characters() {
        let input = TextInput::with_value("🚀🚀🚀🚀");
        let (text, col) = input.window(5);
        assert!(text.width() <= 5);
        assert!(col <= 4);
    }
}
