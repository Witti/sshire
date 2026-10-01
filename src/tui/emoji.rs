//! Curated symbol list and the state of the icon picker.
//!
//! The picker is an overlay in the host form: you type a keyword
//! ("docker", "red"), the list filters itself, arrow keys select, Enter
//! confirms. This module only holds data and logic; drawing happens in
//! `overlays.rs`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::input::TextInput;

/// Columns of the symbol grid (arrow up/down jumps by this many entries).
pub const PICKER_COLUMNS: usize = 10;

/// One entry of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IconEntry {
    pub symbol: &'static str,
    /// Keywords for the search (lowercase, separated by spaces).
    pub keywords: &'static str,
    pub category: &'static str,
}

/// Shorthand so the table below stays readable.
const fn e(symbol: &'static str, keywords: &'static str, category: &'static str) -> IconEntry {
    IconEntry {
        symbol,
        keywords,
        category,
    }
}

/// The curated list (`static` = lives for the whole program run, stored in the binary).
pub static ICONS: &[IconEntry] = &[
    // Servers and infrastructure
    e("🖥️", "server computer desktop", "Server"),
    e("🗄️", "database db archive cabinet", "Server"),
    e("🐳", "docker container whale", "Server"),
    e("☸️", "kubernetes k8s cluster", "Server"),
    e("🔥", "firewall fire hot", "Server"),
    e("🛡️", "security protection shield", "Server"),
    e("🌐", "web network internet http", "Server"),
    e("📡", "antenna radio network satellite", "Server"),
    e("🔌", "plug power", "Server"),
    e("💾", "storage backup disk floppy", "Server"),
    e("⚙️", "gear service settings", "Server"),
    e("🔑", "key vpn", "Server"),
    e("🔒", "locked secure bastion lock", "Server"),
    e("📦", "package container archive registry", "Server"),
    e("📊", "monitoring grafana metrics statistics", "Server"),
    e("📧", "mail email smtp post", "Server"),
    // Environments
    e("🟢", "green ok live online", "Environment"),
    e("🟡", "yellow staging warning", "Environment"),
    e("🔴", "red prod critical offline", "Environment"),
    e("🔵", "blue dev development", "Environment"),
    e("🧪", "test lab experiment", "Environment"),
    e("🚀", "rocket deploy release launch", "Environment"),
    e("🏭", "factory production prod", "Environment"),
    e("🛠️", "tools dev build maintenance", "Environment"),
    // Places
    e("🏠", "house home", "Place"),
    e("🏢", "office company building", "Place"),
    e("☁️", "cloud aws azure", "Place"),
    e("🏡", "home garden house", "Place"),
    e("🌍", "world global earth", "Place"),
    e("🏗️", "construction site new setup", "Place"),
    // Devices
    e("🍓", "raspberry pi", "Device"),
    e("📟", "pager embedded small device", "Device"),
    e("🖨️", "printer print", "Device"),
    e("📷", "camera photo surveillance", "Device"),
    e("💻", "laptop notebook", "Device"),
    e("📱", "phone mobile", "Device"),
    e("🎮", "console game gaming", "Device"),
    e("📺", "television tv media", "Device"),
    e("🕹️", "joystick retro arcade", "Device"),
    e("🔊", "speaker audio sound", "Device"),
    // Animals and fun
    e("🐙", "octopus kraken", "Fun"),
    e("🦊", "fox firefox", "Fun"),
    e("🐧", "penguin linux tux", "Fun"),
    e("🐉", "dragon", "Fun"),
    e("🦄", "unicorn", "Fun"),
    e("🐢", "turtle slow", "Fun"),
    e("🦉", "owl night", "Fun"),
    e("🐝", "bee busy", "Fun"),
    e("🦀", "crab rust", "Fun"),
    e("🐍", "snake python", "Fun"),
    e("🐘", "elephant postgres php", "Fun"),
    e("🐋", "whale docker", "Fun"),
    e("🤖", "robot bot automation", "Fun"),
    e("👾", "alien monster retro", "Fun"),
    e("👻", "ghost", "Fun"),
    e("💎", "diamond gem ruby", "Fun"),
    e("⭐", "star favorite important", "Fun"),
    e("⚡", "lightning fast power", "Fun"),
    e("🎯", "target bullseye", "Fun"),
    e("🧠", "brain ai thinking", "Fun"),
];

/// Filters the list by a search text (case-insensitive).
///
/// Every whitespace-separated search word must appear in the keywords or the
/// category. An empty search returns all entries.
pub fn filter_icons(query: &str) -> Vec<&'static IconEntry> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    ICONS
        .iter()
        .filter(|entry| {
            let category = entry.category.to_lowercase();
            words
                .iter()
                .all(|w| entry.keywords.contains(w.as_str()) || category.contains(w.as_str()))
        })
        .collect()
}

/// Result of a key press in the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerEvent {
    /// The picker stays open.
    None,
    /// A symbol was chosen (the symbol's text).
    Picked(&'static str),
    /// Cancelled (Esc).
    Cancel,
}

/// Picker state: search text and highlighted entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IconPicker {
    pub query: TextInput,
    /// Index into the *filtered* list.
    pub selected: usize,
}

impl IconPicker {
    /// New picker with an empty search.
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently visible (filtered) entries.
    pub fn visible(&self) -> Vec<&'static IconEntry> {
        filter_icons(self.query.value())
    }

    /// The highlighted entry, if the list is not empty.
    pub fn current(&self) -> Option<&'static IconEntry> {
        self.visible().get(self.selected).copied()
    }

    /// Moves the highlight by `delta` and keeps it within the list.
    fn step(&mut self, delta: isize) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        // `saturating_add_signed` adds a signed delta to a `usize` without
        // underflow (at 0 it stays 0).
        self.selected = self.selected.saturating_add_signed(delta).min(len - 1);
    }

    /// Handles a key press.
    pub fn handle_key(&mut self, key: KeyEvent) -> PickerEvent {
        let columns = PICKER_COLUMNS.cast_signed();
        match key.code {
            KeyCode::Esc => return PickerEvent::Cancel,
            KeyCode::Enter => {
                return self
                    .current()
                    .map_or(PickerEvent::None, |entry| PickerEvent::Picked(entry.symbol));
            }
            KeyCode::Left => self.step(-1),
            KeyCode::Right => self.step(1),
            KeyCode::Up => self.step(-columns),
            KeyCode::Down => self.step(columns),
            _ => {
                // Everything else goes into the search; if the text changes, the highlight restarts.
                let before = self.query.value().to_owned();
                // Ctrl-E (the open key) and friends must not change the search text.
                let plain = !key.modifiers.contains(KeyModifiers::CONTROL);
                if plain && self.query.handle_key(key) && self.query.value() != before {
                    self.selected = 0;
                }
            }
        }
        PickerEvent::None
    }
}

#[cfg(test)]
mod tests {
    use unicode_segmentation::UnicodeSegmentation;
    use unicode_width::UnicodeWidthStr;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn list_is_curated_and_valid() {
        assert!(ICONS.len() >= 60, "only {} entries", ICONS.len());
        for entry in ICONS {
            assert_eq!(
                entry.symbol.graphemes(true).count(),
                1,
                "{} is not a single grapheme",
                entry.symbol
            );
            assert!(entry.symbol.width() <= 2, "{} is too wide", entry.symbol);
            assert!(!entry.keywords.is_empty());
        }
        // No duplicates.
        let mut symbols: Vec<_> = ICONS.iter().map(|e| e.symbol).collect();
        symbols.sort_unstable();
        symbols.dedup();
        assert_eq!(symbols.len(), ICONS.len());
    }

    #[test]
    fn every_entry_passes_the_form_validation() {
        for entry in ICONS {
            assert!(crate::validate::check_icon(entry.symbol).is_ok());
        }
    }

    #[test]
    fn filter_matches_keywords_and_category_case_insensitively() {
        assert_eq!(filter_icons("").len(), ICONS.len());
        let docker = filter_icons("DOCKER");
        assert!(docker.iter().any(|e| e.symbol == "🐳"));
        assert!(docker.iter().all(|e| e.keywords.contains("docker")));
        // All words must match.
        let both = filter_icons("server computer");
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].symbol, "🖥️");
        // The category is searched too.
        assert!(filter_icons("device").iter().any(|e| e.symbol == "🍓"));
        assert!(filter_icons("zzzzzz").is_empty());
    }

    #[test]
    fn typing_filters_and_enter_picks() {
        let mut picker = IconPicker::new();
        for c in "docker".chars() {
            assert_eq!(picker.handle_key(key(KeyCode::Char(c))), PickerEvent::None);
        }
        assert_eq!(picker.visible().len(), 2);
        picker.handle_key(key(KeyCode::Right));
        assert_eq!(picker.selected, 1);
        // Further right than the list is long: the highlight stays at the end.
        picker.handle_key(key(KeyCode::Right));
        assert_eq!(picker.selected, 1);
        let ev = picker.handle_key(key(KeyCode::Enter));
        assert_eq!(ev, PickerEvent::Picked("🐋"));
        // Typing resets the highlight.
        picker.handle_key(key(KeyCode::Backspace));
        assert_eq!(picker.selected, 0);
    }

    #[test]
    fn arrows_move_by_rows_and_clamp() {
        let mut picker = IconPicker::new();
        picker.handle_key(key(KeyCode::Down));
        assert_eq!(picker.selected, PICKER_COLUMNS);
        picker.handle_key(key(KeyCode::Up));
        picker.handle_key(key(KeyCode::Up));
        assert_eq!(picker.selected, 0);
        picker.handle_key(key(KeyCode::Left));
        assert_eq!(picker.selected, 0);
        for _ in 0..20 {
            picker.handle_key(key(KeyCode::Down));
        }
        assert_eq!(picker.selected, ICONS.len() - 1);
    }

    #[test]
    fn enter_on_empty_result_does_nothing_and_esc_cancels() {
        let mut picker = IconPicker::new();
        for c in "zzzzz".chars() {
            picker.handle_key(key(KeyCode::Char(c)));
        }
        assert!(picker.current().is_none());
        assert_eq!(picker.handle_key(key(KeyCode::Enter)), PickerEvent::None);
        assert_eq!(picker.handle_key(key(KeyCode::Esc)), PickerEvent::Cancel);
    }
}
