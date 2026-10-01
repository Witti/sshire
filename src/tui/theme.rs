//! Colors and styles of the TUI: four palettes (Mocha, Latte, Tokyo Night, Gruvbox).
//!
//! The user picks the palette in `config.toml` (`theme = "…"`). The style
//! functions (`text()`, `dim()`, …) read the active theme.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

use crate::config::ThemeName;

/// A complete color palette of the TUI.
///
/// All colors live as fields in one place, so you can change the look
/// without searching through the rendering code. `Color::Rgb` needs a
/// terminal with truecolor support (practically all modern ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Background of popups and chip text (darkest or lightest surface).
    pub base: Color,
    /// Normal text.
    pub text: Color,
    /// Dimmed text (secondary information).
    pub dim: Color,
    /// Border in the idle state.
    pub border: Color,
    /// Accent color (titles, selection, matches).
    pub accent: Color,
    /// Background of the selected row.
    pub selection_bg: Color,
    /// Success (✔).
    pub success: Color,
    /// Error (✘).
    pub error: Color,
    /// Warning and favorite star.
    pub warning: Color,
    /// Color rotation for tags without a color of their own.
    pub tag_palette: [Color; 7],
}

/// Shorthand for an RGB color (`const fn`: may be used in `const` values).
const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

impl Theme {
    /// Catppuccin Mocha (dark, default).
    pub const MOCHA: Self = Self {
        base: rgb(30, 30, 46),
        text: rgb(205, 214, 244),
        dim: rgb(127, 132, 156),
        border: rgb(88, 91, 112),
        accent: rgb(203, 166, 247),
        selection_bg: rgb(49, 50, 68),
        success: rgb(166, 227, 161),
        error: rgb(243, 139, 168),
        warning: rgb(249, 226, 175),
        tag_palette: [
            rgb(137, 180, 250), // Blue
            rgb(148, 226, 213), // Teal
            rgb(250, 179, 135), // Orange
            rgb(245, 194, 231), // Pink
            rgb(116, 199, 236), // Sky
            rgb(180, 190, 254), // Lavender
            rgb(242, 205, 205), // Flamingo
        ],
    };

    /// Catppuccin Latte (light).
    pub const LATTE: Self = Self {
        base: rgb(239, 241, 245),
        text: rgb(76, 79, 105),
        dim: rgb(140, 143, 161),
        border: rgb(156, 160, 176),
        accent: rgb(136, 57, 239),
        selection_bg: rgb(204, 208, 218),
        success: rgb(64, 160, 43),
        error: rgb(210, 15, 57),
        warning: rgb(223, 142, 29),
        tag_palette: [
            rgb(30, 102, 245),
            rgb(23, 146, 153),
            rgb(254, 100, 11),
            rgb(234, 118, 203),
            rgb(32, 159, 181),
            rgb(114, 135, 253),
            rgb(221, 120, 120),
        ],
    };

    /// Tokyo Night (dark).
    pub const TOKYO_NIGHT: Self = Self {
        base: rgb(26, 27, 38),
        text: rgb(192, 202, 245),
        dim: rgb(86, 95, 137),
        border: rgb(59, 66, 97),
        accent: rgb(187, 154, 247),
        selection_bg: rgb(41, 46, 66),
        success: rgb(158, 206, 106),
        error: rgb(247, 118, 142),
        warning: rgb(224, 175, 104),
        tag_palette: [
            rgb(122, 162, 247),
            rgb(115, 218, 202),
            rgb(255, 158, 100),
            rgb(255, 117, 160),
            rgb(125, 207, 255),
            rgb(157, 124, 216),
            rgb(180, 249, 248),
        ],
    };

    /// Gruvbox (dark).
    pub const GRUVBOX: Self = Self {
        base: rgb(40, 40, 40),
        text: rgb(235, 219, 178),
        dim: rgb(146, 131, 116),
        border: rgb(102, 92, 84),
        accent: rgb(211, 134, 155),
        selection_bg: rgb(60, 56, 54),
        success: rgb(184, 187, 38),
        error: rgb(251, 73, 52),
        warning: rgb(250, 189, 47),
        tag_palette: [
            rgb(131, 165, 152),
            rgb(142, 192, 124),
            rgb(254, 128, 25),
            rgb(177, 98, 134),
            rgb(250, 189, 47),
            rgb(69, 133, 136),
            rgb(213, 196, 161),
        ],
    };

    /// The palette for a name from the configuration.
    pub fn by_name(name: ThemeName) -> Self {
        match name {
            ThemeName::Mocha => Self::MOCHA,
            ThemeName::Latte => Self::LATTE,
            ThemeName::TokyoNight => Self::TOKYO_NIGHT,
            ThemeName::Gruvbox => Self::GRUVBOX,
        }
    }
}

// The active theme is global: almost every drawing function needs colors, and
// the theme never changes after startup. Instead of passing it through every
// function, it lives in a `OnceLock` – a cell that can be set exactly *once*
// and is only read afterwards (thread-safe).
static CURRENT: OnceLock<Theme> = OnceLock::new();

/// Selects the theme for the entire program run (only the first call has an effect).
pub fn init(theme: Theme) {
    // `set` fails if already set; that is intended here and harmless.
    let _ = CURRENT.set(theme);
}

/// The active theme; without a prior [`init`] (e.g. in tests) Mocha.
pub fn current() -> &'static Theme {
    CURRENT.get_or_init(|| Theme::MOCHA)
}

/// Background of popups and chip text.
pub fn base() -> Color {
    current().base
}

/// Normal text color.
pub fn text_color() -> Color {
    current().text
}

/// Color for success.
pub fn success() -> Color {
    current().success
}

/// Color for errors.
pub fn error() -> Color {
    current().error
}

/// Color for warnings and the favorite star.
pub fn warning() -> Color {
    current().warning
}

/// Accent color.
pub fn accent_color() -> Color {
    current().accent
}

/// Background of the selected row.
pub fn selection_bg() -> Color {
    current().selection_bg
}

/// Style for default text.
pub fn text() -> Style {
    Style::default().fg(text_color())
}

/// Style for dimmed text.
pub fn dim() -> Style {
    Style::default().fg(current().dim)
}

/// Style for bold text (e.g. aliases).
pub fn bold() -> Style {
    Style::default()
        .fg(text_color())
        .add_modifier(Modifier::BOLD)
}

/// Style for highlighted search matches.
pub fn highlight() -> Style {
    Style::default()
        .fg(accent_color())
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Style for borders.
pub fn border() -> Style {
    Style::default().fg(current().border)
}

/// Style for border titles and accents.
pub fn accent() -> Style {
    Style::default()
        .fg(accent_color())
        .add_modifier(Modifier::BOLD)
}

/// Color of a tag: the one stored in the database (`#rrggbb`), otherwise one
/// from the palette, chosen via a hash of the name (same name ⇒ always the
/// same color).
pub fn tag_color(name: &str, configured: Option<&str>) -> Color {
    if let Some(color) = configured.and_then(parse_hex_color) {
        return color;
    }
    // Simple FNV-1a hash over the bytes of the name (deliberately *not*
    // `DefaultHasher`, whose result may change between Rust versions).
    let hash = name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |acc, byte| {
        (acc ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    // `%` yields an index < 7; `as usize` is lossless here.
    let palette = &current().tag_palette;
    palette[(hash % palette.len() as u64) as usize]
}

/// Chip style: dark text on a colored background.
pub fn chip(name: &str, configured: Option<&str>) -> Style {
    Style::default().fg(base()).bg(tag_color(name, configured))
}

/// Parses `#rrggbb` (with or without `#`); anything else yields `None`.
fn parse_hex_color(text: &str) -> Option<Color> {
    let hex = text.trim().trim_start_matches('#');
    // `is_ascii` prevents the slicing below from cutting into the middle of a
    // multi-byte character (that would panic).
    if hex.len() != 6 || !hex.is_ascii() {
        return None;
    }
    let channel = |range: std::ops::Range<usize>| u8::from_str_radix(&hex[range], 16).ok();
    Some(Color::Rgb(channel(0..2)?, channel(2..4)?, channel(4..6)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_color_wins() {
        assert_eq!(tag_color("x", Some("#ff0000")), Color::Rgb(255, 0, 0));
        assert_eq!(tag_color("x", Some("00ff00")), Color::Rgb(0, 255, 0));
    }

    #[test]
    fn invalid_color_falls_back_to_palette() {
        let fallback = tag_color("prod", None);
        assert_eq!(tag_color("prod", Some("rot")), fallback);
        assert_eq!(tag_color("prod", Some("#ääää")), fallback);
    }

    #[test]
    fn theme_is_chosen_by_name() {
        assert_eq!(Theme::by_name(ThemeName::Mocha), Theme::MOCHA);
        assert_eq!(Theme::by_name(ThemeName::Latte), Theme::LATTE);
        assert_eq!(Theme::by_name(ThemeName::TokyoNight), Theme::TOKYO_NIGHT);
        assert_eq!(Theme::by_name(ThemeName::Gruvbox), Theme::GRUVBOX);
    }

    #[test]
    fn themes_differ_from_each_other() {
        let all = [
            Theme::MOCHA,
            Theme::LATTE,
            Theme::TOKYO_NIGHT,
            Theme::GRUVBOX,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.base, b.base);
                assert_ne!(a.accent, b.accent);
            }
        }
    }

    #[test]
    fn palette_color_is_stable_per_name() {
        assert_eq!(tag_color("web", None), tag_color("web", None));
    }
}
