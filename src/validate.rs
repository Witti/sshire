//! Shared input validation for the host form (TUI) and `sshire add` (CLI).
//!
//! Both paths take raw text from the user. So that they apply *exactly the
//! same* rules, the checking lives in exactly one place: here. The module
//! knows neither the terminal nor the database and is therefore easy to test.
//!
//! # Bytes, `char` and graphemes
//!
//! For Unicode text there are three ways of counting that must not be mixed up:
//!
//! * **Bytes** - how much memory the text occupies in UTF-8. `str::len()` and
//!   all indices such as `&text[2..5]` count in bytes! Slicing in the middle of
//!   a multi-byte character crashes the program (panic).
//! * **`char`** - a Unicode "scalar value" (`'ä'`, `'🚀'`). An emoji such as
//!   "🖥️" already consists of *two* `char`s (symbol + variation selector).
//! * **Grapheme cluster** - what humans see as "one character". Flags or
//!   "👨‍👩‍👧" are also a single grapheme even though they consist of many
//!   `char`s. The `unicode-segmentation` crate splits text this way.
//!
//! For the icon field we therefore count graphemes (at most one) and
//! additionally check the display width in terminal columns (at most 2).

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::store::{AuthMethod, HostUpdate, NewHost};

/// The input fields of a host (order = order in the form).
///
/// An `enum` without data: each variant stands for exactly one field. It serves
/// as a key for error messages and for focus handling in the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Alias,
    Hostname,
    User,
    Port,
    IdentityFile,
    ProxyJump,
    ExtraArgs,
    Auth,
    Icon,
    Tags,
    Notes,
}

impl Field {
    /// All fields in form order.
    pub const ALL: [Field; 11] = [
        Field::Alias,
        Field::Hostname,
        Field::User,
        Field::Port,
        Field::IdentityFile,
        Field::ProxyJump,
        Field::ExtraArgs,
        Field::Auth,
        Field::Icon,
        Field::Tags,
        Field::Notes,
    ];

    /// Label for the form and error messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Alias => "Alias",
            Self::Hostname => "Hostname",
            Self::User => "User",
            Self::Port => "Port",
            Self::IdentityFile => "IdentityFile",
            Self::ProxyJump => "ProxyJump",
            Self::ExtraArgs => "Extra-Args",
            Self::Auth => "Auth",
            Self::Icon => "Icon",
            Self::Tags => "Tags",
            Self::Notes => "Notes",
        }
    }

    /// `true` for the fields that ssh determines via `~/.ssh/config`
    /// (Alias through Auth). For `ssh_config` hosts they are read-only.
    pub fn is_connection_field(self) -> bool {
        !matches!(self, Self::Icon | Self::Tags | Self::Notes)
    }
}

/// A validation error together with the field it is shown at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: Field,
    pub message: String,
}

/// Raw input as it comes from the form or CLI (everything still text).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawHost {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: String,
    pub identity_file: String,
    pub proxy_jump: String,
    pub extra_args: String,
    pub icon: String,
    /// Comma-separated, e.g. `prod, web`.
    pub tags: String,
    pub notes: String,
    pub auth: AuthMethod,
}

/// Validated, normalized values (trimmed, empty = `None`, port as a number).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub extra_args: Option<String>,
    pub icon: Option<String>,
    pub notes: Option<String>,
    pub auth_method: AuthMethod,
    pub tags: Vec<String>,
}

// `impl From<X> for Y` tells Rust how to convert an `X` into a `Y`.
// After that `NewHost::from(&valid)` works, and automatically
// `(&valid).into()` too. `From` is the standard way for lossless
// conversions; if something can fail, use `TryFrom`.
impl From<&ValidHost> for NewHost {
    fn from(v: &ValidHost) -> Self {
        // `clone()`: we only borrow `v` but need our own strings.
        Self {
            alias: v.alias.clone(),
            hostname: v.hostname.clone(),
            user: v.user.clone(),
            port: v.port,
            identity_file: v.identity_file.clone(),
            proxy_jump: v.proxy_jump.clone(),
            extra_args: v.extra_args.clone(),
            icon: v.icon.clone(),
            color: None,
            notes: v.notes.clone(),
            // Newly created hosts are always manual (default value), see `NewHost`.
            source: crate::store::HostSource::Manual,
            auth_method: v.auth_method,
        }
    }
}

impl ValidHost {
    /// Builds the update for an existing host. The color is not edited
    /// but carried over from the previous value.
    pub fn to_update(&self, color: Option<String>) -> HostUpdate {
        HostUpdate {
            alias: self.alias.clone(),
            hostname: self.hostname.clone(),
            user: self.user.clone(),
            port: self.port,
            identity_file: self.identity_file.clone(),
            proxy_jump: self.proxy_jump.clone(),
            extra_args: self.extra_args.clone(),
            icon: self.icon.clone(),
            color,
            notes: self.notes.clone(),
            auth_method: self.auth_method,
        }
    }
}

/// Validated metadata (the only fields that can be changed on `ssh_config` hosts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub icon: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

/// Turns empty text into `None`, otherwise the trimmed text.
fn optional(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_owned())
    }
}

/// Alias: required, no whitespace, must not start with `-`.
pub fn check_alias(text: &str) -> Result<String, String> {
    let alias = text.trim();
    if alias.is_empty() {
        return Err("Alias is required".to_owned());
    }
    if alias.chars().any(char::is_whitespace) {
        return Err("Alias must not contain spaces".to_owned());
    }
    if alias.starts_with('-') {
        return Err("Alias must not start with \"-\"".to_owned());
    }
    Ok(alias.to_owned())
}

/// Hostname: optional; must not start with `-` (ssh would read it as an option)
/// and must not contain whitespace.
pub fn check_hostname(text: &str) -> Result<Option<String>, String> {
    check_target_part(text, "Hostname")
}

/// User: same rules as the hostname (it appears as `user@host` in the target).
pub fn check_user(text: &str) -> Result<Option<String>, String> {
    check_target_part(text, "User")
}

fn check_target_part(text: &str, name: &str) -> Result<Option<String>, String> {
    let Some(value) = optional(text) else {
        return Ok(None);
    };
    if value.starts_with('-') {
        return Err(format!("{name} must not start with \"-\""));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must not contain spaces"));
    }
    Ok(Some(value))
}

/// Port: empty (= ssh default) or a number from 1 to 65535.
pub fn check_port(text: &str) -> Result<Option<u16>, String> {
    let Some(value) = optional(text) else {
        return Ok(None);
    };
    // `parse::<u16>` rejects minus signs, letters and numbers > 65535.
    match value.parse::<u16>() {
        Ok(port) if port >= 1 => Ok(Some(port)),
        _ => Err("Port must be a number from 1 to 65535".to_owned()),
    }
}

/// IdentityFile or ProxyJump: optional, must not start with `-`
/// (otherwise `-i -foo` would be mistaken for an option).
pub fn check_path_like(text: &str, name: &str) -> Result<Option<String>, String> {
    let Some(value) = optional(text) else {
        return Ok(None);
    };
    if value.starts_with('-') {
        return Err(format!("{name} must not start with \"-\""));
    }
    Ok(Some(value))
}

/// Extra-Args: optional, must be splittable into words like in a shell.
pub fn check_extra_args(text: &str) -> Result<Option<String>, String> {
    let Some(value) = optional(text) else {
        return Ok(None);
    };
    match shell_words::split(&value) {
        Ok(_) => Ok(Some(value)),
        Err(_) => Err("Extra-Args cannot be parsed (unclosed quote?)".to_owned()),
    }
}

/// Icon: empty or exactly *one* visible symbol (grapheme) with width <= 2.
///
/// Free text remains allowed: Nerd Font glyphs (width 1) are valid too.
pub fn check_icon(text: &str) -> Result<Option<String>, String> {
    let Some(value) = optional(text) else {
        return Ok(None);
    };
    // `graphemes(true)` = extended grapheme clusters (the way a human counts).
    if value.graphemes(true).count() > 1 {
        return Err("Icon: only one symbol allowed".to_owned());
    }
    // `width()` counts terminal columns (emojis usually 2, normal characters 1).
    if value.width() > 2 {
        return Err("Icon is too wide (at most 2 columns)".to_owned());
    }
    Ok(Some(value))
}

/// Notes: optional; line breaks could not be displayed in a single-line field.
pub fn check_notes(text: &str) -> Result<Option<String>, String> {
    Ok(optional(text))
}

/// Splits comma-separated tags: trims, strips a leading `#`, discards
/// empty entries and duplicates (case-insensitively).
///
/// Tag names containing spaces are an error: the search splits its text on
/// whitespace, so a filter like `#my tag` could never match them.
pub fn parse_tags(text: &str) -> Result<Vec<String>, String> {
    let mut tags: Vec<String> = Vec::new();
    for part in text.split(',') {
        let name = part.trim().trim_start_matches('#').trim();
        if name.is_empty() {
            continue;
        }
        if name.chars().any(char::is_whitespace) {
            return Err(format!(
                "Tag \"{name}\" contains spaces (separate tags with commas)"
            ));
        }
        if !tags.iter().any(|t| t.to_lowercase() == name.to_lowercase()) {
            tags.push(name.to_owned());
        }
    }
    Ok(tags)
}

/// Validates the text of a single (text) field. The result is only
/// "ok or error message"; for CLI prompts and live checking in the form.
///
/// `Field::Auth` is not a text field and is always valid.
pub fn validate_field(field: Field, text: &str) -> Result<(), String> {
    match field {
        Field::Alias => check_alias(text).map(drop),
        Field::Hostname => check_hostname(text).map(drop),
        Field::User => check_user(text).map(drop),
        Field::Port => check_port(text).map(drop),
        Field::IdentityFile => check_path_like(text, "IdentityFile").map(drop),
        Field::ProxyJump => check_path_like(text, "ProxyJump").map(drop),
        Field::ExtraArgs => check_extra_args(text).map(drop),
        Field::Icon => check_icon(text).map(drop),
        Field::Tags => parse_tags(text).map(drop),
        Field::Notes => check_notes(text).map(drop),
        Field::Auth => Ok(()),
    }
}

/// Collects errors instead of stopping at the first one.
///
/// `take<T>` is *generic*: it works for any result type `T`
/// (`String`, `Option<u16>`, `Vec<String>`, ...). That is not possible with a
/// closure, because closures apply to only *one* fixed type.
#[derive(Default)]
struct Errors(Vec<FieldError>);

impl Errors {
    /// Passes the value on for `Ok`, remembers the message for `Err`.
    fn take<T>(&mut self, field: Field, result: Result<T, String>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(message) => {
                self.0.push(FieldError { field, message });
                None
            }
        }
    }

    /// `Ok(value)` if no error was collected, otherwise all errors.
    fn finish<T>(self, value: T) -> Result<T, Vec<FieldError>> {
        if self.0.is_empty() {
            Ok(value)
        } else {
            Err(self.0)
        }
    }
}

/// Validates only the metadata (icon, tags, notes). All errors are collected.
pub fn validate_metadata(icon: &str, tags: &str, notes: &str) -> Result<Metadata, Vec<FieldError>> {
    let mut errors = Errors::default();
    let icon = errors.take(Field::Icon, check_icon(icon)).flatten();
    let tags = errors
        .take(Field::Tags, parse_tags(tags))
        .unwrap_or_default();
    let notes = errors.take(Field::Notes, check_notes(notes)).flatten();
    errors.finish(Metadata { icon, notes, tags })
}

/// Validates all fields of a host and collects *all* errors (not just the first).
pub fn validate_host(raw: &RawHost) -> Result<ValidHost, Vec<FieldError>> {
    let mut errors = Errors::default();
    let alias = errors
        .take(Field::Alias, check_alias(&raw.alias))
        .unwrap_or_default();
    let hostname = errors
        .take(Field::Hostname, check_hostname(&raw.hostname))
        .flatten();
    let user = errors.take(Field::User, check_user(&raw.user)).flatten();
    let port = errors.take(Field::Port, check_port(&raw.port)).flatten();
    let identity_file = errors
        .take(
            Field::IdentityFile,
            check_path_like(&raw.identity_file, "IdentityFile"),
        )
        .flatten();
    let proxy_jump = errors
        .take(
            Field::ProxyJump,
            check_path_like(&raw.proxy_jump, "ProxyJump"),
        )
        .flatten();
    let extra_args = errors
        .take(Field::ExtraArgs, check_extra_args(&raw.extra_args))
        .flatten();
    let icon = errors.take(Field::Icon, check_icon(&raw.icon)).flatten();
    let tags = errors
        .take(Field::Tags, parse_tags(&raw.tags))
        .unwrap_or_default();
    let notes = errors.take(Field::Notes, check_notes(&raw.notes)).flatten();
    errors.finish(ValidHost {
        alias,
        hostname,
        user,
        port,
        identity_file,
        proxy_jump,
        extra_args,
        icon,
        notes,
        auth_method: raw.auth,
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_rules() {
        assert_eq!(check_alias("  web1 ").unwrap(), "web1");
        assert!(check_alias("").is_err());
        assert!(check_alias("   ").is_err());
        assert!(check_alias("my host").is_err());
        assert!(check_alias("a\tb").is_err());
        assert!(check_alias("-oProxyCommand=x").is_err());
    }

    #[test]
    fn hostname_and_user_must_not_look_like_options() {
        assert_eq!(check_hostname("").unwrap(), None);
        assert_eq!(check_hostname(" h.invalid ").unwrap().unwrap(), "h.invalid");
        assert!(check_hostname("-h").is_err());
        assert!(check_hostname("a b").is_err());
        assert!(check_user("-u").is_err());
        assert_eq!(check_user("root").unwrap().unwrap(), "root");
    }

    #[test]
    fn port_range() {
        assert_eq!(check_port("").unwrap(), None);
        assert_eq!(check_port("22").unwrap(), Some(22));
        assert_eq!(check_port("65535").unwrap(), Some(65535));
        assert!(check_port("0").is_err());
        assert!(check_port("65536").is_err());
        assert!(check_port("-1").is_err());
        assert!(check_port("abc").is_err());
    }

    #[test]
    fn path_like_fields_reject_leading_dash() {
        assert!(check_path_like("-i", "IdentityFile").is_err());
        assert_eq!(
            check_path_like("~/.ssh/id", "IdentityFile")
                .unwrap()
                .unwrap(),
            "~/.ssh/id"
        );
        assert_eq!(check_path_like("", "ProxyJump").unwrap(), None);
    }

    #[test]
    fn extra_args_must_parse_like_a_shell() {
        assert!(check_extra_args("-o 'A=b c' -v").unwrap().is_some());
        assert!(check_extra_args("-o \"open").is_err());
        assert_eq!(check_extra_args("  ").unwrap(), None);
    }

    #[test]
    fn icon_allows_one_grapheme_up_to_width_two() {
        assert_eq!(check_icon("").unwrap(), None);
        assert_eq!(check_icon("🚀").unwrap().unwrap(), "🚀");
        // Two `char`s (symbol + variation selector), but one grapheme.
        assert!(check_icon("🖥️").is_ok());
        // Composite emojis (ZWJ sequence) are one grapheme.
        assert!(check_icon("👨‍👩‍👧").is_ok());
        // Nerd Font glyph (Private Use Area, width 1).
        assert!(check_icon("\u{f120}").is_ok());
        assert!(check_icon("🚀🚀").is_err());
        assert!(check_icon("ab").is_err());
    }

    #[test]
    fn tags_are_split_cleaned_and_deduplicated() {
        assert_eq!(
            parse_tags(" prod, #web ,, Prod ,db").unwrap(),
            ["prod", "web", "db"]
        );
        assert!(parse_tags("").unwrap().is_empty());
        assert!(parse_tags("two words").is_err());
    }

    #[test]
    fn validate_host_collects_all_errors() {
        let raw = RawHost {
            alias: "bad alias".into(),
            port: "99999".into(),
            extra_args: "'open".into(),
            icon: "ab".into(),
            ..RawHost::default()
        };
        let errors = validate_host(&raw).unwrap_err();
        let fields: Vec<Field> = errors.iter().map(|e| e.field).collect();
        assert_eq!(
            fields,
            [Field::Alias, Field::Port, Field::ExtraArgs, Field::Icon]
        );
    }

    #[test]
    fn validate_host_normalizes_and_converts() {
        let raw = RawHost {
            alias: " web ".into(),
            hostname: "h.invalid".into(),
            port: "2222".into(),
            icon: "🚀".into(),
            tags: "a, b".into(),
            notes: "  ".into(),
            auth: AuthMethod::Key,
            ..RawHost::default()
        };
        let valid = validate_host(&raw).unwrap();
        assert_eq!(valid.alias, "web");
        assert_eq!(valid.port, Some(2222));
        assert_eq!(valid.notes, None);
        assert_eq!(valid.tags, ["a", "b"]);
        let new = NewHost::from(&valid);
        assert_eq!(new.hostname.as_deref(), Some("h.invalid"));
        assert_eq!(new.auth_method, AuthMethod::Key);
        let upd = valid.to_update(Some("#fff".into()));
        assert_eq!(upd.color.as_deref(), Some("#fff"));
        assert_eq!(upd.port, Some(2222));
    }

    #[test]
    fn metadata_validation_ignores_connection_fields() {
        let meta = validate_metadata("🚀", "x, y", "Note").unwrap();
        assert_eq!(meta.tags, ["x", "y"]);
        assert_eq!(meta.notes.as_deref(), Some("Note"));
        assert!(validate_metadata("ab", "", "").is_err());
    }

    #[test]
    fn connection_fields_are_classified() {
        assert!(Field::Alias.is_connection_field());
        assert!(Field::Auth.is_connection_field());
        assert!(!Field::Icon.is_connection_field());
        assert!(!Field::Tags.is_connection_field());
        assert!(!Field::Notes.is_connection_field());
    }
}
