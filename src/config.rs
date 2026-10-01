//! User configuration from `config.toml` in the config directory.
//!
//! The file is *optional*: if it is missing, the defaults apply (and it is not
//! created automatically - `sshire config --example` prints a commented
//! template that you can save yourself).
//!
//! # How `serde` works here
//!
//! `serde` is the standard library for converting between text formats and
//! Rust types. With `#[derive(Deserialize)]` the compiler generates the code
//! that reads, for example, a TOML document into a `struct`. Useful
//! attributes:
//!
//! * `#[serde(default)]` on a struct: fields missing from the file are taken
//!   from the `Default::default()` of the *whole* struct.
//! * `#[serde(rename_all = "kebab-case")]` on an enum: the variants are called
//!   `tokyo-night` in the file instead of `TokyoNight`. This turns enums into
//!   plain strings in TOML (`theme = "latte"`); an unknown string leads to an
//!   error message that lists all valid values.
//! * `#[serde(deny_unknown_fields)]` would abort with an *error* on unknown
//!   keys. We do not want that (only a warning), so we deliberately do not use
//!   it and look for unknown keys ourselves (see [`unknown_keys`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use unicode_segmentation::UnicodeSegmentation;

use crate::paths;

/// Name of the configuration file in the config directory.
const FILE_NAME: &str = "config.toml";

/// Commented example configuration (`sshire config --example`).
///
/// All values match the defaults; a test ensures this.
pub const EXAMPLE_CONFIG: &str = r#"# sshire - example configuration
# Save it at the path printed by `sshire config --path`.
# Every line is optional; missing values fall back to the defaults shown here.

# TUI color scheme: "mocha" | "latte" | "tokyo-night" | "gruvbox"
theme = "mocha"

# Sort order at startup: "name" | "recent" (last connected) | "frequent"
default_sort = "name"

# Show archived hosts at startup?
show_archived = false

# Symbol for hosts without their own icon (exactly one character/emoji)
icon_fallback = "•"

[ssh]
# Path or name of the ssh program
program = "ssh"
# Extra arguments for *all* connections; they come before the
# host-specific options. Example: ["-o", "ServerAliveInterval=30"]
extra_args = []
"#;

/// TUI color scheme (a string in the file, e.g. `"tokyo-night"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThemeName {
    /// Catppuccin Mocha (dark, default).
    #[default]
    Mocha,
    /// Catppuccin Latte (light).
    Latte,
    /// Tokyo Night (dark).
    TokyoNight,
    /// Gruvbox (dark).
    Gruvbox,
}

/// Initial sort order of the host list (a string in the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultSort {
    /// Alphabetically by alias.
    #[default]
    Name,
    /// Most recently connected successfully first.
    Recent,
    /// Most frequently connected first.
    Frequent,
}

/// The `[ssh]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct SshConfig {
    /// The ssh program to run (a name in `PATH` or a full path).
    pub program: String,
    /// Global extra arguments, placed before the host-specific options.
    pub extra_args: Vec<String>,
}

// `Default` by hand instead of via derive: a derived `Default` would leave
// `program` empty (`String::default()`); but we need `"ssh"`.
impl Default for SshConfig {
    fn default() -> Self {
        Self {
            program: "ssh".to_owned(),
            extra_args: Vec::new(),
        }
    }
}

/// The complete configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Config {
    /// TUI color scheme.
    pub theme: ThemeName,
    /// Sort order when the TUI starts.
    pub default_sort: DefaultSort,
    /// Show archived hosts when the TUI starts.
    pub show_archived: bool,
    /// Symbol for hosts without an icon.
    pub icon_fallback: String,
    /// The `[ssh]` section.
    pub ssh: SshConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: ThemeName::default(),
            default_sort: DefaultSort::default(),
            show_archived: false,
            icon_fallback: "•".to_owned(),
            ssh: SshConfig::default(),
        }
    }
}

/// Allowed top-level keys (for the warning on typos).
const KNOWN_KEYS: [&str; 5] = [
    "theme",
    "default_sort",
    "show_archived",
    "icon_fallback",
    "ssh",
];
/// Allowed keys in `[ssh]`.
const KNOWN_SSH_KEYS: [&str; 2] = ["program", "extra_args"];

/// Path of the configuration file (the file itself need not exist).
pub fn config_path() -> Result<PathBuf> {
    Ok(paths::config_dir()?.join(FILE_NAME))
}

/// Loads the configuration from the default location.
///
/// Returns: the configuration and warnings (e.g. unknown keys).
pub fn load() -> Result<(Config, Vec<String>)> {
    load_from(&config_path()?)
}

/// Loads the configuration from `path`. If the file is missing, the defaults apply.
pub fn load_from(path: &Path) -> Result<(Config, Vec<String>)> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        // `ErrorKind::NotFound`: file does not exist => not an error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Config::default(), Vec::new()));
        }
        Err(err) => {
            return Err(err).with_context(|| format!("could not read {}", path.display()));
        }
    };
    parse(&text).with_context(|| format!("Invalid configuration in {}", path.display()))
}

/// Parses the contents of a `config.toml` (no file access, easy to test).
pub fn parse(text: &str) -> Result<(Config, Vec<String>)> {
    // Read as a generic table first: that lets us find unknown keys that
    // `serde` would silently discard when reading directly. The error
    // contains the line and column of the syntax problem.
    let table: toml::Table = text.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let warnings = unknown_keys(&table)
        .into_iter()
        .map(|key| format!("config.toml: unknown key \"{key}\" is ignored"))
        .collect();
    // Then convert the table into the typed struct; wrong types or unknown
    // enum values are rejected here with an understandable message.
    let config: Config = table.try_into().map_err(|e| anyhow::anyhow!("{e}"))?;
    config.validate()?;
    Ok((config, warnings))
}

/// All keys (with an `ssh.` prefix for the section) that we do not know.
fn unknown_keys(table: &toml::Table) -> Vec<String> {
    let mut unknown: Vec<String> = table
        .keys()
        .filter(|k| !KNOWN_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    if let Some(ssh) = table.get("ssh").and_then(toml::Value::as_table) {
        unknown.extend(
            ssh.keys()
                .filter(|k| !KNOWN_SSH_KEYS.contains(&k.as_str()))
                .map(|k| format!("ssh.{k}")),
        );
    }
    unknown
}

impl Config {
    /// Checks values that the type alone does not rule out.
    fn validate(&self) -> Result<()> {
        if self.ssh.program.trim().is_empty() {
            bail!("ssh.program must not be empty");
        }
        // A "character" in the user's sense is a grapheme cluster
        // (emojis often consist of several `char`s).
        if self.icon_fallback.graphemes(true).count() != 1 {
            bail!(
                "icon_fallback must be exactly one character (found: \"{}\")",
                self.icon_fallback
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Config {
        parse(text).unwrap().0
    }

    #[test]
    fn empty_file_gives_defaults() {
        let (config, warnings) = parse("").unwrap();
        assert_eq!(config, Config::default());
        assert!(warnings.is_empty());
        assert_eq!(config.theme, ThemeName::Mocha);
        assert_eq!(config.ssh.program, "ssh");
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let (config, warnings) = load_from(&path).unwrap();
        assert_eq!(config, Config::default());
        assert!(warnings.is_empty());
        // The file is not created.
        assert!(!path.exists());
    }

    #[test]
    fn example_config_equals_defaults() {
        let (config, warnings) = parse(EXAMPLE_CONFIG).unwrap();
        assert_eq!(config, Config::default());
        assert!(warnings.is_empty());
    }

    #[test]
    fn every_theme_value_parses() {
        for (text, expected) in [
            ("mocha", ThemeName::Mocha),
            ("latte", ThemeName::Latte),
            ("tokyo-night", ThemeName::TokyoNight),
            ("gruvbox", ThemeName::Gruvbox),
        ] {
            assert_eq!(ok(&format!("theme = \"{text}\"")).theme, expected);
        }
    }

    #[test]
    fn every_sort_value_parses() {
        for (text, expected) in [
            ("name", DefaultSort::Name),
            ("recent", DefaultSort::Recent),
            ("frequent", DefaultSort::Frequent),
        ] {
            assert_eq!(
                ok(&format!("default_sort = \"{text}\"")).default_sort,
                expected
            );
        }
    }

    #[test]
    fn other_options_parse() {
        let config = ok(r#"
            show_archived = true
            icon_fallback = "🖥️"
            [ssh]
            program = "/opt/homebrew/bin/ssh"
            extra_args = ["-o", "ServerAliveInterval=30"]
        "#);
        assert!(config.show_archived);
        assert_eq!(config.icon_fallback, "🖥️");
        assert_eq!(config.ssh.program, "/opt/homebrew/bin/ssh");
        assert_eq!(config.ssh.extra_args, ["-o", "ServerAliveInterval=30"]);
    }

    #[test]
    fn partial_ssh_section_keeps_other_defaults() {
        let config = ok("[ssh]\nextra_args = [\"-v\"]");
        assert_eq!(config.ssh.program, "ssh");
        assert_eq!(config.ssh.extra_args, ["-v"]);
    }

    #[test]
    fn unknown_keys_warn_but_do_not_fail() {
        let (config, warnings) =
            parse("themee = \"latte\"\ntheme = \"latte\"\n[ssh]\nprogam = \"x\"").unwrap();
        assert_eq!(config.theme, ThemeName::Latte);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("themee"));
        assert!(warnings[1].contains("ssh.progam"));
    }

    #[test]
    fn invalid_values_are_rejected_with_clear_message() {
        for bad in [
            "theme = \"neon\"",
            "default_sort = \"random\"",
            "show_archived = \"yes\"",
            "icon_fallback = \"ab\"",
            "icon_fallback = \"\"",
            "[ssh]\nprogram = \"\"",
            "[ssh]\nextra_args = \"-v\"",
            "theme = ",
        ] {
            assert!(parse(bad).is_err(), "should fail: {bad}");
        }
        let err = parse("theme = \"neon\"").unwrap_err().to_string();
        assert!(err.contains("neon"), "{err}");
    }

    #[test]
    fn load_error_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "theme = \"neon\"").unwrap();
        let err = format!("{:#}", load_from(&path).unwrap_err());
        assert!(err.contains(&path.display().to_string()), "{err}");
    }
}
