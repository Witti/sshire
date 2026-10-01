//! Command-line definition with `clap` (derive flavor).
//!
//! This module only describes *which* arguments exist. What the commands do
//! is decided by `main.rs` (dispatch) and the respective feature modules.

// `use` brings names from other modules/crates into the current scope.
use clap::{Args, Parser, Subcommand};

// `#[derive(...)]` is a macro that automatically generates code for traits
// at compile time. `Parser` builds a complete argument parser (incl.
// `--help`) from this struct; `Debug` allows printing with `{:?}`.
/// sshire – a TUI SSH launcher with host management, tags and a connection log.
#[derive(Debug, Parser)]
#[command(name = "sshire", version, about)]
pub struct Cli {
    /// Command to run. Without one, the TUI starts.
    // `Option<T>` is Rust's type for "no value or a value" (`None` / `Some`).
    // Here: the user may omit the subcommand.
    #[command(subcommand)]
    pub command: Option<Command>,
}

// An `enum` is a type that can be exactly *one* of several variants.
// Each variant may carry its own data (here: the command's arguments).
/// All subcommands of sshire.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the interactive TUI (default when no command is given).
    Tui,
    /// List hosts as a table.
    List {
        /// Only show hosts with this tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// Connect to a host.
    Connect {
        /// Alias of the host.
        alias: String,
    },
    /// Show the connection log, optionally for a single host.
    Log {
        /// Alias of the host; without it the entire log is shown.
        alias: Option<String>,
        /// Maximum number of entries to show.
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Create a new manual host (interactively or via flags).
    Add(AddArgs),
    /// Import hosts from `~/.ssh/config` into the database.
    Import,
    /// Export hosts as JSON to stdout (never passwords or secrets).
    Export {
        /// Output as JSON (the only format; the flag is optional).
        #[arg(long)]
        json: bool,
        /// Also export archived hosts.
        #[arg(long)]
        include_archived: bool,
    },
    /// Show the configuration file (`config.toml`): path or example.
    Config(ConfigArgs),
    /// Set or remove a host's password (hidden input, entered twice).
    Passwd(PasswdArgs),
    /// Internal helper: called by `ssh` as `SSH_ASKPASS`.
    ///
    /// ssh passes the prompt as the only argument (`argv[1]`).
    // `hide = true`: does not show up in `--help` but is still callable.
    // `allow_hyphen_values`: a prompt that starts with "-" is not a flag.
    #[command(hide = true)]
    Askpass {
        /// The prompt from ssh, e.g. "user@host's password: ".
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        prompt: Vec<String>,
    },
}

/// Arguments of `sshire config`.
#[derive(Debug, Clone, Default, Args)]
pub struct ConfigArgs {
    /// Print the path of the configuration file.
    #[arg(long, conflicts_with = "example")]
    pub path: bool,
    /// Print a commented example configuration.
    #[arg(long)]
    pub example: bool,
}

/// Arguments of `sshire passwd`.
#[derive(Debug, Clone, Default, Args)]
pub struct PasswdArgs {
    /// Alias of the host (not needed with `--master`).
    #[arg(required_unless_present = "master")]
    pub alias: Option<String>,
    /// Remove the stored password instead of setting it.
    #[arg(long, conflicts_with = "master")]
    pub delete: bool,
    /// Change the master password of the encrypted store (all passwords are
    /// re-encrypted).
    #[arg(long, conflicts_with_all = ["alias", "delete"])]
    pub master: bool,
}

/// Arguments of `sshire add`.
///
/// Without `--alias` the command asks for everything interactively; with
/// `--alias` it runs without prompts and creates the host from the given
/// flags. All values deliberately stay `String`: validation (e.g. port
/// 1–65535) is handled by `validate.rs`, so CLI and TUI show the same
/// messages.
// `#[derive(Args)]` turns a struct into a group of arguments that can be
// embedded into a subcommand.
#[derive(Debug, Clone, Default, Args)]
pub struct AddArgs {
    /// Unique name of the host (no spaces).
    #[arg(long)]
    pub alias: Option<String>,
    /// Hostname or IP address.
    #[arg(long)]
    pub host: Option<String>,
    /// Username.
    #[arg(long)]
    pub user: Option<String>,
    /// Port (1–65535).
    #[arg(long)]
    pub port: Option<String>,
    /// Icon: a single symbol, e.g. an emoji.
    #[arg(long)]
    pub icon: Option<String>,
    /// Assign a tag (repeatable: `--tag prod --tag web`).
    // `Vec<String>` with repeated `--tag`: clap collects all occurrences.
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Path to the key file (`ssh -i`).
    #[arg(long)]
    pub identity_file: Option<String>,
    /// Jump host (`ssh -J`).
    #[arg(long)]
    pub proxy_jump: Option<String>,
    /// Notes.
    #[arg(long)]
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Internally checks whether the clap definition is consistent.
        Cli::command().debug_assert();
    }

    #[test]
    fn version_flag_is_available() {
        let err = Cli::try_parse_from(["sshire", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn export_and_config_parse() {
        let cli = Cli::parse_from(["sshire", "export"]);
        assert!(matches!(
            cli.command,
            Some(Command::Export {
                json: false,
                include_archived: false
            })
        ));
        let cli = Cli::parse_from(["sshire", "export", "--json", "--include-archived"]);
        assert!(matches!(
            cli.command,
            Some(Command::Export {
                json: true,
                include_archived: true
            })
        ));
        let cli = Cli::parse_from(["sshire", "config", "--path"]);
        assert!(matches!(cli.command, Some(Command::Config(ref a)) if a.path && !a.example));
        let cli = Cli::parse_from(["sshire", "config", "--example"]);
        assert!(matches!(cli.command, Some(Command::Config(ref a)) if a.example && !a.path));
        assert!(Cli::try_parse_from(["sshire", "config", "--path", "--example"]).is_err());
    }

    #[test]
    fn no_subcommand_is_none() {
        let cli = Cli::parse_from(["sshire"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn list_parses_tag() {
        let cli = Cli::parse_from(["sshire", "list", "--tag", "prod"]);
        // `matches!` checks whether a value matches a pattern.
        assert!(matches!(
            cli.command,
            Some(Command::List { tag: Some(ref t) }) if t == "prod"
        ));
    }

    #[test]
    fn log_parses_alias_and_limit() {
        let cli = Cli::parse_from(["sshire", "log"]);
        assert!(matches!(
            cli.command,
            Some(Command::Log {
                alias: None,
                limit: 20
            })
        ));
        let cli = Cli::parse_from(["sshire", "log", "web", "--limit", "5"]);
        assert!(matches!(
            cli.command,
            Some(Command::Log { alias: Some(ref a), limit: 5 }) if a == "web"
        ));
    }

    #[test]
    fn add_parses_flags_and_repeated_tags() {
        let cli = Cli::parse_from([
            "sshire",
            "add",
            "--alias",
            "web",
            "--host",
            "web.example.invalid",
            "--user",
            "admin",
            "--port",
            "2222",
            "--icon",
            "🚀",
            "--tag",
            "prod",
            "--tag",
            "web",
            "--identity-file",
            "~/.ssh/id_test",
            "--proxy-jump",
            "jump.invalid",
            "--notes",
            "Note",
        ]);
        let Some(Command::Add(args)) = cli.command else {
            panic!("expected Add");
        };
        assert_eq!(args.alias.as_deref(), Some("web"));
        assert_eq!(args.host.as_deref(), Some("web.example.invalid"));
        assert_eq!(args.user.as_deref(), Some("admin"));
        assert_eq!(args.port.as_deref(), Some("2222"));
        assert_eq!(args.icon.as_deref(), Some("🚀"));
        assert_eq!(args.tags, ["prod", "web"]);
        assert_eq!(args.identity_file.as_deref(), Some("~/.ssh/id_test"));
        assert_eq!(args.proxy_jump.as_deref(), Some("jump.invalid"));
        assert_eq!(args.notes.as_deref(), Some("Note"));
    }

    #[test]
    fn add_without_flags_is_interactive_mode() {
        let cli = Cli::parse_from(["sshire", "add"]);
        let Some(Command::Add(args)) = cli.command else {
            panic!("expected Add");
        };
        assert!(args.alias.is_none() && args.tags.is_empty());
    }

    #[test]
    fn askpass_is_hidden_but_parseable() {
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("askpass"));
        let cli = Cli::parse_from(["sshire", "askpass", "user@host's password: "]);
        let Some(Command::Askpass { prompt }) = cli.command else {
            panic!("expected Askpass");
        };
        assert_eq!(prompt, ["user@host's password: "]);
        // Also parseable without an argument (the call then fails cleanly later).
        let cli = Cli::parse_from(["sshire", "askpass"]);
        assert!(matches!(cli.command, Some(Command::Askpass { ref prompt }) if prompt.is_empty()));
        // A prompt that starts with "-" is not an option.
        let cli = Cli::parse_from(["sshire", "askpass", "-weird prompt"]);
        assert!(matches!(
            cli.command,
            Some(Command::Askpass { ref prompt }) if prompt.as_slice() == ["-weird prompt"]
        ));
    }

    #[test]
    fn passwd_parses_alias_delete_and_master() {
        let cli = Cli::parse_from(["sshire", "passwd", "web"]);
        let Some(Command::Passwd(args)) = cli.command else {
            panic!("expected Passwd");
        };
        assert_eq!(args.alias.as_deref(), Some("web"));
        assert!(!args.delete && !args.master);

        let cli = Cli::parse_from(["sshire", "passwd", "web", "--delete"]);
        assert!(matches!(cli.command, Some(Command::Passwd(ref a)) if a.delete));

        let cli = Cli::parse_from(["sshire", "passwd", "--master"]);
        assert!(
            matches!(cli.command, Some(Command::Passwd(ref a)) if a.master && a.alias.is_none())
        );

        // Without an alias and without --master, as well as conflicting flags: error.
        assert!(Cli::try_parse_from(["sshire", "passwd"]).is_err());
        assert!(Cli::try_parse_from(["sshire", "passwd", "web", "--master"]).is_err());
        assert!(Cli::try_parse_from(["sshire", "passwd", "--master", "--delete"]).is_err());
    }
}
