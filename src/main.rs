//! Entry point of sshire: parses the command line and dispatches the work.

// `mod x;` includes the file `x.rs` or `x/mod.rs` as a module.
// Without a `mod` line the compiler would ignore the file entirely.
mod cli;
mod commands;
mod config;
mod connect;
mod export;
mod paths;
mod secrets;
mod sshconfig;
mod store;
mod table;
mod timefmt;
mod tui;
mod validate;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cli::{Cli, Command};
use crate::connect::{Programs, Session};
use crate::store::Store;

// `ExitCode` controls the process's exit code. `Result<ExitCode>`: on
// `Err` Rust prints the error and exits with code 1; on `Ok(code)` exactly
// that code is used (e.g. ssh's exit code).
fn main() -> Result<ExitCode> {
    // ssh starts SSH_ASKPASS *without* a subcommand: `sshire "<prompt>"`. This
    // must be detected before clap parsing (clap would reject the prompt as an
    // unknown subcommand).
    if let Some(prompt) = askpass_prompt_from_ssh() {
        return Ok(run_askpass(&[prompt]));
    }

    // Reads `std::env::args`, validates them and returns a `Cli`.
    // On errors or `--help`, clap terminates the program itself.
    let cli = Cli::parse();

    // `match` forces us to handle *all* variants of the enum.
    // `unwrap_or(Command::Tui)`: without a subcommand the TUI is started.
    match cli.command.unwrap_or(Command::Tui) {
        // The `config` command doesn't need the loaded configuration (it might
        // be broken and should still be displayable).
        Command::Config(args) => run_config(&args).map(|()| ExitCode::SUCCESS),
        Command::Tui => {
            let (config, warnings) = config::load()?;
            tui::run(config, warnings).map(|()| ExitCode::SUCCESS)
        }
        // `ref`-free pattern with field names: binds the variant's fields.
        Command::List { tag } => {
            let store = commands::open_store()?;
            commands::list(&store, tag.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Connect { alias } => run_session(&alias, |_| Ok(Session::Shell)),
        Command::Sftp { alias } => run_session(&alias, |_| Ok(Session::Sftp)),
        Command::Mount(args) => run_session(&args.alias, |programs| {
            let target = commands::mount_target(
                programs,
                &args.alias,
                args.mountpoint.as_deref(),
                args.path,
            )?;
            Ok(Session::Mount(target))
        }),
        Command::Umount { alias, mountpoint } => {
            let store = commands::open_store()?;
            let programs = Programs::from(&load_config_cli()?);
            commands::umount(&store, &alias, &programs, mountpoint.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Log { alias, limit } => {
            let store = commands::open_store()?;
            commands::log(&store, alias.as_deref(), limit)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Add(args) => {
            let mut store = commands::open_store()?;
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let mut output = std::io::stdout();
            commands::add_host(&mut store, &args, &mut input, &mut output)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Import => run_import().map(|()| ExitCode::SUCCESS),
        Command::Export {
            include_archived, ..
        } => {
            let store = commands::open_store()?;
            // Without `--json` there is no other format: JSON is the default.
            print!("{}", commands::export(&store, include_archived)?);
            Ok(ExitCode::SUCCESS)
        }
        Command::Passwd(args) => {
            let store = commands::open_store()?;
            commands::passwd(&store, &args)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Askpass { prompt } => Ok(run_askpass(&prompt)),
    }
}

/// `sshire connect | sftp | mount`: starts a session with a host and returns
/// the exit code of the started program.
///
/// `session` builds the session kind from the loaded program settings (the
/// mount point depends on `[mount] dir`).
fn run_session(
    alias: &str,
    session: impl FnOnce(&Programs) -> Result<Session>,
) -> Result<ExitCode> {
    let store = commands::open_store()?;
    let programs = Programs::from(&load_config_cli()?);
    let session = session(&programs)?;
    let code = commands::connect(&store, alias, &programs, &session)?;
    // Exit codes are 0..=255; anything else is mapped to 255.
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(255)))
}

/// Checks whether ssh started us as `SSH_ASKPASS` (see `connect::askpass`).
fn askpass_prompt_from_ssh() -> Option<String> {
    use clap::CommandFactory;
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let env_set = std::env::var_os(connect::askpass::ENV_SOCK).is_some()
        && std::env::var_os(connect::askpass::ENV_TOKEN).is_some();
    let command = Cli::command();
    let mut names: Vec<&str> = command
        .get_subcommands()
        .map(clap::Command::get_name)
        .collect();
    names.push("help");
    connect::askpass::implicit_askpass_prompt(&args, env_set, &names)
}

/// Askpass mode: started by ssh, not by the user.
///
/// Deliberately *without* `open_store` and without a database: the helper only
/// needs the socket from the environment. Errors go to stderr (without
/// secrets), nothing is written to stdout, and the exit code is ≠ 0 – ssh
/// treats that as "no answer".
fn run_askpass(prompt: &[String]) -> ExitCode {
    // `join` concatenates the parts with spaces (normally it is a single argument).
    match connect::askpass::run_client(&prompt.join(" ")) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sshire askpass: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the configuration for CLI commands; warnings go to stderr.
fn load_config_cli() -> Result<config::Config> {
    let (config, warnings) = config::load()?;
    for warning in &warnings {
        eprintln!("Warning: {warning}");
    }
    Ok(config)
}

/// `sshire config --path | --example`.
fn run_config(args: &cli::ConfigArgs) -> Result<()> {
    if args.example {
        print!("{}", config::EXAMPLE_CONFIG);
    } else {
        // Without a flag and with `--path` it's the same: print the path.
        println!("{}", config::config_path()?.display());
    }
    Ok(())
}

/// `sshire import`: reads `~/.ssh/config` (read-only) and reconciles it with the DB.
fn run_import() -> Result<()> {
    // `with_context` attaches a sentence to the error that explains *what* went wrong.
    let db_path = paths::db_path()?;
    let mut store = Store::open(&db_path)
        .with_context(|| format!("Could not open database {}", db_path.display()))?;
    let report = sshconfig::sync_default(&mut store)?;

    println!("ssh_config import complete");
    println!("  created/updated: {}", report.upserted);
    println!("  archived:        {}", report.archived);
    println!("  skipped:         {}", report.skipped);
    // `for` over `&Vec` only borrows the entries.
    for warning in &report.warnings {
        eprintln!("  Warning: {warning}");
    }
    Ok(())
}
