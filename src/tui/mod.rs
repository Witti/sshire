//! Terminal UI built on `ratatui` and `crossterm`.
//!
//! * `app`   – state and logic (no rendering, easy to test)
//! * `event` – key presses → actions
//! * `ui`    – rendering of the main view
//! * `overlays` – rendering of the form, picker, confirmation prompts and dialogs
//! * `form`  – state of the host form
//! * `emoji` – curated symbol list and icon picker state
//! * `input` – single-line text input field and masked password field
//! * `secret` – state of the password dialog (`p`, master password)
//! * `theme` – colors
//! * this module – terminal setup/restore and the event loop
//!
//! # Restoring the terminal cleanly
//!
//! The TUI switches the terminal into *raw mode* (keys arrive one at a time,
//! without echo) and onto the *alternate screen* (a separate screen that
//! disappears on exit). If that stays in place after a crash, the shell is
//! unusable. Three safeguards:
//!
//! 1. [`TerminalGuard`] – an RAII guard: its `Drop` restores the terminal,
//!    no matter how the scope is left (return, `?`, panic with unwinding).
//! 2. A panic hook ([`install_panic_hook`]) restores the terminal *before* the
//!    panic message, so the message lands readably on the normal screen.
//! 3. Before `connect::run`, the terminal is explicitly released so that
//!    ssh finds a normal terminal.

mod app;
mod emoji;
mod event;
mod form;
mod input;
mod overlays;
mod secret;
mod theme;
mod ui;

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self as ct_event, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::commands;
use crate::config::Config;
use crate::connect::Session;
use crate::secrets::SecretString;
use crate::store::Host;

use self::app::{App, Effect, StatusKind};

type Term = Terminal<CrosstermBackend<Stdout>>;

/// How long the loop waits for a key before it "ticks"
/// (lets status messages expire).
const TICK: Duration = Duration::from_millis(250);

/// Puts the terminal back into its normal state. May run multiple times.
///
/// Errors are deliberately ignored (`let _ =`): we are usually already
/// cleaning up (panic/error path) and can't do anything better.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}

/// Enables raw mode and the alternate screen.
fn enter_terminal() -> Result<()> {
    enable_raw_mode().context("Could not enable raw mode")?;
    execute!(io::stdout(), EnterAlternateScreen).context("Could not enable alternate screen")?;
    Ok(())
}

/// RAII guard: while it lives, the terminal is in TUI mode; when it is
/// dropped (`Drop`), the terminal is restored.
///
/// RAII means "resource = lifetime of a value": we don't have to write a
/// `restore()` at every return point, Rust calls `drop` automatically.
struct TerminalGuard;

impl TerminalGuard {
    /// Enters TUI mode. If that fails halfway, `enter_terminal` does not
    /// clean up – so only create the guard *after* success.
    fn new() -> Result<Self> {
        enter_terminal()?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Installs a panic hook that restores the terminal.
///
/// A *panic hook* is a function Rust calls on every panic, before the
/// program unwinds. `take_hook` returns the previous hook (it prints the
/// message); we install a new one that cleans up first and then calls the
/// old one. `Box<dyn Fn…>` is a function object on the heap; `move` moves
/// `previous` into the closure.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

/// Starts the TUI and runs until the user quits.
///
/// `config` comes from `config.toml`; `config_warnings` (e.g. unknown
/// keys) appear in the status bar like the sync warnings.
pub fn run(config: Config, config_warnings: Vec<String>) -> Result<()> {
    // The theme applies for the whole run and is set before the first draw.
    theme::init(theme::Theme::by_name(config.theme));
    // Before switching the terminal: `open_store` can fail, and errors
    // should appear on the normal screen. We collect sync warnings
    // and show them in the status bar.
    let (store, mut warnings) = commands::open_store_collect()?;
    warnings.splice(0..0, config_warnings);
    // The platform's password storage (Keychain or encrypted DB). It is opened
    // after the store because the database is already migrated by then.
    let secrets = crate::secrets::open_default(&crate::paths::db_path()?)
        .context("Could not open password storage")?;
    let mut app = App::with_secrets(store, secrets, config, &warnings)?;

    install_panic_hook();
    let _guard = TerminalGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))
        .context("Could not initialize terminal")?;
    terminal.clear().context("Could not clear terminal")?;

    event_loop(&mut terminal, &mut app)
    // `run` ends here: `_guard` is dropped and restores the terminal.
}

/// The main loop: draw → wait for an event → update state.
fn event_loop(terminal: &mut Term, app: &mut App) -> Result<()> {
    loop {
        terminal
            .draw(|frame| ui::draw(frame, app))
            .context("Drawing failed")?;

        // `poll` waits at most `TICK` for an event; `false` = timeout.
        if !ct_event::poll(TICK).context("Could not read terminal event")? {
            app.tick();
            continue;
        }
        // Other events (e.g. resizing) need nothing: the next loop
        // iteration redraws anyway.
        if let Event::Key(key) = ct_event::read().context("Could not read terminal event")? {
            let has_filter = !app.query.is_empty();
            let Some(action) = event::key_to_action(app.mode, has_filter, key) else {
                continue;
            };
            match app.update(action) {
                Effect::None => {}
                Effect::Quit => return Ok(()),
                Effect::Connect {
                    host,
                    password,
                    session,
                } => {
                    connect_to(terminal, app, &host, password, &session)?;
                }
                Effect::Unmount { alias, mountpoint } => unmount(app, &alias, &mountpoint),
            }
        }
    }
}

/// Unmounts a host. The unmount tools run with captured output, so the TUI
/// keeps the terminal; the result shows up as a status message.
fn unmount(app: &mut App, alias: &str, mountpoint: &std::path::Path) {
    let (kind, text) = match crate::connect::mount::unmount(mountpoint) {
        Ok(()) => {
            crate::connect::mount::remove_mountpoint(mountpoint);
            (
                StatusKind::Success,
                format!("✔ Unmounted {alias} from {}", mountpoint.display()),
            )
        }
        Err(err) => (StatusKind::Error, format!("✘ {err:#}")),
    };
    app.finish_connect(kind, text);
}

/// Releases the terminal, starts the session (on the main thread, as
/// `connect::run` requires) and restores the TUI afterwards.
fn connect_to(
    terminal: &mut Term,
    app: &mut App,
    host: &Host,
    password: Option<SecretString>,
    session: &Session,
) -> Result<()> {
    restore_terminal();
    // Notice above the session on the normal screen.
    match session {
        Session::Shell => println!("→ connecting to {} …", host.alias),
        Session::Sftp => println!("→ opening SFTP session to {} …", host.alias),
        Session::Mount(target) => println!(
            "→ mounting {} at {} …",
            host.alias,
            target.mountpoint.display()
        ),
    }

    // `app.store()` is only visible in tests; that's why `App` exposes the store via
    // `connect_host` instead of handing it out.
    let result = app.run_connect(host, password, session);

    // Restore the terminal – even if the connection failed.
    enter_terminal()?;
    // Discard keys typed while ssh was running, otherwise they "leak" into the TUI.
    while ct_event::poll(Duration::ZERO).unwrap_or(false) {
        let _ = ct_event::read();
    }
    // Screen contents are unknown: redraw completely.
    terminal.clear().context("Could not clear terminal")?;

    let (kind, text) = match result {
        Ok(outcome) => {
            let kind = match outcome.status {
                crate::store::ConnectionStatus::Success => StatusKind::Success,
                crate::store::ConnectionStatus::Failed => StatusKind::Error,
            };
            let mark = if kind == StatusKind::Success {
                "✔"
            } else {
                "✘"
            };
            (
                kind,
                format!(
                    "{mark} {}",
                    commands::describe_outcome(&host.alias, &outcome, session)
                ),
            )
        }
        Err(err) => (
            StatusKind::Error,
            format!("✘ Could not connect to {}: {err:#}", host.alias),
        ),
    };
    app.finish_connect(kind, text);
    Ok(())
}
