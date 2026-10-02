//! Implementation of the CLI commands `list`, `connect`/`sftp`/`mount`/`umount` and `log`.
//!
//! The rendering functions (`render_host_table`, `render_log_table`) are
//! kept separate from the database and terminal so they can be tested.

use std::collections::HashMap;
use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result, bail};

use crate::cli::{AddArgs, PasswdArgs};
use crate::connect::{self, Programs, Session};
use crate::export;
use crate::paths;
use crate::secrets::{
    self, BackendKind, LockState, SecretError, SecretStore, SecretString, check_new_master,
};
use crate::sshconfig;
use crate::store::{Connection, ConnectionStatus, Host, HostSource, HostStats, Store, now_ms};
use crate::table::{Cell, Table, ansi};
use crate::timefmt;
use crate::validate::{Field, RawHost, validate_field, validate_host};

/// Shared startup path: open the DB and synchronize `~/.ssh/config`.
///
/// Sync problems are not fatal: warnings and errors go to stderr,
/// and the (possibly older) database stays usable.
pub fn open_store() -> Result<Store> {
    let (store, warnings) = open_store_collect()?;
    for warning in &warnings {
        eprintln!("Warning: {warning}");
    }
    Ok(store)
}

/// Like [`open_store`], but returns the sync warnings instead of printing them.
///
/// The TUI needs this: while it owns the screen, `eprintln!` would wreck the
/// display. It shows the warnings as a status message instead. A tuple
/// `(A, B)` bundles two return values.
pub fn open_store_collect() -> Result<(Store, Vec<String>)> {
    let db_path = paths::db_path()?;
    let mut store = Store::open(&db_path)
        .with_context(|| format!("could not open database {}", db_path.display()))?;
    // Clean up orphaned log entries (sshire was killed hard); errors do not matter.
    let _ = store.close_stale_connections(24 * 3_600_000);
    let warnings = match sshconfig::sync_default(&mut store) {
        Ok(report) => report.warnings,
        // With anyhow, `{err:#}` shows the whole error chain on one line.
        Err(err) => vec![format!("ssh_config sync failed: {err:#}")],
    };
    Ok((store, warnings))
}

/// Color only if the stream is a terminal and `NO_COLOR` is not set.
///
/// `IsTerminal` (a trait, since Rust 1.70) offers `is_terminal()` for
/// `stdout()`/`stderr()`: `true` if not redirected to a file/pipe.
fn color_enabled(is_terminal: bool) -> bool {
    // Per the convention on no-color.org, a *non-empty* value counts.
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    is_terminal && !no_color
}

/// `user@hostname[:port]`, or "(ssh_config)" for ssh_config hosts without a hostname.
pub fn target_label(host: &Host) -> String {
    let Some(hostname) = host.hostname.as_deref().filter(|h| !h.is_empty()) else {
        return "(ssh_config)".to_owned();
    };
    let mut out = String::new();
    if let Some(user) = host.user.as_deref().filter(|u| !u.is_empty()) {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(hostname);
    if let Some(port) = host.port {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out
}

/// Favorites first, then by alias (case-insensitive).
pub fn sort_hosts(hosts: &mut [Host]) {
    // `sort_by_key` with a tuple: `false < true`, hence `!favorite` for "favorites first".
    hosts.sort_by_key(|h| (!h.favorite, h.alias.to_lowercase()));
}

/// Builds the host table. `now` is the current time in ms (for "3 days ago").
pub fn render_host_table(
    hosts: &[Host],
    stats: &HashMap<i64, HostStats>,
    now: i64,
    color: bool,
) -> Table {
    let mut table = Table::new(
        &["", "", "ALIAS", "", "TARGET", "TAGS", "LAST SUCCESS"],
        color,
    );
    for host in hosts {
        let tags = host
            .tags
            .iter()
            .map(|t| format!("#{}", t.name))
            .collect::<Vec<_>>()
            .join(" ");
        let last = stats
            .get(&host.id)
            .and_then(|s| s.last_success_at)
            .map_or_else(|| "never".to_owned(), |ts| timefmt::relative_time(ts, now));
        let alias_style = if host.source == HostSource::SshConfig {
            ansi::CYAN
        } else {
            ansi::BOLD
        };
        table.push_row(vec![
            if host.favorite {
                Cell::styled("★", ansi::YELLOW)
            } else {
                Cell::plain("")
            },
            Cell::plain(host.icon.clone().unwrap_or_default()),
            Cell::styled(host.alias.clone(), alias_style),
            // 🔑: a password is stored for this host.
            Cell::plain(if host.has_password { "🔑" } else { "" }),
            Cell::plain(target_label(host)),
            Cell::styled(tags, ansi::DIM),
            Cell::styled(last, ansi::DIM),
        ]);
    }
    table
}

/// `sshire export`: all hosts as JSON text (without secrets).
pub fn export(store: &Store, include_archived: bool) -> Result<String> {
    let mut hosts = store.list_hosts(include_archived)?;
    sort_hosts(&mut hosts);
    let stats = store.host_stats()?;
    let mut json = export::export_json(&hosts, &stats)?;
    json.push('\n');
    Ok(json)
}

/// `sshire list [--tag X]`.
pub fn list(store: &Store, tag: Option<&str>) -> Result<()> {
    let mut hosts = store.list_hosts(false)?;
    if let Some(tag) = tag {
        let wanted = tag.trim_start_matches('#');
        hosts.retain(|h| h.tags.iter().any(|t| t.name.eq_ignore_ascii_case(wanted)));
    }
    if hosts.is_empty() {
        println!("No hosts found.");
        return Ok(());
    }
    sort_hosts(&mut hosts);
    let stats = store.host_stats()?;
    let color = color_enabled(std::io::stdout().is_terminal());
    // `{}` uses our `Display` implementation of the table.
    print!("{}", render_host_table(&hosts, &stats, now_ms(), color));
    Ok(())
}

/// Describes the result of a session in one sentence (without the ✔/✘ symbol).
///
/// Shared by the CLI (`connect`, `sftp`, `mount`) and the TUI.
pub fn describe_outcome(
    alias: &str,
    outcome: &connect::ConnectOutcome,
    session: &Session,
) -> String {
    let duration = timefmt::format_duration(i64::try_from(outcome.duration_ms).unwrap_or(i64::MAX));
    if let Session::Mount(target) = session {
        return match (outcome.status, outcome.exit_code, outcome.signal) {
            (ConnectionStatus::Success, ..) => {
                format!("Mounted {alias} at {}", target.mountpoint.display())
            }
            (_, Some(code), _) => format!("Mounting {alias} failed (exit {code})"),
            (_, None, Some(sig)) => format!("Mounting {alias} aborted (signal {sig})"),
            (_, None, None) => format!("Mounting {alias} failed"),
        };
    }
    let what = match session {
        Session::Sftp => "SFTP session",
        _ => "Connection",
    };
    match (outcome.status, outcome.exit_code, outcome.signal) {
        (ConnectionStatus::Success, code, _) => {
            let exit = code.map_or_else(String::new, |c| format!(", exit {c}"));
            format!("{what} to {alias} ended ({duration}{exit})")
        }
        (_, Some(code), _) => {
            format!("{what} to {alias} failed (exit {code}, {duration})")
        }
        (_, None, Some(sig)) => format!("{what} to {alias} aborted (signal {sig})"),
        (_, None, None) => format!("{what} to {alias} failed"),
    }
}

/// Looks up a host that a session may be started with.
fn usable_host(store: &Store, alias: &str) -> Result<Host> {
    let Some(host) = store.get_host_by_alias(alias)? else {
        bail!("Host \"{alias}\" not found");
    };
    if host.archived {
        bail!("Host \"{alias}\" is archived and cannot be connected to");
    }
    Ok(host)
}

/// `sshire connect`, `sshire sftp` and `sshire mount`: starts a session of
/// the given kind; returns the exit code for the sshire process.
pub fn connect(store: &Store, alias: &str, programs: &Programs, session: &Session) -> Result<i32> {
    let host = usable_host(store, alias)?;
    // Checked here as well, so the user is not asked for the master
    // password first.
    if let Session::Mount(target) = session
        && connect::mount::is_mounted(&target.mountpoint)
    {
        bail!(
            "{} is already mounted (unmount it with `sshire umount {alias}`)",
            target.mountpoint.display()
        );
    }
    // Fetch the password *before* starting ssh: the master password prompt
    // still belongs to sshire, not to the ssh session.
    let password = host_password_for_connect(store, &host)?;
    let outcome = connect::run(store, &host, password, programs, session)?;
    let color = color_enabled(std::io::stderr().is_terminal());
    let (mark, style) = match outcome.status {
        ConnectionStatus::Success => ("✔", ansi::GREEN),
        ConnectionStatus::Failed => ("✘", ansi::RED),
    };
    let detail = describe_outcome(alias, &outcome, session);
    if color {
        eprintln!("{style}{mark}{} {detail}", ansi::RESET);
    } else {
        eprintln!("{mark} {detail}");
    }
    Ok(outcome.process_exit_code())
}

/// Mount target for `sshire mount`: the given mount point or the default one.
pub fn mount_target(
    programs: &Programs,
    alias: &str,
    mountpoint: Option<&std::path::Path>,
    remote_path: Option<String>,
) -> Result<connect::MountTarget> {
    let mountpoint = match mountpoint {
        Some(path) => connect::mount::absolute(path)?,
        None => connect::mount::default_mountpoint(&programs.mount, alias)?,
    };
    Ok(connect::MountTarget {
        mountpoint,
        remote_path,
    })
}

/// `sshire umount <alias> [mountpoint]`.
///
/// The default mount point is removed again afterwards (if it is empty); a
/// mount point given explicitly is left alone.
pub fn umount(
    store: &Store,
    alias: &str,
    programs: &Programs,
    mountpoint: Option<&std::path::Path>,
) -> Result<()> {
    if store.get_host_by_alias(alias)?.is_none() {
        bail!("Host \"{alias}\" not found");
    }
    let target = mount_target(programs, alias, mountpoint, None)?;
    let path = &target.mountpoint;
    if !connect::mount::is_mounted(path) {
        bail!("Nothing is mounted at {}", path.display());
    }
    connect::mount::unmount(path)?;
    if mountpoint.is_none() {
        connect::mount::remove_mountpoint(path);
    }
    eprintln!("✔ Unmounted {alias} from {}", path.display());
    Ok(())
}

/// Fetches a host's password for connecting (`None`: none stored).
fn host_password_for_connect(store: &Store, host: &Host) -> Result<Option<SecretString>> {
    if !host.has_password {
        return Ok(None);
    }
    let mut secrets = open_secrets()?;
    unlock_with(secrets.as_mut(), false, &mut prompt_secret)?;
    let password = secrets::fetch_host_password(secrets.as_mut(), store, host)?;
    if password.is_none() {
        eprintln!(
            "Warning: a password was flagged for \"{}\", but none was found - \
             connecting without a stored password.",
            host.alias
        );
    }
    Ok(password)
}

/// Opens the platform's password store (alongside the opened database).
fn open_secrets() -> Result<Box<dyn SecretStore>> {
    let db_path = paths::db_path()?;
    Ok(secrets::open_default(&db_path)?)
}

/// Reads a secret without echo.
///
/// On a terminal, `rpassword` asks hidden via `/dev/tty`. If stdin is not a
/// terminal (e.g. `printf 'pw\npw\n' | sshire passwd web`), one line is read
/// from stdin - which makes the command scriptable and testable. In both
/// cases the prompt goes to stderr or the terminal, never to stdout.
fn prompt_secret(prompt: &str) -> Result<SecretString> {
    if std::io::stdin().is_terminal() {
        // The string is *moved*, not copied: there is only one copy in memory,
        // and it immediately belongs to the `SecretString` (which overwrites it).
        return Ok(SecretString::new(rpassword::prompt_password(prompt)?));
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    // Plenty of space up front so the buffer is not reallocated while reading.
    let mut line = String::with_capacity(512);
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        bail!("input ended before a password was read");
    }
    let trimmed = line.trim_end_matches(['\n', '\r']).len();
    line.truncate(trimmed);
    Ok(SecretString::new(line))
}

/// Unlocks the store (or sets a master password if needed).
///
/// `ask` supplies the input - [`prompt_secret`] in the program, a script in
/// tests. `allow_init`: may a *new* master password be set?
/// Not when connecting: a password flag without a master password is an
/// error state that must not be silently "repaired".
fn unlock_with(
    secrets: &mut dyn SecretStore,
    allow_init: bool,
    ask: &mut dyn FnMut(&str) -> Result<SecretString>,
) -> Result<()> {
    match secrets.lock_state()? {
        LockState::Ready => Ok(()),
        LockState::Locked => {
            let mut attempts = 0;
            loop {
                let master = ask("Master password: ")?;
                match secrets.unlock(master.expose()) {
                    Ok(()) => return Ok(()),
                    // At most three attempts, then the command gives up.
                    Err(SecretError::WrongMasterPassword) if attempts < 2 => {
                        attempts += 1;
                        eprintln!("Wrong master password, please try again.");
                    }
                    Err(err) => return Err(err.into()),
                }
            }
        }
        LockState::NeedsInit if !allow_init => bail!(
            "A password is flagged, but no master password exists - \
             please set the password again with \"sshire passwd <alias>\""
        ),
        LockState::NeedsInit => {
            eprintln!(
                "There is no master password yet. It protects all stored host \
                 passwords - choose a strong one and remember it well: without \
                 the master password the passwords cannot be recovered."
            );
            let master = ask_new_secret("New master password", ask)?;
            check_new_master(master.expose()).map_err(|msg| anyhow::anyhow!(msg))?;
            secrets.initialize(master.expose())?;
            Ok(())
        }
    }
}

/// Asks for a new secret twice and requires both entries to match.
fn ask_new_secret(
    label: &str,
    ask: &mut dyn FnMut(&str) -> Result<SecretString>,
) -> Result<SecretString> {
    let first = ask(&format!("{label}: "))?;
    let second = ask(&format!("{label} (repeat): "))?;
    if first != second {
        bail!("The two entries do not match");
    }
    Ok(first)
}

/// `sshire passwd <alias> [--delete]` or `sshire passwd --master`.
pub fn passwd(store: &Store, args: &PasswdArgs) -> Result<()> {
    let mut secrets = open_secrets()?;
    passwd_with(store, secrets.as_mut(), args, &mut prompt_secret)
}

/// Core of [`passwd`] with a swappable store and input (for tests).
fn passwd_with(
    store: &Store,
    secrets: &mut dyn SecretStore,
    args: &PasswdArgs,
    ask: &mut dyn FnMut(&str) -> Result<SecretString>,
) -> Result<()> {
    if args.master {
        return change_master(secrets, ask);
    }
    let alias = args.alias.as_deref().context("alias missing")?;
    let Some(host) = store.get_host_by_alias(alias)? else {
        bail!("Host \"{alias}\" not found");
    };

    if args.delete {
        // Removing needs no master password.
        secrets::remove_host_password(secrets, store, host.id)?;
        println!("✔ Password for \"{alias}\" removed");
        return Ok(());
    }

    unlock_with(secrets, true, ask)?;
    let password = ask_new_secret(&format!("Password for {alias}"), ask)?;
    if password.expose().is_empty() {
        bail!("The password must not be empty (to remove it: --delete)");
    }
    secrets::save_host_password(secrets, store, host.id, password.expose())?;
    println!(
        "✔ Password for \"{alias}\" saved ({})",
        secrets.kind().label()
    );
    Ok(())
}

/// Changes the master password of the encrypted store.
fn change_master(
    secrets: &mut dyn SecretStore,
    ask: &mut dyn FnMut(&str) -> Result<SecretString>,
) -> Result<()> {
    if secrets.kind() != BackendKind::Encrypted {
        bail!("There is no master password: the Keychain protects the passwords itself");
    }
    if secrets.lock_state()? == LockState::NeedsInit {
        bail!("No master password has been set yet (it is asked for with the first password)");
    }
    let old = ask("Current master password: ")?;
    let new = ask_new_secret("New master password", ask)?;
    check_new_master(new.expose()).map_err(|msg| anyhow::anyhow!(msg))?;
    secrets.change_master(old.expose(), new.expose())?;
    println!("✔ Master password changed, all passwords re-encrypted");
    Ok(())
}

/// Builds the log table; `aliases` maps host IDs to their aliases.
pub fn render_log_table(
    entries: &[Connection],
    aliases: &HashMap<i64, String>,
    color: bool,
) -> Table {
    let mut table = Table::new(&["TIME", "ALIAS", "STATUS", "DURATION", "EXIT"], color);
    for entry in entries {
        let alias = aliases.get(&entry.host_id).map_or("?", String::as_str);
        let status = match entry.status {
            Some(ConnectionStatus::Success) => Cell::styled("✔ success", ansi::GREEN),
            Some(ConnectionStatus::Failed) => Cell::styled("✘ failed", ansi::RED),
            // No end recorded yet: still running, or sshire was aborted.
            None => Cell::styled("… open", ansi::YELLOW),
        };
        table.push_row(vec![
            Cell::plain(timefmt::format_local(entry.started_at)),
            Cell::plain(alias),
            status,
            Cell::plain(
                entry
                    .duration_ms
                    .map_or_else(|| "-".to_owned(), timefmt::format_duration),
            ),
            Cell::plain(
                entry
                    .exit_code
                    .map_or_else(|| "-".to_owned(), |c| c.to_string()),
            ),
        ]);
    }
    table
}

/// `sshire log [alias] [--limit N]`.
pub fn log(store: &Store, alias: Option<&str>, limit: u32) -> Result<()> {
    let host_id = match alias {
        Some(alias) => match store.get_host_by_alias(alias)? {
            Some(host) => Some(host.id),
            None => bail!("Host \"{alias}\" not found"),
        },
        None => None,
    };
    let entries = store.recent_connections(host_id, limit)?;
    if entries.is_empty() {
        println!("No connections logged yet.");
        return Ok(());
    }
    // Resolve archived hosts too, so old entries keep a name.
    let aliases: HashMap<i64, String> = store
        .list_hosts(true)?
        .into_iter()
        .map(|h| (h.id, h.alias))
        .collect();
    let color = color_enabled(std::io::stdout().is_terminal());
    print!("{}", render_log_table(&entries, &aliases, color));
    Ok(())
}

/// Asks for a field on `input` and repeats the question until the input is
/// valid. A value already given via a flag (`preset`) is accepted without asking.
///
/// `R: BufRead` and `W: Write` are *generic* type parameters: the function
/// works with any reader/writer - with stdin/stdout in the program, with an
/// in-memory `Cursor` in tests. The alternative would be `&mut dyn BufRead`
/// (a "trait object"): that needs only one version of the function, but
/// decides at runtime which method to call. Generics are instantiated at
/// compile time for each type separately and are therefore slightly faster.
fn prompt_field<R: BufRead, W: Write>(
    field: Field,
    preset: Option<&str>,
    prompt: &str,
    input: &mut R,
    out: &mut W,
) -> Result<String> {
    if let Some(value) = preset {
        return Ok(value.to_owned());
    }
    loop {
        write!(out, "{prompt}: ")?;
        out.flush()?;
        let mut line = String::new();
        // `read_line` returns the number of bytes read; 0 means end of input.
        if input.read_line(&mut line)? == 0 {
            bail!("input ended before all fields were filled in");
        }
        let line = line.trim().to_owned();
        match validate_field(field, &line) {
            Ok(()) => return Ok(line),
            Err(message) => writeln!(out, "  ✘ {message}")?,
        }
    }
}

/// `sshire add`: creates a manual host.
///
/// * With `--alias`: non-interactive, nothing is asked.
/// * Without `--alias`: interactive prompts for alias, hostname, user, port,
///   icon and tags (values given via flags are not asked again).
///
/// The validation is the same as in the TUI form (`validate.rs`). Returns the
/// ID of the new host.
pub fn add_host<R: BufRead, W: Write>(
    store: &mut Store,
    args: &AddArgs,
    input: &mut R,
    out: &mut W,
) -> Result<i64> {
    let interactive = args.alias.is_none();
    let mut raw = RawHost {
        alias: args.alias.clone().unwrap_or_default(),
        hostname: args.host.clone().unwrap_or_default(),
        user: args.user.clone().unwrap_or_default(),
        port: args.port.clone().unwrap_or_default(),
        identity_file: args.identity_file.clone().unwrap_or_default(),
        proxy_jump: args.proxy_jump.clone().unwrap_or_default(),
        icon: args.icon.clone().unwrap_or_default(),
        notes: args.notes.clone().unwrap_or_default(),
        tags: args.tags.join(","),
        ..RawHost::default()
    };
    if interactive {
        writeln!(out, "Create a new host (leave empty to skip)")?;
        raw.alias = prompt_field(Field::Alias, args.alias.as_deref(), "Alias", input, out)?;
        raw.hostname = prompt_field(
            Field::Hostname,
            args.host.as_deref(),
            "Hostname",
            input,
            out,
        )?;
        raw.user = prompt_field(Field::User, args.user.as_deref(), "User", input, out)?;
        raw.port = prompt_field(Field::Port, args.port.as_deref(), "Port", input, out)?;
        raw.icon = prompt_field(
            Field::Icon,
            args.icon.as_deref(),
            "Icon (one symbol)",
            input,
            out,
        )?;
        if args.tags.is_empty() {
            raw.tags = prompt_field(Field::Tags, None, "Tags (comma-separated)", input, out)?;
        }
    }

    let valid = validate_host(&raw).map_err(|errors| {
        let lines: Vec<String> = errors
            .iter()
            .map(|e| format!("{}: {}", e.field.label(), e.message))
            .collect();
        anyhow::anyhow!("Invalid input:\n  {}", lines.join("\n  "))
    })?;
    // Newly created hosts are always manual; `into()` uses `From<&ValidHost> for NewHost`.
    // Host and tags in *one* transaction: either both or nothing.
    let id = store.insert_host_with_tags(&(&valid).into(), &valid.tags)?;
    writeln!(out, "✔ Host \"{}\" created", valid.alias)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewHost;
    use crate::table::display_width;

    const NOW: i64 = 1_800_000_000_000;

    fn store_with_hosts() -> Store {
        let mut store = Store::open_in_memory().unwrap();
        let mut a = NewHost::new("zeta");
        a.hostname = Some("h1.invalid".into());
        a.user = Some("bob".into());
        a.port = Some(2222);
        a.icon = Some("🚀".into());
        let za = store.insert_host(&a).unwrap();
        let aa = store.insert_host(&NewHost::new("Alpha")).unwrap();
        let fav = store.insert_host(&NewHost::new("mid")).unwrap();
        store.set_favorite(fav, true).unwrap();
        store.set_host_tags(za, &["prod"]).unwrap();
        let _ = aa;
        store
    }

    #[test]
    fn sorts_favorites_first_then_alias() {
        let store = store_with_hosts();
        let mut hosts = store.list_hosts(false).unwrap();
        sort_hosts(&mut hosts);
        let names: Vec<_> = hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(names, ["mid", "Alpha", "zeta"]);
    }

    #[test]
    pub fn target_labels() {
        let store = store_with_hosts();
        let hosts = store.list_hosts(false).unwrap();
        let zeta = hosts.iter().find(|h| h.alias == "zeta").unwrap();
        assert_eq!(target_label(zeta), "bob@h1.invalid:2222");
        let mid = hosts.iter().find(|h| h.alias == "mid").unwrap();
        assert_eq!(target_label(mid), "(ssh_config)");
    }

    #[test]
    fn host_table_has_tags_never_and_aligned_columns() {
        let store = store_with_hosts();
        let mut hosts = store.list_hosts(false).unwrap();
        sort_hosts(&mut hosts);
        let stats = HashMap::from([(
            hosts[2].id,
            HostStats {
                last_success_at: Some(NOW - 3 * 24 * 3_600_000),
                last_failure_at: None,
                total_connections: 1,
            },
        )]);
        let out = render_host_table(&hosts, &stats, NOW, false).to_string();
        assert!(out.contains("#prod"));
        assert!(out.contains("3 days ago"));
        assert!(out.contains("never"));
        assert!(out.contains('★'));
        // The "ALIAS" column starts at the same display position in every row.
        let pos = |line: &str| display_width(&line[..line.find("ALIAS").unwrap_or(0)]);
        let header_pos = pos(out.lines().next().unwrap());
        let zeta_line = out.lines().find(|l| l.contains("zeta")).unwrap();
        let before_alias = &zeta_line[..zeta_line.find("zeta").unwrap()];
        assert_eq!(display_width(before_alias), header_pos);
    }

    #[test]
    fn host_table_marks_hosts_with_password() {
        let store = store_with_hosts();
        let mut hosts = store.list_hosts(false).unwrap();
        let without = render_host_table(&hosts, &HashMap::new(), NOW, false).to_string();
        assert!(!without.contains('🔑'));
        hosts[0].has_password = true;
        let with = render_host_table(&hosts, &HashMap::new(), NOW, false).to_string();
        assert_eq!(with.matches('🔑').count(), 1);
    }

    #[test]
    fn log_table_renders_entries() {
        let entries = vec![
            Connection {
                id: 1,
                host_id: 1,
                started_at: NOW,
                ended_at: Some(NOW + 1),
                duration_ms: Some(42 * 60_000),
                exit_code: Some(255),
                status: Some(ConnectionStatus::Failed),
            },
            Connection {
                id: 2,
                host_id: 99,
                started_at: NOW,
                ended_at: None,
                duration_ms: None,
                exit_code: None,
                status: None,
            },
        ];
        let aliases = HashMap::from([(1, "web".to_owned())]);
        let out = render_log_table(&entries, &aliases, false).to_string();
        assert!(out.contains("web"));
        assert!(out.contains("failed"));
        assert!(out.contains("42 min"));
        assert!(out.contains("255"));
        assert!(out.contains("open"));
        assert!(out.contains('?'));
    }

    #[test]
    fn list_filters_by_tag_via_store_data() {
        let store = store_with_hosts();
        let hosts = store.list_hosts(false).unwrap();
        let tagged: Vec<_> = hosts
            .iter()
            .filter(|h| h.tags.iter().any(|t| t.name == "prod"))
            .collect();
        assert_eq!(tagged.len(), 1);
    }

    fn add_args() -> AddArgs {
        AddArgs::default()
    }

    #[test]
    fn add_with_flags_is_non_interactive() {
        let mut store = Store::open_in_memory().unwrap();
        let args = AddArgs {
            alias: Some("web".into()),
            host: Some("web.example.invalid".into()),
            user: Some("admin".into()),
            port: Some("2222".into()),
            icon: Some("🚀".into()),
            tags: vec!["prod".into(), "web".into()],
            identity_file: Some("~/.ssh/id_test".into()),
            proxy_jump: Some("jump.invalid".into()),
            notes: Some("Note".into()),
        };
        // Empty input: nothing may be read.
        let mut input = std::io::Cursor::new(Vec::new());
        let mut out = Vec::new();
        let id = add_host(&mut store, &args, &mut input, &mut out).unwrap();
        let host = store.get_host(id).unwrap().unwrap();
        assert_eq!(host.alias, "web");
        assert_eq!(host.source, HostSource::Manual);
        assert_eq!(host.port, Some(2222));
        assert_eq!(host.icon.as_deref(), Some("🚀"));
        assert_eq!(host.identity_file.as_deref(), Some("~/.ssh/id_test"));
        assert_eq!(host.proxy_jump.as_deref(), Some("jump.invalid"));
        assert_eq!(host.notes.as_deref(), Some("Note"));
        let tags: Vec<_> = host.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tags, ["prod", "web"]);
        assert!(String::from_utf8(out).unwrap().contains("created"));
    }

    #[test]
    fn add_with_invalid_flags_reports_all_problems_and_stores_nothing() {
        let mut store = Store::open_in_memory().unwrap();
        let args = AddArgs {
            alias: Some("bad alias".into()),
            port: Some("0".into()),
            icon: Some("ab".into()),
            ..add_args()
        };
        let mut input = std::io::Cursor::new(Vec::new());
        let err = add_host(&mut store, &args, &mut input, &mut Vec::new()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Alias") && text.contains("Port") && text.contains("Icon"));
        assert!(store.list_hosts(true).unwrap().is_empty());
    }

    #[test]
    fn add_interactive_reprompts_on_invalid_input() {
        let mut store = Store::open_in_memory().unwrap();
        // Alias: first empty, then with a space (both invalid), then valid.
        // Port: first invalid, then valid. Icon empty, tags set.
        let script = "\n\nmy host\ndb1\nh.invalid\nroot\nabc\n5432\n\nprod, db\n";
        let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();
        let id = add_host(&mut store, &add_args(), &mut input, &mut out).unwrap();
        let host = store.get_host(id).unwrap().unwrap();
        assert_eq!(host.alias, "db1");
        assert_eq!(host.hostname.as_deref(), Some("h.invalid"));
        assert_eq!(host.user.as_deref(), Some("root"));
        assert_eq!(host.port, Some(5432));
        assert_eq!(host.icon, None);
        assert_eq!(host.tags.len(), 2);
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("required"));
        assert!(shown.contains("spaces"));
        assert!(shown.contains("Port must"));
    }

    #[test]
    fn add_interactive_skips_prompts_for_given_flags_and_fails_on_eof() {
        let mut store = Store::open_in_memory().unwrap();
        let args = AddArgs {
            host: Some("h.invalid".into()),
            ..add_args()
        };
        // Only the alias is asked; then the input ends -> error.
        let mut input = std::io::Cursor::new(b"x\n".to_vec());
        let mut out = Vec::new();
        let err = add_host(&mut store, &args, &mut input, &mut out).unwrap_err();
        assert!(err.to_string().contains("input ended"));
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("Alias:"));
        assert!(!shown.contains("Hostname:"));
        assert!(store.list_hosts(true).unwrap().is_empty());
    }

    #[test]
    fn add_rejects_duplicate_alias() {
        let mut store = Store::open_in_memory().unwrap();
        let args = AddArgs {
            alias: Some("web".into()),
            ..add_args()
        };
        let mut input = std::io::Cursor::new(Vec::new());
        add_host(&mut store, &args, &mut input, &mut Vec::new()).unwrap();
        let err = add_host(&mut store, &args, &mut input, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    // ---- Passwords (passwd, unlocking) -----------------------------------

    use crate::secrets::{EncryptedStore, KdfParams, MemoryStore};

    /// Shared log of the questions asked.
    type Asked = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

    /// Input script: returns the answers in order and remembers the questions.
    fn scripted(answers: &[&str]) -> (impl FnMut(&str) -> Result<SecretString>, Asked) {
        let mut queue: std::collections::VecDeque<String> =
            answers.iter().map(|a| (*a).to_owned()).collect();
        let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = std::rc::Rc::clone(&asked);
        let ask = move |prompt: &str| {
            log.borrow_mut().push(prompt.to_owned());
            queue
                .pop_front()
                .map(SecretString::new)
                .ok_or_else(|| anyhow::anyhow!("no more input in the script"))
        };
        (ask, asked)
    }

    fn passwd_args(alias: &str) -> PasswdArgs {
        PasswdArgs {
            alias: Some(alias.into()),
            ..PasswdArgs::default()
        }
    }

    #[test]
    fn passwd_sets_and_deletes_a_password() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("web")).unwrap();
        let mut secrets = MemoryStore::default();

        let (mut ask, _) = scripted(&["s3cret", "s3cret"]);
        passwd_with(&store, &mut secrets, &passwd_args("web"), &mut ask).unwrap();
        assert!(store.get_host(id).unwrap().unwrap().has_password);
        assert_eq!(secrets.get(id).unwrap().unwrap().expose(), "s3cret");

        // --delete asks nothing (the script has no answers) and needs no unlocking.
        let (mut ask, asked) = scripted(&[]);
        let args = PasswdArgs {
            delete: true,
            ..passwd_args("web")
        };
        passwd_with(&store, &mut secrets, &args, &mut ask).unwrap();
        assert!(asked.borrow().is_empty());
        assert!(!store.get_host(id).unwrap().unwrap().has_password);
        assert!(secrets.get(id).unwrap().is_none());
    }

    #[test]
    fn passwd_rejects_mismatch_unknown_alias_and_empty() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("web")).unwrap();
        let mut secrets = MemoryStore::default();

        let (mut ask, _) = scripted(&["one", "two"]);
        let err = passwd_with(&store, &mut secrets, &passwd_args("web"), &mut ask).unwrap_err();
        assert!(err.to_string().contains("do not match"));
        assert!(!store.get_host(id).unwrap().unwrap().has_password);

        let (mut ask, _) = scripted(&[]);
        let err = passwd_with(&store, &mut secrets, &passwd_args("nope"), &mut ask).unwrap_err();
        assert!(err.to_string().contains("not found"));

        let (mut ask, _) = scripted(&["", ""]);
        assert!(passwd_with(&store, &mut secrets, &passwd_args("web"), &mut ask).is_err());
        assert!(!store.get_host(id).unwrap().unwrap().has_password);
    }

    /// Temp DB with host "web" and an encrypted store (fast KDF).
    fn encrypted_fixture() -> (tempfile::TempDir, Store, EncryptedStore, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sshire.db");
        let store = Store::open(&path).unwrap();
        let id = store.insert_host(&NewHost::new("web")).unwrap();
        let enc = EncryptedStore::open_with_params(&path, KdfParams::FAST).unwrap();
        (dir, store, enc, id)
    }

    #[test]
    fn first_passwd_on_encrypted_backend_creates_master_then_reuses_it() {
        let (dir, store, mut enc, id) = encrypted_fixture();
        // Master twice, then the host password twice.
        let (mut ask, asked) = scripted(&["master-password", "master-password", "pw", "pw"]);
        passwd_with(&store, &mut enc, &passwd_args("web"), &mut ask).unwrap();
        assert!(asked.borrow()[0].contains("master"));
        assert!(store.get_host(id).unwrap().unwrap().has_password);

        // New process: locked. Wrong twice, right once (within the 3 attempts).
        let mut again =
            EncryptedStore::open_with_params(&dir.path().join("sshire.db"), KdfParams::FAST)
                .unwrap();
        let (mut ask, asked) = scripted(&["bad", "worse", "master-password"]);
        unlock_with(&mut again, false, &mut ask).unwrap();
        assert_eq!(asked.borrow().len(), 3);
        assert_eq!(again.get(id).unwrap().unwrap().expose(), "pw");
    }

    #[test]
    fn unlock_gives_up_after_three_wrong_attempts() {
        let (dir, store, mut enc, _id) = encrypted_fixture();
        let (mut ask, _) = scripted(&["master-password", "master-password", "pw", "pw"]);
        passwd_with(&store, &mut enc, &passwd_args("web"), &mut ask).unwrap();
        let mut again =
            EncryptedStore::open_with_params(&dir.path().join("sshire.db"), KdfParams::FAST)
                .unwrap();
        let (mut ask, asked) = scripted(&["a", "b", "c", "master-password"]);
        let err = unlock_with(&mut again, false, &mut ask).unwrap_err();
        assert!(err.to_string().contains("Wrong master password"));
        assert_eq!(asked.borrow().len(), 3);
    }

    #[test]
    fn connecting_never_creates_a_master_password() {
        let (_dir, _store, mut enc, _id) = encrypted_fixture();
        let (mut ask, asked) = scripted(&["master-password", "master-password"]);
        let err = unlock_with(&mut enc, false, &mut ask).unwrap_err();
        assert!(err.to_string().contains("no master password"));
        assert!(asked.borrow().is_empty());
    }

    #[test]
    fn new_master_must_be_long_enough_and_match() {
        let (_dir, _store, mut enc, _id) = encrypted_fixture();
        let (mut ask, _) = scripted(&["short", "short"]);
        assert!(unlock_with(&mut enc, true, &mut ask).is_err());
        let (mut ask, _) = scripted(&["long enough one", "long enough two"]);
        assert!(unlock_with(&mut enc, true, &mut ask).is_err());
        assert_eq!(enc.lock_state().unwrap(), LockState::NeedsInit);
    }

    #[test]
    fn passwd_master_changes_the_master_password() {
        let (dir, store, mut enc, id) = encrypted_fixture();
        let (mut ask, _) = scripted(&["master-password", "master-password", "pw", "pw"]);
        passwd_with(&store, &mut enc, &passwd_args("web"), &mut ask).unwrap();

        let args = PasswdArgs {
            master: true,
            ..PasswdArgs::default()
        };
        let (mut ask, _) = scripted(&["master-password", "brand-new-master", "brand-new-master"]);
        passwd_with(&store, &mut enc, &args, &mut ask).unwrap();

        let mut again =
            EncryptedStore::open_with_params(&dir.path().join("sshire.db"), KdfParams::FAST)
                .unwrap();
        assert!(again.unlock("master-password").is_err());
        again.unlock("brand-new-master").unwrap();
        assert_eq!(again.get(id).unwrap().unwrap().expose(), "pw");

        // With the Keychain there is nothing to change.
        let mut memory = MemoryStore::default();
        let (mut ask, _) = scripted(&[]);
        assert!(passwd_with(&store, &mut memory, &args, &mut ask).is_err());
    }
}
