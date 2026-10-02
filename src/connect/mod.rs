//! Starting and logging SSH connections.
//!
//! * `askpass` - hands ssh the password over a private Unix socket (T7)
//! * `sigguard` - lets sshire survive Ctrl-C while ssh is running
//! * `command` - builds the ssh/sftp/sshfs invocation from a host (pure functions)
//! * `mount` - mount points and unmounting for sshfs
//! * this module - starts the program, evaluates the exit status, writes the log
//!
//! There is deliberately no terminal logic here: the TUI (T5) must suspend the
//! terminal *before* [`run`] and restore it afterwards.

pub mod askpass;
mod command;
pub mod mount;
mod sigguard;

use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};

use crate::config::{Config, MountConfig, SftpConfig, SshConfig};
use crate::store::{ConnectionStatus, Host, Store};

pub use command::{SshInvocation, build_invocation, build_mount_invocation, build_sftp_invocation};

use crate::secrets::SecretString;
use askpass::AskpassServer;

/// Exit code ssh returns for its own errors (connection setup, auth, ...).
const SSH_ERROR_EXIT_CODE: i32 = 255;

// Custom `Display` for the status: `impl fmt::Display for T` makes `T`
// formattable with `{}` (and provides `.to_string()` automatically).
// `f` is the output buffer; `write!` writes into it and returns a `fmt::Result`.
impl fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// What kind of session to start with a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Session {
    /// An interactive ssh session.
    Shell,
    /// An interactive sftp session.
    Sftp,
    /// Mount the host with sshfs.
    Mount(MountTarget),
}

/// Where and what to mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTarget {
    /// Local directory to mount at (created if needed).
    pub mountpoint: PathBuf,
    /// Remote directory; `None` is the home directory of the user.
    pub remote_path: Option<String>,
}

/// The program settings of all session kinds (`[ssh]`, `[sftp]`, `[mount]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Programs {
    pub ssh: SshConfig,
    pub sftp: SftpConfig,
    pub mount: MountConfig,
}

impl From<&Config> for Programs {
    fn from(config: &Config) -> Self {
        Self {
            ssh: config.ssh.clone(),
            sftp: config.sftp.clone(),
            mount: config.mount.clone(),
        }
    }
}

/// Result of a finished connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectOutcome {
    /// Exit code of ssh; `None` if ssh was terminated by a signal.
    pub exit_code: Option<i32>,
    /// Signal number if ssh was terminated by a signal (otherwise `None`).
    pub signal: Option<i32>,
    /// Verdict according to [`classify`].
    pub status: ConnectionStatus,
    /// Measured duration in milliseconds.
    pub duration_ms: u64,
}

impl ConnectOutcome {
    /// Exit code sshire itself should return: ssh's own, or for a signal
    /// the shell convention `128 + signal`.
    pub fn process_exit_code(&self) -> i32 {
        match (self.exit_code, self.signal) {
            (Some(code), _) => code,
            (None, Some(sig)) => 128 + sig,
            (None, None) => SSH_ERROR_EXIT_CODE,
        }
    }
}

/// Classifies an exit code: 255 and "no code" (signal) => `Failed`,
/// everything else => `Success` (the connection was up, the remote exit code
/// does not matter).
pub fn classify(exit: Option<i32>) -> ConnectionStatus {
    match exit {
        Some(SSH_ERROR_EXIT_CODE) | None => ConnectionStatus::Failed,
        Some(_) => ConnectionStatus::Success,
    }
}

/// Classification for sshfs: it reports every failure with a non-zero exit
/// code (usually 1, not 255 like ssh); success means "mounted".
fn classify_mount(exit: Option<i32>) -> ConnectionStatus {
    match exit {
        Some(0) => ConnectionStatus::Success,
        _ => ConnectionStatus::Failed,
    }
}

/// Starts a session of the given kind with `host` and logs it.
///
/// `password` is the host password (fetched by the caller *before* leaving the
/// terminal). It is never written into arguments or the environment, but is
/// delivered through [`AskpassServer`] as soon as ssh asks for it. sftp and
/// sshfs start ssh themselves; it inherits the askpass variables.
///
/// `programs` holds the program settings from the configuration.
pub fn run(
    store: &Store,
    host: &Host,
    password: Option<SecretString>,
    programs: &Programs,
    session: &Session,
) -> Result<ConnectOutcome> {
    let mut invocation = match session {
        Session::Shell => build_invocation(host, &programs.ssh)?,
        Session::Sftp => build_sftp_invocation(host, &programs.ssh, &programs.sftp)?,
        Session::Mount(target) => build_mount_invocation(
            host,
            &programs.ssh,
            &programs.mount,
            target.remote_path.as_deref(),
            &target.mountpoint,
        )?,
    };
    let classify_exit = match session {
        Session::Mount(_) => classify_mount,
        Session::Shell | Session::Sftp => classify,
    };
    // The underscore-prefixed name `_askpass` keeps the server alive until the
    // end of the function (a bare `_` would drop the value immediately!). After
    // that, its `Drop` cleans up the thread, socket and directory - even on
    // early returns via `?`.
    let _askpass = match password {
        Some(password) => {
            let server =
                AskpassServer::start(password).context("could not create the askpass socket")?;
            let exe = std::env::current_exe()
                .context("could not determine the path of the sshire binary")?;
            apply_askpass(&mut invocation, &server, &exe)?;
            Some(server)
        }
        None => None,
    };
    // The mount point is created last, so no early error leaves it behind;
    // if this call created it, a failed mount removes it again.
    let created_mountpoint = match session {
        Session::Mount(target) if mount::prepare_mountpoint(&target.mountpoint)? => {
            Some(target.mountpoint.as_path())
        }
        _ => None,
    };
    let outcome = run_invocation(store, host.id, &invocation, classify_exit);
    let mounted = matches!(&outcome, Ok(o) if o.status == ConnectionStatus::Success);
    if let (Some(path), false) = (created_mountpoint, mounted) {
        mount::remove_mountpoint(path);
    }
    outcome
}

/// Extends the ssh invocation with everything password hand-over needs:
/// the askpass variables (path, token - never the password) and
/// `-o NumberOfPasswordPrompts=1` (a wrong password aborts instead of
/// retrying).
fn apply_askpass(
    invocation: &mut SshInvocation,
    server: &AskpassServer,
    exe: &std::path::Path,
) -> Result<()> {
    invocation.env.extend(server.env_for(exe)?);
    // Options must come *before* the target, so insert at the front. `splice`
    // replaces the (empty) range 0..0 with the new elements.
    let extra = askpass::SSH_ARGS.iter().map(|a| (*a).to_owned());
    invocation.args.splice(0..0, extra);
    Ok(())
}

/// Starts a finished invocation and maintains the log. Separate from [`run`]
/// so tests can substitute a fake program for `ssh`.
///
/// `classify_exit` turns the exit code into the log verdict ([`classify`]
/// for ssh and sftp).
fn run_invocation(
    store: &Store,
    host_id: i64,
    invocation: &SshInvocation,
    classify_exit: fn(Option<i32>) -> ConnectionStatus,
) -> Result<ConnectOutcome> {
    // From here on sshire survives Ctrl-C (SIGINT) and Ctrl-\ (SIGQUIT); ssh
    // receives the signals normally. The guard lives until the end of the
    // function (Drop switches it off). It is created *before* the log entry so
    // an error here does not leave an open entry behind.
    let _signal_guard = sigguard::SignalGuard::new().context("signal protection failed")?;
    let log_id = store
        .start_connection(host_id)
        .context("could not record the connection in the log")?;
    let started = Instant::now();

    // `Command` is a builder: `new` creates it, each method sets something
    // and returns `&mut Command`, so calls can be chained.
    let mut cmd = Command::new(&invocation.program);
    cmd.args(&invocation.args);
    // `envs` accepts anything that can be iterated as (name, value) pairs.
    cmd.envs(invocation.env.iter().map(|(k, v)| (k, v)));
    // stdin/stdout/stderr are *inherited by default*: ssh talks directly
    // to the user's terminal (needed for interactive sessions).
    // `status()` starts the process and waits until it exits
    // (unlike `spawn()`, which returns immediately).
    let status = match cmd.status() {
        Ok(status) => status,
        Err(err) => {
            // Program could not be started (e.g. not found): close the entry anyway.
            let _ = store.finish_connection(log_id, None, ConnectionStatus::Failed);
            return Err(err).with_context(|| format!("could not start \"{}\"", invocation.program));
        }
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    // `ExitStatus::code()` is `None` if the process ended due to a signal.
    let exit_code = status.code();
    let signal = signal_of(&status);
    let outcome_status = classify_exit(exit_code);
    store
        .finish_connection(log_id, exit_code, outcome_status)
        .context("could not finish the connection log")?;

    Ok(ConnectOutcome {
        exit_code,
        signal,
        status: outcome_status,
        duration_ms,
    })
}

// `cfg` attributes compile code only on certain platforms.
// `ExitStatusExt` (Unix-specific) provides `signal()`. sshire runs on
// macOS/Linux; the second variant keeps the code compilable elsewhere.
#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewHost;

    fn fake(program: &str, args: &[&str]) -> SshInvocation {
        SshInvocation {
            program: program.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            env: Vec::new(),
        }
    }

    #[test]
    fn classify_follows_plan() {
        assert_eq!(classify(Some(0)), ConnectionStatus::Success);
        assert_eq!(classify(Some(1)), ConnectionStatus::Success);
        assert_eq!(classify(Some(130)), ConnectionStatus::Success);
        assert_eq!(classify(Some(255)), ConnectionStatus::Failed);
        assert_eq!(classify(None), ConnectionStatus::Failed);
    }

    #[test]
    fn process_exit_code_prefers_exit_then_signal() {
        let base = ConnectOutcome {
            exit_code: Some(3),
            signal: None,
            status: ConnectionStatus::Success,
            duration_ms: 0,
        };
        assert_eq!(base.process_exit_code(), 3);
        let sig = ConnectOutcome {
            exit_code: None,
            signal: Some(9),
            ..base
        };
        assert_eq!(sig.process_exit_code(), 137);
    }

    #[test]
    fn success_is_logged() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out = run_invocation(&store, id, &fake("true", &[]), classify).unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.status, ConnectionStatus::Success);
        let log = store.recent_connections(Some(id), 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].status, Some(ConnectionStatus::Success));
        assert_eq!(log[0].exit_code, Some(0));
        assert!(log[0].ended_at.is_some());
    }

    #[test]
    fn exit_255_is_failed() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out = run_invocation(&store, id, &fake("sh", &["-c", "exit 255"]), classify).unwrap();
        assert_eq!(out.exit_code, Some(255));
        assert_eq!(out.status, ConnectionStatus::Failed);
        let log = store.recent_connections(Some(id), 10).unwrap();
        assert_eq!(log[0].status, Some(ConnectionStatus::Failed));
    }

    #[test]
    fn other_exit_code_is_success() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out = run_invocation(&store, id, &fake("sh", &["-c", "exit 7"]), classify).unwrap();
        assert_eq!(out.exit_code, Some(7));
        assert_eq!(out.status, ConnectionStatus::Success);
    }

    #[cfg(unix)]
    #[test]
    fn signal_death_is_failed_without_exit_code() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out = run_invocation(&store, id, &fake("sh", &["-c", "kill -9 $$"]), classify).unwrap();
        assert_eq!(out.exit_code, None);
        assert_eq!(out.signal, Some(9));
        assert_eq!(out.status, ConnectionStatus::Failed);
        let log = store.recent_connections(Some(id), 10).unwrap();
        assert_eq!(log[0].exit_code, None);
        assert_eq!(log[0].status, Some(ConnectionStatus::Failed));
    }

    #[test]
    fn missing_program_closes_log_as_failed_and_errors() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let res = run_invocation(
            &store,
            id,
            &fake("sshire-no-such-program-xyz", &[]),
            classify,
        );
        assert!(res.is_err());
        let log = store.recent_connections(Some(id), 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].status, Some(ConnectionStatus::Failed));
        assert!(log[0].ended_at.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn sshire_survives_sigint_during_connection() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        // The child sends SIGINT to its parent process (= this test).
        // Without the guard the test process would die.
        let out = run_invocation(
            &store,
            id,
            &fake("sh", &["-c", "kill -INT $PPID; exit 0"]),
            classify,
        )
        .unwrap();
        assert_eq!(out.status, ConnectionStatus::Success);
        let log = store.recent_connections(Some(id), 10).unwrap();
        assert_eq!(log[0].status, Some(ConnectionStatus::Success));
        assert!(log[0].ended_at.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn child_still_dies_from_sigint() {
        // Proof that the guard does not hand SIGINT-ignoring down to the child (no SIG_IGN):
        // the child sends itself SIGINT and must die from it.
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out = run_invocation(
            &store,
            id,
            &fake("sh", &["-c", "kill -INT $$; sleep 1"]),
            classify,
        )
        .unwrap();
        assert_eq!(out.signal, Some(2));
        assert_eq!(out.status, ConnectionStatus::Failed);
    }

    #[test]
    fn askpass_is_wired_before_the_target_and_without_the_password() {
        use crate::store::{AuthMethod, HostSource};
        let host = Host {
            id: 1,
            alias: "web".into(),
            hostname: Some("web.example.invalid".into()),
            user: Some("admin".into()),
            port: Some(2222),
            identity_file: None,
            proxy_jump: None,
            extra_args: None,
            icon: None,
            color: None,
            notes: None,
            source: HostSource::Manual,
            favorite: false,
            archived: false,
            auth_method: AuthMethod::Password,
            has_password: true,
            created_at: 0,
            updated_at: 0,
            tags: Vec::new(),
        };
        let mut invocation = build_invocation(&host, &crate::config::SshConfig::default()).unwrap();
        let before = invocation.args.clone();
        let server = AskpassServer::start(SecretString::new("top-secret-pw".into())).unwrap();
        apply_askpass(
            &mut invocation,
            &server,
            std::path::Path::new("/opt/sshire"),
        )
        .unwrap();

        assert_eq!(&invocation.args[..2], ["-o", "NumberOfPasswordPrompts=1"]);
        assert_eq!(&invocation.args[2..], before.as_slice());
        // The target is still last.
        assert_eq!(invocation.args.last().unwrap(), "admin@web.example.invalid");
        let has = |name: &str| invocation.env.iter().any(|(k, _)| k == name);
        assert!(has("SSH_ASKPASS") && has("SSH_ASKPASS_REQUIRE"));
        assert!(has(askpass::ENV_SOCK) && has(askpass::ENV_TOKEN));
        // Neither arguments nor environment (nor the Debug format) contain the password.
        let dump = format!("{invocation:?}");
        assert!(!dump.contains("top-secret-pw"));
    }

    #[test]
    fn mount_classification_only_accepts_zero() {
        assert_eq!(classify_mount(Some(0)), ConnectionStatus::Success);
        assert_eq!(classify_mount(Some(1)), ConnectionStatus::Failed);
        assert_eq!(classify_mount(None), ConnectionStatus::Failed);
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let out =
            run_invocation(&store, id, &fake("sh", &["-c", "exit 1"]), classify_mount).unwrap();
        assert_eq!(out.status, ConnectionStatus::Failed);
    }

    #[test]
    fn display_status() {
        assert_eq!(ConnectionStatus::Success.to_string(), "success");
        assert_eq!(ConnectionStatus::Failed.to_string(), "failed");
    }
}
