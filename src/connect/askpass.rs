//! Password hand-over to `ssh` via `SSH_ASKPASS` and a Unix socket.
//!
//! # Why not simply an argument or environment variable?
//!
//! * **argv** (the command line) can be read by any user on the machine with
//!   `ps`.
//! * **Environment variables** are inherited by all child processes, easily
//!   end up in logs and crash reports, and are visible via
//!   `/proc/<pid>/environ` or `ps eww`.
//! * **Files** leave traces on disk.
//!
//! The password must therefore not appear in any of those places. `ssh` offers
//! a hook for exactly this: if `SSH_ASKPASS` is set, ssh starts the named
//! program when it needs a password and reads the answer from its stdout.
//! We point it at *ourselves*.
//!
//! Important: ssh starts `SSH_ASKPASS` *directly* as a program with the prompt
//! as the only argument (`sshire "user@host's password: "`) - there is no way
//! to add extra arguments such as `askpass`. That is why
//! [`implicit_askpass_prompt`] recognises this invocation in `main`: if the
//! variables `SSHIRE_ASKPASS_SOCK`/`_TOKEN` are set and there is exactly one
//! argument that is not a subcommand, it is the prompt. (The hidden subcommand
//! `sshire askpass <prompt>` also exists for tests and manual experiments.)
//!
//! # Flow
//!
//! ```text
//!  sshire (parent)                 ssh                    sshire askpass
//!  ───────────────                 ───                    ──────────────
//!  fetch password from Keychain
//!  0700 directory + socket,
//!  random token, server thread
//!  start ssh ───────────────────▶  needs a password
//!                                  starts askpass ──────▶ reads SOCK/TOKEN from env
//!  thread: check token  ◀───────────────────────────────  sends "<token>\n"
//!  send password + "\n" ────────────────────────────────▶ writes it to stdout
//!                                  reads stdout  ◀───────  exit 0
//! ```
//!
//! The environment holds only the path and token - the password itself travels
//! exclusively through the socket.
//!
//! # Safeguards
//!
//! * **Directory 0700**: only the current user can reach the socket.
//! * **Token**: 32 random bytes. Without the token the server delivers nothing.
//! * **Constant-time comparison** (`subtle`): an ordinary comparison stops at
//!   the first wrong byte; how long it takes then reveals how many bytes
//!   matched (a *timing attack*). The constant-time comparison always takes
//!   the same time.
//! * **One-shot**: after the first successful delivery the server hands out
//!   nothing more. If the password is wrong, ssh fails (with
//!   `NumberOfPasswordPrompts=1`) instead of retrying endlessly.
//! * **Limited attempts** and length limits for the token line.
//! * **Cleanup via RAII**: [`AskpassServer`] stops the thread in `Drop`
//!   and deletes the directory - even on errors and panics.
//!
//! # Threads
//!
//! `thread::spawn` starts parallel execution. With `move`, the closure is
//! *given ownership* of the values it needs (the thread may outlive the
//! calling function, so it cannot merely borrow anything). The returned
//! `JoinHandle` lets us wait for it to finish later (`join`).
//! `Arc<AtomicBool>` is a flag owned jointly by several threads, here the
//! stop signal.
//!
//! # Limits
//!
//! Anyone running as the *same user* can debug ssh processes anyway, or read
//! `SSHIRE_ASKPASS_TOKEN` and thereby fetch the password as long as it has not
//! been delivered yet. Another user or a filesystem leak cannot get at it. With
//! several hops (ProxyJump) the first password prompt gets the password - the
//! second fails on purpose.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use zeroize::{Zeroize, Zeroizing};

use crate::secrets::{MAX_SECRET_LEN, SecretString, encode_hex};

/// Environment variable holding the socket path.
pub const ENV_SOCK: &str = "SSHIRE_ASKPASS_SOCK";
/// Environment variable holding the token.
pub const ENV_TOKEN: &str = "SSHIRE_ASKPASS_TOKEN";
/// Set by OpenSSH: `confirm` (yes/no question) or `none` (just a message).
const ENV_PROMPT_KIND: &str = "SSH_ASKPASS_PROMPT";

/// Additional ssh arguments: at most *one* password attempt.
pub const SSH_ARGS: [&str; 2] = ["-o", "NumberOfPasswordPrompts=1"];

/// File name of the socket in the private directory (short: path length is limited).
const SOCKET_NAME: &str = "a.sock";
/// Maximum socket path length (`sun_path` is 104 bytes on macOS, 108 on Linux).
const MAX_SOCKET_PATH: usize = 100;
/// Length of the token in bytes (twice as long as hex).
const TOKEN_BYTES: usize = 32;
/// Longest accepted token line (token as hex + newline, with some headroom).
const MAX_TOKEN_LINE: u64 = 128;
/// After this many failed connections the server gives up.
const MAX_FAILED_ATTEMPTS: u32 = 8;
/// How often the server thread checks for new connections / the stop signal.
const POLL_INTERVAL: Duration = Duration::from_millis(25);
/// Time limit per connection on the server side (blocks only that one thread).
const SERVER_IO_TIMEOUT: Duration = Duration::from_secs(2);
/// Time limit of the client (`sshire askpass`) so ssh never hangs forever.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Server (runs in the sshire parent process while ssh is running)
// ---------------------------------------------------------------------------

/// The socket server including its cleanup logic. As long as the object
/// lives, ssh can fetch the password; once it is dropped, everything is gone.
///
/// Deliberately no `Debug`: the token must not show up in logs.
pub struct AskpassServer {
    /// The 0700 directory; `TempDir` deletes it on drop. The field is kept
    /// only for its `Drop` (hence the underscore).
    _dir: TempDir,
    socket_path: PathBuf,
    token: String,
    /// Stop signal for the thread.
    shutdown: Arc<AtomicBool>,
    /// Was the password delivered? (Only tests read this flag.)
    #[cfg(test)]
    delivered: Arc<AtomicBool>,
    /// Handle for waiting on the thread. An `Option` so `drop` can take it
    /// out with `take()` and call `join` (`join` consumes the handle).
    thread: Option<JoinHandle<()>>,
}

impl AskpassServer {
    /// Starts the server with the password to deliver.
    ///
    /// The password is *moved* into the thread and overwritten there after
    /// delivery (or on shutdown).
    pub fn start(password: SecretString) -> io::Result<Self> {
        let dir = make_private_dir()?;
        let socket_path = dir.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, Permissions::from_mode(0o600))?;
        // Non-blocking: `accept` returns immediately if nobody is waiting.
        // That lets the thread check the stop signal regularly.
        listener.set_nonblocking(true)?;

        let token = encode_hex(&crate::secrets::random_bytes::<TOKEN_BYTES>().map_err(to_io)?);
        let shutdown = Arc::new(AtomicBool::new(false));
        let delivered = Arc::new(AtomicBool::new(false));

        // Clones of the `Arc`s and the token for the thread (`Arc::clone` copies
        // only the pointer, not the flag).
        let thread_token = token.clone();
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_delivered = Arc::clone(&delivered);
        let handle = thread::Builder::new()
            .name("askpass-server".to_owned())
            // `move`: the closure takes ownership of everything it uses.
            .spawn(move || {
                serve(
                    &listener,
                    &thread_token,
                    &password,
                    &thread_shutdown,
                    &thread_delivered,
                );
            })?;

        Ok(Self {
            _dir: dir,
            socket_path,
            token,
            shutdown,
            #[cfg(test)]
            delivered,
            thread: Some(handle),
        })
    }

    /// Path of the socket.
    #[cfg(test)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The token.
    #[cfg(test)]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Path of the private directory.
    #[cfg(test)]
    pub fn dir_path(&self) -> &Path {
        self._dir.path()
    }

    /// Was the password already delivered?
    #[cfg(test)]
    pub fn was_delivered(&self) -> bool {
        self.delivered.load(Ordering::Acquire)
    }

    /// Environment variables that ssh (and thereby `sshire askpass`) needs.
    ///
    /// `exe` is the absolute path of the running sshire binary. The
    /// password is *not* included here - only the socket path and token.
    pub fn env_for(&self, exe: &Path) -> Result<Vec<(String, String)>> {
        let to_text = |path: &Path| -> Result<String> {
            path.to_str()
                .map(str::to_owned)
                .context("path is not valid UTF-8")
        };
        Ok(vec![
            ("SSH_ASKPASS".to_owned(), to_text(exe)?),
            // `force`: ssh uses askpass even with a terminal (OpenSSH 8.4+).
            ("SSH_ASKPASS_REQUIRE".to_owned(), "force".to_owned()),
            (ENV_SOCK.to_owned(), to_text(&self.socket_path)?),
            (ENV_TOKEN.to_owned(), self.token.clone()),
        ])
    }
}

impl Drop for AskpassServer {
    /// RAII cleanup: stop the thread, wait for it, delete the directory.
    ///
    /// `Drop::drop` runs automatically when the value leaves its scope -
    /// even on an early return with `?` or on a panic.
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            // An error (panic in the thread) can no longer be remedied here.
            let _ = handle.join();
        }
        // After that, `self._dir` (TempDir) automatically deletes the directory together with the socket.
    }
}

/// Converts a secret error into an `io::Error` (for `start`).
fn to_io(err: crate::secrets::SecretError) -> io::Error {
    io::Error::other(err.to_string())
}

/// Creates a directory with mode 0700 in which the socket path is short enough.
///
/// Candidates in this order: `XDG_RUNTIME_DIR` (Linux: private, RAM only),
/// the default temp directory, `/tmp`.
fn make_private_dir() -> io::Result<TempDir> {
    let mut bases: Vec<Option<PathBuf>> = Vec::new();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    if let Some(runtime) = runtime.filter(|dir| dir.is_dir()) {
        bases.push(Some(runtime));
    }
    bases.push(None); // default temp directory
    bases.push(Some(PathBuf::from("/tmp")));

    let mut last_error = io::Error::other("no suitable directory for the socket");
    for base in bases {
        let mut builder = tempfile::Builder::new();
        builder.prefix("sshire-askpass-");
        let created = match &base {
            Some(path) => builder.tempdir_in(path),
            None => builder.tempdir(),
        };
        match created {
            Ok(dir) if dir.path().join(SOCKET_NAME).as_os_str().len() <= MAX_SOCKET_PATH => {
                // `tempfile` already creates it with 0700; we set it explicitly to be safe.
                fs::set_permissions(dir.path(), Permissions::from_mode(0o700))?;
                return Ok(dir);
            }
            // Path too long: `dir` is dropped (and deleted) here, next candidate.
            Ok(_) => {}
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// Result of handling a single connection.
enum Outcome {
    /// Password was sent.
    Delivered,
    /// Wrong or missing token.
    Rejected,
    /// I/O error (client vanished, timeout, ...).
    Failed,
}

/// Main loop of the server thread.
fn serve(
    listener: &UnixListener,
    token: &str,
    password: &SecretString,
    shutdown: &AtomicBool,
    delivered: &AtomicBool,
) {
    let mut failures = 0_u32;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => match handle_connection(stream, token, password) {
                Outcome::Delivered => {
                    delivered.store(true, Ordering::Release);
                    // One-shot: no further password from here on. When the thread
                    // exits, the password is overwritten as well.
                    return;
                }
                Outcome::Rejected | Outcome::Failed => {
                    failures += 1;
                    if failures >= MAX_FAILED_ATTEMPTS {
                        return;
                    }
                }
            },
            // Nobody is waiting: sleep briefly and check the stop signal again.
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            // Real error on the listener: give up.
            Err(_) => return,
        }
    }
}

/// Handles one connection: read the token, verify it, send the password.
fn handle_connection(stream: UnixStream, token: &str, password: &SecretString) -> Outcome {
    // On macOS the accepted connection inherits the listener's non-blocking
    // mode; we want normal, blocking reads with a timeout.
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(SERVER_IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(SERVER_IO_TIMEOUT)).is_err()
    {
        return Outcome::Failed;
    }

    // Read the token line, but at most `MAX_TOKEN_LINE` bytes: `take` limits
    // the reader so a client cannot send data endlessly.
    let mut line = Vec::with_capacity(MAX_TOKEN_LINE as usize);
    let mut reader = BufReader::new((&stream).take(MAX_TOKEN_LINE));
    match reader.read_until(b'\n', &mut line) {
        Ok(_) if line.last() == Some(&b'\n') => {
            line.pop();
        }
        // No line ending (limit reached, connection closed early): reject.
        Ok(_) => return Outcome::Rejected,
        Err(_) => return Outcome::Failed,
    }

    // Constant-time comparison: `ct_eq` returns a `Choice` (0 or 1) that is
    // only converted to a `bool` at the end. (That the *length* of the
    // token is known is harmless: it is fixed.)
    let matches: bool = line.as_slice().ct_eq(token.as_bytes()).into();
    if !matches {
        return Outcome::Rejected;
    }

    let mut out = &stream;
    let sent = out
        .write_all(password.expose().as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush());
    if sent.is_ok() {
        Outcome::Delivered
    } else {
        Outcome::Failed
    }
}

// ---------------------------------------------------------------------------
// Client (`sshire askpass <prompt>`, started by ssh)
// ---------------------------------------------------------------------------

/// Asks the server for the password.
///
/// A wrong token, an already delivered password or a timeout results in an
/// error (never an empty password).
pub fn fetch_password(socket: &Path, token: &str) -> io::Result<SecretString> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT))?;
    stream.write_all(token.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    // Fixed buffer instead of a growing `Vec`: this avoids scattered copies
    // when growing; `Zeroizing` overwrites it at the end.
    let mut buf = Zeroizing::new([0_u8; MAX_SECRET_LEN + 2]);
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response is too long",
            ));
        }
        let read = stream.read(&mut buf[len..])?;
        if read == 0 {
            break;
        }
        len += read;
    }
    // Expected: "<password>\n". Anything else (including an empty response =
    // server rejected or one-shot already used up) is an error.
    if len < 2 || buf[len - 1] != b'\n' {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no password received",
        ));
    }
    match String::from_utf8(buf[..len - 1].to_vec()) {
        Ok(text) => Ok(SecretString::new(text)),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "password is not valid text",
            ))
        }
    }
}

/// Is this the password prompt for the *host* (`user@host's password: `)?
///
/// Deliberately strict: the prompt must end with `password:` and must not be
/// a passphrase prompt. Otherwise a host name or key path that happens to
/// contain "password" (`Are you sure ... password.example.com ...?`) could
/// deliver the password to the wrong question.
pub fn is_host_password_prompt(prompt: &str) -> bool {
    let lower = prompt.trim_end().to_lowercase();
    lower.ends_with("password:") && !lower.contains("passphrase")
}

/// May the answer to this prompt be typed visibly?
///
/// Only yes/no questions (host key confirmation). Everything else - passphrase,
/// PIN, one-time code - is read hidden (when in doubt, prefer no echo).
fn echo_allowed(prompt: &str) -> bool {
    prompt.to_lowercase().contains("(yes/no")
}

/// Kind of question according to OpenSSH (`SSH_ASKPASS_PROMPT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    /// Normal question: print the answer to stdout.
    Ask,
    /// Yes/no confirmation: only the exit code counts.
    Confirm,
    /// Plain message: display it, read nothing.
    Info,
}

impl PromptKind {
    fn from_env(value: Option<&str>) -> Self {
        match value {
            Some("confirm") => Self::Confirm,
            Some("none") => Self::Info,
            _ => Self::Ask,
        }
    }
}

/// Recognises the invocation by ssh: `sshire "<prompt>"` with the askpass variables set.
///
/// * `args`: the command line *including* the program name (`args[0]`)
/// * `env_set`: are `SSHIRE_ASKPASS_SOCK` and `SSHIRE_ASKPASS_TOKEN` set?
/// * `subcommands`: names of the real subcommands (these are never a prompt)
///
/// Returns the prompt or `None` (then the normal CLI runs).
pub fn implicit_askpass_prompt(
    args: &[String],
    env_set: bool,
    subcommands: &[&str],
) -> Option<String> {
    if !env_set || args.len() != 2 {
        return None;
    }
    let arg = args[1].as_str();
    if arg.starts_with('-') || subcommands.contains(&arg) {
        return None;
    }
    Some(arg.to_owned())
}

/// Entry point for askpass mode (`sshire "<prompt>"` or `sshire askpass <prompt>`).
///
/// * Host password prompt and socket variables set → fetch the password from
///   the server and write it to stdout.
/// * Anything else (host key question, key passphrase, ...) → show it to the
///   user via `/dev/tty` and output their answer. This is necessary because
///   `SSH_ASKPASS_REQUIRE=force` redirects *all* ssh questions here.
///
/// Every error comes back as an `Err`; nothing is written to stdout then and
/// the process exits with a non-zero exit code.
pub fn run_client(prompt: &str) -> Result<()> {
    let kind = PromptKind::from_env(std::env::var(ENV_PROMPT_KIND).ok().as_deref());
    match kind {
        PromptKind::Info => return show_message(prompt),
        PromptKind::Confirm => return confirm_on_tty(prompt),
        PromptKind::Ask => {}
    }

    if is_host_password_prompt(prompt) {
        let sock = std::env::var_os(ENV_SOCK);
        let token = std::env::var(ENV_TOKEN).ok();
        if let (Some(sock), Some(token)) = (sock, token) {
            let password = fetch_password(Path::new(&sock), &token)
                .context("could not fetch the password from the sshire parent process")?;
            return write_stdout(password.expose());
        }
        // Not started by sshire (no variables): treat like any other prompt.
    }

    let answer = prompt_on_tty(prompt).context("input via /dev/tty is not possible")?;
    write_stdout(&answer)
}

/// Writes `text` + newline to stdout unbuffered.
///
/// We duplicate the file descriptor and write directly: Rust's `stdout()`
/// buffers line by line and would leave a copy of the password on the heap.
fn write_stdout(text: &str) -> Result<()> {
    let fd = io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .context("stdout not available")?;
    let mut out = File::from(fd);
    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// Opens the user's terminal. Without a terminal (no TTY) this is an error -
/// waiting for input would take forever anyway.
fn open_tty() -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open("/dev/tty")
}

/// Shows the prompt and reads the answer from the terminal (hidden, except for yes/no).
fn prompt_on_tty(prompt: &str) -> io::Result<Zeroizing<String>> {
    if echo_allowed(prompt) {
        let mut tty = open_tty()?;
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        let mut line = Zeroizing::new(String::new());
        BufReader::new(&tty).read_line(&mut line)?;
        // Strip the line ending (without reallocating the buffer).
        let trimmed = line.trim_end_matches(['\n', '\r']).len();
        line.truncate(trimmed);
        Ok(line)
    } else {
        // `rpassword` turns off echo on the terminal and reads from /dev/tty.
        // The result moves straight into `Zeroizing`.
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }
}

/// `SSH_ASKPASS_PROMPT=none`: show the message, read nothing.
fn show_message(prompt: &str) -> Result<()> {
    match open_tty() {
        Ok(mut tty) => writeln!(tty, "{prompt}")?,
        Err(_) => eprintln!("{prompt}"),
    }
    Ok(())
}

/// `SSH_ASKPASS_PROMPT=confirm`: yes/no on the terminal; "yes" = success (exit 0).
fn confirm_on_tty(prompt: &str) -> Result<()> {
    let mut tty = open_tty().context("confirmation via /dev/tty is not possible")?;
    write!(tty, "{prompt} [y/N] ")?;
    tty.flush()?;
    let mut line = String::new();
    BufReader::new(&tty).read_line(&mut line)?;
    if matches!(
        line.trim().to_lowercase().as_str(),
        "y" | "yes" | "j" | "ja"
    ) {
        Ok(())
    } else {
        bail!("declined")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn server(password: &str) -> AskpassServer {
        AskpassServer::start(SecretString::new(password.to_owned())).unwrap()
    }

    #[test]
    fn correct_token_delivers_the_password() {
        let srv = server("s3cret pässword");
        let got = fetch_password(srv.socket_path(), srv.token()).unwrap();
        assert_eq!(got.expose(), "s3cret pässword");
        assert!(wait_until(|| srv.was_delivered()));
    }

    #[test]
    fn wrong_token_is_rejected_and_server_keeps_listening() {
        let srv = server("pw");
        let bad = fetch_password(srv.socket_path(), "not-the-token");
        assert!(bad.is_err());
        assert!(!srv.was_delivered());
        // The correct client still gets through afterwards.
        let good = fetch_password(srv.socket_path(), srv.token()).unwrap();
        assert_eq!(good.expose(), "pw");
    }

    #[test]
    fn token_with_wrong_length_or_prefix_is_rejected() {
        let srv = server("pw");
        let token = srv.token().to_owned();
        for attempt in [&token[..token.len() - 1], &format!("{token}0"), ""] {
            assert!(fetch_password(srv.socket_path(), attempt).is_err());
        }
        assert!(!srv.was_delivered());
    }

    #[test]
    fn delivery_is_one_shot() {
        let srv = server("pw");
        assert!(fetch_password(srv.socket_path(), srv.token()).is_ok());
        assert!(wait_until(|| srv.was_delivered()));
        // Second attempt with the correct token: nothing more (socket already closed).
        assert!(fetch_password(srv.socket_path(), srv.token()).is_err());
    }

    #[test]
    fn oversized_token_line_is_rejected() {
        let srv = server("pw");
        let mut stream = UnixStream::connect(srv.socket_path()).unwrap();
        stream.write_all(&vec![b'a'; 4096]).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        assert!(reply.is_empty());
        assert!(!srv.was_delivered());
    }

    #[test]
    fn server_gives_up_after_too_many_failures() {
        let srv = server("pw");
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let _ = fetch_password(srv.socket_path(), "wrong");
        }
        // By now the thread has ended; even the correct token no longer helps.
        thread::sleep(Duration::from_millis(100));
        assert!(fetch_password(srv.socket_path(), srv.token()).is_err());
        assert!(!srv.was_delivered());
    }

    #[test]
    fn directory_is_private_and_removed_on_drop() {
        let srv = server("pw");
        let dir = srv.dir_path().to_owned();
        let sock = srv.socket_path().to_owned();
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let sock_mode = fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(sock_mode, 0o600);
        assert!(sock.as_os_str().len() <= MAX_SOCKET_PATH);
        drop(srv);
        assert!(!dir.exists(), "directory must be cleaned up");
    }

    #[test]
    fn drop_stops_an_idle_server_quickly() {
        let srv = server("pw");
        let started = Instant::now();
        drop(srv);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn drop_stops_server_even_if_a_client_hangs() {
        let srv = server("pw");
        // Client connects but never sends a token: at most the time limit.
        let _idle = UnixStream::connect(srv.socket_path()).unwrap();
        let started = Instant::now();
        drop(srv);
        assert!(started.elapsed() < SERVER_IO_TIMEOUT + Duration::from_secs(1));
    }

    #[test]
    fn env_contains_no_password_and_forces_askpass() {
        let srv = server("super-secret-value");
        let env = srv.env_for(Path::new("/usr/local/bin/sshire")).unwrap();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("SSH_ASKPASS"), Some("/usr/local/bin/sshire"));
        assert_eq!(get("SSH_ASKPASS_REQUIRE"), Some("force"));
        assert_eq!(get(ENV_TOKEN), Some(srv.token()));
        assert!(get(ENV_SOCK).unwrap().ends_with(SOCKET_NAME));
        assert!(
            env.iter()
                .all(|(k, v)| !k.contains("super-secret") && !v.contains("super-secret"))
        );
        assert!(SSH_ARGS.iter().all(|a| !a.contains("super-secret")));
        assert_eq!(srv.token().len(), TOKEN_BYTES * 2);
    }

    #[test]
    fn tokens_differ_between_servers() {
        let (a, b) = (server("x"), server("x"));
        assert_ne!(a.token(), b.token());
    }

    #[test]
    fn password_prompt_detection_is_strict() {
        for yes in [
            "user@host's password: ",
            "Password:",
            "Password: ",
            "(user@host) Password: ",
            "root@10.0.0.1's password:",
        ] {
            assert!(is_host_password_prompt(yes), "{yes}");
        }
        for no in [
            "Enter passphrase for key '/home/me/.ssh/id_password': ",
            "Enter passphrase for key '/home/me/.ssh/id_ed25519': ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "The authenticity of host 'password.example.com' can't be established. (yes/no)? ",
            "Verification code: ",
            "Enter PIN for 'PIV Card': ",
            "password",
            "",
        ] {
            assert!(!is_host_password_prompt(no), "{no}");
        }
    }

    #[test]
    fn ssh_style_invocation_is_recognised_only_with_environment() {
        let args =
            |list: &[&str]| -> Vec<String> { list.iter().map(|a| (*a).to_owned()).collect() };
        let subs = ["tui", "list", "connect", "passwd", "askpass", "help"];
        let prompt = "user@host's password: ";
        assert_eq!(
            implicit_askpass_prompt(&args(&["sshire", prompt]), true, &subs).as_deref(),
            Some(prompt)
        );
        // Prompts without spaces ("Password:") count too.
        assert_eq!(
            implicit_askpass_prompt(&args(&["sshire", "Password:"]), true, &subs).as_deref(),
            Some("Password:")
        );
        // Without variables: normal CLI.
        assert!(implicit_askpass_prompt(&args(&["sshire", prompt]), false, &subs).is_none());
        // Subcommands, flags and other argument counts are never a prompt.
        assert!(implicit_askpass_prompt(&args(&["sshire", "list"]), true, &subs).is_none());
        assert!(implicit_askpass_prompt(&args(&["sshire", "--help"]), true, &subs).is_none());
        assert!(implicit_askpass_prompt(&args(&["sshire"]), true, &subs).is_none());
        assert!(implicit_askpass_prompt(&args(&["sshire", "a", "b"]), true, &subs).is_none());
    }

    #[test]
    fn echo_only_for_yes_no_questions() {
        assert!(echo_allowed(
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
        ));
        assert!(!echo_allowed("Enter passphrase for key 'x': "));
        assert!(!echo_allowed("Verification code: "));
    }

    #[test]
    fn prompt_kind_follows_openssh_env() {
        assert_eq!(PromptKind::from_env(None), PromptKind::Ask);
        assert_eq!(PromptKind::from_env(Some("confirm")), PromptKind::Confirm);
        assert_eq!(PromptKind::from_env(Some("none")), PromptKind::Info);
        assert_eq!(PromptKind::from_env(Some("other")), PromptKind::Ask);
    }

    /// Waits up to 2 s for a condition to become true (the server thread
    /// sets its flag only shortly after sending).
    fn wait_until(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        false
    }
}
