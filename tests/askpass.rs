//! Integration tests for `sshire askpass` and the password hand-over to ssh.
//!
//! They start the real, compiled binary (`CARGO_BIN_EXE_sshire`).
//! The test server here speaks the socket protocol *itself* (send a token
//! line, receive password + `\n`) - so it also serves as an independent
//! description of the protocol.
//!
//! Important: no test may hang on a real terminal. For non-password prompts
//! the client opens `/dev/tty`; to make that fail deterministically without a
//! terminal (even when the tests run from a shell with a terminal), every test
//! starts the process in a *new session* (`setsid`) - which has no controlling
//! terminal.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sshire");
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PASSWORD: &str = "integration-test-password";

/// Starts `cmd` in a new session, waits at most 20 s and returns the output.
fn run_detached(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `setsid` is async-signal-safe and is called in the child process
    // between `fork` and `exec`; it does not modify any memory of the parent process.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("process starts");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return child.wait_with_output().expect("output");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("process hangs (timeout exceeded)");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn askpass_cmd(prompt: &str, sock: Option<&Path>, token: Option<&str>) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["askpass", prompt]);
    cmd.env_remove("SSH_ASKPASS_PROMPT");
    cmd.env_remove("SSHIRE_ASKPASS_SOCK");
    cmd.env_remove("SSHIRE_ASKPASS_TOKEN");
    if let Some(sock) = sock {
        cmd.env("SSHIRE_ASKPASS_SOCK", sock);
    }
    if let Some(token) = token {
        cmd.env("SSHIRE_ASKPASS_TOKEN", token);
    }
    cmd
}

/// A mini server following the protocol: read the token line, send the password on a match.
/// Returns the number of handled connections.
fn spawn_server(listener: UnixListener, stop_after: Duration) -> thread::JoinHandle<usize> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + stop_after;
        let mut handled = 0;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    handled += 1;
                    stream.set_nonblocking(false).unwrap();
                    let mut line = String::new();
                    let mut reader = BufReader::new(&stream);
                    reader.read_line(&mut line).unwrap();
                    if line.trim_end() == TOKEN {
                        let mut out = &stream;
                        out.write_all(PASSWORD.as_bytes()).unwrap();
                        out.write_all(b"\n").unwrap();
                    }
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        handled
    })
}

fn socket_dir() -> (tempfile::TempDir, std::path::PathBuf, UnixListener) {
    let dir = tempfile::Builder::new()
        .prefix("ss-it-")
        .tempdir_in("/tmp")
        .unwrap();
    let path = dir.path().join("a.sock");
    let listener = UnixListener::bind(&path).unwrap();
    (dir, path, listener)
}

#[test]
fn askpass_prints_the_password_for_a_host_password_prompt() {
    let (_dir, sock, listener) = socket_dir();
    let server = spawn_server(listener, Duration::from_secs(3));
    let out = run_detached(askpass_cmd(
        "user@host's password: ",
        Some(&sock),
        Some(TOKEN),
    ));
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{PASSWORD}\n")
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains(PASSWORD));
    assert_eq!(server.join().unwrap(), 1);
}

#[test]
fn askpass_fails_without_output_on_wrong_token() {
    let (_dir, sock, listener) = socket_dir();
    let server = spawn_server(listener, Duration::from_secs(2));
    let out = run_detached(askpass_cmd(
        "user@host's password: ",
        Some(&sock),
        Some("wrong-token"),
    ));
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "nothing may be written to stdout on errors"
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains(PASSWORD));
    server.join().unwrap();
}

#[test]
fn askpass_fails_when_the_server_is_gone() {
    let (dir, sock, listener) = socket_dir();
    drop(listener);
    let out = run_detached(askpass_cmd("Password:", Some(&sock), Some(TOKEN)));
    drop(dir);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn non_password_prompts_never_contact_the_server_and_fail_without_tty() {
    let (_dir, sock, listener) = socket_dir();
    let server = spawn_server(listener, Duration::from_millis(1500));
    for prompt in [
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
        "Enter passphrase for key '/home/me/.ssh/id_password': ",
        "Verification code: ",
    ] {
        let out = run_detached(askpass_cmd(prompt, Some(&sock), Some(TOKEN)));
        assert!(
            !out.status.success(),
            "without a terminal the prompt must fail: {prompt}"
        );
        assert!(out.stdout.is_empty(), "{prompt}");
    }
    // The host password must never have been requested for these prompts.
    assert_eq!(server.join().unwrap(), 0);
}

#[test]
fn password_prompt_without_sshire_environment_falls_back_to_tty_and_fails_without_one() {
    let out = run_detached(askpass_cmd("user@host's password: ", None, None));
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn info_prompts_do_not_block() {
    let mut cmd = askpass_cmd("Authenticated to example", None, None);
    cmd.env("SSH_ASKPASS_PROMPT", "none");
    let out = run_detached(cmd);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn confirm_prompts_fail_without_tty() {
    let mut cmd = askpass_cmd("Allow use of key?", None, None);
    cmd.env("SSH_ASKPASS_PROMPT", "confirm");
    let out = run_detached(cmd);
    assert!(!out.status.success());
}

// ---------------------------------------------------------------------------
// End to end: sshire connect with a *fake* ssh (no network)
// ---------------------------------------------------------------------------

/// Isolated environment for sshire: data, home and temp live in temp directories.
struct Sandbox {
    root: tempfile::TempDir,
    tmp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for sub in ["home", "bin", "capture"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        // Short path so the socket path safely fits in `sun_path`.
        let tmp = tempfile::Builder::new()
            .prefix("ss-e2e-")
            .tempdir_in("/tmp")
            .unwrap();
        Self { root, tmp }
    }

    fn capture(&self, name: &str) -> std::path::PathBuf {
        self.root.path().join("capture").join(name)
    }

    /// Writes an "ssh" that calls askpass like the real ssh (without a network).
    fn install_fake_ssh(&self) {
        let script = r#"#!/bin/sh
printf '%s\n' "$@" > "$CAPTURE/args"
env > "$CAPTURE/env"
pw=$("$SSH_ASKPASS" "someone@host.invalid's password: ") || exit 255
printf '%s' "$pw" > "$CAPTURE/pw"
# A second fetch must fail (one-shot).
if "$SSH_ASKPASS" "someone@host.invalid's password: " > "$CAPTURE/second" 2>/dev/null; then
    echo second-delivery-worked > "$CAPTURE/second_ok"
fi
exit 0
"#;
        let path = self.root.path().join("bin/ssh");
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn sshire(&self, args: &[&str], stdin: &str) -> Output {
        let home = self.root.path().join("home");
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env("TMPDIR", self.tmp.path())
            .env("SSHIRE_SECRET_BACKEND", "encrypted")
            .env("CAPTURE", self.root.path().join("capture"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().join("bin").display()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn connect_hands_the_password_to_ssh_through_askpass_only() {
    let sb = Sandbox::new();
    sb.install_fake_ssh();
    const HOST_PW: &str = "e2e-host-password-42";
    const MASTER: &str = "e2e-master-password";

    let add = sb.sshire(
        &[
            "add",
            "--alias",
            "web",
            "--host",
            "host.invalid",
            "--user",
            "someone",
        ],
        "",
    );
    assert!(add.status.success(), "{}", text(&add.stderr));

    // First use: set the master password (twice), then the password (twice).
    let stdin = format!("{MASTER}\n{MASTER}\n{HOST_PW}\n{HOST_PW}\n");
    let passwd = sb.sshire(&["passwd", "web"], &stdin);
    assert!(passwd.status.success(), "{}", text(&passwd.stderr));
    for stream in [&passwd.stdout, &passwd.stderr] {
        assert!(!text(stream).contains(HOST_PW));
    }

    // Connect: master password to unlock, then the fake ssh runs.
    let connect = sb.sshire(&["connect", "web"], &format!("{MASTER}\n"));
    assert!(connect.status.success(), "{}", text(&connect.stderr));
    for stream in [&connect.stdout, &connect.stderr] {
        assert!(!text(stream).contains(HOST_PW));
    }

    // ssh received the password via askpass ...
    assert_eq!(fs::read_to_string(sb.capture("pw")).unwrap(), HOST_PW);
    // ... but it appears neither in the arguments nor in the environment.
    let args = fs::read_to_string(sb.capture("args")).unwrap();
    let env = fs::read_to_string(sb.capture("env")).unwrap();
    assert!(!args.contains(HOST_PW) && !env.contains(HOST_PW));
    let arg_lines: Vec<&str> = args.lines().collect();
    assert_eq!(&arg_lines[..2], ["-o", "NumberOfPasswordPrompts=1"]);
    assert!(env.contains("SSH_ASKPASS_REQUIRE=force"));
    assert!(env.contains("SSHIRE_ASKPASS_SOCK="));
    // One-shot: the second fetch returned nothing.
    assert!(!sb.capture("second_ok").exists());
    // Cleaned up: no askpass directory is left behind.
    let leftovers: Vec<_> = fs::read_dir(sb.tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("sshire-askpass-")
        })
        .collect();
    assert!(leftovers.is_empty(), "left over: {leftovers:?}");
}

#[test]
fn connect_with_wrong_master_password_does_not_start_ssh() {
    let sb = Sandbox::new();
    sb.install_fake_ssh();
    let add = sb.sshire(&["add", "--alias", "web", "--host", "host.invalid"], "");
    assert!(add.status.success());
    let set = sb.sshire(
        &["passwd", "web"],
        "right-master-pw\nright-master-pw\nhostpw\nhostpw\n",
    );
    assert!(set.status.success(), "{}", text(&set.stderr));

    let connect = sb.sshire(&["connect", "web"], "nope\nnope2\nnope3\n");
    assert!(!connect.status.success());
    assert!(text(&connect.stderr).contains("Wrong master password"));
    assert!(
        !sb.capture("args").exists(),
        "ssh must not have been started"
    );
}

#[test]
fn passwd_delete_removes_the_password_and_connect_runs_without_askpass() {
    let sb = Sandbox::new();
    sb.install_fake_ssh();
    assert!(
        sb.sshire(&["add", "--alias", "web", "--host", "host.invalid"], "")
            .status
            .success()
    );
    assert!(
        sb.sshire(
            &["passwd", "web"],
            "right-master-pw\nright-master-pw\nhostpw\nhostpw\n"
        )
        .status
        .success()
    );
    let del = sb.sshire(&["passwd", "web", "--delete"], "");
    assert!(del.status.success(), "{}", text(&del.stderr));
    // Without a password: no unlock needed; the fake ssh finds no askpass
    // and fails when calling "$SSH_ASKPASS" (empty) - exactly what should be visible here.
    let connect = sb.sshire(&["connect", "web"], "");
    let args = fs::read_to_string(sb.capture("args")).unwrap();
    assert!(!args.contains("NumberOfPasswordPrompts"));
    assert!(!connect.status.success());
}
