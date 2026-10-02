//! Shared helpers for the integration tests: an isolated sandbox in which
//! the real `sshire` binary runs, plus fake `ssh`/`sftp`/`sshfs` programs.
//!
//! Every sandbox has its own home, data, config and temp directory, so the
//! tests never touch the user's real files and can run in parallel. The fake
//! programs record their arguments and environment in a capture directory
//! and fetch the password through askpass exactly like the real ssh would.

// Each test crate only uses some of the helpers.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_sshire");

/// Master password used by [`Sandbox::set_password`].
pub const MASTER: &str = "sandbox-master-password";

/// A fake program: records arguments, environment and (if askpass is
/// configured) the delivered password, then exits with `$FAKE_EXIT` (default 0).
///
/// The file names in the capture directory are `<program>.args`,
/// `<program>.env` and `<program>.pw`.
const FAKE_PROGRAM: &str = r#"#!/bin/sh
name=$(basename "$0")
printf '%s\n' "$@" > "$CAPTURE/$name.args"
env > "$CAPTURE/$name.env"
if [ -n "$SSH_ASKPASS" ]; then
    pw=$("$SSH_ASKPASS" "someone@host.invalid's password: ") || exit 255
    printf '%s' "$pw" > "$CAPTURE/$name.pw"
fi
exit "${FAKE_EXIT:-0}"
"#;

/// Isolated environment for one test.
pub struct Sandbox {
    pub root: tempfile::TempDir,
    /// Short path (`/tmp/…`) so askpass socket paths fit into `sun_path`.
    pub tmp: tempfile::TempDir,
    /// Extra environment variables for every sshire call.
    env: Vec<(String, String)>,
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for sub in ["home/.ssh", "bin", "capture"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        let tmp = tempfile::Builder::new()
            .prefix("ss-it-")
            .tempdir_in("/tmp")
            .unwrap();
        Self {
            root,
            tmp,
            env: Vec::new(),
        }
    }

    pub fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    /// Installs the fake under the given names (e.g. `["ssh", "sftp", "sshfs"]`).
    pub fn install_fakes(&self, names: &[&str]) {
        for name in names {
            let path = self.bin_dir().join(name);
            fs::write(&path, FAKE_PROGRAM).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// Sets an environment variable for all following sshire calls.
    pub fn set_env(&mut self, key: &str, value: &str) {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.to_owned(), value.to_owned()));
    }

    /// Runs sshire with `args`, feeds `stdin` and waits (at most 30 s).
    pub fn sshire(&self, args: &[&str], stdin: &str) -> Output {
        let home = self.home();
        let mut cmd = Command::new(BIN);
        // The sandbox root is the working directory (for relative paths).
        cmd.args(args)
            .current_dir(self.root.path())
            .env("HOME", &home)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSHIRE_ASKPASS_SOCK")
            .env_remove("SSHIRE_ASKPASS_TOKEN")
            .env("RUST_BACKTRACE", "0")
            .env("TMPDIR", self.tmp.path())
            .env("SSHIRE_SECRET_BACKEND", "encrypted")
            .env("CAPTURE", self.root.path().join("capture"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", self.bin_dir().display()),
            )
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("sshire starts");
        // Write stdin from a thread: a child that does not read it must not
        // block the test.
        let mut child_stdin = child.stdin.take().unwrap();
        let input = stdin.to_owned();
        let writer = thread::spawn(move || {
            let _ = child_stdin.write_all(input.as_bytes());
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                let _ = writer.join();
                return child.wait_with_output().unwrap();
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("sshire {args:?} hangs (timeout exceeded)");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Like [`Sandbox::sshire`], but asserts success and returns stdout.
    pub fn ok(&self, args: &[&str], stdin: &str) -> String {
        let out = self.sshire(args, stdin);
        assert!(
            out.status.success(),
            "sshire {args:?} failed ({:?}):\n{}",
            out.status,
            text(&out.stderr)
        );
        text(&out.stdout)
    }

    /// Like [`Sandbox::sshire`], but asserts failure and returns stderr.
    pub fn fails(&self, args: &[&str], stdin: &str) -> String {
        let out = self.sshire(args, stdin);
        assert!(
            !out.status.success(),
            "sshire {args:?} should fail, stdout:\n{}",
            text(&out.stdout)
        );
        text(&out.stderr)
    }

    /// Path of sshire's `config.toml` (platform-dependent, asked from sshire).
    pub fn config_path(&self) -> PathBuf {
        PathBuf::from(self.ok(&["config", "--path"], "").trim())
    }

    pub fn write_config(&self, toml: &str) {
        let path = self.config_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, toml).unwrap();
    }

    pub fn write_ssh_config(&self, text: &str) {
        fs::write(self.home().join(".ssh/config"), text).unwrap();
    }

    /// Creates a manual host via `sshire add` flags.
    pub fn add_host(&self, alias: &str, extra: &[&str]) {
        let mut args = vec!["add", "--alias", alias];
        args.extend_from_slice(extra);
        self.ok(&args, "");
    }

    /// Stores `password` for `alias`; creates the master password [`MASTER`]
    /// on first use.
    pub fn set_password(&self, alias: &str, password: &str, first: bool) {
        let stdin = if first {
            format!("{MASTER}\n{MASTER}\n{password}\n{password}\n")
        } else {
            format!("{MASTER}\n{password}\n{password}\n")
        };
        self.ok(&["passwd", alias], &stdin);
    }

    pub fn capture(&self, name: &str) -> PathBuf {
        self.root.path().join("capture").join(name)
    }

    /// The recorded arguments of a fake program (one per line), if it ran.
    pub fn captured_args(&self, program: &str) -> Option<Vec<String>> {
        let text = fs::read_to_string(self.capture(&format!("{program}.args"))).ok()?;
        Some(text.lines().map(str::to_owned).collect())
    }

    pub fn captured(&self, file: &str) -> Option<String> {
        fs::read_to_string(self.capture(file)).ok()
    }

    pub fn clear_capture(&self) {
        let dir = self.root.path().join("capture");
        fs::remove_dir_all(&dir).unwrap();
        fs::create_dir_all(&dir).unwrap();
    }

    /// Leftover askpass directories in the sandbox's temp directory.
    pub fn askpass_leftovers(&self) -> Vec<PathBuf> {
        fs::read_dir(self.tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("sshire-askpass-")
            })
            .map(|e| e.path())
            .collect()
    }
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Does `haystack` contain the consecutive elements `needle`?
pub fn contains_seq(haystack: &[String], needle: &[&str]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a == b))
}

/// Asserts that `dir` is an existing directory.
pub fn assert_dir(dir: &Path) {
    assert!(dir.is_dir(), "{} should be a directory", dir.display());
}
