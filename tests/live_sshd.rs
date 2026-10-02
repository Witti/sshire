//! Tests against a real ssh server, real `ssh`, `sftp` and (on Linux) `sshfs`.
//!
//! They are `#[ignore]`d because they need a prepared server. CI starts one
//! (see `.github/workflows/ci.yml`, job `live`); locally:
//!
//! ```sh
//! SSHIRE_LIVE_HOST=127.0.0.1 SSHIRE_LIVE_PORT=2222 SSHIRE_LIVE_USER=tester \
//! SSHIRE_LIVE_PASSWORD=... SSHIRE_LIVE_KNOWN_HOSTS=/path/to/known_hosts \
//!   cargo test --test live_sshd -- --ignored --test-threads=1
//! ```
//!
//! The server user needs a file `data/hello.txt` containing `hello-from-sshd`
//! in its home directory.

mod common;

use std::fs;
use std::path::Path;

use common::{MASTER, Sandbox, text};

const REMOTE_CONTENT: &str = "hello-from-sshd";

struct Live {
    host: String,
    port: String,
    user: String,
    password: String,
    known_hosts: String,
}

fn live() -> Live {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the live tests"))
    };
    Live {
        host: var("SSHIRE_LIVE_HOST"),
        port: var("SSHIRE_LIVE_PORT"),
        user: var("SSHIRE_LIVE_USER"),
        password: var("SSHIRE_LIVE_PASSWORD"),
        known_hosts: var("SSHIRE_LIVE_KNOWN_HOSTS"),
    }
}

/// Sandbox with the real programs and host "live" with `password` stored.
fn sandbox(live: &Live, password: &str) -> Sandbox {
    let sb = Sandbox::new();
    configure(&sb, live, "", "");
    sb.add_host(
        "live",
        &[
            "--host", &live.host, "--user", &live.user, "--port", &live.port,
        ],
    );
    sb.set_password("live", password, true);
    sb
}

/// Writes the configuration; `ssh_extra`/`sftp_extra` are TOML array items.
///
/// ssh ignores `$HOME` for its own files, so the known_hosts file is passed
/// explicitly and the user's ssh config and keys are switched off: only the
/// stored password may get us in.
fn configure(sb: &Sandbox, live: &Live, ssh_extra: &str, sftp_extra: &str) {
    sb.write_config(&format!(
        r#"[ssh]
extra_args = ["-F", "none", "-o", "UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes", "-o", "PubkeyAuthentication=no"{ssh_extra}]
[sftp]
extra_args = [{sftp_extra}]
[mount]
dir = "{mnt}"
"#,
        known = live.known_hosts,
        mnt = sb.root.path().join("mnt").display(),
    ));
}

/// sftp arguments for a batch file that downloads `data/hello.txt` to `target`.
fn batch_args(sb: &Sandbox, target: &Path) -> String {
    let batch = sb.root.path().join("batch");
    fs::write(
        &batch,
        format!("get data/hello.txt {}\nbye\n", target.display()),
    )
    .unwrap();
    // `-b` switches ssh into BatchMode (no passwords) unless overridden first.
    format!(r#""-o", "BatchMode=no", "-b", "{}""#, batch.display())
}

#[test]
#[ignore = "needs a real ssh server (SSHIRE_LIVE_*)"]
fn live_connect_runs_with_the_stored_password() {
    let live = live();
    let sb = sandbox(&live, &live.password);
    // Run a command instead of a shell, so the session ends by itself.
    configure(
        &sb,
        &live,
        r#", "-o", "RemoteCommand=cat data/hello.txt""#,
        "",
    );
    let out = sb.sshire(&["connect", "live"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains(REMOTE_CONTENT),
        "{}",
        text(&out.stdout)
    );
    assert!(sb.ok(&["log", "live"], "").contains("success"));
}

#[test]
#[ignore = "needs a real ssh server (SSHIRE_LIVE_*)"]
fn live_sftp_downloads_a_file_with_the_stored_password() {
    let live = live();
    let sb = sandbox(&live, &live.password);
    let file = sb.root.path().join("hello.txt");
    configure(&sb, &live, "", &batch_args(&sb, &file));

    let out = sb.sshire(&["sftp", "live"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("SFTP session to live ended"));
    assert_eq!(fs::read_to_string(&file).unwrap().trim(), REMOTE_CONTENT);
    assert!(sb.askpass_leftovers().is_empty());
}

#[test]
#[ignore = "needs a real ssh server (SSHIRE_LIVE_*)"]
fn live_sftp_with_a_wrong_password_fails() {
    let live = live();
    let sb = sandbox(&live, "definitely-not-the-password");
    let file = sb.root.path().join("hello.txt");
    configure(&sb, &live, "", &batch_args(&sb, &file));

    let out = sb.sshire(&["sftp", "live"], &format!("{MASTER}\n"));
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("failed"),
        "{}",
        text(&out.stderr)
    );
    assert!(!file.exists());
    assert!(sb.ok(&["log", "live"], "").contains("failed"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a real ssh server (SSHIRE_LIVE_*) and sshfs"]
fn live_mount_and_umount_with_the_stored_password() {
    let live = live();
    let sb = sandbox(&live, &live.password);
    let mountpoint = sb.root.path().join("mnt").join("live");

    let out = sb.sshire(&["mount", "live", "--path", "data"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    // Unmount even if an assertion below fails.
    struct Unmount<'a>(&'a Sandbox);
    impl Drop for Unmount<'_> {
        fn drop(&mut self) {
            let _ = self.0.sshire(&["umount", "live"], "");
        }
    }
    let guard = Unmount(&sb);

    let content = fs::read_to_string(mountpoint.join("hello.txt")).unwrap();
    assert_eq!(content.trim(), REMOTE_CONTENT);

    // A second mount is refused before asking for the master password.
    let err = sb.fails(&["mount", "live"], "");
    assert!(err.contains("already mounted"), "{err}");

    drop(guard);
    assert!(
        !mountpoint.exists(),
        "the default mount point is removed again"
    );
    let err = sb.fails(&["umount", "live"], "");
    assert!(err.contains("Nothing is mounted"), "{err}");
    assert!(sb.ok(&["log", "live"], "").contains("success"));
}
