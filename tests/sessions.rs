//! End-to-end tests for `sshire sftp`, `sshire mount` and `sshire umount`
//! with fake `sftp`/`sshfs` programs (no network, no FUSE).

mod common;

use std::fs;

use common::{MASTER, Sandbox, assert_dir, contains_seq, text};

/// Sandbox with fakes, a mount directory inside the sandbox and one manual
/// host "web" with all options set.
fn sandbox() -> Sandbox {
    let sb = Sandbox::new();
    sb.install_fakes(&["ssh", "sftp", "sshfs"]);
    let mnt = sb.root.path().join("mnt");
    sb.write_config(&format!(
        "[mount]\ndir = \"{}\"\noptions = [\"reconnect\"]\n",
        mnt.display()
    ));
    sb.add_host(
        "web",
        &[
            "--host",
            "web.invalid",
            "--user",
            "admin",
            "--port",
            "2222",
            "--identity-file",
            "/keys/id_test",
            "--proxy-jump",
            "jump.invalid",
        ],
    );
    sb
}

// ---- sftp --------------------------------------------------------------------

#[test]
fn sftp_translates_host_options() {
    let sb = sandbox();
    let out = sb.sshire(&["sftp", "web"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("SFTP session to web ended"));
    assert_eq!(
        sb.captured_args("sftp").expect("sftp ran"),
        [
            "-P",
            "2222",
            "-i",
            "/keys/id_test",
            "-J",
            "jump.invalid",
            "admin@web.invalid"
        ]
    );
    // ssh itself was not started by sshire.
    assert!(sb.captured_args("ssh").is_none());
    let log = sb.ok(&["log", "web"], "");
    assert!(log.contains("success"), "{log}");
}

#[test]
fn sftp_uses_configured_program_and_arguments() {
    let sb = Sandbox::new();
    sb.install_fakes(&["mysftp"]);
    sb.write_config(
        "[ssh]\nprogram = \"/opt/ssh\"\nextra_args = [\"-o\", \"ServerAliveInterval=30\", \"-t\"]\n\
         [sftp]\nprogram = \"mysftp\"\nextra_args = [\"-l\", \"8000\"]\n",
    );
    sb.write_ssh_config("Host prod\n  HostName prod.invalid\n");
    sb.ok(&["import"], "");
    sb.ok(&["sftp", "prod"], "");
    // sftp extras first, the ssh program via -S, `-t` (shell only) dropped.
    assert_eq!(
        sb.captured_args("mysftp").unwrap(),
        [
            "-l",
            "8000",
            "-S",
            "/opt/ssh",
            "-o",
            "ServerAliveInterval=30",
            "prod"
        ]
    );
}

#[test]
fn sftp_hands_over_the_stored_password() {
    let sb = sandbox();
    sb.set_password("web", "sftp-host-password", true);
    let out = sb.sshire(&["sftp", "web"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sb.captured("sftp.pw").unwrap(), "sftp-host-password");
    let args = sb.captured_args("sftp").unwrap();
    assert_eq!(&args[..2], ["-o", "NumberOfPasswordPrompts=1"]);
    assert_eq!(args.last().unwrap(), "admin@web.invalid");
    for haystack in [
        sb.captured("sftp.args").unwrap(),
        sb.captured("sftp.env").unwrap(),
        text(&out.stdout),
        text(&out.stderr),
    ] {
        assert!(!haystack.contains("sftp-host-password"));
    }
    assert!(sb.askpass_leftovers().is_empty());
}

#[test]
fn sftp_failure_is_reported_and_logged() {
    let mut sb = sandbox();
    sb.set_env("FAKE_EXIT", "255");
    let out = sb.sshire(&["sftp", "web"], "");
    assert_eq!(out.status.code(), Some(255));
    assert!(text(&out.stderr).contains("SFTP session to web failed"));
    assert!(sb.ok(&["log", "web"], "").contains("failed"));

    let err = sb.fails(&["sftp", "nope"], "");
    assert!(err.contains("not found"), "{err}");
}

#[test]
fn sftp_brackets_ipv6_addresses() {
    let sb = Sandbox::new();
    sb.install_fakes(&["sftp"]);
    sb.add_host("v6", &["--host", "2001:db8::1", "--user", "root"]);
    sb.ok(&["sftp", "v6"], "");
    assert_eq!(sb.captured_args("sftp").unwrap(), ["root@[2001:db8::1]"]);
}

// ---- mount -------------------------------------------------------------------

#[test]
fn mount_uses_the_default_mountpoint_and_translates_options() {
    let sb = sandbox();
    let out = sb.sshire(&["mount", "web"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let mountpoint = sb.root.path().join("mnt").join("web");
    assert!(
        text(&out.stderr).contains(&format!("Mounted web at {}", mountpoint.display())),
        "{}",
        text(&out.stderr)
    );
    // The mount point was created (the fake does not really mount).
    assert_dir(&mountpoint);

    let args = sb.captured_args("sshfs").expect("sshfs ran");
    assert!(contains_seq(&args, &["-o", "reconnect"]), "{args:?}");
    assert!(contains_seq(&args, &["-o", "Port=2222"]), "{args:?}");
    assert!(
        contains_seq(&args, &["-o", "IdentityFile=/keys/id_test"]),
        "{args:?}"
    );
    assert!(
        contains_seq(&args, &["-o", "ProxyJump=jump.invalid"]),
        "{args:?}"
    );
    let n = args.len();
    assert_eq!(args[n - 2], "admin@web.invalid:");
    assert_eq!(args[n - 1], mountpoint.to_str().unwrap());
    assert!(sb.ok(&["log", "web"], "").contains("success"));
}

#[test]
fn mount_with_explicit_mountpoint_and_remote_path() {
    let sb = sandbox();
    let target = sb.root.path().join("custom").join("place");
    let target_str = target.to_str().unwrap();
    sb.ok(&["mount", "web", target_str, "--path", "/var/www"], "");
    let args = sb.captured_args("sshfs").unwrap();
    let n = args.len();
    assert_eq!(args[n - 2], "admin@web.invalid:/var/www");
    assert_eq!(args[n - 1], target_str);
    assert_dir(&target);
}

#[test]
fn mount_relative_mountpoint_becomes_absolute() {
    let sb = sandbox();
    // sshire runs in the sandbox root, so "rel" is resolved against it.
    sb.ok(&["mount", "web", "rel"], "");
    let args = sb.captured_args("sshfs").unwrap();
    let target = sb.root.path().join("rel");
    assert_dir(&target);
    let last = std::path::PathBuf::from(args.last().unwrap());
    assert!(last.is_absolute(), "{}", last.display());
    // On macOS the temp directory is behind a symlink (/var -> /private/var).
    assert_eq!(
        fs::canonicalize(last).unwrap(),
        fs::canonicalize(&target).unwrap()
    );
}

#[test]
fn mount_hands_over_the_stored_password() {
    let sb = sandbox();
    sb.set_password("web", "mount-host-password", true);
    let out = sb.sshire(&["mount", "web"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sb.captured("sshfs.pw").unwrap(), "mount-host-password");
    let args = sb.captured_args("sshfs").unwrap();
    assert_eq!(&args[..2], ["-o", "NumberOfPasswordPrompts=1"]);
    assert!(
        !sb.captured("sshfs.args")
            .unwrap()
            .contains("mount-host-password")
    );
    assert!(sb.askpass_leftovers().is_empty());
}

#[test]
fn failed_mount_removes_only_a_mountpoint_it_created() {
    let mut sb = sandbox();
    sb.set_env("FAKE_EXIT", "1");
    let out = sb.sshire(&["mount", "web"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("Mounting web failed"));
    let mountpoint = sb.root.path().join("mnt").join("web");
    assert!(!mountpoint.exists(), "created mount point must be removed");
    assert!(sb.ok(&["log", "web"], "").contains("failed"));

    // A directory that existed before stays.
    let existing = sb.root.path().join("existing");
    fs::create_dir_all(&existing).unwrap();
    sb.fails(&["mount", "web", existing.to_str().unwrap()], "");
    assert_dir(&existing);
}

#[test]
fn mount_uses_configured_program_and_ssh_command() {
    let sb = Sandbox::new();
    sb.install_fakes(&["mysshfs"]);
    let mnt = sb.root.path().join("m");
    sb.write_config(&format!(
        "[ssh]\nprogram = \"/opt/ssh\"\n[mount]\nprogram = \"mysshfs\"\ndir = \"{}\"\noptions = []\n",
        mnt.display()
    ));
    sb.write_ssh_config("Host prod\n  HostName prod.invalid\n");
    sb.ok(&["import"], "");
    sb.ok(&["mount", "prod"], "");
    let args = sb.captured_args("mysshfs").unwrap();
    assert!(
        contains_seq(&args, &["-o", "ssh_command=/opt/ssh"]),
        "{args:?}"
    );
    let n = args.len();
    assert_eq!(args[n - 2], "prod:");
    assert_eq!(args[n - 1], mnt.join("prod").to_str().unwrap());
}

#[test]
fn mount_errors() {
    let sb = sandbox();
    let err = sb.fails(&["mount", "nope"], "");
    assert!(err.contains("not found"), "{err}");

    sb.write_config(&format!(
        "[mount]\nprogram = \"sshire-no-such-sshfs\"\ndir = \"{}\"\n",
        sb.root.path().join("mnt").display()
    ));
    let err = sb.fails(&["mount", "web"], "");
    assert!(err.contains("sshire-no-such-sshfs"), "{err}");
    // The mount point created for the attempt is gone again.
    assert!(!sb.root.path().join("mnt").join("web").exists());
}

// ---- umount ------------------------------------------------------------------

#[test]
fn umount_without_a_mount_fails_cleanly() {
    let sb = sandbox();
    let err = sb.fails(&["umount", "web"], "");
    assert!(err.contains("Nothing is mounted"), "{err}");
    let err = sb.fails(&["unmount", "web"], "");
    assert!(err.contains("Nothing is mounted"), "{err}");
    let err = sb.fails(&["umount", "nope"], "");
    assert!(err.contains("not found"), "{err}");
    // A plain directory is not a mount.
    let dir = sb.root.path().join("plain");
    fs::create_dir_all(&dir).unwrap();
    let err = sb.fails(&["umount", "web", dir.to_str().unwrap()], "");
    assert!(err.contains("Nothing is mounted"), "{err}");
    assert_dir(&dir);
}
