//! End-to-end tests of the command line: every subcommand runs the real
//! binary in an isolated sandbox (see `common`). ssh is replaced by a fake
//! program, so no network is needed.

mod common;

use common::{MASTER, Sandbox, contains_seq, text};

// ---- General ---------------------------------------------------------------

#[test]
fn version_and_help() {
    let sb = Sandbox::new();
    let version = sb.ok(&["--version"], "");
    assert!(version.contains(env!("CARGO_PKG_VERSION")), "{version}");

    let help = sb.ok(&["--help"], "");
    for command in [
        "list", "connect", "sftp", "mount", "umount", "log", "add", "import", "export", "config",
        "passwd",
    ] {
        assert!(help.contains(command), "help is missing {command}:\n{help}");
    }
    // The internal askpass helper stays hidden.
    assert!(!help.contains("askpass"));
}

#[test]
fn unknown_subcommand_fails() {
    let sb = Sandbox::new();
    let err = sb.fails(&["frobnicate"], "");
    assert!(err.contains("frobnicate"), "{err}");
}

// ---- add / list ------------------------------------------------------------

#[test]
fn empty_database_lists_nothing() {
    let sb = Sandbox::new();
    assert!(sb.ok(&["list"], "").contains("No hosts found"));
    assert!(sb.ok(&["log"], "").contains("No connections logged yet"));
}

#[test]
fn add_with_flags_and_list_with_tag_filter() {
    let sb = Sandbox::new();
    sb.add_host(
        "web",
        &[
            "--host",
            "web.invalid",
            "--user",
            "admin",
            "--port",
            "2222",
            "--tag",
            "prod",
            "--tag",
            "web",
            "--icon",
            "🚀",
        ],
    );
    sb.add_host("db", &["--host", "db.invalid", "--tag", "prod"]);

    let list = sb.ok(&["list"], "");
    assert!(list.contains("admin@web.invalid:2222"), "{list}");
    assert!(list.contains("#prod") && list.contains("#web"), "{list}");
    assert!(list.contains("🚀"));
    assert!(list.contains("db.invalid"));

    let web_only = sb.ok(&["list", "--tag", "web"], "");
    assert!(web_only.contains("web.invalid") && !web_only.contains("db.invalid"));
    // Tags are matched case-insensitively.
    let prod = sb.ok(&["list", "--tag", "PROD"], "");
    assert!(prod.contains("web.invalid") && prod.contains("db.invalid"));
    assert!(
        sb.ok(&["list", "--tag", "none"], "")
            .contains("No hosts found")
    );
}

#[test]
fn add_interactively_from_stdin() {
    let sb = Sandbox::new();
    // Alias, hostname, user, port, icon, tags.
    sb.ok(&["add"], "box\nbox.invalid\nalice\n2200\n\nlab, test\n");
    let list = sb.ok(&["list"], "");
    assert!(list.contains("alice@box.invalid:2200"), "{list}");
    assert!(list.contains("#lab") && list.contains("#test"), "{list}");
}

#[test]
fn add_rejects_duplicates_and_invalid_input() {
    let sb = Sandbox::new();
    sb.add_host("web", &["--host", "web.invalid"]);
    let err = sb.fails(&["add", "--alias", "web", "--host", "other.invalid"], "");
    assert!(err.contains("already exists"), "{err}");

    let err = sb.fails(&["add", "--alias", "bad", "--port", "99999"], "");
    assert!(err.contains("Port"), "{err}");
    let err = sb.fails(&["add", "--alias", "my host"], "");
    assert!(err.contains("Alias") || err.contains("alias"), "{err}");
    let err = sb.fails(&["add", "--alias", "-oProxyCommand=x"], "");
    assert!(!err.is_empty());
    // Nothing invalid ended up in the database.
    let list = sb.ok(&["list"], "");
    assert!(
        !list.contains("bad") && !list.contains("ProxyCommand"),
        "{list}"
    );
}

// ---- import (ssh_config) -----------------------------------------------------

#[test]
fn import_reads_ssh_config_and_archives_removed_hosts() {
    let sb = Sandbox::new();
    sb.write_ssh_config(
        "Host prod\n  HostName prod.invalid\n  User root\n\
         Host stage\n  HostName stage.invalid\n\
         Host *.wild\n  User nobody\n",
    );
    let report = sb.ok(&["import"], "");
    assert!(report.contains("created/updated: 2"), "{report}");
    let list = sb.ok(&["list"], "");
    assert!(
        list.contains("root@prod.invalid") && list.contains("stage"),
        "{list}"
    );
    // Wildcard patterns are not hosts.
    assert!(!list.contains("wild"), "{list}");

    // "stage" disappears from the file: it is archived, not deleted.
    sb.write_ssh_config("Host prod\n  HostName prod.invalid\n  User root\n");
    let report = sb.ok(&["import"], "");
    assert!(report.contains("archived:        1"), "{report}");
    let export = sb.ok(&["export"], "");
    assert!(!export.contains("\"stage\""));
    let export = sb.ok(&["export", "--include-archived"], "");
    assert!(export.contains("\"stage\""));

    // Archived hosts cannot be used.
    sb.install_fakes(&["ssh", "sftp", "sshfs"]);
    for command in ["connect", "sftp", "mount"] {
        let err = sb.fails(&[command, "stage"], "");
        assert!(err.contains("archived"), "{command}: {err}");
    }
}

#[test]
fn ssh_config_is_never_modified() {
    let sb = Sandbox::new();
    let original = "Host prod\n  HostName prod.invalid\n";
    sb.write_ssh_config(original);
    sb.ok(&["import"], "");
    sb.add_host("manual", &["--host", "m.invalid"]);
    sb.ok(&["list"], "");
    let now = std::fs::read_to_string(sb.home().join(".ssh/config")).unwrap();
    assert_eq!(now, original);
}

// ---- export ------------------------------------------------------------------

#[test]
fn export_is_valid_json_without_secrets() {
    let sb = Sandbox::new();
    sb.add_host(
        "web",
        &[
            "--host",
            "web.invalid",
            "--user",
            "admin",
            "--tag",
            "prod",
            "--notes",
            "Note",
        ],
    );
    sb.set_password("web", "export-secret-pw", true);
    for args in [
        vec!["export"],
        vec!["export", "--json"],
        vec!["export", "--json", "--include-archived"],
    ] {
        let json = sb.ok(&args, "");
        assert!(!json.contains("export-secret-pw"));
        assert!(!json.contains(MASTER));
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["format_version"], 1);
        let host = &value["hosts"][0];
        assert_eq!(host["alias"], "web");
        assert_eq!(host["hostname"], "web.invalid");
        assert_eq!(host["user"], "admin");
        assert_eq!(host["notes"], "Note");
        assert_eq!(host["has_password"], true);
        assert_eq!(host["tags"][0]["name"], "prod");
    }
}

// ---- config ------------------------------------------------------------------

#[test]
fn config_path_and_example() {
    let sb = Sandbox::new();
    let path = sb.config_path();
    assert!(path.ends_with("sshire/config.toml"), "{}", path.display());
    assert!(path.starts_with(sb.home()), "{}", path.display());
    // `--path` does not create the file.
    assert!(!path.exists());

    let example = sb.ok(&["config", "--example"], "");
    for section in ["[ssh]", "[sftp]", "[mount]"] {
        assert!(example.contains(section), "{example}");
    }
    // The example is a valid configuration without warnings.
    sb.write_config(&example);
    let out = sb.sshire(&["list"], "");
    assert!(out.status.success());
    assert!(
        !text(&out.stderr).contains("Warning"),
        "{}",
        text(&out.stderr)
    );

    sb.fails(&["config", "--path", "--example"], "");
}

#[test]
fn config_warnings_and_errors() {
    let sb = Sandbox::new();
    sb.write_config("themee = \"latte\"\n[mount]\ndirr = \"x\"\n");
    sb.install_fakes(&["ssh"]);
    sb.add_host("web", &["--host", "web.invalid"]);
    let out = sb.sshire(&["connect", "web"], "");
    assert!(out.status.success());
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("themee") && stderr.contains("mount.dirr"),
        "{stderr}"
    );

    sb.write_config("theme = \"neon\"\n");
    let err = sb.fails(&["connect", "web"], "");
    assert!(err.contains("neon"), "{err}");
    assert!(err.contains("config.toml"), "{err}");
    // `config --path` still works with a broken file.
    sb.ok(&["config", "--path"], "");
}

// ---- connect / log -------------------------------------------------------------

#[test]
fn connect_builds_the_ssh_command_and_logs_the_result() {
    let sb = Sandbox::new();
    sb.install_fakes(&["ssh"]);
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
            "~/.ssh/id_test",
            "--proxy-jump",
            "jump.invalid",
        ],
    );
    let out = sb.sshire(&["connect", "web"], "");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("Connection to web ended"));
    let args = sb.captured_args("ssh").expect("ssh ran");
    assert_eq!(
        args,
        [
            "-p",
            "2222",
            "-i",
            "~/.ssh/id_test",
            "-J",
            "jump.invalid",
            "admin@web.invalid"
        ]
    );
    // Without a password there is no askpass.
    assert!(!sb.captured("ssh.env").unwrap().contains("SSH_ASKPASS="));

    let log = sb.ok(&["log", "web"], "");
    assert!(log.contains("success"), "{log}");
}

#[test]
fn connect_propagates_exit_codes_and_classifies_them() {
    let mut sb = Sandbox::new();
    sb.install_fakes(&["ssh"]);
    sb.add_host("web", &["--host", "web.invalid"]);

    // A remote exit code != 255 means "the connection was up".
    sb.set_env("FAKE_EXIT", "7");
    let out = sb.sshire(&["connect", "web"], "");
    assert_eq!(out.status.code(), Some(7));

    // 255 is ssh's own error.
    sb.set_env("FAKE_EXIT", "255");
    let out = sb.sshire(&["connect", "web"], "");
    assert_eq!(out.status.code(), Some(255));
    assert!(text(&out.stderr).contains("failed"));

    let log = sb.ok(&["log", "web"], "");
    assert!(log.contains("success") && log.contains("failed"), "{log}");
    // `--limit` restricts the number of entries.
    let limited = sb.ok(&["log", "--limit", "1"], "");
    assert_eq!(limited.matches("web").count(), 1, "{limited}");
}

#[test]
fn connect_uses_ssh_config_alias_and_configured_program() {
    let sb = Sandbox::new();
    sb.install_fakes(&["myssh"]);
    sb.write_config(
        "[ssh]\nprogram = \"myssh\"\nextra_args = [\"-o\", \"ServerAliveInterval=30\"]\n",
    );
    sb.write_ssh_config("Host prod\n  HostName prod.invalid\n  Port 2200\n");
    sb.ok(&["import"], "");
    sb.ok(&["connect", "prod"], "");
    // ssh reads ~/.ssh/config itself: only the alias is passed.
    assert_eq!(
        sb.captured_args("myssh").unwrap(),
        ["-o", "ServerAliveInterval=30", "prod"]
    );
}

#[test]
fn connect_errors() {
    let sb = Sandbox::new();
    let err = sb.fails(&["connect", "nope"], "");
    assert!(err.contains("not found"), "{err}");

    // The ssh program does not exist: a clear error, and the log entry is closed.
    sb.write_config("[ssh]\nprogram = \"sshire-no-such-ssh\"\n");
    sb.add_host("web", &["--host", "web.invalid"]);
    let err = sb.fails(&["connect", "web"], "");
    assert!(err.contains("sshire-no-such-ssh"), "{err}");
    let log = sb.ok(&["log"], "");
    assert!(log.contains("failed"), "{log}");
}

// ---- passwd ------------------------------------------------------------------

#[test]
fn password_is_delivered_once_and_never_leaks() {
    let sb = Sandbox::new();
    sb.install_fakes(&["ssh"]);
    sb.add_host("web", &["--host", "web.invalid"]);
    sb.set_password("web", "cli-host-password", true);
    assert!(sb.ok(&["list"], "").contains("🔑"));

    let out = sb.sshire(&["connect", "web"], &format!("{MASTER}\n"));
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(sb.captured("ssh.pw").unwrap(), "cli-host-password");
    let args = sb.captured_args("ssh").unwrap();
    assert!(contains_seq(&args, &["-o", "NumberOfPasswordPrompts=1"]));
    for haystack in [
        text(&out.stdout),
        text(&out.stderr),
        sb.captured("ssh.args").unwrap(),
        sb.captured("ssh.env").unwrap(),
    ] {
        assert!(!haystack.contains("cli-host-password"));
    }
    assert!(sb.askpass_leftovers().is_empty());
}

#[test]
fn passwords_are_bound_to_the_master_password() {
    let sb = Sandbox::new();
    sb.install_fakes(&["ssh"]);
    sb.add_host("web", &["--host", "web.invalid"]);
    sb.set_password("web", "pw-1", true);

    // Wrong master password: ssh is not started.
    let err = sb.fails(&["connect", "web"], "wrong\nwrong\nwrong\n");
    assert!(err.contains("Wrong master password"), "{err}");
    assert!(sb.captured_args("ssh").is_none());

    // Change the master password; the host password stays readable.
    let new_master = "a-brand-new-master-pw";
    sb.ok(
        &["passwd", "--master"],
        &format!("{MASTER}\n{new_master}\n{new_master}\n"),
    );
    sb.fails(
        &["connect", "web"],
        &format!("{MASTER}\n{MASTER}\n{MASTER}\n"),
    );
    sb.ok(&["connect", "web"], &format!("{new_master}\n"));
    assert_eq!(sb.captured("ssh.pw").unwrap(), "pw-1");
}

#[test]
fn passwd_rejects_bad_input_and_can_delete() {
    let sb = Sandbox::new();
    sb.add_host("web", &["--host", "web.invalid"]);
    // Master password too short.
    sb.fails(&["passwd", "web"], "short\nshort\npw\npw\n");
    // Entries do not match.
    sb.fails(
        &["passwd", "web"],
        &format!("{MASTER}\n{MASTER}\npw-a\npw-b\n"),
    );
    // Unknown host.
    sb.fails(
        &["passwd", "nope"],
        &format!("{MASTER}\n{MASTER}\npw\npw\n"),
    );

    sb.set_password("web", "pw", false);
    assert!(sb.ok(&["list"], "").contains("🔑"));
    sb.ok(&["passwd", "web", "--delete"], "");
    assert!(!sb.ok(&["list"], "").contains("🔑"));

    // Without --master and without an alias: usage error.
    sb.fails(&["passwd"], "");
}
