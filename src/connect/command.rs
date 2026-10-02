//! Building the ssh command from a [`Host`].
//!
//! Everything here is a *pure* function: nothing starts a process or reads
//! files. That makes all combinations easy to test.

use std::path::Path;

use thiserror::Error;

use crate::config::{MountConfig, SftpConfig, SshConfig};
use crate::store::{Host, HostSource};

/// A fully assembled ssh invocation (not started yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    /// Program to run (normally `"ssh"`; tests use a fake program).
    pub program: String,
    /// Arguments in the order ssh receives them.
    pub args: Vec<String>,
    /// Additional environment variables (name, value) for the child process.
    /// `build_invocation` leaves them empty; `connect::run` adds the askpass
    /// variables when a password is stored (never the password itself).
    pub env: Vec<(String, String)>,
}

/// Errors while building the command.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandError {
    /// The target starts with `-` and would be read by ssh as an option
    /// (option injection, e.g. `-oProxyCommand=...`).
    #[error("Invalid connection target \"{0}\": must not start with \"-\"")]
    DangerousTarget(String),
    /// `extra_args` could not be split into words (e.g. an unclosed quote).
    #[error("Invalid extra ssh arguments: {0}")]
    InvalidExtraArgs(String),
    /// The mount point is not valid UTF-8 and cannot be passed on as text.
    #[error("Invalid mount point \"{0}\": not valid UTF-8")]
    InvalidMountPoint(String),
}

/// Checks that a target cannot be mistaken for an option.
fn check_target(target: &str) -> Result<(), CommandError> {
    if target.starts_with('-') {
        Err(CommandError::DangerousTarget(target.to_owned()))
    } else {
        Ok(())
    }
}

/// Empty or whitespace-only option values count as "not set".
fn non_blank(value: &Option<String>) -> Option<&str> {
    // `as_deref` turns `&Option<String>` into `Option<&str>`.
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Builds the ssh invocation for a host.
///
/// The program and global extra arguments (`extra_args`) come from `[ssh]` in
/// the configuration; the global arguments come *before* all host-specific ones.
///
/// * `SshConfig`: only `ssh [global...] <alias>`; ssh reads `~/.ssh/config` itself.
/// * `Manual`: `ssh [global…] [-p port] [-i key] [-J jump] [extra…] [user@]hostname`.
pub fn build_invocation(host: &Host, ssh: &SshConfig) -> Result<SshInvocation, CommandError> {
    let mut args: Vec<String> = ssh.extra_args.clone();

    let target = match host.source {
        HostSource::SshConfig => host.alias.clone(),
        HostSource::Manual => {
            if let Some(port) = host.port {
                args.push("-p".to_owned());
                args.push(port.to_string());
            }
            if let Some(key) = non_blank(&host.identity_file) {
                args.push("-i".to_owned());
                args.push(key.to_owned());
            }
            if let Some(jump) = non_blank(&host.proxy_jump) {
                args.push("-J".to_owned());
                args.push(jump.to_owned());
            }
            if let Some(extra) = non_blank(&host.extra_args) {
                // `shell_words::split` splits like a shell (honouring quotes).
                // Its error is translated into our error type (`map_err`).
                let words = shell_words::split(extra)
                    .map_err(|e| CommandError::InvalidExtraArgs(e.to_string()))?;
                args.extend(words);
            }
            let name = non_blank(&host.hostname).unwrap_or(&host.alias);
            match non_blank(&host.user) {
                Some(user) => format!("{user}@{name}"),
                None => name.to_owned(),
            }
        }
    };

    // Check the *finished* target: otherwise even a user starting with `-`
    // would slip through as an option.
    check_target(&target)?;
    args.push(target);

    Ok(SshInvocation {
        program: ssh.program.clone(),
        args,
        env: Vec::new(),
    })
}

// ---- sftp and sshfs ------------------------------------------------------
//
// sftp and sshfs start ssh themselves, but spell many options differently
// (`sftp -P port` instead of `ssh -p port`, `sshfs -o IdentityFile=..`
// instead of `ssh -i ..`). So the ssh-style options of a host are first
// parsed into [`SshOpt`] and then rendered in the spelling of each program.
// Options that only make sense for an interactive ssh session (port
// forwardings, `-t`, a remote command, ...) are left out.

/// An ssh option that sftp and sshfs understand in some spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SshOpt {
    /// `-p port`
    Port(String),
    /// `-i identity_file`
    Identity(String),
    /// `-J jump`
    Jump(String),
    /// `-o Key=Value`
    Option(String),
    /// `-F config_file`
    ConfigFile(String),
    /// `-l user`
    User(String),
    /// `-c cipher_spec`
    Cipher(String),
    /// A flag without a value: one of `4 6 A C q v`.
    Flag(char),
}

/// ssh flags that take a value (from `man ssh`).
const SSH_VALUE_FLAGS: &str = "BbcDEeFIiJLlmOoPpQRSWw";
/// ssh flags without a value that sftp/sshfs can express.
const SSH_KEPT_FLAGS: &str = "46ACqv";

/// Parses ssh command-line arguments into the options sftp/sshfs can use.
///
/// Clustered flags (`-vC`, `-p2222`) are understood; everything else -
/// unknown flags, positional words, everything after `--` - is dropped.
fn parse_ssh_args(words: &[String]) -> Vec<SshOpt> {
    let mut opts = Vec::new();
    let mut iter = words.iter();
    while let Some(word) = iter.next() {
        if word == "--" {
            break;
        }
        // A word without a leading `-` would be the target or a remote command.
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        // `char_indices` yields the byte position of each character, so the
        // rest after a value flag can be sliced off safely.
        for (pos, flag) in cluster.char_indices() {
            if SSH_VALUE_FLAGS.contains(flag) {
                let rest = &cluster[pos + flag.len_utf8()..];
                let value = if rest.is_empty() {
                    match iter.next() {
                        Some(value) => value.clone(),
                        None => break,
                    }
                } else {
                    rest.to_owned()
                };
                opts.extend(value_opt(flag, value));
                break;
            }
            if SSH_KEPT_FLAGS.contains(flag) {
                opts.push(SshOpt::Flag(flag));
            }
        }
    }
    opts
}

/// Maps an ssh flag with a value to an [`SshOpt`] (`None`: not usable).
fn value_opt(flag: char, value: String) -> Option<SshOpt> {
    Some(match flag {
        'p' => SshOpt::Port(value),
        'i' => SshOpt::Identity(value),
        'J' => SshOpt::Jump(value),
        'o' => SshOpt::Option(value),
        'F' => SshOpt::ConfigFile(value),
        'l' => SshOpt::User(value),
        'c' => SshOpt::Cipher(value),
        _ => return None,
    })
}

/// Who to connect to, plus the host-specific options.
struct Remote {
    /// `[user@]host` without a path; IPv6 addresses are in brackets.
    target: String,
    opts: Vec<SshOpt>,
}

/// Collects target and options of a host (shared by sftp and sshfs).
///
/// The global `[ssh] extra_args` come first, as with ssh itself.
fn remote_for(host: &Host, ssh: &SshConfig) -> Result<Remote, CommandError> {
    let mut opts = parse_ssh_args(&ssh.extra_args);
    let target = match host.source {
        HostSource::SshConfig => host.alias.clone(),
        HostSource::Manual => {
            if let Some(port) = host.port {
                opts.push(SshOpt::Port(port.to_string()));
            }
            if let Some(key) = non_blank(&host.identity_file) {
                opts.push(SshOpt::Identity(key.to_owned()));
            }
            if let Some(jump) = non_blank(&host.proxy_jump) {
                opts.push(SshOpt::Jump(jump.to_owned()));
            }
            if let Some(extra) = non_blank(&host.extra_args) {
                let words = shell_words::split(extra)
                    .map_err(|e| CommandError::InvalidExtraArgs(e.to_string()))?;
                opts.extend(parse_ssh_args(&words));
            }
            let name = non_blank(&host.hostname).unwrap_or(&host.alias);
            // sftp and sshfs read `host:path`; a bare IPv6 address would be
            // cut at its first colon, so it goes into brackets.
            let name = if name.contains(':') {
                format!("[{name}]")
            } else {
                name.to_owned()
            };
            match non_blank(&host.user) {
                Some(user) => format!("{user}@{name}"),
                None => name,
            }
        }
    };
    check_target(&target)?;
    Ok(Remote { target, opts })
}

/// Builds the sftp invocation for a host: `sftp [extra…] [options…] target`.
pub fn build_sftp_invocation(
    host: &Host,
    ssh: &SshConfig,
    sftp: &SftpConfig,
) -> Result<SshInvocation, CommandError> {
    let remote = remote_for(host, ssh)?;
    let mut args = sftp.extra_args.clone();
    // sftp starts `ssh` itself; a different ssh program is handed over via `-S`.
    if ssh.program != "ssh" {
        args.push("-S".to_owned());
        args.push(ssh.program.clone());
    }
    for opt in remote.opts {
        let (flag, value) = match opt {
            SshOpt::Port(v) => ("-P", v),
            SshOpt::Identity(v) => ("-i", v),
            SshOpt::Jump(v) => ("-J", v),
            SshOpt::Option(v) => ("-o", v),
            SshOpt::ConfigFile(v) => ("-F", v),
            // sftp's `-l` is a bandwidth limit, not the user!
            SshOpt::User(v) => ("-o", format!("User={v}")),
            SshOpt::Cipher(v) => ("-c", v),
            // `sftp -A` only exists in newer OpenSSH versions; the option
            // works everywhere.
            SshOpt::Flag('A') => ("-o", "ForwardAgent=yes".to_owned()),
            SshOpt::Flag(c) => {
                args.push(format!("-{c}"));
                continue;
            }
        };
        args.push(flag.to_owned());
        args.push(value);
    }
    args.push(remote.target);
    Ok(SshInvocation {
        program: sftp.program.clone(),
        args,
        env: Vec::new(),
    })
}

/// Builds the sshfs invocation that mounts `remote_path` (empty: the home
/// directory) of a host at `mountpoint`:
/// `sshfs [-o option…] [ssh options…] target:path mountpoint`.
pub fn build_mount_invocation(
    host: &Host,
    ssh: &SshConfig,
    mount: &MountConfig,
    remote_path: Option<&str>,
    mountpoint: &Path,
) -> Result<SshInvocation, CommandError> {
    let remote = remote_for(host, ssh)?;
    let mountpoint = mountpoint
        .to_str()
        .ok_or_else(|| CommandError::InvalidMountPoint(mountpoint.display().to_string()))?;
    let mut args = Vec::new();
    // The configured options are FUSE syntax already (possibly several,
    // comma-separated) and are passed on unchanged.
    for extra in &mount.options {
        args.push("-o".to_owned());
        args.push(extra.clone());
    }
    // Values from the host, on the other hand, are escaped.
    let mut option = |value: String| {
        args.push("-o".to_owned());
        args.push(escape_fuse_option(&value));
    };
    if ssh.program != "ssh" {
        option(format!("ssh_command={}", ssh.program));
    }
    // On macOS (macFUSE) the volume shows up under this name in the Finder.
    if cfg!(target_os = "macos") {
        option(format!("volname={}", host.alias));
    }
    let mut short = Vec::new();
    for opt in remote.opts {
        match opt {
            SshOpt::Port(v) => option(format!("Port={v}")),
            SshOpt::Identity(v) => option(format!("IdentityFile={v}")),
            SshOpt::Jump(v) => option(format!("ProxyJump={v}")),
            SshOpt::Option(v) => option(normalize_ssh_option(&v)),
            SshOpt::User(v) => option(format!("User={v}")),
            SshOpt::Cipher(v) => option(format!("Ciphers={v}")),
            SshOpt::Flag('4') => option("AddressFamily=inet".to_owned()),
            SshOpt::Flag('6') => option("AddressFamily=inet6".to_owned()),
            SshOpt::Flag('A') => option("ForwardAgent=yes".to_owned()),
            SshOpt::Flag('C') => short.push("-C".to_owned()),
            SshOpt::ConfigFile(v) => {
                short.push("-F".to_owned());
                short.push(v);
            }
            // `-q`/`-v` have no sshfs equivalent.
            SshOpt::Flag(_) => {}
        }
    }
    args.extend(short);
    args.push(format!("{}:{}", remote.target, remote_path.unwrap_or("")));
    // A relative mount point starting with `-` would be read as an option.
    if mountpoint.starts_with('-') {
        args.push(format!("./{mountpoint}"));
    } else {
        args.push(mountpoint.to_owned());
    }
    Ok(SshInvocation {
        program: mount.program.clone(),
        args,
        env: Vec::new(),
    })
}

/// `-o` values of FUSE are comma-separated lists; a comma (or backslash)
/// inside a single value must be escaped with a backslash.
fn escape_fuse_option(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,")
}

/// ssh accepts `-o "Key Value"` and `-o Key=Value`; sshfs only the latter.
fn normalize_ssh_option(option: &str) -> String {
    let option = option.trim();
    match option.find(|c: char| c == '=' || c.is_whitespace()) {
        Some(pos) => {
            let (key, rest) = option.split_at(pos);
            let value = rest.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
            format!("{key}={value}")
        }
        None => option.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AuthMethod, Host};

    fn host(alias: &str, source: HostSource) -> Host {
        Host {
            id: 1,
            alias: alias.to_owned(),
            hostname: None,
            user: None,
            port: None,
            identity_file: None,
            proxy_jump: None,
            extra_args: None,
            icon: None,
            color: None,
            notes: None,
            source,
            favorite: false,
            archived: false,
            auth_method: AuthMethod::default(),
            has_password: false,
            created_at: 0,
            updated_at: 0,
            tags: Vec::new(),
        }
    }

    fn args(host: &Host) -> Vec<String> {
        build_invocation(host, &SshConfig::default()).unwrap().args
    }

    #[test]
    fn ssh_config_host_uses_only_alias() {
        let mut h = host("prod", HostSource::SshConfig);
        h.hostname = Some("example.invalid".into());
        h.user = Some("root".into());
        h.port = Some(2222);
        h.extra_args = Some("-v".into());
        let inv = build_invocation(&h, &SshConfig::default()).unwrap();
        assert_eq!(inv.program, "ssh");
        assert_eq!(inv.args, ["prod"]);
        assert!(inv.env.is_empty());
    }

    #[test]
    fn ssh_settings_program_and_global_args_come_first() {
        let ssh = SshConfig {
            program: "/opt/ssh".to_owned(),
            extra_args: vec!["-o".to_owned(), "ServerAliveInterval=30".to_owned()],
        };
        // ssh_config host: global arguments before the alias.
        let h = host("prod", HostSource::SshConfig);
        let inv = build_invocation(&h, &ssh).unwrap();
        assert_eq!(inv.program, "/opt/ssh");
        assert_eq!(inv.args, ["-o", "ServerAliveInterval=30", "prod"]);
        // Manual host: global options before the host-specific ones.
        let mut m = host("box", HostSource::Manual);
        m.port = Some(2222);
        m.extra_args = Some("-v".into());
        let inv = build_invocation(&m, &ssh).unwrap();
        assert_eq!(
            inv.args,
            ["-o", "ServerAliveInterval=30", "-p", "2222", "-v", "box"]
        );
    }

    #[test]
    fn manual_minimal_uses_alias_as_target() {
        assert_eq!(args(&host("box", HostSource::Manual)), ["box"]);
    }

    #[test]
    fn manual_hostname_and_user() {
        let mut h = host("box", HostSource::Manual);
        h.hostname = Some("example.invalid".into());
        assert_eq!(args(&h), ["example.invalid"]);
        h.user = Some("alice".into());
        assert_eq!(args(&h), ["alice@example.invalid"]);
    }

    #[test]
    fn manual_user_without_hostname_uses_alias() {
        let mut h = host("box", HostSource::Manual);
        h.user = Some("alice".into());
        assert_eq!(args(&h), ["alice@box"]);
    }

    #[test]
    fn manual_all_options_in_order() {
        let mut h = host("box", HostSource::Manual);
        h.hostname = Some("example.invalid".into());
        h.user = Some("alice".into());
        h.port = Some(2222);
        h.identity_file = Some("~/.ssh/id_test".into());
        h.proxy_jump = Some("jump@bastion.invalid".into());
        h.extra_args = Some("-o StrictHostKeyChecking=no -A".into());
        assert_eq!(
            args(&h),
            [
                "-p",
                "2222",
                "-i",
                "~/.ssh/id_test",
                "-J",
                "jump@bastion.invalid",
                "-o",
                "StrictHostKeyChecking=no",
                "-A",
                "alice@example.invalid"
            ]
        );
    }

    #[test]
    fn extra_args_respect_quotes() {
        let mut h = host("box", HostSource::Manual);
        h.extra_args = Some(r#"-o "ProxyCommand=nc -x proxy %h %p" -o 'Foo=a b'"#.into());
        assert_eq!(
            args(&h),
            [
                "-o",
                "ProxyCommand=nc -x proxy %h %p",
                "-o",
                "Foo=a b",
                "box"
            ]
        );
    }

    #[test]
    fn blank_options_are_ignored() {
        let mut h = host("box", HostSource::Manual);
        h.hostname = Some("  ".into());
        h.identity_file = Some("".into());
        h.extra_args = Some("   ".into());
        assert_eq!(args(&h), ["box"]);
    }

    #[test]
    fn unbalanced_quote_is_an_error_not_a_panic() {
        let mut h = host("box", HostSource::Manual);
        h.extra_args = Some(r#"-o "broken"#.into());
        assert!(matches!(
            build_invocation(&h, &SshConfig::default()),
            Err(CommandError::InvalidExtraArgs(_))
        ));
    }

    #[test]
    fn dangerous_targets_are_rejected() {
        let mut h = host("-oProxyCommand=evil", HostSource::Manual);
        assert!(matches!(
            build_invocation(&h, &SshConfig::default()),
            Err(CommandError::DangerousTarget(_))
        ));
        // Also the alias of an ssh_config host.
        h.source = HostSource::SshConfig;
        assert!(build_invocation(&h, &SshConfig::default()).is_err());
        // Dangerous hostname or user.
        let mut h = host("ok", HostSource::Manual);
        h.hostname = Some("-oProxyCommand=evil".into());
        assert!(build_invocation(&h, &SshConfig::default()).is_err());
        let mut h = host("ok", HostSource::Manual);
        h.user = Some("-oProxyCommand=evil".into());
        assert!(build_invocation(&h, &SshConfig::default()).is_err());
    }

    #[test]
    fn dash_inside_target_is_fine() {
        let mut h = host("my-box", HostSource::Manual);
        h.hostname = Some("web-1.example.invalid".into());
        assert_eq!(args(&h), ["web-1.example.invalid"]);
    }
    // ---- sftp / sshfs ----

    fn words(text: &str) -> Vec<String> {
        shell_words::split(text).unwrap()
    }

    #[test]
    fn ssh_args_are_parsed_including_clusters() {
        assert_eq!(
            parse_ssh_args(&words(
                "-vC -p2222 -i key -o 'Foo=a b' -l bob -L 8080:x:80 -t -A -J j1 -- cmd"
            )),
            [
                SshOpt::Flag('v'),
                SshOpt::Flag('C'),
                SshOpt::Port("2222".into()),
                SshOpt::Identity("key".into()),
                SshOpt::Option("Foo=a b".into()),
                SshOpt::User("bob".into()),
                SshOpt::Flag('A'),
                SshOpt::Jump("j1".into()),
            ]
        );
        // A value flag at the very end without a value is dropped.
        assert_eq!(parse_ssh_args(&words("-4 -p")), [SshOpt::Flag('4')]);
        // `-tp 22`: the value flag comes last in the cluster.
        assert_eq!(
            parse_ssh_args(&words("-tp 22")),
            [SshOpt::Port("22".into())]
        );
    }

    fn manual_host() -> Host {
        let mut h = host("box", HostSource::Manual);
        h.hostname = Some("example.invalid".into());
        h.user = Some("alice".into());
        h.port = Some(2222);
        h.identity_file = Some("~/.ssh/id_test".into());
        h.proxy_jump = Some("jump.invalid".into());
        h.extra_args = Some("-A -v -L 1:x:2 -l bob".into());
        h
    }

    #[test]
    fn sftp_uses_sftp_spelling() {
        let inv = build_sftp_invocation(
            &manual_host(),
            &SshConfig::default(),
            &SftpConfig::default(),
        )
        .unwrap();
        assert_eq!(inv.program, "sftp");
        assert_eq!(
            inv.args,
            [
                "-P",
                "2222",
                "-i",
                "~/.ssh/id_test",
                "-J",
                "jump.invalid",
                "-o",
                "ForwardAgent=yes",
                "-v",
                "-o",
                "User=bob",
                "alice@example.invalid"
            ]
        );
    }

    #[test]
    fn sftp_for_ssh_config_host_uses_alias_and_settings() {
        let ssh = SshConfig {
            program: "/opt/ssh".to_owned(),
            extra_args: words("-o ServerAliveInterval=30 -t"),
        };
        let sftp = SftpConfig {
            program: "/opt/sftp".to_owned(),
            extra_args: words("-l 8000"),
        };
        let mut h = host("prod", HostSource::SshConfig);
        h.port = Some(1);
        let inv = build_sftp_invocation(&h, &ssh, &sftp).unwrap();
        assert_eq!(inv.program, "/opt/sftp");
        assert_eq!(
            inv.args,
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
    fn ipv6_hosts_are_bracketed_for_sftp_and_sshfs() {
        let mut h = host("v6", HostSource::Manual);
        h.hostname = Some("2001:db8::1".into());
        h.user = Some("root".into());
        let inv = build_sftp_invocation(&h, &SshConfig::default(), &SftpConfig::default()).unwrap();
        assert_eq!(inv.args, ["root@[2001:db8::1]"]);
        let mount = MountConfig {
            options: Vec::new(),
            ..MountConfig::default()
        };
        let inv = build_mount_invocation(
            &h,
            &SshConfig::default(),
            &mount,
            None,
            Path::new("/mnt/v6"),
        )
        .unwrap();
        let mut expected = Vec::new();
        if cfg!(target_os = "macos") {
            expected.extend(["-o", "volname=v6"]);
        }
        expected.extend(["root@[2001:db8::1]:", "/mnt/v6"]);
        assert_eq!(inv.args, expected);
    }

    #[test]
    fn sshfs_turns_options_into_dash_o() {
        let mut h = manual_host();
        h.extra_args = Some("-C -4 -o 'ServerAliveCountMax 5' -F cfg -i 'a,b'".into());
        let ssh = SshConfig {
            program: "/opt/ssh".to_owned(),
            extra_args: Vec::new(),
        };
        let mount = MountConfig {
            options: vec!["reconnect,follow_symlinks".to_owned()],
            ..MountConfig::default()
        };
        let inv = build_mount_invocation(&h, &ssh, &mount, Some("/var/www"), Path::new("/mnt/box"))
            .unwrap();
        assert_eq!(inv.program, "sshfs");
        let mut expected = vec![
            "-o",
            "reconnect,follow_symlinks",
            "-o",
            "ssh_command=/opt/ssh",
        ];
        if cfg!(target_os = "macos") {
            expected.extend(["-o", "volname=box"]);
        }
        expected.extend([
            "-o",
            "Port=2222",
            "-o",
            "IdentityFile=~/.ssh/id_test",
            "-o",
            "ProxyJump=jump.invalid",
            "-o",
            "AddressFamily=inet",
            "-o",
            "ServerAliveCountMax=5",
            "-o",
            "IdentityFile=a\\,b",
            "-C",
            "-F",
            "cfg",
            "alice@example.invalid:/var/www",
            "/mnt/box",
        ]);
        assert_eq!(inv.args, expected);
    }

    #[test]
    fn sshfs_mounts_home_by_default_and_guards_the_mountpoint() {
        let mount = MountConfig {
            options: Vec::new(),
            ..MountConfig::default()
        };
        let h = host("prod", HostSource::SshConfig);
        let inv = build_mount_invocation(&h, &SshConfig::default(), &mount, None, Path::new("-m"))
            .unwrap();
        let mut expected = Vec::new();
        if cfg!(target_os = "macos") {
            expected.extend(["-o", "volname=prod"]);
        }
        expected.extend(["prod:", "./-m"]);
        assert_eq!(inv.args, expected);
        // Dangerous targets are rejected here as well.
        let h = host("-oProxyCommand=evil", HostSource::SshConfig);
        assert!(
            build_mount_invocation(&h, &SshConfig::default(), &mount, None, Path::new("/m"))
                .is_err()
        );
        assert!(build_sftp_invocation(&h, &SshConfig::default(), &SftpConfig::default()).is_err());
    }

    #[test]
    fn normalize_and_escape_helpers() {
        assert_eq!(normalize_ssh_option("Port=22"), "Port=22");
        assert_eq!(normalize_ssh_option("Port 22"), "Port=22");
        assert_eq!(normalize_ssh_option(" Port = 22 "), "Port=22");
        assert_eq!(normalize_ssh_option("Compression"), "Compression");
        assert_eq!(escape_fuse_option("a,b\\c"), "a\\,b\\\\c");
    }
}
