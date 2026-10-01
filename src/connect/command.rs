//! Building the ssh command from a [`Host`].
//!
//! Everything here is a *pure* function: nothing starts a process or reads
//! files. That makes all combinations easy to test.

use thiserror::Error;

use crate::config::SshConfig;
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
}
