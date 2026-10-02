//! Helpers for mounting hosts with sshfs: where the mount point lives,
//! whether something is mounted there, and how to unmount it again.
//!
//! The mount itself is an ordinary invocation (see `command.rs`) that
//! `connect::run` starts like ssh: sshfs authenticates in the foreground
//! (password via askpass, host key prompts in the terminal) and then moves
//! into the background, so the call returns once the mount is up.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::MountConfig;
use crate::paths;

/// Default mount point of a host: `<mount.dir>/<alias>`.
pub fn default_mountpoint(config: &MountConfig, alias: &str) -> Result<PathBuf> {
    Ok(expand_dir(&config.dir)?.join(dir_name(alias)))
}

/// Resolves `~` and relative paths of the configured base directory.
fn expand_dir(dir: &str) -> Result<PathBuf> {
    let dir = dir.trim();
    let path = if dir == "~" {
        paths::home_dir()?
    } else if let Some(rest) = dir.strip_prefix("~/") {
        paths::home_dir()?.join(rest)
    } else {
        PathBuf::from(dir)
    };
    absolute(&path)
}

/// Makes a path absolute (relative to the current directory), without
/// touching the file system otherwise.
pub fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("invalid path {}", path.display()))
}

/// Turns an alias into a single, harmless directory name.
fn dir_name(alias: &str) -> String {
    let name: String = alias
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    match name.as_str() {
        "" | "." | ".." => "_".to_owned(),
        _ => name,
    }
}

/// Is a file system mounted at `path`?
///
/// A mount point lies on a different device than its parent directory. If
/// the directory cannot even be read (e.g. "Transport endpoint is not
/// connected" after the server went away), a dead mount is assumed - it
/// still has to be unmounted.
#[cfg(unix)]
pub fn is_mounted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = path.parent() else {
        return false;
    };
    match (std::fs::metadata(path), std::fs::metadata(parent)) {
        (Ok(own), Ok(up)) => own.dev() != up.dev(),
        (Err(err), _) if err.kind() == std::io::ErrorKind::NotFound => false,
        (Err(_), _) => true,
        (Ok(_), Err(_)) => false,
    }
}

#[cfg(not(unix))]
pub fn is_mounted(_path: &Path) -> bool {
    false
}

/// Creates the mount point if needed and rejects one that is already in use.
///
/// Returns whether the directory was created here, so a failed mount can
/// remove it again without touching a directory the user made.
pub fn prepare_mountpoint(path: &Path) -> Result<bool> {
    if is_mounted(path) {
        bail!(
            "{} is already mounted (unmount it with `sshire umount`)",
            path.display()
        );
    }
    if path.is_dir() {
        return Ok(false);
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("could not create mount point {}", path.display()))?;
    Ok(true)
}

/// Unmount commands in the order they are tried.
fn unmount_commands(path: &str) -> Vec<(&'static str, Vec<String>)> {
    let path = path.to_owned();
    if cfg!(target_os = "macos") {
        vec![
            ("umount", vec![path.clone()]),
            ("diskutil", vec!["unmount".to_owned(), path]),
        ]
    } else {
        vec![
            ("fusermount3", vec!["-u".to_owned(), path.clone()]),
            ("fusermount", vec!["-u".to_owned(), path.clone()]),
            ("umount", vec![path]),
        ]
    }
}

/// Unmounts `path` with the platform's tools.
///
/// The output of the tools is captured (the TUI keeps the terminal) and only
/// shows up in the error message.
pub fn unmount(path: &Path) -> Result<()> {
    let text = path
        .to_str()
        .with_context(|| format!("invalid mount point {}", path.display()))?;
    let mut first_error: Option<String> = None;
    for (program, args) in unmount_commands(text) {
        match Command::new(program).args(&args).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = stderr.trim();
                let reason = if reason.is_empty() {
                    format!("exit {}", output.status.code().unwrap_or(-1))
                } else {
                    reason.to_owned()
                };
                first_error.get_or_insert(format!("{program}: {reason}"));
            }
            // Tool not installed: try the next one.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                first_error.get_or_insert(format!("{program}: {err}"));
            }
        }
    }
    match first_error {
        Some(reason) => bail!("could not unmount {}: {reason}", path.display()),
        None => bail!(
            "could not unmount {}: no unmount tool found",
            path.display()
        ),
    }
}

/// Removes the (empty) mount point after unmounting; errors are ignored,
/// e.g. if the user put files there.
pub fn remove_mountpoint(path: &Path) {
    let _ = std::fs::remove_dir(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_name_is_a_single_harmless_component() {
        assert_eq!(dir_name("web"), "web");
        assert_eq!(dir_name("a/b"), "a_b");
        assert_eq!(dir_name(".."), "_");
        assert_eq!(dir_name("."), "_");
        assert_eq!(dir_name(""), "_");
    }

    #[test]
    fn default_mountpoint_expands_home_and_appends_alias() {
        let config = MountConfig {
            dir: "~/mnt".to_owned(),
            ..MountConfig::default()
        };
        let home = paths::home_dir().unwrap();
        assert_eq!(
            default_mountpoint(&config, "web").unwrap(),
            home.join("mnt").join("web")
        );
        let config = MountConfig {
            dir: "/srv/mounts".to_owned(),
            ..MountConfig::default()
        };
        assert_eq!(
            default_mountpoint(&config, "x/y").unwrap(),
            PathBuf::from("/srv/mounts/x_y")
        );
        // Relative directories become absolute.
        let config = MountConfig {
            dir: "rel".to_owned(),
            ..MountConfig::default()
        };
        assert!(default_mountpoint(&config, "web").unwrap().is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn plain_directories_are_not_mounted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_mounted(dir.path()));
        assert!(!is_mounted(&dir.path().join("missing")));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_creates_the_mountpoint() {
        let dir = tempfile::tempdir().unwrap();
        let point = dir.path().join("a").join("web");
        assert!(prepare_mountpoint(&point).unwrap());
        assert!(point.is_dir());
        // Again: fine, nothing is mounted there - but not created this time.
        assert!(!prepare_mountpoint(&point).unwrap());
        remove_mountpoint(&point);
        assert!(!point.exists());
    }
}
