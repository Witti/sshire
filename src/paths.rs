//! Resolving sshire's directories and file paths.
//!
//! * Config directory (e.g. `~/.config/sshire/` or the macOS equivalent)
//! * Data directory (the SQLite file `sshire.db` lives here)
//! * Path to `~/.ssh/config` (read-only)

use std::path::{Path, PathBuf};

use directories::{BaseDirs, ProjectDirs};
use thiserror::Error;

/// File name of the SQLite database.
const DB_FILE_NAME: &str = "sshire.db";

// `thiserror` automatically derives the `Display` and `std::error::Error`
// traits for this enum. The text in `#[error(...)]` is the error message.
// Dedicated error types are common for library modules; `main` can pass
// them along conveniently thanks to `anyhow`.
/// Errors while resolving paths.
#[derive(Debug, Error)]
pub enum PathError {
    /// No home directory could be determined.
    #[error("Could not determine the home directory")]
    NoHomeDir,
    /// A directory could not be created.
    #[error("Could not create directory {path}")]
    CreateDir {
        path: PathBuf,
        // `#[source]` attaches the original error as the cause.
        #[source]
        source: std::io::Error,
    },
}

/// Returns the platform-standard project directories for sshire.
fn project_dirs() -> Result<ProjectDirs, PathError> {
    // `ProjectDirs::from` returns an `Option`. `ok_or` turns it into a
    // `Result`: `None` becomes our error, `Some(x)` becomes `Ok(x)`.
    ProjectDirs::from("", "", "sshire").ok_or(PathError::NoHomeDir)
}

/// Creates `dir` including any missing parent directories (if needed) and returns it.
fn ensure_dir(dir: &Path) -> Result<PathBuf, PathError> {
    // `map_err` converts the error type; the `?` after it immediately returns
    // `Err(..)` to the caller on failure, otherwise the function carries on.
    std::fs::create_dir_all(dir).map_err(|source| PathError::CreateDir {
        path: dir.to_path_buf(),
        source,
    })?;
    Ok(dir.to_path_buf())
}

/// sshire's config directory; created on demand.
pub fn config_dir() -> Result<PathBuf, PathError> {
    ensure_dir(project_dirs()?.config_dir())
}

/// sshire's data directory; created on demand.
pub fn data_dir() -> Result<PathBuf, PathError> {
    ensure_dir(project_dirs()?.data_dir())
}

/// Path of the SQLite database `sshire.db` in the data directory.
///
/// The directory is created, the file itself is not.
pub fn db_path() -> Result<PathBuf, PathError> {
    Ok(db_path_in(&data_dir()?))
}

/// Appends the DB file name to a directory (pure function, easy to test).
fn db_path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILE_NAME)
}

/// The user's home directory.
pub fn home_dir() -> Result<PathBuf, PathError> {
    let base = BaseDirs::new().ok_or(PathError::NoHomeDir)?;
    Ok(base.home_dir().to_path_buf())
}

/// Path to the user's `~/.ssh/config`. The file does not have to exist.
pub fn ssh_config_path() -> Result<PathBuf, PathError> {
    Ok(ssh_config_path_in(&home_dir()?))
}

/// Builds the ssh config path relative to a home directory.
fn ssh_config_path_in(home: &Path) -> PathBuf {
    home.join(".ssh").join("config")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_path_has_expected_file_name() {
        let p = db_path_in(Path::new("/tmp/data"));
        assert_eq!(p, PathBuf::from("/tmp/data/sshire.db"));
    }

    #[test]
    fn ssh_config_path_is_under_dot_ssh() {
        let p = ssh_config_path_in(Path::new("/home/alice"));
        assert_eq!(p, PathBuf::from("/home/alice/.ssh/config"));
    }

    #[test]
    fn ensure_dir_creates_nested_directories() {
        let base = std::env::temp_dir().join(format!("sshire-test-{}", std::process::id()));
        let nested = base.join("a").join("b");
        assert!(ensure_dir(&nested).is_ok());
        assert!(nested.is_dir());
        // Clean up; errors here don't matter for the test.
        let _ = std::fs::remove_dir_all(&base);
    }
}
