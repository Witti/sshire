//! Persistence layer: SQLite database (`sshire.db`).
//!
//! Module layout:
//! * `migrations` – schema definition and versioning of the database
//! * `hosts`      – host models and host queries
//! * `tags`       – tags and the host <-> tag assignment
//! * `connections`– connection log and statistics
//!
//! The central type is [`Store`]: it owns the database connection, and all
//! operations are methods on it (spread across several `impl` blocks in the
//! submodules).

mod connections;
mod hosts;
mod migrations;
mod tags;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::ErrorCode;
use thiserror::Error;

// Re-exports: this lets you write `store::Host` instead of `store::hosts::Host`.
pub use connections::{Connection, ConnectionStatus, HostStats};
pub use hosts::{AuthMethod, HostUpdate, NewHost};
pub use hosts::{Host, HostSource, SshConfigHost};
// `Tag` lives inside `Host::tags`; the export names the type explicitly.
pub use tags::Tag;

/// Errors of the store layer.
///
/// `#[derive(Error)]` (thiserror) generates `Display` and `std::error::Error`.
/// `#[from]` additionally generates a `From` implementation: this lets the
/// `?` operator convert a `rusqlite::Error` into a `StoreError` automatically,
/// without us having to write `map_err`.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Any SQLite error that has no variant of its own.
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The migrations could not be applied.
    #[error("Migration failed: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    /// A host with this alias already exists (or collides).
    #[error("A host with the alias \"{0}\" already exists")]
    DuplicateAlias(String),
    /// A tag with this name already exists.
    #[error("A tag named \"{0}\" already exists")]
    #[allow(dead_code)] // only produced by `create_tag` (see there)
    DuplicateTag(String),
    /// The requested record does not exist.
    #[error("{entity} with ID {id} was not found")]
    NotFound { entity: &'static str, id: i64 },
    /// An input is invalid (e.g. an empty tag name).
    #[error("Invalid input: {0}")]
    InvalidInput(&'static str),
}

/// Shorthand for results of the store layer.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Error when reading an unknown enum text from the database.
///
/// Used by the enums' `FromSql` implementations.
#[derive(Debug, Error)]
#[error("unknown value \"{value}\" for {kind}")]
pub(crate) struct InvalidEnumValue {
    pub kind: &'static str,
    pub value: String,
}

/// Current time as Unix milliseconds (`i64`), the database's time format.
pub fn now_ms() -> i64 {
    // `duration_since` only fails if the system clock is before 1970.
    // `unwrap_or_default()` then yields `Duration::ZERO` instead of panicking.
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // `as_millis()` is `u128`; `try_from` checks whether it fits into `i64`.
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

/// Checks whether a SQLite error is a violation of a UNIQUE / PRIMARY KEY
/// constraint (e.g. a duplicate alias).
pub(crate) fn is_unique_violation(err: &rusqlite::Error) -> bool {
    // `matches!` is shorthand for a `match` that returns `true`/`false`.
    // The `if` after the pattern is a "guard" (an additional condition).
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == ErrorCode::ConstraintViolation
                && (e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    || e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
    )
}

/// Handle to the SQLite database.
///
/// The store *owns* the connection. When it is dropped (`Drop`), the
/// connection closes automatically – an example of RAII (resources are tied
/// to the lifetime of values).
pub struct Store {
    // The field is private; the submodules (`hosts`, `tags`, …) may still use
    // it, because private fields are visible to the module *and* its child
    // modules.
    conn: rusqlite::Connection,
}

impl Store {
    /// Opens (or creates) the database file and migrates the schema.
    ///
    /// `impl AsRef<Path>` means: any type that can be viewed as a `&Path`
    /// (`&str`, `String`, `PathBuf`, …) is allowed as an argument.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        // WAL (write-ahead log): readers don't block writers. The pragma returns
        // a result row (the new mode), so we read it with `query_row` instead
        // of using `execute`.
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        // Waits up to 5 s on a locked DB instead of reporting "busy" immediately.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Self::init(conn)
    }

    /// Opens a transient in-memory database (tests only).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(rusqlite::Connection::open_in_memory()?)
    }

    /// Shared initialization: enable foreign keys, migrate the schema.
    fn init(mut conn: rusqlite::Connection) -> Result<Self> {
        // SQLite only enforces foreign keys (and thus `ON DELETE CASCADE`) if you
        // explicitly switch it on per connection.
        conn.pragma_update(None, "foreign_keys", true)?;
        // `&mut conn`: the migration needs a *mutable* borrow.
        migrations::migrations().to_latest(&mut conn)?;
        Ok(Self { conn })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_is_idempotent_on_file_db() {
        let dir =
            std::env::temp_dir().join(format!("sshire-test-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sshire.db");

        {
            let store = Store::open(&path).unwrap();
            store.insert_host(&NewHost::new("a")).unwrap();
        } // `store` is dropped here -> connection closed

        // Second open: migrations run again, data is preserved.
        let store = Store::open(&path).unwrap();
        assert_eq!(store.list_hosts(true).unwrap().len(), 1);
        let fk: i64 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let store = Store::open_in_memory().unwrap();
        let err = store.conn.execute(
            "INSERT INTO host_tags (host_id, tag_id) VALUES (999, 999)",
            [],
        );
        assert!(err.is_err());
    }

    #[test]
    fn now_ms_is_plausible() {
        // After 2020-01-01 in milliseconds.
        assert!(now_ms() > 1_577_836_800_000);
    }
}
