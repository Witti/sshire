//! Schema definition and versioning of the database.
//!
//! `rusqlite_migration` stores the schema version in SQLite's `user_version`
//! pragma and only applies the migrations that are still missing. Opening the
//! same file twice is therefore harmless.
//!
//! Important: never change migrations that have already shipped; append new
//! `M::up(...)` entries at the end instead.

use rusqlite_migration::{M, Migrations};

/// Migration 1: initial schema.
///
/// Timestamps are `INTEGER` (Unix milliseconds). Booleans are `INTEGER`
/// with 0/1 (SQLite has no dedicated bool type). `CHECK` protects the enum
/// columns even against writes from outside our code.
const SCHEMA_V1: &str = "
CREATE TABLE hosts (
    id            INTEGER PRIMARY KEY,
    alias         TEXT    NOT NULL UNIQUE,
    hostname      TEXT,
    user          TEXT,
    port          INTEGER CHECK (port IS NULL OR (port BETWEEN 1 AND 65535)),
    identity_file TEXT,
    proxy_jump    TEXT,
    extra_args    TEXT,
    icon          TEXT,
    color         TEXT,
    notes         TEXT,
    source        TEXT    NOT NULL DEFAULT 'manual'
                          CHECK (source IN ('manual', 'ssh_config')),
    favorite      INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
    archived      INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    auth_method   TEXT    NOT NULL DEFAULT 'agent'
                          CHECK (auth_method IN ('agent', 'key', 'password')),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE tags (
    id    INTEGER PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE COLLATE NOCASE,
    color TEXT,
    icon  TEXT
);

CREATE TABLE host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    tag_id  INTEGER NOT NULL REFERENCES tags(id)  ON DELETE CASCADE,
    PRIMARY KEY (host_id, tag_id)
);
CREATE INDEX idx_host_tags_tag ON host_tags(tag_id);

-- status/ended_at/duration_ms/exit_code sind NULL, solange die Verbindung läuft.
CREATE TABLE connections (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    duration_ms INTEGER,
    exit_code   INTEGER,
    status      TEXT CHECK (status IS NULL OR status IN ('success', 'failed'))
);
CREATE INDEX idx_connections_host_started ON connections(host_id, started_at);

-- Nur Linux-Backend (T7).
CREATE TABLE secrets (
    host_id    INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);

-- Schlüssel/Wert-Ablage, z. B. Argon2-Salt und Verifier (T7).
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";

/// Migration 2: reason for archiving.
///
/// `archived_reason` distinguishes "archived by the user" (`user`) from
/// "archived automatically because the host disappeared from `~/.ssh/config`"
/// (`missing`). Only `missing` is undone again by the ssh_config sync.
/// Existing archived rows come from the sync (the TUI could not archive
/// before) and are therefore set to `missing`.
const SCHEMA_V2: &str = "
ALTER TABLE hosts ADD COLUMN archived_reason TEXT
    CHECK (archived_reason IS NULL OR archived_reason IN ('user', 'missing'));
UPDATE hosts SET archived_reason = 'missing' WHERE archived = 1;
";

/// Migration 3: marker "a password is stored for this host".
///
/// The password itself is never in the database (Keychain or the encrypted
/// `secrets` table). The flag spares the TUI from querying the Keychain on
/// every redraw. Rows that are already in `secrets` get the flag directly
/// (the table was unused so far; the statement is just a precaution).
const SCHEMA_V3: &str = "
ALTER TABLE hosts ADD COLUMN has_password INTEGER NOT NULL DEFAULT 0
    CHECK (has_password IN (0, 1));
UPDATE hosts SET has_password = 1 WHERE id IN (SELECT host_id FROM secrets);
";

/// Returns the list of all migrations in order.
pub fn migrations() -> Migrations<'static> {
    // `'static` is a lifetime: the SQL texts are constants and live as long
    // as the whole program.
    Migrations::new(vec![M::up(SCHEMA_V1), M::up(SCHEMA_V2), M::up(SCHEMA_V3)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_valid() {
        // Validates the migrations against a temporary in-memory DB.
        migrations().validate().unwrap();
    }

    #[test]
    fn v1_database_with_data_migrates_to_v2() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        // State of the shipped version: only migration 1 applied.
        Migrations::new(vec![M::up(SCHEMA_V1)])
            .to_latest(&mut conn)
            .unwrap();
        for (alias, archived) in [("alive", 0), ("gone", 1)] {
            conn.execute(
                "INSERT INTO hosts (alias, archived, created_at, updated_at) VALUES (?1, ?2, 1, 1)",
                rusqlite::params![alias, archived],
            )
            .unwrap();
        }
        migrations().to_latest(&mut conn).unwrap();
        let reason = |alias: &str| -> Option<String> {
            conn.query_row(
                "SELECT archived_reason FROM hosts WHERE alias = ?1",
                [alias],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(reason("alive"), None);
        assert_eq!(reason("gone").as_deref(), Some("missing"));
        // The CHECK rejects unknown reasons.
        assert!(
            conn.execute("UPDATE hosts SET archived_reason = 'x'", [])
                .is_err()
        );
    }

    #[test]
    fn v2_database_with_data_migrates_to_v3() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        // State before T7: migrations 1 and 2.
        Migrations::new(vec![M::up(SCHEMA_V1), M::up(SCHEMA_V2)])
            .to_latest(&mut conn)
            .unwrap();
        for alias in ["plain", "legacy"] {
            conn.execute(
                "INSERT INTO hosts (alias, created_at, updated_at) VALUES (?1, 1, 1)",
                [alias],
            )
            .unwrap();
        }
        // A (hypothetical) legacy row in `secrets` is detected as "has password".
        conn.execute(
            "INSERT INTO secrets (host_id, nonce, ciphertext) \
             SELECT id, x'00', x'00' FROM hosts WHERE alias = 'legacy'",
            [],
        )
        .unwrap();
        migrations().to_latest(&mut conn).unwrap();
        let flag = |alias: &str| -> i64 {
            conn.query_row(
                "SELECT has_password FROM hosts WHERE alias = ?1",
                [alias],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(flag("plain"), 0);
        assert_eq!(flag("legacy"), 1);
        // The CHECK rejects values outside 0/1.
        assert!(
            conn.execute("UPDATE hosts SET has_password = 2", [])
                .is_err()
        );
    }
}
