//! Host models and host queries.

use std::collections::{HashMap, HashSet};

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Row, params};

use super::tags::{Tag, load_tags_for_all_hosts, load_tags_for_host, set_host_tags_on};
use super::{InvalidEnumValue, Result, Store, StoreError, is_unique_violation, now_ms};

// ---------------------------------------------------------------------------
// Enums with TEXT conversion
// ---------------------------------------------------------------------------

/// Where a host comes from.
// `derive` generates trait implementations automatically. `Default` with
// `#[default]` marks the variant returned by `HostSource::default()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostSource {
    /// Created in sshire itself.
    #[default]
    Manual,
    /// Imported from `~/.ssh/config`.
    SshConfig,
}

impl HostSource {
    /// The text stored in the database (must match the `CHECK`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::SshConfig => "ssh_config",
        }
    }

    /// Counterpart to [`as_str`](Self::as_str); `None` for unknown text.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "manual" => Some(Self::Manual),
            "ssh_config" => Some(Self::SshConfig),
            _ => None,
        }
    }
}

// A *trait* describes capabilities a type can have (similar to an
// interface). By implementing `ToSql`, `HostSource` may be used directly as
// a parameter in `params![...]` – rusqlite then calls this method.
impl ToSql for HostSource {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        // `.into()` uses a `From` implementation: &str -> ToSqlOutput.
        Ok(self.as_str().into())
    }
}

// `FromSql` is the opposite direction: it lets rusqlite evaluate
// `row.get::<_, HostSource>(..)`. `ValueRef` is a borrowed view of the raw
// SQLite value.
impl FromSql for HostSource {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        // `as_str()?`: fails if the column is not TEXT (the `?` passes the
        // `FromSqlError` straight on).
        let text = value.as_str()?;
        Self::parse(text).ok_or_else(|| {
            FromSqlError::Other(Box::new(InvalidEnumValue {
                kind: "HostSource",
                value: text.to_owned(),
            }))
        })
    }
}

/// How authentication happens when connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMethod {
    /// ssh-agent or ssh's default behavior.
    #[default]
    Agent,
    /// Explicit key (`identity_file`).
    Key,
    /// Password (from the SecretStore, T7).
    Password,
}

impl AuthMethod {
    /// The text stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Key => "key",
            Self::Password => "password",
        }
    }

    /// Counterpart to [`as_str`](Self::as_str).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "agent" => Some(Self::Agent),
            "key" => Some(Self::Key),
            "password" => Some(Self::Password),
            _ => None,
        }
    }
}

impl ToSql for AuthMethod {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.as_str().into())
    }
}

impl FromSql for AuthMethod {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let text = value.as_str()?;
        Self::parse(text).ok_or_else(|| {
            FromSqlError::Other(Box::new(InvalidEnumValue {
                kind: "AuthMethod",
                value: text.to_owned(),
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/// A host as it is stored in the database (incl. tags).
///
/// `Option<T>` is Rust's replacement for `NULL`: `Some(value)` or `None`.
/// rusqlite maps SQL `NULL` to `None` automatically (and vice versa).
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub id: i64,
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub extra_args: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub notes: Option<String>,
    pub source: HostSource,
    pub favorite: bool,
    pub archived: bool,
    pub auth_method: AuthMethod,
    /// Is a password stored for this host? (Only the marker – the password
    /// itself lives in the `SecretStore`, never in the database.)
    pub has_password: bool,
    /// Unix milliseconds.
    pub created_at: i64,
    /// Unix milliseconds.
    pub updated_at: i64,
    pub tags: Vec<Tag>,
}

/// Data for creating a new host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NewHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub extra_args: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub notes: Option<String>,
    pub source: HostSource,
    pub auth_method: AuthMethod,
}

impl NewHost {
    /// Minimal host with only an alias; everything else is empty/default (test helper).
    #[cfg(test)]
    pub fn new(alias: impl Into<String>) -> Self {
        // `..Default::default()` fills all unnamed fields with their default
        // values (struct update syntax).
        Self {
            alias: alias.into(),
            ..Default::default()
        }
    }
}

/// All fields changeable via [`Store::update_host`].
///
/// `source`, `favorite`, `archived` and timestamps are deliberately not
/// handled here but through dedicated methods or maintained automatically.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostUpdate {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
    pub extra_args: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub notes: Option<String>,
    pub auth_method: AuthMethod,
}

/// The fields of a host that come from `~/.ssh/config` (for the sync, T3).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshConfigHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
    pub proxy_jump: Option<String>,
}

/// Column list for all host queries (must match [`host_from_row`]).
const HOST_COLUMNS: &str = "id, alias, hostname, user, port, identity_file, proxy_jump, \
     extra_args, icon, color, notes, source, favorite, archived, auth_method, \
     has_password, created_at, updated_at";

/// Builds a [`Host`] from a result row (without tags yet).
///
/// `row.get("name")` reads the column by name; the target type is derived
/// from the field type (type inference) and converted via `FromSql`.
fn host_from_row(row: &Row<'_>) -> rusqlite::Result<Host> {
    Ok(Host {
        id: row.get("id")?,
        alias: row.get("alias")?,
        hostname: row.get("hostname")?,
        user: row.get("user")?,
        port: row.get("port")?,
        identity_file: row.get("identity_file")?,
        proxy_jump: row.get("proxy_jump")?,
        extra_args: row.get("extra_args")?,
        icon: row.get("icon")?,
        color: row.get("color")?,
        notes: row.get("notes")?,
        source: row.get("source")?,
        favorite: row.get("favorite")?,
        archived: row.get("archived")?,
        auth_method: row.get("auth_method")?,
        has_password: row.get("has_password")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        tags: Vec::new(),
    })
}

/// Translates a UNIQUE error into [`StoreError::DuplicateAlias`].
fn alias_error(err: rusqlite::Error, alias: &str) -> StoreError {
    if is_unique_violation(&err) {
        StoreError::DuplicateAlias(alias.to_owned())
    } else {
        StoreError::Sqlite(err)
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

// An `impl` block attaches methods to a type. You may have any number of
// `impl Store` blocks – we spread them across several files.
//
// `&self`  = read-only access to the store (a borrow).
// `&mut self` = exclusive, mutating access; needed for transactions,
// because `Connection::transaction` itself requires `&mut`.
impl Store {
    /// Creates a host and returns the new ID. Production code uses the atomic
    /// variant `insert_host_with_tags`; this one is a shorthand for tests.
    #[cfg(test)]
    pub fn insert_host(&self, new: &NewHost) -> Result<i64> {
        insert_host_on(&self.conn, new)
    }

    /// Creates a host *and* sets its tags – all in one transaction:
    /// if a step fails, the host is not created either.
    pub fn insert_host_with_tags<S: AsRef<str>>(
        &mut self,
        new: &NewHost,
        tags: &[S],
    ) -> Result<i64> {
        let tx = self.conn.transaction()?;
        // `&tx` automatically becomes `&Connection`: `Transaction` implements
        // `Deref<Target = Connection>` ("deref coercion"). That way the same
        // helper functions work inside and outside a transaction.
        let id = insert_host_on(&tx, new)?;
        set_host_tags_on(&tx, id, tags)?;
        // Without `commit`, `Drop` would roll everything back.
        tx.commit()?;
        Ok(id)
    }

    /// Updates a host and replaces its tags, atomically in one transaction.
    pub fn update_host_with_tags<S: AsRef<str>>(
        &mut self,
        id: i64,
        upd: &HostUpdate,
        tags: &[S],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        update_host_on(&tx, id, upd)?;
        set_host_tags_on(&tx, id, tags)?;
        tx.commit()?;
        Ok(())
    }

    /// Overwrites a host's editable fields (shorthand for tests, see
    /// `update_host_with_tags`).
    #[cfg(test)]
    pub fn update_host(&self, id: i64, upd: &HostUpdate) -> Result<()> {
        update_host_on(&self.conn, id, upd)
    }

    /// Fetches a host by ID (incl. tags); `None` if it doesn't exist.
    pub fn get_host(&self, id: i64) -> Result<Option<Host>> {
        self.get_host_where("id = ?1", params![id])
    }

    /// Fetches a host by alias (incl. tags); `None` if it doesn't exist.
    pub fn get_host_by_alias(&self, alias: &str) -> Result<Option<Host>> {
        self.get_host_where("alias = ?1", params![alias])
    }

    /// Shared part of `get_host*`. `where_clause` is always a fixed text from
    /// our code here; values come exclusively via `params`.
    fn get_host_where(
        &self,
        where_clause: &str,
        params: impl rusqlite::Params,
    ) -> Result<Option<Host>> {
        let sql = format!("SELECT {HOST_COLUMNS} FROM hosts WHERE {where_clause}");
        // `query_row` expects exactly one row; `.optional()` (trait
        // `OptionalExtension`) turns "no row" into `Ok(None)` instead of an error.
        use rusqlite::OptionalExtension;
        let host = self
            .conn
            .query_row(&sql, params, host_from_row)
            .optional()?;
        match host {
            Some(mut host) => {
                host.tags = load_tags_for_host(&self.conn, host.id)?;
                Ok(Some(host))
            }
            None => Ok(None),
        }
    }

    /// Lists hosts alphabetically (case-insensitive), incl. tags.
    ///
    /// Avoids the "N+1" problem: instead of issuing one tag query per host,
    /// there are exactly two queries (hosts, then all tags).
    pub fn list_hosts(&self, include_archived: bool) -> Result<Vec<Host>> {
        let sql = format!(
            "SELECT {HOST_COLUMNS} FROM hosts WHERE (?1 OR archived = 0) \
             ORDER BY alias COLLATE NOCASE, id"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        // `query_map` calls the closure for each row and returns an iterator of
        // `Result<Host>`. `collect::<Result<Vec<_>, _>>()` gathers everything
        // into a `Vec` and stops at the first error.
        let mut hosts = stmt
            .query_map(params![include_archived], host_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut tags_by_host: HashMap<i64, Vec<Tag>> = load_tags_for_all_hosts(&self.conn)?;
        for host in &mut hosts {
            // `remove` moves the Vec out of the map (no copying);
            // `unwrap_or_default` yields an empty Vec for hosts without tags.
            host.tags = tags_by_host.remove(&host.id).unwrap_or_default();
        }
        Ok(hosts)
    }

    /// Deletes a host; tag assignments, log and secrets disappear via CASCADE.
    pub fn delete_host(&self, id: i64) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM hosts WHERE id = ?1", params![id])?;
        require_changed(changed, id)
    }

    /// Sets or removes the favorite star.
    pub fn set_favorite(&self, id: i64, favorite: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE hosts SET favorite = ?1, updated_at = ?2 WHERE id = ?3",
            params![favorite, now_ms(), id],
        )?;
        require_changed(changed, id)
    }

    /// Maintains the "password stored" marker. The password itself is managed
    /// by the `SecretStore`; this method only changes the flag.
    pub fn set_has_password(&self, id: i64, has_password: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE hosts SET has_password = ?1 WHERE id = ?2",
            params![has_password, id],
        )?;
        require_changed(changed, id)
    }

    /// Archives a host (reason `user`: deliberately by the user, the ssh_config
    /// sync does not undo this) or restores it (the reason is cleared).
    pub fn set_archived(&self, id: i64, archived: bool) -> Result<()> {
        let reason = archived.then_some("user");
        let changed = self.conn.execute(
            "UPDATE hosts SET archived = ?1, archived_reason = ?2, updated_at = ?3 WHERE id = ?4",
            params![archived, reason, now_ms(), id],
        )?;
        require_changed(changed, id)
    }

    /// Creates or updates an `ssh_config` host (key: alias).
    ///
    /// For an existing entry, only hostname/user/port/identity_file/proxy_jump
    /// are overwritten; a host archived automatically (`missing`) is
    /// reactivated, one archived by the user (`user`) stays archived; icon,
    /// notes, color, favorite and tags are left untouched. If the alias already
    /// exists as a *manual* host, it is not touched and
    /// [`StoreError::DuplicateAlias`] is returned (the caller can skip it).
    pub fn upsert_ssh_config_host(&self, host: &SshConfigHost) -> Result<i64> {
        use rusqlite::OptionalExtension;
        let now = now_ms();
        // `ON CONFLICT ... DO UPDATE ... WHERE`: update only for ssh_config rows.
        // `RETURNING id` yields the ID; if the WHERE doesn't match, no row comes back.
        let id = self
            .conn
            .query_row(
                "INSERT INTO hosts (alias, hostname, user, port, identity_file, proxy_jump, \
                 source, auth_method, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ssh_config', 'agent', ?7, ?7) \
                 ON CONFLICT(alias) DO UPDATE SET \
                    hostname = excluded.hostname, user = excluded.user, \
                    port = excluded.port, identity_file = excluded.identity_file, \
                    proxy_jump = excluded.proxy_jump, \
                    archived = CASE WHEN hosts.archived_reason = 'user' THEN 1 ELSE 0 END, \
                    archived_reason = CASE WHEN hosts.archived_reason = 'user' \
                        THEN 'user' ELSE NULL END, \
                    updated_at = excluded.updated_at \
                 WHERE hosts.source = 'ssh_config' \
                 RETURNING id",
                params![
                    host.alias,
                    host.hostname,
                    host.user,
                    host.port,
                    host.identity_file,
                    host.proxy_jump,
                    now,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        id.ok_or_else(|| StoreError::DuplicateAlias(host.alias.clone()))
    }

    /// Archives all `ssh_config` hosts whose alias does not appear in
    /// `present_aliases`. Returns the number of newly archived hosts.
    ///
    /// `&mut self` because a transaction runs here: either all hosts are
    /// archived or (on an error) none.
    pub fn archive_missing_ssh_config_hosts(
        &mut self,
        present_aliases: &[String],
    ) -> Result<usize> {
        let present: HashSet<&str> = present_aliases.iter().map(String::as_str).collect();
        let tx = self.conn.transaction()?;
        let now = now_ms();

        let candidates: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, alias FROM hosts WHERE source = 'ssh_config' AND archived = 0",
            )?;
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };

        let mut archived = 0;
        for (id, alias) in candidates {
            if !present.contains(alias.as_str()) {
                tx.execute(
                    "UPDATE hosts SET archived = 1, archived_reason = 'missing', updated_at = ?1 WHERE id = ?2",
                    params![now, id],
                )?;
                archived += 1;
            }
        }
        // Without `commit()`, the transaction would be rolled back automatically
        // via `Drop` when leaving the scope (RAII).
        tx.commit()?;
        Ok(archived)
    }
}

/// INSERT on any connection (also inside a transaction).
fn insert_host_on(conn: &rusqlite::Connection, new: &NewHost) -> Result<i64> {
    let now = now_ms();
    // `params![...]` binds values to `?1, ?2, …` – never build values into the
    // SQL via string formatting (SQL injection!).
    conn.execute(
        "INSERT INTO hosts (alias, hostname, user, port, identity_file, proxy_jump, \
         extra_args, icon, color, notes, source, auth_method, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)",
        params![
            new.alias,
            new.hostname,
            new.user,
            new.port,
            new.identity_file,
            new.proxy_jump,
            new.extra_args,
            new.icon,
            new.color,
            new.notes,
            new.source,
            new.auth_method,
            now,
        ],
    )
    // Closure `|e| ...`: a small anonymous function that only runs on error.
    .map_err(|e| alias_error(e, &new.alias))?;
    Ok(conn.last_insert_rowid())
}

/// UPDATE on any connection (also inside a transaction).
fn update_host_on(conn: &rusqlite::Connection, id: i64, upd: &HostUpdate) -> Result<()> {
    let changed = conn
        .execute(
            "UPDATE hosts SET alias = ?1, hostname = ?2, user = ?3, port = ?4, \
             identity_file = ?5, proxy_jump = ?6, extra_args = ?7, icon = ?8, \
             color = ?9, notes = ?10, auth_method = ?11, updated_at = ?12 \
             WHERE id = ?13",
            params![
                upd.alias,
                upd.hostname,
                upd.user,
                upd.port,
                upd.identity_file,
                upd.proxy_jump,
                upd.extra_args,
                upd.icon,
                upd.color,
                upd.notes,
                upd.auth_method,
                now_ms(),
                id,
            ],
        )
        .map_err(|e| alias_error(e, &upd.alias))?;
    require_changed(changed, id)
}

/// Converts "0 rows affected" into [`StoreError::NotFound`].
fn require_changed(changed: usize, id: i64) -> Result<()> {
    if changed == 0 {
        Err(StoreError::NotFound { entity: "Host", id })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn has_password_flag_is_maintained() {
        let s = store();
        let id = s.insert_host(&NewHost::new("a")).unwrap();
        assert!(!s.get_host(id).unwrap().unwrap().has_password);
        s.set_has_password(id, true).unwrap();
        assert!(s.get_host(id).unwrap().unwrap().has_password);
        assert!(s.list_hosts(true).unwrap()[0].has_password);
        s.set_has_password(id, false).unwrap();
        assert!(!s.get_host(id).unwrap().unwrap().has_password);
        assert!(matches!(
            s.set_has_password(999, true),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn update_host_keeps_has_password_flag() {
        let s = store();
        let id = s.insert_host(&NewHost::new("a")).unwrap();
        s.set_has_password(id, true).unwrap();
        let upd = HostUpdate {
            alias: "renamed".into(),
            ..Default::default()
        };
        s.update_host(id, &upd).unwrap();
        assert!(s.get_host(id).unwrap().unwrap().has_password);
    }

    #[test]
    fn enum_text_roundtrip() {
        for s in [HostSource::Manual, HostSource::SshConfig] {
            assert_eq!(HostSource::parse(s.as_str()), Some(s));
        }
        for a in [AuthMethod::Agent, AuthMethod::Key, AuthMethod::Password] {
            assert_eq!(AuthMethod::parse(a.as_str()), Some(a));
        }
        assert_eq!(HostSource::parse("x"), None);
        assert_eq!(AuthMethod::parse(""), None);
    }

    #[test]
    fn enum_sql_roundtrip_and_invalid_value() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let back: AuthMethod = conn
            .query_row("SELECT ?1", params![AuthMethod::Password], |r| r.get(0))
            .unwrap();
        assert_eq!(back, AuthMethod::Password);
        let back: HostSource = conn
            .query_row("SELECT ?1", params![HostSource::SshConfig], |r| r.get(0))
            .unwrap();
        assert_eq!(back, HostSource::SshConfig);
        // Unknown text -> error instead of a panic.
        let bad: rusqlite::Result<AuthMethod> = conn.query_row("SELECT 'bogus'", [], |r| r.get(0));
        assert!(bad.is_err());
    }

    #[test]
    fn check_constraint_rejects_invalid_enum_text() {
        let s = store();
        let res = s.conn.execute(
            "INSERT INTO hosts (alias, source, created_at, updated_at) VALUES ('x', 'nope', 0, 0)",
            [],
        );
        assert!(res.is_err());
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let s = store();
        let new = NewHost {
            alias: "web".into(),
            hostname: Some("example.com".into()),
            user: Some("root".into()),
            port: Some(2222),
            identity_file: Some("~/.ssh/id".into()),
            proxy_jump: Some("bastion".into()),
            extra_args: Some("-A".into()),
            icon: Some("🌐".into()),
            color: Some("#ff0000".into()),
            notes: Some("Note".into()),
            source: HostSource::Manual,
            auth_method: AuthMethod::Key,
        };
        let id = s.insert_host(&new).unwrap();
        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!(h.alias, "web");
        assert_eq!(h.hostname.as_deref(), Some("example.com"));
        assert_eq!(h.port, Some(2222));
        assert_eq!(h.auth_method, AuthMethod::Key);
        assert_eq!(h.icon.as_deref(), Some("🌐"));
        assert!(!h.favorite && !h.archived);
        assert!(h.tags.is_empty());
        assert_eq!(h.created_at, h.updated_at);

        let by_alias = s.get_host_by_alias("web").unwrap().unwrap();
        assert_eq!(by_alias.id, id);
        assert!(s.get_host(id + 1).unwrap().is_none());
        assert!(s.get_host_by_alias("nope").unwrap().is_none());
    }

    #[test]
    fn minimal_host_has_null_fields() {
        let s = store();
        let id = s.insert_host(&NewHost::new("min")).unwrap();
        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!(h.hostname, None);
        assert_eq!(h.port, None);
        assert_eq!(h.source, HostSource::Manual);
        assert_eq!(h.auth_method, AuthMethod::Agent);
    }

    #[test]
    fn duplicate_alias_gives_meaningful_error() {
        let s = store();
        s.insert_host(&NewHost::new("dup")).unwrap();
        let err = s.insert_host(&NewHost::new("dup")).unwrap_err();
        assert!(matches!(err, StoreError::DuplicateAlias(ref a) if a == "dup"));
        assert!(err.to_string().contains("dup"));

        // Also when renaming via update.
        let other = s.insert_host(&NewHost::new("other")).unwrap();
        let upd = HostUpdate {
            alias: "dup".into(),
            ..Default::default()
        };
        assert!(matches!(
            s.update_host(other, &upd),
            Err(StoreError::DuplicateAlias(_))
        ));
    }

    #[test]
    fn update_changes_fields_and_timestamp() {
        let s = store();
        let id = s.insert_host(&NewHost::new("a")).unwrap();
        let before = s.get_host(id).unwrap().unwrap();
        let upd = HostUpdate {
            alias: "b".into(),
            hostname: Some("h".into()),
            port: Some(22),
            auth_method: AuthMethod::Password,
            ..Default::default()
        };
        s.update_host(id, &upd).unwrap();
        let after = s.get_host(id).unwrap().unwrap();
        assert_eq!(after.alias, "b");
        assert_eq!(after.hostname.as_deref(), Some("h"));
        assert_eq!(after.auth_method, AuthMethod::Password);
        assert_eq!(after.created_at, before.created_at);
        assert!(after.updated_at >= before.updated_at);
        assert!(matches!(
            s.update_host(9999, &upd),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn favorite_archive_and_listing() {
        let s = store();
        let a = s.insert_host(&NewHost::new("zeta")).unwrap();
        let b = s.insert_host(&NewHost::new("Alpha")).unwrap();
        s.set_favorite(a, true).unwrap();
        s.set_archived(b, true).unwrap();
        assert!(s.get_host(a).unwrap().unwrap().favorite);

        let active = s.list_hosts(false).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].alias, "zeta");

        let all = s.list_hosts(true).unwrap();
        // Case-insensitive sorting: Alpha before zeta.
        let aliases: Vec<_> = all.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(aliases, ["Alpha", "zeta"]);

        s.set_archived(b, false).unwrap();
        assert_eq!(s.list_hosts(false).unwrap().len(), 2);
        assert!(matches!(
            s.set_favorite(999, true),
            Err(StoreError::NotFound { .. })
        ));
        assert!(matches!(
            s.set_archived(999, true),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn delete_host_and_not_found() {
        let s = store();
        let id = s.insert_host(&NewHost::new("gone")).unwrap();
        s.delete_host(id).unwrap();
        assert!(s.get_host(id).unwrap().is_none());
        assert!(matches!(
            s.delete_host(id),
            Err(StoreError::NotFound { .. })
        ));
    }

    fn cfg(alias: &str, hostname: &str) -> SshConfigHost {
        SshConfigHost {
            alias: alias.into(),
            hostname: Some(hostname.into()),
            user: Some("u".into()),
            port: Some(22),
            identity_file: None,
            proxy_jump: None,
        }
    }

    #[test]
    fn upsert_inserts_then_keeps_metadata() {
        let mut s = store();
        let id = s
            .upsert_ssh_config_host(&cfg("srv", "old.example"))
            .unwrap();
        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!(h.source, HostSource::SshConfig);

        // Set own metadata.
        s.update_host(
            id,
            &HostUpdate {
                alias: "srv".into(),
                hostname: Some("old.example".into()),
                icon: Some("🖥".into()),
                notes: Some("important".into()),
                color: Some("blue".into()),
                ..Default::default()
            },
        )
        .unwrap();
        s.set_favorite(id, true).unwrap();
        s.set_host_tags(id, &["prod", "db"]).unwrap();

        // Archived as the sync would do it (host was missing from the config).
        s.archive_missing_ssh_config_hosts(&[]).unwrap();
        assert!(s.get_host(id).unwrap().unwrap().archived);

        // Sync again with changed config fields.
        let mut changed = cfg("srv", "new.example");
        changed.port = Some(2200);
        changed.proxy_jump = Some("jump".into());
        let id2 = s.upsert_ssh_config_host(&changed).unwrap();
        assert_eq!(id, id2);

        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!(h.hostname.as_deref(), Some("new.example"));
        assert_eq!(h.port, Some(2200));
        assert_eq!(h.proxy_jump.as_deref(), Some("jump"));
        assert!(!h.archived, "upsert must reset archived");
        // Metadata stays:
        assert_eq!(h.icon.as_deref(), Some("🖥"));
        assert_eq!(h.notes.as_deref(), Some("important"));
        assert_eq!(h.color.as_deref(), Some("blue"));
        assert!(h.favorite);
        let tag_names: Vec<_> = h.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tag_names, ["db", "prod"]);
        assert_eq!(s.list_hosts(true).unwrap().len(), 1);
    }

    #[test]
    fn upsert_does_not_overwrite_manual_host() {
        let s = store();
        let mut new = NewHost::new("mine");
        new.hostname = Some("manual.example".into());
        s.insert_host(&new).unwrap();
        let err = s
            .upsert_ssh_config_host(&cfg("mine", "cfg.example"))
            .unwrap_err();
        assert!(matches!(err, StoreError::DuplicateAlias(_)));
        let h = s.get_host_by_alias("mine").unwrap().unwrap();
        assert_eq!(h.hostname.as_deref(), Some("manual.example"));
        assert_eq!(h.source, HostSource::Manual);
    }

    #[test]
    fn archive_missing_only_touches_ssh_config_hosts() {
        let mut s = store();
        s.upsert_ssh_config_host(&cfg("keep", "k")).unwrap();
        s.upsert_ssh_config_host(&cfg("gone", "g")).unwrap();
        s.insert_host(&NewHost::new("manual")).unwrap();

        let n = s
            .archive_missing_ssh_config_hosts(&["keep".to_string()])
            .unwrap();
        assert_eq!(n, 1);
        assert!(s.get_host_by_alias("gone").unwrap().unwrap().archived);
        assert!(!s.get_host_by_alias("keep").unwrap().unwrap().archived);
        assert!(!s.get_host_by_alias("manual").unwrap().unwrap().archived);

        // Second run: nothing left to do.
        assert_eq!(
            s.archive_missing_ssh_config_hosts(&["keep".to_string()])
                .unwrap(),
            0
        );
        // An empty list archives all remaining ssh_config hosts.
        assert_eq!(s.archive_missing_ssh_config_hosts(&[]).unwrap(), 1);
        // Reappearing -> reactivated.
        s.upsert_ssh_config_host(&cfg("gone", "g")).unwrap();
        assert!(!s.get_host_by_alias("gone").unwrap().unwrap().archived);
    }

    #[test]
    fn user_archive_survives_sync_and_missing_archive_does_not() {
        let mut s = store();
        let id = s.upsert_ssh_config_host(&cfg("srv", "h.example")).unwrap();
        s.set_archived(id, true).unwrap();
        // The sync still sees the host: stays archived.
        s.upsert_ssh_config_host(&cfg("srv", "h2.example")).unwrap();
        let h = s.get_host(id).unwrap().unwrap();
        assert!(h.archived);
        assert_eq!(h.hostname.as_deref(), Some("h2.example"));
        // If it disappears from the config, the reason stays "user" …
        assert_eq!(s.archive_missing_ssh_config_hosts(&[]).unwrap(), 0);
        s.upsert_ssh_config_host(&cfg("srv", "h2.example")).unwrap();
        assert!(s.get_host(id).unwrap().unwrap().archived);
        // … until the user restores it.
        s.set_archived(id, false).unwrap();
        assert!(!s.get_host(id).unwrap().unwrap().archived);
        // Automatically archived hosts, on the other hand, come back with the sync.
        assert_eq!(s.archive_missing_ssh_config_hosts(&[]).unwrap(), 1);
        assert!(s.get_host(id).unwrap().unwrap().archived);
        s.upsert_ssh_config_host(&cfg("srv", "h2.example")).unwrap();
        assert!(!s.get_host(id).unwrap().unwrap().archived);
    }

    #[test]
    fn insert_with_tags_is_atomic() {
        let mut s = store();
        // An empty tag name is invalid for the store and aborts.
        let err = s.insert_host_with_tags(&NewHost::new("x"), &["ok", "  "]);
        assert!(matches!(err, Err(StoreError::InvalidInput(_))));
        assert!(s.get_host_by_alias("x").unwrap().is_none());
        assert!(s.list_tags().unwrap().is_empty());
        let id = s
            .insert_host_with_tags(&NewHost::new("x"), &["a", "b"])
            .unwrap();
        assert_eq!(s.get_host(id).unwrap().unwrap().tags.len(), 2);
        // Duplicate alias: error and no leftover tags.
        let dup = s.insert_host_with_tags(&NewHost::new("x"), &["c"]);
        assert!(matches!(dup, Err(StoreError::DuplicateAlias(_))));
        assert!(s.find_tag("c").unwrap().is_none());
    }

    #[test]
    fn update_with_tags_is_atomic() {
        let mut s = store();
        let id = s.insert_host_with_tags(&NewHost::new("x"), &["a"]).unwrap();
        let upd = HostUpdate {
            alias: "y".into(),
            ..Default::default()
        };
        let err = s.update_host_with_tags(id, &upd, &["b", ""]);
        assert!(err.is_err());
        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!(h.alias, "x");
        assert_eq!(h.tags[0].name, "a");
        s.update_host_with_tags(id, &upd, &["b"]).unwrap();
        let h = s.get_host(id).unwrap().unwrap();
        assert_eq!((h.alias.as_str(), h.tags[0].name.as_str()), ("y", "b"));
    }
}
