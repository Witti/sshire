//! Connection log: start/end of ssh sessions and per-host statistics.

use std::collections::HashMap;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Row, params};

use super::{InvalidEnumValue, Result, Store, StoreError, now_ms};

/// Outcome of a connection.
///
/// ssh exit code 255 means `Failed`, anything else `Success`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Success,
    Failed,
}

impl ConnectionStatus {
    /// The text stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }

    /// Counterpart to [`as_str`](Self::as_str).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "success" => Some(Self::Success),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl ToSql for ConnectionStatus {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.as_str().into())
    }
}

impl FromSql for ConnectionStatus {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let text = value.as_str()?;
        Self::parse(text).ok_or_else(|| {
            FromSqlError::Other(Box::new(InvalidEnumValue {
                kind: "ConnectionStatus",
                value: text.to_owned(),
            }))
        })
    }
}

/// An entry in the connection log.
///
/// (Not to be confused with `rusqlite::Connection`, the database connection.)
/// While the connection is running, `ended_at`, `duration_ms`, `exit_code`
/// and `status` are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: i64,
    pub host_id: i64,
    /// Unix milliseconds.
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub duration_ms: Option<i64>,
    pub exit_code: Option<i32>,
    pub status: Option<ConnectionStatus>,
}

/// Aggregated metrics of a host (for the list and sorting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostStats {
    /// Start time of the last successful connection.
    pub last_success_at: Option<i64>,
    /// Start time of the last failed connection.
    pub last_failure_at: Option<i64>,
    /// Number of all logged connections (including still-running/aborted ones).
    pub total_connections: i64,
}

fn connection_from_row(row: &Row<'_>) -> rusqlite::Result<Connection> {
    Ok(Connection {
        id: row.get("id")?,
        host_id: row.get("host_id")?,
        started_at: row.get("started_at")?,
        ended_at: row.get("ended_at")?,
        duration_ms: row.get("duration_ms")?,
        exit_code: row.get("exit_code")?,
        status: row.get("status")?,
    })
}

impl Store {
    /// Logs the start of a connection and returns the log ID.
    pub fn start_connection(&self, host_id: i64) -> Result<i64> {
        let res = self.conn.execute(
            "INSERT INTO connections (host_id, started_at) VALUES (?1, ?2)",
            params![host_id, now_ms()],
        );
        match res {
            Ok(_) => Ok(self.conn.last_insert_rowid()),
            // Foreign key violated = host does not exist.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY =>
            {
                Err(StoreError::NotFound {
                    entity: "Host",
                    id: host_id,
                })
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Completes a log entry: sets end, duration, exit code and status.
    ///
    /// `exit_code: Option<i32>` – `None` if ssh was terminated by a signal
    /// (there is no exit code then); `NULL` is stored in the DB in that case.
    pub fn finish_connection(
        &self,
        id: i64,
        exit_code: Option<i32>,
        status: ConnectionStatus,
    ) -> Result<()> {
        let now = now_ms();
        // SQL computes the duration itself from `started_at`; `MAX(0, ..)` guards
        // against clock jumps backwards.
        let changed = self.conn.execute(
            "UPDATE connections SET ended_at = ?1, duration_ms = MAX(0, ?1 - started_at), \
             exit_code = ?2, status = ?3 WHERE id = ?4",
            params![now, exit_code, status, id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound {
                entity: "Connection",
                id,
            });
        }
        Ok(())
    }

    /// Marks orphaned entries as `failed`: still open (`ended_at IS NULL`) and
    /// started more than `older_than_ms` milliseconds ago (e.g. because sshire
    /// was killed with SIGKILL). Returns the count.
    pub fn close_stale_connections(&self, older_than_ms: i64) -> Result<usize> {
        let now = now_ms();
        let changed = self.conn.execute(
            "UPDATE connections SET ended_at = ?1, status = 'failed' \
             WHERE ended_at IS NULL AND started_at < ?2",
            params![now, now.saturating_sub(older_than_ms)],
        )?;
        Ok(changed)
    }

    /// Newest entries first; optionally restricted to one host.
    pub fn recent_connections(&self, host_id: Option<i64>, limit: u32) -> Result<Vec<Connection>> {
        // `?1 IS NULL OR host_id = ?1`: `None` is bound as SQL NULL and switches
        // the filter off – so a single statement is enough.
        let mut stmt = self.conn.prepare(
            "SELECT id, host_id, started_at, ended_at, duration_ms, exit_code, status \
             FROM connections WHERE (?1 IS NULL OR host_id = ?1) \
             ORDER BY started_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![host_id, limit], connection_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Metrics of all hosts with at least one connection, in a single query.
    ///
    /// Hosts without log entries are missing from the map (callers: `stats.get(&id)`).
    pub fn host_stats(&self) -> Result<HashMap<i64, HostStats>> {
        // `CASE WHEN ... END` yields NULL if the condition doesn't match;
        // `MAX` ignores NULLs – that gives us the latest time per status.
        let mut stmt = self.conn.prepare(
            "SELECT host_id, \
                    MAX(CASE WHEN status = 'success' THEN started_at END), \
                    MAX(CASE WHEN status = 'failed'  THEN started_at END), \
                    COUNT(*) \
             FROM connections GROUP BY host_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                HostStats {
                    last_success_at: row.get(1)?,
                    last_failure_at: row.get(2)?,
                    total_connections: row.get(3)?,
                },
            ))
        })?;
        // An iterator of `Result<(K, V)>` can be collected directly into a
        // `Result<HashMap<K, V>>`.
        let map = rows.collect::<std::result::Result<HashMap<_, _>, _>>()?;
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewHost;

    #[test]
    fn status_roundtrip() {
        for s in [ConnectionStatus::Success, ConnectionStatus::Failed] {
            assert_eq!(ConnectionStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(ConnectionStatus::parse("ok"), None);
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let back: ConnectionStatus = conn
            .query_row("SELECT ?1", params![ConnectionStatus::Failed], |r| r.get(0))
            .unwrap();
        assert_eq!(back, ConnectionStatus::Failed);
    }

    #[test]
    fn start_and_finish_connection() {
        let s = Store::open_in_memory().unwrap();
        let h = s.insert_host(&NewHost::new("h")).unwrap();
        let id = s.start_connection(h).unwrap();

        let running = &s.recent_connections(Some(h), 10).unwrap()[0];
        assert_eq!(running.id, id);
        assert!(running.ended_at.is_none() && running.status.is_none());

        s.finish_connection(id, Some(0), ConnectionStatus::Success)
            .unwrap();
        let done = &s.recent_connections(None, 10).unwrap()[0];
        assert_eq!(done.status, Some(ConnectionStatus::Success));
        assert_eq!(done.exit_code, Some(0));
        let ended = done.ended_at.unwrap();
        assert!(ended >= done.started_at);
        assert_eq!(done.duration_ms, Some(ended - done.started_at));

        // Aborted by signal: no exit code.
        let id2 = s.start_connection(h).unwrap();
        s.finish_connection(id2, None, ConnectionStatus::Failed)
            .unwrap();
        let c = &s.recent_connections(Some(h), 1).unwrap()[0];
        assert_eq!(c.exit_code, None);
        assert_eq!(c.status, Some(ConnectionStatus::Failed));
    }

    #[test]
    fn unknown_ids_give_not_found() {
        let s = Store::open_in_memory().unwrap();
        assert!(matches!(
            s.start_connection(123),
            Err(StoreError::NotFound { .. })
        ));
        assert!(matches!(
            s.finish_connection(123, Some(0), ConnectionStatus::Success),
            Err(StoreError::NotFound { .. })
        ));
    }

    /// Inserts a log entry with a fixed time directly (deterministic).
    fn insert_at(s: &Store, host: i64, at: i64, status: ConnectionStatus) {
        s.conn
            .execute(
                "INSERT INTO connections (host_id, started_at, ended_at, duration_ms, exit_code, status) \
                 VALUES (?1, ?2, ?2 + 10, 10, 0, ?3)",
                params![host, at, status],
            )
            .unwrap();
    }

    #[test]
    fn recent_connections_order_limit_and_filter() {
        let s = Store::open_in_memory().unwrap();
        let a = s.insert_host(&NewHost::new("a")).unwrap();
        let b = s.insert_host(&NewHost::new("b")).unwrap();
        insert_at(&s, a, 100, ConnectionStatus::Success);
        insert_at(&s, b, 200, ConnectionStatus::Failed);
        insert_at(&s, a, 300, ConnectionStatus::Success);

        let all = s.recent_connections(None, 10).unwrap();
        let times: Vec<_> = all.iter().map(|c| c.started_at).collect();
        assert_eq!(times, [300, 200, 100]);
        assert_eq!(s.recent_connections(None, 2).unwrap().len(), 2);
        assert_eq!(s.recent_connections(Some(a), 10).unwrap().len(), 2);
        assert_eq!(s.recent_connections(Some(b), 10).unwrap().len(), 1);
        assert!(s.recent_connections(None, 0).unwrap().is_empty());
    }

    #[test]
    fn host_stats_aggregates_in_one_query() {
        let s = Store::open_in_memory().unwrap();
        let a = s.insert_host(&NewHost::new("a")).unwrap();
        let b = s.insert_host(&NewHost::new("b")).unwrap();
        let c = s.insert_host(&NewHost::new("c")).unwrap();
        insert_at(&s, a, 100, ConnectionStatus::Success);
        insert_at(&s, a, 200, ConnectionStatus::Failed);
        insert_at(&s, a, 300, ConnectionStatus::Success);
        insert_at(&s, a, 400, ConnectionStatus::Failed);
        insert_at(&s, b, 50, ConnectionStatus::Failed);

        let stats = s.host_stats().unwrap();
        assert_eq!(
            stats[&a],
            HostStats {
                last_success_at: Some(300),
                last_failure_at: Some(400),
                total_connections: 4
            }
        );
        assert_eq!(
            stats[&b],
            HostStats {
                last_success_at: None,
                last_failure_at: Some(50),
                total_connections: 1
            }
        );
        assert!(!stats.contains_key(&c));
    }

    #[test]
    fn connections_cascade_with_host() {
        let s = Store::open_in_memory().unwrap();
        let h = s.insert_host(&NewHost::new("h")).unwrap();
        s.start_connection(h).unwrap();
        s.delete_host(h).unwrap();
        assert!(s.recent_connections(None, 10).unwrap().is_empty());
        assert!(s.host_stats().unwrap().is_empty());
    }

    #[test]
    fn check_constraint_rejects_invalid_status() {
        let s = Store::open_in_memory().unwrap();
        let h = s.insert_host(&NewHost::new("h")).unwrap();
        let res = s.conn.execute(
            "INSERT INTO connections (host_id, started_at, status) VALUES (?1, 0, 'maybe')",
            params![h],
        );
        assert!(res.is_err());
    }

    #[test]
    fn stale_open_connections_are_closed() {
        let store = Store::open_in_memory().unwrap();
        let host = store.insert_host(&crate::store::NewHost::new("a")).unwrap();
        let old = store.start_connection(host).unwrap();
        let fresh = store.start_connection(host).unwrap();
        // Artificially shift the first entry 2 days into the past.
        store
            .conn
            .execute(
                "UPDATE connections SET started_at = started_at - 172800000 WHERE id = ?1",
                params![old],
            )
            .unwrap();
        let day = 24 * 3_600_000;
        assert_eq!(store.close_stale_connections(day).unwrap(), 1);
        let log = store.recent_connections(None, 10).unwrap();
        let old_e = log.iter().find(|c| c.id == old).unwrap();
        let fresh_e = log.iter().find(|c| c.id == fresh).unwrap();
        assert_eq!(old_e.status, Some(ConnectionStatus::Failed));
        assert!(old_e.ended_at.is_some());
        assert_eq!(fresh_e.status, None);
        // A second run finds nothing more.
        assert_eq!(store.close_stale_connections(day).unwrap(), 0);
    }
}
