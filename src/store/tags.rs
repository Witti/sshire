//! Tags and the host <-> tag assignment (`host_tags`).

use std::collections::HashMap;

use rusqlite::{OptionalExtension, Row, params};

use super::{Result, Store, StoreError, is_unique_violation};

/// A freely assignable label for hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub id: i64,
    pub name: String,
    pub color: Option<String>,
    pub icon: Option<String>,
}

fn tag_from_row(row: &Row<'_>) -> rusqlite::Result<Tag> {
    Ok(Tag {
        id: row.get("id")?,
        name: row.get("name")?,
        color: row.get("color")?,
        icon: row.get("icon")?,
    })
}

/// Trims whitespace at the edges and rejects empty names.
fn clean_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        Err(StoreError::InvalidInput("Tag name must not be empty"))
    } else {
        Ok(name)
    }
}

// The following free functions take `&rusqlite::Connection`. Thanks to
// "deref coercion", a `Transaction` can be passed as a `&Connection` too –
// so they work both inside and outside of transactions.

/// Fetches the tag with this name or creates it.
fn get_or_create_tag_on(conn: &rusqlite::Connection, name: &str) -> Result<Tag> {
    let name = clean_name(name)?;
    // `INSERT OR IGNORE`: if the name already exists (UNIQUE), nothing happens.
    conn.execute(
        "INSERT OR IGNORE INTO tags (name) VALUES (?1)",
        params![name],
    )?;
    // The name is `COLLATE NOCASE`, so the lookup is case-insensitive.
    Ok(conn.query_row(
        "SELECT id, name, color, icon FROM tags WHERE name = ?1",
        params![name],
        tag_from_row,
    )?)
}

fn ensure_host_exists(conn: &rusqlite::Connection, host_id: i64) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosts WHERE id = ?1)",
        params![host_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::NotFound {
            entity: "Host",
            id: host_id,
        })
    }
}

/// A host's tags, alphabetical.
pub(super) fn load_tags_for_host(conn: &rusqlite::Connection, host_id: i64) -> Result<Vec<Tag>> {
    let mut stmt = conn.prepare(
        "SELECT t.id, t.name, t.color, t.icon FROM tags t \
         JOIN host_tags ht ON ht.tag_id = t.id \
         WHERE ht.host_id = ?1 ORDER BY t.name COLLATE NOCASE",
    )?;
    let tags = stmt
        .query_map(params![host_id], tag_from_row)?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(tags)
}

/// All tags of all hosts in *one* query, grouped by `host_id`.
pub(super) fn load_tags_for_all_hosts(
    conn: &rusqlite::Connection,
) -> Result<HashMap<i64, Vec<Tag>>> {
    let mut stmt = conn.prepare(
        "SELECT ht.host_id, t.id, t.name, t.color, t.icon FROM host_tags ht \
         JOIN tags t ON t.id = ht.tag_id \
         ORDER BY t.name COLLATE NOCASE",
    )?;
    let mut map: HashMap<i64, Vec<Tag>> = HashMap::new();
    // Walk the rows as an iterator; the closure returns a tuple (host_id, Tag).
    let rows = stmt.query_map([], |row| {
        let host_id: i64 = row.get(0)?;
        let tag = Tag {
            id: row.get(1)?,
            name: row.get(2)?,
            color: row.get(3)?,
            icon: row.get(4)?,
        };
        Ok((host_id, tag))
    })?;
    for row in rows {
        let (host_id, tag) = row?;
        // `entry(..).or_default()` returns the Vec for the key (creating it if needed).
        map.entry(host_id).or_default().push(tag);
    }
    Ok(map)
}

/// Replaces a host's tags on any connection or within a running transaction
/// (`&Transaction` derefs to `&Connection`).
/// The caller opens the transaction itself.
pub(super) fn set_host_tags_on<S: AsRef<str>>(
    conn: &rusqlite::Connection,
    host_id: i64,
    names: &[S],
) -> Result<()> {
    ensure_host_exists(conn, host_id)?;
    conn.execute("DELETE FROM host_tags WHERE host_id = ?1", params![host_id])?;
    for name in names {
        let tag = get_or_create_tag_on(conn, name.as_ref())?;
        // OR IGNORE: names listed twice are harmless.
        conn.execute(
            "INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?1, ?2)",
            params![host_id, tag.id],
        )?;
    }
    Ok(())
}

impl Store {
    /// Creates a new tag; errors with [`StoreError::DuplicateTag`] if the name exists.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn create_tag(&self, name: &str) -> Result<Tag> {
        let name = clean_name(name)?;
        self.conn
            .execute("INSERT INTO tags (name) VALUES (?1)", params![name])
            .map_err(|e| {
                if is_unique_violation(&e) {
                    StoreError::DuplicateTag(name.to_owned())
                } else {
                    StoreError::Sqlite(e)
                }
            })?;
        Ok(Tag {
            id: self.conn.last_insert_rowid(),
            name: name.to_owned(),
            color: None,
            icon: None,
        })
    }

    /// Returns the tag with this name, creating it if it is missing.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn get_or_create_tag(&self, name: &str) -> Result<Tag> {
        get_or_create_tag_on(&self.conn, name)
    }

    /// All tags, alphabetical.
    pub fn list_tags(&self) -> Result<Vec<Tag>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, color, icon FROM tags ORDER BY name COLLATE NOCASE")?;
        let tags = stmt
            .query_map([], tag_from_row)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(tags)
    }

    /// Renames a tag.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn rename_tag(&self, id: i64, new_name: &str) -> Result<()> {
        let new_name = clean_name(new_name)?;
        let changed = self
            .conn
            .execute(
                "UPDATE tags SET name = ?1 WHERE id = ?2",
                params![new_name, id],
            )
            .map_err(|e| {
                if is_unique_violation(&e) {
                    StoreError::DuplicateTag(new_name.to_owned())
                } else {
                    StoreError::Sqlite(e)
                }
            })?;
        if changed == 0 {
            return Err(StoreError::NotFound { entity: "Tag", id });
        }
        Ok(())
    }

    /// Deletes a tag; assignments disappear via CASCADE.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn delete_tag(&self, id: i64) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM tags WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(StoreError::NotFound { entity: "Tag", id });
        }
        Ok(())
    }

    /// Replaces a host's tags with exactly the given names
    /// (missing tags are created).
    ///
    /// `names: &[S]` with `S: AsRef<str>` is *generic*: both `&[&str]` and
    /// `&[String]` fit.
    ///
    /// Everything runs in one transaction: if a step fails, the old state is
    /// preserved. That is why the method needs `&mut self`.
    pub fn set_host_tags<S: AsRef<str>>(&mut self, host_id: i64, names: &[S]) -> Result<()> {
        // `transaction()` starts `BEGIN`. The `Transaction` object rolls back
        // automatically when dropped (`Drop`) if `commit()` was not reached –
        // e.g. because a `?` bailed out earlier.
        let tx = self.conn.transaction()?;
        set_host_tags_on(&tx, host_id, names)?;
        tx.commit()?;
        Ok(())
    }

    /// Adds a tag to a host (creating the tag if needed).
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn add_tag_to_host(&mut self, host_id: i64, name: &str) -> Result<Tag> {
        let tx = self.conn.transaction()?;
        ensure_host_exists(&tx, host_id)?;
        let tag = get_or_create_tag_on(&tx, name)?;
        tx.execute(
            "INSERT OR IGNORE INTO host_tags (host_id, tag_id) VALUES (?1, ?2)",
            params![host_id, tag.id],
        )?;
        tx.commit()?;
        Ok(tag)
    }

    /// Removes the tag (by name) from a host. Returns `true` if the assignment
    /// existed. The tag itself is kept.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn remove_tag_from_host(&self, host_id: i64, name: &str) -> Result<bool> {
        let name = clean_name(name)?;
        let changed = self.conn.execute(
            "DELETE FROM host_tags WHERE host_id = ?1 \
             AND tag_id = (SELECT id FROM tags WHERE name = ?2)",
            params![host_id, name],
        )?;
        Ok(changed > 0)
    }

    /// Looks up a tag by name.
    #[allow(dead_code)] // T6 only uses set_host_tags/list_tags; individual tag management has no TUI hookup (yet), covered by tests
    pub fn find_tag(&self, name: &str) -> Result<Option<Tag>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, color, icon FROM tags WHERE name = ?1",
                params![name.trim()],
                tag_from_row,
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewHost;

    fn names(tags: &[Tag]) -> Vec<&str> {
        tags.iter().map(|t| t.name.as_str()).collect()
    }

    #[test]
    fn create_list_rename_delete() {
        let s = Store::open_in_memory().unwrap();
        let a = s.create_tag("prod").unwrap();
        s.create_tag("Dev").unwrap();
        assert_eq!(names(&s.list_tags().unwrap()), ["Dev", "prod"]);

        // Duplicate (even with different capitalization) -> DuplicateTag.
        assert!(matches!(
            s.create_tag("PROD"),
            Err(StoreError::DuplicateTag(_))
        ));

        s.rename_tag(a.id, "production").unwrap();
        assert!(matches!(
            s.rename_tag(a.id, "dev"),
            Err(StoreError::DuplicateTag(_))
        ));
        assert!(matches!(
            s.rename_tag(999, "x"),
            Err(StoreError::NotFound { .. })
        ));

        s.delete_tag(a.id).unwrap();
        assert_eq!(names(&s.list_tags().unwrap()), ["Dev"]);
        assert!(matches!(
            s.delete_tag(a.id),
            Err(StoreError::NotFound { .. })
        ));
    }

    #[test]
    fn get_or_create_is_stable_and_validates() {
        let s = Store::open_in_memory().unwrap();
        let a = s.get_or_create_tag("  web ").unwrap();
        let b = s.get_or_create_tag("WEB").unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.name, "web");
        assert!(matches!(
            s.get_or_create_tag("   "),
            Err(StoreError::InvalidInput(_))
        ));
        assert_eq!(s.list_tags().unwrap().len(), 1);
    }

    #[test]
    fn set_add_remove_host_tags() {
        let mut s = Store::open_in_memory().unwrap();
        let h = s.insert_host(&NewHost::new("h")).unwrap();

        s.set_host_tags(h, &["b", "a", "a"]).unwrap();
        assert_eq!(names(&s.get_host(h).unwrap().unwrap().tags), ["a", "b"]);

        // Replace (also with Vec<String>).
        s.set_host_tags(h, &["c".to_string()]).unwrap();
        assert_eq!(names(&s.get_host(h).unwrap().unwrap().tags), ["c"]);

        s.add_tag_to_host(h, "d").unwrap();
        s.add_tag_to_host(h, "d").unwrap(); // idempotent
        assert_eq!(names(&s.get_host(h).unwrap().unwrap().tags), ["c", "d"]);

        assert!(s.remove_tag_from_host(h, "c").unwrap());
        assert!(!s.remove_tag_from_host(h, "c").unwrap());
        assert_eq!(names(&s.get_host(h).unwrap().unwrap().tags), ["d"]);
        // The tag itself still exists.
        assert!(s.find_tag("c").unwrap().is_some());

        s.set_host_tags::<&str>(h, &[]).unwrap();
        assert!(s.get_host(h).unwrap().unwrap().tags.is_empty());
    }

    #[test]
    fn unknown_host_is_not_found_and_rolls_back() {
        let mut s = Store::open_in_memory().unwrap();
        assert!(matches!(
            s.set_host_tags(42, &["x"]),
            Err(StoreError::NotFound { .. })
        ));
        assert!(matches!(
            s.add_tag_to_host(42, "x"),
            Err(StoreError::NotFound { .. })
        ));
        // Nothing created (rollback or earlier abort).
        assert!(s.list_tags().unwrap().is_empty());
    }

    #[test]
    fn set_host_tags_is_atomic() {
        let mut s = Store::open_in_memory().unwrap();
        let h = s.insert_host(&NewHost::new("h")).unwrap();
        s.set_host_tags(h, &["keep"]).unwrap();
        // Invalid (empty) name in the middle of the list -> error, old state stays.
        let res = s.set_host_tags(h, &["new", " "]);
        assert!(matches!(res, Err(StoreError::InvalidInput(_))));
        assert_eq!(names(&s.get_host(h).unwrap().unwrap().tags), ["keep"]);
        assert!(s.find_tag("new").unwrap().is_none());
    }

    #[test]
    fn cascade_on_host_and_tag_delete() {
        let mut s = Store::open_in_memory().unwrap();
        let h1 = s.insert_host(&NewHost::new("h1")).unwrap();
        let h2 = s.insert_host(&NewHost::new("h2")).unwrap();
        s.set_host_tags(h1, &["x", "y"]).unwrap();
        s.set_host_tags(h2, &["x"]).unwrap();

        let count = |s: &Store| -> i64 {
            s.conn
                .query_row("SELECT COUNT(*) FROM host_tags", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(&s), 3);

        // Delete host -> its assignments are gone, tags stay.
        s.delete_host(h1).unwrap();
        assert_eq!(count(&s), 1);
        assert_eq!(s.list_tags().unwrap().len(), 2);

        // Delete tag -> assignment gone.
        let x = s.find_tag("x").unwrap().unwrap();
        s.delete_tag(x.id).unwrap();
        assert_eq!(count(&s), 0);
        assert!(s.get_host(h2).unwrap().unwrap().tags.is_empty());
    }

    #[test]
    fn list_hosts_attaches_tags_per_host() {
        let mut s = Store::open_in_memory().unwrap();
        let a = s.insert_host(&NewHost::new("a")).unwrap();
        let b = s.insert_host(&NewHost::new("b")).unwrap();
        s.insert_host(&NewHost::new("c")).unwrap();
        s.set_host_tags(a, &["t1", "t2"]).unwrap();
        s.set_host_tags(b, &["t2"]).unwrap();

        let hosts = s.list_hosts(false).unwrap();
        assert_eq!(names(&hosts[0].tags), ["t1", "t2"]);
        assert_eq!(names(&hosts[1].tags), ["t2"]);
        assert!(hosts[2].tags.is_empty());
    }
}
