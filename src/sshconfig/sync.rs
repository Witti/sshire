//! Reconciling a parsed ssh config with the database.

use crate::store::{Result, SshConfigHost, Store, StoreError};

use super::parser::{ParsedConfig, ParsedHost};

// `Default` automatically creates a value in which every field has its own
// default (numbers 0, `Vec` empty). That way the report starts out empty.
/// Result of a sync run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Number of hosts created or updated.
    pub upserted: usize,
    /// Number of newly archived hosts (no longer present in the config).
    pub archived: usize,
    /// Number of skipped hosts (alias collides with a manual host).
    pub skipped: usize,
    /// Notes for the user (parser warnings, collisions).
    pub warnings: Vec<String>,
}

/// Converts a parsed host into the store model.
fn to_store_host(host: &ParsedHost) -> SshConfigHost {
    SshConfigHost {
        alias: host.alias.clone(),
        hostname: host.hostname.clone(),
        user: host.user.clone(),
        port: host.port,
        identity_file: host.identity_file.clone(),
        proxy_jump: host.proxy_jump.clone(),
    }
}

/// Writes all hosts of the config into the store and archives vanished ones.
///
/// If an alias collides with a manually created host, it is skipped
/// (warning). If the config could not be read completely
/// (`parsed.incomplete`), nothing is archived – otherwise a temporarily
/// unreadable `Include` would make all affected hosts disappear.
pub fn sync(store: &mut Store, parsed: &ParsedConfig) -> Result<SyncReport> {
    let mut report = SyncReport::default();

    for host in &parsed.hosts {
        match store.upsert_ssh_config_host(&to_store_host(host)) {
            Ok(_) => report.upserted += 1,
            // Pattern with a binding: only this one error case is caught, all other
            // errors propagate upward via `return Err(..)`.
            Err(StoreError::DuplicateAlias(alias)) => {
                report.skipped += 1;
                report.warnings.push(format!(
                    "Host \"{alias}\" skipped: already exists as a manual host"
                ));
            }
            Err(other) => return Err(other),
        }
    }

    if parsed.incomplete {
        report.warnings.push(
            "Config could not be read completely – vanished hosts were not archived".to_string(),
        );
    } else {
        let aliases: Vec<String> = parsed.hosts.iter().map(|h| h.alias.clone()).collect();
        report.archived = store.archive_missing_ssh_config_hosts(&aliases)?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{HostSource, NewHost};

    fn parsed(aliases: &[&str]) -> ParsedConfig {
        ParsedConfig {
            hosts: aliases
                .iter()
                .map(|a| ParsedHost {
                    alias: (*a).to_string(),
                    hostname: Some(format!("{a}.example.com")),
                    ..ParsedHost::default()
                })
                .collect(),
            ..ParsedConfig::default()
        }
    }

    #[test]
    fn upsert_keeps_metadata() {
        let mut store = Store::open_in_memory().unwrap();
        sync(&mut store, &parsed(&["web"])).unwrap();
        let id = store.get_host_by_alias("web").unwrap().unwrap().id;
        store.set_favorite(id, true).unwrap();

        // Second run with a changed hostname.
        let mut p = parsed(&["web"]);
        p.hosts[0].hostname = Some("new.example.com".into());
        let report = sync(&mut store, &p).unwrap();
        assert_eq!(report.upserted, 1);

        let host = store.get_host_by_alias("web").unwrap().unwrap();
        assert_eq!(host.hostname.as_deref(), Some("new.example.com"));
        assert!(host.favorite);
        assert_eq!(host.source, HostSource::SshConfig);
    }

    #[test]
    fn vanished_hosts_are_archived_and_restored() {
        let mut store = Store::open_in_memory().unwrap();
        sync(&mut store, &parsed(&["a", "b"])).unwrap();
        let report = sync(&mut store, &parsed(&["a"])).unwrap();
        assert_eq!(report.archived, 1);
        assert!(store.get_host_by_alias("b").unwrap().unwrap().archived);

        // If the host reappears, it is active again.
        sync(&mut store, &parsed(&["a", "b"])).unwrap();
        assert!(!store.get_host_by_alias("b").unwrap().unwrap().archived);
    }

    #[test]
    fn collision_with_manual_host_is_skipped() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert_host(&NewHost::new("web")).unwrap();
        let report = sync(&mut store, &parsed(&["web", "db"])).unwrap();
        assert_eq!(report.upserted, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        let web = store.get_host_by_alias("web").unwrap().unwrap();
        assert_eq!(web.source, HostSource::Manual);
        assert!(web.hostname.is_none());
    }

    #[test]
    fn incomplete_parse_does_not_archive() {
        let mut store = Store::open_in_memory().unwrap();
        sync(&mut store, &parsed(&["a", "b"])).unwrap();
        let mut p = parsed(&["a"]);
        p.incomplete = true;
        let report = sync(&mut store, &p).unwrap();
        assert_eq!(report.archived, 0);
        assert!(!store.get_host_by_alias("b").unwrap().unwrap().archived);
    }
}
