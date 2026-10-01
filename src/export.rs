//! JSON export of the hosts (`sshire export`).
//!
//! The export uses its own slim structs instead of serializing `Host`
//! directly. That way only what is *explicitly* listed here ends up in the
//! JSON - if a new (possibly sensitive) field is added to `Host` later, it is
//! not exported by accident. Passwords and other secrets are never included:
//! there is only `has_password: bool`.
//!
//! `serde::Serialize` is the counterpart to `Deserialize`: `#[derive(Serialize)]`
//! generates the code that converts a struct into JSON (or another format).

use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat};
use serde::Serialize;

use crate::store::{Host, HostStats, Tag};

/// Version of the export format (increase on incompatible changes).
const FORMAT_VERSION: u32 = 1;

/// Top level of the export.
#[derive(Debug, Serialize)]
struct Export {
    format_version: u32,
    hosts: Vec<ExportHost>,
}

/// A host in the export.
#[derive(Debug, Serialize)]
struct ExportHost {
    alias: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    extra_args: Option<String>,
    icon: Option<String>,
    color: Option<String>,
    notes: Option<String>,
    source: &'static str,
    favorite: bool,
    archived: bool,
    auth_method: &'static str,
    /// Only the flag - never the password itself.
    has_password: bool,
    tags: Vec<ExportTag>,
    created_at: Option<String>,
    updated_at: Option<String>,
    stats: ExportStats,
}

/// A tag in the export.
#[derive(Debug, Serialize)]
struct ExportTag {
    name: String,
    color: Option<String>,
    icon: Option<String>,
}

/// Connection statistics of a host.
#[derive(Debug, Serialize)]
struct ExportStats {
    /// Time of the last successful connection (ISO 8601, UTC).
    last_success_at: Option<String>,
    total_connections: i64,
}

/// Unix milliseconds as ISO 8601 text in UTC (`2026-01-31T12:00:00Z`).
fn iso8601(ts_ms: i64) -> Option<String> {
    DateTime::from_timestamp_millis(ts_ms).map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn export_tag(tag: &Tag) -> ExportTag {
    ExportTag {
        name: tag.name.clone(),
        color: tag.color.clone(),
        icon: tag.icon.clone(),
    }
}

fn export_host(host: &Host, stats: Option<&HostStats>) -> ExportHost {
    ExportHost {
        alias: host.alias.clone(),
        hostname: host.hostname.clone(),
        user: host.user.clone(),
        port: host.port,
        identity_file: host.identity_file.clone(),
        proxy_jump: host.proxy_jump.clone(),
        extra_args: host.extra_args.clone(),
        icon: host.icon.clone(),
        color: host.color.clone(),
        notes: host.notes.clone(),
        source: host.source.as_str(),
        favorite: host.favorite,
        archived: host.archived,
        auth_method: host.auth_method.as_str(),
        has_password: host.has_password,
        tags: host.tags.iter().map(export_tag).collect(),
        created_at: iso8601(host.created_at),
        updated_at: iso8601(host.updated_at),
        stats: ExportStats {
            last_success_at: stats.and_then(|s| s.last_success_at).and_then(iso8601),
            total_connections: stats.map_or(0, |s| s.total_connections),
        },
    }
}

/// Builds the JSON text (pretty-printed) for the given hosts.
pub fn export_json(hosts: &[Host], stats: &HashMap<i64, HostStats>) -> Result<String> {
    let export = Export {
        format_version: FORMAT_VERSION,
        hosts: hosts
            .iter()
            .map(|h| export_host(h, stats.get(&h.id)))
            .collect(),
    };
    serde_json::to_string_pretty(&export).context("could not serialize the export")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AuthMethod, HostSource};

    fn host() -> Host {
        Host {
            id: 7,
            alias: "web".into(),
            hostname: Some("web.example.invalid".into()),
            user: Some("admin".into()),
            port: Some(2222),
            identity_file: Some("~/.ssh/id_test".into()),
            proxy_jump: None,
            extra_args: None,
            icon: Some("🚀".into()),
            color: None,
            notes: Some("Note".into()),
            source: HostSource::Manual,
            favorite: true,
            archived: false,
            auth_method: AuthMethod::Password,
            has_password: true,
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_100_000,
            tags: vec![Tag {
                id: 1,
                name: "prod".into(),
                color: Some("#ff0000".into()),
                icon: None,
            }],
        }
    }

    fn parsed(hosts: &[Host], stats: &HashMap<i64, HostStats>) -> serde_json::Value {
        serde_json::from_str(&export_json(hosts, stats).unwrap()).unwrap()
    }

    #[test]
    fn export_has_expected_format() {
        let mut stats = HashMap::new();
        stats.insert(
            7,
            HostStats {
                last_success_at: Some(1_700_000_200_000),
                last_failure_at: Some(1_700_000_300_000),
                total_connections: 5,
            },
        );
        let json = parsed(&[host()], &stats);
        assert_eq!(json["format_version"], 1);
        let h = &json["hosts"][0];
        assert_eq!(h["alias"], "web");
        assert_eq!(h["port"], 2222);
        assert_eq!(h["icon"], "🚀");
        assert_eq!(h["notes"], "Note");
        assert_eq!(h["source"], "manual");
        assert_eq!(h["has_password"], true);
        assert_eq!(h["tags"][0]["name"], "prod");
        assert_eq!(h["created_at"], "2023-11-14T22:13:20Z");
        assert_eq!(h["stats"]["last_success_at"], "2023-11-14T22:16:40Z");
        assert_eq!(h["stats"]["total_connections"], 5);
        assert!(h["proxy_jump"].is_null());
    }

    #[test]
    fn host_without_stats_has_null_and_zero() {
        let json = parsed(&[host()], &HashMap::new());
        assert!(json["hosts"][0]["stats"]["last_success_at"].is_null());
        assert_eq!(json["hosts"][0]["stats"]["total_connections"], 0);
    }

    #[test]
    fn export_contains_no_secret_fields() {
        let text = export_json(&[host()], &HashMap::new()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        // Exactly these keys are allowed - anything else would be a leak.
        let allowed = [
            "alias",
            "hostname",
            "user",
            "port",
            "identity_file",
            "proxy_jump",
            "extra_args",
            "icon",
            "color",
            "notes",
            "source",
            "favorite",
            "archived",
            "auth_method",
            "has_password",
            "tags",
            "created_at",
            "updated_at",
            "stats",
        ];
        for key in json["hosts"][0].as_object().unwrap().keys() {
            assert!(allowed.contains(&key.as_str()), "unexpected field {key}");
        }
        // No field named "password" or similar; only the `has_password` flag.
        assert!(!text.contains("\"password\":"));
        assert!(!text.contains("secret"));
    }
}
