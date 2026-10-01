//! Read-only parser for `~/.ssh/config`, including sync into the database.
//!
//! Module layout:
//! * `parser` – reads the config (incl. `Include`) and returns `ParsedConfig`
//! * `sync`   – reconciles the result with the database
//!
//! The ssh config is only ever read, never written.

mod parser;
mod sync;

// `pub use` re-exports items from submodules: outside code can simply use
// `sshconfig::parse_config` instead of `sshconfig::parser::parse_config`.
// This keeps the internal file layout an implementation detail.
pub use parser::parse_config;
pub use sync::{SyncReport, sync};

use anyhow::{Context, Result};

use crate::paths;
use crate::store::Store;

/// Reads the default `~/.ssh/config` and reconciles it with the store.
///
/// Intended for `sshire import` and for CLI/TUI startup (T4/T5).
/// Parser warnings come first in [`SyncReport::warnings`].
pub fn sync_default(store: &mut Store) -> Result<SyncReport> {
    let home = paths::home_dir()?;
    let main = paths::ssh_config_path()?;
    let parsed = parse_config(&main, &home);
    // `.context(..)` attaches a readable description to the error.
    let mut report = sync(store, &parsed).context("Syncing with the database failed")?;
    // Put parser warnings before the sync warnings.
    let mut warnings = parsed.warnings;
    warnings.append(&mut report.warnings);
    report.warnings = warnings;
    Ok(report)
}
