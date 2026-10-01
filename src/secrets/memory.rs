//! Simple in-memory store, for tests only.
//!
//! This lets TUI, CLI and ops logic be tested without touching the Keychain
//! or encryption.

use std::collections::HashMap;

use super::{BackendKind, Result, SecretError, SecretStore, SecretString};

/// Store backed by a `HashMap`.
#[derive(Default)]
pub struct MemoryStore {
    entries: HashMap<i64, String>,
    /// Makes `delete` fail (to test error paths).
    pub fail_delete: bool,
}

impl SecretStore for MemoryStore {
    fn kind(&self) -> BackendKind {
        BackendKind::Keychain
    }

    fn get(&mut self, host_id: i64) -> Result<Option<SecretString>> {
        Ok(self.entries.get(&host_id).cloned().map(SecretString::new))
    }

    fn set(&mut self, host_id: i64, secret: &str) -> Result<()> {
        self.entries.insert(host_id, secret.to_owned());
        Ok(())
    }

    fn delete(&mut self, host_id: i64) -> Result<()> {
        if self.fail_delete {
            return Err(SecretError::Backend("simulated error".to_owned()));
        }
        self.entries.remove(&host_id);
        Ok(())
    }
}
