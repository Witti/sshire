//! macOS Keychain as the password store (compiled on macOS only).
//!
//! Each host password is an entry with service `sshire` and account
//! `host:<id>`. The database contains none of it. macOS handles encryption
//! and access control (possibly with a confirmation dialog from the system).
//!
//! The Keychain has no `ON DELETE CASCADE`: when a host is deleted, sshire
//! must remove the entry itself (see `delete_host_with_secret`).

use keyring::Entry;

use super::{BackendKind, Result, SecretError, SecretStore, SecretString};

/// Service name of the entries in the Keychain.
const SERVICE: &str = "sshire";

/// Keychain store. Holds only the service name; the entries live in the system.
pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    /// Store with the real service name `sshire`.
    pub fn new() -> Self {
        Self::with_service(SERVICE)
    }

    /// Store with a different service name (tests use `sshire-test` so real
    /// entries are never touched).
    pub fn with_service(service: &str) -> Self {
        Self {
            service: service.to_owned(),
        }
    }

    /// The Keychain entry for a host.
    fn entry(&self, host_id: i64) -> Result<Entry> {
        Entry::new(&self.service, &format!("host:{host_id}")).map_err(map_error)
    }
}

/// Translates Keychain errors into our error type (no secrets in the text).
fn map_error(err: keyring::Error) -> SecretError {
    SecretError::Backend(format!("Keychain: {err}"))
}

impl SecretStore for KeychainStore {
    fn kind(&self) -> BackendKind {
        BackendKind::Keychain
    }

    fn get(&mut self, host_id: i64) -> Result<Option<SecretString>> {
        match self.entry(host_id)?.get_password() {
            // The string moves straight into the zeroizing wrapper (no copy).
            Ok(password) => Ok(Some(SecretString::new(password))),
            // "No entry" is a normal case, not an error.
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_error(err)),
        }
    }

    fn set(&mut self, host_id: i64, secret: &str) -> Result<()> {
        if secret.is_empty() {
            return Err(SecretError::InvalidInput("empty password"));
        }
        self.entry(host_id)?.set_password(secret).map_err(map_error)
    }

    fn delete(&mut self, host_id: i64) -> Result<()> {
        match self.entry(host_id)?.delete_credential() {
            // Idempotent: if nothing was there, the goal ("gone") is already met.
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_error(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes to the *real* Keychain (service `sshire-test`) and may trigger
    /// system dialogs, so it only runs manually:
    /// `cargo test keychain -- --ignored`.
    #[test]
    #[ignore = "touches the real macOS Keychain"]
    fn roundtrip_in_real_keychain() {
        let mut store = KeychainStore::with_service("sshire-test");
        let id = 987_654_321;
        store.delete(id).unwrap();
        assert!(store.get(id).unwrap().is_none());
        store.set(id, "pässword").unwrap();
        assert_eq!(store.get(id).unwrap().unwrap().expose(), "pässword");
        store.delete(id).unwrap();
        store.delete(id).unwrap();
        assert!(store.get(id).unwrap().is_none());
    }

    #[test]
    fn empty_password_is_rejected_before_touching_the_keychain() {
        let mut store = KeychainStore::with_service("sshire-test");
        assert!(matches!(
            store.set(1, ""),
            Err(SecretError::InvalidInput(_))
        ));
    }
}
