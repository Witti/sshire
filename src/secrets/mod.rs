//! Secure storage of host passwords.
//!
//! sshire **never** stores passwords in plain text, and never in the normal
//! hosts table. The platform decides which store is used:
//!
//! * `keychain` - macOS: the system Keychain (compiled on macOS only)
//! * `encrypted` - everywhere: an encrypted `secrets` table in the SQLite DB,
//!   protected by a master password (the default on Linux)
//!
//! # Traits as an abstraction
//!
//! Both stores implement the same [`SecretStore`] trait. A *trait* is a list
//! of methods a type must offer - similar to an interface. The rest of the
//! program (TUI, CLI) works only with `Box<dyn SecretStore>`: a pointer to
//! *some* type that implements the trait. Which one it is gets chosen only at
//! runtime in [`open_default`] (*dynamic dispatch*; the call goes through a
//! function table).
//!
//! # Conditional compilation
//!
//! `#[cfg(target_os = "macos")]` means: this code exists only when compiling
//! for macOS. On Linux the compiler never even sees it - so it may use crates
//! there that do not exist on Linux.
//!
//! # Secrets in memory
//!
//! Passwords travel through the program as [`SecretString`]. This is a thin
//! wrapper around `zeroize::Zeroizing<String>`: when dropped (`Drop`), the
//! memory is overwritten with zeros so the password does not linger in RAM
//! longer than necessary. Also, `Debug` never prints the contents, so an
//! accidental `{:?}` or `dbg!` reveals nothing.

mod encrypted;
#[cfg(target_os = "macos")]
mod keychain;
#[cfg(test)]
mod memory;

use std::fmt;
use std::path::Path;

use anyhow::Context;
use thiserror::Error;
use zeroize::Zeroizing;

pub use encrypted::EncryptedStore;
#[cfg(test)]
pub use encrypted::KdfParams;
pub(crate) use encrypted::random_bytes;
#[cfg(test)]
pub use memory::MemoryStore;

use crate::store::{Host, Store};

/// Minimum length of the master password (in characters).
pub const MIN_MASTER_LEN: usize = 8;
/// Maximum length of a host password (in bytes); guards against absurd input.
pub const MAX_SECRET_LEN: usize = 1024;
/// Name of the environment variable that forces the backend.
const BACKEND_ENV: &str = "SSHIRE_SECRET_BACKEND";

/// A secret (password) that is overwritten when dropped.
///
/// No `Clone` and no derived `Debug`: copies would leave more traces in
/// memory, and `{:?}` must never print the password.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes over a `String` (from now on it is overwritten when dropped).
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The plain text. The name is a reminder that the secret is exposed here.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    // Custom `Debug` implementation: never prints the contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<hidden>)")
    }
}

impl PartialEq for SecretString {
    /// Constant-time comparison (see `connect::askpass` on timing attacks).
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.expose()
            .as_bytes()
            .ct_eq(other.expose().as_bytes())
            .into()
    }
}

impl Eq for SecretString {}

/// Which store is used (for display and selection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Keychain.
    Keychain,
    /// Encrypted table in the SQLite DB (master password).
    Encrypted,
}

impl BackendKind {
    /// Short name for the UI ("Keychain" / "encrypted").
    pub fn label(self) -> &'static str {
        match self {
            Self::Keychain => "Keychain",
            Self::Encrypted => "encrypted",
        }
    }
}

/// Whether the store is usable right away or first needs a master password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Ready (Keychain, or the key is already in memory).
    Ready,
    /// A master password exists but must be entered ([`SecretStore::unlock`]).
    Locked,
    /// There is no master password yet ([`SecretStore::initialize`]).
    NeedsInit,
}

/// Errors of the secret stores. The messages never contain a password.
#[derive(Debug, Error)]
pub enum SecretError {
    /// The store is locked: enter the master password first.
    #[error("The password store is locked (master password required)")]
    Locked,
    /// No master password has been set yet.
    #[error("No master password has been set yet")]
    NotInitialized,
    /// A master password already exists.
    #[error("A master password has already been set")]
    AlreadyInitialized,
    /// The entered master password does not match the verifier.
    #[error("Wrong master password")]
    WrongMasterPassword,
    /// An input is not allowed (empty, too long, too short, ...).
    #[error("Invalid input: {0}")]
    InvalidInput(&'static str),
    /// Stored data is damaged or was tampered with.
    #[error("Stored data is corrupted or has been tampered with: {0}")]
    Corrupt(String),
    /// This store does not offer the feature.
    #[error("Not supported by this password store: {0}")]
    Unsupported(&'static str),
    /// Error from the underlying system (Keychain, database, randomness, ...).
    #[error("Password store unavailable: {0}")]
    Backend(String),
}

/// Shorthand for results of the secret layer.
pub type Result<T> = std::result::Result<T, SecretError>;

/// Common interface of all password stores.
///
/// The methods take `&mut self` because some stores change their state when
/// unlocking (key in memory). `host_id` is the ID from the `hosts` table.
pub trait SecretStore {
    /// Which store this is.
    fn kind(&self) -> BackendKind;

    /// Current lock state. Default: always ready (Keychain).
    fn lock_state(&self) -> Result<LockState> {
        Ok(LockState::Ready)
    }

    /// Unlocks the store with the master password. Default: nothing to do.
    fn unlock(&mut self, _master: &str) -> Result<()> {
        Ok(())
    }

    /// Sets a new master password (only for [`LockState::NeedsInit`]).
    fn initialize(&mut self, _master: &str) -> Result<()> {
        Err(SecretError::Unsupported("master password"))
    }

    /// Changes the master password and re-encrypts all entries.
    fn change_master(&mut self, _old: &str, _new: &str) -> Result<()> {
        Err(SecretError::Unsupported("changing the master password"))
    }

    /// Reads a host's password; `Ok(None)` if none is stored.
    fn get(&mut self, host_id: i64) -> Result<Option<SecretString>>;

    /// Stores or replaces a host's password.
    fn set(&mut self, host_id: i64, secret: &str) -> Result<()>;

    /// Deletes a host's password. Idempotent: "was not there" is not an error.
    fn delete(&mut self, host_id: i64) -> Result<()>;
}

/// Chooses the store by platform or environment variable.
///
/// A pure function (the variable's value is passed in) so it can be tested
/// without modifying the process environment.
pub fn select_backend(override_value: Option<&str>) -> Result<BackendKind> {
    match override_value.map(str::trim) {
        None | Some("") => Ok(default_backend()),
        Some("encrypted") => Ok(BackendKind::Encrypted),
        Some("keychain") => {
            if cfg!(target_os = "macos") {
                Ok(BackendKind::Keychain)
            } else {
                Err(SecretError::Unsupported(
                    "the Keychain exists only on macOS",
                ))
            }
        }
        Some(_) => Err(SecretError::InvalidInput(
            "SSHIRE_SECRET_BACKEND must be \"encrypted\" or \"keychain\"",
        )),
    }
}

/// Default backend of the platform.
fn default_backend() -> BackendKind {
    // `cfg!` is like `#[cfg]`, but as an expression: yields `true`/`false`.
    if cfg!(target_os = "macos") {
        BackendKind::Keychain
    } else {
        BackendKind::Encrypted
    }
}

/// Opens the platform's store (or the one chosen via `SSHIRE_SECRET_BACKEND`).
///
/// `db_path` is the SQLite file; the encrypted backend keeps its data there.
/// The file must already be migrated (i.e. after `Store::open`).
pub fn open_default(db_path: &Path) -> Result<Box<dyn SecretStore>> {
    let override_value = std::env::var(BACKEND_ENV).ok();
    open_backend(select_backend(override_value.as_deref())?, db_path)
}

/// Opens the given store.
pub fn open_backend(kind: BackendKind, db_path: &Path) -> Result<Box<dyn SecretStore>> {
    match kind {
        BackendKind::Encrypted => Ok(Box::new(EncryptedStore::open(db_path)?)),
        BackendKind::Keychain => open_keychain(),
    }
}

#[cfg(target_os = "macos")]
fn open_keychain() -> Result<Box<dyn SecretStore>> {
    Ok(Box::new(keychain::KeychainStore::new()))
}

#[cfg(not(target_os = "macos"))]
fn open_keychain() -> Result<Box<dyn SecretStore>> {
    Err(SecretError::Unsupported(
        "the Keychain exists only on macOS",
    ))
}

/// Validates a *new* master password (minimum length, no control characters).
pub fn check_new_master(master: &str) -> std::result::Result<(), &'static str> {
    if master.chars().count() < MIN_MASTER_LEN {
        Err("The master password must be at least 8 characters long")
    } else if master.chars().any(char::is_control) {
        Err("The master password must not contain control characters")
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Interplay of store and database (the `has_password` flag)
// ---------------------------------------------------------------------------
//
// The order matters so that a password never becomes "orphaned":
//  * save: secret first, then the flag - if the flag fails, there is a
//    secret without a flag (harmless, setting it again repairs it);
//  * delete: secret first, then the flag or host - if deleting the secret
//    fails, everything else stays unchanged and the error is reported.

/// Stores the password and sets the `has_password` flag.
pub fn save_host_password(
    secrets: &mut dyn SecretStore,
    store: &Store,
    host_id: i64,
    password: &str,
) -> anyhow::Result<()> {
    secrets.set(host_id, password)?;
    store
        .set_has_password(host_id, true)
        .context("the password was stored, but the flag in the database was not set")?;
    Ok(())
}

/// Removes the password and clears the flag.
pub fn remove_host_password(
    secrets: &mut dyn SecretStore,
    store: &Store,
    host_id: i64,
) -> anyhow::Result<()> {
    secrets.delete(host_id)?;
    store.set_has_password(host_id, false)?;
    Ok(())
}

/// Deletes a host *and* its password. The Keychain has no
/// `ON DELETE CASCADE`, so the secret is removed first and always
/// (even if the flag is missing - `delete` is idempotent and needs no
/// master password).
pub fn delete_host_with_secret(
    secrets: &mut dyn SecretStore,
    store: &Store,
    host_id: i64,
) -> anyhow::Result<()> {
    secrets
        .delete(host_id)
        .context("the stored password could not be removed - host not deleted")?;
    store.delete_host(host_id)?;
    Ok(())
}

/// Fetches the password for establishing a connection.
///
/// `Ok(None)`: the host has no password. If the flag does not match the
/// store (flag set but no entry), the flag is repaired and `None` is
/// returned as well.
pub fn fetch_host_password(
    secrets: &mut dyn SecretStore,
    store: &Store,
    host: &Host,
) -> anyhow::Result<Option<SecretString>> {
    if !host.has_password {
        return Ok(None);
    }
    match secrets.get(host.id)? {
        Some(secret) => Ok(Some(secret)),
        None => {
            store.set_has_password(host.id, false)?;
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Hex helpers (for the token and database text)
// ---------------------------------------------------------------------------

/// Bytes as lowercase hex.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Counterpart to [`encode_hex`]; `None` for invalid text.
pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    // `as_chunks` splits into groups of two; a remainder means: odd length.
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    pairs
        .iter()
        .map(|[high, low]| Some(nibble(*high)? << 4 | nibble(*low)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewHost;

    #[test]
    fn secret_string_debug_never_leaks() {
        let secret = SecretString::new("hunter2".to_owned());
        assert!(!format!("{secret:?}").contains("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(secret, SecretString::new("hunter2".to_owned()));
        assert_ne!(secret, SecretString::new("hunter3".to_owned()));
    }

    #[test]
    fn hex_roundtrip_and_rejects_garbage() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(encode_hex(&bytes), "000fa5ff");
        assert_eq!(decode_hex("000fa5ff").unwrap(), bytes);
        assert!(decode_hex("0").is_none());
        assert!(decode_hex("zz").is_none());
        assert!(decode_hex("A5").is_none());
    }

    #[test]
    fn backend_selection_follows_override() {
        assert_eq!(
            select_backend(Some("encrypted")).unwrap(),
            BackendKind::Encrypted
        );
        assert_eq!(select_backend(None).unwrap(), default_backend());
        assert_eq!(select_backend(Some("")).unwrap(), default_backend());
        assert!(select_backend(Some("bogus")).is_err());
        #[cfg(not(target_os = "macos"))]
        assert!(select_backend(Some("keychain")).is_err());
        #[cfg(target_os = "macos")]
        assert_eq!(
            select_backend(Some("keychain")).unwrap(),
            BackendKind::Keychain
        );
    }

    #[test]
    fn master_password_rules() {
        assert!(check_new_master("short").is_err());
        assert!(check_new_master("long enough pw").is_ok());
        assert!(check_new_master("tab\tinside-pw").is_err());
    }

    #[test]
    fn save_remove_and_fetch_maintain_the_flag() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let mut secrets = MemoryStore::default();
        save_host_password(&mut secrets, &store, id, "pw").unwrap();
        let host = store.get_host(id).unwrap().unwrap();
        assert!(host.has_password);
        let got = fetch_host_password(&mut secrets, &store, &host).unwrap();
        assert_eq!(got.unwrap().expose(), "pw");

        remove_host_password(&mut secrets, &store, id).unwrap();
        let host = store.get_host(id).unwrap().unwrap();
        assert!(!host.has_password);
        assert!(secrets.get(id).unwrap().is_none());
    }

    #[test]
    fn fetch_heals_a_stale_flag() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        store.set_has_password(id, true).unwrap();
        let host = store.get_host(id).unwrap().unwrap();
        let mut secrets = MemoryStore::default();
        assert!(
            fetch_host_password(&mut secrets, &store, &host)
                .unwrap()
                .is_none()
        );
        assert!(!store.get_host(id).unwrap().unwrap().has_password);
    }

    #[test]
    fn deleting_a_host_removes_its_secret_first() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let mut secrets = MemoryStore::default();
        save_host_password(&mut secrets, &store, id, "pw").unwrap();
        delete_host_with_secret(&mut secrets, &store, id).unwrap();
        assert!(store.get_host(id).unwrap().is_none());
        assert!(secrets.get(id).unwrap().is_none());
    }

    #[test]
    fn failing_secret_delete_keeps_the_host() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_host(&NewHost::new("a")).unwrap();
        let mut secrets = MemoryStore::default();
        secrets.fail_delete = true;
        assert!(delete_host_with_secret(&mut secrets, &store, id).is_err());
        assert!(store.get_host(id).unwrap().is_some());
    }
}
