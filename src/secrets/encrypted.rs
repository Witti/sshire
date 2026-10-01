//! Passwords encrypted inside the SQLite database (master password).
//!
//! This backend compiles on *all* platforms (so it can be tested on macOS
//! too) and is the default on Linux.
//!
//! # How the encryption works (simply explained)
//!
//! * **AEAD** ("Authenticated Encryption with Associated Data"): a scheme that
//!   *encrypts* and *authenticates* data at the same time. Anyone who changes
//!   the ciphertext by even a single bit gets an error on decryption instead
//!   of wrong data. We use XChaCha20-Poly1305.
//! * **Nonce** ("number used once"): a random number that goes into the
//!   encryption together with the key. The same combination of key + nonce
//!   must **never** be used for two different messages - otherwise plaintexts
//!   can be computed from the ciphertexts. That is why we draw a new, random
//!   24-byte nonce for *every* encryption. At 192 bits a random collision is
//!   practically impossible (that is exactly what the "X" variant is for).
//! * **AAD** ("Additional Authenticated Data"): extra data that is *not*
//!   encrypted but is authenticated along with the message. We pass
//!   `sshire:v1:host:<id>`. If someone copies host 1's row into host 2's row,
//!   the AAD no longer matches and decryption fails.
//! * **KDF** ("Key Derivation Function"): the 32-byte key is derived from the
//!   master password. We use **Argon2id**: deliberately slow and memory-hungry
//!   (64 MiB) so every guess an attacker makes is expensive - even on GPUs. A
//!   random *salt* ensures that identical passwords do not lead to the same
//!   key and that precomputed tables are useless.
//! * **Verifier**: a known plaintext, encrypted with the derived key and
//!   stored in `meta`. On unlock it is decrypted: if that works, the master
//!   password was correct.
//!
//! Salt, Argon2 parameters and verifier live in the `meta` table. Because the
//! parameters are stored alongside, they can be raised later without old
//! databases becoming unreadable.
//!
//! # Key in memory
//!
//! The key lives as `Zeroizing<[u8; 32]>` in RAM only and is held for the
//! lifetime of the process (so you do not have to unlock again for every
//! connection). It is overwritten when dropped. It is never written to disk.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension, params};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::{
    BackendKind, LockState, MAX_SECRET_LEN, Result, SecretError, SecretStore, SecretString,
    decode_hex, encode_hex,
};

/// Length of the key in bytes (XChaCha20 needs 256 bits).
const KEY_LEN: usize = 32;
/// Length of the nonce in bytes (XChaCha20: 192 bits).
const NONCE_LEN: usize = 24;
/// Length of the salt in bytes.
const SALT_LEN: usize = 16;

/// Identifier of the scheme, so it could be switched later.
const KDF_ALGO: &str = "argon2id-v19";
/// Known plaintext of the verifier.
const VERIFIER_PLAINTEXT: &[u8] = b"sshire-master-password-verifier-v1";
/// AAD of the verifier (different from any host AAD, so it is never confused with a row).
const VERIFIER_AAD: &[u8] = b"sshire:v1:verifier";
/// Start of the AAD for host passwords; the host ID is appended.
const HOST_AAD_PREFIX: &str = "sshire:v1:host:";

// Keys of the `meta` table.
const META_ALGO: &str = "kdf_algo";
const META_M: &str = "kdf_m_kib";
const META_T: &str = "kdf_t";
const META_P: &str = "kdf_p";
const META_SALT: &str = "kdf_salt";
const META_VERIFIER: &str = "verifier";
const META_KEYS: [&str; 6] = [META_ALGO, META_M, META_T, META_P, META_SALT, META_VERIFIER];

/// Cost parameters of Argon2id.
///
/// They are stored in `meta` on creation; on unlock the *stored* values
/// always apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory requirement in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl KdfParams {
    /// Production values: 64 MiB, 3 passes, 1 thread.
    pub const PRODUCTION: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };

    /// Minimal cost - just so tests do not compute 64 MiB every time.
    #[cfg(test)]
    pub const FAST: Self = Self {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    /// Upper bounds for values that are *read*: a tampered `meta` table
    /// must not be able to cripple sshire with absurd costs.
    fn check_sane(self) -> Result<()> {
        let ok = (8..=1_048_576).contains(&self.m_kib)
            && (1..=64).contains(&self.t)
            && (1..=16).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(SecretError::Corrupt(
                "invalid Argon2 parameters in the database".to_owned(),
            ))
        }
    }
}

/// What is stored in `meta` (everything needed for deriving and verifying).
struct Header {
    params: KdfParams,
    salt: Vec<u8>,
    verifier_nonce: [u8; NONCE_LEN],
    verifier_ct: Vec<u8>,
}

/// Encrypted store inside the SQLite database.
///
/// Owns its *own* connection to the same file as the `Store`
/// (SQLite allows multiple connections; in WAL mode they do not block each other).
pub struct EncryptedStore {
    conn: Connection,
    /// Parameters for *new* master passwords.
    new_params: KdfParams,
    /// The derived key, while unlocked.
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl EncryptedStore {
    /// Opens the store with the production parameters.
    ///
    /// The database must already be migrated (i.e. call `Store::open` first).
    pub fn open(db_path: &Path) -> Result<Self> {
        Self::open_with_params(db_path, KdfParams::PRODUCTION)
    }

    /// Like [`EncryptedStore::open`], with custom parameters for new master passwords.
    pub fn open_with_params(db_path: &Path, new_params: KdfParams) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        // Without this line SQLite would ignore `ON DELETE CASCADE`.
        conn.pragma_update(None, "foreign_keys", true)?;
        Ok(Self {
            conn,
            new_params,
            key: None,
        })
    }

    /// Reads the header from `meta`. `None` if no master password exists yet.
    fn load_header(&self) -> Result<Option<Header>> {
        let mut stmt = self.conn.prepare("SELECT key, value FROM meta")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut meta: HashMap<String, String> = HashMap::new();
        for row in rows {
            let (key, value) = row?;
            if META_KEYS.contains(&key.as_str()) {
                meta.insert(key, value);
            }
        }
        if meta.is_empty() {
            return Ok(None);
        }
        let corrupt = |what: &str| SecretError::Corrupt(format!("meta: {what}"));
        let get = |key: &str| meta.get(key).ok_or_else(|| corrupt("entry missing"));
        if get(META_ALGO)? != KDF_ALGO {
            return Err(corrupt("unknown derivation scheme"));
        }
        let number =
            |key: &str| -> Result<u32> { get(key)?.parse().map_err(|_| corrupt("invalid number")) };
        let params = KdfParams {
            m_kib: number(META_M)?,
            t: number(META_T)?,
            p: number(META_P)?,
        };
        params.check_sane()?;
        let salt = decode_hex(get(META_SALT)?).ok_or_else(|| corrupt("invalid salt"))?;
        if salt.len() < SALT_LEN {
            return Err(corrupt("salt too short"));
        }
        let verifier =
            decode_hex(get(META_VERIFIER)?).ok_or_else(|| corrupt("invalid verifier"))?;
        if verifier.len() <= NONCE_LEN {
            return Err(corrupt("verifier too short"));
        }
        let (nonce, ct) = verifier.split_at(NONCE_LEN);
        let mut verifier_nonce = [0_u8; NONCE_LEN];
        verifier_nonce.copy_from_slice(nonce);
        Ok(Some(Header {
            params,
            salt,
            verifier_nonce,
            verifier_ct: ct.to_vec(),
        }))
    }

    /// Derives the key and checks it against the verifier.
    fn derive_and_verify(master: &str, header: &Header) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let key = derive_key(master, &header.salt, header.params)?;
        let plain = open(
            &key,
            VERIFIER_AAD,
            &header.verifier_nonce,
            &header.verifier_ct,
        )
        .map_err(|_| SecretError::WrongMasterPassword)?;
        // Additionally compare against the expected plaintext in constant time.
        if plain.as_slice().ct_eq(VERIFIER_PLAINTEXT).into() {
            Ok(key)
        } else {
            Err(SecretError::WrongMasterPassword)
        }
    }

    /// The key if unlocked - otherwise the matching error.
    fn key(&self) -> Result<&Zeroizing<[u8; KEY_LEN]>> {
        match &self.key {
            Some(key) => Ok(key),
            None => match self.load_header()? {
                Some(_) => Err(SecretError::Locked),
                None => Err(SecretError::NotInitialized),
            },
        }
    }

    /// Writes parameters, salt and verifier to `meta` (within a transaction).
    fn write_header(
        tx: &rusqlite::Transaction<'_>,
        params: KdfParams,
        salt: &[u8],
        verifier_nonce: &[u8; NONCE_LEN],
        verifier_ct: &[u8],
    ) -> Result<()> {
        let mut verifier = Vec::with_capacity(NONCE_LEN + verifier_ct.len());
        verifier.extend_from_slice(verifier_nonce);
        verifier.extend_from_slice(verifier_ct);
        let entries: [(&str, String); 6] = [
            (META_ALGO, KDF_ALGO.to_owned()),
            (META_M, params.m_kib.to_string()),
            (META_T, params.t.to_string()),
            (META_P, params.p.to_string()),
            (META_SALT, encode_hex(salt)),
            (META_VERIFIER, encode_hex(&verifier)),
        ];
        for (key, value) in entries {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
        }
        Ok(())
    }
}

impl SecretStore for EncryptedStore {
    fn kind(&self) -> BackendKind {
        BackendKind::Encrypted
    }

    fn lock_state(&self) -> Result<LockState> {
        if self.key.is_some() {
            return Ok(LockState::Ready);
        }
        Ok(match self.load_header()? {
            Some(_) => LockState::Locked,
            None => LockState::NeedsInit,
        })
    }

    fn unlock(&mut self, master: &str) -> Result<()> {
        let header = self.load_header()?.ok_or(SecretError::NotInitialized)?;
        self.key = Some(Self::derive_and_verify(master, &header)?);
        Ok(())
    }

    fn initialize(&mut self, master: &str) -> Result<()> {
        if self.load_header()?.is_some() {
            return Err(SecretError::AlreadyInitialized);
        }
        // If entries exist without a master password, `meta` has been lost.
        // A new master password would make the old entries unreadable
        // forever - that must not happen silently.
        let existing: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
        if existing > 0 {
            return Err(SecretError::Corrupt(
                "there are encrypted passwords, but no master password salt".to_owned(),
            ));
        }
        let params = self.new_params;
        params.check_sane()?;
        let salt = random_bytes::<SALT_LEN>()?;
        let key = derive_key(master, &salt, params)?;
        let (nonce, ct) = seal(&key, VERIFIER_AAD, VERIFIER_PLAINTEXT)?;
        let tx = self.conn.transaction()?;
        Self::write_header(&tx, params, &salt, &nonce, &ct)?;
        tx.commit()?;
        self.key = Some(key);
        Ok(())
    }

    fn change_master(&mut self, old: &str, new: &str) -> Result<()> {
        let header = self.load_header()?.ok_or(SecretError::NotInitialized)?;
        let old_key = Self::derive_and_verify(old, &header)?;
        let params = self.new_params;
        params.check_sane()?;
        let salt = random_bytes::<SALT_LEN>()?;
        let new_key = derive_key(new, &salt, params)?;
        let (v_nonce, v_ct) = seal(&new_key, VERIFIER_AAD, VERIFIER_PLAINTEXT)?;

        // Everything in one transaction: if something aborts, the old state is
        // fully preserved (no mixed state of old and new key).
        let tx = self.conn.transaction()?;
        let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx.prepare("SELECT host_id, nonce, ciphertext FROM secrets")?;
            let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<std::result::Result<_, _>>()?
        };
        for (host_id, nonce, ct) in rows {
            let aad = host_aad(host_id);
            let plain = open(&old_key, &aad, &nonce, &ct).map_err(|_| {
                SecretError::Corrupt(format!("entry for host {host_id} is unreadable"))
            })?;
            let (new_nonce, new_ct) = seal(&new_key, &aad, &plain)?;
            tx.execute(
                "UPDATE secrets SET nonce = ?1, ciphertext = ?2 WHERE host_id = ?3",
                params![new_nonce.as_slice(), new_ct, host_id],
            )?;
        }
        Self::write_header(&tx, params, &salt, &v_nonce, &v_ct)?;
        tx.commit()?;
        self.key = Some(new_key);
        Ok(())
    }

    fn get(&mut self, host_id: i64) -> Result<Option<SecretString>> {
        let key = self.key()?;
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM secrets WHERE host_id = ?1",
                params![host_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((nonce, ct)) = row else {
            return Ok(None);
        };
        let plain = open(key, &host_aad(host_id), &nonce, &ct).map_err(|_| {
            SecretError::Corrupt(format!("password of host {host_id} cannot be decrypted"))
        })?;
        // Bytes -> String. If that fails, the buffer is overwritten anyway.
        match String::from_utf8(plain.to_vec()) {
            Ok(text) => Ok(Some(SecretString::new(text))),
            Err(err) => {
                let mut bytes = err.into_bytes();
                bytes.zeroize();
                Err(SecretError::Corrupt(
                    "password is not valid text".to_owned(),
                ))
            }
        }
    }

    fn set(&mut self, host_id: i64, secret: &str) -> Result<()> {
        if secret.is_empty() {
            return Err(SecretError::InvalidInput("empty password"));
        }
        if secret.len() > MAX_SECRET_LEN {
            return Err(SecretError::InvalidInput("password is too long"));
        }
        let key = self.key()?;
        // A fresh nonce every time - even when overwriting the same host.
        let (nonce, ct) = seal(key, &host_aad(host_id), secret.as_bytes())?;
        self.conn.execute(
            "INSERT INTO secrets (host_id, nonce, ciphertext) VALUES (?1, ?2, ?3) \
             ON CONFLICT(host_id) DO UPDATE \
             SET nonce = excluded.nonce, ciphertext = excluded.ciphertext",
            params![host_id, nonce.as_slice(), ct],
        )?;
        Ok(())
    }

    fn delete(&mut self, host_id: i64) -> Result<()> {
        // Deleting needs no key - nothing has to be decrypted.
        self.conn
            .execute("DELETE FROM secrets WHERE host_id = ?1", params![host_id])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cryptographic building blocks
// ---------------------------------------------------------------------------

impl From<rusqlite::Error> for SecretError {
    fn from(err: rusqlite::Error) -> Self {
        // SQLite messages do not contain bound values, so no passwords.
        Self::Backend(format!("Database: {err}"))
    }
}

/// The AAD of a host password: `sshire:v1:host:<id>`.
fn host_aad(host_id: i64) -> Vec<u8> {
    format!("{HOST_AAD_PREFIX}{host_id}").into_bytes()
}

/// Random bytes from the operating system (for salt and nonces).
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0_u8; N];
    getrandom::fill(&mut buf)
        .map_err(|err| SecretError::Backend(format!("Random numbers unavailable: {err}")))?;
    Ok(buf)
}

/// Derives a 32-byte key from the master password with Argon2id.
fn derive_key(master: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN))
        .map_err(|err| SecretError::Backend(format!("Argon2 parameters: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon
        .hash_password_into(master.as_bytes(), salt, key.as_mut_slice())
        .map_err(|err| SecretError::Backend(format!("Key derivation: {err}")))?;
    Ok(key)
}

/// Builds the cipher from the key. (With the `zeroize` feature the cipher
/// overwrites its key itself when dropped.)
fn cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SecretError::Backend("Invalid key length".to_owned()))
}

/// Encrypts `plaintext` with a fresh random nonce; returns (nonce, ciphertext+tag).
fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = cipher(key)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecretError::Backend("Encryption failed".to_owned()))?;
    Ok((nonce, ciphertext))
}

/// Decrypts and verifies tag *and* AAD. An error (`Err(())`) means:
/// wrong key, wrong AAD or modified material - deliberately without
/// distinction so an attacker learns nothing from it.
fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, ()> {
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| ())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| ())?;
    let plain = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())?;
    // Straight into `Zeroizing`: the plaintext is overwritten when dropped.
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{NewHost, Store};

    const MASTER: &str = "correct horse battery";

    /// Temp directory with a migrated DB and two hosts.
    struct Fixture {
        dir: tempfile::TempDir,
        ids: [i64; 2],
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path().join("sshire.db")).unwrap();
            let a = store.insert_host(&NewHost::new("a")).unwrap();
            let b = store.insert_host(&NewHost::new("b")).unwrap();
            Self { dir, ids: [a, b] }
        }

        fn path(&self) -> std::path::PathBuf {
            self.dir.path().join("sshire.db")
        }

        fn open(&self) -> EncryptedStore {
            EncryptedStore::open_with_params(&self.path(), KdfParams::FAST).unwrap()
        }

        /// Opened and initialized with `MASTER`.
        fn ready(&self) -> EncryptedStore {
            let mut store = self.open();
            store.initialize(MASTER).unwrap();
            store
        }

        fn raw(&self) -> Connection {
            Connection::open(self.path()).unwrap()
        }
    }

    #[test]
    fn roundtrip_and_replace() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        assert!(store.get(fx.ids[0]).unwrap().is_none());
        store.set(fx.ids[0], "pässwörd 🔑").unwrap();
        assert_eq!(
            store.get(fx.ids[0]).unwrap().unwrap().expose(),
            "pässwörd 🔑"
        );
        store.set(fx.ids[0], "second").unwrap();
        assert_eq!(store.get(fx.ids[0]).unwrap().unwrap().expose(), "second");
        store.delete(fx.ids[0]).unwrap();
        store.delete(fx.ids[0]).unwrap(); // idempotent
        assert!(store.get(fx.ids[0]).unwrap().is_none());
    }

    #[test]
    fn plaintext_never_hits_the_database() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "very-secret-needle").unwrap();
        let ct: Vec<u8> = fx
            .raw()
            .query_row("SELECT ciphertext FROM secrets", [], |r| r.get(0))
            .unwrap();
        let needle = b"very-secret-needle";
        assert!(!ct.windows(needle.len()).any(|w| w == needle));
        // Nonce 24 bytes, ciphertext = plaintext + 16-byte tag.
        let nonce_len: i64 = fx
            .raw()
            .query_row("SELECT length(nonce) FROM secrets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(nonce_len, 24);
        assert_eq!(ct.len(), needle.len() + 16);
    }

    #[test]
    fn every_encryption_uses_a_fresh_nonce() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        let nonce_of = || -> Vec<u8> {
            fx.raw()
                .query_row(
                    "SELECT nonce FROM secrets WHERE host_id = ?1",
                    [fx.ids[0]],
                    |r| r.get(0),
                )
                .unwrap()
        };
        store.set(fx.ids[0], "same").unwrap();
        let first = nonce_of();
        store.set(fx.ids[0], "same").unwrap();
        assert_ne!(first, nonce_of());
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let fx = Fixture::new();
        fx.ready();
        let mut again = fx.open();
        assert_eq!(again.lock_state().unwrap(), LockState::Locked);
        assert!(matches!(
            again.unlock("definitely wrong"),
            Err(SecretError::WrongMasterPassword)
        ));
        // Still locked: no access without a key.
        assert!(matches!(again.get(fx.ids[0]), Err(SecretError::Locked)));
        assert!(matches!(
            again.set(fx.ids[0], "x"),
            Err(SecretError::Locked)
        ));
        again.unlock(MASTER).unwrap();
        assert_eq!(again.lock_state().unwrap(), LockState::Ready);
    }

    #[test]
    fn uninitialized_store_needs_init() {
        let fx = Fixture::new();
        let mut store = fx.open();
        assert_eq!(store.lock_state().unwrap(), LockState::NeedsInit);
        assert!(matches!(
            store.set(fx.ids[0], "x"),
            Err(SecretError::NotInitialized)
        ));
        assert!(matches!(
            store.unlock(MASTER),
            Err(SecretError::NotInitialized)
        ));
        store.initialize(MASTER).unwrap();
        assert!(matches!(
            store.initialize("another master"),
            Err(SecretError::AlreadyInitialized)
        ));
    }

    #[test]
    fn tampered_ciphertext_or_nonce_is_detected() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "secret").unwrap();
        let raw = fx.raw();
        let (nonce, ct): (Vec<u8>, Vec<u8>) = raw
            .query_row("SELECT nonce, ciphertext FROM secrets", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        raw.execute("UPDATE secrets SET ciphertext = ?1", [&bad_ct])
            .unwrap();
        assert!(matches!(store.get(fx.ids[0]), Err(SecretError::Corrupt(_))));
        raw.execute("UPDATE secrets SET ciphertext = ?1", [&ct])
            .unwrap();
        assert!(store.get(fx.ids[0]).unwrap().is_some());

        let mut bad_nonce = nonce.clone();
        bad_nonce[5] ^= 0x80;
        raw.execute("UPDATE secrets SET nonce = ?1", [&bad_nonce])
            .unwrap();
        assert!(matches!(store.get(fx.ids[0]), Err(SecretError::Corrupt(_))));
        // A nonce that is too short is also rejected cleanly (no panic).
        raw.execute("UPDATE secrets SET nonce = x'0102'", [])
            .unwrap();
        assert!(matches!(store.get(fx.ids[0]), Err(SecretError::Corrupt(_))));
    }

    #[test]
    fn ciphertext_is_bound_to_its_host_via_aad() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "secret of a").unwrap();
        // An attacker with DB access copies the row from host a to host b.
        fx.raw()
            .execute(
                "INSERT INTO secrets (host_id, nonce, ciphertext) \
                 SELECT ?1, nonce, ciphertext FROM secrets WHERE host_id = ?2",
                [fx.ids[1], fx.ids[0]],
            )
            .unwrap();
        assert!(matches!(store.get(fx.ids[1]), Err(SecretError::Corrupt(_))));
        // Host a stays readable.
        assert_eq!(
            store.get(fx.ids[0]).unwrap().unwrap().expose(),
            "secret of a"
        );
    }

    #[test]
    fn salt_and_params_are_persisted_and_used_on_unlock() {
        let fx = Fixture::new();
        {
            let mut store = fx.ready();
            store.set(fx.ids[0], "persisted").unwrap();
        }
        let raw = fx.raw();
        let meta = |key: &str| -> String {
            raw.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(meta("kdf_algo"), "argon2id-v19");
        assert_eq!(meta("kdf_m_kib"), "8");
        assert_eq!(meta("kdf_t"), "1");
        assert_eq!(meta("kdf_p"), "1");
        assert_eq!(decode_hex(&meta("kdf_salt")).unwrap().len(), SALT_LEN);

        // A new instance with *different* defaults still unlocks, because
        // the stored parameters apply.
        let other = KdfParams {
            m_kib: 16,
            t: 2,
            p: 1,
        };
        let mut again = EncryptedStore::open_with_params(&fx.path(), other).unwrap();
        again.unlock(MASTER).unwrap();
        assert_eq!(again.get(fx.ids[0]).unwrap().unwrap().expose(), "persisted");
    }

    #[test]
    fn two_stores_have_different_salts() {
        let (a, b) = (Fixture::new(), Fixture::new());
        a.ready();
        b.ready();
        let salt = |fx: &Fixture| -> String {
            fx.raw()
                .query_row("SELECT value FROM meta WHERE key = 'kdf_salt'", [], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_ne!(salt(&a), salt(&b));
    }

    #[test]
    fn tampered_params_are_rejected_not_executed() {
        let fx = Fixture::new();
        fx.ready();
        fx.raw()
            .execute(
                "UPDATE meta SET value = '4294967295' WHERE key = 'kdf_m_kib'",
                [],
            )
            .unwrap();
        let mut again = fx.open();
        assert!(matches!(again.unlock(MASTER), Err(SecretError::Corrupt(_))));
    }

    #[test]
    fn initialize_refuses_when_secrets_exist_without_header() {
        let fx = Fixture::new();
        {
            let mut store = fx.ready();
            store.set(fx.ids[0], "x").unwrap();
        }
        fx.raw().execute("DELETE FROM meta", []).unwrap();
        let mut again = fx.open();
        assert!(matches!(
            again.initialize("fresh master pw"),
            Err(SecretError::Corrupt(_))
        ));
    }

    #[test]
    fn delete_works_while_locked() {
        let fx = Fixture::new();
        {
            let mut store = fx.ready();
            store.set(fx.ids[0], "x").unwrap();
        }
        let mut locked = fx.open();
        locked.delete(fx.ids[0]).unwrap();
        let count: i64 = fx
            .raw()
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn deleting_the_host_cascades_to_its_secret() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "x").unwrap();
        let db = Store::open(fx.path()).unwrap();
        db.delete_host(fx.ids[0]).unwrap();
        let count: i64 = fx
            .raw()
            .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn rejects_empty_and_oversized_passwords() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        assert!(matches!(
            store.set(fx.ids[0], ""),
            Err(SecretError::InvalidInput(_))
        ));
        let huge = "x".repeat(MAX_SECRET_LEN + 1);
        assert!(matches!(
            store.set(fx.ids[0], &huge),
            Err(SecretError::InvalidInput(_))
        ));
    }

    #[test]
    fn change_master_reencrypts_everything() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "one").unwrap();
        store.set(fx.ids[1], "two").unwrap();
        assert!(matches!(
            store.change_master("wrong old master", "brand new master"),
            Err(SecretError::WrongMasterPassword)
        ));
        store.change_master(MASTER, "brand new master").unwrap();
        assert_eq!(store.get(fx.ids[1]).unwrap().unwrap().expose(), "two");

        let mut again = fx.open();
        assert!(again.unlock(MASTER).is_err());
        again.unlock("brand new master").unwrap();
        assert_eq!(again.get(fx.ids[0]).unwrap().unwrap().expose(), "one");
        assert_eq!(again.get(fx.ids[1]).unwrap().unwrap().expose(), "two");
    }

    #[test]
    fn failed_change_master_rolls_back() {
        let fx = Fixture::new();
        let mut store = fx.ready();
        store.set(fx.ids[0], "one").unwrap();
        // Damage a row: change_master must abort and change nothing.
        fx.raw()
            .execute("UPDATE secrets SET ciphertext = x'00'", [])
            .unwrap();
        assert!(store.change_master(MASTER, "brand new master").is_err());
        let mut again = fx.open();
        again.unlock(MASTER).unwrap();
        assert!(again.unlock("brand new master").is_err());
    }
}
