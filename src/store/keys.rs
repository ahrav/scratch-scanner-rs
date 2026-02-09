//! Store key bootstrap and run-mode metadata.
//!
//! This module owns persistence identity key material. It loads the optional
//! `SCANNER_SECRET_KEY` environment variable and always returns derived subkeys:
//! - `identity_key` for rule/occurrence identifiers.
//! - `secret_key` for per-finding secret hashing.
//! - `metadata_key` for run metadata authentication/derivation.
//!
//! Missing or invalid env input falls back to an ephemeral per-process key and
//! marks run metadata accordingly so downstream consumers can avoid assuming
//! cross-run correlation.

use std::ffi::OsStr;
use std::fmt;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;

/// Environment variable used to load persistent store key material.
pub const SCANNER_SECRET_KEY_ENV: &str = "SCANNER_SECRET_KEY";

/// Store key contract version.
pub const STORE_KEYS_VERSION: u8 = 1;

/// Versioned key derivation contexts (BLAKE3 KDF).
pub const KEY_DERIVE_CONTEXT_IDENTITY_V1: &str = "scanner.store.keys.v1.identity";
/// Versioned key derivation contexts (BLAKE3 KDF).
pub const KEY_DERIVE_CONTEXT_SECRET_V1: &str = "scanner.store.keys.v1.secret";
/// Versioned key derivation contexts (BLAKE3 KDF).
pub const KEY_DERIVE_CONTEXT_METADATA_V1: &str = "scanner.store.keys.v1.metadata";

/// Correlation mode for this run's persistence identity outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationMode {
    /// Persistent key material loaded from `SCANNER_SECRET_KEY`.
    Persistent,
    /// Ephemeral key generated for this process only.
    Ephemeral,
}

/// Source of key material used for this run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// Key loaded from `SCANNER_SECRET_KEY`.
    EnvVar,
    /// Env var missing; ephemeral fallback was used.
    MissingEnvVar,
    /// Env var present but invalid; ephemeral fallback was used.
    InvalidEnvVar,
}

/// Public run metadata for persistence correlation semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunModeMetadata {
    /// Contract version for key derivation and metadata semantics.
    pub version: u8,
    /// Whether outputs are cross-run correlatable.
    pub correlation_mode: CorrelationMode,
    /// Where root key material came from for this run.
    pub key_source: KeySource,
}

impl RunModeMetadata {
    const fn persistent() -> Self {
        Self {
            version: STORE_KEYS_VERSION,
            correlation_mode: CorrelationMode::Persistent,
            key_source: KeySource::EnvVar,
        }
    }

    const fn ephemeral(source: KeySource) -> Self {
        Self {
            version: STORE_KEYS_VERSION,
            correlation_mode: CorrelationMode::Ephemeral,
            key_source: source,
        }
    }

    /// Returns true when key material is persistent and cross-run correlatable.
    #[must_use]
    pub const fn is_persistent(self) -> bool {
        matches!(self.correlation_mode, CorrelationMode::Persistent)
    }
}

/// Derived store keys for persistence identity contracts.
#[derive(Clone, Copy)]
pub struct StoreKeys {
    identity_key: [u8; 32],
    secret_key: [u8; 32],
    metadata_key: [u8; 32],
    run_mode: RunModeMetadata,
}

impl fmt::Debug for StoreKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreKeys")
            .field("run_mode", &self.run_mode)
            .field("identity_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("metadata_key", &"<redacted>")
            .finish()
    }
}

impl StoreKeys {
    /// Bootstrap store keys from `SCANNER_SECRET_KEY` with ephemeral fallback.
    ///
    /// `SCANNER_SECRET_KEY` must be standard base64 that decodes to exactly 32 bytes.
    /// Any missing/invalid value produces an ephemeral per-process key.
    #[must_use]
    pub fn bootstrap_from_env() -> Self {
        Self::bootstrap_from_os_value(std::env::var_os(SCANNER_SECRET_KEY_ENV).as_deref())
    }

    fn bootstrap_from_os_value(value: Option<&OsStr>) -> Self {
        if let Some(raw) = value {
            if let Some(root_key) = parse_root_key(raw) {
                return Self::from_root_key(root_key, RunModeMetadata::persistent());
            }
            let root_key = generate_ephemeral_root_key();
            return Self::from_root_key(
                root_key,
                RunModeMetadata::ephemeral(KeySource::InvalidEnvVar),
            );
        }

        let root_key = generate_ephemeral_root_key();
        Self::from_root_key(
            root_key,
            RunModeMetadata::ephemeral(KeySource::MissingEnvVar),
        )
    }

    fn from_root_key(root_key: [u8; 32], run_mode: RunModeMetadata) -> Self {
        let identity_key = blake3::derive_key(KEY_DERIVE_CONTEXT_IDENTITY_V1, &root_key);
        let secret_key = blake3::derive_key(KEY_DERIVE_CONTEXT_SECRET_V1, &root_key);
        let metadata_key = blake3::derive_key(KEY_DERIVE_CONTEXT_METADATA_V1, &root_key);

        Self {
            identity_key,
            secret_key,
            metadata_key,
            run_mode,
        }
    }

    /// Run metadata indicating persistent vs ephemeral correlation mode.
    #[must_use]
    pub const fn run_mode(&self) -> RunModeMetadata {
        self.run_mode
    }

    /// Key for rule fingerprint and occurrence-id derivation.
    #[must_use]
    pub(crate) const fn identity_key(&self) -> &[u8; 32] {
        &self.identity_key
    }

    /// Key for per-finding secret hash derivation.
    #[must_use]
    pub(crate) const fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }

    /// Key for metadata derivation/authentication.
    #[must_use]
    pub const fn metadata_key(&self) -> &[u8; 32] {
        &self.metadata_key
    }

    #[cfg(test)]
    pub(crate) fn from_test_root_key(root_key: [u8; 32], run_mode: RunModeMetadata) -> Self {
        Self::from_root_key(root_key, run_mode)
    }
}

fn parse_root_key(raw: &OsStr) -> Option<[u8; 32]> {
    let encoded = raw.to_str()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn generate_ephemeral_root_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    if fill_from_urandom(&mut key).is_ok() {
        return key;
    }

    // Fallback entropy path if `/dev/urandom` is unavailable.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scanner.store.keys.ephemeral.v1");
    hasher.update(&std::process::id().to_le_bytes());
    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
        hasher.update(&now.as_nanos().to_le_bytes());
    }
    let stack_marker = 0u8;
    hasher.update(&(std::ptr::addr_of!(stack_marker) as usize).to_le_bytes());
    let tid = format!("{:?}", std::thread::current().id());
    hasher.update(tid.as_bytes());
    *hasher.finalize().as_bytes()
}

fn fill_from_urandom(out: &mut [u8; 32]) -> std::io::Result<()> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_secret_key_env<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let prev = std::env::var_os(SCANNER_SECRET_KEY_ENV);
        match value {
            Some(v) => std::env::set_var(SCANNER_SECRET_KEY_ENV, v),
            None => std::env::remove_var(SCANNER_SECRET_KEY_ENV),
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        match prev {
            Some(v) => std::env::set_var(SCANNER_SECRET_KEY_ENV, v),
            None => std::env::remove_var(SCANNER_SECRET_KEY_ENV),
        }

        match result {
            Ok(v) => v,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn encode(bytes: [u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn valid_env_key_sets_persistent_mode() {
        let env_key = encode([0x11; 32]);
        with_secret_key_env(Some(&env_key), || {
            let keys_a = StoreKeys::bootstrap_from_env();
            let keys_b = StoreKeys::bootstrap_from_env();
            assert_eq!(
                keys_a.run_mode().correlation_mode,
                CorrelationMode::Persistent
            );
            assert_eq!(keys_a.run_mode().key_source, KeySource::EnvVar);
            assert_eq!(keys_a.identity_key(), keys_b.identity_key());
            assert_eq!(keys_a.secret_key(), keys_b.secret_key());
            assert_eq!(keys_a.metadata_key(), keys_b.metadata_key());
        });
    }

    #[test]
    fn missing_env_key_falls_back_to_ephemeral() {
        with_secret_key_env(None, || {
            let keys = StoreKeys::bootstrap_from_env();
            assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
            assert_eq!(keys.run_mode().key_source, KeySource::MissingEnvVar);
        });
    }

    #[test]
    fn invalid_env_key_falls_back_to_ephemeral() {
        with_secret_key_env(Some("not-base64"), || {
            let keys = StoreKeys::bootstrap_from_env();
            assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
            assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);
        });
    }

    #[test]
    fn wrong_length_env_key_falls_back_to_ephemeral() {
        let short = base64::engine::general_purpose::STANDARD.encode([0x22; 31]);
        with_secret_key_env(Some(&short), || {
            let keys = StoreKeys::bootstrap_from_env();
            assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
            assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);
        });
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_env_key_falls_back_to_ephemeral() {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let prev = std::env::var_os(SCANNER_SECRET_KEY_ENV);
        std::env::set_var(
            SCANNER_SECRET_KEY_ENV,
            OsString::from_vec(vec![0xFF, 0xFE, 0xFD]),
        );

        let keys = StoreKeys::bootstrap_from_env();
        assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
        assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);

        match prev {
            Some(v) => std::env::set_var(SCANNER_SECRET_KEY_ENV, v),
            None => std::env::remove_var(SCANNER_SECRET_KEY_ENV),
        }
    }

    #[test]
    fn debug_output_redacts_key_material() {
        let env_key = encode([0xAB; 32]);
        with_secret_key_env(Some(&env_key), || {
            let keys = StoreKeys::bootstrap_from_env();
            let dbg = format!("{keys:?}");
            assert!(dbg.contains("<redacted>"));
            assert!(!dbg.contains(&env_key));
        });
    }

    #[test]
    fn run_mode_is_persistent_helper_matches_mode() {
        let persistent = RunModeMetadata::persistent();
        let ephemeral = RunModeMetadata::ephemeral(KeySource::MissingEnvVar);
        assert!(persistent.is_persistent());
        assert!(!ephemeral.is_persistent());
    }
}
