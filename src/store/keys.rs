//! Store key bootstrap and run-mode metadata.
//!
//! This module owns persistence identity key material. It loads the optional
//! `SCANNER_SECRET_KEY` environment variable and always returns derived subkeys:
//! - `identity_key` — used by [`identity::rule_fingerprint`](super::identity::rule_fingerprint)
//!   and [`identity::occurrence_id`](super::identity::occurrence_id).
//! - `secret_key` — used by [`identity::secret_hash`](super::identity::secret_hash).
//! - `metadata_key` — available for run metadata authentication/derivation.
//!
//! Missing or invalid env input falls back to an ephemeral per-process key and
//! marks run metadata accordingly so downstream consumers can avoid assuming
//! cross-run correlation.
//!
//! # Key Derivation Model
//!
//! Subkeys are derived via [`blake3::derive_key`], which implements BLAKE3's
//! key-derivation function (KDF) mode. Unlike `new_keyed` (which is a PRF/MAC),
//! `derive_key` accepts an arbitrary-length context string and is purpose-built
//! for deriving independent subkeys from a single root key. Each subkey's
//! context string (e.g. [`KEY_DERIVE_CONTEXT_IDENTITY_V1`]) acts as a
//! domain separator, ensuring that subkeys are cryptographically independent
//! even though they share the same root material.
//!
//! # Ephemeral Fallback
//!
//! When the environment variable is missing or invalid, the module generates a
//! one-time random root key (preferring `/dev/urandom`, with a deterministic
//! entropy-mixing fallback). The resulting [`RunModeMetadata`] advertises
//! [`CorrelationMode::Ephemeral`] so that callers know the derived IDs are
//! only meaningful within the current process and cannot be correlated across
//! runs.

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

/// Identity hashing mode controlling keyed vs unkeyed derivation.
///
/// - `Keyed`: All identity hashes (root_id, path_id, occurrence_id, secret_hash)
///   are keyed with operator-specific material. Cross-operator hashes never collide,
///   preventing hash-based correlation attacks between operators.
/// - `Unkeyed`: Identity hashes use a fixed zero key. Useful for debugging and
///   reproducibility when operator isolation is not required.
///
/// Note: `rule_fingerprint` is **always unkeyed** regardless of this mode (rules
/// are stable policy definitions, not operator-specific). `secret_hash` is
/// **always keyed** regardless of this mode (to prevent rainbow-table attacks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdHashMode {
    /// Keyed identity derivation using operator secret material.
    Keyed = 1,
    /// Unkeyed identity derivation using a fixed zero key.
    Unkeyed = 2,
}

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
    id_hash_mode: IdHashMode,
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
    /// `SCANNER_SECRET_KEY` must be standard base64 (RFC 4648 §4) that decodes to
    /// exactly 32 bytes. Any missing, non-UTF-8, incorrectly-sized, or
    /// non-base64 value produces an ephemeral per-process key; check
    /// [`RunModeMetadata::key_source`] to distinguish these cases.
    ///
    /// # Thread Safety
    ///
    /// This reads `std::env::var_os` which is not synchronized against
    /// concurrent `set_var` calls. In production this is fine (env is set once
    /// before threads spawn); tests that mutate the env must serialize access.
    #[must_use]
    pub fn bootstrap_from_env() -> Self {
        Self::bootstrap_from_os_value(std::env::var_os(SCANNER_SECRET_KEY_ENV).as_deref())
    }

    fn bootstrap_from_os_value(value: Option<&OsStr>) -> Self {
        if let Some(raw) = value {
            match parse_root_key(raw) {
                Ok(root_key) => {
                    return Self::from_root_key(root_key, RunModeMetadata::persistent());
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: {} is set but invalid ({}). \
                         Falling back to ephemeral key \u{2014} cross-run correlation is disabled.",
                        SCANNER_SECRET_KEY_ENV, e
                    );
                    let root_key = generate_ephemeral_root_key();
                    return Self::from_root_key(
                        root_key,
                        RunModeMetadata::ephemeral(KeySource::InvalidEnvVar),
                    );
                }
            }
        }

        let root_key = generate_ephemeral_root_key();
        Self::from_root_key(
            root_key,
            RunModeMetadata::ephemeral(KeySource::MissingEnvVar),
        )
    }

    /// Derive all three subkeys from `root_key` using BLAKE3 KDF mode.
    ///
    /// Each subkey uses a distinct context string, so the three keys are
    /// cryptographically independent even though they share the same root.
    fn from_root_key(root_key: [u8; 32], run_mode: RunModeMetadata) -> Self {
        let identity_key = blake3::derive_key(KEY_DERIVE_CONTEXT_IDENTITY_V1, &root_key);
        let secret_key = blake3::derive_key(KEY_DERIVE_CONTEXT_SECRET_V1, &root_key);
        let metadata_key = blake3::derive_key(KEY_DERIVE_CONTEXT_METADATA_V1, &root_key);

        // Default to Keyed mode when persistent key material is available,
        // Unkeyed when ephemeral (since there is no stable operator secret).
        let id_hash_mode = if run_mode.is_persistent() {
            IdHashMode::Keyed
        } else {
            IdHashMode::Unkeyed
        };

        Self {
            identity_key,
            secret_key,
            metadata_key,
            run_mode,
            id_hash_mode,
        }
    }

    /// Run metadata indicating persistent vs ephemeral correlation mode.
    #[must_use]
    pub const fn run_mode(&self) -> RunModeMetadata {
        self.run_mode
    }

    /// Key for rule fingerprint and occurrence-id derivation.
    #[cfg(test)]
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

    /// Identity hashing mode (keyed vs unkeyed).
    #[must_use]
    pub const fn id_hash_mode(&self) -> IdHashMode {
        self.id_hash_mode
    }

    /// Returns the effective identity key based on [`IdHashMode`].
    ///
    /// - `Keyed`: returns the operator-derived identity key.
    /// - `Unkeyed`: returns a fixed all-zero key (deterministic, operator-independent).
    #[must_use]
    pub const fn effective_identity_key(&self) -> &[u8; 32] {
        match self.id_hash_mode {
            IdHashMode::Keyed => &self.identity_key,
            IdHashMode::Unkeyed => &ZERO_KEY,
        }
    }

    /// Override the identity hashing mode for this key set.
    pub fn with_id_hash_mode(mut self, mode: IdHashMode) -> Self {
        self.id_hash_mode = mode;
        self
    }

    #[cfg(test)]
    pub(crate) fn from_test_root_key(root_key: [u8; 32], run_mode: RunModeMetadata) -> Self {
        Self::from_root_key(root_key, run_mode)
    }
}

/// Fixed all-zero key used in [`IdHashMode::Unkeyed`] mode.
const ZERO_KEY: [u8; 32] = [0u8; 32];

/// Specific failure modes for `parse_root_key`.
///
/// Structured errors enable callers to emit targeted diagnostics rather than a
/// generic "invalid key" message.
#[derive(Debug)]
enum ParseKeyError {
    /// The env var value is not valid UTF-8.
    NonUtf8,
    /// The UTF-8 string is not valid standard base64.
    InvalidBase64(base64::DecodeError),
    /// The base64 decoded to a valid byte string, but not 32 bytes.
    WrongLength { got: usize },
}

impl fmt::Display for ParseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8 => write!(f, "value is not valid UTF-8"),
            Self::InvalidBase64(e) => write!(f, "not valid base64: {e}"),
            Self::WrongLength { got } => write!(f, "decoded to {got} bytes, expected 32"),
        }
    }
}

fn parse_root_key(raw: &OsStr) -> Result<[u8; 32], ParseKeyError> {
    let encoded = raw.to_str().ok_or(ParseKeyError::NonUtf8)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(ParseKeyError::InvalidBase64)?;
    if bytes.len() != 32 {
        return Err(ParseKeyError::WrongLength { got: bytes.len() });
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Generate a one-time ephemeral root key.
///
/// Prefers `/dev/urandom` (cryptographically strong on all supported platforms).
/// If that fails (e.g. sandboxed environment without filesystem access), falls
/// back to BLAKE3-mixing several low-quality entropy sources:
///
/// - **Domain tag** — prevents collisions with other BLAKE3 uses.
/// - **PID** — unique within a boot epoch.
/// - **Wall-clock nanos** — high-resolution monotonic-ish timestamp.
/// - **Stack pointer** — ASLR-randomized virtual address.
/// - **Thread ID** — distinguishes concurrent bootstrap calls.
///
/// This fallback is *not* cryptographically strong (an attacker who knows the
/// process state can predict the key), but it is sufficient for the ephemeral
/// use case: the IDs are only valid within the current process and are never
/// persisted or shared.
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

/// Read 32 bytes from `/dev/urandom`.
///
/// Uses the filesystem path rather than the `getrandom` crate to avoid an
/// extra dependency for a single call site. `/dev/urandom` is non-blocking
/// and available on all Linux/macOS targets this scanner supports.
#[cfg(unix)]
fn fill_from_urandom(out: &mut [u8; 32]) -> std::io::Result<()> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(out)?;
    Ok(())
}

#[cfg(not(unix))]
fn fill_from_urandom(_out: &mut [u8; 32]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "urandom not available on this platform",
    ))
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

    // ================================================================
    // Subkey independence & env edge cases
    // ================================================================

    #[test]
    fn subkeys_are_mutually_distinct() {
        let keys = StoreKeys::from_test_root_key(
            [0x5A; 32],
            RunModeMetadata {
                version: STORE_KEYS_VERSION,
                correlation_mode: CorrelationMode::Persistent,
                key_source: KeySource::EnvVar,
            },
        );
        assert_ne!(keys.identity_key(), keys.secret_key());
        assert_ne!(keys.identity_key(), keys.metadata_key());
        assert_ne!(keys.secret_key(), keys.metadata_key());
    }

    #[test]
    fn different_root_keys_produce_different_subkeys() {
        let meta = RunModeMetadata {
            version: STORE_KEYS_VERSION,
            correlation_mode: CorrelationMode::Persistent,
            key_source: KeySource::EnvVar,
        };
        let a = StoreKeys::from_test_root_key([0x11; 32], meta);
        let b = StoreKeys::from_test_root_key([0x22; 32], meta);
        // All 6 pairwise comparisons across the two key sets differ
        assert_ne!(a.identity_key(), b.identity_key());
        assert_ne!(a.secret_key(), b.secret_key());
        assert_ne!(a.metadata_key(), b.metadata_key());
        assert_ne!(a.identity_key(), b.secret_key());
        assert_ne!(a.identity_key(), b.metadata_key());
        assert_ne!(a.secret_key(), b.metadata_key());
    }

    #[test]
    fn ephemeral_keys_are_unique_per_call() {
        let a = StoreKeys::bootstrap_from_os_value(None);
        let b = StoreKeys::bootstrap_from_os_value(None);
        // Ephemeral keys should differ between calls (different random root)
        assert_ne!(a.identity_key(), b.identity_key());
    }

    #[test]
    fn empty_env_var_falls_back_to_ephemeral() {
        // SCANNER_SECRET_KEY="" → empty string, base64 decodes to 0 bytes != 32
        with_secret_key_env(Some(""), || {
            let keys = StoreKeys::bootstrap_from_env();
            assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
            assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);
        });
    }

    #[test]
    fn over_length_key_33_bytes_falls_back() {
        // 33 bytes base64-encoded → decoded length is 33 != 32
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x33; 33]);
        with_secret_key_env(Some(&encoded), || {
            let keys = StoreKeys::bootstrap_from_env();
            assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
            assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);
        });
    }

    #[test]
    fn url_safe_base64_falls_back() {
        // URL-safe base64 uses '-' and '_' instead of '+' and '/'.
        // The STANDARD decoder should reject this.
        let encoded = base64::engine::general_purpose::URL_SAFE.encode([0x44; 32]);
        // Only test if URL-safe encoding actually differs from standard for this input
        let standard = base64::engine::general_purpose::STANDARD.encode([0x44; 32]);
        if encoded != standard {
            with_secret_key_env(Some(&encoded), || {
                let keys = StoreKeys::bootstrap_from_env();
                assert_eq!(keys.run_mode().correlation_mode, CorrelationMode::Ephemeral);
                assert_eq!(keys.run_mode().key_source, KeySource::InvalidEnvVar);
            });
        }
    }

    // ================================================================
    // Structured ParseKeyError tests
    // ================================================================

    #[test]
    fn parse_key_invalid_base64_returns_specific_error() {
        let raw = OsString::from("not-valid-base64!!!");
        let err = parse_root_key(&raw).expect_err("should fail");
        assert!(
            matches!(err, ParseKeyError::InvalidBase64(_)),
            "expected InvalidBase64, got: {err:?}"
        );
    }

    #[test]
    fn parse_key_wrong_length_returns_specific_error() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x22; 31]);
        let raw = OsString::from(encoded);
        let err = parse_root_key(&raw).expect_err("should fail");
        assert!(
            matches!(err, ParseKeyError::WrongLength { got: 31 }),
            "expected WrongLength {{ got: 31 }}, got: {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn parse_key_non_utf8_returns_specific_error() {
        let raw = OsString::from_vec(vec![0xFF, 0xFE]);
        let err = parse_root_key(&raw).expect_err("should fail");
        assert!(
            matches!(err, ParseKeyError::NonUtf8),
            "expected NonUtf8, got: {err:?}"
        );
    }

    #[test]
    fn parse_key_error_display_messages() {
        let non_utf8 = ParseKeyError::NonUtf8;
        assert_eq!(non_utf8.to_string(), "value is not valid UTF-8");

        let wrong_len = ParseKeyError::WrongLength { got: 16 };
        assert_eq!(wrong_len.to_string(), "decoded to 16 bytes, expected 32");

        // InvalidBase64 display includes the inner error
        let raw = OsString::from("not-valid-base64!!!");
        if let Err(ParseKeyError::InvalidBase64(inner)) = parse_root_key(&raw) {
            let msg = format!("not valid base64: {inner}");
            assert_eq!(ParseKeyError::InvalidBase64(inner).to_string(), msg);
        }
    }

    #[test]
    fn parse_key_valid_input_returns_ok() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x42; 32]);
        let raw = OsString::from(encoded);
        let result = parse_root_key(&raw).expect("should succeed");
        assert_eq!(result, [0x42; 32]);
    }
}
