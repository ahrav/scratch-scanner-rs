//! On-disk cache for serialized Vectorscan databases.
//!
//! Reduces repeated startup compilation by caching serialized `hs_database_t`
//! to disk, keyed by a deterministic BLAKE3 hash of compile inputs.
//!
//! # File format
//!
//! ```text
//! | MAGIC (8B): b"VSDBCACH"              |
//! | PAYLOAD_LEN (8B, LE u64)             |
//! | KEY_HASH (32B): blake3 of cache key  |
//! | PAYLOAD (PAYLOAD_LEN bytes)          |  -- hs_serialize_database output
//! | MAC_TAG (16B): AEGIS-128L MAC        |  -- over header || payload
//! ```
//!
//! # Integrity
//!
//! A 16-byte AEGIS-128L MAC covers the header and payload. The MAC key is
//! derived from the cache key hash: `blake3(b"vsdb-mac-key" || key_hash)[..16]`.
//! On load, any mismatch (magic, payload length, key hash, or MAC) causes the
//! corrupt file to be deleted and a cache miss returned.
//!
//! # Cache key
//!
//! The key is a BLAKE3 hash over a domain separation tag plus all compile
//! inputs: kind, mode, platform, Vectorscan version, patterns, flags, and ids.
//! A domain tag (`DOMAIN_TAG`) encodes structural assumptions about the file
//! format and MAC scheme; changing it automatically invalidates all old caches.
//!
//! # Environment controls
//!
//! - `SCANNER_VS_DB_CACHE=0|false|off|no` disables caching.
//! - `SCANNER_VS_DB_CACHE_DIR=/path` overrides the cache directory.
//! - Default directory: `$HOME/.cache/scanner-rs/vsdb`, fallback `$TMPDIR/scanner-rs-vsdb`.

use libc::{c_char, c_int, c_uint};
use std::ffi::CString;
use std::path::PathBuf;
use std::ptr;

use vectorscan_rs_sys as vs;

/// Magic bytes at the start of every cache file.
const MAGIC: &[u8; 8] = b"VSDBCACH";

/// Header size: 8 (magic) + 8 (payload_len) + 32 (key_hash).
const HEADER_LEN: usize = 8 + 8 + 32;

/// AEGIS-128L MAC tag size.
const MAC_LEN: usize = 16;

/// Domain separation tag embedded in the cache key hash. Changing this string
/// invalidates all previously cached files without requiring a manual version
/// bump.
const DOMAIN_TAG: &[u8] = b"scanner-rs-vsdb-v2:blake3+aegis128l-mac";

/// Inputs for computing a deterministic cache key.
pub(super) struct CacheKeyInput<'a> {
    /// DB kind tag, e.g. `b"prefilter"`, `b"stream"`.
    pub kind: &'a [u8],
    /// Vectorscan compile mode (`HS_MODE_BLOCK` or `HS_MODE_STREAM`).
    pub mode: c_uint,
    /// Target platform fingerprint.
    pub platform: &'a vs::hs_platform_info_t,
    /// Compiled pattern expressions.
    pub patterns: &'a [CString],
    /// Per-pattern compile flags. `None` when the flags pointer is null.
    pub flags: Option<&'a [c_uint]>,
    /// Per-pattern expression IDs.
    pub ids: &'a [c_uint],
}

/// On-disk cache for serialized Vectorscan databases.
///
/// A `None` `dir` means the cache is disabled (either explicitly via env var
/// or implicitly under `cfg!(test)`). All methods degrade to no-ops: `try_load`
/// returns `None`, `try_store` silently does nothing.
///
/// # Thread safety
///
/// Each `VsDbCache` is used within a single thread during engine construction.
/// Concurrent processes writing the same key are safe because `try_store` uses
/// tmp-file + rename, so readers never observe partial writes.
pub(super) struct VsDbCache {
    /// Cache directory, or `None` when caching is disabled.
    dir: Option<PathBuf>,
}

impl VsDbCache {
    /// Creates a new cache handle by reading environment variables once.
    ///
    /// Returns a disabled cache under `cfg!(test)` unless
    /// `SCANNER_VS_DB_CACHE_TEST=1` is set.
    pub fn new() -> Self {
        if !Self::enabled() {
            return Self { dir: None };
        }
        Self {
            dir: Self::resolve_dir(),
        }
    }

    /// Computes a deterministic BLAKE3 hex cache key from compile inputs.
    ///
    /// The key is a 64-char hex string. Identical inputs always produce the
    /// same key; any change in kind, mode, platform, patterns, flags, or ids
    /// yields a different key. Works even when the cache is disabled (the key
    /// is cheap to compute and callers may log it).
    pub fn cache_key(&self, input: &CacheKeyInput<'_>) -> String {
        let mut hasher = blake3::Hasher::new();
        hash_len_prefixed(&mut hasher, DOMAIN_TAG);
        hash_len_prefixed(&mut hasher, input.kind);
        hash_u32(&mut hasher, input.mode);
        hash_u32(&mut hasher, input.platform.tune);
        hash_u64(&mut hasher, input.platform.cpu_features);
        hash_u64(&mut hasher, input.platform.reserved1);
        hash_u64(&mut hasher, input.platform.reserved2);
        hash_len_prefixed(&mut hasher, vs::HS_VERSION_STRING);
        hash_u64(&mut hasher, input.patterns.len() as u64);
        for pat in input.patterns {
            hash_len_prefixed(&mut hasher, pat.as_bytes_with_nul());
        }
        match input.flags {
            Some(flags) => {
                hash_u64(&mut hasher, flags.len() as u64);
                for &f in flags {
                    hash_u32(&mut hasher, f);
                }
            }
            None => {
                // Distinguish "no flags" from "zero flags".
                hash_u64(&mut hasher, u64::MAX);
            }
        }
        hash_u64(&mut hasher, input.ids.len() as u64);
        for &id in input.ids {
            hash_u32(&mut hasher, id);
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Attempts to load a cached, integrity-verified database by key.
    ///
    /// Returns `None` on any failure (disabled, missing, corrupt, MAC mismatch).
    /// Corrupt files are deleted as a side effect.
    ///
    /// # Safety (caller obligation)
    ///
    /// The returned `*mut hs_database_t` is heap-allocated by Vectorscan and
    /// must be freed with `hs_free_database` when no longer needed. The caller
    /// owns the pointer.
    pub fn try_load(&self, key: &str) -> Option<*mut vs::hs_database_t> {
        let dir = self.dir.as_ref()?;
        let path = dir.join(format!("{key}.hsdb"));
        let bytes = std::fs::read(&path).ok()?;

        // Minimum size: header + mac (payload may be zero but hs_deserialize
        // rejects that, so we still check).
        if bytes.len() < HEADER_LEN + MAC_LEN {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify magic.
        if &bytes[..8] != MAGIC.as_slice() {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Read and validate payload length.
        let payload_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let expected_total = HEADER_LEN + payload_len + MAC_LEN;
        if bytes.len() != expected_total {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify key hash.
        let stored_key_hash: [u8; 32] = bytes[16..48].try_into().unwrap();
        let expected_key_hash = *blake3::hash(key.as_bytes()).as_bytes();
        if stored_key_hash != expected_key_hash {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify MAC over (header || payload).
        let data_end = HEADER_LEN + payload_len;
        let stored_mac: [u8; 16] = bytes[data_end..data_end + MAC_LEN].try_into().unwrap();
        let computed_mac = compute_mac(&stored_key_hash, &bytes[..data_end]);
        if computed_mac != stored_mac {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Deserialize the Vectorscan database.
        let payload = &bytes[HEADER_LEN..data_end];
        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let rc = unsafe {
            vs::hs_deserialize_database(
                payload.as_ptr().cast::<c_char>(),
                payload.len(),
                &mut db as *mut *mut vs::hs_database_t,
            )
        };
        if rc == vs::HS_SUCCESS as c_int && !db.is_null() {
            Some(db)
        } else {
            let _ = std::fs::remove_file(&path);
            None
        }
    }

    /// Serializes and stores a compiled database under `key` (best-effort).
    ///
    /// Uses write-to-tmp + rename for atomic file creation. Any failure is
    /// silently ignored — correctness never depends on cache persistence.
    pub fn try_store(&self, key: &str, db: *const vs::hs_database_t) {
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }

        let out_path = dir.join(format!("{key}.hsdb"));
        if out_path.exists() {
            return;
        }

        // Serialize the database.
        let mut bytes_ptr: *mut c_char = ptr::null_mut();
        let mut bytes_len: usize = 0;
        let rc = unsafe {
            vs::hs_serialize_database(
                db,
                &mut bytes_ptr as *mut *mut c_char,
                &mut bytes_len as *mut usize,
            )
        };
        if rc != vs::HS_SUCCESS as c_int || bytes_ptr.is_null() || bytes_len == 0 {
            if !bytes_ptr.is_null() {
                unsafe { libc::free(bytes_ptr.cast()) };
            }
            return;
        }

        let payload = unsafe { std::slice::from_raw_parts(bytes_ptr.cast::<u8>(), bytes_len) };

        // Build the file contents: header || payload || mac.
        let key_hash = *blake3::hash(key.as_bytes()).as_bytes();

        let total_len = HEADER_LEN + bytes_len + MAC_LEN;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&(bytes_len as u64).to_le_bytes());
        buf.extend_from_slice(&key_hash);
        buf.extend_from_slice(payload);

        unsafe { libc::free(bytes_ptr.cast()) };

        // Compute MAC over header + payload (everything before the MAC slot).
        let mac = compute_mac(&key_hash, &buf);
        buf.extend_from_slice(&mac);

        // Atomic write via tmp + rename.
        let tmp_path = dir.join(format!("{key}.{}.tmp", std::process::id()));
        if std::fs::write(&tmp_path, &buf).is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return;
        }
        let _ = std::fs::rename(&tmp_path, &out_path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Returns `true` if the cache is enabled.
    ///
    /// Disabled under `cfg!(test)` unless `SCANNER_VS_DB_CACHE_TEST=1` is set.
    /// Otherwise reads `SCANNER_VS_DB_CACHE`; any of `0|false|off|no` disables.
    fn enabled() -> bool {
        if cfg!(test) {
            return std::env::var("SCANNER_VS_DB_CACHE_TEST").is_ok_and(|v| v.trim() == "1");
        }
        match std::env::var("SCANNER_VS_DB_CACHE") {
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            }
            Err(_) => true,
        }
    }

    /// Resolves the cache directory with a 3-tier fallback:
    /// 1. `SCANNER_VS_DB_CACHE_DIR` env var (explicit override)
    /// 2. `$HOME/.cache/scanner-rs/vsdb` (XDG-style default)
    /// 3. `$TMPDIR/scanner-rs-vsdb` (last resort)
    fn resolve_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("SCANNER_VS_DB_CACHE_DIR") {
            return Some(PathBuf::from(dir));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".cache")
                    .join("scanner-rs")
                    .join("vsdb"),
            );
        }
        Some(std::env::temp_dir().join("scanner-rs-vsdb"))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Computes an AEGIS-128L MAC over `data` using a key derived from `key_hash`.
///
/// Key derivation: `blake3(b"vsdb-mac-key" || key_hash)[..16]`. The domain
/// prefix prevents the MAC key from colliding with the cache key itself.
fn compute_mac(key_hash: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use aegis::aegis128l::Aegis128LMac;

    // Derive a 16-byte MAC key: blake3(b"vsdb-mac-key" || key_hash)[..16].
    let mut kdf = blake3::Hasher::new();
    kdf.update(b"vsdb-mac-key");
    kdf.update(key_hash);
    let derived = kdf.finalize();
    let mac_key: [u8; 16] = derived.as_bytes()[..16].try_into().unwrap();

    let mut mac = Aegis128LMac::<16>::new(&mac_key);
    mac.update(data);
    mac.finalize()
}

/// Feeds `bytes` into `hasher` with a length prefix to prevent concatenation
/// ambiguity (e.g. `["ab", "c"]` vs `["a", "bc"]` hash differently).
#[inline]
fn hash_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Feeds a fixed-width `u32` into the hasher (no length prefix needed).
#[inline]
fn hash_u32(hasher: &mut blake3::Hasher, v: u32) {
    hasher.update(&v.to_le_bytes());
}

/// Feeds a fixed-width `u64` into the hasher (no length prefix needed).
#[inline]
fn hash_u64(hasher: &mut blake3::Hasher, v: u64) {
    hasher.update(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    fn test_platform() -> vs::hs_platform_info_t {
        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
            platform.assume_init()
        }
    }

    fn test_cache_input<'a>(
        kind: &'a [u8],
        patterns: &'a [CString],
        flags: &'a [c_uint],
        ids: &'a [c_uint],
        platform: &'a vs::hs_platform_info_t,
    ) -> CacheKeyInput<'a> {
        CacheKeyInput {
            kind,
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform,
            patterns,
            flags: Some(flags),
            ids,
        }
    }

    #[test]
    fn cache_key_is_deterministic() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let input = test_cache_input(b"test", &pats, &flags, &ids, &platform);
        let k1 = cache.cache_key(&input);
        let k2 = cache.cache_key(&input);
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_changes_on_kind() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"prefilter", &pats, &flags, &ids, &platform);
        let i2 = test_cache_input(b"stream", &pats, &flags, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_changes_on_pattern() {
        let platform = test_platform();
        let pats1 = [CString::new("abc").unwrap()];
        let pats2 = [CString::new("xyz").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats1, &flags, &ids, &platform);
        let i2 = test_cache_input(b"test", &pats2, &flags, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_changes_on_flags() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags1 = [vs::HS_FLAG_PREFILTER as c_uint];
        let flags2 = [vs::HS_FLAG_SINGLEMATCH as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats, &flags1, &ids, &platform);
        let i2 = test_cache_input(b"test", &pats, &flags2, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_none_flags_differs_from_empty() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: None,
            ids: &ids,
        };
        let i2 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: Some(&[]),
            ids: &ids,
        };
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    /// Helper: compile a trivial block-mode DB for round-trip tests.
    fn compile_trivial_db() -> *mut vs::hs_database_t {
        let pat = CString::new("test").unwrap();
        let expr_ptrs = [pat.as_ptr()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let platform = test_platform();
        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut err: *mut vs::hs_compile_error_t = ptr::null_mut();
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                1,
                vs::HS_MODE_BLOCK as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut err as *mut *mut vs::hs_compile_error_t,
            )
        };
        assert_eq!(rc, vs::HS_SUCCESS as c_int);
        assert!(!db.is_null());
        db
    }

    #[test]
    fn round_trip_store_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-round-trip-key";

        cache.try_store(key, db as *const vs::hs_database_t);
        let loaded = cache.try_load(key);
        assert!(loaded.is_some(), "expected cache hit after store");

        // Clean up both DBs.
        unsafe {
            vs::hs_free_database(db);
            if let Some(loaded_db) = loaded {
                vs::hs_free_database(loaded_db);
            }
        }
    }

    #[test]
    fn corrupted_mac_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-corrupt-mac";

        cache.try_store(key, db as *const vs::hs_database_t);
        unsafe { vs::hs_free_database(db) };

        // Corrupt the last byte (MAC tag).
        let path = dir.path().join(format!("{key}.hsdb"));
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        assert!(cache.try_load(key).is_none(), "corrupt MAC should miss");
        assert!(!path.exists(), "corrupt file should be deleted");
    }

    #[test]
    fn truncated_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-truncated";

        cache.try_store(key, db as *const vs::hs_database_t);
        unsafe { vs::hs_free_database(db) };

        // Truncate the file.
        let path = dir.path().join(format!("{key}.hsdb"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..HEADER_LEN]).unwrap();

        assert!(cache.try_load(key).is_none(), "truncated file should miss");
        assert!(!path.exists(), "truncated file should be deleted");
    }

    #[test]
    fn wrong_key_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-right-key";

        cache.try_store(key, db as *const vs::hs_database_t);
        unsafe { vs::hs_free_database(db) };

        // Rename the file to a different key name.
        let src = dir.path().join(format!("{key}.hsdb"));
        let dst = dir.path().join("wrong-key.hsdb");
        std::fs::rename(&src, &dst).unwrap();

        assert!(
            cache.try_load("wrong-key").is_none(),
            "wrong key should miss"
        );
    }

    #[test]
    fn disabled_cache_always_misses() {
        let cache = VsDbCache { dir: None };
        assert!(cache.try_load("anything").is_none());
    }
}
