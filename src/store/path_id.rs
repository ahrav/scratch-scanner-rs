//! Path identity derivation and canonicalization.
//!
//! A **path** represents a scanned object within a root: a file, an archive
//! entry, or a virtual object from stdin. `path_id` is a 32-byte BLAKE3 hash
//! derived from the owning root_id plus a canonical path representation.
//!
//! # Path canonicalization
//!
//! Component-based normalization:
//! 1. Split on `/` and `\` separators.
//! 2. Remove `.` (current directory) components.
//! 3. Resolve `..` lexically (pop previous component, if any).
//! 4. Rejoin with `/` as the canonical separator.
//!
//! This produces a stable, platform-independent path suitable for hashing.

use super::keys::StoreKeys;
use super::root_id::RootId;

/// 32-byte path identity hash.
pub type PathId = [u8; 32];

const PATH_ID_DOMAIN: &[u8] = b"scanner.store.identity.v1.path_id";

/// Default path scheme for filesystem paths.
pub const PATH_SCHEME_FS_V1: &str = "fs_path_v1";

/// Canonicalize a path string using purely lexical component-based
/// normalization (no filesystem access).
///
/// - Splits on both `/` and `\`.
/// - Removes `.` components.
/// - Resolves `..` lexically (pops the previous non-`..` component).
/// - Rejoins with `/` as the canonical separator.
/// - Strips leading `/` for consistent relative representation.
///
/// The result is a stable, platform-independent representation suitable
/// for hashing. Because this is lexical-only, symlinks are **not**
/// resolved — two paths that resolve to the same inode through different
/// symlink chains will produce different path IDs.
#[must_use]
pub fn canonicalize_path(raw: &str) -> String {
    let mut components: Vec<&str> = Vec::new();
    for part in raw.split(&['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other),
        }
    }
    components.join("/")
}

/// Compute a canonical path identity hash.
///
/// ```text
/// path_id = H_key(domain ‖ 0x00 ‖ root_id ‖ scheme_len(u32le) ‖ scheme ‖ canonical_path)
/// ```
///
/// The domain prefix and null byte provide domain separation from
/// [`root_id`](super::root_id::root_id) and other identity hashes that
/// share the same key material, preventing cross-scope collisions.
///
/// The hash is keyed or unkeyed based on `keys.id_hash_mode()`. Keyed
/// mode prevents cross-operator hash correlation (see [`IdHashMode`]
/// for details).
#[must_use]
pub fn path_id(
    root_id: &RootId,
    path_scheme: &str,
    canonical_path: &str,
    keys: &StoreKeys,
) -> PathId {
    let key = keys.effective_identity_key();
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(PATH_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(root_id);
    hasher.update(&(path_scheme.len() as u32).to_le_bytes());
    hasher.update(path_scheme.as_bytes());
    hasher.update(canonical_path.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::keys::{
        CorrelationMode, IdHashMode, KeySource, RunModeMetadata, StoreKeys, STORE_KEYS_VERSION,
    };

    fn test_keys() -> StoreKeys {
        StoreKeys::from_test_root_key(
            [0x5A; 32],
            RunModeMetadata {
                version: STORE_KEYS_VERSION,
                correlation_mode: CorrelationMode::Persistent,
                key_source: KeySource::EnvVar,
            },
        )
    }

    // ── canonicalize_path ──────────────────────────────────────────

    #[test]
    fn canonicalize_removes_dot_components() {
        assert_eq!(canonicalize_path("a/./b/./c"), "a/b/c");
    }

    #[test]
    fn canonicalize_resolves_dotdot_lexically() {
        assert_eq!(canonicalize_path("a/b/../c"), "a/c");
    }

    #[test]
    fn canonicalize_normalizes_separators() {
        assert_eq!(canonicalize_path(r"a\b\c"), "a/b/c");
    }

    #[test]
    fn canonicalize_mixed_separators() {
        assert_eq!(canonicalize_path(r"a/b\c/./d\..\e"), "a/b/c/e");
    }

    #[test]
    fn canonicalize_strips_leading_slash() {
        assert_eq!(canonicalize_path("/a/b/c"), "a/b/c");
    }

    #[test]
    fn canonicalize_strips_trailing_slash() {
        assert_eq!(canonicalize_path("a/b/c/"), "a/b/c");
    }

    #[test]
    fn canonicalize_empty_input() {
        assert_eq!(canonicalize_path(""), "");
    }

    #[test]
    fn canonicalize_single_dot() {
        assert_eq!(canonicalize_path("."), "");
    }

    #[test]
    fn canonicalize_dotdot_at_root_is_dropped() {
        // ".." at root has nothing to pop — it's just dropped.
        assert_eq!(canonicalize_path("../a/b"), "a/b");
    }

    #[test]
    fn canonicalize_multiple_slashes() {
        assert_eq!(canonicalize_path("a///b//c"), "a/b/c");
    }

    // ── path_id ────────────────────────────────────────────────────

    #[test]
    fn path_id_is_deterministic() {
        let keys = test_keys();
        let root = [0xAA; 32];
        let a = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        let b = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        assert_eq!(a, b);
    }

    #[test]
    fn different_root_different_path_id() {
        let keys = test_keys();
        let a = path_id(&[0xAA; 32], PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        let b = path_id(&[0xBB; 32], PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        assert_ne!(a, b);
    }

    #[test]
    fn different_path_different_path_id() {
        let keys = test_keys();
        let root = [0xAA; 32];
        let a = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        let b = path_id(&root, PATH_SCHEME_FS_V1, "src/lib.rs", &keys);
        assert_ne!(a, b);
    }

    #[test]
    fn different_scheme_different_path_id() {
        let keys = test_keys();
        let root = [0xAA; 32];
        let a = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &keys);
        let b = path_id(&root, "archive_entry_v1", "src/main.rs", &keys);
        assert_ne!(a, b);
    }

    #[test]
    fn keyed_vs_unkeyed_differ() {
        let keyed = test_keys();
        let unkeyed = keyed.with_id_hash_mode(IdHashMode::Unkeyed);
        let root = [0xAA; 32];
        let a = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &keyed);
        let b = path_id(&root, PATH_SCHEME_FS_V1, "src/main.rs", &unkeyed);
        assert_ne!(a, b);
    }
}
