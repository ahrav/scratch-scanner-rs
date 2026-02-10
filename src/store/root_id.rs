//! Root identity derivation.
//!
//! A **root** is the top-level scanned entity: a Git repository, a local
//! directory, an archive file, an S3 bucket, stdin, etc.
//!
//! `root_id` is a 32-byte BLAKE3 hash that uniquely identifies a root across
//! runs. The hash is derived from:
//! - A root kind discriminant (Git, FS, archive, stdin, S3, …)
//! - An identity scheme tag (e.g. `git_remote_url_v1`, `fs_device_inode_v1`)
//! - Scheme-specific canonical identity bytes
//!
//! Keyed or unkeyed derivation is controlled by [`IdHashMode`].

use super::keys::StoreKeys;

/// 32-byte root identity hash.
pub type RootId = [u8; 32];

const ROOT_ID_DOMAIN: &[u8] = b"scanner.store.identity.v1.root_id";

/// Root kind discriminant.
///
/// Each variant represents a distinct class of scan target. New kinds can be
/// added without breaking existing hashes (the discriminant byte is embedded
/// in the canonical payload).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RootKind {
    /// Git repository.
    Git = 1,
    /// Local filesystem directory or file.
    Fs = 2,
    /// Archive file (zip, tar, etc.).
    Archive = 3,
    /// Standard input stream.
    Stdin = 4,
    /// S3 bucket or object.
    S3 = 5,
}

impl RootKind {
    /// Convert from integer, returning `None` for unknown values.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Git),
            2 => Some(Self::Fs),
            3 => Some(Self::Archive),
            4 => Some(Self::Stdin),
            5 => Some(Self::S3),
            _ => None,
        }
    }
}

/// Input for root identity derivation.
pub struct RootIdInput<'a> {
    /// Kind of scan target.
    pub kind: RootKind,
    /// Identity scheme tag (e.g. `"git_remote_url_v1"`).
    pub identity_scheme: &'a str,
    /// Scheme-specific canonical identity bytes.
    pub canonical_identity: &'a [u8],
}

/// Compute a canonical root identity hash.
///
/// The canonical encoding:
/// ```text
/// root_id_domain ‖ 0x00 ‖ kind(u8) ‖ scheme_len(u32le) ‖ scheme ‖ identity_bytes
/// ```
///
/// The domain prefix prevents cross-context collisions (e.g. a path-id
/// hash can never collide with a root-id hash). The null byte separates
/// the fixed-length domain from variable-length fields. The explicit
/// `scheme_len` prevents ambiguity between `(scheme="ab", id="cd")` and
/// `(scheme="abc", id="d")`.
///
/// The hash is keyed or unkeyed based on `keys.id_hash_mode()`.
#[must_use]
pub fn root_id(input: &RootIdInput<'_>, keys: &StoreKeys) -> RootId {
    let key = keys.effective_identity_key();
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(ROOT_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&[input.kind as u8]);
    hasher.update(&(input.identity_scheme.len() as u32).to_le_bytes());
    hasher.update(input.identity_scheme.as_bytes());
    hasher.update(input.canonical_identity);
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

    #[test]
    fn root_id_is_deterministic() {
        let keys = test_keys();
        let input = RootIdInput {
            kind: RootKind::Git,
            identity_scheme: "git_remote_url_v1",
            canonical_identity: b"https://github.com/org/repo.git",
        };
        let a = root_id(&input, &keys);
        let b = root_id(&input, &keys);
        assert_eq!(a, b);
    }

    #[test]
    fn different_kind_different_root_id() {
        let keys = test_keys();
        let git = root_id(
            &RootIdInput {
                kind: RootKind::Git,
                identity_scheme: "test_v1",
                canonical_identity: b"same",
            },
            &keys,
        );
        let fs = root_id(
            &RootIdInput {
                kind: RootKind::Fs,
                identity_scheme: "test_v1",
                canonical_identity: b"same",
            },
            &keys,
        );
        assert_ne!(git, fs);
    }

    #[test]
    fn different_scheme_different_root_id() {
        let keys = test_keys();
        let a = root_id(
            &RootIdInput {
                kind: RootKind::Git,
                identity_scheme: "git_remote_url_v1",
                canonical_identity: b"https://example.com/repo.git",
            },
            &keys,
        );
        let b = root_id(
            &RootIdInput {
                kind: RootKind::Git,
                identity_scheme: "git_root_commit_v1",
                canonical_identity: b"https://example.com/repo.git",
            },
            &keys,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn different_identity_bytes_different_root_id() {
        let keys = test_keys();
        let a = root_id(
            &RootIdInput {
                kind: RootKind::Git,
                identity_scheme: "git_remote_url_v1",
                canonical_identity: b"https://github.com/org/repo-a.git",
            },
            &keys,
        );
        let b = root_id(
            &RootIdInput {
                kind: RootKind::Git,
                identity_scheme: "git_remote_url_v1",
                canonical_identity: b"https://github.com/org/repo-b.git",
            },
            &keys,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn keyed_vs_unkeyed_differ() {
        let keyed = test_keys();
        let unkeyed = keyed.with_id_hash_mode(IdHashMode::Unkeyed);
        let input = RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_device_inode_v1",
            canonical_identity: b"/home/user/project",
        };
        let a = root_id(&input, &keyed);
        let b = root_id(&input, &unkeyed);
        assert_ne!(a, b);
    }

    #[test]
    fn root_kind_roundtrip() {
        for v in 1..=5 {
            let kind = RootKind::from_u8(v).expect("valid kind");
            assert_eq!(kind as u8, v);
        }
        assert!(RootKind::from_u8(0).is_none());
        assert!(RootKind::from_u8(6).is_none());
        assert!(RootKind::from_u8(255).is_none());
    }
}
