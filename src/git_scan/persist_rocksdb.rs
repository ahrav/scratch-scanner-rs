//! RocksDB-backed persistence adapters.
//!
//! This module is feature-gated. Enable with `--features rocksdb`.
//! The adapter uses a single RocksDB instance with plain key/value pairs
//! and relies on sorted keys for efficient `multi_get` access.
//! When the feature is disabled, all public constructors and methods return
//! explicit backend errors.

use std::io;
use std::path::Path;

use super::errors::{PersistError, RepoOpenError, SpillError};
use super::finalize::WriteOp;
#[cfg(feature = "rocksdb")]
use super::finalize::{build_ref_wm_key, build_seen_blob_key};
use super::object_id::OidBytes;
use super::persist::PersistenceStore;
use super::repo_open::RefWatermarkStore;
use super::seen_store::SeenBlobStore;
use super::start_set::StartSetId;
#[cfg(feature = "rocksdb")]
use super::watermark_keys::decode_ref_watermark_value;

#[cfg(feature = "rocksdb")]
use rocksdb::{Options, WriteBatch, DB};

/// RocksDB-backed store for Git scan persistence.
///
/// The store retains the `repo_id` and `policy_hash` used to build
/// `seen_blob` keys for the spill/dedupe stage.
/// Watermark loading uses the caller-supplied `(repo_id, policy_hash)` so the
/// same RocksDB instance can serve multiple namespaces if needed.
#[derive(Debug)]
pub struct RocksDbStore {
    #[cfg(feature = "rocksdb")]
    db: DB,
    #[cfg(feature = "rocksdb")]
    repo_id: u64,
    #[cfg(feature = "rocksdb")]
    policy_hash: [u8; 32],
}

impl RocksDbStore {
    /// Opens or creates a RocksDB database at the given path.
    ///
    /// When `rocksdb` feature is disabled, this returns an explicit error.
    pub fn open(
        path: impl AsRef<Path>,
        repo_id: u64,
        policy_hash: [u8; 32],
    ) -> Result<Self, PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, path).map_err(|err| PersistError::backend(err.to_string()))?;
            Ok(Self {
                db,
                repo_id,
                policy_hash,
            })
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (path, repo_id, policy_hash);
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }
}

impl PersistenceStore for RocksDbStore {
    fn write_data_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            debug_assert!(
                ops.windows(2).all(|w| w[0].key <= w[1].key),
                "data ops must be sorted by key"
            );
            let mut batch = WriteBatch::default();
            for op in ops {
                batch.put(&op.key, &op.value);
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = ops;
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }

    fn write_watermark_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            debug_assert!(
                ops.windows(2).all(|w| w[0].key <= w[1].key),
                "watermark ops must be sorted by key"
            );
            let mut batch = WriteBatch::default();
            for op in ops {
                batch.put(&op.key, &op.value);
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = ops;
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }
}

impl SeenBlobStore for RocksDbStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            // `oids` are expected to be sorted to preserve key ordering.
            let mut keys = Vec::with_capacity(oids.len());
            for oid in oids {
                keys.push(build_seen_blob_key(self.repo_id, &self.policy_hash, oid));
            }
            debug_assert!(
                keys.windows(2).all(|w| w[0] <= w[1]),
                "seen keys must be sorted"
            );

            let results = self.db.multi_get(keys.iter());
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                match res {
                    Ok(Some(_)) => out.push(true),
                    Ok(None) => out.push(false),
                    Err(err) => return Err(SpillError::Io(io::Error::other(err.to_string()))),
                }
            }
            Ok(out)
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = oids;
            Err(SpillError::Io(io::Error::other(
                "rocksdb support not enabled",
            )))
        }
    }
}

impl RefWatermarkStore for RocksDbStore {
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        #[cfg(feature = "rocksdb")]
        {
            // `ref_names` are expected to be sorted to preserve key ordering.
            let mut keys = Vec::with_capacity(ref_names.len());
            for name in ref_names {
                keys.push(build_ref_wm_key(repo_id, &policy_hash, &start_set_id, name));
            }
            debug_assert!(
                keys.windows(2).all(|w| w[0] <= w[1]),
                "watermark keys must be sorted"
            );

            let results = self.db.multi_get(keys.iter());
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                match res {
                    Ok(Some(val)) => {
                        let decoded =
                            decode_ref_watermark_value(val.as_ref()).ok_or_else(|| {
                                RepoOpenError::io(io::Error::other(
                                    "invalid watermark value encoding",
                                ))
                            })?;
                        out.push(Some(decoded));
                    }
                    Ok(None) => out.push(None),
                    Err(err) => return Err(RepoOpenError::io(io::Error::other(err.to_string()))),
                }
            }
            Ok(out)
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (repo_id, policy_hash, start_set_id, ref_names);
            Err(RepoOpenError::io(io::Error::other(
                "rocksdb support not enabled",
            )))
        }
    }
}
