//! Persistence store contracts and backends for filesystem finding persistence.
//!
//! # Submodules by phase
//!
//! **Phase A** — shared contracts and cryptographic identity:
//! - [`keys`] — key bootstrap from `SCANNER_SECRET_KEY` (or ephemeral fallback)
//!   and [`RunModeMetadata`] describing the correlation semantics of this run.
//! - [`identity`] — versioned, deterministic derivation of [`RuleFingerprint`],
//!   [`SecretHash`], and [`OccurrenceId`] from engine findings and store keys.
//! - [`fs`] — write-side API ([`StoreProducer`]) used by the scheduler FS scan
//!   paths to hand off post-dedupe findings to a persistence backend.
//!
//! **Phase C** — append-only log persistence backend:
//! - [`log`] — framed binary codec ([`log::format`]) and bounded single-writer
//!   runtime ([`log::writer`]) that implements [`StoreProducer`] with segment
//!   rotation, CRC integrity, and backpressure.

pub mod fs;
pub mod identity;
pub mod keys;
pub mod log;

#[cfg(test)]
pub(crate) use fs::{EmitOnlyStoreProducer, FailingStoreProducer};
pub use fs::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, InMemoryStoreProducer,
    NullStoreProducer, OwnedFsFindingBatch, StoreProducer,
};
pub use identity::{
    occurrence_id, rule_fingerprint, secret_hash, IdentityError, IdentityFlags, OccurrenceId,
    OccurrenceInput, RuleFingerprint, SecretHash, VariantDiscriminant, IDENTITY_CONTRACT_VERSION,
};
pub use keys::{
    CorrelationMode, KeySource, RunModeMetadata, StoreKeys, SCANNER_SECRET_KEY_ENV,
    STORE_KEYS_VERSION,
};
#[cfg(feature = "bench")]
pub use log::SecretHashCache;
pub use log::{
    default_fs_log_root, list_finalized_segment_files, AppendLogStoreProducer, LogWriterConfig,
    SCANNER_FS_LOG_DIR_ENV,
};
