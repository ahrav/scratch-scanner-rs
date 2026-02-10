//! Persistence store contracts, cryptographic identity, and SQLite backend.
//!
//! This module is the public surface for finding persistence. It re-exports
//! the most-used types from its submodules so callers can write
//! `use crate::store::{StoreProducer, StoreKeys, ...}` without reaching
//! into internal module paths.
//!
//! # Submodules
//!
//! **Shared contracts and cryptographic identity:**
//! - [`keys`] — key bootstrap from `SCANNER_SECRET_KEY` (or ephemeral fallback)
//!   and [`RunModeMetadata`] describing the correlation semantics of this run.
//! - [`identity`] — versioned, deterministic derivation of [`RuleFingerprint`],
//!   [`SecretHash`], and [`OccurrenceId`] from engine findings and store keys.
//! - [`fs`] — write-side API ([`StoreProducer`]) used by the scheduler FS scan
//!   paths to hand off post-dedupe findings to a persistence backend.
//!
//! **SQLite persistence:**
//! - [`db`] — SQLite-backed findings database: schema, write path
//!   ([`SqliteStoreProducer`]), and read-path queries for CLI commands.
//!   Key query functions (`list_runs`, `diff_runs`, etc.) are re-exported
//!   here for ergonomic access from the orchestrator.
//! - [`root_id`] — root identity derivation (Git, FS, archive, stdin, S3).
//! - [`path_id`] — path identity derivation and canonicalization.
//!
//! **Triage:**
//! - [`triage`] — secret triage status tracking ([`TriageStore`]).

pub mod db;
pub mod fs;
pub mod identity;
pub mod keys;
pub mod path_id;
pub mod root_id;
pub mod triage;

pub use db::{
    configure_connection, configure_readonly_connection, diff_runs, ensure_schema, list_findings,
    list_runs, list_secrets, resolve_run_pk, DiffResult, FindingRow, RunCounters, RunStatus,
    RunSummary, SecretSummary, SqliteStoreConfig, SqliteStoreProducer, SCHEMA_VERSION,
};
#[cfg(test)]
pub(crate) use fs::{EmitOnlyStoreProducer, FailingStoreProducer};
pub use fs::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, InMemoryStoreProducer,
    NullStoreProducer, OwnedFsFindingBatch, StoreProducer,
};
pub use identity::{
    occurrence_id, rule_fingerprint, secret_hash, secret_hash_with_truncation, IdentityError,
    IdentityFlags, OccurrenceId, OccurrenceInput, RuleFingerprint, SecretHash, SecretLenBucket,
    VariantDiscriminant, IDENTITY_CONTRACT_VERSION, MAX_SECRET_HASH_BYTES,
};
pub use keys::{
    CorrelationMode, IdHashMode, KeySource, RunModeMetadata, StoreKeys, SCANNER_SECRET_KEY_ENV,
    STORE_KEYS_VERSION,
};
pub use path_id::{canonicalize_path, path_id, PathId, PATH_SCHEME_FS_V1};
pub use root_id::{root_id, RootId, RootIdInput, RootKind};
pub use triage::{TriageClock, TriageStatus, TriageStore};
