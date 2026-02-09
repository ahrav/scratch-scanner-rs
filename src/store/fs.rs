//! Filesystem persistence producer contracts.
//!
//! This module defines the write-side API used by scheduler FS scan paths
//! to hand off post-dedupe findings to a persistence backend.
//!
//! # Data flow
//!
//! ```text
//! Engine findings ──► build_persistence_batch() ──► FsFindingRecord[]
//!                                                       │
//!                                               FsFindingBatch { path, findings }
//!                                                       │
//!                                               StoreProducer::emit_fs_batch()
//!                                                       │
//!                               ┌───────────────────────┼───────────────────────┐
//!                               ▼                       ▼                       ▼
//!                       NullStoreProducer      InMemoryStoreProducer     (custom backend)
//!                          (no-op)               (test / diag)
//! ```
//!
//! At run end, [`StoreProducer::record_fs_run_loss`] captures drop/failure
//! accounting so the backend can mark the run as incomplete when warranted.
//!
//! # Implementations
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`NullStoreProducer`] | Default no-op for CLI / feature-off paths |
//! | [`InMemoryStoreProducer`] | Collects batches in memory for tests and diagnostics |

use crate::engine::NormHash;
use std::fmt;
use std::sync::Mutex;

/// Persistence-ready representation of one FS finding.
///
/// This is the post-dedupe, backend-agnostic record emitted by the scheduler.
/// All offsets are absolute byte positions within the scanned object (file or
/// archive entry). The `norm_hash` is the BLAKE3 digest of the normalized
/// secret value, used for cross-run deduplication by the persistence backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsFindingRecord {
    /// Engine rule identifier that matched.
    pub rule_id: u32,
    /// Start of the root-buffer region that contains the match (inclusive).
    pub root_hint_start: u64,
    /// End of the root-buffer region that contains the match (exclusive).
    pub root_hint_end: u64,
    /// Start of the matched span within the (possibly decoded) buffer.
    pub span_start: u64,
    /// End of the matched span within the (possibly decoded) buffer.
    pub span_end: u64,
    /// BLAKE3 digest of the normalized secret value (32 bytes).
    pub norm_hash: NormHash,
}

/// Borrowed finding batch produced by one scan loop iteration.
///
/// Each batch groups all post-dedupe findings for a single scanned object
/// (plain file or archive entry). The `object_path` is the filesystem path
/// (or virtual archive path) as raw bytes, and `findings` contains the
/// deduplicated records for that object.
#[derive(Clone, Copy, Debug)]
pub struct FsFindingBatch<'a> {
    /// Filesystem or virtual path of the scanned object (UTF-8, not
    /// null-terminated). For archive entries this is the composite
    /// `parent::entry` virtual path.
    pub object_path: &'a [u8],
    /// Post-dedupe findings for this object, in scan-order.
    pub findings: &'a [FsFindingRecord],
}

/// Run-level loss accounting for FS persistence.
///
/// Emitted once per run via [`StoreProducer::record_fs_run_loss`] so the
/// backend can decide whether to mark the run as complete or flag data loss.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsRunLoss {
    /// Findings dropped by engine max-findings caps.
    pub dropped_findings: u64,
    /// Number of persistence batch emissions that failed.
    pub persistence_emit_failures: u64,
    /// Whether the run should be treated as incomplete.
    pub incomplete: bool,
}

/// Persistence producer error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsStoreError {
    detail: String,
}

impl FsStoreError {
    #[inline]
    pub fn backend(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    #[inline]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for FsStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fs persistence error: {}", self.detail)
    }
}

impl std::error::Error for FsStoreError {}

/// Producer interface for FS finding persistence.
///
/// Implementations must be `Send + Sync` because the scheduler calls
/// `emit_fs_batch` from worker threads. The trait is object-safe so it
/// can be stored as `Arc<dyn StoreProducer>` in scheduler configs.
///
/// # Contract
///
/// - `emit_fs_batch` is called zero or more times during a scan, once per
///   scanned object that produced findings. Batches may arrive out of file
///   order when workers run in parallel.
/// - `record_fs_run_loss` is called exactly once at the end of a scan run.
///   Implementations should persist or log the loss data before returning.
/// - Errors from either method are counted in [`FsRunLoss::persistence_emit_failures`]
///   but do **not** abort the scan; the scheduler continues scanning.
pub trait StoreProducer: Send + Sync + 'static {
    /// Emit one post-dedupe finding batch for a single scanned object.
    ///
    /// Called from a worker thread. The batch borrows data from scratch
    /// buffers, so implementations must copy or serialize before returning.
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError>;

    /// Record run-level loss accounting once per run.
    ///
    /// Called after all files have been scanned and all workers have joined.
    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError>;
}

/// No-op producer that discards all batches and loss records.
///
/// Used as the default when no persistence backend is configured
/// (CLI default, feature-off builds, and benchmarks).
#[derive(Clone, Copy, Debug, Default)]
pub struct NullStoreProducer;

impl StoreProducer for NullStoreProducer {
    #[inline]
    fn emit_fs_batch(&self, _batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        Ok(())
    }

    #[inline]
    fn record_fs_run_loss(&self, _loss: FsRunLoss) -> Result<(), FsStoreError> {
        Ok(())
    }
}

/// In-memory producer that collects all batches for later inspection.
///
/// Useful in integration tests to assert that the scheduler emits the
/// expected findings and loss records without needing a real backend.
/// Access collected data via [`batches()`](Self::batches) and
/// [`losses()`](Self::losses).
#[derive(Debug, Default)]
pub struct InMemoryStoreProducer {
    batches: Mutex<Vec<OwnedFsFindingBatch>>,
    losses: Mutex<Vec<FsRunLoss>>,
}

/// Owned copy of a finding batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedFsFindingBatch {
    pub object_path: Vec<u8>,
    pub findings: Vec<FsFindingRecord>,
}

impl InMemoryStoreProducer {
    /// Returns a clone of all collected finding batches.
    #[inline]
    pub fn batches(&self) -> Vec<OwnedFsFindingBatch> {
        self.batches
            .lock()
            .expect("in-memory fs store producer mutex poisoned")
            .clone()
    }

    /// Returns a clone of all recorded run-loss entries.
    #[inline]
    pub fn losses(&self) -> Vec<FsRunLoss> {
        self.losses
            .lock()
            .expect("in-memory fs store producer mutex poisoned")
            .clone()
    }
}

impl StoreProducer for InMemoryStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        let mut guard = self
            .batches
            .lock()
            .expect("in-memory fs store producer mutex poisoned");
        guard.push(OwnedFsFindingBatch {
            object_path: batch.object_path.to_vec(),
            findings: batch.findings.to_vec(),
        });
        Ok(())
    }

    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        self.losses
            .lock()
            .expect("in-memory fs store producer mutex poisoned")
            .push(loss);
        Ok(())
    }
}
