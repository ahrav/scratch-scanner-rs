//! Persistence store contract and helpers.
//!
//! This module defines the write-only persistence API used after finalize.
//! Callers must write data ops before watermark ops to prevent advancing
//! watermarks past unscanned blobs.
//!
//! # Two-phase contract
//! - `data_ops` are always safe to write.
//! - `watermark_ops` must only be written for `FinalizeOutcome::Complete`.
//! - Each write call should be atomic within the store implementation.

use super::errors::PersistError;
use super::finalize::{FinalizeOutcome, FinalizeOutput, WriteOp};

/// Persistence store interface for finalize output.
///
/// Implementations should write the provided ops atomically within each call.
/// Callers may rely on `data_ops` being durable before attempting watermark
/// writes.
pub trait PersistenceStore {
    /// Writes data ops (blob_ctx + finding + seen_blob).
    ///
    /// Implementations may assume ops are pre-sorted by key, but must not
    /// require it for correctness.
    fn write_data_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError>;
    /// Writes watermark ops (ref_watermark).
    ///
    /// These ops are only issued for `FinalizeOutcome::Complete`.
    fn write_watermark_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError>;
}

/// Persist finalize output with two-phase semantics.
///
/// # Ordering contract
/// 1. Write `data_ops` first.
/// 2. If and only if the run is complete, write `watermark_ops`.
///
/// Errors during the data phase prevent any watermark writes. If the
/// watermark phase fails, callers may retry watermark writes without
/// re-scanning, since data ops are already durable.
pub fn persist_finalize_output(
    store: &dyn PersistenceStore,
    output: &FinalizeOutput,
) -> Result<FinalizeOutcome, PersistError> {
    if !output.data_ops.is_empty() {
        store.write_data_ops(&output.data_ops)?;
    }

    if matches!(output.outcome, FinalizeOutcome::Complete) && !output.watermark_ops.is_empty() {
        store.write_watermark_ops(&output.watermark_ops)?;
    }

    Ok(output.outcome)
}

/// In-memory persistence store for tests and diagnostics.
///
/// This store is not thread-safe; it uses `RefCell` for interior mutability.
#[derive(Debug, Default)]
pub struct InMemoryPersistenceStore {
    pub data_ops: std::cell::RefCell<Vec<WriteOp>>,
    pub watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
}

impl PersistenceStore for InMemoryPersistenceStore {
    fn write_data_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError> {
        self.data_ops.borrow_mut().extend_from_slice(ops);
        Ok(())
    }

    fn write_watermark_ops(&self, ops: &[WriteOp]) -> Result<(), PersistError> {
        self.watermark_ops.borrow_mut().extend_from_slice(ops);
        Ok(())
    }
}
