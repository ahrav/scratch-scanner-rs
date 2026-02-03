//! Integration tests for persistence ordering.

use std::cell::Cell;

use scanner_rs::git_scan::{
    persist_finalize_output, FinalizeOutcome, FinalizeOutput, FinalizeStats, PersistError,
    PersistenceStore, WriteOp,
};

#[derive(Default)]
struct FailingWatermarkStore {
    data_calls: Cell<u32>,
    watermark_calls: Cell<u32>,
}

impl PersistenceStore for FailingWatermarkStore {
    fn write_data_ops(&self, _ops: &[WriteOp]) -> Result<(), PersistError> {
        self.data_calls.set(self.data_calls.get() + 1);
        Ok(())
    }

    fn write_watermark_ops(&self, _ops: &[WriteOp]) -> Result<(), PersistError> {
        self.watermark_calls.set(self.watermark_calls.get() + 1);
        Err(PersistError::backend("watermark write failed"))
    }
}

#[test]
fn data_ops_written_before_watermarks() {
    let store = FailingWatermarkStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: FinalizeStats::default(),
    };

    let err = persist_finalize_output(&store, &output).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("watermark write failed"));
    assert_eq!(store.data_calls.get(), 1);
    assert_eq!(store.watermark_calls.get(), 1);
}

#[test]
fn partial_runs_skip_watermarks() {
    let store = FailingWatermarkStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Partial { skipped_count: 2 },
        stats: FinalizeStats::default(),
    };

    let res = persist_finalize_output(&store, &output).unwrap();
    assert_eq!(res, FinalizeOutcome::Partial { skipped_count: 2 });
    assert_eq!(store.data_calls.get(), 1);
    assert_eq!(store.watermark_calls.get(), 0);
}
