//! Integration edge-case tests for the append-only log writer.
//!
//! Validates:
//! - Writer thread I/O error surfaces as terminal error.
//! - Multiple sequential runs in the same store root coexist.
//! - Batch durability mode writes without error.
//! - Finding IDs are deterministic across producer instances with the same key.

use regex::bytes::Regex;
use scanner_rs::store::log::{
    LogDurabilityMode, LogRecord, LogRecordReader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
};
use scanner_rs::store::{
    list_finalized_segment_files, AppendLogStoreProducer, FsFindingBatch, FsFindingRecord,
    FsRunLoss, LogWriterConfig, StoreProducer, SCANNER_SECRET_KEY_ENV,
};
use scanner_rs::{RuleSpec, ValidatorKind};
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

fn simple_rule() -> RuleSpec {
    RuleSpec {
        name: "secret",
        anchors: &[b"SECRET"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        offline_validation: None,
        re: Regex::new("SECRET[A-Z0-9]+").unwrap(),
    }
}

fn sample_finding(rule_id: u32, start: u64) -> FsFindingRecord {
    FsFindingRecord {
        rule_id,
        root_hint_start: start,
        root_hint_end: start + 16,
        span_start: start + 1,
        span_end: start + 15,
        norm_hash: [rule_id as u8; 32],
        confidence_score: 0,
    }
}

fn with_secret_key_env<T>(value: &str, f: impl FnOnce() -> T) -> T {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap();

    let prev = std::env::var_os(SCANNER_SECRET_KEY_ENV);
    std::env::set_var(SCANNER_SECRET_KEY_ENV, value);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    match prev {
        Some(v) => std::env::set_var(SCANNER_SECRET_KEY_ENV, v),
        None => std::env::remove_var(SCANNER_SECRET_KEY_ENV),
    }

    match result {
        Ok(v) => v,
        Err(p) => std::panic::resume_unwind(p),
    }
}

/// Helper: decode all records from finalized segments.
fn decode_all_records(store_root: &std::path::Path, max_payload: u32) -> Vec<LogRecord> {
    let bins = list_finalized_segment_files(store_root).unwrap();
    let mut records = Vec::new();
    for bin in bins {
        let f = fs::File::open(bin).unwrap();
        let mut reader = LogRecordReader::new(f, max_payload);
        while let Some(rec) = reader.next_record().unwrap() {
            records.push(rec);
        }
    }
    records
}

#[test]
fn writer_thread_io_error_surfaces_as_terminal_error() {
    // Force a write error by pointing `max_segment_bytes` so small that even
    // the RunEnd frame by itself exceeds it, then confirm the terminal error
    // surfaces correctly. Instead of relying on filesystem manipulation
    // (which is platform/timing-dependent), we use a valid store root but
    // craft a situation where the writer encounters an I/O error by removing
    // the run directory mid-write.
    //
    // Strategy: use a write_delay to slow the writer, rename the run directory
    // away while the writer is sleeping, then confirm the error surfaces.
    let tmp = TempDir::new().unwrap();
    let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
    cfg.max_segment_bytes = 512;
    cfg.max_frame_payload_bytes = 250;
    cfg.max_inflight_batches = 4;
    cfg.max_inflight_bytes = 16 * 1024 * 1024;
    // Long write delay so we can rename the directory between writes.
    cfg.write_delay = Some(std::time::Duration::from_millis(500));

    let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

    // Emit two findings to fill the channel. The writer will process the first
    // one (writing + 500ms delay), giving us a window to rename the directory.
    for i in 0..2u64 {
        let findings = vec![sample_finding(0, i * 100)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: format!("file-{i}.txt").as_bytes(),
                findings: &findings,
            })
            .unwrap();
    }

    // Wait for the writer to start processing the first finding (write it,
    // then start the 500ms delay).
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Rename the entire run directory away. When the writer wakes from its
    // delay and tries to process the second finding (triggering rotation),
    // it will fail because the segments directory path no longer exists.
    let mut renamed = Vec::new();
    for entry in fs::read_dir(tmp.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            let orig = entry.path();
            let moved = tmp.path().join(format!(
                "{}-moved",
                orig.file_name().unwrap().to_str().unwrap()
            ));
            fs::rename(&orig, &moved).unwrap();
            renamed.push((moved, orig));
        }
    }

    // Now close the producer. The writer thread should hit the I/O error
    // during rotation and surface it as a terminal error.
    let close_result = producer.record_fs_run_loss(FsRunLoss::default());

    // Restore directories so TempDir cleanup works.
    for (moved, orig) in &renamed {
        if moved.exists() && !orig.exists() {
            let _ = fs::rename(moved, orig);
        }
    }

    assert!(
        close_result.is_err(),
        "expected terminal error from I/O failure during rotation, got: {close_result:?}"
    );
}

#[test]
fn multiple_sequential_runs_in_same_store_root() {
    let tmp = TempDir::new().unwrap();
    let store_root = tmp.path().to_path_buf();

    // Run 1.
    let cfg1 = LogWriterConfig::for_root(store_root.clone());
    let producer1 = AppendLogStoreProducer::new(&[simple_rule()], cfg1.clone()).unwrap();
    let f1 = vec![sample_finding(0, 0)];
    producer1
        .emit_fs_batch(FsFindingBatch {
            object_path: b"run1.txt",
            findings: &f1,
        })
        .unwrap();
    producer1.record_fs_run_loss(FsRunLoss::default()).unwrap();

    let bins_after_1 = list_finalized_segment_files(&store_root).unwrap();
    assert!(!bins_after_1.is_empty(), "expected segments from first run");

    // Run 2.
    let cfg2 = LogWriterConfig::for_root(store_root.clone());
    let producer2 = AppendLogStoreProducer::new(&[simple_rule()], cfg2).unwrap();
    let f2 = vec![sample_finding(0, 100)];
    producer2
        .emit_fs_batch(FsFindingBatch {
            object_path: b"run2.txt",
            findings: &f2,
        })
        .unwrap();
    producer2.record_fs_run_loss(FsRunLoss::default()).unwrap();

    let bins_after_2 = list_finalized_segment_files(&store_root).unwrap();
    assert!(
        bins_after_2.len() > bins_after_1.len(),
        "expected additional segments from second run"
    );

    // Segments from both runs should be in order (run dirs are sorted).
    let names: Vec<String> = bins_after_2
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    for w in names.windows(2) {
        assert!(
            w[0] <= w[1],
            "segment paths should be in sorted order: {} vs {}",
            w[0],
            w[1]
        );
    }
}

#[test]
fn batch_durability_mode_writes_without_error() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
    cfg.durability = LogDurabilityMode::Batch;

    let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

    for i in 0..5u64 {
        let findings = vec![sample_finding(0, i * 100)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: format!("batch-{i}.txt").as_bytes(),
                findings: &findings,
            })
            .unwrap();
    }

    producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

    let records = decode_all_records(&cfg.root_dir, cfg.max_frame_payload_bytes);
    assert!(matches!(records.first(), Some(LogRecord::RunStart(_))));
    assert!(records.iter().any(|r| matches!(r, LogRecord::RunEnd(_))));

    let batch_count = records
        .iter()
        .filter(|r| matches!(r, LogRecord::FindingBatch(_)))
        .count();
    assert_eq!(batch_count, 5, "expected 5 finding batch frames");
}

#[test]
fn finding_id_deterministic_across_producer_instances() {
    // Fixed SCANNER_SECRET_KEY, same rules/batch → identical finding_id values.
    with_secret_key_env("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", || {
        let tmp = TempDir::new().unwrap();

        // Producer 1.
        let cfg1 = LogWriterConfig::for_root(tmp.path().join("store1"));
        let producer1 = AppendLogStoreProducer::new(&[simple_rule()], cfg1.clone()).unwrap();
        let findings = vec![sample_finding(0, 42)];
        producer1
            .emit_fs_batch(FsFindingBatch {
                object_path: b"same-path.txt",
                findings: &findings,
            })
            .unwrap();
        producer1.record_fs_run_loss(FsRunLoss::default()).unwrap();

        // Producer 2 (same key, same rules, same batch data).
        let cfg2 = LogWriterConfig::for_root(tmp.path().join("store2"));
        let producer2 = AppendLogStoreProducer::new(&[simple_rule()], cfg2.clone()).unwrap();
        let findings = vec![sample_finding(0, 42)];
        producer2
            .emit_fs_batch(FsFindingBatch {
                object_path: b"same-path.txt",
                findings: &findings,
            })
            .unwrap();
        producer2.record_fs_run_loss(FsRunLoss::default()).unwrap();

        // Extract finding IDs from both stores.
        let records1 = decode_all_records(&cfg1.root_dir, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let records2 = decode_all_records(&cfg2.root_dir, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);

        let ids1: Vec<[u8; 32]> = records1
            .iter()
            .filter_map(|r| match r {
                LogRecord::FindingBatch(b) => {
                    Some(b.findings.iter().map(|f| f.finding_id).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();

        let ids2: Vec<[u8; 32]> = records2
            .iter()
            .filter_map(|r| match r {
                LogRecord::FindingBatch(b) => {
                    Some(b.findings.iter().map(|f| f.finding_id).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();

        assert_eq!(
            ids1, ids2,
            "finding IDs should be identical across producer instances with same key"
        );
        assert!(!ids1.is_empty(), "expected at least one finding ID");
    });
}
