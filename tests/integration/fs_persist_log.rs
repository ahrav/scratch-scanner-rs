//! Integration tests for the append-only log persistence backend.
//!
//! Validates the end-to-end pipeline: engine scan → `StoreProducer` emit →
//! on-disk segment files → reader decode. Key properties tested:
//!
//! - **Determinism**: finding IDs are identical regardless of worker count.
//! - **Completeness**: both root-level and transform-derived findings are
//!   persisted.
//! - **Ordering**: `RuleDef` frames are emitted in sorted fingerprint order.
//! - **Codec round-trip**: all persisted records decode successfully via
//!   `LogRecordReader`.

use base64::Engine as _;
use regex::bytes::Regex;
use scanner_rs::scheduler::{parallel_scan_dir, ParallelScanConfig};
use scanner_rs::store::log::{LogRecord, LogRecordReader};
use scanner_rs::store::{
    list_finalized_segment_files, AppendLogStoreProducer, LogWriterConfig, StoreProducer,
    SCANNER_SECRET_KEY_ENV,
};
use scanner_rs::{AnchorPolicy, Engine};
use scanner_rs::{
    Gate, RuleSpec, TransformConfig, TransformId, TransformMode, Tuning, ValidatorKind,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

/// Aggregate view of decoded log segments used for test assertions.
#[derive(Debug)]
struct PersistedSummary {
    /// Unique finding IDs across all segments (deterministic per run config).
    finding_ids: BTreeSet<[u8; 32]>,
    /// Unique object paths that had at least one finding.
    finding_paths: BTreeSet<Vec<u8>>,
    /// Rule fingerprints in the order RuleDef frames appeared on disk.
    rule_defs_in_order: Vec<[u8; 32]>,
    /// Total number of individual findings across all batches.
    findings_count: usize,
}

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
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new("SECRET[A-Z0-9]+").unwrap(),
    }
}

fn base64_transform() -> TransformConfig {
    TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }
}

fn tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 32,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 512,
        max_utf16_decoded_bytes_per_window: 4096,
        max_transform_depth: 2,
        max_total_decode_output_bytes: 128 * 1024,
        max_work_items: 256,
        max_findings_per_chunk: 2048,
        scan_utf16_variants: true,
    }
}

fn write_test_corpus(root: &Path) {
    fs::create_dir_all(root).unwrap();
    let secret = b"SECRETXYZ12345";
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);

    fs::write(root.join("plain.txt"), b"prefix SECRETXYZ12345 suffix").unwrap();
    fs::write(root.join("encoded.txt"), format!("prefix {encoded} suffix")).unwrap();
}

/// Read all finalized `.bin` segments and aggregate into a [`PersistedSummary`].
fn decode_log(store_root: &Path, max_frame_payload: u32) -> PersistedSummary {
    let mut finding_ids = BTreeSet::new();
    let mut finding_paths = BTreeSet::new();
    let mut rule_defs = Vec::new();
    let mut findings_count = 0usize;

    let bins = list_finalized_segment_files(store_root).unwrap();
    assert!(!bins.is_empty(), "expected finalized .bin segments");

    for seg in bins {
        let f = fs::File::open(seg).unwrap();
        let mut reader = LogRecordReader::new(f, max_frame_payload);
        while let Some(record) = reader.next_record().unwrap() {
            match record {
                LogRecord::RuleDef(rule) => {
                    rule_defs.push(rule.rule_fingerprint);
                }
                LogRecord::FindingBatch(batch) => {
                    finding_paths.insert(batch.object_path.clone());
                    findings_count += batch.findings.len();
                    for finding in batch.findings {
                        finding_ids.insert(finding.finding_id);
                    }
                }
                _ => {}
            }
        }
    }

    PersistedSummary {
        finding_ids,
        finding_paths,
        rule_defs_in_order: rule_defs,
        findings_count,
    }
}

fn run_scan(scan_root: &Path, workers: usize) -> PersistedSummary {
    let store_tmp = TempDir::new().unwrap();
    let store_root = store_tmp.path().join("store");

    let rules = vec![simple_rule()];
    let engine = Arc::new(Engine::new_with_anchor_policy(
        rules.clone(),
        vec![base64_transform()],
        tuning(),
        AnchorPolicy::ManualOnly,
    ));

    let mut writer_cfg = LogWriterConfig::for_root(store_root.clone());
    writer_cfg.max_segment_bytes = 512 * 1024;
    writer_cfg.max_frame_payload_bytes = 256 * 1024;
    let producer = Arc::new(AppendLogStoreProducer::new(&rules, writer_cfg.clone()).unwrap());

    let mut cfg = ParallelScanConfig {
        workers,
        skip_hidden: false,
        respect_gitignore: false,
        ..Default::default()
    };
    cfg.store_producer = Some(Arc::clone(&producer) as Arc<dyn StoreProducer>);

    let report = parallel_scan_dir(scan_root, engine, cfg).unwrap();
    let decoded = decode_log(&store_root, writer_cfg.max_frame_payload_bytes);
    assert_eq!(
        decoded.findings_count as u64, report.metrics.findings_emitted,
        "persisted finding count should match emitted findings"
    );
    decoded
}

#[test]
fn fs_append_log_writer_is_deterministic_and_covers_transform_and_root_findings() {
    with_secret_key_env(
        // base64(32 zero bytes): deterministic key material across runs
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        || {
            let scan_tmp = TempDir::new().unwrap();
            write_test_corpus(scan_tmp.path());

            let single_worker = run_scan(scan_tmp.path(), 1);
            let multi_worker = run_scan(scan_tmp.path(), 4);

            assert_eq!(
                single_worker.finding_ids, multi_worker.finding_ids,
                "finding IDs should be deterministic across worker counts"
            );

            assert!(
                single_worker
                    .rule_defs_in_order
                    .windows(2)
                    .all(|w| w[0] <= w[1]),
                "RuleDef frames must be emitted in sorted fingerprint order"
            );

            let has_plain = single_worker
                .finding_paths
                .iter()
                .any(|p| String::from_utf8_lossy(p).contains("plain.txt"));
            let has_encoded = single_worker
                .finding_paths
                .iter()
                .any(|p| String::from_utf8_lossy(p).contains("encoded.txt"));

            assert!(has_plain, "expected root finding from plain.txt");
            assert!(
                has_encoded,
                "expected transform-derived finding from encoded.txt"
            );
        },
    );
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
