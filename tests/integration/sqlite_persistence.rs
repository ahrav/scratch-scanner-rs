//! Integration tests for the SQLite persistence layer.
//!
//! Covers:
//! - 5.1 Identity conformance (keyed vs unkeyed, rule_fp always unkeyed, secret_hash keyed)
//! - 5.2 Run status semantics
//! - 5.4 SQLite roundtrip (write → query → verify)

use scanner_rs::store::{
    db::{
        query::{self, resolve_run_pk},
        schema::configure_connection,
        writer::{RunCounters, RunStatus, SqliteStoreConfig, SqliteStoreProducer},
    },
    identity::{
        rule_fingerprint, secret_hash, secret_hash_with_truncation, SecretLenBucket,
        MAX_SECRET_HASH_BYTES,
    },
    keys::{IdHashMode, StoreKeys},
    path_id::canonicalize_path,
    root_id::{self, RootIdInput, RootKind},
    FsFindingBatch, FsFindingRecord, FsRunLoss, StoreProducer,
};

// ---------------------------------------------------------------------------
// 5.1 Identity conformance
// ---------------------------------------------------------------------------

#[test]
fn rule_fingerprint_is_always_unkeyed() {
    // Two different ephemeral keys produce the same rule fingerprint.
    let keys_a = StoreKeys::bootstrap_from_env();
    let keys_b = StoreKeys::bootstrap_from_env();

    let rule = scanner_rs::demo_rules().into_iter().next().unwrap();
    let fp_a = rule_fingerprint(&rule, &keys_a);
    let fp_b = rule_fingerprint(&rule, &keys_b);
    assert_eq!(fp_a, fp_b, "rule_fingerprint must be key-independent");
}

#[test]
fn secret_hash_is_always_keyed() {
    let keys_a = StoreKeys::bootstrap_from_env();
    let keys_b = StoreKeys::bootstrap_from_env();

    let norm = [0x42u8; 32];
    let sh_a = secret_hash(&norm, &keys_a);
    let sh_b = secret_hash(&norm, &keys_b);
    assert_ne!(
        sh_a, sh_b,
        "secret_hash must use key material (different ephemeral keys → different hashes)"
    );
}

#[test]
fn keyed_vs_unkeyed_root_id_differs() {
    let keys = StoreKeys::bootstrap_from_env();
    let keys_keyed = keys.with_id_hash_mode(IdHashMode::Keyed);
    let keys_unkeyed = keys.with_id_hash_mode(IdHashMode::Unkeyed);

    let input = RootIdInput {
        kind: RootKind::Fs,
        identity_scheme: "fs_path_v1",
        canonical_identity: b"/tmp/test",
    };

    let root_keyed = root_id::root_id(&input, &keys_keyed);
    let root_unkeyed = root_id::root_id(&input, &keys_unkeyed);

    assert_ne!(
        root_keyed, root_unkeyed,
        "keyed and unkeyed root_ids must differ"
    );
}

#[test]
fn root_id_deterministic_for_same_mode() {
    let keys = StoreKeys::bootstrap_from_env();
    let input = RootIdInput {
        kind: RootKind::Fs,
        identity_scheme: "fs_path_v1",
        canonical_identity: b"/tmp/test",
    };

    let r1 = root_id::root_id(&input, &keys);
    let r2 = root_id::root_id(&input, &keys);
    assert_eq!(r1, r2, "same input + same keys must produce same root_id");
}

#[test]
fn different_root_kinds_produce_different_ids() {
    let keys = StoreKeys::bootstrap_from_env();

    let fs_root = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/test",
        },
        &keys,
    );
    let git_root = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Git,
            identity_scheme: "git_remote_url_v1",
            canonical_identity: b"/tmp/test",
        },
        &keys,
    );
    assert_ne!(fs_root, git_root, "different root kinds must differ");
}

#[test]
fn path_canonicalization_is_deterministic() {
    assert_eq!(canonicalize_path("a/b/../c"), "a/c");
    assert_eq!(canonicalize_path("a/./b/./c"), "a/b/c");
    assert_eq!(canonicalize_path("/foo/bar"), "foo/bar");
    assert_eq!(canonicalize_path("a\\b\\c"), "a/b/c");
    assert_eq!(canonicalize_path("./a/b"), "a/b");
}

#[test]
fn secret_len_bucket_classification() {
    // 0 is still ≤ 64, so it's Short (Unknown is for N/A cases, not zero length).
    assert_eq!(SecretLenBucket::from_len(0), SecretLenBucket::Short);
    assert_eq!(SecretLenBucket::from_len(10), SecretLenBucket::Short);
    assert_eq!(SecretLenBucket::from_len(64), SecretLenBucket::Short);
    assert_eq!(SecretLenBucket::from_len(65), SecretLenBucket::Medium);
    assert_eq!(SecretLenBucket::from_len(512), SecretLenBucket::Medium);
    assert_eq!(SecretLenBucket::from_len(513), SecretLenBucket::Long);
    assert_eq!(SecretLenBucket::from_len(10000), SecretLenBucket::Long);
}

#[test]
fn max_secret_hash_bytes_truncation() {
    let keys = StoreKeys::bootstrap_from_env();

    let short = vec![0x42u8; 100];
    let sh1 = secret_hash_with_truncation(&short, &keys);

    let at_max = vec![0x42u8; MAX_SECRET_HASH_BYTES];
    let sh2 = secret_hash_with_truncation(&at_max, &keys);

    let over_max = vec![0x42u8; MAX_SECRET_HASH_BYTES + 1000];
    let sh3 = secret_hash_with_truncation(&over_max, &keys);

    assert_ne!(
        sh1, sh2,
        "different lengths should produce different hashes"
    );
    assert_ne!(sh2, sh3, "truncated hash should differ from non-truncated");
}

// ---------------------------------------------------------------------------
// 5.2 Run status semantics
// ---------------------------------------------------------------------------

#[test]
fn run_status_complete() {
    assert_eq!(
        RunCounters::default().derive_status(false),
        RunStatus::Complete
    );
}

#[test]
fn run_status_complete_with_coverage_limits() {
    assert_eq!(
        RunCounters::default().derive_status(true),
        RunStatus::CompleteWithCoverageLimits
    );
}

#[test]
fn run_status_incomplete_on_dropped() {
    let c = RunCounters {
        dropped_findings: 3,
        ..Default::default()
    };
    assert_eq!(c.derive_status(false), RunStatus::Incomplete);
}

#[test]
fn run_status_incomplete_on_emit_failures() {
    let c = RunCounters {
        emit_failures: 2,
        ..Default::default()
    };
    assert_eq!(c.derive_status(false), RunStatus::Incomplete);
}

#[test]
fn run_status_incomplete_overrides_coverage_limits() {
    let c = RunCounters {
        dropped_findings: 1,
        ..Default::default()
    };
    assert_eq!(c.derive_status(true), RunStatus::Incomplete);
}

// ---------------------------------------------------------------------------
// 5.4 SQLite roundtrip
// ---------------------------------------------------------------------------

fn make_config(
    db_path: std::path::PathBuf,
    root_id: [u8; 32],
    mode: IdHashMode,
) -> SqliteStoreConfig {
    SqliteStoreConfig {
        db_path,
        root_id,
        root_kind: RootKind::Fs,
        identity_scheme: "fs_path_v1".to_string(),
        canonical_identity: b"/tmp/test-project".to_vec(),
        display_name: Some("test-project".to_string()),
        id_hash_mode: mode,
        scanner_version: Some("0.1.0-test".to_string()),
    }
}

#[test]
fn sqlite_roundtrip_write_and_query() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/test-project",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();

    let rec = FsFindingRecord {
        rule_id: 0,
        root_hint_start: 100,
        root_hint_end: 120,
        span_start: 102,
        span_end: 118,
        norm_hash: [0x42; 32],
    };
    let batch = FsFindingBatch {
        object_path: b"src/main.rs",
        findings: &[rec],
    };

    producer.emit_fs_batch(batch).unwrap();
    producer.end_run(false).unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let runs = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, RunStatus::Complete as i32);
    assert_eq!(runs[0].root_display.as_deref(), Some("test-project"));

    // Resolve run by hex prefix.
    let hex_prefix = &runs[0].run_id_hex[..8];
    let resolved = resolve_run_pk(&conn, hex_prefix).unwrap();
    assert_eq!(resolved, Some(runs[0].run_pk));
}

#[test]
fn idempotent_reinsert_same_finding() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/idem",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();

    let rec = FsFindingRecord {
        rule_id: 1,
        root_hint_start: 50,
        root_hint_end: 70,
        span_start: 52,
        span_end: 68,
        norm_hash: [0xAA; 32],
    };
    let batch = FsFindingBatch {
        object_path: b"foo.txt",
        findings: &[rec],
    };

    producer.emit_fs_batch(batch).unwrap();
    producer.emit_fs_batch(batch).unwrap();
    producer.end_run(false).unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    // Rule should be deduplicated (same norm_hash used as fingerprint placeholder).
    let rule_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rules WHERE rule_fingerprint = ?1",
            rusqlite::params![[0xAAu8; 32].as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rule_count, 1, "rule should be deduplicated");
}

#[test]
fn two_runs_share_root() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/shared",
        },
        &keys,
    );

    // Two sequential runs with the same root.
    for _ in 0..2 {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let producer = SqliteStoreProducer::open(config).unwrap();
        producer.end_run(false).unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let root_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM roots", [], |r| r.get(0))
        .unwrap();
    assert_eq!(root_count, 1);

    let runs = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(runs.len(), 2);
}

#[test]
fn run_loss_marks_status_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/loss",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();
    producer
        .record_fs_run_loss(FsRunLoss {
            dropped_findings: 5,
            persistence_emit_failures: 0,
        })
        .unwrap();
    producer.end_run(false).unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let runs = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, RunStatus::Incomplete as i32);
}

#[test]
fn coverage_limits_run_status() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/coverage",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();
    producer.end_run(true).unwrap(); // had_coverage_limits = true

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let runs = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, RunStatus::CompleteWithCoverageLimits as i32);
}

#[test]
fn list_runs_filters_by_status() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/filter",
        },
        &keys,
    );

    // Run 1: complete.
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        p.end_run(false).unwrap();
    }
    // Run 2: incomplete (loss).
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        p.record_fs_run_loss(FsRunLoss {
            dropped_findings: 1,
            persistence_emit_failures: 0,
        })
        .unwrap();
        p.end_run(false).unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let all = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(all.len(), 2);

    let complete = query::list_runs(&conn, Some(RunStatus::Complete as i32), 100).unwrap();
    assert_eq!(complete.len(), 1);

    let incomplete = query::list_runs(&conn, Some(RunStatus::Incomplete as i32), 100).unwrap();
    assert_eq!(incomplete.len(), 1);
}
