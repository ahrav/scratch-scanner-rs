//! Integration tests for the SQLite persistence layer.
//!
//! Covers:
//! - 5.1 Identity conformance (keyed vs unkeyed, rule_fp always unkeyed, secret_hash keyed)
//! - 5.2 Run status semantics
//! - 5.4 SQLite roundtrip (write → query → verify)

use scanner_rs::store::{
    db::{
        query::{self, resolve_run_pk},
        schema::{configure_connection, ensure_schema},
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
use std::fs;
use std::process::Command;

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

    // Rule should be deduplicated by rule identity.
    let rule_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rules WHERE rule_id = ?1",
            rusqlite::params![1_i64],
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

#[test]
fn emit_batch_persists_queryable_findings_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/persist-findings",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();
    let run_pk = producer.run_pk().expect("run_pk");

    let rec = FsFindingRecord {
        rule_id: 7,
        root_hint_start: 10,
        root_hint_end: 20,
        span_start: 10,
        span_end: 20,
        norm_hash: [0x33; 32],
    };
    producer
        .emit_fs_batch(FsFindingBatch {
            object_path: b"src/main.rs",
            findings: &[rec],
        })
        .unwrap();
    producer.end_run(false).unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();
    let findings = query::list_findings(&conn, run_pk, None, None, 100).unwrap();
    assert_eq!(findings.len(), 1, "expected persisted finding row");
}

#[test]
fn rules_do_not_collapse_when_norm_hash_matches() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/rule-separation",
        },
        &keys,
    );

    let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
    let producer = SqliteStoreProducer::open(config).unwrap();
    let shared_norm_hash = [0x99; 32];
    let batch = FsFindingBatch {
        object_path: b"src/lib.rs",
        findings: &[
            FsFindingRecord {
                rule_id: 1,
                root_hint_start: 0,
                root_hint_end: 5,
                span_start: 0,
                span_end: 5,
                norm_hash: shared_norm_hash,
            },
            FsFindingRecord {
                rule_id: 2,
                root_hint_start: 10,
                root_hint_end: 15,
                span_start: 10,
                span_end: 15,
                norm_hash: shared_norm_hash,
            },
        ],
    };
    producer.emit_fs_batch(batch).unwrap();
    producer.end_run(false).unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();
    let distinct_rule_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        distinct_rule_count, 2,
        "different rule ids must persist as distinct rules even with same norm hash"
    );
}

#[test]
fn fs_scan_with_persist_findings_finalizes_run() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("secret.txt"),
        b"token=xoxa-1234567890abcdef\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_scanner-rs"))
        .args(["scan", "fs"])
        .arg(root.path())
        .arg("--persist-findings")
        .output()
        .expect("run scanner-rs scan fs");
    assert!(
        output.status.success(),
        "scan command failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let db_path = root.path().join(".scanner-store").join("findings.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let (status, ended_at): (i32, Option<i64>) = conn
        .query_row(
            "SELECT status, ended_at FROM runs ORDER BY run_pk DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_ne!(
        status,
        RunStatus::InProgress as i32,
        "run must be finalized"
    );
    assert!(ended_at.is_some(), "run must have ended_at");
}

#[test]
fn store_list_runs_command_succeeds_against_existing_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    ensure_schema(&conn).unwrap();
    let root_id = [0xABu8; 32];
    conn.execute(
        "INSERT INTO roots (root_id, root_kind, identity_scheme, canonical_identity, display_name)
         VALUES (?1, 2, 'fs_path_v1', X'01', 'manual-root')",
        rusqlite::params![root_id.as_slice()],
    )
    .unwrap();
    let root_pk = conn.last_insert_rowid();
    let run_id: [u8; 16] = [0x11; 16];
    conn.execute(
        "INSERT INTO runs (run_id, root_pk, id_hash_mode, started_at, ended_at, status, findings_emitted, objects_scanned)
         VALUES (?1, ?2, 1, 1, 2, 1, 0, 0)",
        rusqlite::params![run_id.as_slice(), root_pk],
    )
    .unwrap();
    drop(conn);

    let output = Command::new(env!("CARGO_BIN_EXE_scanner-rs"))
        .args(["store", "list-runs"])
        .arg(format!("--store-dir={}", dir.path().display()))
        .arg("--format=json")
        .output()
        .expect("run scanner-rs store list-runs");
    assert!(
        output.status.success(),
        "store list-runs failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn store_list_findings_json_output_is_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();
    ensure_schema(&conn).unwrap();

    let root_id = [0xAAu8; 32];
    conn.execute(
        "INSERT INTO roots (root_id, root_kind, identity_scheme, canonical_identity, display_name)
         VALUES (?1, 2, 'fs_path_v1', X'01', 'root')",
        rusqlite::params![root_id.as_slice()],
    )
    .unwrap();
    let root_pk = conn.last_insert_rowid();

    let run_id: [u8; 16] = [0x22; 16];
    conn.execute(
        "INSERT INTO runs (run_id, root_pk, id_hash_mode, started_at, ended_at, status, findings_emitted, objects_scanned)
         VALUES (?1, ?2, 1, 1, 2, 1, 1, 1)",
        rusqlite::params![run_id.as_slice(), root_pk],
    )
    .unwrap();
    let run_pk = conn.last_insert_rowid();

    let path_id = [0x33u8; 32];
    conn.execute(
        "INSERT INTO paths (path_id, root_pk, canonical_path) VALUES (?1, ?2, ?3)",
        rusqlite::params![path_id.as_slice(), root_pk, "bad\"name\\x.txt"],
    )
    .unwrap();
    let path_pk = conn.last_insert_rowid();

    let rule_fp = [0x44u8; 32];
    conn.execute(
        "INSERT INTO rules (rule_fingerprint, rule_id, rule_name) VALUES (?1, 7, ?2)",
        rusqlite::params![rule_fp.as_slice(), "rule\"quoted"],
    )
    .unwrap();
    let rule_pk = conn.last_insert_rowid();

    let secret_hash = [0x55u8; 32];
    conn.execute(
        "INSERT INTO secrets (secret_hash, secret_len_bucket, first_seen_run, last_seen_run, occurrence_count, status)
         VALUES (?1, 1, ?2, ?2, 1, 0)",
        rusqlite::params![secret_hash.as_slice(), run_pk],
    )
    .unwrap();
    let secret_pk = conn.last_insert_rowid();

    let occ_id = [0x66u8; 32];
    conn.execute(
        "INSERT INTO occurrences (occurrence_id, root_pk, path_pk, rule_pk, secret_pk, start_byte, end_byte, identity_flags, object_path)
         VALUES (?1, ?2, ?3, ?4, ?5, 10, 20, 0, ?6)",
        rusqlite::params![
            occ_id.as_slice(),
            root_pk,
            path_pk,
            rule_pk,
            secret_pk,
            "bad\"name\\x.txt"
        ],
    )
    .unwrap();
    let occ_pk = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO observations (run_pk, occ_pk, batch_seqno) VALUES (?1, ?2, 1)",
        rusqlite::params![run_pk, occ_pk],
    )
    .unwrap();
    drop(conn);

    let run_id_hex = run_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let output = Command::new(env!("CARGO_BIN_EXE_scanner-rs"))
        .args(["store", "list-findings"])
        .arg(format!("--store-dir={}", dir.path().display()))
        .arg(format!("--run={run_id_hex}"))
        .arg("--format=json")
        .output()
        .expect("run scanner-rs store list-findings");
    assert!(
        output.status.success(),
        "store list-findings failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(parsed.is_array(), "list-findings JSON must be an array");
}

#[test]
fn db_reopen_across_lifetimes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/reopen",
        },
        &keys,
    );

    // First lifetime: write a finding.
    let run_pk_1;
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let producer = SqliteStoreProducer::open(config).unwrap();
        run_pk_1 = producer.run_pk().expect("run_pk");

        let rec = FsFindingRecord {
            rule_id: 1,
            root_hint_start: 0,
            root_hint_end: 10,
            span_start: 0,
            span_end: 10,
            norm_hash: [0xEE; 32],
        };
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"reopen.rs",
                findings: &[rec],
            })
            .unwrap();
        producer.end_run(false).unwrap();
        // Producer dropped here — connection closed.
    }

    // Second lifetime: reopen and verify data survives.
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let producer = SqliteStoreProducer::open(config).unwrap();
        let run_pk_2 = producer.run_pk().expect("run_pk");
        assert_ne!(run_pk_1, run_pk_2, "second open creates a new run");
        producer.end_run(false).unwrap();
    }

    // Verify both runs are queryable.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let runs = query::list_runs(&conn, None, 100).unwrap();
    assert_eq!(runs.len(), 2, "both runs should survive reopen");

    // First run's finding should be queryable.
    let findings = query::list_findings(&conn, run_pk_1, None, None, 100).unwrap();
    assert_eq!(
        findings.len(),
        1,
        "finding from first lifetime should persist"
    );
}

// ---------------------------------------------------------------------------
// 5.5 Edge-case coverage
// ---------------------------------------------------------------------------

/// diff_runs with both runs empty should return empty sets and zero unchanged.
#[test]
fn diff_runs_with_empty_runs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/diff-empty",
        },
        &keys,
    );

    // Two runs, neither has findings.
    let run_pk_a;
    let run_pk_b;
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        run_pk_a = p.run_pk().expect("run_pk");
        p.end_run(false).unwrap();
    }
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        run_pk_b = p.run_pk().expect("run_pk");
        p.end_run(false).unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    let diff = query::diff_runs(&conn, run_pk_a, run_pk_b, None).unwrap();
    assert!(diff.new_findings.is_empty(), "no new findings expected");
    assert!(
        diff.resolved_findings.is_empty(),
        "no resolved findings expected"
    );
    assert_eq!(diff.unchanged_count, 0, "zero unchanged expected");
}

/// diff_runs with a limit caps the new and resolved result sets.
#[test]
fn diff_runs_respects_limit() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/diff-limit",
        },
        &keys,
    );

    // Run A: emit 3 findings.
    let run_pk_a;
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        run_pk_a = p.run_pk().expect("run_pk");
        for i in 0..3u8 {
            let rec = FsFindingRecord {
                rule_id: u32::from(i),
                root_hint_start: u64::from(i) * 100,
                root_hint_end: u64::from(i) * 100 + 50,
                span_start: u64::from(i) * 100,
                span_end: u64::from(i) * 100 + 50,
                norm_hash: [i.wrapping_add(0x10); 32],
            };
            p.emit_fs_batch(FsFindingBatch {
                object_path: format!("file_{i}.rs").as_bytes(),
                findings: &[rec],
            })
            .unwrap();
        }
        p.end_run(false).unwrap();
    }

    // Run B: empty (all 3 findings are "resolved" relative to B).
    let run_pk_b;
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        run_pk_b = p.run_pk().expect("run_pk");
        p.end_run(false).unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    // Without limit: all 3 resolved.
    let diff_all = query::diff_runs(&conn, run_pk_a, run_pk_b, None).unwrap();
    assert_eq!(diff_all.resolved_findings.len(), 3);

    // With limit=1: only 1 resolved returned.
    let diff_limited = query::diff_runs(&conn, run_pk_a, run_pk_b, Some(1)).unwrap();
    assert_eq!(
        diff_limited.resolved_findings.len(),
        1,
        "limit should cap resolved findings"
    );
}

/// Schema re-open on an existing database with the current version should be a
/// no-op (no migration errors).
#[test]
fn schema_reopen_on_existing_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");

    // First open creates the schema.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        configure_connection(&conn).unwrap();
        ensure_schema(&conn).unwrap();
    }

    // Second open should succeed without errors (idempotent migration).
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        configure_connection(&conn).unwrap();
        ensure_schema(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert!(version > 0, "user_version must be set after migration");
    }
}

/// touch_secret_observation updates first_seen_run, last_seen_run, and
/// occurrence_count correctly across multiple runs.
#[test]
fn secret_observation_counters_track_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("findings.db");
    let keys = StoreKeys::bootstrap_from_env();
    let root_id = root_id::root_id(
        &RootIdInput {
            kind: RootKind::Fs,
            identity_scheme: "fs_path_v1",
            canonical_identity: b"/tmp/secret-obs",
        },
        &keys,
    );

    let shared_hash = [0xDD; 32];

    // Run 1: emit a finding with shared_hash.
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        p.emit_fs_batch(FsFindingBatch {
            object_path: b"a.rs",
            findings: &[FsFindingRecord {
                rule_id: 0,
                root_hint_start: 0,
                root_hint_end: 10,
                span_start: 0,
                span_end: 10,
                norm_hash: shared_hash,
            }],
        })
        .unwrap();
        p.end_run(false).unwrap();
    }

    // Run 2: emit the same finding again — occurrence_count should increase.
    {
        let config = make_config(db_path.clone(), root_id, keys.id_hash_mode());
        let p = SqliteStoreProducer::open(config).unwrap();
        p.emit_fs_batch(FsFindingBatch {
            object_path: b"a.rs",
            findings: &[FsFindingRecord {
                rule_id: 0,
                root_hint_start: 0,
                root_hint_end: 10,
                span_start: 0,
                span_end: 10,
                norm_hash: shared_hash,
            }],
        })
        .unwrap();
        p.end_run(false).unwrap();
    }

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    configure_connection(&conn).unwrap();

    // Verify the secret's aggregate counters.
    let (occ_count, first_run, last_run): (i64, i64, i64) = conn
        .query_row(
            "SELECT occurrence_count, first_seen_run, last_seen_run FROM secrets LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert!(
        occ_count >= 2,
        "occurrence_count should be >= 2 after two runs, got {occ_count}"
    );
    assert!(
        first_run <= last_run,
        "first_seen_run ({first_run}) should be <= last_seen_run ({last_run})"
    );
    assert_ne!(
        first_run, last_run,
        "first and last seen runs should differ across two runs"
    );
}
