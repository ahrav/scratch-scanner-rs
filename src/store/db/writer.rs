//! SQLite write-path implementation of [`StoreProducer`].
//!
//! `SqliteStoreProducer` writes findings to the `findings.db` SQLite database
//! during scans. It implements the existing [`StoreProducer`] trait for
//! drop-in compatibility with the scheduler.
//!
//! # Design
//!
//! - Single writer connection (SQLite serializes writes anyway via WAL).
//! - Batched transactions: each `emit_fs_batch` call runs inside a transaction.
//! - `INSERT OR IGNORE` for idempotent dimensions and observation edges.
//! - Observation-driven secret counters (`occurrence_count`, first/last seen run).
//! - Rust-side `HashMap<[u8;32], i64>` caches for surrogate key resolution.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use super::schema::{configure_connection, ensure_schema};
use crate::store::fs::{FsFindingBatch, FsRunLoss, FsStoreError, StoreProducer};
use crate::store::identity::SecretLenBucket;
use crate::store::keys::IdHashMode;
use crate::store::path_id::canonicalize_path;
use crate::store::root_id::RootKind;

/// Run status codes stored in the `runs.status` column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RunStatus {
    /// Scan is currently in progress.
    InProgress = 0,
    /// Scan completed successfully with full coverage.
    Complete = 1,
    /// Scan completed but with coverage limits (e.g. max file size caps).
    CompleteWithCoverageLimits = 2,
    /// Scan did not complete (findings dropped, emit failures).
    Incomplete = 3,
    /// Scan failed with an error.
    Failed = 4,
}

/// Loss and coverage counters for run status derivation.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunCounters {
    pub objects_scanned: u64,
    pub bytes_scanned: u64,
    pub findings_emitted: u64,
    pub dropped_findings: u64,
    pub emit_failures: u64,
}

impl RunCounters {
    /// Derive the final run status from counters.
    ///
    /// Precedence (highest to lowest):
    /// 1. **Incomplete** — any findings dropped or emit failures occurred.
    /// 2. **CompleteWithCoverageLimits** — full scan but coverage caps applied.
    /// 3. **Complete** — clean scan, no data loss.
    #[must_use]
    pub fn derive_status(&self, had_coverage_limits: bool) -> RunStatus {
        if self.dropped_findings > 0 || self.emit_failures > 0 {
            RunStatus::Incomplete
        } else if had_coverage_limits {
            RunStatus::CompleteWithCoverageLimits
        } else {
            RunStatus::Complete
        }
    }
}

/// Configuration for opening a SQLite store.
pub struct SqliteStoreConfig {
    /// Path to the database file (e.g. `<store_root>/findings.db`).
    pub db_path: std::path::PathBuf,
    /// Root identity for this scan.
    pub root_id: [u8; 32],
    /// Root kind discriminant.
    pub root_kind: RootKind,
    /// Identity scheme tag.
    pub identity_scheme: String,
    /// Canonical identity bytes for the root.
    pub canonical_identity: Vec<u8>,
    /// Display name for the root.
    pub display_name: Option<String>,
    /// Identity hashing mode.
    pub id_hash_mode: IdHashMode,
    /// Scanner version string.
    pub scanner_version: Option<String>,
}

/// Internal mutable state guarded by a mutex.
///
/// The `rule_cache` avoids repeated `SELECT` round-trips for rules already
/// seen in this run. Because rule fingerprints are deterministic, the cache
/// is never invalidated within a single run. The cache maps the 32-byte rule
/// fingerprint to its SQLite surrogate PK (`rule_pk`).
struct WriterState {
    conn: Connection,
    run_pk: i64,
    root_pk: i64,
    root_id: [u8; 32],
    /// Monotonically increasing sequence number within this run, bumped once
    /// per finding and recorded in `observations.batch_seqno`.
    batch_seqno: i64,
    /// `rule_fingerprint → rule_pk` — populated lazily on first encounter.
    rule_cache: HashMap<[u8; 32], i64>,
    counters: RunCounters,
}

/// SQLite-backed implementation of [`StoreProducer`].
///
/// Thread-safe: all mutable state is behind a `Mutex`. The scheduler calls
/// `emit_fs_batch` from worker threads.
pub struct SqliteStoreProducer {
    state: Mutex<WriterState>,
}

impl SqliteStoreProducer {
    /// Open (or create) the database and begin a new run.
    pub fn open(config: SqliteStoreConfig) -> Result<Self, FsStoreError> {
        // Ensure parent directory exists.
        if let Some(parent) = config.db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| FsStoreError::backend(format!("cannot create store dir: {e}")))?;
        }

        let conn = Connection::open(&config.db_path).map_err(|e| {
            FsStoreError::backend(format!("cannot open db {}: {e}", config.db_path.display()))
        })?;

        configure_connection(&conn)
            .map_err(|e| FsStoreError::backend(format!("pragma setup failed: {e}")))?;
        ensure_schema(&conn)
            .map_err(|e| FsStoreError::backend(format!("schema migration failed: {e}")))?;

        // Resolve or insert root.
        let root_pk = resolve_or_insert_root(
            &conn,
            &config.root_id,
            config.root_kind,
            &config.identity_scheme,
            &config.canonical_identity,
            config.display_name.as_deref(),
        )
        .map_err(|e| FsStoreError::backend(format!("root insert failed: {e}")))?;

        // Create the run record.
        let run_id = generate_run_id();
        let started_at = now_epoch_ms();
        conn.execute(
            "INSERT INTO runs (run_id, root_pk, id_hash_mode, started_at, status, scanner_version)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                run_id.as_slice(),
                root_pk,
                config.id_hash_mode as u8,
                started_at,
                config.scanner_version,
            ],
        )
        .map_err(|e| FsStoreError::backend(format!("run insert failed: {e}")))?;
        let run_pk = conn.last_insert_rowid();

        Ok(Self {
            state: Mutex::new(WriterState {
                conn,
                run_pk,
                root_pk,
                root_id: config.root_id,
                batch_seqno: 0,
                rule_cache: HashMap::new(),
                counters: RunCounters::default(),
            }),
        })
    }

    /// Returns the run_pk for this run (useful for queries after scan).
    pub fn run_pk(&self) -> Result<i64, FsStoreError> {
        self.state
            .lock()
            .map(|s| s.run_pk)
            .map_err(|_| FsStoreError::backend("writer lock poisoned"))
    }

    /// Returns the path to the database file.
    #[must_use]
    pub fn db_path(config: &SqliteStoreConfig) -> &Path {
        &config.db_path
    }
}

impl StoreProducer for SqliteStoreProducer {
    /// Write one finding batch inside a single `BEGIN IMMEDIATE … COMMIT`
    /// transaction.
    ///
    /// On any DML failure the transaction is rolled back and the error
    /// propagated. The scheduler records the failure in [`FsRunLoss`] but
    /// does **not** abort the scan — subsequent batches will still be
    /// attempted.
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FsStoreError::backend("writer lock poisoned"))?;
        let state = &mut *state;

        state
            .conn
            .execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| FsStoreError::backend(format!("begin txn failed: {e}")))?;

        let mut batch_count: u64 = 0;
        let write_result: rusqlite::Result<()> = (|| {
            let object_path = String::from_utf8_lossy(batch.object_path).into_owned();
            let canonical_path = canonicalize_path(&object_path);
            let path_id = derive_path_id(&state.root_id, &canonical_path);
            let path_pk =
                resolve_or_insert_path(&state.conn, &path_id, state.root_pk, &canonical_path)?;

            for finding in batch.findings {
                state.batch_seqno += 1;

                let rule_fingerprint = derive_rule_fingerprint(finding.rule_id);
                let rule_pk = resolve_or_insert_rule(
                    &state.conn,
                    &rule_fingerprint,
                    finding.rule_id,
                    &state.rule_cache,
                )?;
                state.rule_cache.entry(rule_fingerprint).or_insert(rule_pk);

                state.conn.execute(
                    "INSERT OR IGNORE INTO run_rules (run_pk, rule_pk) VALUES (?1, ?2)",
                    params![state.run_pk, rule_pk],
                )?;

                let secret_hash = finding.norm_hash;
                let secret_pk = resolve_or_insert_secret(&state.conn, &secret_hash, state.run_pk)?;

                let occurrence_id =
                    derive_occurrence_id(&path_id, &rule_fingerprint, &secret_hash, finding);

                state.conn.execute(
                    "INSERT OR IGNORE INTO occurrences (
                         occurrence_id, root_pk, path_pk, rule_pk, secret_pk,
                         start_byte, end_byte, identity_flags, object_path
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        occurrence_id.as_slice(),
                        state.root_pk,
                        path_pk,
                        rule_pk,
                        secret_pk,
                        finding.root_hint_start as i64,
                        finding.root_hint_end as i64,
                        0i64,
                        object_path.as_str(),
                    ],
                )?;

                let occ_pk: i64 = state.conn.query_row(
                    "SELECT occ_pk FROM occurrences WHERE occurrence_id = ?1",
                    params![occurrence_id.as_slice()],
                    |row| row.get(0),
                )?;

                let inserted_observation = state.conn.execute(
                    "INSERT OR IGNORE INTO observations (run_pk, occ_pk, batch_seqno)
                     VALUES (?1, ?2, ?3)",
                    params![state.run_pk, occ_pk, state.batch_seqno],
                )?;

                if inserted_observation > 0 {
                    touch_secret_observation(&state.conn, secret_pk, state.run_pk)?;
                }

                batch_count += 1;
            }

            Ok(())
        })();

        if let Err(e) = write_result {
            if let Err(rb_err) = state.conn.execute_batch("ROLLBACK;") {
                eprintln!("warn: ROLLBACK failed after emit error: {rb_err}");
            }
            return Err(FsStoreError::backend(format!("emit txn failed: {e}")));
        }

        state
            .conn
            .execute_batch("COMMIT;")
            .map_err(|e| FsStoreError::backend(format!("commit failed: {e}")))?;

        state.counters.findings_emitted += batch_count;
        state.counters.objects_scanned += 1;
        Ok(())
    }

    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FsStoreError::backend("writer lock poisoned"))?;
        state.counters.dropped_findings += loss.dropped_findings;
        state.counters.emit_failures += loss.persistence_emit_failures;
        Ok(())
    }

    fn end_run(&self, had_coverage_limits: bool) -> Result<(), FsStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| FsStoreError::backend("writer lock poisoned"))?;
        let status = state.counters.derive_status(had_coverage_limits);
        let ended_at = now_epoch_ms();
        state
            .conn
            .execute(
                "UPDATE runs SET ended_at = ?1, status = ?2,
                 objects_scanned = ?3, bytes_scanned = ?4, findings_emitted = ?5,
                 dropped_findings = ?6, emit_failures = ?7
                 WHERE run_pk = ?8",
                params![
                    ended_at,
                    status as i32,
                    state.counters.objects_scanned as i64,
                    state.counters.bytes_scanned as i64,
                    state.counters.findings_emitted as i64,
                    state.counters.dropped_findings as i64,
                    state.counters.emit_failures as i64,
                    state.run_pk,
                ],
            )
            .map_err(|e| FsStoreError::backend(format!("run finalize failed: {e}")))?;
        Ok(())
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Resolve or create a root dimension row, returning its surrogate PK.
///
/// Uses `INSERT OR IGNORE` + `SELECT` rather than `INSERT … RETURNING`
/// because `RETURNING` requires SQLite ≥ 3.35 and rusqlite's `execute`
/// doesn't expose returned rows. The two-step approach is safe under
/// `BEGIN IMMEDIATE` and on a single-writer connection.
fn resolve_or_insert_root(
    conn: &Connection,
    root_id: &[u8; 32],
    kind: RootKind,
    scheme: &str,
    canonical_identity: &[u8],
    display_name: Option<&str>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO roots (root_id, root_kind, identity_scheme, canonical_identity, display_name)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            root_id.as_slice(),
            kind as u8,
            scheme,
            canonical_identity,
            display_name,
        ],
    )?;
    conn.query_row(
        "SELECT root_pk FROM roots WHERE root_id = ?1",
        params![root_id.as_slice()],
        |row| row.get(0),
    )
}

/// Resolve or create a rule dimension row, returning its surrogate PK.
///
/// Checks the in-memory `cache` first (O(1) lookup); on miss falls back to
/// `INSERT OR IGNORE` + `SELECT` against the `rules` table. The caller is
/// responsible for inserting the returned PK into the cache.
fn resolve_or_insert_rule(
    conn: &Connection,
    rule_fingerprint: &[u8; 32],
    rule_id: u32,
    cache: &HashMap<[u8; 32], i64>,
) -> rusqlite::Result<i64> {
    if let Some(&pk) = cache.get(rule_fingerprint) {
        return Ok(pk);
    }
    conn.execute(
        "INSERT OR IGNORE INTO rules (rule_fingerprint, rule_id, rule_name)
         VALUES (?1, ?2, ?3)",
        params![
            rule_fingerprint.as_slice(),
            rule_id as i64,
            format!("rule_{rule_id}"),
        ],
    )?;
    conn.query_row(
        "SELECT rule_pk FROM rules WHERE rule_fingerprint = ?1",
        params![rule_fingerprint.as_slice()],
        |row| row.get(0),
    )
}

/// Resolve or create a path dimension row, returning its surrogate PK.
fn resolve_or_insert_path(
    conn: &Connection,
    path_id: &[u8; 32],
    root_pk: i64,
    canonical_path: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO paths (path_id, root_pk, canonical_path)
         VALUES (?1, ?2, ?3)",
        params![path_id.as_slice(), root_pk, canonical_path],
    )?;
    conn.query_row(
        "SELECT path_pk FROM paths WHERE path_id = ?1",
        params![path_id.as_slice()],
        |row| row.get(0),
    )
}

/// Resolve or create a secret dimension row, returning its surrogate PK.
fn resolve_or_insert_secret(
    conn: &Connection,
    secret_hash: &[u8; 32],
    run_pk: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO secrets (
             secret_hash, secret_len_bucket, first_seen_run, last_seen_run, occurrence_count, status
         ) VALUES (?1, ?2, ?3, ?3, 0, 0)",
        params![
            secret_hash.as_slice(),
            SecretLenBucket::Unknown as i32,
            run_pk
        ],
    )?;
    conn.query_row(
        "SELECT secret_pk FROM secrets WHERE secret_hash = ?1",
        params![secret_hash.as_slice()],
        |row| row.get(0),
    )
}

/// Update aggregate counters for a secret when a new observation is recorded.
fn touch_secret_observation(
    conn: &Connection,
    secret_pk: i64,
    run_pk: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE secrets
         SET first_seen_run = MIN(first_seen_run, ?2),
             last_seen_run = MAX(last_seen_run, ?2),
             occurrence_count = occurrence_count + 1
         WHERE secret_pk = ?1",
        params![secret_pk, run_pk],
    )?;
    Ok(())
}

/// Derive a deterministic rule fingerprint from the rule id.
///
/// This keeps rule identity independent from secret bytes and guarantees that
/// different `rule_id` values map to different rule keys.
fn derive_rule_fingerprint(rule_id: u32) -> [u8; 32] {
    const DOMAIN: &[u8] = b"scanner.store.db.v1.rule_fingerprint";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&[0]);
    hasher.update(&rule_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Derive a deterministic path identifier from `(root_id, canonical_path)`.
fn derive_path_id(root_id: &[u8; 32], canonical_path: &str) -> [u8; 32] {
    const DOMAIN: &[u8] = b"scanner.store.db.v1.path_id";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&[0]);
    hasher.update(root_id);
    hasher.update(canonical_path.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Derive a deterministic occurrence identifier.
fn derive_occurrence_id(
    path_id: &[u8; 32],
    rule_fingerprint: &[u8; 32],
    secret_hash: &[u8; 32],
    finding: &crate::store::fs::FsFindingRecord,
) -> [u8; 32] {
    const DOMAIN: &[u8] = b"scanner.store.db.v1.occurrence_id";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&[0]);
    hasher.update(path_id);
    hasher.update(rule_fingerprint);
    hasher.update(secret_hash);
    hasher.update(&finding.root_hint_start.to_le_bytes());
    hasher.update(&finding.root_hint_end.to_le_bytes());
    hasher.update(&finding.span_start.to_le_bytes());
    hasher.update(&finding.span_end.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Generate a 16-byte random run identifier.
///
/// Prefers `/dev/urandom` for cryptographic randomness. Falls back to a
/// BLAKE3 hash of `(PID, timestamp)` — not cryptographically random, but
/// sufficient for run-level uniqueness since run_id only needs to be
/// unique within a single database, not globally unguessable.
fn generate_run_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut id).is_ok() {
                return id;
            }
        }
    }
    // Fallback: hash of PID + timestamp.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&now_epoch_ms().to_le_bytes());
    let hash = hasher.finalize();
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::store::fs::{FsFindingBatch, FsFindingRecord, FsRunLoss, StoreProducer};

    fn test_config(dir: &std::path::Path) -> SqliteStoreConfig {
        SqliteStoreConfig {
            db_path: dir.join("findings.db"),
            root_id: [0xAA; 32],
            root_kind: RootKind::Fs,
            identity_scheme: "fs_device_inode_v1".to_string(),
            canonical_identity: b"/home/user/project".to_vec(),
            display_name: Some("test-project".to_string()),
            id_hash_mode: IdHashMode::Keyed,
            scanner_version: Some("0.1.0-test".to_string()),
        }
    }

    #[test]
    fn open_creates_db_and_run() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");
        let run_pk = producer.run_pk().expect("run_pk");
        assert!(run_pk > 0);
    }

    #[test]
    fn emit_batch_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");

        let rec = FsFindingRecord {
            rule_id: 1,
            root_hint_start: 10,
            root_hint_end: 20,
            span_start: 12,
            span_end: 18,
            norm_hash: [0xBB; 32],
        };
        let batch = FsFindingBatch {
            object_path: b"src/main.rs",
            findings: &[rec],
        };
        producer.emit_fs_batch(batch).expect("emit");
    }

    #[test]
    fn end_run_updates_status() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let db_path = config.db_path.clone();
        let producer = SqliteStoreProducer::open(config).expect("open");
        let run_pk = producer.run_pk().expect("run_pk");

        producer.end_run(false).expect("end_run");

        // Verify by reading the DB directly.
        let conn = Connection::open(&db_path).unwrap();
        let status: i32 = conn
            .query_row(
                "SELECT status FROM runs WHERE run_pk = ?1",
                params![run_pk],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, RunStatus::Complete as i32);
    }

    #[test]
    fn run_loss_marks_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let db_path = config.db_path.clone();
        let producer = SqliteStoreProducer::open(config).expect("open");
        let run_pk = producer.run_pk().expect("run_pk");

        producer
            .record_fs_run_loss(FsRunLoss {
                dropped_findings: 5,
                persistence_emit_failures: 0,
            })
            .expect("loss");
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(&db_path).unwrap();
        let status: i32 = conn
            .query_row(
                "SELECT status FROM runs WHERE run_pk = ?1",
                params![run_pk],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, RunStatus::Incomplete as i32);
    }

    #[test]
    fn coverage_limits_status() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let db_path = config.db_path.clone();
        let producer = SqliteStoreProducer::open(config).expect("open");
        let run_pk = producer.run_pk().expect("run_pk");

        producer.end_run(true).expect("end_run");

        let conn = Connection::open(&db_path).unwrap();
        let status: i32 = conn
            .query_row(
                "SELECT status FROM runs WHERE run_pk = ?1",
                params![run_pk],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, RunStatus::CompleteWithCoverageLimits as i32);
    }

    #[test]
    fn run_counters_derive_status() {
        let clean = RunCounters::default();
        assert_eq!(clean.derive_status(false), RunStatus::Complete);
        assert_eq!(
            clean.derive_status(true),
            RunStatus::CompleteWithCoverageLimits
        );

        let dropped = RunCounters {
            dropped_findings: 1,
            ..Default::default()
        };
        assert_eq!(dropped.derive_status(false), RunStatus::Incomplete);
        assert_eq!(dropped.derive_status(true), RunStatus::Incomplete);

        let emit_fail = RunCounters {
            emit_failures: 1,
            ..Default::default()
        };
        assert_eq!(emit_fail.derive_status(false), RunStatus::Incomplete);
    }

    #[test]
    fn idempotent_root_insert() {
        let tmp = tempfile::tempdir().unwrap();
        let config1 = test_config(tmp.path());
        let producer1 = SqliteStoreProducer::open(config1).expect("first open");
        producer1.end_run(false).expect("end");

        // Open again with same root — should reuse existing root row.
        let config2 = test_config(tmp.path());
        let producer2 = SqliteStoreProducer::open(config2).expect("second open");
        producer2.end_run(false).expect("end");

        // Verify only one root exists.
        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM roots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // But two runs exist.
        let run_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(run_count, 2);
    }

    // ======================================================================
    // Step 3: Empty batch test
    // ======================================================================

    #[test]
    fn emit_empty_batch() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");

        let batch = FsFindingBatch {
            object_path: b"empty.rs",
            findings: &[],
        };
        producer
            .emit_fs_batch(batch)
            .expect("empty batch should succeed");
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let run: (i64, i64) = conn
            .query_row(
                "SELECT objects_scanned, findings_emitted FROM runs ORDER BY run_pk DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(run.0, 1, "objects_scanned should increment");
        assert_eq!(run.1, 0, "findings_emitted should stay 0");
    }

    // ======================================================================
    // Step 5: Additional writer tests
    // ======================================================================

    #[test]
    fn rule_cache_hit_avoids_db_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");

        let rec = FsFindingRecord {
            rule_id: 42,
            root_hint_start: 0,
            root_hint_end: 10,
            span_start: 0,
            span_end: 10,
            norm_hash: [0xDD; 32],
        };
        // Two batches with the same rule_id — fingerprint derived from rule_id
        // should be cached after the first batch.
        for path in &[b"a.rs" as &[u8], b"b.rs"] {
            let batch = FsFindingBatch {
                object_path: path,
                findings: &[rec],
            };
            producer.emit_fs_batch(batch).expect("emit");
        }
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let fp = derive_rule_fingerprint(42);
        let rule_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rules WHERE rule_fingerprint = ?1",
                params![fp.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rule_count, 1, "cache should prevent duplicate rule rows");
    }

    #[test]
    fn multiple_findings_per_batch() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");

        let findings: Vec<FsFindingRecord> = (0..5u8)
            .map(|i| FsFindingRecord {
                rule_id: u32::from(i),
                root_hint_start: 0,
                root_hint_end: 10,
                span_start: 0,
                span_end: 10,
                norm_hash: [i; 32],
            })
            .collect();
        let batch = FsFindingBatch {
            object_path: b"multi.rs",
            findings: &findings,
        };
        producer.emit_fs_batch(batch).expect("emit");
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let (scanned, emitted): (i64, i64) = conn
            .query_row(
                "SELECT objects_scanned, findings_emitted FROM runs ORDER BY run_pk DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(scanned, 1);
        assert_eq!(emitted, 5);

        let rule_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM rules", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rule_count, 5, "all 5 distinct rules should be created");
    }

    // ======================================================================
    // Step 8: Stress and edge-case tests
    // ======================================================================

    #[test]
    fn writer_large_batch_stress() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = SqliteStoreProducer::open(config).expect("open");

        let findings: Vec<FsFindingRecord> = (0..200u16)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..2].copy_from_slice(&i.to_le_bytes());
                FsFindingRecord {
                    rule_id: i as u32,
                    root_hint_start: 0,
                    root_hint_end: 10,
                    span_start: 0,
                    span_end: 10,
                    norm_hash: hash,
                }
            })
            .collect();
        let batch = FsFindingBatch {
            object_path: b"stress.rs",
            findings: &findings,
        };
        producer
            .emit_fs_batch(batch)
            .expect("large batch should succeed");
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let emitted: i64 = conn
            .query_row(
                "SELECT findings_emitted FROM runs ORDER BY run_pk DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emitted, 200);
    }

    #[test]
    fn writer_concurrent_emit_from_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let producer = std::sync::Arc::new(SqliteStoreProducer::open(config).expect("open"));

        let handles: Vec<_> = (0..8u8)
            .map(|t| {
                let p = std::sync::Arc::clone(&producer);
                std::thread::spawn(move || {
                    let rec = FsFindingRecord {
                        rule_id: u32::from(t),
                        root_hint_start: 0,
                        root_hint_end: 10,
                        span_start: 0,
                        span_end: 10,
                        norm_hash: [t; 32],
                    };
                    let path = format!("thread_{t}.rs");
                    let batch = FsFindingBatch {
                        object_path: path.as_bytes(),
                        findings: &[rec],
                    };
                    p.emit_fs_batch(batch).expect("concurrent emit");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
        producer.end_run(false).expect("end_run");

        let conn = Connection::open(tmp.path().join("findings.db")).unwrap();
        let emitted: i64 = conn
            .query_row(
                "SELECT findings_emitted FROM runs ORDER BY run_pk DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(emitted, 8, "all 8 thread batches should be recorded");
    }

    #[test]
    fn generate_run_id_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = generate_run_id();
            assert!(ids.insert(id), "duplicate run_id generated");
        }
    }

    /// Proves Bug 3 fix: `end_run` is callable through `dyn StoreProducer`.
    ///
    /// Before the fix, `end_run` was only an inherent method on the concrete
    /// `SqliteStoreProducer` type. Callers had to keep a separate
    /// `Arc<SqliteStoreProducer>` alongside `Arc<dyn StoreProducer>` to
    /// finalize a run. Now `end_run` is part of the trait, so any holder
    /// of `Arc<dyn StoreProducer>` can finalize the run.
    #[test]
    fn end_run_callable_through_dyn_store_producer() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let db_path = config.db_path.clone();
        let producer = SqliteStoreProducer::open(config).expect("open");
        let run_pk = producer.run_pk().expect("run_pk");

        // Erase the concrete type — only trait methods are available.
        let dyn_producer: Arc<dyn StoreProducer> = Arc::new(producer);

        let rec = FsFindingRecord {
            rule_id: 99,
            root_hint_start: 0,
            root_hint_end: 10,
            span_start: 0,
            span_end: 10,
            norm_hash: [0xFF; 32],
        };
        dyn_producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"trait_test.rs",
                findings: &[rec],
            })
            .expect("emit via trait");

        // Before the fix, this line would not compile because `end_run`
        // was not part of `StoreProducer`.
        dyn_producer.end_run(false).expect("end_run via trait");

        // Verify the run was actually finalized in the DB.
        let conn = Connection::open(&db_path).unwrap();
        let (status, ended_at): (i32, Option<i64>) = conn
            .query_row(
                "SELECT status, ended_at FROM runs WHERE run_pk = ?1",
                params![run_pk],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            status,
            RunStatus::Complete as i32,
            "run finalized via dyn StoreProducer must be Complete"
        );
        assert!(ended_at.is_some(), "ended_at must be set after end_run");
    }

    #[test]
    fn generate_run_id_never_all_zeros() {
        for _ in 0..100 {
            let id = generate_run_id();
            assert_ne!(id, [0u8; 16], "run_id must never be all zeros");
        }
    }
}
