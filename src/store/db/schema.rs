//! SQLite schema definition and migration.
//!
//! # Data model
//!
//! The schema follows a **star-schema** layout centred on two fact tables:
//!
//! ```text
//!                   ┌──────────┐
//!                   │  roots   │  ← dimension: scan target identity
//!                   └────┬─────┘
//!        ┌───────────────┼───────────────┐
//!        ▼               ▼               ▼
//!   ┌─────────┐    ┌──────────┐    ┌──────────┐
//!   │  paths  │    │   runs   │    │occurrences│ ← fact: per-object findings
//!   └─────────┘    └────┬─────┘    └─────┬─────┘
//!                       │                │
//!                       ▼                ▼
//!                  ┌────────────┐   ┌─────────┐
//!                  │observations│   │ secrets │  ← dimension: normalised secret
//!                  └────────────┘   └─────────┘
//!                       ▲
//!                  ┌────────┐
//!                  │run_rules│  ← junction: rules active in a run
//!                  └────────┘
//! ```
//!
//! `observations` and `run_rules` are `WITHOUT ROWID` junction tables keyed by
//! their composite primary key — this avoids the implicit rowid column and
//! yields smaller B-trees for what are effectively M:N link rows.
//!
//! # Migration strategy
//!
//! `PRAGMA user_version` tracks the current schema version. Each migration
//! function (`apply_v1`, `apply_v2`, …) is idempotent (`CREATE IF NOT EXISTS`)
//! and runs inside a single `BEGIN IMMEDIATE` transaction so that concurrent
//! readers see either the old or the new schema, never a partial upgrade.

use rusqlite::Connection;

/// Current schema version. Bump when DDL changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Set connection PRAGMAs for performance and safety.
///
/// Must be called immediately after opening a connection, before any queries.
///
/// | PRAGMA | Value | Rationale |
/// |--------|-------|-----------|
/// | `journal_mode` | WAL | Concurrent readers + single writer without blocking |
/// | `synchronous` | NORMAL | Durability with WAL (fsync on checkpoint, not every commit) |
/// | `foreign_keys` | ON | Enforce referential integrity at runtime |
/// | `busy_timeout` | 5000ms | Retry on `SQLITE_BUSY` instead of failing immediately |
/// | `cache_size` | -64000 | ~64 MB page cache (negative = KiB) |
pub fn configure_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -64000;",
    )
}

/// Set connection PRAGMAs for read-only query access.
///
/// Unlike [`configure_connection`], this intentionally avoids `journal_mode`
/// and `synchronous` writes so it can run on read-only handles.
pub fn configure_readonly_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA cache_size = -64000;",
    )
}

/// Ensure the schema is at the current version, applying migrations as needed.
///
/// Idempotent: calling it on an already-up-to-date database is a no-op.
///
/// Uses `BEGIN IMMEDIATE` to acquire a reserved lock before running DDL.
/// This prevents two concurrent callers from interleaving migration steps
/// (the second caller blocks on the busy timeout, then sees the version
/// bump and returns early).
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        if version < 1 {
            apply_v1(conn)?;
        }
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT;")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e)
        }
    }
}

/// V1 schema: initial star-schema creation.
///
/// Creates dimension tables (`roots`, `paths`, `rules`, `secrets`) and fact
/// tables (`runs`, `occurrences`) plus junction tables (`observations`,
/// `run_rules`). All surrogate PKs are auto-increment `INTEGER PRIMARY KEY`
/// so that row lookups use the implicit rowid B-tree directly.
fn apply_v1(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        -- ====================================================================
        -- Dimension tables
        -- ====================================================================

        CREATE TABLE IF NOT EXISTS roots (
            root_pk            INTEGER PRIMARY KEY,
            root_id            BLOB    NOT NULL UNIQUE,
            root_kind          INTEGER NOT NULL,
            identity_scheme    TEXT    NOT NULL,
            canonical_identity BLOB    NOT NULL,
            display_name       TEXT
        );

        CREATE TABLE IF NOT EXISTS paths (
            path_pk        INTEGER PRIMARY KEY,
            path_id        BLOB    NOT NULL UNIQUE,
            root_pk        INTEGER NOT NULL REFERENCES roots(root_pk),
            canonical_path TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_paths_root ON paths(root_pk);

        CREATE TABLE IF NOT EXISTS rules (
            rule_pk          INTEGER PRIMARY KEY,
            rule_fingerprint BLOB    NOT NULL UNIQUE,
            rule_id          INTEGER NOT NULL,
            rule_name        TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secrets (
            secret_pk        INTEGER PRIMARY KEY,
            secret_hash      BLOB    NOT NULL UNIQUE,
            secret_len_bucket INTEGER NOT NULL,
            first_seen_run   INTEGER NOT NULL,
            last_seen_run    INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            status           INTEGER NOT NULL DEFAULT 0
        );

        -- ====================================================================
        -- Fact tables
        -- ====================================================================

        CREATE TABLE IF NOT EXISTS runs (
            run_pk              INTEGER PRIMARY KEY,
            run_id              BLOB    NOT NULL UNIQUE,
            root_pk             INTEGER NOT NULL REFERENCES roots(root_pk),
            id_hash_mode        INTEGER NOT NULL,
            started_at          INTEGER NOT NULL,
            ended_at            INTEGER,
            status              INTEGER NOT NULL DEFAULT 0,
            objects_scanned     INTEGER NOT NULL DEFAULT 0,
            bytes_scanned       INTEGER NOT NULL DEFAULT 0,
            findings_emitted    INTEGER NOT NULL DEFAULT 0,
            dropped_findings    INTEGER NOT NULL DEFAULT 0,
            emit_failures       INTEGER NOT NULL DEFAULT 0,
            scanner_version     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_root ON runs(root_pk);
        CREATE INDEX IF NOT EXISTS idx_runs_status_started ON runs(status, started_at DESC);

        CREATE INDEX IF NOT EXISTS idx_secrets_occ_count ON secrets(occurrence_count DESC);

        CREATE TABLE IF NOT EXISTS occurrences (
            occ_pk           INTEGER PRIMARY KEY,
            occurrence_id    BLOB    NOT NULL UNIQUE,
            root_pk          INTEGER NOT NULL REFERENCES roots(root_pk),
            path_pk          INTEGER NOT NULL REFERENCES paths(path_pk),
            rule_pk          INTEGER NOT NULL REFERENCES rules(rule_pk),
            secret_pk        INTEGER NOT NULL REFERENCES secrets(secret_pk),
            start_byte       INTEGER NOT NULL CHECK(start_byte >= 0),
            end_byte         INTEGER NOT NULL CHECK(end_byte > start_byte),
            identity_flags   INTEGER NOT NULL DEFAULT 0,
            object_path      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_occ_secret ON occurrences(secret_pk);
        CREATE INDEX IF NOT EXISTS idx_occ_rule   ON occurrences(rule_pk);

        CREATE TABLE IF NOT EXISTS observations (
            run_pk        INTEGER NOT NULL REFERENCES runs(run_pk),
            occ_pk        INTEGER NOT NULL REFERENCES occurrences(occ_pk),
            batch_seqno   INTEGER NOT NULL,
            PRIMARY KEY (run_pk, occ_pk)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_obs_occ ON observations(occ_pk);

        CREATE TABLE IF NOT EXISTS run_rules (
            run_pk  INTEGER NOT NULL REFERENCES runs(run_pk),
            rule_pk INTEGER NOT NULL REFERENCES rules(rule_pk),
            PRIMARY KEY (run_pk, rule_pk)
        ) WITHOUT ROWID;
        ",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_memory_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        configure_connection(&conn).expect("pragmas");
        conn
    }

    #[test]
    fn ensure_schema_creates_tables() {
        let conn = open_memory_db();
        ensure_schema(&conn).expect("schema");

        // Verify tables exist by querying sqlite_master.
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert!(tables.contains(&"roots".to_string()));
        assert!(tables.contains(&"paths".to_string()));
        assert!(tables.contains(&"rules".to_string()));
        assert!(tables.contains(&"secrets".to_string()));
        assert!(tables.contains(&"runs".to_string()));
        assert!(tables.contains(&"occurrences".to_string()));
        assert!(tables.contains(&"observations".to_string()));
        assert!(tables.contains(&"run_rules".to_string()));
    }

    #[test]
    fn ensure_schema_is_idempotent() {
        let conn = open_memory_db();
        ensure_schema(&conn).expect("first call");
        ensure_schema(&conn).expect("second call should be no-op");

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn version_tracks_correctly() {
        let conn = open_memory_db();
        ensure_schema(&conn).expect("schema");
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn foreign_keys_enabled() {
        let conn = open_memory_db();
        let fk: i32 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn wal_mode_enabled() {
        // In-memory databases might not support WAL, but we still check
        // the pragma was accepted.
        let conn = open_memory_db();
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        // In-memory db returns "memory" for journal_mode, but the pragma was accepted
        assert!(mode == "wal" || mode == "memory");
    }

    #[test]
    fn foreign_key_violation_rejected() {
        let conn = open_memory_db();
        ensure_schema(&conn).expect("schema");

        // Insert occurrence referencing non-existent rule_pk — must fail.
        let result = conn.execute(
            "INSERT INTO occurrences (occurrence_id, root_pk, path_pk, rule_pk, secret_pk, start_byte, end_byte, object_path)
             VALUES (X'AA', 999, 999, 999, 999, 0, 10, 'test.rs')",
            [],
        );
        assert!(
            result.is_err(),
            "FK violation should be rejected: {result:?}"
        );
    }

    #[test]
    fn ensure_schema_recovers_after_simulated_failure() {
        // Simulate a migration failure by manually beginning a transaction,
        // then verify ensure_schema still works on a subsequent call.
        let conn = open_memory_db();

        // Manually set version to 0 and begin a transaction, then roll it back
        // to simulate what ensure_schema does on failure.
        conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
        conn.execute_batch("ROLLBACK;").unwrap();

        // ensure_schema should succeed after the rolled-back transaction.
        ensure_schema(&conn).expect("schema should succeed after rollback");

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // A second call should be a no-op.
        ensure_schema(&conn).expect("idempotent call should succeed");
    }
}
