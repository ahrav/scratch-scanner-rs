//! Triage database DDL and connection setup.
//!
//! The triage database (`triage.sqlite`) is separate from the main findings
//! database so that user triage decisions survive `findings.db` deletion.
//!
//! WAL mode is used for concurrent read access.

use rusqlite::Connection;

/// Current triage schema version, tracked via `PRAGMA user_version`.
pub const TRIAGE_SCHEMA_VERSION: i32 = 1;

/// DDL statements for the triage schema.
const TRIAGE_DDL: &str = "
-- Occurrence-level triage decisions.
CREATE TABLE IF NOT EXISTS occurrence_triage (
    root_id        BLOB    NOT NULL,           -- 32 bytes
    occurrence_id  BLOB    NOT NULL,           -- 32 bytes
    status         INTEGER NOT NULL,           -- 0=active, 1=suppressed, 2=false_positive, 3=accepted_risk
    reason         TEXT,                       -- optional human note
    updated_by     TEXT,                       -- operator/user identity
    clock          INTEGER NOT NULL,           -- Lamport clock at time of write
    updated_at     INTEGER NOT NULL,           -- unix epoch ms
    PRIMARY KEY (root_id, occurrence_id)
) WITHOUT ROWID;

-- Secret-level triage decisions (applies to all occurrences of a secret).
CREATE TABLE IF NOT EXISTS secret_triage (
    root_id        BLOB    NOT NULL,           -- 32 bytes
    secret_hash    BLOB    NOT NULL,           -- 32 bytes
    status         INTEGER NOT NULL,           -- same status codes as occurrence_triage
    reason         TEXT,
    updated_by     TEXT,
    clock          INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (root_id, secret_hash)
) WITHOUT ROWID;
";

/// Configure connection pragmas for the triage database.
///
/// - **WAL** — allows concurrent readers while a write is in progress.
/// - **synchronous=NORMAL** — WAL integrity is maintained by the OS;
///   trades a tiny durability window for ~2× write throughput.
/// - **foreign_keys=ON** — enforces `REFERENCES` constraints.
/// - **busy_timeout=5000ms** — retries internally on `SQLITE_BUSY`
///   instead of returning an immediate error to the caller.
pub fn configure_triage_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(())
}

/// Ensure the triage schema is created. Idempotent.
///
/// Uses `BEGIN IMMEDIATE … COMMIT` to prevent interleaving with concurrent
/// callers and to guarantee atomicity: if DDL succeeds but the version
/// pragma fails, the entire migration is rolled back.
pub fn ensure_triage_schema(conn: &Connection) -> rusqlite::Result<()> {
    let current_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;

    if current_version >= TRIAGE_SCHEMA_VERSION {
        return Ok(());
    }

    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        conn.execute_batch(TRIAGE_DDL)?;
        conn.pragma_update(None, "user_version", TRIAGE_SCHEMA_VERSION)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        configure_triage_connection(&conn).unwrap();
        ensure_triage_schema(&conn).unwrap();
        // Second call should be a no-op.
        ensure_triage_schema(&conn).unwrap();

        let version: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, TRIAGE_SCHEMA_VERSION);
    }

    #[test]
    fn tables_exist_after_schema() {
        let conn = Connection::open_in_memory().unwrap();
        configure_triage_connection(&conn).unwrap();
        ensure_triage_schema(&conn).unwrap();

        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('occurrence_triage', 'secret_triage')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn schema_recovers_after_rolled_back_transaction() {
        let conn = Connection::open_in_memory().unwrap();
        configure_triage_connection(&conn).unwrap();

        // Simulate a rolled-back migration attempt.
        conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
        conn.execute_batch("ROLLBACK;").unwrap();

        // ensure_triage_schema should succeed after the rollback.
        ensure_triage_schema(&conn).unwrap();

        let version: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, TRIAGE_SCHEMA_VERSION);

        // Verify tables were actually created.
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('occurrence_triage', 'secret_triage')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn version_set_correctly_after_schema() {
        let conn = Connection::open_in_memory().unwrap();
        configure_triage_connection(&conn).unwrap();
        ensure_triage_schema(&conn).unwrap();

        let version: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, TRIAGE_SCHEMA_VERSION);

        // Second call is a no-op — version should remain the same.
        ensure_triage_schema(&conn).unwrap();
        let version2: i32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version2, TRIAGE_SCHEMA_VERSION);
    }
}
