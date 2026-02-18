//! SQLite read-path queries for CLI store commands.
//!
//! These queries back the `store list-runs`, `store list-findings`,
//! `store diff`, and `store list-secrets` CLI subcommands. They read
//! from the tables defined in [`super::schema`] (`runs`, `roots`,
//! `occurrences`, `observations`, `rules`, `secrets`).
//!
//! All functions take a shared `&Connection` (read-only is sufficient)
//! and return owned result types that are ready for display formatting
//! in [`crate::unified::orchestrator::run_store_command`].
//!
//! # Run identification
//!
//! Runs are stored with a 16-byte binary `run_id`. The CLI accepts
//! hex prefixes for convenience; [`resolve_run_pk`] handles prefix
//! matching (exact match for full 16 bytes, `hex(run_id) LIKE` for
//! shorter prefixes).

use rusqlite::{params, Connection};

/// One row from the `runs` table, joined with `roots` for display name.
///
/// Fields are pre-formatted for CLI output: `run_id` is hex-encoded,
/// timestamps are raw epoch milliseconds (formatted by the caller).
/// `status` uses the integer codes from [`super::writer::RunStatus`]:
/// 0 = in-progress, 1 = complete, 2 = complete-with-coverage-limits,
/// 3 = incomplete, 4 = failed.
#[derive(Clone, Debug)]
pub struct RunSummary {
    pub run_pk: i64,
    pub run_id_hex: String,
    pub root_display: Option<String>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: i32,
    pub findings_emitted: i64,
    pub objects_scanned: i64,
}

/// A single finding (occurrence) with rule and secret context joined in.
///
/// Represents one row from the `occurrences` table joined with `rules`
/// (for the human-readable rule name) and `secrets` (for the hash).
/// Byte offsets are relative to the scanned object, not the source file.
#[derive(Clone, Debug)]
pub struct FindingRow {
    pub occurrence_id_hex: String,
    pub object_path: String,
    pub rule_name: String,
    pub start_byte: i64,
    pub end_byte: i64,
    pub secret_hash_hex: String,
    /// Additive confidence score from gate signals (0–10 for Phase 1).
    pub confidence_score: i8,
}

/// Set-difference result of comparing two runs by their observations.
///
/// The comparison key is `occ_pk` (occurrence primary key): a finding is
/// "new" if its `occ_pk` appears in run B but not run A, "resolved" if
/// it appears in A but not B, and "unchanged" if present in both.
#[derive(Clone, Debug, Default)]
pub struct DiffResult {
    pub new_findings: Vec<FindingRow>,
    pub resolved_findings: Vec<FindingRow>,
    pub unchanged_count: i64,
}

/// Aggregate stats for a unique secret (keyed by `secret_hash`).
///
/// `first_seen_run` / `last_seen_run` are `run_pk` values, not run IDs.
/// `status` mirrors the triage status from the `secrets` table.
#[derive(Clone, Debug)]
pub struct SecretSummary {
    pub secret_hash_hex: String,
    pub occurrence_count: i64,
    pub first_seen_run: i64,
    pub last_seen_run: i64,
    pub status: i32,
}

/// List runs ordered by `started_at DESC`, optionally filtered by status code.
///
/// Joins `roots` to include the human-readable `display_name`.
/// Returns at most `limit` rows.
pub fn list_runs(
    conn: &Connection,
    status_filter: Option<i32>,
    limit: usize,
) -> rusqlite::Result<Vec<RunSummary>> {
    let mut stmt = if let Some(status) = status_filter {
        let mut s = conn.prepare(
            "SELECT r.run_pk, r.run_id, ro.display_name, r.started_at, r.ended_at,
                    r.status, r.findings_emitted, r.objects_scanned
             FROM runs r
             JOIN roots ro ON ro.root_pk = r.root_pk
             WHERE r.status = ?1
             ORDER BY r.started_at DESC
             LIMIT ?2",
        )?;
        let rows = s.query_map(params![status, limit as i64], map_run_row)?;
        return rows.collect();
    } else {
        conn.prepare(
            "SELECT r.run_pk, r.run_id, ro.display_name, r.started_at, r.ended_at,
                    r.status, r.findings_emitted, r.objects_scanned
             FROM runs r
             JOIN roots ro ON ro.root_pk = r.root_pk
             ORDER BY r.started_at DESC
             LIMIT ?1",
        )?
    };

    let rows = stmt.query_map(params![limit as i64], map_run_row)?;
    rows.collect()
}

fn map_run_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RunSummary> {
    let run_id: Vec<u8> = row.get(1)?;
    Ok(RunSummary {
        run_pk: row.get(0)?,
        run_id_hex: hex_encode(&run_id),
        root_display: row.get(2)?,
        started_at: row.get(3)?,
        ended_at: row.get(4)?,
        status: row.get(5)?,
        findings_emitted: row.get(6)?,
        objects_scanned: row.get(7)?,
    })
}

/// List findings for a given run, with optional LIKE filters on rule name and path.
///
/// Filters use SQL `LIKE '%pattern%'` (substring match, case-insensitive for ASCII
/// per SQLite default).
/// Results are ordered by `(object_path, start_byte)` for stable output.
pub fn list_findings(
    conn: &Connection,
    run_pk: i64,
    rule_filter: Option<&str>,
    path_filter: Option<&str>,
    limit: usize,
) -> rusqlite::Result<Vec<FindingRow>> {
    let mut sql = String::from(
        "SELECT o.occurrence_id, o.object_path, ru.rule_name, o.start_byte, o.end_byte,
                s.secret_hash, o.confidence_score
         FROM observations ob
         JOIN occurrences o  ON o.occ_pk = ob.occ_pk
         JOIN rules ru       ON ru.rule_pk = o.rule_pk
         JOIN secrets s      ON s.secret_pk = o.secret_pk
         WHERE ob.run_pk = ?1",
    );

    if rule_filter.is_some() {
        sql.push_str(" AND ru.rule_name LIKE ?2");
    }
    if path_filter.is_some() {
        let param_idx = if rule_filter.is_some() { "?3" } else { "?2" };
        sql.push_str(&format!(" AND o.object_path LIKE {param_idx}"));
    }
    sql.push_str(" ORDER BY o.object_path, o.start_byte");

    // Determine the next parameter index for LIMIT.
    let mut next_param = 2;
    if rule_filter.is_some() {
        next_param += 1;
    }
    if path_filter.is_some() {
        next_param += 1;
    }
    sql.push_str(&format!(" LIMIT ?{next_param}"));

    let mut stmt = conn.prepare(&sql)?;
    let limit_val = limit as i64;

    let rows = match (rule_filter, path_filter) {
        (Some(rule), Some(path)) => {
            let rule_pat = format!("%{rule}%");
            let path_pat = format!("%{path}%");
            stmt.query_map(
                params![run_pk, rule_pat, path_pat, limit_val],
                map_finding_row,
            )?
        }
        (Some(rule), None) => {
            let rule_pat = format!("%{rule}%");
            stmt.query_map(params![run_pk, rule_pat, limit_val], map_finding_row)?
        }
        (None, Some(path)) => {
            let path_pat = format!("%{path}%");
            stmt.query_map(params![run_pk, path_pat, limit_val], map_finding_row)?
        }
        (None, None) => stmt.query_map(params![run_pk, limit_val], map_finding_row)?,
    };

    rows.collect()
}

fn map_finding_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRow> {
    let occ_id: Vec<u8> = row.get(0)?;
    let secret: Vec<u8> = row.get(5)?;
    let raw_score: i64 = row.get(6)?;
    debug_assert!(
        i8::try_from(raw_score).is_ok(),
        "confidence_score out of i8 range in DB: {raw_score}"
    );
    Ok(FindingRow {
        occurrence_id_hex: hex_encode(&occ_id),
        object_path: row.get(1)?,
        rule_name: row.get(2)?,
        start_byte: row.get(3)?,
        end_byte: row.get(4)?,
        secret_hash_hex: hex_encode(&secret),
        confidence_score: i8::try_from(raw_score).unwrap_or(0),
    })
}

/// Compute a set-difference between two runs on their `occ_pk` sets.
///
/// "New" = in `run_b_pk` but not `run_a_pk`.
/// "Resolved" = in `run_a_pk` but not `run_b_pk`.
/// "Unchanged" = present in both (counted, not returned in full).
///
/// The comparison uses `observations` (the run-to-occurrence join table),
/// so only findings actually observed in each run participate.
///
/// When `limit` is `Some(n)`, at most `n` rows are returned for each of the
/// "new" and "resolved" sets. Pass `None` for an unbounded result.
pub fn diff_runs(
    conn: &Connection,
    run_a_pk: i64,
    run_b_pk: i64,
    limit: Option<usize>,
) -> rusqlite::Result<DiffResult> {
    let limit_clause = match limit {
        Some(_) => " LIMIT ?3",
        None => "",
    };

    let new_sql = format!(
        "SELECT o.occurrence_id, o.object_path, ru.rule_name, o.start_byte, o.end_byte,
                s.secret_hash, o.confidence_score
         FROM observations ob
         JOIN occurrences o  ON o.occ_pk = ob.occ_pk
         JOIN rules ru       ON ru.rule_pk = o.rule_pk
         JOIN secrets s      ON s.secret_pk = o.secret_pk
         WHERE ob.run_pk = ?1
           AND NOT EXISTS (
             SELECT 1 FROM observations oa WHERE oa.run_pk = ?2 AND oa.occ_pk = ob.occ_pk
           ){limit_clause}"
    );

    let new_findings: Vec<FindingRow> = if let Some(n) = limit {
        conn.prepare(&new_sql)?
            .query_map(params![run_b_pk, run_a_pk, n as i64], map_finding_row)?
            .collect::<rusqlite::Result<_>>()?
    } else {
        conn.prepare(&new_sql)?
            .query_map(params![run_b_pk, run_a_pk], map_finding_row)?
            .collect::<rusqlite::Result<_>>()?
    };

    let resolved_findings: Vec<FindingRow> = if let Some(n) = limit {
        conn.prepare(&new_sql)?
            .query_map(params![run_a_pk, run_b_pk, n as i64], map_finding_row)?
            .collect::<rusqlite::Result<_>>()?
    } else {
        conn.prepare(&new_sql)?
            .query_map(params![run_a_pk, run_b_pk], map_finding_row)?
            .collect::<rusqlite::Result<_>>()?
    };

    // Unchanged count.
    let unchanged_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM observations ob1
         WHERE ob1.run_pk = ?1
           AND EXISTS (SELECT 1 FROM observations ob2 WHERE ob2.run_pk = ?2 AND ob2.occ_pk = ob1.occ_pk)",
        params![run_a_pk, run_b_pk],
        |row| row.get(0),
    )?;

    Ok(DiffResult {
        new_findings,
        resolved_findings,
        unchanged_count,
    })
}

/// List unique secrets ordered by occurrence count (descending).
///
/// Optionally filtered by triage `status`. Returns pre-aggregated
/// data from the `secrets` table (no joins needed).
pub fn list_secrets(
    conn: &Connection,
    status_filter: Option<i32>,
    limit: usize,
) -> rusqlite::Result<Vec<SecretSummary>> {
    if let Some(status) = status_filter {
        let mut stmt = conn.prepare(
            "SELECT secret_hash, occurrence_count, first_seen_run, last_seen_run, status
             FROM secrets WHERE status = ?1
             ORDER BY occurrence_count DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![status, limit as i64], map_secret_row)?;
        return rows.collect();
    }

    let mut stmt = conn.prepare(
        "SELECT secret_hash, occurrence_count, first_seen_run, last_seen_run, status
         FROM secrets
         ORDER BY occurrence_count DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], map_secret_row)?;
    rows.collect()
}

fn map_secret_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretSummary> {
    let hash: Vec<u8> = row.get(0)?;
    Ok(SecretSummary {
        secret_hash_hex: hex_encode(&hash),
        occurrence_count: row.get(1)?,
        first_seen_run: row.get(2)?,
        last_seen_run: row.get(3)?,
        status: row.get(4)?,
    })
}

/// Resolve a `run_pk` from a hex-encoded `run_id` prefix.
///
/// Supports two modes:
/// - **Exact match** (32 hex chars = full 16-byte run_id): binary equality.
/// - **Prefix match** (< 32 hex chars): `hex(run_id) LIKE 'PREFIX%'`.
///
/// Returns `Ok(None)` if the prefix is malformed (odd length, non-hex)
/// or no run matches.
pub fn resolve_run_pk(conn: &Connection, hex_prefix: &str) -> rusqlite::Result<Option<i64>> {
    let bytes = hex_decode(hex_prefix);
    if bytes.is_empty() {
        return Ok(None);
    }

    // For exact match (full 16-byte run_id).
    if bytes.len() == 16 {
        return conn
            .query_row(
                "SELECT run_pk FROM runs WHERE run_id = ?1",
                params![bytes],
                |row| row.get(0),
            )
            .optional();
    }

    // Prefix match: use hex LIKE on the stored blob.
    let like_pattern = format!("{}%", hex_prefix.to_lowercase());
    conn.query_row(
        "SELECT run_pk FROM runs WHERE hex(run_id) LIKE ?1",
        params![like_pattern.to_uppercase()],
        |row| row.get(0),
    )
    .optional()
}

// ============================================================================
// Hex encoding helpers (no external dependency)
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return Vec::new(),
        }
    }
    bytes
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> rusqlite::Result<Option<T>>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> rusqlite::Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::db::schema::{configure_connection, ensure_schema};

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        configure_connection(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    fn insert_test_root(conn: &Connection) -> i64 {
        let root_id: [u8; 32] = [0xAA; 32];
        conn.execute(
            "INSERT INTO roots (root_id, root_kind, identity_scheme, canonical_identity, display_name)
             VALUES (?1, 2, 'fs_v1', X'AA', 'test-project')",
            params![root_id.as_slice()],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn insert_test_run(conn: &Connection, root_pk: i64, run_id: &[u8; 16]) -> i64 {
        conn.execute(
            "INSERT INTO runs (run_id, root_pk, id_hash_mode, started_at, status, findings_emitted, objects_scanned)
             VALUES (?1, ?2, 1, 1000, 1, 0, 0)",
            params![run_id.as_slice(), root_pk],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn list_runs_returns_inserted_runs() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        insert_test_run(&conn, root_pk, &[1; 16]);
        insert_test_run(&conn, root_pk, &[2; 16]);

        let runs = list_runs(&conn, None, 100).unwrap();
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn list_runs_filters_by_status() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        // Update status to Incomplete.
        conn.execute(
            "UPDATE runs SET status = 3 WHERE run_pk = ?1",
            params![run_pk],
        )
        .unwrap();

        let complete = list_runs(&conn, Some(1), 100).unwrap();
        assert_eq!(complete.len(), 0);

        let incomplete = list_runs(&conn, Some(3), 100).unwrap();
        assert_eq!(incomplete.len(), 1);
    }

    #[test]
    fn resolve_run_pk_by_hex() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let run_pk = insert_test_run(&conn, root_pk, &run_id);

        // Full hex match.
        let found = resolve_run_pk(&conn, "0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(found, Some(run_pk));

        // Prefix match.
        let found = resolve_run_pk(&conn, "01020304").unwrap();
        assert_eq!(found, Some(run_pk));

        // No match.
        let found = resolve_run_pk(&conn, "ff000000").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn hex_encode_roundtrip() {
        let bytes = vec![0x01, 0xAB, 0xCD, 0xEF];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "01abcdef");
        let decoded = hex_decode(&hex);
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn hex_decode_invalid() {
        assert!(hex_decode("zz").is_empty());
        assert!(hex_decode("abc").is_empty()); // Odd length.
    }

    /// Insert a complete finding across all tables using direct SQL.
    ///
    /// The writer's `emit_fs_batch` only resolves rules today, so query tests
    /// must populate occurrences/secrets/paths/observations manually.
    #[allow(clippy::too_many_arguments)]
    fn insert_test_finding(
        conn: &Connection,
        run_pk: i64,
        root_pk: i64,
        occurrence_id: &[u8; 32],
        rule_fingerprint: &[u8; 32],
        rule_name: &str,
        secret_hash: &[u8; 32],
        path_id: &[u8; 32],
        object_path: &str,
        start_byte: i64,
        end_byte: i64,
    ) -> i64 {
        conn.execute(
            "INSERT OR IGNORE INTO rules (rule_fingerprint, rule_id, rule_name) VALUES (?1, ?2, ?3)",
            params![rule_fingerprint.as_slice(), 1i64, rule_name],
        )
        .unwrap();
        let rule_pk: i64 = conn
            .query_row(
                "SELECT rule_pk FROM rules WHERE rule_fingerprint = ?1",
                params![rule_fingerprint.as_slice()],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT OR IGNORE INTO secrets (secret_hash, secret_len_bucket, first_seen_run, last_seen_run, occurrence_count, status)
             VALUES (?1, 0, ?2, ?2, 1, 0)",
            params![secret_hash.as_slice(), run_pk],
        )
        .unwrap();
        let secret_pk: i64 = conn
            .query_row(
                "SELECT secret_pk FROM secrets WHERE secret_hash = ?1",
                params![secret_hash.as_slice()],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT OR IGNORE INTO paths (path_id, root_pk, canonical_path) VALUES (?1, ?2, ?3)",
            params![path_id.as_slice(), root_pk, object_path],
        )
        .unwrap();
        let path_pk: i64 = conn
            .query_row(
                "SELECT path_pk FROM paths WHERE path_id = ?1",
                params![path_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT OR IGNORE INTO occurrences (occurrence_id, root_pk, path_pk, rule_pk, secret_pk, start_byte, end_byte, object_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                occurrence_id.as_slice(),
                root_pk,
                path_pk,
                rule_pk,
                secret_pk,
                start_byte,
                end_byte,
                object_path
            ],
        )
        .unwrap();
        let occ_pk: i64 = conn
            .query_row(
                "SELECT occ_pk FROM occurrences WHERE occurrence_id = ?1",
                params![occurrence_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT OR IGNORE INTO observations (run_pk, occ_pk, batch_seqno) VALUES (?1, ?2, 1)",
            params![run_pk, occ_pk],
        )
        .unwrap();

        occ_pk
    }

    /// Convenience wrapper: derives all byte arrays from a single `idx` byte.
    fn insert_finding_simple(conn: &Connection, run_pk: i64, root_pk: i64, idx: u8) -> i64 {
        let occurrence_id = [idx; 32];
        let rule_fingerprint = [idx; 32];
        let rule_name = format!("test_rule_{idx}");
        let secret_hash = [idx.wrapping_add(0x80); 32];
        let path_id = [idx.wrapping_add(0x40); 32];
        let object_path = format!("src/file_{idx}.rs");
        insert_test_finding(
            conn,
            run_pk,
            root_pk,
            &occurrence_id,
            &rule_fingerprint,
            &rule_name,
            &secret_hash,
            &path_id,
            &object_path,
            i64::from(idx) * 100,
            i64::from(idx) * 100 + 50,
        )
    }

    #[test]
    fn list_secrets_empty_db() {
        let conn = setup_db();
        let secrets = list_secrets(&conn, None, 100).unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    fn diff_runs_empty() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_a = insert_test_run(&conn, root_pk, &[1; 16]);
        let run_b = insert_test_run(&conn, root_pk, &[2; 16]);

        let diff = diff_runs(&conn, run_a, run_b, None).unwrap();
        assert!(diff.new_findings.is_empty());
        assert!(diff.resolved_findings.is_empty());
        assert_eq!(diff.unchanged_count, 0);
    }

    // ======================================================================
    // Step 2: Critical query tests with populated data
    // ======================================================================

    #[test]
    fn list_findings_returns_populated_findings() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        insert_finding_simple(&conn, run_pk, root_pk, 1);

        let findings = list_findings(&conn, run_pk, None, None, 100).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "test_rule_1");
        assert_eq!(findings[0].object_path, "src/file_1.rs");
        assert_eq!(findings[0].start_byte, 100);
        assert_eq!(findings[0].end_byte, 150);
        // Verify hex encoding of occurrence_id and secret_hash.
        assert_eq!(findings[0].occurrence_id_hex, hex_encode(&[1u8; 32]));
        assert_eq!(
            findings[0].secret_hash_hex,
            hex_encode(&[1u8.wrapping_add(0x80); 32])
        );
    }

    #[test]
    fn list_findings_with_rule_filter() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        insert_finding_simple(&conn, run_pk, root_pk, 1);
        insert_finding_simple(&conn, run_pk, root_pk, 2);

        let filtered = list_findings(&conn, run_pk, Some("rule_1"), None, 100).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_name, "test_rule_1");
    }

    #[test]
    fn list_findings_with_path_filter() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        insert_finding_simple(&conn, run_pk, root_pk, 1);
        insert_finding_simple(&conn, run_pk, root_pk, 2);

        let filtered = list_findings(&conn, run_pk, None, Some("file_2"), 100).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].object_path, "src/file_2.rs");
    }

    #[test]
    fn list_findings_with_both_filters() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        insert_finding_simple(&conn, run_pk, root_pk, 1);
        insert_finding_simple(&conn, run_pk, root_pk, 2);
        insert_finding_simple(&conn, run_pk, root_pk, 3);

        // Match both rule and path for idx=2.
        let filtered = list_findings(&conn, run_pk, Some("rule_2"), Some("file_2"), 100).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_name, "test_rule_2");
        assert_eq!(filtered[0].object_path, "src/file_2.rs");

        // Rule matches idx=1 but path matches idx=2 — no overlap.
        let empty = list_findings(&conn, run_pk, Some("rule_1"), Some("file_2"), 100).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn diff_runs_with_new_and_resolved_findings() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_a = insert_test_run(&conn, root_pk, &[1; 16]);
        let run_b = insert_test_run(&conn, root_pk, &[2; 16]);

        // Finding 1: only in run A (resolved).
        insert_finding_simple(&conn, run_a, root_pk, 1);
        // Finding 2: only in run B (new).
        insert_finding_simple(&conn, run_b, root_pk, 2);
        // Finding 3: in both runs (unchanged).
        let occ_pk_3 = insert_finding_simple(&conn, run_a, root_pk, 3);
        conn.execute(
            "INSERT OR IGNORE INTO observations (run_pk, occ_pk, batch_seqno) VALUES (?1, ?2, 1)",
            params![run_b, occ_pk_3],
        )
        .unwrap();

        let diff = diff_runs(&conn, run_a, run_b, None).unwrap();
        assert_eq!(diff.new_findings.len(), 1, "one new finding in run B");
        assert_eq!(diff.resolved_findings.len(), 1, "one resolved from run A");
        assert_eq!(diff.unchanged_count, 1, "one unchanged across both");
        assert_eq!(diff.new_findings[0].rule_name, "test_rule_2");
        assert_eq!(diff.resolved_findings[0].rule_name, "test_rule_1");
    }

    #[test]
    fn list_secrets_with_populated_data() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        insert_finding_simple(&conn, run_pk, root_pk, 1);
        insert_finding_simple(&conn, run_pk, root_pk, 2);

        // Bump occurrence_count on the first secret so we can verify ordering.
        conn.execute(
            "UPDATE secrets SET occurrence_count = 5 WHERE secret_hash = ?1",
            params![[1u8.wrapping_add(0x80); 32].as_slice()],
        )
        .unwrap();

        let secrets = list_secrets(&conn, None, 100).unwrap();
        assert_eq!(secrets.len(), 2);
        // ORDER BY occurrence_count DESC — secret with count=5 comes first.
        assert_eq!(secrets[0].occurrence_count, 5);
        assert_eq!(secrets[1].occurrence_count, 1);
    }

    #[test]
    fn resolve_run_pk_ambiguous_prefix() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        // Two runs whose hex starts with "AA".
        let run_a = insert_test_run(&conn, root_pk, &[0xAA; 16]);
        let run_b = insert_test_run(
            &conn,
            root_pk,
            &[0xAA, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        // Prefix "AA" matches both — query_row returns the first match.
        let found = resolve_run_pk(&conn, "AA").unwrap();
        assert!(found.is_some(), "ambiguous prefix should still return a pk");
        let pk = found.unwrap();
        assert!(pk == run_a || pk == run_b);
    }

    // ======================================================================
    // Step 4: Additional query tests
    // ======================================================================

    #[test]
    fn list_findings_ordered_by_path_and_offset() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);

        // Insert findings with different paths/offsets to verify ordering.
        // idx=3: path "src/file_3.rs", start_byte=300
        insert_finding_simple(&conn, run_pk, root_pk, 3);
        // idx=1: path "src/file_1.rs", start_byte=100
        insert_finding_simple(&conn, run_pk, root_pk, 1);
        // idx=2: path "src/file_2.rs", start_byte=200
        insert_finding_simple(&conn, run_pk, root_pk, 2);

        let findings = list_findings(&conn, run_pk, None, None, 100).unwrap();
        assert_eq!(findings.len(), 3);
        // ORDER BY (object_path, start_byte) → file_1, file_2, file_3.
        assert_eq!(findings[0].object_path, "src/file_1.rs");
        assert_eq!(findings[1].object_path, "src/file_2.rs");
        assert_eq!(findings[2].object_path, "src/file_3.rs");
    }

    #[test]
    fn resolve_run_pk_case_insensitive() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_id: [u8; 16] = [0xAB, 0xCD, 0xEF, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let run_pk = insert_test_run(&conn, root_pk, &run_id);

        // Mixed-case prefix — code does `.to_uppercase()` before LIKE.
        let found = resolve_run_pk(&conn, "AbCdEf12").unwrap();
        assert_eq!(found, Some(run_pk));
    }

    #[test]
    fn hex_decode_edge_cases() {
        // Empty string → empty vec.
        assert!(hex_decode("").is_empty());
        // Whitespace-only → trimmed to empty → empty vec.
        assert!(hex_decode("   ").is_empty());
        // Leading/trailing whitespace trimmed before decoding.
        assert_eq!(hex_decode(" 01ab "), vec![0x01, 0xAB]);
    }

    #[test]
    fn list_findings_respects_limit() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_pk = insert_test_run(&conn, root_pk, &[1; 16]);
        for idx in 1..=5u8 {
            insert_finding_simple(&conn, run_pk, root_pk, idx);
        }

        let limited = list_findings(&conn, run_pk, None, None, 2).unwrap();
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn diff_runs_with_only_unchanged() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        let run_a = insert_test_run(&conn, root_pk, &[1; 16]);
        let run_b = insert_test_run(&conn, root_pk, &[2; 16]);

        // Same finding observed in both runs.
        let occ_pk = insert_finding_simple(&conn, run_a, root_pk, 1);
        conn.execute(
            "INSERT OR IGNORE INTO observations (run_pk, occ_pk, batch_seqno) VALUES (?1, ?2, 1)",
            params![run_b, occ_pk],
        )
        .unwrap();

        let diff = diff_runs(&conn, run_a, run_b, None).unwrap();
        assert!(diff.new_findings.is_empty());
        assert!(diff.resolved_findings.is_empty());
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn list_runs_limit_respected() {
        let conn = setup_db();
        let root_pk = insert_test_root(&conn);
        for i in 1..=5u8 {
            insert_test_run(&conn, root_pk, &[i; 16]);
        }

        let limited = list_runs(&conn, None, 2).unwrap();
        assert_eq!(limited.len(), 2);
    }
}
