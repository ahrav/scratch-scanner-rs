//! Triage CRUD operations.
//!
//! Triage operates at two levels: **occurrence** (one specific finding)
//! and **secret** (all occurrences sharing a secret hash). When querying,
//! occurrence-level decisions take priority; secret-level acts as a
//! fallback. If neither exists, the finding is implicitly active.
//!
//! All writes increment a file-backed Lamport clock and record the new
//! clock value in the row, enabling last-writer-wins merge resolution
//! when syncing triage databases across machines.

use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use super::clock::TriageClock;
use super::schema::{configure_triage_connection, ensure_triage_schema};

/// Triage status codes (shared by occurrence and secret triage).
///
/// Stored as `i32` in SQLite. Unknown values are treated as un-triaged
/// (see [`TriageStatus::from_i32`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TriageStatus {
    /// Finding is live and should be reported / acted on.
    Active = 0,
    /// Temporarily hidden from output (e.g. during investigation).
    Suppressed = 1,
    /// Confirmed not a real secret — detector misfired.
    FalsePositive = 2,
    /// Real secret but risk is acknowledged and no action required.
    AcceptedRisk = 3,
}

impl TriageStatus {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Suppressed),
            2 => Some(Self::FalsePositive),
            3 => Some(Self::AcceptedRisk),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suppressed => "suppressed",
            Self::FalsePositive => "false_positive",
            Self::AcceptedRisk => "accepted_risk",
        }
    }
}

/// An occurrence-level triage record, as stored in `occurrence_triage`.
///
/// Returned by listing / query operations; not used for writes (those
/// take individual parameters).
#[derive(Clone, Debug)]
pub struct OccurrenceTriageRow {
    pub root_id: Vec<u8>,
    pub occurrence_id: Vec<u8>,
    pub status: i32,
    pub reason: Option<String>,
    pub updated_by: Option<String>,
    pub clock: i64,
    pub updated_at: i64,
}

/// A secret-level triage record, as stored in `secret_triage`.
///
/// Applies to every occurrence that shares this `secret_hash` unless
/// overridden by an occurrence-level decision.
#[derive(Clone, Debug)]
pub struct SecretTriageRow {
    pub root_id: Vec<u8>,
    pub secret_hash: Vec<u8>,
    pub status: i32,
    pub reason: Option<String>,
    pub updated_by: Option<String>,
    pub clock: i64,
    pub updated_at: i64,
}

/// Handle for performing triage operations on the triage database.
///
/// Owns a SQLite connection and a file-backed Lamport clock. Each write
/// increments the clock and embeds the new value in the row, so that
/// concurrent databases can be merged with last-writer-wins semantics
/// by comparing clock values.
///
/// Not `Clone` — the Lamport clock file is exclusively owned.
pub struct TriageStore {
    conn: Connection,
    clock: TriageClock,
}

impl TriageStore {
    /// Open or create the triage database and clock in `triage_dir`.
    pub fn open(triage_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(triage_dir)?;

        let db_path = triage_dir.join("triage.sqlite");
        let conn = Connection::open(&db_path)
            .map_err(|e| io::Error::other(format!("failed to open triage db: {e}")))?;
        configure_triage_connection(&conn)
            .map_err(|e| io::Error::other(format!("triage db pragma error: {e}")))?;
        ensure_triage_schema(&conn)
            .map_err(|e| io::Error::other(format!("triage schema error: {e}")))?;

        let clock = TriageClock::open(triage_dir)?;
        Ok(Self { conn, clock })
    }

    /// Set triage status for an occurrence (upsert).
    ///
    /// If a row already exists for `(root_id, occurrence_id)`, it is
    /// replaced entirely (status, reason, updated_by, clock, timestamp).
    pub fn set_occurrence_status(
        &mut self,
        root_id: &[u8; 32],
        occurrence_id: &[u8; 32],
        status: TriageStatus,
        reason: Option<&str>,
        updated_by: Option<&str>,
    ) -> io::Result<()> {
        let clock_val = self.clock.tick()? as i64;
        let now = epoch_ms();

        self.conn
            .execute(
                "INSERT INTO occurrence_triage (root_id, occurrence_id, status, reason, updated_by, clock, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (root_id, occurrence_id) DO UPDATE SET
                     status = excluded.status,
                     reason = excluded.reason,
                     updated_by = excluded.updated_by,
                     clock = excluded.clock,
                     updated_at = excluded.updated_at",
                params![
                    root_id.as_slice(),
                    occurrence_id.as_slice(),
                    status as i32,
                    reason,
                    updated_by,
                    clock_val,
                    now,
                ],
            )
            .map_err(|e| io::Error::other(format!("triage write failed: {e}")))?;

        Ok(())
    }

    /// Set triage status for a secret (upsert, applies to all occurrences).
    ///
    /// Acts as a fallback: individual occurrence-level decisions still
    /// take priority when queried via [`effective_status`](Self::effective_status).
    pub fn set_secret_status(
        &mut self,
        root_id: &[u8; 32],
        secret_hash: &[u8; 32],
        status: TriageStatus,
        reason: Option<&str>,
        updated_by: Option<&str>,
    ) -> io::Result<()> {
        let clock_val = self.clock.tick()? as i64;
        let now = epoch_ms();

        self.conn
            .execute(
                "INSERT INTO secret_triage (root_id, secret_hash, status, reason, updated_by, clock, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (root_id, secret_hash) DO UPDATE SET
                     status = excluded.status,
                     reason = excluded.reason,
                     updated_by = excluded.updated_by,
                     clock = excluded.clock,
                     updated_at = excluded.updated_at",
                params![
                    root_id.as_slice(),
                    secret_hash.as_slice(),
                    status as i32,
                    reason,
                    updated_by,
                    clock_val,
                    now,
                ],
            )
            .map_err(|e| io::Error::other(format!("triage write failed: {e}")))?;

        Ok(())
    }

    /// Get the effective triage status for an occurrence.
    ///
    /// Checks occurrence-level triage first, then falls back to secret-level.
    /// Returns `None` if no triage decision exists (implicitly active).
    pub fn effective_status(
        &self,
        root_id: &[u8; 32],
        occurrence_id: &[u8; 32],
        secret_hash: &[u8; 32],
    ) -> io::Result<Option<TriageStatus>> {
        // Occurrence-level takes priority.
        let occ: Option<i32> = self
            .conn
            .query_row(
                "SELECT status FROM occurrence_triage WHERE root_id = ?1 AND occurrence_id = ?2",
                params![root_id.as_slice(), occurrence_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| io::Error::other(format!("triage query failed: {e}")))?;

        if let Some(status) = occ {
            return Ok(TriageStatus::from_i32(status));
        }

        // Fall back to secret-level.
        let sec: Option<i32> = self
            .conn
            .query_row(
                "SELECT status FROM secret_triage WHERE root_id = ?1 AND secret_hash = ?2",
                params![root_id.as_slice(), secret_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| io::Error::other(format!("triage query failed: {e}")))?;

        Ok(sec.and_then(TriageStatus::from_i32))
    }

    /// List occurrence-level triage decisions for a root, up to `limit` rows.
    pub fn list_occurrence_triage(
        &self,
        root_id: &[u8; 32],
        limit: usize,
    ) -> io::Result<Vec<OccurrenceTriageRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT root_id, occurrence_id, status, reason, updated_by, clock, updated_at
                 FROM occurrence_triage WHERE root_id = ?1
                 ORDER BY updated_at DESC, clock DESC LIMIT ?2",
            )
            .map_err(|e| io::Error::other(format!("triage query failed: {e}")))?;

        let rows = stmt
            .query_map(params![root_id.as_slice(), limit as i64], |row| {
                Ok(OccurrenceTriageRow {
                    root_id: row.get(0)?,
                    occurrence_id: row.get(1)?,
                    status: row.get(2)?,
                    reason: row.get(3)?,
                    updated_by: row.get(4)?,
                    clock: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            })
            .map_err(|e| io::Error::other(format!("triage query failed: {e}")))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("triage row error: {e}")))
    }

    /// Reopen (set back to active) a previously triaged occurrence.
    pub fn reopen_occurrence(
        &mut self,
        root_id: &[u8; 32],
        occurrence_id: &[u8; 32],
        updated_by: Option<&str>,
    ) -> io::Result<()> {
        self.set_occurrence_status(
            root_id,
            occurrence_id,
            TriageStatus::Active,
            Some("reopened"),
            updated_by,
        )
    }
}

fn epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
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

    fn test_root() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_occ() -> [u8; 32] {
        [0xBB; 32]
    }

    fn test_secret() -> [u8; 32] {
        [0xCC; 32]
    }

    #[test]
    fn suppress_and_query_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        store
            .set_occurrence_status(
                &test_root(),
                &test_occ(),
                TriageStatus::Suppressed,
                Some("known test key"),
                Some("alice"),
            )
            .unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::Suppressed));
    }

    #[test]
    fn secret_triage_applies_as_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        // No occurrence-level triage, set secret-level.
        store
            .set_secret_status(
                &test_root(),
                &test_secret(),
                TriageStatus::FalsePositive,
                None,
                None,
            )
            .unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::FalsePositive));
    }

    #[test]
    fn occurrence_triage_overrides_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        store
            .set_secret_status(
                &test_root(),
                &test_secret(),
                TriageStatus::FalsePositive,
                None,
                None,
            )
            .unwrap();

        store
            .set_occurrence_status(
                &test_root(),
                &test_occ(),
                TriageStatus::AcceptedRisk,
                None,
                None,
            )
            .unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::AcceptedRisk));
    }

    #[test]
    fn no_triage_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = TriageStore::open(dir.path()).unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, None);
    }

    #[test]
    fn reopen_sets_active() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        store
            .set_occurrence_status(
                &test_root(),
                &test_occ(),
                TriageStatus::Suppressed,
                None,
                None,
            )
            .unwrap();

        store
            .reopen_occurrence(&test_root(), &test_occ(), Some("bob"))
            .unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::Active));
    }

    #[test]
    fn list_occurrence_triage_returns_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        let occ1 = [0x01; 32];
        let occ2 = [0x02; 32];
        store
            .set_occurrence_status(&test_root(), &occ1, TriageStatus::Suppressed, None, None)
            .unwrap();
        store
            .set_occurrence_status(&test_root(), &occ2, TriageStatus::FalsePositive, None, None)
            .unwrap();

        let rows = store.list_occurrence_triage(&test_root(), 100).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn upsert_updates_existing() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        store
            .set_occurrence_status(
                &test_root(),
                &test_occ(),
                TriageStatus::Suppressed,
                Some("first"),
                None,
            )
            .unwrap();

        store
            .set_occurrence_status(
                &test_root(),
                &test_occ(),
                TriageStatus::AcceptedRisk,
                Some("updated"),
                None,
            )
            .unwrap();

        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::AcceptedRisk));

        // Only one row should exist.
        let rows = store.list_occurrence_triage(&test_root(), 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("updated"));
    }

    // ======================================================================
    // Step 6: Triage persistence and isolation tests
    // ======================================================================

    #[test]
    fn triage_store_reopen_preserves_state() {
        let dir = tempfile::tempdir().unwrap();

        // Write a decision, then drop the store.
        {
            let mut store = TriageStore::open(dir.path()).unwrap();
            store
                .set_occurrence_status(
                    &test_root(),
                    &test_occ(),
                    TriageStatus::FalsePositive,
                    Some("test key"),
                    Some("alice"),
                )
                .unwrap();
        }

        // Reopen and verify the decision persisted.
        let store = TriageStore::open(dir.path()).unwrap();
        let status = store
            .effective_status(&test_root(), &test_occ(), &test_secret())
            .unwrap();
        assert_eq!(status, Some(TriageStatus::FalsePositive));

        let rows = store.list_occurrence_triage(&test_root(), 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("test key"));
        assert_eq!(rows[0].updated_by.as_deref(), Some("alice"));
    }

    #[test]
    fn triage_multiple_roots_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        let root_a = [0x01; 32];
        let root_b = [0x02; 32];
        let occ = [0xBB; 32];
        let secret = [0xCC; 32];

        // Same occurrence_id under different root_ids.
        store
            .set_occurrence_status(&root_a, &occ, TriageStatus::Suppressed, None, None)
            .unwrap();
        store
            .set_occurrence_status(&root_b, &occ, TriageStatus::AcceptedRisk, None, None)
            .unwrap();

        let status_a = store.effective_status(&root_a, &occ, &secret).unwrap();
        let status_b = store.effective_status(&root_b, &occ, &secret).unwrap();

        assert_eq!(status_a, Some(TriageStatus::Suppressed));
        assert_eq!(status_b, Some(TriageStatus::AcceptedRisk));
    }

    #[test]
    fn triage_status_from_i32_out_of_range() {
        assert_eq!(TriageStatus::from_i32(-1), None);
        assert_eq!(TriageStatus::from_i32(4), None);
        assert_eq!(TriageStatus::from_i32(i32::MAX), None);
        assert_eq!(TriageStatus::from_i32(i32::MIN), None);

        // Valid range.
        assert_eq!(TriageStatus::from_i32(0), Some(TriageStatus::Active));
        assert_eq!(TriageStatus::from_i32(3), Some(TriageStatus::AcceptedRisk));
    }

    // ======================================================================
    // Step 8: Clock monotonicity across operations
    // ======================================================================

    #[test]
    fn triage_clock_monotonic_across_operations() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TriageStore::open(dir.path()).unwrap();

        let root = test_root();
        let occ1 = [0x01; 32];
        let occ2 = [0x02; 32];
        let occ3 = [0x03; 32];

        store
            .set_occurrence_status(&root, &occ1, TriageStatus::Suppressed, None, None)
            .unwrap();
        store
            .set_occurrence_status(&root, &occ2, TriageStatus::FalsePositive, None, None)
            .unwrap();
        store
            .set_occurrence_status(&root, &occ3, TriageStatus::AcceptedRisk, None, None)
            .unwrap();

        let rows = store.list_occurrence_triage(&root, 100).unwrap();
        assert_eq!(rows.len(), 3);

        // Clock values should be strictly increasing (1, 2, 3).
        let clocks: Vec<i64> = rows.iter().map(|r| r.clock).collect();
        // Rows are ordered by updated_at DESC, so clocks should be descending.
        for window in clocks.windows(2) {
            assert!(
                window[0] > window[1],
                "clocks must be strictly decreasing in list order: {clocks:?}"
            );
        }
    }
}
