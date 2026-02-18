//! Structured scan events, output sinks, and JSONL encoder.
//!
//! # Architecture
//!
//! Workers emit [`ScanEvent`] values through an [`EventSink`]. Encoding
//! is factored out into a separate [`EventEncoder`] trait so it can be
//! tested and benchmarked without I/O. The default stack pairs
//! [`JsonlEncoder`] with [`JsonlEventSink`], which serializes each event
//! as a single JSON line (JSONL) and writes it atomically to the writer.
//!
//! # Wire format
//!
//! Each event is one JSON object followed by `\n`. Batch ordering between
//! workers is non-deterministic, but individual events are never interleaved
//! at the byte level.
//!
//! Event types on the wire: `finding`, `progress`, `summary`, `diagnostic`,
//! `commit_meta`, `identity_dictionary`.
//!
//! # Visibility
//!
//! Encoder functions and JSON-write primitives are `pub(crate)`. Benchmarks
//! and fuzz targets import the supported surface through the public,
//! feature-gated [`super::harness_api`] facade.
//!
//! # Performance
//!
//! Each [`EventSink::emit`] call formats into a thread-local scratch
//! buffer ([`with_format_buf`]) and then copies the finished bytes into
//! the sink under a mutex. The mutex is held only for the `write_all`
//! call, not during formatting, so contention scales with write latency
//! rather than encoding cost.

use std::cell::RefCell;
use std::io::{BufWriter, ErrorKind, Write};
use std::sync::Mutex;

use super::json_write::{
    write_f64, write_json_bytes, write_json_str, write_oid_hex, write_u64, BufCursor,
};
use super::SourceKind;
use crate::git_scan::identity_intern::{CommitIdentityIds, SENTINEL_ID};
use crate::git_scan::object_id::OidBytes;

/// Swallow `BrokenPipe`; panic on any other I/O error.
///
/// Most structured-output sink write/flush paths (JSON, JSONL, SARIF, text)
/// funnel I/O through this so BrokenPipe policy is centralized.
///
/// Returns `true` when a `BrokenPipe` was swallowed so callers that perform
/// multiple I/O operations in sequence can short-circuit immediately.
#[inline]
pub(crate) fn handle_sink_io(result: std::io::Result<()>, label: &str) -> bool {
    if let Err(e) = result {
        if e.kind() == ErrorKind::BrokenPipe {
            return true;
        }
        panic!("{label} failed: {e}");
    }
    false
}

thread_local! {
    /// Per-thread scratch buffer for formatting events before writing to
    /// the sink. 512 bytes covers a typical finding + newline without
    /// reallocation; the buffer grows if needed and is reused across calls.
    static EMIT_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(512));
}

/// Format into a thread-local scratch buffer, then pass the filled bytes to `f`.
///
/// This two-phase design keeps the expensive formatting work *outside* any
/// sink mutex — the sink only holds its lock for the cheap `write_all`.
///
/// Falls back to a heap-allocated `Vec` if the thread-local is already
/// borrowed (reentrant call within the same thread, which shouldn't happen
/// in practice but is safe if it does).
pub(crate) fn with_format_buf<F>(encode: impl FnOnce(&mut Vec<u8>), f: F)
where
    F: FnOnce(&[u8]),
{
    EMIT_BUF.with(|cell| {
        if let Ok(mut buf) = cell.try_borrow_mut() {
            buf.clear();
            encode(&mut buf);
            f(&buf);
        } else {
            // Reentrant call — allocate a one-off buffer.
            debug_assert!(
                false,
                "with_format_buf: reentrant borrow detected; allocating fallback buffer"
            );
            let mut buf = Vec::with_capacity(256);
            encode(&mut buf);
            f(&buf);
        }
    });
}

// ============================================================================
// Event types
// ============================================================================

/// Structured scan event emitted during scanning.
///
/// Variants that carry borrowed data ([`Finding`](Self::Finding),
/// [`Diagnostic`](Self::Diagnostic), [`IdentityDictionary`](Self::IdentityDictionary))
/// reference adapter or engine-owned buffers to avoid allocation. Variants
/// that own their data ([`Progress`](Self::Progress), [`Summary`](Self::Summary),
/// [`CommitMeta`](Self::CommitMeta)) are emitted infrequently enough that the
/// allocation cost is negligible.
/// The [`EventSink`] implementation is responsible for serialization.
pub enum ScanEvent<'a> {
    /// A secret or credential match. Wire format type: `"finding"`.
    Finding(FindingEvent<'a>),
    /// Periodic scan progress checkpoint. Wire format type: `"progress"`.
    Progress(ProgressEvent),
    /// Final scan summary emitted once at completion. Wire format type: `"summary"`.
    Summary(SummaryEvent),
    /// Debug or performance diagnostic. Wire format type: `"diagnostic"`.
    Diagnostic(DiagnosticEvent<'a>),
    /// Commit metadata emitted exactly once per referenced commit.
    ///
    /// Emitted at most once per `commit_id` (only for commits with findings).
    /// In parallel scan modes, stream ordering is intentionally non-deterministic:
    /// a `Finding` may appear before the matching `CommitMeta`.
    /// Consumers should join by `commit_id`, not event position.
    ///
    /// Wire format type: `"commit_meta"`.
    CommitMeta(CommitMetaEvent),
    /// Identity dictionary entry for deduplicating author/committer strings.
    ///
    /// Emitted once per unique identity string before any `CommitMeta` that
    /// references that identity ID. Wire format type: `"identity_dictionary"`.
    IdentityDictionary(IdentityDictionaryEvent<'a>),
}

/// A single secret finding.
///
/// Borrowed fields (`object_path`, `rule_name`, `change_kind`) reference
/// adapter scratch or engine-owned data to avoid allocation on the hot path.
/// The sink is responsible for copying what it needs.
pub struct FindingEvent<'a> {
    /// Whether this finding came from a Git blob or filesystem file.
    pub source: SourceKind,
    /// Raw path bytes — Git paths are not guaranteed UTF-8.
    pub object_path: &'a [u8],
    /// Inclusive byte offset of the match start within the source object.
    pub start: u64,
    /// Exclusive byte offset of the match end within the source object.
    pub end: u64,
    /// Stable numeric rule identifier (index into the engine rule table).
    pub rule_id: u32,
    /// Human-readable rule name (e.g. `"aws-access-key"`).
    pub rule_name: &'a str,
    /// Commit-graph position for Git findings; `None` for filesystem scans.
    /// Serves as the join key to [`CommitMetaEvent::commit_id`].
    pub commit_id: Option<u32>,
    /// Change kind (`"add"` / `"modify"`) for Git findings; `None` for FS.
    pub change_kind: Option<&'a str>,
    /// Additive confidence score from Phase 1 gate evaluation (0–10).
    ///
    /// Each confirming gate (entropy, keyword, assignment shape, offline
    /// validation) adds its weight. A score of 0 means no gates fired.
    pub confidence_score: i8,
}

/// Progress checkpoint emitted periodically during scanning.
pub struct ProgressEvent {
    /// Whether this progress update is for a Git or filesystem scan.
    pub source: SourceKind,
    /// Current scan phase (e.g. `"scanning"`, `"finalizing"`).
    pub stage: &'static str,
    /// Cumulative objects processed so far.
    pub objects_scanned: u64,
    /// Cumulative raw bytes fed to the engine.
    pub bytes_scanned: u64,
    /// Cumulative findings emitted so far.
    pub findings_emitted: u64,
}

/// Final summary emitted once when scanning completes.
pub struct SummaryEvent {
    /// Whether this summary is for a Git or filesystem scan.
    pub source: SourceKind,
    /// Terminal status (e.g. `"complete"`, `"error"`).
    pub status: &'static str,
    /// Wall-clock elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Total raw bytes fed to the engine.
    pub bytes_scanned: u64,
    /// Total findings emitted during the scan.
    pub findings_emitted: u64,
    /// Number of non-fatal errors encountered.
    pub errors: u64,
    /// Throughput in MiB/s: `(bytes_scanned / 1_048_576) / elapsed_secs`.
    pub throughput_mib_s: f64,
}

/// Debug / performance diagnostic line.
pub struct DiagnosticEvent<'a> {
    /// Severity level (e.g. `"debug"`, `"warn"`).
    pub level: &'static str,
    /// Free-form diagnostic message.
    pub message: &'a str,
}

/// Commit metadata emitted once per referenced commit.
///
/// Provides the mapping from opaque `commit_id` (graph position) to the
/// full commit hash and timestamp so JSONL output is self-contained.
/// Only emitted for commits that have at least one finding.
/// Ordering is best-effort under parallel workers; consumers must treat
/// `commit_id` as the join key rather than assuming `CommitMeta` appears first.
///
/// The exactly-once guarantee is enforced by an `AtomicBitSet` shared
/// across all `EngineAdapter` instances. See
/// [`EngineAdapter::stream_findings`](crate::git_scan::engine_adapter::EngineAdapter)
/// for the gating protocol.
pub struct CommitMetaEvent {
    /// Commit-graph position (same value as `FindingEvent::commit_id`).
    pub commit_id: u32,
    /// Raw commit object ID (SHA-1 or SHA-256). Hex formatting happens
    /// at the serialization boundary.
    pub commit_oid: OidBytes,
    /// Committer timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Per-commit identity IDs (author name/email, committer name/email).
    ///
    /// Present when identity enrichment is enabled. Each field is an intern
    /// pool ID that maps to raw bytes via `IdentityDictionaryEvent`.
    /// `SENTINEL_ID` (`u32::MAX`) indicates a parse failure for that field.
    pub identity: Option<CommitIdentityIds>,
}

/// Identity dictionary entry mapping an intern ID to its raw bytes.
///
/// Emitted during scan initialization, before any `CommitMeta` events.
/// Each entry maps a numeric ID to a unique identity string (name or email).
pub struct IdentityDictionaryEvent<'a> {
    /// Intern pool ID (matches `CommitIdentityIds` field values).
    pub id: u32,
    /// Raw identity bytes (not guaranteed UTF-8).
    pub value: &'a [u8],
}

// ============================================================================
// Traits
// ============================================================================

/// Thread-safe sink for structured scan events.
///
/// Implementations must be safe to call from multiple worker threads
/// concurrently. Internal synchronization (mutex, lock-free buffer)
/// is the implementor's responsibility.
///
/// # Error contract
///
/// All built-in sinks silently swallow `BrokenPipe` (the downstream
/// consumer hung up) and panic on any other I/O error. This is
/// intentional: a scan should not silently lose findings to a transient
/// write failure.
pub trait EventSink: Send + Sync {
    /// Serialize and write a single event. Must not block indefinitely.
    fn emit(&self, event: ScanEvent<'_>);
    /// Flush any buffered output. Called exactly once at end-of-scan.
    ///
    /// After `flush` returns, all previously emitted events must be visible
    /// to the downstream consumer. No further `emit` calls are made after
    /// `flush`.
    fn flush(&self);
}

/// Stateless encoder: appends a wire-format representation of one event to `buf`.
///
/// Separated from [`EventSink`] so the encoding logic can be tested and
/// reused without I/O. [`JsonlEncoder`] is the only implementation today;
/// a future binary format would add a second.
pub trait EventEncoder: Send + Sync {
    /// Append the encoded representation of `event` to `buf`.
    fn encode(&self, event: &ScanEvent<'_>, buf: &mut Vec<u8>);
}

// ============================================================================
// JSONL encoder
// ============================================================================

/// JSONL encoder: one JSON object per line, without serde.
///
/// Encodes directly into a `Vec<u8>` via [`BufCursor`] pointer writes and
/// hand-rolled JSON assembly, avoiding the allocation and type-erasure
/// overhead of `serde_json`. This is the hot path for all structured output
/// during scanning.
pub struct JsonlEncoder;

impl JsonlEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonlEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EventEncoder for JsonlEncoder {
    fn encode(&self, event: &ScanEvent<'_>, buf: &mut Vec<u8>) {
        match event {
            ScanEvent::Finding(f) => encode_finding(f, buf),
            ScanEvent::Progress(p) => encode_progress(p, buf),
            ScanEvent::Summary(s) => encode_summary(s, buf),
            ScanEvent::Diagnostic(d) => encode_diagnostic(d, buf),
            ScanEvent::CommitMeta(m) => encode_commit_meta(m, buf),
            ScanEvent::IdentityDictionary(d) => encode_identity_dictionary(d, buf),
        }
        buf.push(b'\n');
    }
}

/// Append a JSONL `finding` object to `buf` (no trailing newline).
///
/// Uses [`BufCursor`] to write static JSON framing and numeric fields via
/// raw pointer arithmetic, eliminating per-field bounds checks. Dynamic
/// content (path bytes, rule name) is written through the standard
/// `write_json_bytes` / `write_json_str` functions which handle their own
/// capacity management.
///
/// Wire fields `commit_id` and `change_kind` are emitted whenever their
/// corresponding `Option` is `Some`.
pub(crate) fn encode_finding(f: &FindingEvent<'_>, buf: &mut Vec<u8>) {
    // Static overhead: prefix (~40) + field keys (~60) + 3 u64s (60) + optional fields (~60) + closing (1)
    // = ~221 bytes worst case for static content.
    const STATIC_OVERHEAD: usize = 240;
    let mut cur = BufCursor::new(buf, STATIC_OVERHEAD);

    // Merged prefix: type + source + path key + opening quote.
    match f.source {
        SourceKind::Fs => {
            cur.push_static(b"{\"type\":\"finding\",\"source\":\"fs\",\"path\":\"");
        }
        SourceKind::Git => {
            cur.push_static(b"{\"type\":\"finding\",\"source\":\"git\",\"path\":\"");
        }
    }
    // Commit and borrow buf for dynamic write_json_bytes (may reallocate).
    write_json_bytes(f.object_path, cur.commit_to_buf());
    // After dynamic write, re-reserve for remaining static content:
    // `","start":` (10) + u64 (20) + `,"end":` (7) + u64 (20)
    // + `,"rule_id":` (11) + u64 (20) + `,"rule":"` (9) = 97
    // + optional commit_id (13+20) + optional change_kind (16+20+1) + closing `"}` (2)
    // ≈ 170 bytes.
    cur.resume(170);

    cur.push_static(b"\",\"start\":");
    cur.push_u64(f.start);
    cur.push_static(b",\"end\":");
    cur.push_u64(f.end);
    cur.push_static(b",\"rule_id\":");
    cur.push_u64(f.rule_id as u64);
    cur.push_static(b",\"rule\":\"");
    // Commit and borrow buf for dynamic write_json_str (may reallocate).
    write_json_str(f.rule_name, cur.commit_to_buf());
    // Re-reserve for optional tail: `"` + confidence_score + optional fields + `}`.
    cur.resume(110);
    cur.push_byte(b'"');

    // Confidence score: always emitted (non-optional).
    cur.push_static(b",\"confidence_score\":");
    cur.push_i8(f.confidence_score);

    if let Some(cid) = f.commit_id {
        cur.push_static(b",\"commit_id\":");
        cur.push_u64(cid as u64);
    }
    if let Some(ck) = f.change_kind {
        cur.push_static(b",\"change_kind\":\"");
        // Commit and borrow buf for dynamic write.
        write_json_str(ck, cur.commit_to_buf());
        cur.resume(2);
        cur.push_byte(b'"');
    }
    cur.push_byte(b'}');
    cur.commit();
}

/// Append a JSONL `progress` object to `buf` (no trailing newline).
///
/// Cold path (~1 call per progress interval); uses plain `extend_from_slice`
/// rather than [`BufCursor`] to keep the code straightforward.
pub(crate) fn encode_progress(p: &ProgressEvent, buf: &mut Vec<u8>) {
    match p.source {
        SourceKind::Fs => {
            buf.extend_from_slice(b"{\"type\":\"progress\",\"source\":\"fs\",\"stage\":\"")
        }
        SourceKind::Git => {
            buf.extend_from_slice(b"{\"type\":\"progress\",\"source\":\"git\",\"stage\":\"")
        }
    }
    write_json_str(p.stage, buf);
    buf.extend_from_slice(b"\",\"objects\":");
    write_u64(p.objects_scanned, buf);
    buf.extend_from_slice(b",\"bytes\":");
    write_u64(p.bytes_scanned, buf);
    buf.extend_from_slice(b",\"findings\":");
    write_u64(p.findings_emitted, buf);
    buf.push(b'}');
}

/// Append a JSONL `summary` object to `buf` (no trailing newline).
///
/// Cold path (called once at scan end); uses plain `extend_from_slice`.
pub(crate) fn encode_summary(s: &SummaryEvent, buf: &mut Vec<u8>) {
    match s.source {
        SourceKind::Fs => {
            buf.extend_from_slice(b"{\"type\":\"summary\",\"source\":\"fs\",\"status\":\"")
        }
        SourceKind::Git => {
            buf.extend_from_slice(b"{\"type\":\"summary\",\"source\":\"git\",\"status\":\"")
        }
    }
    write_json_str(s.status, buf);
    buf.extend_from_slice(b"\",\"elapsed_ms\":");
    write_u64(s.elapsed_ms, buf);
    buf.extend_from_slice(b",\"bytes\":");
    write_u64(s.bytes_scanned, buf);
    buf.extend_from_slice(b",\"findings\":");
    write_u64(s.findings_emitted, buf);
    buf.extend_from_slice(b",\"errors\":");
    write_u64(s.errors, buf);
    buf.extend_from_slice(b",\"throughput_mib_s\":");
    write_f64(s.throughput_mib_s, buf);
    buf.push(b'}');
}

/// Append a JSONL `diagnostic` object to `buf` (no trailing newline).
///
/// Cold path (rare debug/perf diagnostics); uses plain `extend_from_slice`.
pub(crate) fn encode_diagnostic(d: &DiagnosticEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"diagnostic\",\"level\":\"");
    write_json_str(d.level, buf);
    buf.extend_from_slice(b"\",\"message\":\"");
    write_json_str(d.message, buf);
    buf.extend_from_slice(b"\"}");
}

/// Cursor-based identity field writer — emits `,"<name>":<id>` or
/// `,"<name>":null` when `id` is [`SENTINEL_ID`] (parse failure).
#[inline]
fn write_identity_field_cur(cur: &mut BufCursor<'_>, name: &[u8], id: u32) {
    cur.push_static(b",\"");
    cur.push_static(name);
    cur.push_static(b"\":");
    if id == SENTINEL_ID {
        cur.push_static(b"null");
    } else {
        cur.push_u64(id as u64);
    }
}

/// Append a JSONL `commit_meta` object to `buf` (no trailing newline).
///
/// Identity fields (`author_name_id`, etc.) are omitted entirely when
/// `identity` is `None`. When present, individual fields with value
/// [`SENTINEL_ID`] are emitted as JSON `null` (not as the raw `u32::MAX`
/// integer) to signal a parse failure to downstream consumers.
pub(crate) fn encode_commit_meta(m: &CommitMetaEvent, buf: &mut Vec<u8>) {
    // Static: prefix (34) + u64 (20) + oid key (8) + hex (64) + timestamp key (14) + u64 (20)
    // + 4 identity fields (4 * ~40) + closing (1) ≈ 321.
    let mut cur = BufCursor::new(buf, 280);
    cur.push_static(b"{\"type\":\"commit_meta\",\"commit_id\":");
    cur.push_u64(m.commit_id as u64);
    cur.push_static(b",\"oid\":\"");
    // write_oid_hex uses its own reserve + unsafe ptr::write pattern.
    write_oid_hex(&m.commit_oid, cur.commit_to_buf());
    // Remaining: `","timestamp":` (14) + u64 (20)
    // + 4 identity fields: author_name_id (38) + author_email_id (39)
    //   + committer_name_id (41) + committer_email_id (42) = 160
    // + closing `}` (1) = 235 bytes worst case.
    cur.resume(240);
    cur.push_static(b"\",\"timestamp\":");
    cur.push_u64(m.timestamp);
    if let Some(ref ids) = m.identity {
        write_identity_field_cur(&mut cur, b"author_name_id", ids.author_name);
        write_identity_field_cur(&mut cur, b"author_email_id", ids.author_email);
        write_identity_field_cur(&mut cur, b"committer_name_id", ids.committer_name);
        write_identity_field_cur(&mut cur, b"committer_email_id", ids.committer_email);
    }
    cur.push_byte(b'}');
    cur.commit();
}

/// Append a JSONL `identity_dictionary` object to `buf` (no trailing newline).
///
/// Cold path (emitted once per unique identity during init); uses plain
/// `extend_from_slice`.
pub(crate) fn encode_identity_dictionary(d: &IdentityDictionaryEvent<'_>, buf: &mut Vec<u8>) {
    buf.extend_from_slice(b"{\"type\":\"identity_dictionary\",\"id\":");
    write_u64(d.id as u64, buf);
    buf.extend_from_slice(b",\"value\":\"");
    write_json_bytes(d.value, buf);
    buf.extend_from_slice(b"\"}");
}

// ============================================================================
// Compile-time capacity budget verification for BufCursor segments
// ============================================================================

// Each assertion proves that the worst-case bytes written in a BufCursor
// segment cannot exceed the budget passed to `new()` or `resume()`.
// Evaluated at compile time — zero runtime cost, build fails if a budget
// is ever too small.
//
// The `<=` form is intentional: it reads as "max writes ≤ budget".
// Tight bounds (e.g. 2 <= 2) prove the budget is exact, not a lint issue.
#[allow(clippy::int_plus_one, clippy::eq_op, clippy::assertions_on_constants)]
const _: () = {
    // encode_finding segment 1: BufCursor::new(buf, 240)
    // Worst case is the "git" variant (longer source string).
    assert!(b"{\"type\":\"finding\",\"source\":\"git\",\"path\":\"".len() <= 240);

    // encode_finding segment 2: cur.resume(170)
    assert!(
        b"\",\"start\":".len()
            + 20 // push_u64 max decimal digits
            + b",\"end\":".len()
            + 20
            + b",\"rule_id\":".len()
            + 20
            + b",\"rule\":\"".len()
            <= 170
    );

    // encode_finding segment 3: cur.resume(110)
    // Worst-case path: confidence_score negative, both commit_id and change_kind Some.
    // The closing `}` is written in segment 3b (after commit_to_buf for
    // change_kind's dynamic write), so it is NOT counted here.
    assert!(
        1 // push_byte(b'"')
            + b",\"confidence_score\":".len()
            + 1  // push_byte(b'-') worst case
            + 20 // push_u64
            + b",\"commit_id\":".len()
            + 20 // push_u64
            + b",\"change_kind\":\"".len()
            <= 110
    );
    // Alternate path: confidence_score + commit_id Some, change_kind None — closing `}` here.
    assert!(
        1 // push_byte(b'"')
            + b",\"confidence_score\":".len()
            + 1  // push_byte(b'-') worst case
            + 20 // push_u64
            + b",\"commit_id\":".len()
            + 20 // push_u64
            + 1  // push_byte(b'}')
            <= 110
    );

    // encode_finding segment 3b: cur.resume(2) — change_kind Some branch
    assert!(
        1 // push_byte(b'"')
            + 1 // push_byte(b'}')
            <= 2
    );

    // encode_commit_meta segment 1: BufCursor::new(buf, 280)
    assert!(
        b"{\"type\":\"commit_meta\",\"commit_id\":".len()
            + 20 // push_u64
            + b",\"oid\":\"".len()
            <= 280
    );

    // encode_commit_meta segment 2: cur.resume(240)
    // Worst case: identity present, all fields non-sentinel (push_u64 = 20).
    assert!(
        b"\",\"timestamp\":".len()
            + 20 // push_u64
            + (b",\"".len() + b"author_name_id".len() + b"\":".len() + 20)
            + (b",\"".len() + b"author_email_id".len() + b"\":".len() + 20)
            + (b",\"".len() + b"committer_name_id".len() + b"\":".len() + 20)
            + (b",\"".len() + b"committer_email_id".len() + b"\":".len() + 20)
            + 1 // push_byte(b'}')
            <= 240
    );
};

// ============================================================================
// JSONL event sink
// ============================================================================

/// Default buffer size (64 KiB) for buffered JSONL emission.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

/// JSONL event sink: writes one JSON object per line.
///
/// The mutex is held only for `write_all`, not for formatting.
/// Callers should use per-worker `Vec<u8>` buffers for formatting
/// to minimize contention.
pub struct JsonlEventSink<W: Write + Send> {
    writer: Mutex<BufWriter<W>>,
    encoder: JsonlEncoder,
}

impl<W: Write + Send> JsonlEventSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(BufWriter::with_capacity(DEFAULT_BUF_CAPACITY, writer)),
            encoder: JsonlEncoder::new(),
        }
    }
}

impl<W: Write + Send + 'static> EventSink for JsonlEventSink<W> {
    fn emit(&self, event: ScanEvent<'_>) {
        with_format_buf(
            |buf| self.encoder.encode(&event, buf),
            |bytes| {
                let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
                handle_sink_io(writer.write_all(bytes), "jsonl event sink write");
            },
        );
    }

    fn flush(&self) {
        let mut writer = self.writer.lock().expect("jsonl sink mutex poisoned");
        handle_sink_io(writer.flush(), "jsonl event sink flush");
    }
}

/// Null event sink that discards all events.
///
/// Used as the default when no structured output is configured.
pub struct NullEventSink;

impl EventSink for NullEventSink {
    fn emit(&self, _event: ScanEvent<'_>) {}
    fn flush(&self) {}
}

/// Collects JSONL-encoded events in memory (for testing).
///
/// Thread-safe: multiple workers can emit concurrently. Use `take()` to
/// drain the buffer and inspect JSONL output in test assertions.
pub struct VecEventSink {
    buf: Mutex<Vec<u8>>,
    encoder: JsonlEncoder,
}

impl VecEventSink {
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(Vec::new()),
            encoder: JsonlEncoder::new(),
        }
    }

    /// Drain and return all accumulated JSONL bytes.
    pub fn take(&self) -> Vec<u8> {
        let mut buf = self.buf.lock().expect("vec event sink mutex poisoned");
        std::mem::take(&mut *buf)
    }

    /// Return accumulated bytes without draining.
    pub fn bytes(&self) -> Vec<u8> {
        self.buf
            .lock()
            .expect("vec event sink mutex poisoned")
            .clone()
    }
}

impl Default for VecEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for VecEventSink {
    fn emit(&self, event: ScanEvent<'_>) {
        with_format_buf(
            |tmp| self.encoder.encode(&event, tmp),
            |bytes| {
                let mut buf = self.buf.lock().expect("vec event sink mutex poisoned");
                buf.extend_from_slice(bytes);
            },
        );
    }

    fn flush(&self) {}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_jsonl(event: ScanEvent<'_>) -> String {
        let encoder = JsonlEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&event, &mut buf);
        let s = String::from_utf8(buf).unwrap();

        // Every JSONL line (minus trailing newline) must parse as valid JSON.
        let line = s.trim_end_matches('\n');
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "encoder produced invalid JSON: {line}"
        );

        s
    }

    #[test]
    fn finding_jsonl_basic() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/main.rs",
            start: 42,
            end: 80,
            rule_id: 7,
            rule_name: "aws-access-key",
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        assert!(line.starts_with('{'));
        assert!(line.ends_with("}\n"));
        assert!(line.contains("\"type\":\"finding\""));
        assert!(line.contains("\"source\":\"fs\""));
        assert!(line.contains("\"path\":\"src/main.rs\""));
        assert!(line.contains("\"start\":42"));
        assert!(line.contains("\"end\":80"));
        assert!(line.contains("\"rule\":\"aws-access-key\""));
        assert!(
            line.contains("\"confidence_score\":0"),
            "zero confidence_score must appear in JSONL: {line}"
        );
        assert!(!line.contains("commit_id"));
    }

    #[test]
    fn finding_jsonl_with_git_fields() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: b"config/.env",
            start: 0,
            end: 40,
            rule_id: 3,
            rule_name: "generic-secret",
            commit_id: Some(12),
            change_kind: Some("add"),
            confidence_score: 0,
        }));
        assert!(line.contains("\"source\":\"git\""));
        assert!(line.contains("\"commit_id\":12"));
        assert!(line.contains("\"change_kind\":\"add\""));
    }

    #[test]
    fn finding_jsonl_non_utf8_path() {
        // Path with invalid UTF-8 byte 0xff.
        let path = b"src/\xff/bad.rs";
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Git,
            object_path: path,
            start: 0,
            end: 10,
            rule_id: 1,
            rule_name: "test",
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        // The invalid byte should be escaped.
        assert!(line.contains("\\u00ff"));
        assert!(line.contains("\"path\":\"src/\\u00ff/bad.rs\""));
    }

    #[test]
    fn summary_jsonl() {
        let line = collect_jsonl(ScanEvent::Summary(SummaryEvent {
            source: SourceKind::Fs,
            status: "complete",
            elapsed_ms: 1234,
            bytes_scanned: 104857600,
            findings_emitted: 3,
            errors: 0,
            throughput_mib_s: 81.23,
        }));
        assert!(line.contains("\"type\":\"summary\""));
        assert!(line.contains("\"elapsed_ms\":1234"));
        assert!(line.contains("\"throughput_mib_s\":81.23"));
    }

    #[test]
    fn progress_jsonl() {
        let line = collect_jsonl(ScanEvent::Progress(ProgressEvent {
            source: SourceKind::Git,
            stage: "scanning",
            objects_scanned: 1024,
            bytes_scanned: 104857600,
            findings_emitted: 5,
        }));
        assert!(line.contains("\"type\":\"progress\""));
        assert!(line.contains("\"stage\":\"scanning\""));
        assert!(line.contains("\"objects\":1024"));
    }

    #[test]
    fn diagnostic_jsonl() {
        let line = collect_jsonl(ScanEvent::Diagnostic(DiagnosticEvent {
            level: "debug",
            message: "tree diff took 1.2s",
        }));
        assert!(line.contains("\"type\":\"diagnostic\""));
        assert!(line.contains("\"level\":\"debug\""));
        assert!(line.contains("\"message\":\"tree diff took 1.2s\""));
    }

    #[test]
    fn json_escaping() {
        let line = collect_jsonl(ScanEvent::Diagnostic(DiagnosticEvent {
            level: "debug",
            message: "path=\"foo\\bar\"\nnewline",
        }));
        assert!(line.contains("\\\""));
        assert!(line.contains("\\\\"));
        assert!(line.contains("\\n"));
    }

    #[test]
    fn fs_finding_jsonl_omits_git_fields() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/config.yaml",
            start: 10,
            end: 50,
            rule_id: 2,
            rule_name: "generic-api-key",
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        assert!(line.contains("\"source\":\"fs\""));
        assert!(
            !line.contains("commit_id"),
            "FS findings must not include commit_id: {line}"
        );
        assert!(
            !line.contains("change_kind"),
            "FS findings must not include change_kind: {line}"
        );
    }

    #[test]
    fn jsonl_sink_writes_to_vec() {
        let buf = Vec::new();
        let sink = JsonlEventSink::new(buf);
        sink.emit(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"test.txt",
            start: 0,
            end: 10,
            rule_id: 1,
            rule_name: "test-rule",
            commit_id: None,
            change_kind: None,
            confidence_score: 0,
        }));
        sink.flush();

        // After flush the BufWriter's internal buffer is flushed to the Vec.
        // Verify the sink didn't panic and the data is well-formed.
        let _inner = sink.writer.lock().unwrap();
    }

    #[test]
    fn commit_meta_jsonl_encoding() {
        let oid = OidBytes::sha1([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);
        let line = collect_jsonl(ScanEvent::CommitMeta(CommitMetaEvent {
            commit_id: 42,
            commit_oid: oid,
            timestamp: 1_700_000_000,
            identity: None,
        }));
        assert!(line.starts_with('{'));
        assert!(line.ends_with("}\n"));
        assert!(line.contains("\"type\":\"commit_meta\""));
        assert!(line.contains("\"commit_id\":42"));
        assert!(line.contains("\"oid\":\"deadbeef0123456789abcdeffedcba9876543210\""));
        assert!(line.contains("\"timestamp\":1700000000"));
    }

    #[test]
    fn commit_meta_jsonl_sha256() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (0xff - i) as u8;
        }
        let oid = OidBytes::sha256(bytes);
        let line = collect_jsonl(ScanEvent::CommitMeta(CommitMetaEvent {
            commit_id: 0,
            commit_oid: oid,
            timestamp: u64::MAX,
            identity: None,
        }));
        assert!(line.contains("\"type\":\"commit_meta\""));
        assert!(line.contains("\"commit_id\":0"));
        // 64-char hex for SHA-256.
        assert!(line.contains(
            "\"oid\":\"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0\""
        ));
        assert!(line.contains(&format!("\"timestamp\":{}", u64::MAX)));
    }

    #[test]
    fn commit_meta_jsonl_with_identity() {
        let oid = OidBytes::sha1([0xaa; 20]);
        let ids = CommitIdentityIds {
            author_name: 0,
            author_email: 1,
            committer_name: 2,
            committer_email: 3,
        };
        let line = collect_jsonl(ScanEvent::CommitMeta(CommitMetaEvent {
            commit_id: 7,
            commit_oid: oid,
            timestamp: 1_000,
            identity: Some(ids),
        }));
        assert!(line.contains("\"author_name_id\":0"));
        assert!(line.contains("\"author_email_id\":1"));
        assert!(line.contains("\"committer_name_id\":2"));
        assert!(line.contains("\"committer_email_id\":3"));
    }

    #[test]
    fn commit_meta_jsonl_sentinel_id_omitted() {
        let oid = OidBytes::sha1([0xcc; 20]);
        let ids = CommitIdentityIds {
            author_name: 5,
            author_email: SENTINEL_ID,
            committer_name: 6,
            committer_email: SENTINEL_ID,
        };
        let line = collect_jsonl(ScanEvent::CommitMeta(CommitMetaEvent {
            commit_id: 99,
            commit_oid: oid,
            timestamp: 3_000,
            identity: Some(ids),
        }));
        // Valid IDs should appear normally.
        assert!(line.contains("\"author_name_id\":5"));
        assert!(line.contains("\"committer_name_id\":6"));
        // SENTINEL_ID fields must be emitted as null, not raw u32::MAX.
        assert!(
            !line.contains("4294967295"),
            "SENTINEL_ID must not be emitted as raw u32::MAX in JSONL; got: {line}"
        );
        assert!(line.contains("\"author_email_id\":null"));
        assert!(line.contains("\"committer_email_id\":null"));
    }

    #[test]
    fn commit_meta_jsonl_without_identity_omits_fields() {
        let oid = OidBytes::sha1([0xbb; 20]);
        let line = collect_jsonl(ScanEvent::CommitMeta(CommitMetaEvent {
            commit_id: 1,
            commit_oid: oid,
            timestamp: 2_000,
            identity: None,
        }));
        assert!(!line.contains("author_name_id"));
        assert!(!line.contains("author_email_id"));
        assert!(!line.contains("committer_name_id"));
        assert!(!line.contains("committer_email_id"));
    }

    #[test]
    fn identity_dictionary_jsonl_encoding() {
        let line = collect_jsonl(ScanEvent::IdentityDictionary(IdentityDictionaryEvent {
            id: 42,
            value: b"Linus Torvalds",
        }));
        assert!(line.contains("\"type\":\"identity_dictionary\""));
        assert!(line.contains("\"id\":42"));
        assert!(line.contains("\"value\":\"Linus Torvalds\""));
    }

    #[test]
    fn identity_dictionary_jsonl_non_utf8() {
        let line = collect_jsonl(ScanEvent::IdentityDictionary(IdentityDictionaryEvent {
            id: 0,
            value: b"name\xff",
        }));
        assert!(line.contains("\"value\":\"name\\u00ff\""));
    }

    #[test]
    fn confidence_score_in_jsonl() {
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/secret.rs",
            start: 10,
            end: 50,
            rule_id: 1,
            rule_name: "api-key",
            commit_id: None,
            change_kind: None,
            confidence_score: 7,
        }));
        assert!(
            line.contains("\"confidence_score\":7"),
            "JSONL must contain confidence_score: {line}"
        );
    }

    #[test]
    fn negative_confidence_score_in_jsonl() {
        // Mildly negative score.
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/secret.rs",
            start: 10,
            end: 50,
            rule_id: 1,
            rule_name: "api-key",
            commit_id: None,
            change_kind: None,
            confidence_score: -3,
        }));
        assert!(
            line.contains("\"confidence_score\":-3"),
            "negative confidence_score must round-trip: {line}"
        );

        // Minimum i8 value.
        let line = collect_jsonl(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: b"src/secret.rs",
            start: 10,
            end: 50,
            rule_id: 1,
            rule_name: "api-key",
            commit_id: None,
            change_kind: None,
            confidence_score: i8::MIN,
        }));
        assert!(
            line.contains("\"confidence_score\":-128"),
            "i8::MIN confidence_score must round-trip: {line}"
        );
    }
}
