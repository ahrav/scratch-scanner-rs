//! Engine adapter for Git blob scanning.
//!
//! Bridges decoded blob bytes into the core `Engine` using overlap-safe chunking
//! and a fixed-size ring buffer, then aggregates findings per blob with
//! deterministic ordering.
//!
//! # Algorithm
//! 1. Stream blob bytes into fixed windows using `RingChunker`.
//! 2. Scan each window with `Engine::scan_chunk_into` at the correct base offset.
//! 3. Drop findings that fall entirely inside the overlap prefix so each match
//!    is recorded exactly once.
//! 4. Convert findings into `FindingKey` values (no raw secret bytes).
//! 5. Sort + dedup per blob to guarantee deterministic ordering.
//!
//! Blobs that fit in a single chunk skip the ring buffer entirely (fast path).
//!
//! # Design
//! - Chunk overlap uses `Engine::required_overlap()` and
//!   `ScanScratch::drop_prefix_findings`.
//! - A fixed-size ring buffer streams blob bytes into the scanner, avoiding
//!   per-blob allocations beyond the chunk window.
//! - Findings are stored in a shared arena with per-blob spans.
//! - `CommitMeta` events are emitted at most once per commit using an
//!   `AtomicBitSet` shared across all adapter instances. See
//!   [`EngineAdapter::stream_findings`] for the exactly-once protocol.
//!
//! # Invariants
//! - Results are returned in candidate order.
//! - `ScannedBlob.findings` indexes into the adapter's findings arena.
//! - Path refs in results point into the mapping arena supplied by the caller.
//! - When the debug allocation guard is enabled, scanning must not allocate.

use std::fmt;
use std::sync::Arc;

use gix_commitgraph::Position;

use crate::content_policy::{self, ContentVerdict};
use crate::scheduler::AllocGuard;
use crate::stdx::AtomicBitSet;
use crate::unified::events::{
    CommitMetaEvent, DiagnosticEvent, EventSink, FindingEvent, ScanEvent,
};
use crate::unified::SourceKind;
use crate::{Engine, FileId, NormHash, ScanScratch};

use super::commit_graph::CommitGraphIndex;
use super::identity_intern::IdentityInterner;

use super::alloc_guard;
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate};
use super::pack_exec::{PackExecError, PackObjectSink};
use super::perf;
use super::tree_candidate::CandidateContext;

/// Bundles the event sink and commit-graph state needed for exactly-once
/// `CommitMeta` emission during scanning.
///
/// Passed as a single argument to runner entry-points that forward these
/// into [`EngineAdapter::new_with_event_sink`].
pub struct CommitMetaContext {
    /// Structured event sink for streaming scan progress and diagnostics.
    pub event_sink: Arc<dyn EventSink>,
    /// Maps commit-graph positions to OIDs and timestamps.
    pub commit_graph_index: Arc<CommitGraphIndex>,
    /// Emit-once bitset — one bit per commit-graph position.
    pub commit_meta_seen: Arc<AtomicBitSet>,
    /// Identity interner for resolving intern IDs to raw name/email bytes.
    ///
    /// Present when identity enrichment is enabled (`enrich_identities`).
    /// The runner reads this for upfront `IdentityDictionary` emission;
    /// it is carried here to avoid a separate plumbing path through the
    /// scheduler into per-worker adapter construction.
    pub identity_interner: Option<Arc<IdentityInterner>>,
}

/// Default chunk window size for adapter scanning (1 MiB).
pub const DEFAULT_CHUNK_BYTES: usize = 1 << 20;

/// Engine adapter configuration.
#[derive(Clone, Copy, Debug)]
pub struct EngineAdapterConfig {
    /// Total chunk window size (prefix + payload).
    ///
    /// The adapter will clamp this to at least `required_overlap + 1`.
    /// Use `0` to select the default (`DEFAULT_CHUNK_BYTES`).
    pub chunk_bytes: usize,
    /// When `true`, scan binary blobs instead of skipping them.
    pub scan_binary: bool,
}

impl Default for EngineAdapterConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            scan_binary: false,
        }
    }
}

/// Normalized finding key for Git persistence.
///
/// Order is total and stable: `(start, end, rule_id, norm_hash)`.
///
/// `start`/`end` are derived from `FindingRec.root_hint_*`, which use the
/// *full match span* in blob coordinates. For transform-derived findings,
/// these spans map back to the encoded bytes that produced the match.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FindingKey {
    /// Inclusive start offset within the blob.
    pub start: u32,
    /// Exclusive end offset within the blob.
    pub end: u32,
    /// Stable rule identifier.
    pub rule_id: u32,
    /// Normalized secret hash (no raw secret bytes stored).
    pub norm_hash: NormHash,
}

/// Range into the adapter findings arena for a single blob.
///
/// The span indexes into `ScannedBlobs.finding_arena` (or the adapter's
/// internal arena prior to `take_results`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingSpan {
    /// Start index in the findings arena.
    pub start: u32,
    /// Number of findings for the blob.
    pub len: u32,
}

/// Blob scanned by the engine adapter.
///
/// The `ctx.path_ref` points into the mapping arena owned by the caller.
#[derive(Clone, Debug)]
pub struct ScannedBlob {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context with path reference (mapping arena).
    pub ctx: CandidateContext,
    /// Sorted + deduped findings span in the adapter findings arena.
    pub findings: FindingSpan,
}

/// Collected scan results with a shared findings arena.
///
/// The findings arena is shared across blobs; individual blobs reference it
/// via `FindingSpan`.
#[derive(Clone, Debug)]
pub struct ScannedBlobs {
    /// Blobs scanned in candidate order.
    pub blobs: Vec<ScannedBlob>,
    /// Shared findings arena referenced by `ScannedBlob.findings`.
    pub finding_arena: Vec<FindingKey>,
}

/// Always-on Git scan counters for user-facing summaries.
///
/// Unlike `git-perf` counters, these values are recorded in all builds and
/// track the same core dimensions as FS summaries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitScanCommonMetrics {
    /// Number of blob payloads sent through the scanner.
    pub objects_scanned: u64,
    /// Number of chunk windows scanned across all objects.
    pub chunks_scanned: u64,
    /// Total payload bytes scanned.
    pub bytes_scanned: u64,
    /// Findings emitted to the event stream.
    pub findings_emitted: u64,
    /// Blobs skipped because they were classified as binary.
    pub binary_skipped: u64,
    /// Blobs skipped pre-scan because extension matched the binary skip set.
    pub ext_skipped: u64,
    /// Blobs skipped pre-scan because filename matched the lock-file table.
    pub lock_skipped: u64,
    /// Blobs scanned via extracted text from binary formats.
    pub binary_extracted: u64,
}

impl GitScanCommonMetrics {
    #[inline(always)]
    pub fn merge_from(&mut self, other: &Self) {
        self.objects_scanned = self.objects_scanned.saturating_add(other.objects_scanned);
        self.chunks_scanned = self.chunks_scanned.saturating_add(other.chunks_scanned);
        self.bytes_scanned = self.bytes_scanned.saturating_add(other.bytes_scanned);
        self.findings_emitted = self.findings_emitted.saturating_add(other.findings_emitted);
        self.binary_skipped = self.binary_skipped.saturating_add(other.binary_skipped);
        self.ext_skipped = self.ext_skipped.saturating_add(other.ext_skipped);
        self.lock_skipped = self.lock_skipped.saturating_add(other.lock_skipped);
        self.binary_extracted = self.binary_extracted.saturating_add(other.binary_extracted);
    }
}

/// Engine adapter error taxonomy.
#[derive(Debug)]
pub enum EngineAdapterError {
    /// Finding offsets exceed `u32` bounds.
    FindingOffsetOverflow { start: u64, end: u64 },
    /// Findings arena index exceeds `u32` bounds.
    FindingArenaOverflow { end: usize, max: u32 },
}

impl fmt::Display for EngineAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FindingOffsetOverflow { start, end } => {
                write!(f, "finding offsets exceed u32: {start}..{end}")
            }
            Self::FindingArenaOverflow { end, max } => {
                write!(f, "findings arena index {end} exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for EngineAdapterError {}

impl From<EngineAdapterError> for PackExecError {
    fn from(err: EngineAdapterError) -> Self {
        PackExecError::Sink(err.to_string())
    }
}

/// Git engine adapter that implements `PackObjectSink`.
///
/// The adapter reuses a ring chunker and scratch space across blobs to
/// minimize allocations on hot paths. Results accumulate until
/// `take_results` or `clear_results` is called.
///
/// When an `EventSink` is configured, findings are also streamed as
/// structured [`ScanEvent::Finding`] events during scanning (in addition
/// to being recorded in `ScannedBlobs` for persistence).
pub struct EngineAdapter<'a> {
    engine: &'a Engine,
    scratch: ScanScratch,
    overlap: usize,
    results: Vec<ScannedBlob>,
    /// Accumulated findings across all blobs; each `ScannedBlob.findings`
    /// indexes a contiguous span here.
    findings_arena: Vec<FindingKey>,
    /// Per-blob scratch: populated by `scan_blob_into_buf`, read by
    /// `stream_findings`, drained into the arena by `record_findings`,
    /// then cleared at the start of the next `scan_blob_into_buf` call.
    findings_buf: Vec<FindingKey>,
    chunker: RingChunker,
    // Monotone ID for this adapter instance; wraps on overflow.
    next_file_id: u32,
    /// Structured event sink for streaming findings.
    event_sink: Arc<dyn EventSink>,
    /// When `true`, skip the binary content check and scan everything.
    scan_binary: bool,
    /// Reusable buffer for binary format text extraction.
    extract_buf: Vec<u8>,
    /// Temporary workspace for extractors (e.g. per-entry reads in JARs).
    extract_scratch: Vec<u8>,
    /// Commit-graph index for resolving `commit_id` → OID + timestamp.
    commit_graph: Arc<CommitGraphIndex>,
    /// Emit-once gating for `CommitMeta` events.
    ///
    /// Each bit corresponds to a commit-graph position.
    /// `test_and_set(pos)` returns `true` exactly once per position across
    /// all adapter instances sharing the same `Arc`, ensuring at most one
    /// `CommitMeta` event per commit even under concurrent pack-exec workers.
    commit_meta_seen: Arc<AtomicBitSet>,
    /// Always-on counters for machine-readable scan summaries.
    metrics: GitScanCommonMetrics,
}

impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter with a structured event sink.
    ///
    /// Findings are streamed as structured events during scanning (in addition
    /// to being accumulated in `ScannedBlobs` for persistence).
    ///
    /// # Panics (debug only)
    ///
    /// Debug-asserts that `ctx.commit_meta_seen.bit_length()` is at least
    /// `ctx.commit_graph_index.len()`. A mismatched bitset would silently
    /// skip `CommitMeta` emission for high-position commits.
    #[must_use]
    pub fn new_with_event_sink(
        engine: &'a Engine,
        config: EngineAdapterConfig,
        ctx: CommitMetaContext,
    ) -> Self {
        debug_assert!(
            ctx.commit_meta_seen.bit_length() >= ctx.commit_graph_index.len(),
            "AtomicBitSet bit_length ({}) must be >= CommitGraphIndex len ({})",
            ctx.commit_meta_seen.bit_length(),
            ctx.commit_graph_index.len(),
        );
        let overlap = engine.required_overlap();
        let chunk_bytes = effective_chunk_bytes(config.chunk_bytes, overlap);
        Self {
            engine,
            scratch: engine.new_scratch(),
            overlap,
            results: Vec::new(),
            findings_arena: Vec::new(),
            findings_buf: Vec::with_capacity(64),
            chunker: RingChunker::new(chunk_bytes, overlap),
            next_file_id: 0,
            event_sink: ctx.event_sink,
            scan_binary: config.scan_binary,
            extract_buf: Vec::with_capacity(crate::content_policy::extract::EXTRACT_OUTPUT_CAP),
            extract_scratch: Vec::with_capacity(crate::content_policy::extract::JAR_ENTRY_CAP),
            commit_graph: ctx.commit_graph_index,
            commit_meta_seen: ctx.commit_meta_seen,
            metrics: GitScanCommonMetrics::default(),
        }
    }

    /// Returns adapter results in the order candidates were emitted.
    #[must_use]
    pub fn results(&self) -> &[ScannedBlob] {
        &self.results
    }

    /// Returns the shared findings arena.
    ///
    /// Each `ScannedBlob.findings` references a span in this arena.
    #[must_use]
    pub fn findings_arena(&self) -> &[FindingKey] {
        &self.findings_arena
    }

    /// Takes ownership of the accumulated results and findings arena.
    pub fn take_results(&mut self) -> ScannedBlobs {
        ScannedBlobs {
            blobs: std::mem::take(&mut self.results),
            finding_arena: std::mem::take(&mut self.findings_arena),
        }
    }

    /// Clears accumulated results while preserving allocated capacity.
    ///
    /// This does not reset the file-id counter; file ids continue to
    /// monotonically wrap.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.findings_arena.clear();
        self.findings_buf.clear();
        self.metrics = GitScanCommonMetrics::default();
    }

    /// Reserves capacity for upcoming blob results.
    pub fn reserve_results(&mut self, additional: usize) {
        self.results.reserve(additional);
    }

    /// Reserves capacity in the shared findings arena.
    pub fn reserve_findings(&mut self, additional: usize) {
        self.findings_arena.reserve(additional);
    }

    /// Reserves capacity for the per-blob findings buffer.
    ///
    /// The per-blob buffer is drained into the shared arena after each blob,
    /// so this only needs to cover the expected peak per-blob finding count
    /// (not the cumulative total).
    pub fn reserve_findings_buf(&mut self, additional: usize) {
        self.findings_buf.reserve(additional);
    }

    /// Returns the always-on scan summary counters accumulated by this adapter.
    #[must_use]
    pub const fn metrics(&self) -> GitScanCommonMetrics {
        self.metrics
    }

    /// Takes the current metrics snapshot and resets counters to zero.
    pub fn take_metrics(&mut self) -> GitScanCommonMetrics {
        std::mem::take(&mut self.metrics)
    }

    /// Emits a loose candidate blob for scanning.
    ///
    /// This follows the same path/arena and finding aggregation logic as
    /// packed candidates.
    ///
    /// # Errors
    /// - `FindingOffsetOverflow` or `FindingArenaOverflow` for oversized blobs.
    pub fn emit_loose(
        &mut self,
        candidate: &LooseCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, path, bytes)?;
        self.stream_findings(
            path,
            candidate.ctx.commit_id,
            candidate.ctx.change_kind.as_str(),
        );
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
    }

    /// Stream findings from `findings_buf` to the event sink.
    ///
    /// Called after `scan_blob_into_buf` and before `record_findings`.
    ///
    /// # Exactly-once `CommitMeta` gating
    ///
    /// When `findings_buf` is non-empty and `commit_id` falls within the
    /// commit-graph range, `commit_meta_seen.test_and_set(commit_id)` is
    /// called. The atomic bitset returns `true` exactly once per position
    /// (across all adapter instances sharing the same `Arc<AtomicBitSet>`),
    /// so the resulting `CommitMeta` event is emitted at most once per
    /// `commit_id` — even when multiple workers or blobs reference the
    /// same commit.
    ///
    /// Within the adapter call that wins `test_and_set`, `CommitMeta` is
    /// emitted before that adapter's finding events. Across parallel adapters,
    /// global stream order is intentionally non-deterministic: a `Finding`
    /// for a commit may appear before that commit's `CommitMeta`.
    ///
    /// Commits with zero findings never trigger `CommitMeta` emission.
    ///
    /// When `commit_id` is out of range (>= `commit_graph.len()`), a
    /// `Diagnostic` event at warn level is emitted instead of `CommitMeta`.
    /// Findings are still emitted regardless.
    fn stream_findings(&self, path: &[u8], commit_id: u32, change_kind: &str) {
        if !self.findings_buf.is_empty() {
            if (commit_id as usize) < self.commit_graph.len() {
                if self.commit_meta_seen.test_and_set(commit_id as usize) {
                    let oid = self.commit_graph.commit_oid(Position(commit_id));
                    let ts = self.commit_graph.committer_timestamp(Position(commit_id));
                    let identity = self.commit_graph.identity_ids(Position(commit_id));
                    self.event_sink.emit(ScanEvent::CommitMeta(CommitMetaEvent {
                        commit_id,
                        commit_oid: oid,
                        timestamp: ts,
                        identity,
                    }));
                }
            } else {
                self.event_sink.emit(ScanEvent::Diagnostic(DiagnosticEvent {
                    level: "warn",
                    message: "commit_id out of commit-graph range; CommitMeta skipped",
                }));
            }
        }
        for f in &self.findings_buf {
            self.event_sink.emit(ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: path,
                start: u64::from(f.start),
                end: u64::from(f.end),
                rule_id: f.rule_id,
                rule_name: self.engine.rule_name(f.rule_id),
                commit_id: Some(commit_id),
                change_kind: Some(change_kind),
            }));
        }
    }

    /// Classify, optionally extract, and scan a single blob into `findings_buf`.
    ///
    /// When `scan_binary` is false the blob is classified via
    /// [`content_policy::classify_content`]. Text blobs are scanned directly;
    /// extractable binary formats (`.class`, `.pyc`, etc.) have their text
    /// extracted first; opaque binaries are skipped entirely.
    ///
    /// On return, `self.findings_buf` contains the sorted+deduped findings
    /// for this blob. The caller is responsible for streaming them to the
    /// event sink and recording them in the findings arena.
    fn scan_blob_into_buf(
        &mut self,
        file_id: FileId,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        self.findings_buf.clear();
        if !self.scan_binary {
            match content_policy::classify_content(bytes, path, content_policy::CHECK_LEN) {
                ContentVerdict::Binary => {
                    perf::record_scan_binary_skip();
                    self.metrics.binary_skipped = self.metrics.binary_skipped.saturating_add(1);
                    return Ok(());
                }
                ContentVerdict::BinaryExtractable(fmt) => {
                    use crate::content_policy::extract::{extract_content, ExtractResult};
                    if extract_content(fmt, bytes, &mut self.extract_buf, &mut self.extract_scratch)
                        == ExtractResult::Ok
                    {
                        perf::record_scan_binary_extract();
                        self.metrics.binary_extracted =
                            self.metrics.binary_extracted.saturating_add(1);
                        scan_blob_chunked_with_chunker(
                            self.engine,
                            &mut self.scratch,
                            file_id,
                            &self.extract_buf,
                            self.overlap,
                            &mut self.chunker,
                            &mut self.findings_buf,
                        )?;
                        self.record_scanned_payload(self.extract_buf.len());
                        return Ok(());
                    }
                    perf::record_scan_binary_skip();
                    self.metrics.binary_skipped = self.metrics.binary_skipped.saturating_add(1);
                    return Ok(());
                }
                ContentVerdict::Text => {}
            }
        }
        self.scan_blob_payload(file_id, bytes)
    }

    /// Scans raw blob bytes (bypassing content classification) and updates
    /// metrics. Called by `scan_blob_into_buf` for text blobs.
    fn scan_blob_payload(
        &mut self,
        file_id: FileId,
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        scan_blob_chunked_with_chunker(
            self.engine,
            &mut self.scratch,
            file_id,
            bytes,
            self.overlap,
            &mut self.chunker,
            &mut self.findings_buf,
        )?;
        self.record_scanned_payload(bytes.len());
        Ok(())
    }

    /// Increments scan metrics for a successfully scanned payload.
    #[inline(always)]
    fn record_scanned_payload(&mut self, scanned_len: usize) {
        self.metrics.objects_scanned = self.metrics.objects_scanned.saturating_add(1);
        self.metrics.bytes_scanned = self
            .metrics
            .bytes_scanned
            .saturating_add(scanned_len as u64);
        self.metrics.chunks_scanned =
            self.metrics
                .chunks_scanned
                .saturating_add(chunk_count_for_blob_len(
                    scanned_len,
                    self.chunker.chunk_bytes(),
                    self.overlap,
                ));
    }

    /// Transfer `findings_buf` into the shared arena and return the span.
    ///
    /// Must be called after `scan_blob_into_buf` (which populates
    /// `findings_buf`) and `stream_findings` (which reads it). The span
    /// indexes into `findings_arena` for the just-scanned blob.
    fn record_findings(&mut self) -> Result<FindingSpan, EngineAdapterError> {
        let start = self.findings_arena.len();
        let len = self.findings_buf.len();
        let end = start.saturating_add(len);
        if end > u32::MAX as usize {
            return Err(EngineAdapterError::FindingArenaOverflow { end, max: u32::MAX });
        }

        // Extend the shared arena; the returned span is used by `ScannedBlob`.
        self.findings_arena.extend_from_slice(&self.findings_buf);
        self.metrics.findings_emitted = self.metrics.findings_emitted.saturating_add(len as u64);
        Ok(FindingSpan {
            start: start as u32,
            len: len as u32,
        })
    }
}

impl PackObjectSink for EngineAdapter<'_> {
    /// Scans a pack-sourced blob, streams findings to the event sink, and
    /// records results in the adapter arena.
    ///
    /// Follows the same scan → stream → record pipeline as
    /// [`emit_loose`](Self::emit_loose); the only difference is the candidate
    /// type (`PackCandidate` carries a pack offset).
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, path, bytes)?;
        self.stream_findings(
            path,
            candidate.ctx.commit_id,
            candidate.ctx.change_kind.as_str(),
        );
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
    }
}

#[cfg(test)]
impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter with dummy commit-graph state (test-only).
    ///
    /// Production callers must use [`new_with_event_sink`](Self::new_with_event_sink)
    /// with a real `CommitMetaContext`.
    #[must_use]
    pub fn new(engine: &'a Engine, config: EngineAdapterConfig) -> Self {
        use crate::unified::events::NullEventSink;

        Self::new_with_event_sink(
            engine,
            config,
            CommitMetaContext {
                event_sink: Arc::new(NullEventSink),
                commit_graph_index: Arc::new(CommitGraphIndex::empty()),
                commit_meta_seen: Arc::new(AtomicBitSet::empty(1)),
                identity_interner: None,
            },
        )
    }
}

/// Scan a blob with overlap-safe chunking and return sorted + deduped findings.
///
/// Findings are normalized into `FindingKey` values and ordered deterministically.
///
/// # Errors
/// - `FindingOffsetOverflow` if any finding span exceeds `u32` bounds.
pub fn scan_blob_chunked(
    engine: &Engine,
    blob: &[u8],
    chunk_bytes: usize,
) -> Result<Vec<FindingKey>, EngineAdapterError> {
    let overlap = engine.required_overlap();
    let chunk_bytes = effective_chunk_bytes(chunk_bytes, overlap);
    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();
    scan_blob_chunked_into(
        engine,
        &mut scratch,
        FileId(0),
        blob,
        chunk_bytes,
        overlap,
        &mut out,
    )?;
    Ok(out)
}

/// Clamp requested chunk sizes for overlap and offset safety.
///
/// Ensures `chunk_bytes > overlap` (so each chunk makes forward progress)
/// and caps the result at `u32::MAX` so finding offsets can safely downcast
/// to `u32`. A `requested` value of `0` selects [`DEFAULT_CHUNK_BYTES`].
fn effective_chunk_bytes(requested: usize, overlap: usize) -> usize {
    // Enforce progress and clamp to u32::MAX for offset conversion safety.
    // Finding offsets are stored as `u32`, so chunking must preserve bounds.
    let min = overlap.saturating_add(1).max(1);
    let base = if requested == 0 {
        DEFAULT_CHUNK_BYTES
    } else {
        requested
    };
    base.max(min).min(u32::MAX as usize)
}

/// Computes the number of chunk windows emitted for a blob of the given length,
/// accounting for overlap between adjacent windows.
///
/// Returns at least 1 (single-chunk fast path), matching `RingChunker` behavior.
#[inline(always)]
fn chunk_count_for_blob_len(blob_len: usize, chunk_bytes: usize, overlap: usize) -> u64 {
    if blob_len <= chunk_bytes {
        return 1;
    }
    // RingChunker emits one full chunk, then advances by (chunk-overlap) bytes
    // per subsequent window, with a final partial chunk when remainder exists.
    let step = chunk_bytes.saturating_sub(overlap).max(1);
    let remaining = blob_len.saturating_sub(chunk_bytes);
    let extra = remaining.saturating_add(step - 1) / step;
    1u64.saturating_add(extra as u64)
}

/// Internal scan entry point that creates a fresh `RingChunker` and delegates
/// to [`scan_blob_chunked_with_chunker`]. Used by the public
/// [`scan_blob_chunked`] API when no reusable chunker is available.
fn scan_blob_chunked_into(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    blob: &[u8],
    chunk_bytes: usize,
    overlap: usize,
    out: &mut Vec<FindingKey>,
) -> Result<(), EngineAdapterError> {
    let mut chunker = RingChunker::new(chunk_bytes, overlap);
    scan_blob_chunked_with_chunker(engine, scratch, file_id, blob, overlap, &mut chunker, out)
}

/// Scan a blob using a reusable chunker and optional allocation guard.
///
/// The chunker is reset before use and must have the same overlap as the
/// caller-provided `overlap`. `out` is cleared and populated with sorted,
/// deduped findings.
///
/// When the debug allocation guard is enabled, `assert_no_alloc()` is called
/// after the scan to verify no heap allocations occurred in the hot path.
fn scan_blob_chunked_with_chunker(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    blob: &[u8],
    overlap: usize,
    chunker: &mut RingChunker,
    out: &mut Vec<FindingKey>,
) -> Result<(), EngineAdapterError> {
    perf::record_scan_blob();

    // Fast path: blob fits in a single chunk — skip the ring buffer memcpy.
    // When blob.len() <= chunk_bytes, feed() emits at most one full chunk and
    // flush() emits the remainder. Either way it's exactly one chunk, so we
    // can construct the ChunkView directly on the blob bytes.
    if blob.len() <= chunker.chunk_bytes() {
        perf::record_scan_chunker_bypass();
        let (res, nanos) = perf::time(|| {
            let guard = if alloc_guard::enabled() {
                Some(AllocGuard::new())
            } else {
                None
            };

            out.clear();
            let mut err: Option<EngineAdapterError> = None;

            let view = ChunkView {
                base: 0,
                is_first: true,
                window: blob,
            };
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);

            if let Some(err) = err {
                return Err(err);
            }

            let ((), _sd_nanos) = perf::time(|| {
                if !out.is_empty() {
                    out.sort_unstable();
                    out.dedup();
                }
            });
            perf::record_scan_sort_dedup(_sd_nanos);

            if let Some(guard) = guard {
                guard.assert_no_alloc();
            }

            Ok(())
        });

        if res.is_ok() {
            perf::record_scan(blob.len(), nanos);
        }

        return res;
    }

    // Slow path: blob spans multiple chunks — stream through the ring buffer.
    let (res, nanos) = perf::time(|| {
        let guard = if alloc_guard::enabled() {
            Some(AllocGuard::new())
        } else {
            None
        };

        out.clear();
        chunker.reset();
        debug_assert_eq!(chunker.overlap(), overlap, "overlap mismatch");
        let mut err: Option<EngineAdapterError> = None;

        chunker.feed(blob, |view| {
            if err.is_some() {
                return;
            }
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);
        });
        chunker.flush(|view| {
            if err.is_some() {
                return;
            }
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);
        });

        if let Some(err) = err {
            return Err(err);
        }

        let ((), _sd_nanos) = perf::time(|| {
            if !out.is_empty() {
                out.sort_unstable();
                out.dedup();
            }
        });
        perf::record_scan_sort_dedup(_sd_nanos);

        if let Some(guard) = guard {
            guard.assert_no_alloc();
        }

        Ok(())
    });

    if res.is_ok() {
        perf::record_scan(blob.len(), nanos);
    }

    res
}

/// Scan a single chunk window and collect findings into `out`.
///
/// After scanning, findings wholly within the overlap prefix are dropped
/// to avoid cross-chunk duplication. Remaining findings are converted to
/// `FindingKey` values and appended to `out`. If any finding offset
/// exceeds `u32` bounds, `err` is set and the function returns early.
///
/// The `err` out-parameter (instead of a `Result` return) allows this
/// function to be called inside the `RingChunker::feed` / `flush`
/// closures, which use `FnMut(ChunkView)` with no `Result` return.
fn scan_chunk(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    overlap: usize,
    view: ChunkView<'_>,
    out: &mut Vec<FindingKey>,
    err: &mut Option<EngineAdapterError>,
) {
    perf::record_scan_chunk();
    engine.scan_chunk_into(view.window, file_id, view.base, scratch);
    // Skip findings that are fully contained in the overlap prefix.
    // This keeps each match while avoiding duplicate reporting.
    let new_bytes_start = if view.is_first {
        view.base
    } else {
        view.base.saturating_add(overlap as u64)
    };
    scratch.drop_prefix_findings(new_bytes_start);

    let recs = scratch.findings();
    let hashes = scratch.norm_hashes();
    debug_assert_eq!(recs.len(), hashes.len(), "finding/hash mismatch");

    for (rec, hash) in recs.iter().zip(hashes.iter()) {
        let start = rec.root_hint_start;
        let end = rec.root_hint_end;
        if start > u32::MAX as u64 || end > u32::MAX as u64 {
            *err = Some(EngineAdapterError::FindingOffsetOverflow { start, end });
            return;
        }
        out.push(FindingKey {
            start: start as u32,
            end: end as u32,
            rule_id: rec.rule_id,
            norm_hash: *hash,
        });
    }
}

/// A single chunk window produced by the ring chunker.
///
/// Each view represents a contiguous slice of a blob, potentially including
/// an overlap prefix from the previous window. After scanning, findings
/// whose `drop_hint_end` falls at or before the overlap boundary are dropped
/// to prevent double-reporting — except for the first window (`is_first`),
/// where no prior window exists to own those bytes.
struct ChunkView<'a> {
    /// Absolute start offset of `window` within the blob.
    base: u64,
    /// Indicates the first window so the overlap prefix is not dropped.
    is_first: bool,
    /// Window bytes: overlap prefix followed by new bytes.
    window: &'a [u8],
}

/// Fixed-size ring chunker for streaming blob bytes into scan windows.
///
/// Accepts arbitrary-length input via `feed`, emitting full chunk windows
/// as they fill. The ring retains `overlap` trailing bytes between windows
/// so the scan engine can detect secrets that straddle chunk boundaries.
/// A final partial window is emitted by `flush`.
///
/// # Usage protocol
///
/// 1. Construct once with `new(chunk_bytes, overlap)`.
/// 2. Call `feed(data, callback)` — may invoke the callback zero or more
///    times, once per full `chunk_bytes` window.
/// 3. Call `flush(callback)` — emits the final partial window (if any)
///    and resets internal state for reuse.
/// 4. To reuse across blobs, call `reset()` before the next `feed` cycle.
///
/// The first emitted window has `is_first = true`, which tells the scan
/// layer not to drop findings in the overlap prefix (there is no prior
/// window whose "new bytes" region owns them).
///
/// # Invariant
/// `chunk_bytes > overlap`, enforced at construction.
struct RingChunker {
    chunk_bytes: usize,
    overlap: usize,
    buf: Vec<u8>,
    filled: usize,
    base: u64,
    is_first: bool,
}

impl RingChunker {
    fn new(chunk_bytes: usize, overlap: usize) -> Self {
        assert!(chunk_bytes > 0, "chunk_bytes must be > 0");
        assert!(chunk_bytes > overlap, "chunk_bytes must exceed overlap");
        Self {
            chunk_bytes,
            overlap,
            buf: vec![0u8; chunk_bytes],
            filled: 0,
            base: 0,
            is_first: true,
        }
    }

    fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    fn overlap(&self) -> usize {
        self.overlap
    }

    /// Resets the chunker for reuse with a new blob.
    ///
    /// Clears the fill cursor and base offset; the next `feed` call will
    /// treat the first emitted window as `is_first = true`.
    fn reset(&mut self) {
        self.filled = 0;
        self.base = 0;
        self.is_first = true;
    }

    /// Stream data into fixed windows and invoke the callback per full chunk.
    ///
    /// Each window is `chunk_bytes` long and includes the overlap prefix.
    fn feed(&mut self, mut data: &[u8], mut on_chunk: impl FnMut(ChunkView<'_>)) {
        while !data.is_empty() {
            let space = self.chunk_bytes - self.filled;
            let n = space.min(data.len());
            self.buf[self.filled..self.filled + n].copy_from_slice(&data[..n]);
            self.filled += n;
            data = &data[n..];

            if self.filled == self.chunk_bytes {
                on_chunk(ChunkView {
                    base: self.base,
                    is_first: self.is_first,
                    window: &self.buf[..self.filled],
                });
                self.is_first = false;
                let step = self.chunk_bytes - self.overlap;
                // Retain the overlap prefix so the next window includes it.
                if self.overlap > 0 {
                    self.buf
                        .copy_within(self.chunk_bytes - self.overlap..self.chunk_bytes, 0);
                    self.base = self.base.saturating_add(step as u64);
                    self.filled = self.overlap;
                } else {
                    self.base = self.base.saturating_add(step as u64);
                    self.filled = 0;
                }
            }
        }
    }

    /// Emit the final partial chunk (if any), then reset internal state.
    fn flush(&mut self, mut on_chunk: impl FnMut(ChunkView<'_>)) {
        if self.filled == 0 {
            return;
        }
        // Avoid emitting a final chunk that contains only the overlap prefix.
        if !self.is_first && self.filled <= self.overlap {
            self.reset();
            return;
        }
        on_chunk(ChunkView {
            base: self.base,
            is_first: self.is_first,
            window: &self.buf[..self.filled],
        });
        self.reset();
    }
}

// Compile-time assertion: EngineAdapter must be Send so it can be pooled
// across scoped thread boundaries (same pattern as PackCache/PackExecScratch).
const _: () = {
    fn _assert_send<T: Send>() {}
    fn _check() {
        _assert_send::<super::EngineAdapter<'_>>();
    }
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_scan::alloc_guard;
    use crate::git_scan::pack_candidates::LooseCandidate;
    use crate::git_scan::tree_candidate::{CandidateContext, ChangeKind};
    use crate::git_scan::ByteRef;
    use crate::{demo_engine_with_anchor_mode, AnchorMode};

    /// Verify that the scan hot path allocates nothing after warmup.
    ///
    /// The alloc guard uses **global** counters, so allocations from any
    /// thread are visible. Run with:
    ///
    /// ```sh
    /// SCANNER_RS_ALLOC_GUARD=1 cargo test --lib scan_alloc_guard_no_alloc_after_warmup \
    ///     -- --test-threads=1
    /// ```
    #[test]
    fn scan_alloc_guard_no_alloc_after_warmup() {
        if std::env::var("SCANNER_RS_ALLOC_GUARD").ok().as_deref() != Some("1") {
            eprintln!(
                "alloc guard test skipped; set SCANNER_RS_ALLOC_GUARD=1 and \
                 run with --test-threads=1 to enable"
            );
            return;
        }

        let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());

        let ctx = CandidateContext {
            commit_id: 0,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        };
        let candidate = LooseCandidate {
            oid: OidBytes::from_slice(&[0u8; 20]),
            ctx,
        };
        let path = b"test.txt";
        let blob = b"no findings here";

        alloc_guard::set_enabled(false);
        adapter
            .emit_loose(&candidate, path, blob)
            .expect("warmup scan");

        alloc_guard::set_enabled(true);
        adapter
            .emit_loose(&candidate, path, blob)
            .expect("guarded scan");
        alloc_guard::set_enabled(false);
    }

    fn make_candidate() -> LooseCandidate {
        make_candidate_with_ctx(0, ChangeKind::Add)
    }

    /// Blob of exactly chunk_bytes takes the bypass path (single chunk).
    #[test]
    fn chunker_bypass_exact_chunk_size() {
        let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
        let config = EngineAdapterConfig::default();
        let mut adapter = EngineAdapter::new(&engine, config);
        let candidate = make_candidate();

        // Blob exactly chunk_bytes long — should take bypass (one chunk).
        let blob = vec![b'a'; config.chunk_bytes];
        adapter
            .emit_loose(&candidate, b"test.txt", &blob)
            .expect("exact chunk_bytes scan");
        assert_eq!(adapter.results().len(), 1);
    }

    /// Blob of chunk_bytes + 1 takes the slow path (two chunks).
    #[test]
    fn chunker_slow_path_chunk_size_plus_one() {
        let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
        let config = EngineAdapterConfig::default();
        let mut adapter = EngineAdapter::new(&engine, config);
        let candidate = make_candidate();

        // Blob one byte over chunk_bytes — must use the ring chunker.
        let blob = vec![b'a'; config.chunk_bytes + 1];
        adapter
            .emit_loose(&candidate, b"test.txt", &blob)
            .expect("chunk_bytes+1 scan");
        assert_eq!(adapter.results().len(), 1);
    }

    /// Binary blob (contains NUL byte) is skipped entirely.
    #[test]
    fn binary_blob_skipped() {
        let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        let candidate = make_candidate();

        let mut blob = vec![b'a'; 1024];
        blob[512] = 0; // NUL byte at offset 512
        adapter
            .emit_loose(&candidate, b"image.png", &blob)
            .expect("binary scan");
        // Should have a result entry with zero findings.
        assert_eq!(adapter.results().len(), 1);
        assert_eq!(adapter.results()[0].findings.len, 0);
    }

    /// Pure-text blob is not skipped.
    #[test]
    fn text_blob_not_skipped() {
        let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        let candidate = make_candidate();

        let blob = b"this is plain text with no NUL bytes";
        adapter
            .emit_loose(&candidate, b"readme.txt", blob)
            .expect("text scan");
        assert_eq!(adapter.results().len(), 1);
    }

    /// is_likely_binary edge cases (delegated to content_policy).
    #[test]
    fn is_likely_binary_edge_cases() {
        use crate::content_policy::is_likely_binary;
        // Empty blob is not binary.
        assert!(!is_likely_binary(b"", 8192));
        // All-text is not binary.
        assert!(!is_likely_binary(b"hello world", 8192));
        // NUL at first byte.
        assert!(is_likely_binary(b"\0hello", 8192));
        // NUL beyond check_len is not detected.
        let mut data = vec![b'a'; 100];
        data.push(0);
        assert!(!is_likely_binary(&data, 100));
        // NUL at exact boundary.
        let mut data2 = vec![b'a'; 99];
        data2.push(0);
        assert!(is_likely_binary(&data2, 100));
    }

    // -- Attribution event tests ------------------------------------------------

    use crate::git_scan::commit_graph::CommitGraphIndex;
    use crate::stdx::AtomicBitSet;
    use crate::unified::events::{EventSink, ScanEvent, VecEventSink};
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};

    /// Build a test adapter with event sink and dummy commit-graph / bitset.
    ///
    /// The dummy graph is empty and the bitset has a single bit; this means
    /// `stream_findings` will skip commit-meta emission (commit_id out of
    /// range), which is fine for tests that only verify finding events.
    fn test_adapter_with_sink<'a>(
        engine: &'a Engine,
        sink: Arc<VecEventSink>,
    ) -> EngineAdapter<'a> {
        EngineAdapter::new_with_event_sink(
            engine,
            EngineAdapterConfig::default(),
            CommitMetaContext {
                event_sink: sink,
                commit_graph_index: Arc::new(CommitGraphIndex::empty()),
                commit_meta_seen: Arc::new(AtomicBitSet::empty(1)),
                identity_interner: None,
            },
        )
    }
    use crate::{
        demo_tuning, AnchorPolicy, Gate, RuleSpec, TransformConfig, TransformId, TransformMode,
        ValidatorKind,
    };
    use regex::bytes::Regex;

    fn test_engine_with_tok_rule() -> Engine {
        let rule = RuleSpec {
            name: "tok",
            anchors: &[b"TOK_"],
            radius: 16,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            offline_validation: None,
            re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
        };

        let transforms = vec![TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 4,
            max_encoded_len: 1024,
            max_decoded_bytes: 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }];

        Engine::new_with_anchor_policy(
            vec![rule],
            transforms,
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        )
    }

    fn make_candidate_with_ctx(commit_id: u32, change_kind: ChangeKind) -> LooseCandidate {
        let ctx = CandidateContext {
            commit_id,
            parent_idx: 0,
            change_kind,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        };
        LooseCandidate {
            oid: OidBytes::from_slice(&[0u8; 20]),
            ctx,
        }
    }

    #[test]
    fn git_finding_event_carries_add_attribution() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        let candidate = make_candidate_with_ctx(42, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"secret.txt", blob)
            .expect("scan with Add attribution");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"commit_id\":42"),
            "expected commit_id:42 in: {output}"
        );
        assert!(
            output.contains("\"change_kind\":\"add\""),
            "expected change_kind:add in: {output}"
        );
    }

    #[test]
    fn git_finding_event_carries_modify_attribution() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        let candidate = make_candidate_with_ctx(99, ChangeKind::Modify);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"secret.txt", blob)
            .expect("scan with Modify attribution");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"commit_id\":99"),
            "expected commit_id:99 in: {output}"
        );
        assert!(
            output.contains("\"change_kind\":\"modify\""),
            "expected change_kind:modify in: {output}"
        );
    }

    #[test]
    fn no_finding_blob_emits_no_events() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
        let blob = b"nothing suspicious here";
        adapter
            .emit_loose(&candidate, b"clean.txt", blob)
            .expect("scan clean blob");

        let output = sink.take();
        assert!(output.is_empty(), "expected no events for clean blob");
    }

    #[test]
    fn pack_object_sink_carries_attribution() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        let ctx = CandidateContext {
            commit_id: 77,
            parent_idx: 0,
            change_kind: ChangeKind::Modify,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        };
        let candidate = PackCandidate {
            oid: OidBytes::from_slice(&[0u8; 20]),
            ctx,
            pack_id: 0,
            offset: 0,
        };
        let blob = b"prefix TOK_ABCDEFGH suffix";

        PackObjectSink::emit(&mut adapter, &candidate, b"packed.txt", blob)
            .expect("pack path scan");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"commit_id\":77"),
            "pack path must carry commit_id: {output}"
        );
        assert!(
            output.contains("\"change_kind\":\"modify\""),
            "pack path must carry change_kind: {output}"
        );
    }

    #[test]
    fn git_finding_events_carry_source_git() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"secret.txt", blob)
            .expect("scan");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"source\":\"git\""),
            "git findings must have source:git: {output}"
        );
    }

    #[test]
    fn commit_id_zero_roundtrips_as_some() {
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_sink(&engine, sink.clone());

        // commit_id 0 is a valid graph position (root commit).
        let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"root.txt", blob)
            .expect("scan with commit_id 0");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"commit_id\":0"),
            "commit_id:0 must appear in JSONL (not be treated as None): {output}"
        );
        assert!(
            output.contains("\"change_kind\":\"add\""),
            "change_kind must still appear with commit_id 0: {output}"
        );
    }

    // -- CommitMeta emission tests ----------------------------------------------

    use crate::git_scan::commit_walk::{CommitGraph, ParentScratch};
    use crate::git_scan::errors::CommitPlanError;
    use gix_commitgraph::Position;

    /// Tiny commit-graph stub with known OIDs and timestamps.
    struct SmallTestGraph {
        oids: Vec<OidBytes>,
        timestamps: Vec<u64>,
    }

    impl SmallTestGraph {
        fn new(entries: &[(OidBytes, u64)]) -> Self {
            let (oids, timestamps) = entries.iter().cloned().unzip();
            Self { oids, timestamps }
        }
    }

    impl CommitGraph for SmallTestGraph {
        fn num_commits(&self) -> u32 {
            self.oids.len() as u32
        }
        fn lookup(&self, _oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
            Ok(None)
        }
        fn generation(&self, _pos: Position) -> u32 {
            0
        }
        fn collect_parents(
            &self,
            _pos: Position,
            _max: u32,
            scratch: &mut ParentScratch,
        ) -> Result<(), CommitPlanError> {
            scratch.clear();
            Ok(())
        }
        fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
            Ok(self.oids[pos.0 as usize])
        }
        fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
            Ok(self.oids[pos.0 as usize])
        }
        fn committer_timestamp(&self, pos: Position) -> u64 {
            self.timestamps[pos.0 as usize]
        }
    }

    /// Build an adapter wired to a real `CommitGraphIndex` + fresh `AtomicBitSet`.
    fn test_adapter_with_graph<'a>(
        engine: &'a Engine,
        sink: Arc<VecEventSink>,
        entries: &[(OidBytes, u64)],
    ) -> EngineAdapter<'a> {
        let graph = SmallTestGraph::new(entries);
        let cg = Arc::new(CommitGraphIndex::build(&graph).expect("build test graph"));
        let seen = Arc::new(AtomicBitSet::empty(cg.len().max(1)));
        EngineAdapter::new_with_event_sink(
            engine,
            EngineAdapterConfig::default(),
            CommitMetaContext {
                event_sink: sink,
                commit_graph_index: cg,
                commit_meta_seen: seen,
                identity_interner: None,
            },
        )
    }

    fn test_oid(n: u8) -> OidBytes {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        OidBytes::sha1(bytes)
    }

    fn parse_jsonl_types(output: &str) -> Vec<(&str, Option<u64>)> {
        output
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let ty = if l.contains("\"type\":\"commit_meta\"") {
                    "commit_meta"
                } else if l.contains("\"type\":\"finding\"") {
                    "finding"
                } else {
                    "other"
                };
                // Extract commit_id value.
                let cid = l.find("\"commit_id\":").map(|start| {
                    let rest = &l[start + "\"commit_id\":".len()..];
                    let end = rest
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(rest.len());
                    rest[..end].parse::<u64>().unwrap()
                });
                (ty, cid)
            })
            .collect()
    }

    #[test]
    fn single_adapter_commit_meta_precedes_its_findings() {
        let entries = vec![(test_oid(0xab), 1_700_000_000)];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

        let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"secret.txt", blob)
            .expect("scan");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        let events = parse_jsonl_types(&output);

        assert!(
            events.len() >= 2,
            "expected commit_meta + finding, got: {output}"
        );
        assert_eq!(
            events[0].0, "commit_meta",
            "first event must be commit_meta: {output}"
        );
        assert_eq!(events[0].1, Some(0));
        assert_eq!(
            events[1].0, "finding",
            "second event must be finding: {output}"
        );
        // Verify OID hex and timestamp are present.
        assert!(
            output.contains("\"oid\":\"ab"),
            "commit_meta must contain OID hex: {output}"
        );
        assert!(
            output.contains("\"timestamp\":1700000000"),
            "commit_meta must contain timestamp: {output}"
        );
    }

    #[derive(Default)]
    struct ReorderGateState {
        meta_waiting: bool,
        allow_meta_emit: bool,
    }

    /// Event sink that blocks the first `CommitMeta` until another worker emits
    /// a `Finding`. This makes cross-worker ordering inversions deterministic.
    struct BlockingCommitMetaSink {
        events: Mutex<Vec<&'static str>>,
        state: Mutex<ReorderGateState>,
        cv: Condvar,
    }

    impl BlockingCommitMetaSink {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                state: Mutex::new(ReorderGateState::default()),
                cv: Condvar::new(),
            }
        }

        fn wait_until_meta_waiting(&self, timeout: Duration) -> bool {
            let start = Instant::now();
            let mut state = self
                .state
                .lock()
                .expect("blocking sink state mutex poisoned");
            while !state.meta_waiting {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return false;
                }
                let wait_for = timeout.saturating_sub(elapsed);
                let (next_state, timed_out) = self
                    .cv
                    .wait_timeout(state, wait_for)
                    .expect("blocking sink condvar wait poisoned");
                state = next_state;
                if timed_out.timed_out() && !state.meta_waiting {
                    return false;
                }
            }
            true
        }

        fn events(&self) -> Vec<&'static str> {
            self.events
                .lock()
                .expect("blocking sink events mutex poisoned")
                .clone()
        }
    }

    impl EventSink for BlockingCommitMetaSink {
        fn emit(&self, event: ScanEvent<'_>) {
            match event {
                ScanEvent::CommitMeta(_) => {
                    let mut state = self
                        .state
                        .lock()
                        .expect("blocking sink state mutex poisoned");
                    state.meta_waiting = true;
                    self.cv.notify_all();
                    while !state.allow_meta_emit {
                        state = self
                            .cv
                            .wait(state)
                            .expect("blocking sink condvar wait poisoned");
                    }
                    drop(state);

                    self.events
                        .lock()
                        .expect("blocking sink events mutex poisoned")
                        .push("commit_meta");
                }
                ScanEvent::Finding(_) => {
                    self.events
                        .lock()
                        .expect("blocking sink events mutex poisoned")
                        .push("finding");
                    let mut state = self
                        .state
                        .lock()
                        .expect("blocking sink state mutex poisoned");
                    if state.meta_waiting {
                        state.allow_meta_emit = true;
                        self.cv.notify_all();
                    }
                }
                _ => {}
            }
        }

        fn flush(&self) {}
    }

    #[test]
    fn parallel_adapters_can_emit_finding_before_commit_meta_for_same_commit() {
        let entries = vec![(test_oid(0xdd), 4_000)];
        let engine = Arc::new(test_engine_with_tok_rule());
        let sink = Arc::new(BlockingCommitMetaSink::new());

        let graph = SmallTestGraph::new(&entries);
        let commit_graph_index = Arc::new(CommitGraphIndex::build(&graph).expect("build graph"));
        let commit_meta_seen = Arc::new(AtomicBitSet::empty(commit_graph_index.len().max(1)));
        let blob = b"prefix TOK_ABCDEFGH suffix";

        let worker_a = {
            let engine = Arc::clone(&engine);
            let sink = Arc::clone(&sink);
            let commit_graph_index = Arc::clone(&commit_graph_index);
            let commit_meta_seen = Arc::clone(&commit_meta_seen);
            std::thread::spawn(move || {
                let event_sink: Arc<dyn EventSink> = sink;
                let mut adapter = EngineAdapter::new_with_event_sink(
                    engine.as_ref(),
                    EngineAdapterConfig::default(),
                    CommitMetaContext {
                        event_sink,
                        commit_graph_index,
                        commit_meta_seen,
                        identity_interner: None,
                    },
                );
                let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
                adapter
                    .emit_loose(&candidate, b"a.txt", blob)
                    .expect("worker A scan");
            })
        };

        assert!(
            sink.wait_until_meta_waiting(Duration::from_secs(2)),
            "timed out waiting for worker A to block in commit_meta emit"
        );

        let worker_b = {
            let engine = Arc::clone(&engine);
            let sink = Arc::clone(&sink);
            let commit_graph_index = Arc::clone(&commit_graph_index);
            let commit_meta_seen = Arc::clone(&commit_meta_seen);
            std::thread::spawn(move || {
                let event_sink: Arc<dyn EventSink> = sink;
                let mut adapter = EngineAdapter::new_with_event_sink(
                    engine.as_ref(),
                    EngineAdapterConfig::default(),
                    CommitMetaContext {
                        event_sink,
                        commit_graph_index,
                        commit_meta_seen,
                        identity_interner: None,
                    },
                );
                let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
                adapter
                    .emit_loose(&candidate, b"b.txt", blob)
                    .expect("worker B scan");
            })
        };

        worker_b.join().expect("worker B join");
        worker_a.join().expect("worker A join");

        let events = sink.events();
        let first_finding = events
            .iter()
            .position(|ty| *ty == "finding")
            .expect("expected at least one finding event");
        let first_meta = events
            .iter()
            .position(|ty| *ty == "commit_meta")
            .expect("expected commit_meta event");
        assert!(
            first_finding < first_meta,
            "expected a finding before commit_meta for the same commit: {events:?}"
        );
    }

    #[test]
    fn commit_meta_emitted_once_per_commit() {
        let entries = vec![(test_oid(0xaa), 1000), (test_oid(0xbb), 2000)];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

        let blob = b"prefix TOK_ABCDEFGH suffix";

        // Two scans with the same commit_id=0.
        let c0 = make_candidate_with_ctx(0, ChangeKind::Add);
        adapter.emit_loose(&c0, b"a.txt", blob).expect("scan 1");
        adapter.emit_loose(&c0, b"b.txt", blob).expect("scan 2");

        // One scan with commit_id=1.
        let c1 = make_candidate_with_ctx(1, ChangeKind::Add);
        adapter.emit_loose(&c1, b"c.txt", blob).expect("scan 3");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        let events = parse_jsonl_types(&output);

        let meta_count = events.iter().filter(|(t, _)| *t == "commit_meta").count();
        assert_eq!(
            meta_count, 2,
            "expected exactly 2 commit_meta events (one per unique commit_id), got {meta_count}: {output}"
        );

        // Verify each commit_id has exactly one commit_meta.
        let meta_ids: Vec<u64> = events
            .iter()
            .filter(|(t, _)| *t == "commit_meta")
            .map(|(_, id)| id.unwrap())
            .collect();
        assert!(meta_ids.contains(&0), "missing commit_meta for id=0");
        assert!(meta_ids.contains(&1), "missing commit_meta for id=1");
    }

    #[test]
    fn no_commit_meta_without_findings() {
        let entries = vec![(test_oid(0xcc), 3000)];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

        let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
        let blob = b"nothing suspicious here";
        adapter
            .emit_loose(&candidate, b"clean.txt", blob)
            .expect("scan clean blob");

        let output = sink.take();
        assert!(
            output.is_empty(),
            "no events should be emitted for blobs without findings"
        );
    }

    #[test]
    fn out_of_range_commit_id_emits_diagnostic() {
        // Graph has 1 entry (positions 0..1); commit_id=5 is out of range.
        let entries = vec![(test_oid(0xaa), 1000)];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

        let candidate = make_candidate_with_ctx(5, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"secret.txt", blob)
            .expect("scan with out-of-range commit_id");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        // Findings should still be emitted.
        assert!(
            output.contains("\"type\":\"finding\""),
            "findings must still be emitted for out-of-range commit_id: {output}"
        );
        // No commit_meta should be emitted (commit_id is out of range).
        assert!(
            !output.contains("\"type\":\"commit_meta\""),
            "commit_meta must not be emitted for out-of-range commit_id: {output}"
        );
        // A diagnostic warning should be emitted so the skip is visible.
        assert!(
            output.contains("\"type\":\"diagnostic\""),
            "expected a diagnostic event for out-of-range commit_id, got: {output}"
        );
    }

    #[test]
    fn commit_meta_carries_correct_oid_and_timestamp() {
        let oid = OidBytes::sha1([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);
        let entries = vec![(oid, 1_234_567_890)];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

        let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
        let blob = b"prefix TOK_ABCDEFGH suffix";
        adapter
            .emit_loose(&candidate, b"s.txt", blob)
            .expect("scan");

        let output = String::from_utf8(sink.take()).expect("valid UTF-8");
        assert!(
            output.contains("\"oid\":\"deadbeef0123456789abcdeffedcba9876543210\""),
            "OID hex must match: {output}"
        );
        assert!(
            output.contains("\"timestamp\":1234567890"),
            "timestamp must match: {output}"
        );
    }

    #[test]
    #[should_panic(expected = "AtomicBitSet bit_length")]
    fn mismatched_bitset_and_graph_panics_in_debug() {
        // Graph has 3 entries but bitset only has 1 bit — mismatch.
        let entries = vec![
            (test_oid(0xaa), 1000),
            (test_oid(0xbb), 2000),
            (test_oid(0xcc), 3000),
        ];
        let engine = test_engine_with_tok_rule();
        let sink = Arc::new(VecEventSink::new());
        let graph = SmallTestGraph::new(&entries);
        let cg = Arc::new(CommitGraphIndex::build(&graph).expect("build test graph"));
        // Deliberately create a bitset smaller than the graph.
        let seen = Arc::new(AtomicBitSet::empty(1));
        let _adapter = EngineAdapter::new_with_event_sink(
            &engine,
            EngineAdapterConfig::default(),
            CommitMetaContext {
                event_sink: sink,
                commit_graph_index: cg,
                commit_meta_seen: seen,
                identity_interner: None,
            },
        );
    }
}
