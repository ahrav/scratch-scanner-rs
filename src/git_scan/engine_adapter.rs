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
//! # Design
//! - Chunk overlap uses `Engine::required_overlap()` and
//!   `ScanScratch::drop_prefix_findings`.
//! - A fixed-size ring buffer streams blob bytes into the scanner, avoiding
//!   per-blob allocations beyond the chunk window.
//! - Findings are stored in a shared arena with per-blob spans.
//!
//! # Invariants
//! - Results are returned in candidate order.
//! - `ScannedBlob.findings` indexes into the adapter's findings arena.
//! - Path refs in results point into the mapping arena supplied by the caller.
//! - When the debug allocation guard is enabled, scanning must not allocate.

use std::fmt;

use crate::scheduler::AllocGuard;
use crate::{Engine, FileId, NormHash, ScanScratch};

use super::alloc_guard;
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate};
use super::pack_exec::{PackExecError, PackObjectSink};
use super::perf;
use super::tree_candidate::CandidateContext;

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
}

impl Default for EngineAdapterConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: DEFAULT_CHUNK_BYTES,
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
pub struct EngineAdapter<'a> {
    engine: &'a Engine,
    scratch: ScanScratch,
    overlap: usize,
    chunk_bytes: usize,
    results: Vec<ScannedBlob>,
    findings_arena: Vec<FindingKey>,
    findings_buf: Vec<FindingKey>,
    chunker: RingChunker,
    // Monotone ID for this adapter instance; wraps on overflow.
    next_file_id: u32,
}

impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter bound to the given engine.
    ///
    /// The adapter computes overlap from `engine.required_overlap()` and
    /// clamps `config.chunk_bytes` to ensure forward progress. Scratch
    /// space and the ring chunker are allocated once and reused across
    /// all subsequent `emit` / `emit_loose` calls.
    #[must_use]
    pub fn new(engine: &'a Engine, config: EngineAdapterConfig) -> Self {
        let overlap = engine.required_overlap();
        let chunk_bytes = effective_chunk_bytes(config.chunk_bytes, overlap);
        Self {
            engine,
            scratch: engine.new_scratch(),
            overlap,
            chunk_bytes,
            results: Vec::new(),
            findings_arena: Vec::new(),
            findings_buf: Vec::with_capacity(64),
            chunker: RingChunker::new(chunk_bytes, overlap),
            next_file_id: 0,
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
    pub fn reserve_findings_buf(&mut self, additional: usize) {
        self.findings_buf.reserve(additional);
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
        _path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, bytes)?;
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
    }

    fn scan_blob_into_buf(
        &mut self,
        file_id: FileId,
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        self.findings_buf.clear();
        if is_likely_binary(bytes, 8192) {
            perf::record_scan_binary_skip();
            return Ok(());
        }
        scan_blob_chunked_with_chunker(
            self.engine,
            &mut self.scratch,
            file_id,
            bytes,
            self.overlap,
            &mut self.chunker,
            &mut self.findings_buf,
        )
    }

    fn record_findings(&mut self) -> Result<FindingSpan, EngineAdapterError> {
        let start = self.findings_arena.len();
        let len = self.findings_buf.len();
        let end = start.saturating_add(len);
        if end > u32::MAX as usize {
            return Err(EngineAdapterError::FindingArenaOverflow { end, max: u32::MAX });
        }

        // Extend the shared arena; the returned span is used by `ScannedBlob`.
        self.findings_arena.extend_from_slice(&self.findings_buf);
        Ok(FindingSpan {
            start: start as u32,
            len: len as u32,
        })
    }
}

impl PackObjectSink for EngineAdapter<'_> {
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        _path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, bytes)?;
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
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
/// Ensures `chunk_bytes > overlap` and caps the result at `u32::MAX` so
/// finding offsets can safely downcast to `u32`.
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

/// Returns `true` if the first `check_len` bytes of `data` contain a NUL byte,
/// indicating the blob is likely binary (images, compiled objects, etc.).
///
/// Uses `memchr` for SIMD-accelerated scanning, matching Git's own
/// `buffer_is_binary` heuristic. Empty blobs are not considered binary.
#[inline]
fn is_likely_binary(data: &[u8], check_len: usize) -> bool {
    if data.is_empty() {
        return false;
    }
    let end = data.len().min(check_len);
    memchr::memchr(0, &data[..end]).is_some()
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
/// an overlap prefix from the previous window. The `is_first` flag prevents
/// the first window's prefix from being treated as overlap.
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
#[cfg(test)]
const _: () = {
    fn assert_send<T: Send>() {}
    fn check() {
        assert_send::<super::EngineAdapter<'_>>();
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
        let ctx = CandidateContext {
            commit_id: 0,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        };
        LooseCandidate {
            oid: OidBytes::from_slice(&[0u8; 20]),
            ctx,
        }
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

    /// is_likely_binary edge cases.
    #[test]
    fn is_likely_binary_edge_cases() {
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
}
