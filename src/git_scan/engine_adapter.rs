//! Engine adapter for Git blob scanning.
//!
//! Bridges decoded blob bytes into the core `Engine` using overlap-safe chunking
//! and a fixed-size ring buffer, then aggregates findings per blob with
//! deterministic ordering.
//!
//! # Design
//! - Chunk overlap uses `Engine::required_overlap()` and `ScanScratch::drop_prefix_findings`.
//! - A fixed-size ring buffer streams blob bytes into the scanner, avoiding
//!   per-blob allocations beyond the chunk window.
//! - Findings are converted to `FindingKey` values (no raw secret bytes),
//!   sorted + deduped per blob, and stored in a shared arena with per-blob spans.
//!
//! # Invariants
//! - Results are returned in candidate order.
//! - `ScannedBlob.findings` indexes into the adapter's findings arena.
//! - Path refs in results point into the adapter's path arena.
//! - When the debug allocation guard is enabled, scanning must not allocate.

use std::fmt;

use crate::scheduler::AllocGuard;
use crate::{Engine, FileId, NormHash, ScanScratch};

use super::alloc_guard;
use super::byte_arena::{ByteArena, ByteRef};
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate};
use super::pack_exec::{PackExecError, PackObjectSink};
use super::tree_candidate::CandidateContext;

/// Default chunk window size for adapter scanning (1 MiB).
pub const DEFAULT_CHUNK_BYTES: usize = 1 << 20;
/// Default capacity for the adapter path arena (4 MiB).
pub const DEFAULT_PATH_ARENA_BYTES: u32 = 4 * 1024 * 1024;

/// Engine adapter configuration.
#[derive(Clone, Copy, Debug)]
pub struct EngineAdapterConfig {
    /// Total chunk window size (prefix + payload).
    ///
    /// The adapter will clamp this to at least `required_overlap + 1`.
    pub chunk_bytes: usize,
    /// Maximum bytes for the adapter path arena.
    pub path_arena_bytes: u32,
}

impl Default for EngineAdapterConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            path_arena_bytes: DEFAULT_PATH_ARENA_BYTES,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingSpan {
    /// Start index in the findings arena.
    pub start: u32,
    /// Number of findings for the blob.
    pub len: u32,
}

/// Blob scanned by the engine adapter.
#[derive(Clone, Debug)]
pub struct ScannedBlob {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context with path reference (adapter-owned arena).
    pub ctx: CandidateContext,
    /// Sorted + deduped findings span in the adapter findings arena.
    pub findings: FindingSpan,
}

/// Collected scan results with a shared findings arena.
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
    /// Path length exceeds `ByteRef` limits.
    PathTooLong { len: usize, max: u16 },
    /// Path arena is out of space.
    PathArenaFull { needed: usize, remaining: u32 },
    /// Finding offsets exceed `u32` bounds.
    FindingOffsetOverflow { start: u64, end: u64 },
    /// Findings arena index exceeds `u32` bounds.
    FindingArenaOverflow { end: usize, max: u32 },
}

impl fmt::Display for EngineAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathTooLong { len, max } => {
                write!(f, "path length {len} exceeds max {max}")
            }
            Self::PathArenaFull { needed, remaining } => {
                write!(
                    f,
                    "path arena full (needed {needed} bytes, remaining {remaining})"
                )
            }
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
/// minimize allocations on hot paths.
pub struct EngineAdapter<'a> {
    engine: &'a Engine,
    scratch: ScanScratch,
    overlap: usize,
    chunk_bytes: usize,
    path_arena: ByteArena,
    results: Vec<ScannedBlob>,
    findings_arena: Vec<FindingKey>,
    findings_buf: Vec<FindingKey>,
    chunker: RingChunker,
    next_file_id: u32,
}

impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter.
    #[must_use]
    pub fn new(engine: &'a Engine, config: EngineAdapterConfig) -> Self {
        let overlap = engine.required_overlap();
        let chunk_bytes = effective_chunk_bytes(config.chunk_bytes, overlap);
        Self {
            engine,
            scratch: engine.new_scratch(),
            overlap,
            chunk_bytes,
            path_arena: ByteArena::with_capacity(config.path_arena_bytes),
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

    /// Returns the adapter-owned path arena.
    #[must_use]
    pub fn path_arena(&self) -> &ByteArena {
        &self.path_arena
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
    pub fn emit_loose(
        &mut self,
        candidate: &LooseCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let path_ref = self.intern_path(path)?;
        let mut ctx = candidate.ctx;
        ctx.path_ref = path_ref;

        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, bytes)?;
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx,
            findings: span,
        });
        Ok(())
    }

    fn intern_path(&mut self, path: &[u8]) -> Result<ByteRef, EngineAdapterError> {
        if path.len() > ByteRef::MAX_LEN as usize {
            return Err(EngineAdapterError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN,
            });
        }
        self.path_arena
            .intern(path)
            .ok_or(EngineAdapterError::PathArenaFull {
                needed: path.len(),
                remaining: self.path_arena.remaining(),
            })
    }

    fn scan_blob_into_buf(
        &mut self,
        file_id: FileId,
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        self.findings_buf.clear();
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
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let path_ref = self.intern_path(path)?;
        let mut ctx = candidate.ctx;
        ctx.path_ref = path_ref;

        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, bytes)?;
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx,
            findings: span,
        });
        Ok(())
    }
}

/// Scan a blob with overlap-safe chunking and return sorted + deduped findings.
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

fn effective_chunk_bytes(requested: usize, overlap: usize) -> usize {
    // Enforce progress and clamp to u32::MAX for offset conversion safety.
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

/// Scan a blob using a reusable chunker and optional allocation guard.
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

    out.sort_unstable();
    out.dedup();

    if let Some(guard) = guard {
        guard.assert_no_alloc();
    }

    Ok(())
}

fn scan_chunk(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    overlap: usize,
    view: ChunkView<'_>,
    out: &mut Vec<FindingKey>,
    err: &mut Option<EngineAdapterError>,
) {
    engine.scan_chunk_into(view.window, file_id, view.base, scratch);
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

struct ChunkView<'a> {
    /// Absolute start offset of `window` within the blob.
    base: u64,
    is_first: bool,
    window: &'a [u8],
}

/// Fixed-size ring chunker for streaming blob bytes.
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

    fn overlap(&self) -> usize {
        self.overlap
    }

    fn reset(&mut self) {
        self.filled = 0;
        self.base = 0;
        self.is_first = true;
    }

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
