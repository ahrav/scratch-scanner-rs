#![allow(dead_code, unused_imports, unused_variables, unused_assignments)]
//! High-throughput content scanner with bounded decoding and explicit provenance.
//!
//! The engine is optimized for scanning large byte streams using:
//! - Anchor-based windowing (Aho-Corasick) to limit regex work.
//! - Optional two-phase confirmation for noisy rules.
//! - Transform decoding (URL percent, Base64) with streaming gates and budgets.
//! - Base64 encoded-space pre-gate (YARA-style) to skip wasteful decodes.
//! - Fixed-capacity scratch buffers to avoid per-chunk allocation churn.
//!
//! High-level flow (single chunk):
//! 1) Anchor scan over raw + UTF-16 variants.
//! 2) Build and merge windows around anchors.
//! 3) Optional two-phase confirm, then expand to full windows.
//! 4) Regex validation inside windows.
//! 5) Optional transform decode with gating, bounded recursion, and dedupe.
//!
//! Pipeline flow (files):
//! Path -> Walker -> FileTable -> Reader -> Chunk -> Engine -> Findings -> Output.
//!
//! For a longer design walkthrough, see `docs/architecture.md`.

pub mod pipeline;
pub mod pool;
pub mod regex2anchor;
pub mod scratch_memory;
pub mod stdx;
pub mod b64_yara_gate;
#[cfg(test)]
pub mod test_utils;
pub mod util;

use crate::regex2anchor::{
    compile_trigger_plan, AnchorDeriveConfig, ResidueGatePlan, TriggerPlan, UnfilterableReason,
};
use crate::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, PaddingPolicy, WhitespacePolicy};
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use memchr::memchr;
use memchr::memmem;
use regex::bytes::Regex;
use std::cell::{Cell, UnsafeCell};
use std::fs::File;
use std::io::{self, Read};
use std::ops::{ControlFlow, Range};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;
use std::slice;
use std::sync::Arc;

use crate::pool::NodePoolType;
use crate::scratch_memory::ScratchVec;
use crate::stdx::{DynamicBitSet, FixedSet128};

// --------------------------
// Public API types
// --------------------------

/// Opaque file identifier used to index into [`FileTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId(pub u32);

/// Compact index into the decode-step arena.
///
/// Steps are chained from the root buffer to derived buffers so findings can be
/// reconstructed without cloning vectors on the hot path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StepId(u32);

const STEP_ROOT: StepId = StepId(u32::MAX);

impl Default for StepId {
    fn default() -> Self {
        STEP_ROOT
    }
}

/// Identifies a supported transform used for derived-buffer scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransformId {
    UrlPercent,
    Base64,
    // Add more: JsonUnescape, HtmlUnescape, Gzip, Zlib, Brotli, etc.
}

/// Controls when a transform is applied during scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformMode {
    Disabled,
    Always,

    /// Correctness trade (explicit).
    /// Skips this transform if this buffer already produced any findings.
    IfNoFindingsInThisBuffer,
}

/// Gate policy for expensive transform decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    None,

    /// Stream-decode and proceed only if decoded bytes contain any anchor variant
    /// (raw + UTF-16LE/BE variants).
    AnchorsInDecoded,
}

/// Configuration for a single transform stage.
#[derive(Clone, Debug)]
pub struct TransformConfig {
    /// Transform kind.
    pub id: TransformId,

    /// When this transform is applied.
    pub mode: TransformMode,

    /// Gate policy (if enabled).
    pub gate: Gate,

    /// Minimum encoded length to consider for span detection.
    pub min_len: usize,
    /// Limit of candidate spans to process per buffer.
    pub max_spans_per_buffer: usize,
    /// Maximum encoded length to consider for a span.
    pub max_encoded_len: usize,

    /// Maximum decoded bytes produced per span.
    pub max_decoded_bytes: usize,

    /// URL option: treat '+' as space.
    pub plus_to_space: bool,

    /// Base64 option: allow space as whitespace during span detection.
    pub base64_allow_space_ws: bool,
}

/// Base64 decode/gate instrumentation counters.
#[cfg(feature = "b64-stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Base64DecodeStats {
    /// Number of base64 spans considered (after span caps).
    pub spans: u64,
    /// Total encoded bytes across considered spans.
    pub span_bytes: u64,

    /// Number of spans checked by the pre-decode base64 gate.
    pub pre_gate_checks: u64,
    /// Spans that passed the pre-decode base64 gate.
    pub pre_gate_pass: u64,
    /// Spans skipped by the pre-decode base64 gate.
    pub pre_gate_skip: u64,
    /// Encoded bytes skipped by the pre-decode base64 gate.
    pub pre_gate_skip_bytes: u64,

    /// Number of spans actually sent to the base64 decoder.
    pub decode_attempts: u64,
    /// Total encoded bytes sent to the base64 decoder.
    pub decode_attempt_bytes: u64,
    /// Number of decode attempts that failed/truncated/empty.
    pub decode_errors: u64,

    /// Total decoded bytes produced by the decoder (even if discarded).
    pub decoded_bytes_total: u64,
    /// Decoded bytes kept (anchor hit).
    pub decoded_bytes_kept: u64,
    /// Decoded bytes discarded due to no anchor hit.
    pub decoded_bytes_wasted_no_anchor: u64,
    /// Decoded bytes discarded due to decode errors/truncation.
    pub decoded_bytes_wasted_error: u64,
}

#[cfg(feature = "b64-stats")]
impl Base64DecodeStats {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn add(&mut self, other: &Self) {
        self.spans = self.spans.saturating_add(other.spans);
        self.span_bytes = self.span_bytes.saturating_add(other.span_bytes);

        self.pre_gate_checks = self.pre_gate_checks.saturating_add(other.pre_gate_checks);
        self.pre_gate_pass = self.pre_gate_pass.saturating_add(other.pre_gate_pass);
        self.pre_gate_skip = self.pre_gate_skip.saturating_add(other.pre_gate_skip);
        self.pre_gate_skip_bytes = self
            .pre_gate_skip_bytes
            .saturating_add(other.pre_gate_skip_bytes);

        self.decode_attempts = self.decode_attempts.saturating_add(other.decode_attempts);
        self.decode_attempt_bytes = self
            .decode_attempt_bytes
            .saturating_add(other.decode_attempt_bytes);
        self.decode_errors = self.decode_errors.saturating_add(other.decode_errors);

        self.decoded_bytes_total = self
            .decoded_bytes_total
            .saturating_add(other.decoded_bytes_total);
        self.decoded_bytes_kept = self
            .decoded_bytes_kept
            .saturating_add(other.decoded_bytes_kept);
        self.decoded_bytes_wasted_no_anchor = self
            .decoded_bytes_wasted_no_anchor
            .saturating_add(other.decoded_bytes_wasted_no_anchor);
        self.decoded_bytes_wasted_error = self
            .decoded_bytes_wasted_error
            .saturating_add(other.decoded_bytes_wasted_error);
    }
}

/// UTF-16 endianness used when validating UTF-16 anchor hits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Utf16Endianness {
    Le,
    Be,
}

/// A single decode step in the provenance chain for a finding.
#[derive(Clone, Debug)]
pub enum DecodeStep {
    /// Transform step is deterministic via transform_idx (index into Engine.transforms).
    Transform {
        transform_idx: usize,
        parent_span: Range<usize>, // span in the parent representation
    },

    /// Not a queued transform. This is a local validation step used when an UTF-16 anchor variant hits.
    /// The consumer can replay this by decoding parent_span as UTF-16 with the given endianness.
    Utf16Window {
        endianness: Utf16Endianness,
        parent_span: Range<usize>, // span in the parent representation
    },
}

/// High-level finding with provenance and root-span hint.
#[derive(Clone, Debug)]
pub struct Finding {
    /// Rule name that produced this finding.
    pub rule: &'static str,

    /// Span in the final representation obtained by applying `decode_steps`.
    /// - If `decode_steps` is empty, this is a span in the input buffer.
    /// - If the last step is `Utf16Window`, span is in the UTF-8 bytes produced by decoding.
    pub span: Range<usize>,

    /// Best-effort hint into the original/root buffer.
    /// - For raw findings in root: exact match span.
    /// - For derived buffers: outermost container span in root (or best available).
    /// - For UTF-16 window findings in root: the decoded window span in root.
    pub root_span_hint: Range<usize>,

    /// Decode steps from root buffer to the representation where `span` applies.
    pub decode_steps: Vec<DecodeStep>,
}

/// Compact finding record stored during scanning.
///
/// This is later materialized into [`Finding`] by expanding the decode-step chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingRec {
    /// Source file id for the finding.
    pub file_id: FileId,
    /// Rule index (engine-local).
    pub rule_id: u32,
    /// Span start in the current buffer (byte index).
    pub span_start: u32,
    /// Span end in the current buffer (byte index).
    pub span_end: u32,
    /// Best-effort root span hint (absolute byte offset in file).
    pub root_hint_start: u64,
    /// Best-effort root span hint (absolute byte offset in file).
    pub root_hint_end: u64,
    /// Decode-step chain id for reconstructing provenance.
    /// Valid only while the originating `ScanScratch` arena is alive and not reset.
    pub step_id: StepId,
}

/// Two-phase rule specification: confirm in a smaller seed window, then expand.
#[derive(Clone, Debug)]
pub struct TwoPhaseSpec {
    /// Radius for the seed window used for confirm checks.
    pub seed_radius: usize,
    /// Radius for the expanded window after confirmation.
    pub full_radius: usize,
    /// Patterns that must appear within the seed window to confirm.
    pub confirm_any: &'static [&'static [u8]],
}

/// Rule configuration for anchor scan + regex validation.
#[derive(Clone, Debug)]
pub struct RuleSpec {
    /// Rule name used for reporting.
    pub name: &'static str,

    /// ASCII-ish anchors. The engine also generates UTF-16LE/BE variants.
    pub anchors: &'static [&'static [u8]],

    /// Radius in bytes around an anchor hit (raw representation).
    pub radius: usize,

    /// Optional two-phase confirm + expand configuration.
    pub two_phase: Option<TwoPhaseSpec>,

    /// Optional cheap byte-substring check before running regex.
    pub must_contain: Option<&'static [u8]>,

    /// Final check. Bytes regex (no UTF-8 assumption).
    pub re: Regex,
}

/// Engine tuning knobs for performance and DoS protection.
#[derive(Clone, Debug)]
pub struct Tuning {
    /// Window merge gap (bytes) when coalescing adjacent anchor hits.
    pub merge_gap: usize,

    /// After merging, if windows per (rule, variant) still exceed this, coalesce under pressure.
    pub max_windows_per_rule_variant: usize,
    /// Starting gap used during pressure coalescing.
    pub pressure_gap_start: usize,

    /// Prevent vector blowups before merging by collapsing to a single coalesced range.
    pub max_anchor_hits_per_rule_variant: usize,

    /// UTF-16 decoding (for validation).
    pub max_utf16_decoded_bytes_per_window: usize,

    /// Max transform depth (number of decode steps) per work item chain.
    pub max_transform_depth: usize,

    /// Counts ALL decoded output bytes:
    /// - full decodes
    /// - streaming gate decoded chunks
    /// - UTF-16 window decode output
    pub max_total_decode_output_bytes: usize,

    /// Hard cap on number of enqueued decoded buffers (DoS control).
    pub max_work_items: usize,

    /// Hard cap on findings per buffer/chunk.
    pub max_findings_per_chunk: usize,
}

// --------------------------
// Pipeline data types
// --------------------------

/// File table flag: input appears to be binary.
pub const FILE_FLAG_BINARY: u32 = 1 << 0;
/// File table flag: file was skipped by the pipeline.
pub const FILE_FLAG_SKIPPED: u32 = 1 << 1;

/// Columnar file metadata store used by the pipeline.
///
/// Uses parallel vectors (SoA) to keep memory note simple and allow stable
/// indexing via [`FileId`].
#[derive(Default)]
pub struct FileTable {
    paths: Vec<PathBuf>,
    sizes: Vec<u64>,
    dev_inodes: Vec<(u64, u64)>,
    flags: Vec<u32>,
}

impl FileTable {
    /// Creates a table with capacity hints for the parallel arrays.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            paths: Vec::with_capacity(cap),
            sizes: Vec::with_capacity(cap),
            dev_inodes: Vec::with_capacity(cap),
            flags: Vec::with_capacity(cap),
        }
    }

    /// Inserts a new file record and returns its [`FileId`].
    pub fn push(&mut self, path: PathBuf, size: u64, dev_inode: (u64, u64), flags: u32) -> FileId {
        assert!(self.paths.len() < u32::MAX as usize);
        let id = FileId(self.paths.len() as u32);
        self.paths.push(path);
        self.sizes.push(size);
        self.dev_inodes.push(dev_inode);
        self.flags.push(flags);
        id
    }

    /// Returns the number of tracked files.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns true when the table is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Returns the path for a given file id.
    pub fn path(&self, id: FileId) -> &PathBuf {
        &self.paths[id.0 as usize]
    }

    /// Returns the file size for a given file id.
    pub fn size(&self, id: FileId) -> u64 {
        self.sizes[id.0 as usize]
    }

    /// Returns stored flags for a given file id.
    pub fn flags(&self, id: FileId) -> u32 {
        self.flags[id.0 as usize]
    }
}

/// A chunk of file data plus its overlap prefix.
///
/// `prefix_len` indicates how many bytes at the front are overlap from the
/// previous chunk. `payload()` excludes that prefix.
pub struct Chunk {
    pub file_id: FileId,
    pub base_offset: u64,
    pub len: u32,
    pub prefix_len: u32,
    pub buf: BufferHandle,
}

impl Chunk {
    /// Full data slice, including the overlap prefix.
    pub fn data(&self) -> &[u8] {
        let end = self.len as usize;
        &self.buf.as_slice()[..end]
    }

    /// Payload slice excluding the overlap prefix.
    pub fn payload(&self) -> &[u8] {
        let start = self.prefix_len as usize;
        let end = self.len as usize;
        &self.buf.as_slice()[start..end]
    }
}

/// Maximum chunk buffer length (bytes).
pub const BUFFER_LEN_MAX: usize = 2 * 1024 * 1024;
/// Alignment for pooled buffers (bytes).
pub const BUFFER_ALIGN: usize = 4096;

const _: () = {
    assert!(BUFFER_LEN_MAX > 0);
    assert!(BUFFER_LEN_MAX.is_power_of_two());
    assert!(BUFFER_ALIGN.is_power_of_two());
    assert!(BUFFER_ALIGN <= 4096);
    assert!(BUFFER_LEN_MAX.is_multiple_of(BUFFER_ALIGN));
};

/// Shared pool state with interior mutability for allocation-free chunk buffers.
///
/// This is intentionally single-threaded: we use `Rc` + `Cell` + `UnsafeCell`
/// for zero-overhead access. If/when the pipeline becomes multi-threaded, this
/// must be replaced with a thread-safe pool or per-thread pools.
struct BufferPoolInner {
    pool: UnsafeCell<NodePoolType<BUFFER_LEN_MAX, BUFFER_ALIGN>>,
    // Fast-path availability check to avoid touching the bitset on empty pools.
    available: Cell<u32>,
    capacity: u32,
}

impl BufferPoolInner {
    fn acquire_slot(&self) -> NonNull<u8> {
        let avail = self.available.get();
        assert!(avail > 0, "buffer pool exhausted");

        let ptr = unsafe { (&mut *self.pool.get()).acquire() };
        self.available.set(avail - 1);

        ptr
    }

    fn release_slot(&self, ptr: NonNull<u8>) {
        unsafe { (&mut *self.pool.get()).release(ptr) };

        let avail = self.available.get();
        let new_avail = avail + 1;
        assert!(new_avail <= self.capacity);
        self.available.set(new_avail);
    }
}

/// Fixed-capacity pool of aligned buffers used for file chunks.
///
/// Each acquired buffer is returned to the pool when its [`BufferHandle`] drops.
/// This pool is `Rc`-backed and intended for single-threaded use.
#[derive(Clone)]
pub struct BufferPool(Rc<BufferPoolInner>);

impl BufferPool {
    /// Creates a buffer pool with `capacity` buffers.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        assert!(capacity <= u32::MAX as usize);

        let pool = NodePoolType::<BUFFER_LEN_MAX, BUFFER_ALIGN>::init(capacity as u32);

        Self(Rc::new(BufferPoolInner {
            pool: UnsafeCell::new(pool),
            available: Cell::new(capacity as u32),
            capacity: capacity as u32,
        }))
    }

    /// Attempts to acquire a buffer; returns `None` if the pool is exhausted.
    pub fn try_acquire(&self) -> Option<BufferHandle> {
        if self.0.available.get() == 0 {
            return None;
        }

        let ptr = self.0.acquire_slot();
        Some(BufferHandle {
            pool: Rc::clone(&self.0),
            ptr,
        })
    }

    /// Acquires a buffer, panicking if the pool is exhausted.
    pub fn acquire(&self) -> BufferHandle {
        self.try_acquire().expect("buffer pool exhausted")
    }

    /// Returns the fixed buffer length for this pool.
    pub fn buf_len(&self) -> usize {
        BUFFER_LEN_MAX
    }
}

/// RAII handle to a pool buffer, returned to the pool on drop.
pub struct BufferHandle {
    pool: Rc<BufferPoolInner>,
    ptr: NonNull<u8>,
}

impl BufferHandle {
    /// Returns a shared view over the entire buffer.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Returns a mutable view over the entire buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Zeroes the entire buffer.
    pub fn clear(&mut self) {
        self.as_mut_slice().fill(0);
    }
}

impl Drop for BufferHandle {
    fn drop(&mut self) {
        let ptr = self.ptr;
        self.pool.release_slot(ptr);
    }
}

/// Reads a file in fixed-size chunks, preserving overlap between chunks.
///
/// The overlap allows anchor windows to extend across chunk boundaries without
/// missing matches. Each emitted `Chunk` includes:
/// - `prefix_len`: bytes copied from the previous chunk tail
/// - `base_offset`: file offset where the chunk *starts* in the original file
///
/// This makes span reporting consistent even when a match begins in the overlap.
pub fn read_file_chunks(
    file_id: FileId,
    path: &Path,
    pool: &BufferPool,
    chunk_size: usize,
    overlap: usize,
    mut emit: impl FnMut(Chunk) -> ControlFlow<()>,
) -> io::Result<()> {
    assert!(chunk_size > 0);
    assert!(chunk_size.saturating_add(overlap) <= BUFFER_LEN_MAX);
    let mut file = File::open(path)?;
    let mut tail_len = 0usize;
    let mut tail = vec![0u8; overlap];
    let mut offset = 0u64;

    loop {
        let mut handle = pool.acquire();
        let buf = handle.as_mut_slice();
        debug_assert!(buf.len() >= tail_len + chunk_size);

        if tail_len > 0 {
            buf[..tail_len].copy_from_slice(&tail[..tail_len]);
        }

        let read = file.read(&mut buf[tail_len..tail_len + chunk_size])?;
        if read == 0 {
            break;
        }

        let total_len = tail_len + read;
        let base_offset = offset.saturating_sub(tail_len as u64);
        let next_tail_len = if overlap > 0 {
            let keep = overlap.min(total_len);
            tail[..keep].copy_from_slice(&buf[total_len - keep..total_len]);
            keep
        } else {
            0
        };

        let chunk = Chunk {
            file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: tail_len as u32,
            buf: handle,
        };

        if let ControlFlow::Break(()) = emit(chunk) {
            break;
        }

        tail_len = next_tail_len;

        offset = offset.saturating_add(read as u64);
    }

    Ok(())
}

/// Configuration for synchronous, in-process scanning.
pub struct ScannerConfig {
    /// Bytes per chunk read from disk (excluding overlap).
    pub chunk_size: usize,
    /// Number of in-flight I/O buffers.
    pub io_queue: usize,
    /// Reader thread count used by the caller (for pool sizing).
    pub reader_threads: usize,
    /// Scan thread count used by the caller (for pool sizing).
    pub scan_threads: usize,
}

impl ScannerConfig {
    /// Computes the backing buffer pool capacity needed for this configuration.
    pub fn pool_capacity(&self) -> usize {
        self.io_queue
            .saturating_add(self.scan_threads.saturating_mul(2))
            .saturating_add(self.reader_threads)
    }
}

/// Single-process scanner that reuses buffers and scratch state.
///
/// This runtime uses `Rc`-backed pools internally and is intended for
/// single-threaded use.
pub struct ScannerRuntime {
    engine: Arc<Engine>,
    config: ScannerConfig,
    overlap: usize,
    pool: BufferPool,
}

impl ScannerRuntime {
    /// Creates a scanner runtime with its own buffer pool and overlap settings.
    pub fn new(engine: Arc<Engine>, config: ScannerConfig) -> Self {
        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(config.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size + overlap exceeds BUFFER_LEN_MAX"
        );
        let pool = BufferPool::new(config.pool_capacity());
        Self {
            engine,
            config,
            overlap,
            pool,
        }
    }

    /// Scans a single file synchronously, returning findings with provenance.
    pub fn scan_file_sync(&self, file_id: FileId, path: &Path) -> io::Result<Vec<Finding>> {
        let mut scratch = self.engine.new_scratch();
        let mut out = Vec::new();

        read_file_chunks(
            file_id,
            path,
            &self.pool,
            self.config.chunk_size,
            self.overlap,
            |chunk| {
                self.engine.scan_chunk_into(
                    chunk.data(),
                    chunk.file_id,
                    chunk.base_offset,
                    &mut scratch,
                );
                let new_bytes_start = chunk.base_offset + chunk.prefix_len as u64;
                scratch.drop_prefix_findings(new_bytes_start);
                self.engine
                    .drain_findings_materialized(&mut scratch, &mut out);
                ControlFlow::Continue(())
            },
        )?;

        Ok(out)
    }
}

// --------------------------
// Internal compiled representation
// --------------------------

/// Anchor variant used during matching and window scaling.
///
/// Raw anchors match input bytes directly. UTF-16 variants match byte-encoded
/// UTF-16LE/BE anchors and double window radii via `scale()` so windows are
/// sized in bytes, not code units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Variant {
    Raw,
    Utf16Le,
    Utf16Be,
}

impl Variant {
    fn idx(self) -> usize {
        match self {
            Variant::Raw => 0,
            Variant::Utf16Le => 1,
            Variant::Utf16Be => 2,
        }
    }

    fn scale(self) -> usize {
        match self {
            Variant::Raw => 1,
            Variant::Utf16Le | Variant::Utf16Be => 2,
        }
    }

    fn utf16_endianness(self) -> Option<Utf16Endianness> {
        match self {
            Variant::Raw => None,
            Variant::Utf16Le => Some(Utf16Endianness::Le),
            Variant::Utf16Be => Some(Utf16Endianness::Be),
        }
    }
}

/// Mapping entry from an anchor pattern id to a rule/variant accumulator.
///
/// Anchor patterns are deduped in the Aho-Corasick automaton. Each pattern id
/// can fan out to multiple rules and variants; `pat_offsets` slices into the
/// flat `pat_targets` array. A `Target` is a compact (rule_id, variant) pair
/// packed into `u32` to keep the fanout table cache-friendly and avoid extra
/// pointer chasing.
#[derive(Clone, Copy, Debug)]
struct Target(u32);

impl Target {
    const VARIANT_MASK: u32 = 0b11;
    const VARIANT_SHIFT: u32 = 2;

    fn new(rule_id: u32, variant: Variant) -> Self {
        debug_assert!(rule_id <= (u32::MAX >> Self::VARIANT_SHIFT));
        Self((rule_id << Self::VARIANT_SHIFT) | variant.idx() as u32)
    }

    fn rule_id(self) -> usize {
        (self.0 >> Self::VARIANT_SHIFT) as usize
    }

    fn variant(self) -> Variant {
        match self.0 & Self::VARIANT_MASK {
            0 => Variant::Raw,
            1 => Variant::Utf16Le,
            2 => Variant::Utf16Be,
            _ => unreachable!("invalid variant tag"),
        }
    }
}

/// Packed byte patterns with an offset table.
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm-any patterns contiguous for cache-friendly memmem checks.
#[derive(Clone, Debug)]
struct PackedPatterns {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl PackedPatterns {
    fn with_capacity(patterns: usize, bytes: usize) -> Self {
        let mut offsets = Vec::with_capacity(patterns.saturating_add(1));
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(bytes),
            offsets,
        }
    }

    fn push_raw(&mut self, pat: &[u8]) {
        self.bytes.extend_from_slice(pat);
        debug_assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    fn push_utf16le(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(b);
            self.bytes.push(0);
        }
        debug_assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    fn push_utf16be(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(0);
            self.bytes.push(b);
        }
        debug_assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }
}

/// Two-phase rule data compiled per variant for fast confirm checks.
///
/// Stores prepacked confirm patterns per variant so the scan loop can run
/// memmem without per-hit allocation or UTF-16 conversions.
#[derive(Clone, Debug)]
struct TwoPhaseCompiled {
    seed_radius: usize,
    full_radius: usize,

    // confirm patterns per variant (raw bytes for Raw, utf16-bytes for Utf16Le/Be)
    confirm: [PackedPatterns; 3],
}

/// Compiled rule representation used during scanning.
///
/// This keeps precompiled regexes and optional two-phase data to minimize
/// work in the hot path.
#[derive(Clone, Debug)]
struct RuleCompiled {
    name: &'static str,
    radius: usize,
    must_contain: Option<&'static [u8]>,
    re: Regex,
    two_phase: Option<TwoPhaseCompiled>,
}

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpanU32 {
    start: u32,
    end: u32,
}

impl SpanU32 {
    fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

/// Accumulates anchor hit windows with optional coalesced fallback.
///
/// When hit counts exceed configured limits, this switches to a single merged
/// window to cap memory growth.
/// Accumulates raw anchor hit windows for a single (rule, variant).
///
/// This starts as a simple append-only list of windows. If the number of hits
/// exceeds a configured cap, it switches to a single "coalesced" window that
/// covers the union of all hits seen so far. That fallback is deliberately
/// conservative: it may make the window larger than necessary, but it prevents
/// unbounded memory growth and guarantees we still scan any true matches.
struct HitAccumulator {
    windows: ScratchVec<SpanU32>,
    coalesced: Option<SpanU32>,
}

impl HitAccumulator {
    fn with_capacity(cap: usize) -> Self {
        Self {
            windows: ScratchVec::with_capacity(cap)
                .expect("scratch hit accumulator allocation failed"),
            coalesced: None,
        }
    }

    fn push(&mut self, start: usize, end: usize, max_hits: usize) {
        let r = SpanU32::new(start, end);
        if let Some(c) = self.coalesced.as_mut() {
            // Once coalesced, we only widen the single window. This ensures
            // correctness (superset) while bounding per-rule memory.
            c.start = c.start.min(r.start);
            c.end = c.end.max(r.end);
            return;
        }

        if self.windows.len() < max_hits {
            self.windows.push(r);
            return;
        }

        // Switch to coalesced fallback once we exceed the hit cap.
        // This trades precision for deterministic memory usage.
        let mut c = self.windows[0];
        let win_len = self.windows.len();
        for i in 1..win_len {
            let w = self.windows[i];
            c.start = c.start.min(w.start);
            c.end = c.end.max(w.end);
        }
        c.start = c.start.min(r.start);
        c.end = c.end.max(r.end);

        self.windows.clear();
        self.coalesced = Some(c);
    }

    fn reset(&mut self) {
        self.windows.clear();
        self.coalesced = None;
    }

    fn capacity(&self) -> usize {
        self.windows.capacity()
    }

    fn take_into(&mut self, out: &mut ScratchVec<SpanU32>) {
        out.clear();
        if let Some(c) = self.coalesced.take() {
            out.push(c);
        } else {
            let len = self.windows.len();
            for i in 0..len {
                out.push(self.windows[i]);
            }
            self.windows.clear();
        }
    }
}

/// Scratch buffers used by the streaming gate to detect anchors across boundaries.
///
/// `tail` preserves a small suffix of the prior chunk, and `scratch` holds the
/// current decode window so we can test anchors without full decoding.
///
/// The tail length is `max_anchor_pat_len - 1`, which is the minimum overlap
/// required to avoid missing an anchor that straddles two decode chunks.
struct GateScratch {
    tail: Vec<u8>,
    scratch: Vec<u8>,
}

impl GateScratch {
    fn reset(&mut self) {
        self.tail.clear();
        self.scratch.clear();
    }
}

/// Node in the decode-step arena, linking to its parent step.
struct StepNode {
    parent: StepId,
    step: DecodeStep,
}

/// Arena for decode steps so findings store compact `StepId` references.
///
/// Why an arena?
/// - Decoding is recursive; each derived buffer adds provenance.
/// - Storing full `Vec<DecodeStep>` per finding would allocate and clone heavily.
/// - A parent-linked arena lets us store provenance once and share it across
///   findings, with O(length) reconstruction only when materializing output.
///
/// This is append-only and reset between scans. `StepId` values are only valid
/// while this arena is alive and not reset.
#[derive(Default)]
struct StepArena {
    nodes: Vec<StepNode>,
}

impl StepArena {
    fn reset(&mut self) {
        self.nodes.clear();
    }

    fn push(&mut self, parent: StepId, step: DecodeStep) -> StepId {
        let id = StepId(self.nodes.len() as u32);
        self.nodes.push(StepNode { parent, step });
        id
    }

    /// Reconstructs the step chain from root to leaf.
    fn materialize(&self, mut id: StepId, out: &mut Vec<DecodeStep>) {
        out.clear();
        while id != STEP_ROOT {
            let cur = id;
            let node = &self.nodes[cur.0 as usize];
            out.push(node.step.clone());
            id = node.parent;
        }
        out.reverse();
    }
}

/// Contiguous decoded-byte slab for derived buffers.
///
/// This is a monotonic append-only buffer:
/// - Decoders append into the slab and receive a `Range<usize>` back.
/// - Work items carry those ranges instead of owning new allocations.
/// - The slab never reallocates (capacity == global decode budget), so the
///   returned ranges remain valid for the lifetime of a scan.
///
/// The slab is cleared between scans, which invalidates all ranges at once.
struct DecodeSlab {
    buf: Vec<u8>,
    limit: usize,
}

impl DecodeSlab {
    fn with_limit(limit: usize) -> Self {
        let buf = Vec::with_capacity(limit);
        Self { buf, limit }
    }

    fn reset(&mut self) {
        self.buf.clear();
    }

    fn slice(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    fn append_stream_decode(
        &mut self,
        tc: &TransformConfig,
        input: &[u8],
        max_out: usize,
        ctx_total_decode_output_bytes: &mut usize,
        global_limit: usize,
    ) -> Result<Range<usize>, ()> {
        let start_len = self.buf.len();
        let start_ctx = *ctx_total_decode_output_bytes;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, input, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if ctx_total_decode_output_bytes.saturating_add(chunk.len()) > global_limit {
                truncated = true;
                return ControlFlow::Break(());
            }
            if self.buf.len().saturating_add(chunk.len()) > self.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            self.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            *ctx_total_decode_output_bytes =
                ctx_total_decode_output_bytes.saturating_add(chunk.len());

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            self.buf.truncate(start_len);
            *ctx_total_decode_output_bytes = start_ctx;
            return Err(());
        }

        Ok(start_len..(start_len + local_out))
    }
}

/// Per-scan scratch state reused across chunks.
///
/// This is the main allocation amortization vehicle: it owns buffers for window
/// accumulation, decode slabs, and work queues. It is not thread-safe and should
/// be used by a single worker at a time.
pub struct ScanScratch {
    out: Vec<FindingRec>,             // Hot-path findings (bounded by max_findings).
    max_findings: usize,              // Per-chunk cap from tuning.
    findings_dropped: usize,          // Overflow counter when cap is exceeded.
    work_q: Vec<WorkItem>,            // Scan queue over root + decoded buffers.
    work_head: usize,                 // Cursor into work_q.
    slab: DecodeSlab,                 // Decoded output storage.
    seen: FixedSet128,                // Dedupe for decoded buffers.
    total_decode_output_bytes: usize, // Global decode budget tracker.
    work_items_enqueued: usize,       // Work queue budget tracker.
    accs: Vec<[HitAccumulator; 3]>,   // Per (rule, variant) hit accumulators.
    touched_pairs: ScratchVec<u32>,   // Scratch list of touched pairs.
    touched: DynamicBitSet,           // Bitset for touched pairs.
    touched_any: bool,                // Fast path for "none touched".
    windows: ScratchVec<SpanU32>,     // Merged windows for a pair.
    expanded: ScratchVec<SpanU32>,    // Expanded windows for two-phase rules.
    spans: ScratchVec<SpanU32>,       // Transform span candidates.
    gate: GateScratch,                // Streaming gate scratch buffers.
    step_arena: StepArena,            // Decode provenance arena.
    utf16_buf: Vec<u8>,               // UTF-16 decode output buffer.
    steps_buf: Vec<DecodeStep>,       // Materialization scratch.
    #[cfg(feature = "b64-stats")]
    base64_stats: Base64DecodeStats,  // Base64 decode/gate instrumentation.
}

impl ScanScratch {
    fn new(engine: &Engine) -> Self {
        let rules_len = engine.rules.len();
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        let max_findings = engine.tuning.max_findings_per_chunk;
        let mut accs = Vec::with_capacity(rules_len);
        for _ in 0..rules_len {
            accs.push(std::array::from_fn(|_| {
                HitAccumulator::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
            }));
        }

        let max_steps = engine.tuning.max_work_items.saturating_add(
            rules_len.saturating_mul(2 * engine.tuning.max_windows_per_rule_variant),
        );
        let tail_keep = engine.max_anchor_pat_len.saturating_sub(1);
        let seen_cap = pow2_at_least(
            engine
                .tuning
                .max_work_items
                .next_power_of_two()
                .saturating_mul(2)
                .max(1024),
        );

        Self {
            out: Vec::with_capacity(max_findings),
            max_findings,
            findings_dropped: 0,
            work_q: Vec::with_capacity(engine.tuning.max_work_items.saturating_add(1)),
            work_head: 0,
            slab: DecodeSlab::with_limit(engine.tuning.max_total_decode_output_bytes),
            seen: FixedSet128::with_pow2(seen_cap),
            total_decode_output_bytes: 0,
            work_items_enqueued: 0,
            accs,
            touched_pairs: ScratchVec::with_capacity(rules_len.saturating_mul(3))
                .expect("scratch touched_pairs allocation failed"),
            touched: DynamicBitSet::empty(rules_len.saturating_mul(3)),
            touched_any: false,
            windows: ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                .expect("scratch windows allocation failed"),
            expanded: ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed"),
            spans: ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed"),
            gate: GateScratch {
                tail: Vec::with_capacity(tail_keep),
                scratch: Vec::with_capacity(tail_keep.saturating_add(1024)),
            },
            step_arena: StepArena {
                nodes: Vec::with_capacity(max_steps),
            },
            utf16_buf: Vec::with_capacity(engine.tuning.max_utf16_decoded_bytes_per_window),
            steps_buf: Vec::with_capacity(engine.tuning.max_transform_depth.saturating_add(1)),
            #[cfg(feature = "b64-stats")]
            base64_stats: Base64DecodeStats::default(),
        }
    }

    /// Clears per-scan state and revalidates scratch capacities against the engine.
    fn reset_for_scan(&mut self, engine: &Engine) {
        self.out.clear();
        self.findings_dropped = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.gate.reset();
        self.step_arena.reset();
        self.utf16_buf.clear();
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();
        self.touched_pairs.clear();
        self.touched_any = false;
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        let accs_need_rebuild = self.accs.len() != engine.rules.len()
            || self
                .accs
                .first()
                .map(|accs| accs[0].capacity() < engine.tuning.max_anchor_hits_per_rule_variant)
                .unwrap_or(true);
        if accs_need_rebuild {
            self.accs.clear();
            self.accs.reserve(engine.rules.len());
            for _ in 0..engine.rules.len() {
                self.accs.push(std::array::from_fn(|_| {
                    HitAccumulator::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                }));
            }
        }
        let expected_bits = engine.rules.len().saturating_mul(3);
        if self.touched.bit_length() != expected_bits {
            self.touched = DynamicBitSet::empty(expected_bits);
        } else {
            self.touched.clear();
        }
        if self.touched_pairs.capacity() < expected_bits {
            self.touched_pairs = ScratchVec::with_capacity(expected_bits)
                .expect("scratch touched_pairs allocation failed");
        }
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        if self.spans.capacity() < max_spans {
            self.spans =
                ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed");
        }
        if self.windows.capacity() < engine.tuning.max_anchor_hits_per_rule_variant {
            self.windows =
                ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                    .expect("scratch windows allocation failed");
        }
        if self.expanded.capacity() < engine.tuning.max_windows_per_rule_variant {
            self.expanded = ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed");
        }
        if self.max_findings != engine.tuning.max_findings_per_chunk {
            self.max_findings = engine.tuning.max_findings_per_chunk;
        }
        if self.out.capacity() < self.max_findings {
            self.out
                .reserve(self.max_findings.saturating_sub(self.out.capacity()));
        }
    }

    /// Returns per-scan base64 decode/gate stats.
    #[cfg(feature = "b64-stats")]
    pub fn base64_stats(&self) -> Base64DecodeStats {
        self.base64_stats
    }

    /// Drains accumulated findings and returns them.
    pub fn drain_findings(&mut self) -> Vec<FindingRec> {
        self.out.split_off(0)
    }

    /// Moves all findings into `out`, reusing its allocation.
    pub fn drain_findings_into(&mut self, out: &mut Vec<FindingRec>) {
        out.clear();
        out.append(&mut self.out);
    }

    /// Drops findings that are fully contained in a chunk prefix.
    pub fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        if new_bytes_start == 0 {
            return;
        }
        self.out.retain(|rec| rec.root_hint_end > new_bytes_start);
    }

    fn mark_touched(&mut self, rule_id: usize, variant: Variant) {
        let idx = rule_id * 3 + variant.idx();
        self.touched.set(idx);
        self.touched_any = true;
    }

    /// Returns a shared view of accumulated finding records.
    pub fn findings(&self) -> &[FindingRec] {
        &self.out
    }

    pub fn dropped_findings(&self) -> usize {
        self.findings_dropped
    }

    fn push_finding(&mut self, rec: FindingRec) {
        if self.out.len() < self.max_findings {
            self.out.push(rec);
        } else {
            self.findings_dropped = self.findings_dropped.saturating_add(1);
        }
    }
}

/// Reference to a buffer being scanned.
///
/// `Root` points to the input chunk. `Slab(range)` points into `DecodeSlab`.
#[derive(Default)]
enum BufRef {
    #[default]
    Root,
    Slab(Range<usize>),
}

/// Work item in the transform/scan queue.
///
/// Carries the decode provenance (StepId) and a root-span hint for reporting.
/// Depth enforces the transform recursion limit.
#[derive(Default)]
struct WorkItem {
    buf: BufRef,
    step_id: StepId,
    root_hint: Option<Range<usize>>, // None for root buffer; Some for derived buffers
    depth: usize,
}

// --------------------------
// Engine
// --------------------------

/// Compiled scanning engine with anchor patterns, rules, and transforms.
pub struct Engine {
    rules: Vec<RuleCompiled>,
    transforms: Vec<TransformConfig>,
    tuning: Tuning,

    // Anchors AC (raw + UTF16 variants), deduped patterns.
    ac_anchors: AhoCorasick,
    pat_targets: Vec<Target>,
    pat_offsets: Vec<u32>,
    // Base64 pre-decode gate built from anchor patterns.
    //
    // This runs in *encoded space* and is deliberately conservative:
    // if a decoded buffer contains an anchor, at least one YARA-style base64
    // permutation of that anchor must appear in the encoded stream. We still
    // perform the decoded-space gate for correctness; this pre-gate exists
    // purely to skip wasteful decodes when no anchor could possibly appear.
    b64_gate: Option<Base64YaraGate>,

    // Residue gates for rules without anchors (pass 2).
    residue_rules: Vec<(usize, ResidueGatePlan)>,
    unfilterable_rules: Vec<(usize, UnfilterableReason)>,
    anchor_plan_stats: AnchorPlanStats,

    max_anchor_pat_len: usize,
    max_window_diameter_bytes: usize,
}

/// Summary of anchor derivation choices during engine build.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorPlanStats {
    pub manual_rules: usize,
    pub derived_rules: usize,
    pub residue_rules: usize,
    pub unfilterable_rules: usize,
}

/// Policy for selecting anchors during engine compilation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorPolicy {
    /// Prefer derived anchors, falling back to manual anchors if derivation fails.
    PreferDerived,
    /// Only use manual anchors; skip derivation.
    ManualOnly,
    /// Only use derived anchors; ignore manual anchors entirely.
    DerivedOnly,
}

impl Engine {
    /// Compiles rule specs into an engine with prebuilt anchor automata.
    pub fn new(rules: Vec<RuleSpec>, transforms: Vec<TransformConfig>, tuning: Tuning) -> Self {
        Self::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::PreferDerived)
    }

    /// Compiles rule specs into an engine with a specific anchor policy.
    pub fn new_with_anchor_policy(
        rules: Vec<RuleSpec>,
        transforms: Vec<TransformConfig>,
        tuning: Tuning,
        policy: AnchorPolicy,
    ) -> Self {
        let rules_compiled = rules.iter().map(compile_rule).collect::<Vec<_>>();

        // Build deduped anchor patterns: pattern -> targets
        let mut pat_map: AHashMap<Vec<u8>, Vec<Target>> = AHashMap::new();
        let mut residue_rules: Vec<(usize, ResidueGatePlan)> = Vec::new();
        let mut unfilterable_rules: Vec<(usize, UnfilterableReason)> = Vec::new();
        let mut anchor_plan_stats = AnchorPlanStats::default();
        let derive_cfg = AnchorDeriveConfig {
            utf8: false,
            ..AnchorDeriveConfig::default()
        };
        let allow_manual = matches!(
            policy,
            AnchorPolicy::ManualOnly | AnchorPolicy::PreferDerived
        );
        let allow_derive = matches!(
            policy,
            AnchorPolicy::DerivedOnly | AnchorPolicy::PreferDerived
        );

        for (rid, r) in rules.iter().enumerate() {
            debug_assert!(rid <= u32::MAX as usize);
            let rid_u32 = rid as u32;
            let mut manual_used = false;
            let mut add_manual = |pat_map: &mut AHashMap<Vec<u8>, Vec<Target>>| {
                if !allow_manual {
                    return;
                }
                if manual_used || r.anchors.is_empty() {
                    return;
                }
                manual_used = true;
                anchor_plan_stats.manual_rules = anchor_plan_stats.manual_rules.saturating_add(1);
                for &a in r.anchors {
                    add_pat_raw(pat_map, a, Target::new(rid_u32, Variant::Raw));
                    add_pat_owned(
                        pat_map,
                        utf16le_bytes(a),
                        Target::new(rid_u32, Variant::Utf16Le),
                    );
                    add_pat_owned(
                        pat_map,
                        utf16be_bytes(a),
                        Target::new(rid_u32, Variant::Utf16Be),
                    );
                }
            };

            if !allow_derive {
                add_manual(&mut pat_map);
                continue;
            }

            let plan = match compile_trigger_plan(r.re.as_str(), &derive_cfg) {
                Ok(plan) => plan,
                Err(_) => {
                    unfilterable_rules.push((rid, UnfilterableReason::UnsupportedRegexFeatures));
                    anchor_plan_stats.unfilterable_rules =
                        anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    add_manual(&mut pat_map);
                    continue;
                }
            };

            match plan {
                TriggerPlan::Anchored { anchors, .. } => {
                    anchor_plan_stats.derived_rules =
                        anchor_plan_stats.derived_rules.saturating_add(1);
                    for anchor in anchors {
                        add_pat_raw(&mut pat_map, &anchor, Target::new(rid_u32, Variant::Raw));
                        add_pat_owned(
                            &mut pat_map,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le),
                        );
                        add_pat_owned(
                            &mut pat_map,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be),
                        );
                    }
                }
                TriggerPlan::Residue { gate } => {
                    residue_rules.push((rid, gate));
                    anchor_plan_stats.residue_rules =
                        anchor_plan_stats.residue_rules.saturating_add(1);
                    add_manual(&mut pat_map);
                }
                TriggerPlan::Unfilterable { reason } => {
                    unfilterable_rules.push((rid, reason));
                    anchor_plan_stats.unfilterable_rules =
                        anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    add_manual(&mut pat_map);
                }
            }
        }

        let (anchor_patterns, pat_targets, pat_offsets) = map_to_patterns(pat_map);
        let max_anchor_pat_len = anchor_patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        // Build the base64 pre-gate from the same anchor universe as the decoded gate:
        // raw anchors plus UTF-16 variants. This keeps the pre-gate *sound* with
        // respect to anchor presence in decoded bytes, while allowing false positives.
        //
        // Padding/whitespace policy mirrors our span detection/decoder behavior:
        // - Stop at '=' (treat padding as end-of-span)
        // - Ignore RFC4648 whitespace (space is only allowed if the span finder allows it)
        let b64_gate = if anchor_patterns.is_empty() {
            None
        } else {
            Some(Base64YaraGate::build(
                anchor_patterns.iter().map(|p| p.as_slice()),
                Base64YaraGateConfig {
                    min_pattern_len: 0,
                    padding_policy: PaddingPolicy::StopAndHalt,
                    whitespace_policy: WhitespacePolicy::Rfc4648,
                },
            ))
        };

        let ac_anchors = AhoCorasickBuilder::new()
            .prefilter(true)
            .build(anchor_patterns.iter().map(|p| p.as_slice()))
            .expect("build anchors AC");

        let mut max_window_diameter_bytes = 0usize;
        for r in &rules {
            let base = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };
            for scale in [1usize, 2usize] {
                let diameter = base.saturating_mul(2).saturating_mul(scale);
                max_window_diameter_bytes = max_window_diameter_bytes.max(diameter);
            }
        }

        Self {
            rules: rules_compiled,
            transforms,
            tuning,
            ac_anchors,
            pat_targets,
            pat_offsets,
            b64_gate,
            residue_rules,
            unfilterable_rules,
            anchor_plan_stats,
            max_anchor_pat_len,
            max_window_diameter_bytes,
        }
    }

    /// Returns a summary of how anchors were chosen during compilation.
    pub fn anchor_plan_stats(&self) -> AnchorPlanStats {
        self.anchor_plan_stats
    }

    /// Rules that could not be given a sound gate from their regex pattern.
    pub fn unfilterable_rules(&self) -> &[(usize, UnfilterableReason)] {
        &self.unfilterable_rules
    }

    /// Single-buffer scan helper (allocates scratch per call).
    pub fn scan_chunk(&self, hay: &[u8]) -> Vec<Finding> {
        let mut scratch = ScanScratch::new(self);
        self.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
        self.materialize_findings(&mut scratch)
    }

    /// Scans a buffer and appends findings into the provided scratch state.
    ///
    /// The scratch is reset before use and reuses its buffers to avoid per-call
    /// allocations. Findings are stored as compact [`FindingRec`] entries.
    pub fn scan_chunk_into(
        &self,
        root_buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        // High-level flow:
        // 1) Scan anchors in the current buffer and build windows.
        // 2) Run regex validation inside those windows (raw + UTF-16 variants).
        // 3) Optionally decode transforms into derived buffers (gated + deduped),
        //    enqueueing them into a work queue for recursive scanning.
        //
        // Budgets (decode bytes, work items, depth) are enforced on the fly so
        // no single input can force unbounded work.
        scratch.reset_for_scan(self);
        scratch.work_q.push(WorkItem {
            buf: BufRef::Root,
            step_id: STEP_ROOT,
            root_hint: None,
            depth: 0,
        });

        while scratch.work_head < scratch.work_q.len() {
            // Work-queue traversal avoids recursion and makes transform depth
            // and total work item budgets explicit and enforceable.
            if scratch.total_decode_output_bytes >= self.tuning.max_total_decode_output_bytes {
                break;
            }

            let item = std::mem::take(&mut scratch.work_q[scratch.work_head]);
            scratch.work_head += 1;

            let before = scratch.out.len();
            let (buf_ptr, buf_len) = match item.buf {
                BufRef::Root => (root_buf.as_ptr(), root_buf.len()),
                BufRef::Slab(range) => unsafe {
                    debug_assert!(range.end <= scratch.slab.buf.len());
                    let ptr = scratch.slab.buf.as_ptr().add(range.start);
                    (ptr, range.end.saturating_sub(range.start))
                },
            };

            // SAFETY: slab buffer never reallocates (capacity fixed to limit), and we only append.
            let cur_buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len) };

            self.scan_rules_on_buffer(
                cur_buf,
                item.step_id,
                item.root_hint.clone(),
                base_offset,
                file_id,
                scratch,
            );
            let found_any_in_this_buf = scratch.out.len() > before;

            if item.depth >= self.tuning.max_transform_depth {
                continue;
            }
            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                continue;
            }

            for (tidx, tc) in self.transforms.iter().enumerate() {
                if tc.mode == TransformMode::Disabled {
                    continue;
                }
                if tc.mode == TransformMode::IfNoFindingsInThisBuffer && found_any_in_this_buf {
                    continue;
                }

                if cur_buf.len() < tc.min_len {
                    continue;
                }

                if !transform_quick_trigger(tc, cur_buf) {
                    continue;
                }

                find_spans_into(tc, cur_buf, &mut scratch.spans);
                if scratch.spans.is_empty() {
                    continue;
                }

                let span_len = scratch.spans.len().min(tc.max_spans_per_buffer);
                for i in 0..span_len {
                    let enc_span = scratch.spans[i].to_range();
                    if scratch.work_items_enqueued >= self.tuning.max_work_items {
                        break;
                    }
                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        break;
                    }

                    let enc = &cur_buf[enc_span.clone()];
                    if tc.id == TransformId::Base64 {
                        // Base64-only prefilter: cheap encoded-space gate.
                        // This is only used when the decoded gate is enabled, and it never
                        // replaces the decoded check. It exists to avoid paying decode cost
                        // when a span cannot possibly contain any anchor after decoding.
                        #[cfg(feature = "b64-stats")]
                        {
                            scratch.base64_stats.spans =
                                scratch.base64_stats.spans.saturating_add(1);
                            scratch.base64_stats.span_bytes = scratch
                                .base64_stats
                                .span_bytes
                                .saturating_add(enc.len() as u64);
                        }
                        if tc.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.pre_gate_checks = scratch
                                        .base64_stats
                                        .pre_gate_checks
                                        .saturating_add(1);
                                }
                                if !gate.hits(enc) {
                                    #[cfg(feature = "b64-stats")]
                                    {
                                        scratch.base64_stats.pre_gate_skip = scratch
                                            .base64_stats
                                            .pre_gate_skip
                                            .saturating_add(1);
                                        scratch.base64_stats.pre_gate_skip_bytes = scratch
                                            .base64_stats
                                            .pre_gate_skip_bytes
                                            .saturating_add(enc.len() as u64);
                                    }
                                    continue;
                                }
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.pre_gate_pass = scratch
                                        .base64_stats
                                        .pre_gate_pass
                                        .saturating_add(1);
                                }
                            }
                        }
                    }

                    let remaining = self
                        .tuning
                        .max_total_decode_output_bytes
                        .saturating_sub(scratch.total_decode_output_bytes);
                    if remaining == 0 {
                        break;
                    }
                    let max_out = tc.max_decoded_bytes.min(remaining);

                    let decoded_range = if tc.gate == Gate::AnchorsInDecoded {
                        match self.decode_stream_gated_into_slab(tc, enc, max_out, scratch) {
                            Some(r) => r,
                            None => continue,
                        }
                    } else {
                        match scratch.slab.append_stream_decode(
                            tc,
                            enc,
                            max_out,
                            &mut scratch.total_decode_output_bytes,
                            self.tuning.max_total_decode_output_bytes,
                        ) {
                            Ok(r) => r,
                            Err(_) => continue,
                        }
                    };

                    let decoded = scratch.slab.slice(decoded_range.clone());
                    if decoded.is_empty() {
                        continue;
                    }

                    let h = hash128(decoded);
                    if !scratch.seen.insert(h) {
                        continue;
                    }

                    let child_step_id = scratch.step_arena.push(
                        item.step_id,
                        DecodeStep::Transform {
                            transform_idx: tidx,
                            parent_span: enc_span.clone(),
                        },
                    );

                    let child_root_hint = if item.root_hint.is_none() {
                        Some(enc_span.clone())
                    } else {
                        item.root_hint.clone()
                    };

                    scratch.work_q.push(WorkItem {
                        buf: BufRef::Slab(decoded_range),
                        step_id: child_step_id,
                        root_hint: child_root_hint,
                        depth: item.depth + 1,
                    });

                    scratch.work_items_enqueued += 1;
                }
            }
        }
    }

    /// Scans a buffer and returns finding records.
    pub fn scan_chunk_records(
        &self,
        buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) -> Vec<FindingRec> {
        self.scan_chunk_into(buf, file_id, base_offset, scratch);
        scratch.drain_findings()
    }

    /// Returns the required overlap between chunks for correctness.
    ///
    /// This ensures anchor windows (including two-phase expansions) fit across
    /// chunk boundaries.
    pub fn required_overlap(&self) -> usize {
        self.max_window_diameter_bytes
            .saturating_add(self.max_anchor_pat_len.saturating_sub(1))
    }

    /// Returns the rule name for a rule id used in [`FindingRec`].
    pub fn rule_name(&self, rule_id: u32) -> &str {
        self.rules
            .get(rule_id as usize)
            .map(|r| r.name)
            .unwrap_or("<unknown-rule>")
    }

    /// Allocates a fresh scratch state sized for this engine.
    pub fn new_scratch(&self) -> ScanScratch {
        ScanScratch::new(self)
    }

    fn materialize_findings(&self, scratch: &mut ScanScratch) -> Vec<Finding> {
        let mut out = Vec::with_capacity(scratch.out.len());
        self.drain_findings_materialized(scratch, &mut out);
        out
    }

    /// Drains compact findings from scratch and materializes provenance.
    pub fn drain_findings_materialized(&self, scratch: &mut ScanScratch, out: &mut Vec<Finding>) {
        for rec in scratch.out.drain(..) {
            let rule = &self.rules[rec.rule_id as usize];
            scratch
                .step_arena
                .materialize(rec.step_id, &mut scratch.steps_buf);
            out.push(Finding {
                rule: rule.name,
                span: (rec.span_start as usize)..(rec.span_end as usize),
                root_span_hint: u64_to_usize(rec.root_hint_start)..u64_to_usize(rec.root_hint_end),
                decode_steps: scratch.steps_buf.clone(),
            });
        }
    }

    fn scan_rules_on_buffer(
        &self,
        buf: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        debug_assert!(buf.len() <= u32::MAX as usize);
        debug_assert!(self.tuning.merge_gap <= u32::MAX as usize);
        debug_assert!(self.tuning.pressure_gap_start <= u32::MAX as usize);
        let hay_len = buf.len() as u32;
        let merge_gap = self.tuning.merge_gap as u32;
        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

        // L1: anchor scan (raw + utf16 variants), fanout to rules via pat_targets.
        for m in self.ac_anchors.find_overlapping_iter(buf) {
            let pid = m.pattern().as_usize();
            let start = self.pat_offsets[pid] as usize;
            let end = self.pat_offsets[pid + 1] as usize;
            let targets = &self.pat_targets[start..end];

            for &t in targets {
                let rule_id = t.rule_id();
                let variant = t.variant();
                let rule = &self.rules[rule_id];

                // Seed radius depends on whether two-phase is used.
                let seed_r = if let Some(tp) = &rule.two_phase {
                    tp.seed_radius
                } else {
                    rule.radius
                };

                let scale = variant.scale();
                let seed_radius_bytes = seed_r.saturating_mul(scale);

                let lo = m.start().saturating_sub(seed_radius_bytes);
                let hi = (m.end() + seed_radius_bytes).min(buf.len());

                scratch.accs[rule_id][variant.idx()].push(
                    lo,
                    hi,
                    self.tuning.max_anchor_hits_per_rule_variant,
                );
                scratch.mark_touched(rule_id, variant);
            }
        }

        if !scratch.touched_any {
            return;
        }

        // Only process (rule, variant) pairs that were actually touched by an
        // anchor hit in this buffer. This avoids O(rules * variants) work when
        // nothing matched, which is critical once rule counts grow.
        const VARIANTS: [Variant; 3] = [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
        scratch.touched_pairs.clear();
        for pair in scratch.touched.iter_set() {
            scratch.touched_pairs.push(pair as u32);
        }
        scratch.touched.clear();
        scratch.touched_any = false;
        let touched_len = scratch.touched_pairs.len();
        for i in 0..touched_len {
            let pair = scratch.touched_pairs[i] as usize;
            let rid = pair / 3;
            let vidx = pair % 3;
            let variant = VARIANTS[vidx];
            let rule = &self.rules[rid];

            {
                let acc = &mut scratch.accs[rid][vidx];
                acc.take_into(&mut scratch.windows);
            }
            if scratch.windows.is_empty() {
                continue;
            }

            // Windows are pushed in non-decreasing order of anchor match positions.
            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
            coalesce_under_pressure_sorted(
                &mut scratch.windows,
                hay_len,
                pressure_gap_start,
                self.tuning.max_windows_per_rule_variant,
            );

            if let Some(tp) = &rule.two_phase {
                // Two-phase: confirm in seed windows, then expand.
                let seed_radius_bytes = tp.seed_radius.saturating_mul(variant.scale());
                let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                scratch.expanded.clear();
                let windows_len = scratch.windows.len();
                for i in 0..windows_len {
                    let seed = scratch.windows[i];
                    let seed_range = seed.to_range();
                    let win = &buf[seed_range.clone()];
                    if !contains_any_memmem(win, &tp.confirm[vidx]) {
                        continue;
                    }

                    let lo = seed_range.start.saturating_sub(extra);
                    let hi = (seed_range.end + extra).min(buf.len());
                    scratch.expanded.push(SpanU32::new(lo, hi));
                }

                if scratch.expanded.is_empty() {
                    continue;
                }

                merge_ranges_with_gap_sorted(&mut scratch.expanded, merge_gap);
                coalesce_under_pressure_sorted(
                    &mut scratch.expanded,
                    hay_len,
                    pressure_gap_start,
                    self.tuning.max_windows_per_rule_variant,
                );

                let expanded_len = scratch.expanded.len();
                for i in 0..expanded_len {
                    let w = scratch.expanded[i].to_range();
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                }
            } else {
                let win_len = scratch.windows.len();
                for i in 0..win_len {
                    let w = scratch.windows[i].to_range();
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_window(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        w: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        match variant {
            Variant::Raw => {
                let window = &buf[w.clone()];

                if let Some(needle) = rule.must_contain {
                    if memmem::find(window, needle).is_none() {
                        return;
                    }
                }

                for rm in rule.re.find_iter(window) {
                    let span_in_buf = (w.start + rm.start())..(w.start + rm.end());
                    let root_span_hint = root_hint.clone().unwrap_or_else(|| span_in_buf.clone());

                    scratch.push_finding(FindingRec {
                        file_id,
                        rule_id,
                        span_start: span_in_buf.start as u32,
                        span_end: span_in_buf.end as u32,
                        root_hint_start: base_offset + root_span_hint.start as u64,
                        root_hint_end: base_offset + root_span_hint.end as u64,
                        step_id,
                    });
                }
            }

            Variant::Utf16Le | Variant::Utf16Be => {
                // Decode this window as UTF-16 and run the same validators on UTF-8 output.
                let remaining = self
                    .tuning
                    .max_total_decode_output_bytes
                    .saturating_sub(scratch.total_decode_output_bytes);
                if remaining == 0 {
                    return;
                }

                let max_out = self
                    .tuning
                    .max_utf16_decoded_bytes_per_window
                    .min(remaining);

                let decoded = match variant {
                    Variant::Utf16Le => {
                        decode_utf16le_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    Variant::Utf16Be => {
                        decode_utf16be_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    _ => unreachable!(),
                };

                if decoded.is_err() {
                    return;
                }

                let decoded = &scratch.utf16_buf;
                if decoded.is_empty() {
                    return;
                }

                scratch.total_decode_output_bytes = scratch
                    .total_decode_output_bytes
                    .saturating_add(decoded.len());
                if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
                    return;
                }

                if let Some(needle) = rule.must_contain {
                    if memmem::find(decoded, needle).is_none() {
                        return;
                    }
                }

                let utf16_step_id = scratch.step_arena.push(
                    step_id,
                    DecodeStep::Utf16Window {
                        endianness: variant.utf16_endianness().unwrap(),
                        parent_span: w.clone(),
                    },
                );

                let max_findings = scratch.max_findings;
                let out = &mut scratch.out;
                let dropped = &mut scratch.findings_dropped;
                for rm in rule.re.find_iter(decoded) {
                    let span = rm.start()..rm.end();

                    let root_span_hint = root_hint.clone().unwrap_or_else(|| w.clone());

                    if out.len() < max_findings {
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: span.start as u32,
                            span_end: span.end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            step_id: utf16_step_id,
                        });
                    } else {
                        *dropped = dropped.saturating_add(1);
                    }
                }
            }
        }
    }

    fn decode_stream_gated_into_slab(
        &self,
        tc: &TransformConfig,
        encoded: &[u8],
        max_out: usize,
        scratch: &mut ScanScratch,
    ) -> Option<Range<usize>> {
        if max_out == 0 {
            return None;
        }
        #[cfg(feature = "b64-stats")]
        let is_b64 = tc.id == TransformId::Base64;

        // Keep enough bytes to detect anchors that straddle decode chunk boundaries.
        let tail_keep = self.max_anchor_pat_len.saturating_sub(1);
        scratch.gate.reset();

        let start_len = scratch.slab.buf.len();
        let mut local_out = 0usize;
        let mut truncated = false;
        let mut hit = false;

        // Decode once while checking for anchors. If no anchors appear in the decoded
        // stream, the slab append is rolled back and the transform is skipped.
        //
        // We keep a small tail window so anchors that straddle decode chunk boundaries
        // are still detected without re-decoding or buffering the entire output.
        #[cfg(feature = "b64-stats")]
        if is_b64 {
            scratch.base64_stats.decode_attempts =
                scratch.base64_stats.decode_attempts.saturating_add(1);
            scratch.base64_stats.decode_attempt_bytes = scratch
                .base64_stats
                .decode_attempt_bytes
                .saturating_add(encoded.len() as u64);
        }

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len())
                > self.tuning.max_total_decode_output_bytes
            {
                truncated = true;
                return ControlFlow::Break(());
            }
            if scratch.slab.buf.len().saturating_add(chunk.len()) > scratch.slab.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            scratch.slab.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            scratch.total_decode_output_bytes = scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len());

            // Sliding decoded window: tail (prev chunk) + current chunk.
            scratch.gate.scratch.clear();
            scratch.gate.scratch.extend_from_slice(&scratch.gate.tail);
            scratch.gate.scratch.extend_from_slice(chunk);

            if !hit && self.ac_anchors.is_match(&scratch.gate.scratch) {
                hit = true;
            }

            if tail_keep > 0 {
                let keep = tail_keep.min(scratch.gate.scratch.len());
                scratch.gate.tail.clear();
                scratch
                    .gate
                    .tail
                    .extend_from_slice(&scratch.gate.scratch[scratch.gate.scratch.len() - keep..]);
            }

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            #[cfg(feature = "b64-stats")]
            if is_b64 {
                scratch.base64_stats.decode_errors =
                    scratch.base64_stats.decode_errors.saturating_add(1);
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_error = scratch
                    .base64_stats
                    .decoded_bytes_wasted_error
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(start_len);
            return None;
        }

        if !hit {
            #[cfg(feature = "b64-stats")]
            if is_b64 {
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_no_anchor = scratch
                    .base64_stats
                    .decoded_bytes_wasted_no_anchor
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(start_len);
            return None;
        }

        #[cfg(feature = "b64-stats")]
        if is_b64 {
            scratch.base64_stats.decoded_bytes_total = scratch
                .base64_stats
                .decoded_bytes_total
                .saturating_add(local_out as u64);
            scratch.base64_stats.decoded_bytes_kept = scratch
                .base64_stats
                .decoded_bytes_kept
                .saturating_add(local_out as u64);
        }

        Some(start_len..(start_len + local_out))
    }
}

// --------------------------
// Compile helpers
// --------------------------

fn compile_rule(spec: &RuleSpec) -> RuleCompiled {
    let two_phase = spec.two_phase.as_ref().map(|tp| {
        let count = tp.confirm_any.len();
        let raw_bytes = tp.confirm_any.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);
        let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
        let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
        let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

        for &p in tp.confirm_any {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        TwoPhaseCompiled {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm: [raw, le, be],
        }
    });

    RuleCompiled {
        name: spec.name,
        radius: spec.radius,
        must_contain: spec.must_contain,
        re: spec.re.clone(),
        two_phase,
    }
}

fn add_pat_raw(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: &[u8], target: Target) {
    if let Some(existing) = map.get_mut(pat) {
        existing.push(target);
    } else {
        map.insert(pat.to_vec(), vec![target]);
    }
}

fn add_pat_owned(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: Vec<u8>, target: Target) {
    if let Some(existing) = map.get_mut(pat.as_slice()) {
        existing.push(target);
    } else {
        map.insert(pat, vec![target]);
    }
}

fn map_to_patterns(map: AHashMap<Vec<u8>, Vec<Target>>) -> (Vec<Vec<u8>>, Vec<Target>, Vec<u32>) {
    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(map.len());
    let mut flat: Vec<Target> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(map.len().saturating_add(1));
    offsets.push(0);

    let mut total_targets = 0usize;
    for ts in map.values() {
        total_targets = total_targets.saturating_add(ts.len());
    }
    flat.reserve(total_targets);

    for (p, ts) in map {
        patterns.push(p);
        flat.extend(ts);
        debug_assert!(flat.len() <= u32::MAX as usize);
        // Prefix-sum offsets: each pattern id maps to flat[start..end].
        offsets.push(flat.len() as u32);
    }

    (patterns, flat, offsets)
}

// --------------------------
// Window merge / coalesce (no repeated sorting)
// --------------------------

// Assumes `ranges` is already sorted by start.
//
// The `gap` parameter allows "soft merging": ranges that are within `gap` bytes
// are merged into a single window. This intentionally widens windows to reduce
// the count of regex runs, trading a small amount of extra scanning for fewer
// window boundaries.
fn merge_ranges_with_gap_sorted(ranges: &mut ScratchVec<SpanU32>, gap: u32) {
    if ranges.len() <= 1 {
        return;
    }

    let mut write = 0usize;
    let mut cur = ranges[0];
    let len = ranges.len();

    for i in 1..len {
        let r = ranges[i];
        debug_assert!(r.start >= cur.start);
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
        } else {
            ranges[write] = cur;
            write += 1;
            cur = r;
        }
    }
    ranges[write] = cur;
    write += 1;
    ranges.truncate(write);
}

// Assumes `ranges` is already sorted and preferably already merged with a small gap.
//
// This is a pressure valve for adversarial inputs that trigger too many anchor
// hits. It increases the merge gap exponentially until the window count fits
// within `max_windows`, and as a last resort collapses to one window. The result
// is always a superset of the original windows, so correctness is preserved.
fn coalesce_under_pressure_sorted(
    ranges: &mut ScratchVec<SpanU32>,
    hay_len: u32,
    mut gap: u32,
    max_windows: usize,
) {
    if ranges.len() <= max_windows {
        return;
    }

    // Increase the merge gap until we fit the cap or hit the buffer length.
    while ranges.len() > max_windows && gap < hay_len {
        merge_ranges_with_gap_sorted(ranges, gap);
        gap = gap.saturating_mul(2);
    }

    if ranges.len() > max_windows && !ranges.is_empty() {
        // Hard fallback: collapse to a single window to bound work deterministically.
        let start = ranges[0].start;
        let end = ranges[ranges.len() - 1].end;
        ranges.clear();
        ranges.push(SpanU32 {
            start: start.min(hay_len),
            end: end.min(hay_len),
        });
    }
}

// --------------------------
// Confirm helpers
// --------------------------

fn contains_any_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        if memmem::find(hay, &needles.bytes[start..end]).is_some() {
            return true;
        }
    }
    false
}

// --------------------------
// UTF-16 helpers
// --------------------------

fn utf16le_bytes(anchor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchor.len() * 2);
    for &b in anchor {
        out.push(b);
        out.push(0);
    }
    out
}

fn utf16be_bytes(anchor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchor.len() * 2);
    for &b in anchor {
        out.push(0);
        out.push(b);
    }
    out
}

#[derive(Debug)]
enum Utf16DecodeError {
    OutputTooLarge,
}

fn decode_utf16le_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_buf(input, max_out, true, &mut out)?;
    Ok(out)
}

fn decode_utf16be_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_buf(input, max_out, false, &mut out)?;
    Ok(out)
}

fn decode_utf16le_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut Vec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, true, out)
}

fn decode_utf16be_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut Vec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, false, out)
}

fn decode_utf16_to_buf(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut Vec<u8>,
) -> Result<(), Utf16DecodeError> {
    // Ignore a trailing odd byte; it cannot form a full UTF-16 code unit.
    let n = input.len() / 2;
    let iter = (0..n).map(|i| {
        let b0 = input[2 * i];
        let b1 = input[2 * i + 1];
        if le {
            u16::from_le_bytes([b0, b1])
        } else {
            u16::from_be_bytes([b0, b1])
        }
    });

    out.clear();
    for r in std::char::decode_utf16(iter) {
        let ch = r.unwrap_or('\u{FFFD}');
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if out.len() + s.len() > max_out {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

// --------------------------
// Transform: URL percent
// --------------------------

#[derive(Debug)]
enum UrlDecodeError {
    OutputTooLarge,
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn is_urlish(b: u8) -> bool {
    // Conservative "URL-ish" run for span detection.
    matches!(
        b,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'%' | b'+'
            | b'-' | b'_' | b'.' | b'~'
            | b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'@'
            | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*'
            | b',' | b';' | b'='
    )
}

trait SpanSink {
    fn clear(&mut self);
    fn len(&self) -> usize;
    fn push(&mut self, span: Range<usize>);
}

impl SpanSink for Vec<Range<usize>> {
    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        Vec::push(self, span);
    }
}

impl SpanSink for ScratchVec<Range<usize>> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, span);
    }
}

impl SpanSink for ScratchVec<SpanU32> {
    fn clear(&mut self) {
        ScratchVec::clear(self);
    }

    fn len(&self) -> usize {
        ScratchVec::len(self)
    }

    fn push(&mut self, span: Range<usize>) {
        ScratchVec::push(self, SpanU32::new(span.start, span.end));
    }
}

// FIX: include unescaped prefix by scanning URL-ish runs, not starting at first '%'.
//
// We intentionally scan the entire URL-ish run so decoded output retains any
// plain-text prefix (e.g., "token=" before "%3D"). We still require at least
// one percent-escape (and optionally '+') to avoid decoding every plain word.
fn find_url_spans(
    hay: &[u8],
    min_len: usize,
    max_len: usize,
    max_spans: usize,
    plus_to_space: bool,
) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    find_url_spans_into(hay, min_len, max_len, max_spans, plus_to_space, &mut spans);
    spans
}

fn find_url_spans_into(
    hay: &[u8],
    min_len: usize,
    max_len: usize,
    max_spans: usize,
    plus_to_space: bool,
    spans: &mut impl SpanSink,
) {
    spans.clear();
    let mut i = 0usize;

    while i < hay.len() && spans.len() < max_spans {
        if !is_urlish(hay[i]) {
            i += 1;
            continue;
        }

        let start = i;
        let mut triggers = 0usize;

        while i < hay.len() && is_urlish(hay[i]) && (i - start) < max_len {
            let b = hay[i];
            if b == b'%' || (plus_to_space && b == b'+') {
                triggers += 1;
            }
            i += 1;
        }

        let end = i;
        if triggers > 0 && (end - start) >= min_len {
            spans.push(start..end);
        }
    }
}

fn stream_decode_url_percent(
    input: &[u8],
    plus_to_space: bool,
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), UrlDecodeError> {
    fn flush_buf(
        out: &mut [u8],
        n: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *n == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*n]);
        *n = 0;
        cf
    }

    let mut out = [0u8; 1024];
    let mut n = 0usize;

    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];

        let decoded =
            if b == b'%' && i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) {
                let hi = hex_val(input[i + 1]);
                let lo = hex_val(input[i + 2]);
                i += 3;
                (hi << 4) | lo
            } else if plus_to_space && b == b'+' {
                i += 1;
                b' '
            } else {
                i += 1;
                b
            };

        out[n] = decoded;
        n += 1;

        if n >= out.len() - 4 {
            match flush_buf(&mut out, &mut n, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    match flush_buf(&mut out, &mut n, &mut on_bytes) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Ok(()),
    }
}

fn decode_url_percent_to_vec(
    input: &[u8],
    plus_to_space: bool,
    max_out: usize,
) -> Result<Vec<u8>, UrlDecodeError> {
    let mut out = Vec::with_capacity(input.len().min(max_out));
    let mut too_large = false;

    stream_decode_url_percent(input, plus_to_space, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })?;

    if too_large {
        return Err(UrlDecodeError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform: Base64 (urlsafe + std alph, ignores whitespace)
// --------------------------

#[derive(Debug)]
enum Base64DecodeError {
    InvalidByte(u8),
    InvalidPadding,
    TruncatedQuantum,
    OutputTooLarge,
}

fn is_b64_char(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'+' | b'/' | b'='
            | b'-' | b'_'
    )
}

fn is_b64_ws(b: u8, allow_space: bool) -> bool {
    matches!(b, b'\n' | b'\r' | b'\t') || (allow_space && b == b' ')
}

fn is_b64_or_ws(b: u8, allow_space: bool) -> bool {
    is_b64_char(b) || is_b64_ws(b, allow_space)
}

// Simple span finder. It is permissive by design.
//
// Why permissive?
// - We want to avoid false negatives at this stage.
// - Tightening is handled by length caps, span limits, and decode gating.
//
// This keeps the span finder cheap and predictable, while later stages enforce
// cost limits and correctness.
fn find_base64_spans(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    find_base64_spans_into(
        hay,
        min_chars,
        max_len,
        max_spans,
        allow_space_ws,
        &mut spans,
    );
    spans
}

fn find_base64_spans_into(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
    spans: &mut impl SpanSink,
) {
    spans.clear();
    let mut i = 0usize;

    while i < hay.len() && spans.len() < max_spans {
        if !is_b64_or_ws(hay[i], allow_space_ws) {
            i += 1;
            continue;
        }

        let start = i;
        let mut b64_chars = 0usize;
        let mut last_b64 = None::<usize>;

        while i < hay.len() && is_b64_or_ws(hay[i], allow_space_ws) && (i - start) < max_len {
            if is_b64_char(hay[i]) {
                b64_chars += 1;
                last_b64 = Some(i);
            }
            i += 1;
        }

        if b64_chars >= min_chars {
            if let Some(last) = last_b64 {
                // Trim trailing whitespace by ending at the last base64 byte.
                spans.push(start..(last + 1));
            }
        }
    }
}

fn stream_decode_base64(
    input: &[u8],
    mut on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), Base64DecodeError> {
    // Streaming decoder that accepts both standard and URL-safe alphabets and
    // ignores whitespace. It validates padding rules and allows an unpadded tail
    // (2 or 3 bytes in the final quantum) because real-world data often omits '='.
    //
    // This is used for both actual decode and decoded-gate streaming, so we
    // keep it branch-light and bounded in memory (fixed 1KB output buffer).
    fn flush_buf(
        out: &mut [u8],
        out_len: &mut usize,
        on: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        if *out_len == 0 {
            return ControlFlow::Continue(());
        }
        let cf = on(&out[..*out_len]);
        *out_len = 0;
        cf
    }

    let mut quad: [u8; 4] = [0; 4];
    let mut qn = 0usize;
    let mut seen_pad = false;

    let mut out: [u8; 1024] = [0; 1024];
    let mut out_len = 0usize;

    for &b in input {
        // ignore whitespace broadly
        if matches!(b, b' ' | b'\n' | b'\r' | b'\t') {
            continue;
        }

        let v = match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(64),
            _ => None,
        }
        .ok_or(Base64DecodeError::InvalidByte(b))?;

        if seen_pad {
            return Err(Base64DecodeError::InvalidPadding);
        }

        quad[qn] = v;
        qn += 1;

        if qn < 4 {
            continue;
        }

        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        let d = quad[3];

        if a == 64 || b == 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }

        let b0 = (a << 2) | (b >> 4);

        if c == 64 && d != 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }

        if c == 64 && d == 64 {
            out[out_len] = b0;
            out_len += 1;
            seen_pad = true;
        } else {
            let b1 = ((b & 0x0F) << 4) | (c >> 2);

            if d == 64 {
                out[out_len] = b0;
                out[out_len + 1] = b1;
                out_len += 2;
                seen_pad = true;
            } else {
                let b2 = ((c & 0x03) << 6) | d;

                out[out_len] = b0;
                out[out_len + 1] = b1;
                out[out_len + 2] = b2;
                out_len += 3;
            }
        }

        qn = 0;

        if out_len >= out.len() - 4 {
            match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(()) => return Ok(()),
            }
        }
    }

    // Handle unpadded tail
    if qn == 1 {
        return Err(Base64DecodeError::TruncatedQuantum);
    } else if qn == 2 {
        let a = quad[0];
        let b = quad[1];
        if a == 64 || b == 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        out[out_len] = b0;
        out_len += 1;
    } else if qn == 3 {
        let a = quad[0];
        let b = quad[1];
        let c = quad[2];
        if a == 64 || b == 64 || c == 64 {
            return Err(Base64DecodeError::InvalidPadding);
        }
        let b0 = (a << 2) | (b >> 4);
        let b1 = ((b & 0x0F) << 4) | (c >> 2);
        out[out_len] = b0;
        out[out_len + 1] = b1;
        out_len += 2;
    }

    match flush_buf(&mut out, &mut out_len, &mut on_bytes) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Ok(()),
    }
}

fn decode_base64_to_vec(input: &[u8], max_out: usize) -> Result<Vec<u8>, Base64DecodeError> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut too_large = false;

    stream_decode_base64(input, |chunk| {
        if out.len() + chunk.len() > max_out {
            too_large = true;
            return ControlFlow::Break(());
        }
        out.extend_from_slice(chunk);
        ControlFlow::Continue(())
    })?;

    if too_large {
        return Err(Base64DecodeError::OutputTooLarge);
    }
    Ok(out)
}

// --------------------------
// Transform dispatch
// --------------------------

fn transform_quick_trigger(tc: &TransformConfig, buf: &[u8]) -> bool {
    match tc.id {
        TransformId::UrlPercent => {
            if memchr(b'%', buf).is_some() {
                return true;
            }
            if tc.plus_to_space && memchr(b'+', buf).is_some() {
                return true;
            }
            false
        }
        TransformId::Base64 => true, // span finder is the real filter; keep trigger cheap
    }
}

fn find_spans_into(tc: &TransformConfig, buf: &[u8], out: &mut impl SpanSink) {
    match tc.id {
        TransformId::UrlPercent => find_url_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.plus_to_space,
            out,
        ),
        TransformId::Base64 => find_base64_spans_into(
            buf,
            tc.min_len,
            tc.max_encoded_len,
            tc.max_spans_per_buffer,
            tc.base64_allow_space_ws,
            out,
        ),
    }
}

fn stream_decode(
    tc: &TransformConfig,
    input: &[u8],
    on_bytes: impl FnMut(&[u8]) -> ControlFlow<()>,
) -> Result<(), ()> {
    match tc.id {
        TransformId::UrlPercent => {
            stream_decode_url_percent(input, tc.plus_to_space, on_bytes).map_err(|_| ())
        }
        TransformId::Base64 => stream_decode_base64(input, on_bytes).map_err(|_| ()),
    }
}

fn decode_to_vec(tc: &TransformConfig, input: &[u8], max_out: usize) -> Result<Vec<u8>, ()> {
    match tc.id {
        TransformId::UrlPercent => {
            decode_url_percent_to_vec(input, tc.plus_to_space, max_out).map_err(|_| ())
        }
        TransformId::Base64 => decode_base64_to_vec(input, max_out).map_err(|_| ()),
    }
}

// --------------------------
// Hashing (decoded buffer dedupe)
// --------------------------

/// Collision-resistant 128-bit hash using AEGIS-128L.
///
/// Design intent:
/// - We need a *fast* but *low-collision* fingerprint for decoded buffers.
/// - SipHash is strong but slower; non-crypto hashes are fast but risky.
/// - AEGIS-128L uses AES-NI on modern CPUs and yields a 128-bit MAC.
///
/// By fixing key/nonce to zero and authenticating `bytes` as associated data,
/// we get a deterministic 128-bit tag that behaves like a PRF. This is not a
/// general-purpose cryptographic hash, but it is collision-resistant enough
/// for in-process deduplication and avoids an extra dependency.
fn hash128(bytes: &[u8]) -> u128 {
    use aegis::aegis128l::Aegis128L;
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let aegis = Aegis128L::new(&key, &nonce);
    // Encrypt empty message, authenticate `bytes` as associated data.
    let (_ciphertext, tag) = aegis.encrypt(&[], bytes);
    u128::from_le_bytes(tag)
}

fn pow2_at_least(v: usize) -> usize {
    v.next_power_of_two()
}

fn u64_to_usize(v: u64) -> usize {
    if v > (usize::MAX as u64) {
        usize::MAX
    } else {
        v as usize
    }
}

// --------------------------
// Demo engine (rules + transforms)
// --------------------------

/// Anchor selection mode for demo rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorMode {
    /// Use the hand-curated anchors on each rule.
    Manual,
    /// Derive anchors from regex patterns (empty anchors trigger derivation).
    Derived,
}

/// Builds a demo engine with a representative subset of secret rules.
pub fn demo_engine() -> Engine {
    Engine::new(demo_rules(), demo_transforms(), demo_tuning())
}

/// Builds a demo engine with either manual or derived anchors.
pub fn demo_engine_with_anchor_mode(mode: AnchorMode) -> Engine {
    let policy = match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    Engine::new_with_anchor_policy(demo_rules(), demo_transforms(), demo_tuning(), policy)
}

fn demo_rules() -> Vec<RuleSpec> {
    // Subset of gitleaks rules translated into RuleSpec (anchors/radius/two_phase/etc).
    // (Rule ids/regexes taken from gitleaks default config; ported as a representative subset.)
    //
    // Families covered:
    // - AWS
    // - GitHub (PAT/OAuth/App)
    // - GitLab
    // - Slack (token + webhook)
    // - Stripe
    // - SendGrid
    // - npm
    // - Databricks
    // - Private key (PEM-ish)

    const AWS_ACCESS_TOKEN_ANCHORS: &[&[u8]] = &[
        b"A3T", b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA", b"ANPA", b"ANVA", b"ASIA",
    ];

    const GITHUB_PAT_ANCHORS: &[&[u8]] = &[b"ghp_"];
    const GITHUB_OAUTH_ANCHORS: &[&[u8]] = &[b"gho_"];
    const GITHUB_APP_ANCHORS: &[&[u8]] = &[b"ghu_", b"ghs_"];
    const GITLAB_PAT_ANCHORS: &[&[u8]] = &[b"glpat-"];

    const SLACK_TOKEN_ANCHORS: &[&[u8]] = &[b"xoxb-", b"xoxa-", b"xoxp-", b"xoxr-", b"xoxs-"];
    const SLACK_WEBHOOK_ANCHORS: &[&[u8]] = &[b"hooks.slack.com/services/"];

    const STRIPE_TOKEN_ANCHORS: &[&[u8]] = &[
        b"sk_test_",
        b"sk_live_",
        b"sk_prod_",
        b"rk_test_",
        b"rk_live_",
        b"rk_prod_",
    ];

    const SENDGRID_TOKEN_ANCHORS: &[&[u8]] = &[b"SG.", b"sg."];

    const NPM_TOKEN_ANCHORS: &[&[u8]] = &[b"npm_"];

    const DATABRICKS_TOKEN_ANCHORS: &[&[u8]] = &[b"dapi", b"DAPI"];

    const PRIVATE_KEY_ANCHORS: &[&[u8]] = &[b"-----BEGIN"];
    const PRIVATE_KEY_CONFIRM: &[&[u8]] = &[b"PRIVATE KEY"];

    vec![
        RuleSpec {
            name: "aws-access-token",
            anchors: AWS_ACCESS_TOKEN_ANCHORS,
            radius: 64,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
        },
        RuleSpec {
            name: "github-pat",
            anchors: GITHUB_PAT_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "github-oauth",
            anchors: GITHUB_OAUTH_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "github-app-token",
            anchors: GITHUB_APP_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"(ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "gitlab-pat",
            anchors: GITLAB_PAT_ANCHORS,
            radius: 64,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"glpat-[0-9a-zA-Z\-\_]{20}").unwrap(),
        },
        RuleSpec {
            name: "slack-access-token",
            anchors: SLACK_TOKEN_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"xox[baprs]-([0-9a-zA-Z]{10,48})").unwrap(),
        },
        RuleSpec {
            name: "slack-web-hook",
            anchors: SLACK_WEBHOOK_ANCHORS,
            radius: 160,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,46}").unwrap(),
        },
        RuleSpec {
            name: "stripe-access-token",
            anchors: STRIPE_TOKEN_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}").unwrap(),
        },
        RuleSpec {
            name: "sendgrid-api-token",
            anchors: SENDGRID_TOKEN_ANCHORS,
            radius: 128,
            two_phase: None,
            must_contain: None,
            re: Regex::new(
                r#"(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\"|\n|\r|\s|\x60]|$)"#,
            )
            .unwrap(),
        },
        RuleSpec {
            name: "npm-access-token",
            anchors: NPM_TOKEN_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r#"(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60]|$)"#).unwrap(),
        },
        RuleSpec {
            name: "databricks-api-token",
            anchors: DATABRICKS_TOKEN_ANCHORS,
            radius: 96,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r#"(?i)\b(dapi[a-h0-9]{32})(?:['|\"|\n|\r|\s|\x60]|$)"#).unwrap(),
        },
        RuleSpec {
            name: "private-key",
            anchors: PRIVATE_KEY_ANCHORS,
            radius: 0, // unused when two_phase is set
            two_phase: Some(TwoPhaseSpec {
                seed_radius: 256,
                full_radius: 16 * 1024,
                confirm_any: PRIVATE_KEY_CONFIRM,
            }),
            must_contain: None,
            // Require a complete BEGIN..END block for "PRIVATE KEY" to avoid ultra-noisy partial matches.
            re: Regex::new(
                r"(?is)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----.*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY-----",
            )
            .unwrap(),
        },
    ]
}

fn demo_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            // Performance-first: gate base64 by anchors in decoded output.
            gate: Gate::AnchorsInDecoded,
            min_len: 32,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

fn demo_tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 16,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 2048,
        max_utf16_decoded_bytes_per_window: 64 * 1024,
        max_transform_depth: 3,
        max_total_decode_output_bytes: 512 * 1024,
        max_work_items: 256,
        max_findings_per_chunk: 8192,
    }
}

// --------------------------
// Tests (show key edge cases)
// --------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::ops::Range;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Tiny base64 encoder for tests (standard alphabet, with '=' padding).
    fn b64_encode(input: &[u8]) -> String {
        const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0usize;

        while i < input.len() {
            let b0 = input[i];
            let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
            let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

            let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

            let c0 = ((n >> 18) & 63) as usize;
            let c1 = ((n >> 12) & 63) as usize;
            let c2 = ((n >> 6) & 63) as usize;
            let c3 = (n & 63) as usize;

            out.push(ALPH[c0] as char);
            out.push(ALPH[c1] as char);

            if i + 1 < input.len() {
                out.push(ALPH[c2] as char);
            } else {
                out.push('=');
            }

            if i + 2 < input.len() {
                out.push(ALPH[c3] as char);
            } else {
                out.push('=');
            }

            i += 3;
        }

        out
    }

    #[test]
    fn hash128_deterministic() {
        let data = b"hello world";
        let h1 = hash128(data);
        let h2 = hash128(data);
        assert_eq!(h1, h2);

        // Different inputs produce different hashes.
        let h3 = hash128(b"hello worlD");
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash128_collision_resistant() {
        // Verify that small changes produce different hashes.
        let base = b"AKIAIOSFODNN7EXAMPLE";
        let h_base = hash128(base);

        // Single byte change.
        let mut modified = *base;
        modified[0] ^= 1;
        assert_ne!(h_base, hash128(&modified));

        // Append a byte.
        let mut appended = base.to_vec();
        appended.push(0);
        assert_ne!(h_base, hash128(&appended));

        // Empty input has distinct hash.
        let h_empty = hash128(b"");
        assert_ne!(h_base, h_empty);
    }

    #[test]
    fn url_span_includes_prefix_and_finds_ghp() {
        let eng = demo_engine();
        // ghp_ + 36 chars
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let url = token.replace("_", "%5F"); // ghp%5Faaaa...
        let hay = format!("token={}", url).into_bytes();

        let hits = eng.scan_chunk(&hay);
        assert!(hits.iter().any(|h| h.rule == "github-pat"));
    }

    #[test]
    fn base64_utf16_aws_key_is_detected() {
        let eng = demo_engine();

        let aws = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
        let utf16le = super::utf16le_bytes(aws);
        let b64 = b64_encode(&utf16le);

        let hay = format!("prefix {} suffix", b64).into_bytes();
        let hits = eng.scan_chunk(&hay);

        assert!(hits.iter().any(|h| h.rule == "aws-access-token"));
    }

    #[test]
    fn anchor_policy_prefers_derived_over_manual() {
        const MANUAL: &[&[u8]] = &[b"bar"];
        let rule = RuleSpec {
            name: "derived-prefers",
            anchors: MANUAL,
            radius: 0,
            two_phase: None,
            must_contain: None,
            re: Regex::new("foo").unwrap(),
        };

        let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.derived_rules, 1);
        assert_eq!(stats.manual_rules, 0);

        let hits = eng.scan_chunk(b"barfoo");
        assert!(hits.iter().any(|h| h.rule == "derived-prefers"));
    }

    #[test]
    fn anchor_policy_falls_back_to_manual_on_unfilterable() {
        const MANUAL: &[&[u8]] = &[b"Z"];
        let rule = RuleSpec {
            name: "manual-fallback",
            anchors: MANUAL,
            radius: 0,
            two_phase: None,
            must_contain: None,
            re: Regex::new(".*").unwrap(),
        };

        let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.manual_rules, 1);
        assert_eq!(stats.derived_rules, 0);
        assert_eq!(stats.unfilterable_rules, 1);

        let hits = eng.scan_chunk(b"Z");
        assert!(hits.iter().any(|h| h.rule == "manual-fallback"));
    }

    #[test]
    fn nested_encoding_is_skipped_in_gated_mode() {
        let eng = demo_engine();

        // URL-encoded underscore inside base64.
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let url = token.replace("_", "%5F"); // ghp%5Faaaa...
        let b64 = b64_encode(url.as_bytes());

        let hay = format!("X{}Y", b64).into_bytes();

        let hits = eng.scan_chunk(&hay);
        assert!(!hits.iter().any(|h| h.rule == "github-pat"));
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn write_temp_file(bytes: &[u8]) -> std::io::Result<TempFile> {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("scanner_rs_test_{}_{}", std::process::id(), stamp));
        std::fs::write(&path, bytes)?;
        Ok(TempFile { path })
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    enum StepKind {
        Transform { idx: usize },
        Utf16 { le: bool },
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct FindingKey {
        rule: &'static str,
        span: Range<usize>,
        steps: Vec<StepKind>,
    }

    fn findings_to_keys(findings: &[Finding]) -> HashSet<FindingKey> {
        findings
            .iter()
            .map(|f| {
                let steps = f
                    .decode_steps
                    .iter()
                    .map(|step| match step {
                        DecodeStep::Transform { transform_idx, .. } => StepKind::Transform {
                            idx: *transform_idx,
                        },
                        DecodeStep::Utf16Window { endianness, .. } => StepKind::Utf16 {
                            le: matches!(endianness, Utf16Endianness::Le),
                        },
                    })
                    .collect();
                FindingKey {
                    rule: f.rule,
                    span: f.span.clone(),
                    steps,
                }
            })
            .collect()
    }

    #[derive(Clone)]
    struct RefWorkItem {
        buf: Vec<u8>,
        steps: Vec<StepKind>,
        depth: usize,
    }

    fn reference_scan_keys(engine: &Engine, rules: &[RuleSpec], buf: &[u8]) -> HashSet<FindingKey> {
        let mut out = HashSet::new();
        let mut work_q = Vec::new();
        work_q.push(RefWorkItem {
            buf: buf.to_vec(),
            steps: Vec::new(),
            depth: 0,
        });

        let mut work_head = 0usize;
        let mut total_decode_output_bytes = 0usize;
        let mut work_items_enqueued = 0usize;
        let mut seen = HashSet::<u128>::new();

        while work_head < work_q.len() {
            let item = work_q[work_head].clone();
            work_head += 1;

            let found_any = scan_rules_reference(
                engine,
                rules,
                &item.buf,
                &item.steps,
                &mut out,
                &mut total_decode_output_bytes,
            );

            if item.depth >= engine.tuning.max_transform_depth {
                continue;
            }
            if work_items_enqueued >= engine.tuning.max_work_items {
                continue;
            }

            for (tidx, tc) in engine.transforms.iter().enumerate() {
                if tc.mode == TransformMode::Disabled {
                    continue;
                }
                if tc.mode == TransformMode::IfNoFindingsInThisBuffer && found_any {
                    continue;
                }
                if item.buf.len() < tc.min_len {
                    continue;
                }
                if !transform_quick_trigger(tc, &item.buf) {
                    continue;
                }

                let mut spans = Vec::new();
                find_spans_into(tc, &item.buf, &mut spans);
                if spans.is_empty() {
                    continue;
                }

                let span_len = spans.len().min(tc.max_spans_per_buffer);
                for enc_span in spans.iter().take(span_len) {
                    if work_items_enqueued >= engine.tuning.max_work_items {
                        break;
                    }
                    if total_decode_output_bytes >= engine.tuning.max_total_decode_output_bytes {
                        break;
                    }

                    let enc_span = enc_span.clone();
                    let enc = &item.buf[enc_span.clone()];

                    let remaining = engine
                        .tuning
                        .max_total_decode_output_bytes
                        .saturating_sub(total_decode_output_bytes);
                    if remaining == 0 {
                        break;
                    }
                    let max_out = tc.max_decoded_bytes.min(remaining);

                    let decoded = match decode_to_vec(tc, enc, max_out) {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    };
                    if decoded.is_empty() {
                        continue;
                    }

                    total_decode_output_bytes =
                        total_decode_output_bytes.saturating_add(decoded.len());
                    if total_decode_output_bytes > engine.tuning.max_total_decode_output_bytes {
                        break;
                    }

                    if tc.gate == Gate::AnchorsInDecoded && !engine.ac_anchors.is_match(&decoded) {
                        continue;
                    }

                    let h = hash128(&decoded);
                    if !seen.insert(h) {
                        continue;
                    }

                    let mut steps = item.steps.clone();
                    steps.push(StepKind::Transform { idx: tidx });

                    work_q.push(RefWorkItem {
                        buf: decoded,
                        steps,
                        depth: item.depth + 1,
                    });
                    work_items_enqueued += 1;
                }
            }
        }

        out
    }

    fn scan_rules_reference(
        engine: &Engine,
        rules: &[RuleSpec],
        buf: &[u8],
        steps: &[StepKind],
        out: &mut HashSet<FindingKey>,
        total_decode_output_bytes: &mut usize,
    ) -> bool {
        let mut found_any = false;

        for rule in rules {
            for variant in [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be] {
                let windows = collect_windows_for_variant(buf, rule, variant, &engine.tuning);
                if windows.is_empty() {
                    continue;
                }

                match variant {
                    Variant::Raw => {
                        for w in windows {
                            let window = &buf[w.clone()];
                            for rm in rule.re.find_iter(window) {
                                let span = (w.start + rm.start())..(w.start + rm.end());
                                out.insert(FindingKey {
                                    rule: rule.name,
                                    span,
                                    steps: steps.to_vec(),
                                });
                                found_any = true;
                            }
                        }
                    }
                    Variant::Utf16Le | Variant::Utf16Be => {
                        for w in windows {
                            if *total_decode_output_bytes
                                >= engine.tuning.max_total_decode_output_bytes
                            {
                                return found_any;
                            }

                            let remaining = engine
                                .tuning
                                .max_total_decode_output_bytes
                                .saturating_sub(*total_decode_output_bytes);
                            if remaining == 0 {
                                return found_any;
                            }
                            let max_out = engine
                                .tuning
                                .max_utf16_decoded_bytes_per_window
                                .min(remaining);

                            let decoded = match variant {
                                Variant::Utf16Le => decode_utf16le_to_vec(&buf[w.clone()], max_out),
                                Variant::Utf16Be => decode_utf16be_to_vec(&buf[w.clone()], max_out),
                                _ => unreachable!(),
                            };

                            let decoded = match decoded {
                                Ok(bytes) => bytes,
                                Err(_) => continue,
                            };

                            if decoded.is_empty() {
                                continue;
                            }

                            *total_decode_output_bytes =
                                total_decode_output_bytes.saturating_add(decoded.len());
                            if *total_decode_output_bytes
                                > engine.tuning.max_total_decode_output_bytes
                            {
                                return found_any;
                            }

                            let mut steps = steps.to_vec();
                            steps.push(StepKind::Utf16 {
                                le: matches!(
                                    variant.utf16_endianness().unwrap(),
                                    Utf16Endianness::Le
                                ),
                            });

                            for rm in rule.re.find_iter(&decoded) {
                                let span = rm.start()..rm.end();
                                out.insert(FindingKey {
                                    rule: rule.name,
                                    span,
                                    steps: steps.clone(),
                                });
                                found_any = true;
                            }
                        }
                    }
                }
            }
        }

        found_any
    }

    fn collect_windows_for_variant(
        buf: &[u8],
        rule: &RuleSpec,
        variant: Variant,
        tuning: &Tuning,
    ) -> Vec<Range<usize>> {
        let anchors = rule
            .anchors
            .iter()
            .map(|a| match variant {
                Variant::Raw => a.to_vec(),
                Variant::Utf16Le => utf16le_bytes(a),
                Variant::Utf16Be => utf16be_bytes(a),
            })
            .collect::<Vec<_>>();

        let seed_radius = match rule.two_phase.as_ref() {
            Some(tp) => tp.seed_radius,
            None => rule.radius,
        };
        let seed_radius_bytes = seed_radius.saturating_mul(variant.scale());

        let mut windows = Vec::new();
        push_anchor_windows(buf, &anchors, seed_radius_bytes, &mut windows);
        if windows.is_empty() {
            return windows;
        }

        merge_ranges_with_gap(&mut windows, tuning.merge_gap);
        coalesce_under_pressure(
            &mut windows,
            buf.len(),
            tuning.pressure_gap_start,
            tuning.max_windows_per_rule_variant,
        );

        let Some(tp) = rule.two_phase.as_ref() else {
            return windows;
        };

        let confirm = tp
            .confirm_any
            .iter()
            .map(|c| match variant {
                Variant::Raw => c.to_vec(),
                Variant::Utf16Le => utf16le_bytes(c),
                Variant::Utf16Be => utf16be_bytes(c),
            })
            .collect::<Vec<_>>();

        let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
        let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

        let mut expanded = Vec::new();
        for seed in windows {
            let win = &buf[seed.clone()];
            if !confirm.iter().any(|c| memmem::find(win, c).is_some()) {
                continue;
            }

            let lo = seed.start.saturating_sub(extra);
            let hi = (seed.end + extra).min(buf.len());
            expanded.push(lo..hi);
        }

        if expanded.is_empty() {
            return expanded;
        }

        merge_ranges_with_gap(&mut expanded, tuning.merge_gap);
        coalesce_under_pressure(
            &mut expanded,
            buf.len(),
            tuning.pressure_gap_start,
            tuning.max_windows_per_rule_variant,
        );

        expanded
    }

    fn push_anchor_windows(
        buf: &[u8],
        anchors: &[Vec<u8>],
        radius: usize,
        out: &mut Vec<Range<usize>>,
    ) {
        for anchor in anchors {
            if anchor.is_empty() {
                continue;
            }

            let mut start = 0usize;
            while start < buf.len() {
                let hay = &buf[start..];
                let Some(pos) = memmem::find(hay, anchor) else {
                    break;
                };
                let idx = start + pos;
                let lo = idx.saturating_sub(radius);
                let hi = (idx + anchor.len() + radius).min(buf.len());
                out.push(lo..hi);
                start = idx + 1;
            }
        }
    }

    fn merge_ranges_with_gap(ranges: &mut Vec<Range<usize>>, gap: usize) {
        if ranges.len() <= 1 {
            return;
        }

        ranges.sort_by_key(|r| r.start);
        let mut merged = Vec::with_capacity(ranges.len());
        let mut cur = ranges[0].clone();

        for r in ranges.iter().skip(1) {
            if r.start <= cur.end.saturating_add(gap) {
                cur.end = cur.end.max(r.end);
            } else {
                merged.push(cur);
                cur = r.clone();
            }
        }

        merged.push(cur);
        *ranges = merged;
    }

    fn coalesce_under_pressure(
        ranges: &mut Vec<Range<usize>>,
        hay_len: usize,
        mut gap: usize,
        max_windows: usize,
    ) {
        if ranges.len() <= max_windows {
            return;
        }

        while ranges.len() > max_windows && gap < hay_len {
            merge_ranges_with_gap(ranges, gap);
            gap = gap.saturating_mul(2);
        }

        if ranges.len() > max_windows && !ranges.is_empty() {
            let start = ranges.first().unwrap().start;
            let end = ranges.last().unwrap().end;
            ranges.clear();
            ranges.push(start.min(hay_len)..end.min(hay_len));
        }
    }

    #[derive(Clone, Debug)]
    struct TokenCase {
        rule_name: &'static str,
        token: Vec<u8>,
    }

    #[derive(Clone, Debug)]
    struct InputCase {
        rule_name: &'static str,
        buf: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug)]
    enum BaseEncoding {
        Raw,
        Utf16Le,
        Utf16Be,
    }

    #[derive(Clone, Copy, Debug)]
    enum TransformChain {
        None,
        Url,
        Base64,
        UrlThenBase64,
        Base64ThenUrl,
    }

    const TOKEN_RULE_NAMES: &[&str] = &[
        "aws-access-token",
        "github-pat",
        "github-oauth",
        "github-app-token",
        "gitlab-pat",
        "slack-access-token",
        "slack-web-hook",
        "stripe-access-token",
        "sendgrid-api-token",
        "npm-access-token",
        "databricks-api-token",
        "private-key",
    ];

    fn token_strategy() -> BoxedStrategy<TokenCase> {
        const ALNUM_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const ALNUM_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        const ALNUM_MIXED: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const GITLAB_CHARS: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        const BASE64_CHARS: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const SENDGRID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789=_-.";
        const DATABRICKS_CHARS: &[u8] = b"abcdefgh0123456789";

        let aws = prop::collection::vec(any::<u8>(), 16).prop_map(|bytes| {
            let mut token = b"AKIA".to_vec();
            token.extend(map_bytes(&bytes, ALNUM_UPPER));
            TokenCase {
                rule_name: "aws-access-token",
                token,
            }
        });

        let github_pat = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
            rule_name: "github-pat",
            token: [b"ghp_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
        });

        let github_oauth = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
            rule_name: "github-oauth",
            token: [b"gho_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
        });

        let github_app = prop::collection::vec(any::<u8>(), 37).prop_map(|bytes| {
            let prefixes = [b"ghu_".as_slice(), b"ghs_".as_slice()];
            let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
            let mut token = prefix.to_vec();
            token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
            TokenCase {
                rule_name: "github-app-token",
                token,
            }
        });

        let gitlab_pat = prop::collection::vec(any::<u8>(), 20).prop_map(|bytes| TokenCase {
            rule_name: "gitlab-pat",
            token: [b"glpat-".as_slice(), &map_bytes(&bytes, GITLAB_CHARS)].concat(),
        });

        let slack_access = prop::collection::vec(any::<u8>(), 21).prop_map(|bytes| {
            let prefixes = [
                b"xoxb-".as_slice(),
                b"xoxa-".as_slice(),
                b"xoxp-".as_slice(),
                b"xoxr-".as_slice(),
                b"xoxs-".as_slice(),
            ];
            let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
            let mut token = prefix.to_vec();
            token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
            TokenCase {
                rule_name: "slack-access-token",
                token,
            }
        });

        let slack_webhook = prop::collection::vec(any::<u8>(), 44).prop_map(|bytes| TokenCase {
            rule_name: "slack-web-hook",
            token: [
                b"https://hooks.slack.com/services/".as_slice(),
                &map_bytes(&bytes, BASE64_CHARS),
            ]
            .concat(),
        });

        let stripe = prop::collection::vec(any::<u8>(), 17).prop_map(|bytes| {
            let prefixes = [
                b"sk_test_".as_slice(),
                b"sk_live_".as_slice(),
                b"pk_test_".as_slice(),
                b"pk_live_".as_slice(),
            ];
            let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
            let mut token = prefix.to_vec();
            token.extend(map_bytes(&bytes[1..], ALNUM_LOWER));
            TokenCase {
                rule_name: "stripe-access-token",
                token,
            }
        });

        let sendgrid = prop::collection::vec(any::<u8>(), 67).prop_map(|bytes| {
            let prefixes = [b"SG.".as_slice(), b"sg.".as_slice()];
            let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
            let mut token = prefix.to_vec();
            token.extend(map_bytes(&bytes[1..], SENDGRID_CHARS));
            TokenCase {
                rule_name: "sendgrid-api-token",
                token,
            }
        });

        let npm = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
            rule_name: "npm-access-token",
            token: [b"npm_".as_slice(), &map_bytes(&bytes, ALNUM_LOWER)].concat(),
        });

        let databricks = prop::collection::vec(any::<u8>(), 33).prop_map(|bytes| {
            let prefixes = [b"dapi".as_slice(), b"DAPI".as_slice()];
            let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
            let mut token = prefix.to_vec();
            token.extend(map_bytes(&bytes[1..], DATABRICKS_CHARS));
            TokenCase {
                rule_name: "databricks-api-token",
                token,
            }
        });

        let private_key = prop::collection::vec(any::<u8>(), 64).prop_map(|bytes| {
            let mut token = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
            token.extend(map_bytes(&bytes, BASE64_CHARS));
            token.extend(b"\n-----END PRIVATE KEY-----");
            TokenCase {
                rule_name: "private-key",
                token,
            }
        });

        prop_oneof![
            aws,
            github_pat,
            github_oauth,
            github_app,
            gitlab_pat,
            slack_access,
            slack_webhook,
            stripe,
            sendgrid,
            npm,
            databricks,
            private_key,
        ]
        .boxed()
    }

    fn base_encoding_strategy() -> BoxedStrategy<BaseEncoding> {
        prop_oneof![
            Just(BaseEncoding::Raw),
            Just(BaseEncoding::Utf16Le),
            Just(BaseEncoding::Utf16Be),
        ]
        .boxed()
    }

    fn transform_chain_strategy() -> BoxedStrategy<TransformChain> {
        prop_oneof![
            Just(TransformChain::None),
            Just(TransformChain::Url),
            Just(TransformChain::Base64),
            Just(TransformChain::UrlThenBase64),
            Just(TransformChain::Base64ThenUrl),
        ]
        .boxed()
    }

    fn input_case_strategy() -> BoxedStrategy<InputCase> {
        (
            token_strategy(),
            base_encoding_strategy(),
            transform_chain_strategy(),
            prop::collection::vec(any::<u8>(), 0..64),
            prop::collection::vec(any::<u8>(), 0..64),
        )
            .prop_map(|(token_case, base, chain, prefix, suffix)| {
                let mut token = token_case.token;
                if requires_trailing_delimiter(token_case.rule_name) {
                    token.push(b' ');
                }
                let encoded = apply_encoding(&token, base, chain);
                let mut buf = Vec::new();
                buf.extend(prefix);
                buf.extend(encoded);
                buf.extend(suffix);
                InputCase {
                    rule_name: token_case.rule_name,
                    buf,
                }
            })
            .boxed()
    }

    fn map_bytes(bytes: &[u8], charset: &[u8]) -> Vec<u8> {
        bytes
            .iter()
            .map(|b| charset[*b as usize % charset.len()])
            .collect()
    }

    fn apply_encoding(token: &[u8], base: BaseEncoding, chain: TransformChain) -> Vec<u8> {
        let bytes = match base {
            BaseEncoding::Raw => token.to_vec(),
            BaseEncoding::Utf16Le => utf16le_bytes(token),
            BaseEncoding::Utf16Be => utf16be_bytes(token),
        };

        match chain {
            TransformChain::None => bytes,
            TransformChain::Url => url_percent_encode_all(&bytes),
            TransformChain::Base64 => b64_encode(&bytes).into_bytes(),
            TransformChain::UrlThenBase64 => {
                let url = url_percent_encode_all(&bytes);
                b64_encode(&url).into_bytes()
            }
            TransformChain::Base64ThenUrl => {
                let b64 = b64_encode(&bytes);
                url_percent_encode_all(b64.as_bytes())
            }
        }
    }

    fn url_percent_encode_all(input: &[u8]) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = Vec::with_capacity(input.len().saturating_mul(3));
        for &b in input {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0F) as usize]);
        }
        out
    }

    fn requires_trailing_delimiter(rule_name: &str) -> bool {
        matches!(
            rule_name,
            "sendgrid-api-token" | "npm-access-token" | "databricks-api-token"
        )
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct RecKey {
        rule_id: u32,
        span_start: u32,
        span_end: u32,
    }

    fn scan_in_chunks_with_overlap(
        engine: &Engine,
        buf: &[u8],
        chunk_size: usize,
        overlap: usize,
    ) -> Vec<FindingRec> {
        let mut scratch = engine.new_scratch();
        let mut out = Vec::new();
        let mut batch = Vec::new();

        let mut tail = Vec::new();
        let mut tail_len = 0usize;
        let mut offset = 0usize;

        while offset < buf.len() {
            let read = (buf.len() - offset).min(chunk_size);
            let mut chunk = vec![0u8; tail_len + read];
            if tail_len > 0 {
                chunk[..tail_len].copy_from_slice(&tail[..tail_len]);
            }
            chunk[tail_len..tail_len + read].copy_from_slice(&buf[offset..offset + read]);

            let base_offset = offset.saturating_sub(tail_len) as u64;
            engine.scan_chunk_into(&chunk, FileId(0), base_offset, &mut scratch);
            scratch.drop_prefix_findings(offset as u64);
            scratch.drain_findings_into(&mut batch);
            out.append(&mut batch);

            let total_len = tail_len + read;
            let next_tail_len = overlap.min(total_len);
            if tail.len() < next_tail_len {
                tail.resize(next_tail_len, 0);
            }
            if next_tail_len > 0 {
                tail[..next_tail_len].copy_from_slice(&chunk[total_len - next_tail_len..total_len]);
            }
            tail_len = next_tail_len;
            offset += read;
        }

        out
    }

    fn scan_in_chunks(engine: &Engine, buf: &[u8], chunk_size: usize) -> Vec<FindingRec> {
        scan_in_chunks_with_overlap(engine, buf, chunk_size, engine.required_overlap())
    }

    fn recs_to_keys(recs: &[FindingRec]) -> HashSet<RecKey> {
        recs.iter()
            .map(|rec| RecKey {
                rule_id: rec.rule_id,
                span_start: rec.span_start,
                span_end: rec.span_end,
            })
            .collect()
    }

    fn replay_steps(engine: &Engine, root: &[u8], steps: &[DecodeStep]) -> Option<Vec<u8>> {
        let mut cur = root.to_vec();

        for step in steps {
            match step {
                DecodeStep::Transform {
                    transform_idx,
                    parent_span,
                } => {
                    if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                        return None;
                    }
                    let tc = engine.transforms.get(*transform_idx)?;
                    let decoded =
                        decode_to_vec(tc, &cur[parent_span.clone()], tc.max_decoded_bytes).ok()?;
                    cur = decoded;
                }
                DecodeStep::Utf16Window {
                    endianness,
                    parent_span,
                } => {
                    if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                        return None;
                    }
                    let max_out = engine.tuning.max_utf16_decoded_bytes_per_window;
                    let decoded = match endianness {
                        Utf16Endianness::Le => {
                            decode_utf16le_to_vec(&cur[parent_span.clone()], max_out).ok()?
                        }
                        Utf16Endianness::Be => {
                            decode_utf16be_to_vec(&cur[parent_span.clone()], max_out).ok()?
                        }
                    };
                    cur = decoded;
                }
            }
        }

        Some(cur)
    }

    fn validate_findings(engine: &Engine, root: &[u8], findings: &[Finding]) -> Result<(), String> {
        for finding in findings {
            let buf = replay_steps(engine, root, &finding.decode_steps)
                .ok_or_else(|| format!("decode steps failed for {}", finding.rule))?;

            if finding.span.end > buf.len() {
                return Err(format!(
                    "span out of bounds for {} ({} > {})",
                    finding.rule,
                    finding.span.end,
                    buf.len()
                ));
            }

            let rule = engine
                .rules
                .iter()
                .find(|r| r.name == finding.rule)
                .ok_or_else(|| format!("rule not found: {}", finding.rule))?;

            let mut matched = false;
            for rm in rule.re.find_iter(&buf) {
                if rm.start() == finding.span.start && rm.end() == finding.span.end {
                    matched = true;
                    break;
                }
            }

            if !matched {
                return Err(format!(
                    "span not aligned with regex for {} at {:?}",
                    finding.rule, finding.span
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn token_strategy_covers_demo_rules() {
        let expected: HashSet<&str> = demo_rules().iter().map(|r| r.name).collect();
        let provided: HashSet<&str> = TOKEN_RULE_NAMES.iter().copied().collect();
        assert_eq!(expected, provided);
    }

    #[test]
    fn scan_file_sync_materializes_provenance_across_chunks() -> std::io::Result<()> {
        let engine = Arc::new(demo_engine());
        let runtime = ScannerRuntime::new(
            engine.clone(),
            ScannerConfig {
                chunk_size: 32,
                io_queue: 2,
                reader_threads: 1,
                scan_threads: 1,
            },
        );

        let aws = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
        let utf16le = super::utf16le_bytes(aws);
        let b64 = b64_encode(&utf16le);

        let mut buf = vec![b'!'; 17];
        buf.extend_from_slice(b64.as_bytes());
        buf.extend(vec![b'!'; 17]);

        let tmp = write_temp_file(&buf)?;
        let findings = runtime.scan_file_sync(FileId(0), tmp.path())?;

        assert!(findings.iter().any(|f| f.rule == "aws-access-token"));
        if let Err(msg) = validate_findings(&engine, &buf, &findings) {
            panic!("{}", msg);
        }

        Ok(())
    }

    #[test]
    fn scan_file_sync_drops_prefix_duplicates() -> std::io::Result<()> {
        const ANCHORS: &[&[u8]] = &[b"X"];
        let rules = vec![RuleSpec {
            name: "toy-token",
            anchors: ANCHORS,
            radius: 0,
            two_phase: None,
            must_contain: None,
            re: Regex::new("X").unwrap(),
        }];
        let engine = Arc::new(Engine::new(rules, Vec::new(), demo_tuning()));
        let runtime = ScannerRuntime::new(
            engine,
            ScannerConfig {
                chunk_size: 4,
                io_queue: 1,
                reader_threads: 1,
                scan_threads: 1,
            },
        );

        let mut buf = vec![b'A'; 6];
        buf[3] = b'X'; // last byte of chunk 1, also prefix of chunk 2

        let tmp = write_temp_file(&buf)?;
        let findings = runtime.scan_file_sync(FileId(0), tmp.path())?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].root_span_hint, 3..4);

        Ok(())
    }

    #[test]
    fn utf16_overlap_accounts_for_scaled_radius() {
        let rule = RuleSpec {
            name: "utf16-boundary",
            anchors: &[b"tok_"],
            radius: 12,
            two_phase: None,
            must_contain: None,
            re: Regex::new(r"aaatok_[0-9]{8}bbbb").unwrap(),
        };
        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let anchor_len_utf16 = b"tok_".len() * 2;
        let radius = 12usize;
        let old_overlap = radius
            .saturating_mul(2)
            .saturating_add(anchor_len_utf16)
            .saturating_sub(1);
        let expected_overlap = anchor_len_utf16 + radius.saturating_mul(4) - 1;

        assert_eq!(engine.required_overlap(), expected_overlap);
        assert!(old_overlap < engine.required_overlap());

        let token = b"aaatok_12345678bbbb";
        let utf16 = utf16le_bytes(token);

        let mut buf = vec![b'!'; 30];
        buf.extend_from_slice(&utf16);
        buf.extend(vec![b'!'; 12]);

        let chunk_size = 67;

        let bad = scan_in_chunks_with_overlap(&engine, &buf, chunk_size, old_overlap);
        assert!(
            !bad.iter()
                .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
            "expected miss with undersized overlap"
        );

        let good = scan_in_chunks(&engine, &buf, chunk_size);
        assert!(
            good.iter()
                .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
            "expected match with required_overlap"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            .. ProptestConfig::default()
        })]

        #[test]
        fn prop_engine_matches_reference(case in input_case_strategy()) {
            let engine = demo_engine();
            let rules = demo_rules();

            let findings = engine.scan_chunk(&case.buf);
            let engine_keys = findings_to_keys(&findings);
            let ref_keys = reference_scan_keys(&engine, &rules, &case.buf);

            prop_assert_eq!(engine_keys, ref_keys);

            if let Err(msg) = validate_findings(&engine, &case.buf, &findings) {
                prop_assert!(false, "{}", msg);
            }
        }

        #[test]
        fn prop_chunked_matches_full(case in input_case_strategy(), chunk_size in 1usize..256) {
            let engine = demo_engine();
            let mut scratch = engine.new_scratch();
            let full = engine.scan_chunk_records(&case.buf, FileId(0), 0, &mut scratch);
            let chunked = scan_in_chunks(&engine, &case.buf, chunk_size);

            let full_keys = recs_to_keys(&full);
            let chunked_keys = recs_to_keys(&chunked);

            prop_assert!(chunked_keys.is_superset(&full_keys));
        }
    }

    #[cfg(feature = "stdx-proptest")]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        const PROPTEST_CASES: u32 = 32;
        const PROPTEST_FUZZ_MULTIPLIER: u32 = 1;

        fn proptest_config() -> ProptestConfig {
            let cases = crate::test_utils::proptest_cases(PROPTEST_CASES);
            let mult = crate::test_utils::proptest_fuzz_multiplier(PROPTEST_FUZZ_MULTIPLIER);
            ProptestConfig::with_cases(cases.saturating_mul(mult))
        }

        proptest! {
            #![proptest_config(proptest_config())]

            #[test]
            fn prop_scan_chunk_reuse_scratch_matches_fresh(
                case_a in input_case_strategy(),
                case_b in input_case_strategy(),
            ) {
                let engine = demo_engine();
                let mut scratch = engine.new_scratch();
                let mut out = Vec::new();

                engine.scan_chunk_into(&case_a.buf, FileId(0), 0, &mut scratch);
                engine.drain_findings_materialized(&mut scratch, &mut out);
                let keys_a = findings_to_keys(&out);
                let fresh_a = findings_to_keys(&engine.scan_chunk(&case_a.buf));
                prop_assert_eq!(keys_a, fresh_a);

                out.clear();
                engine.scan_chunk_into(&case_b.buf, FileId(0), 0, &mut scratch);
                engine.drain_findings_materialized(&mut scratch, &mut out);
                let keys_b = findings_to_keys(&out);
                let fresh_b = findings_to_keys(&engine.scan_chunk(&case_b.buf));
                prop_assert_eq!(keys_b, fresh_b);
            }

            #[test]
            fn prop_hit_accumulator_coalesces(
                ranges in prop::collection::vec((0u32..512, 0u32..512), 0..128),
                max_hits in 1usize..32
            ) {
                let mut acc = HitAccumulator::with_capacity(max_hits);
                let mut ref_windows: Vec<SpanU32> = Vec::new();
                let mut ref_coalesced: Option<SpanU32> = None;

                for (a, b) in ranges {
                    let (start, end) = if a <= b { (a, b) } else { (b, a) };
                    let start = start as usize;
                    let end = end as usize;
                    acc.push(start, end, max_hits);

                    let r = SpanU32::new(start, end);
                    if let Some(c) = ref_coalesced.as_mut() {
                        c.start = c.start.min(r.start);
                        c.end = c.end.max(r.end);
                    } else if ref_windows.len() < max_hits {
                        ref_windows.push(r);
                    } else {
                        let mut c = ref_windows[0];
                        for w in &ref_windows[1..] {
                            c.start = c.start.min(w.start);
                            c.end = c.end.max(w.end);
                        }
                        c.start = c.start.min(r.start);
                        c.end = c.end.max(r.end);
                        ref_windows.clear();
                        ref_coalesced = Some(c);
                    }
                }

                match (acc.coalesced, ref_coalesced) {
                    (Some(actual), Some(expected)) => {
                        prop_assert_eq!(actual, expected);
                        prop_assert_eq!(acc.windows.len(), 0);
                    }
                    (None, None) => {
                        prop_assert_eq!(acc.windows.len(), ref_windows.len());
                        for (i, expected) in ref_windows.iter().enumerate() {
                            prop_assert_eq!(acc.windows[i], *expected);
                        }
                    }
                    _ => {
                        prop_assert!(false, "coalesced state mismatch");
                    }
                }
            }

            #[test]
            fn prop_span_finders_match_vec_vs_scratch(
                buf in prop::collection::vec(any::<u8>(), 0..256),
                min_len in 1usize..32,
                max_len in 1usize..96,
                max_spans in 0usize..32,
                plus_to_space in any::<bool>(),
                allow_space_ws in any::<bool>(),
            ) {
                let max_len = max_len.max(min_len);
                let mut vec_out: Vec<Range<usize>> = Vec::new();
                let mut scratch_out: ScratchVec<Range<usize>> =
                    ScratchVec::with_capacity(max_spans).unwrap();

                find_url_spans_into(
                    &buf,
                    min_len,
                    max_len,
                    max_spans,
                    plus_to_space,
                    &mut vec_out,
                );
                find_url_spans_into(
                    &buf,
                    min_len,
                    max_len,
                    max_spans,
                    plus_to_space,
                    &mut scratch_out,
                );
                prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());

                vec_out.clear();
                scratch_out.clear();
                find_base64_spans_into(
                    &buf,
                    min_len,
                    max_len,
                    max_spans,
                    allow_space_ws,
                    &mut vec_out,
                );
                find_base64_spans_into(
                    &buf,
                    min_len,
                    max_len,
                    max_spans,
                    allow_space_ws,
                    &mut scratch_out,
                );
                prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());
            }
        }
    }
}
