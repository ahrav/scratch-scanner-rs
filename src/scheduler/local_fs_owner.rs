//! Canonical Local Filesystem Scanner
//!
//! # Architecture
//!
//! - CPU workers do both I/O and scan (no separate I/O threads)
//! - Uses `LocalFirst` buffer pool policy (same thread acquires and releases)
//! - Sequential reads with overlap carry (no seeks, no re-reading overlap)
//! - Discovery thread enqueues files; workers process entire files
//!
//! # Module Role
//!
//! This is the single local-filesystem scan path used by the scheduler. The
//! module name is retained for historical reasons, but all local scan entry
//! points (`scan_local`, `LocalConfig`, `LocalFile`) live here.
//!
//! # Why Blocking Reads First?
//!
//! 1. **Strong baseline**: Kernel page cache is highly optimized; often hits memory
//! 2. **Minimal complexity**: No async runtime, no completion queues
//! 3. **Measureable**: Establish baseline before adding io_uring complexity
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: Every discovered file is scanned (blocking buffer acquire)
//! - **Chunk overlap**: `engine.required_overlap()` bytes overlap between chunks
//! - **Budget bounded**: `max_in_flight_objects` limits discovered-but-not-complete files
//! - **Buffer bounded**: `pool_buffers` limits peak memory
//! - **Snapshot semantics**: File size taken at open time (consistent point-in-time)
//!
//! # Performance Characteristics
//!
//! | Workload | Expected Behavior |
//! |----------|-------------------|
//! | Hot cache (small files) | CPU-bound, near memory bandwidth |
//! | Cold cache (SSD) | I/O-bound, ~3-5 GB/s with good SSD |
//! | Cold cache (HDD) | I/O-bound, ~150-200 MB/s sequential |
//!
//! # I/O Pattern: Overlap Carry
//!
//! Instead of seeking back for each chunk's overlap:
//! 1. Acquire ONE buffer per file (blocking)
//! 2. Read sequentially, carry overlap bytes forward via `copy_within`
//! 3. Eliminates: seeks, re-reading overlap from kernel, per-chunk pool churn
//!
//! ```text
//! Iteration 1:                    Iteration 2:
//! ┌─────────────────────────┐     ┌─────────────────────────┐
//! │      payload bytes      │     │overlap│  new payload    │
//! │      (from read)        │     │(copy) │  (from read)    │
//! └─────────────────────────┘     └─────────────────────────┘
//!                           │            ▲
//!                           └────────────┘
//!                         copy_within(tail → head)
//! ```
//!
//! # When to Consider io_uring
//!
//! Profile first. If workers show significant idle time waiting on reads
//! (visible in `perf` as time in `read` syscall), io_uring may help.
//! For page-cache-hot workloads, blocking reads are competitive.

use super::count_budget::CountBudget;
use super::engine_trait::{EngineScratch, FindingRecord, FindingWithHashRecord, ScanEngine};
use super::executor::{Executor, ExecutorConfig, WorkerCtx};
use super::metrics::{MetricsSnapshot, WorkerMetricsLocal};
use super::ts_buffer_pool::{TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::archive::formats::zip::LimitedRead;
use crate::archive::formats::{
    tar::TAR_BLOCK_LEN, GzipStream, TarCursor, TarInput, TarNext, TarRead, ZipCursor, ZipEntryMeta,
    ZipNext, ZipOpen,
};
use crate::archive::path::apply_hash_suffix_truncation;
use crate::archive::{
    detect_kind_from_name_bytes, detect_kind_from_path, sniff_kind_from_header, ArchiveBudgets,
    ArchiveConfig, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult, EntryPathCanonicalizer,
    EntrySkipReason, PartialReason, VirtualPathBuilder, DEFAULT_MAX_COMPONENTS,
};
use crate::scheduler::engine_stub::BUFFER_LEN_MAX;
use crate::store::{FsFindingBatch, FsFindingRecord, FsRunLoss, StoreProducer};

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for local filesystem scanning.
///
/// # Sizing Guidelines
///
/// - `chunk_size`: 64-256 KiB typical. Larger = fewer syscalls, more memory per file.
/// - `pool_buffers`: Bound peak memory. Should be >= `workers` to avoid starvation.
/// - `max_in_flight_objects`: Bound discovery depth. Too high = memory for paths/metadata.
/// - `max_file_size`: Open-time size cap; oversized files are skipped.
#[derive(Clone)]
pub struct LocalConfig {
    /// Number of CPU worker threads.
    pub workers: usize,

    /// Payload bytes per chunk (excluding overlap).
    ///
    /// Actual buffer size = `chunk_size + engine.required_overlap()`.
    pub chunk_size: usize,

    /// Total buffers in the pool.
    ///
    /// Bounds peak memory: `pool_buffers * (chunk_size + overlap)`.
    pub pool_buffers: usize,

    /// Per-worker local queue capacity in buffer pool.
    pub local_queue_cap: usize,

    /// Max discovered-but-not-complete files.
    ///
    /// Controls discovery backpressure. Higher = more path metadata in memory.
    pub max_in_flight_objects: usize,

    /// Maximum file size in bytes to scan.
    ///
    /// Files larger than this are skipped after `open()` based on the
    /// snapshot size from `metadata().len()`.
    pub max_file_size: u64,

    /// Seed for deterministic executor behavior.
    pub seed: u64,

    /// If true, deduplicate findings within each chunk.
    ///
    /// This is a defense-in-depth measure for engines that might emit
    /// duplicate findings for the same match (e.g., overlapping patterns).
    /// Cross-chunk deduplication is handled separately by `drop_prefix_findings`.
    pub dedupe_within_chunk: bool,

    /// Archive scanning configuration.
    pub archive: ArchiveConfig,

    /// When `true`, skip files that appear to be binary (NUL byte heuristic).
    /// Defaults to `true`. Set to `false` via `--scan-binary` to scan everything.
    pub skip_binary: bool,

    /// Structured event sink for finding output.
    ///
    /// All findings are emitted as `ScanEvent::Finding` through this sink.
    pub event_sink: Arc<dyn crate::unified::events::EventSink>,

    /// Optional persistence producer for post-dedupe FS finding batches.
    pub store_producer: Option<Arc<dyn StoreProducer>>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            workers: 8,
            chunk_size: 64 * 1024, // 64 KiB
            pool_buffers: 32,
            local_queue_cap: 4,
            max_in_flight_objects: 256,
            max_file_size: u64::MAX,
            seed: 0x853c49e6748fea9b,
            dedupe_within_chunk: true,
            archive: ArchiveConfig::default(),
            skip_binary: true,
            event_sink: Arc::new(crate::unified::events::NullEventSink),
            store_producer: None,
        }
    }
}

impl std::fmt::Debug for LocalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalConfig")
            .field("workers", &self.workers)
            .field("chunk_size", &self.chunk_size)
            .field("pool_buffers", &self.pool_buffers)
            .field("local_queue_cap", &self.local_queue_cap)
            .field("max_in_flight_objects", &self.max_in_flight_objects)
            .field("max_file_size", &self.max_file_size)
            .field("seed", &self.seed)
            .field("dedupe_within_chunk", &self.dedupe_within_chunk)
            .field("archive", &self.archive)
            .field("skip_binary", &self.skip_binary)
            .field("event_sink", &"<dyn EventSink>")
            .field(
                "store_producer",
                &self.store_producer.as_ref().map(|_| "<dyn StoreProducer>"),
            )
            .finish()
    }
}

impl LocalConfig {
    /// Validate configuration against engine constraints.
    ///
    /// # Panics
    ///
    /// Panics if configuration violates invariants.
    pub fn validate<E: ScanEngine>(&self, engine: &E) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(self.local_queue_cap > 0, "local_queue_cap must be > 0");
        assert!(
            self.max_in_flight_objects > 0,
            "max_in_flight_objects must be > 0"
        );
        if let Err(err) = self.archive.validate() {
            panic!("archive config invalid: {err}");
        }

        let overlap = engine.required_overlap();
        let buf_len = self.chunk_size.saturating_add(overlap);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
            self.chunk_size,
            overlap,
            buf_len,
            BUFFER_LEN_MAX
        );

        // Warn if pool is undersized
        #[cfg(debug_assertions)]
        if self.pool_buffers < self.workers {
            eprintln!(
                "[LocalConfig] Warning: pool_buffers ({}) < workers ({}). \
                 Workers may contend heavily for buffers.",
                self.pool_buffers, self.workers
            );
        }
    }

    /// Compute buffer length including overlap.
    pub fn buffer_len<E: ScanEngine>(&self, engine: &E) -> usize {
        self.chunk_size.saturating_add(engine.required_overlap())
    }

    /// Compute peak memory usage for buffers.
    pub fn peak_buffer_memory<E: ScanEngine>(&self, engine: &E) -> usize {
        self.pool_buffers.saturating_mul(self.buffer_len(engine))
    }
}

// ============================================================================
// Local File Discovery
// ============================================================================

/// A file to be scanned.
#[derive(Debug, Clone)]
pub struct LocalFile {
    /// Path to the file.
    pub path: PathBuf,
    /// File size hint in bytes.
    ///
    /// Discovery may skip per-file metadata for performance, so this can be 0.
    /// Open-time metadata determines the actual size and enforcement.
    pub size: u64,
}

/// Iterator over files to scan.
///
/// This is a simple wrapper; real implementations would walk directories,
/// filter by extension, respect gitignore, etc.
pub trait FileSource: Send + 'static {
    /// Get the next file to scan, if any.
    fn next_file(&mut self) -> Option<LocalFile>;
}

/// Simple file source from a list of paths.
#[derive(Debug)]
pub struct VecFileSource {
    files: std::vec::IntoIter<LocalFile>,
}

impl VecFileSource {
    pub fn new(files: Vec<LocalFile>) -> Self {
        Self {
            files: files.into_iter(),
        }
    }

    /// Create from an Arc slice by cloning the inner data.
    ///
    /// This allows multiple iterations over the same file list without
    /// modifying the original data. The clone happens at source creation
    /// time, not during iteration.
    pub fn from_arc(files: std::sync::Arc<[LocalFile]>) -> Self {
        Self::new(files.to_vec())
    }
}

impl FileSource for VecFileSource {
    fn next_file(&mut self) -> Option<LocalFile> {
        self.files.next()
    }
}

// ============================================================================
// Task Types
// ============================================================================

/// A file task for the executor.
#[derive(Debug)]
struct FileTask {
    /// Run-scoped file ID.
    file_id: FileId,
    /// Path to open.
    path: PathBuf,
    /// File size hint from discovery (not used in processing).
    ///
    /// May be 0 if discovery skipped metadata for performance.
    ///
    /// Processing uses `file.metadata().len()` for snapshot-at-open semantics.
    /// Kept for logging/debugging the discovery phase.
    #[allow(dead_code)]
    size: u64,
    /// In-flight permit (released when task completes).
    _permit: super::count_budget::CountPermit,
}

// ============================================================================
// Per-Worker Scratch
// ============================================================================

/// Per-worker scratch state for local scanning.
///
/// # Invariants
/// - Buffers are preallocated and reused to avoid per-chunk allocations.
/// - Per-depth vectors (`vpaths`, `tar_cursors`, `path_budget_used`) are sized
///   to `max_archive_depth + 2` and indexed by depth.
/// - `next_virtual_file_id` stays in the high-bit namespace to avoid collisions
///   with real file ids.
struct LocalScratch<E: ScanEngine> {
    engine: Arc<E>,
    pool: TsBufferPool,

    /// Per-worker engine scratch.
    scan_scratch: E::Scratch,
    /// Per-worker findings buffer (avoids alloc per chunk).
    pending: Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Per-worker persistence batch buffer (avoids alloc per chunk).
    persist_batch: Vec<FsFindingRecord>,

    /// Archive path canonicalization scratch.
    canon: EntryPathCanonicalizer,
    /// Preallocated virtual path builders (depth 0..max_depth+1).
    vpaths: Vec<VirtualPathBuilder>,
    /// Per-depth path budget usage counters.
    path_budget_used: Vec<usize>,
    /// Reused archive budgets (no per-archive allocation).
    budgets: ArchiveBudgets,
    /// Per-depth TAR cursors (one per nested depth).
    tar_cursors: Vec<TarCursor>,
    /// Reused ZIP cursor with preallocated buffers.
    zip_cursor: ZipCursor<File>,
    /// Scratch buffer for entry display bytes when we need to append a hash suffix.
    entry_display_buf: Vec<u8>,
    /// Scratch buffer for gzip header peeking (bounded).
    gzip_header_buf: Vec<u8>,
    /// Scratch buffer for gzip header filename (bounded).
    gzip_name_buf: Vec<u8>,
    /// Monotonic virtual `FileId` generator for archive entries.
    next_virtual_file_id: u32,
    /// Shared abort flag set when `FailRun` policy triggers.
    abort_run: Arc<AtomicBool>,

    /// Structured event sink for finding output.
    event_sink: Arc<dyn crate::unified::events::EventSink>,
    /// Optional persistence producer for post-dedupe findings.
    store_producer: Option<Arc<dyn StoreProducer>>,

    /// Configuration flags.
    dedupe_within_chunk: bool,
    chunk_size: usize,
    max_file_size: u64,
    archive: ArchiveConfig,
    /// When `true`, skip files that appear to be binary.
    skip_binary: bool,
    /// Probe buffer for binary detection when archive sniffing is disabled.
    binary_probe_buf: [u8; crate::content_policy::CHECK_LEN],
    /// Reusable buffer for reading extractable binary files (input).
    #[cfg(feature = "binary-extract")]
    extract_buf: Vec<u8>,
    /// Reusable buffer for extraction output.
    #[cfg(feature = "binary-extract")]
    extract_out_buf: Vec<u8>,
    /// Temporary workspace for extractors (e.g. per-entry reads in JARs).
    #[cfg(feature = "binary-extract")]
    extract_scratch: Vec<u8>,
}

// ============================================================================
// Run Statistics
// ============================================================================

/// Statistics from a local scan run.
///
/// Core counters (`files_enqueued`, `bytes_enqueued`, `io_errors`) are always
/// populated regardless of build configuration. Persistence-loss counters are
/// populated when FS persistence plumbing is enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalStats {
    /// Files discovered and enqueued.
    pub files_enqueued: u64,
    /// Total bytes across all enqueued files (hint-based).
    ///
    /// If discovery skipped metadata, this may undercount and should not be
    /// treated as authoritative for throughput calculations.
    pub bytes_enqueued: u64,
    /// Files that failed to process due to I/O errors.
    ///
    /// This includes file open failures, metadata read failures, and
    /// read errors during scanning. Aggregated from worker metrics.
    pub io_errors: u64,
    /// Findings dropped by engine max-findings caps.
    pub dropped_findings: u64,
    /// Persistence batch emission failures observed during scan loops.
    pub persistence_emit_failures: u64,
    /// Whether run-loss counters indicate an incomplete persistence run.
    pub persistence_incomplete: bool,
}

/// Complete report from a local scan.
///
/// Core metrics in `metrics` (`bytes_scanned`, `chunks_scanned`, `io_errors`,
/// `findings_emitted`) are always aggregated from worker threads.
/// Perf-only metrics require `all(feature = "perf-stats", debug_assertions)`.
/// `stats.io_errors` is derived from `metrics.io_errors` for convenience.
#[derive(Debug, Default)]
pub struct LocalReport {
    pub stats: LocalStats,
    pub metrics: MetricsSnapshot,
}

// ============================================================================
// Helpers
// ============================================================================

/// Fixed-capacity stack buffer for diagnostic messages (no heap allocation).
///
/// Implements [`fmt::Write`] so it can be used with `write!()`.  Output
/// beyond `N` bytes is silently truncated.
struct StackMsg<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackMsg<N> {
    #[inline]
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    #[inline]
    fn as_str(&self) -> &str {
        // SAFETY: `fmt::Write::write_str` only accepts valid UTF-8, and we
        // only copy full byte sequences from those slices, so the buffer
        // contents are always valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> std::fmt::Write for StackMsg<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = N - self.len;
        let n = bytes.len().min(remaining);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

/// Deduplicate findings in place by (rule_id, root_hint, span, norm_hash).
///
/// # Algorithm
///
/// 1. Sort by `(rule_id, root_hint_start, root_hint_end, span_start, span_end, norm_hash)` — O(n log n)
/// 2. Dedup adjacent elements with matching keys — O(n)
///
/// Total: O(n log n) vs O(n²) for pairwise comparison.
///
/// # Why Sort Before Dedup?
///
/// `Vec::dedup_by` only removes *adjacent* duplicates. Sorting brings
/// identical findings together, ensuring all duplicates are removed.
/// The sort key ordering also provides stable, deterministic output ordering.
///
/// # When This Is Needed
///
/// This handles within-chunk duplicates (same finding emitted multiple times
/// by the engine). Cross-chunk duplicates are handled by `drop_prefix_findings`.
///
/// # CRITICAL: `norm_hash` must remain in the dedup key
///
/// Two findings with identical `(rule_id, root_hint, span)` but different
/// `norm_hash` values represent **distinct secrets** and must NOT be collapsed.
/// This occurs when transform chains produce different decoded values at the
/// same encoded location. Removing `norm_hash` from the key causes silent
/// data loss. The git-scan path uses `FindingKey` (which includes `norm_hash`)
/// for the same reason.
#[inline]
fn dedupe_findings<F: FindingWithHashRecord>(findings: &mut Vec<F>) {
    if findings.len() <= 1 {
        return;
    }

    findings.sort_unstable_by_key(|f| {
        (
            f.rule_id(),
            f.root_hint_start(),
            f.root_hint_end(),
            f.span_start(),
            f.span_end(),
            *f.norm_hash(),
        )
    });

    findings.dedup_by(|a, b| {
        a.rule_id() == b.rule_id()
            && a.root_hint_start() == b.root_hint_start()
            && a.root_hint_end() == b.root_hint_end()
            && a.span_start() == b.span_start()
            && a.span_end() == b.span_end()
            && a.norm_hash() == b.norm_hash()
    });
}

/// Account for effective drop loss after scheduler-side pruning.
///
/// The engine reports dropped findings (due to max-findings caps) *before*
/// overlap-prefix pruning and within-chunk dedupe. Findings removed by those
/// scheduler passes would have been discarded anyway and are not lossful for
/// persistence, so we subtract them from the engine-reported drops.
///
/// ```text
///   effective_drops = engine_reported_drops − scheduler_pruned
/// ```
///
/// Without this adjustment a chunk where the engine dropped 2 findings and the
/// scheduler pruned 2 duplicates would falsely report 2 drops, triggering the
/// `persistence_incomplete` signal even though every unique finding was emitted.
#[inline]
fn account_effective_dropped_findings(
    metrics: &mut WorkerMetricsLocal,
    engine_dropped: u64,
    scheduler_pruned: usize,
) {
    let effective = engine_dropped.saturating_sub(scheduler_pruned as u64);
    metrics.findings_dropped = metrics.findings_dropped.saturating_add(effective);
}

/// Emit structured finding events via the [`EventSink`].
///
/// Emits one [`ScanEvent::Finding`] per finding record.
///
/// [`EventSink`]: crate::unified::events::EventSink
#[inline]
fn emit_findings<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    event_sink: &dyn crate::unified::events::EventSink,
    path: &[u8],
    findings: &[F],
) {
    if findings.is_empty() {
        return;
    }

    for rec in findings {
        event_sink.emit(crate::unified::events::ScanEvent::Finding(
            crate::unified::events::FindingEvent {
                source: crate::unified::SourceKind::Fs,
                object_path: path,
                start: rec.root_hint_start(),
                end: rec.root_hint_end(),
                rule_id: rec.rule_id(),
                rule_name: engine.rule_name(rec.rule_id()),
                commit_id: None,
                change_kind: None,
            },
        ));
    }
}

/// Convert engine-typed findings into the flat [`FsFindingRecord`] format
/// expected by the persistence layer.
///
/// `out` is cleared and repopulated. It is pre-sized to
/// `max_findings_per_chunk` at worker init, so no reallocation occurs.
#[inline]
fn build_persistence_batch<F: FindingWithHashRecord>(
    findings: &[F],
    out: &mut Vec<FsFindingRecord>,
) {
    out.clear();
    // `out` is `persist_batch`, pre-sized to max_findings_per_chunk at
    // worker init. After `clear()`, capacity is guaranteed sufficient.
    debug_assert!(
        out.capacity() >= findings.len(),
        "persist_batch capacity ({}) < findings count ({})",
        out.capacity(),
        findings.len(),
    );
    for finding in findings {
        out.push(FsFindingRecord {
            rule_id: finding.rule_id(),
            root_hint_start: finding.root_hint_start(),
            root_hint_end: finding.root_hint_end(),
            span_start: finding.span_start(),
            span_end: finding.span_end(),
            norm_hash: *finding.norm_hash(),
        });
    }
}

/// Build and emit a persistence batch for one chunk's post-dedupe findings.
///
/// No-ops when `store_producer` is `None` or `findings` is empty.
/// On emit failure, increments `persistence_emit_failures` and `io_errors`,
/// and emits a diagnostic event. The scan continues — persistence errors are
/// fail-soft per batch, not per run.
#[inline]
fn emit_persistence_batch<F: FindingWithHashRecord>(
    store_producer: Option<&dyn StoreProducer>,
    event_sink: &dyn crate::unified::events::EventSink,
    path: &[u8],
    findings: &[F],
    persist_batch: &mut Vec<FsFindingRecord>,
    metrics: &mut WorkerMetricsLocal,
) {
    let Some(producer) = store_producer else {
        return;
    };
    if findings.is_empty() {
        return;
    }

    build_persistence_batch(findings, persist_batch);
    if let Err(err) = producer.emit_fs_batch(FsFindingBatch {
        object_path: path,
        findings: persist_batch.as_slice(),
    }) {
        metrics.persistence_emit_failures = metrics.persistence_emit_failures.saturating_add(1);
        let mut msg = StackMsg::<256>::new();
        let _ = std::fmt::Write::write_fmt(
            &mut msg,
            format_args!("fs persistence batch emit failed: {}", err.detail()),
        );
        event_sink.emit(crate::unified::events::ScanEvent::Diagnostic(
            crate::unified::events::DiagnosticEvent {
                level: "error",
                message: msg.as_str(),
            },
        ));
    }
}

/// Allocate a virtual `FileId` for archive entries.
///
/// Virtual IDs live in the high-bit namespace (`0x8000_0000..=0xFFFF_FFFF`)
/// to avoid collision with real file IDs (which start at 0 and grow upward).
/// The counter wraps after ~2^31 entries, but collisions are tolerable:
/// `FileId` is only used by the engine for internal attribution, not for
/// deduplication or correctness in the scheduler.
#[inline]
fn alloc_virtual_file_id(next_virtual_file_id: &mut u32) -> FileId {
    const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
    const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

    let id = *next_virtual_file_id;
    let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
    *next_virtual_file_id = next;
    FileId(id)
}

/// Length of a locator suffix: `@` + kind byte + 16 hex digits = 18 bytes.
///
/// Locators are appended to virtual path segments to disambiguate entries
/// that share the same display name within an archive. The format is
/// `@<kind><hex64>` where `kind` identifies the offset type:
/// - `t` = tar header block index
/// - `z` = ZIP local file header offset (when valid)
/// - `c` = ZIP central directory file header offset (fallback)
const LOCATOR_LEN: usize = 18;

/// Write a `u64` as 16 lowercase hex digits into `out16`.
#[inline(always)]
fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
    debug_assert_eq!(out16.len(), 16);
    for (i, out) in out16.iter_mut().enumerate().take(16) {
        let shift = (15 - i) * 4;
        let nyb = ((x >> shift) & 0xF) as u8;
        *out = match nyb {
            0..=9 => b'0' + nyb,
            _ => b'a' + (nyb - 10),
        };
    }
}

/// Format a locator suffix into `out` and return the full slice.
///
/// See [`LOCATOR_LEN`] for format description.
#[inline]
fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

/// Dispatch archive scanning by kind.
///
/// Routes to `process_gzip_file`, `process_tar_file`, `process_targz_file`,
/// or `process_zip_file` based on the detected [`ArchiveKind`].
///
/// The caller is responsible for recording archive-level stats
/// (`record_archive_scanned` / `record_archive_skipped` / `record_archive_partial`)
/// based on the returned [`ArchiveEnd`].
#[inline]
fn dispatch_archive_scan<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    kind: ArchiveKind,
) -> ArchiveEnd {
    match kind {
        ArchiveKind::Gzip => process_gzip_file(task, ctx),
        ArchiveKind::Tar => process_tar_file(task, ctx),
        ArchiveKind::TarGz => process_targz_file(task, ctx),
        ArchiveKind::Zip => process_zip_file(task, ctx),
    }
}

/// Hard cap on per-read output for archive streams (256 KiB).
///
/// Archive entry reads are clamped to this value even when the pool buffer
/// is larger. This bounds decompressor output per iteration, keeping
/// inflation-ratio checks responsive and limiting peak stack/heap pressure
/// from a single decompression call.
const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

/// Outcome of scanning an archive container.
///
/// Used by `dispatch_archive_scan` and its callees to communicate
/// whether the archive was fully consumed, entirely skipped, or
/// partially scanned (budget exhaustion, corruption, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveEnd {
    /// All entries in the archive were scanned to completion.
    Scanned,
    /// The archive was not scanned at all (e.g., I/O error, encrypted,
    /// unsupported format). The reason is recorded for telemetry.
    Skipped(ArchiveSkipReason),
    /// Scanning stopped partway through the archive (budget exceeded,
    /// malformed entry, inflation ratio exceeded). Some entries may
    /// have been fully scanned before the stop.
    Partial(PartialReason),
}

/// Map an archive-level skip reason to the corresponding partial-scan reason.
///
/// Used when a nested archive is skipped mid-stream, promoting the skip into
/// a partial outcome for the parent entry/archive. Unmapped variants fall
/// through to `MalformedZip` as a conservative default.
#[inline(always)]
fn map_archive_skip_to_partial(reason: ArchiveSkipReason) -> PartialReason {
    match reason {
        ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
        ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
        ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
        ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
            PartialReason::ArchiveOutputBudgetExceeded
        }
        ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
        ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
        ArchiveSkipReason::UnsupportedFeature => PartialReason::UnsupportedFeature,
        _ => PartialReason::MalformedZip,
    }
}

/// Extract the [`PartialReason`] from a [`BudgetHit`].
///
/// Every budget violation carries a reason; this collapses the four `BudgetHit`
/// variants into a flat `PartialReason` for recording in metrics and diagnostics.
#[inline(always)]
fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

/// Convert a [`BudgetHit`] into the corresponding [`ArchiveEnd`] outcome.
///
/// `SkipArchive` maps to `Skipped`; all others map to `Partial`.
#[inline(always)]
fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(_) => ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded),
    }
}

/// Borrowed view into [`LocalScratch`] for archive scanning.
///
/// Splits the per-worker scratch into disjoint borrows so nested archive
/// scans can recurse without aliasing. Each nesting level consumes the
/// head element of `vpaths`, `path_budget_used`, and `tar_cursors` via
/// `split_first_mut`, passing the tail to the child `ArchiveScanCtx`.
///
/// # Invariants
/// - All buffers are preallocated in `LocalScratch` and must not grow.
/// - Nested scans borrow disjoint slices of scratch buffers (no aliasing).
/// - `budgets` is shared across nested scans to enforce global caps.
/// - `path_budget_used` tracks per-depth virtual path byte usage.
/// - `abort_run` is set when `FailRun` policies trigger; callers must stop
///   dispatching new files once it becomes true.
struct ArchiveScanCtx<'a, E: ScanEngine> {
    engine: &'a Arc<E>,
    pool: &'a TsBufferPool,
    event_sink: &'a dyn crate::unified::events::EventSink,
    store_producer: Option<&'a dyn StoreProducer>,
    scan_scratch: &'a mut E::Scratch,
    /// Reusable findings drain buffer (cleared before each `drain_findings_into`).
    pending: &'a mut Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Reusable persistence batch buffer.
    persist_batch: &'a mut Vec<FsFindingRecord>,
    /// Shared budget tracker — enforces archive, entry, and root output caps.
    budgets: &'a mut ArchiveBudgets,
    canon: &'a mut EntryPathCanonicalizer,
    /// Per-depth virtual path builders. Head is consumed at this depth.
    vpaths: &'a mut [VirtualPathBuilder],
    /// Per-depth byte counters for virtual path budget enforcement.
    path_budget_used: &'a mut [usize],
    /// Per-depth tar header cursors. Head is consumed at this depth.
    tar_cursors: &'a mut [TarCursor],
    gzip_header_buf: &'a mut Vec<u8>,
    gzip_name_buf: &'a mut Vec<u8>,
    next_virtual_file_id: &'a mut u32,
    metrics: &'a mut WorkerMetricsLocal,
    archive: &'a ArchiveConfig,
    dedupe: bool,
    chunk_size: usize,
    /// Shared abort flag; set by `FailRun` policy handlers.
    abort_run: &'a AtomicBool,
}

impl<'a, E: ScanEngine> ArchiveScanCtx<'a, E> {
    /// Create a top-level archive scan context from per-worker scratch.
    ///
    /// Borrows all depth-indexed slices at full length; nested calls peel off
    /// the head element via `split_first_mut` before constructing child contexts.
    fn new(scratch: &'a mut LocalScratch<E>, metrics: &'a mut WorkerMetricsLocal) -> Self {
        Self {
            engine: &scratch.engine,
            pool: &scratch.pool,
            event_sink: &*scratch.event_sink,
            store_producer: scratch.store_producer.as_deref(),
            scan_scratch: &mut scratch.scan_scratch,
            pending: &mut scratch.pending,
            persist_batch: &mut scratch.persist_batch,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            next_virtual_file_id: &mut scratch.next_virtual_file_id,
            metrics,
            archive: &scratch.archive,
            dedupe: scratch.dedupe_within_chunk,
            chunk_size: scratch.chunk_size,
            abort_run: scratch.abort_run.as_ref(),
        }
    }
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
///
/// Discarded bytes still count against archive and root output budgets because
/// the decompressor already produced them. Returns `Err` with the triggering
/// [`PartialReason`] if charging the discard pushes a budget over its limit.
#[inline(always)]
fn charge_discarded_bytes(budgets: &mut ArchiveBudgets, bytes: u64) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(budget_hit_to_partial_reason(hit)),
    }
}

/// Apply decompressed-output budgeting for a read of `n` bytes.
///
/// Returns `(allowed, clamped)` where:
/// - `allowed` is the prefix length to scan/emits.
/// - `clamped` signals the caller must stop after this iteration.
///
/// If the decoder produced more bytes than allowed, the extra bytes are charged
/// as discarded output so archive/root caps remain accurate.
#[inline(always)]
fn apply_entry_budget_clamp(
    budgets: &mut ArchiveBudgets,
    n: usize,
    entry_partial_reason: &mut Option<PartialReason>,
    outcome: &mut ArchiveEnd,
    stop_archive: &mut bool,
) -> (u64, bool) {
    let mut allowed = n as u64;
    if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
        let r = budget_hit_to_partial_reason(hit);
        allowed = a;
        *entry_partial_reason = Some(r);
        if !matches!(hit, BudgetHit::SkipEntry(_)) {
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
    }

    if allowed == 0 {
        if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (0, true);
    }

    if allowed < n as u64 {
        let extra = (n as u64).saturating_sub(allowed);
        if let Err(r) = charge_discarded_bytes(budgets, extra) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (allowed, true);
    }

    (allowed, false)
}

/// Drain remaining tar entry payload bytes to realign the stream.
///
/// After a nested archive scan or a budget clamp, the tar entry may have
/// unread payload bytes. These must be consumed so the tar cursor stays
/// aligned to the next entry header. Discarded bytes are charged against
/// the decompressed-output budgets via [`charge_discarded_bytes`].
///
/// Returns `Err(MalformedTar)` on EOF or I/O error mid-drain.
fn discard_remaining_payload(
    input: &mut dyn TarRead,
    budgets: &mut ArchiveBudgets,
    buf: &mut [u8],
    mut remaining: u64,
) -> Result<(), PartialReason> {
    while remaining > 0 {
        let step = buf.len().min(remaining as usize);
        let n = match input.read(&mut buf[..step]) {
            Ok(n) => n,
            Err(_) => return Err(PartialReason::MalformedTar),
        };
        if n == 0 {
            return Err(PartialReason::MalformedTar);
        }
        budgets.charge_compressed_in(input.take_compressed_delta());
        charge_discarded_bytes(budgets, n as u64)?;
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(())
}

/// Scan a `.gz` file as a single virtual entry (`<gunzip>`).
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Concatenated gzip members are treated as one stream.
fn process_gzip_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let scratch = &mut ctx.scratch;
    let metrics = &mut ctx.metrics;
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let dedupe = scratch.dedupe_within_chunk;

    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    let parent_bytes = task.path.as_os_str().as_encoded_bytes();
    let max_len = scratch.archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let (mut gz, name_len) = match GzipStream::new_with_header(
        file,
        &mut scratch.gzip_header_buf,
        &mut scratch.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    let entry_name_bytes = if let Some(len) = name_len {
        let c = scratch.canon.canonicalize(
            &scratch.gzip_name_buf[..len],
            DEFAULT_MAX_COMPONENTS,
            max_len,
        );
        if c.had_traversal {
            metrics.archive.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            metrics.archive.record_component_cap_exceeded();
        }
        if c.truncated {
            metrics.archive.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    let path_bytes = scratch.vpaths[1]
        .build(parent_bytes, entry_name_bytes, max_len)
        .bytes;
    let need = path_bytes.len();
    if scratch.path_budget_used[1].saturating_add(need)
        > scratch.archive.max_virtual_path_bytes_per_archive
    {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
    }
    scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return budget_hit_to_archive_end(hit);
    }
    if let Err(hit) = scratch.budgets.begin_entry() {
        scratch.budgets.exit_archive();
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return budget_hit_to_archive_end(hit);
    }

    let mut buf = scratch.pool.acquire();

    let entry_file_id = alloc_virtual_file_id(&mut scratch.next_virtual_file_id);
    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        let allowance = scratch
            .budgets
            .remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        scratch
            .budgets
            .charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } =
            scratch.budgets.charge_decompressed_out(allowed)
        {
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf.as_slice()[..read_len];

        engine.scan_chunk_into(data, entry_file_id, base_offset, &mut scratch.scan_scratch);
        let engine_dropped = scratch.scan_scratch.dropped_findings();
        let before_prefix = scratch.scan_scratch.pending_findings_len();
        if !entry_scanned {
            metrics.archive.record_entry_scanned();
            entry_scanned = true;
        }

        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);
        let after_prefix = scratch.scan_scratch.pending_findings_len();

        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        let before_dedupe = scratch.pending.len();
        if dedupe && before_dedupe > 1 {
            dedupe_findings(&mut scratch.pending);
        }
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(before_dedupe.saturating_sub(scratch.pending.len()));
        account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

        metrics.findings_emitted = metrics
            .findings_emitted
            .wrapping_add(scratch.pending.len() as u64);

        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            metrics,
        );
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );

        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(allowed);

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    scratch.budgets.end_entry(offset > 0);
    scratch.budgets.exit_archive();

    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    scratch.gzip_header_buf = hdr_buf;

    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }

    if let Some(r) = entry_partial_reason {
        metrics.archive.record_entry_partial(r, path_bytes, false);
    }

    outcome
}

/// Scan a gzip stream as a single virtual entry.
///
/// # Invariants
/// - Offsets are decompressed byte offsets.
/// - Budget clamps stop scanning deterministically.
fn scan_gzip_stream_nested<E: ScanEngine, R: Read>(
    scan: &mut ArchiveScanCtx<'_, E>,
    gz: &mut GzipStream<R>,
    display: &[u8],
) -> ArchiveEnd {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let dedupe = scan.dedupe;
    let overlap = scan.engine.required_overlap();
    let file_id = alloc_virtual_file_id(scan.next_virtual_file_id);

    if let Err(hit) = budgets.begin_entry() {
        return budget_hit_to_archive_end(hit);
    }

    let mut buf = scan.pool.acquire();

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        budgets.charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf.as_slice()[..read_len];

        scan.engine
            .scan_chunk_into(data, file_id, base_offset, scan.scan_scratch);
        let engine_dropped = scan.scan_scratch.dropped_findings();
        let before_prefix = scan.scan_scratch.pending_findings_len();
        if !entry_scanned {
            scan.metrics.archive.record_entry_scanned();
            entry_scanned = true;
        }

        let new_bytes_start = offset;
        scan.scan_scratch.drop_prefix_findings(new_bytes_start);
        let after_prefix = scan.scan_scratch.pending_findings_len();

        scan.pending.clear();
        scan.scan_scratch.drain_findings_into(scan.pending);

        let before_dedupe = scan.pending.len();
        if dedupe && before_dedupe > 1 {
            dedupe_findings(scan.pending);
        }
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(before_dedupe.saturating_sub(scan.pending.len()));
        account_effective_dropped_findings(scan.metrics, engine_dropped, scheduler_pruned);

        scan.metrics.findings_emitted = scan
            .metrics
            .findings_emitted
            .wrapping_add(scan.pending.len() as u64);

        emit_persistence_batch(
            scan.store_producer,
            scan.event_sink,
            display,
            scan.pending,
            scan.persist_batch,
            scan.metrics,
        );
        emit_findings(scan.engine.as_ref(), scan.event_sink, display, scan.pending);

        scan.metrics.chunks_scanned = scan.metrics.chunks_scanned.saturating_add(1);
        scan.metrics.bytes_scanned = scan.metrics.bytes_scanned.saturating_add(allowed);

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    budgets.end_entry(offset > 0);
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }
    if let Some(r) = entry_partial_reason {
        scan.metrics.archive.record_entry_partial(r, display, false);
    }

    outcome
}

/// Scan a tar stream (plain or gzip-wrapped), optionally recursing into nested archives.
///
/// # Invariants
/// - Entry payloads are scanned with chunk+overlap semantics.
/// - Non-regular entries are skipped explicitly.
/// - Malformed headers or payload reads yield `PartialReason::MalformedTar`.
/// - Caller has already entered the archive budget for this container.
/// - `depth` is 1-based; nested expansion stops at `max_archive_depth`.
fn scan_tar_stream_nested<E: ScanEngine>(
    scan: &mut ArchiveScanCtx<'_, E>,
    input: &mut dyn TarRead,
    container_display: &[u8],
    depth: u8,
    ratio_active: bool,
) -> ArchiveEnd {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let dedupe = scan.dedupe;
    let overlap = scan.engine.required_overlap();
    let max_len = scan.archive.max_virtual_path_len_per_entry;
    let max_depth = scan.archive.max_archive_depth;

    let (cur_vpath, rest_vpaths) = scan
        .vpaths
        .split_first_mut()
        .expect("vpath scratch exhausted");
    let (cur_path_used, rest_path_used) = scan
        .path_budget_used
        .split_first_mut()
        .expect("path budget scratch exhausted");
    let (cur_cursor, rest_cursors) = scan
        .tar_cursors
        .split_first_mut()
        .expect("tar cursor scratch exhausted");

    cur_cursor.reset();
    *cur_path_used = 0;

    let mut buf = scan.pool.acquire();
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (entry_display, entry_size, entry_pad, entry_typeflag, nested_kind) = {
            let meta = match cur_cursor.next_entry(input, budgets, scan.archive) {
                Ok(TarNext::End) => break,
                Ok(TarNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(TarNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            };

            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, b't', meta.header_block_index);
            let entry_display = {
                let c = scan
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    scan.metrics.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    scan.metrics.archive.record_component_cap_exceeded();
                }
                if c.truncated {
                    scan.metrics.archive.record_path_truncated();
                }
                cur_vpath
                    .build_with_suffix(container_display, c.bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if cur_path_used.saturating_add(need) > scan.archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            *cur_path_used = cur_path_used.saturating_add(need);

            let nested_kind = detect_kind_from_name_bytes(meta.name);

            (
                entry_display,
                meta.size,
                meta.pad,
                meta.typeflag,
                nested_kind,
            )
        };

        let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
        if !is_regular {
            scan.metrics.archive.record_entry_skipped(
                EntrySkipReason::NonRegular,
                entry_display,
                false,
            );
            match cur_cursor.skip_payload_and_pad(input, budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                _ => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        budgets.begin_entry_scan();
        let mut stop_archive = false;

        if let Some(kind) = nested_kind {
            match kind {
                ArchiveKind::Zip => {
                    scan.metrics.archive.record_archive_skipped(
                        ArchiveSkipReason::NeedsRandomAccessNoSpill,
                        entry_display,
                        false,
                    );
                    match scan.archive.unsupported_policy {
                        crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                            // Fall back to scanning raw bytes.
                        }
                        crate::archive::UnsupportedPolicy::FailArchive => {
                            scan.metrics.archive.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                        crate::archive::UnsupportedPolicy::FailRun => {
                            scan.abort_run.store(true, Ordering::Relaxed);
                            scan.metrics.archive.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                    }
                }
                ArchiveKind::Gzip | ArchiveKind::Tar | ArchiveKind::TarGz => {
                    if depth >= max_depth {
                        scan.metrics.archive.record_archive_skipped(
                            ArchiveSkipReason::DepthExceeded,
                            entry_display,
                            false,
                        );
                    } else if let Err(hit) = budgets.enter_archive() {
                        let r = budget_hit_to_archive_end(hit);
                        match r {
                            ArchiveEnd::Skipped(reason) => scan
                                .metrics
                                .archive
                                .record_archive_skipped(reason, entry_display, false),
                            ArchiveEnd::Partial(reason) => scan
                                .metrics
                                .archive
                                .record_archive_partial(reason, entry_display, false),
                            _ => {}
                        }
                    } else {
                        scan.metrics.archive.record_archive_seen();
                        scan.metrics.archive.record_entry_scanned();

                        let nested_outcome = match kind {
                            ArchiveKind::Gzip => {
                                let (gunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (gunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    pool: scan.pool,
                                    event_sink: scan.event_sink,
                                    store_producer: scan.store_producer,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    persist_batch: scan.persist_batch,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: vpaths_tail,
                                    path_budget_used: path_used_tail,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    metrics: scan.metrics,
                                    archive: scan.archive,
                                    dedupe: scan.dedupe,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };

                                let (mut gz, name_len) = match GzipStream::new_with_header(
                                    LimitedRead::new(input, entry_size),
                                    child.gzip_header_buf,
                                    child.gzip_name_buf,
                                    max_len,
                                ) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                        budgets.exit_archive();
                                        budgets.end_entry(true);
                                        break;
                                    }
                                };
                                let entry_name_bytes = if let Some(len) = name_len {
                                    let c = child.canon.canonicalize(
                                        &child.gzip_name_buf[..len],
                                        DEFAULT_MAX_COMPONENTS,
                                        max_len,
                                    );
                                    if c.had_traversal {
                                        child.metrics.archive.record_path_had_traversal();
                                    }
                                    if c.component_cap_exceeded {
                                        child.metrics.archive.record_component_cap_exceeded();
                                    }
                                    if c.truncated {
                                        child.metrics.archive.record_path_truncated();
                                    }
                                    c.bytes
                                } else {
                                    b"<gunzip>"
                                };
                                let gunzip_display = gunzip_vpath
                                    .build(entry_display, entry_name_bytes, max_len)
                                    .bytes;
                                *gunzip_path_used = 0;
                                let need = gunzip_display.len();
                                if gunzip_path_used.saturating_add(need)
                                    > scan.archive.max_virtual_path_bytes_per_archive
                                {
                                    outcome =
                                        ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                                    budgets.exit_archive();
                                    budgets.end_entry(true);
                                    break;
                                }
                                *gunzip_path_used = gunzip_path_used.saturating_add(need);

                                let out =
                                    scan_gzip_stream_nested(&mut child, &mut gz, gunzip_display);
                                let (entry_reader, hdr_buf) = gz.into_inner().into_parts();
                                *child.gzip_header_buf = hdr_buf;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Tar => {
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    pool: scan.pool,
                                    event_sink: scan.event_sink,
                                    store_producer: scan.store_producer,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    persist_batch: scan.persist_batch,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    metrics: scan.metrics,
                                    archive: scan.archive,
                                    dedupe: scan.dedupe,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };
                                let mut entry_reader = LimitedRead::new(input, entry_size);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut entry_reader,
                                    entry_display,
                                    depth + 1,
                                    ratio_active,
                                );
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarGz => {
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    pool: scan.pool,
                                    event_sink: scan.event_sink,
                                    store_producer: scan.store_producer,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    persist_batch: scan.persist_batch,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    metrics: scan.metrics,
                                    archive: scan.archive,
                                    dedupe: scan.dedupe,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut gz = GzipStream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    entry_display,
                                    depth + 1,
                                    true,
                                );
                                let entry_reader = gz.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Zip => unreachable!(),
                        };

                        budgets.exit_archive();

                        let mut entry_partial_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };

                        match nested_outcome.0 {
                            ArchiveEnd::Scanned => scan.metrics.archive.record_archive_scanned(),
                            ArchiveEnd::Skipped(r) => {
                                scan.metrics
                                    .archive
                                    .record_archive_skipped(r, entry_display, false)
                            }
                            ArchiveEnd::Partial(r) => {
                                scan.metrics.archive.record_archive_partial(
                                    r,
                                    entry_display,
                                    false,
                                );
                            }
                        }

                        budgets.end_entry(true);

                        let stop_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };
                        if let Some(r) = stop_reason {
                            if matches!(r, PartialReason::RootOutputBudgetExceeded) {
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if !stop_archive && nested_outcome.1 > 0 {
                            if entry_partial_reason.is_none() {
                                entry_partial_reason = Some(PartialReason::MalformedTar);
                            }
                            if let Err(r) = discard_remaining_payload(
                                input,
                                budgets,
                                buf.as_mut_slice(),
                                nested_outcome.1,
                            ) {
                                if entry_partial_reason.is_none() {
                                    entry_partial_reason = Some(r);
                                }
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if let Some(r) = entry_partial_reason {
                            scan.metrics
                                .archive
                                .record_entry_partial(r, entry_display, false);
                        }

                        if !stop_archive {
                            match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
                                Ok(Ok(())) => {}
                                _ => {
                                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                    stop_archive = true;
                                }
                            }
                        }

                        if stop_archive {
                            break;
                        }

                        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
                        continue;
                    }
                }
            }
        }

        let entry_file_id = alloc_virtual_file_id(scan.next_virtual_file_id);
        let mut remaining = entry_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut stop_archive = false;

        while remaining > 0 {
            if carry > 0 && have > 0 {
                buf.as_mut_slice().copy_within(have - carry..have, 0);
            }

            let allow = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allow == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.as_mut_slice().len().saturating_sub(carry))
                .min(allow.min(remaining).min(u64::from(u32::MAX)) as usize);
            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut buf.as_mut_slice()[carry..carry + read_max];
            let n = match input.read(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    entry_partial_reason = Some(PartialReason::MalformedTar);
                    stop_archive = true;
                    break;
                }
            };
            budgets.charge_compressed_in(input.take_compressed_delta());
            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                stop_archive = true;
                break;
            }
            remaining = remaining.saturating_sub(n as u64);

            let (allowed, clamped) = apply_entry_budget_clamp(
                budgets,
                n,
                &mut entry_partial_reason,
                &mut outcome,
                &mut stop_archive,
            );
            if allowed == 0 {
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;
            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf.as_slice()[..read_len];

            scan.engine
                .scan_chunk_into(data, entry_file_id, base_offset, scan.scan_scratch);
            let engine_dropped = scan.scan_scratch.dropped_findings();
            let before_prefix = scan.scan_scratch.pending_findings_len();
            if !entry_scanned {
                scan.metrics.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scan.scan_scratch.drop_prefix_findings(new_bytes_start);
            let after_prefix = scan.scan_scratch.pending_findings_len();

            scan.pending.clear();
            scan.scan_scratch.drain_findings_into(scan.pending);

            let before_dedupe = scan.pending.len();
            if dedupe && before_dedupe > 1 {
                dedupe_findings(scan.pending);
            }
            let scheduler_pruned = before_prefix
                .saturating_sub(after_prefix)
                .saturating_add(before_dedupe.saturating_sub(scan.pending.len()));
            account_effective_dropped_findings(scan.metrics, engine_dropped, scheduler_pruned);

            scan.metrics.findings_emitted = scan
                .metrics
                .findings_emitted
                .wrapping_add(scan.pending.len() as u64);
            emit_persistence_batch(
                scan.store_producer,
                scan.event_sink,
                entry_display,
                scan.pending,
                scan.persist_batch,
                scan.metrics,
            );
            emit_findings(
                scan.engine.as_ref(),
                scan.event_sink,
                entry_display,
                scan.pending,
            );

            scan.metrics.chunks_scanned = scan.metrics.chunks_scanned.saturating_add(1);
            scan.metrics.bytes_scanned = scan.metrics.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            if clamped {
                break;
            }
        }

        if !stop_archive && remaining > 0 {
            if let Err(r) = discard_remaining_payload(input, budgets, buf.as_mut_slice(), remaining)
            {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
                stop_archive = true;
            }
        }

        budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            scan.metrics
                .archive
                .record_entry_partial(r, entry_display, false);
        }

        if stop_archive {
            break;
        }

        match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
            Ok(Ok(())) => {}
            Ok(Err(r)) => {
                outcome = ArchiveEnd::Partial(r);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                break;
            }
        }
        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    outcome
}

/// Shared entry point for `.tar` and `.tar.gz` root files.
///
/// Wires up the [`ArchiveScanCtx`] from [`LocalScratch`], resets budgets,
/// enters the archive scope, then delegates to [`scan_tar_stream_nested`]
/// at depth 1. This avoids duplicating budget setup between the two formats.
///
/// The caller (`process_tar_file` / `process_targz_file`) is responsible for
/// opening the file and wrapping it in the appropriate [`TarInput`] variant.
fn process_tar_like<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    mut input: TarInput,
) -> ArchiveEnd {
    let parent_bytes = task.path.as_os_str().as_encoded_bytes();

    let (scratch, metrics) = {
        let WorkerCtx {
            scratch, metrics, ..
        } = ctx;
        (scratch, metrics)
    };

    let mut scan = ArchiveScanCtx::new(scratch, metrics);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let ratio_active = matches!(input, TarInput::Gzip(_));
    let outcome = scan_tar_stream_nested(&mut scan, &mut input, parent_bytes, 1, ratio_active);

    scan.budgets.exit_archive();
    outcome
}

/// Process a plain `.tar` file.
fn process_tar_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };
    process_tar_like::<E>(task, ctx, TarInput::Plain(file))
}

/// Process a `.tar.gz` file via gzip+tar streaming.
fn process_targz_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };
    process_tar_like::<E>(task, ctx, TarInput::Gzip(GzipStream::new(file)))
}

/// Scan a ZIP file using file-backed random access.
///
/// # Design Notes
/// - Central directory parsing is bounded by metadata budgets.
/// - Only stored/deflated entries are scanned; others are skipped explicitly.
fn process_zip_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
) -> ArchiveEnd {
    let (scratch, metrics) = {
        let WorkerCtx {
            scratch, metrics, ..
        } = ctx;
        (scratch, metrics)
    };
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let dedupe = scratch.dedupe_within_chunk;
    let LocalScratch {
        engine,
        pool,
        event_sink,
        store_producer,
        scan_scratch,
        pending,
        persist_batch,
        archive,
        canon,
        vpaths,
        path_budget_used,
        budgets,
        zip_cursor,
        entry_display_buf,
        next_virtual_file_id,
        abort_run,
        ..
    } = scratch;
    let overlap = engine.required_overlap();

    let file = match File::open(&task.path) {
        Ok(f) => f,
        Err(_) => {
            metrics.io_errors = metrics.io_errors.saturating_add(1);
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    budgets.reset();
    if let Err(hit) = budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let cursor = zip_cursor;
    let open = match cursor.open(file, budgets, archive) {
        Ok(open) => open,
        Err(_) => {
            budgets.exit_archive();
            return ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
        }
    };

    match open {
        ZipOpen::Ready => {}
        ZipOpen::Skip(r) => {
            budgets.exit_archive();
            if r == ArchiveSkipReason::UnsupportedFeature {
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry
                    | crate::archive::UnsupportedPolicy::FailArchive => {
                        return ArchiveEnd::Skipped(r);
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        abort_run.store(true, Ordering::Relaxed);
                        return ArchiveEnd::Skipped(r);
                    }
                }
            }
            return ArchiveEnd::Skipped(r);
        }
        ZipOpen::Stop(r) => {
            budgets.exit_archive();
            return ArchiveEnd::Partial(r);
        }
    }

    let parent_bytes = task.path.as_os_str().as_encoded_bytes();
    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(path_budget_used.len() > 1);
    path_budget_used[1] = 0;

    let mut buf = pool.acquire();
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
            entry_display,
        ) = {
            let meta = match cursor.next_entry(budgets, archive) {
                Ok(ZipNext::End) => break,
                Ok(ZipNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(ZipNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    break;
                }
            };

            let (locator_kind, locator_value) = if meta.lfh_offset_valid {
                (b'z', meta.local_header_offset)
            } else {
                (b'c', meta.cdfh_offset)
            };
            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, locator_kind, locator_value);
            let entry_display = {
                let c = canon.canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    metrics.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    metrics.archive.record_component_cap_exceeded();
                }
                let entry_bytes = if meta.name_truncated {
                    metrics.archive.record_path_truncated();
                    entry_display_buf.clear();
                    entry_display_buf.extend_from_slice(c.bytes);
                    apply_hash_suffix_truncation(entry_display_buf, meta.name_hash64, max_len);
                    entry_display_buf.as_slice()
                } else {
                    if c.truncated {
                        metrics.archive.record_path_truncated();
                    }
                    c.bytes
                };
                vpaths[1]
                    .build_with_suffix(parent_bytes, entry_bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            path_budget_used[1] = path_budget_used[1].saturating_add(need);

            if meta.is_dir {
                metrics.archive.record_entry_skipped(
                    EntrySkipReason::NonRegular,
                    entry_display,
                    false,
                );
                continue;
            }

            if meta.is_encrypted() {
                metrics.archive.record_entry_skipped(
                    EntrySkipReason::EncryptedEntry,
                    entry_display,
                    false,
                );
                match archive.encrypted_policy {
                    crate::archive::EncryptedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::EncryptedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                    crate::archive::EncryptedPolicy::FailRun => {
                        abort_run.store(true, Ordering::Relaxed);
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                }
            }
            if !meta.compression_supported() {
                metrics.archive.record_entry_skipped(
                    EntrySkipReason::UnsupportedCompression,
                    entry_display,
                    false,
                );
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::UnsupportedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        abort_run.store(true, Ordering::Relaxed);
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                }
            }

            (
                meta.flags,
                meta.method,
                meta.compressed_size,
                meta.uncompressed_size,
                meta.local_header_offset,
                meta.cdfh_offset,
                meta.lfh_offset_valid,
                meta.is_dir,
                meta.name_truncated,
                meta.name_hash64,
                entry_display,
            )
        };

        let meta = ZipEntryMeta {
            name: b"",
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
        };

        budgets.begin_entry_scan();

        let mut reader = match cursor.open_entry_reader(&meta, budgets) {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                if r == PartialReason::MalformedZip {
                    metrics.archive.record_entry_skipped(
                        EntrySkipReason::CorruptEntry,
                        entry_display,
                        false,
                    );
                    budgets.end_entry(false);
                    continue;
                }
                outcome = ArchiveEnd::Partial(r);
                budgets.end_entry(false);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
                budgets.end_entry(false);
                break;
            }
        };

        let path_bytes = entry_display;
        let entry_file_id = alloc_virtual_file_id(next_virtual_file_id);

        let mut last_comp = 0u64;
        let ratio_active = meta.method == 8;

        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut stop_archive = false;

        loop {
            if carry > 0 && have > 0 {
                buf.as_mut_slice().copy_within(have - carry..have, 0);
            }

            let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

            let n = match reader.read_decompressed(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    entry_partial_reason = Some(PartialReason::MalformedZip);
                    break;
                }
            };

            let now = reader.total_compressed();
            let delta = now.saturating_sub(last_comp);
            last_comp = now;
            if delta > 0 {
                budgets.charge_compressed_in(delta);
            }

            if n == 0 {
                break;
            }

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                budgets.charge_decompressed_out(allowed)
            {
                let r = budget_hit_to_partial_reason(hit);
                allowed = a;
                entry_partial_reason = Some(r);
                if !matches!(hit, BudgetHit::SkipEntry(_)) {
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
            }
            if allowed == 0 {
                if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;

            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf.as_slice()[..read_len];

            engine.scan_chunk_into(data, entry_file_id, base_offset, scan_scratch);
            let engine_dropped = scan_scratch.dropped_findings();
            let before_prefix = scan_scratch.pending_findings_len();
            if !entry_scanned {
                metrics.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scan_scratch.drop_prefix_findings(new_bytes_start);
            let after_prefix = scan_scratch.pending_findings_len();

            pending.clear();
            scan_scratch.drain_findings_into(pending);

            let before_dedupe = pending.len();
            if dedupe && before_dedupe > 1 {
                dedupe_findings(pending);
            }
            let scheduler_pruned = before_prefix
                .saturating_sub(after_prefix)
                .saturating_add(before_dedupe.saturating_sub(pending.len()));
            account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

            metrics.findings_emitted = metrics.findings_emitted.wrapping_add(pending.len() as u64);
            emit_persistence_batch(
                store_producer.as_deref(),
                &**event_sink,
                path_bytes,
                pending,
                persist_batch,
                metrics,
            );
            emit_findings(engine.as_ref(), &**event_sink, path_bytes, pending);

            metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
            metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);

            have = read_len;
            carry = overlap.min(read_len);

            if allowed_usize < n {
                let extra = (n - allowed_usize) as u64;
                if let Err(r) = charge_discarded_bytes(budgets, extra) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }
        }

        budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            metrics.archive.record_entry_partial(r, path_bytes, false);
        }
        if stop_archive {
            break;
        }
    }

    budgets.exit_archive();
    outcome
}

// ============================================================================
// File Processing
// ============================================================================

/// Read a file with an extractable binary format, extract text, and scan it.
///
/// Reads the entire file (up to 64 MiB) into `extract_buf`, runs the
/// format-specific extractor, then scans the extracted text through the
/// engine as a single chunk.
///
/// # Prerequisites
///
/// - The file must already be open. This function rewinds to position 0
///   before reading (the caller's probe/header read may have advanced it).
///
/// # Failure modes
///
/// - I/O errors (seek, read) increment `ctx.metrics.io_errors` and return
///   without scanning.
/// - Extraction failure (`ParseError` or `Empty`) returns without scanning.
///   No error is recorded because the file was already classified as
///   extractable by extension; a parse failure simply means the content
///   didn't match (e.g. a `.class` file with corrupt magic).
#[cfg(feature = "binary-extract")]
fn extract_and_scan_file<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    file: &mut File,
    file_size: u64,
    path_bytes: &[u8],
    fmt: crate::content_policy::ExtractableFormat,
) {
    use crate::content_policy::extract::{extract_content, ExtractResult};

    // Seek back to start — the probe/header read may have advanced the position.
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
        #[cfg(debug_assertions)]
        eprintln!(
            "[local] Failed to rewind for extraction {:?}: {}",
            task.path, e
        );
        let _ = e;
        return;
    }

    // Read the entire file into a temporary buffer.
    let read_limit = file_size.min(64 * 1024 * 1024) as usize; // 64 MiB cap
    let scratch = &mut ctx.scratch;
    scratch.extract_buf.clear();
    scratch.extract_buf.reserve(read_limit);
    if file
        .take(read_limit as u64)
        .read_to_end(&mut scratch.extract_buf)
        .is_err()
    {
        ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
        return;
    }

    // Extract scannable text (extract_content clears out before dispatch).
    let result = extract_content(
        fmt,
        &scratch.extract_buf,
        &mut scratch.extract_out_buf,
        &mut scratch.extract_scratch,
    );

    if result != ExtractResult::Ok || scratch.extract_out_buf.is_empty() {
        return;
    }

    ctx.metrics.binary_extracted = ctx.metrics.binary_extracted.wrapping_add(1);

    // Scan the extracted text as a single chunk.
    let engine = &scratch.engine;
    engine.scan_chunk_into(
        &scratch.extract_out_buf,
        task.file_id,
        0,
        &mut scratch.scan_scratch,
    );
    let engine_dropped = scratch.scan_scratch.dropped_findings();
    let before_prefix = scratch.scan_scratch.pending_findings_len();

    scratch.pending.clear();
    scratch
        .scan_scratch
        .drain_findings_into(&mut scratch.pending);

    let before_dedupe = scratch.pending.len();
    if scratch.dedupe_within_chunk {
        dedupe_findings(&mut scratch.pending);
    }
    let scheduler_pruned = before_prefix
        .saturating_sub(before_dedupe)
        .saturating_add(before_dedupe.saturating_sub(scratch.pending.len()));
    account_effective_dropped_findings(&mut ctx.metrics, engine_dropped, scheduler_pruned);
    if !scratch.pending.is_empty() {
        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            &mut ctx.metrics,
        );
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );
        let count = scratch.pending.len() as u64;
        ctx.metrics.findings_emitted = ctx.metrics.findings_emitted.saturating_add(count);
    }
    ctx.metrics.bytes_scanned = ctx
        .metrics
        .bytes_scanned
        .saturating_add(scratch.extract_out_buf.len() as u64);
    ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);
}

/// Process a single file: open, classify, chunk-scan, close.
///
/// This is the per-task entry point called by each executor worker. The flow:
/// 1. Check abort flag.
/// 2. Detect archive format by extension, then by header magic.
/// 3. If archive: dispatch to `dispatch_archive_scan` and return.
/// 4. If binary-skip enabled: probe for NUL bytes / extractable format.
/// 5. Otherwise: sequential chunk+overlap scan via the buffer pool.
///
/// # Design: Sequential Read with Overlap Carry
///
/// Instead of seeking back for each chunk's overlap, we:
/// 1. Acquire ONE buffer for the entire file (blocking)
/// 2. Read sequentially, carrying overlap bytes forward via `copy_within`
/// 3. No seeks, no re-reading overlap from kernel, no per-chunk pool churn
///
/// # File Size Semantics
///
/// Uses file size from metadata after open (not discovery hint).
/// This gives point-in-time snapshot semantics:
/// - Truncated files: we stop at actual EOF
/// - Growing files: we stop at size-at-open (consistent snapshot)
///
/// # Chunk Processing Loop
///
/// ```text
/// ┌────────────────────────────────────────────────────────────────────┐
/// │                        process_file() flow                         │
/// └────────────────────────────────────────────────────────────────────┘
///
/// open(path) ─► metadata.len() ─► acquire_buffer()
///                    │
///                    ▼
///     ┌──────────────────────────────┐
///     │     for each chunk:          │◄──────────────────┐
///     │  1. copy_within(overlap)     │                   │
///     │  2. read(new_bytes)          │                   │
///     │  3. scan_chunk_into()        │                   │
///     │  4. drop_prefix_findings()   │                   │
///     │  5. emit_findings()          │                   │
///     └──────────────┬───────────────┘                   │
///                    │                                   │
///                    ▼                                   │
///            offset < file_size? ───yes──────────────────┘
///                    │
///                    no
///                    ▼
///             release_buffer()
/// ```
///
/// # Error Handling
///
/// I/O errors are logged (debug builds) but do not propagate — fail-soft
/// per file. The executor continues with remaining files.
fn process_file<E: ScanEngine>(task: FileTask, ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>) {
    if ctx.scratch.abort_run.load(Ordering::Relaxed) {
        return;
    }
    let scratch = &mut ctx.scratch;
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size;
    let skip_binary = scratch.skip_binary;
    let path_bytes = task.path.as_os_str().as_encoded_bytes();
    let ext_kind = if scratch.archive.enabled {
        detect_kind_from_path(&task.path)
    } else {
        None
    };

    if let Some(kind) = ext_kind {
        ctx.metrics.archive.record_archive_seen();
        let outcome = dispatch_archive_scan(&task, ctx, kind);
        match outcome {
            ArchiveEnd::Scanned => ctx.metrics.archive.record_archive_scanned(),
            ArchiveEnd::Skipped(r) => ctx
                .metrics
                .archive
                .record_archive_skipped(r, path_bytes, false),
            ArchiveEnd::Partial(r) => ctx
                .metrics
                .archive
                .record_archive_partial(r, path_bytes, false),
        }
        return;
    }

    // Open file
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    let open_start = std::time::Instant::now();

    let mut file = match File::open(&task.path) {
        Ok(f) => f,
        Err(e) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to open file {:?}: {}", task.path, e);
            let _ = e;

            return;
        }
    };

    // Use actual file size after open (snapshot semantics)
    // Discovery size is just a hint; file may have changed
    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to get metadata {:?}: {}", task.path, e);
            let _ = e;

            return;
        }
    };

    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        ctx.metrics.open_stat_ns = ctx
            .metrics
            .open_stat_ns
            .saturating_add(open_start.elapsed().as_nanos() as u64);
    }

    // Empty file: nothing to scan
    if file_size == 0 {
        return;
    }

    // Enforce size cap at open time for snapshot semantics.
    if file_size > scratch.max_file_size {
        return;
    }

    if scratch.archive.enabled {
        let mut header = [0u8; TAR_BLOCK_LEN];
        let n = match file.read(&mut header) {
            Ok(n) => n,
            Err(e) => {
                ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
                #[cfg(debug_assertions)]
                eprintln!("[local] Failed to read header {:?}: {}", task.path, e);
                let _ = e;
                return;
            }
        };
        if n > 0 {
            if let Some(kind) = sniff_kind_from_header(&header[..n]) {
                ctx.metrics.archive.record_archive_seen();
                let outcome = dispatch_archive_scan(&task, ctx, kind);
                match outcome {
                    ArchiveEnd::Scanned => ctx.metrics.archive.record_archive_scanned(),
                    ArchiveEnd::Skipped(r) => ctx
                        .metrics
                        .archive
                        .record_archive_skipped(r, path_bytes, false),
                    ArchiveEnd::Partial(r) => ctx
                        .metrics
                        .archive
                        .record_archive_partial(r, path_bytes, false),
                }
                return;
            }

            // Reuse the already-read header bytes for binary classification.
            if skip_binary {
                let verdict = crate::content_policy::classify_content(
                    &header[..n],
                    path_bytes,
                    crate::content_policy::CHECK_LEN,
                );
                match verdict {
                    crate::content_policy::ContentVerdict::Binary => {
                        ctx.metrics.binary_skipped = ctx.metrics.binary_skipped.wrapping_add(1);
                        return;
                    }
                    crate::content_policy::ContentVerdict::BinaryExtractable(_fmt) => {
                        #[cfg(feature = "binary-extract")]
                        {
                            extract_and_scan_file(
                                &task, ctx, &mut file, file_size, path_bytes, _fmt,
                            );
                        }
                        #[cfg(not(feature = "binary-extract"))]
                        {
                            ctx.metrics.binary_skipped = ctx.metrics.binary_skipped.wrapping_add(1);
                        }
                        return;
                    }
                    crate::content_policy::ContentVerdict::Text => {}
                }
            }
        }
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to rewind {:?}: {}", task.path, e);
            let _ = e;
            return;
        }
    } else if skip_binary {
        // No archive sniffing — read a small probe for binary detection.
        let probe_buf = &mut scratch.binary_probe_buf;
        let n = match file.read(probe_buf.as_mut_slice()) {
            Ok(n) => n,
            Err(e) => {
                ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
                #[cfg(debug_assertions)]
                eprintln!("[local] Failed to read probe {:?}: {}", task.path, e);
                let _ = e;
                return;
            }
        };
        if n > 0 {
            let verdict = crate::content_policy::classify_content(
                &probe_buf[..n],
                path_bytes,
                crate::content_policy::CHECK_LEN,
            );
            match verdict {
                crate::content_policy::ContentVerdict::Binary => {
                    ctx.metrics.binary_skipped = ctx.metrics.binary_skipped.wrapping_add(1);
                    return;
                }
                crate::content_policy::ContentVerdict::BinaryExtractable(_fmt) => {
                    #[cfg(feature = "binary-extract")]
                    {
                        ctx.metrics.binary_extracted = ctx.metrics.binary_extracted.wrapping_add(1);
                        extract_and_scan_file(&task, ctx, &mut file, file_size, path_bytes, _fmt);
                    }
                    #[cfg(not(feature = "binary-extract"))]
                    {
                        ctx.metrics.binary_skipped = ctx.metrics.binary_skipped.wrapping_add(1);
                    }
                    return;
                }
                crate::content_policy::ContentVerdict::Text => {}
            }
        }
        if let Err(e) = file.seek(SeekFrom::Start(0)) {
            ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
            #[cfg(debug_assertions)]
            eprintln!("[local] Failed to rewind {:?}: {}", task.path, e);
            let _ = e;
            return;
        }
    }

    // Acquire ONE buffer for the entire file (blocking, never skip)
    // This is correct because:
    // 1. CountBudget limits in-flight files, so pool sizing should accommodate
    // 2. Blocking is the right primitive for work-conserving semantics
    let mut buf = scratch.pool.acquire();

    // State for overlap carry pattern
    let mut offset: u64 = 0; // Logical offset of next "new" bytes
    let mut carry: usize = 0; // Bytes of overlap prefix for next scan
    let mut have: usize = 0; // Total bytes in buffer from last iteration

    loop {
        // Move tail overlap bytes to front as next prefix
        // This is a tiny copy (overlap bytes, typically 16-256)
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        // Read next payload bytes after the prefix.
        // Cap by remaining snapshot size to maintain point-in-time semantics:
        // if the file grows after open, we only scan up to the original size.
        let read_start = carry;
        let remaining_in_snapshot = file_size.saturating_sub(offset) as usize;
        if remaining_in_snapshot == 0 {
            // Reached snapshot boundary - done with this file
            break;
        }
        let read_max = chunk_size.min(buf.len() - carry).min(remaining_in_snapshot);
        let dst = &mut buf.as_mut_slice()[read_start..read_start + read_max];

        #[cfg(all(feature = "perf-stats", debug_assertions))]
        let read_start_t = std::time::Instant::now();

        let n = match read_some(&mut file, dst) {
            Ok(n) => n,
            Err(e) => {
                ctx.metrics.io_errors = ctx.metrics.io_errors.saturating_add(1);
                #[cfg(debug_assertions)]
                eprintln!("[local] Read failed for {:?}: {}", task.path, e);
                let _ = e;

                break;
            }
        };

        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            ctx.metrics.read_ns = ctx
                .metrics
                .read_ns
                .saturating_add(read_start_t.elapsed().as_nanos() as u64);
        }

        // EOF: done with this file
        if n == 0 {
            break;
        }

        let read_len = carry + n; // Total bytes available for scanning
        let _prefix_len = carry; // (for debugging/tracing)

        // base_offset: absolute file offset of buf[0]
        // For first chunk: base_offset = 0, prefix_len = 0
        // For subsequent: base_offset = offset - carry
        let base_offset = offset.saturating_sub(carry as u64);

        // Scan the chunk
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        let scan_start_t = std::time::Instant::now();

        let data = &buf.as_slice()[..read_len];
        engine.scan_chunk_into(data, task.file_id, base_offset, &mut scratch.scan_scratch);
        let engine_dropped = scratch.scan_scratch.dropped_findings();
        let before_prefix = scratch.scan_scratch.pending_findings_len();

        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            ctx.metrics.scan_ns = ctx
                .metrics
                .scan_ns
                .saturating_add(scan_start_t.elapsed().as_nanos() as u64);
        }

        // Drop findings whose root_hint_end is in the prefix region.
        // These will be (or were) found by the chunk that "owns" those bytes.
        // new_bytes_start == offset (the first truly new byte in this scan)
        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);
        let after_prefix = scratch.scan_scratch.pending_findings_len();

        // Extract findings
        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        // Optional within-chunk dedupe (only needed if engine can emit duplicates)
        let before_dedupe = scratch.pending.len();
        if scratch.dedupe_within_chunk && before_dedupe > 1 {
            dedupe_findings(&mut scratch.pending);
        }
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(before_dedupe.saturating_sub(scratch.pending.len()));
        account_effective_dropped_findings(&mut ctx.metrics, engine_dropped, scheduler_pruned);

        // Count findings before emitting (pending.len() is the count for this chunk)
        ctx.metrics.findings_emitted = ctx
            .metrics
            .findings_emitted
            .wrapping_add(scratch.pending.len() as u64);

        emit_persistence_batch(
            scratch.store_producer.as_deref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
            &mut scratch.persist_batch,
            &mut ctx.metrics,
        );
        // Emit findings
        emit_findings(
            engine.as_ref(),
            &*scratch.event_sink,
            path_bytes,
            &scratch.pending,
        );

        // Update metrics with ACTUAL bytes scanned (not planned)
        let actual_payload = n; // New bytes read this iteration
        ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);
        ctx.metrics.bytes_scanned = ctx
            .metrics
            .bytes_scanned
            .saturating_add(actual_payload as u64);

        // Advance offset by actual payload read
        offset = offset.saturating_add(actual_payload as u64);
        have = read_len;
        carry = overlap.min(read_len);

        // Stop at snapshot size (consistent point-in-time semantics)
        if offset >= file_size {
            break;
        }
    }

    // Buffer returned to pool on drop
    // Permit released when FileTask drops
}

/// Read some bytes, handling EINTR.
///
/// Returns number of bytes read (0 at EOF).
///
/// # Why not `read_exact`?
///
/// We want partial reads at EOF (to handle final chunk), while `read_exact`
/// returns `UnexpectedEof` on short reads. This wrapper gives us EINTR-safe
/// partial-read semantics.
///
/// # Signal Handling
///
/// `EINTR` (interrupted system call) can occur when a signal is delivered
/// during the read. This wrapper retries automatically, which is the standard
/// Unix idiom for non-interruptible reads.
fn read_some(file: &mut File, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan local files with blocking reads.
///
/// This is the low-level entry point for local filesystem scanning. For most
/// use cases, prefer [`parallel_scan_dir`](super::parallel_scan::parallel_scan_dir)
/// which handles directory walking and gitignore.
///
/// # Arguments
///
/// - `engine`: Detection engine (determines overlap, provides scan logic)
/// - `source`: Iterator of files to scan (e.g., [`VecFileSource`])
/// - `cfg`: Configuration for workers, chunking, and memory budgets (includes `event_sink`)
///
/// # Returns
///
/// [`LocalReport`] containing:
/// - `stats`: Discovery statistics (files enqueued, bytes, I/O errors)
/// - `metrics`: Executor metrics (chunks scanned, bytes scanned, timing)
///
/// # Execution Model
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │                           scan_local()                              │
/// └─────────────────────────────────────────────────────────────────────┘
///                    │
///         ┌─────────┴─────────┐
///         ▼                   ▼
///   ┌───────────────┐   ┌───────────────────────────────────────────┐
///   │  main thread  │   │              Executor                     │
///   │  (discovery)  │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐     │
///   │               │──►│  │Worker 0 │ │Worker 1 │ │Worker N │     │
///   │  next_file()  │   │  └─────────┘ └─────────┘ └─────────┘     │
///   │  in loop      │   │       │           │           │          │
///   └───────────────┘   │       ▼           ▼           ▼          │
///                       │  process_file() process_file() ...       │
///                       └───────────────────────────────────────────┘
/// ```
///
/// The main thread pulls files from `source` and enqueues them. Workers
/// process files in parallel using work-stealing. The `CountBudget` limits
/// how far ahead discovery can run.
///
/// # Example
///
/// ```ignore
/// // With MockEngine (for testing):
/// let engine = Arc::new(MockEngine::new(rules, 16));
/// let files = vec![LocalFile { path: "test.txt".into(), size: 1024 }];
/// let source = VecFileSource::new(files);
///
/// let report = scan_local(engine, source, LocalConfig::default());
///
/// // With real Engine (for production):
/// let engine = Arc::new(Engine::new(rules, transforms, tuning));
/// let report = scan_local(engine, source, LocalConfig::default());
/// ```
pub fn scan_local<E, S>(engine: Arc<E>, mut source: S, cfg: LocalConfig) -> LocalReport
where
    E: ScanEngine,
    S: FileSource,
{
    cfg.validate(engine.as_ref());

    let overlap = engine.required_overlap();
    let buf_len = cfg.chunk_size.saturating_add(overlap);

    // Create buffer pool (workers acquire and release via local queues)
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: cfg.pool_buffers,
        workers: cfg.workers,
        local_queue_cap: cfg.local_queue_cap,
    });

    // Object budget for discovery backpressure
    let budget = CountBudget::new(cfg.max_in_flight_objects);

    let archive_cfg = cfg.archive.clone();
    let abort_run = Arc::new(AtomicBool::new(false));

    // Capture config values before moving into closure
    let dedupe = cfg.dedupe_within_chunk;
    let chunk_size = cfg.chunk_size;
    let event_sink = cfg.event_sink.clone();
    let store_producer = cfg.store_producer.clone();

    // Keep a handle for post-join diagnostics (the original is moved into
    // the executor's init closure).
    let run_event_sink = Arc::clone(&event_sink);

    // Create executor
    let ex = Executor::<FileTask>::new(
        ExecutorConfig {
            workers: cfg.workers,
            seed: cfg.seed,
            ..ExecutorConfig::default()
        },
        {
            let engine = Arc::clone(&engine);
            let pool = pool.clone();
            let abort_run = Arc::clone(&abort_run);
            let store_producer = store_producer.clone();
            move |_wid| {
                let findings_cap = engine.max_findings_per_chunk();
                let scan_scratch = engine.new_scratch();
                let depth_cap = archive_cfg.max_archive_depth as usize + 2;
                let mut vpaths = Vec::with_capacity(depth_cap);
                for _ in 0..depth_cap {
                    vpaths.push(VirtualPathBuilder::with_capacity(
                        archive_cfg.max_virtual_path_len_per_entry,
                    ));
                }
                let path_budget_used = vec![0usize; depth_cap];
                let mut tar_cursors = Vec::with_capacity(depth_cap);
                for _ in 0..depth_cap {
                    tar_cursors.push(TarCursor::with_capacity(&archive_cfg));
                }
                let entry_display_cap = archive_cfg.max_virtual_path_len_per_entry;
                let gzip_name_cap = archive_cfg.max_virtual_path_len_per_entry;
                let gzip_header_cap = archive_cfg
                    .max_virtual_path_len_per_entry
                    .saturating_add(256)
                    .min(archive_cfg.max_archive_metadata_bytes as usize)
                    .clamp(64, 64 * 1024);

                LocalScratch {
                    engine: Arc::clone(&engine),
                    pool: pool.clone(),
                    scan_scratch,
                    pending: Vec::with_capacity(findings_cap),
                    persist_batch: Vec::with_capacity(findings_cap),
                    canon: EntryPathCanonicalizer::with_capacity(
                        DEFAULT_MAX_COMPONENTS,
                        archive_cfg.max_virtual_path_len_per_entry,
                    ),
                    vpaths,
                    path_budget_used,
                    budgets: ArchiveBudgets::new(&archive_cfg),
                    tar_cursors,
                    zip_cursor: ZipCursor::with_capacity(&archive_cfg),
                    entry_display_buf: Vec::with_capacity(entry_display_cap),
                    gzip_header_buf: vec![0u8; gzip_header_cap],
                    gzip_name_buf: Vec::with_capacity(gzip_name_cap),
                    next_virtual_file_id: 0x8000_0000,
                    abort_run: Arc::clone(&abort_run),
                    event_sink: Arc::clone(&event_sink),
                    store_producer: store_producer.clone(),
                    dedupe_within_chunk: dedupe,
                    chunk_size,
                    max_file_size: cfg.max_file_size,
                    archive: archive_cfg.clone(),
                    skip_binary: cfg.skip_binary,
                    binary_probe_buf: [0u8; crate::content_policy::CHECK_LEN],
                    #[cfg(feature = "binary-extract")]
                    extract_buf: Vec::with_capacity(
                        crate::content_policy::extract::EXTRACT_INPUT_CAP,
                    ),
                    #[cfg(feature = "binary-extract")]
                    extract_out_buf: Vec::with_capacity(
                        crate::content_policy::extract::EXTRACT_OUTPUT_CAP,
                    ),
                    #[cfg(feature = "binary-extract")]
                    extract_scratch: Vec::with_capacity(
                        crate::content_policy::extract::JAR_ENTRY_CAP,
                    ),
                }
            }
        },
        process_file::<E>,
    );

    // Discovery loop
    let mut stats = LocalStats::default();
    let mut next_file_id: u32 = 0;
    // Batch discovery injections to amortize wakeups and injector contention.
    // Keep the batch small to avoid large bursts of in-flight work.
    let batch_cap = cfg.max_in_flight_objects.clamp(1, 64);
    let mut batch: Vec<FileTask> = Vec::with_capacity(batch_cap);

    let mut aborted = false;
    while let Some(file) = source.next_file() {
        if abort_run.load(Ordering::Relaxed) {
            aborted = true;
            break;
        }
        // Acquire in-flight permit (blocks if at capacity)
        let permit = budget.acquire(1);
        if abort_run.load(Ordering::Relaxed) {
            aborted = true;
            drop(permit);
            break;
        }

        let file_id = FileId(next_file_id);
        next_file_id = next_file_id.wrapping_add(1);

        stats.files_enqueued = stats.files_enqueued.saturating_add(1);
        stats.bytes_enqueued = stats.bytes_enqueued.saturating_add(file.size);

        // Enqueue task
        let task = FileTask {
            file_id,
            path: file.path,
            size: file.size,
            _permit: permit,
        };

        batch.push(task);
        if batch.len() >= batch_cap {
            // This should not fail since we haven't called join() yet.
            ex.spawn_external_batch(std::mem::take(&mut batch))
                .expect("executor rejected task batch before join");
        }
    }

    if !aborted && !batch.is_empty() {
        ex.spawn_external_batch(batch)
            .expect("executor rejected task batch before join");
    } else if aborted {
        batch.clear();
    }

    // Wait for all files to complete
    let metrics = ex.join();

    // Aggregate I/O errors from worker metrics into stats
    stats.io_errors = metrics.io_errors;
    stats.dropped_findings = metrics.findings_dropped;
    stats.persistence_emit_failures = metrics.persistence_emit_failures;
    stats.persistence_incomplete =
        stats.dropped_findings > 0 || stats.persistence_emit_failures > 0;

    if let Some(producer) = store_producer.as_deref() {
        let run_loss = FsRunLoss {
            dropped_findings: stats.dropped_findings,
            persistence_emit_failures: stats.persistence_emit_failures,
        };
        if let Err(err) = producer.record_fs_run_loss(run_loss) {
            stats.persistence_emit_failures = stats.persistence_emit_failures.saturating_add(1);
            stats.persistence_incomplete = true;
            let mut msg = StackMsg::<256>::new();
            let _ = std::fmt::Write::write_fmt(
                &mut msg,
                format_args!("fs persistence run-loss recording failed: {}", err.detail()),
            );
            run_event_sink.emit(crate::unified::events::ScanEvent::Diagnostic(
                crate::unified::events::DiagnosticEvent {
                    level: "error",
                    message: msg.as_str(),
                },
            ));
        }
    }

    LocalReport { stats, metrics }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{FileId, RuleSpec, TransformConfig, Tuning, ValidatorKind};
    use crate::archive::PartialReason;
    use crate::scheduler::engine_stub::{FindingRec, MockEngine, MockRule, RuleId};
    use crate::scheduler::engine_trait::{EngineScratch, FindingWithHash, ScanEngine};
    use crate::store::{EmitOnlyStoreProducer, FailingStoreProducer, InMemoryStoreProducer};
    use crate::unified::events::VecEventSink;
    use crate::Engine;
    use regex::bytes::Regex;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    fn test_engine() -> MockEngine {
        MockEngine::new(
            vec![
                MockRule {
                    name: "secret".into(),
                    pattern: b"SECRET".to_vec(),
                },
                MockRule {
                    name: "password".into(),
                    pattern: b"PASSWORD".to_vec(),
                },
            ],
            16, // 16 byte overlap
        )
    }

    fn small_config_with_sink(sink: Arc<VecEventSink>) -> LocalConfig {
        LocalConfig {
            workers: 2,
            chunk_size: 64, // Tiny for testing
            pool_buffers: 8,
            local_queue_cap: 2,
            max_in_flight_objects: 8,
            max_file_size: u64::MAX,
            seed: 12345,
            dedupe_within_chunk: true,
            archive: ArchiveConfig::default(),
            skip_binary: true,
            event_sink: sink,
            store_producer: None,
        }
    }

    fn small_config() -> LocalConfig {
        small_config_with_sink(Arc::new(VecEventSink::new()))
    }

    fn real_test_tuning(max_findings_per_chunk: usize) -> Tuning {
        Tuning {
            merge_gap: 64,
            max_windows_per_rule_variant: 64,
            pressure_gap_start: 128,
            max_anchor_hits_per_rule_variant: 256,
            max_utf16_decoded_bytes_per_window: 4096,
            max_transform_depth: 2,
            max_total_decode_output_bytes: 1024 * 1024,
            max_work_items: 64,
            max_findings_per_chunk,
            scan_utf16_variants: true,
        }
    }

    fn real_simple_rule() -> RuleSpec {
        RuleSpec {
            name: "secret",
            anchors: &[b"SECRET"],
            radius: 32,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            local_context: None,
            secret_group: None,
            re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
        }
    }

    struct DuplicateDropEngine;

    struct DuplicateDropScratch {
        findings: Vec<FindingWithHash<FindingRec>>,
        dropped_findings: u64,
    }

    impl EngineScratch for DuplicateDropScratch {
        type Finding = FindingWithHash<FindingRec>;

        fn clear(&mut self) {
            self.findings.clear();
            self.dropped_findings = 0;
        }

        fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
            self.findings
                .retain(|f| f.finding.root_hint_end >= new_bytes_start);
        }

        fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
            out.append(&mut self.findings);
        }

        fn pending_findings_len(&self) -> usize {
            self.findings.len()
        }

        fn dropped_findings(&self) -> u64 {
            self.dropped_findings
        }
    }

    impl ScanEngine for DuplicateDropEngine {
        type Scratch = DuplicateDropScratch;

        fn required_overlap(&self) -> usize {
            0
        }

        fn new_scratch(&self) -> Self::Scratch {
            DuplicateDropScratch {
                findings: Vec::with_capacity(4),
                dropped_findings: 0,
            }
        }

        fn scan_chunk_into(
            &self,
            _data: &[u8],
            _file_id: FileId,
            _base_offset: u64,
            scratch: &mut Self::Scratch,
        ) {
            scratch.clear();
            let finding = FindingWithHash::new(
                FindingRec {
                    rule_id: RuleId(0),
                    root_hint_start: 0,
                    root_hint_end: 6,
                    span_start: 0,
                    span_end: 6,
                },
                [0xAB; 32],
            );
            // Scheduler dedupe will collapse these to one.
            // Scheduler dedupe will collapse these to one.  The engine
            // emitted both copies so `dropped_findings` stays 0 — the
            // "drop" is purely scheduler-side dedup, not an engine cap.
            scratch.findings.push(finding);
            scratch.findings.push(finding);
        }

        fn rule_name(&self, _rule_id: u32) -> &str {
            "duplicate-drop"
        }

        fn max_findings_per_chunk(&self) -> usize {
            4
        }
    }

    fn assert_perf_u64(actual: u64, expected: u64) {
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(actual, expected);
        } else {
            assert_eq!(actual, 0);
        }
    }

    #[test]
    fn zip_budget_clamp_charges_discarded_bytes() {
        let cfg = ArchiveConfig {
            max_uncompressed_bytes_per_entry: 4,
            max_total_uncompressed_bytes_per_archive: 5,
            max_total_uncompressed_bytes_per_root: 5,
            ..ArchiveConfig::default()
        };

        let mut budgets = ArchiveBudgets::new(&cfg);
        assert!(budgets.enter_archive().is_ok());
        budgets.begin_entry_scan();

        let mut entry_partial_reason = None;
        let mut outcome = ArchiveEnd::Scanned;
        let mut stop_archive = false;

        let (allowed, clamped) = apply_entry_budget_clamp(
            &mut budgets,
            6,
            &mut entry_partial_reason,
            &mut outcome,
            &mut stop_archive,
        );

        assert_eq!(allowed, 4);
        assert!(clamped);
        assert!(stop_archive);
        assert_eq!(budgets.root_decompressed_out(), 5);
        assert_eq!(
            outcome,
            ArchiveEnd::Partial(PartialReason::ArchiveOutputBudgetExceeded)
        );
    }

    #[test]
    fn scans_single_file_with_findings() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        // Create temp file with secret
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "hello SECRET world").unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);

        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert_eq!(report.stats.files_enqueued, 1);
        assert!(report.metrics.chunks_scanned >= 1);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("secret"), "output: {}", output_str);
    }

    #[test]
    fn handles_empty_file() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let source = VecFileSource::new(vec![LocalFile { path, size: 0 }]);

        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert_eq!(report.stats.files_enqueued, 1);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn enforces_max_file_size_at_open_time() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "SECRETABCD1234").unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let source = VecFileSource::new(vec![LocalFile { path, size: 4 }]);

        let mut cfg = small_config_with_sink(sink.clone());
        cfg.max_file_size = 4; // Smaller than actual file size at open time.

        let report = scan_local(engine, source, cfg);

        assert_eq!(report.stats.files_enqueued, 1);
        assert_eq!(report.metrics.bytes_scanned, 0);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn handles_no_files() {
        let engine = Arc::new(test_engine());

        let source = VecFileSource::new(vec![]);

        let report = scan_local(engine, source, small_config());

        assert_eq!(report.stats.files_enqueued, 0);
        assert_eq!(report.metrics.chunks_scanned, 0);
    }

    #[test]
    fn finds_boundary_spanning_secret() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        // Create file where SECRET spans chunk boundary
        // With chunk_size=64 and overlap=16, secret at position ~60 will span
        let mut tmp = NamedTempFile::new().unwrap();
        let padding = vec![b'x'; 60];
        tmp.write_all(&padding).unwrap();
        tmp.write_all(b"SECRET").unwrap();
        tmp.write_all(&[b'y'; 100]).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);

        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert!(report.metrics.chunks_scanned >= 2);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);

        // Should find exactly one SECRET (not duplicated due to overlap)
        let count = output_str.matches("secret").count();
        assert_eq!(
            count, 1,
            "expected 1 finding, got {}: {}",
            count, output_str
        );
    }

    #[test]
    fn processes_multiple_files() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let mut files = Vec::new();
        let mut temps = Vec::new();

        for i in 0..5 {
            let mut tmp = NamedTempFile::new().unwrap();
            writeln!(tmp, "file {} contains SECRET", i).unwrap();
            tmp.flush().unwrap();

            let path = tmp.path().to_path_buf();
            let size = tmp.as_file().metadata().unwrap().len();
            files.push(LocalFile { path, size });
            temps.push(tmp); // Keep alive
        }

        let source = VecFileSource::new(files);

        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert_eq!(report.stats.files_enqueued, 5);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        let count = output_str.matches("secret").count();
        assert_eq!(
            count, 5,
            "expected 5 findings, got {}: {}",
            count, output_str
        );
    }

    #[test]
    fn config_validation() {
        let engine = test_engine();

        // Valid config
        let cfg = LocalConfig::default();
        cfg.validate(&engine);
    }

    #[test]
    #[should_panic(expected = "exceeds BUFFER_LEN_MAX")]
    fn config_validation_rejects_oversized_chunk() {
        let engine = test_engine();

        // Invalid: chunk_size + overlap > BUFFER_LEN_MAX
        let bad_cfg = LocalConfig {
            chunk_size: BUFFER_LEN_MAX, // Will exceed with overlap
            ..Default::default()
        };
        bad_cfg.validate(&engine); // Should panic
    }

    #[test]
    fn metrics_track_bytes() {
        let engine = Arc::new(test_engine());

        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![b'a'; 1000];
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);

        let report = scan_local(engine, source, small_config());

        // bytes_scanned should be ~1000 (the actual payload scanned)
        assert!(report.metrics.bytes_scanned >= 1000);
    }

    #[test]
    fn archive_detection_skips_when_enabled() {
        let engine = Arc::new(test_engine());

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sample.zip");
        fs::write(&path, b"SECRET").unwrap();
        let size = fs::metadata(&path).unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config();
        cfg.archive.enabled = true;

        let report = scan_local(engine, source, cfg);

        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(report.metrics.archive.archives_seen, 1);
            assert_eq!(report.metrics.archive.archives_partial, 1);
            assert_eq!(
                report.metrics.archive.partial_reasons[PartialReason::MalformedZip.as_usize()],
                1
            );
        } else {
            assert_eq!(report.metrics.archive.archives_seen, 0);
            assert_eq!(report.metrics.archive.archives_partial, 0);
            assert_eq!(
                report.metrics.archive.partial_reasons[PartialReason::MalformedZip.as_usize()],
                0
            );
        }
    }

    #[test]
    fn archive_extension_scans_when_disabled() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sample.zip");
        fs::write(&path, b"hello SECRET world").unwrap();
        let size = fs::metadata(&path).unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink.clone());
        cfg.archive.enabled = false;

        let report = scan_local(engine, source, cfg);

        assert_perf_u64(report.metrics.archive.archives_seen, 0);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("secret"),
            "expected finding for archive extension when disabled; output: {output_str}"
        );
    }

    // ---------------------------------------------------------------
    // dedupe_findings unit tests
    // ---------------------------------------------------------------

    fn finding(rule: u16, start: u64, end: u64) -> FindingRec {
        FindingRec {
            rule_id: RuleId(rule),
            root_hint_start: start,
            root_hint_end: end,
            span_start: start,
            span_end: end,
        }
    }

    /// Wrap a `FindingRec` with a default norm_hash for dedupe tests.
    fn hashed(f: FindingRec) -> FindingWithHash<FindingRec> {
        FindingWithHash::new(f, [0; 32])
    }

    #[test]
    fn dedupe_empty_vec() {
        let mut v: Vec<FindingWithHash<FindingRec>> = Vec::new();
        dedupe_findings(&mut v);
        assert!(v.is_empty());
    }

    #[test]
    fn dedupe_single_element() {
        let mut v = vec![hashed(finding(0, 10, 16))];
        dedupe_findings(&mut v);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].finding.root_hint_start, 10);
    }

    #[test]
    fn dedupe_removes_exact_duplicates() {
        let mut v = vec![
            hashed(finding(0, 10, 16)),
            hashed(finding(0, 10, 16)), // dup
            hashed(finding(1, 20, 28)),
            hashed(finding(1, 20, 28)), // dup
            hashed(finding(2, 50, 56)),
        ];
        dedupe_findings(&mut v);
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn dedupe_preserves_different_rules_same_offsets() {
        let mut v = vec![
            hashed(finding(0, 10, 16)),
            hashed(finding(1, 10, 16)),
            hashed(finding(2, 10, 16)),
        ];
        dedupe_findings(&mut v);
        assert_eq!(v.len(), 3, "distinct rule_ids should all be kept");
    }

    #[test]
    fn dedupe_preserves_same_rule_different_offsets() {
        let mut v = vec![
            hashed(finding(0, 10, 16)),
            hashed(finding(0, 20, 26)),
            hashed(finding(0, 30, 36)),
        ];
        dedupe_findings(&mut v);
        assert_eq!(v.len(), 3, "distinct offsets should all be kept");
    }

    #[test]
    fn dedupe_works_for_finding_with_hash_carrier() {
        let mut v = vec![
            FindingWithHash::new(finding(0, 10, 16), [1; 32]),
            FindingWithHash::new(finding(0, 10, 16), [1; 32]), // dup
            FindingWithHash::new(finding(1, 20, 26), [2; 32]),
        ];
        dedupe_findings(&mut v);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].finding.rule_id, RuleId(0));
        assert_eq!(v[1].finding.rule_id, RuleId(1));
    }

    #[test]
    fn persistence_batches_emitted_for_regular_fs_loop() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(InMemoryStoreProducer::default());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET one SECRET two").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink);
        cfg.store_producer = Some(producer.clone());

        let report = scan_local(engine, source, cfg);
        let batches = producer.batches();
        let persisted: usize = batches.iter().map(|b| b.findings.len()).sum();

        assert!(!batches.is_empty(), "expected persisted fs finding batches");
        assert_eq!(persisted as u64, report.metrics.findings_emitted);
    }

    #[test]
    fn dropped_findings_roll_up_into_persistence_run_loss() {
        let engine = Arc::new(Engine::new(
            vec![real_simple_rule()],
            Vec::<TransformConfig>::new(),
            real_test_tuning(1), // force max-findings drops
        ));
        let producer = Arc::new(InMemoryStoreProducer::default());
        let sink = Arc::new(VecEventSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET12345678 and SECRETABCDEFGH").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink);
        cfg.chunk_size = 1024;
        cfg.store_producer = Some(producer.clone());
        let report = scan_local(engine, source, cfg);

        assert!(report.stats.dropped_findings > 0);
        assert!(report.stats.persistence_incomplete);

        let losses = producer.losses();
        assert_eq!(losses.len(), 1);
        assert_eq!(losses[0].dropped_findings, report.stats.dropped_findings);
        assert_eq!(
            losses[0].persistence_emit_failures,
            report.stats.persistence_emit_failures
        );
        assert!(losses[0].incomplete());
    }

    #[test]
    fn duplicate_only_drop_does_not_mark_persistence_incomplete() {
        let engine = Arc::new(DuplicateDropEngine);
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(InMemoryStoreProducer::default());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"data").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink);
        cfg.workers = 1;
        cfg.store_producer = Some(producer.clone());

        let report = scan_local(engine, source, cfg);

        assert_eq!(report.metrics.findings_emitted, 1);
        assert_eq!(
            report.stats.dropped_findings, 0,
            "drops that correspond only to scheduler-pruned duplicates should not mark run loss"
        );
        assert!(!report.stats.persistence_incomplete);

        let losses = producer.losses();
        assert_eq!(losses.len(), 1);
        assert_eq!(losses[0].dropped_findings, 0);
        assert!(!losses[0].incomplete());
    }

    /// Regression: persistence emit failures must NOT inflate io_errors.
    ///
    /// `io_errors` is documented as "file open, read, metadata failures" and
    /// operators / automation rely on that definition. Persistence backend
    /// errors are a different failure domain — they have their own counter
    /// (`persistence_emit_failures`).
    #[test]
    fn persistence_failure_does_not_inflate_io_errors() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(FailingStoreProducer);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET one SECRET two").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink);
        cfg.store_producer = Some(producer);

        let report = scan_local(engine, source, cfg);

        // Persistence failures should be tracked separately.
        assert!(
            report.stats.persistence_emit_failures > 0,
            "expected persistence failures from FailingStoreProducer"
        );
        // io_errors must reflect only real file I/O problems — the file
        // above was read successfully, so io_errors should be zero.
        assert_eq!(
            report.stats.io_errors, 0,
            "persistence failures must not be counted as io_errors"
        );
    }

    /// Regression: record_fs_run_loss failure must NOT inflate io_errors.
    ///
    /// Same principle as above: a persistence backend call failing at run
    /// end is not a file-system I/O error.
    #[test]
    fn run_loss_failure_does_not_inflate_io_errors() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(EmitOnlyStoreProducer::new());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET one").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink);
        cfg.store_producer = Some(producer.clone());

        let report = scan_local(engine, source, cfg);

        // Batches emitted fine (EmitOnlyStoreProducer succeeds on emit).
        assert!(!producer.batches().is_empty());

        // record_fs_run_loss fails — that must NOT bump io_errors.
        assert_eq!(
            report.stats.io_errors, 0,
            "run_loss failure must not be counted as io_errors"
        );

        // But persistence_incomplete should be true (run_loss failure
        // increments persistence_emit_failures).
        assert!(report.stats.persistence_incomplete);
        assert!(report.stats.persistence_emit_failures > 0);
    }

    #[test]
    fn dedupe_same_span_different_hash_preserves_both() {
        let mut v = vec![
            FindingWithHash::new(finding(0, 10, 16), [0xAA; 32]),
            FindingWithHash::new(finding(0, 10, 16), [0xBB; 32]),
        ];
        dedupe_findings(&mut v);
        assert_eq!(
            v.len(),
            2,
            "same span but different norm_hash must be preserved"
        );
    }

    #[test]
    fn dedupe_same_span_same_hash_collapses() {
        let mut v = vec![
            FindingWithHash::new(finding(0, 10, 16), [0xCC; 32]),
            FindingWithHash::new(finding(0, 10, 16), [0xCC; 32]),
        ];
        dedupe_findings(&mut v);
        assert_eq!(
            v.len(),
            1,
            "identical span and norm_hash should collapse to one"
        );
    }

    // ---------------------------------------------------------------
    // scan_local: overlap dedup, exact-size, multi-secret, reuse
    // ---------------------------------------------------------------

    #[test]
    fn overlap_dedup_no_double_report() {
        // Place SECRET so it falls entirely within the overlap region between
        // chunk 1 and chunk 2. With chunk_size=64 and overlap=16, SECRET at
        // offset 50 spans [50..56]. In chunk 2 (overlap carry from [48..64]),
        // drop_prefix_findings(64) drops it since root_hint_end=56 < 64.
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![b'x'; 50];
        data.extend_from_slice(b"SECRET");
        data.extend_from_slice(&[b'y'; 100]); // ensure >1 chunk
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert!(report.metrics.chunks_scanned >= 2);
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        let count = output_str.matches("secret").count();
        assert_eq!(
            count, 1,
            "SECRET in overlap region must be reported exactly once, got {count}: {output_str}"
        );
    }

    #[test]
    fn file_exactly_chunk_size() {
        // File of exactly chunk_size bytes should be scanned in one chunk.
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        // chunk_size=64 in small_config; place SECRET in the middle.
        let mut data = vec![b'x'; 20];
        data.extend_from_slice(b"SECRET");
        data.resize(64, b'z');
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert_eq!(report.metrics.chunks_scanned, 1);
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(
            output_str.matches("secret").count(),
            1,
            "single chunk should find SECRET"
        );
    }

    #[test]
    fn multiple_secrets_across_chunks_in_one_file() {
        // One file spanning 3+ chunks, each containing a SECRET well away
        // from overlap boundaries.
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        // chunk_size=64, overlap=16.
        // Place SECRETs at offsets 4, 100, and 196 — each solidly within
        // the "new bytes" region of their respective chunks.
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![b'A'; 4];
        data.extend_from_slice(b"SECRET"); // offset 4..10
        data.resize(100, b'B');
        data.extend_from_slice(b"SECRET"); // offset 100..106
        data.resize(196, b'C');
        data.extend_from_slice(b"SECRET"); // offset 196..202
        data.resize(256, b'D'); // ensure 3+ chunks
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

        assert!(
            report.metrics.chunks_scanned >= 3,
            "need at least 3 chunks, got {}",
            report.metrics.chunks_scanned
        );
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        let count = output_str.matches("secret").count();
        assert_eq!(
            count, 3,
            "each SECRET in its own chunk region should be found; got {count}: {output_str}"
        );
    }

    #[test]
    fn two_files_no_cross_contamination() {
        // Scan two files back-to-back and verify findings are correct for each.
        // Tests that per-worker scratch is properly cleared between files.
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());

        let dir = TempDir::new().unwrap();
        let p1 = dir.path().join("first.txt");
        let p2 = dir.path().join("second.txt");
        fs::write(&p1, b"first SECRET here").unwrap();
        fs::write(&p2, b"second PASSWORD there").unwrap();

        let s1 = fs::metadata(&p1).unwrap().len();
        let s2 = fs::metadata(&p2).unwrap().len();
        let files = vec![
            LocalFile { path: p1, size: s1 },
            LocalFile { path: p2, size: s2 },
        ];

        let source = VecFileSource::new(files);
        let cfg = LocalConfig {
            workers: 1,
            ..small_config_with_sink(sink.clone())
        };
        let report = scan_local(engine, source, cfg);

        assert_eq!(report.stats.files_enqueued, 2);
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(
            output_str.matches("secret").count(),
            1,
            "first file's SECRET"
        );
        assert_eq!(
            output_str.matches("password").count(),
            1,
            "second file's PASSWORD"
        );
    }

    // ---------------------------------------------------------------
    // Error-path tests for persistence plumbing
    // ---------------------------------------------------------------

    #[test]
    fn persistence_emit_failure_increments_counters() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(FailingStoreProducer);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET one SECRET two").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink.clone());
        cfg.store_producer = Some(producer);

        let report = scan_local(engine, source, cfg);

        assert!(
            report.stats.persistence_emit_failures > 0,
            "expected persistence_emit_failures > 0, got {}",
            report.stats.persistence_emit_failures
        );
        assert!(
            report.stats.persistence_incomplete,
            "expected persistence_incomplete to be true"
        );

        // Verify a diagnostic event was emitted for the failure.
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("persistence batch emit failed") || output_str.contains("injected"),
            "expected diagnostic event about emit failure; output: {output_str}"
        );
    }

    #[test]
    fn run_loss_record_failure_increments_counters_and_emits_diagnostic() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecEventSink::new());
        let producer = Arc::new(EmitOnlyStoreProducer::new());

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"SECRET one SECRET two").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config_with_sink(sink.clone());
        cfg.store_producer = Some(producer.clone());

        let report = scan_local(engine, source, cfg);

        // Emit should have succeeded — batches were collected.
        assert!(
            !producer.batches().is_empty(),
            "emit should have succeeded and collected batches"
        );

        // run_loss failure bumps persistence_emit_failures and sets incomplete.
        assert!(
            report.stats.persistence_incomplete,
            "expected persistence_incomplete after run-loss record failure"
        );
        // The persistence_emit_failures counter should include the run-loss failure.
        assert!(
            report.stats.persistence_emit_failures >= 1,
            "expected persistence_emit_failures >= 1 from run-loss failure, got {}",
            report.stats.persistence_emit_failures
        );

        // Verify a diagnostic event was emitted for the run-loss failure.
        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("run-loss recording failed") || output_str.contains("injected"),
            "expected diagnostic event about run-loss failure; output: {output_str}"
        );
    }

    // ---------------------------------------------------------------
    // build_persistence_batch field mapping
    // ---------------------------------------------------------------

    #[test]
    fn build_persistence_batch_maps_all_fields() {
        let finding = FindingRec {
            rule_id: RuleId(42),
            root_hint_start: 100,
            root_hint_end: 200,
            span_start: 110,
            span_end: 190,
        };
        let hash = [0xDE; 32];
        let wrapped = FindingWithHash::new(finding, hash);
        let findings = vec![wrapped];
        let mut out = Vec::with_capacity(findings.len());

        build_persistence_batch(&findings, &mut out);

        assert_eq!(out.len(), 1);
        let rec = &out[0];
        assert_eq!(rec.rule_id, 42);
        assert_eq!(rec.root_hint_start, 100);
        assert_eq!(rec.root_hint_end, 200);
        assert_eq!(rec.span_start, 110);
        assert_eq!(rec.span_end, 190);
        assert_eq!(rec.norm_hash, [0xDE; 32]);
    }
}
