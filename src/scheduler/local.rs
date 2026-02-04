//! Local Filesystem Scanner
//!
//! # Architecture
//!
//! - CPU workers do both I/O and scan (no separate I/O threads)
//! - Uses `LocalFirst` buffer pool policy (same thread acquires and releases)
//! - Sequential reads with overlap carry (no seeks, no re-reading overlap)
//! - Discovery thread enqueues files; workers process entire files
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
use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use super::executor::{Executor, ExecutorConfig, WorkerCtx};
use super::metrics::{MetricsSnapshot, WorkerMetricsLocal};
use super::ts_buffer_pool::{TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::archive::formats::{
    tar::TAR_BLOCK_LEN, GzipStream, TarCursor, TarInput, TarNext, TarRead,
};
use crate::archive::{
    detect_kind_from_name_bytes, detect_kind_from_path, sniff_kind_from_header, ArchiveBudgets,
    ArchiveConfig, ArchiveKind, ArchiveSkipReason, BudgetHit, ChargeResult, EntryPathCanonicalizer,
    EntrySkipReason, PartialReason, VirtualPathBuilder, DEFAULT_MAX_COMPONENTS,
};
use crate::scheduler::engine_stub::BUFFER_LEN_MAX;
use crate::scheduler::output_sink::OutputSink;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
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
#[derive(Clone, Debug)]
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
        }
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

struct LocalScratch<E: ScanEngine> {
    engine: Arc<E>,
    pool: TsBufferPool,
    out: Arc<dyn OutputSink>,

    /// Per-worker engine scratch.
    scan_scratch: E::Scratch,
    /// Per-worker findings buffer (avoids alloc per chunk).
    pending: Vec<<E::Scratch as EngineScratch>::Finding>,
    /// Per-worker output formatting buffer.
    out_buf: Vec<u8>,

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
    /// Scratch buffer for gzip header peeking (bounded).
    gzip_header_buf: Vec<u8>,
    /// Scratch buffer for gzip header filename (bounded).
    gzip_name_buf: Vec<u8>,
    /// Monotonic virtual `FileId` generator for archive entries.
    next_virtual_file_id: u32,

    /// Configuration flags.
    dedupe_within_chunk: bool,
    chunk_size: usize,
    max_file_size: u64,
    archive: ArchiveConfig,
}

// ============================================================================
// Run Statistics
// ============================================================================

/// Statistics from a local scan run.
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
}

/// Complete report from a local scan.
#[derive(Debug, Default)]
pub struct LocalReport {
    pub stats: LocalStats,
    pub metrics: MetricsSnapshot,
}

// ============================================================================
// Helpers
// ============================================================================

/// Deduplicate findings in place by (rule_id, root_hint).
///
/// # Algorithm
///
/// 1. Sort by `(rule_id, root_hint_start, root_hint_end)` — O(n log n)
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
#[inline]
fn dedupe_findings<F: FindingRecord>(findings: &mut Vec<F>) {
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
        )
    });

    findings.dedup_by(|a, b| {
        a.rule_id() == b.rule_id()
            && a.root_hint_start() == b.root_hint_start()
            && a.root_hint_end() == b.root_hint_end()
            && a.span_start() == b.span_start()
            && a.span_end() == b.span_end()
    });
}

/// Format and emit findings to the output sink.
///
/// # Output Format
///
/// Each finding is formatted as: `<path>:<start>-<end> <rule_name>\n`
///
/// Example: `/home/user/code/config.js:42-68 aws-access-key`
///
/// # Buffer Reuse
///
/// The `out_buf` is reused across calls to avoid allocation per file.
/// It's cleared at the start of each call.
#[inline]
fn emit_findings<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    out: &Arc<dyn OutputSink>,
    out_buf: &mut Vec<u8>,
    path: &[u8],
    findings: &[F],
) {
    if findings.is_empty() {
        return;
    }

    out_buf.clear();

    for rec in findings {
        // Format: path:start-end rulename\n
        out_buf.extend_from_slice(path);
        out_buf.push(b':');

        // Simple integer formatting to avoid allocation
        use std::io::Write;
        writeln!(
            out_buf,
            "{}-{} {}",
            rec.root_hint_start(),
            rec.root_hint_end(),
            engine.rule_name(rec.rule_id())
        )
        .expect("write to Vec<u8> cannot fail");
    }

    out.write_all(out_buf);
}

/// Allocate a virtual `FileId` for archive entries (high-bit namespace).
#[inline]
fn alloc_virtual_file_id(next_virtual_file_id: &mut u32) -> FileId {
    const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
    const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

    let id = *next_virtual_file_id;
    let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
    *next_virtual_file_id = next;
    FileId(id)
}

#[inline]
/// Dispatch archive scanning by kind.
///
/// Currently gzip/tar/tar.gz are supported; other formats are skipped.
fn dispatch_archive_scan<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    kind: ArchiveKind,
) -> ArchiveEnd {
    match kind {
        ArchiveKind::Gzip => process_gzip_file(task, ctx),
        ArchiveKind::Tar => process_tar_file(task, ctx),
        ArchiveKind::TarGz => process_targz_file(task, ctx),
        _ => ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature),
    }
}

/// Hard cap on per-read output for archive streams.
const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveEnd {
    Scanned,
    Skipped(ArchiveSkipReason),
    Partial(PartialReason),
}

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

#[inline(always)]
fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

#[inline(always)]
fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(_) => ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded),
    }
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
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

/// Drain remaining tar entry payload bytes to realign the stream.
fn discard_remaining_payload<R: TarRead>(
    input: &mut R,
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

        engine.scan_chunk_into(data, task.file_id, base_offset, &mut scratch.scan_scratch);
        if !entry_scanned {
            metrics.archive.record_entry_scanned();
            entry_scanned = true;
        }

        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);

        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        if dedupe && scratch.pending.len() > 1 {
            dedupe_findings(&mut scratch.pending);
        }

        metrics.findings_emitted = metrics
            .findings_emitted
            .wrapping_add(scratch.pending.len() as u64);

        emit_findings(
            engine.as_ref(),
            &scratch.out,
            &mut scratch.out_buf,
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

/// Scan a tar stream (plain or gzip-wrapped) as sequential entries.
///
/// # Invariants
/// - Entry payloads are scanned with chunk+overlap semantics.
/// - Non-regular entries are skipped explicitly.
/// - Malformed headers or payload reads yield `PartialReason::MalformedTar`.
fn scan_tar_stream<E: ScanEngine, R: TarRead>(
    scratch: &mut LocalScratch<E>,
    metrics: &mut WorkerMetricsLocal,
    input: &mut R,
    parent_bytes: &[u8],
    ratio_active: bool,
) -> ArchiveEnd {
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let dedupe = scratch.dedupe_within_chunk;
    let archive_cfg = &scratch.archive;
    let max_len = archive_cfg.max_virtual_path_len_per_entry;

    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let cursor = scratch
        .tar_cursors
        .get_mut(0)
        .expect("tar cursor scratch exhausted");
    cursor.reset();

    let mut buf = scratch.pool.acquire();
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (entry_name, entry_size, entry_pad, entry_typeflag) =
            match cursor.next_entry(input, &mut scratch.budgets, archive_cfg) {
                Ok(TarNext::End) => break,
                Ok(TarNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(TarNext::Entry(m)) => (m.name, m.size, m.pad, m.typeflag),
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            };

        let (entry_display, is_regular) = {
            let c = scratch
                .canon
                .canonicalize(entry_name, DEFAULT_MAX_COMPONENTS, max_len);
            if c.had_traversal {
                metrics.archive.record_path_had_traversal();
            }
            if c.component_cap_exceeded {
                metrics.archive.record_component_cap_exceeded();
            }
            if c.truncated {
                metrics.archive.record_path_truncated();
            }
            let entry_display = scratch.vpaths[1]
                .build(parent_bytes, c.bytes, max_len)
                .bytes;
            let _nested_kind = detect_kind_from_name_bytes(entry_name);
            let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
            (entry_display, is_regular)
        };

        let need = entry_display.len();
        if scratch.path_budget_used[1].saturating_add(need)
            > archive_cfg.max_virtual_path_bytes_per_archive
        {
            outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
            break;
        }
        scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

        if !is_regular {
            metrics
                .archive
                .record_entry_skipped(EntrySkipReason::NonRegular, entry_display, false);
            match cursor.skip_payload_and_pad(input, &mut scratch.budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                Ok(Err(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        scratch.budgets.begin_entry_scan();

        let entry_file_id = alloc_virtual_file_id(&mut scratch.next_virtual_file_id);
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

            let allow = scratch
                .budgets
                .remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allow == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
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
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
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
            scratch
                .budgets
                .charge_compressed_in(input.take_compressed_delta());
            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                stop_archive = true;
                break;
            }
            remaining = remaining.saturating_sub(n as u64);

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                scratch.budgets.charge_decompressed_out(allowed)
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
                if let Err(r) = charge_discarded_bytes(&mut scratch.budgets, n as u64) {
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

            engine.scan_chunk_into(data, entry_file_id, base_offset, &mut scratch.scan_scratch);
            if !entry_scanned {
                metrics.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scratch.scan_scratch.drop_prefix_findings(new_bytes_start);

            scratch.pending.clear();
            scratch
                .scan_scratch
                .drain_findings_into(&mut scratch.pending);

            if dedupe && scratch.pending.len() > 1 {
                dedupe_findings(&mut scratch.pending);
            }

            metrics.findings_emitted = metrics
                .findings_emitted
                .wrapping_add(scratch.pending.len() as u64);
            emit_findings(
                engine.as_ref(),
                &scratch.out,
                &mut scratch.out_buf,
                entry_display,
                &scratch.pending,
            );

            metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
            metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            if allowed_usize < n {
                let extra = (n - allowed_usize) as u64;
                if let Err(r) = charge_discarded_bytes(&mut scratch.budgets, extra) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }
        }

        if !stop_archive && remaining > 0 {
            if let Err(r) = discard_remaining_payload(
                input,
                &mut scratch.budgets,
                buf.as_mut_slice(),
                remaining,
            ) {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
                stop_archive = true;
            }
        }

        scratch.budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            metrics
                .archive
                .record_entry_partial(r, entry_display, false);
        }

        if stop_archive {
            break;
        }

        match cursor.skip_padding_only(input, &mut scratch.budgets, entry_pad) {
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
        cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    outcome
}

/// Scan a `.tar` or `.tar.gz` root by wiring budgets + tar stream scanning.
fn process_tar_like<E: ScanEngine>(
    task: &FileTask,
    ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>,
    mut input: TarInput,
) -> ArchiveEnd {
    let scratch = &mut ctx.scratch;
    let metrics = &mut ctx.metrics;
    let parent_bytes = task.path.as_os_str().as_encoded_bytes();

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        return budget_hit_to_archive_end(hit);
    }

    let ratio_active = matches!(input, TarInput::Gzip(_));
    let outcome = scan_tar_stream(scratch, metrics, &mut input, parent_bytes, ratio_active);

    scratch.budgets.exit_archive();
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

// ============================================================================
// File Processing
// ============================================================================

/// Process a single file: open, chunk, scan, close.
///
/// When archive scanning is enabled, archive containers are detected by
/// extension/magic and routed through the archive dispatch path before any
/// chunk reads are issued.
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
/// I/O errors are logged but do not propagate (fail-soft per file).
/// The executor continues with remaining files.
fn process_file<E: ScanEngine>(task: FileTask, ctx: &mut WorkerCtx<FileTask, LocalScratch<E>>) {
    let scratch = &mut ctx.scratch;
    let engine = &scratch.engine;
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size;
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
        let data = &buf.as_slice()[..read_len];
        engine.scan_chunk_into(data, task.file_id, base_offset, &mut scratch.scan_scratch);

        // Drop findings whose root_hint_end is in the prefix region.
        // These will be (or were) found by the chunk that "owns" those bytes.
        // new_bytes_start == offset (the first truly new byte in this scan)
        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);

        // Extract findings
        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        // Optional within-chunk dedupe (only needed if engine can emit duplicates)
        if scratch.dedupe_within_chunk && scratch.pending.len() > 1 {
            dedupe_findings(&mut scratch.pending);
        }

        // Count findings before emitting (pending.len() is the count for this chunk)
        ctx.metrics.findings_emitted = ctx
            .metrics
            .findings_emitted
            .wrapping_add(scratch.pending.len() as u64);

        // Emit findings
        emit_findings(
            engine.as_ref(),
            &scratch.out,
            &mut scratch.out_buf,
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
/// - `cfg`: Configuration for workers, chunking, and memory budgets
/// - `out`: Output sink for findings (e.g., [`VecSink`](super::output_sink::VecSink))
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
/// let sink = Arc::new(VecSink::new());
///
/// let report = scan_local(engine, source, LocalConfig::default(), sink);
///
/// // With real Engine (for production):
/// let engine = Arc::new(Engine::new(rules, transforms, tuning));
/// let report = scan_local(engine, source, LocalConfig::default(), sink);
/// ```
pub fn scan_local<E, S>(
    engine: Arc<E>,
    mut source: S,
    cfg: LocalConfig,
    out: Arc<dyn OutputSink>,
) -> LocalReport
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

    // Capture config values before moving into closure
    let dedupe = cfg.dedupe_within_chunk;
    let chunk_size = cfg.chunk_size;

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
            let out = Arc::clone(&out);
            move |_wid| {
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
                let gzip_name_cap = archive_cfg.max_virtual_path_len_per_entry;
                let gzip_header_cap = archive_cfg
                    .max_virtual_path_len_per_entry
                    .saturating_add(256)
                    .min(archive_cfg.max_archive_metadata_bytes as usize)
                    .clamp(64, 64 * 1024);

                LocalScratch {
                    engine: Arc::clone(&engine),
                    pool: pool.clone(),
                    out: Arc::clone(&out),
                    scan_scratch,
                    pending: Vec::with_capacity(4096), // Reasonable default
                    out_buf: Vec::with_capacity(64 * 1024),
                    canon: EntryPathCanonicalizer::with_capacity(
                        DEFAULT_MAX_COMPONENTS,
                        archive_cfg.max_virtual_path_len_per_entry,
                    ),
                    vpaths,
                    path_budget_used,
                    budgets: ArchiveBudgets::new(&archive_cfg),
                    tar_cursors,
                    gzip_header_buf: vec![0u8; gzip_header_cap],
                    gzip_name_buf: Vec::with_capacity(gzip_name_cap),
                    next_virtual_file_id: 0x8000_0000,
                    dedupe_within_chunk: dedupe,
                    chunk_size,
                    max_file_size: cfg.max_file_size,
                    archive: archive_cfg.clone(),
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

    while let Some(file) = source.next_file() {
        // Acquire in-flight permit (blocks if at capacity)
        let permit = budget.acquire(1);

        let file_id = FileId(next_file_id);
        next_file_id = next_file_id.wrapping_add(1);

        stats.files_enqueued += 1;
        stats.bytes_enqueued += file.size;

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

    if !batch.is_empty() {
        ex.spawn_external_batch(batch)
            .expect("executor rejected task batch before join");
    }

    // Wait for all files to complete
    let metrics = ex.join();

    out.flush();

    // Aggregate I/O errors from worker metrics into stats
    stats.io_errors = metrics.io_errors;

    LocalReport { stats, metrics }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveSkipReason;
    use crate::scheduler::engine_stub::{MockEngine, MockRule};
    use crate::scheduler::output_sink::VecSink;
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

    fn small_config() -> LocalConfig {
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
        }
    }

    #[test]
    fn scans_single_file_with_findings() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        // Create temp file with secret
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "hello SECRET world").unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);

        let report = scan_local(engine, source, small_config(), sink.clone());

        assert_eq!(report.stats.files_enqueued, 1);
        assert!(report.metrics.chunks_scanned >= 1);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("secret"), "output: {}", output_str);
    }

    #[test]
    fn handles_empty_file() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let source = VecFileSource::new(vec![LocalFile { path, size: 0 }]);

        let report = scan_local(engine, source, small_config(), sink.clone());

        assert_eq!(report.stats.files_enqueued, 1);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn enforces_max_file_size_at_open_time() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "SECRETABCD1234").unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let source = VecFileSource::new(vec![LocalFile { path, size: 4 }]);

        let mut cfg = small_config();
        cfg.max_file_size = 4; // Smaller than actual file size at open time.

        let report = scan_local(engine, source, cfg, sink.clone());

        assert_eq!(report.stats.files_enqueued, 1);
        assert_eq!(report.metrics.bytes_scanned, 0);
        assert!(sink.take().is_empty());
    }

    #[test]
    fn handles_no_files() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        let source = VecFileSource::new(vec![]);

        let report = scan_local(engine, source, small_config(), sink.clone());

        assert_eq!(report.stats.files_enqueued, 0);
        assert_eq!(report.metrics.chunks_scanned, 0);
    }

    #[test]
    fn finds_boundary_spanning_secret() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

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

        let report = scan_local(engine, source, small_config(), sink.clone());

        assert!(
            report.metrics.chunks_scanned >= 2,
            "should need multiple chunks"
        );

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
        let sink = Arc::new(VecSink::new());

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

        let report = scan_local(engine, source, small_config(), sink.clone());

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
        let sink = Arc::new(VecSink::new());

        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![b'a'; 1000];
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);

        let report = scan_local(engine, source, small_config(), sink);

        // bytes_scanned should be ~1000 (the actual payload scanned)
        assert!(report.metrics.bytes_scanned >= 1000);
    }

    #[test]
    fn archive_detection_skips_when_enabled() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sample.zip");
        fs::write(&path, b"SECRET").unwrap();
        let size = fs::metadata(&path).unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let mut cfg = small_config();
        cfg.archive.enabled = true;

        let report = scan_local(engine, source, cfg, sink);

        assert_eq!(report.metrics.archive.archives_seen, 1);
        assert_eq!(report.metrics.archive.archives_skipped, 1);
        assert_eq!(
            report.metrics.archive.archive_skip_reasons
                [ArchiveSkipReason::UnsupportedFeature.as_usize()],
            1
        );
    }

    #[test]
    fn archive_extension_scans_when_disabled() {
        let engine = Arc::new(test_engine());
        let sink = Arc::new(VecSink::new());

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sample.zip");
        fs::write(&path, b"hello SECRET world").unwrap();
        let size = fs::metadata(&path).unwrap().len();

        let source = VecFileSource::new(vec![LocalFile { path, size }]);
        let cfg = small_config();

        let report = scan_local(engine, source, cfg, sink.clone());

        assert_eq!(report.metrics.archive.archives_seen, 0);

        let output = sink.take();
        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("secret"),
            "expected finding for archive extension when disabled; output: {output_str}"
        );
    }
}
