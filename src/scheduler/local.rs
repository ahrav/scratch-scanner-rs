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
use super::metrics::MetricsSnapshot;
use super::ts_buffer_pool::{TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::scheduler::engine_stub::BUFFER_LEN_MAX;
use crate::scheduler::output_sink::OutputSink;

use std::fs::File;
use std::io::{self, Read};
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

    /// Seed for deterministic executor behavior.
    pub seed: u64,

    /// If true, deduplicate findings within each chunk.
    ///
    /// This is a defense-in-depth measure for engines that might emit
    /// duplicate findings for the same match (e.g., overlapping patterns).
    /// Cross-chunk deduplication is handled separately by `drop_prefix_findings`.
    pub dedupe_within_chunk: bool,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            workers: 8,
            chunk_size: 64 * 1024, // 64 KiB
            pool_buffers: 32,
            local_queue_cap: 4,
            max_in_flight_objects: 256,
            seed: 0x853c49e6748fea9b,
            dedupe_within_chunk: true,
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
    /// File size in bytes.
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

    /// Configuration flags.
    dedupe_within_chunk: bool,
    chunk_size: usize,
}

// ============================================================================
// Run Statistics
// ============================================================================

/// Statistics from a local scan run.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalStats {
    /// Files discovered and enqueued.
    pub files_enqueued: u64,
    /// Total bytes across all enqueued files.
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

// ============================================================================
// File Processing
// ============================================================================

/// Process a single file: open, chunk, scan, close.
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

    // Path bytes for output
    let path_bytes = task.path.as_os_str().as_encoded_bytes();

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
                eprintln!("[local] Read failed: {}", e);
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
                LocalScratch {
                    engine: Arc::clone(&engine),
                    pool: pool.clone(),
                    out: Arc::clone(&out),
                    scan_scratch,
                    pending: Vec::with_capacity(4096), // Reasonable default
                    out_buf: Vec::with_capacity(64 * 1024),
                    dedupe_within_chunk: dedupe,
                    chunk_size,
                }
            }
        },
        process_file::<E>,
    );

    // Discovery loop
    let mut stats = LocalStats::default();
    let mut next_file_id: u32 = 0;

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

        // This should not fail since we haven't called join() yet
        ex.spawn_external(task)
            .expect("executor rejected task before join");
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
    use crate::scheduler::engine_stub::{MockEngine, MockRule};
    use crate::scheduler::output_sink::VecSink;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
            seed: 12345,
            dedupe_within_chunk: true,
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
}
