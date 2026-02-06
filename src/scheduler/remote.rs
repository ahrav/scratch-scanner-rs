//! Remote Fetch Pipeline
//!
//! # Architecture
//!
//! ```text
//! Discovery Thread       I/O Threads (N)         CPU Workers (M)
//! â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€    â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//!    list_page()             â†“
//!        â†“              ObjectWork recv
//!    bounded chan  â”€â”€â”€â”€â”€â†’   â†“
//!                       fetch_range()
//!                       retry/backoff
//!                            â†“
//!                       ScanChunk task  â”€â”€â”€â”€â†’  scan_chunk_into()
//!                       (buffer handoff)       drop_prefix_findings()
//!                                              emit findings
//!                                              release buffer
//! ```
//!
//! # Key Design Decisions
//!
//! 1. **Separate I/O and CPU threads**: Network latency doesn't block scanning
//! 2. **GlobalOnly buffer pool**: I/O threads acquire, CPU workers release
//! 3. **Bounded object queue**: Discovery backpressure via channel capacity
//! 4. **CountBudget for objects**: Caps discovered-but-not-complete objects
//! 5. **ObjectToken via Arc**: Permit released when all chunks complete
//!
//! # Backpressure Chain
//!
//! ```text
//! Discovery â†’ object_queue_cap â†’ I/O threads â†’ pool_buffers â†’ CPU executor
//!          â†‘                                  â†‘
//!    CountBudget                        TsBufferPool
//! ```
//!
//! # Retry Policy
//!
//! - Exponential backoff with jitter
//! - Configurable max attempts
//! - Optional per-object time budget
//! - Error classification: Retryable vs Permanent

use super::count_budget::{CountBudget, CountPermit};
use super::executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
use super::metrics::MetricsSnapshot;
use super::rng::XorShift64;
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
use crate::perf_stats;
use crate::scheduler::engine_stub::{FileId, FindingRec, MockEngine, ScanScratch, BUFFER_LEN_MAX};
use crate::scheduler::output_sink::OutputSink;

use crossbeam_channel as chan;

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Error Classification
// ============================================================================

/// Classification of backend errors for retry decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient error - worth retrying (network timeout, 503, rate limit)
    Retryable,
    /// Permanent error - don't retry (404, auth failure, invalid response)
    Permanent,
}

// ============================================================================
// Retry Policy
// ============================================================================

/// Configuration for retry behavior.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Maximum attempts per fetch (including initial attempt).
    pub max_attempts: u32,
    /// Base delay before first retry.
    pub base_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Jitter as percentage of computed delay (0-100).
    /// Jitter helps avoid thundering herd when multiple fetches fail.
    pub jitter_pct: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            jitter_pct: 20,
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for remote scanning pipeline.
#[derive(Clone, Debug)]
pub struct RemoteConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,

    /// Number of dedicated I/O threads for fetching.
    pub io_threads: usize,

    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,

    /// Hard cap on discovered-but-not-fully-processed objects.
    /// Controls memory for object metadata (paths, handles, permits).
    pub max_in_flight_objects: usize,

    /// Bounded queue depth between discovery and I/O threads.
    /// Smaller = tighter backpressure, less memory for queued work.
    pub object_queue_cap: usize,

    /// How many objects to request per list_page call.
    pub discover_batch: usize,

    /// Total buffers in the global pool.
    /// Caps: buffered bytes + queued scan tasks.
    /// Rule of thumb: `pool_buffers >= io_threads + cpu_workers`
    pub pool_buffers: usize,

    /// Retry policy for transient failures.
    pub retry: RetryPolicy,

    /// Abort an object if total time exceeds this (including retries).
    /// `None` means no time budget.
    pub max_object_time: Option<Duration>,

    /// Seed for deterministic retry jitter.
    pub seed: u64,

    /// If true, deduplicate findings within each chunk.
    pub dedupe_within_chunk: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            io_threads: 8,
            chunk_size: 256 * 1024,
            max_in_flight_objects: 512,
            object_queue_cap: 256,
            discover_batch: 256,
            pool_buffers: 64,
            retry: RetryPolicy::default(),
            max_object_time: Some(Duration::from_secs(30)),
            seed: 1,
            dedupe_within_chunk: true,
        }
    }
}

impl RemoteConfig {
    /// Validate configuration against engine constraints.
    ///
    /// # Panics
    ///
    /// Panics if configuration violates invariants.
    pub fn validate(&self, engine: &MockEngine) {
        assert!(self.cpu_workers > 0, "cpu_workers must be > 0");
        assert!(self.io_threads > 0, "io_threads must be > 0");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(
            self.max_in_flight_objects > 0,
            "max_in_flight_objects must be > 0"
        );
        assert!(self.object_queue_cap > 0, "object_queue_cap must be > 0");
        assert!(self.discover_batch > 0, "discover_batch must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(self.retry.max_attempts > 0, "max_attempts must be > 0");
        assert!(self.retry.jitter_pct <= 100, "jitter_pct must be <= 100");

        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(self.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
            self.chunk_size,
            overlap,
            buf_len,
            BUFFER_LEN_MAX
        );
    }
}

// ============================================================================
// Remote Object
// ============================================================================

/// A single remote object to scan.
#[derive(Clone, Debug)]
pub struct RemoteObject<H> {
    /// Backend-specific handle for fetching.
    pub handle: H,
    /// Object size in bytes.
    pub size: u64,
    /// Display bytes for output (path/key). Can be non-UTF8.
    pub display: Vec<u8>,
}

// ============================================================================
// Remote Backend Trait
// ============================================================================

/// Contract for remote data sources.
///
/// Implementations handle the actual network/API calls.
/// The scheduler handles threading, retry, backpressure.
///
/// # Blocking vs Async
///
/// This trait uses blocking calls executed on dedicated I/O threads.
/// This is simpler than async and works well for moderate concurrency.
/// For very high concurrency (1000+ concurrent fetches), consider
/// an async backend with tokio/async-std.
pub trait RemoteBackend: Send + Sync + 'static {
    /// Backend-specific object handle (e.g., S3 key, HTTP URL).
    type Object: Send + 'static;

    /// Pagination cursor for list operations.
    type Cursor: Default + Send + 'static;

    /// Backend-specific error type.
    type Error: std::fmt::Debug + Send + Sync + 'static;

    /// List up to `max` objects starting from cursor.
    ///
    /// Returns empty vec when enumeration is complete.
    /// Updates cursor for next page.
    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error>;

    /// Fetch exactly `dst.len()` bytes from object starting at `start`.
    ///
    /// # Contract (IMPORTANT)
    ///
    /// On success, returns number of bytes written:
    /// - If `start + dst.len() <= object_size`: MUST return `dst.len()` (exact fill)
    /// - If `start >= object_size`: MUST return `0` (EOF)
    /// - If `start < object_size < start + dst.len()`: MUST return `object_size - start` (final partial)
    ///
    /// **Partial reads within range are NOT allowed.** If the backend cannot fill
    /// the entire requested range (e.g., network timeout mid-read), it MUST return
    /// an error (classified as `Retryable` or `Permanent`).
    ///
    /// # Rationale
    ///
    /// This simplifies the scheduler: it doesn't need to loop on partial reads.
    /// S3, HTTP, and GCS backends can trivially implement "fill exactly" by
    /// looping internally on their underlying read calls.
    ///
    /// # Example Implementation
    ///
    /// ```ignore
    /// fn fetch_range(&self, obj: &Key, start: u64, dst: &mut [u8]) -> Result<usize, Error> {
    ///     let mut filled = 0;
    ///     while filled < dst.len() {
    ///         match self.inner_read(obj, start + filled as u64, &mut dst[filled..])? {
    ///             0 => break, // EOF
    ///             n => filled += n,
    ///         }
    ///     }
    ///     Ok(filled)
    /// }
    /// ```
    fn fetch_range(
        &self,
        obj: &Self::Object,
        start: u64,
        dst: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Classify error for retry decisions.
    fn classify_error(&self, err: &Self::Error) -> ErrorClass;
}

// ============================================================================
// Statistics
// ============================================================================

/// I/O thread statistics (per-thread, merged at end).
#[derive(Clone, Copy, Debug, Default)]
pub struct IoStats {
    pub objects_started: u64,
    pub objects_completed: u64,
    pub objects_failed: u64,

    pub chunks_fetched: u64,
    /// Payload bytes fetched (excludes overlap).
    pub payload_bytes_fetched: u64,

    pub retryable_errors: u64,
    pub permanent_errors: u64,
    pub retries: u64,
}

impl IoStats {
    fn merge(&mut self, other: IoStats) {
        self.objects_started += other.objects_started;
        self.objects_completed += other.objects_completed;
        self.objects_failed += other.objects_failed;
        self.chunks_fetched += other.chunks_fetched;
        self.payload_bytes_fetched += other.payload_bytes_fetched;
        self.retryable_errors += other.retryable_errors;
        self.permanent_errors += other.permanent_errors;
        self.retries += other.retries;
    }
}

/// Discovery thread statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct RemoteStats {
    /// Objects returned by `list_page` calls.
    pub objects_discovered: u64,
    /// Objects sent to the I/O channel (may be fewer if pipeline stops
    /// mid-discovery).
    pub objects_enqueued: u64,
}

/// End-of-run report.
#[derive(Debug, Default)]
pub struct RemoteRunReport {
    /// Discovery-side stats (listing).
    pub remote: RemoteStats,
    /// I/O-thread-side stats (fetch, retry, scan).
    pub io: IoStats,
}

// ============================================================================
// Run Errors
// ============================================================================

/// Errors that can occur during remote scanning.
#[derive(Debug)]
pub enum RemoteRunError<E> {
    /// Error during object listing.
    List(E),
    /// An I/O thread panicked.
    IoThreadPanicked,
}

// ============================================================================
// Internal Types
// ============================================================================

/// Token holding the in-flight object permit.
///
/// The permit is released when the last Arc<ObjectToken> is dropped,
/// which happens after all chunk tasks for the object complete.
struct ObjectToken {
    _permit: CountPermit,
    file_id: FileId,
    display: Arc<[u8]>,
}

/// Work item sent from discovery to I/O threads.
struct ObjectWork<H> {
    handle: H,
    size: u64,
    token: Arc<ObjectToken>,
}

/// Task sent from I/O threads to CPU executor.
enum CpuTask {
    ScanChunk {
        /// Shared token for this object (permit released when all chunks done).
        token: Arc<ObjectToken>,
        /// Absolute offset of buffer[0] in the object.
        base_offset: u64,
        /// Overlap prefix length (bytes to skip for dedup).
        prefix_len: u32,
        /// Total valid bytes in buffer.
        len: u32,
        /// Buffer with data to scan.
        buf: TsBufferHandle,
    },
}

/// Per-CPU-worker scratch space.
struct CpuScratch {
    engine: Arc<MockEngine>,
    out: Arc<dyn OutputSink>,

    scratch: ScanScratch,
    pending: Vec<FindingRec>,
    out_buf: Vec<u8>,

    dedupe_within_chunk: bool,
}

// ============================================================================
// CPU Worker Logic
// ============================================================================

/// In-place dedupe of findings by `(rule_id, root_hint, span)`.
fn dedupe_pending_in_place(p: &mut Vec<FindingRec>) {
    if p.len() <= 1 {
        return;
    }

    p.sort_unstable_by(|a, b| {
        (
            a.rule_id,
            a.root_hint_start,
            a.root_hint_end,
            a.span_start,
            a.span_end,
        )
            .cmp(&(
                b.rule_id,
                b.root_hint_start,
                b.root_hint_end,
                b.span_start,
                b.span_end,
            ))
    });

    p.dedup_by(|a, b| {
        a.rule_id == b.rule_id
            && a.root_hint_start == b.root_hint_start
            && a.root_hint_end == b.root_hint_end
            && a.span_start == b.span_start
            && a.span_end == b.span_end
    });
}

/// Formats findings into `out_buf` and flushes them to the output sink.
fn emit_findings_formatted(
    engine: &MockEngine,
    out: &Arc<dyn OutputSink>,
    out_buf: &mut Vec<u8>,
    display: &[u8],
    recs: &[FindingRec],
) {
    if recs.is_empty() {
        return;
    }

    out_buf.clear();

    for rec in recs {
        out_buf.extend_from_slice(display);
        let rule = engine.rule_name(rec.rule_id);

        // Vec<u8> implements io::Write
        writeln!(
            out_buf,
            ":{}-{} {}",
            rec.root_hint_start, rec.root_hint_end, rule
        )
        .expect("write to Vec<u8> cannot fail");
    }

    out.write_all(out_buf.as_slice());
}

/// Executes a single scan-chunk task on a CPU worker thread.
fn cpu_runner(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch>) {
    match task {
        CpuTask::ScanChunk {
            token,
            base_offset,
            prefix_len,
            len,
            buf,
        } => {
            let engine = &ctx.scratch.engine;
            let data = &buf.as_slice()[..(len as usize)];

            engine.scan_chunk_into(data, token.file_id, base_offset, &mut ctx.scratch.scratch);

            // Drop findings fully contained in the prefix
            let new_bytes_start = base_offset + prefix_len as u64;
            ctx.scratch.scratch.drop_prefix_findings(new_bytes_start);

            // Clear pending before draining new findings
            ctx.scratch.pending.clear();
            ctx.scratch
                .scratch
                .drain_findings_into(&mut ctx.scratch.pending);

            if ctx.scratch.dedupe_within_chunk && ctx.scratch.pending.len() > 1 {
                dedupe_pending_in_place(&mut ctx.scratch.pending);
            }

            emit_findings_formatted(
                engine,
                &ctx.scratch.out,
                &mut ctx.scratch.out_buf,
                &token.display,
                &ctx.scratch.pending,
            );

            // Metrics: count payload bytes only
            let payload = (len as u64).saturating_sub(prefix_len as u64);
            perf_stats::sat_add_u64(&mut ctx.metrics.chunks_scanned, 1);
            perf_stats::sat_add_u64(&mut ctx.metrics.bytes_scanned, payload);

            // Buffer returned to pool on drop
            drop(buf);
        }
    }
}

// ============================================================================
// Retry Logic
// ============================================================================

/// Computes exponential backoff with jitter.
///
/// `attempt` is 1-based (1 = first retry). Delay is
/// `base_delay * 2^(attempt-1)`, capped at `max_delay`, then jittered
/// by `+/- jitter_pct%` uniform.
fn compute_backoff(attempt: u32, policy: RetryPolicy, rng: &mut XorShift64) -> Duration {
    // attempt starts at 1 for the first try
    let exp = attempt.saturating_sub(1).min(30);
    let mut d = policy.base_delay.saturating_mul(1u32 << exp);
    if d > policy.max_delay {
        d = policy.max_delay;
    }

    let jitter_pct = policy.jitter_pct.min(100) as u64;
    if jitter_pct == 0 {
        return d;
    }

    let jitter_ns = (d.as_nanos() as u64).saturating_mul(jitter_pct) / 100;
    let span = jitter_ns.saturating_mul(2);
    if span == 0 {
        return d;
    }

    // Uniform in [d - jitter, d + jitter]
    let r = rng.next_u64() % (span + 1);
    let offset = r as i128 - jitter_ns as i128;
    let base = d.as_nanos() as i128;
    let out = (base + offset).max(0) as u128;

    Duration::from_nanos(out.min(u64::MAX as u128) as u64)
}

// ============================================================================
// I/O Thread Logic
// ============================================================================

/// Blocking buffer acquire for I/O threads.
///
/// I/O threads are not the hot path, so we use a simple spin-then-park loop.
///
/// # Why spin-then-park instead of a proper blocking semaphore?
///
/// 1. Simplicity: no additional synchronization primitives needed
/// 2. Typical case: buffers available immediately (CPU workers release fast)
/// 3. Fallback: short park avoids busy-wait while remaining responsive to `stop`
///
/// The 200-spin threshold is tuned for ~200ns of spinning before yielding.
fn acquire_buffer_blocking(pool: &TsBufferPool, stop: &AtomicBool) -> Option<TsBufferHandle> {
    let mut spins: u32 = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(h) = pool.try_acquire() {
            return Some(h);
        }

        if spins < 200 {
            spins += 1;
            std::hint::spin_loop();
        } else {
            std::thread::park_timeout(Duration::from_micros(200));
            spins = 0;
        }
    }
}

/// I/O worker loop: fetch chunks from remote backend, enqueue scan tasks.
///
/// # Buffer Lifecycle
///
/// Buffers are acquired just-in-time (after computing what to fetch) and
/// released immediately on error. This ensures:
/// 1. No buffer held during backoff sleep (would starve other workers)
/// 2. Failed fetches release buffers for retry or other files
///
/// # Retry Strategy
///
/// Each chunk fetch is retried independently. If a chunk fails permanently,
/// the entire object is marked failed (no partial results).
#[allow(clippy::too_many_arguments)]
fn io_worker_loop<B: RemoteBackend>(
    wid: usize,
    backend: Arc<B>,
    rx: chan::Receiver<ObjectWork<B::Object>>,
    pool: TsBufferPool,
    cpu: ExecutorHandle<CpuTask>,
    cfg: RemoteConfig,
    overlap: usize,
    stop: Arc<AtomicBool>,
) -> IoStats {
    let mut stats = IoStats::default();
    let mut rng = XorShift64::new(cfg.seed ^ ((wid as u64).wrapping_mul(0xD1B54A32D192ED03)));

    while let Ok(work) = rx.recv() {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        perf_stats::sat_add_u64(&mut stats.objects_started, 1);
        let started = Instant::now();

        let size = work.size;
        let chunk = cfg.chunk_size as u64;

        // Offset of new bytes (payload start)
        let mut offset: u64 = 0;
        let mut failed = false;

        'chunk_loop: while offset < size {
            if stop.load(Ordering::Relaxed) {
                failed = true;
                break;
            }

            // Check object time budget before starting chunk
            let time_remaining = if let Some(limit) = cfg.max_object_time {
                let elapsed = started.elapsed();
                if elapsed >= limit {
                    failed = true;
                    break;
                }
                Some(limit - elapsed)
            } else {
                None
            };

            // Range calculation: [base_offset, base_offset + prefix_len + payload_len)
            let base_offset = offset.saturating_sub(overlap as u64);
            let prefix_len = (offset - base_offset) as usize;
            let payload_len = (size - offset).min(chunk) as usize;
            let request_len = prefix_len + payload_len;

            // Retry loop - buffer acquired INSIDE, dropped before sleep
            let mut attempt: u32 = 0;

            loop {
                attempt += 1;

                // Check stop before each attempt
                if stop.load(Ordering::Relaxed) {
                    failed = true;
                    break 'chunk_loop;
                }

                // Acquire buffer just-in-time (not held during backoff sleep)
                let mut buf = match acquire_buffer_blocking(&pool, &stop) {
                    Some(b) => b,
                    None => {
                        failed = true;
                        break 'chunk_loop;
                    }
                };

                let dst = &mut buf.as_mut_slice()[..request_len];

                match backend.fetch_range(&work.handle, base_offset, dst) {
                    Ok(fetched) => {
                        // Validate fetch result per contract:
                        // - fetched == request_len: normal case (got all requested bytes)
                        // - fetched < request_len: only valid if we reached actual EOF
                        // - fetched == 0: unexpected (we calculated request based on size)

                        if fetched == 0 {
                            // Unexpected EOF before expected position
                            failed = true;
                            drop(buf);
                            break 'chunk_loop;
                        }

                        // Check for partial reads
                        if fetched < request_len {
                            // Partial read - only valid if we've reached actual EOF
                            let end_offset = base_offset + fetched as u64;
                            if end_offset != size {
                                // Partial read that doesn't reach EOF = contract violation
                                // Backend should have either filled exactly or returned error
                                perf_stats::sat_add_u64(&mut stats.permanent_errors, 1);
                                failed = true;
                                drop(buf);
                                break 'chunk_loop;
                            }
                            // else: valid final partial (reached EOF)
                        }

                        // Calculate actual payload (may be less than planned on final chunk)
                        let actual_payload = fetched.saturating_sub(prefix_len);

                        // Enqueue scan task (buffer ownership transfers to CPU side)
                        if cpu
                            .spawn(CpuTask::ScanChunk {
                                token: Arc::clone(&work.token),
                                base_offset,
                                prefix_len: prefix_len as u32,
                                len: fetched as u32,
                                buf,
                            })
                            .is_err()
                        {
                            // Executor closed
                            stop.store(true, Ordering::Relaxed);
                            failed = true;
                            break 'chunk_loop;
                        }

                        perf_stats::sat_add_u64(&mut stats.chunks_fetched, 1);
                        perf_stats::sat_add_u64(
                            &mut stats.payload_bytes_fetched,
                            actual_payload as u64,
                        );

                        // Advance by actual payload, not planned
                        offset = offset.saturating_add(actual_payload as u64);
                        break; // Success, exit retry loop
                    }
                    Err(err) => {
                        // Drop buffer BEFORE sleeping or breaking
                        drop(buf);

                        match backend.classify_error(&err) {
                            ErrorClass::Permanent => {
                                perf_stats::sat_add_u64(&mut stats.permanent_errors, 1);
                                failed = true;
                                break 'chunk_loop;
                            }
                            ErrorClass::Retryable => {
                                perf_stats::sat_add_u64(&mut stats.retryable_errors, 1);
                                if attempt >= cfg.retry.max_attempts {
                                    failed = true;
                                    break 'chunk_loop;
                                }

                                // Compute backoff
                                let backoff = compute_backoff(attempt, cfg.retry, &mut rng);

                                // Check if sleeping would exceed time budget
                                if let Some(remaining) = time_remaining {
                                    let elapsed_since_chunk_start = started
                                        .elapsed()
                                        .saturating_sub(cfg.max_object_time.unwrap() - remaining);
                                    if elapsed_since_chunk_start + backoff > remaining {
                                        // Would exceed budget; fail now
                                        failed = true;
                                        break 'chunk_loop;
                                    }
                                }

                                perf_stats::sat_add_u64(&mut stats.retries, 1);
                                std::thread::sleep(backoff);
                                continue; // Retry (will re-acquire buffer)
                            }
                        }
                    }
                }
            }
        }

        if failed {
            perf_stats::sat_add_u64(&mut stats.objects_failed, 1);
            // work.token dropped here; permit releases when all enqueued chunks finish
        } else {
            perf_stats::sat_add_u64(&mut stats.objects_completed, 1);
        }
    }

    stats
}

// ============================================================================
// Entry Point
// ============================================================================

/// Run remote scanning pipeline.
///
/// # Arguments
///
/// - `engine`: Detection engine (determines overlap, provides scan logic)
/// - `backend`: Remote data source implementation
/// - `cfg`: Pipeline configuration
/// - `out`: Output sink for findings
///
/// # Returns
///
/// `(RemoteRunReport, MetricsSnapshot)` on success.
///
/// # Errors
///
/// - `RemoteRunError::List(e)`: Error during object listing
/// - `RemoteRunError::IoThreadPanicked`: An I/O thread panicked
///
/// # Example
///
/// ```ignore
/// let engine = Arc::new(MockEngine::new(rules, 16));
/// let backend = Arc::new(MyS3Backend::new(bucket));
/// let sink = Arc::new(VecSink::new());
///
/// let (report, metrics) = scan_remote(engine, backend, RemoteConfig::default(), sink)?;
/// ```
pub fn scan_remote<B: RemoteBackend>(
    engine: Arc<MockEngine>,
    backend: Arc<B>,
    cfg: RemoteConfig,
    out: Arc<dyn OutputSink>,
) -> Result<(RemoteRunReport, MetricsSnapshot), RemoteRunError<B::Error>> {
    cfg.validate(&engine);

    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    // Buffer pool shared between CPU workers and I/O threads.
    // Use minimal worker config (workers=1, local_queue_cap=1) since I/O
    // threads use global queue directly - the pool primarily tracks
    // buffer lifecycle rather than worker-local caching.
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: cfg.pool_buffers,
        workers: 1,
        local_queue_cap: 1,
    });

    let object_budget = Arc::new(CountBudget::new(cfg.max_in_flight_objects));

    // CPU executor for scanning
    let ex = Executor::<CpuTask>::new(
        ExecutorConfig {
            workers: cfg.cpu_workers,
            seed: cfg.seed,
            ..ExecutorConfig::default()
        },
        {
            let engine = Arc::clone(&engine);
            let out = Arc::clone(&out);
            let dedupe = cfg.dedupe_within_chunk;
            move |_wid| CpuScratch {
                engine: Arc::clone(&engine),
                out: Arc::clone(&out),
                scratch: engine.new_scratch(),
                pending: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
                out_buf: Vec::with_capacity(64 * 1024),
                dedupe_within_chunk: dedupe,
            }
        },
        cpu_runner,
    );

    let cpu_handle = ex.handle();

    // Bounded channel for discovery â†’ I/O backpressure
    let (tx, rx) = chan::bounded::<ObjectWork<B::Object>>(cfg.object_queue_cap);
    let stop = Arc::new(AtomicBool::new(false));

    // Spawn I/O threads
    let mut io_threads = Vec::with_capacity(cfg.io_threads);
    for wid in 0..cfg.io_threads {
        let backend = Arc::clone(&backend);
        let rx = rx.clone();
        let pool = pool.clone();
        let cpu = cpu_handle.clone();
        let cfg2 = cfg.clone();
        let stop2 = Arc::clone(&stop);

        io_threads.push(thread::spawn(move || {
            io_worker_loop(wid, backend, rx, pool, cpu, cfg2, overlap, stop2)
        }));
    }
    drop(rx); // Close our receiver; only I/O threads hold receivers now

    // Discovery loop (single thread for now)
    let mut report = RemoteRunReport::default();
    let mut cursor = B::Cursor::default();
    let mut next_file_id: u32 = 0;

    'discovery: loop {
        // Check stop before listing
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let page = backend
            .list_page(&mut cursor, cfg.discover_batch)
            .map_err(RemoteRunError::List)?;

        if page.is_empty() {
            break;
        }

        for obj in page {
            report.remote.objects_discovered += 1;

            // Check stop flag before acquiring permit
            if stop.load(Ordering::Relaxed) {
                break 'discovery;
            }

            // Acquire in-flight permit (blocks if at limit)
            let permit = object_budget.acquire(1);

            let file_id = FileId(next_file_id);
            next_file_id = next_file_id.checked_add(1).expect("FileId overflow");

            let token = Arc::new(ObjectToken {
                _permit: permit,
                file_id,
                display: obj.display.into_boxed_slice().into(),
            });

            let mut work = Some(ObjectWork {
                handle: obj.handle,
                size: obj.size,
                token,
            });

            // Send with timeout loop to check stop while waiting
            // This prevents deadlock if I/O threads exit while queue is full
            loop {
                if stop.load(Ordering::Relaxed) {
                    break 'discovery;
                }

                // Take the work item for this send attempt
                let w = work.take().expect("work already sent");

                match tx.send_timeout(w, Duration::from_millis(100)) {
                    Ok(()) => {
                        report.remote.objects_enqueued += 1;
                        break; // Success, exit send loop
                    }
                    Err(chan::SendTimeoutError::Timeout(returned)) => {
                        // Queue full, put work back and retry after checking stop
                        work = Some(returned);
                        continue;
                    }
                    Err(chan::SendTimeoutError::Disconnected(_)) => {
                        // I/O threads have all exited (channel disconnected)
                        // This is not necessarily an error - could be stop triggered
                        break 'discovery;
                    }
                }
            }
        }
    }

    // Close sender to signal I/O threads to drain and exit
    drop(tx);

    // Join I/O threads and merge stats
    for t in io_threads {
        let s = t.join().map_err(|_| RemoteRunError::IoThreadPanicked)?;
        report.io.merge(s);
    }

    // All I/O work done; join CPU executor
    let cpu_metrics = ex.join();

    out.flush();

    Ok((report, cpu_metrics))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::engine_stub::MockRule;
    use crate::scheduler::output_sink::VecSink;

    // ========================================================================
    // Mock Backend
    // ========================================================================

    #[derive(Clone)]
    struct MockObj {
        key: Vec<u8>,
        data: Vec<u8>,
    }

    struct MockBackend {
        objs: Vec<MockObj>,
    }

    #[derive(Default)]
    struct MockCursor {
        i: usize,
    }

    impl RemoteBackend for MockBackend {
        type Object = MockObj;
        type Cursor = MockCursor;
        type Error = &'static str;

        fn list_page(
            &self,
            cursor: &mut Self::Cursor,
            max: usize,
        ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
            if cursor.i >= self.objs.len() {
                return Ok(Vec::new());
            }
            let end = (cursor.i + max).min(self.objs.len());
            let mut out = Vec::with_capacity(end - cursor.i);
            for j in cursor.i..end {
                let o = self.objs[j].clone();
                out.push(RemoteObject {
                    handle: o.clone(),
                    size: o.data.len() as u64,
                    display: o.key.clone(),
                });
            }
            cursor.i = end;
            Ok(out)
        }

        fn fetch_range(
            &self,
            obj: &Self::Object,
            start: u64,
            dst: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let s = start as usize;
            if s >= obj.data.len() {
                return Ok(0);
            }
            let end = (s + dst.len()).min(obj.data.len());
            let n = end - s;
            dst[..n].copy_from_slice(&obj.data[s..end]);
            Ok(n)
        }

        fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
            ErrorClass::Permanent
        }
    }

    // ========================================================================
    // Retryable Mock Backend
    // ========================================================================

    struct RetryBackend {
        obj: MockObj,
        fail_first_n: std::sync::atomic::AtomicU32,
    }

    impl RemoteBackend for RetryBackend {
        type Object = ();
        type Cursor = bool; // true = done
        type Error = &'static str;

        fn list_page(
            &self,
            cursor: &mut Self::Cursor,
            _max: usize,
        ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
            if *cursor {
                return Ok(Vec::new());
            }
            *cursor = true;
            Ok(vec![RemoteObject {
                handle: (),
                size: self.obj.data.len() as u64,
                display: self.obj.key.clone(),
            }])
        }

        fn fetch_range(
            &self,
            _obj: &Self::Object,
            start: u64,
            dst: &mut [u8],
        ) -> Result<usize, Self::Error> {
            // Fail first N attempts
            let remaining = self.fail_first_n.load(Ordering::Relaxed);
            if remaining > 0 {
                self.fail_first_n.fetch_sub(1, Ordering::Relaxed);
                return Err("transient failure");
            }

            let s = start as usize;
            if s >= self.obj.data.len() {
                return Ok(0);
            }
            let end = (s + dst.len()).min(self.obj.data.len());
            let n = end - s;
            dst[..n].copy_from_slice(&self.obj.data[s..end]);
            Ok(n)
        }

        fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
            ErrorClass::Retryable
        }
    }

    // ========================================================================
    // Helper
    // ========================================================================

    fn test_engine(overlap: usize) -> MockEngine {
        MockEngine::new(
            vec![MockRule {
                name: "secret".to_string(),
                pattern: b"SECRET".to_vec(),
            }],
            overlap,
        )
    }

    fn small_config() -> RemoteConfig {
        RemoteConfig {
            cpu_workers: 2,
            io_threads: 2,
            chunk_size: 64,
            max_in_flight_objects: 16,
            object_queue_cap: 8,
            discover_batch: 8,
            pool_buffers: 8,
            retry: RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(10),
                jitter_pct: 10,
            },
            max_object_time: Some(Duration::from_secs(5)),
            seed: 42,
            dedupe_within_chunk: true,
        }
    }

    // ========================================================================
    // Tests
    // ========================================================================

    #[test]
    fn remote_pipeline_finds_secret() {
        let engine = Arc::new(test_engine(16));
        let backend = Arc::new(MockBackend {
            objs: vec![MockObj {
                key: b"obj-1".to_vec(),
                data: b"hello SECRET world".to_vec(),
            }],
        });
        let sink = Arc::new(VecSink::new());

        let (report, _metrics) =
            scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

        assert_eq!(report.remote.objects_discovered, 1);
        assert_eq!(report.remote.objects_enqueued, 1);
        assert_eq!(report.io.objects_completed, 1);

        let out = sink.take();
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("secret"), "output: {}", out_str);
        assert!(out_str.contains("obj-1"), "output: {}", out_str);
    }

    #[test]
    fn remote_pipeline_handles_boundary_spanning_secret() {
        // Force SECRET to span chunk boundary
        // chunk_size=8, overlap=6 means SECRET (6 bytes) can span
        let engine = Arc::new(test_engine(6));

        // Position SECRET so it starts near end of first chunk
        // First chunk: bytes 0-7, second chunk: bytes 2-9 (overlap=6)
        let data = b"xxSECRETyy"; // SECRET at positions 2-7

        let backend = Arc::new(MockBackend {
            objs: vec![MockObj {
                key: b"boundary-test".to_vec(),
                data: data.to_vec(),
            }],
        });
        let sink = Arc::new(VecSink::new());

        let cfg = RemoteConfig {
            chunk_size: 8,
            ..small_config()
        };

        let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

        assert_eq!(report.io.objects_completed, 1);

        let out = sink.take();
        let out_str = String::from_utf8_lossy(&out);

        // Note: With overlapping chunks, the same secret may be found in multiple
        // chunks. The current implementation only deduplicates within each chunk
        // (dedupe_within_chunk), not across chunks. Cross-chunk deduplication
        // would require a global findings collector which isn't implemented
        // for the remote scanner.
        //
        // For now, we verify the secret is found at least once.
        let count = out_str.matches("secret").count();
        assert!(
            count >= 1,
            "expected at least 1 finding, got {}: {}",
            count,
            out_str
        );
    }

    #[test]
    fn remote_pipeline_handles_empty_backend() {
        let engine = Arc::new(test_engine(16));
        let backend = Arc::new(MockBackend { objs: vec![] });
        let sink = Arc::new(VecSink::new());

        let (report, _metrics) =
            scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

        assert_eq!(report.remote.objects_discovered, 0);
        assert_eq!(report.io.objects_completed, 0);
    }

    #[test]
    fn remote_pipeline_processes_multiple_objects() {
        let engine = Arc::new(test_engine(16));

        let objs: Vec<MockObj> = (0..10)
            .map(|i| MockObj {
                key: format!("obj-{}", i).into_bytes(),
                data: format!("file {} has SECRET here", i).into_bytes(),
            })
            .collect();

        let backend = Arc::new(MockBackend { objs });
        let sink = Arc::new(VecSink::new());

        let (report, _metrics) =
            scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

        assert_eq!(report.remote.objects_discovered, 10);
        assert_eq!(report.io.objects_completed, 10);

        let out = sink.take();
        let out_str = String::from_utf8_lossy(&out);

        // Should find 10 secrets
        let count = out_str.matches("secret").count();
        assert_eq!(count, 10, "expected 10 findings, got {}", count);
    }

    #[test]
    fn remote_pipeline_retries_transient_failures() {
        let engine = Arc::new(test_engine(16));

        let backend = Arc::new(RetryBackend {
            obj: MockObj {
                key: b"retry-obj".to_vec(),
                data: b"data with SECRET".to_vec(),
            },
            fail_first_n: std::sync::atomic::AtomicU32::new(2), // Fail twice, succeed on third
        });

        let sink = Arc::new(VecSink::new());

        let cfg = RemoteConfig {
            retry: RetryPolicy {
                max_attempts: 5,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                jitter_pct: 0,
            },
            ..small_config()
        };

        let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

        assert_eq!(report.io.objects_completed, 1);
        assert_eq!(report.io.retryable_errors, 2);
        assert_eq!(report.io.retries, 2);

        let out = sink.take();
        assert!(
            !out.is_empty(),
            "should have found the secret after retries"
        );
    }

    #[test]
    fn backoff_respects_max_delay() {
        let policy = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            jitter_pct: 0,
        };
        let mut rng = XorShift64::new(1);

        // After many attempts, delay should be capped at max_delay
        let d = compute_backoff(10, policy, &mut rng);
        assert_eq!(d, Duration::from_millis(500));
    }

    #[test]
    fn backoff_applies_jitter() {
        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter_pct: 50,
        };

        let mut rng = XorShift64::new(42);

        // Collect several backoff values and verify they vary
        let values: Vec<Duration> = (0..10)
            .map(|_| compute_backoff(2, policy, &mut rng))
            .collect();

        // Base delay for attempt 2 is 200ms, jitter is Â±50% = Â±100ms
        // So values should be in [100ms, 300ms]
        for d in &values {
            assert!(
                *d >= Duration::from_millis(100) && *d <= Duration::from_millis(300),
                "backoff {} out of expected range",
                d.as_millis()
            );
        }

        // Values should not all be identical (jitter working)
        let unique: std::collections::HashSet<_> = values.iter().map(|d| d.as_nanos()).collect();
        assert!(unique.len() > 1, "jitter should produce varying values");
    }

    #[test]
    fn config_validation_rejects_invalid() {
        let engine = test_engine(16);

        // chunk_size + overlap > BUFFER_LEN_MAX
        let cfg = RemoteConfig {
            chunk_size: BUFFER_LEN_MAX,
            ..Default::default()
        };

        let result = std::panic::catch_unwind(|| cfg.validate(&engine));
        assert!(result.is_err(), "should panic on oversized chunk");
    }

    // ========================================================================
    // Partial Read Backend (contract violation test)
    // ========================================================================

    struct PartialReadBackend {
        obj: MockObj,
        /// Return only this many bytes per read (to simulate partial reads)
        bytes_per_read: usize,
    }

    impl RemoteBackend for PartialReadBackend {
        type Object = ();
        type Cursor = bool;
        type Error = &'static str;

        fn list_page(
            &self,
            cursor: &mut Self::Cursor,
            _max: usize,
        ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
            if *cursor {
                return Ok(Vec::new());
            }
            *cursor = true;
            Ok(vec![RemoteObject {
                handle: (),
                size: self.obj.data.len() as u64,
                display: self.obj.key.clone(),
            }])
        }

        fn fetch_range(
            &self,
            _obj: &Self::Object,
            start: u64,
            dst: &mut [u8],
        ) -> Result<usize, Self::Error> {
            let s = start as usize;
            if s >= self.obj.data.len() {
                return Ok(0);
            }
            // Intentionally return partial read (violates contract)
            let max_read = self.bytes_per_read.min(dst.len());
            let end = (s + max_read).min(self.obj.data.len());
            let n = end - s;
            dst[..n].copy_from_slice(&self.obj.data[s..end]);
            Ok(n)
        }

        fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
            ErrorClass::Permanent
        }
    }

    #[test]
    fn partial_reads_cause_object_failure() {
        // This test verifies that partial reads (contract violations) are detected
        // and cause the object to fail rather than silently skipping bytes.
        let engine = Arc::new(test_engine(16));

        // Backend returns only 17 bytes per read, but we request more
        let backend = Arc::new(PartialReadBackend {
            obj: MockObj {
                key: b"partial-test".to_vec(),
                data: b"lots of data here with SECRET somewhere".to_vec(),
            },
            bytes_per_read: 17,
        });

        let sink = Arc::new(VecSink::new());

        let cfg = RemoteConfig {
            chunk_size: 64, // Larger than bytes_per_read
            ..small_config()
        };

        let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

        // Object should fail because partial reads violate the contract
        assert_eq!(
            report.io.objects_failed, 1,
            "partial reads should cause object failure"
        );
        assert_eq!(report.io.objects_completed, 0);
    }

    // ========================================================================
    // Permanent Error Backend
    // ========================================================================

    struct PermanentErrorBackend {
        obj: MockObj,
    }

    impl RemoteBackend for PermanentErrorBackend {
        type Object = ();
        type Cursor = bool;
        type Error = &'static str;

        fn list_page(
            &self,
            cursor: &mut Self::Cursor,
            _max: usize,
        ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
            if *cursor {
                return Ok(Vec::new());
            }
            *cursor = true;
            Ok(vec![RemoteObject {
                handle: (),
                size: self.obj.data.len() as u64,
                display: self.obj.key.clone(),
            }])
        }

        fn fetch_range(
            &self,
            _obj: &Self::Object,
            _start: u64,
            _dst: &mut [u8],
        ) -> Result<usize, Self::Error> {
            // Always return permanent error
            Err("permanent failure")
        }

        fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
            ErrorClass::Permanent
        }
    }

    #[test]
    fn permanent_errors_cause_immediate_failure() {
        let engine = Arc::new(test_engine(16));

        let backend = Arc::new(PermanentErrorBackend {
            obj: MockObj {
                key: b"perm-error-test".to_vec(),
                data: b"data with SECRET".to_vec(),
            },
        });

        let sink = Arc::new(VecSink::new());

        let (report, _metrics) =
            scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

        assert_eq!(report.io.objects_failed, 1);
        assert_eq!(report.io.objects_completed, 0);
        assert_eq!(report.io.permanent_errors, 1);
        // No retries for permanent errors
        assert_eq!(report.io.retries, 0);
    }

    #[test]
    fn retryable_errors_exhaust_attempts() {
        let engine = Arc::new(test_engine(16));

        // Fail more times than max_attempts to ensure exhaustion
        let backend = Arc::new(RetryBackend {
            obj: MockObj {
                key: b"retry-exhaust".to_vec(),
                data: b"data with SECRET".to_vec(),
            },
            fail_first_n: std::sync::atomic::AtomicU32::new(100), // More than max_attempts
        });

        let sink = Arc::new(VecSink::new());

        let cfg = RemoteConfig {
            retry: RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                jitter_pct: 0,
            },
            ..small_config()
        };

        let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

        assert_eq!(report.io.objects_failed, 1);
        assert_eq!(report.io.objects_completed, 0);
        // Should have 3 retryable errors (initial + 2 retries)
        assert_eq!(report.io.retryable_errors, 3);
        // Retries = attempts - 1 = 2
        assert_eq!(report.io.retries, 2);
    }
}
