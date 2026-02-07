//! Local Filesystem Scanner with io_uring
//!
//! # Architecture
//!
//! - I/O threads use io_uring for async reads
//! - CPU threads run the work-stealing executor for scanning
//! - Buffer ownership transfers: I/O thread acquires, CPU thread releases
//! - Overlap bytes are carried in-memory between chunks (payload-only reads)
//!
//! # Why io_uring?
//!
//! - High concurrency on cold storage (NVMe, network mounts)
//! - Batched syscalls reduce kernel overhead
//! - CPU workers never block on I/O
//!
//! # Correctness Guarantees
//!
//! - **Work-conserving**: Backpressure delays discovery, never drops files
//! - **Chunk overlap**: `engine.required_overlap()` bytes overlap between chunks
//! - **Budget bounded**: `max_in_flight_files` limits discovered-but-not-complete files
//! - **Buffer bounded**: `pool_buffers` limits peak memory
//! - **Exactly-once per chunk**: No duplicate scans
//!
//! # When to Use
//!
//! Profile first! io_uring may be slower than blocking reads when:
//! - Everything is in page cache
//! - Files are tiny (syscall overhead dominates)
//!
//! io_uring tends to win on:
//! - Cold cache workloads
//! - High-latency storage (network mounts)
//! - Many concurrent files
//!
//! # Platform
//!
//! Linux-only. Feature-gated behind `io-uring` feature.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use super::count_budget::{CountBudget, CountPermit};
use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use super::executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
use super::local::LocalFile;
use super::local_fs_sharded::{
    acquire_buffer_with_backoff, push_with_backoff, shard_scan_loop, ScanChunk, ShardFileWork,
    ShardIoStats, ShardScanStats, ShardedFsReport, SHARD_SPSC_CAP, SNIFF_HEADER_LEN, SPIN_ITERS,
};
use super::metrics::MetricsSnapshot;
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::perf_stats;
use crate::scheduler::affinity::pin_current_thread_to_core;
use crate::stdx::spsc::{spsc_channel, OwnedSpscProducer};
use crate::unified::events::{EventSink, FindingEvent, ScanEvent};
use crate::unified::SourceKind;

use crossbeam_channel as chan;
use crossbeam_queue::ArrayQueue;

use io_uring::{opcode, types, IoUring, Probe};

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// ============================================================================
// Configuration
// ============================================================================

/// Open/stat execution mode for io_uring file setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum OpenStatMode {
    /// Default: use io_uring open/stat when supported, otherwise fallback.
    #[default]
    UringPreferred,
    /// Force blocking open + fstat path (parity/debug).
    BlockingOnly,
    /// Require io_uring open/stat; error if unsupported.
    UringRequired,
}

/// Path resolution policy for openat2 when available.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum ResolvePolicy {
    /// Default: no path resolution constraints (match current behavior).
    #[default]
    Default,
    /// Disallow symlink traversal in all components (opt-in).
    NoSymlinks,
    /// Restrict traversal beneath dirfd root (requires dirfd strategy).
    BeneathRoot,
}

/// Configuration for local FS scanning using io_uring I/O threads + CPU executor scan threads.
#[derive(Clone, Debug)]
pub struct LocalFsUringConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,

    /// Number of I/O threads running io_uring.
    pub io_threads: usize,

    /// Number of SQ/CQ entries per io_uring.
    pub ring_entries: u32,

    /// Max in-flight ops per I/O thread (reads + open/stat).
    /// Must be <= ring_entries - 1.
    pub io_depth: usize,

    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,

    /// Hard cap on in-flight files (discovered, queued, or scanning).
    pub max_in_flight_files: usize,

    /// Bounded queue from discovery -> I/O threads.
    pub file_queue_cap: usize,

    /// Total buffers in the global pool.
    ///
    /// This bounds:
    /// - in-flight reads (each holds a buffer)
    /// - queued scan tasks (each holds a buffer)
    pub pool_buffers: usize,

    /// Use io_uring registered buffers (`READ_FIXED`) for reads.
    ///
    /// This can reduce per-op overhead for high-IOPS workloads, but requires
    /// registering all buffers up-front and limits the pool size to `u16::MAX`.
    pub use_registered_buffers: bool,

    /// Open/stat execution mode for io_uring file setup.
    pub open_stat_mode: OpenStatMode,

    /// Path resolution policy for openat2 (ignored when unsupported).
    pub resolve_policy: ResolvePolicy,

    /// Follow symbolic links during discovery.
    pub follow_symlinks: bool,

    /// Skip files larger than this (None = no limit).
    pub max_file_size: Option<u64>,

    /// Seed for deterministic executor behavior.
    pub seed: u64,

    /// Deduplicate findings within each chunk.
    pub dedupe_within_chunk: bool,
}

impl Default for LocalFsUringConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            io_threads: 4,
            ring_entries: 256,
            io_depth: 128,
            chunk_size: 256 * 1024,
            max_in_flight_files: 512,
            file_queue_cap: 256,
            pool_buffers: 256,
            use_registered_buffers: false,
            open_stat_mode: OpenStatMode::default(),
            resolve_policy: ResolvePolicy::default(),
            follow_symlinks: false,
            max_file_size: None,
            seed: 1,
            dedupe_within_chunk: true,
        }
    }
}

impl LocalFsUringConfig {
    /// Validate configuration against engine requirements.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid.
    pub fn validate<E: ScanEngine>(&self, engine: &E) {
        assert!(self.cpu_workers > 0, "cpu_workers must be > 0");
        assert!(self.io_threads > 0, "io_threads must be > 0");
        assert!(self.ring_entries >= 8, "ring_entries must be >= 8");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(
            self.max_in_flight_files > 0,
            "max_in_flight_files must be > 0"
        );
        assert!(self.file_queue_cap > 0, "file_queue_cap must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        if self.use_registered_buffers {
            assert!(
                self.pool_buffers <= u16::MAX as usize,
                "pool_buffers ({}) must be <= u16::MAX for registered buffers",
                self.pool_buffers
            );
        }

        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(self.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
            buf_len,
            BUFFER_LEN_MAX
        );

        let max_depth = (self.ring_entries as usize).saturating_sub(1);
        assert!(self.io_depth > 0, "io_depth must be > 0");
        assert!(
            self.io_depth <= max_depth,
            "io_depth ({}) must be <= ring_entries - 1 ({})",
            self.io_depth,
            max_depth
        );

        // Buffer pool must be large enough to not guarantee starvation.
        // Minimum: each I/O thread can saturate io_depth.
        // Additional headroom for CPU task pipeline recommended but not required.
        let min_pool = self.io_threads.saturating_mul(self.io_depth);
        assert!(
            self.pool_buffers >= min_pool,
            "pool_buffers ({}) must be >= io_threads * io_depth ({}) to avoid starvation",
            self.pool_buffers,
            min_pool
        );
    }
}

// ============================================================================
// Summary Counters
// ============================================================================

/// Discovery and I/O counters (no identifiers logged for security).
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalFsSummary {
    pub files_seen: u64,
    pub files_enqueued: u64,
    pub walk_errors: u64,
    pub open_errors: u64,
    pub read_errors: u64,
    pub files_skipped_size: u64,
}

/// Per-I/O-thread counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct UringIoStats {
    pub files_started: u64,
    pub files_open_failed: u64,
    pub open_ops_submitted: u64,
    pub open_ops_completed: u64,
    pub stat_ops_submitted: u64,
    pub stat_ops_completed: u64,
    pub open_failures: u64,
    pub stat_failures: u64,
    pub open_stat_fallbacks: u64,
    pub reads_submitted: u64,
    pub reads_completed: u64,
    pub read_errors: u64,
    pub short_reads: u64,
}

// ============================================================================
// Fixed Buffer Pool (io_uring READ_FIXED)
// ============================================================================

/// Fixed buffer pool backed by a stable buffer table.
///
/// Buffers are allocated once and never moved, allowing safe registration with
/// io_uring via `register_buffers`. Handles return buffers to a global free
/// queue on drop.
struct FixedBufferPool {
    buffer_len: usize,
    buffers: Vec<Box<[u8]>>,
    free: ArrayQueue<usize>,
}

impl FixedBufferPool {
    fn new(buffer_len: usize, total: usize) -> Arc<Self> {
        let mut buffers = Vec::with_capacity(total);
        for _ in 0..total {
            buffers.push(vec![0u8; buffer_len].into_boxed_slice());
        }

        let free = ArrayQueue::new(total);
        for idx in 0..total {
            free.push(idx).expect("fixed buffer free queue overflow");
        }

        Arc::new(Self {
            buffer_len,
            buffers,
            free,
        })
    }

    #[inline]
    fn buffer_len(&self) -> usize {
        self.buffer_len
    }

    #[inline]
    fn try_acquire(self: &Arc<Self>) -> Option<FixedBufferHandle> {
        self.free.pop().map(|index| FixedBufferHandle {
            pool: Arc::clone(self),
            index,
        })
    }

    /// Builds iovec list for `register_buffers`.
    ///
    /// The returned iovecs borrow the pool's heap buffers. The pool
    /// must outlive the io_uring registration (call `unregister_buffers`
    /// before dropping the pool).
    fn iovecs(&self) -> Vec<libc::iovec> {
        self.buffers
            .iter()
            .map(|buf| libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            })
            .collect()
    }

    #[inline]
    fn buf_ptr(&self, index: usize) -> *mut u8 {
        self.buffers[index].as_ptr() as *mut u8
    }

    #[inline]
    fn buf_len(&self, index: usize) -> usize {
        self.buffers[index].len()
    }
}

struct FixedBufferHandle {
    pool: Arc<FixedBufferPool>,
    index: usize,
}

impl FixedBufferHandle {
    #[inline]
    fn buf_index(&self) -> u16 {
        self.index as u16
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.pool.buffers[self.index]
    }

    /// Mutable slice of the buffer.
    ///
    /// # Safety
    ///
    /// This uses `unsafe` to create a mutable slice from pooled storage.
    /// It is sound because each buffer index is owned by exactly one handle
    /// at a time (enforced by the free queue), and `&mut self` guarantees
    /// exclusive access to this handle.
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        let ptr = self.pool.buf_ptr(self.index);
        let len = self.pool.buf_len(self.index);
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }
}

impl Drop for FixedBufferHandle {
    fn drop(&mut self) {
        self.pool
            .free
            .push(self.index)
            .expect("fixed buffer free queue overflow");
    }
}

impl UringIoStats {
    fn merge(&mut self, other: UringIoStats) {
        self.files_started += other.files_started;
        self.files_open_failed += other.files_open_failed;
        self.open_ops_submitted += other.open_ops_submitted;
        self.open_ops_completed += other.open_ops_completed;
        self.stat_ops_submitted += other.stat_ops_submitted;
        self.stat_ops_completed += other.stat_ops_completed;
        self.open_failures += other.open_failures;
        self.stat_failures += other.stat_failures;
        self.open_stat_fallbacks += other.open_stat_fallbacks;
        self.reads_submitted += other.reads_submitted;
        self.reads_completed += other.reads_completed;
        self.read_errors += other.read_errors;
        self.short_reads += other.short_reads;
    }
}

// ============================================================================
// Internal Types
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct OpenStatCaps {
    /// IORING_OP_OPENAT supported.
    openat: bool,
    /// IORING_OP_OPENAT2 supported.
    openat2: bool,
    /// IORING_OP_STATX supported.
    statx: bool,
    /// Kernel guarantees submit-time parameter stability.
    submit_stable: bool,
}

impl OpenStatCaps {
    #[inline]
    fn supports_open_stat(&self) -> bool {
        (self.openat || self.openat2) && self.statx
    }
}

/// Map resolve policy to openat2 resolve bits (ignored when openat2 unsupported).
fn resolve_bits(policy: ResolvePolicy) -> u64 {
    match policy {
        ResolvePolicy::Default => 0,
        ResolvePolicy::NoSymlinks => libc::RESOLVE_NO_SYMLINKS,
        ResolvePolicy::BeneathRoot => libc::RESOLVE_BENEATH,
    }
}

fn probe_uring_caps(ring: &IoUring) -> io::Result<OpenStatCaps> {
    // Probe opcode availability and submit-stable behavior once per ring.
    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe)?;

    Ok(OpenStatCaps {
        openat: probe.is_supported(opcode::OpenAt::CODE),
        openat2: probe.is_supported(opcode::OpenAt2::CODE),
        statx: probe.is_supported(opcode::Statx::CODE),
        submit_stable: ring.params().is_feature_submit_stable(),
    })
}

/// Token that holds the in-flight file permit until all chunk tasks complete.
struct FileToken {
    _permit: CountPermit,
    file_id: FileId,
    /// Path bytes for output (no heap allocation per finding).
    display: Arc<[u8]>,
}

/// Work item for I/O threads.
struct FileWork {
    path: PathBuf,
    size: u64,
    token: Arc<FileToken>,
}

/// CPU task type for the executor.
enum CpuTask {
    ScanChunk {
        token: Arc<FileToken>,
        base_offset: u64,
        prefix_len: u32,
        len: u32,
        buf: FixedBufferHandle,
    },
}

/// Per-CPU-worker scratch space.
struct CpuScratch<E: ScanEngine> {
    engine: Arc<E>,
    event_sink: Arc<dyn EventSink>,
    scratch: E::Scratch,
    pending: Vec<<E::Scratch as EngineScratch>::Finding>,
    dedupe_within_chunk: bool,
}

// ============================================================================
// Deduplication Helpers
// ============================================================================

/// In-place dedupe of findings by (rule_id, root_hint, span).
fn dedupe_pending_in_place<F: FindingRecord>(p: &mut Vec<F>) {
    if p.len() <= 1 {
        return;
    }

    p.sort_unstable_by_key(|f| {
        (
            f.rule_id(),
            f.root_hint_start(),
            f.root_hint_end(),
            f.span_start(),
            f.span_end(),
        )
    });

    p.dedup_by(|a, b| {
        a.rule_id() == b.rule_id()
            && a.root_hint_start() == b.root_hint_start()
            && a.root_hint_end() == b.root_hint_end()
            && a.span_start() == b.span_start()
            && a.span_end() == b.span_end()
    });
}

/// Emit findings as structured events.
fn emit_findings<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    event_sink: &dyn EventSink,
    display: &[u8],
    recs: &[F],
) {
    if recs.is_empty() {
        return;
    }

    for rec in recs {
        event_sink.emit(ScanEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: display,
            start: rec.root_hint_start(),
            end: rec.root_hint_end(),
            rule_id: rec.rule_id(),
            rule_name: engine.rule_name(rec.rule_id()),
            commit_id: None,
            change_kind: None,
        }));
    }
}

// ============================================================================
// CPU Task Runner
// ============================================================================

fn cpu_runner<E: ScanEngine>(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch<E>>) {
    match task {
        CpuTask::ScanChunk {
            token,
            base_offset,
            prefix_len,
            len,
            buf,
        } => {
            let engine = ctx.scratch.engine.as_ref();

            let len_usize = len as usize;
            let data = &buf.as_slice()[..len_usize];

            engine.scan_chunk_into(data, token.file_id, base_offset, &mut ctx.scratch.scratch);

            // Drop findings fully contained in prefix (overlap region).
            let new_bytes_start = base_offset + prefix_len as u64;
            ctx.scratch.scratch.drop_prefix_findings(new_bytes_start);

            // CRITICAL: Clear pending before drain to avoid accumulating findings
            // across chunks. drain_findings_into uses append(), not replace.
            ctx.scratch.pending.clear();
            ctx.scratch
                .scratch
                .drain_findings_into(&mut ctx.scratch.pending);

            if ctx.scratch.dedupe_within_chunk {
                dedupe_pending_in_place(&mut ctx.scratch.pending);
            }

            emit_findings(
                engine,
                &*ctx.scratch.event_sink,
                &token.display,
                &ctx.scratch.pending,
            );

            // Metrics: payload bytes only (exclude overlap prefix).
            let payload = (len as u64).saturating_sub(prefix_len as u64);
            ctx.metrics.chunks_scanned = ctx.metrics.chunks_scanned.saturating_add(1);
            ctx.metrics.bytes_scanned = ctx.metrics.bytes_scanned.saturating_add(payload);

            // Buffer returns to pool on drop (RAII).
            drop(buf);
        }
    }
}

// ============================================================================
// I/O Worker State
// ============================================================================

/// Per-file state tracked by I/O worker.
///
/// # Invariants
///
/// - `in_flight` is 0 or 1 (single op in-flight per file)
/// - `done` is monotonic: once true, never reset to false
/// - `failed` is monotonic: once true, never reset to false
/// - `phase` only moves forward: PendingOpen → PendingStat → ReadyRead
struct FileState {
    phase: FilePhase,
    in_flight: u32,
    done: bool,
    failed: bool,
    token: Arc<FileToken>,
}

/// Phase-specific data for a file slot.
enum FilePhase {
    /// Path queued for open via io_uring (or fallback).
    PendingOpen { path: PathBuf },
    /// File opened; waiting on statx for size snapshot.
    PendingStat { file: Option<File> },
    /// Ready for read submissions with size + overlap tracking.
    Ready(ReadState),
}

struct ReadState {
    file: File,
    size: u64,
    next_offset: u64,
    overlap_buf: Box<[u8]>,
    overlap_len: usize,
}

/// Per-op state for completion matching.
///
/// # Lifetime Coupling
///
/// - `Open`: path + open_how must live until CQE is reaped
/// - `Stat`: statx buffer must live until CQE is reaped
/// - `Read`: buffer must live until CQE is reaped
enum Op {
    Open(OpenOp),
    Stat(StatOp),
    Read(ReadOp),
}

struct OpenOp {
    file_slot: usize,
    path: CString,
    open_how: Option<Box<types::OpenHow>>,
}

struct StatOp {
    file_slot: usize,
    statx_buf: Box<libc::statx>,
}

struct ReadOp {
    file_slot: usize,
    base_offset: u64,
    prefix_len: usize,
    payload_len: usize,
    buf: FixedBufferHandle,
}

// ============================================================================
// I/O Worker Loop
// ============================================================================

/// Drain all in-flight operations before returning.
///
/// Waits for every outstanding CQE and disposes of the associated `Op`.
/// For `Read` ops the `FixedBufferHandle` is dropped, returning it to the
/// pool. For `Open` ops with a successful result the returned fd is closed
/// to prevent leaks. No scan tasks are spawned — this is a shutdown path.
///
/// # Safety requirement
///
/// This MUST be called before dropping the ring/ops if any operations
/// are in-flight, otherwise the kernel may write to freed memory.
fn drain_in_flight(
    ring: &mut IoUring,
    ops: &mut [Option<Op>],
    in_flight_ops: &mut usize,
    stats: &mut UringIoStats,
) -> io::Result<()> {
    while *in_flight_ops > 0 {
        ring.submit_and_wait(1)?;

        for cqe in ring.completion() {
            let op_slot = cqe.user_data() as usize;

            if let Some(op) = ops.get_mut(op_slot).and_then(|o| o.take()) {
                let res = cqe.result();
                *in_flight_ops = in_flight_ops.saturating_sub(1);

                match op {
                    Op::Read(op) => {
                        // Buffer dropped here, returned to pool
                        drop(op.buf);
                        perf_stats::sat_add_u64(&mut stats.reads_completed, 1);
                        if res < 0 {
                            perf_stats::sat_add_u64(&mut stats.read_errors, 1);
                        }
                    }
                    Op::Open(_op) => {
                        perf_stats::sat_add_u64(&mut stats.open_ops_completed, 1);
                        if res < 0 {
                            perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        } else {
                            // Prevent fd leak on shutdown path.
                            unsafe {
                                libc::close(res);
                            }
                        }
                    }
                    Op::Stat(_op) => {
                        perf_stats::sat_add_u64(&mut stats.stat_ops_completed, 1);
                        if res < 0 {
                            perf_stats::sat_add_u64(&mut stats.stat_failures, 1);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Open file with optional O_NOFOLLOW for symlink safety.
#[cfg(unix)]
fn open_file_safe(path: &Path, follow_symlinks: bool) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.read(true);

    if !follow_symlinks {
        // O_NOFOLLOW: fail if path is a symlink (prevents TOCTOU)
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    opts.open(path)
}

/// Main I/O worker loop using io_uring.
///
/// # Correctness
///
/// - **Single-chunk-in-flight per file**: We only allow one outstanding read
///   per file to ensure prefix-drop deduplication logic is valid (no gaps from
///   failed earlier chunks).
/// - **Open/stat staging**: Each file advances `PendingOpen → PendingStat → Ready`
///   before any reads are submitted.
/// - **Drain before return**: All in-flight ops MUST complete before we return,
///   otherwise the kernel may write to freed memory.
/// - **Buffer lifetime**: Buffers live in `ops[]` until CQE is reaped.
/// - **Fallback safety**: Unsupported open/stat opcodes fall back to blocking
///   open + fstat unless `open_stat_mode = UringRequired`.
///
/// # Shutdown
///
/// On `stop` signal or channel close, we stop accepting new work but drain
/// all in-flight operations to completion.
fn io_worker_loop<E: ScanEngine>(
    _wid: usize,
    rx: chan::Receiver<FileWork>,
    pool: Arc<FixedBufferPool>,
    cpu: ExecutorHandle<CpuTask>,
    engine: Arc<E>,
    cfg: LocalFsUringConfig,
    stop: Arc<AtomicBool>,
) -> io::Result<UringIoStats> {
    let overlap = engine.required_overlap();
    let chunk_size = cfg.chunk_size;
    let buf_len = overlap.saturating_add(chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    let mut ring = IoUring::new(cfg.ring_entries)?;
    let mut stats = UringIoStats::default();
    let mut registered_buffers = false;

    // Probe once per ring to decide open/stat eligibility and record fallback.
    let mut open_stat_fallback = false;
    let open_stat_caps = match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => None,
        _ => match probe_uring_caps(&ring) {
            Ok(caps) => Some(caps),
            Err(err) => {
                if cfg.open_stat_mode == OpenStatMode::UringRequired {
                    return Err(err);
                }
                open_stat_fallback = true;
                None
            }
        },
    };

    let open_stat_supported = open_stat_caps
        .as_ref()
        .is_some_and(|caps| caps.supports_open_stat());
    let _submit_stable = open_stat_caps
        .as_ref()
        .is_some_and(|caps| caps.submit_stable);

    match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => {}
        OpenStatMode::UringPreferred => {
            if !open_stat_supported {
                open_stat_fallback = true;
            }
        }
        OpenStatMode::UringRequired => {
            if !open_stat_supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "io_uring open/stat opcodes unsupported",
                ));
            }
        }
    }

    if open_stat_fallback {
        perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
    }

    if cfg.use_registered_buffers {
        let bufs = pool.iovecs();
        // SAFETY: Buffers are owned by the pool and live for the lifetime
        // of the ring. We unregister after draining completions.
        unsafe {
            ring.submitter().register_buffers(&bufs)?;
        }
        registered_buffers = true;
    }

    // File slab + per-phase queues for files ready to submit (not in-flight).
    let mut files: Vec<Option<FileState>> = Vec::new();
    let mut free_file_slots: Vec<usize> = Vec::new();
    // CORRECTNESS: Files in ready queues have in_flight == 0.
    let mut open_ready: VecDeque<usize> = VecDeque::new();
    let mut stat_ready: VecDeque<usize> = VecDeque::new();
    let mut read_ready: VecDeque<usize> = VecDeque::new();

    // Op slots keyed by user_data.
    let slots = cfg.ring_entries as usize;
    let mut ops: Vec<Option<Op>> = (0..slots).map(|_| None).collect();
    let mut free_ops: Vec<usize> = (0..slots).rev().collect();

    let mut in_flight_ops: usize = 0;
    let mut stopping = false;
    let mut channel_closed = false;

    /// Result of blocking open + fstat for files when io_uring open/stat
    /// ops are unsupported or the mode is `BlockingOnly`.
    enum BlockingOutcome {
        /// File opened and sized; ready for read submissions.
        Ready(ReadState),
        /// File skipped (empty or exceeds `max_file_size`).
        Skipped,
        /// Open or fstat failed.
        Failed,
    }

    let blocking_open = |path: &Path, stats: &mut UringIoStats| -> BlockingOutcome {
        // Use O_NOFOLLOW when follow_symlinks is false to prevent TOCTOU attacks.
        let file = match open_file_safe(path, cfg.follow_symlinks) {
            Ok(f) => f,
            Err(_) => {
                perf_stats::sat_add_u64(&mut stats.files_open_failed, 1);
                return BlockingOutcome::Failed;
            }
        };

        // Use actual file size from fstat, not discovery-time size.
        // This handles files that grew or shrank between discovery and open.
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                perf_stats::sat_add_u64(&mut stats.files_open_failed, 1);
                return BlockingOutcome::Failed;
            }
        };

        if let Some(max_sz) = cfg.max_file_size {
            if size > max_sz {
                return BlockingOutcome::Skipped;
            }
        }

        if size == 0 {
            return BlockingOutcome::Skipped;
        }

        BlockingOutcome::Ready(ReadState {
            file,
            size,
            next_offset: 0,
            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
            overlap_len: 0,
        })
    };

    // Helper: add file work to tracking.
    let add_file = |w: FileWork,
                    stats: &mut UringIoStats,
                    files: &mut Vec<Option<FileState>>,
                    free_file_slots: &mut Vec<usize>,
                    open_ready: &mut VecDeque<usize>,
                    read_ready: &mut VecDeque<usize>| {
        perf_stats::sat_add_u64(&mut stats.files_started, 1);

        if open_stat_supported {
            let slot = free_file_slots.pop().unwrap_or_else(|| {
                files.push(None);
                files.len() - 1
            });

            files[slot] = Some(FileState {
                phase: FilePhase::PendingOpen { path: w.path },
                in_flight: 0,
                done: false,
                failed: false,
                token: w.token,
            });

            open_ready.push_back(slot);
            return;
        }

        // Blocking fallback: open + fstat to build read state.
        let read_state = match blocking_open(&w.path, stats) {
            BlockingOutcome::Ready(state) => state,
            BlockingOutcome::Skipped => {
                drop(w.token);
                return;
            }
            BlockingOutcome::Failed => {
                drop(w.token);
                return;
            }
        };

        let slot = free_file_slots.pop().unwrap_or_else(|| {
            files.push(None);
            files.len() - 1
        });

        files[slot] = Some(FileState {
            phase: FilePhase::Ready(read_state),
            in_flight: 0,
            done: false,
            failed: false,
            token: w.token,
        });

        read_ready.push_back(slot);
    };

    loop {
        // Check stop flag - but don't exit immediately, must drain first.
        if stop.load(Ordering::Relaxed) {
            stopping = true;
        }

        // If stopping, don't accept new files.
        if !stopping && !channel_closed {
            // Pull new files opportunistically (batch up to 64).
            for _ in 0..64 {
                match rx.try_recv() {
                    Ok(w) => add_file(
                        w,
                        &mut stats,
                        &mut files,
                        &mut free_file_slots,
                        &mut open_ready,
                        &mut read_ready,
                    ),
                    Err(chan::TryRecvError::Empty) => break,
                    Err(chan::TryRecvError::Disconnected) => {
                        channel_closed = true;
                        break;
                    }
                }
            }
        }

        // Track SQEs queued this iteration for batched submission.
        let mut submitted_this_round = 0;

        // Fill submissions up to io_depth.
        // CORRECTNESS: Only one op in-flight per file at a time.
        while in_flight_ops < cfg.io_depth && !stopping {
            if free_ops.is_empty() {
                break;
            }

            let mut scheduled = false;

            // Prefer reads (buffered) to keep throughput high.
            if let Some(file_slot) = read_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    // Stale slot.
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                match &mut st.phase {
                    FilePhase::Ready(rs) => {
                        // INVARIANT: Files in read queue should have in_flight == 0.
                        debug_assert_eq!(
                            st.in_flight, 0,
                            "file in read queue should not have in-flight ops"
                        );

                        if rs.next_offset >= rs.size {
                            st.done = true;
                            files[file_slot] = None;
                            free_file_slots.push(file_slot);
                            continue;
                        }

                        if let Some(mut buf) = pool.try_acquire() {
                            let offset = rs.next_offset;
                            let prefix_len = rs.overlap_len;

                            let payload_len = (rs.size - offset).min(chunk_size as u64) as usize;

                            debug_assert!(prefix_len + payload_len <= buf_len);

                            // Copy overlap bytes from the previous chunk into the buffer so we
                            // only read the payload from disk (no overlap re-reads).
                            if prefix_len > 0 {
                                buf.as_mut_slice()[..prefix_len]
                                    .copy_from_slice(&rs.overlap_buf[..prefix_len]);
                            }

                            let op_slot = free_ops.pop().unwrap();
                            let fd = rs.file.as_raw_fd();
                            // SAFETY: `prefix_len < buffer_len` (clamped above), so
                            // `add(prefix_len)` stays within the buffer allocation.
                            let ptr = unsafe { buf.as_mut_slice().as_mut_ptr().add(prefix_len) };

                            let entry = if cfg.use_registered_buffers {
                                opcode::ReadFixed::new(
                                    types::Fd(fd),
                                    ptr,
                                    payload_len as u32,
                                    buf.buf_index(),
                                )
                                .offset(offset)
                                .build()
                            } else {
                                opcode::Read::new(types::Fd(fd), ptr, payload_len as u32)
                                    .offset(offset)
                                    .build()
                            }
                            .user_data(op_slot as u64);

                            // SAFETY:
                            // - `buf` lives in `ops[op_slot]` until completion
                            // - `rs.file` lives until file cleanup
                            // - We drain all in-flight ops before returning
                            unsafe {
                                let mut sq = ring.submission();
                                if sq.push(&entry).is_err() {
                                    // SQ unexpectedly full - return resources and break.
                                    drop(buf);
                                    free_ops.push(op_slot);
                                    read_ready.push_front(file_slot);
                                    break;
                                }
                            }

                            let base_offset = offset.saturating_sub(prefix_len as u64);

                            ops[op_slot] = Some(Op::Read(ReadOp {
                                file_slot,
                                base_offset,
                                prefix_len,
                                payload_len,
                                buf,
                            }));

                            in_flight_ops += 1;
                            submitted_this_round += 1;
                            perf_stats::sat_add_u64(&mut stats.reads_submitted, 1);

                            st.in_flight = 1; // Exactly 1 - single in-flight per file
                            rs.next_offset = rs.next_offset.saturating_add(payload_len as u64);
                            scheduled = true;
                        } else {
                            // No buffer: re-queue and allow open/stat to proceed.
                            read_ready.push_back(file_slot);
                        }
                    }
                    FilePhase::PendingOpen { .. } => {
                        open_ready.push_back(file_slot);
                    }
                    FilePhase::PendingStat { .. } => {
                        stat_ready.push_back(file_slot);
                    }
                }
            }

            if scheduled {
                continue;
            }

            if let Some(file_slot) = stat_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingStat { file } = &st.phase else {
                    // Phase drift: re-queue based on actual phase.
                    match &st.phase {
                        FilePhase::PendingOpen { .. } => open_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingStat { .. } => {}
                    }
                    continue;
                };

                let Some(file) = file.as_ref() else {
                    // Already moved; mark failed to avoid spin.
                    st.failed = true;
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                };

                debug_assert_eq!(
                    st.in_flight, 0,
                    "file in stat queue should not have in-flight ops"
                );

                // SAFETY: `libc::statx` is a C struct where all-zeros is a valid
                // representation. The kernel overwrites the fields we need.
                let mut statx_buf = Box::new(unsafe { std::mem::zeroed::<libc::statx>() });
                let statx_ptr = statx_buf.as_mut() as *mut libc::statx as *mut types::statx;
                let empty_path = b"\0";

                let entry = opcode::Statx::new(
                    types::Fd(file.as_raw_fd()),
                    empty_path.as_ptr() as *const _,
                    statx_ptr,
                )
                .flags(libc::AT_EMPTY_PATH)
                .mask(libc::STATX_SIZE | libc::STATX_TYPE | libc::STATX_MODE)
                .build();

                let op_slot = free_ops.pop().unwrap();
                let entry = entry.user_data(op_slot as u64);

                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        stat_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(Op::Stat(StatOp {
                    file_slot,
                    statx_buf,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                perf_stats::sat_add_u64(&mut stats.stat_ops_submitted, 1);
                st.in_flight = 1;
                scheduled = true;
            }

            if scheduled {
                continue;
            }

            if let Some(file_slot) = open_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingOpen { path } = &st.phase else {
                    match &st.phase {
                        FilePhase::PendingStat { .. } => stat_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingOpen { .. } => {}
                    }
                    continue;
                };

                debug_assert_eq!(
                    st.in_flight, 0,
                    "file in open queue should not have in-flight ops"
                );

                let flags = libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | if cfg.follow_symlinks {
                        0
                    } else {
                        libc::O_NOFOLLOW
                    };
                let use_openat2 = open_stat_caps.as_ref().is_some_and(|caps| caps.openat2);

                let path_cstr = match CString::new(path.as_os_str().as_bytes()) {
                    Ok(s) => s,
                    Err(_) => {
                        perf_stats::sat_add_u64(&mut stats.files_open_failed, 1);
                        perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        st.failed = true;
                        st.done = true;
                        files[file_slot] = None;
                        free_file_slots.push(file_slot);
                        continue;
                    }
                };

                let open_how = if use_openat2 {
                    let resolve = resolve_bits(cfg.resolve_policy);
                    Some(Box::new(
                        types::OpenHow::new().flags(flags as u64).resolve(resolve),
                    ))
                } else {
                    None
                };

                let op_slot = free_ops.pop().unwrap();
                let entry = if use_openat2 {
                    let how = open_how.as_ref().expect("open_how missing");
                    opcode::OpenAt2::new(
                        types::Fd(libc::AT_FDCWD),
                        path_cstr.as_ptr(),
                        how.as_ref(),
                    )
                    .build()
                } else {
                    opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), path_cstr.as_ptr())
                        .flags(flags)
                        .mode(0)
                        .build()
                }
                .user_data(op_slot as u64);

                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        open_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(Op::Open(OpenOp {
                    file_slot,
                    path: path_cstr,
                    open_how,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                perf_stats::sat_add_u64(&mut stats.open_ops_submitted, 1);
                st.in_flight = 1;
                scheduled = true;
            }

            if !scheduled {
                break;
            }
        }

        // Batch submit if we queued anything.
        if submitted_this_round > 0 {
            ring.submit()?;
        }

        // Decide what to do based on current state.
        if in_flight_ops == 0 {
            if stopping {
                // Clean shutdown: nothing in flight, stop requested.
                break;
            }

            let has_work =
                !open_ready.is_empty() || !stat_ready.is_empty() || !read_ready.is_empty();

            if !has_work {
                if channel_closed {
                    // No work, no more incoming, no in-flight. Done.
                    break;
                }
                // Block on channel for new work.
                match rx.recv() {
                    Ok(w) => {
                        add_file(
                            w,
                            &mut stats,
                            &mut files,
                            &mut free_file_slots,
                            &mut open_ready,
                            &mut read_ready,
                        );
                        continue;
                    }
                    Err(_) => {
                        channel_closed = true;
                        // Check if we have any ready files to process.
                        if !has_work {
                            break;
                        }
                        // Else continue to try submitting.
                        continue;
                    }
                }
            } else {
                // Work queued but resources unavailable (likely buffers).
                // Yield to let CPU workers release buffers, then retry.
                // This avoids busy-spin while waiting for pool.
                std::thread::yield_now();
                continue;
            }
        }

        // We have ops in flight - wait for at least one completion.
        // Drain CQ before waiting to avoid a syscall if completions are ready.
        let cq_empty = {
            let cq = ring.completion();
            cq.is_empty()
        };
        if cq_empty {
            // Only use submit_and_wait if we didn't submit this round.
            if submitted_this_round == 0 {
                ring.submit_and_wait(1)?;
            } else if in_flight_ops >= cfg.io_depth {
                // At capacity, must wait for completions before submitting more.
                ring.submit_and_wait(1)?;
            }
            // else: we submitted and have room, check completions opportunistically
        }

        // Drain completions.
        for cqe in ring.completion() {
            let op_slot = cqe.user_data() as usize;
            let res = cqe.result();

            // CRITICAL: Unknown user_data indicates internal accounting bug.
            let op = ops
                .get_mut(op_slot)
                .and_then(|o| o.take())
                .unwrap_or_else(|| {
                    panic!(
                        "io_uring CQE with unknown user_data {} (max slot: {})",
                        op_slot,
                        slots - 1
                    );
                });

            free_ops.push(op_slot);
            in_flight_ops = in_flight_ops.saturating_sub(1);
            match op {
                Op::Read(op) => {
                    perf_stats::sat_add_u64(&mut stats.reads_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        // File already cleaned up (shouldn't happen with 1-in-flight).
                        drop(op.buf);
                        continue;
                    };

                    st.in_flight = 0;

                    let FilePhase::Ready(rs) = &mut st.phase else {
                        drop(op.buf);
                        continue;
                    };

                    if res < 0 {
                        // Read syscall failed.
                        perf_stats::sat_add_u64(&mut stats.read_errors, 1);
                        st.failed = true;
                        st.done = true;
                        drop(op.buf);
                    } else {
                        let n = res as usize;
                        if n == 0 {
                            // Unexpected EOF (empty read).
                            perf_stats::sat_add_u64(&mut stats.read_errors, 1);
                            st.failed = true;
                            st.done = true;
                            drop(op.buf);
                        } else {
                            if n < op.payload_len {
                                // Short read: file likely shrank. Treat as truncation.
                                // We scan what we got, but mark file done since we can't
                                // trust our offset calculations for subsequent chunks.
                                perf_stats::sat_add_u64(&mut stats.short_reads, 1);
                                st.done = true;
                            }

                            let total_len = op.prefix_len.saturating_add(n);
                            let len = total_len as u32;

                            if overlap > 0 {
                                let overlap_len = overlap.min(total_len);
                                if overlap_len > 0 {
                                    let start = total_len - overlap_len;
                                    rs.overlap_buf[..overlap_len].copy_from_slice(
                                        &op.buf.as_slice()[start..start + overlap_len],
                                    );
                                }
                                rs.overlap_len = overlap_len;
                            }

                            let task = CpuTask::ScanChunk {
                                token: Arc::clone(&st.token),
                                base_offset: op.base_offset,
                                prefix_len: op.prefix_len as u32,
                                len,
                                buf: op.buf,
                            };

                            if cpu.spawn(task).is_err() {
                                // CPU executor shut down. Start stopping.
                                stopping = true;
                                st.failed = true;
                                st.done = true;
                            } else {
                                // Successfully spawned. If file has more data, re-queue.
                                if !st.done && !st.failed && rs.next_offset < rs.size {
                                    read_ready.push_back(op.file_slot);
                                } else {
                                    st.done = true;
                                }
                            }
                        }
                    }

                    // Cleanup file if done and no more in-flight.
                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                Op::Open(op) => {
                    perf_stats::sat_add_u64(&mut stats.open_ops_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        if res >= 0 {
                            unsafe {
                                libc::close(res);
                            }
                        }
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        perf_stats::sat_add_u64(&mut stats.open_failures, 1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
                            let path = match &mut st.phase {
                                FilePhase::PendingOpen { path } => std::mem::take(path),
                                _ => PathBuf::new(),
                            };

                            match blocking_open(&path, &mut stats) {
                                BlockingOutcome::Ready(read_state) => {
                                    st.phase = FilePhase::Ready(read_state);
                                    read_ready.push_back(op.file_slot);
                                }
                                BlockingOutcome::Skipped => {
                                    st.done = true;
                                }
                                BlockingOutcome::Failed => {
                                    st.failed = true;
                                    st.done = true;
                                }
                            }
                        } else {
                            perf_stats::sat_add_u64(&mut stats.files_open_failed, 1);
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let fd = res;
                        // SAFETY: fd came from io_uring openat/openat2 and is owned by us now.
                        let file = unsafe { File::from_raw_fd(fd) };
                        st.phase = FilePhase::PendingStat { file: Some(file) };
                        stat_ready.push_back(op.file_slot);
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                Op::Stat(op) => {
                    perf_stats::sat_add_u64(&mut stats.stat_ops_completed, 1);
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        perf_stats::sat_add_u64(&mut stats.stat_failures, 1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            perf_stats::sat_add_u64(&mut stats.open_stat_fallbacks, 1);
                            let file = match &mut st.phase {
                                FilePhase::PendingStat { file } => file.as_ref(),
                                _ => None,
                            };

                            if let Some(file) = file {
                                match file.metadata() {
                                    Ok(m) => {
                                        let size = m.len();
                                        if let Some(max_sz) = cfg.max_file_size {
                                            if size > max_sz {
                                                st.done = true;
                                                if st.done && st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        }
                                        if size == 0 {
                                            st.done = true;
                                            if st.done && st.in_flight == 0 {
                                                files[op.file_slot] = None;
                                                free_file_slots.push(op.file_slot);
                                            }
                                            continue;
                                        }

                                        let file = match &mut st.phase {
                                            FilePhase::PendingStat { file } => {
                                                file.take().expect("file missing in PendingStat")
                                            }
                                            _ => {
                                                st.failed = true;
                                                st.done = true;
                                                if st.done && st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        };

                                        st.phase = FilePhase::Ready(ReadState {
                                            file,
                                            size,
                                            next_offset: 0,
                                            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                            overlap_len: 0,
                                        });
                                        read_ready.push_back(op.file_slot);
                                    }
                                    Err(_) => {
                                        st.failed = true;
                                        st.done = true;
                                    }
                                }
                            } else {
                                st.failed = true;
                                st.done = true;
                            }
                        } else {
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let statx = &*op.statx_buf;
                        let size = statx.stx_size;

                        if let Some(max_sz) = cfg.max_file_size {
                            if size > max_sz {
                                st.done = true;
                            }
                        }

                        if !st.done {
                            if size == 0 {
                                st.done = true;
                            } else {
                                let file = match &mut st.phase {
                                    FilePhase::PendingStat { file } => {
                                        file.take().expect("file missing in PendingStat")
                                    }
                                    _ => {
                                        st.failed = true;
                                        st.done = true;
                                        if st.done && st.in_flight == 0 {
                                            files[op.file_slot] = None;
                                            free_file_slots.push(op.file_slot);
                                        }
                                        continue;
                                    }
                                };

                                st.phase = FilePhase::Ready(ReadState {
                                    file,
                                    size,
                                    next_offset: 0,
                                    overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                    overlap_len: 0,
                                });
                                read_ready.push_back(op.file_slot);
                            }
                        }
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
            }
        }
    }

    // SAFETY: Drain any remaining in-flight ops before returning.
    // This ensures the kernel finishes writing before we drop buffers.
    if in_flight_ops > 0 {
        drain_in_flight(&mut ring, &mut ops, &mut in_flight_ops, &mut stats)?;
    }

    if registered_buffers {
        // Ignore unregister errors; ring teardown will clean up in worst case.
        let _ = ring.submitter().unregister_buffers();
    }

    Ok(stats)
}

// ============================================================================
// Discovery Walker
// ============================================================================

fn walk_and_send_files(
    root: &Path,
    cfg: &LocalFsUringConfig,
    budget: &Arc<CountBudget>,
    tx: &chan::Sender<FileWork>,
    next_file_id: &mut u32,
    summary: &mut LocalFsSummary,
) -> io::Result<()> {
    let mut stack: Vec<PathBuf> = Vec::with_capacity(1024);
    stack.push(root.to_path_buf());

    while let Some(path) = stack.pop() {
        let meta = if cfg.follow_symlinks {
            match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => {
                    summary.walk_errors = summary.walk_errors.saturating_add(1);
                    continue;
                }
            }
        } else {
            match fs::symlink_metadata(&path) {
                Ok(m) => {
                    if m.file_type().is_symlink() {
                        continue;
                    }
                    m
                }
                Err(_) => {
                    summary.walk_errors = summary.walk_errors.saturating_add(1);
                    continue;
                }
            }
        };

        if meta.is_dir() {
            let rd = match fs::read_dir(&path) {
                Ok(rd) => rd,
                Err(_) => {
                    summary.walk_errors = summary.walk_errors.saturating_add(1);
                    continue;
                }
            };

            for ent in rd {
                match ent {
                    Ok(ent) => stack.push(ent.path()),
                    Err(_) => summary.walk_errors = summary.walk_errors.saturating_add(1),
                }
            }
            continue;
        }

        if !meta.is_file() {
            continue;
        }

        summary.files_seen = summary.files_seen.saturating_add(1);

        let size = meta.len();

        if let Some(max_sz) = cfg.max_file_size {
            if size > max_sz {
                summary.files_skipped_size = summary.files_skipped_size.saturating_add(1);
                continue;
            }
        }

        // Backpressure: blocks until permit available.
        let permit = budget.acquire(1);

        let id = *next_file_id;
        *next_file_id = next_file_id.checked_add(1).expect("FileId overflow");
        let file_id = FileId(id);

        let display = path
            .as_os_str()
            .as_bytes()
            .to_vec()
            .into_boxed_slice()
            .into();

        let token = Arc::new(FileToken {
            _permit: permit,
            file_id,
            display,
        });

        // Backpressure: bounded channel send blocks here.
        tx.send(FileWork { path, size, token })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "io threads stopped"))?;

        summary.files_enqueued = summary.files_enqueued.saturating_add(1);
    }

    Ok(())
}

// ============================================================================
// Entry Point
// ============================================================================

/// Scan local filesystem using io_uring.
///
/// # Arguments
///
/// - `engine`: Detection engine implementing [`ScanEngine`]
/// - `roots`: Root directories to scan
/// - `cfg`: Configuration
/// - `event_sink`: Event sink for findings
///
/// # Returns
///
/// Tuple of (discovery summary, I/O stats, CPU metrics).
///
/// # Errors
///
/// Returns `io::Error` if io_uring initialization fails or an I/O thread panics.
pub fn scan_local_fs_uring<E: ScanEngine>(
    engine: Arc<E>,
    roots: &[PathBuf],
    cfg: LocalFsUringConfig,
    event_sink: Arc<dyn EventSink>,
) -> io::Result<(LocalFsSummary, UringIoStats, MetricsSnapshot)> {
    cfg.validate(engine.as_ref());

    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    // Global-only pool because I/O threads acquire and CPU threads release.
    let pool = FixedBufferPool::new(buf_len, cfg.pool_buffers);

    let file_budget = Arc::new(CountBudget::new(cfg.max_in_flight_files));

    // CPU executor for scanning.
    let ex = Executor::<CpuTask>::new(
        ExecutorConfig {
            workers: cfg.cpu_workers,
            seed: cfg.seed,
            ..ExecutorConfig::default()
        },
        {
            let engine = Arc::clone(&engine);
            let event_sink = Arc::clone(&event_sink);
            let dedupe = cfg.dedupe_within_chunk;
            move |_wid| CpuScratch {
                engine: Arc::clone(&engine),
                event_sink: Arc::clone(&event_sink),
                scratch: engine.new_scratch(),
                // Match the local scan default: avoid steady-state allocs without
                // relying on engine-specific tuning details.
                pending: Vec::with_capacity(4096),
                dedupe_within_chunk: dedupe,
            }
        },
        cpu_runner::<E>,
    );

    let cpu = ex.handle();

    let (tx, rx) = chan::bounded::<FileWork>(cfg.file_queue_cap);

    let stop = Arc::new(AtomicBool::new(false));

    // Spawn I/O threads.
    let mut io_threads = Vec::with_capacity(cfg.io_threads);
    for wid in 0..cfg.io_threads {
        let rx = rx.clone();
        let pool = pool.clone();
        let cpu = cpu.clone();
        let engine = Arc::clone(&engine);
        let cfg2 = cfg.clone();
        let stop2 = Arc::clone(&stop);

        io_threads.push(thread::spawn(move || {
            io_worker_loop(wid, rx, pool, cpu, engine, cfg2, stop2)
        }));
    }
    drop(rx);

    // Discovery walk: DFS, bounded by file_budget + bounded channel.
    let mut summary = LocalFsSummary::default();
    let mut next_file_id: u32 = 0;

    for root in roots {
        walk_and_send_files(
            root,
            &cfg,
            &file_budget,
            &tx,
            &mut next_file_id,
            &mut summary,
        )?;
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }

    drop(tx);

    // Join I/O threads and merge stats.
    let mut io_stats = UringIoStats::default();
    for t in io_threads {
        match t.join() {
            Ok(Ok(s)) => io_stats.merge(s),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::other("io thread panicked")),
        }
    }

    summary.open_errors = io_stats.files_open_failed;
    summary.read_errors = io_stats.read_errors;

    // Join CPU executor.
    let cpu_metrics = ex.join();

    event_sink.flush();

    Ok((summary, io_stats, cpu_metrics))
}

// ============================================================================
// Per-Shard io_uring I/O — Sharded Variant
// ============================================================================
//
// The functions below implement the per-shard io_uring I/O thread that feeds
// an SPSC ring (instead of a CPU executor). This reuses `ScanChunk`,
// `shard_scan_loop`, `TsBufferPool`, and helpers from `local_fs_sharded`.
//
// Key differences from `io_worker_loop`:
// - Output goes to an SPSC producer (`ScanChunk::Chunk`) instead of `cpu.spawn`.
// - Buffer pool is `TsBufferPool` instead of `FixedBufferPool`.
// - No registered buffers (`READ_FIXED`); always uses `Read` opcode.
// - Sends `EndOfFile` / `Shutdown` sentinels through the SPSC ring.
// - Stats type is `ShardIoStats` (from `local_fs_sharded`).

/// Lightweight io_uring-specific configuration extracted from [`ShardedFsUringConfig`].
///
/// Avoids threading the full config struct into the I/O loop closure.
struct UringShardConfig {
    ring_entries: u32,
    io_depth: usize,
    chunk_size: usize,
    max_file_size: Option<u64>,
    follow_symlinks: bool,
    open_stat_mode: OpenStatMode,
    resolve_policy: ResolvePolicy,
}

/// Configuration for sharded filesystem scanning using per-shard io_uring I/O.
///
/// Combines the shard topology fields from [`super::local_fs_sharded::ShardedFsConfig`]
/// with io_uring-specific tuning knobs.
pub struct ShardedFsUringConfig {
    // -- Shard topology (shared with blocking variant) --
    /// Number of shards (each shard = 1 io_uring I/O thread + 1 scan thread).
    pub shards: usize,
    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,
    /// Maximum file size to scan (bytes). Files larger than this are skipped.
    pub max_file_size: u64,
    /// Number of buffers allocated per shard's pool.
    pub pool_buffers_per_shard: usize,
    /// Per-worker local queue capacity in the buffer pool.
    pub local_queue_cap: usize,
    /// Maximum in-flight files per shard (bounded channel capacity).
    pub max_in_flight_per_shard: usize,
    /// Enable within-chunk finding deduplication.
    pub dedupe_within_chunk: bool,
    /// Event sink for emitting findings and progress events.
    pub event_sink: Arc<dyn EventSink>,
    /// Whether to attempt pinning threads to CPU cores.
    pub pin_threads: bool,

    // -- io_uring-specific --
    /// Number of SQ/CQ entries per io_uring ring.
    pub ring_entries: u32,
    /// Max in-flight ops per I/O thread.
    pub io_depth: usize,
    /// Open/stat execution mode.
    pub open_stat_mode: OpenStatMode,
    /// Path resolution policy for openat2.
    pub resolve_policy: ResolvePolicy,
    /// Follow symbolic links during open.
    pub follow_symlinks: bool,
}

/// Per-op state for sharded read completions.
///
/// Identical to [`ReadOp`] but uses [`TsBufferHandle`] instead of
/// [`FixedBufferHandle`]. No `buf_index` since we never use `READ_FIXED`.
struct ShardReadOp {
    file_slot: usize,
    base_offset: u64,
    prefix_len: usize,
    payload_len: usize,
    buf: TsBufferHandle,
}

/// Per-op discriminant for sharded io_uring completions.
enum ShardOp {
    Open(OpenOp),
    Stat(StatOp),
    Read(ShardReadOp),
}

/// Per-shard io_uring I/O thread main loop.
///
/// Structurally identical to [`io_worker_loop`] with these substitutions:
/// - `FixedBufferPool` → `TsBufferPool`
/// - `cpu.spawn(CpuTask)` → `push_with_backoff(&mut producer, ScanChunk::Chunk{..})`
/// - Sends `ScanChunk::EndOfFile` after each file completes
/// - Sends `ScanChunk::Shutdown` after draining the file channel
/// - No registered buffers (always `opcode::Read`)
///
/// # Shutdown Protocol
///
/// 1. The coordinator drops `crossbeam_channel::Sender`.
/// 2. This loop drains remaining files from the channel.
/// 3. After drain, pushes `ScanChunk::Shutdown` into the SPSC ring.
/// 4. The scan thread (reused from `local_fs_sharded`) receives `Shutdown` and exits.
fn shard_io_uring_loop<E: ScanEngine>(
    file_rx: crossbeam_channel::Receiver<ShardFileWork>,
    mut producer: OwnedSpscProducer<ScanChunk, SHARD_SPSC_CAP>,
    pool: TsBufferPool,
    engine: Arc<E>,
    cfg: &UringShardConfig,
) -> io::Result<ShardIoStats> {
    let overlap = engine.required_overlap();
    let chunk_size = cfg.chunk_size;
    let buf_len = overlap.saturating_add(chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    let mut ring = IoUring::new(cfg.ring_entries)?;
    let mut stats = ShardIoStats::default();

    // Local backoff counter passed to push_with_backoff.
    // Accumulated into stats at the end.
    let mut local_push_yields: u64 = 0;

    // Probe once per ring to decide open/stat eligibility.
    let mut open_stat_fallback = false;
    let open_stat_caps = match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => None,
        _ => match probe_uring_caps(&ring) {
            Ok(caps) => Some(caps),
            Err(err) => {
                if cfg.open_stat_mode == OpenStatMode::UringRequired {
                    return Err(err);
                }
                open_stat_fallback = true;
                None
            }
        },
    };

    let open_stat_supported = open_stat_caps
        .as_ref()
        .is_some_and(|caps| caps.supports_open_stat());

    match cfg.open_stat_mode {
        OpenStatMode::BlockingOnly => {}
        OpenStatMode::UringPreferred => {
            if !open_stat_supported {
                open_stat_fallback = true;
            }
        }
        OpenStatMode::UringRequired => {
            if !open_stat_supported {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "io_uring open/stat opcodes unsupported",
                ));
            }
        }
    }

    let _ = open_stat_fallback; // consumed by stats in the original; kept for parity

    // File slab + per-phase queues.
    let mut files: Vec<Option<FileState>> = Vec::new();
    let mut free_file_slots: Vec<usize> = Vec::new();
    let mut open_ready: VecDeque<usize> = VecDeque::new();
    let mut stat_ready: VecDeque<usize> = VecDeque::new();
    let mut read_ready: VecDeque<usize> = VecDeque::new();

    // Op slots keyed by user_data.
    let slots = cfg.ring_entries as usize;
    let mut ops: Vec<Option<ShardOp>> = (0..slots).map(|_| None).collect();
    let mut free_ops: Vec<usize> = (0..slots).rev().collect();

    let mut in_flight_ops: usize = 0;
    let mut channel_closed = false;

    // --- Blocking open+stat fallback (reused from io_worker_loop) ---

    /// Result of blocking open + fstat (same semantics as in `io_worker_loop`).
    enum BlockingOutcome {
        /// File opened and sized; ready for shard I/O submission.
        Ready(ReadState),
        /// File skipped (empty or exceeds `max_file_size`).
        Skipped,
        /// Open or fstat failed.
        Failed,
    }

    let blocking_open = |path: &Path, stats: &mut ShardIoStats| -> BlockingOutcome {
        let file = match open_file_safe(path, cfg.follow_symlinks) {
            Ok(f) => f,
            Err(_) => {
                stats.io_errors = stats.io_errors.saturating_add(1);
                return BlockingOutcome::Failed;
            }
        };

        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                stats.io_errors = stats.io_errors.saturating_add(1);
                return BlockingOutcome::Failed;
            }
        };

        if let Some(max_sz) = cfg.max_file_size {
            if size > max_sz {
                return BlockingOutcome::Skipped;
            }
        }

        if size == 0 {
            return BlockingOutcome::Skipped;
        }

        BlockingOutcome::Ready(ReadState {
            file,
            size,
            next_offset: 0,
            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
            overlap_len: 0,
        })
    };

    // Helper: add file work to tracking.
    let add_file =
        |w: ShardFileWork,
         stats: &mut ShardIoStats,
         files: &mut Vec<Option<FileState>>,
         free_file_slots: &mut Vec<usize>,
         open_ready: &mut VecDeque<usize>,
         read_ready: &mut VecDeque<usize>,
         producer: &mut OwnedSpscProducer<ScanChunk, SHARD_SPSC_CAP>| {
            // Build display path for finding attribution.
            let display: Arc<[u8]> = w
                .path
                .as_os_str()
                .as_bytes()
                .to_vec()
                .into_boxed_slice()
                .into();
            let file_id = FileId(0);
            let token = Arc::new(FileToken {
                _permit: w._permit,
                file_id,
                display,
            });

            if open_stat_supported {
                let slot = free_file_slots.pop().unwrap_or_else(|| {
                    files.push(None);
                    files.len() - 1
                });

                files[slot] = Some(FileState {
                    phase: FilePhase::PendingOpen { path: w.path },
                    in_flight: 0,
                    done: false,
                    failed: false,
                    token,
                });

                open_ready.push_back(slot);
                return;
            }

            // Blocking fallback.
            let read_state = match blocking_open(&w.path, stats) {
                BlockingOutcome::Ready(state) => state,
                BlockingOutcome::Skipped => {
                    drop(token);
                    return;
                }
                BlockingOutcome::Failed => {
                    drop(token);
                    return;
                }
            };

            let slot = free_file_slots.pop().unwrap_or_else(|| {
                files.push(None);
                files.len() - 1
            });

            files[slot] = Some(FileState {
                phase: FilePhase::Ready(read_state),
                in_flight: 0,
                done: false,
                failed: false,
                token,
            });

            read_ready.push_back(slot);
        };

    // ---- Main loop ----

    loop {
        // Pull new files opportunistically (batch up to 64).
        if !channel_closed {
            for _ in 0..64 {
                match file_rx.try_recv() {
                    Ok(w) => add_file(
                        w,
                        &mut stats,
                        &mut files,
                        &mut free_file_slots,
                        &mut open_ready,
                        &mut read_ready,
                        &mut producer,
                    ),
                    Err(crossbeam_channel::TryRecvError::Empty) => break,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => {
                        channel_closed = true;
                        break;
                    }
                }
            }
        }

        let mut submitted_this_round = 0;

        // Fill submissions up to io_depth.
        while in_flight_ops < cfg.io_depth {
            if free_ops.is_empty() {
                break;
            }

            let mut scheduled = false;

            // Priority: reads > stat > open (keep throughput high).
            if let Some(file_slot) = read_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    // Push EndOfFile so scan thread resets per-file state.
                    push_with_backoff(&mut producer, ScanChunk::EndOfFile, &mut local_push_yields);
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                match &mut st.phase {
                    FilePhase::Ready(rs) => {
                        debug_assert_eq!(st.in_flight, 0);

                        if rs.next_offset >= rs.size {
                            st.done = true;
                            push_with_backoff(
                                &mut producer,
                                ScanChunk::EndOfFile,
                                &mut local_push_yields,
                            );
                            files[file_slot] = None;
                            free_file_slots.push(file_slot);
                            continue;
                        }

                        if let Some(mut buf) = pool.try_acquire() {
                            let offset = rs.next_offset;
                            let prefix_len = rs.overlap_len;
                            let payload_len = (rs.size - offset).min(chunk_size as u64) as usize;

                            debug_assert!(prefix_len + payload_len <= buf_len);

                            if prefix_len > 0 {
                                buf.as_mut_slice()[..prefix_len]
                                    .copy_from_slice(&rs.overlap_buf[..prefix_len]);
                            }

                            let op_slot = free_ops.pop().unwrap();
                            let fd = rs.file.as_raw_fd();
                            // SAFETY: `prefix_len < buf_len` so `add(prefix_len)` is in-bounds.
                            let ptr = unsafe { buf.as_mut_slice().as_mut_ptr().add(prefix_len) };

                            let entry = opcode::Read::new(types::Fd(fd), ptr, payload_len as u32)
                                .offset(offset)
                                .build()
                                .user_data(op_slot as u64);

                            unsafe {
                                let mut sq = ring.submission();
                                if sq.push(&entry).is_err() {
                                    drop(buf);
                                    free_ops.push(op_slot);
                                    read_ready.push_front(file_slot);
                                    break;
                                }
                            }

                            let base_offset = offset.saturating_sub(prefix_len as u64);

                            ops[op_slot] = Some(ShardOp::Read(ShardReadOp {
                                file_slot,
                                base_offset,
                                prefix_len,
                                payload_len,
                                buf,
                            }));

                            in_flight_ops += 1;
                            submitted_this_round += 1;
                            st.in_flight = 1;
                            rs.next_offset = rs.next_offset.saturating_add(payload_len as u64);
                            scheduled = true;
                        } else {
                            read_ready.push_back(file_slot);
                        }
                    }
                    FilePhase::PendingOpen { .. } => {
                        open_ready.push_back(file_slot);
                    }
                    FilePhase::PendingStat { .. } => {
                        stat_ready.push_back(file_slot);
                    }
                }
            }

            if scheduled {
                continue;
            }

            // --- Stat submissions ---
            if let Some(file_slot) = stat_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingStat { file } = &st.phase else {
                    match &st.phase {
                        FilePhase::PendingOpen { .. } => open_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingStat { .. } => {}
                    }
                    continue;
                };

                let Some(file) = file.as_ref() else {
                    st.failed = true;
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                };

                debug_assert_eq!(st.in_flight, 0);

                let mut statx_buf = Box::new(unsafe { std::mem::zeroed::<libc::statx>() });
                let statx_ptr = statx_buf.as_mut() as *mut libc::statx as *mut types::statx;
                let empty_path = b"\0";

                let entry = opcode::Statx::new(
                    types::Fd(file.as_raw_fd()),
                    empty_path.as_ptr() as *const _,
                    statx_ptr,
                )
                .flags(libc::AT_EMPTY_PATH)
                .mask(libc::STATX_SIZE | libc::STATX_TYPE | libc::STATX_MODE)
                .build();

                let op_slot = free_ops.pop().unwrap();
                let entry = entry.user_data(op_slot as u64);

                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        stat_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(ShardOp::Stat(StatOp {
                    file_slot,
                    statx_buf,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                st.in_flight = 1;
                scheduled = true;
            }

            if scheduled {
                continue;
            }

            // --- Open submissions ---
            if let Some(file_slot) = open_ready.pop_front() {
                let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                    continue;
                };

                if st.failed || st.done {
                    st.done = true;
                    files[file_slot] = None;
                    free_file_slots.push(file_slot);
                    continue;
                }

                let FilePhase::PendingOpen { path } = &st.phase else {
                    match &st.phase {
                        FilePhase::PendingStat { .. } => stat_ready.push_back(file_slot),
                        FilePhase::Ready(_) => read_ready.push_back(file_slot),
                        FilePhase::PendingOpen { .. } => {}
                    }
                    continue;
                };

                debug_assert_eq!(st.in_flight, 0);

                let flags = libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | if cfg.follow_symlinks {
                        0
                    } else {
                        libc::O_NOFOLLOW
                    };
                let use_openat2 = open_stat_caps.as_ref().is_some_and(|caps| caps.openat2);

                let path_cstr = match CString::new(path.as_os_str().as_bytes()) {
                    Ok(s) => s,
                    Err(_) => {
                        stats.io_errors = stats.io_errors.saturating_add(1);
                        st.failed = true;
                        st.done = true;
                        files[file_slot] = None;
                        free_file_slots.push(file_slot);
                        continue;
                    }
                };

                let open_how = if use_openat2 {
                    let resolve = resolve_bits(cfg.resolve_policy);
                    Some(Box::new(
                        types::OpenHow::new().flags(flags as u64).resolve(resolve),
                    ))
                } else {
                    None
                };

                let op_slot = free_ops.pop().unwrap();
                let entry = if use_openat2 {
                    let how = open_how.as_ref().expect("open_how missing");
                    opcode::OpenAt2::new(
                        types::Fd(libc::AT_FDCWD),
                        path_cstr.as_ptr(),
                        how.as_ref(),
                    )
                    .build()
                } else {
                    opcode::OpenAt::new(types::Fd(libc::AT_FDCWD), path_cstr.as_ptr())
                        .flags(flags)
                        .mode(0)
                        .build()
                }
                .user_data(op_slot as u64);

                unsafe {
                    let mut sq = ring.submission();
                    if sq.push(&entry).is_err() {
                        free_ops.push(op_slot);
                        open_ready.push_front(file_slot);
                        break;
                    }
                }

                ops[op_slot] = Some(ShardOp::Open(OpenOp {
                    file_slot,
                    path: path_cstr,
                    open_how,
                }));

                in_flight_ops += 1;
                submitted_this_round += 1;
                st.in_flight = 1;
                scheduled = true;
            }

            if !scheduled {
                break;
            }
        }

        // Batch submit.
        if submitted_this_round > 0 {
            ring.submit()?;
        }

        // Decide what to do based on current state.
        if in_flight_ops == 0 {
            let has_work =
                !open_ready.is_empty() || !stat_ready.is_empty() || !read_ready.is_empty();

            if !has_work {
                if channel_closed {
                    break;
                }
                // Block on channel for new work.
                match file_rx.recv() {
                    Ok(w) => {
                        add_file(
                            w,
                            &mut stats,
                            &mut files,
                            &mut free_file_slots,
                            &mut open_ready,
                            &mut read_ready,
                            &mut producer,
                        );
                        continue;
                    }
                    Err(_) => {
                        channel_closed = true;
                        break;
                    }
                }
            } else {
                // Work queued but resources unavailable. Yield then retry.
                std::thread::yield_now();
                continue;
            }
        }

        // Wait for completions.
        let cq_empty = {
            let cq = ring.completion();
            cq.is_empty()
        };
        if cq_empty {
            if submitted_this_round == 0 {
                ring.submit_and_wait(1)?;
            } else if in_flight_ops >= cfg.io_depth {
                ring.submit_and_wait(1)?;
            }
        }

        // Drain completions.
        for cqe in ring.completion() {
            let op_slot = cqe.user_data() as usize;
            let res = cqe.result();

            let op = ops
                .get_mut(op_slot)
                .and_then(|o| o.take())
                .unwrap_or_else(|| {
                    panic!(
                        "shard io_uring CQE with unknown user_data {} (max slot: {})",
                        op_slot,
                        slots - 1
                    );
                });

            free_ops.push(op_slot);
            in_flight_ops = in_flight_ops.saturating_sub(1);

            match op {
                ShardOp::Read(op) => {
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        drop(op.buf);
                        continue;
                    };

                    st.in_flight = 0;

                    let FilePhase::Ready(rs) = &mut st.phase else {
                        drop(op.buf);
                        continue;
                    };

                    if res < 0 {
                        stats.io_errors = stats.io_errors.saturating_add(1);
                        st.failed = true;
                        st.done = true;
                        drop(op.buf);
                    } else {
                        let n = res as usize;
                        if n == 0 {
                            stats.io_errors = stats.io_errors.saturating_add(1);
                            st.failed = true;
                            st.done = true;
                            drop(op.buf);
                        } else {
                            if n < op.payload_len {
                                st.done = true;
                            }

                            let total_len = op.prefix_len.saturating_add(n);
                            let len = total_len as u32;

                            // Update overlap carry for next chunk.
                            if overlap > 0 {
                                let overlap_len = overlap.min(total_len);
                                if overlap_len > 0 {
                                    let start = total_len - overlap_len;
                                    rs.overlap_buf[..overlap_len].copy_from_slice(
                                        &op.buf.as_slice()[start..start + overlap_len],
                                    );
                                }
                                rs.overlap_len = overlap_len;
                            }

                            stats.bytes_read = stats.bytes_read.saturating_add(n as u64);

                            // Push chunk into SPSC ring for the scan thread.
                            push_with_backoff(
                                &mut producer,
                                ScanChunk::Chunk {
                                    buf: op.buf,
                                    base_offset: op.base_offset,
                                    prefix_len: op.prefix_len as u32,
                                    len,
                                    display: Arc::clone(&st.token.display),
                                    file_id: st.token.file_id,
                                },
                                &mut local_push_yields,
                            );

                            if !st.done && !st.failed && rs.next_offset < rs.size {
                                read_ready.push_back(op.file_slot);
                            } else {
                                st.done = true;
                            }
                        }
                    }

                    if st.done && st.in_flight == 0 {
                        push_with_backoff(
                            &mut producer,
                            ScanChunk::EndOfFile,
                            &mut local_push_yields,
                        );
                        stats.files_processed = stats.files_processed.saturating_add(1);
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                ShardOp::Open(op) => {
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        if res >= 0 {
                            unsafe {
                                libc::close(res);
                            }
                        }
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        stats.io_errors = stats.io_errors.saturating_add(1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            let path = match &mut st.phase {
                                FilePhase::PendingOpen { path } => std::mem::take(path),
                                _ => PathBuf::new(),
                            };

                            match blocking_open(&path, &mut stats) {
                                BlockingOutcome::Ready(read_state) => {
                                    st.phase = FilePhase::Ready(read_state);
                                    read_ready.push_back(op.file_slot);
                                }
                                BlockingOutcome::Skipped => {
                                    st.done = true;
                                }
                                BlockingOutcome::Failed => {
                                    st.failed = true;
                                    st.done = true;
                                }
                            }
                        } else {
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let fd = res;
                        let file = unsafe { File::from_raw_fd(fd) };
                        st.phase = FilePhase::PendingStat { file: Some(file) };
                        stat_ready.push_back(op.file_slot);
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
                ShardOp::Stat(op) => {
                    let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                        continue;
                    };

                    st.in_flight = 0;

                    if res < 0 {
                        stats.io_errors = stats.io_errors.saturating_add(1);
                        let errno = -res;
                        let can_fallback = cfg.open_stat_mode != OpenStatMode::UringRequired
                            && (errno == libc::EINVAL || errno == libc::EOPNOTSUPP);

                        if can_fallback {
                            let file = match &mut st.phase {
                                FilePhase::PendingStat { file } => file.as_ref(),
                                _ => None,
                            };

                            if let Some(file) = file {
                                match file.metadata() {
                                    Ok(m) => {
                                        let size = m.len();
                                        if let Some(max_sz) = cfg.max_file_size {
                                            if size > max_sz {
                                                st.done = true;
                                                if st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        }
                                        if size == 0 {
                                            st.done = true;
                                            if st.in_flight == 0 {
                                                files[op.file_slot] = None;
                                                free_file_slots.push(op.file_slot);
                                            }
                                            continue;
                                        }

                                        let file = match &mut st.phase {
                                            FilePhase::PendingStat { file } => {
                                                file.take().expect("file missing in PendingStat")
                                            }
                                            _ => {
                                                st.failed = true;
                                                st.done = true;
                                                if st.in_flight == 0 {
                                                    files[op.file_slot] = None;
                                                    free_file_slots.push(op.file_slot);
                                                }
                                                continue;
                                            }
                                        };

                                        st.phase = FilePhase::Ready(ReadState {
                                            file,
                                            size,
                                            next_offset: 0,
                                            overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                            overlap_len: 0,
                                        });
                                        read_ready.push_back(op.file_slot);
                                    }
                                    Err(_) => {
                                        st.failed = true;
                                        st.done = true;
                                    }
                                }
                            } else {
                                st.failed = true;
                                st.done = true;
                            }
                        } else {
                            st.failed = true;
                            st.done = true;
                        }
                    } else {
                        let statx = &*op.statx_buf;
                        let size = statx.stx_size;

                        if let Some(max_sz) = cfg.max_file_size {
                            if size > max_sz {
                                st.done = true;
                            }
                        }

                        if !st.done {
                            if size == 0 {
                                st.done = true;
                            } else {
                                let file = match &mut st.phase {
                                    FilePhase::PendingStat { file } => {
                                        file.take().expect("file missing in PendingStat")
                                    }
                                    _ => {
                                        st.failed = true;
                                        st.done = true;
                                        if st.in_flight == 0 {
                                            files[op.file_slot] = None;
                                            free_file_slots.push(op.file_slot);
                                        }
                                        continue;
                                    }
                                };

                                st.phase = FilePhase::Ready(ReadState {
                                    file,
                                    size,
                                    next_offset: 0,
                                    overlap_buf: vec![0u8; overlap].into_boxed_slice(),
                                    overlap_len: 0,
                                });
                                read_ready.push_back(op.file_slot);
                            }
                        }
                    }

                    if st.done && st.in_flight == 0 {
                        files[op.file_slot] = None;
                        free_file_slots.push(op.file_slot);
                    }
                }
            }
        }
    }

    // SAFETY: Drain remaining in-flight ops before returning.
    if in_flight_ops > 0 {
        // Reuse drain logic: convert ShardOp to the drain-compatible form.
        // We drain manually here since ShardOp != Op.
        while in_flight_ops > 0 {
            ring.submit_and_wait(1)?;

            for cqe in ring.completion() {
                let op_slot = cqe.user_data() as usize;

                if let Some(op) = ops.get_mut(op_slot).and_then(|o| o.take()) {
                    let res = cqe.result();
                    in_flight_ops = in_flight_ops.saturating_sub(1);

                    match op {
                        ShardOp::Read(op) => {
                            drop(op.buf);
                        }
                        ShardOp::Open(_op) => {
                            if res >= 0 {
                                unsafe {
                                    libc::close(res);
                                }
                            }
                        }
                        ShardOp::Stat(_op) => {}
                    }
                }
            }
        }
    }

    // Push shutdown sentinel for the scan thread.
    push_with_backoff(&mut producer, ScanChunk::Shutdown, &mut local_push_yields);

    // Accumulate backoff counters into stats.
    stats.push_yields = stats.push_yields.saturating_add(local_push_yields);

    Ok(stats)
}

// ============================================================================
// Sharded io_uring Coordinator
// ============================================================================

/// Scan local filesystem files using per-shard io_uring I/O threads.
///
/// Structurally identical to [`super::local_fs_sharded::scan_local_fs_sharded`]
/// but uses [`shard_io_uring_loop`] instead of the blocking I/O thread. The scan
/// thread ([`shard_scan_loop`]) is reused directly from `local_fs_sharded`.
///
/// # Platform
///
/// Linux-only. Requires kernel io_uring support (5.1+, 5.6+ for open/stat).
pub fn scan_local_fs_uring_sharded<E: ScanEngine>(
    engine: Arc<E>,
    files: impl Iterator<Item = LocalFile>,
    cfg: ShardedFsUringConfig,
) -> io::Result<ShardedFsReport> {
    let num_shards = cfg.shards.max(1);
    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(
        buf_len <= BUFFER_LEN_MAX,
        "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
        buf_len,
        BUFFER_LEN_MAX
    );

    let wall_start = std::time::Instant::now();

    // --- Create per-shard infrastructure ---

    let mut shard_senders: Vec<crossbeam_channel::Sender<ShardFileWork>> =
        Vec::with_capacity(num_shards);
    let mut shard_receivers: Vec<crossbeam_channel::Receiver<ShardFileWork>> =
        Vec::with_capacity(num_shards);
    let mut shard_budgets: Vec<Arc<CountBudget>> = Vec::with_capacity(num_shards);

    for _ in 0..num_shards {
        let (tx, rx) = crossbeam_channel::bounded(cfg.max_in_flight_per_shard);
        shard_senders.push(tx);
        shard_receivers.push(rx);
        shard_budgets.push(CountBudget::new(cfg.max_in_flight_per_shard));
    }

    // --- Spawn shard threads ---

    let mut io_handles: Vec<thread::JoinHandle<io::Result<ShardIoStats>>> =
        Vec::with_capacity(num_shards);
    let mut scan_handles: Vec<thread::JoinHandle<ShardScanStats>> = Vec::with_capacity(num_shards);

    for (shard_idx, file_rx) in shard_receivers.iter().enumerate() {
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: buf_len,
            total_buffers: cfg.pool_buffers_per_shard,
            workers: 2,
            local_queue_cap: cfg.local_queue_cap,
        });

        let (spsc_producer, spsc_consumer) = spsc_channel::<ScanChunk, SHARD_SPSC_CAP>();

        let file_rx = file_rx.clone();
        let engine_io = Arc::clone(&engine);
        let engine_scan = Arc::clone(&engine);
        let event_sink = Arc::clone(&cfg.event_sink);
        let dedupe = cfg.dedupe_within_chunk;
        let pin_threads = cfg.pin_threads;

        let uring_cfg = UringShardConfig {
            ring_entries: cfg.ring_entries,
            io_depth: cfg.io_depth,
            chunk_size: cfg.chunk_size,
            max_file_size: Some(cfg.max_file_size),
            follow_symlinks: cfg.follow_symlinks,
            open_stat_mode: cfg.open_stat_mode,
            resolve_policy: cfg.resolve_policy,
        };

        // I/O thread (io_uring)
        let io_pool = pool.clone();
        let io_handle = thread::Builder::new()
            .name(format!("shard-{shard_idx}-uring-io"))
            .spawn(move || {
                if pin_threads {
                    let core = shard_idx * 2;
                    let _ = pin_current_thread_to_core(core);
                }

                shard_io_uring_loop::<E>(file_rx, spsc_producer, io_pool, engine_io, &uring_cfg)
            })
            .map_err(io::Error::other)?;

        // Scan thread (reused from local_fs_sharded)
        let scan_handle = thread::Builder::new()
            .name(format!("shard-{shard_idx}-scan"))
            .spawn(move || {
                if pin_threads {
                    let core = shard_idx * 2 + 1;
                    let _ = pin_current_thread_to_core(core);
                }

                shard_scan_loop(spsc_consumer, engine_scan, event_sink, dedupe)
            })
            .map_err(io::Error::other)?;

        io_handles.push(io_handle);
        scan_handles.push(scan_handle);
    }

    drop(shard_receivers);

    // --- Round-robin files across shards ---

    let mut files_enqueued: u64 = 0;
    let mut shard_rr: usize = 0;

    for local_file in files {
        let shard_idx = shard_rr % num_shards;
        shard_rr = shard_rr.wrapping_add(1);

        let permit = shard_budgets[shard_idx].acquire(1);

        let work = ShardFileWork {
            path: local_file.path,
            size: local_file.size,
            _permit: permit,
        };

        if shard_senders[shard_idx].send(work).is_err() {
            break;
        }

        files_enqueued = files_enqueued.saturating_add(1);
    }

    drop(shard_senders);

    // --- Join all threads and collect stats ---

    let mut io_stats: Vec<ShardIoStats> = Vec::with_capacity(num_shards);
    let mut scan_stats: Vec<ShardScanStats> = Vec::with_capacity(num_shards);

    for handle in io_handles {
        match handle.join() {
            Ok(Ok(s)) => io_stats.push(s),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::other("shard io_uring I/O thread panicked")),
        }
    }

    for handle in scan_handles {
        match handle.join() {
            Ok(s) => scan_stats.push(s),
            Err(_) => return Err(io::Error::other("shard scan thread panicked")),
        }
    }

    let wall_time_ns = wall_start.elapsed().as_nanos() as u64;

    cfg.event_sink.flush();

    // --- Aggregate metrics ---

    let mut metrics = MetricsSnapshot::new();

    for io_s in &io_stats {
        metrics.io_errors = metrics.io_errors.saturating_add(io_s.io_errors);
    }

    for scan_s in &scan_stats {
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(scan_s.bytes_scanned);
        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(scan_s.chunks_scanned);
        metrics.findings_emitted = metrics
            .findings_emitted
            .saturating_add(scan_s.findings_emitted);
    }

    metrics.worker_count = (num_shards * 2) as u32;
    metrics.duration_ns = wall_time_ns;

    Ok(ShardedFsReport {
        io_stats,
        scan_stats,
        files_enqueued,
        wall_time_ns,
        metrics,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::engine_stub::{EngineTuning, MockEngine, MockRule};
    use super::super::{TsBufferPool, TsBufferPoolConfig};
    use super::*;
    use crate::unified::events::VecEventSink;
    use tempfile::tempdir;

    #[test]
    fn uring_finds_boundary_spanning_match() -> io::Result<()> {
        // Create a mock engine that looks for "SECRET"
        let engine = Arc::new(MockEngine::with_tuning(
            vec![MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            }],
            6, // overlap = pattern length to catch boundary spans
            EngineTuning {
                max_findings_per_chunk: 128,
                max_rules: 16,
            },
        ));

        let dir = tempdir()?;
        let file_path = dir.path().join("a.txt");

        // Force boundary for chunk_size=8.
        // Content: "xxxxSECRETyyyyyy" (16 bytes)
        // With chunk_size=8, first chunk = [0..8), second = [8..16)
        // "SECRET" spans bytes 4-10, crossing the boundary at 8.
        let content = b"xxxxSECRETyyyyyy";
        std::fs::write(&file_path, content)?;

        let sink = Arc::new(VecEventSink::new());

        let cfg = LocalFsUringConfig {
            cpu_workers: 2,
            io_threads: 1,
            ring_entries: 64,
            io_depth: 16,
            chunk_size: 8,
            max_in_flight_files: 8,
            file_queue_cap: 8,
            pool_buffers: 32,
            use_registered_buffers: false,
            open_stat_mode: OpenStatMode::BlockingOnly,
            resolve_policy: ResolvePolicy::Default,
            follow_symlinks: false,
            max_file_size: None,
            seed: 123,
            dedupe_within_chunk: true,
        };

        let (_summary, _io_stats, _cpu_metrics) =
            scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

        let out = sink.take();
        let out_str = String::from_utf8_lossy(&out);
        assert!(
            out_str.contains("secret"),
            "expected output to contain rule name 'secret', got: {}",
            out_str
        );

        Ok(())
    }

    #[test]
    fn global_only_pool_works() {
        // Verify global-only pool (workers=0, local_queue_cap=0) doesn't panic
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 8,
            workers: 0,
            local_queue_cap: 0,
        });

        // Acquire and release a buffer to verify basic functionality
        let buf = pool.try_acquire();
        assert!(buf.is_some());

        drop(buf);

        // Verify we can acquire again after release
        let buf2 = pool.try_acquire();
        assert!(buf2.is_some());
    }

    #[test]
    fn uring_open_stat_parity_with_blocking() -> io::Result<()> {
        let engine = Arc::new(MockEngine::with_tuning(
            vec![MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            }],
            6,
            EngineTuning {
                max_findings_per_chunk: 128,
                max_rules: 16,
            },
        ));

        let dir = tempdir()?;
        let file_path = dir.path().join("a.txt");
        std::fs::write(&file_path, b"xxSECRETyy")?;

        let base_cfg = LocalFsUringConfig {
            cpu_workers: 2,
            io_threads: 1,
            ring_entries: 64,
            io_depth: 16,
            chunk_size: 16,
            max_in_flight_files: 8,
            file_queue_cap: 8,
            pool_buffers: 32,
            use_registered_buffers: false,
            open_stat_mode: OpenStatMode::BlockingOnly,
            resolve_policy: ResolvePolicy::Default,
            follow_symlinks: false,
            max_file_size: None,
            seed: 123,
            dedupe_within_chunk: true,
        };

        let sink_blocking = Arc::new(VecEventSink::new());
        let (_summary, _io_stats, _cpu_metrics) = scan_local_fs_uring(
            Arc::clone(&engine),
            &[dir.path().to_path_buf()],
            base_cfg.clone(),
            sink_blocking.clone(),
        )?;
        let out_blocking = sink_blocking.take();

        let sink_uring = Arc::new(VecEventSink::new());
        let mut uring_cfg = base_cfg;
        uring_cfg.open_stat_mode = OpenStatMode::UringPreferred;
        let (_summary, _io_stats, _cpu_metrics) = scan_local_fs_uring(
            Arc::clone(&engine),
            &[dir.path().to_path_buf()],
            uring_cfg,
            sink_uring.clone(),
        )?;
        let out_uring = sink_uring.take();

        assert_eq!(
            out_blocking, out_uring,
            "open/stat path should match blocking output"
        );

        Ok(())
    }

    #[test]
    fn blocking_mode_skips_open_stat_ops() -> io::Result<()> {
        let engine = Arc::new(MockEngine::with_tuning(
            vec![MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            }],
            6,
            EngineTuning {
                max_findings_per_chunk: 128,
                max_rules: 16,
            },
        ));

        let dir = tempdir()?;
        let file_path = dir.path().join("a.txt");
        std::fs::write(&file_path, b"xxSECRETyy")?;

        let cfg = LocalFsUringConfig {
            cpu_workers: 2,
            io_threads: 1,
            ring_entries: 64,
            io_depth: 16,
            chunk_size: 16,
            max_in_flight_files: 8,
            file_queue_cap: 8,
            pool_buffers: 32,
            use_registered_buffers: false,
            open_stat_mode: OpenStatMode::BlockingOnly,
            resolve_policy: ResolvePolicy::Default,
            follow_symlinks: false,
            max_file_size: None,
            seed: 123,
            dedupe_within_chunk: true,
        };

        let sink = Arc::new(VecEventSink::new());
        let (_summary, io_stats, _cpu_metrics) =
            scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink)?;

        assert_eq!(io_stats.open_ops_submitted, 0);
        assert_eq!(io_stats.stat_ops_submitted, 0);
        assert_eq!(io_stats.open_stat_fallbacks, 0);

        Ok(())
    }
}
