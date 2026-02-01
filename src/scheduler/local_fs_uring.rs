//! Local Filesystem Scanner with io_uring
//!
//! # Architecture
//!
//! - I/O threads use io_uring for async reads
//! - CPU threads run the work-stealing executor for scanning
//! - Buffer ownership transfers: I/O thread acquires, CPU thread releases
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
use super::engine_stub::{FileId, FindingRec, MockEngine, ScanScratch, BUFFER_LEN_MAX};
use super::executor::{Executor, ExecutorConfig, ExecutorHandle, WorkerCtx};
use super::metrics::MetricsSnapshot;
use super::output_sink::OutputSink;
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};

use crossbeam_channel as chan;

use io_uring::{opcode, types, IoUring};

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for local FS scanning using io_uring I/O threads + CPU executor scan threads.
#[derive(Clone, Debug)]
pub struct LocalFsUringConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,

    /// Number of I/O threads running io_uring.
    pub io_threads: usize,

    /// Number of SQ/CQ entries per io_uring.
    pub ring_entries: u32,

    /// Max in-flight read ops per I/O thread.
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
    pub fn validate(&self, engine: &MockEngine) {
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
    pub reads_submitted: u64,
    pub reads_completed: u64,
    pub read_errors: u64,
    pub short_reads: u64,
}

impl UringIoStats {
    fn merge(&mut self, other: UringIoStats) {
        self.files_started += other.files_started;
        self.files_open_failed += other.files_open_failed;
        self.reads_submitted += other.reads_submitted;
        self.reads_completed += other.reads_completed;
        self.read_errors += other.read_errors;
        self.short_reads += other.short_reads;
    }
}

// ============================================================================
// Internal Types
// ============================================================================

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
// Deduplication Helpers
// ============================================================================

/// In-place dedupe of findings by (rule_id, root_hint, span).
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

/// Format and emit findings to output sink.
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

        use std::io::Write as _;
        let _ = write!(
            out_buf,
            ":{}-{} {}\n",
            rec.root_hint_start, rec.root_hint_end, rule
        );
    }

    out.write_all(out_buf.as_slice());
}

// ============================================================================
// CPU Task Runner
// ============================================================================

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

            emit_findings_formatted(
                engine,
                &ctx.scratch.out,
                &mut ctx.scratch.out_buf,
                &token.display,
                &ctx.scratch.pending,
            );

            // Metrics: payload bytes only (exclude overlap prefix).
            let payload = (len as u64).saturating_sub(prefix_len as u64);
            ctx.metrics.chunks_scanned += 1;
            ctx.metrics.bytes_scanned += payload;

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
/// - `in_flight` is 0 or 1 (we enforce single-chunk-in-flight per file)
/// - `done` is monotonic: once true, never reset to false
/// - `failed` is monotonic: once true, never reset to false
/// - `next_offset` only advances, never retreats
struct FileState {
    file: File,
    size: u64,
    next_offset: u64,
    in_flight: u32,
    done: bool,
    failed: bool,
    token: Arc<FileToken>,
}

/// Per-read-op state for completion matching.
///
/// # Lifetime Coupling
///
/// The `buf` field's backing memory is referenced by the kernel until the
/// corresponding CQE is reaped. The `file_slot` keeps the file open.
/// Both must remain valid until completion.
struct Op {
    file_slot: usize,
    base_offset: u64,
    prefix_len: usize,
    requested_len: usize,
    buf: TsBufferHandle,
}

// ============================================================================
// I/O Worker Loop
// ============================================================================

/// Drain all in-flight operations before returning.
///
/// SAFETY: This MUST be called before dropping the ring/ops if any operations
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
                // Buffer dropped here, returned to pool
                drop(op.buf);
                *in_flight_ops = in_flight_ops.saturating_sub(1);
                stats.reads_completed += 1;

                // Count errors even during drain
                if cqe.result() < 0 {
                    stats.read_errors += 1;
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
/// - **Drain before return**: All in-flight ops MUST complete before we return,
///   otherwise the kernel may write to freed memory.
/// - **Buffer lifetime**: Buffers live in `ops[]` until CQE is reaped.
///
/// # Shutdown
///
/// On `stop` signal or channel close, we stop accepting new work but drain
/// all in-flight operations to completion.
fn io_worker_loop(
    _wid: usize,
    rx: chan::Receiver<FileWork>,
    pool: TsBufferPool,
    cpu: ExecutorHandle<CpuTask>,
    engine: Arc<MockEngine>,
    cfg: LocalFsUringConfig,
    stop: Arc<AtomicBool>,
) -> io::Result<UringIoStats> {
    let overlap = engine.required_overlap();
    let chunk_size = cfg.chunk_size;
    let buf_len = overlap.saturating_add(chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    let mut ring = IoUring::new(cfg.ring_entries)?;
    let mut stats = UringIoStats::default();

    // File slab + queue for files ready to submit (not currently in-flight).
    let mut files: Vec<Option<FileState>> = Vec::new();
    let mut free_file_slots: Vec<usize> = Vec::new();
    // CORRECTNESS: Files in `ready` queue have in_flight == 0.
    // We enforce exactly one chunk in-flight per file to ensure prefix-drop
    // logic is valid (no gaps from failed earlier chunks).
    let mut ready: VecDeque<usize> = VecDeque::new();

    // Op slots keyed by user_data.
    let slots = cfg.ring_entries as usize;
    let mut ops: Vec<Option<Op>> = (0..slots).map(|_| None).collect();
    let mut free_ops: Vec<usize> = (0..slots).rev().collect();

    let mut in_flight_ops: usize = 0;
    let mut stopping = false;
    let mut channel_closed = false;

    // Helper: add file work to tracking.
    let add_file = |w: FileWork,
                    stats: &mut UringIoStats,
                    files: &mut Vec<Option<FileState>>,
                    free_file_slots: &mut Vec<usize>,
                    ready: &mut VecDeque<usize>,
                    follow_symlinks: bool| {
        stats.files_started += 1;

        // Use O_NOFOLLOW when follow_symlinks is false to prevent TOCTOU attacks.
        let file = match open_file_safe(&w.path, follow_symlinks) {
            Ok(f) => f,
            Err(_) => {
                stats.files_open_failed += 1;
                // Drop token: permit releases immediately (no scan tasks).
                drop(w.token);
                return;
            }
        };

        // Use actual file size from fstat, not discovery-time size.
        // This handles files that grew or shrank between discovery and open.
        let size = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => {
                stats.files_open_failed += 1;
                drop(w.token);
                return;
            }
        };

        // Skip empty files.
        if size == 0 {
            drop(w.token);
            return;
        }

        let slot = free_file_slots.pop().unwrap_or_else(|| {
            files.push(None);
            files.len() - 1
        });

        files[slot] = Some(FileState {
            file,
            size,
            next_offset: 0,
            in_flight: 0,
            done: false,
            failed: false,
            token: w.token,
        });

        ready.push_back(slot);
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
                        &mut ready,
                        cfg.follow_symlinks,
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
        // CORRECTNESS: Only one chunk in-flight per file at a time.
        while in_flight_ops < cfg.io_depth && !stopping {
            if ready.is_empty() {
                break;
            }
            if free_ops.is_empty() {
                break;
            }

            // Acquire buffer first to avoid holding op slot while stalled.
            let Some(buf) = pool.try_acquire() else {
                break;
            };

            let file_slot = ready.pop_front().unwrap();
            let Some(st) = files.get_mut(file_slot).and_then(|s| s.as_mut()) else {
                // Stale slot.
                drop(buf);
                continue;
            };

            // INVARIANT: Files in ready queue should have in_flight == 0.
            debug_assert_eq!(
                st.in_flight, 0,
                "file in ready queue should not have in-flight ops"
            );

            if st.failed || st.done || st.next_offset >= st.size {
                st.done = true;
                drop(buf);
                // Cleanup immediately since nothing in flight.
                files[file_slot] = None;
                free_file_slots.push(file_slot);
                continue;
            }

            let offset = st.next_offset;
            let base_offset = offset.saturating_sub(overlap as u64);
            let prefix_len = (offset - base_offset) as usize;

            let payload_len = (st.size - offset).min(chunk_size as u64) as usize;
            let requested_len = prefix_len + payload_len;

            debug_assert!(requested_len <= buf_len);

            let op_slot = free_ops.pop().unwrap();
            let fd = st.file.as_raw_fd();
            let ptr = buf.as_slice().as_ptr() as *mut u8;

            let entry = opcode::Read::new(types::Fd(fd), ptr, requested_len as u32)
                .offset(base_offset)
                .build()
                .user_data(op_slot as u64);

            // SAFETY:
            // - `buf` lives in `ops[op_slot]` until completion
            // - `st.file` lives until file cleanup
            // - We drain all in-flight ops before returning
            unsafe {
                let mut sq = ring.submission();
                if sq.push(&entry).is_err() {
                    // SQ unexpectedly full - return resources and break.
                    drop(buf);
                    free_ops.push(op_slot);
                    ready.push_front(file_slot);
                    break;
                }
            }

            ops[op_slot] = Some(Op {
                file_slot,
                base_offset,
                prefix_len,
                requested_len,
                buf,
            });

            in_flight_ops += 1;
            submitted_this_round += 1;
            stats.reads_submitted += 1;

            st.in_flight = 1; // Exactly 1 - single in-flight per file
            st.next_offset = st.next_offset.saturating_add(payload_len as u64);
            // NOTE: Do NOT add back to ready here. Happens on completion.
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

            if ready.is_empty() {
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
                            &mut ready,
                            cfg.follow_symlinks,
                        );
                        continue;
                    }
                    Err(_) => {
                        channel_closed = true;
                        // Check if we have any ready files to process.
                        if ready.is_empty() {
                            break;
                        }
                        // Else continue to try submitting.
                        continue;
                    }
                }
            } else {
                // Files ready but no buffers available.
                // Yield to let CPU workers release buffers, then retry.
                // This avoids busy-spin while waiting for pool.
                std::thread::yield_now();
                continue;
            }
        }

        // We have ops in flight - wait for at least one completion.
        // Only use submit_and_wait if we didn't submit this round.
        if submitted_this_round == 0 {
            ring.submit_and_wait(1)?;
        } else if in_flight_ops >= cfg.io_depth {
            // At capacity, must wait for completions before submitting more.
            ring.submit_and_wait(1)?;
        }
        // else: we submitted and have room, check completions opportunistically

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
            stats.reads_completed += 1;

            let Some(st) = files.get_mut(op.file_slot).and_then(|s| s.as_mut()) else {
                // File already cleaned up (shouldn't happen with 1-in-flight).
                drop(op.buf);
                continue;
            };

            st.in_flight = 0;

            if res < 0 {
                // Read syscall failed.
                stats.read_errors += 1;
                st.failed = true;
                st.done = true;
                drop(op.buf);
            } else {
                let n = res as usize;
                if n == 0 {
                    // Unexpected EOF (empty read).
                    stats.read_errors += 1;
                    st.failed = true;
                    st.done = true;
                    drop(op.buf);
                } else {
                    if n < op.requested_len {
                        // Short read: file likely shrank. Treat as truncation.
                        // We scan what we got, but mark file done since we can't
                        // trust our offset calculations for subsequent chunks.
                        stats.short_reads += 1;
                        st.done = true;
                    }

                    let actual_prefix = op.prefix_len.min(n);
                    let len = n as u32;

                    let task = CpuTask::ScanChunk {
                        token: Arc::clone(&st.token),
                        base_offset: op.base_offset,
                        prefix_len: actual_prefix as u32,
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
                        if !st.done && !st.failed && st.next_offset < st.size {
                            ready.push_back(op.file_slot);
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
    }

    // SAFETY: Drain any remaining in-flight ops before returning.
    // This ensures the kernel finishes writing before we drop buffers.
    if in_flight_ops > 0 {
        drain_in_flight(&mut ring, &mut ops, &mut in_flight_ops, &mut stats)?;
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
                    summary.walk_errors += 1;
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
                    summary.walk_errors += 1;
                    continue;
                }
            }
        };

        if meta.is_dir() {
            let rd = match fs::read_dir(&path) {
                Ok(rd) => rd,
                Err(_) => {
                    summary.walk_errors += 1;
                    continue;
                }
            };

            for ent in rd {
                match ent {
                    Ok(ent) => stack.push(ent.path()),
                    Err(_) => summary.walk_errors += 1,
                }
            }
            continue;
        }

        if !meta.is_file() {
            continue;
        }

        summary.files_seen += 1;

        let size = meta.len();

        if let Some(max_sz) = cfg.max_file_size {
            if size > max_sz {
                summary.files_skipped_size += 1;
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

        summary.files_enqueued += 1;
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
/// - `engine`: Detection engine (provides overlap requirement and scanning)
/// - `roots`: Root directories to scan
/// - `cfg`: Configuration
/// - `out`: Output sink for findings
///
/// # Returns
///
/// Tuple of (discovery summary, I/O stats, CPU metrics).
///
/// # Errors
///
/// Returns `io::Error` if io_uring initialization fails or an I/O thread panics.
pub fn scan_local_fs_uring(
    engine: Arc<MockEngine>,
    roots: &[PathBuf],
    cfg: LocalFsUringConfig,
    out: Arc<dyn OutputSink>,
) -> io::Result<(LocalFsSummary, UringIoStats, MetricsSnapshot)> {
    cfg.validate(&engine);

    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(buf_len <= BUFFER_LEN_MAX);

    // Global-only pool because I/O threads acquire and CPU threads release.
    // Using workers=0 and local_queue_cap=0 configures global-only mode.
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: cfg.pool_buffers,
        workers: 0,
        local_queue_cap: 0,
    });

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
            Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "io thread panicked")),
        }
    }

    summary.open_errors = io_stats.files_open_failed;
    summary.read_errors = io_stats.read_errors;

    // Join CPU executor.
    let cpu_metrics = ex.join();

    out.flush();

    Ok((summary, io_stats, cpu_metrics))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::engine_stub::{EngineTuning, MockRule};
    use super::super::output_sink::VecSink;
    use super::*;
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

        let sink = Arc::new(VecSink::new());

        let cfg = LocalFsUringConfig {
            cpu_workers: 2,
            io_threads: 1,
            ring_entries: 64,
            io_depth: 16,
            chunk_size: 8,
            max_in_flight_files: 8,
            file_queue_cap: 8,
            pool_buffers: 32,
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
}
