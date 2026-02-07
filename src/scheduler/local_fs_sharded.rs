//! Share-Nothing Filesystem Scanner with posix_fadvise Prefetch
//!
//! # Architecture
//!
//! Each worker thread does both I/O and scan, keeping data hot in L1/L2 cache.
//! Only a file channel is shared (cold path, per-file granularity).
//!
//! ```text
//! Coordinator (main thread)
//!   |  files via shared bounded channel (cold path, per-file granularity)
//!   v
//! Worker 0: recv file → open → [fadvise + read → scan → emit] loop → next file
//! Worker 1: recv file → open → [fadvise + read → scan → emit] loop → next file
//!   ...
//! Worker N-1: file_rx exhausted → exit
//!
//! Per-worker (share-nothing):
//!   - worker_id → own local queue in TsBufferPool (zero contention)
//!   - own engine scratch (reused across all files)
//!   - own findings Vec (reused across all chunks)
//!   - ONE buffer per file, copy_within for overlap carry
//! ```
//!
//! # Backpressure
//!
//! - **File-level**: Bounded file channel (coordinator → workers).
//! - **Buffer-level**: Per-worker local queue in [`TsBufferPool`] limits peak memory.
//!
//! # posix_fadvise
//!
//! - `FADV_SEQUENTIAL` once at file open → kernel uses aggressive readahead
//! - `FADV_WILLNEED` before scanning each chunk, for *next* chunk's range →
//!   kernel prefetches during scan, overlapping I/O with CPU work

use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use super::local::LocalFile;
use super::metrics::MetricsSnapshot;
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::archive::{detect_kind_from_path, sniff_kind_from_header, ArchiveConfig};
use crate::scheduler::affinity::pin_current_thread_to_core;
use crate::scheduler::worker_id::set_current_worker_id;
use crate::unified::events::{EventSink, FindingEvent, ScanEvent};
use crate::unified::SourceKind;

// ============================================================================
// Constants
// ============================================================================

/// Header sniff buffer size for archive detection.
const SNIFF_HEADER_LEN: usize = 8;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the share-nothing filesystem scanner.
///
/// # Sizing Guidelines
///
/// | Parameter | Default | Guidance |
/// |-----------|---------|----------|
/// | `workers` | CPU count | One thread per core, each doing I/O+scan |
/// | `chunk_size` | 256 KiB | Larger = fewer syscalls, more memory per file |
/// | `max_file_size` | 100 MiB | Skip files larger than this |
/// | `pool_buffers_per_worker` | 4 | Per-worker local queue size |
/// | `file_channel_cap` | 256 | Bounded file channel depth |
pub struct ShardedFsConfig {
    /// Number of worker threads, each doing both I/O and scan.
    pub workers: usize,

    /// Payload bytes per chunk (excluding overlap).
    ///
    /// Actual buffer size = `chunk_size + engine.required_overlap()`.
    pub chunk_size: usize,

    /// Maximum file size to scan (bytes). Files larger than this are skipped.
    pub max_file_size: u64,

    /// Number of buffers per worker in the pool's local queue.
    pub pool_buffers_per_worker: usize,

    /// Per-worker local queue capacity in the buffer pool.
    pub local_queue_cap: usize,

    /// Capacity of the bounded file channel from coordinator to workers.
    pub file_channel_cap: usize,

    /// Enable within-chunk finding deduplication.
    pub dedupe_within_chunk: bool,

    /// Archive scanning configuration.
    pub archive: ArchiveConfig,

    /// Event sink for emitting findings and progress events.
    pub event_sink: Arc<dyn EventSink>,

    /// Whether to attempt pinning worker threads to CPU cores.
    pub pin_threads: bool,
}

// ============================================================================
// FileWork — what the coordinator sends to workers
// ============================================================================

/// A file work item sent from the coordinator to worker threads.
struct FileWork {
    path: PathBuf,
}

// ============================================================================
// Per-Worker Statistics
// ============================================================================

/// Per-worker statistics (each worker does both I/O and scan).
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkerStats {
    /// Number of files fully processed.
    pub files_processed: u64,
    /// Total bytes read from disk.
    pub bytes_read: u64,
    /// Total bytes scanned (payload only, excluding overlap prefix).
    pub bytes_scanned: u64,
    /// Number of chunks scanned.
    pub chunks_scanned: u64,
    /// Total findings emitted.
    pub findings_emitted: u64,
    /// Number of I/O errors (open, stat, read failures).
    pub io_errors: u64,
    /// Number of files skipped because they are archives.
    pub archives_skipped: u64,
    /// Cumulative nanoseconds spent in open + fstat.
    pub open_stat_ns: u64,
    /// Cumulative nanoseconds spent in read syscalls.
    pub read_ns: u64,
    /// Cumulative nanoseconds spent in scan_chunk_into.
    pub scan_ns: u64,
}

/// Aggregated report from a filesystem scan.
#[derive(Debug)]
pub struct ShardedFsReport {
    /// Per-worker statistics (each worker does both I/O and scan).
    pub worker_stats: Vec<WorkerStats>,
    /// Total number of files enqueued.
    pub files_enqueued: u64,
    /// Wall-clock time of the entire scan in nanoseconds.
    pub wall_time_ns: u64,
    /// Aggregated metrics compatible with existing `MetricsSnapshot` consumers.
    pub metrics: MetricsSnapshot,
    /// Wall-clock nanoseconds the coordinator spent in the feed loop
    /// (iterating `walk_rx` + sending to `file_tx`).
    pub feed_elapsed_ns: u64,
    /// Cumulative nanoseconds the coordinator blocked inside `file_tx.send()`.
    /// High ratio to `feed_elapsed_ns` means workers are keeping up (channel full).
    pub feed_block_ns: u64,
}

// ============================================================================
// posix_fadvise helpers
// ============================================================================

/// Hint the kernel to use aggressive sequential readahead for the file.
#[cfg(target_os = "linux")]
fn fadvise_sequential(file: &File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
}

#[cfg(not(target_os = "linux"))]
fn fadvise_sequential(_file: &File) {}

/// Hint the kernel to prefetch bytes at `[offset, offset+len)`.
#[cfg(target_os = "linux")]
fn fadvise_willneed(file: &File, offset: i64, len: i64) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_WILLNEED);
    }
}

#[cfg(not(target_os = "linux"))]
fn fadvise_willneed(_file: &File, _offset: i64, _len: i64) {}

// ============================================================================
// EINTR-safe read helper
// ============================================================================

/// Read into `dst`, retrying on `EINTR`.
#[inline(always)]
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
// Deduplication Helpers
// ============================================================================

/// In-place deduplication of findings by `(rule_id, root_hint, span)`.
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

/// Emit findings as structured events through the event sink.
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
// Buffer acquisition with backoff
// ============================================================================

/// Acquire a buffer from the pool, spinning briefly then yielding when empty.
#[inline]
fn acquire_buffer_with_backoff(pool: &TsBufferPool) -> TsBufferHandle {
    if let Some(buf) = pool.try_acquire() {
        return buf;
    }
    loop {
        for _ in 0..16 {
            core::hint::spin_loop();
            if let Some(buf) = pool.try_acquire() {
                return buf;
            }
        }
        std::thread::yield_now();
    }
}

// ============================================================================
// Worker Thread — share-nothing I/O + scan
// ============================================================================

/// Worker thread main loop: receives files, does I/O and scan inline.
///
/// Each worker owns its engine scratch, findings buffer, and buffer pool
/// local queue. Data read from disk stays hot in L1/L2 when scanned
/// immediately.
#[allow(clippy::too_many_arguments)]
fn worker<E: ScanEngine>(
    file_rx: crossbeam_channel::Receiver<FileWork>,
    engine: Arc<E>,
    pool: TsBufferPool,
    event_sink: Arc<dyn EventSink>,
    chunk_size: usize,
    max_file_size: u64,
    archive_cfg: ArchiveConfig,
    dedupe: bool,
) -> WorkerStats {
    let overlap = engine.required_overlap();
    let mut stats = WorkerStats::default();
    let mut scratch = engine.new_scratch();
    let mut pending: Vec<<E::Scratch as EngineScratch>::Finding> = Vec::with_capacity(4096);

    for work in file_rx.iter() {
        process_file(
            &work,
            engine.as_ref(),
            &pool,
            &*event_sink,
            overlap,
            chunk_size,
            max_file_size,
            &archive_cfg,
            dedupe,
            &mut scratch,
            &mut pending,
            &mut stats,
        );
    }

    stats
}

/// Process a single file: open, stat, detect archives, read+scan chunks inline.
#[allow(clippy::too_many_arguments)]
fn process_file<E: ScanEngine>(
    work: &FileWork,
    engine: &E,
    pool: &TsBufferPool,
    event_sink: &dyn EventSink,
    overlap: usize,
    chunk_size: usize,
    max_file_size: u64,
    archive_cfg: &ArchiveConfig,
    dedupe: bool,
    scratch: &mut E::Scratch,
    pending: &mut Vec<<E::Scratch as EngineScratch>::Finding>,
    stats: &mut WorkerStats,
) {
    // --- Open + stat ---
    let t_open = Instant::now();
    let mut file = match File::open(&work.path) {
        Ok(f) => f,
        Err(_) => {
            stats.io_errors = stats.io_errors.saturating_add(1);
            return;
        }
    };

    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => {
            stats.io_errors = stats.io_errors.saturating_add(1);
            return;
        }
    };
    let open_stat_elapsed = t_open.elapsed().as_nanos() as u64;
    stats.open_stat_ns = stats.open_stat_ns.saturating_add(open_stat_elapsed);

    let file_size = meta.len();

    if file_size == 0 {
        return;
    }
    if file_size > max_file_size {
        return;
    }

    // --- Archive detection ---
    if archive_cfg.enabled {
        let is_archive = detect_kind_from_path(&work.path).is_some() || {
            let mut header = [0u8; SNIFF_HEADER_LEN];
            let sniffed = match read_some(&mut file, &mut header) {
                Ok(n) => sniff_kind_from_header(&header[..n]).is_some(),
                Err(_) => false,
            };
            let _ = file.seek(io::SeekFrom::Start(0));
            sniffed
        };

        if is_archive {
            stats.archives_skipped = stats.archives_skipped.saturating_add(1);
            return;
        }
    }

    // --- posix_fadvise: sequential readahead for entire file ---
    fadvise_sequential(&file);

    // --- Build display path (shared across all chunks of this file) ---
    #[cfg(unix)]
    let display: Arc<[u8]> = {
        use std::os::unix::ffi::OsStrExt;
        work.path
            .as_os_str()
            .as_bytes()
            .to_vec()
            .into_boxed_slice()
            .into()
    };
    #[cfg(not(unix))]
    let display: Arc<[u8]> = work
        .path
        .to_string_lossy()
        .as_bytes()
        .to_vec()
        .into_boxed_slice()
        .into();

    let file_id = FileId(0);

    // --- Acquire ONE buffer for the entire file ---
    let mut buf = acquire_buffer_with_backoff(pool);

    // --- Read+scan loop with overlap carry (copy_within pattern) ---
    let mut offset: u64 = 0; // Logical offset of next "new" bytes
    let mut carry: usize = 0; // Bytes of overlap prefix for next scan
    let mut have: usize = 0; // Total bytes in buffer from last iteration

    loop {
        // Move tail overlap bytes to front as next prefix (tiny, in-cache).
        if carry > 0 && have > 0 {
            buf.as_mut_slice().copy_within(have - carry..have, 0);
        }

        // Cap by remaining file size.
        let remaining = file_size.saturating_sub(offset) as usize;
        if remaining == 0 {
            break;
        }

        let read_max = chunk_size.min(buf.len() - carry).min(remaining);
        let dst = &mut buf.as_mut_slice()[carry..carry + read_max];

        // Prefetch next chunk while we're about to read this one.
        let next_offset = offset.saturating_add(read_max as u64);
        if next_offset < file_size {
            fadvise_willneed(&file, next_offset as i64, chunk_size as i64);
        }

        // --- Read ---
        let t_read = Instant::now();
        let n = match read_some(&mut file, dst) {
            Ok(n) => n,
            Err(_) => {
                stats.io_errors = stats.io_errors.saturating_add(1);
                break;
            }
        };
        let read_elapsed = t_read.elapsed().as_nanos() as u64;
        stats.read_ns = stats.read_ns.saturating_add(read_elapsed);

        if n == 0 {
            break;
        }

        let total_len = carry + n;
        let base_offset = offset.saturating_sub(carry as u64);

        // --- Scan --- (data is hot in L1/L2 from the read above)
        let data = &buf.as_slice()[..total_len];

        let t_scan = Instant::now();
        engine.scan_chunk_into(data, file_id, base_offset, scratch);
        let scan_elapsed = t_scan.elapsed().as_nanos() as u64;
        stats.scan_ns = stats.scan_ns.saturating_add(scan_elapsed);

        // Drop findings fully contained in the overlap prefix.
        let new_bytes_start = offset;
        scratch.drop_prefix_findings(new_bytes_start);

        // Drain findings.
        pending.clear();
        scratch.drain_findings_into(pending);

        if dedupe && pending.len() > 1 {
            dedupe_pending_in_place(pending);
        }

        emit_findings(engine, event_sink, &display, pending);

        // Metrics: payload bytes only.
        stats.chunks_scanned = stats.chunks_scanned.saturating_add(1);
        stats.bytes_scanned = stats.bytes_scanned.saturating_add(n as u64);
        stats.bytes_read = stats.bytes_read.saturating_add(n as u64);
        stats.findings_emitted = stats.findings_emitted.saturating_add(pending.len() as u64);

        // Advance.
        offset = offset.saturating_add(n as u64);
        have = total_len;
        carry = overlap.min(total_len);

        if offset >= file_size {
            break;
        }
    }

    // Buffer returns to pool on drop.
    drop(buf);

    stats.files_processed = stats.files_processed.saturating_add(1);
}

// ============================================================================
// Coordinator Entry Point
// ============================================================================

/// Scan local filesystem files using share-nothing worker threads.
///
/// # Architecture
///
/// ```text
/// scan_local_fs_sharded()
///   |
///   |  1. Create shared file channel
///   |  2. Create shared TsBufferPool (per-worker local queues)
///   |  3. Spawn N worker threads (each does I/O + scan)
///   |  4. Feed files into file channel
///   |  5. Drop file sender → workers drain → exit
///   |  6. Join all threads, collect stats
///   v
/// ShardedFsReport
/// ```
pub fn scan_local_fs_sharded<E: ScanEngine>(
    engine: Arc<E>,
    files: impl Iterator<Item = LocalFile>,
    cfg: ShardedFsConfig,
) -> io::Result<ShardedFsReport> {
    let num_workers = cfg.workers.max(1);
    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(
        buf_len <= BUFFER_LEN_MAX,
        "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
        buf_len,
        BUFFER_LEN_MAX
    );

    let wall_start = Instant::now();

    // --- Shared infrastructure ---

    // File channel: coordinator → workers (all workers compete for files).
    let (file_tx, file_rx) = crossbeam_channel::bounded::<FileWork>(cfg.file_channel_cap);

    // Shared buffer pool with per-worker local queues.
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: buf_len,
        total_buffers: num_workers * cfg.pool_buffers_per_worker,
        workers: num_workers,
        local_queue_cap: cfg.local_queue_cap,
    });

    // --- Spawn worker threads ---

    let mut handles: Vec<thread::JoinHandle<WorkerStats>> = Vec::with_capacity(num_workers);

    for idx in 0..num_workers {
        let file_rx = file_rx.clone();
        let worker_pool = pool.clone();
        let engine_ref = Arc::clone(&engine);
        let event_sink = Arc::clone(&cfg.event_sink);
        let chunk_size = cfg.chunk_size;
        let max_file_size = cfg.max_file_size;
        let archive_cfg = cfg.archive.clone();
        let dedupe = cfg.dedupe_within_chunk;
        let pin_threads = cfg.pin_threads;

        let handle = thread::Builder::new()
            .name(format!("worker-{idx}"))
            .spawn(move || {
                // Set worker ID for buffer pool local queue routing.
                set_current_worker_id(Some(idx));

                if pin_threads {
                    let _ = pin_current_thread_to_core(idx);
                }

                let stats = worker::<E>(
                    file_rx,
                    engine_ref,
                    worker_pool,
                    event_sink,
                    chunk_size,
                    max_file_size,
                    archive_cfg,
                    dedupe,
                );

                // Clear worker ID before exit.
                set_current_worker_id(None);

                stats
            })
            .map_err(io::Error::other)?;

        handles.push(handle);
    }

    // Drop coordinator's clone of file_rx so channel disconnection is
    // driven solely by thread exits.
    drop(file_rx);

    // --- Feed files into the file channel ---

    let mut files_enqueued: u64 = 0;
    let mut feed_block_ns: u64 = 0;
    let feed_start = Instant::now();

    for local_file in files {
        let work = FileWork {
            path: local_file.path,
        };

        let send_t = Instant::now();
        if file_tx.send(work).is_err() {
            break;
        }
        feed_block_ns = feed_block_ns.saturating_add(send_t.elapsed().as_nanos() as u64);
        files_enqueued = files_enqueued.saturating_add(1);
    }

    let feed_elapsed_ns = feed_start.elapsed().as_nanos() as u64;

    // Drop file sender: workers drain remaining files, then exit.
    drop(file_tx);

    // --- Join all threads and collect stats ---

    let mut worker_stats: Vec<WorkerStats> = Vec::with_capacity(num_workers);

    for handle in handles {
        match handle.join() {
            Ok(s) => worker_stats.push(s),
            Err(_) => return Err(io::Error::other("worker thread panicked")),
        }
    }

    let wall_time_ns = wall_start.elapsed().as_nanos() as u64;

    cfg.event_sink.flush();

    // --- Aggregate metrics ---

    let mut metrics = MetricsSnapshot::new();

    for ws in &worker_stats {
        metrics.io_errors = metrics.io_errors.saturating_add(ws.io_errors);
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(ws.bytes_scanned);
        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(ws.chunks_scanned);
        metrics.findings_emitted = metrics.findings_emitted.saturating_add(ws.findings_emitted);
    }

    metrics.worker_count = num_workers as u32;
    metrics.duration_ns = wall_time_ns;

    Ok(ShardedFsReport {
        worker_stats,
        files_enqueued,
        wall_time_ns,
        metrics,
        feed_elapsed_ns,
        feed_block_ns,
    })
}
