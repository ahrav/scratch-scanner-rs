//! Owner-Compute Filesystem Scanner
//!
//! # Architecture
//!
//! This module provides two execution modes:
//! - owner-compute: a coordinator feeds files to a shared worker queue
//! - inline walk+scan: walker threads discover and scan files directly
//!
//! Each worker owns its I/O buffer, engine scratch, and findings vec.
//! Workers perform both blocking file I/O and scanning on the same thread,
//! keeping data hot in L1/L2 cache between read and scan:
//!
//! ```text
//! Coordinator (main thread)
//!   |  files via shared bounded channel (cold path, per-file granularity)
//!   v
//! Worker 0: recv file → open → [fadvise + read → scan → emit] loop → next file
//! Worker 1: recv file → open → [fadvise + read → scan → emit] loop → next file
//!   ...
//! Worker N-1: file_rx exhausted → exit
//! ```
//!
//! Per-worker (share-nothing):
//!   - ONE `Vec<u8>` allocated at thread start, reused across all files
//!   - own engine scratch (reused across all files)
//!   - own findings Vec (reused across all chunks)
//!
//! # Invariants
//!
//! - A file is scanned by at most one worker in a given run.
//! - Worker-local scan state (`Vec<u8>`, scratch, pending findings) is never shared.
//! - Per-file open/read failures are counted in stats and do not stop the scan.
//!
//! # File Distribution
//!
//! Files are distributed via a single shared bounded channel. Workers compete
//! for files, providing natural load balancing: fast workers automatically
//! pick up more files. This avoids the imbalance risk of round-robin dispatch
//! when file sizes vary.
//!
//! # posix_fadvise (Linux only)
//!
//! - `FADV_SEQUENTIAL` once at file open → kernel uses aggressive readahead
//! - `FADV_WILLNEED` before scanning each chunk, for *next* chunk's range →
//!   kernel prefetches during scan, overlapping I/O with CPU work
//!
//! # Error Model
//!
//! Per-file failures are reflected in `OwnerWorkerStats::io_errors`.
//! Public entry points only return `io::Error` for orchestration failures
//! (for example worker thread spawn/join failure in owner-compute mode).

use std::cell::UnsafeCell;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crossbeam_utils::CachePadded;

use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use super::local::LocalFile;
use super::metrics::MetricsSnapshot;
use crate::api::FileId;
use crate::archive::{detect_kind_from_path, sniff_kind_from_header, ArchiveConfig};
use crate::scheduler::affinity::pin_current_thread_to_core;
use crate::unified::events::{EventSink, FindingEvent, ScanEvent};
use crate::unified::SourceKind;

/// Header sniff buffer size for archive detection.
const SNIFF_HEADER_LEN: usize = 8;

// ============================================================================
// posix_fadvise helpers
// ============================================================================

/// Hint the kernel to use aggressive sequential readahead for the file.
#[cfg(target_os = "linux")]
fn fadvise_sequential(file: &File) {
    use std::os::unix::io::AsRawFd;
    // Safety: the fd comes from a live `File`, and `posix_fadvise` neither
    // retains pointers nor mutates Rust-owned memory.
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
    // Safety: same as `fadvise_sequential`; arguments are plain value hints.
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_WILLNEED);
    }
}

#[cfg(not(target_os = "linux"))]
fn fadvise_willneed(_file: &File, _offset: i64, _len: i64) {}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for owner-compute filesystem scanning.
pub struct OwnerComputeFsConfig {
    /// Number of owner-compute workers.
    pub workers: usize,
    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,
    /// Maximum file size to scan (bytes). Larger files are skipped.
    pub max_file_size: u64,
    /// Capacity of the shared bounded file channel from coordinator to workers.
    pub file_channel_cap: usize,
    /// Enable within-chunk finding deduplication.
    pub dedupe_within_chunk: bool,
    /// Archive scanning configuration.
    pub archive: ArchiveConfig,
    /// Shared event sink for finding output.
    pub event_sink: Arc<dyn EventSink>,
    /// Whether to pin each worker thread to a CPU core (best effort).
    pub pin_threads: bool,
}

// ============================================================================
// Per-Worker Statistics
// ============================================================================

/// Per-worker statistics for owner-compute scanning.
#[derive(Clone, Copy, Debug, Default)]
pub struct OwnerWorkerStats {
    /// Files successfully processed.
    pub files_processed: u64,
    /// Total chunks scanned by this worker.
    pub chunks_scanned: u64,
    /// Total payload bytes scanned by this worker.
    pub bytes_scanned: u64,
    /// Findings emitted by this worker.
    pub findings_emitted: u64,
    /// File I/O errors encountered.
    pub io_errors: u64,
    /// Files skipped because they are archives.
    pub archives_skipped: u64,
    /// Cumulative open+metadata time (nanoseconds).
    pub open_stat_ns: u64,
    /// Cumulative read syscall time (nanoseconds).
    pub read_ns: u64,
    /// Cumulative scan time (nanoseconds).
    pub scan_ns: u64,
}

// ============================================================================
// Report
// ============================================================================

/// Aggregated report from owner-compute scanning.
#[derive(Debug)]
pub struct OwnerComputeFsReport {
    /// Per-worker stats in worker index order.
    pub worker_stats: Vec<OwnerWorkerStats>,
    /// Total files enqueued by discovery.
    pub files_enqueued: u64,
    /// End-to-end wall time (nanoseconds).
    pub wall_time_ns: u64,
    /// Aggregated metrics for compatibility with existing consumers.
    pub metrics: MetricsSnapshot,
    /// Wall-clock nanoseconds the coordinator spent in the feed loop
    /// (iterating the file iterator + sending to the shared channel).
    pub feed_elapsed_ns: u64,
    /// Cumulative nanoseconds the coordinator blocked inside `file_tx.send()`.
    /// High ratio to `feed_elapsed_ns` means workers are keeping up (channel full).
    pub feed_block_ns: u64,
}

// ============================================================================
// Helpers
// ============================================================================

/// `EINTR`-retrying wrapper around [`File::read`].
///
/// Loops on `ErrorKind::Interrupted` so callers never see spurious
/// zero-byte returns from signal delivery.
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

/// Sort+dedup findings by `(rule_id, root_hint_start, root_hint_end, span_start, span_end)`.
///
/// Eliminates duplicate findings within a single chunk that share the same
/// rule and span coordinates. Operates in-place to avoid allocation.
///
/// Complexity: `O(n log n)` from sort, `O(n)` dedup pass.
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

/// Emits each finding as a [`FindingEvent`] through the event sink.
///
/// Side effect: sends one event per finding to `event_sink`.
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
// Per-File Processing
// ============================================================================

/// Read and scan a single file in chunked passes.
///
/// Opens the file, checks size limits, detects (and skips) archives, then
/// loops over payload-sized reads feeding each chunk to the engine.
///
/// Overlap between consecutive chunks is maintained in `buf[0..carry]` so
/// that matches spanning a chunk boundary are not missed. Findings whose
/// root hint falls entirely within the overlap prefix are dropped to avoid
/// double-reporting from the previous chunk.
///
/// Errors on open, metadata, or mid-file reads are counted in `stats` and
/// do not propagate — the caller simply moves on to the next file.
///
/// # Preconditions
/// - `buf.len() >= overlap + chunk_size`
/// - `pending` and `scratch` are worker-local and can be freely reused
#[allow(clippy::too_many_arguments)]
fn process_file<E: ScanEngine>(
    engine: &E,
    event_sink: &dyn EventSink,
    local_file: LocalFile,
    file_id: FileId,
    chunk_size: usize,
    overlap: usize,
    max_file_size: u64,
    archive_cfg: &ArchiveConfig,
    dedupe: bool,
    buf: &mut [u8],
    pending: &mut Vec<<E::Scratch as EngineScratch>::Finding>,
    scratch: &mut E::Scratch,
    stats: &mut OwnerWorkerStats,
) {
    scratch.clear();

    // --- Open + stat ---
    #[cfg(feature = "stats")]
    let t_open = Instant::now();
    let mut file = match File::open(&local_file.path) {
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
    #[cfg(feature = "stats")]
    {
        stats.open_stat_ns = stats
            .open_stat_ns
            .saturating_add(t_open.elapsed().as_nanos() as u64);
    }

    let file_size = meta.len();
    if file_size == 0 || file_size > max_file_size {
        return;
    }

    // --- Archive detection ---
    if archive_cfg.enabled {
        // Fast path: extension/path-based archive detection avoids an I/O read.
        // Fallback: sniff first bytes, then seek back so chunk scanning starts at 0.
        let is_archive = detect_kind_from_path(&local_file.path).is_some() || {
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

    let path_bytes = local_file.path.as_os_str().as_encoded_bytes();
    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;

    loop {
        if carry > 0 && have > 0 {
            // Preserve overlap suffix from previous read as prefix for next scan window.
            buf.copy_within(have - carry..have, 0);
        }

        let remaining = file_size.saturating_sub(offset) as usize;
        if remaining == 0 {
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(remaining);

        // Prefetch next chunk while we're about to read this one.
        let next_offset = offset.saturating_add(read_max as u64);
        if next_offset < file_size {
            fadvise_willneed(&file, next_offset as i64, chunk_size as i64);
        }

        #[cfg(feature = "stats")]
        let t_read = Instant::now();
        let n = match read_some(&mut file, &mut buf[carry..carry + read_max]) {
            Ok(n) => n,
            Err(_) => {
                stats.io_errors = stats.io_errors.saturating_add(1);
                break;
            }
        };
        #[cfg(feature = "stats")]
        {
            stats.read_ns = stats
                .read_ns
                .saturating_add(t_read.elapsed().as_nanos() as u64);
        }

        if n == 0 {
            break;
        }

        let read_len = carry + n;
        // Base offset points to buffer index 0, which may include overlap carried forward.
        let base_offset = offset.saturating_sub(carry as u64);

        #[cfg(feature = "stats")]
        let t_scan = Instant::now();
        engine.scan_chunk_into(&buf[..read_len], file_id, base_offset, scratch);
        #[cfg(feature = "stats")]
        {
            stats.scan_ns = stats
                .scan_ns
                .saturating_add(t_scan.elapsed().as_nanos() as u64);
        }

        // Drop findings wholly in overlap prefix.
        // They were already emitted in the previous iteration's chunk.
        scratch.drop_prefix_findings(offset);
        pending.clear();
        scratch.drain_findings_into(pending);
        if dedupe {
            dedupe_pending_in_place(pending);
        }
        emit_findings(engine, event_sink, path_bytes, pending);

        stats.findings_emitted = stats.findings_emitted.saturating_add(pending.len() as u64);
        stats.chunks_scanned = stats.chunks_scanned.saturating_add(1);
        stats.bytes_scanned = stats.bytes_scanned.saturating_add(n as u64);

        offset = offset.saturating_add(n as u64);
        have = read_len;
        carry = overlap.min(read_len);

        if offset >= file_size {
            break;
        }
    }

    stats.files_processed = stats.files_processed.saturating_add(1);
}

// ============================================================================
// Coordinator Entry Point
// ============================================================================

/// Scan local filesystem files with owner-compute workers.
///
/// Files are distributed via a single shared bounded channel. Workers compete
/// for files, providing natural load balancing when file sizes vary. Each
/// worker performs open/read/scan/emit on its own thread using a single
/// reusable `Vec<u8>` buffer (zero per-file allocation).
///
/// # Preconditions
/// - `cfg.file_channel_cap > 0`
/// - `cfg.chunk_size + engine.required_overlap() <= BUFFER_LEN_MAX`
///
/// # Errors
/// - returns `io::Error` if a worker thread fails to spawn
/// - returns `io::Error` if a worker thread panics while processing
///
/// # Panics
/// - if preconditions above are violated
pub fn scan_local_fs_owner_compute<E: ScanEngine>(
    engine: Arc<E>,
    files: impl Iterator<Item = LocalFile>,
    cfg: OwnerComputeFsConfig,
) -> io::Result<OwnerComputeFsReport> {
    let worker_count = cfg.workers.max(1);
    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(
        buf_len <= BUFFER_LEN_MAX,
        "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
        buf_len,
        BUFFER_LEN_MAX
    );
    assert!(cfg.file_channel_cap > 0, "file_channel_cap must be > 0");

    let wall_start = Instant::now();

    // Single shared channel — workers compete for files (natural load balancing).
    let (file_tx, file_rx) = crossbeam_channel::bounded::<LocalFile>(cfg.file_channel_cap);

    let mut handles = Vec::with_capacity(worker_count);
    for worker_idx in 0..worker_count {
        let rx = file_rx.clone();
        let worker_engine = Arc::clone(&engine);
        let worker_sink = Arc::clone(&cfg.event_sink);
        let worker_archive = cfg.archive.clone();
        let worker_chunk_size = cfg.chunk_size;
        let worker_max_file_size = cfg.max_file_size;
        let worker_dedupe = cfg.dedupe_within_chunk;
        let worker_pin = cfg.pin_threads;

        let handle = thread::Builder::new()
            .name(format!("owner-worker-{worker_idx}"))
            .spawn(move || {
                if worker_pin {
                    let _ = pin_current_thread_to_core(worker_idx);
                }

                let mut stats = OwnerWorkerStats::default();
                let mut scratch = worker_engine.new_scratch();
                let mut pending: Vec<<E::Scratch as EngineScratch>::Finding> =
                    Vec::with_capacity(4096);
                let mut buf = vec![0u8; buf_len];
                // Stripe file IDs by worker to avoid collisions across threads.
                let mut file_seq = worker_idx as u32;
                let stride = worker_count as u32;

                for local_file in rx.iter() {
                    let file_id = FileId(file_seq);
                    file_seq = file_seq.wrapping_add(stride.max(1));
                    process_file(
                        worker_engine.as_ref(),
                        &*worker_sink,
                        local_file,
                        file_id,
                        worker_chunk_size,
                        overlap,
                        worker_max_file_size,
                        &worker_archive,
                        worker_dedupe,
                        &mut buf,
                        &mut pending,
                        &mut scratch,
                        &mut stats,
                    );
                }

                // Return worker-local totals for final aggregation by coordinator.
                stats
            })
            .map_err(io::Error::other)?;
        handles.push(handle);
    }

    // Drop coordinator's clone so channel disconnection is driven by worker exits.
    drop(file_rx);

    // --- Feed files into the shared channel ---
    let mut files_enqueued = 0u64;
    #[cfg(feature = "stats")]
    let mut feed_block_ns = 0u64;
    #[cfg(feature = "stats")]
    let feed_start = Instant::now();

    for local_file in files {
        #[cfg(feature = "stats")]
        let send_t = Instant::now();
        if file_tx.send(local_file).is_err() {
            // All receivers are gone (worker panicked/exited); stop feeding.
            break;
        }
        #[cfg(feature = "stats")]
        {
            feed_block_ns = feed_block_ns.saturating_add(send_t.elapsed().as_nanos() as u64);
        }
        files_enqueued = files_enqueued.saturating_add(1);
    }

    #[cfg(feature = "stats")]
    let feed_elapsed_ns = feed_start.elapsed().as_nanos() as u64;
    #[cfg(not(feature = "stats"))]
    let (feed_elapsed_ns, feed_block_ns) = (0u64, 0u64);

    // Drop sender: workers drain remaining files, then exit.
    drop(file_tx);

    let mut worker_stats = Vec::with_capacity(worker_count);
    for handle in handles {
        match handle.join() {
            Ok(s) => worker_stats.push(s),
            // Surface panic as I/O-style orchestration failure to caller.
            Err(_) => return Err(io::Error::other("owner worker thread panicked")),
        }
    }

    let wall_time_ns = wall_start.elapsed().as_nanos() as u64;
    cfg.event_sink.flush();

    let mut metrics = MetricsSnapshot::new();
    for s in &worker_stats {
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(s.bytes_scanned);
        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(s.chunks_scanned);
        metrics.findings_emitted = metrics.findings_emitted.saturating_add(s.findings_emitted);
        metrics.io_errors = metrics.io_errors.saturating_add(s.io_errors);
        #[cfg(feature = "stats")]
        {
            metrics.open_stat_ns = metrics.open_stat_ns.saturating_add(s.open_stat_ns);
            metrics.read_ns = metrics.read_ns.saturating_add(s.read_ns);
            metrics.scan_ns = metrics.scan_ns.saturating_add(s.scan_ns);
        }
    }
    metrics.worker_count = worker_count as u32;
    metrics.duration_ns = wall_time_ns;

    Ok(OwnerComputeFsReport {
        worker_stats,
        files_enqueued,
        wall_time_ns,
        metrics,
        feed_elapsed_ns,
        feed_block_ns,
    })
}

// ============================================================================
// Inline Walk+Scan (single thread pool)
// ============================================================================

/// Configuration for inline walk+scan filesystem scanning.
///
/// Unlike [`OwnerComputeFsConfig`], there is no file channel — the walker
/// threads ARE the scanner threads. Directory-level work-stealing from the
/// `ignore` crate provides load balancing.
pub struct InlineWalkScanConfig {
    /// Number of walker/scanner threads.
    pub workers: usize,
    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,
    /// Maximum file size to scan (bytes). Larger files are skipped.
    pub max_file_size: u64,
    /// Enable within-chunk finding deduplication.
    pub dedupe_within_chunk: bool,
    /// Archive scanning configuration.
    pub archive: ArchiveConfig,
    /// Shared event sink for finding output.
    pub event_sink: Arc<dyn EventSink>,
}

/// Report from inline walk+scan.
///
/// Like [`OwnerComputeFsReport`] but without coordinator feed timing
/// (there is no channel — walker threads scan directly).
#[derive(Debug)]
pub struct InlineWalkScanReport {
    /// Per-worker stats in slot-claim order.
    pub worker_stats: Vec<OwnerWorkerStats>,
    /// Total files discovered by the walker (includes skipped).
    pub files_discovered: u64,
    /// End-to-end wall time (nanoseconds).
    pub wall_time_ns: u64,
    /// Aggregated metrics for compatibility with existing consumers.
    pub metrics: MetricsSnapshot,
}

/// Pre-allocated, cache-line-padded stats slots for zero-contention aggregation.
///
/// Each walker thread claims one slot via `fetch_add` at init time.
/// After `walker.run()` returns, the main thread reads `next` to know
/// how many slots were used and iterates them to produce the aggregate.
struct StatsSlots {
    slots: Vec<CachePadded<UnsafeCell<OwnerWorkerStats>>>,
    next: AtomicUsize,
}

/// # Safety
///
/// Each slot is exclusively owned by one thread after claiming via
/// `fetch_add`; no two threads share a slot. The main thread only reads
/// slots after all walker threads have joined (`walker.run()` blocks
/// until completion), establishing a happens-before edge.
///
/// Slot capacity is `worker_count + 1`, which accounts for the `ignore`
/// crate potentially spawning one extra thread. If more threads are
/// spawned than capacity, the `slots[slot_idx]` access panics at
/// runtime — a deliberate fail-loud rather than UB.
unsafe impl Sync for StatsSlots {}

impl StatsSlots {
    /// Create fixed-capacity stats slots for walker threads.
    ///
    /// Callers must size `capacity` to the maximum number of walker threads
    /// that may claim a slot during one `scan_local_fs_inline` run.
    fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(CachePadded::new(UnsafeCell::new(
                OwnerWorkerStats::default(),
            )));
        }
        Self {
            slots,
            next: AtomicUsize::new(0),
        }
    }
}

/// Scan a filesystem tree by walking and scanning inline on the same threads.
///
/// Uses `ignore::WalkBuilder::build_parallel()` to walk the directory tree
/// with work-stealing at directory granularity. Each walker thread allocates
/// its own engine scratch, I/O buffer, and stats slot at init time, then
/// scans every file it discovers — no channel, no second thread pool.
///
/// This preserves directory locality (the thread that discovers a file scans
/// it immediately) and eliminates all per-file synchronization.
///
/// # Preconditions
/// - `cfg.chunk_size + engine.required_overlap() <= BUFFER_LEN_MAX`
///
/// # Panics
/// - if the precondition above is violated
pub fn scan_local_fs_inline<E: ScanEngine>(
    engine: Arc<E>,
    root: &Path,
    cfg: InlineWalkScanConfig,
) -> io::Result<InlineWalkScanReport> {
    let worker_count = cfg.workers.max(1);
    let overlap = engine.required_overlap();
    let buf_len = overlap.saturating_add(cfg.chunk_size);
    assert!(
        buf_len <= BUFFER_LEN_MAX,
        "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
        buf_len,
        BUFFER_LEN_MAX,
    );

    let wall_start = Instant::now();

    // +1 slot to handle ignore crate potentially spawning an extra thread.
    let stats_slots = Arc::new(StatsSlots::new(worker_count + 1));
    let files_discovered = Arc::new(AtomicUsize::new(0));

    let chunk_size = cfg.chunk_size;
    let max_file_size = cfg.max_file_size;
    let dedupe = cfg.dedupe_within_chunk;
    let archive_cfg = cfg.archive;
    let event_sink = cfg.event_sink;

    let walker = ignore::WalkBuilder::new(root)
        .threads(worker_count)
        .follow_links(false)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .build_parallel();

    walker.run(|| {
        // Factory: called once per walker thread — allocate per-thread state.
        let engine = Arc::clone(&engine);
        let event_sink = Arc::clone(&event_sink);
        let archive_cfg = archive_cfg.clone();
        let stats_slots = Arc::clone(&stats_slots);
        let files_discovered = Arc::clone(&files_discovered);

        let mut scratch = engine.new_scratch();
        let mut buf = vec![0u8; buf_len];
        let mut pending = Vec::with_capacity(4096);

        // Claim an exclusive stats slot — no contention after this point.
        // Relaxed ordering is sufficient: uniqueness comes from atomic RMW itself.
        let slot_idx = stats_slots.next.fetch_add(1, Ordering::Relaxed);
        // Safety: slot_idx < capacity (one slot per thread), exclusively owned.
        let stats: &mut OwnerWorkerStats = unsafe { &mut *stats_slots.slots[slot_idx].get() };

        let mut file_seq = 0u32;

        // Per-entry: called for every dir entry — scan files inline.
        Box::new(move |result: Result<ignore::DirEntry, ignore::Error>| {
            if let Ok(entry) = result {
                if entry.file_type().is_some_and(|ft| ft.is_file()) {
                    // Discovery count is approximate-in-time but exact at completion.
                    files_discovered.fetch_add(1, Ordering::Relaxed);
                    let local_file = LocalFile {
                        path: entry.into_path(),
                        size: 0, // Size checked at open time via fstat.
                    };
                    // IDs are only required to be stable within this walker thread.
                    let file_id = FileId(file_seq);
                    file_seq = file_seq.wrapping_add(1);
                    process_file(
                        engine.as_ref(),
                        &*event_sink,
                        local_file,
                        file_id,
                        chunk_size,
                        overlap,
                        max_file_size,
                        &archive_cfg,
                        dedupe,
                        &mut buf,
                        &mut pending,
                        &mut scratch,
                        stats,
                    );
                }
            }
            ignore::WalkState::Continue
        })
    });

    // walker.run() blocks until all threads complete.
    let wall_time_ns = wall_start.elapsed().as_nanos() as u64;
    let total_discovered = files_discovered.load(Ordering::Relaxed) as u64;

    event_sink.flush();

    // Aggregate per-worker stats.
    // `used` is the number of successfully claimed slots.
    let used = stats_slots.next.load(Ordering::Relaxed);
    let mut worker_stats = Vec::with_capacity(used);
    let mut metrics = MetricsSnapshot::new();

    for i in 0..used {
        // Safety: all walker threads have joined; we have exclusive access.
        let s = unsafe { &*stats_slots.slots[i].get() };
        worker_stats.push(*s);

        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(s.bytes_scanned);
        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(s.chunks_scanned);
        metrics.findings_emitted = metrics.findings_emitted.saturating_add(s.findings_emitted);
        metrics.io_errors = metrics.io_errors.saturating_add(s.io_errors);
        #[cfg(feature = "stats")]
        {
            metrics.open_stat_ns = metrics.open_stat_ns.saturating_add(s.open_stat_ns);
            metrics.read_ns = metrics.read_ns.saturating_add(s.read_ns);
            metrics.scan_ns = metrics.scan_ns.saturating_add(s.scan_ns);
        }
    }
    metrics.worker_count = used as u32;
    metrics.duration_ns = wall_time_ns;

    Ok(InlineWalkScanReport {
        worker_stats,
        files_discovered: total_discovered,
        wall_time_ns,
        metrics,
    })
}
