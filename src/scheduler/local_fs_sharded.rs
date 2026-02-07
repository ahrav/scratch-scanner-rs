//! Per-Shard Share-Nothing Filesystem Scanner
//!
//! # Architecture
//!
//! Each shard is a pair of threads connected by a wait-free SPSC ring buffer:
//!
//! ```text
//! Discovery (round-robins files across shards)
//!     +---> Shard 0: [file_rx] --> I/O thread --SPSC--> Scan thread
//!     +---> Shard 1: [file_rx] --> I/O thread --SPSC--> Scan thread
//!     +---> Shard N: [file_rx] --> I/O thread --SPSC--> Scan thread
//! ```
//!
//! ## I/O Thread
//!
//! Blocking `open` + `fstat` + sequential `read` using standard library I/O.
//! Reads file data in chunks with overlap carry, pushes filled buffers as
//! [`ScanChunk::Chunk`] into the SPSC ring. Sends [`ScanChunk::EndOfFile`]
//! after each file and [`ScanChunk::Shutdown`] after draining its file channel.
//!
//! ## Scan Thread
//!
//! Consumes chunks from the SPSC ring, runs the scan engine, deduplicates
//! findings across chunk boundaries (overlap prefix drop), and emits findings
//! through the [`EventSink`].
//!
//! # Backpressure
//!
//! - **File-level**: [`CountBudget`] per shard limits discovered-but-not-scanned files.
//! - **Chunk-level**: SPSC ring capacity (power-of-2) limits buffered chunks.
//! - **Buffer-level**: [`TsBufferPool`] per shard limits peak memory.
//!
//! # Platform
//!
//! This module uses only standard library I/O (no `io_uring`, no platform-specific
//! APIs). It works on all platforms supported by Rust.
//!
//! # Performance
//!
//! The share-nothing design eliminates cross-shard contention. Each shard has its
//! own buffer pool, SPSC ring, and file channel. The only shared state is the
//! [`EventSink`] (which has internal synchronization).
//!
//! ```text
//! Shard 0:  [TsBufferPool] [SPSC<64>]  [crossbeam Receiver]
//! Shard 1:  [TsBufferPool] [SPSC<64>]  [crossbeam Receiver]
//!   ...no shared mutable state between shards...
//! ```

use std::fs::File;
use std::io::{self, Read, Seek};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use super::count_budget::{CountBudget, CountPermit};
use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
use super::local_fs_owner::LocalFile;
use super::metrics::MetricsSnapshot;
use super::ts_buffer_pool::{TsBufferHandle, TsBufferPool, TsBufferPoolConfig};
use crate::api::FileId;
use crate::archive::{detect_kind_from_path, sniff_kind_from_header, ArchiveConfig};
use crate::scheduler::affinity::pin_current_thread_to_core;
use crate::stdx::spsc::{spsc_channel, OwnedSpscConsumer, OwnedSpscProducer};
use crate::unified::events::{EventSink, FindingEvent, ScanEvent};
use crate::unified::SourceKind;

// ============================================================================
// Constants
// ============================================================================

/// SPSC ring capacity (must be power of 2).
///
/// 64 slots allows the I/O thread to read-ahead substantially before the scan
/// thread catches up, reducing `yield_now()` context switches on large files.
/// A 50 MiB file at 256 KiB chunks produces ~195 chunks; with 8 slots the I/O
/// thread blocked after every 8 reads, generating thousands of yield-induced
/// context switches. At 64, most files fit entirely in the ring.
///
/// Memory cost per shard is 64 × `size_of::<ScanChunk>()` (a few KiB);
/// the bulk allocation lives in the `TsBufferPool`, not the ring slots.
pub(super) const SHARD_SPSC_CAP: usize = 64;

/// Number of spin iterations before yielding when a ring operation fails.
///
/// Brief spin avoids the cost of a full `thread::yield_now()` context switch
/// on transient contention. After `SPIN_ITERS` spin-loop hints, we retry the
/// operation once before falling back to `thread::yield_now()`.
pub(super) const SPIN_ITERS: u32 = 32;

/// Header sniff buffer size for archive detection.
///
/// 8 bytes is sufficient to detect ZIP, GZIP, and tar magic bytes.
pub(super) const SNIFF_HEADER_LEN: usize = 8;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the sharded filesystem scanner.
///
/// # Sizing Guidelines
///
/// | Parameter | Default | Guidance |
/// |-----------|---------|----------|
/// | `shards` | `num_cpus` | One I/O + one scan thread per shard |
/// | `chunk_size` | 256 KiB | Larger = fewer syscalls, more memory per file |
/// | `max_file_size` | 100 MiB | Skip files larger than this |
/// | `pool_buffers_per_shard` | 32 | Bounds peak memory per shard |
/// | `max_in_flight_per_shard` | 64 | Bounds discovered-but-not-scanned files |
/// | `spsc_capacity` | 64 | Power-of-2 SPSC ring depth |
pub struct ShardedFsConfig {
    /// Number of shards (each shard = 1 I/O thread + 1 scan thread).
    ///
    /// Default: `num_cpus` (2× oversubscription). I/O threads spend most
    /// time in blocking syscalls, so scan threads rarely compete for CPU.
    pub shards: usize,

    /// Payload bytes per chunk (excluding overlap).
    ///
    /// Actual buffer size = `chunk_size + engine.required_overlap()`.
    pub chunk_size: usize,

    /// Maximum file size to scan (bytes). Files larger than this are skipped.
    pub max_file_size: u64,

    /// Number of buffers allocated per shard's pool.
    ///
    /// Bounds peak memory per shard: `pool_buffers_per_shard * buffer_len`.
    pub pool_buffers_per_shard: usize,

    /// Per-worker local queue capacity in the buffer pool.
    ///
    /// Each shard has 2 workers (I/O + scan), so keep this small (2-4).
    pub local_queue_cap: usize,

    /// Maximum in-flight files per shard (CountBudget capacity).
    ///
    /// Discovery blocks when this many files are queued/scanning in a shard.
    pub max_in_flight_per_shard: usize,

    /// SPSC ring capacity (must be power of 2).
    ///
    /// This is advisory; the actual capacity is the const generic `SHARD_SPSC_CAP`.
    pub spsc_capacity: usize,

    /// Enable within-chunk finding deduplication.
    ///
    /// When true, findings within the same chunk are deduplicated by
    /// `(rule_id, root_hint, span)` before emission.
    pub dedupe_within_chunk: bool,

    /// Archive scanning configuration.
    ///
    /// Archives are detected but skipped in this implementation (future work).
    pub archive: ArchiveConfig,

    /// Event sink for emitting findings and progress events.
    pub event_sink: Arc<dyn EventSink>,

    /// Whether to attempt pinning I/O and scan threads to CPU cores.
    ///
    /// On platforms that do not support affinity (e.g., macOS), pinning is
    /// attempted and silently ignored on failure.
    pub pin_threads: bool,
}

// ============================================================================
// ScanChunk — payload traveling through the SPSC ring
// ============================================================================

/// A unit of work traveling from the I/O thread to the scan thread through
/// the SPSC ring buffer.
///
/// ```text
/// I/O thread                          SPSC ring                    Scan thread
///   open+read ----> Chunk { buf, ... } ----> scan_chunk_into()
///   EOF        ----> EndOfFile         ----> reset scratch
///   done       ----> Shutdown          ----> exit loop
/// ```
pub(super) enum ScanChunk {
    /// A filled buffer ready for scanning.
    Chunk {
        /// Pooled buffer containing overlap prefix + payload bytes.
        buf: TsBufferHandle,
        /// Absolute byte offset of `buf[0]` in the file.
        base_offset: u64,
        /// Number of overlap prefix bytes at the start of the buffer.
        /// These bytes were carried from the tail of the previous chunk.
        prefix_len: u32,
        /// Total valid bytes in the buffer (prefix + payload).
        len: u32,
        /// File path bytes for finding attribution (shared, no per-finding alloc).
        display: Arc<[u8]>,
        /// File ID for engine scan attribution.
        file_id: FileId,
    },
    /// Sentinel: no more chunks for the current file.
    ///
    /// The scan thread uses this to clear per-file scratch state.
    EndOfFile,
    /// Sentinel: the I/O thread has drained its file channel and is exiting.
    ///
    /// The scan thread should exit its loop after receiving this.
    Shutdown,
}

// ============================================================================
// ShardFileWork — what the coordinator sends to each shard's I/O thread
// ============================================================================

/// A file work item sent from the coordinator to a shard's I/O thread.
///
/// The `_permit` field holds a [`CountPermit`] that is automatically released
/// when this work item is dropped (after the file has been fully processed
/// or skipped).
pub(super) struct ShardFileWork {
    /// Absolute path to the file.
    pub(super) path: PathBuf,
    /// Discovery-time file size hint (re-checked at open time).
    pub(super) size: u64,
    /// Backpressure permit — released on drop.
    pub(super) _permit: CountPermit,
}

// ============================================================================
// Per-Shard Statistics
// ============================================================================

/// I/O thread statistics for a single shard.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShardIoStats {
    /// Number of files fully processed (opened, read, chunks pushed).
    pub files_processed: u64,
    /// Total bytes read from disk across all files.
    pub bytes_read: u64,
    /// Number of I/O errors (open, stat, read failures).
    pub io_errors: u64,
    /// Cumulative nanoseconds spent in open + fstat syscalls.
    pub open_stat_ns: u64,
    /// Cumulative nanoseconds spent in read syscalls.
    pub read_ns: u64,
    /// Number of files skipped because they are archives.
    pub archives_skipped: u64,
    /// `yield_now()` calls in `push_with_backoff` slow path.
    pub push_yields: u64,
    /// `yield_now()` calls in `acquire_buffer_with_backoff` slow path.
    pub acquire_yields: u64,
}

/// Scan thread statistics for a single shard.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShardScanStats {
    /// Number of chunks scanned.
    pub chunks_scanned: u64,
    /// Total bytes scanned (payload only, excluding overlap prefix).
    pub bytes_scanned: u64,
    /// Total findings emitted.
    pub findings_emitted: u64,
    /// Cumulative nanoseconds spent in `scan_chunk_into`.
    pub scan_ns: u64,
    /// `yield_now()` calls while waiting for the SPSC ring.
    /// Each yield is a syscall (~2-5μs). Multiply by estimated cost
    /// to approximate total wait time without per-call `Instant::now()` overhead.
    pub pop_yields: u64,
    /// `try_pop` succeeded on first attempt (no spin needed).
    pub pop_immediate: u64,
}

/// Aggregated report from a sharded filesystem scan.
#[derive(Debug)]
pub struct ShardedFsReport {
    /// Per-shard I/O thread statistics.
    pub io_stats: Vec<ShardIoStats>,
    /// Per-shard scan thread statistics.
    pub scan_stats: Vec<ShardScanStats>,
    /// Total number of files enqueued across all shards.
    pub files_enqueued: u64,
    /// Wall-clock time of the entire scan in nanoseconds.
    pub wall_time_ns: u64,
    /// Aggregated metrics compatible with existing `MetricsSnapshot` consumers.
    pub metrics: MetricsSnapshot,
}

// ============================================================================
// EINTR-safe read helper
// ============================================================================

/// Read into `dst`, retrying on `EINTR`.
///
/// Standard `File::read` can return `ErrorKind::Interrupted` on signal delivery.
/// This helper transparently retries, matching POSIX `read(2)` semantics that
/// most callers expect.
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
///
/// Sorts findings by their dedup key and removes consecutive duplicates.
/// This handles the case where the same secret is found multiple times
/// within a single chunk (e.g., via different transform paths).
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
///
/// Each finding is emitted as a `ScanEvent::Finding` with `SourceKind::Fs`.
/// The `display` bytes are used as the object path (avoiding per-finding
/// allocation since the path is shared across all chunks of a file).
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
// Scan Thread
// ============================================================================

/// Scan thread main loop for a single shard.
///
/// Consumes [`ScanChunk`] values from the SPSC ring, runs the scan engine on
/// each chunk, handles overlap-based deduplication, and emits findings through
/// the event sink.
///
/// # Wait Strategy
///
/// When the SPSC ring is empty, the scan thread spins briefly (32 iterations
/// of `core::hint::spin_loop()` hints), retries once, then yields to the OS
/// scheduler. This balances latency (fast wakeup on new data) with CPU
/// efficiency (no busy-wait when the I/O thread is blocked on disk).
///
/// # Chunk Processing
///
/// ```text
/// for each Chunk:
///   1. scan_chunk_into(data, file_id, base_offset, scratch)
///   2. drop_prefix_findings(base_offset + prefix_len)  // overlap dedup
///   3. drain_findings_into(pending)
///   4. dedupe_pending_in_place(pending)                 // within-chunk dedup
///   5. emit_findings(pending)
///   6. accumulate stats
/// ```
pub(super) fn shard_scan_loop<E: ScanEngine>(
    mut consumer: OwnedSpscConsumer<ScanChunk, SHARD_SPSC_CAP>,
    engine: Arc<E>,
    event_sink: Arc<dyn EventSink>,
    dedupe: bool,
) -> ShardScanStats {
    let mut stats = ShardScanStats::default();
    let mut scratch = engine.new_scratch();
    let mut pending: Vec<<E::Scratch as EngineScratch>::Finding> = Vec::with_capacity(4096);

    loop {
        // Try to pop a chunk from the SPSC ring.
        let chunk = match consumer.try_pop() {
            Some(c) => {
                stats.pop_immediate += 1;
                c
            }
            None => {
                // Ring empty: spin (hint only), retry once, then yield.
                for _ in 0..SPIN_ITERS {
                    core::hint::spin_loop();
                }
                match consumer.try_pop() {
                    Some(c) => c,
                    None => {
                        stats.pop_yields += 1;
                        std::thread::yield_now();
                        continue;
                    }
                }
            }
        };

        match chunk {
            ScanChunk::Shutdown => return stats,
            ScanChunk::EndOfFile => {
                scratch.clear();
            }
            ScanChunk::Chunk {
                buf,
                base_offset,
                prefix_len,
                len,
                display,
                file_id,
            } => {
                process_scan_chunk(
                    engine.as_ref(),
                    &*event_sink,
                    &mut scratch,
                    &mut pending,
                    &mut stats,
                    buf,
                    base_offset,
                    prefix_len,
                    len,
                    &display,
                    file_id,
                    dedupe,
                );
            }
        }
    }
}

/// Process a single scan chunk: scan, dedup, emit findings, update stats.
///
/// Extracted from the scan loop to keep the main loop body small and the
/// chunk-processing logic in one place.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn process_scan_chunk<E: ScanEngine>(
    engine: &E,
    event_sink: &dyn EventSink,
    scratch: &mut E::Scratch,
    pending: &mut Vec<<E::Scratch as EngineScratch>::Finding>,
    stats: &mut ShardScanStats,
    buf: TsBufferHandle,
    base_offset: u64,
    prefix_len: u32,
    len: u32,
    display: &[u8],
    file_id: FileId,
    dedupe: bool,
) {
    let len_usize = len as usize;
    let data = &buf.as_slice()[..len_usize];

    #[cfg(feature = "stats")]
    let t0 = Instant::now();
    engine.scan_chunk_into(data, file_id, base_offset, scratch);
    #[cfg(feature = "stats")]
    let scan_elapsed = t0.elapsed().as_nanos() as u64;

    // Drop findings fully contained in the overlap prefix.
    let new_bytes_start = base_offset + prefix_len as u64;
    scratch.drop_prefix_findings(new_bytes_start);

    // Drain findings from scratch into the pending buffer.
    // CRITICAL: Clear pending before drain to avoid accumulating across chunks.
    pending.clear();
    scratch.drain_findings_into(pending);

    if dedupe {
        dedupe_pending_in_place(pending);
    }

    emit_findings(engine, event_sink, display, pending);

    // Metrics: payload bytes only (exclude overlap prefix).
    let payload = (len as u64).saturating_sub(prefix_len as u64);
    stats.chunks_scanned = stats.chunks_scanned.saturating_add(1);
    stats.bytes_scanned = stats.bytes_scanned.saturating_add(payload);
    stats.findings_emitted = stats.findings_emitted.saturating_add(pending.len() as u64);
    #[cfg(feature = "stats")]
    {
        stats.scan_ns = stats.scan_ns.saturating_add(scan_elapsed);
    }

    // Buffer returns to pool on drop (RAII).
    drop(buf);
}

// ============================================================================
// I/O Thread
// ============================================================================

/// I/O thread main loop for a single shard.
///
/// Receives file work items from the coordinator via a `crossbeam_channel`,
/// opens each file, reads it in chunks with overlap carry, and pushes filled
/// buffers into the SPSC ring for the scan thread.
///
/// # I/O Pattern: Overlap Carry
///
/// ```text
/// Chunk 1:                        Chunk 2:
/// +-------------------------+     +--------+------------------+
/// |      payload bytes      |     |overlap |  new payload     |
/// |      (from read)        |     |(stack) |  (from read)     |
/// +-------------------------+     +--------+------------------+
///                           |            ^
///                           +------------+
///                        copied from tail of chunk 1
/// ```
///
/// The overlap bytes are carried in a stack-local buffer (not re-read from
/// disk), eliminating seeks and reducing syscall overhead.
///
/// # Archive Detection
///
/// Files are checked for archive signatures (extension-based, then header-based
/// sniffing). Archives are currently skipped (counted in stats). Future work
/// will dispatch archive entries for recursive scanning.
///
/// # Shutdown Protocol
///
/// 1. The coordinator drops the `crossbeam_channel::Sender` when all files
///    have been enqueued.
/// 2. The I/O thread drains remaining files from the channel.
/// 3. After the channel is exhausted, the I/O thread pushes
///    [`ScanChunk::Shutdown`] into the SPSC ring.
/// 4. The scan thread receives `Shutdown` and exits.
fn shard_io_blocking<E: ScanEngine>(
    file_rx: crossbeam_channel::Receiver<ShardFileWork>,
    mut producer: OwnedSpscProducer<ScanChunk, SHARD_SPSC_CAP>,
    pool: TsBufferPool,
    engine: &E,
    cfg: &ShardedFsConfig,
) -> ShardIoStats {
    let overlap = engine.required_overlap();
    let chunk_size = cfg.chunk_size;
    let buf_len = overlap.saturating_add(chunk_size);
    debug_assert!(
        buf_len <= BUFFER_LEN_MAX,
        "chunk_size + overlap ({}) exceeds BUFFER_LEN_MAX ({})",
        buf_len,
        BUFFER_LEN_MAX
    );

    let mut stats = ShardIoStats::default();
    let mut next_file_id: u32 = 0;

    // Stack-local overlap carry buffer. Reused across files to avoid allocation.
    let mut overlap_buf = vec![0u8; overlap];

    for work in file_rx.iter() {
        // Use a unique FileId per file so engine overlap/dedupe state cannot
        // leak across different files when scratch is reused.
        let file_id = FileId(next_file_id);
        next_file_id = next_file_id.wrapping_add(1);
        process_file(
            &work,
            file_id,
            &mut producer,
            &pool,
            overlap,
            chunk_size,
            cfg.max_file_size,
            &cfg.archive,
            &mut overlap_buf,
            &mut stats,
        );
    }

    // Channel drained. Push shutdown sentinel.
    push_with_backoff(&mut producer, ScanChunk::Shutdown, &mut stats.push_yields);
    stats
}

/// Process a single file: open, stat, detect archives, read chunks, push to SPSC.
///
/// This function encapsulates the per-file I/O logic. Errors on individual files
/// are counted in stats but do not abort the scan.
#[allow(clippy::too_many_arguments)]
fn process_file(
    work: &ShardFileWork,
    file_id: FileId,
    producer: &mut OwnedSpscProducer<ScanChunk, SHARD_SPSC_CAP>,
    pool: &TsBufferPool,
    overlap: usize,
    chunk_size: usize,
    max_file_size: u64,
    archive_cfg: &ArchiveConfig,
    overlap_buf: &mut [u8],
    stats: &mut ShardIoStats,
) {
    // --- Open + stat ---
    #[cfg(feature = "stats")]
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
    #[cfg(feature = "stats")]
    {
        let open_stat_elapsed = t_open.elapsed().as_nanos() as u64;
        stats.open_stat_ns = stats.open_stat_ns.saturating_add(open_stat_elapsed);
    }

    let size = meta.len();

    // Size enforcement: skip empty files and files exceeding the cap.
    if size == 0 {
        return;
    }
    if size > max_file_size {
        return;
    }

    // Local backoff counters — accumulated into stats at the end of this function,
    // avoiding split-borrow issues with `stats` and its fields.
    let mut local_push_yields: u64 = 0;
    let mut local_acquire_yields: u64 = 0;

    // --- Archive detection ---
    // TODO(ahrav): The sharded path does not yet support archive extraction
    // (gzip/tar/zip). When archive scanning is enabled we detect and skip archives
    // to avoid scanning compressed binary data that would produce false positives.
    // This means secrets inside archives are not found in this code path — a known
    // limitation vs the full `local_fs_owner.rs` scanner which extracts and scans archive
    // contents. Tracked for follow-up implementation.
    if archive_cfg.enabled {
        let is_archive = detect_kind_from_path(&work.path).is_some() || {
            // Sniff header bytes for magic signatures.
            let mut header = [0u8; SNIFF_HEADER_LEN];
            let sniffed = match read_some(&mut file, &mut header) {
                Ok(n) => sniff_kind_from_header(&header[..n]).is_some(),
                Err(_) => false,
            };
            // Always seek back to the start after reading header bytes,
            // regardless of whether an archive was detected.
            let _ = file.seek(io::SeekFrom::Start(0));
            sniffed
        };

        if is_archive {
            stats.archives_skipped = stats.archives_skipped.saturating_add(1);
            push_with_backoff(producer, ScanChunk::EndOfFile, &mut local_push_yields);
            stats.push_yields = stats.push_yields.saturating_add(local_push_yields);
            return;
        }
    }

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

    // --- Read loop with overlap carry ---
    let mut file_offset: u64 = 0;
    let mut overlap_len: usize = 0;
    let mut first_chunk = true;

    loop {
        if file_offset >= size {
            break;
        }

        // Acquire a buffer from the pool (blocking spin+yield).
        let mut buf = acquire_buffer_with_backoff(pool, &mut local_acquire_yields);

        // Copy overlap prefix from the carry buffer into the head of the buffer.
        let prefix_len = if first_chunk {
            first_chunk = false;
            0
        } else {
            let pl = overlap_len;
            if pl > 0 {
                buf.as_mut_slice()[..pl].copy_from_slice(&overlap_buf[..pl]);
            }
            pl
        };

        // Compute how many payload bytes to read.
        let remaining = size.saturating_sub(file_offset);
        let payload_want = (remaining as usize).min(chunk_size);

        // Read payload bytes into the buffer after the overlap prefix.
        #[cfg(feature = "stats")]
        let t_read = Instant::now();
        let payload_got = match read_full(
            &mut file,
            &mut buf.as_mut_slice()[prefix_len..prefix_len + payload_want],
        ) {
            Ok(n) => n,
            Err(_) => {
                stats.io_errors = stats.io_errors.saturating_add(1);
                // Drop the buffer (returns to pool) and abort this file.
                drop(buf);
                break;
            }
        };
        #[cfg(feature = "stats")]
        {
            let read_elapsed = t_read.elapsed().as_nanos() as u64;
            stats.read_ns = stats.read_ns.saturating_add(read_elapsed);
        }

        if payload_got == 0 {
            // Unexpected EOF (file shrank between stat and read).
            drop(buf);
            break;
        }

        let total_len = prefix_len + payload_got;

        // Update overlap carry buffer for the next iteration.
        if overlap > 0 {
            let ol = overlap.min(total_len);
            let start = total_len - ol;
            overlap_buf[..ol].copy_from_slice(&buf.as_slice()[start..start + ol]);
            overlap_len = ol;
        }

        let base_offset = if prefix_len > 0 {
            file_offset.saturating_sub(prefix_len as u64)
        } else {
            file_offset
        };

        stats.bytes_read = stats.bytes_read.saturating_add(payload_got as u64);
        file_offset = file_offset.saturating_add(payload_got as u64);

        // Push chunk into SPSC ring (with backoff on full).
        push_with_backoff(
            producer,
            ScanChunk::Chunk {
                buf,
                base_offset,
                prefix_len: prefix_len as u32,
                len: total_len as u32,
                display: Arc::clone(&display),
                file_id,
            },
            &mut local_push_yields,
        );
    }

    // Send EndOfFile sentinel so the scan thread knows to reset per-file state.
    push_with_backoff(producer, ScanChunk::EndOfFile, &mut local_push_yields);
    stats.files_processed = stats.files_processed.saturating_add(1);

    // Accumulate local backoff counters into per-shard stats.
    stats.push_yields = stats.push_yields.saturating_add(local_push_yields);
    stats.acquire_yields = stats.acquire_yields.saturating_add(local_acquire_yields);
}

/// Read exactly `dst.len()` bytes, retrying on short reads and EINTR.
///
/// Returns the total number of bytes read. May return less than `dst.len()`
/// only at EOF.
fn read_full(file: &mut File, dst: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < dst.len() {
        match read_some(file, &mut dst[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Push a value into the SPSC producer, spinning briefly then yielding on full.
///
/// This never fails; it retries until the consumer makes room. The scan thread
/// must always be consuming (or the system would deadlock), so this eventually
/// succeeds.
///
/// Wait strategy: try push → spin (hint only, no retry) → retry once → yield.
/// This avoids the O(SPIN_ITERS) retries-per-spin that caused excessive context
/// switches with small ring capacities.
///
/// `push_yields` is incremented on each `yield_now()` call in the slow path.
#[inline]
pub(super) fn push_with_backoff<T: Send + 'static, const N: usize>(
    producer: &mut OwnedSpscProducer<T, N>,
    mut value: T,
    push_yields: &mut u64,
) {
    // Fast path: ring likely has room.
    match producer.try_push(value) {
        Ok(()) => return,
        Err(v) => value = v,
    }

    loop {
        // Spin with CPU hint (no retry during spin — just wait for cache line).
        for _ in 0..SPIN_ITERS {
            core::hint::spin_loop();
        }
        // Retry once after spin.
        match producer.try_push(value) {
            Ok(()) => return,
            Err(v) => value = v,
        }
        *push_yields += 1;
        // Yield to OS scheduler before next spin round.
        std::thread::yield_now();
    }
}

/// Acquire a buffer from the pool, spinning briefly then yielding when empty.
///
/// This never fails; it retries until a buffer becomes available. The scan
/// thread drops buffers (returning them to the pool) as it processes chunks,
/// so this eventually succeeds.
///
/// Wait strategy: try acquire → spin (hint only) → retry once → yield.
///
/// `acquire_yields` is incremented on each `yield_now()` call in the slow path.
#[inline]
pub(super) fn acquire_buffer_with_backoff(
    pool: &TsBufferPool,
    acquire_yields: &mut u64,
) -> TsBufferHandle {
    // Fast path: pool likely has a buffer.
    if let Some(buf) = pool.try_acquire() {
        return buf;
    }

    loop {
        for _ in 0..SPIN_ITERS {
            core::hint::spin_loop();
        }
        if let Some(buf) = pool.try_acquire() {
            return buf;
        }
        *acquire_yields += 1;
        std::thread::yield_now();
    }
}

// ============================================================================
// Coordinator Entry Point
// ============================================================================

/// Scan local filesystem files using a sharded share-nothing architecture.
///
/// # Architecture
///
/// ```text
/// scan_local_fs_sharded()
///   |
///   |  1. Create N shard file channels
///   |  2. Create N count budgets (one per shard)
///   |  3. For each shard, spawn:
///   |     - TsBufferPool (per-shard, 2 workers)
///   |     - SPSC ring (capacity SHARD_SPSC_CAP)
///   |     - I/O thread (shard_io_blocking)
///   |     - Scan thread (shard_scan_loop)
///   |  4. Round-robin files across shards
///   |  5. Drop senders -> I/O threads drain -> Shutdown -> scan threads exit
///   |  6. Join all threads, collect stats
///   v
/// ShardedFsReport
/// ```
///
/// # Arguments
///
/// * `engine` - Detection engine (shared across all shards via `Arc`)
/// * `files` - Iterator of files to scan (consumed by the coordinator)
/// * `cfg` - Sharded scanner configuration
///
/// # Blocking
///
/// This function blocks the calling thread until all files have been enqueued,
/// all shard I/O threads have drained their file channels, and all scan threads
/// have exited. Typical usage is to call this from a dedicated coordinator
/// thread or from `main`.
///
/// # Returns
///
/// A [`ShardedFsReport`] containing per-shard statistics and aggregated metrics.
///
/// # Errors
///
/// Returns `io::Error` if thread spawning fails or a thread panics.
pub fn scan_local_fs_sharded<E: ScanEngine>(
    engine: Arc<E>,
    files: impl Iterator<Item = LocalFile>,
    cfg: ShardedFsConfig,
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

    let wall_start = Instant::now();

    // --- Create per-shard infrastructure ---

    // File channels: coordinator sends file work items to each shard's I/O thread.
    let mut shard_senders: Vec<crossbeam_channel::Sender<ShardFileWork>> =
        Vec::with_capacity(num_shards);
    let mut shard_receivers: Vec<crossbeam_channel::Receiver<ShardFileWork>> =
        Vec::with_capacity(num_shards);

    // Count budgets: one per shard for file-level backpressure.
    let mut shard_budgets: Vec<Arc<CountBudget>> = Vec::with_capacity(num_shards);

    for _ in 0..num_shards {
        let (tx, rx) = crossbeam_channel::bounded(cfg.max_in_flight_per_shard);
        shard_senders.push(tx);
        shard_receivers.push(rx);
        shard_budgets.push(CountBudget::new(cfg.max_in_flight_per_shard));
    }

    // --- Spawn shard threads ---

    let mut io_handles: Vec<thread::JoinHandle<ShardIoStats>> = Vec::with_capacity(num_shards);
    let mut scan_handles: Vec<thread::JoinHandle<ShardScanStats>> = Vec::with_capacity(num_shards);

    for (shard_idx, file_rx) in shard_receivers.iter().enumerate() {
        // Per-shard buffer pool: 2 workers (I/O thread + scan thread).
        let pool = TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: buf_len,
            total_buffers: cfg.pool_buffers_per_shard,
            workers: 2,
            local_queue_cap: cfg.local_queue_cap,
        });

        // SPSC channel connecting I/O thread -> scan thread.
        let (spsc_producer, spsc_consumer) = spsc_channel::<ScanChunk, SHARD_SPSC_CAP>();

        let file_rx = file_rx.clone();
        let engine_io = Arc::clone(&engine);
        let engine_scan = Arc::clone(&engine);
        let event_sink = Arc::clone(&cfg.event_sink);
        let dedupe = cfg.dedupe_within_chunk;
        let pin_threads = cfg.pin_threads;

        // Capture config values needed by the I/O thread.
        let io_chunk_size = cfg.chunk_size;
        let io_max_file_size = cfg.max_file_size;
        let io_archive = cfg.archive.clone();

        // I/O thread
        let io_pool = pool.clone();
        let io_handle = thread::Builder::new()
            .name(format!("shard-{shard_idx}-io"))
            .spawn(move || {
                // Attempt CPU pinning (best-effort).
                if pin_threads {
                    let core = shard_idx * 2;
                    let _ = pin_current_thread_to_core(core);
                }

                // Build a lightweight config view for the I/O function.
                let io_cfg = ShardedFsConfig {
                    shards: 0, // unused inside I/O thread
                    chunk_size: io_chunk_size,
                    max_file_size: io_max_file_size,
                    pool_buffers_per_shard: 0,  // unused
                    local_queue_cap: 0,         // unused
                    max_in_flight_per_shard: 0, // unused
                    spsc_capacity: 0,           // unused
                    dedupe_within_chunk: false, // unused by I/O thread
                    archive: io_archive,
                    event_sink: Arc::new(crate::unified::events::NullEventSink),
                    pin_threads: false, // already pinned above
                };

                shard_io_blocking::<E>(file_rx, spsc_producer, io_pool, engine_io.as_ref(), &io_cfg)
            })
            .map_err(io::Error::other)?;

        // Scan thread
        let scan_handle = thread::Builder::new()
            .name(format!("shard-{shard_idx}-scan"))
            .spawn(move || {
                // Attempt CPU pinning (best-effort).
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

    // Drop extra receiver clones (each shard's I/O thread owns one).
    drop(shard_receivers);

    // --- Round-robin files across shards ---

    let mut files_enqueued: u64 = 0;
    let mut shard_rr: usize = 0;

    for local_file in files {
        let shard_idx = shard_rr % num_shards;
        shard_rr = shard_rr.wrapping_add(1);

        // Acquire backpressure permit for this shard (blocks if at capacity).
        let permit = shard_budgets[shard_idx].acquire(1);

        let work = ShardFileWork {
            path: local_file.path,
            size: local_file.size,
            _permit: permit,
        };

        // Send to the shard's file channel. This blocks if the channel is full
        // (bounded channel provides additional backpressure).
        if shard_senders[shard_idx].send(work).is_err() {
            // I/O thread dropped its receiver (unexpected). Stop enqueuing.
            break;
        }

        files_enqueued = files_enqueued.saturating_add(1);
    }

    // Drop senders: I/O threads will drain remaining files, then see channel
    // closed and push Shutdown sentinel.
    drop(shard_senders);

    // --- Join all threads and collect stats ---

    let mut io_stats: Vec<ShardIoStats> = Vec::with_capacity(num_shards);
    let mut scan_stats: Vec<ShardScanStats> = Vec::with_capacity(num_shards);

    for handle in io_handles {
        match handle.join() {
            Ok(s) => io_stats.push(s),
            Err(_) => return Err(io::Error::other("shard I/O thread panicked")),
        }
    }

    for handle in scan_handles {
        match handle.join() {
            Ok(s) => scan_stats.push(s),
            Err(_) => return Err(io::Error::other("shard scan thread panicked")),
        }
    }

    let wall_time_ns = wall_start.elapsed().as_nanos() as u64;

    // Flush the event sink.
    cfg.event_sink.flush();

    // --- Aggregate metrics into MetricsSnapshot ---

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

    metrics.worker_count = (num_shards * 2) as u32; // I/O + scan threads
    metrics.duration_ns = wall_time_ns;

    Ok(ShardedFsReport {
        io_stats,
        scan_stats,
        files_enqueued,
        wall_time_ns,
        metrics,
    })
}

#[cfg(test)]
mod file_id_tests {
    use super::*;
    use crate::scheduler::engine_trait::{EngineScratch, FindingRecord, ScanEngine};
    use crate::unified::events::NullEventSink;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Clone)]
    struct TestFinding {
        start: u64,
        end: u64,
    }

    impl FindingRecord for TestFinding {
        fn rule_id(&self) -> u32 {
            0
        }

        fn root_hint_start(&self) -> u64 {
            self.start
        }

        fn root_hint_end(&self) -> u64 {
            self.end
        }

        fn span_start(&self) -> u64 {
            self.start
        }

        fn span_end(&self) -> u64 {
            self.end
        }
    }

    struct TestScratch {
        findings: Vec<TestFinding>,
        seen: HashSet<(u32, u64, u64)>,
    }

    impl EngineScratch for TestScratch {
        type Finding = TestFinding;

        fn clear(&mut self) {
            // Intentionally keep `seen` across files to model engines that keep
            // file-scoped dedupe state outside the drain buffer.
            self.findings.clear();
        }

        fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
            self.findings
                .retain(|f| f.root_hint_end() >= new_bytes_start);
        }

        fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
            out.append(&mut self.findings);
        }
    }

    struct FileScopedDedupeEngine;

    impl ScanEngine for FileScopedDedupeEngine {
        type Scratch = TestScratch;

        fn required_overlap(&self) -> usize {
            0
        }

        fn new_scratch(&self) -> Self::Scratch {
            TestScratch {
                findings: Vec::new(),
                seen: HashSet::new(),
            }
        }

        fn scan_chunk_into(
            &self,
            data: &[u8],
            file_id: FileId,
            base_offset: u64,
            scratch: &mut Self::Scratch,
        ) {
            const NEEDLE: &[u8] = b"SECRET";
            if data.len() < NEEDLE.len() {
                return;
            }

            for i in 0..=data.len() - NEEDLE.len() {
                if &data[i..i + NEEDLE.len()] != NEEDLE {
                    continue;
                }
                let start = base_offset + i as u64;
                let end = start + NEEDLE.len() as u64;
                if scratch.seen.insert((file_id.0, start, end)) {
                    scratch.findings.push(TestFinding { start, end });
                }
            }
        }

        fn rule_name(&self, _rule_id: u32) -> &str {
            "test-rule"
        }
    }

    #[test]
    fn sharded_scanner_assigns_distinct_file_ids_per_file() {
        let dir = tempdir().expect("tempdir");
        let p1 = dir.path().join("a.txt");
        let p2 = dir.path().join("b.txt");
        std::fs::write(&p1, b"SECRET").expect("write a");
        std::fs::write(&p2, b"SECRET").expect("write b");

        let files = vec![
            LocalFile { path: p1, size: 6 },
            LocalFile { path: p2, size: 6 },
        ];

        let report = scan_local_fs_sharded(
            Arc::new(FileScopedDedupeEngine),
            files.into_iter(),
            ShardedFsConfig {
                shards: 1,
                chunk_size: 64 * 1024,
                max_file_size: u64::MAX,
                pool_buffers_per_shard: 4,
                local_queue_cap: 2,
                max_in_flight_per_shard: 8,
                spsc_capacity: SHARD_SPSC_CAP,
                dedupe_within_chunk: false,
                archive: ArchiveConfig {
                    enabled: false,
                    ..Default::default()
                },
                event_sink: Arc::new(NullEventSink),
                pin_threads: false,
            },
        )
        .expect("scan should succeed");

        assert_eq!(
            report.metrics.findings_emitted, 2,
            "distinct FileIds per file are required to avoid cross-file dedupe suppression"
        );
    }
}
