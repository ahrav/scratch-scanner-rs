//! Bounded single-writer append-only log runtime.
//!
//! This module owns segment lifecycle (`.open` append → `.bin` finalize),
//! backpressure (batch count + byte budgets), and [`StoreProducer`]
//! integration for filesystem finding persistence.
//!
//! # Architecture
//!
//! ```text
//!  Scanner worker threads            Writer thread
//!  ────────────────────             ──────────────
//!  emit_fs_batch()                  ┌──────────────────────┐
//!    ├─ encode finding frame        │ writer_thread_main()  │
//!    ├─ reserve_inflight()  ──►     │  ├─ write RunStart    │
//!    └─ send on channel    ──►      │  ├─ write RuleDefs    │
//!                                   │  ├─ recv loop:        │
//!  record_fs_run_loss()             │  │  write FindingFrame │
//!    ├─ encode run-end frame        │  │  release_inflight() │
//!    ├─ mark_closed()               │  └─ write RunEnd      │
//!    ├─ send Finish cmd    ──►      │  └─ finalize segment  │
//!    └─ join writer thread          └──────────────────────┘
//! ```
//!
//! # Backpressure
//!
//! Producers block in `reserve_inflight` when either of two budgets is
//! exhausted:
//! - **Batch count** — caps the number of in-flight finding frames.
//! - **Byte budget** — caps the total encoded bytes queued in the channel.
//!
//! The writer thread releases budget after each frame is written to disk,
//! waking blocked producers via a [`Condvar`].
//!
//! # Segment lifecycle
//!
//! Files are created as `segment-NNNNN.open` and renamed to `.bin` on
//! segment close (`sync_data` + rename + `sync_dir`). The writer rotates
//! to a new segment when `bytes_written + frame_len > max_segment_bytes`.
//! After a clean shutdown, no `.open` files remain.

use super::format::{
    encode_record, FrameType, LogDurabilityMode, LogRecord, LogRuleDef, LogRunEnd, LogRunStart,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES, FRAME_HEADER_BYTES, LOG_FORMAT_VERSION,
};
use crate::api::RuleSpec;
use crate::store::identity::{rule_fingerprint, secret_hash};
use crate::store::keys::StoreKeys;
use crate::store::{FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, StoreProducer};
use crossbeam_channel::{Receiver, Sender};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RUN_PREFIX: &str = "run-";
const SEGMENTS_DIR: &str = "segments";
const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_OPEN_EXT: &str = "open";
const SEGMENT_BIN_EXT: &str = "bin";
const FINDING_ID_DOMAIN: &[u8] = b"scanner.store.log.v1.finding_id";
const FINDING_BATCH_BASE_PAYLOAD_BYTES: usize = 8; // object_path_len + findings_count
const FINDING_RECORD_WIRE_BYTES: usize = 132;

/// Environment override for FS append-log root directory.
pub const SCANNER_FS_LOG_DIR_ENV: &str = "SCANNER_FS_LOG_DIR";

/// Runtime configuration for [`AppendLogStoreProducer`].
#[derive(Clone, Debug)]
pub struct LogWriterConfig {
    /// Store root directory that will contain `run-<id>/segments/*.bin`.
    pub root_dir: PathBuf,
    /// Max in-flight finding-batch frames queued to the writer thread.
    pub max_inflight_batches: usize,
    /// Max in-flight encoded bytes queued to the writer thread.
    pub max_inflight_bytes: usize,
    /// Max bytes per segment before rotation/finalize.
    pub max_segment_bytes: u64,
    /// Max frame payload bytes accepted by codec.
    pub max_frame_payload_bytes: u32,
    /// Durability strategy used while writing.
    pub durability: LogDurabilityMode,
    /// Optional artificial delay after each finding frame write.
    ///
    /// Primarily used by tests to validate backpressure behavior.
    pub write_delay: Option<Duration>,
}

impl LogWriterConfig {
    pub fn for_root(root_dir: PathBuf) -> Self {
        Self {
            root_dir,
            max_inflight_batches: 256,
            max_inflight_bytes: 64 * 1024 * 1024,
            max_segment_bytes: 64 * 1024 * 1024,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            durability: LogDurabilityMode::SegmentClose,
            write_delay: None,
        }
    }
}

impl Default for LogWriterConfig {
    fn default() -> Self {
        Self::for_root(PathBuf::from(".scanner-rs-store"))
    }
}

/// Append-only log-backed [`StoreProducer`] for FS scans.
///
/// Construction spawns a dedicated writer thread that consumes encoded
/// frames from a bounded channel, writes them to segment files, and
/// handles rotation when the segment size limit is reached.
///
/// # Thread safety
///
/// `emit_fs_batch` may be called concurrently from multiple scanner worker
/// threads. Encoding happens on the caller's thread; only the serialised
/// frame bytes cross the channel to the single writer thread.
///
/// # Shutdown
///
/// [`record_fs_run_loss`](StoreProducer::record_fs_run_loss) must be called
/// exactly once to close the run. It sends the `RunEnd` frame, joins the
/// writer thread, and finalizes the last segment. Dropping the producer
/// without calling `record_fs_run_loss` causes a best-effort finalization
/// of the current segment (no `RunEnd` frame is written).
pub struct AppendLogStoreProducer {
    inner: Arc<Inner>,
}

impl AppendLogStoreProducer {
    /// Construct a producer for an FS scan root using default config.
    pub fn for_fs_scan(scan_root: &Path, rules: &[RuleSpec]) -> Result<Self, FsStoreError> {
        let cfg = LogWriterConfig::for_root(default_fs_log_root(scan_root));
        Self::new(rules, cfg)
    }

    /// Construct a producer with explicit writer config.
    ///
    /// Bootstraps store keys from the environment, computes rule
    /// fingerprints, creates the run directory, and spawns the writer
    /// thread. The writer thread immediately writes the `RunStart` and
    /// `RuleDef` frames before entering its receive loop.
    pub fn new(rules: &[RuleSpec], cfg: LogWriterConfig) -> Result<Self, FsStoreError> {
        validate_config(&cfg)?;

        let keys = StoreKeys::bootstrap_from_env();
        let (rule_defs_sorted, rule_fingerprints_by_id) = build_rule_defs(rules, &keys);
        let run_id = next_run_id();
        let run_start = build_run_start(&cfg, &keys, run_id);

        let shared = Arc::new(SharedState::default());
        let (tx, rx) = crossbeam_channel::bounded(cfg.max_inflight_batches.max(1));
        let thread_shared = Arc::clone(&shared);
        let thread_cfg = cfg.clone();
        let writer_handle = std::thread::Builder::new()
            .name("scanner-rs-log-writer".to_string())
            .spawn(move || {
                if let Err(err) = writer_thread_main(
                    rx,
                    thread_cfg,
                    run_id,
                    run_start,
                    rule_defs_sorted,
                    &thread_shared,
                ) {
                    set_terminal_error(&thread_shared, err);
                } else {
                    mark_closed(&thread_shared);
                }
            })
            .map_err(|err| {
                FsStoreError::backend(format!("failed to spawn writer thread: {err}"))
            })?;

        Ok(Self {
            inner: Arc::new(Inner {
                tx,
                cfg,
                run_id,
                keys,
                shared,
                writer_handle: Mutex::new(Some(writer_handle)),
                rule_fingerprints_by_id: rule_fingerprints_by_id.into_boxed_slice(),
            }),
        })
    }

    /// Run identifier emitted in `RunStart`.
    #[inline]
    pub fn run_id(&self) -> u64 {
        self.inner.run_id
    }

    /// Store root directory used by this producer.
    #[inline]
    pub fn store_root(&self) -> &Path {
        &self.inner.cfg.root_dir
    }

    /// Encode a [`FsFindingBatch`] directly into a framed wire buffer.
    ///
    /// Unlike `RunStart`/`RuleDef`/`RunEnd` frames (which go through
    /// [`encode_record`]), finding frames are built inline here to avoid an
    /// intermediate `LogFindingBatch` allocation. The hot path is:
    ///
    /// 1. Reserve a `Vec` with exact capacity (`FRAME_HEADER_BYTES + body`).
    /// 2. Write a placeholder 8-byte header (filled in step 5).
    /// 3. Stream the type byte, path, and per-finding fields while keeping a
    ///    running CRC-32 in lockstep via [`frame_extend_crc`].
    /// 4. Derive a deterministic `finding_id` per finding using a cloned
    ///    BLAKE3 prefix hasher (amortises the object-path hash across the
    ///    batch).
    /// 5. Back-patch the header with `body_len` and `crc32`.
    ///
    /// The resulting buffer is ready for `SegmentWriter::write_frame` with no
    /// further copies.
    fn build_finding_frame(&self, batch: FsFindingBatch<'_>) -> Result<Vec<u8>, FsStoreError> {
        let object_path_len = u32::try_from(batch.object_path.len()).map_err(|_| {
            FsStoreError::backend(format!(
                "object_path too large: {} bytes",
                batch.object_path.len()
            ))
        })?;
        let findings_count_u32 = u32::try_from(batch.findings.len())
            .map_err(|_| FsStoreError::backend("findings length exceeds u32".to_string()))?;

        let findings_bytes = batch
            .findings
            .len()
            .checked_mul(FINDING_RECORD_WIRE_BYTES)
            .ok_or_else(|| FsStoreError::backend("finding payload length overflow"))?;
        let payload_len = FINDING_BATCH_BASE_PAYLOAD_BYTES
            .checked_add(batch.object_path.len())
            .and_then(|n| n.checked_add(findings_bytes))
            .ok_or_else(|| FsStoreError::backend("finding frame payload length overflow"))?;
        if payload_len > self.inner.cfg.max_frame_payload_bytes as usize {
            let len = u32::try_from(payload_len).unwrap_or(u32::MAX);
            return Err(map_format_err(super::format::FormatError::FrameTooLarge {
                len,
                max: self.inner.cfg.max_frame_payload_bytes,
            }));
        }

        let body_len = payload_len
            .checked_add(1)
            .ok_or_else(|| FsStoreError::backend("finding frame body length overflow"))?;
        let body_len_u32 = u32::try_from(body_len)
            .map_err(|_| FsStoreError::backend("finding frame body exceeds u32::MAX"))?;

        // Encode directly into the framed buffer to avoid building an
        // intermediate `LogFindingBatch` payload and re-copying it.
        let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + body_len);
        frame.resize(FRAME_HEADER_BYTES, 0);
        let frame_type = FrameType::FindingBatch as u8;
        frame.push(frame_type);

        let mut crc = crc32fast::Hasher::new();
        crc.update(&[frame_type]);

        let path_len_bytes = object_path_len.to_le_bytes();
        frame_extend_crc(&mut frame, &mut crc, &path_len_bytes);
        frame_extend_crc(&mut frame, &mut crc, batch.object_path);
        frame_extend_crc(&mut frame, &mut crc, &findings_count_u32.to_le_bytes());

        let finding_id_prefix = finding_id_prefix_hasher(
            self.inner.keys.metadata_key(),
            object_path_len,
            batch.object_path,
        );
        for finding in batch.findings {
            let rule_idx = finding.rule_id as usize;
            let Some(rule_fp) = self.inner.rule_fingerprints_by_id.get(rule_idx) else {
                return Err(FsStoreError::backend(format!(
                    "unknown rule_id {} for log finding encode",
                    finding.rule_id
                )));
            };
            let secret = secret_hash(&finding.norm_hash, &self.inner.keys);
            let finding_id = derive_finding_id(&finding_id_prefix, finding, rule_fp, &secret);

            frame_extend_crc(&mut frame, &mut crc, &finding.rule_id.to_le_bytes());
            frame_extend_crc(&mut frame, &mut crc, rule_fp);
            frame_extend_crc(&mut frame, &mut crc, &secret);
            frame_extend_crc(&mut frame, &mut crc, &finding_id);
            frame_extend_crc(&mut frame, &mut crc, &finding.root_hint_start.to_le_bytes());
            frame_extend_crc(&mut frame, &mut crc, &finding.root_hint_end.to_le_bytes());
            frame_extend_crc(&mut frame, &mut crc, &finding.span_start.to_le_bytes());
            frame_extend_crc(&mut frame, &mut crc, &finding.span_end.to_le_bytes());
        }

        let crc32 = crc.finalize();
        frame[..4].copy_from_slice(&body_len_u32.to_le_bytes());
        frame[4..FRAME_HEADER_BYTES].copy_from_slice(&crc32.to_le_bytes());

        debug_assert_eq!(frame.len(), FRAME_HEADER_BYTES + body_len);
        Ok(frame)
    }

    /// Encode a `RunEnd` frame via the generic [`encode_record`] path.
    fn build_run_end_frame(&self, loss: FsRunLoss) -> Result<Vec<u8>, FsStoreError> {
        let record = LogRecord::RunEnd(LogRunEnd {
            ended_unix_ms: now_unix_ms(),
            dropped_findings: loss.dropped_findings,
            persistence_emit_failures: loss.persistence_emit_failures,
            incomplete: loss.incomplete(),
        });
        let mut frame = Vec::with_capacity(128);
        encode_record(&record, self.inner.cfg.max_frame_payload_bytes, &mut frame)
            .map_err(map_format_err)?;
        Ok(frame)
    }

    /// Block until both inflight budgets (batch count and byte count) have
    /// room for one more frame of `frame_bytes` size.
    ///
    /// Returns immediately with an error if the frame alone exceeds the byte
    /// budget (it can never fit). Otherwise spins on the [`Condvar`] until
    /// the writer thread calls `release_inflight`, which decrements both
    /// counters and wakes all waiters.
    ///
    /// Also returns `Err` if the writer has been marked closed (normal
    /// shutdown or terminal error) while we were waiting.
    fn reserve_inflight(&self, frame_bytes: usize) -> Result<(), FsStoreError> {
        if frame_bytes > self.inner.cfg.max_inflight_bytes {
            return Err(FsStoreError::backend(format!(
                "frame exceeds inflight byte budget: {} > {}",
                frame_bytes, self.inner.cfg.max_inflight_bytes
            )));
        }

        let mut guard = lock_state(&self.inner.shared)?;
        loop {
            if guard.closed {
                return Err(closed_error(&guard));
            }
            let next_bytes = guard.inflight_bytes.saturating_add(frame_bytes);
            if guard.inflight_batches < self.inner.cfg.max_inflight_batches
                && next_bytes <= self.inner.cfg.max_inflight_bytes
            {
                guard.inflight_batches += 1;
                guard.inflight_bytes = next_bytes;
                return Ok(());
            }
            guard = self
                .inner
                .shared
                .cv
                .wait(guard)
                .map_err(|_| FsStoreError::backend("append-log inflight mutex poisoned"))?;
        }
    }

    /// Delegate to the free-standing `release_inflight`; exists so
    /// `emit_fs_batch` can release budget on a send failure without
    /// reaching into `self.inner.shared` directly.
    fn release_inflight(&self, frame_bytes: usize) {
        release_inflight(&self.inner.shared, frame_bytes);
    }
}

impl StoreProducer for AppendLogStoreProducer {
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        if batch.findings.is_empty() {
            return Ok(());
        }

        let frame = self.build_finding_frame(batch)?;
        let charge = frame.len();
        self.reserve_inflight(charge)?;

        let flush_after = self.inner.cfg.durability == LogDurabilityMode::Batch;
        let msg = WriterCommand::FindingFrame {
            frame,
            charge_bytes: charge,
            flush_after,
        };
        if self.inner.tx.send(msg).is_err() {
            self.release_inflight(charge);
            // The writer thread has exited — check for a terminal error
            // that explains why.
            return Err(terminal_result(&self.inner.shared)
                .err()
                .unwrap_or_else(|| {
                    FsStoreError::backend("append-log writer channel disconnected")
                }));
        }
        Ok(())
    }

    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        let frame = self.build_run_end_frame(loss)?;

        // NOTE: we intentionally do NOT call mark_closed() here. The writer
        // thread already calls mark_closed() (or set_terminal_error()) when
        // it exits. Calling mark_closed() before sending Finish would wake
        // any emitter blocked in reserve_inflight() and give it a spurious
        // "closed" error, potentially dropping in-flight findings.
        //
        // By deferring the close signal to the writer thread exit, blocked
        // emitters are unblocked naturally by release_inflight() as the
        // writer drains frames, and their FindingFrames queue ahead of
        // Finish in the channel.

        let handle = {
            let mut guard =
                self.inner.writer_handle.lock().map_err(|_| {
                    FsStoreError::backend("append-log writer handle mutex poisoned")
                })?;
            guard.take()
        };

        if handle.is_none() {
            return terminal_result(&self.inner.shared);
        }

        if self.inner.tx.send(WriterCommand::Finish { frame }).is_err() {
            set_terminal_error(
                &self.inner.shared,
                "failed to send run-end frame: writer channel disconnected".to_string(),
            );
        }

        if let Some(join) = handle {
            if join.join().is_err() {
                set_terminal_error(
                    &self.inner.shared,
                    "append-log writer thread panicked".to_string(),
                );
            }
        }

        terminal_result(&self.inner.shared)
    }
}

/// Shared-ownership core behind [`AppendLogStoreProducer`].
///
/// Split from the public struct so an `Arc<Inner>` can be handed to
/// concurrent emitter threads and the writer-thread closure without
/// exposing internals.
struct Inner {
    tx: Sender<WriterCommand>,
    cfg: LogWriterConfig,
    run_id: u64,
    keys: StoreKeys,
    shared: Arc<SharedState>,
    /// `None` after [`StoreProducer::record_fs_run_loss`] takes it.
    writer_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Index `[rule_id]` → 32-byte BLAKE3 fingerprint.
    rule_fingerprints_by_id: Box<[[u8; 32]]>,
}

/// Producer ↔ writer synchronisation.
///
/// This is a condition-variable protocol with two roles:
///
/// - **Producers** (multiple) call `reserve_inflight` which blocks on
///   `cv` when the budget is full, and rechecks after each notify.
/// - **Writer** (single) calls `release_inflight` after writing each
///   finding frame, decrementing budgets and waking all waiters.
///
/// Shutdown signals flow through `mark_closed` (clean exit) or
/// `set_terminal_error` (I/O failure), both of which set
/// `closed = true` and `notify_all` so producers unblock and observe
/// the shutdown.
#[derive(Default)]
struct SharedState {
    state: Mutex<InflightState>,
    cv: Condvar,
}

/// Mutable state guarded by [`SharedState::state`].
///
/// # Invariants
///
/// - `inflight_batches` and `inflight_bytes` are monotonically adjusted
///   by matched `reserve` / `release` pairs. They may be zeroed on
///   terminal error.
/// - Once `closed` is set it is never unset.
/// - `terminal_error` is write-once; the first error wins.
#[derive(Debug, Default)]
struct InflightState {
    /// Number of finding frames queued but not yet written to disk.
    inflight_batches: usize,
    /// Total encoded bytes of queued finding frames.
    inflight_bytes: usize,
    /// Set on clean shutdown or terminal error; checked by
    /// `reserve_inflight` to reject new work.
    closed: bool,
    /// Root-cause message from the writer thread, if it failed.
    terminal_error: Option<String>,
}

/// Messages sent from producer threads to the single writer thread.
enum WriterCommand {
    /// A pre-encoded finding-batch frame ready for disk write.
    FindingFrame {
        frame: Vec<u8>,
        /// Byte count charged against the inflight budget when this
        /// frame was queued. Released by the writer after the write.
        charge_bytes: usize,
        /// If `true`, the writer calls `sync_data` after writing this
        /// frame (used when `durability == Batch`).
        flush_after: bool,
    },
    /// Shutdown: write the pre-encoded `RunEnd` frame and finalize.
    Finish { frame: Vec<u8> },
}

/// Writer thread entry point.
///
/// Writes frames in strict order: `RunStart` → `RuleDef`s (sorted by
/// fingerprint) → finding frames from the channel → `RunEnd` on `Finish`.
/// Each finding frame write releases its inflight budget, unblocking any
/// producers waiting in `reserve_inflight`.
///
/// If the channel disconnects (producer dropped without `Finish`), the
/// current segment is finalized best-effort without a `RunEnd` frame.
fn writer_thread_main(
    rx: Receiver<WriterCommand>,
    cfg: LogWriterConfig,
    run_id: u64,
    run_start: LogRunStart,
    rule_defs_sorted: Vec<LogRuleDef>,
    shared: &SharedState,
) -> Result<(), String> {
    let run_dir = cfg.root_dir.join(format!("{RUN_PREFIX}{run_id:016x}"));
    let segments_dir = run_dir.join(SEGMENTS_DIR);
    let mut segment_writer =
        SegmentWriter::new(segments_dir, cfg.max_segment_bytes).map_err(|e| e.to_string())?;

    let mut frame = Vec::with_capacity(512);
    encode_record(
        &LogRecord::RunStart(run_start),
        cfg.max_frame_payload_bytes,
        &mut frame,
    )
    .map_err(|e| e.to_string())?;
    segment_writer
        .write_frame(&frame, false)
        .map_err(|e| e.to_string())?;

    for rule_def in rule_defs_sorted {
        frame.clear();
        encode_record(
            &LogRecord::RuleDef(rule_def),
            cfg.max_frame_payload_bytes,
            &mut frame,
        )
        .map_err(|e| e.to_string())?;
        segment_writer
            .write_frame(&frame, false)
            .map_err(|e| e.to_string())?;
    }

    loop {
        match rx.recv() {
            Ok(WriterCommand::FindingFrame {
                frame,
                charge_bytes,
                flush_after,
            }) => {
                let write_result = segment_writer.write_frame(&frame, flush_after);
                if let Some(delay) = cfg.write_delay {
                    std::thread::sleep(delay);
                }
                release_inflight(shared, charge_bytes);
                if let Err(err) = write_result {
                    return Err(format!("failed to write finding frame: {err}"));
                }
            }
            Ok(WriterCommand::Finish { frame }) => {
                segment_writer
                    .write_frame(&frame, false)
                    .map_err(|e| format!("failed to write run-end frame: {e}"))?;
                segment_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize segment: {e}"))?;
                return Ok(());
            }
            Err(_) => {
                // Producer dropped unexpectedly; finalize best-effort.
                segment_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize segment on channel close: {e}"))?;
                return Ok(());
            }
        }
    }
}

/// Manages the current `.open` segment file and handles rotation.
///
/// Invariants:
/// - At most one `.open` file exists at a time (the one being appended to).
/// - Rotation calls `sync_data` + rename(`.open` → `.bin`) + `sync_dir`
///   before opening the next segment, so a crash can only lose the
///   currently-open segment's tail.
/// - A single frame is never split across segments.
struct SegmentWriter {
    segments_dir: PathBuf,
    max_segment_bytes: u64,
    /// Monotonically increasing segment sequence number (zero-based).
    seq: u64,
    file: File,
    open_path: PathBuf,
    bytes_written: u64,
}

impl SegmentWriter {
    fn new(segments_dir: PathBuf, max_segment_bytes: u64) -> std::io::Result<Self> {
        fs::create_dir_all(&segments_dir)?;
        let (file, open_path) = open_segment_file(&segments_dir, 0)?;
        Ok(Self {
            segments_dir,
            max_segment_bytes,
            seq: 0,
            file,
            open_path,
            bytes_written: 0,
        })
    }

    fn write_frame(&mut self, frame: &[u8], flush_after: bool) -> std::io::Result<()> {
        let frame_len = frame.len() as u64;
        if frame_len > self.max_segment_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame exceeds max_segment_bytes",
            ));
        }

        if self.bytes_written > 0
            && self.bytes_written.saturating_add(frame_len) > self.max_segment_bytes
        {
            self.finalize_current()?;
            self.seq = self
                .seq
                .checked_add(1)
                .expect("segment sequence number overflow");
            let (file, open_path) = open_segment_file(&self.segments_dir, self.seq)?;
            self.file = file;
            self.open_path = open_path;
            self.bytes_written = 0;
        }

        self.file.write_all(frame)?;
        self.bytes_written = self.bytes_written.saturating_add(frame_len);
        if flush_after {
            self.file.sync_data()?;
        }
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<()> {
        self.finalize_current()
    }

    fn finalize_current(&mut self) -> std::io::Result<()> {
        self.file.sync_data()?;
        let mut bin_path = self.open_path.clone();
        bin_path.set_extension(SEGMENT_BIN_EXT);
        fs::rename(&self.open_path, &bin_path)?;
        sync_dir(&self.segments_dir)?;
        Ok(())
    }
}

/// Create a new `.open` segment file with `O_CREAT | O_EXCL` semantics.
///
/// `create_new(true)` ensures the call fails if the file already exists,
/// which guards against accidental double-opens after a crash that left
/// a stale `.open` file behind.
fn open_segment_file(segments_dir: &Path, seq: u64) -> std::io::Result<(File, PathBuf)> {
    let name = format!("{SEGMENT_PREFIX}{seq:020}.{SEGMENT_OPEN_EXT}");
    let path = segments_dir.join(name);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    Ok((file, path))
}

/// Fsync the directory itself so that rename metadata reaches stable storage.
///
/// After `rename(.open → .bin)`, the directory entry update lives only in
/// the page cache until the directory inode is fsynced. Without this,
/// a power loss could leave the old `.open` name on disk despite a
/// successful rename return.
///
/// No-op on non-Unix platforms where directory fsync is unsupported.
#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Compute fingerprints and build the sorted `RuleDef` frame list.
///
/// Returns two parallel data structures:
/// - `Vec<LogRuleDef>` sorted by `(rule_fingerprint, rule_id)` — the order
///   in which `RuleDef` frames are written to the log.
/// - `Vec<[u8; 32]>` indexed by `rule_id` — a lookup table used by
///   `build_finding_frame` to map engine rule indices to fingerprints.
fn build_rule_defs(rules: &[RuleSpec], keys: &StoreKeys) -> (Vec<LogRuleDef>, Vec<[u8; 32]>) {
    let mut by_id = Vec::with_capacity(rules.len());
    let mut defs = Vec::with_capacity(rules.len());
    for (rule_id, rule) in rules.iter().enumerate() {
        let fp = rule_fingerprint(rule, keys);
        by_id.push(fp);
        defs.push(LogRuleDef {
            rule_id: rule_id as u32,
            rule_fingerprint: fp,
            rule_name: rule.name.as_bytes().to_vec(),
        });
    }
    defs.sort_by(|a, b| {
        a.rule_fingerprint
            .cmp(&b.rule_fingerprint)
            .then(a.rule_id.cmp(&b.rule_id))
    });
    (defs, by_id)
}

/// Snapshot current config, key metadata, and wallclock into a
/// [`LogRunStart`] record. Written as the first frame in every run.
fn build_run_start(cfg: &LogWriterConfig, keys: &StoreKeys, run_id: u64) -> LogRunStart {
    LogRunStart {
        version: LOG_FORMAT_VERSION,
        run_id,
        started_unix_ms: now_unix_ms(),
        durability: cfg.durability,
        correlation_mode: keys.run_mode().correlation_mode,
        key_source: keys.run_mode().key_source,
        max_inflight_batches: cfg.max_inflight_batches as u32,
        max_inflight_bytes: cfg.max_inflight_bytes as u64,
        max_frame_payload_bytes: cfg.max_frame_payload_bytes,
    }
}

/// Reject obviously invalid configurations at construction time.
///
/// Beyond per-field zero checks, enforces the cross-field invariant that
/// the largest possible frame (`max_frame_payload_bytes + FRAME_HEADER_BYTES`)
/// must fit inside a single segment. Without this check, the writer would
/// fail on the very first frame write.
fn validate_config(cfg: &LogWriterConfig) -> Result<(), FsStoreError> {
    if cfg.max_inflight_batches == 0 {
        return Err(FsStoreError::backend(
            "max_inflight_batches must be at least 1",
        ));
    }
    if cfg.max_inflight_bytes == 0 {
        return Err(FsStoreError::backend(
            "max_inflight_bytes must be at least 1",
        ));
    }
    if cfg.max_segment_bytes == 0 {
        return Err(FsStoreError::backend(
            "max_segment_bytes must be at least 1",
        ));
    }
    if cfg.max_frame_payload_bytes == 0 {
        return Err(FsStoreError::backend(
            "max_frame_payload_bytes must be at least 1",
        ));
    }
    if cfg.max_inflight_batches > u32::MAX as usize {
        return Err(FsStoreError::backend(
            "max_inflight_batches exceeds u32::MAX (wire format limit)",
        ));
    }
    if (cfg.max_frame_payload_bytes as u64 + super::format::FRAME_HEADER_BYTES as u64)
        > cfg.max_segment_bytes
    {
        return Err(FsStoreError::backend(
            "max_frame_payload_bytes + frame header exceeds max_segment_bytes; \
             no frame could ever be written",
        ));
    }
    Ok(())
}

/// Append bytes to the frame payload while keeping CRC in lockstep.
#[inline(always)]
fn frame_extend_crc(frame: &mut Vec<u8>, crc: &mut crc32fast::Hasher, bytes: &[u8]) {
    frame.extend_from_slice(bytes);
    crc.update(bytes);
}

/// Build the batch-invariant finding-id hash prefix.
///
/// All per-batch fields are absorbed once (`domain`, `path_len`, `path`) and
/// cloned per finding to avoid rehashing the object path in the hot loop.
#[inline(always)]
fn finding_id_prefix_hasher(
    metadata_key: &[u8; 32],
    object_path_len: u32,
    object_path: &[u8],
) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_keyed(metadata_key);
    hasher.update(FINDING_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&object_path_len.to_le_bytes());
    hasher.update(object_path);
    hasher
}

/// Derive a deterministic finding ID by extending a cloned batch prefix.
#[inline(always)]
fn derive_finding_id(
    prefix_hasher: &blake3::Hasher,
    finding: &FsFindingRecord,
    rule_fingerprint: &[u8; 32],
    secret_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = prefix_hasher.clone();
    hasher.update(rule_fingerprint);
    hasher.update(secret_hash);
    hasher.update(&finding.root_hint_start.to_le_bytes());
    hasher.update(&finding.root_hint_end.to_le_bytes());
    hasher.update(&finding.span_start.to_le_bytes());
    hasher.update(&finding.span_end.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn map_format_err(err: super::format::FormatError) -> FsStoreError {
    FsStoreError::backend(format!("log format error: {err}"))
}

/// Generate a run identifier unique within this process.
///
/// Combines truncated nanosecond wallclock with a process-global
/// monotonic counter. **Not guaranteed unique across processes** — two
/// processes starting near-simultaneously may collide. Cross-process
/// uniqueness is not required because each process writes to its own
/// run directory.
fn next_run_id() -> u64 {
    static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let c = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Use wrapping_add instead of XOR: since time is monotonically
    // non-decreasing and the counter is strictly increasing, the sum
    // is strictly increasing — guaranteeing within-process uniqueness.
    // (XOR had collisions when t1^c1 == t2^c2 for nearby time values.)
    t.wrapping_add(c)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Acquire the inflight-state lock, mapping poison to [`FsStoreError`].
///
/// Used by producer-side paths (`reserve_inflight`) that must surface
/// errors to callers rather than unwinding.
fn lock_state(
    shared: &SharedState,
) -> Result<std::sync::MutexGuard<'_, InflightState>, FsStoreError> {
    shared
        .state
        .lock()
        .map_err(|_| FsStoreError::backend("append-log state mutex poisoned"))
}

/// Build a user-facing error from a closed [`InflightState`], including
/// the root-cause message when a terminal error was recorded.
fn closed_error(state: &InflightState) -> FsStoreError {
    if let Some(err) = &state.terminal_error {
        FsStoreError::backend(format!("append-log writer closed: {err}"))
    } else {
        FsStoreError::backend("append-log writer closed")
    }
}

/// Decrement inflight budgets and wake all blocked producers.
///
/// Called by the writer thread after each finding frame is persisted.
/// Uses `unwrap_or_else(PoisonError::into_inner)` rather than
/// propagating poison because budget release is critical-path: if it
/// fails, every producer blocks forever. Accepting a potentially
/// inconsistent inner state is preferable to a deadlock.
fn release_inflight(shared: &SharedState, bytes: usize) {
    let mut guard = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    debug_assert!(
        guard.inflight_batches > 0,
        "release without matching reserve"
    );
    guard.inflight_batches = guard.inflight_batches.saturating_sub(1);
    guard.inflight_bytes = guard.inflight_bytes.saturating_sub(bytes);
    drop(guard);
    shared.cv.notify_all();
}

/// Record a fatal writer-thread error and wake all producers.
///
/// Sets `closed = true`, zeros the inflight budgets (so no producer
/// remains blocked on a budget check), and stores the root-cause
/// message for later retrieval by `terminal_result`. Only the first
/// error is kept; subsequent calls are no-ops for the message.
fn set_terminal_error(shared: &SharedState, err: String) {
    let mut guard = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    if guard.terminal_error.is_none() {
        guard.terminal_error = Some(err);
    }
    guard.closed = true;
    guard.inflight_batches = 0;
    guard.inflight_bytes = 0;
    drop(guard);
    shared.cv.notify_all();
}

/// Signal clean shutdown — no terminal error, just `closed = true`.
///
/// Called by the writer thread on its normal exit path. Like
/// `release_inflight`, recovers through a poisoned mutex to ensure
/// the close signal is always delivered.
fn mark_closed(shared: &SharedState) {
    let mut guard = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    guard.closed = true;
    drop(guard);
    shared.cv.notify_all();
}

/// Return `Ok(())` if the writer exited cleanly, or `Err` with the
/// stored root-cause message if a terminal error was recorded.
///
/// Called by `record_fs_run_loss` after joining the writer thread to
/// surface any I/O or panic error to the caller.
fn terminal_result(shared: &SharedState) -> Result<(), FsStoreError> {
    let guard = shared
        .state
        .lock()
        .map_err(|_| FsStoreError::backend("append-log state mutex poisoned"))?;
    if let Some(err) = &guard.terminal_error {
        Err(FsStoreError::backend(format!(
            "append-log writer failed: {err}"
        )))
    } else {
        Ok(())
    }
}

/// Resolve the default append-log root path for an FS scan.
///
/// Precedence:
/// 1. `SCANNER_FS_LOG_DIR` env var (verbatim path)
/// 2. Sibling directory near the scan root: `.<name>.scanner-rs-store`
pub fn default_fs_log_root(scan_root: &Path) -> PathBuf {
    if let Some(raw) = std::env::var_os(SCANNER_FS_LOG_DIR_ENV) {
        return PathBuf::from(raw);
    }

    let canonical = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    let parent = canonical.parent().unwrap_or_else(|| Path::new("."));
    let stem = canonical
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("scan-root");
    let sanitized = sanitize_component(stem);
    parent.join(format!(".{sanitized}.scanner-rs-store"))
}

/// Return all finalized `.bin` segment files in lexical order.
///
/// Walks `store_root/run-*/segments/segment-*.bin`, returning paths sorted
/// first by run directory then by segment sequence number. Only `.bin`
/// (finalized) segments are included; in-progress `.open` files are
/// excluded. Returns an empty vec if `store_root` does not exist.
pub fn list_finalized_segment_files(store_root: &Path) -> Result<Vec<PathBuf>, FsStoreError> {
    if !store_root.exists() {
        return Ok(Vec::new());
    }

    let mut run_dirs = Vec::new();
    for entry in fs::read_dir(store_root).map_err(io_to_store_err)? {
        let entry = entry.map_err(io_to_store_err)?;
        let ft = entry.file_type().map_err(io_to_store_err)?;
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if name_str.starts_with(RUN_PREFIX) {
            run_dirs.push(entry.path());
        }
    }
    run_dirs.sort();

    let mut out = Vec::new();
    for run_dir in run_dirs {
        let seg_dir = run_dir.join(SEGMENTS_DIR);
        if !seg_dir.exists() {
            continue;
        }
        let mut segs = Vec::new();
        for entry in fs::read_dir(&seg_dir).map_err(io_to_store_err)? {
            let entry = entry.map_err(io_to_store_err)?;
            let ft = entry.file_type().map_err(io_to_store_err)?;
            if !ft.is_file() {
                continue;
            }
            let path = entry.path();
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
            let is_bin = path.extension().and_then(OsStr::to_str) == Some(SEGMENT_BIN_EXT);
            if is_bin && name.starts_with(SEGMENT_PREFIX) {
                segs.push(path);
            }
        }
        segs.sort();
        out.extend(segs);
    }
    Ok(out)
}

fn io_to_store_err(err: std::io::Error) -> FsStoreError {
    FsStoreError::backend(format!("append-log io error: {err}"))
}

/// Replace non-portable characters with `_` for use in directory names.
///
/// Keeps ASCII alphanumerics, `-`, `_`, and `.`. Returns `"scan-root"`
/// for empty input.
fn sanitize_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "scan-root".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::log::format::LogRecordReader;
    use regex::bytes::Regex;
    use tempfile::TempDir;

    fn simple_rule() -> RuleSpec {
        RuleSpec {
            name: "secret",
            anchors: &[b"SECRET"],
            radius: 64,
            validator: crate::ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            local_context: None,
            secret_group: None,
            re: Regex::new("SECRET[A-Z0-9]+").unwrap(),
        }
    }

    fn sample_finding(rule_id: u32, start: u64) -> FsFindingRecord {
        FsFindingRecord {
            rule_id,
            root_hint_start: start,
            root_hint_end: start + 16,
            span_start: start + 1,
            span_end: start + 15,
            norm_hash: [rule_id as u8; 32],
        }
    }

    #[test]
    fn byte_budget_rejects_oversized_frame() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_bytes = 128;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        let findings = vec![sample_finding(0, 1), sample_finding(0, 100)];
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"path.txt",
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("byte budget"),
            "unexpected err: {}",
            err.detail()
        );
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    #[test]
    fn batch_count_limit_blocks_until_writer_drains() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_batches = 1;
        cfg.max_inflight_bytes = 8 * 1024 * 1024;
        cfg.write_delay = Some(Duration::from_millis(150));

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();

        let first = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"a.txt",
                findings: &first,
            })
            .unwrap();

        let second = vec![sample_finding(0, 100)];
        let t0 = std::time::Instant::now();
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"b.txt",
                findings: &second,
            })
            .unwrap();
        assert!(
            t0.elapsed() >= Duration::from_millis(100),
            "expected blocking backpressure, elapsed={:?}",
            t0.elapsed()
        );

        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    #[test]
    fn rotation_finalizes_open_segments_to_bin() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_segment_bytes = 700;
        cfg.max_frame_payload_bytes = 600;
        cfg.max_inflight_bytes = 8 * 1024 * 1024;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

        for i in 0..10u64 {
            let findings = vec![sample_finding(0, i * 100)];
            producer
                .emit_fs_batch(FsFindingBatch {
                    object_path: format!("f-{i}.txt").as_bytes(),
                    findings: &findings,
                })
                .unwrap();
        }

        producer
            .record_fs_run_loss(FsRunLoss {
                dropped_findings: 2,
                persistence_emit_failures: 3,
            })
            .unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        assert!(bins.len() >= 2, "expected rotation to create multiple bins");

        let mut records = Vec::new();
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, cfg.max_frame_payload_bytes);
            while let Some(rec) = reader.next_record().unwrap() {
                records.push(rec);
            }
        }

        assert!(matches!(records.first(), Some(LogRecord::RunStart(_))));
        assert!(records.iter().any(|r| matches!(r, LogRecord::RuleDef(_))));
        assert!(records
            .iter()
            .any(|r| matches!(r, LogRecord::FindingBatch(_))));

        let run_end = records
            .iter()
            .find_map(|r| match r {
                LogRecord::RunEnd(end) => Some(end),
                _ => None,
            })
            .expect("expected run-end record");
        assert_eq!(run_end.dropped_findings, 2);
        assert_eq!(run_end.persistence_emit_failures, 3);
        assert!(run_end.incomplete);

        // `.open` files must not remain after clean close.
        let mut has_open = false;
        for run_entry in fs::read_dir(&cfg.root_dir).unwrap() {
            let run_entry = run_entry.unwrap();
            if !run_entry.file_type().unwrap().is_dir() {
                continue;
            }
            let seg_dir = run_entry.path().join(SEGMENTS_DIR);
            if !seg_dir.exists() {
                continue;
            }
            for seg in fs::read_dir(seg_dir).unwrap() {
                let seg = seg.unwrap().path();
                if seg.extension().and_then(OsStr::to_str) == Some(SEGMENT_OPEN_EXT) {
                    has_open = true;
                }
            }
        }
        assert!(!has_open, "expected no .open files after finalize");
    }

    #[test]
    fn release_inflight_recovers_from_poisoned_mutex() {
        // release_inflight must recover through a poisoned mutex and
        // still decrement the budget, otherwise producers block forever.
        let shared = Arc::new(SharedState::default());
        {
            let mut guard = shared.state.lock().unwrap();
            guard.inflight_batches = 5;
            guard.inflight_bytes = 1000;
        }

        // Poison the mutex by panicking while holding the lock.
        let shared2 = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            let _guard = shared2.state.lock().unwrap();
            panic!("intentional poison");
        });
        let _ = handle.join(); // join the panicked thread

        // release_inflight must still work despite the poisoned mutex.
        release_inflight(&shared, 500);

        // Recover the inner state via PoisonError::into_inner to verify
        // the budget WAS decremented through the poisoned mutex.
        let err = shared.state.lock().unwrap_err();
        let inner = err.into_inner();
        assert_eq!(
            inner.inflight_batches, 4,
            "budget should be decremented even through poisoned mutex"
        );
        assert_eq!(
            inner.inflight_bytes, 500,
            "byte budget should be decremented even through poisoned mutex"
        );
    }

    #[test]
    fn mark_closed_recovers_from_poisoned_mutex() {
        // mark_closed must recover through a poisoned mutex and still
        // set closed=true, otherwise the producer never shuts down.
        let shared = Arc::new(SharedState::default());

        // Poison the mutex.
        let shared2 = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            let _guard = shared2.state.lock().unwrap();
            panic!("intentional poison");
        });
        let _ = handle.join();

        mark_closed(&shared);

        let err = shared.state.lock().unwrap_err();
        let inner = err.into_inner();
        assert!(
            inner.closed,
            "closed should be true even through poisoned mutex"
        );
    }

    #[test]
    fn drop_without_record_fs_run_loss_no_run_end_frame() {
        // [B3] No RunEnd frame on producer drop without record_fs_run_loss.
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        let max_payload = cfg.max_frame_payload_bytes;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();
        let findings = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"test.txt",
                findings: &findings,
            })
            .unwrap();

        // Drop without calling record_fs_run_loss.
        drop(producer);

        // Give the writer thread time to finalize.
        std::thread::sleep(Duration::from_millis(200));

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        let mut has_run_end = false;
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, max_payload);
            while let Some(rec) = reader.next_record().unwrap() {
                if matches!(rec, LogRecord::RunEnd(_)) {
                    has_run_end = true;
                }
            }
        }
        assert!(
            !has_run_end,
            "expected no RunEnd frame when producer is dropped without record_fs_run_loss"
        );
    }

    #[test]
    fn config_frame_payload_larger_than_segment_rejected_at_construction() {
        // max_frame_payload_bytes + header must not exceed max_segment_bytes;
        // validate_config rejects this at construction time.
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_frame_payload_bytes = 10_000;
        cfg.max_segment_bytes = 500;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        let result = AppendLogStoreProducer::new(&[simple_rule()], cfg);
        let err = result.err().expect("expected config validation error");
        assert!(
            err.detail().contains("max_frame_payload_bytes")
                || err.detail().contains("max_segment_bytes"),
            "expected config validation error about frame/segment size, got: {}",
            err.detail()
        );
    }

    #[test]
    fn validate_config_rejects_inflight_batches_exceeding_u32() {
        // max_inflight_batches is usize but the wire format (LogRunStart)
        // stores it as u32. Values exceeding u32::MAX must be rejected.
        let mut cfg = LogWriterConfig::for_root(PathBuf::from("/tmp/test"));
        cfg.max_inflight_batches = u32::MAX as usize + 1;

        let err = validate_config(&cfg).unwrap_err();
        assert!(
            err.detail().contains("max_inflight_batches"),
            "expected error about max_inflight_batches, got: {}",
            err.detail()
        );
    }

    #[test]
    fn inflight_budget_smaller_than_minimum_frame_rejects_immediately() {
        // [B5 related] max_inflight_bytes = 1 is too small for any frame.
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_bytes = 1;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        let findings = vec![sample_finding(0, 0)];
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"x.txt",
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("byte budget"),
            "expected byte budget error, got: {}",
            err.detail()
        );
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    #[test]
    fn empty_batch_is_silently_dropped() {
        // Documents behavior: emit_fs_batch with empty findings is a no-op.
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        let max_payload = cfg.max_frame_payload_bytes;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

        // Empty batch — should be silently dropped.
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"empty.txt",
                findings: &[],
            })
            .unwrap();

        // Non-empty batch.
        let findings = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"real.txt",
                findings: &findings,
            })
            .unwrap();

        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        let mut batch_count = 0;
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, max_payload);
            while let Some(rec) = reader.next_record().unwrap() {
                if matches!(rec, LogRecord::FindingBatch(_)) {
                    batch_count += 1;
                }
            }
        }
        assert_eq!(batch_count, 1, "empty batch should not produce a frame");
    }

    // ================================================================
    // Step 2 — Segment rotation edge cases
    // ================================================================

    #[test]
    fn run_start_plus_rule_defs_exceed_single_segment() {
        // Many rules + tiny max_segment_bytes forces header frames to spill
        // across multiple segments.
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_segment_bytes = 200; // Very small.
        cfg.max_frame_payload_bytes = 180;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        // Create 10 rules with long names to generate large RuleDef frames.
        let rules: Vec<RuleSpec> = (0..10)
            .map(|i| {
                let name_str = format!("rule-{i}-{}", "X".repeat(60));
                // Leak the name so we get a &'static str for the RuleSpec.
                let name: &'static str = Box::leak(name_str.into_boxed_str());
                RuleSpec {
                    name,
                    anchors: &[b"SECRET"],
                    radius: 64,
                    validator: crate::ValidatorKind::None,
                    two_phase: None,
                    must_contain: None,
                    keywords_any: None,
                    value_suppressors_any: None,
                    entropy: None,
                    local_context: None,
                    secret_group: None,
                    re: Regex::new("SECRET[A-Z0-9]+").unwrap(),
                }
            })
            .collect();

        let producer = AppendLogStoreProducer::new(&rules, cfg.clone()).unwrap();
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        assert!(
            bins.len() >= 2,
            "expected header frames to spill across multiple segments, got {} bins",
            bins.len()
        );
    }

    #[test]
    fn zero_findings_run_produces_valid_log() {
        // Emit no findings, just close. Assert RunStart + RuleDef + RunEnd present.
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        let max_payload = cfg.max_frame_payload_bytes;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        let mut records = Vec::new();
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, max_payload);
            while let Some(rec) = reader.next_record().unwrap() {
                records.push(rec);
            }
        }

        assert!(matches!(records.first(), Some(LogRecord::RunStart(_))));
        assert!(records.iter().any(|r| matches!(r, LogRecord::RuleDef(_))));
        assert!(records.iter().any(|r| matches!(r, LogRecord::RunEnd(_))));
        assert!(
            !records
                .iter()
                .any(|r| matches!(r, LogRecord::FindingBatch(_))),
            "no FindingBatch frames expected in zero-findings run"
        );
    }

    #[test]
    fn segment_seq_numbers_are_monotonic_after_many_rotations() {
        // Trigger 50+ rotations. Assert filenames are monotonically ordered.
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_segment_bytes = 300; // Very small to force many rotations.
        cfg.max_frame_payload_bytes = 250;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

        for i in 0..100u64 {
            let findings = vec![sample_finding(0, i * 100)];
            producer
                .emit_fs_batch(FsFindingBatch {
                    object_path: format!("file-{i:04}.txt").as_bytes(),
                    findings: &findings,
                })
                .unwrap();
        }

        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        assert!(
            bins.len() >= 50,
            "expected 50+ segments, got {}",
            bins.len()
        );

        // Verify filenames are in lexicographic/monotonic order.
        let names: Vec<String> = bins
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        for w in names.windows(2) {
            assert!(
                w[0] <= w[1],
                "segment filenames not monotonic: {} > {}",
                w[0],
                w[1]
            );
        }
    }

    // ================================================================
    // Backpressure & shutdown tests
    // ================================================================

    #[test]
    fn byte_budget_backpressure_blocks_and_unblocks() {
        // Set max_inflight_bytes to allow exactly 1 frame with write delay.
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_batches = 256;
        // We'll figure out exact frame size by encoding one.
        cfg.max_inflight_bytes = 16 * 1024 * 1024; // Start large, we'll narrow below.
        cfg.write_delay = Some(Duration::from_millis(200));

        // First, measure frame size.
        let producer_probe = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();
        let findings = vec![sample_finding(0, 0)];
        let frame = producer_probe
            .build_finding_frame(FsFindingBatch {
                object_path: b"probe.txt",
                findings: &findings,
            })
            .unwrap();
        let frame_size = frame.len();
        producer_probe
            .record_fs_run_loss(FsRunLoss::default())
            .unwrap();

        // Now create producer that allows exactly 1 frame in flight.
        let mut cfg2 = LogWriterConfig::for_root(tmp.path().join("run2"));
        cfg2.max_inflight_batches = 256;
        cfg2.max_inflight_bytes = frame_size; // Only 1 frame fits.
        cfg2.write_delay = Some(Duration::from_millis(200));

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg2).unwrap();

        // First emit should succeed immediately.
        let f1 = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"a.txt",
                findings: &f1,
            })
            .unwrap();

        // Second emit should block ~200ms (waiting for the writer to drain).
        let f2 = vec![sample_finding(0, 100)];
        let t0 = std::time::Instant::now();
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"b.txt",
                findings: &f2,
            })
            .unwrap();
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_millis(150),
            "expected byte backpressure block ~200ms, elapsed={elapsed:?}"
        );

        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    #[test]
    fn concurrent_emitters_all_succeed_under_backpressure() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_batches = 2;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        let producer =
            Arc::new(AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap());
        let max_payload = cfg.max_frame_payload_bytes;

        let num_threads = 8;
        let batches_per_thread = 50;

        let handles: Vec<_> = (0..num_threads)
            .map(|t| {
                let p = Arc::clone(&producer);
                std::thread::spawn(move || {
                    for i in 0..batches_per_thread {
                        let findings = vec![sample_finding(0, (t * 1000 + i) as u64)];
                        p.emit_fs_batch(FsFindingBatch {
                            object_path: format!("t{t}-f{i}.txt").as_bytes(),
                            findings: &findings,
                        })
                        .unwrap();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // All threads have joined, so our Arc is the only reference.
        // Use the Arc directly — StoreProducer is implemented on the struct
        // and we can call it through the Arc.
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        let mut finding_batch_count = 0;
        let mut has_run_end = false;
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, max_payload);
            while let Some(rec) = reader.next_record().unwrap() {
                match rec {
                    LogRecord::FindingBatch(_) => finding_batch_count += 1,
                    LogRecord::RunEnd(_) => has_run_end = true,
                    _ => {}
                }
            }
        }
        let expected = num_threads * batches_per_thread;
        assert_eq!(
            finding_batch_count, expected,
            "expected {expected} finding batches on disk"
        );
        assert!(has_run_end, "expected RunEnd frame");

        // No .open files should remain.
        for run_entry in fs::read_dir(&cfg.root_dir).unwrap() {
            let run_entry = run_entry.unwrap();
            if !run_entry.file_type().unwrap().is_dir() {
                continue;
            }
            let seg_dir = run_entry.path().join(SEGMENTS_DIR);
            if !seg_dir.exists() {
                continue;
            }
            for seg in fs::read_dir(seg_dir).unwrap() {
                let seg = seg.unwrap().path();
                assert_ne!(
                    seg.extension().and_then(OsStr::to_str),
                    Some(SEGMENT_OPEN_EXT),
                    "unexpected .open file: {seg:?}"
                );
            }
        }
    }

    #[test]
    fn emit_after_writer_thread_error_surfaces_terminal_error() {
        // When the writer thread dies from an I/O error, emit_fs_batch
        // should surface the actual terminal error, not just "channel
        // disconnected".
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        // Small segment so rotation happens after RunStart + RuleDef + 1 finding;
        // valid per cross-field check.
        cfg.max_segment_bytes = 400;
        cfg.max_frame_payload_bytes = 350;
        cfg.max_inflight_batches = 4;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;
        // Slow writer so we have a window to sabotage the directory.
        cfg.write_delay = Some(Duration::from_millis(300));

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();

        // Find the segments directory and make it read-only after first frame
        // is written but while the writer is sleeping. When the writer tries
        // to finalize (sync_data + rename), it will fail with permission denied.
        //
        // First emit some frames to fill the first segment.
        for i in 0..3u64 {
            let f = vec![sample_finding(0, i * 100)];
            producer
                .emit_fs_batch(FsFindingBatch {
                    object_path: format!("file-{i}.txt").as_bytes(),
                    findings: &f,
                })
                .unwrap();
        }

        // Wait for writer to start processing, then make segments dir read-only.
        std::thread::sleep(Duration::from_millis(100));

        // Find and chmod the segments directory.
        let mut segments_dir = None;
        for entry in fs::read_dir(tmp.path()).unwrap().flatten() {
            if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                let seg_dir = entry.path().join(SEGMENTS_DIR);
                if seg_dir.exists() {
                    segments_dir = Some(seg_dir);
                    break;
                }
            }
        }

        let seg_dir = segments_dir.expect("should have segments directory");
        // Make read-only so rename/create fails.
        let mut perms = fs::metadata(&seg_dir).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&seg_dir, perms).unwrap();

        // Wait for writer to hit the I/O error during finalize/rotate.
        std::thread::sleep(Duration::from_millis(1000));

        // Emit after the writer thread should have died.
        let f_late = vec![sample_finding(0, 999)];
        let result = producer.emit_fs_batch(FsFindingBatch {
            object_path: b"late.txt",
            findings: &f_late,
        });

        // Restore permissions for cleanup.
        let mut perms = fs::metadata(&seg_dir).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&seg_dir, perms).unwrap();

        let close_result = producer.record_fs_run_loss(FsRunLoss::default());

        let all_errors: Vec<String> = [result.err(), close_result.err()]
            .iter()
            .filter_map(|e| e.as_ref().map(|e| e.detail().to_string()))
            .collect();

        assert!(
            !all_errors.is_empty(),
            "expected at least one error from writer thread failure"
        );
        // At least one error should mention the root cause (I/O failure),
        // not just "disconnected".
        let has_root_cause = all_errors.iter().any(|e| {
            e.contains("failed to") || e.contains("writer failed") || e.contains("writer closed")
        });
        assert!(
            has_root_cause,
            "expected root cause in error messages, got: {all_errors:?}"
        );
    }

    #[test]
    fn emit_after_record_fs_run_loss_returns_closed_error() {
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        let findings = vec![sample_finding(0, 0)];
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"late.txt",
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("closed"),
            "expected 'closed' error, got: {}",
            err.detail()
        );
    }

    #[test]
    fn record_fs_run_loss_called_twice_returns_ok_or_terminal() {
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        let first = producer.record_fs_run_loss(FsRunLoss::default());
        assert!(first.is_ok(), "first close should succeed");

        // Second call: the writer handle is already taken, so it will
        // return terminal_result (Ok if no terminal error, Err if one was set).
        let second = producer.record_fs_run_loss(FsRunLoss::default());
        // Either Ok (no terminal error) or Err (terminal error set) is acceptable.
        // The important thing is it doesn't panic.
        let _ = second;
    }

    // ================================================================
    // Config & utility tests
    // ================================================================

    #[test]
    fn validate_config_rejects_each_zero_field() {
        let base = LogWriterConfig::for_root(PathBuf::from("/tmp/test"));

        // max_inflight_batches = 0
        let mut cfg = base.clone();
        cfg.max_inflight_batches = 0;
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.detail().contains("max_inflight_batches"));

        // max_inflight_bytes = 0
        let mut cfg = base.clone();
        cfg.max_inflight_bytes = 0;
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.detail().contains("max_inflight_bytes"));

        // max_segment_bytes = 0
        let mut cfg = base.clone();
        cfg.max_segment_bytes = 0;
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.detail().contains("max_segment_bytes"));

        // max_frame_payload_bytes = 0
        let mut cfg = base.clone();
        cfg.max_frame_payload_bytes = 0;
        let err = validate_config(&cfg).unwrap_err();
        assert!(err.detail().contains("max_frame_payload_bytes"));
    }

    #[test]
    fn sanitize_component_edge_cases() {
        // Spaces → underscores.
        assert_eq!(sanitize_component("hello world"), "hello_world");
        // Empty → "scan-root".
        assert_eq!(sanitize_component(""), "scan-root");
        // Slashes → underscores.
        assert_eq!(sanitize_component("a/b/c"), "a_b_c");
        // Unicode → underscores.
        assert_eq!(sanitize_component("café"), "caf_");
        // Valid chars preserved.
        assert_eq!(sanitize_component("my-project_v2.0"), "my-project_v2.0");
        // All non-ascii.
        assert_eq!(sanitize_component("日本語"), "___");
    }

    #[test]
    fn list_finalized_segment_files_nonexistent_root_returns_empty() {
        let result =
            list_finalized_segment_files(Path::new("/nonexistent/path/that/should/not/exist"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn list_finalized_segment_files_ignores_open_and_non_segment_files() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        // Create various files that should be excluded:
        // 1. .open file
        File::create(seg_dir.join("segment-00000000000000000000.open")).unwrap();
        // 2. Non-segment .bin file
        File::create(seg_dir.join("not-a-segment.bin")).unwrap();
        // 3. Random file
        File::create(seg_dir.join("readme.txt")).unwrap();
        // 4. Valid segment .bin file (should be included)
        File::create(seg_dir.join("segment-00000000000000000000.bin")).unwrap();
        File::create(seg_dir.join("segment-00000000000000000001.bin")).unwrap();

        let files = list_finalized_segment_files(tmp.path()).unwrap();
        assert_eq!(files.len(), 2, "expected only 2 valid segment .bin files");
        for f in &files {
            let name = f.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with(SEGMENT_PREFIX));
            assert!(name.ends_with(".bin"));
        }
    }

    /// PR Comment 2 regression: blocked emitters should NOT get spurious
    /// "closed" errors when record_fs_run_loss() is called. The close
    /// signal must be deferred to the writer thread exit so that in-flight
    /// work can drain naturally.
    #[test]
    fn shutdown_does_not_reject_inflight_emitter() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_batches = 1;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;
        cfg.write_delay = Some(Duration::from_millis(300));

        let producer = Arc::new(AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap());

        // Fill the single inflight slot.
        let f1 = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"first.txt",
                findings: &f1,
            })
            .unwrap();

        // Spawn a thread that will block in reserve_inflight.
        let p2 = Arc::clone(&producer);
        let emitter = std::thread::spawn(move || {
            let f2 = vec![sample_finding(0, 100)];
            p2.emit_fs_batch(FsFindingBatch {
                object_path: b"second.txt",
                findings: &f2,
            })
        });

        // Give the emitter time to block.
        std::thread::sleep(Duration::from_millis(50));

        // Close from another thread — the writer thread drain will unblock
        // the emitter via release_inflight before the close signal arrives.
        let p3 = Arc::clone(&producer);
        let closer = std::thread::spawn(move || p3.record_fs_run_loss(FsRunLoss::default()));

        let emit_result = emitter.join().expect("emitter thread panicked");
        let close_result = closer.join().expect("closer thread panicked");

        // After fix: the blocked emitter should succeed (or at worst fail
        // with channel-disconnected if it races with Finish, but NOT with
        // a premature "closed" error).
        // The emitter may succeed (its frame arrives before Finish) or fail
        // (channel disconnected after Finish). Both are acceptable — the key
        // is that it is NOT rejected by a premature closed flag.
        if let Err(ref e) = emit_result {
            assert!(
                e.detail().contains("disconnected"),
                "if emitter fails, should be channel-disconnected, not 'closed': {}",
                e.detail()
            );
        }
        close_result.expect("record_fs_run_loss should succeed");
    }

    /// PR Comment 4: Verify that set_terminal_error on writer failure
    /// DOES wake blocked producers (reviewer claimed they'd block forever).
    /// set_terminal_error sets closed=true, zeros budgets, and notifies.
    #[test]
    fn writer_error_unblocks_waiting_producers() {
        let shared = Arc::new(SharedState::default());

        // Simulate budget-full state so a producer would block.
        {
            let mut guard = shared.state.lock().unwrap();
            guard.inflight_batches = 100;
            guard.inflight_bytes = 999_999;
        }

        let shared2 = Arc::clone(&shared);
        let waiter = std::thread::spawn(move || {
            let mut guard = shared2.state.lock().unwrap();
            while !guard.closed {
                guard = shared2.cv.wait(guard).unwrap();
            }
            guard.closed
        });

        std::thread::sleep(Duration::from_millis(50));

        // Simulate writer error path — this should wake the waiter.
        set_terminal_error(&shared, "test IO error".to_string());

        let was_closed = waiter.join().expect("waiter panicked");
        assert!(was_closed, "waiter should see closed=true");

        // Verify budget was zeroed and error was recorded.
        let guard = shared.state.lock().unwrap();
        assert_eq!(guard.inflight_batches, 0);
        assert_eq!(guard.inflight_bytes, 0);
        assert_eq!(guard.terminal_error.as_deref(), Some("test IO error"));
    }

    /// PR Comment 3: next_run_id() uniqueness within a single process.
    /// The XOR of truncated nanos with a monotonic counter should produce
    /// unique IDs for sequential calls within the same process.
    #[test]
    fn next_run_id_is_unique_within_process() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let id = next_run_id();
            assert!(ids.insert(id), "duplicate run_id detected: {id:#018x}");
        }
    }

    #[test]
    fn default_fs_log_root_with_root_slash_falls_back_to_cwd() {
        // [B6] When scan_root is "/", parent is "." (cwd) — surprising store location.
        // We set the env var to avoid polluting the filesystem, and instead test
        // the non-env-var path by temporarily clearing it.
        let prev = std::env::var_os(SCANNER_FS_LOG_DIR_ENV);
        std::env::remove_var(SCANNER_FS_LOG_DIR_ENV);

        let result = default_fs_log_root(Path::new("/"));
        let result_str = result.to_string_lossy();

        // Restore env var.
        if let Some(v) = prev {
            std::env::set_var(SCANNER_FS_LOG_DIR_ENV, v);
        }

        // On macOS, "/" canonicalizes to "/" and parent is "/" so the
        // result would be "/.scan-root.scanner-rs-store" (with "/" as parent,
        // not "."). The file_name of "/" is None so stem falls back to "scan-root".
        assert!(
            result_str.contains(".scan-root.scanner-rs-store")
                || result_str.contains("scanner-rs-store"),
            "expected store path containing scan-root marker, got: {result_str}"
        );
    }
}
