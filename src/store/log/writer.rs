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
    encode_record, LogDurabilityMode, LogFindingBatch, LogFindingRecord, LogRecord, LogRuleDef,
    LogRunEnd, LogRunStart, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, LOG_FORMAT_VERSION,
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

    fn build_finding_frame(&self, batch: FsFindingBatch<'_>) -> Result<Vec<u8>, FsStoreError> {
        if batch.object_path.len() > u32::MAX as usize {
            return Err(FsStoreError::backend(format!(
                "object_path too large: {} bytes",
                batch.object_path.len()
            )));
        }

        let mut findings = Vec::with_capacity(batch.findings.len());
        for finding in batch.findings {
            let rule_idx = finding.rule_id as usize;
            let Some(rule_fp) = self.inner.rule_fingerprints_by_id.get(rule_idx) else {
                return Err(FsStoreError::backend(format!(
                    "unknown rule_id {} for log finding encode",
                    finding.rule_id
                )));
            };
            let secret = secret_hash(&finding.norm_hash, &self.inner.keys);
            let finding_id = derive_finding_id(
                self.inner.keys.metadata_key(),
                batch.object_path,
                finding,
                rule_fp,
                &secret,
            )?;
            findings.push(LogFindingRecord {
                rule_id: finding.rule_id,
                rule_fingerprint: *rule_fp,
                secret_hash: secret,
                finding_id,
                root_hint_start: finding.root_hint_start,
                root_hint_end: finding.root_hint_end,
                span_start: finding.span_start,
                span_end: finding.span_end,
            });
        }

        let record = LogRecord::FindingBatch(LogFindingBatch {
            object_path: batch.object_path.to_vec(),
            findings,
        });
        let mut frame = Vec::with_capacity(512);
        encode_record(&record, self.inner.cfg.max_frame_payload_bytes, &mut frame)
            .map_err(map_format_err)?;
        Ok(frame)
    }

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
            return Err(FsStoreError::backend(
                "append-log writer channel disconnected",
            ));
        }
        Ok(())
    }

    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        let frame = self.build_run_end_frame(loss)?;
        mark_closed(&self.inner.shared);

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

struct Inner {
    tx: Sender<WriterCommand>,
    cfg: LogWriterConfig,
    run_id: u64,
    keys: StoreKeys,
    shared: Arc<SharedState>,
    writer_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    rule_fingerprints_by_id: Box<[[u8; 32]]>,
}

#[derive(Default)]
struct SharedState {
    state: Mutex<InflightState>,
    cv: Condvar,
}

#[derive(Default)]
struct InflightState {
    inflight_batches: usize,
    inflight_bytes: usize,
    closed: bool,
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
            self.seq = self.seq.saturating_add(1);
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

fn open_segment_file(segments_dir: &Path, seq: u64) -> std::io::Result<(File, PathBuf)> {
    let name = format!("{SEGMENT_PREFIX}{seq:020}.{SEGMENT_OPEN_EXT}");
    let path = segments_dir.join(name);
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    Ok((file, path))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

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
    Ok(())
}

/// Derive a deterministic 32-byte finding identifier via BLAKE3-keyed hash.
///
/// The hash input is domain-separated (`FINDING_ID_DOMAIN` + NUL byte) and
/// includes the full set of finding coordinates: object path, rule
/// fingerprint, secret hash, and byte-offset ranges. This ensures the ID
/// is stable across runs when the same secret key is used, enabling
/// cross-run correlation and deduplication.
fn derive_finding_id(
    metadata_key: &[u8; 32],
    object_path: &[u8],
    finding: &FsFindingRecord,
    rule_fingerprint: &[u8; 32],
    secret_hash: &[u8; 32],
) -> Result<[u8; 32], FsStoreError> {
    let path_len = u32::try_from(object_path.len())
        .map_err(|_| FsStoreError::backend("object_path length exceeds u32"))?;
    let mut hasher = blake3::Hasher::new_keyed(metadata_key);
    hasher.update(FINDING_ID_DOMAIN);
    hasher.update(&[0]);
    hasher.update(&path_len.to_le_bytes());
    hasher.update(object_path);
    hasher.update(rule_fingerprint);
    hasher.update(secret_hash);
    hasher.update(&finding.root_hint_start.to_le_bytes());
    hasher.update(&finding.root_hint_end.to_le_bytes());
    hasher.update(&finding.span_start.to_le_bytes());
    hasher.update(&finding.span_end.to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn map_format_err(err: super::format::FormatError) -> FsStoreError {
    FsStoreError::backend(format!("log format error: {err}"))
}

fn next_run_id() -> u64 {
    static RUN_COUNTER: AtomicU64 = AtomicU64::new(1);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let c = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    t ^ c
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn lock_state(
    shared: &SharedState,
) -> Result<std::sync::MutexGuard<'_, InflightState>, FsStoreError> {
    shared
        .state
        .lock()
        .map_err(|_| FsStoreError::backend("append-log state mutex poisoned"))
}

fn closed_error(state: &InflightState) -> FsStoreError {
    if let Some(err) = &state.terminal_error {
        FsStoreError::backend(format!("append-log writer closed: {err}"))
    } else {
        FsStoreError::backend("append-log writer closed")
    }
}

fn release_inflight(shared: &SharedState, bytes: usize) {
    if let Ok(mut guard) = shared.state.lock() {
        guard.inflight_batches = guard.inflight_batches.saturating_sub(1);
        guard.inflight_bytes = guard.inflight_bytes.saturating_sub(bytes);
        shared.cv.notify_all();
    }
}

fn set_terminal_error(shared: &SharedState, err: String) {
    if let Ok(mut guard) = shared.state.lock() {
        if guard.terminal_error.is_none() {
            guard.terminal_error = Some(err);
        }
        guard.closed = true;
        guard.inflight_batches = 0;
        guard.inflight_bytes = 0;
        shared.cv.notify_all();
    }
}

fn mark_closed(shared: &SharedState) {
    if let Ok(mut guard) = shared.state.lock() {
        guard.closed = true;
        shared.cv.notify_all();
    }
}

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
}
