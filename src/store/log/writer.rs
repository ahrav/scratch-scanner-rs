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
//!    ├─ plan + reserve inflight ─►  │ writer_thread_main()  │
//!    ├─ acquire pooled frame        │  ├─ write RunStart    │
//!    ├─ encode finding payload      │  ├─ write RuleDefs    │
//!    └─ send on channel    ──►      │  ├─ recv loop:        │
//!  record_fs_run_loss()             │  │  write FindingFrame │
//!    ├─ build run-end record        │  │  bind seq+segment   │
//!    ├─ send Finish cmd    ──►      │  │  release_inflight() │
//!    └─ join writer thread          │  └─ write RunEnd + finalize
//!                                   └──────────────────────┘
//! ```
//!
//! # Backpressure
//!
//! Producers block in `reserve_inflight` when either of two budgets is
//! exhausted:
//! - **Batch count** — caps the number of in-flight finding frames.
//! - **Byte budget** — caps the total encoded bytes queued in the channel.
//!
//! The writer thread recycles each finding-frame buffer and releases budget
//! after each frame write, waking blocked producers via a [`Condvar`].
//!
//! # Segment lifecycle
//!
//! Files are created as `segment-<20-digit-seq>.open` and renamed to `.bin` on
//! segment close (`sync_data` + rename + `sync_dir`). The writer rotates
//! to a new segment when `bytes_written + frame_len + trailer_bytes >
//! max_segment_bytes`, so every finalized segment can append its integrity
//! trailer (`frame_count`, `total_frame_bytes`, BLAKE3 CRC chain).
//! After a clean shutdown, no `.open` files remain.

use super::format::{
    append_segment_trailer, encode_record_with_position, extend_frame_crc_chain,
    finalize_v2_frame_in_place, frame_crc_from_header, FramePosition, FrameType, LogDurabilityMode,
    LogRecord, LogRuleDef, LogRunEnd, LogRunStart, SegmentTrailer, DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
    FRAME_HEADER_BYTES, FRAME_V2_LEN_FLAG, FRAME_V2_POSITION_BYTES, LOG_FORMAT_VERSION,
    SEGMENT_TRAILER_BYTES,
};
use super::reader::{LogReadErrorReason, LogReader};
use super::secret_cache::SecretHashCache;
use crate::api::RuleSpec;
use crate::store::identity::rule_fingerprint;
use crate::store::keys::StoreKeys;
use crate::store::{FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, StoreProducer};
use crossbeam_channel::{Receiver, Sender};
use crossbeam_queue::ArrayQueue;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RUN_PREFIX: &str = "run-";
const SEGMENTS_DIR: &str = "segments";
const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_OPEN_EXT: &str = "open";
const SEGMENT_BIN_EXT: &str = "bin";
/// Domain separation tag for the keyed BLAKE3 finding-id derivation.
///
/// Prevents collisions with any other keyed hashes derived from
/// `metadata_key`. Changing this string invalidates all previously-emitted
/// finding IDs.
const FINDING_ID_DOMAIN: &[u8] = b"scanner.store.log.v1.finding_id";
const FINDING_BATCH_BASE_PAYLOAD_BYTES: usize = 8; // object_path_len (4) + findings_count (4)

/// Per-finding wire size in a `FindingBatch` frame body.
///
/// ```text
///   rule_id            4 bytes   u32-LE
///   rule_fingerprint  32 bytes   BLAKE3
///   secret_hash       32 bytes   BLAKE3
///   finding_id        32 bytes   BLAKE3
///   root_hint_start    8 bytes   u64-LE
///   root_hint_end      8 bytes   u64-LE
///   span_start         8 bytes   u64-LE
///   span_end           8 bytes   u64-LE
///                    ─────────
///   total            132 bytes
/// ```
const FINDING_RECORD_WIRE_BYTES: usize = 132;
const FINDING_FRAME_POOL_MIN_CAPACITY: usize = 256;
const FINDING_FRAME_POOL_DEFAULT_CAPACITY: usize = 4 * 1024;

/// Environment override for FS append-log root directory.
pub const SCANNER_FS_LOG_DIR_ENV: &str = "SCANNER_FS_LOG_DIR";

/// Runtime configuration for [`AppendLogStoreProducer`].
///
/// All budget and size fields are validated at construction time by
/// [`validate_config`]. The cross-field invariant
/// `max_frame_payload_bytes + V2 frame overhead + trailer <= max_segment_bytes`
/// is enforced so that no single frame can exceed a segment.
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
/// writer thread, and finalizes the last segment.
///
/// If the producer is dropped without calling `record_fs_run_loss`, the
/// `Drop` impl closes the channel and joins the writer thread, ensuring
/// the current segment is finalized (no `RunEnd` frame is written in
/// this case).
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
        let finding_frame_pool = Arc::new(FindingFramePool::new(
            cfg.max_inflight_batches,
            finding_frame_pool_capacity_hint(&cfg),
        ));
        let (tx, rx) = crossbeam_channel::bounded(cfg.max_inflight_batches.max(1));
        let thread_shared = Arc::clone(&shared);
        let thread_pool = Arc::clone(&finding_frame_pool);
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
                    &thread_pool,
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
                tx: Some(tx),
                cfg,
                run_id,
                keys,
                shared,
                writer_handle: Mutex::new(Some(writer_handle)),
                rule_fingerprints_by_id: rule_fingerprints_by_id.into_boxed_slice(),
                finding_frame_pool,
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

    /// Pre-compute finding-frame sizes and validate limits before reserving
    /// inflight budget.
    ///
    /// Returns a [`FindingFramePlan`] containing the wire-level lengths
    /// (`body_len`, `body_len_word`, `frame_len`) and already-cast count
    /// fields so that [`build_finding_frame`](Self::build_finding_frame)
    /// can serialize without redundant checks. Runs entirely on the
    /// producer thread with no locks held.
    fn plan_finding_frame(
        &self,
        batch: FsFindingBatch<'_>,
    ) -> Result<FindingFramePlan, FsStoreError> {
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
            .checked_add(1 + FRAME_V2_POSITION_BYTES)
            .ok_or_else(|| FsStoreError::backend("finding frame body length overflow"))?;
        let body_len_u32 = u32::try_from(body_len)
            .map_err(|_| FsStoreError::backend("finding frame body exceeds u32::MAX"))?;
        let body_len_word = FRAME_V2_LEN_FLAG | body_len_u32;
        let frame_len = FRAME_HEADER_BYTES
            .checked_add(body_len)
            .ok_or_else(|| FsStoreError::backend("finding frame length overflow"))?;

        Ok(FindingFramePlan {
            object_path_len,
            findings_count_u32,
            body_len,
            body_len_word,
            frame_len,
        })
    }

    /// Encode a [`FsFindingBatch`] directly into a pooled frame buffer.
    ///
    /// Unlike `RunStart`/`RuleDef`/`RunEnd` frames (which go through
    /// [`encode_record`]), finding frames are built inline here to avoid an
    /// intermediate `LogFindingBatch` allocation. The resulting buffer is
    /// ready for writer-thread position binding and disk write with no
    /// additional payload re-encoding.
    ///
    /// # Wire layout
    ///
    /// ```text
    /// ┌──────────────┬──────────┬──────────────┬──────────────────────┬───────────────┐
    /// │ frame_len(4) │ crc32(4) │ frame_seq(8) │ segment_id(8)        │ type_byte(1)  │
    /// ├──────────────┴──────────┴──────────────┴──────────────────────┴───────────────┤
    /// │ object_path_len(4) │ object_path │ findings_count(4)                         │
    /// ├──────────────────────────────────────────────────────────────────────────────┤
    /// │ per finding × N:                                                           │
    /// │   rule_id(4) | rule_fp(32) | secret(32) | finding_id(32)                   │
    /// │   | root_hint_start(8) | root_hint_end(8) | span_start(8) | span_end(8)   │
    /// └──────────────────────────────────────────────────────────────────────────────┘
    /// ```
    ///
    /// The writer thread patches `frame_seq`/`segment_id`, then computes CRC-32
    /// over the entire body (`frame_seq .. end`) immediately before disk write.
    fn build_finding_frame(
        &self,
        batch: FsFindingBatch<'_>,
        plan: FindingFramePlan,
        frame: &mut Vec<u8>,
    ) -> Result<(), FsStoreError> {
        frame.clear();
        if frame.capacity() < plan.frame_len {
            frame.reserve(plan.frame_len - frame.capacity());
        }

        // Reserve space for frame header (frame_len + crc32) and position fields.
        // `crc32`, `frame_seq`, and `segment_id` are patched by the writer thread.
        frame.resize(FRAME_HEADER_BYTES + FRAME_V2_POSITION_BYTES, 0);

        // Build the entire body without CRC tracking. The writer thread later
        // patches position fields and computes CRC over the full body.
        frame.push(FrameType::FindingBatch as u8);
        frame.extend_from_slice(&plan.object_path_len.to_le_bytes());
        frame.extend_from_slice(batch.object_path);
        frame.extend_from_slice(&plan.findings_count_u32.to_le_bytes());

        let finding_id_prefix = finding_id_prefix_hasher(
            self.inner.keys.metadata_key(),
            plan.object_path_len,
            batch.object_path,
        );
        let mut secret_cache = SecretHashCache::new();
        for finding in batch.findings {
            let rule_idx = finding.rule_id as usize;
            let Some(rule_fp) = self.inner.rule_fingerprints_by_id.get(rule_idx) else {
                return Err(FsStoreError::backend(format!(
                    "unknown rule_id {} for log finding encode",
                    finding.rule_id
                )));
            };
            let secret = secret_cache.get_or_compute(&finding.norm_hash, &self.inner.keys);
            let finding_id = derive_finding_id(&finding_id_prefix, finding, rule_fp, &secret);

            frame.extend_from_slice(&finding.rule_id.to_le_bytes());
            frame.extend_from_slice(rule_fp);
            frame.extend_from_slice(&secret);
            frame.extend_from_slice(&finding_id);
            frame.extend_from_slice(&finding.root_hint_start.to_le_bytes());
            frame.extend_from_slice(&finding.root_hint_end.to_le_bytes());
            frame.extend_from_slice(&finding.span_start.to_le_bytes());
            frame.extend_from_slice(&finding.span_end.to_le_bytes());
        }

        frame[..4].copy_from_slice(&plan.body_len_word.to_le_bytes());
        frame[4..FRAME_HEADER_BYTES].copy_from_slice(&0u32.to_le_bytes());

        debug_assert_eq!(frame.len(), FRAME_HEADER_BYTES + plan.body_len);
        Ok(())
    }

    /// Build the [`LogRunEnd`] payload written during `Finish`.
    ///
    /// Captures the current wall-clock timestamp and propagates the loss
    /// counters (`dropped_findings`, `persistence_emit_failures`) and
    /// the `incomplete` flag from the accumulated [`FsRunLoss`].
    fn build_run_end_record(&self, loss: FsRunLoss) -> LogRunEnd {
        LogRunEnd {
            ended_unix_ms: now_unix_ms(),
            dropped_findings: loss.dropped_findings,
            persistence_emit_failures: loss.persistence_emit_failures,
            incomplete: loss.incomplete(),
        }
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
    /// Encode and queue a finding batch for disk write.
    ///
    /// Steps: plan (compute sizes) → reserve inflight budget (may block) →
    /// acquire pooled frame → encode inline → send to writer thread.
    /// On any failure after reservation, the budget and buffer are released
    /// before returning the error.
    fn emit_fs_batch(&self, batch: FsFindingBatch<'_>) -> Result<(), FsStoreError> {
        if batch.findings.is_empty() {
            return Ok(());
        }

        let plan = self.plan_finding_frame(batch)?;
        let charge = plan.frame_len;
        // Reserve first so the number of concurrently held frame buffers
        // remains bounded by inflight budgets.
        self.reserve_inflight(charge)?;

        let mut frame = self.inner.finding_frame_pool.acquire(charge);
        if let Err(err) = self.build_finding_frame(batch, plan, &mut frame) {
            self.inner.finding_frame_pool.recycle(frame);
            self.release_inflight(charge);
            return Err(err);
        }

        let flush_after = self.inner.cfg.durability == LogDurabilityMode::Batch;
        let msg = WriterCommand::FindingFrame {
            frame,
            charge_bytes: charge,
            flush_after,
        };
        let send_err = match self.inner.tx.as_ref() {
            Some(tx) => {
                match tx.send(msg) {
                    Ok(()) => None,
                    Err(err) => {
                        // Recover the frame from the SendError.
                        let WriterCommand::FindingFrame {
                            frame,
                            charge_bytes,
                            ..
                        } = err.0
                        else {
                            unreachable!("emit_fs_batch only sends FindingFrame")
                        };
                        self.inner.finding_frame_pool.recycle(frame);
                        self.release_inflight(charge_bytes);
                        Some(())
                    }
                }
            }
            None => {
                // Channel already closed (Drop or record_fs_run_loss).
                // `frame` is still in `msg` which we own, but it was moved
                // into `msg` above. Recover it.
                let WriterCommand::FindingFrame {
                    frame,
                    charge_bytes,
                    ..
                } = msg
                else {
                    unreachable!("emit_fs_batch only sends FindingFrame")
                };
                self.inner.finding_frame_pool.recycle(frame);
                self.release_inflight(charge_bytes);
                Some(())
            }
        };
        if send_err.is_some() {
            return Err(terminal_result(&self.inner.shared)
                .err()
                .unwrap_or_else(|| {
                    FsStoreError::backend("append-log writer channel disconnected")
                }));
        }
        Ok(())
    }

    /// Encode a `RunEnd` frame, send `Finish` to the writer, and join the
    /// writer thread. The close signal is intentionally deferred to the
    /// writer thread's exit so that blocked emitters can drain naturally
    /// via `release_inflight` rather than receiving spurious "closed" errors.
    fn record_fs_run_loss(&self, loss: FsRunLoss) -> Result<(), FsStoreError> {
        let run_end = self.build_run_end_record(loss);

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

        let send_ok = self
            .inner
            .tx
            .as_ref()
            .is_some_and(|tx| tx.send(WriterCommand::Finish { run_end }).is_ok());
        if !send_ok {
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

/// Best-effort cleanup: close the channel so the writer thread sees a
/// disconnect, then join it to ensure the segment is fully finalized
/// before the process continues. If `record_fs_run_loss` was already
/// called, both the sender and handle are `None` and this is a no-op.
impl Drop for Inner {
    fn drop(&mut self) {
        // Close the channel first so the writer thread's recv() returns Err.
        self.tx.take();
        // Now join the writer thread (it will finalize the segment).
        if let Ok(mut guard) = self.writer_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Shared-ownership core behind [`AppendLogStoreProducer`].
///
/// Split from the public struct so an `Arc<Inner>` can be handed to
/// concurrent emitter threads and the writer-thread closure without
/// exposing internals.
struct Inner {
    /// `None` after `Drop` or `record_fs_run_loss` closes the channel.
    tx: Option<Sender<WriterCommand>>,
    cfg: LogWriterConfig,
    run_id: u64,
    keys: StoreKeys,
    shared: Arc<SharedState>,
    /// `None` after [`StoreProducer::record_fs_run_loss`] takes it.
    writer_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Index `[rule_id]` → 32-byte BLAKE3 fingerprint.
    rule_fingerprints_by_id: Box<[[u8; 32]]>,
    finding_frame_pool: Arc<FindingFramePool>,
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

/// Precomputed finding-frame sizing metadata used by the hot path.
///
/// Built by `plan_finding_frame` so we can reserve inflight budget before
/// encoding and avoid redundant length arithmetic.
#[derive(Clone, Copy, Debug)]
struct FindingFramePlan {
    object_path_len: u32,
    findings_count_u32: u32,
    body_len: usize,
    body_len_word: u32,
    frame_len: usize,
}

/// Bounded, reusable storage for encoded finding frames.
///
/// Producers acquire a `Vec<u8>`, encode directly into it, then transfer
/// ownership to the writer thread through `WriterCommand::FindingFrame`.
/// The writer recycles buffers after each write.
struct FindingFramePool {
    free: ArrayQueue<Vec<u8>>,
    acquire_misses: AtomicU64,
    grow_count: AtomicU64,
    dropped_recycles: AtomicU64,
}

impl FindingFramePool {
    /// Create a pool with `slots` reusable buffers, each pre-allocated to
    /// `prealloc_capacity` bytes. `slots` is clamped to at least 1.
    fn new(slots: usize, prealloc_capacity: usize) -> Self {
        let slots = slots.max(1);
        let free = ArrayQueue::new(slots);
        for _ in 0..slots {
            // Startup seeding amortizes steady-state frame allocation churn.
            let _ = free.push(Vec::with_capacity(prealloc_capacity));
        }
        Self {
            free,
            acquire_misses: AtomicU64::new(0),
            grow_count: AtomicU64::new(0),
            dropped_recycles: AtomicU64::new(0),
        }
    }

    /// Pop a buffer from the pool (or allocate a fresh one on miss), ensuring
    /// at least `min_capacity` bytes of capacity. The returned `Vec` is empty.
    #[inline]
    #[allow(clippy::manual_unwrap_or_default)] // keep explicit fallback to bump miss counter
    fn acquire(&self, min_capacity: usize) -> Vec<u8> {
        let mut frame = match self.free.pop() {
            Some(frame) => frame,
            None => {
                self.acquire_misses.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        };
        frame.clear();
        if frame.capacity() < min_capacity {
            self.grow_count.fetch_add(1, Ordering::Relaxed);
            frame.reserve(min_capacity - frame.capacity());
        }
        frame
    }

    /// Return a buffer to the pool for reuse. If the pool is full the buffer
    /// is silently dropped (capacity is bounded by the channel size).
    #[inline]
    fn recycle(&self, mut frame: Vec<u8>) {
        frame.clear();
        if self.free.push(frame).is_err() {
            self.dropped_recycles.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Snapshot of pool health counters: `(acquire_misses, grow_count, dropped_recycles)`.
    ///
    /// All counters use `Relaxed` ordering — suitable for metrics collection
    /// and diagnostics, not for synchronisation.
    #[allow(dead_code)] // Retained for production metrics; currently called only in tests.
    fn debug_counters(&self) -> (u64, u64, u64) {
        (
            self.acquire_misses.load(Ordering::Relaxed),
            self.grow_count.load(Ordering::Relaxed),
            self.dropped_recycles.load(Ordering::Relaxed),
        )
    }
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
    /// Shutdown: write `RunEnd` and finalize.
    Finish { run_end: LogRunEnd },
}

/// Writer thread entry point.
///
/// Writes frames in strict order: `RunStart` → `RuleDef`s (sorted by
/// fingerprint) → finding frames from the channel → `RunEnd` on `Finish`.
/// Each finding frame write recycles its buffer and releases inflight budget,
/// unblocking producers waiting in `reserve_inflight`.
///
/// If the channel disconnects (producer dropped without `Finish`), the
/// current segment is finalized best-effort without a `RunEnd` frame.
fn writer_thread_main(
    rx: Receiver<WriterCommand>,
    cfg: LogWriterConfig,
    run_id: u64,
    run_start: LogRunStart,
    rule_defs_sorted: Vec<LogRuleDef>,
    finding_frame_pool: &FindingFramePool,
    shared: &SharedState,
) -> Result<(), String> {
    let run_dir = cfg.root_dir.join(format!("{RUN_PREFIX}{run_id:016x}"));
    let segments_dir = run_dir.join(SEGMENTS_DIR);
    let mut segment_writer =
        SegmentWriter::new(segments_dir, cfg.max_segment_bytes).map_err(|e| e.to_string())?;

    let mut next_frame_seq = 0u64;
    let mut frame = Vec::with_capacity(512);
    write_record_v2(
        &mut segment_writer,
        &mut next_frame_seq,
        &LogRecord::RunStart(run_start),
        cfg.max_frame_payload_bytes,
        false,
        &mut frame,
    )?;

    for rule_def in rule_defs_sorted {
        write_record_v2(
            &mut segment_writer,
            &mut next_frame_seq,
            &LogRecord::RuleDef(rule_def),
            cfg.max_frame_payload_bytes,
            false,
            &mut frame,
        )?;
    }

    loop {
        match rx.recv() {
            Ok(WriterCommand::FindingFrame {
                mut frame,
                charge_bytes,
                flush_after,
            }) => {
                let write_result = write_prebuilt_v2_frame(
                    &mut segment_writer,
                    &mut next_frame_seq,
                    &mut frame,
                    flush_after,
                );
                if let Some(delay) = cfg.write_delay {
                    std::thread::sleep(delay);
                }
                // Recycle before waking producers so newly-unblocked emitters
                // can immediately reuse this buffer.
                finding_frame_pool.recycle(frame);
                release_inflight(shared, charge_bytes);
                if let Err(err) = write_result {
                    return Err(format!("failed to write finding frame: {err}"));
                }
            }
            Ok(WriterCommand::Finish { run_end }) => {
                write_record_v2(
                    &mut segment_writer,
                    &mut next_frame_seq,
                    &LogRecord::RunEnd(run_end),
                    cfg.max_frame_payload_bytes,
                    false,
                    &mut frame,
                )
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

/// Encode a [`LogRecord`] into a V2 frame and write it to disk.
///
/// Handles the full encode → position-bind → CRC → write pipeline for
/// non-finding records (`RunStart`, `RuleDef`, `RunEnd`). The record is
/// first encoded with a placeholder position, then the writer obtains the
/// real `segment_id` from [`SegmentWriter::prepare_for_frame`] (which may
/// trigger rotation), assigns a monotonic `frame_seq`, patches the position
/// prefix and CRC via [`finalize_v2_frame_in_place`], and finally writes
/// the completed frame.
fn write_record_v2(
    segment_writer: &mut SegmentWriter,
    next_frame_seq: &mut u64,
    record: &LogRecord,
    max_frame_payload_bytes: u32,
    flush_after: bool,
    frame_buf: &mut Vec<u8>,
) -> Result<(), String> {
    frame_buf.clear();
    encode_record_with_position(
        record,
        max_frame_payload_bytes,
        FramePosition::default(),
        frame_buf,
    )
    .map_err(|e| format!("failed to encode frame payload: {e}"))?;
    let segment_id = segment_writer
        .prepare_for_frame(frame_buf.len() as u64)
        .map_err(|e| format!("failed to prepare segment: {e}"))?;
    let frame_seq = *next_frame_seq;
    *next_frame_seq = next_frame_seq
        .checked_add(1)
        .ok_or_else(|| "frame sequence overflow".to_string())?;
    finalize_v2_frame_in_place(
        frame_buf,
        FramePosition {
            frame_seq,
            segment_id,
        },
    )
    .map_err(|e| format!("failed to patch v2 frame: {e}"))?;
    segment_writer
        .write_prepared_frame(frame_buf, flush_after)
        .map_err(|e| format!("failed to write v2 frame: {e}"))?;
    Ok(())
}

/// Write a pre-encoded V2 frame (finding batch) to disk.
///
/// Unlike [`write_record_v2`], the frame body is already fully serialized
/// by [`AppendLogStoreProducer::build_finding_frame`] on the producer
/// thread. This function only binds the position (`frame_seq` +
/// `segment_id`), recomputes the CRC, and writes. Keeping serialization on
/// the producer side avoids holding the segment writer during encoding.
fn write_prebuilt_v2_frame(
    segment_writer: &mut SegmentWriter,
    next_frame_seq: &mut u64,
    frame: &mut [u8],
    flush_after: bool,
) -> Result<(), String> {
    let segment_id = segment_writer
        .prepare_for_frame(frame.len() as u64)
        .map_err(|e| format!("failed to prepare segment: {e}"))?;
    let frame_seq = *next_frame_seq;
    *next_frame_seq = next_frame_seq
        .checked_add(1)
        .ok_or_else(|| "frame sequence overflow".to_string())?;
    finalize_v2_frame_in_place(
        frame,
        FramePosition {
            frame_seq,
            segment_id,
        },
    )
    .map_err(|e| format!("failed to patch v2 frame: {e}"))?;
    segment_writer
        .write_prepared_frame(frame, flush_after)
        .map_err(|e| format!("failed to write v2 frame: {e}"))
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
    file: BufWriter<File>,
    open_path: PathBuf,
    bytes_written: u64,
    frame_count: u64,
    frame_crc_chain: [u8; 32],
}

impl SegmentWriter {
    /// Create the segments directory and open the first `.open` segment file.
    fn new(segments_dir: PathBuf, max_segment_bytes: u64) -> std::io::Result<Self> {
        fs::create_dir_all(&segments_dir)?;
        let (file, open_path) = open_segment_file(&segments_dir, 0)?;
        Ok(Self {
            segments_dir,
            max_segment_bytes,
            seq: 0,
            file: BufWriter::new(file),
            open_path,
            bytes_written: 0,
            frame_count: 0,
            frame_crc_chain: [0u8; 32],
        })
    }

    /// Ensure the current segment has room for one additional frame.
    ///
    /// Segments reserve trailer space so every finalized `.bin` ends with a
    /// deterministic integrity footer.
    fn prepare_for_frame(&mut self, frame_len: u64) -> std::io::Result<u64> {
        let trailer_bytes = SEGMENT_TRAILER_BYTES as u64;
        if frame_len.saturating_add(trailer_bytes) > self.max_segment_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame exceeds max_segment_bytes",
            ));
        }

        if self.bytes_written > 0
            && self
                .bytes_written
                .saturating_add(frame_len)
                .saturating_add(trailer_bytes)
                > self.max_segment_bytes
        {
            self.finalize_current()?;
            self.seq = self
                .seq
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("segment sequence number overflow"))?;
            let (file, open_path) = open_segment_file(&self.segments_dir, self.seq)?;
            self.file = BufWriter::new(file);
            self.open_path = open_path;
            self.bytes_written = 0;
            self.frame_count = 0;
            self.frame_crc_chain = [0u8; 32];
        }
        Ok(self.seq)
    }

    /// Append a frame after [`prepare_for_frame`](Self::prepare_for_frame).
    fn write_prepared_frame(&mut self, frame: &[u8], flush_after: bool) -> std::io::Result<()> {
        if frame.len() < FRAME_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "frame is shorter than header",
            ));
        }
        let frame_crc = frame_crc_from_header(frame)
            .map_err(|e| std::io::Error::other(format!("invalid frame header: {e}")))?;
        self.file.write_all(frame)?;
        self.bytes_written = self.bytes_written.saturating_add(frame.len() as u64);
        self.frame_count = self.frame_count.saturating_add(1);
        self.frame_crc_chain = extend_frame_crc_chain(&self.frame_crc_chain, frame_crc);
        if flush_after {
            self.file.flush()?;
            self.file.get_ref().sync_data()?;
        }
        Ok(())
    }

    /// Compatibility helper for tests that write already-finalized frames.
    #[cfg(test)]
    fn write_frame(&mut self, frame: &[u8], flush_after: bool) -> std::io::Result<()> {
        self.prepare_for_frame(frame.len() as u64)?;
        self.write_prepared_frame(frame, flush_after)
    }

    /// Finalize the current segment (sync + rename `.open` → `.bin`) and
    /// consume the writer. Called once at the end of a run.
    fn finish(mut self) -> std::io::Result<()> {
        self.finalize_current()
    }

    /// Flush the BufWriter, sync the underlying file's data, rename
    /// `.open` → `.bin`, and fsync the directory. After this call
    /// the segment is durable on disk.
    fn finalize_current(&mut self) -> std::io::Result<()> {
        let mut trailer = Vec::with_capacity(SEGMENT_TRAILER_BYTES);
        append_segment_trailer(
            &mut trailer,
            &SegmentTrailer {
                segment_id: self.seq,
                frame_count: self.frame_count,
                total_frame_bytes: self.bytes_written,
                frame_crc_chain: self.frame_crc_chain,
            },
        );
        self.file.write_all(&trailer)?;
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        let mut bin_path = self.open_path.clone();
        bin_path.set_extension(SEGMENT_BIN_EXT);
        rename_noreplace(&self.open_path, &bin_path)?;
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

/// Rename `from` to `to`, failing if `to` already exists.
///
/// Uses platform-specific atomic rename where available to close the
/// TOCTOU gap between `exists()` and `rename()`.
#[cfg(target_os = "linux")]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_from = CString::new(from.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let c_to = CString::new(to.as_os_str().as_bytes()).map_err(std::io::Error::other)?;

    // RENAME_NOREPLACE = 1
    let ret = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            c_from.as_ptr(),
            libc::AT_FDCWD,
            c_to.as_ptr(),
            1, // RENAME_NOREPLACE
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    // Fall back to plain rename on old kernels that don't support renameat2.
    if err.raw_os_error() == Some(libc::ENOSYS) {
        return fs::rename(from, to);
    }
    Err(err)
}

/// Rename `from` to `to`, failing if `to` already exists.
#[cfg(target_os = "macos")]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    extern "C" {
        fn renamex_np(from: *const libc::c_char, to: *const libc::c_char, flags: u32) -> i32;
    }

    let c_from = CString::new(from.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
    let c_to = CString::new(to.as_os_str().as_bytes()).map_err(std::io::Error::other)?;

    // RENAME_EXCL = 0x00000004
    let ret = unsafe { renamex_np(c_from.as_ptr(), c_to.as_ptr(), 0x00000004) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Rename `from` to `to`. Falls back to plain `fs::rename` on platforms
/// without atomic no-overwrite rename support — a TOCTOU gap remains on
/// these targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
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
/// the largest possible V2 frame plus the segment trailer must fit inside
/// a single segment.
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
    let max_frame_len = cfg.max_frame_payload_bytes as u64
        + super::format::FRAME_HEADER_BYTES as u64
        + super::format::FRAME_V2_POSITION_BYTES as u64
        + 1;
    if max_frame_len + SEGMENT_TRAILER_BYTES as u64 > cfg.max_segment_bytes {
        return Err(FsStoreError::backend(
            "max_frame_payload_bytes + v2 frame overhead + trailer exceeds max_segment_bytes; \
             no frame could ever be written",
        ));
    }
    Ok(())
}

/// Startup hint for per-frame pooled `Vec<u8>` capacity.
///
/// Uses per-frame byte budget as a signal, then clamps to a conservative range
/// to avoid large eager allocations while still covering common small frames.
#[inline]
fn finding_frame_pool_capacity_hint(cfg: &LogWriterConfig) -> usize {
    let per_frame_budget = cfg
        .max_inflight_bytes
        .checked_div(cfg.max_inflight_batches.max(1))
        .unwrap_or(0);
    let max_frame_len =
        cfg.max_frame_payload_bytes as usize + FRAME_HEADER_BYTES + FRAME_V2_POSITION_BYTES + 1;
    per_frame_budget.min(max_frame_len).clamp(
        FINDING_FRAME_POOL_MIN_CAPACITY,
        FINDING_FRAME_POOL_DEFAULT_CAPACITY,
    )
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
///
/// The resulting 32-byte BLAKE3 hash is keyed by the store metadata key and
/// absorbs every field that distinguishes one finding from another within the
/// same object path: rule fingerprint, secret hash, and byte offsets. Two
/// findings are considered identical iff their IDs match — this drives
/// cross-run deduplication in downstream consumers.
///
/// All per-finding fields are packed into a single contiguous 96-byte buffer
/// (rule_fp:32 + secret:32 + 4×u64:32) and fed to BLAKE3 in one `update`
/// call, reducing function-call overhead and improving internal buffering.
#[inline(always)]
fn derive_finding_id(
    prefix_hasher: &blake3::Hasher,
    finding: &FsFindingRecord,
    rule_fingerprint: &[u8; 32],
    secret_hash: &[u8; 32],
) -> [u8; 32] {
    // 32 (rule_fp) + 32 (secret) + 4×8 (u64 offsets) = 96 bytes.
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(rule_fingerprint);
    buf[32..64].copy_from_slice(secret_hash);
    buf[64..72].copy_from_slice(&finding.root_hint_start.to_le_bytes());
    buf[72..80].copy_from_slice(&finding.root_hint_end.to_le_bytes());
    buf[80..88].copy_from_slice(&finding.span_start.to_le_bytes());
    buf[88..96].copy_from_slice(&finding.span_end.to_le_bytes());

    let mut hasher = prefix_hasher.clone();
    hasher.update(&buf);
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
    let duration = SystemTime::now().duration_since(UNIX_EPOCH);
    debug_assert!(duration.is_ok(), "system clock is before Unix epoch");
    let t = duration.unwrap_or(Duration::ZERO).as_nanos() as u64;
    let c = RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Use wrapping_add instead of XOR: since time is monotonically
    // non-decreasing and the counter is strictly increasing, the sum
    // is strictly increasing — guaranteeing within-process uniqueness.
    // (XOR had collisions when t1^c1 == t2^c2 for nearby time values.)
    t.wrapping_add(c)
}

fn now_unix_ms() -> u64 {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH);
    debug_assert!(duration.is_ok(), "system clock is before Unix epoch");
    duration.unwrap_or(Duration::ZERO).as_millis() as u64
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

/// Decrement inflight budgets and wake one blocked producer.
///
/// Called by the writer thread after each finding frame is persisted.
/// Uses `unwrap_or_else(PoisonError::into_inner)` rather than
/// propagating poison because budget release is critical-path: if it
/// fails, every producer blocks forever. Accepting a potentially
/// inconsistent inner state is preferable to a deadlock.
///
/// Uses `notify_one` rather than `notify_all`: each release frees
/// exactly one batch slot, so only one waiter can make progress.
/// Shutdown paths (`set_terminal_error`, `mark_closed`) still use
/// `notify_all` so every blocked producer observes the shutdown.
fn release_inflight(shared: &SharedState, bytes: usize) {
    let mut guard = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    debug_assert!(
        guard.inflight_batches > 0,
        "release without matching reserve"
    );
    guard.inflight_batches = guard.inflight_batches.saturating_sub(1);
    guard.inflight_bytes = guard.inflight_bytes.saturating_sub(bytes);
    drop(guard);
    shared.cv.notify_one();
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

/// Outcome for one `.open` segment processed by [`recover_open_segments`].
///
/// Each `.open` file lands in exactly one of three buckets: successfully
/// truncated-and-finalized (`Recovered`), redundant because a `.bin` peer
/// already exists (`DiscardedDuplicateBin`), or empty / entirely corrupt
/// (`DiscardedEmpty`). The variant payloads carry enough detail for
/// diagnostics and metrics without requiring callers to re-inspect the
/// filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenSegmentRecoveryOutcome {
    /// `.open` was scanned to a deterministic boundary and finalized as `.bin`.
    Recovered {
        /// File length before recovery.
        original_len: u64,
        /// Length retained after truncate-to-boundary.
        recovered_len: u64,
        /// Number of bytes removed from the tail.
        truncated_bytes: u64,
        /// First recoverable decode failure reason that terminated scanning, if any.
        stop_reason: Option<LogReadErrorReason>,
    },
    /// `.open` was removed because matching `.bin` already existed.
    DiscardedDuplicateBin,
    /// `.open` contained no valid frames and was removed.
    DiscardedEmpty {
        /// File length before removal.
        original_len: u64,
        /// First decode failure reason, if any (`None` for 0-byte files).
        stop_reason: Option<LogReadErrorReason>,
    },
}

/// Recovery metadata for one `.open` file processed during startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSegmentRecoveryEntry {
    /// Absolute path to the `.open` segment that was processed.
    pub open_path: PathBuf,
    /// Corresponding `.bin` path (the finalization target, or the existing
    /// peer that caused a duplicate discard).
    pub bin_path: PathBuf,
    /// What happened to this `.open` file.
    pub outcome: OpenSegmentRecoveryOutcome,
}

/// Deterministic report from [`recover_open_segments`].
///
/// Collects one [`OpenSegmentRecoveryEntry`] per `.open` file found in the
/// segments directory, sorted by filename. Callers can use the convenience
/// methods ([`recovered_count`](Self::recovered_count),
/// [`discarded_count`](Self::discarded_count), etc.) for summary metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenSegmentRecoveryReport {
    /// Per-file outcomes, ordered by ascending segment filename.
    pub entries: Vec<OpenSegmentRecoveryEntry>,
}

impl OpenSegmentRecoveryReport {
    /// Number of `.open` files finalized into `.bin`.
    #[inline]
    pub fn recovered_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| matches!(entry.outcome, OpenSegmentRecoveryOutcome::Recovered { .. }))
            .count()
    }

    /// Number of `.open` files discarded because `.bin` already existed.
    #[inline]
    pub fn discarded_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.outcome,
                    OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
                )
            })
            .count()
    }

    /// Number of `.open` files discarded because they contained no valid frames.
    #[inline]
    pub fn discarded_empty_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.outcome,
                    OpenSegmentRecoveryOutcome::DiscardedEmpty { .. }
                )
            })
            .count()
    }
}

/// Recover stale `.open` segments and finalize them as `.bin`.
///
/// Deterministic policy:
/// - Iterate `run-*` directories and `.open` files in lexical order.
/// - Scan each `.open` with [`LogReader`] until clean EOF or first bad frame.
/// - Treat first recoverable decode error as EOF boundary (`truncate` to last good byte).
/// - Surface `Io` and `UnsupportedVersion` as hard errors (no byte mutation).
/// - Rename `.open` → `.bin` after truncate.
/// - If matching `.bin` already exists, remove `.open` and record discard.
///
/// This is intended for startup recovery before query/replay workflows.
pub fn recover_open_segments(
    store_root: &Path,
    max_frame_payload_bytes: u32,
) -> Result<OpenSegmentRecoveryReport, FsStoreError> {
    if !store_root.exists() {
        return Ok(OpenSegmentRecoveryReport::default());
    }

    let mut report = OpenSegmentRecoveryReport::default();
    let run_dirs = list_run_dirs(store_root)?;
    for run_dir in run_dirs {
        let seg_dir = run_dir.join(SEGMENTS_DIR);
        if !seg_dir.exists() {
            continue;
        }

        let mut open_segments = Vec::new();
        for entry in fs::read_dir(&seg_dir).map_err(io_to_store_err)? {
            let entry = entry.map_err(io_to_store_err)?;
            let ft = entry.file_type().map_err(io_to_store_err)?;
            if !ft.is_file() {
                continue;
            }
            let path = entry.path();
            let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
            let is_open = path.extension().and_then(OsStr::to_str) == Some(SEGMENT_OPEN_EXT);
            if is_open && name.starts_with(SEGMENT_PREFIX) {
                open_segments.push(path);
            }
        }
        open_segments.sort();

        for open_path in open_segments {
            let mut bin_path = open_path.clone();
            bin_path.set_extension(SEGMENT_BIN_EXT);
            if bin_path.exists() {
                fs::remove_file(&open_path).map_err(|e| io_to_store_err_at(e, &open_path))?;
                report.entries.push(OpenSegmentRecoveryEntry {
                    open_path,
                    bin_path,
                    outcome: OpenSegmentRecoveryOutcome::DiscardedDuplicateBin,
                });
                continue;
            }

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&open_path)
                .map_err(|e| io_to_store_err_at(e, &open_path))?;
            let original_len = file
                .metadata()
                .map_err(|e| io_to_store_err_at(e, &open_path))?
                .len();

            let (recovered_len, stop_reason) =
                scan_recovery_boundary(&mut file, max_frame_payload_bytes)?;
            let recovered_len = recovered_len.min(original_len);
            drop(file);

            // No valid frames: discard the file instead of creating a
            // confusing 0-byte `.bin`.
            if recovered_len == 0 {
                fs::remove_file(&open_path).map_err(|e| io_to_store_err_at(e, &open_path))?;
                report.entries.push(OpenSegmentRecoveryEntry {
                    open_path,
                    bin_path,
                    outcome: OpenSegmentRecoveryOutcome::DiscardedEmpty {
                        original_len,
                        stop_reason,
                    },
                });
                continue;
            }

            // Re-open for truncation and sync if needed.
            if recovered_len < original_len {
                let file = OpenOptions::new()
                    .write(true)
                    .open(&open_path)
                    .map_err(|e| io_to_store_err_at(e, &open_path))?;
                file.set_len(recovered_len)
                    .map_err(|e| io_to_store_err_at(e, &open_path))?;
                file.sync_data()
                    .map_err(|e| io_to_store_err_at(e, &open_path))?;
            }

            match rename_noreplace(&open_path, &bin_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Another process created .bin between our exists()
                    // check and rename. Treat as concurrent duplicate.
                    fs::remove_file(&open_path).map_err(|e| io_to_store_err_at(e, &open_path))?;
                    report.entries.push(OpenSegmentRecoveryEntry {
                        open_path,
                        bin_path,
                        outcome: OpenSegmentRecoveryOutcome::DiscardedDuplicateBin,
                    });
                    continue;
                }
                Err(e) => return Err(io_to_store_err_at(e, &bin_path)),
            }
            sync_dir(&seg_dir).map_err(|e| io_to_store_err_at(e, &seg_dir))?;

            report.entries.push(OpenSegmentRecoveryEntry {
                open_path,
                bin_path,
                outcome: OpenSegmentRecoveryOutcome::Recovered {
                    original_len,
                    recovered_len,
                    truncated_bytes: original_len.saturating_sub(recovered_len),
                    stop_reason,
                },
            });
        }
    }
    Ok(report)
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

    let run_dirs = list_run_dirs(store_root)?;
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

/// Drive a [`LogReader`] forward through `file` until clean EOF or first bad
/// frame, returning `(last_valid_byte_offset, stop_reason)`.
///
/// The caller truncates the file at the returned offset, discarding any
/// partial trailing frame. A `None` stop reason means the reader reached
/// clean EOF with no corruption — the entire file is valid. `Io` and
/// `UnsupportedVersion` reasons are promoted to hard errors (callers cannot
/// safely mutate bytes for transport failures, and must preserve forward-
/// version segments), while all other reasons (CRC, truncated, malformed,
/// etc.) are treated as a recoverable boundary.
fn scan_recovery_boundary(
    file: &mut File,
    max_frame_payload_bytes: u32,
) -> Result<(u64, Option<LogReadErrorReason>), FsStoreError> {
    let mut reader = LogReader::buffered(file, max_frame_payload_bytes);
    loop {
        match reader.next_frame_validated() {
            Ok(Some(())) => {}
            Ok(None) => return Ok((reader.next_frame_offset(), None)),
            Err(err) => {
                if err.reason() == LogReadErrorReason::Io {
                    return Err(FsStoreError::backend(format!(
                        "failed to recover open segment at offset {}: {}",
                        err.frame_offset(),
                        err
                    )));
                }
                if err.reason() == LogReadErrorReason::UnsupportedVersion {
                    return Err(FsStoreError::backend(format!(
                        "failed to recover open segment at offset {}: unsupported version: {}",
                        err.frame_offset(),
                        err
                    )));
                }
                return Ok((reader.next_frame_offset(), Some(err.reason())));
            }
        }
    }
}

/// Collect `run-*` directories under `store_root` in lexical order.
///
/// Lexical ordering over the hex run-id suffix gives chronological order
/// within a single process (run IDs are time+counter). Cross-process ordering
/// is best-effort because run-id generation is per-process.
fn list_run_dirs(store_root: &Path) -> Result<Vec<PathBuf>, FsStoreError> {
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
    Ok(run_dirs)
}

fn io_to_store_err(err: std::io::Error) -> FsStoreError {
    FsStoreError::backend(format!("append-log io error ({:?}): {err}", err.kind()))
}

fn io_to_store_err_at(err: std::io::Error, path: &Path) -> FsStoreError {
    FsStoreError::backend(format!(
        "append-log io error ({:?}) at '{}': {err}",
        err.kind(),
        path.display()
    ))
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
    use crate::store::keys::{CorrelationMode, KeySource};
    use crate::store::log::format::{
        encode_record, LogDurabilityMode, LogRecord, LogRecordReader, LogRunEnd, LogRunStart,
        DEFAULT_MAX_FRAME_PAYLOAD_BYTES, FRAME_HEADER_BYTES, LOG_FORMAT_VERSION,
    };
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

    fn recovery_run_start() -> LogRunStart {
        LogRunStart {
            version: LOG_FORMAT_VERSION,
            run_id: 1,
            started_unix_ms: 2,
            durability: LogDurabilityMode::SegmentClose,
            correlation_mode: CorrelationMode::Persistent,
            key_source: KeySource::EnvVar,
            max_inflight_batches: 8,
            max_inflight_bytes: 64 * 1024,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
        }
    }

    fn recovery_run_end() -> LogRunEnd {
        LogRunEnd {
            ended_unix_ms: 3,
            dropped_findings: 0,
            persistence_emit_failures: 0,
            incomplete: false,
        }
    }

    fn rewrite_frame_body_byte_and_recompute_crc(frame: &mut [u8], body_offset: usize, value: u8) {
        let body_idx = FRAME_HEADER_BYTES + body_offset;
        frame[body_idx] = value;

        let mut crc = crc32fast::Hasher::new();
        crc.update(&frame[FRAME_HEADER_BYTES..]);
        let crc32 = crc.finalize();
        frame[4..FRAME_HEADER_BYTES].copy_from_slice(&crc32.to_le_bytes());
    }

    fn decode_recovered_records(bin_path: &std::path::Path) -> Vec<LogRecord> {
        let f = File::open(bin_path).unwrap();
        let mut reader = LogRecordReader::new(f, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let mut records = Vec::new();
        while let Some(rec) = reader.next_record().unwrap() {
            records.push(rec);
        }
        records
    }

    fn run_marked_incomplete(
        records: &[LogRecord],
        stop_reason: Option<LogReadErrorReason>,
    ) -> bool {
        if stop_reason.is_some() {
            return true;
        }
        !records
            .iter()
            .any(|record| matches!(record, LogRecord::RunEnd(run_end) if !run_end.incomplete))
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
        // max_frame_payload_bytes + header + type byte must not exceed
        // max_segment_bytes; validate_config rejects this at construction time.
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
    fn config_rejects_segment_that_cannot_fit_frame_type_byte() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_frame_payload_bytes = 1_024;
        cfg.max_segment_bytes = cfg.max_frame_payload_bytes as u64 + FRAME_HEADER_BYTES as u64;

        let err = AppendLogStoreProducer::new(&[simple_rule()], cfg)
            .err()
            .expect("expected config validation error");
        assert!(
            err.detail().contains("max_frame_payload_bytes")
                || err.detail().contains("max_segment_bytes")
                || err.detail().contains("frame header"),
            "expected frame/segment validation error, got: {}",
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
        cfg.max_segment_bytes = 320; // Very small after reserving trailer space.
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
        cfg.max_segment_bytes = 380; // Very small to force many rotations.
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
    fn finding_frame_pool_reuses_grown_buffers_after_warmup() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_inflight_batches = 1;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        let findings: Vec<_> = (0..48u64).map(|i| sample_finding(0, i * 100)).collect();

        // Warm up once so the pooled buffer can grow to this frame shape.
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"warmup.txt",
                findings: &findings,
            })
            .unwrap();

        let before = producer.inner.finding_frame_pool.debug_counters();
        for _ in 0..20 {
            producer
                .emit_fs_batch(FsFindingBatch {
                    object_path: b"steady-state.txt",
                    findings: &findings,
                })
                .unwrap();
        }
        let after = producer.inner.finding_frame_pool.debug_counters();

        assert_eq!(
            after.0, before.0,
            "steady-state should not allocate new frame buffers (pool miss)"
        );
        assert_eq!(
            after.1, before.1,
            "steady-state should not grow pooled frame capacity"
        );
        assert_eq!(
            after.2, before.2,
            "steady-state should not drop recycled frame buffers"
        );

        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

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
        let frame_size = producer_probe
            .plan_finding_frame(FsFindingBatch {
                object_path: b"probe.txt",
                findings: &findings,
            })
            .unwrap()
            .frame_len;
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
        cfg.max_frame_payload_bytes = 300;
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

    #[test]
    fn recover_open_segments_truncates_tail_and_renames_to_bin() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        let expected_recovered_len = bytes.len() as u64;
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        // Simulate crash during second frame write.
        bytes.truncate(bytes.len() - 5);
        fs::write(&open_path, &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 1);
        assert_eq!(report.discarded_count(), 0);

        let entry = &report.entries[0];
        assert_eq!(entry.open_path, open_path);
        assert_eq!(entry.bin_path, bin_path);
        match entry.outcome {
            OpenSegmentRecoveryOutcome::Recovered {
                recovered_len,
                truncated_bytes,
                stop_reason,
                ..
            } => {
                assert_eq!(recovered_len, expected_recovered_len);
                assert!(truncated_bytes > 0);
                assert_eq!(stop_reason, Some(LogReadErrorReason::Truncated));
            }
            OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
            | OpenSegmentRecoveryOutcome::DiscardedEmpty { .. } => {
                panic!("expected recovered outcome")
            }
        }

        assert!(!open_path.exists(), ".open should be renamed away");
        assert!(bin_path.exists(), "recovered .bin should exist");

        let f = File::open(&bin_path).unwrap();
        let mut reader = LogRecordReader::new(f, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn recover_open_segments_crc_failure_stops_at_first_bad_frame_and_marks_incomplete() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        let expected_recovered_len = bytes.len() as u64;

        let mut corrupt_run_end = Vec::new();
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut corrupt_run_end,
        )
        .unwrap();
        corrupt_run_end[FRAME_HEADER_BYTES] ^= 0x01;
        bytes.extend_from_slice(&corrupt_run_end);
        // Valid trailing frame should be ignored: recovery stops at the first bad frame.
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();

        fs::write(&open_path, &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 1);

        let entry = &report.entries[0];
        assert_eq!(entry.open_path, open_path);
        assert_eq!(entry.bin_path, bin_path);
        let stop_reason = match entry.outcome {
            OpenSegmentRecoveryOutcome::Recovered {
                recovered_len,
                truncated_bytes,
                stop_reason,
                ..
            } => {
                assert_eq!(recovered_len, expected_recovered_len);
                assert!(truncated_bytes > 0);
                assert_eq!(stop_reason, Some(LogReadErrorReason::CrcMismatch));
                stop_reason
            }
            OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
            | OpenSegmentRecoveryOutcome::DiscardedEmpty { .. } => {
                panic!("expected recovered outcome")
            }
        };

        let records = decode_recovered_records(&bin_path);
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0], LogRecord::RunStart(_)));
        assert!(
            run_marked_incomplete(&records, stop_reason),
            "CRC stop reason should mark recovered run incomplete"
        );
    }

    /// Recovery uses skip-decode (`next_frame_validated`) which checks CRC
    /// and version gate but skips full payload decode. A frame with valid CRC
    /// but an invalid enum value (e.g. reserved key_source) passes the
    /// recovery scan because the frame boundary is trustworthy. The semantic
    /// error is surfaced later at query time, not at recovery time.
    #[test]
    fn recover_open_segments_reserved_identity_metadata_violation_passes_skip_decode() {
        // RunStart payload layout:
        // version(2) + run_id(8) + started(8) + durability(1) + correlation_mode(1)
        // + key_source(1) + max_inflight_batches(4) + max_inflight_bytes(8)
        // + max_frame_payload_bytes(4)
        const RUN_START_KEY_SOURCE_BODY_OFFSET: usize = 1 + 2 + 8 + 8 + 1 + 1;

        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();

        let mut invalid_identity_run_start = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut invalid_identity_run_start,
        )
        .unwrap();
        // key_source uses a small fixed domain; 0xFF exercises reserved/unknown value handling.
        // CRC is recomputed, so the frame is structurally valid.
        rewrite_frame_body_byte_and_recompute_crc(
            &mut invalid_identity_run_start,
            RUN_START_KEY_SOURCE_BODY_OFFSET,
            0xFF,
        );
        bytes.extend_from_slice(&invalid_identity_run_start);
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();

        let expected_total_len = bytes.len() as u64;
        fs::write(&open_path, &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 1);

        let entry = &report.entries[0];
        assert_eq!(entry.open_path, open_path);
        assert_eq!(entry.bin_path, bin_path);
        // Skip-decode accepts all CRC-valid frames, so the entire file is
        // recovered with clean EOF (no truncation, no stop reason).
        match entry.outcome {
            OpenSegmentRecoveryOutcome::Recovered {
                recovered_len,
                truncated_bytes,
                stop_reason,
                ..
            } => {
                assert_eq!(recovered_len, expected_total_len);
                assert_eq!(truncated_bytes, 0);
                assert_eq!(stop_reason, None);
            }
            OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
            | OpenSegmentRecoveryOutcome::DiscardedEmpty { .. } => {
                panic!("expected recovered outcome")
            }
        }

        // The .bin file contains all bytes. Full decode will hit the invalid
        // enum in the second RunStart — that error is surfaced at query time.
        let bin_len = fs::metadata(&bin_path).unwrap().len();
        assert_eq!(bin_len, expected_total_len);
    }

    #[test]
    fn recover_open_segments_unsupported_version_is_hard_error() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut run_start = recovery_run_start();
        run_start.version = LOG_FORMAT_VERSION.wrapping_add(1);

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(run_start),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        let original_len = bytes.len() as u64;
        fs::write(&open_path, &bytes).unwrap();

        let err = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        assert!(
            err.detail().contains("unsupported version"),
            "expected unsupported version error, got: {}",
            err.detail()
        );

        assert!(
            open_path.exists(),
            ".open should remain for unsupported versions"
        );
        assert!(
            !bin_path.exists(),
            ".bin should not be created on hard error"
        );
        let current_len = fs::metadata(&open_path).unwrap().len();
        assert_eq!(
            current_len, original_len,
            "unsupported-version recovery must not truncate source bytes"
        );
    }

    #[test]
    fn recover_open_segments_discards_open_when_matching_bin_exists() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        fs::write(&bin_path, b"already-finalized").unwrap();
        fs::write(&open_path, b"stale-open").unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 0);
        assert_eq!(report.discarded_count(), 1);
        assert!(
            matches!(
                report.entries[0].outcome,
                OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
            ),
            "expected duplicate-bin discard outcome"
        );
        assert!(!open_path.exists(), "stale .open should be removed");
        assert!(bin_path.exists(), "existing .bin should remain");
        assert_eq!(fs::read(&bin_path).unwrap(), b"already-finalized");
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
    /// The wrapping_add of truncated nanos with a monotonic counter should
    /// produce unique IDs for sequential calls within the same process.
    #[test]
    fn next_run_id_is_unique_within_process() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let id = next_run_id();
            assert!(ids.insert(id), "duplicate run_id detected: {id:#018x}");
        }
    }

    /// Drop must join the writer thread and finalize the segment without
    /// requiring an explicit `record_fs_run_loss` call. Before the Drop
    /// impl, the writer thread was detached and the test had to sleep.
    #[test]
    fn drop_joins_writer_thread_and_finalizes_segment() {
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg.clone()).unwrap();
        let findings = vec![sample_finding(0, 0)];
        producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"drop-test.txt",
                findings: &findings,
            })
            .unwrap();

        // Drop the producer — this should join the writer thread synchronously.
        drop(producer);

        // No sleep needed: if Drop joins the thread, the segment is already
        // finalized by the time we reach here.
        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        assert!(
            !bins.is_empty(),
            "expected finalized .bin segment after Drop (no sleep)"
        );
    }

    #[test]
    fn segment_sequence_overflow_returns_error_instead_of_panic() {
        let tmp = TempDir::new().unwrap();
        let segments_dir = tmp.path().join("segments");
        let mut sw = SegmentWriter::new(segments_dir, 256).unwrap();

        // Force the sequence counter to u64::MAX so the next rotation overflows.
        sw.seq = u64::MAX;
        // Write enough to fill the current segment, then write again to trigger rotation.
        sw.file.write_all(&[0u8; 128]).unwrap();
        sw.bytes_written = 128;

        // This second write should trigger rotation once trailer reservation
        // is considered: 128 + 128 + trailer > 256.
        // which increments seq from u64::MAX → overflow.
        let result = sw.write_frame(&[0u8; 128], false);
        assert!(
            result.is_err(),
            "expected error on sequence overflow, not panic"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    /// Field-level round-trip: emit a batch with known values via the inline
    /// encoder (`build_finding_frame`), read back from disk, and verify every
    /// decoded `LogFindingRecord` field matches the independently-computed
    /// expected value. This closes the coverage gap between the inline encoder
    /// and `encode_finding_batch` (format.rs) paths.
    #[test]
    fn finding_frame_field_level_round_trip() {
        use crate::store::identity::{rule_fingerprint as compute_rule_fp, secret_hash};
        use crate::store::log::format::{LogFindingBatch as DecodedBatch, LogRecord};

        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        let max_payload = cfg.max_frame_payload_bytes;
        let rules = [simple_rule()];

        let producer = AppendLogStoreProducer::new(&rules, cfg.clone()).unwrap();
        let keys = &producer.inner.keys;

        // Compute expected derived values independently.
        let expected_rule_fp = compute_rule_fp(&rules[0], keys);
        let norm_hash_a: [u8; 32] = [0xAA; 32];
        let norm_hash_b: [u8; 32] = [0xBB; 32];
        let expected_secret_a = secret_hash(&norm_hash_a, keys);
        let expected_secret_b = secret_hash(&norm_hash_b, keys);

        // Use non-trivial, distinct field values to catch transposition bugs.
        let findings = vec![
            FsFindingRecord {
                rule_id: 0,
                root_hint_start: 100,
                root_hint_end: 200,
                span_start: 110,
                span_end: 190,
                norm_hash: norm_hash_a,
            },
            FsFindingRecord {
                rule_id: 0,
                root_hint_start: 300,
                root_hint_end: 400,
                span_start: 310,
                span_end: 390,
                norm_hash: norm_hash_b,
            },
        ];

        let object_path = b"test/round-trip.txt";

        // Compute expected finding_ids independently using the same derivation.
        let prefix_hasher =
            finding_id_prefix_hasher(keys.metadata_key(), object_path.len() as u32, object_path);
        let expected_finding_id_a = derive_finding_id(
            &prefix_hasher,
            &findings[0],
            &expected_rule_fp,
            &expected_secret_a,
        );
        let expected_finding_id_b = derive_finding_id(
            &prefix_hasher,
            &findings[1],
            &expected_rule_fp,
            &expected_secret_b,
        );

        producer
            .emit_fs_batch(FsFindingBatch {
                object_path,
                findings: &findings,
            })
            .unwrap();
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();

        // Read back and decode.
        let bins = list_finalized_segment_files(&cfg.root_dir).unwrap();
        let mut decoded_batches: Vec<DecodedBatch> = Vec::new();
        for bin in &bins {
            let f = File::open(bin).unwrap();
            let mut reader = LogRecordReader::new(f, max_payload);
            while let Some(rec) = reader.next_record().unwrap() {
                if let LogRecord::FindingBatch(batch) = rec {
                    decoded_batches.push(batch);
                }
            }
        }

        assert_eq!(
            decoded_batches.len(),
            1,
            "expected exactly one finding batch"
        );
        let batch = &decoded_batches[0];
        assert_eq!(batch.object_path, object_path);
        assert_eq!(batch.findings.len(), 2);

        // Finding A: verify every field.
        let fa = &batch.findings[0];
        assert_eq!(fa.rule_id, 0);
        assert_eq!(
            fa.rule_fingerprint, expected_rule_fp,
            "rule_fingerprint mismatch (finding A)"
        );
        assert_eq!(
            fa.secret_hash, expected_secret_a,
            "secret_hash mismatch (finding A)"
        );
        assert_eq!(
            fa.finding_id, expected_finding_id_a,
            "finding_id mismatch (finding A)"
        );
        assert_eq!(fa.root_hint_start, 100);
        assert_eq!(fa.root_hint_end, 200);
        assert_eq!(fa.span_start, 110);
        assert_eq!(fa.span_end, 190);

        // Finding B: verify every field.
        let fb = &batch.findings[1];
        assert_eq!(fb.rule_id, 0);
        assert_eq!(
            fb.rule_fingerprint, expected_rule_fp,
            "rule_fingerprint mismatch (finding B)"
        );
        assert_eq!(
            fb.secret_hash, expected_secret_b,
            "secret_hash mismatch (finding B)"
        );
        assert_eq!(
            fb.finding_id, expected_finding_id_b,
            "finding_id mismatch (finding B)"
        );
        assert_eq!(fb.root_hint_start, 300);
        assert_eq!(fb.root_hint_end, 400);
        assert_eq!(fb.span_start, 310);
        assert_eq!(fb.span_end, 390);
    }

    /// Invalid rule_id in a finding should surface an error from
    /// build_finding_frame, not panic or produce corrupt data.
    #[test]
    fn invalid_rule_id_returns_error() {
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        // rule_id 99 doesn't exist — only rule 0 was registered.
        let findings = vec![FsFindingRecord {
            rule_id: 99,
            root_hint_start: 0,
            root_hint_end: 16,
            span_start: 1,
            span_end: 15,
            norm_hash: [0xCC; 32],
        }];
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"bad-rule.txt",
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("unknown rule_id"),
            "expected 'unknown rule_id' error, got: {}",
            err.detail()
        );
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    /// plan_finding_frame checks: object_path too large to fit in u32.
    #[test]
    fn plan_finding_frame_rejects_oversized_object_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();

        // Use a payload that exceeds max_frame_payload_bytes.
        let long_path = vec![b'x'; producer.inner.cfg.max_frame_payload_bytes as usize + 1];
        let findings = vec![sample_finding(0, 0)];
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: &long_path,
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("too large") || err.detail().contains("FrameTooLarge"),
            "expected size error, got: {}",
            err.detail()
        );
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
    }

    /// plan_finding_frame: findings count × record size overflows.
    #[test]
    fn plan_finding_frame_rejects_too_many_findings() {
        let tmp = TempDir::new().unwrap();
        let mut cfg = LogWriterConfig::for_root(tmp.path().to_path_buf());
        cfg.max_frame_payload_bytes = 512;
        cfg.max_segment_bytes = 1024;
        cfg.max_inflight_bytes = 16 * 1024 * 1024;

        let producer = AppendLogStoreProducer::new(&[simple_rule()], cfg).unwrap();
        // 4 findings × 132 bytes = 528 > 512 max_frame_payload_bytes
        let findings: Vec<_> = (0..4).map(|i| sample_finding(0, i * 100)).collect();
        let err = producer
            .emit_fs_batch(FsFindingBatch {
                object_path: b"many.txt",
                findings: &findings,
            })
            .unwrap_err();
        assert!(
            err.detail().contains("FrameTooLarge") || err.detail().contains("too large"),
            "expected frame too large error, got: {}",
            err.detail()
        );
        producer.record_fs_run_loss(FsRunLoss::default()).unwrap();
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

    #[test]
    fn recover_completely_valid_open_no_truncation() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        let original_len = bytes.len() as u64;
        fs::write(&open_path, &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 1);
        assert_eq!(report.discarded_count(), 0);

        let entry = &report.entries[0];
        match entry.outcome {
            OpenSegmentRecoveryOutcome::Recovered {
                original_len: orig,
                recovered_len,
                truncated_bytes,
                stop_reason,
            } => {
                assert_eq!(orig, original_len);
                assert_eq!(recovered_len, original_len);
                assert_eq!(truncated_bytes, 0);
                assert_eq!(stop_reason, None);
            }
            OpenSegmentRecoveryOutcome::DiscardedDuplicateBin
            | OpenSegmentRecoveryOutcome::DiscardedEmpty { .. } => {
                panic!("expected recovered outcome")
            }
        }

        assert!(!open_path.exists());
        assert!(bin_path.exists());

        let records = decode_recovered_records(&bin_path);
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0], LogRecord::RunStart(_)));
        assert!(matches!(records[1], LogRecord::RunEnd(_)));
    }

    #[test]
    fn recover_empty_open_file() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        fs::write(&open_path, b"").unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 0);
        assert_eq!(report.discarded_empty_count(), 1);

        let entry = &report.entries[0];
        match entry.outcome {
            OpenSegmentRecoveryOutcome::DiscardedEmpty {
                original_len,
                stop_reason,
            } => {
                assert_eq!(original_len, 0);
                assert_eq!(stop_reason, None);
            }
            _ => panic!("expected DiscardedEmpty outcome"),
        }

        assert!(!open_path.exists());
        assert!(!bin_path.exists(), "0-byte .bin should not be created");
    }

    #[test]
    fn recover_open_segments_frame_0_corrupt_discards_file() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        // Create .open with a CRC-corrupted first frame.
        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        bytes[FRAME_HEADER_BYTES] ^= 0x01; // flip body byte to break CRC
        fs::write(&open_path, &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.recovered_count(), 0);
        assert_eq!(report.discarded_empty_count(), 1);

        let entry = &report.entries[0];
        match entry.outcome {
            OpenSegmentRecoveryOutcome::DiscardedEmpty {
                original_len,
                stop_reason,
            } => {
                assert!(original_len > 0);
                assert_eq!(stop_reason, Some(LogReadErrorReason::CrcMismatch));
            }
            _ => panic!("expected DiscardedEmpty outcome"),
        }

        assert!(!open_path.exists());
        assert!(!bin_path.exists(), "0-byte .bin should not be created");
    }

    #[test]
    fn recover_multiple_open_in_one_run() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open1 = seg_dir.join("segment-00000000000000000000.open");
        let open2 = seg_dir.join("segment-00000000000000000001.open");

        let mut bytes1 = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes1,
        )
        .unwrap();
        fs::write(&open1, &bytes1).unwrap();

        let mut bytes2 = Vec::new();
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes2,
        )
        .unwrap();
        fs::write(&open2, &bytes2).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.recovered_count(), 2);

        let names: Vec<&str> = report
            .entries
            .iter()
            .map(|e| e.open_path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(names[0] < names[1], "expected lexical order: {names:?}");

        let bin1 = seg_dir.join("segment-00000000000000000000.bin");
        let bin2 = seg_dir.join("segment-00000000000000000001.bin");
        assert!(bin1.exists());
        assert!(bin2.exists());
    }

    #[test]
    fn recover_multiple_run_dirs() {
        let tmp = TempDir::new().unwrap();

        for run_name in &["run-0000000000000001", "run-0000000000000002"] {
            let seg_dir = tmp.path().join(run_name).join("segments");
            fs::create_dir_all(&seg_dir).unwrap();

            let open_path = seg_dir.join("segment-00000000000000000000.open");
            let mut bytes = Vec::new();
            encode_record(
                &LogRecord::RunStart(recovery_run_start()),
                DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
                &mut bytes,
            )
            .unwrap();
            fs::write(&open_path, &bytes).unwrap();
        }

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.recovered_count(), 2);

        let run_dirs: Vec<String> = report
            .entries
            .iter()
            .map(|e| {
                e.open_path
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert!(
            run_dirs[0] < run_dirs[1],
            "expected run order preserved: {run_dirs:?}"
        );
    }

    #[test]
    fn recover_no_open_files_is_noop() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        fs::write(seg_dir.join("segment-00000000000000000000.bin"), &bytes).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert!(report.entries.is_empty());
        assert_eq!(report.recovered_count(), 0);
        assert_eq!(report.discarded_count(), 0);
    }

    #[test]
    fn recover_idempotency() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        fs::write(&open_path, &bytes).unwrap();

        let report1 = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report1.recovered_count(), 1);
        assert!(bin_path.exists());

        let report2 = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert!(report2.entries.is_empty());

        let records = decode_recovered_records(&bin_path);
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0], LogRecord::RunStart(_)));
    }

    #[test]
    fn recover_mixed_scenario() {
        let tmp = TempDir::new().unwrap();

        // Run 1: one valid .open + one duplicate (.bin already exists).
        let run1_dir = tmp.path().join("run-0000000000000001");
        let seg1_dir = run1_dir.join("segments");
        fs::create_dir_all(&seg1_dir).unwrap();

        let mut valid_bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut valid_bytes,
        )
        .unwrap();
        fs::write(
            seg1_dir.join("segment-00000000000000000000.open"),
            &valid_bytes,
        )
        .unwrap();

        fs::write(
            seg1_dir.join("segment-00000000000000000001.bin"),
            b"already-finalized",
        )
        .unwrap();
        fs::write(seg1_dir.join("segment-00000000000000000001.open"), b"stale").unwrap();

        // Run 2: one truncated .open.
        let run2_dir = tmp.path().join("run-0000000000000002");
        let seg2_dir = run2_dir.join("segments");
        fs::create_dir_all(&seg2_dir).unwrap();

        let mut trunc_bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut trunc_bytes,
        )
        .unwrap();
        let good_len = trunc_bytes.len();
        encode_record(
            &LogRecord::RunEnd(recovery_run_end()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut trunc_bytes,
        )
        .unwrap();
        trunc_bytes.truncate(good_len + 3);
        fs::write(
            seg2_dir.join("segment-00000000000000000000.open"),
            &trunc_bytes,
        )
        .unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.recovered_count(), 2, "expected 2 recovered");
        assert_eq!(report.discarded_count(), 1, "expected 1 discarded");
        assert_eq!(report.entries.len(), 3);
    }

    #[test]
    fn recover_nonexistent_root_is_noop() {
        let report = recover_open_segments(
            Path::new("/nonexistent/path/that/should/not/exist"),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
        )
        .unwrap();
        assert!(report.entries.is_empty());
        assert_eq!(report.recovered_count(), 0);
        assert_eq!(report.discarded_count(), 0);
    }

    #[test]
    fn rename_noreplace_fails_when_target_exists() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.tmp");
        let target = tmp.path().join("target.tmp");

        fs::write(&source, b"src").unwrap();
        fs::write(&target, b"tgt").unwrap();

        let err = rename_noreplace(&source, &target).unwrap_err();
        // On macOS/Linux this is EEXIST → AlreadyExists.
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "expected AlreadyExists, got: {err:?}"
        );
        // Source should still exist (rename was not performed).
        assert!(source.exists());
        // Target should be unchanged.
        assert_eq!(fs::read(&target).unwrap(), b"tgt");
    }

    #[test]
    fn rename_noreplace_succeeds_when_target_absent() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.tmp");
        let target = tmp.path().join("target.tmp");

        fs::write(&source, b"data").unwrap();

        rename_noreplace(&source, &target).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&target).unwrap(), b"data");
    }

    // ================================================================
    // Recovery: Tier 3 — Coverage gaps
    // ================================================================

    #[test]
    fn recover_multiple_run_dirs_with_mixed_open_files() {
        let tmp = TempDir::new().unwrap();

        // Run 1: one .open (valid), one .open + matching .bin (duplicate).
        let run1_seg = tmp.path().join("run-0000000000000001").join("segments");
        fs::create_dir_all(&run1_seg).unwrap();
        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        fs::write(run1_seg.join("segment-00000000000000000000.open"), &bytes).unwrap();
        fs::write(run1_seg.join("segment-00000000000000000001.open"), b"stale").unwrap();
        fs::write(run1_seg.join("segment-00000000000000000001.bin"), b"final").unwrap();

        // Run 2: one empty .open.
        let run2_seg = tmp.path().join("run-0000000000000002").join("segments");
        fs::create_dir_all(&run2_seg).unwrap();
        fs::write(run2_seg.join("segment-00000000000000000000.open"), b"").unwrap();

        // Run 3: one .open with corrupt frame 0.
        let run3_seg = tmp.path().join("run-0000000000000003").join("segments");
        fs::create_dir_all(&run3_seg).unwrap();
        let mut corrupt = bytes.clone();
        corrupt[FRAME_HEADER_BYTES] ^= 0x01;
        fs::write(run3_seg.join("segment-00000000000000000000.open"), &corrupt).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();

        assert_eq!(report.recovered_count(), 1, "one valid .open → .bin");
        assert_eq!(report.discarded_count(), 1, "one duplicate discard");
        assert_eq!(
            report.discarded_empty_count(),
            2,
            "one 0-byte + one corrupt-frame-0"
        );
        assert_eq!(report.entries.len(), 4);
    }

    #[test]
    fn recover_header_only_truncation_less_than_8_bytes() {
        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let bin_path = seg_dir.join("segment-00000000000000000000.bin");

        // 3 bytes: not enough for even a frame header.
        fs::write(&open_path, [0xAA, 0xBB, 0xCC]).unwrap();

        let report = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.discarded_empty_count(), 1);

        let entry = &report.entries[0];
        match entry.outcome {
            OpenSegmentRecoveryOutcome::DiscardedEmpty {
                original_len,
                stop_reason,
            } => {
                assert_eq!(original_len, 3);
                assert_eq!(stop_reason, Some(LogReadErrorReason::Truncated));
            }
            _ => panic!("expected DiscardedEmpty outcome"),
        }

        assert!(!open_path.exists());
        assert!(!bin_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn scan_recovery_boundary_io_error_returns_err() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let run_dir = tmp.path().join("run-0000000000000001");
        let seg_dir = run_dir.join("segments");
        fs::create_dir_all(&seg_dir).unwrap();

        let open_path = seg_dir.join("segment-00000000000000000000.open");
        let mut bytes = Vec::new();
        encode_record(
            &LogRecord::RunStart(recovery_run_start()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut bytes,
        )
        .unwrap();
        fs::write(&open_path, &bytes).unwrap();

        // Remove read permission.
        fs::set_permissions(&open_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = recover_open_segments(tmp.path(), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);

        // Restore permissions for cleanup.
        fs::set_permissions(&open_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(result.is_err(), "expected error when file is unreadable");
    }
}
