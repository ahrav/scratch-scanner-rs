//! Connector-first scheduler entrypoint for enumerate/read/scan workflows.
//!
//! # Purpose
//!
//! This module bridges the [`gossip_contracts`] connector API to the scanner-rs
//! scheduler. It owns **page-level orchestration**: enumerating items from a
//! connector shard, validating each page against shard and cursor invariants,
//! gating progress behind a per-page completion barrier, and checkpointing the
//! cursor only after every item on a page reaches a terminal state.
//!
//! Item-level execution uses the connector read surface directly:
//! `open()` as the baseline path and `read_range()` when advertised by
//! capabilities. Chunk scanning and dedupe reuse the same helpers as the
//! local/remote scheduler paths to preserve finding semantics.
//!
//! # High-level flow
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │  loop {                                                             │
//! │    1. enumerate_page(shard, cursor, budgets)                        │
//! │    2. enforce page-size budget (hard cap on item count)             │
//! │    3. validate_page(shard, cursor, items, next_cursor)              │
//! │    4. if empty → complete(next_cursor), break                       │
//! │    5. create PageCompletionBarrier(N items)                         │
//! │    6. dispatch items (each holds a PageItemToken)                   │
//! │    7. ── barrier.wait_until_complete() ──────────────────────       │
//! │    8. checkpoint(next_cursor)                                       │
//! │    9. optionally choose_split_point → split_hint                    │
//! │   10. cursor ← next_cursor                                         │
//! │  }                                                                  │
//! │  flush event sink                                                   │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! On error at any step, the loop exits immediately. Checkpoints already
//! persisted are durable. If a terminal call itself fails (`complete`), that
//! terminal method has been attempted and returned an error.
//!
//! # Core invariant
//!
//! **Checkpoint advancement is strictly page-gated.** The cursor is never
//! persisted via [`ProgressSink::checkpoint`] until every item on the current
//! page has been released (success or terminal failure). This prevents the
//! coordinator from believing items are processed when they have not been,
//! which would cause data loss on crash-recovery.
//!
//! The [`PageCompletionBarrier`] / [`PageItemToken`] pair enforces this:
//! tokens are RAII guards that decrement the barrier on drop, so even panics
//! in item processing release the barrier rather than deadlocking the
//! enumeration loop.
//!
//! # Key types
//!
//! | Type | Role |
//! |------|------|
//! | [`ConnectorConfig`] | Tuning knobs (chunk size, budgets, split hints) |
//! | [`ProgressSink`] | Persistence contract for cursor checkpointing and shard lifecycle |
//! | [`ConnectorSource`] | Blanket trait alias for `ConnectorInstance + Send + 'static` |
//! | [`PageCompletionBarrier`] | Mutex+condvar barrier tracking outstanding items per page |
//! | [`PageItemToken`] | RAII guard tying one item's lifecycle to its page barrier |
//! | [`ConnectorRunReport`] | End-of-run statistics (enumeration counters) |
//! | [`ConnectorRunError`] | Error taxonomy covering enumeration, validation, and persistence failures |

use super::engine_stub::BUFFER_LEN_MAX;
use super::engine_trait::{EngineScratch as _, ScanEngine};
use super::metrics::{MetricsSnapshot, WorkerMetricsLocal};
use super::scan_helpers::{
    account_effective_dropped_findings, apply_cross_rule_dedupe,
    emit_findings as shared_emit_findings,
};
use crate::api::FileId;
use crate::unified::events::{DiagnosticEvent, EventSink, ScanEvent};

use gossip_contracts::connector::{
    validate_page, Budgets, ConnectorInstance, Cursor, EnumerateError, ItemKey,
    PageValidationError, ReadError, ScanItem,
};
use gossip_contracts::coordination::ShardSpec;

use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Tuning knobs for a connector pipeline scan.
///
/// Controls chunk geometry, page enumeration budgets, and optional split-hint
/// behavior. All fields have sensible defaults via [`Default`]; callers
/// typically override only the fields relevant to their workload profile.
///
/// Call [`validate`](Self::validate) before use to assert scheduler invariants
/// (positive counts, chunk+overlap within `BUFFER_LEN_MAX`, etc.).
#[derive(Clone, Copy, Debug)]
pub struct ConnectorConfig {
    /// Number of CPU worker threads for scanning.
    ///
    /// **Not yet wired**: the current pipeline processes items synchronously
    /// on the calling thread. This field is validated and reserved for the
    /// upcoming async dispatch implementation. Setting it has no effect on
    /// runtime behavior today.
    pub cpu_workers: usize,
    /// Payload bytes per chunk (excluding overlap region).
    /// The total buffer allocation per chunk is `chunk_size + required_overlap`.
    pub chunk_size: usize,
    /// Page budgets passed to [`EnumerationConnector::enumerate_page`].
    /// Controls max items and max bytes per enumeration call.
    pub page_budgets: Budgets,
    /// Optional budgets for [`EnumerationConnector::choose_split_point`].
    /// When `Some`, a split-hint request is issued after each checkpoint.
    /// When `None`, split-hint logic is skipped entirely.
    pub split_hint_budgets: Option<Budgets>,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            chunk_size: 256 * 1024,
            page_budgets: Budgets::try_new(256, 16 * 1024 * 1024, None)
                .expect("valid default page budgets"),
            split_hint_budgets: Some(
                Budgets::try_new(32, 1024 * 1024, None).expect("valid default split-hint budgets"),
            ),
        }
    }
}

impl ConnectorConfig {
    /// Validate that every field satisfies scheduler invariants.
    ///
    /// Checks that all counts are positive, budget fields are positive,
    /// `chunk_size > required_overlap` (so carry bytes fully satisfy the
    /// engine's cross-chunk overlap requirement), and
    /// `chunk_size + required_overlap <= BUFFER_LEN_MAX` (the engine's hard
    /// buffer cap). `required_overlap` comes from the engine and represents
    /// the minimum overlap needed for cross-chunk pattern matching.
    pub fn validate(&self, required_overlap: usize) -> Result<(), String> {
        if self.cpu_workers == 0 {
            return Err("cpu_workers must be > 0".into());
        }
        if self.chunk_size == 0 {
            return Err("chunk_size must be > 0".into());
        }
        if required_overlap >= self.chunk_size {
            return Err(format!(
                "chunk_size ({}) must be > required_overlap ({}) for correct cross-chunk scanning",
                self.chunk_size, required_overlap
            ));
        }
        if self.page_budgets.max_items() == 0 {
            return Err("page_budgets.max_items must be > 0".into());
        }
        if self.page_budgets.max_bytes() == 0 {
            return Err("page_budgets.max_bytes must be > 0".into());
        }
        if let Some(split) = self.split_hint_budgets {
            if split.max_items() == 0 {
                return Err("split_hint_budgets.max_items must be > 0".into());
            }
            if split.max_bytes() == 0 {
                return Err("split_hint_budgets.max_bytes must be > 0".into());
            }
        }

        let buf_len = required_overlap.saturating_add(self.chunk_size);
        if buf_len > BUFFER_LEN_MAX {
            return Err(format!(
                "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
                self.chunk_size, required_overlap, buf_len, BUFFER_LEN_MAX
            ));
        }
        Ok(())
    }
}

/// Persistence contract for shard progress during a connector scan.
///
/// The pipeline calls these methods in a strict lifecycle order:
///
/// 1. [`shard_spec`](Self::shard_spec) + [`cursor`](Self::cursor) — read once
///    at scan start to establish the shard boundaries and resume point.
/// 2. [`checkpoint`](Self::checkpoint) — called after every page-completion
///    barrier, persisting the cursor that marks the *end* of the completed page.
/// 3. Exactly one terminal transition on success:
///    - [`complete`](Self::complete) — the connector returned an empty terminal
///      page; the shard is fully scanned.
///    - [`park`](Self::park) — the scan yields ownership (e.g., timeout or
///      graceful shutdown) without completing the shard.
///
///    **Current behavior note:** this module currently calls `complete()` on
///    terminal empty pages and does not call `park()`.
///
///    **On error:** the progress sink may have received zero or more
///    `checkpoint` calls before the error. If the error comes from
///    `complete()`, that terminal call was attempted and failed.
/// 4. [`split_hint`](Self::split_hint) — optionally called between checkpoint
///    and the next enumerate, suggesting a key at which the coordinator could
///    split this shard for parallelism.
///
/// Implementations must be idempotent for `checkpoint` and `split_hint` in the
/// presence of retries at the orchestration layer.
pub trait ProgressSink: Send {
    /// Sink-specific persistence or coordination error.
    type Error: std::fmt::Debug + Send + Sync + 'static;

    /// Shard key range owned by this scan attempt.
    fn shard_spec(&self) -> &ShardSpec;
    /// Resume cursor for this scan attempt (initial or last-checkpointed).
    fn cursor(&self) -> Cursor;
    /// Persist progress after every completed page barrier.
    ///
    /// `cursor` is the `next_cursor` returned by the page whose barrier just
    /// cleared. After this returns `Ok`, crash-recovery will resume from this
    /// cursor rather than re-processing the completed page.
    fn checkpoint(&mut self, cursor: &Cursor) -> Result<(), Self::Error>;
    /// Persist terminal completion state (shard fully scanned).
    fn complete(&mut self, final_cursor: &Cursor) -> Result<(), Self::Error>;
    /// Persist parked state when the run yields shard ownership without completing.
    fn park(&mut self) -> Result<(), Self::Error>;
    /// Persist a split-point hint for the coordinator.
    ///
    /// The coordinator may use this key to split the shard into two sub-shards
    /// for increased parallelism. Advisory only — the coordinator is free to
    /// ignore it.
    fn split_hint(&mut self, key: &ItemKey) -> Result<(), Self::Error>;
}

/// Convenience bound: a [`ConnectorInstance`] that is `Send + 'static` so it
/// can be moved into the scheduler's enumeration thread.
///
/// Automatically implemented for any type satisfying the bounds.
pub trait ConnectorSource: ConnectorInstance + Send + 'static {}

impl<T> ConnectorSource for T where T: ConnectorInstance + Send + 'static {}

/// Enumeration-side run statistics accumulated during page-level orchestration.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorEnumerateStats {
    /// Non-empty pages successfully enumerated and processed.
    pub pages_enumerated: u64,
    /// Total items seen across all pages (before any filtering).
    pub items_discovered: u64,
    /// Items dispatched for read/scan processing.
    pub items_enqueued: u64,
    /// Successful [`ProgressSink::checkpoint`] calls.
    pub checkpoints_committed: u64,
    /// Split-hint keys persisted via [`ProgressSink::split_hint`].
    pub split_hints_emitted: u64,
    /// Items that failed with a retryable read error (skipped, eligible for retry).
    pub items_failed_retryable: u64,
    /// Items that failed with a permanent read error (skipped, not retryable).
    pub items_failed_permanent: u64,
}

/// End-of-run report for a connector scan.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorRunReport {
    /// Page-level enumeration counters.
    pub enumerate: ConnectorEnumerateStats,
}

/// Errors that can occur during connector-pipeline execution.
///
/// The generic parameter `E` is the [`ProgressSink::Error`] associated type,
/// so callers see a fully concrete error when the progress backend is known.
///
/// **Partial progress:** When the pipeline returns any of these errors,
/// zero or more pages may have been successfully checkpointed before the
/// failure. The [`ProgressSink`] cursor reflects the last successful
/// checkpoint. If the returned error is [`ConnectorRunError::Progress`], a
/// terminal lifecycle call such as [`ProgressSink::complete`] may have been
/// attempted and failed.
#[derive(Debug)]
pub enum ConnectorRunError<E> {
    /// Connector enumeration or split-hint selection failed.
    Enumerate(EnumerateError),
    /// A returned page violated shard/cursor invariants.
    /// Boxed because [`PageValidationError`] carries diagnostic context.
    PageValidation(Box<PageValidationError>),
    /// The [`ProgressSink`] returned an error from checkpoint, complete, or
    /// split_hint (`park` is part of the trait surface but is not called by
    /// the current run loop).
    Progress(E),
    /// The item dispatch strategy failed (e.g., queue full, worker pool rejection).
    /// Contains a human-readable description of the dispatch failure.
    Dispatch(String),
    /// Page ID counter exceeded `u64::MAX`.
    PageIdOverflow,
    /// A connector returned more items than the configured page budget allows.
    BudgetExceeded {
        /// Number of items the connector actually returned.
        returned: usize,
        /// Maximum allowed by [`Budgets::max_items`].
        limit: usize,
    },
    /// The [`ConnectorConfig`] failed validation.
    Config(String),
    /// Item file ID allocation exceeded `u32::MAX`.
    FileIdOverflow,
}

/// Shared CPU-side chunk runner used by both `open()` and `read_range()` paths.
///
/// Reuses one engine scratch, one temporary findings buffer, and one I/O buffer
/// across all items so connector I/O paths stay allocation-light and produce
/// identical finding semantics regardless of how bytes are fetched.
struct ConnectorCpuRunner<E: ScanEngine> {
    engine: Arc<E>,
    event_sink: Arc<dyn EventSink>,
    scratch: E::Scratch,
    pending: Vec<<E::Scratch as super::engine_trait::EngineScratch>::Finding>,
    buf: Vec<u8>,
    overlap: usize,
    chunk_size: usize,
}

impl<E: ScanEngine> ConnectorCpuRunner<E> {
    fn new(
        engine: Arc<E>,
        event_sink: Arc<dyn EventSink>,
        overlap: usize,
        chunk_size: usize,
    ) -> Self {
        Self {
            scratch: engine.new_scratch(),
            pending: Vec::with_capacity(engine.max_findings_per_chunk()),
            buf: vec![0u8; overlap.saturating_add(chunk_size)],
            engine,
            event_sink,
            overlap,
            chunk_size,
        }
    }

    /// Scan one assembled chunk and emit findings/events with connector parity.
    ///
    /// Associated function (not `&mut self`) to enable split borrows in
    /// [`stream_chunks`](Self::stream_chunks), where `self.buf` is borrowed
    /// mutably for I/O while other fields feed into scan/emit logic.
    ///
    /// # Invariants
    ///
    /// - `base_offset` is the absolute offset of `data[0]`.
    /// - `prefix_len` bytes at the front of `data` are overlap bytes copied from
    ///   the previous chunk; findings that end before `base_offset + prefix_len`
    ///   are dropped to avoid duplicate emission across chunk boundaries.
    /// - Cross-rule dedupe runs after overlap pruning so all connector read paths
    ///   share the same post-processing semantics as local scheduler scans.
    #[allow(clippy::too_many_arguments)] // Split-borrow artifact; private helper only.
    fn scan_chunk_impl(
        engine: &E,
        event_sink: &dyn EventSink,
        scratch: &mut E::Scratch,
        pending: &mut Vec<<E::Scratch as super::engine_trait::EngineScratch>::Finding>,
        item: &ScanItem,
        file_id: FileId,
        base_offset: u64,
        prefix_len: usize,
        data: &[u8],
        metrics: &mut WorkerMetricsLocal,
    ) {
        engine.scan_chunk_into(data, file_id, base_offset, scratch);
        let engine_dropped = scratch.dropped_findings();

        // The copied prefix belongs to the previous chunk. Any finding fully
        // before `new_bytes_start` has already been eligible for emission there.
        let new_bytes_start = base_offset.saturating_add(prefix_len as u64);
        let before_prefix = scratch.pending_findings_len();
        scratch.drop_prefix_findings(new_bytes_start);
        let after_prefix = scratch.pending_findings_len();

        pending.clear();
        scratch.drain_findings_into(pending);
        let dedupe_removed = apply_cross_rule_dedupe(pending, engine);
        let scheduler_pruned = before_prefix
            .saturating_sub(after_prefix)
            .saturating_add(dedupe_removed);
        account_effective_dropped_findings(metrics, engine_dropped, scheduler_pruned);

        metrics.findings_emitted = metrics
            .findings_emitted
            .saturating_add(pending.len() as u64);
        shared_emit_findings(engine, event_sink, item_display_bytes(item), pending);

        let payload = data.len().saturating_sub(prefix_len);
        metrics.chunks_scanned = metrics.chunks_scanned.saturating_add(1);
        metrics.bytes_scanned = metrics.bytes_scanned.saturating_add(payload as u64);
    }

    /// Unified overlap-aware chunking loop, parameterized by an I/O closure.
    ///
    /// `read_fn(offset, dst)` fills `dst` with payload bytes starting at
    /// the given absolute offset and returns the byte count. Returning 0
    /// signals EOF. The loop preserves `self.overlap` bytes from the tail
    /// of each chunk as a prefix for the next, so cross-chunk pattern matches
    /// are visible to the scan engine.
    fn stream_chunks<F>(
        &mut self,
        item: &ScanItem,
        file_id: FileId,
        metrics: &mut WorkerMetricsLocal,
        mut read_fn: F,
    ) -> Result<(), ReadError>
    where
        F: FnMut(u64, &mut [u8]) -> Result<usize, ReadError>,
    {
        let overlap = self.overlap;
        let chunk_size = self.chunk_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;

        loop {
            if carry > 0 && have > 0 {
                debug_assert!(
                    have >= carry,
                    "overlap carry ({carry}) exceeds buffer fill ({have})"
                );
                // Preserve trailing overlap so cross-chunk matches are still visible.
                self.buf.copy_within(have - carry..have, 0);
            }

            let n = read_fn(offset, &mut self.buf[carry..carry + chunk_size])?;
            if n == 0 {
                break;
            }

            let len = carry + n;
            let base_offset = offset.saturating_sub(carry as u64);
            Self::scan_chunk_impl(
                &self.engine,
                &*self.event_sink,
                &mut self.scratch,
                &mut self.pending,
                item,
                file_id,
                base_offset,
                carry,
                &self.buf[..len],
                metrics,
            );

            offset = offset.saturating_add(n as u64);
            have = len;
            carry = overlap.min(len);
        }
        Ok(())
    }

    /// Read and scan an item using the connector's advertised capabilities.
    ///
    /// Dispatches to `read_range()` when available (random-access path) or
    /// falls back to `open()` (sequential reader). Both paths share the same
    /// overlap-aware chunking loop via [`stream_chunks`](Self::stream_chunks).
    fn stream_item<C: ConnectorSource + ?Sized>(
        &mut self,
        connector: &mut C,
        item: &ScanItem,
        file_id: FileId,
        metrics: &mut WorkerMetricsLocal,
    ) -> Result<(), ReadError> {
        let budgets = item_read_budgets();
        if connector.caps().range_read {
            let item_ref = item.item_ref();
            self.stream_chunks(item, file_id, metrics, |offset, dst| {
                let n = connector.read_range(item_ref, offset, dst, budgets)?;
                if n > dst.len() {
                    return Err(ReadError::permanent(format!(
                        "connector read_range returned {} bytes for {}-byte buffer",
                        n,
                        dst.len()
                    )));
                }
                Ok(n)
            })
        } else {
            let mut reader = connector.open(item.item_ref(), budgets)?;
            self.stream_chunks(item, file_id, metrics, |_offset, dst| {
                read_some(reader.as_mut(), dst).map_err(read_error_from_io)
            })
        }
    }
}

#[inline]
fn item_display_bytes(item: &ScanItem) -> &[u8] {
    item.location()
        .map(|loc| loc.display().as_bytes())
        .unwrap_or_else(|| item.item_key().as_bytes())
}

/// Maximum consecutive EINTR retries before surfacing as an error.
/// 1024 is generous enough for real signal storms while preventing infinite loops.
const MAX_EINTR_RETRIES: usize = 1024;

#[inline]
fn read_some(reader: &mut dyn io::Read, dst: &mut [u8]) -> io::Result<usize> {
    // Treat EINTR as a transient kernel interruption, not connector failure.
    for _ in 0..MAX_EINTR_RETRIES {
        match reader.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Interrupted,
        format!("exceeded {MAX_EINTR_RETRIES} consecutive EINTR retries"),
    ))
}

/// Convert `std::io::Error` into connector contract error classes.
///
/// Classifying deterministic input/state failures as permanent prevents useless
/// retries, while transport/transient kinds remain retryable for higher layers.
fn read_error_from_io(err: io::Error) -> ReadError {
    let msg = format!("connector reader failed: {err}");
    match err.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::InvalidInput
        | io::ErrorKind::InvalidData
        | io::ErrorKind::Unsupported => ReadError::permanent(msg),
        _ => ReadError::retryable(msg),
    }
}

/// Permissive budget for item-level reads.
///
/// Enumeration budgets (max_items, max_bytes) are semantically bound to
/// page listing, not individual payload IO. Item reads should be capped
/// only by the orchestration layer's size-bounded/deadline-aware adapter
/// (per the ReadConnector trait contract), so we pass the widest advisory
/// hint to avoid any connector misinterpreting a tight enumeration budget
/// as a read cap.
fn item_read_budgets() -> Budgets {
    Budgets::try_new(1, u64::MAX, None).expect("valid item-read budgets")
}

/// Emit one warning diagnostic for an item-level read error.
///
/// Includes retry class and stable item key so operators can distinguish noisy
/// transient failures from deterministic configuration/data problems.
fn emit_read_error_diagnostic(event_sink: &dyn EventSink, item: &ScanItem, err: &ReadError) {
    let msg = format!(
        "connector read {} error for item {}: {}",
        err.class(),
        item.item_key(),
        err.message()
    );
    event_sink.emit(ScanEvent::Diagnostic(DiagnosticEvent {
        level: "warn",
        message: &msg,
    }));
}

/// Monotonically increasing page identifier within a single scan run.
#[cfg(feature = "bench")]
pub(super) type PageId = u64;
#[cfg(not(feature = "bench"))]
type PageId = u64;

/// Barrier that blocks checkpoint advancement until every item on a page
/// reaches a terminal state (success or handled item failure).
///
/// The enumeration loop creates one barrier per non-empty page, seeded with
/// `outstanding_items == item_count`. Each dispatched item holds a
/// [`PageItemToken`] whose drop path decrements the counter. The enumeration
/// thread calls [`wait_until_complete`](Self::wait_until_complete), which
/// parks on the condvar until the counter hits zero.
///
/// # Poison recovery
///
/// All lock acquisitions use [`lock_or_recover`](Self::lock_or_recover),
/// which recovers from mutex poison rather than panicking.
///
/// **Safety justification**: `PageCompletionState` contains only a `usize`
/// counter (`outstanding_items`) that is monotonically decremented. There are
/// no complex invariants a partial update could violate — the worst case is a
/// stale count, which the barrier will still drain correctly. The alternative
/// (propagating the panic) would deadlock the enumeration loop, which is
/// strictly worse than continuing with a recovered counter.
#[derive(Debug)]
#[cfg_attr(feature = "bench", allow(dead_code))]
pub(super) struct PageCompletionBarrier {
    page_id: PageId,
    state: Mutex<PageCompletionState>,
    cv: Condvar,
}

#[derive(Debug)]
struct PageCompletionState {
    /// Count of items that have not yet reached a terminal state.
    /// Monotonically decreases from `item_count` to 0.
    outstanding_items: usize,
}

impl PageCompletionBarrier {
    /// Create a new barrier expecting `outstanding_items` releases before
    /// `wait_until_complete` unblocks. Returned inside an `Arc` because
    /// both the enumeration thread and item tokens share ownership.
    pub(super) fn new(page_id: PageId, outstanding_items: usize) -> Arc<Self> {
        Arc::new(Self {
            page_id,
            state: Mutex::new(PageCompletionState { outstanding_items }),
            cv: Condvar::new(),
        })
    }

    /// Lock state with poison recovery.
    ///
    /// If the mutex was poisoned by a panic in another thread, we recover
    /// the inner state and continue. `PageCompletionState` holds only a
    /// `usize` counter — no complex invariants a partial update could
    /// violate. The alternative (propagating the panic) would deadlock the
    /// enumeration loop.
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, PageCompletionState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!(
                    "[connector] page {} barrier mutex poisoned, recovering",
                    self.page_id
                );
                poisoned.into_inner()
            }
        }
    }

    /// Block the calling thread until every item token has been released.
    /// Called by the enumeration loop after dispatching a page's items.
    ///
    /// Uses a 60-second diagnostic interval: if the barrier hasn't drained
    /// within that window, a warning is logged and the wait resumes.
    pub(super) fn wait_until_complete(&self) {
        let timeout = Duration::from_secs(60);
        let mut state = self.lock_or_recover();
        while state.outstanding_items > 0 {
            let (guard, wait_result) = match self.cv.wait_timeout(state, timeout) {
                Ok(result) => result,
                Err(poisoned) => {
                    eprintln!(
                        "[connector] page {} barrier condvar poisoned, recovering",
                        self.page_id
                    );
                    poisoned.into_inner()
                }
            };
            state = guard;
            if wait_result.timed_out() && state.outstanding_items > 0 {
                eprintln!(
                    "page {} barrier: still waiting for {} outstanding items",
                    self.page_id, state.outstanding_items
                );
            }
        }
    }

    /// Decrement the outstanding counter by one. When it reaches zero, wake
    /// the enumeration thread blocked in `wait_until_complete`.
    ///
    /// The `assert` catches double-release bugs unconditionally; the
    /// subtraction would also panic on underflow (overflow-checks=true)
    /// but the assertion provides a clearer diagnostic.
    pub(super) fn release_item(&self) {
        let mut state = self.lock_or_recover();
        assert!(
            state.outstanding_items > 0,
            "page {} outstanding counter underflow",
            self.page_id
        );
        state.outstanding_items -= 1;
        if state.outstanding_items == 0 {
            self.cv.notify_all();
        }
    }

    #[cfg(test)]
    fn outstanding_items(&self) -> usize {
        self.lock_or_recover().outstanding_items
    }
}

/// RAII guard tying one item's lifecycle to its page's completion barrier.
///
/// Holding a token keeps the barrier's outstanding count positive, which
/// prevents the enumeration loop from advancing past this page. Calling
/// [`complete`](Self::complete) or dropping the token releases the item.
///
/// The `active` flag ensures exactly-once release: explicit `complete()` sets
/// it to `false`, so the subsequent `Drop` is a no-op.
#[derive(Debug)]
pub(super) struct PageItemToken {
    barrier: Arc<PageCompletionBarrier>,
    /// `true` until this token has been released (via `complete` or `drop`).
    active: bool,
}

impl PageItemToken {
    pub(super) fn new(barrier: &Arc<PageCompletionBarrier>) -> Self {
        Self {
            barrier: Arc::clone(barrier),
            active: true,
        }
    }

    /// Mark this item as terminally resolved (success or handled failure).
    /// Releases the barrier's outstanding count.
    pub(super) fn complete(mut self) {
        self.release();
    }

    fn release(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.barrier.release_item();
    }
}

/// Safety net: if the token is dropped without an explicit `complete()` call
/// (e.g., due to a panic in item processing), the barrier is still released.
/// This prevents the enumeration loop from deadlocking on a stuck barrier.
impl Drop for PageItemToken {
    fn drop(&mut self) {
        self.release();
    }
}

/// Connector-native scheduler entrypoint.
///
/// Page-level orchestration runs in a strict order:
/// 1. Enumerate one connector page from the current cursor.
/// 2. Validate page invariants against the shard and cursor.
/// 3. Record page items as enqueued/processed.
/// 4. Wait at the page completion barrier.
/// 5. Checkpoint progress at `next_cursor`.
/// 6. Optionally emit a split hint.
/// 7. Repeat until a terminal empty page, then call `complete`.
///
/// # Errors
///
/// - [`ConnectorRunError::Config`] if [`ConnectorConfig::validate`] fails.
/// - [`ConnectorRunError::Enumerate`] if enumeration or split-hint selection fails.
/// - [`ConnectorRunError::PageValidation`] if a connector returns an invalid page.
/// - [`ConnectorRunError::BudgetExceeded`] if a page returns more items than the budget allows.
/// - [`ConnectorRunError::Dispatch`] if the item dispatch strategy fails.
/// - [`ConnectorRunError::Progress`] if checkpoint/complete/split-hint persistence fails.
/// - [`ConnectorRunError::PageIdOverflow`] if more than `u64::MAX` pages are enumerated.
/// - [`ConnectorRunError::FileIdOverflow`] if item `FileId` allocation exceeds `u32::MAX`.
pub fn scan_connector<E, C, P>(
    engine: Arc<E>,
    connector: &mut C,
    cfg: ConnectorConfig,
    progress: &mut P,
    event_sink: Arc<dyn EventSink>,
) -> Result<(ConnectorRunReport, MetricsSnapshot), ConnectorRunError<P::Error>>
where
    E: ScanEngine,
    C: ConnectorSource + ?Sized,
    P: ProgressSink + ?Sized,
{
    let overlap = engine.required_overlap();
    let dispatch_sink = Arc::clone(&event_sink);
    let mut cpu_runner = ConnectorCpuRunner::new(
        Arc::clone(&engine),
        Arc::clone(&dispatch_sink),
        overlap,
        cfg.chunk_size,
    );
    let mut worker_metrics = WorkerMetricsLocal::new();
    let mut next_file_id: u32 = 0;

    let (mut report, _) = scan_connector_with_page_dispatch(
        engine,
        connector,
        cfg,
        progress,
        event_sink,
        |_page_id, connector, items, item_tokens| {
            for (item, token) in items.iter().zip(item_tokens) {
                let file_id = FileId(next_file_id);
                next_file_id = next_file_id
                    .checked_add(1)
                    .ok_or(ConnectorRunError::FileIdOverflow)?;

                if let Err(read_err) =
                    cpu_runner.stream_item(connector, item, file_id, &mut worker_metrics)
                {
                    worker_metrics.io_errors = worker_metrics.io_errors.saturating_add(1);
                    if read_err.is_retryable() {
                        worker_metrics.items_failed_retryable =
                            worker_metrics.items_failed_retryable.saturating_add(1);
                    } else {
                        worker_metrics.items_failed_permanent =
                            worker_metrics.items_failed_permanent.saturating_add(1);
                    }
                    emit_read_error_diagnostic(&*dispatch_sink, item, &read_err);
                }

                token.complete();
            }
            Ok(())
        },
    )?;

    report.enumerate.items_failed_retryable = worker_metrics.items_failed_retryable;
    report.enumerate.items_failed_permanent = worker_metrics.items_failed_permanent;

    let mut metrics = MetricsSnapshot::new();
    metrics.merge_worker(&worker_metrics);
    Ok((report, metrics))
}

/// Inner loop parameterized by a page-dispatch strategy.
///
/// `dispatch_page_items` receives each page's connector handle, items, and
/// completion tokens. The public [`scan_connector`] uses this hook to execute
/// connector item reads/chunk scans while tests inject custom dispatch logic
/// to exercise the barrier under concurrent release patterns.
///
/// The loop body follows the flow documented in the module-level docs:
/// enumerate -> validate -> dispatch -> barrier -> checkpoint -> split-hint.
fn scan_connector_with_page_dispatch<E, C, P, D>(
    engine: Arc<E>,
    connector: &mut C,
    cfg: ConnectorConfig,
    progress: &mut P,
    event_sink: Arc<dyn EventSink>,
    mut dispatch_page_items: D,
) -> Result<(ConnectorRunReport, MetricsSnapshot), ConnectorRunError<P::Error>>
where
    E: ScanEngine,
    C: ConnectorSource + ?Sized,
    P: ProgressSink + ?Sized,
    D: FnMut(
        PageId,
        &mut C,
        &[ScanItem],
        Vec<PageItemToken>,
    ) -> Result<(), ConnectorRunError<P::Error>>,
{
    cfg.validate(engine.required_overlap())
        .map_err(ConnectorRunError::Config)?;

    let mut report = ConnectorRunReport::default();
    let mut cursor = progress.cursor();
    let shard = progress.shard_spec().clone();
    let mut next_page_id: PageId = 0;

    let result = (|| {
        loop {
            // Step 1: fetch one page of items from the connector.
            let page = connector
                .enumerate_page(&shard, &cursor, cfg.page_budgets)
                .map_err(ConnectorRunError::Enumerate)?;
            let (items, next_cursor) = page.into_parts();

            // Step 1b: enforce hard page-size limit (budgets are advisory).
            let budget_limit = cfg.page_budgets.max_items();
            if items.len() > budget_limit {
                return Err(ConnectorRunError::BudgetExceeded {
                    returned: items.len(),
                    limit: budget_limit,
                });
            }

            // Step 2: reject invalid pages *before* any state mutation.
            validate_page(&shard, &cursor, &items, &next_cursor)
                .map_err(|err| ConnectorRunError::PageValidation(Box::new(err)))?;

            // Step 3: an empty page is the connector's terminal signal.
            if items.is_empty() {
                progress
                    .complete(&next_cursor)
                    .map_err(ConnectorRunError::Progress)?;
                break;
            }

            let page_id = next_page_id;
            next_page_id = next_page_id
                .checked_add(1)
                .ok_or(ConnectorRunError::PageIdOverflow)?;

            // Step 4-5: create barrier + tokens and hand items to the dispatch strategy.
            let (page_barrier, page_tokens) = track_page_items(page_id, items.len());
            record_page_enqueue_and_processing(&items, &mut report);
            dispatch_page_items(page_id, connector, &items, page_tokens)?;

            // Step 6: block until every token is released (the core invariant).
            wait_for_page_completion_barrier(page_barrier.as_ref());

            // Step 7: safe to persist — all items on this page are terminal.
            progress
                .checkpoint(&next_cursor)
                .map_err(ConnectorRunError::Progress)?;
            report.enumerate.checkpoints_committed =
                report.enumerate.checkpoints_committed.saturating_add(1);

            // Step 8: optionally ask the connector for a shard split suggestion.
            if let Some(split_budgets) = cfg.split_hint_budgets {
                let split_key = connector
                    .choose_split_point(&shard, &next_cursor, split_budgets)
                    .map_err(ConnectorRunError::Enumerate)?;
                if let Some(split_key) = split_key {
                    progress
                        .split_hint(&split_key)
                        .map_err(ConnectorRunError::Progress)?;
                    report.enumerate.split_hints_emitted =
                        report.enumerate.split_hints_emitted.saturating_add(1);
                }
            }

            // Step 9: advance cursor for the next iteration.
            cursor = next_cursor;
        }
        Ok(())
    })();

    // Flush buffered events regardless of success or failure so that
    // events from completed pages are never silently dropped.
    event_sink.flush();

    result.map(|()| (report, MetricsSnapshot::default()))
}

/// Create a barrier seeded with `item_count` and one token per item.
/// The barrier and tokens share ownership via `Arc`, so either side can
/// outlive the other without use-after-free.
pub(super) fn track_page_items(
    page_id: PageId,
    item_count: usize,
) -> (Arc<PageCompletionBarrier>, Vec<PageItemToken>) {
    let barrier = PageCompletionBarrier::new(page_id, item_count);
    let tokens = (0..item_count)
        .map(|_| PageItemToken::new(&barrier))
        .collect();
    (barrier, tokens)
}

/// Bump enumeration counters for the items on this page.
fn record_page_enqueue_and_processing(items: &[ScanItem], report: &mut ConnectorRunReport) {
    let item_count = items.len() as u64;
    report.enumerate.pages_enumerated = report.enumerate.pages_enumerated.saturating_add(1);
    report.enumerate.items_discovered =
        report.enumerate.items_discovered.saturating_add(item_count);
    report.enumerate.items_enqueued = report.enumerate.items_enqueued.saturating_add(item_count);
}

/// Block until the page barrier drains. This is the enforcement point for
/// the module's core invariant: checkpoint is never persisted until every
/// item on the page has been resolved.
fn wait_for_page_completion_barrier(page_barrier: &PageCompletionBarrier) {
    page_barrier.wait_until_complete();
}

#[cfg(test)]
#[path = "connector_pipeline_tests.rs"]
mod tests;
