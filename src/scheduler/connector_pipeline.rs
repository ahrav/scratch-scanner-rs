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
//! Item-level read/chunk/scan execution is intentionally stubbed: the current
//! [`scan_connector`] immediately completes every item token synchronously.
//! Future work will hand tokens off to I/O and CPU worker pools.
//!
//! # High-level flow
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │  loop {                                                             │
//! │    1. enumerate_page(shard, cursor, budgets)                        │
//! │    2. validate_page(shard, cursor, items, next_cursor)              │
//! │    3. if empty → complete(next_cursor), break                       │
//! │    4. create PageCompletionBarrier(N items)                         │
//! │    5. dispatch items (each holds a PageItemToken)                   │
//! │    6. ── barrier.wait_until_complete() ──────────────────────       │
//! │    7. checkpoint(next_cursor)                                       │
//! │    8. optionally choose_split_point → split_hint                    │
//! │    9. cursor ← next_cursor                                         │
//! │  }                                                                  │
//! │  flush event sink                                                   │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! On error at any step, the loop exits immediately. Checkpoints already
//! persisted are durable; no terminal transition (complete/park) is called.
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
use super::engine_trait::ScanEngine;
use super::metrics::MetricsSnapshot;
use crate::unified::events::EventSink;

use gossip_contracts::connector::{
    validate_page, Budgets, ConnectorInstance, Cursor, EnumerateError, ItemKey,
    PageValidationError, ScanItem,
};
use gossip_contracts::coordination::ShardSpec;

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
    /// Checks that all counts are positive, budget fields are positive, and
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
///    **On error:** If the pipeline returns `Err`, no terminal transition is
///    called. The progress sink may have received zero or more `checkpoint`
///    calls before the error. The coordinator must treat the absence of a
///    terminal transition as an implicit failure and handle accordingly
///    (e.g., re-assign the shard from the last-checkpointed cursor).
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
/// checkpoint. No terminal lifecycle transition ([`ProgressSink::complete`]
/// or [`ProgressSink::park`]) is called on error paths.
#[derive(Debug)]
pub enum ConnectorRunError<E> {
    /// Connector enumeration or split-hint selection failed.
    Enumerate(EnumerateError),
    /// A returned page violated shard/cursor invariants.
    /// Boxed because [`PageValidationError`] carries diagnostic context.
    PageValidation(Box<PageValidationError>),
    /// The [`ProgressSink`] returned an error from checkpoint, complete,
    /// park, or split_hint.
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
}

/// Monotonically increasing page identifier within a single scan run.
type PageId = u64;

/// Barrier that blocks checkpoint advancement until every item on a page
/// reaches a terminal state (success or permanent failure).
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
/// which absorbs mutex poison rather than propagating it. This is deliberate:
/// a panic in one item's processing must not prevent the barrier from draining,
/// because a stuck barrier would deadlock the entire enumeration loop.
#[derive(Debug)]
struct PageCompletionBarrier {
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
    fn new(page_id: PageId, outstanding_items: usize) -> Arc<Self> {
        Arc::new(Self {
            page_id,
            state: Mutex::new(PageCompletionState { outstanding_items }),
            cv: Condvar::new(),
        })
    }

    /// Acquire the inner mutex, absorbing poison to avoid cascading panics.
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, PageCompletionState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Block the calling thread until every item token has been released.
    /// Called by the enumeration loop after dispatching a page's items.
    ///
    /// Uses a 60-second diagnostic interval: if the barrier hasn't drained
    /// within that window, a warning is logged and the wait resumes.
    fn wait_until_complete(&self) {
        let timeout = Duration::from_secs(60);
        let mut state = self.lock_or_recover();
        while state.outstanding_items > 0 {
            let (guard, wait_result) = match self.cv.wait_timeout(state, timeout) {
                Ok(tuple) => tuple,
                Err(poisoned) => {
                    let (guard, wait_result) = poisoned.into_inner();
                    (guard, wait_result)
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
    /// The `debug_assert` catches double-release bugs in tests; in release
    /// builds the subtraction panics on underflow (overflow-checks=true).
    fn release_item(&self) {
        let mut state = self.lock_or_recover();
        debug_assert!(
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
struct PageItemToken {
    barrier: Arc<PageCompletionBarrier>,
    /// `true` until this token has been released (via `complete` or `drop`).
    active: bool,
}

impl PageItemToken {
    fn new(barrier: &Arc<PageCompletionBarrier>) -> Self {
        Self {
            barrier: Arc::clone(barrier),
            active: true,
        }
    }

    /// Mark this item as terminally resolved (success or permanent failure).
    /// Releases the barrier's outstanding count.
    fn complete(mut self) {
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
/// This function currently owns **page** lifecycle semantics. Item-level read/chunk
/// execution is intentionally delegated to follow-up tasks.
///
/// # Errors
///
/// - [`ConnectorRunError::Enumerate`] if enumeration or split-hint selection fails.
/// - [`ConnectorRunError::PageValidation`] if a connector returns an invalid page.
/// - [`ConnectorRunError::Progress`] if checkpoint/complete/split-hint persistence fails.
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
    scan_connector_with_page_dispatch(
        engine,
        connector,
        cfg,
        progress,
        event_sink,
        |_page_id, _items, item_tokens| {
            // Current page processing is synchronous; future connector read/chunk
            // work transfers these tokens to async item workers.
            for token in item_tokens {
                token.complete();
            }
            Ok(())
        },
    )
}

/// Inner loop parameterized by a page-dispatch strategy.
///
/// `dispatch_page_items` receives each page's items and their completion
/// tokens. The public [`scan_connector`] passes a closure that immediately
/// completes all tokens (synchronous stub). Tests inject custom dispatch
/// logic to exercise the barrier under concurrent release patterns.
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
    D: FnMut(PageId, &[ScanItem], Vec<PageItemToken>) -> Result<(), ConnectorRunError<P::Error>>,
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
            dispatch_page_items(page_id, &items, page_tokens)?;

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
fn track_page_items(
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
mod tests {
    use super::*;
    use crate::scheduler::engine_stub::{MockEngine, MockRule};
    use crate::unified::events::VecEventSink;

    use gossip_contracts::connector::{
        ConnectorCapabilities, EnumerationConnector, EnumerationPage, ItemRef, ReadConnector,
        ReadError, ScanItem, VersionId,
    };
    use gossip_contracts::coordination::ShardSpec;
    use gossip_contracts::identity::{ObjectVersionId, StableItemId};

    use rstest::rstest;

    use std::collections::VecDeque;
    use std::io;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ProgressCall {
        Checkpoint(Cursor),
        SplitHint(ItemKey),
        Complete(Cursor),
    }

    struct MockProgress {
        shard: ShardSpec,
        cursor: Cursor,
        calls: Vec<ProgressCall>,
        fail_checkpoint: bool,
        checkpoint_notifier: Option<mpsc::Sender<Cursor>>,
    }

    impl MockProgress {
        fn new(shard: ShardSpec, cursor: Cursor) -> Self {
            Self {
                shard,
                cursor,
                calls: Vec::new(),
                fail_checkpoint: false,
                checkpoint_notifier: None,
            }
        }

        fn with_checkpoint_failure(mut self) -> Self {
            self.fail_checkpoint = true;
            self
        }

        fn with_checkpoint_notifier(mut self, notifier: mpsc::Sender<Cursor>) -> Self {
            self.checkpoint_notifier = Some(notifier);
            self
        }
    }

    impl ProgressSink for MockProgress {
        type Error = &'static str;

        fn shard_spec(&self) -> &ShardSpec {
            &self.shard
        }

        fn cursor(&self) -> Cursor {
            self.cursor.clone()
        }

        fn checkpoint(&mut self, cursor: &Cursor) -> Result<(), Self::Error> {
            if self.fail_checkpoint {
                return Err("checkpoint failed");
            }
            self.cursor = cursor.clone();
            self.calls.push(ProgressCall::Checkpoint(cursor.clone()));
            if let Some(notifier) = &self.checkpoint_notifier {
                let _ = notifier.send(cursor.clone());
            }
            Ok(())
        }

        fn complete(&mut self, final_cursor: &Cursor) -> Result<(), Self::Error> {
            self.cursor = final_cursor.clone();
            self.calls
                .push(ProgressCall::Complete(final_cursor.clone()));
            Ok(())
        }

        fn park(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn split_hint(&mut self, key: &ItemKey) -> Result<(), Self::Error> {
            self.calls.push(ProgressCall::SplitHint(key.clone()));
            Ok(())
        }
    }

    struct MockConnector {
        pages: VecDeque<Result<EnumerationPage, EnumerateError>>,
        split_hints: VecDeque<Result<Option<ItemKey>, EnumerateError>>,
    }

    impl MockConnector {
        fn new(pages: Vec<EnumerationPage>) -> Self {
            Self {
                pages: pages.into_iter().map(Ok).collect(),
                split_hints: VecDeque::new(),
            }
        }

        fn with_split_hints(mut self, hints: Vec<Option<ItemKey>>) -> Self {
            self.split_hints = hints.into_iter().map(Ok).collect();
            self
        }
    }

    impl EnumerationConnector for MockConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }

        fn enumerate_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            self.pages
                .pop_front()
                .unwrap_or_else(|| Ok(EnumerationPage::new(Vec::new(), Cursor::initial())))
        }

        fn choose_split_point(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<ItemKey>, EnumerateError> {
            self.split_hints.pop_front().unwrap_or(Ok(None))
        }
    }

    impl ReadConnector for MockConnector {
        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::unsupported("open"))
        }
    }

    fn test_engine(overlap: usize) -> MockEngine {
        MockEngine::new(
            vec![MockRule {
                name: "secret".to_string(),
                pattern: b"SECRET".to_vec(),
            }],
            overlap,
        )
    }

    fn item(key: &[u8], stable_fill: u8, version: &[u8]) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(key).unwrap(),
            ItemRef::try_from_slice(key).unwrap(),
            StableItemId::from_bytes([stable_fill; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(version)),
        )
    }

    #[test]
    fn scan_connector_enumerates_validates_checkpoints_and_completes() {
        let shard = ShardSpec::unbounded();
        let k2 = ItemKey::try_from_slice(b"k2").unwrap();
        let k3 = ItemKey::try_from_slice(b"k3").unwrap();

        let pages = vec![
            EnumerationPage::new(
                vec![item(b"k1", 1, b"v1"), item(b"k2", 2, b"v2")],
                Cursor::with_last_key(k2.clone()),
            ),
            EnumerationPage::new(
                vec![item(b"k3", 3, b"v3")],
                Cursor::with_last_key(k3.clone()),
            ),
            EnumerationPage::new(Vec::new(), Cursor::with_last_key(k3.clone())),
        ];
        let mut connector = MockConnector::new(pages).with_split_hints(vec![
            Some(ItemKey::try_from_slice(b"split-a").unwrap()),
            Some(ItemKey::try_from_slice(b"split-b").unwrap()),
        ]);
        let mut progress = MockProgress::new(shard.clone(), Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let cfg = ConnectorConfig {
            split_hint_budgets: Some(Budgets::try_new(1, 1024, None).unwrap()),
            ..ConnectorConfig::default()
        };
        let (report, metrics) = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            cfg,
            &mut progress,
            sink,
        )
        .unwrap();

        assert_eq!(report.enumerate.pages_enumerated, 2);
        assert_eq!(report.enumerate.items_discovered, 3);
        assert_eq!(report.enumerate.items_enqueued, 3);
        assert_eq!(report.enumerate.checkpoints_committed, 2);
        assert_eq!(report.enumerate.split_hints_emitted, 2);
        assert_eq!(metrics.tasks_executed, 0);

        assert_eq!(
            progress.calls,
            vec![
                ProgressCall::Checkpoint(Cursor::with_last_key(k2)),
                ProgressCall::SplitHint(ItemKey::try_from_slice(b"split-a").unwrap()),
                ProgressCall::Checkpoint(Cursor::with_last_key(k3.clone())),
                ProgressCall::SplitHint(ItemKey::try_from_slice(b"split-b").unwrap()),
                ProgressCall::Complete(Cursor::with_last_key(k3)),
            ]
        );
    }

    #[test]
    fn scan_connector_rejects_invalid_page_before_checkpointing() {
        let shard = ShardSpec::with_range(b"a", b"z");
        let bad_page = EnumerationPage::new(vec![item(b"b", 1, b"v1")], Cursor::initial());
        let mut connector = MockConnector::new(vec![bad_page]);
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let err = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            ConnectorConfig::default(),
            &mut progress,
            sink,
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorRunError::PageValidation(_)));
        assert!(progress.calls.is_empty());
    }

    #[test]
    fn scan_connector_maps_checkpoint_error_to_progress_error() {
        let shard = ShardSpec::unbounded();
        let k1 = ItemKey::try_from_slice(b"k1").unwrap();
        let pages = vec![
            EnumerationPage::new(vec![item(b"k1", 1, b"v1")], Cursor::with_last_key(k1)),
            EnumerationPage::new(
                Vec::new(),
                Cursor::with_last_key(ItemKey::try_from_slice(b"k1").unwrap()),
            ),
        ];
        let mut connector = MockConnector::new(pages);
        let mut progress = MockProgress::new(shard, Cursor::initial()).with_checkpoint_failure();
        let sink = Arc::new(VecEventSink::new());

        let err = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            ConnectorConfig::default(),
            &mut progress,
            sink,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ConnectorRunError::Progress("checkpoint failed")
        ));
        assert!(progress.calls.is_empty());
    }

    #[test]
    fn page_tokens_track_page_id_and_outstanding_items() {
        let (barrier, tokens) = track_page_items(7, 2);
        assert_eq!(barrier.page_id, 7);
        assert_eq!(barrier.outstanding_items(), 2);
        assert!(tokens.iter().all(|token| token.barrier.page_id == 7));

        let mut tokens = tokens.into_iter();
        tokens.next().unwrap().complete();
        assert_eq!(barrier.outstanding_items(), 1);

        tokens.next().unwrap().complete();
        assert_eq!(barrier.outstanding_items(), 0);
    }

    #[test]
    fn scan_connector_waits_for_page_completion_before_checkpoint() {
        let shard = ShardSpec::unbounded();
        let page_key = ItemKey::try_from_slice(b"k1").unwrap();
        let checkpoint_cursor = Cursor::with_last_key(page_key.clone());

        let pages = vec![
            EnumerationPage::new(
                vec![item(b"k1", 1, b"v1")],
                Cursor::with_last_key(page_key.clone()),
            ),
            EnumerationPage::new(Vec::new(), checkpoint_cursor.clone()),
        ];

        let (dispatch_started_tx, dispatch_started_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (checkpoint_tx, checkpoint_rx) = mpsc::channel::<Cursor>();
        let (done_tx, done_rx) = mpsc::channel();

        let _scan_worker = thread::spawn(move || {
            let mut connector = MockConnector::new(pages);
            let mut progress =
                MockProgress::new(shard, Cursor::initial()).with_checkpoint_notifier(checkpoint_tx);
            let sink = Arc::new(VecEventSink::new());
            let mut release_rx = Some(release_rx);

            let result = scan_connector_with_page_dispatch(
                Arc::new(test_engine(16)),
                &mut connector,
                ConnectorConfig::default(),
                &mut progress,
                sink,
                move |page_id, items, tokens| {
                    assert_eq!(page_id, 0);
                    assert_eq!(items.len(), tokens.len());
                    assert!(tokens.iter().all(|token| token.barrier.page_id == page_id));
                    dispatch_started_tx.send(()).unwrap();

                    let release_rx = release_rx.take().expect("single non-empty page expected");
                    let _token_worker = thread::spawn(move || {
                        release_rx.recv().expect("release signal dropped");
                        for token in tokens {
                            token.complete();
                        }
                    });
                    Ok(())
                },
            )
            .map(|_| progress.calls);
            done_tx.send(result).unwrap();
        });

        dispatch_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("page dispatch did not start");
        assert!(matches!(
            checkpoint_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        release_tx.send(()).expect("failed to release page tokens");
        let calls = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("scan_connector did not finish (possible barrier deadlock)")
            .expect("scan_connector returned error");
        let observed_checkpoint = checkpoint_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("checkpoint not emitted");

        assert_eq!(observed_checkpoint, checkpoint_cursor);
        assert_eq!(
            calls,
            vec![
                ProgressCall::Checkpoint(checkpoint_cursor.clone()),
                ProgressCall::Complete(checkpoint_cursor),
            ]
        );
    }

    #[test]
    fn scan_connector_releases_page_barrier_on_terminal_failure() {
        let shard = ShardSpec::unbounded();
        let last_key = ItemKey::try_from_slice(b"k2").unwrap();
        let checkpoint_cursor = Cursor::with_last_key(last_key);
        let pages = vec![
            EnumerationPage::new(
                vec![item(b"k1", 1, b"v1"), item(b"k2", 2, b"v2")],
                checkpoint_cursor.clone(),
            ),
            EnumerationPage::new(Vec::new(), checkpoint_cursor.clone()),
        ];

        let (done_tx, done_rx) = mpsc::channel();
        let _scan_worker = thread::spawn(move || {
            let mut connector = MockConnector::new(pages);
            let mut progress = MockProgress::new(shard, Cursor::initial());
            let sink = Arc::new(VecEventSink::new());

            let result = scan_connector_with_page_dispatch(
                Arc::new(test_engine(16)),
                &mut connector,
                ConnectorConfig::default(),
                &mut progress,
                sink,
                |_page_id, _items, tokens| {
                    let mut tokens = tokens.into_iter();
                    tokens.next().unwrap().complete();
                    tokens.next().unwrap().complete();
                    Ok(())
                },
            )
            .map(|_| progress.calls);

            done_tx.send(result).unwrap();
        });

        let calls = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("scan_connector did not finish (possible failure-path deadlock)")
            .expect("scan_connector returned error");
        assert_eq!(
            calls,
            vec![
                ProgressCall::Checkpoint(checkpoint_cursor.clone()),
                ProgressCall::Complete(checkpoint_cursor),
            ]
        );
    }

    // -- ConnectorConfig::validate() coverage --

    #[rstest]
    #[case::cpu_workers_zero("cpu_workers", "cpu_workers must be > 0")]
    #[case::chunk_size_zero("chunk_size", "chunk_size must be > 0")]
    fn validate_rejects_zero_field(#[case] field: &str, #[case] expected_msg: &str) {
        let mut cfg = ConnectorConfig::default();
        match field {
            "cpu_workers" => cfg.cpu_workers = 0,
            "chunk_size" => cfg.chunk_size = 0,
            _ => unreachable!(),
        }
        let err = cfg.validate(16).unwrap_err();
        assert_eq!(err, expected_msg);
    }

    #[test]
    fn validate_rejects_chunk_plus_overlap_exceeding_max() {
        let cfg = ConnectorConfig {
            chunk_size: BUFFER_LEN_MAX,
            ..ConnectorConfig::default()
        };
        let err = cfg.validate(16).unwrap_err();
        assert!(err.contains("exceeds BUFFER_LEN_MAX"), "got: {err}");
    }

    #[test]
    fn validate_accepts_default_config() {
        ConnectorConfig::default().validate(16).unwrap();
    }

    // -- PageCompletionBarrier edge cases --

    #[test]
    fn barrier_zero_items_completes_immediately() {
        let barrier = PageCompletionBarrier::new(0, 0);
        barrier.wait_until_complete();
        assert_eq!(barrier.outstanding_items(), 0);
    }

    #[test]
    fn token_drop_without_complete_releases_barrier() {
        let (barrier, tokens) = track_page_items(1, 2);
        assert_eq!(barrier.outstanding_items(), 2);
        drop(tokens);
        assert_eq!(barrier.outstanding_items(), 0);
    }

    #[test]
    fn barrier_lock_or_recover_absorbs_mutex_poison() {
        let barrier = PageCompletionBarrier::new(0, 2);

        // Poison the mutex by panicking while holding the guard.
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            let _guard = b.state.lock().unwrap();
            panic!("intentional poison");
        });
        let _ = handle.join();

        // The mutex is now poisoned. lock_or_recover should absorb it.
        assert_eq!(barrier.outstanding_items(), 2);
        barrier.release_item();
        assert_eq!(barrier.outstanding_items(), 1);
        barrier.release_item();
        assert_eq!(barrier.outstanding_items(), 0);
    }

    // -- Integration: empty first page --

    #[test]
    fn scan_connector_handles_empty_first_page() {
        let shard = ShardSpec::unbounded();
        let pages = vec![EnumerationPage::new(Vec::new(), Cursor::initial())];
        let mut connector = MockConnector::new(pages);
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let (report, _) = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            ConnectorConfig::default(),
            &mut progress,
            sink,
        )
        .unwrap();

        assert_eq!(report.enumerate.pages_enumerated, 0);
        assert_eq!(report.enumerate.items_discovered, 0);
        assert_eq!(report.enumerate.checkpoints_committed, 0);
        assert_eq!(
            progress.calls,
            vec![ProgressCall::Complete(Cursor::initial())]
        );
    }

    // -- Integration: split hints disabled --

    #[test]
    fn scan_connector_skips_split_hints_when_disabled() {
        let shard = ShardSpec::unbounded();
        let k1 = ItemKey::try_from_slice(b"k1").unwrap();
        let pages = vec![
            EnumerationPage::new(
                vec![item(b"k1", 1, b"v1")],
                Cursor::with_last_key(k1.clone()),
            ),
            EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
        ];
        let mut connector = MockConnector::new(pages);
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let cfg = ConnectorConfig {
            split_hint_budgets: None,
            ..ConnectorConfig::default()
        };
        let (report, _) = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            cfg,
            &mut progress,
            sink,
        )
        .unwrap();

        assert_eq!(report.enumerate.split_hints_emitted, 0);
        assert_eq!(
            progress.calls,
            vec![
                ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
                ProgressCall::Complete(Cursor::with_last_key(k1)),
            ]
        );
    }

    // -- Error propagation: enumeration failure --

    #[test]
    fn scan_connector_returns_enumerate_error_on_first_page() {
        let shard = ShardSpec::unbounded();
        let mut connector = MockConnector {
            pages: vec![Err(EnumerateError::permanent("simulated failure"))].into(),
            split_hints: VecDeque::new(),
        };
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let err = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            ConnectorConfig::default(),
            &mut progress,
            sink,
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorRunError::Enumerate(_)));
        assert!(progress.calls.is_empty());
    }

    // -- Error propagation: split-hint failure --

    #[test]
    fn scan_connector_returns_error_on_split_hint_failure() {
        let shard = ShardSpec::unbounded();
        let k1 = ItemKey::try_from_slice(b"k1").unwrap();
        let pages = vec![
            EnumerationPage::new(
                vec![item(b"k1", 1, b"v1")],
                Cursor::with_last_key(k1.clone()),
            ),
            EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
        ];
        let mut connector = MockConnector {
            pages: pages.into_iter().map(Ok).collect(),
            split_hints: vec![Err(EnumerateError::permanent("split failed"))].into(),
        };
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let cfg = ConnectorConfig {
            split_hint_budgets: Some(Budgets::try_new(1, 1024, None).unwrap()),
            ..ConnectorConfig::default()
        };
        let err = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            cfg,
            &mut progress,
            sink,
        )
        .unwrap_err();

        assert!(matches!(err, ConnectorRunError::Enumerate(_)));
        // Checkpoint was committed before the split-hint error.
        assert_eq!(
            progress.calls,
            vec![ProgressCall::Checkpoint(Cursor::with_last_key(k1))]
        );
    }

    // -- Budget enforcement --

    #[test]
    fn scan_connector_rejects_page_exceeding_budget() {
        let shard = ShardSpec::unbounded();
        let k1 = ItemKey::try_from_slice(b"k1").unwrap();
        // Budget allows max 2 items, but page returns 3.
        let oversized_page = EnumerationPage::new(
            vec![
                item(b"k1", 1, b"v1"),
                item(b"k2", 2, b"v2"),
                item(b"k3", 3, b"v3"),
            ],
            Cursor::with_last_key(k1),
        );
        let mut connector = MockConnector::new(vec![oversized_page]);
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let cfg = ConnectorConfig {
            page_budgets: Budgets::try_new(2, 16 * 1024 * 1024, None).unwrap(),
            ..ConnectorConfig::default()
        };
        let err = scan_connector(
            Arc::new(test_engine(16)),
            &mut connector,
            cfg,
            &mut progress,
            sink,
        )
        .unwrap_err();

        assert!(
            matches!(
                err,
                ConnectorRunError::BudgetExceeded {
                    returned: 3,
                    limit: 2
                }
            ),
            "expected BudgetExceeded, got: {err:?}"
        );
        assert!(progress.calls.is_empty(), "no checkpoint should occur");
    }

    // -- Error propagation: dispatch failure --

    #[test]
    fn scan_connector_dispatch_error_prevents_checkpoint() {
        let shard = ShardSpec::unbounded();
        let k1 = ItemKey::try_from_slice(b"k1").unwrap();
        let pages = vec![
            EnumerationPage::new(vec![item(b"k1", 1, b"v1")], Cursor::with_last_key(k1)),
            EnumerationPage::new(Vec::new(), Cursor::initial()),
        ];
        let mut connector = MockConnector::new(pages);
        let mut progress = MockProgress::new(shard, Cursor::initial());
        let sink = Arc::new(VecEventSink::new());

        let err = scan_connector_with_page_dispatch(
            Arc::new(test_engine(16)),
            &mut connector,
            ConnectorConfig::default(),
            &mut progress,
            sink,
            |_page_id, _items, _tokens| Err(ConnectorRunError::Dispatch("dispatch failed".into())),
        )
        .unwrap_err();

        assert!(
            matches!(err, ConnectorRunError::Dispatch(ref msg) if msg == "dispatch failed"),
            "expected Dispatch error, got: {err:?}"
        );
        assert!(
            progress.calls.is_empty(),
            "no checkpoint should be committed after dispatch failure"
        );
    }
}
