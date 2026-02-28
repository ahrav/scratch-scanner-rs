//! Connector-first scheduler entrypoints.
//!
//! This module defines the connector-native API boundary for scheduler execution.
//! It currently runs page-level orchestration (enumerate -> validate -> checkpoint)
//! while item-level read/chunk execution lands in follow-up tasks.

use super::engine_stub::{MockEngine, BUFFER_LEN_MAX};
use super::metrics::MetricsSnapshot;
use crate::unified::events::EventSink;

use gossip_contracts::connector::{
    validate_page, Budgets, ConnectorInstance, Cursor, EnumerateError, ErrorClass, ItemKey,
    PageValidationError, ReadError, ScanItem,
};
use gossip_contracts::coordination::ShardSpec;

use std::sync::Arc;
use std::time::Duration;

/// Connector-native alias for scheduler error classification.
pub type ConnectorErrorClass = ErrorClass;

/// Configuration for connector pipeline scanning.
#[derive(Clone, Copy, Debug)]
pub struct ConnectorScanConfig {
    /// Number of CPU worker threads for scanning.
    pub cpu_workers: usize,
    /// Number of dedicated I/O threads for connector reads.
    pub io_threads: usize,
    /// Payload bytes per chunk (excluding overlap).
    pub chunk_size: usize,
    /// Hard cap on discovered-but-not-fully-processed items.
    pub max_in_flight_items: usize,
    /// Bounded queue depth between enumeration and I/O workers.
    pub item_queue_cap: usize,
    /// Total buffers in the global pool.
    pub pool_buffers: usize,
    /// Page budgets passed to connector enumeration.
    pub page_budgets: Budgets,
    /// Optional budgets for split-hint requests.
    pub split_hint_budgets: Option<Budgets>,
    /// Abort an item if total time exceeds this (including retries).
    pub max_item_time: Option<Duration>,
    /// Seed for deterministic retry jitter and scheduling behavior.
    pub seed: u64,
    /// If true, deduplicate findings within each chunk.
    pub dedupe_within_chunk: bool,
    /// Pin worker and I/O threads to CPU cores where supported.
    pub pin_threads: bool,
}

impl Default for ConnectorScanConfig {
    fn default() -> Self {
        Self {
            cpu_workers: 8,
            io_threads: 8,
            chunk_size: 256 * 1024,
            max_in_flight_items: 512,
            item_queue_cap: 256,
            pool_buffers: 64,
            page_budgets: Budgets::try_new(256, 16 * 1024 * 1024, None)
                .expect("valid default page budgets"),
            split_hint_budgets: Some(
                Budgets::try_new(32, 1024 * 1024, None).expect("valid default split-hint budgets"),
            ),
            max_item_time: Some(Duration::from_secs(30)),
            seed: 1,
            dedupe_within_chunk: true,
            pin_threads: super::affinity::default_pin_threads(),
        }
    }
}

impl ConnectorScanConfig {
    /// Validate configuration against scheduler invariants.
    ///
    /// # Panics
    ///
    /// Panics if configuration violates invariants.
    pub fn validate(&self, required_overlap: usize) {
        assert!(self.cpu_workers > 0, "cpu_workers must be > 0");
        assert!(self.io_threads > 0, "io_threads must be > 0");
        assert!(self.chunk_size > 0, "chunk_size must be > 0");
        assert!(
            self.max_in_flight_items > 0,
            "max_in_flight_items must be > 0"
        );
        assert!(self.item_queue_cap > 0, "item_queue_cap must be > 0");
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(
            self.page_budgets.max_items() > 0,
            "page_budgets.max_items must be > 0"
        );
        assert!(
            self.page_budgets.max_bytes() > 0,
            "page_budgets.max_bytes must be > 0"
        );
        if let Some(split) = self.split_hint_budgets {
            assert!(
                split.max_items() > 0,
                "split_hint_budgets.max_items must be > 0"
            );
            assert!(
                split.max_bytes() > 0,
                "split_hint_budgets.max_bytes must be > 0"
            );
        }

        let buf_len = required_overlap.saturating_add(self.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size ({}) + overlap ({}) = {} exceeds BUFFER_LEN_MAX ({})",
            self.chunk_size,
            required_overlap,
            buf_len,
            BUFFER_LEN_MAX
        );
    }
}

/// Back-compat alias while callers migrate to [`ConnectorScanConfig`].
pub type ConnectorConfig = ConnectorScanConfig;

/// Connector-native progress persistence contract.
pub trait ProgressSink: Send {
    /// Sink-specific persistence or coordination error.
    type Error: std::fmt::Debug + Send + Sync + 'static;

    /// Shard currently owned by this scan attempt.
    fn shard_spec(&self) -> &ShardSpec;
    /// Resume cursor to start this scan attempt.
    fn cursor(&self) -> Cursor;
    /// Persist progress after a completed page barrier.
    fn checkpoint(&mut self, cursor: &Cursor) -> Result<(), Self::Error>;
    /// Persist terminal completion state.
    fn complete(&mut self, final_cursor: &Cursor) -> Result<(), Self::Error>;
    /// Persist parked state when the run yields ownership.
    fn park(&mut self) -> Result<(), Self::Error>;
    /// Persist an optional split-point hint.
    fn split_hint(&mut self, key: &ItemKey) -> Result<(), Self::Error>;
}

/// Connector runtime source contract for scheduler execution.
pub trait ConnectorSource: ConnectorInstance + Send + 'static {}

impl<T> ConnectorSource for T where T: ConnectorInstance + Send + 'static {}

/// Enumeration-side run statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorEnumerateStats {
    pub pages_enumerated: u64,
    pub items_discovered: u64,
    pub items_enqueued: u64,
    pub checkpoints_committed: u64,
    pub parks: u64,
    pub split_hints_emitted: u64,
}

/// I/O-side run statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorIoStats {
    pub items_started: u64,
    pub items_completed: u64,
    pub items_failed: u64,
    pub chunks_read: u64,
    pub payload_bytes_read: u64,
    pub retryable_errors: u64,
    pub permanent_errors: u64,
    pub retries: u64,
}

/// End-of-run report for connector pipeline execution.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorRunReport {
    pub enumerate: ConnectorEnumerateStats,
    pub io: ConnectorIoStats,
}

/// Errors that can occur during connector-pipeline execution.
#[derive(Debug)]
pub enum ConnectorRunError<E> {
    Enumerate(EnumerateError),
    Read(ReadError),
    PageValidation(Box<PageValidationError>),
    Progress(E),
    IoThreadPanicked,
    NotYetImplemented,
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
pub fn scan_connector<C, P>(
    engine: Arc<MockEngine>,
    connector: &mut C,
    cfg: ConnectorScanConfig,
    progress: &mut P,
    event_sink: Arc<dyn EventSink>,
) -> Result<(ConnectorRunReport, MetricsSnapshot), ConnectorRunError<P::Error>>
where
    C: ConnectorSource + ?Sized,
    P: ProgressSink + ?Sized,
{
    cfg.validate(engine.required_overlap());

    let mut report = ConnectorRunReport::default();
    let mut cursor = progress.cursor();
    let shard = progress.shard_spec().clone();

    loop {
        let page = connector
            .enumerate_page(&shard, &cursor, cfg.page_budgets)
            .map_err(ConnectorRunError::Enumerate)?;
        let (items, next_cursor) = page.into_parts();

        validate_page(&shard, &cursor, &items, &next_cursor)
            .map_err(|err| ConnectorRunError::PageValidation(Box::new(err)))?;

        if items.is_empty() {
            progress
                .complete(&next_cursor)
                .map_err(ConnectorRunError::Progress)?;
            break;
        }

        record_page_enqueue_and_processing(&items, &mut report);
        wait_for_page_completion_barrier(&items);

        progress
            .checkpoint(&next_cursor)
            .map_err(ConnectorRunError::Progress)?;
        report.enumerate.checkpoints_committed =
            report.enumerate.checkpoints_committed.saturating_add(1);

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

        cursor = next_cursor;
    }

    event_sink.flush();
    Ok((report, MetricsSnapshot::default()))
}

fn record_page_enqueue_and_processing(items: &[ScanItem], report: &mut ConnectorRunReport) {
    let item_count = items.len() as u64;
    report.enumerate.pages_enumerated = report.enumerate.pages_enumerated.saturating_add(1);
    report.enumerate.items_discovered =
        report.enumerate.items_discovered.saturating_add(item_count);
    report.enumerate.items_enqueued = report.enumerate.items_enqueued.saturating_add(item_count);
}

fn wait_for_page_completion_barrier(_items: &[ScanItem]) {
    // Enumeration currently processes each page synchronously. This call-site
    // is the explicit checkpoint barrier that follow-up tasks extend with
    // page-scoped outstanding item tracking.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::engine_stub::MockRule;
    use crate::unified::events::VecEventSink;

    use gossip_contracts::connector::{
        ConnectorCapabilities, EnumerationConnector, EnumerationPage, ItemRef, ReadConnector,
        ScanItem, VersionId,
    };
    use gossip_contracts::coordination::ShardSpec;
    use gossip_contracts::identity::{ObjectVersionId, StableItemId};

    use std::collections::VecDeque;
    use std::io;

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
    }

    impl MockProgress {
        fn new(shard: ShardSpec, cursor: Cursor) -> Self {
            Self {
                shard,
                cursor,
                calls: Vec::new(),
                fail_checkpoint: false,
            }
        }

        fn with_checkpoint_failure(mut self) -> Self {
            self.fail_checkpoint = true;
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

        let cfg = ConnectorScanConfig {
            split_hint_budgets: Some(Budgets::try_new(1, 1024, None).unwrap()),
            ..ConnectorScanConfig::default()
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
            ConnectorScanConfig::default(),
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
            ConnectorScanConfig::default(),
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
}
