//! Connector-first scheduler entrypoints.
//!
//! This module defines the connector-native API boundary for scheduler execution.
//! Runtime implementation of the connector loop lands in follow-up tasks.

use super::engine_stub::{MockEngine, BUFFER_LEN_MAX};
use super::metrics::MetricsSnapshot;
use crate::unified::events::EventSink;

use gossip_contracts::connector::{
    Budgets, ConnectorInstance, Cursor, EnumerateError, ErrorClass, ItemKey, PageValidationError,
    ReadError,
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
/// This validates connector-scan configuration and exposes the stable API
/// boundary used by follow-on migration tasks.
pub fn scan_connector<C, P>(
    engine: Arc<MockEngine>,
    _connector: &mut C,
    cfg: ConnectorScanConfig,
    _progress: &mut P,
    _event_sink: Arc<dyn EventSink>,
) -> Result<(ConnectorRunReport, MetricsSnapshot), ConnectorRunError<P::Error>>
where
    C: ConnectorSource + ?Sized,
    P: ProgressSink + ?Sized,
{
    cfg.validate(engine.required_overlap());
    Err(ConnectorRunError::NotYetImplemented)
}
