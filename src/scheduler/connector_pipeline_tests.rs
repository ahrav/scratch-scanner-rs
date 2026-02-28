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

use std::collections::{HashMap, VecDeque};
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
    fail_complete: bool,
    fail_split_hint: bool,
    checkpoint_notifier: Option<mpsc::Sender<Cursor>>,
}

impl MockProgress {
    fn new(shard: ShardSpec, cursor: Cursor) -> Self {
        Self {
            shard,
            cursor,
            calls: Vec::new(),
            fail_checkpoint: false,
            fail_complete: false,
            fail_split_hint: false,
            checkpoint_notifier: None,
        }
    }

    fn with_checkpoint_failure(mut self) -> Self {
        self.fail_checkpoint = true;
        self
    }

    fn with_complete_failure(mut self) -> Self {
        self.fail_complete = true;
        self
    }

    fn with_split_hint_failure(mut self) -> Self {
        self.fail_split_hint = true;
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
        if self.fail_complete {
            return Err("complete failed");
        }
        self.cursor = final_cursor.clone();
        self.calls
            .push(ProgressCall::Complete(final_cursor.clone()));
        Ok(())
    }

    fn park(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn split_hint(&mut self, key: &ItemKey) -> Result<(), Self::Error> {
        if self.fail_split_hint {
            return Err("split_hint failed");
        }
        self.calls.push(ProgressCall::SplitHint(key.clone()));
        Ok(())
    }
}

struct MockConnector {
    pages: VecDeque<Result<EnumerationPage, EnumerateError>>,
    split_hints: VecDeque<Result<Option<ItemKey>, EnumerateError>>,
    caps: ConnectorCapabilities,
    payloads: HashMap<Vec<u8>, Vec<u8>>,
    open_error: Option<ReadError>,
    read_range_error: Option<ReadError>,
    per_item_open_errors: HashMap<Vec<u8>, ReadError>,
    /// When true, read_range returns n > dst.len() to simulate a contract violation.
    read_range_overflow: bool,
    open_calls: u64,
    read_range_calls: u64,
}

impl MockConnector {
    fn new(pages: Vec<EnumerationPage>) -> Self {
        let mut payloads = HashMap::new();
        for page in &pages {
            for item in page.items() {
                payloads
                    .entry(item.item_ref().as_bytes().to_vec())
                    .or_insert_with(Vec::new);
            }
        }
        Self {
            pages: pages.into_iter().map(Ok).collect(),
            split_hints: VecDeque::new(),
            caps: ConnectorCapabilities::default(),
            payloads,
            open_error: None,
            read_range_error: None,
            per_item_open_errors: HashMap::new(),
            read_range_overflow: false,
            open_calls: 0,
            read_range_calls: 0,
        }
    }

    fn with_split_hints(mut self, hints: Vec<Option<ItemKey>>) -> Self {
        self.split_hints = hints.into_iter().map(Ok).collect();
        self
    }

    fn with_range_read(mut self) -> Self {
        self.caps.range_read = true;
        self
    }

    fn with_item_payload(mut self, key: &[u8], payload: &[u8]) -> Self {
        self.payloads.insert(key.to_vec(), payload.to_vec());
        self
    }

    fn with_open_error(mut self, err: ReadError) -> Self {
        self.open_error = Some(err);
        self
    }

    fn with_item_open_error(mut self, key: &[u8], err: ReadError) -> Self {
        self.per_item_open_errors.insert(key.to_vec(), err);
        self
    }

    fn with_read_range_error(mut self, err: ReadError) -> Self {
        self.read_range_error = Some(err);
        self
    }

    fn with_read_range_overflow(mut self) -> Self {
        self.read_range_overflow = true;
        self
    }
}

impl EnumerationConnector for MockConnector {
    fn caps(&self) -> ConnectorCapabilities {
        self.caps
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
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        self.open_calls = self.open_calls.saturating_add(1);
        if let Some(err) = self.per_item_open_errors.get(item_ref.as_bytes()).cloned() {
            return Err(err);
        }
        if let Some(err) = self.open_error.clone() {
            return Err(err);
        }
        let payload = self
            .payloads
            .get(item_ref.as_bytes())
            .cloned()
            .unwrap_or_default();
        Ok(Box::new(io::Cursor::new(payload)))
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        _budgets: Budgets,
    ) -> Result<usize, ReadError> {
        self.read_range_calls = self.read_range_calls.saturating_add(1);
        if let Some(err) = self.read_range_error.clone() {
            return Err(err);
        }
        if self.read_range_overflow {
            // Simulate a contract violation: report more bytes than buffer.
            return Ok(dst.len() + 1);
        }
        let payload = self
            .payloads
            .get(item_ref.as_bytes())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        if start >= payload.len() {
            return Ok(0);
        }
        let n = dst.len().min(payload.len() - start);
        dst[..n].copy_from_slice(&payload[start..start + n]);
        Ok(n)
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

/// Create a [`ScanItem`] with distinct `item_key` and `item_ref`.
///
/// This tests the contract that read paths use `item_ref` (the storage
/// address) rather than `item_key` (the logical identifier).
fn item_with_ref(key: &[u8], item_ref: &[u8], stable_fill: u8, version: &[u8]) -> ScanItem {
    ScanItem::new(
        ItemKey::try_from_slice(key).unwrap(),
        ItemRef::try_from_slice(item_ref).unwrap(),
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
    assert_eq!(report.enumerate.items_failed_retryable, 0);
    assert_eq!(report.enumerate.items_failed_permanent, 0);
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
    let (barrier, tokens) = track_page_items(PageId(7), 2);
    assert_eq!(barrier.page_id, PageId(7));
    assert_eq!(barrier.outstanding_items(), 2);
    assert!(tokens
        .iter()
        .all(|token| token.barrier.page_id == PageId(7)));

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
            move |page_id, _connector, items, tokens| {
                assert_eq!(page_id, PageId::ZERO);
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
            |_page_id, _connector, _items, tokens| {
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
fn validate_rejects_overlap_ge_chunk_size() {
    let cfg = ConnectorConfig {
        chunk_size: 64,
        ..ConnectorConfig::default()
    };
    // overlap == chunk_size: must be rejected.
    let err = cfg.validate(64).unwrap_err();
    assert!(
        err.contains("chunk_size") && err.contains("required_overlap"),
        "expected overlap >= chunk_size rejection, got: {err}"
    );
    // overlap > chunk_size: must also be rejected.
    let err = cfg.validate(128).unwrap_err();
    assert!(
        err.contains("chunk_size") && err.contains("required_overlap"),
        "expected overlap > chunk_size rejection, got: {err}"
    );
    // overlap < chunk_size: must pass.
    cfg.validate(63).unwrap();
}

#[test]
fn validate_accepts_default_config() {
    ConnectorConfig::default().validate(16).unwrap();
}

// -- read_error_from_io classification --

#[rstest]
#[case::not_found(io::ErrorKind::NotFound, false)]
#[case::permission_denied(io::ErrorKind::PermissionDenied, false)]
#[case::invalid_input(io::ErrorKind::InvalidInput, false)]
#[case::invalid_data(io::ErrorKind::InvalidData, false)]
#[case::unsupported(io::ErrorKind::Unsupported, false)]
#[case::connection_reset(io::ErrorKind::ConnectionReset, true)]
#[case::timed_out(io::ErrorKind::TimedOut, true)]
#[case::other(io::ErrorKind::Other, true)]
fn read_error_from_io_classifies_error_kinds(
    #[case] kind: io::ErrorKind,
    #[case] expected_retryable: bool,
) {
    let io_err = io::Error::new(kind, "test error");
    let read_err = read_error_from_io(io_err);
    assert_eq!(
        read_err.is_retryable(),
        expected_retryable,
        "{kind:?} should be {}",
        if expected_retryable {
            "retryable"
        } else {
            "permanent"
        }
    );
}

// -- read_some EINTR retry bound --

/// Mock reader that returns `Interrupted` a configurable number of times
/// before succeeding.
struct InterruptReader {
    remaining_interrupts: usize,
    payload: Vec<u8>,
    pos: usize,
}

impl io::Read for InterruptReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining_interrupts > 0 {
            self.remaining_interrupts -= 1;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "EINTR"));
        }
        let n = buf.len().min(self.payload.len() - self.pos);
        buf[..n].copy_from_slice(&self.payload[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn read_some_retries_eintr_then_succeeds() {
    let mut reader = InterruptReader {
        remaining_interrupts: 5,
        payload: b"hello".to_vec(),
        pos: 0,
    };
    let mut buf = [0u8; 5];
    let n = read_some(&mut reader, &mut buf).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf, b"hello");
}

#[test]
fn read_some_fails_after_max_eintr_retries() {
    let mut reader = InterruptReader {
        remaining_interrupts: MAX_EINTR_RETRIES + 1,
        payload: b"data".to_vec(),
        pos: 0,
    };
    let mut buf = [0u8; 4];
    let err = read_some(&mut reader, &mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    assert!(
        err.to_string().contains("exceeded"),
        "error should mention retry exhaustion: {}",
        err
    );
}

// -- PageCompletionBarrier edge cases --

#[test]
fn barrier_zero_items_completes_immediately() {
    let barrier = PageCompletionBarrier::new(PageId::ZERO, 0);
    barrier.wait_until_complete();
    assert_eq!(barrier.outstanding_items(), 0);
}

#[test]
fn token_drop_without_complete_releases_barrier() {
    let (barrier, tokens) = track_page_items(PageId(1), 2);
    assert_eq!(barrier.outstanding_items(), 2);
    drop(tokens);
    assert_eq!(barrier.outstanding_items(), 0);
}

#[test]
fn barrier_lock_or_recover_survives_poisoned_mutex() {
    let barrier = PageCompletionBarrier::new(PageId::ZERO, 2);

    // Poison the mutex by panicking while holding the guard.
    let b = Arc::clone(&barrier);
    let handle = thread::spawn(move || {
        let _guard = b.state.lock().unwrap();
        panic!("intentional poison");
    });
    let _ = handle.join();

    // The mutex is now poisoned. lock_or_recover should recover, not panic.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        barrier.release_item();
    }));
    assert!(result.is_ok(), "expected recovery from poisoned mutex");
    assert_eq!(barrier.outstanding_items(), 1);
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

// -- Integration: empty item payload --

#[rstest]
#[case::open_path(false)]
#[case::range_read_path(true)]
fn scan_connector_handles_empty_item_payload(#[case] use_range_read: bool) {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    // MockConnector::new auto-populates empty payloads for items.
    let mut connector = MockConnector::new(pages);
    if use_range_read {
        connector = connector.with_range_read();
    }
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(16)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(metrics.bytes_scanned, 0);
    assert_eq!(metrics.chunks_scanned, 0);
    assert_eq!(metrics.findings_emitted, 0);
    assert_eq!(metrics.io_errors, 0);
    assert_eq!(report.enumerate.items_failed_retryable, 0);
    assert_eq!(report.enumerate.items_failed_permanent, 0);
    // Progress lifecycle still runs despite empty payload.
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k1)),
        ]
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
    let mut connector = MockConnector::new(Vec::new());
    connector.pages = vec![Err(EnumerateError::permanent("simulated failure"))].into();
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
    let mut connector = MockConnector::new(pages);
    connector.split_hints = vec![Err(EnumerateError::permanent("split failed"))].into();
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
        |_page_id, _connector, _items, _tokens| {
            Err(ConnectorRunError::Dispatch("dispatch failed".into()))
        },
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

// -- Error propagation: progress.complete() failure --

#[test]
fn scan_connector_maps_complete_error_to_progress_error() {
    let shard = ShardSpec::unbounded();
    // Single empty page triggers `complete()` immediately.
    let pages = vec![EnumerationPage::new(Vec::new(), Cursor::initial())];
    let mut connector = MockConnector::new(pages);
    let mut progress = MockProgress::new(shard, Cursor::initial()).with_complete_failure();
    let sink = Arc::new(VecEventSink::new());

    let err = scan_connector(
        Arc::new(test_engine(16)),
        &mut connector,
        ConnectorConfig::default(),
        &mut progress,
        sink,
    )
    .unwrap_err();

    assert!(
        matches!(err, ConnectorRunError::Progress("complete failed")),
        "expected Progress(complete failed), got: {err:?}"
    );
    assert!(
        progress.calls.is_empty(),
        "no calls should be recorded when complete fails"
    );
}

// -- Error propagation: progress.split_hint() failure --

#[test]
fn scan_connector_maps_split_hint_persistence_error_to_progress_error() {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    // Connector returns a split key so split_hint() is called.
    let mut connector = MockConnector::new(pages).with_split_hints(vec![Some(k1.clone())]);
    let mut progress = MockProgress::new(shard, Cursor::initial()).with_split_hint_failure();
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

    assert!(
        matches!(err, ConnectorRunError::Progress("split_hint failed")),
        "expected Progress(split_hint failed), got: {err:?}"
    );
    // Checkpoint was committed before the split-hint persistence failure.
    assert_eq!(
        progress.calls,
        vec![ProgressCall::Checkpoint(Cursor::with_last_key(k1))]
    );
}

fn count_jsonl_findings(encoded: &str) -> usize {
    encoded
        .lines()
        .filter(|line| line.contains("\"type\"") && line.contains("\"finding\""))
        .count()
}

#[test]
fn scan_connector_streams_items_via_open_and_emits_findings() {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let payload = b"prefix SECRET suffix";
    let mut connector = MockConnector::new(pages).with_item_payload(b"k1", payload);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    // chunk_size must exceed required_overlap for valid cross-chunk scanning.
    // overlap=6 (enough for 6-byte "SECRET" pattern), chunk_size=8 > 6.
    let cfg = ConnectorConfig {
        chunk_size: 8,
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(6)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert!(connector.open_calls > 0);
    assert_eq!(connector.read_range_calls, 0);
    assert_eq!(metrics.io_errors, 0);
    assert_eq!(metrics.bytes_scanned, payload.len() as u64);
    assert_eq!(metrics.chunks_scanned, 3);
    assert_eq!(metrics.findings_emitted, 1);
    assert_eq!(report.enumerate.items_failed_retryable, 0);
    assert_eq!(report.enumerate.items_failed_permanent, 0);

    let encoded = String::from_utf8(sink.bytes()).unwrap();
    assert_eq!(count_jsonl_findings(&encoded), 1);
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k1)),
        ]
    );
}

#[test]
fn scan_connector_uses_range_read_when_capability_advertised() {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let payload = b"AAASECRETBBB";
    let mut connector = MockConnector::new(pages)
        .with_range_read()
        .with_item_payload(b"k1", payload);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    // chunk_size must exceed required_overlap for valid cross-chunk scanning.
    // overlap=6 (enough for 6-byte "SECRET" pattern), chunk_size=8 > 6.
    let cfg = ConnectorConfig {
        chunk_size: 8,
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(6)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(connector.open_calls, 0);
    assert!(connector.read_range_calls > 0);
    assert_eq!(metrics.io_errors, 0);
    assert_eq!(metrics.bytes_scanned, payload.len() as u64);
    assert_eq!(metrics.findings_emitted, 1);
    assert_eq!(report.enumerate.items_failed_retryable, 0);
    assert_eq!(report.enumerate.items_failed_permanent, 0);

    let encoded = String::from_utf8(sink.bytes()).unwrap();
    assert_eq!(count_jsonl_findings(&encoded), 1);
}

#[rstest]
#[case::retryable(ReadError::retryable("temporary read failure"), "retryable", 1, 0)]
#[case::permanent(ReadError::permanent("missing object"), "permanent", 0, 1)]
fn scan_connector_classifies_read_errors_and_continues_page(
    #[case] read_err: ReadError,
    #[case] expected_class: &str,
    #[case] expected_retryable: u64,
    #[case] expected_permanent: u64,
) {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let mut connector = MockConnector::new(pages).with_open_error(read_err);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(16)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(metrics.io_errors, 1);
    assert_eq!(metrics.bytes_scanned, 0);
    assert_eq!(metrics.findings_emitted, 0);
    assert_eq!(report.enumerate.items_failed_retryable, expected_retryable);
    assert_eq!(report.enumerate.items_failed_permanent, expected_permanent);
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k1)),
        ]
    );

    let encoded = String::from_utf8(sink.bytes()).unwrap();
    assert!(encoded.contains("connector read"));
    assert!(encoded.contains(expected_class));
}

#[test]
fn scan_connector_error_on_one_item_does_not_prevent_scanning_remaining_items() {
    let shard = ShardSpec::unbounded();
    let k2 = ItemKey::try_from_slice(b"k2").unwrap();
    // Page with two items: k1 will fail, k2 has a scannable payload.
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1"), item(b"k2", 2, b"v2")],
            Cursor::with_last_key(k2.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k2.clone())),
    ];
    let mut connector = MockConnector::new(pages)
        .with_item_open_error(b"k1", ReadError::permanent("k1 gone"))
        .with_item_payload(b"k2", b"payload SECRET tail");
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        chunk_size: 256,
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(6)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    // k1 failed permanently; k2 scanned successfully.
    assert_eq!(metrics.io_errors, 1);
    assert_eq!(report.enumerate.items_failed_permanent, 1);
    assert_eq!(report.enumerate.items_failed_retryable, 0);
    assert!(
        metrics.bytes_scanned > 0,
        "k2 payload should have been scanned"
    );
    assert_eq!(metrics.findings_emitted, 1, "SECRET in k2 should be found");

    // Checkpoint and complete should both fire (page completes normally).
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k2.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k2)),
        ]
    );
}

// -- read_range error paths --

#[rstest]
#[case::retryable(ReadError::retryable("temporary range failure"), "retryable", 1, 0)]
#[case::permanent(ReadError::permanent("range read denied"), "permanent", 0, 1)]
fn scan_connector_classifies_range_read_errors_and_continues_page(
    #[case] read_err: ReadError,
    #[case] expected_class: &str,
    #[case] expected_retryable: u64,
    #[case] expected_permanent: u64,
) {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let mut connector = MockConnector::new(pages)
        .with_range_read()
        .with_read_range_error(read_err);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(16)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(metrics.io_errors, 1);
    assert_eq!(metrics.bytes_scanned, 0);
    assert_eq!(metrics.findings_emitted, 0);
    assert_eq!(connector.open_calls, 0);
    assert!(connector.read_range_calls > 0);
    assert_eq!(report.enumerate.items_failed_retryable, expected_retryable);
    assert_eq!(report.enumerate.items_failed_permanent, expected_permanent);

    let encoded = String::from_utf8(sink.bytes()).unwrap();
    assert!(encoded.contains("connector read"));
    assert!(encoded.contains(expected_class));

    // Page still completes and checkpoints.
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k1)),
        ]
    );
}

#[test]
fn scan_connector_read_range_overflow_is_permanent_error() {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let mut connector = MockConnector::new(pages)
        .with_range_read()
        .with_read_range_overflow()
        .with_item_payload(b"k1", b"some data");
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(16)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(metrics.io_errors, 1);
    assert_eq!(report.enumerate.items_failed_permanent, 1);
    assert_eq!(report.enumerate.items_failed_retryable, 0);

    // Page still checkpoints despite the error.
    assert_eq!(
        progress.calls,
        vec![
            ProgressCall::Checkpoint(Cursor::with_last_key(k1.clone())),
            ProgressCall::Complete(Cursor::with_last_key(k1)),
        ]
    );
}

// -- ConnectorRunError Display/Error --

#[test]
fn connector_run_error_display_formats_all_variants() {
    let err: ConnectorRunError<&str> = ConnectorRunError::FileIdOverflow;
    assert!(err.to_string().contains("u32::MAX"), "got: {err}");

    let err: ConnectorRunError<&str> = ConnectorRunError::BudgetExceeded {
        returned: 10,
        limit: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("10") && msg.contains("5"), "got: {msg}");

    let err: ConnectorRunError<&str> = ConnectorRunError::PageIdOverflow;
    assert!(err.to_string().contains("u64::MAX"), "got: {err}");

    let err: ConnectorRunError<&str> = ConnectorRunError::Config("bad".into());
    assert!(err.to_string().contains("bad"), "got: {err}");

    let err: ConnectorRunError<&str> = ConnectorRunError::Dispatch("queue full".into());
    assert!(err.to_string().contains("queue full"), "got: {err}");

    let err: ConnectorRunError<&str> = ConnectorRunError::Progress("sink broke");
    assert!(err.to_string().contains("sink broke"), "got: {err}");
}

#[test]
fn connector_run_error_source_delegates_for_enumerate_and_page_validation() {
    use std::error::Error;

    let enumerate_err = EnumerateError::permanent("enum fail");
    let err: ConnectorRunError<&str> = ConnectorRunError::Enumerate(enumerate_err);
    assert!(err.source().is_some(), "Enumerate should have a source");

    let page_err = validate_page(
        &ShardSpec::with_range(b"a", b"z"),
        &Cursor::initial(),
        &[item(b"b", 1, b"v1")],
        &Cursor::initial(),
    )
    .unwrap_err();
    let err: ConnectorRunError<&str> = ConnectorRunError::PageValidation(Box::new(page_err));
    assert!(
        err.source().is_some(),
        "PageValidation should have a source"
    );

    let err: ConnectorRunError<&str> = ConnectorRunError::FileIdOverflow;
    assert!(err.source().is_none(), "FileIdOverflow has no source");
}

// -- PageId newtype --

#[test]
fn page_id_checked_next_increments_and_detects_overflow() {
    assert_eq!(PageId::ZERO.checked_next(), Some(PageId(1)));
    assert_eq!(PageId(u64::MAX).checked_next(), None);
}

#[test]
fn page_id_display_shows_inner_value() {
    assert_eq!(format!("{}", PageId::ZERO), "0");
    assert_eq!(format!("{}", PageId(42)), "42");
}

// -- Per-item byte limit (max_item_bytes) --

#[test]
fn scan_connector_enforces_max_item_bytes() {
    let shard = ShardSpec::unbounded();
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let payload = vec![0xAA; 128];
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let mut connector = MockConnector::new(pages).with_item_payload(b"k1", &payload);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        chunk_size: 32,
        max_item_bytes: 64,
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (report, metrics) = scan_connector(
        Arc::new(test_engine(8)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(metrics.io_errors, 1);
    assert_eq!(report.enumerate.items_failed_permanent, 1);
    let encoded = String::from_utf8(sink.bytes()).unwrap();
    assert!(
        encoded.contains("max_item_bytes"),
        "diagnostic should mention max_item_bytes, got: {encoded}"
    );
}

#[test]
fn validate_rejects_zero_max_item_bytes() {
    let cfg = ConnectorConfig {
        max_item_bytes: 0,
        ..ConnectorConfig::default()
    };
    let err = cfg.validate(16).unwrap_err();
    assert!(
        err.contains("max_item_bytes"),
        "expected max_item_bytes rejection, got: {err}"
    );
}

// -- FileId pre-validation --

#[test]
fn scan_connector_file_id_overflow_at_page_start_prevents_partial_processing() {
    let shard = ShardSpec::unbounded();
    let k2 = ItemKey::try_from_slice(b"k2").unwrap();
    let pages = vec![
        EnumerationPage::new(
            vec![item(b"k1", 1, b"v1"), item(b"k2", 2, b"v2")],
            Cursor::with_last_key(k2.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k2.clone())),
    ];
    let mut connector = MockConnector::new(pages);
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());

    // Start file_id at u32::MAX so the 2-item page overflows.
    let engine = Arc::new(test_engine(16));
    let dispatch_sink = Arc::clone(&sink) as Arc<dyn EventSink>;
    let cfg = ConnectorConfig {
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let next_file_id: u32 = u32::MAX;

    let err = scan_connector_with_page_dispatch(
        engine,
        &mut connector,
        cfg,
        &mut progress,
        dispatch_sink,
        |_page_id, _connector, items, _tokens| {
            let count =
                u32::try_from(items.len()).map_err(|_| ConnectorRunError::FileIdOverflow)?;
            next_file_id
                .checked_add(count)
                .ok_or(ConnectorRunError::FileIdOverflow)?;
            Ok(())
        },
    )
    .unwrap_err();

    assert!(
        matches!(err, ConnectorRunError::FileIdOverflow),
        "expected FileIdOverflow, got: {err:?}"
    );
    assert!(
        progress.calls.is_empty(),
        "no checkpoints should occur on FileIdOverflow"
    );
}

// -- F9: reads use item_ref, not item_key --

#[rstest]
#[case::open_path(false)]
#[case::range_read_path(true)]
fn scan_connector_reads_from_item_ref_not_item_key(#[case] use_range_read: bool) {
    let shard = ShardSpec::unbounded();
    // item_key is "k1", item_ref is "ref1": payload is keyed by "ref1".
    let k1 = ItemKey::try_from_slice(b"k1").unwrap();
    let payload = b"payload with SECRET inside";
    let pages = vec![
        EnumerationPage::new(
            vec![item_with_ref(b"k1", b"ref1", 1, b"v1")],
            Cursor::with_last_key(k1.clone()),
        ),
        EnumerationPage::new(Vec::new(), Cursor::with_last_key(k1.clone())),
    ];
    let mut connector = MockConnector::new(Vec::new());
    connector.pages = pages.into_iter().map(Ok).collect();
    connector
        .payloads
        .insert(b"ref1".to_vec(), payload.to_vec());
    if use_range_read {
        connector.caps.range_read = true;
    }
    let mut progress = MockProgress::new(shard, Cursor::initial());
    let sink = Arc::new(VecEventSink::new());
    let sink_dyn: Arc<dyn EventSink> = sink.clone();

    let cfg = ConnectorConfig {
        chunk_size: 256,
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };
    let (_report, metrics) = scan_connector(
        Arc::new(test_engine(6)),
        &mut connector,
        cfg,
        &mut progress,
        sink_dyn,
    )
    .unwrap();

    assert_eq!(
        metrics.bytes_scanned,
        payload.len() as u64,
        "reads should use item_ref (ref1) to find the payload, not item_key (k1)"
    );
    assert_eq!(metrics.findings_emitted, 1);
}
