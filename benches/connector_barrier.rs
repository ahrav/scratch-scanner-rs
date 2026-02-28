//! Performance benchmarks for connector pipeline page-level primitives.
//!
//! Tests five hypotheses:
//!
//! - **H4**: Mutex-based `PageCompletionBarrier` contention under concurrent release
//! - **H1**: Per-page `Vec<PageItemToken>` allocation overhead
//! - **H5**: `notify_all` vs `notify_one` cost with a single waiter
//! - **H4-alt**: Atomic barrier alternative (AtomicUsize + thread::park/unpark)
//! - **H10/H11**: End-to-end page-level throughput baseline

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use scanner_rs::{bench_track_page_items, BenchToken};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// H4: Barrier contention under concurrent release
// ---------------------------------------------------------------------------

/// Distribute `tokens` across `thread_count` threads; each thread releases
/// its slice. Measures wall time from spawn to barrier drain.
fn barrier_contention_mutex(items_per_page: usize, thread_count: usize) {
    let (barrier, tokens) = bench_track_page_items(0, items_per_page);

    // Distribute tokens into per-thread chunks.
    let chunks = distribute_tokens(tokens, thread_count);

    thread::scope(|s| {
        for chunk in chunks {
            s.spawn(move || {
                for token in chunk {
                    token.complete();
                }
            });
        }
        // The waiter is the scope thread itself.
        barrier.wait_until_complete();
    });

    black_box(());
}

fn bench_barrier_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("barrier_contention");
    group.sample_size(100);

    for &items in &[1, 10, 64, 256, 1024] {
        for &threads in &[1, 2, 4, 8, 16] {
            // Skip configurations where threads exceed items.
            if threads > items {
                continue;
            }
            group.bench_with_input(
                BenchmarkId::new(format!("mutex/items={items}"), threads),
                &(items, threads),
                |b, &(item_count, tc)| {
                    b.iter(|| barrier_contention_mutex(item_count, tc));
                },
            );
        }
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// H1: Vec allocation overhead per page
// ---------------------------------------------------------------------------

/// Measure the cost of creating a barrier + token Vec for each page
/// (the "fresh alloc" path that track_page_items uses).
fn vec_alloc_fresh(item_count: usize) {
    let (barrier, tokens) = bench_track_page_items(0, item_count);
    for token in tokens {
        token.complete();
    }
    barrier.wait_until_complete();
}

/// Reuse a pre-allocated Vec by clearing and extending.
/// Shows the delta achievable by recycling the token buffer.
fn vec_alloc_reuse(item_count: usize, reuse_buf: &mut Vec<BenchToken>) {
    let (barrier, tokens) = bench_track_page_items(0, item_count);

    reuse_buf.clear();
    reuse_buf.extend(tokens);

    for token in reuse_buf.drain(..) {
        token.complete();
    }
    barrier.wait_until_complete();
}

fn bench_vec_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_alloc");

    for &items in &[1, 10, 64, 256, 1024] {
        group.bench_with_input(BenchmarkId::new("fresh", items), &items, |b, &n| {
            b.iter(|| vec_alloc_fresh(n));
        });
        group.bench_with_input(BenchmarkId::new("reuse", items), &items, |b, &n| {
            // Pre-allocate once with capacity matching the largest run.
            let mut buf = Vec::with_capacity(n);
            b.iter(|| vec_alloc_reuse(n, &mut buf));
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// H5: notify_all vs notify_one
// ---------------------------------------------------------------------------

/// Drain barrier using notify_all (current production code path).
/// Workers release from threads; waiter blocks until complete.
fn notify_all_drain(item_count: usize, thread_count: usize) {
    let (barrier, tokens) = bench_track_page_items(0, item_count);
    let chunks = distribute_tokens(tokens, thread_count);

    thread::scope(|s| {
        for chunk in chunks {
            s.spawn(move || {
                for token in chunk {
                    token.complete();
                }
            });
        }
        barrier.wait_until_complete();
    });
}

/// Drain barrier using an atomic-only approach (no condvar at all).
/// Uses AtomicUsize + thread::park/unpark as the notification mechanism.
fn notify_atomic_drain(item_count: usize, thread_count: usize) {
    let outstanding = Arc::new(AtomicUsize::new(item_count));
    let waiter_handle = thread::current();

    thread::scope(|s| {
        let items_per_thread = item_count / thread_count.max(1);
        let remainder = item_count % thread_count.max(1);

        let mut offset = 0;
        for t in 0..thread_count {
            let count = items_per_thread + if t < remainder { 1 } else { 0 };
            let outstanding = Arc::clone(&outstanding);
            let waiter = waiter_handle.clone();
            s.spawn(move || {
                for _ in 0..count {
                    black_box(offset); // Prevent elision of the loop body.
                    if outstanding.fetch_sub(1, Ordering::Release) == 1 {
                        waiter.unpark();
                    }
                }
            });
            offset += count;
        }
        // Park until the last release wakes us.
        while outstanding.load(Ordering::Acquire) > 0 {
            thread::park();
        }
    });

    black_box(());
}

fn bench_notify(c: &mut Criterion) {
    let mut group = c.benchmark_group("notify_strategy");
    let thread_count = 4;

    for &items in &[1, 256, 1024] {
        group.bench_with_input(
            BenchmarkId::new("mutex_notify_all", items),
            &items,
            |b, &n| {
                b.iter(|| notify_all_drain(n, thread_count));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("atomic_park_unpark", items),
            &items,
            |b, &n| {
                b.iter(|| notify_atomic_drain(n, thread_count));
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// H4-alt: Atomic barrier variant (head-to-head with Mutex)
// ---------------------------------------------------------------------------

/// Standalone atomic barrier for A/B comparison.
/// Uses `AtomicUsize` + `thread::park`/`unpark` instead of Mutex + Condvar.
struct AtomicBarrier {
    outstanding: AtomicUsize,
    waiter: thread::Thread,
}

impl AtomicBarrier {
    fn new(count: usize) -> Arc<Self> {
        Arc::new(Self {
            outstanding: AtomicUsize::new(count),
            waiter: thread::current(),
        })
    }

    fn release_one(&self) {
        if self.outstanding.fetch_sub(1, Ordering::Release) == 1 {
            self.waiter.unpark();
        }
    }

    fn wait(&self) {
        while self.outstanding.load(Ordering::Acquire) > 0 {
            thread::park();
        }
    }
}

fn barrier_contention_atomic(items_per_page: usize, thread_count: usize) {
    let barrier = AtomicBarrier::new(items_per_page);

    thread::scope(|s| {
        let items_per_thread = items_per_page / thread_count.max(1);
        let remainder = items_per_page % thread_count.max(1);

        for t in 0..thread_count {
            let count = items_per_thread + if t < remainder { 1 } else { 0 };
            let barrier = Arc::clone(&barrier);
            s.spawn(move || {
                for _ in 0..count {
                    barrier.release_one();
                }
            });
        }
        barrier.wait();
    });

    black_box(());
}

fn bench_atomic_barrier(c: &mut Criterion) {
    let mut group = c.benchmark_group("barrier_atomic_vs_mutex");
    group.sample_size(100);

    for &items in &[1, 10, 64, 256, 1024] {
        for &threads in &[1, 2, 4, 8, 16] {
            if threads > items {
                continue;
            }
            group.bench_with_input(
                BenchmarkId::new(format!("atomic/items={items}"), threads),
                &(items, threads),
                |b, &(item_count, tc)| {
                    b.iter(|| barrier_contention_atomic(item_count, tc));
                },
            );
            group.bench_with_input(
                BenchmarkId::new(format!("mutex/items={items}"), threads),
                &(items, threads),
                |b, &(item_count, tc)| {
                    b.iter(|| barrier_contention_mutex(item_count, tc));
                },
            );
        }
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// H10/H11: Page-level throughput baseline via scan_connector
// ---------------------------------------------------------------------------
//
// These benchmarks exercise the full scan_connector pipeline with a
// MockConnector + MockProgress to measure end-to-end throughput.
// The synchronous stub completes all tokens inline, so this captures:
//   - enumerate_page overhead
//   - validate_page overhead
//   - barrier create+drain overhead
//   - checkpoint I/O cost (mock = in-memory)
//   - per-page Vec allocation
//
// Re-running after async dispatch lands reveals the H10 serial gap.

use scanner_rs::scheduler::connector_pipeline::{scan_connector, ConnectorConfig, ProgressSink};
use scanner_rs::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_rs::unified::events::VecEventSink;

use gossip_contracts::connector::{
    Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector, EnumerationPage,
    ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, VersionId,
};
use gossip_contracts::coordination::ShardSpec;
use gossip_contracts::identity::{ObjectVersionId, StableItemId};

use std::collections::VecDeque;
use std::io;

// ---- Mock types (mirrors test module; duplicated here because test-only
//      types are not exported) ----

struct BenchMockConnector {
    pages: VecDeque<EnumerationPage>,
}

impl BenchMockConnector {
    fn new(page_count: usize, items_per_page: usize) -> Self {
        let mut pages = VecDeque::with_capacity(page_count + 1);
        let mut key_counter: u64 = 0;

        for _ in 0..page_count {
            let items: Vec<ScanItem> = (0..items_per_page)
                .map(|_| {
                    key_counter += 1;
                    let key_bytes = key_counter.to_be_bytes();
                    ScanItem::new(
                        ItemKey::try_from_slice(&key_bytes).unwrap(),
                        ItemRef::try_from_slice(&key_bytes).unwrap(),
                        StableItemId::from_bytes([key_counter as u8; 32]),
                        VersionId::Strong(ObjectVersionId::from_version_bytes(&key_bytes)),
                    )
                })
                .collect();

            let last_key = items.last().map(|i| i.item_key().clone()).unwrap();
            pages.push_back(EnumerationPage::new(items, Cursor::with_last_key(last_key)));
        }

        // Terminal empty page.
        let terminal_cursor = if let Some(last_page) = pages.back() {
            last_page.next_cursor().clone()
        } else {
            Cursor::initial()
        };
        pages.push_back(EnumerationPage::new(Vec::new(), terminal_cursor));

        Self { pages }
    }
}

impl EnumerationConnector for BenchMockConnector {
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
            .ok_or_else(|| EnumerateError::permanent("no more pages"))
    }

    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }
}

impl ReadConnector for BenchMockConnector {
    fn open(
        &mut self,
        _item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        // Return an empty reader so the scan loop completes one zero-byte
        // read cycle per item without triggering error diagnostics.
        // This keeps the benchmark measuring page-level orchestration
        // overhead (enumerate, validate, barrier, checkpoint) rather than
        // error handling noise.
        Ok(Box::new(io::empty()))
    }
}

struct BenchMockProgress {
    shard: ShardSpec,
    cursor: Cursor,
}

impl BenchMockProgress {
    fn new() -> Self {
        Self {
            shard: ShardSpec::unbounded(),
            cursor: Cursor::initial(),
        }
    }
}

impl ProgressSink for BenchMockProgress {
    type Error = std::convert::Infallible;

    fn shard_spec(&self) -> &ShardSpec {
        &self.shard
    }

    fn cursor(&self) -> Cursor {
        self.cursor.clone()
    }

    fn checkpoint(&mut self, cursor: &Cursor) -> Result<(), Self::Error> {
        self.cursor = cursor.clone();
        Ok(())
    }

    fn complete(&mut self, cursor: &Cursor) -> Result<(), Self::Error> {
        self.cursor = cursor.clone();
        Ok(())
    }

    fn park(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn split_hint(&mut self, _key: &ItemKey) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn throughput_scan(page_count: usize, items_per_page: usize) {
    let engine = Arc::new(MockEngine::new(
        vec![MockRule {
            name: "bench".to_string(),
            pattern: b"BENCH".to_vec(),
        }],
        16,
    ));
    let mut connector = BenchMockConnector::new(page_count, items_per_page);
    let mut progress = BenchMockProgress::new();
    let sink = Arc::new(VecEventSink::new());

    // Adjust page budget to accommodate items_per_page.
    let cfg = ConnectorConfig {
        page_budgets: Budgets::try_new(items_per_page.max(1), 64 * 1024 * 1024, None).unwrap(),
        split_hint_budgets: None,
        ..ConnectorConfig::default()
    };

    let result = scan_connector(engine, &mut connector, cfg, &mut progress, sink);
    black_box(result.unwrap());
}

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("page_throughput");

    for &pages in &[1, 10, 100, 1000] {
        for &items in &[1, 10, 256] {
            group.bench_with_input(
                BenchmarkId::new(format!("pages={pages}/items={items}"), pages * items),
                &(pages, items),
                |b, &(pc, ipc)| {
                    b.iter(|| throughput_scan(pc, ipc));
                },
            );
        }
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split a Vec of tokens into `n` roughly equal chunks.
fn distribute_tokens(tokens: Vec<BenchToken>, n: usize) -> Vec<Vec<BenchToken>> {
    let total = tokens.len();
    let per_thread = total / n.max(1);
    let remainder = total % n.max(1);

    let mut chunks = Vec::with_capacity(n);
    let mut iter = tokens.into_iter();

    for t in 0..n {
        let count = per_thread + if t < remainder { 1 } else { 0 };
        chunks.push(iter.by_ref().take(count).collect());
    }
    chunks
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_barrier_contention,
    bench_vec_alloc,
    bench_notify,
    bench_atomic_barrier,
    bench_throughput,
);
criterion_main!(benches);
