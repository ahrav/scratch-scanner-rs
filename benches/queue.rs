//! Benchmarks for the intrusive FIFO queue.
//!
//! Tests push/pop performance, cache behavior across node sizes, and comparison with VecDeque.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::stdx::{Queue, QueueLink, QueueNode};
use std::collections::VecDeque;

const OPS_PER_ITER: u64 = 10_000;

// ============================================================================
// Node Types for Benchmarking
// ============================================================================

/// Tag type for single-queue benchmarks.
#[derive(Debug)]
enum BenchTag {}

/// Tag type for multi-queue benchmarks (first queue).
#[derive(Debug)]
enum Tag1 {}

/// Tag type for multi-queue benchmarks (second queue).
#[derive(Debug)]
enum Tag2 {}

/// Small node (16 bytes) - cache-friendly, fits multiple per cache line.
#[derive(Debug)]
#[repr(C)]
struct SmallNode {
    value: u64,
    link: QueueLink<Self, BenchTag>,
}

impl SmallNode {
    fn new(value: u64) -> Self {
        Self {
            value,
            link: QueueLink::new(),
        }
    }
}

impl QueueNode<BenchTag> for SmallNode {
    fn queue_link(&mut self) -> &mut QueueLink<Self, BenchTag> {
        &mut self.link
    }
    fn queue_link_ref(&self) -> &QueueLink<Self, BenchTag> {
        &self.link
    }
}

/// Medium node (64 bytes) - cache-line sized.
#[derive(Debug)]
#[repr(C, align(64))]
struct MediumNode {
    value: u64,
    link: QueueLink<Self, BenchTag>,
    _padding: [u8; 32],
}

impl MediumNode {
    fn new(value: u64) -> Self {
        Self {
            value,
            link: QueueLink::new(),
            _padding: [0; 32],
        }
    }
}

impl QueueNode<BenchTag> for MediumNode {
    fn queue_link(&mut self) -> &mut QueueLink<Self, BenchTag> {
        &mut self.link
    }
    fn queue_link_ref(&self) -> &QueueLink<Self, BenchTag> {
        &self.link
    }
}

/// Large node (256 bytes) - causes cache pressure.
#[derive(Debug)]
#[repr(C, align(64))]
struct LargeNode {
    value: u64,
    link: QueueLink<Self, BenchTag>,
    _padding: [u8; 224],
}

impl LargeNode {
    fn new(value: u64) -> Self {
        Self {
            value,
            link: QueueLink::new(),
            _padding: [0; 224],
        }
    }
}

impl QueueNode<BenchTag> for LargeNode {
    fn queue_link(&mut self) -> &mut QueueLink<Self, BenchTag> {
        &mut self.link
    }
    fn queue_link_ref(&self) -> &QueueLink<Self, BenchTag> {
        &self.link
    }
}

/// Node with two queue links for multi-tag benchmarks.
#[derive(Debug)]
struct DualTagNode {
    value: u64,
    link1: QueueLink<Self, Tag1>,
    link2: QueueLink<Self, Tag2>,
}

impl DualTagNode {
    fn new(value: u64) -> Self {
        Self {
            value,
            link1: QueueLink::new(),
            link2: QueueLink::new(),
        }
    }
}

impl QueueNode<Tag1> for DualTagNode {
    fn queue_link(&mut self) -> &mut QueueLink<Self, Tag1> {
        &mut self.link1
    }
    fn queue_link_ref(&self) -> &QueueLink<Self, Tag1> {
        &self.link1
    }
}

impl QueueNode<Tag2> for DualTagNode {
    fn queue_link(&mut self) -> &mut QueueLink<Self, Tag2> {
        &mut self.link2
    }
    fn queue_link_ref(&self) -> &QueueLink<Self, Tag2> {
        &self.link2
    }
}

// ============================================================================
// Push Benchmarks
// ============================================================================

fn bench_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/push");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Small nodes
    group.bench_function("small_16B", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            // Drain to unlink nodes for next iteration
            while q.pop().is_some() {}
        })
    });

    // Medium nodes
    group.bench_function("medium_64B", |b| {
        let mut nodes: Vec<MediumNode> = (0..OPS_PER_ITER).map(|i| MediumNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<MediumNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while q.pop().is_some() {}
        })
    });

    // Large nodes
    group.bench_function("large_256B", |b| {
        let mut nodes: Vec<LargeNode> = (0..OPS_PER_ITER).map(|i| LargeNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<LargeNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while q.pop().is_some() {}
        })
    });

    group.finish();
}

// ============================================================================
// Pop Benchmarks
// ============================================================================

fn bench_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/pop");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Small nodes - measure pop in isolation
    // Use same pattern as push: push all, then pop all in each iteration
    group.bench_function("small_16B", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            // Setup: push all nodes (not measured as primary)
            for node in &mut nodes {
                q.push(node);
            }
            // Measured: pop all nodes
            while let Some(ptr) = q.pop() {
                black_box(ptr);
            }
        })
    });

    // Medium nodes
    group.bench_function("medium_64B", |b| {
        let mut nodes: Vec<MediumNode> = (0..OPS_PER_ITER).map(|i| MediumNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<MediumNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while let Some(ptr) = q.pop() {
                black_box(ptr);
            }
        })
    });

    // Large nodes
    group.bench_function("large_256B", |b| {
        let mut nodes: Vec<LargeNode> = (0..OPS_PER_ITER).map(|i| LargeNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<LargeNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while let Some(ptr) = q.pop() {
                black_box(ptr);
            }
        })
    });

    group.finish();
}

// ============================================================================
// Peek Benchmarks
// ============================================================================

fn bench_peek(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/peek");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Peek on empty queue
    group.bench_function("empty", |b| {
        let q: Queue<SmallNode, BenchTag> = Queue::init();
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.peek());
            }
        })
    });

    // Peek on single-element queue
    group.bench_function("single", |b| {
        let mut node = SmallNode::new(42);
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        q.push(&mut node);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.peek());
            }
        })
    });

    // Peek on large queue (10K elements)
    group.bench_function("large_10k", |b| {
        let mut nodes: Vec<SmallNode> = (0..10_000).map(|i| SmallNode::new(i)).collect();
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        for node in &mut nodes {
            q.push(node);
        }
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.peek());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Metadata Benchmarks (is_empty, len)
// ============================================================================

fn bench_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/metadata");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // is_empty on empty queue
    group.bench_function("is_empty/empty", |b| {
        let q: Queue<SmallNode, BenchTag> = Queue::init();
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.is_empty());
            }
        })
    });

    // is_empty on non-empty queue
    group.bench_function("is_empty/non_empty", |b| {
        let mut node = SmallNode::new(42);
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        q.push(&mut node);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.is_empty());
            }
        })
    });

    // len on empty queue
    group.bench_function("len/empty", |b| {
        let q: Queue<SmallNode, BenchTag> = Queue::init();
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.len());
            }
        })
    });

    // len on large queue
    group.bench_function("len/large_10k", |b| {
        let mut nodes: Vec<SmallNode> = (0..10_000).map(|i| SmallNode::new(i)).collect();
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        for node in &mut nodes {
            q.push(node);
        }
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.len());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Fill/Drain Benchmarks
// ============================================================================

fn bench_fill_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/fill_drain");

    for count in [100u64, 1_000, 10_000] {
        group.throughput(Throughput::Elements(count));

        group.bench_with_input(BenchmarkId::new("small", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<SmallNode, BenchTag> = Queue::init();
                // Fill
                for node in &mut nodes {
                    q.push(node);
                }
                // Drain
                while q.pop().is_some() {}
            })
        });

        group.bench_with_input(BenchmarkId::new("medium", count), &count, |b, &count| {
            let mut nodes: Vec<MediumNode> = (0..count).map(|i| MediumNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<MediumNode, BenchTag> = Queue::init();
                for node in &mut nodes {
                    q.push(node);
                }
                while q.pop().is_some() {}
            })
        });

        group.bench_with_input(BenchmarkId::new("large", count), &count, |b, &count| {
            let mut nodes: Vec<LargeNode> = (0..count).map(|i| LargeNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<LargeNode, BenchTag> = Queue::init();
                for node in &mut nodes {
                    q.push(node);
                }
                while q.pop().is_some() {}
            })
        });
    }

    group.finish();
}

// ============================================================================
// Alternating Push/Pop Benchmarks
// ============================================================================

fn bench_alternating(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/alternating");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // 1:1 ratio - push then pop
    group.bench_function("ratio_1_1", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
                black_box(q.pop());
            }
        })
    });

    // 2:1 ratio - push push pop
    group.bench_function("ratio_2_1", |b| {
        let count = OPS_PER_ITER / 2;
        let mut nodes: Vec<SmallNode> = (0..count * 2).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            let mut idx = 0;
            for _ in 0..count {
                q.push(&mut nodes[idx]);
                idx += 1;
                q.push(&mut nodes[idx]);
                idx += 1;
                black_box(q.pop());
            }
            // Drain remaining
            while q.pop().is_some() {}
        })
    });

    // 1:2 ratio - push pop pop (on pre-filled queue)
    group.bench_function("ratio_1_2", |b| {
        let count = OPS_PER_ITER / 3;
        let mut nodes: Vec<SmallNode> = (0..count * 3).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            // Pre-fill with 2*count nodes
            for node in nodes.iter_mut().take(count as usize * 2) {
                q.push(node);
            }
            let mut idx = count as usize * 2;
            for _ in 0..count {
                if idx < nodes.len() {
                    q.push(&mut nodes[idx]);
                    idx += 1;
                }
                black_box(q.pop());
                black_box(q.pop());
            }
            // Drain remaining
            while q.pop().is_some() {}
        })
    });

    group.finish();
}

// ============================================================================
// Steady State Benchmarks (Fixed-size Window)
// ============================================================================

fn bench_steady_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/steady_state");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    for window_size in [10u64, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("window", window_size),
            &window_size,
            |b, &window_size| {
                let total_nodes = window_size + OPS_PER_ITER;
                let mut nodes: Vec<SmallNode> =
                    (0..total_nodes).map(|i| SmallNode::new(i)).collect();
                b.iter(|| {
                    let mut q: Queue<SmallNode, BenchTag> = Queue::init();
                    // Fill to window size
                    for node in nodes.iter_mut().take(window_size as usize) {
                        q.push(node);
                    }
                    // Steady state: push one, pop one
                    for i in window_size as usize..total_nodes as usize {
                        q.push(&mut nodes[i]);
                        black_box(q.pop());
                    }
                    // Drain
                    while q.pop().is_some() {}
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// VecDeque Comparison Benchmarks
// ============================================================================

fn bench_vs_vecdeque(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/vs_vecdeque");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Intrusive queue push/pop cycle
    group.bench_function("intrusive/push_pop", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while q.pop().is_some() {}
        })
    });

    // VecDeque push/pop cycle (stores u64 values like SmallNode.value)
    group.bench_function("vecdeque/push_pop", |b| {
        b.iter(|| {
            let mut q: VecDeque<u64> = VecDeque::new();
            for i in 0..OPS_PER_ITER {
                q.push_back(black_box(i));
            }
            while q.pop_front().is_some() {}
        })
    });

    // VecDeque with pre-allocated capacity
    group.bench_function("vecdeque/push_pop_preallocated", |b| {
        b.iter(|| {
            let mut q: VecDeque<u64> = VecDeque::with_capacity(OPS_PER_ITER as usize);
            for i in 0..OPS_PER_ITER {
                q.push_back(black_box(i));
            }
            while q.pop_front().is_some() {}
        })
    });

    // Alternating push/pop - intrusive
    group.bench_function("intrusive/alternating", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
                black_box(q.pop());
            }
        })
    });

    // Alternating push/pop - VecDeque
    group.bench_function("vecdeque/alternating", |b| {
        b.iter(|| {
            let mut q: VecDeque<u64> = VecDeque::new();
            for i in 0..OPS_PER_ITER {
                q.push_back(black_box(i));
                black_box(q.pop_front());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Cache Pressure Benchmarks
// ============================================================================

fn bench_cache_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/cache_pressure");

    // L1 cache (~32KB) - small working set
    // With SmallNode at 16B, ~2000 nodes fit in L1
    let l1_count = 1_000u64;
    group.throughput(Throughput::Elements(l1_count * 10)); // 10 iterations
    group.bench_function("l1_fit", |b| {
        let mut nodes: Vec<SmallNode> = (0..l1_count).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for _ in 0..10 {
                for node in &mut nodes {
                    q.push(node);
                }
                while q.pop().is_some() {}
            }
        })
    });

    // L2 cache (~256KB) - medium working set
    // With MediumNode at 64B, ~4000 nodes fit in L2
    let l2_count = 2_000u64;
    group.throughput(Throughput::Elements(l2_count * 5));
    group.bench_function("l2_fit", |b| {
        let mut nodes: Vec<MediumNode> = (0..l2_count).map(|i| MediumNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<MediumNode, BenchTag> = Queue::init();
            for _ in 0..5 {
                for node in &mut nodes {
                    q.push(node);
                }
                while q.pop().is_some() {}
            }
        })
    });

    // L3 cache (~8MB) - large working set
    // With LargeNode at 256B, ~32000 nodes fit in L3
    let l3_count = 20_000u64;
    group.throughput(Throughput::Elements(l3_count));
    group.bench_function("l3_pressure", |b| {
        let mut nodes: Vec<LargeNode> = (0..l3_count).map(|i| LargeNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<LargeNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while q.pop().is_some() {}
        })
    });

    group.finish();
}

// ============================================================================
// Assertion Overhead Benchmarks
// ============================================================================

/// This benchmark documents the cost of runtime assertions in the queue.
/// The queue uses `assert!` (not `debug_assert!`) for invariant checks.
fn bench_assertion_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/assertion_overhead");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Note: We can't easily disable assertions in release mode since they use assert!
    // This benchmark documents the current cost with assertions enabled.
    // Compare release vs debug builds to see the full impact.

    group.bench_function("push_with_assertions", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while q.pop().is_some() {}
        })
    });

    group.bench_function("pop_with_assertions", |b| {
        let mut nodes: Vec<SmallNode> = (0..OPS_PER_ITER).map(|i| SmallNode::new(i)).collect();
        b.iter(|| {
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            while let Some(ptr) = q.pop() {
                black_box(ptr);
            }
        })
    });

    // is_empty and len also have assertions
    group.bench_function("is_empty_with_assertions", |b| {
        let mut node = SmallNode::new(42);
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        q.push(&mut node);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.is_empty());
            }
        })
    });

    group.bench_function("len_with_assertions", |b| {
        let mut node = SmallNode::new(42);
        let mut q: Queue<SmallNode, BenchTag> = Queue::init();
        q.push(&mut node);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                black_box(q.len());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Multi-Tag Benchmarks
// ============================================================================

fn bench_multi_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/multi_tag");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Single node in two queues simultaneously
    group.bench_function("dual_queue_push_pop", |b| {
        let mut nodes: Vec<DualTagNode> = (0..OPS_PER_ITER).map(|i| DualTagNode::new(i)).collect();
        b.iter(|| {
            let mut q1: Queue<DualTagNode, Tag1> = Queue::init();
            let mut q2: Queue<DualTagNode, Tag2> = Queue::init();

            // Push to both queues
            for node in &mut nodes {
                q1.push(node);
                q2.push(node);
            }

            // Pop from both queues
            while q1.pop().is_some() {}
            while q2.pop().is_some() {}
        })
    });

    // Alternating between two queues
    group.bench_function("dual_queue_alternating", |b| {
        let mut nodes: Vec<DualTagNode> = (0..OPS_PER_ITER).map(|i| DualTagNode::new(i)).collect();
        b.iter(|| {
            let mut q1: Queue<DualTagNode, Tag1> = Queue::init();
            let mut q2: Queue<DualTagNode, Tag2> = Queue::init();

            for node in &mut nodes {
                q1.push(node);
                q2.push(node);
                black_box(q1.pop());
                black_box(q2.pop());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Scaling Benchmarks
// ============================================================================

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/scaling");

    for count in [10u64, 100, 1_000, 10_000, 100_000] {
        group.throughput(Throughput::Elements(count));

        group.bench_with_input(BenchmarkId::new("push_pop", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<SmallNode, BenchTag> = Queue::init();
                for node in &mut nodes {
                    q.push(node);
                }
                while q.pop().is_some() {}
            })
        });
    }

    group.finish();
}

// ============================================================================
// Bulk Operations Benchmarks
// ============================================================================

fn bench_bulk_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/bulk_ops");

    // reset() benchmark - measures the cost of reset() + link cleanup
    for count in [100u64, 1_000, 10_000] {
        group.throughput(Throughput::Elements(count));

        group.bench_with_input(BenchmarkId::new("reset", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<SmallNode, BenchTag> = Queue::init();
                for node in &mut nodes {
                    q.push(node);
                }
                q.reset();
                black_box(q.is_empty());
                // Must reset node links after queue reset
                for node in &mut nodes {
                    node.link.reset();
                }
            })
        });

        group.bench_with_input(BenchmarkId::new("take_all", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            b.iter(|| {
                let mut q: Queue<SmallNode, BenchTag> = Queue::init();
                for node in &mut nodes {
                    q.push(node);
                }
                let mut taken = q.take_all();
                black_box(taken.len());
                // Drain taken queue to unlink nodes
                while taken.pop().is_some() {}
            })
        });
    }

    group.finish();
}

// ============================================================================
// Contains Benchmarks (O(n) lookup)
// ============================================================================

fn bench_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue/contains");

    for count in [10u64, 100, 1_000, 10_000] {
        group.throughput(Throughput::Elements(1)); // Single lookup

        // Lookup at head (O(1) best case)
        group.bench_with_input(BenchmarkId::new("head", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            b.iter(|| {
                black_box(q.contains(&nodes[0]));
            })
        });

        // Lookup at tail (O(n) worst case)
        group.bench_with_input(BenchmarkId::new("tail", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            let last_idx = count as usize - 1;
            b.iter(|| {
                black_box(q.contains(&nodes[last_idx]));
            })
        });

        // Lookup of non-existent node
        group.bench_with_input(BenchmarkId::new("not_found", count), &count, |b, &count| {
            let mut nodes: Vec<SmallNode> = (0..count).map(|i| SmallNode::new(i)).collect();
            let not_in_queue = SmallNode::new(999_999);
            let mut q: Queue<SmallNode, BenchTag> = Queue::init();
            for node in &mut nodes {
                q.push(node);
            }
            b.iter(|| {
                black_box(q.contains(&not_in_queue));
            })
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_push,
    bench_pop,
    bench_peek,
    bench_metadata,
    bench_fill_drain,
    bench_alternating,
    bench_steady_state,
    bench_vs_vecdeque,
    bench_cache_pressure,
    bench_assertion_overhead,
    bench_multi_tag,
    bench_scaling,
    bench_bulk_ops,
    bench_contains,
);

criterion_main!(benches);
