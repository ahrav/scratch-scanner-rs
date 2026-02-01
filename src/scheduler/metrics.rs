//! # Metrics Module
//!
//! Cheap, deterministic metrics collection for scheduler observability.
//!
//! ## Design
//!
//! - **Per-worker local metrics**: Hot path updates are plain integer ops (no atomics)
//! - **Cache-line aligned**: Prevents false sharing when workers are in contiguous memory
//! - **Log2 histogram**: O(1) record, O(64) percentile lookup
//! - **Post-run aggregation**: Merge after workers join, avoiding contention
//!
//! ## Performance Characteristics
//!
//! | Operation | Cost | Notes |
//! |-----------|------|-------|
//! | `record()` | ~3-5 cycles | No bounds checks, wrapping arithmetic |
//! | `merge()` | ~64 adds | One pass over buckets |
//! | `percentile()` | ~64 compares | Linear scan (could be optimized) |
//!
//! ## False Sharing Prevention
//!
//! `WorkerMetricsLocal` is aligned to 64 bytes (cache line size on x86-64).
//! When workers store metrics in a contiguous array (e.g., `Vec<WorkerMetricsLocal>`),
//! this alignment ensures each worker's hot counters don't share cache lines with
//! adjacent workers, preventing cache thrashing.
//!
//! ## Log2 Histogram Precision
//!
//! Bucket k covers `[2^k, 2^(k+1))`, giving ~50% error margin.
//! This is acceptable for scheduler observability where we care about order-of-magnitude
//! differences (e.g., "did P99 go from microseconds to milliseconds?").
//!
//! For higher precision, consider linear-log hybrid histograms (future work).

/// Log2 histogram for cheap p95/p99-ish tracking.
///
/// Buckets represent power-of-2 ranges:
/// - Bucket 0: [0, 2)
/// - Bucket 1: [2, 4)
/// - Bucket k: [2^k, 2^(k+1))
///
/// Maximum trackable value is 2^63.
///
/// ## Precision note
///
/// Error margin is ~50% (values 512 and 1023 both land in bucket 9).
/// Sufficient for detecting order-of-magnitude regressions, not subtle degradations.
#[derive(Clone, Debug)]
pub struct Log2Hist {
    /// Count per bucket.
    pub buckets: [u64; 64],
    /// Total count of recorded values.
    pub count: u64,
    /// Sum of all recorded values (for mean calculation).
    /// Uses wrapping arithmetic - will overflow after ~584 years of nanoseconds.
    pub sum: u64,
}

impl Default for Log2Hist {
    fn default() -> Self {
        Self::new()
    }
}

impl Log2Hist {
    /// Create a new empty histogram.
    pub const fn new() -> Self {
        Self {
            buckets: [0; 64],
            count: 0,
            sum: 0,
        }
    }

    /// Record a value.
    ///
    /// # Performance
    /// - No bounds checks (bucket_index guarantees 0..64)
    /// - Wrapping arithmetic (no overflow checks)
    /// - ~3-5 cycles on modern x86-64
    #[inline(always)]
    pub fn record(&mut self, v: u64) {
        let b = bucket_index(v);
        // SAFETY: bucket_index always returns 0..63 (see its implementation).
        // The index is derived from leading_zeros which is 0..64 for u64,
        // and our formula maps that to 0..63.
        unsafe {
            let slot = self.buckets.get_unchecked_mut(b);
            *slot = slot.wrapping_add(1);
        }
        self.count = self.count.wrapping_add(1);
        self.sum = self.sum.wrapping_add(v);
    }

    /// Record multiple identical values (batch recording).
    ///
    /// # Performance
    /// Same as `record()` - useful when you have a count of events at the same value.
    #[inline(always)]
    pub fn record_n(&mut self, v: u64, n: u64) {
        if n == 0 {
            return;
        }
        let b = bucket_index(v);
        // SAFETY: same as record() - bucket_index guarantees 0..63
        unsafe {
            let slot = self.buckets.get_unchecked_mut(b);
            *slot = slot.wrapping_add(n);
        }
        self.count = self.count.wrapping_add(n);
        self.sum = self.sum.wrapping_add(v.wrapping_mul(n));
    }

    /// Approximate percentile by returning the bucket lower bound.
    ///
    /// # Arguments
    /// * `p` - Percentile as a fraction in [0.0, 1.0]
    ///
    /// # Returns
    /// - `Some(lower_bound)` of the bucket containing that percentile
    /// - `None` if no values have been recorded
    ///
    /// # Precision note
    /// Returns the *lower* bound of the bucket. If all values are 1,
    /// p50 returns 0 (the lower bound of bucket 0 which covers [0, 2)).
    pub fn percentile_lower_bound(&self, p: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        debug_assert!((0.0..=1.0).contains(&p), "percentile must be in [0.0, 1.0]");

        let target = ((self.count as f64) * p).ceil() as u64;
        let mut seen = 0u64;

        for (i, &c) in self.buckets.iter().enumerate() {
            seen = seen.wrapping_add(c);
            if seen >= target {
                return Some(bucket_lower_bound(i));
            }
        }
        Some(1u64 << 63)
    }

    /// Get the p50 (median) lower bound.
    #[inline]
    pub fn p50(&self) -> Option<u64> {
        self.percentile_lower_bound(0.50)
    }

    /// Get the p95 lower bound.
    #[inline]
    pub fn p95(&self) -> Option<u64> {
        self.percentile_lower_bound(0.95)
    }

    /// Get the p99 lower bound.
    #[inline]
    pub fn p99(&self) -> Option<u64> {
        self.percentile_lower_bound(0.99)
    }

    /// Mean value (returns 0 if no values recorded).
    ///
    /// Note: May be inaccurate if sum has wrapped (after ~584 years of ns values).
    #[inline]
    pub fn mean(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.sum.wrapping_div(self.count)
        }
    }

    /// Merge another histogram into this one.
    pub fn merge(&mut self, other: &Log2Hist) {
        for i in 0..64 {
            self.buckets[i] = self.buckets[i].wrapping_add(other.buckets[i]);
        }
        self.count = self.count.wrapping_add(other.count);
        self.sum = self.sum.wrapping_add(other.sum);
    }

    /// Reset the histogram to empty state.
    pub fn reset(&mut self) {
        self.buckets = [0; 64];
        self.count = 0;
        self.sum = 0;
    }
}

/// Compute bucket index for a value.
///
/// # Returns
/// Index in range [0, 63].
///
/// # Mapping
/// - 0 -> bucket 0
/// - 1 -> bucket 0
/// - 2..3 -> bucket 1
/// - 4..7 -> bucket 2
/// - 2^k..(2^(k+1)-1) -> bucket k
#[inline(always)]
fn bucket_index(v: u64) -> usize {
    if v == 0 {
        return 0;
    }
    // leading_zeros is 0..64 for u64
    // For v=1: lz=63, result=0
    // For v=2: lz=62, result=1
    // For v=2^63: lz=0, result=63
    (63 - v.leading_zeros()) as usize
}

/// Get the lower bound of a bucket.
#[inline]
fn bucket_lower_bound(bucket: usize) -> u64 {
    if bucket == 0 {
        0
    } else {
        1u64 << bucket
    }
}

/// Per-worker local metrics.
///
/// # Cache Line Alignment
///
/// Aligned to 64 bytes to prevent false sharing when workers store metrics
/// in contiguous memory. Without this, adjacent workers' updates would
/// invalidate each other's cache lines, causing significant slowdown.
///
/// # Thread Safety
///
/// NOT thread-safe. Each worker must own its metrics exclusively during
/// execution. Aggregate via `MetricsSnapshot::merge_worker` after workers join.
///
/// # Hot Path Design
///
/// All updates are plain integer ops with wrapping arithmetic.
/// No atomics, no locks, no bounds checks on histograms.
#[derive(Clone, Debug, Default)]
#[repr(align(64))] // Cache line alignment - prevents false sharing
pub struct WorkerMetricsLocal {
    // ===== HOT COUNTERS (first cache line) =====
    // Group frequently-updated fields together for cache locality
    /// Tasks executed by this worker.
    pub tasks_executed: u64,
    /// Tasks enqueued by this worker (local spawns).
    pub tasks_enqueued: u64,
    /// Local pops (tasks from own deque).
    pub local_pops: u64,
    /// Successful steals.
    pub steal_successes: u64,
    /// Bytes scanned by this worker.
    pub bytes_scanned: u64,
    /// Chunks scanned by this worker.
    pub chunks_scanned: u64,
    /// Objects completed by this worker.
    pub objects_completed: u64,
    /// Steal attempts.
    pub steal_attempts: u64,
    // 8 * 8 = 64 bytes (one cache line)

    // ===== SECONDARY COUNTERS (second cache line) =====
    /// Injector pops (tasks from global queue).
    pub injector_pops: u64,
    /// Idle spin iterations.
    pub idle_spins: u64,
    /// Times worker parked (slept).
    pub park_count: u64,
    /// I/O errors encountered (file open, read, metadata failures).
    pub io_errors: u64,
    // Padding to separate from histograms
    _pad: [u64; 4],
    // 8 * 8 = 64 bytes (second cache line)

    // ===== COLD DATA (histograms - rarely read during execution) =====
    /// Time-in-queue observations in nanoseconds.
    pub queue_time_ns: Log2Hist,
    /// Task execution time observations in nanoseconds.
    pub task_time_ns: Log2Hist,
}

// Compile-time verification of alignment
const _: () = {
    // WorkerMetricsLocal must be cache-line aligned
    assert!(std::mem::align_of::<WorkerMetricsLocal>() >= 64);
};

impl WorkerMetricsLocal {
    /// Create new empty worker metrics.
    pub const fn new() -> Self {
        Self {
            tasks_executed: 0,
            tasks_enqueued: 0,
            local_pops: 0,
            steal_successes: 0,
            bytes_scanned: 0,
            chunks_scanned: 0,
            objects_completed: 0,
            steal_attempts: 0,
            injector_pops: 0,
            idle_spins: 0,
            park_count: 0,
            io_errors: 0,
            _pad: [0; 4],
            queue_time_ns: Log2Hist::new(),
            task_time_ns: Log2Hist::new(),
        }
    }

    /// Local hit rate: `local_pops / (local_pops + injector_pops + steal_successes)`.
    ///
    /// Measures how often this worker consumed tasks from its own deque vs.
    /// fetching from the global injector or stealing from peers.
    pub fn local_hit_rate(&self) -> f64 {
        let total = self
            .local_pops
            .wrapping_add(self.injector_pops)
            .wrapping_add(self.steal_successes);
        if total == 0 {
            0.0
        } else {
            self.local_pops as f64 / total as f64
        }
    }

    /// Steal success rate: `steal_successes / steal_attempts`.
    ///
    /// Indicates how often steal attempts found work. A rate near 0 means
    /// peers' deques were usually empty when this worker tried to steal.
    pub fn steal_rate(&self) -> f64 {
        if self.steal_attempts == 0 {
            0.0
        } else {
            self.steal_successes as f64 / self.steal_attempts as f64
        }
    }
}

/// Aggregated metrics snapshot from all workers.
///
/// # Lifecycle
///
/// 1. Workers run with their own [`WorkerMetricsLocal`] (no contention)
/// 2. After all workers join, create one `MetricsSnapshot`
/// 3. Call [`merge_worker`](Self::merge_worker) for each worker's metrics
/// 4. Query aggregate statistics (rates, percentiles, throughput)
///
/// # Thread Safety
///
/// Like `WorkerMetricsLocal`, this is **not thread-safe**. Intended for
/// single-threaded aggregation after parallel work completes.
///
/// # Example
///
/// ```ignore
/// let mut snapshot = MetricsSnapshot::new();
/// for worker in workers {
///     snapshot.merge_worker(&worker.metrics);
/// }
/// snapshot.duration_ns = elapsed.as_nanos() as u64;
/// println!("Throughput: {:.2} GB/s", snapshot.gb_per_sec());
/// ```
#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    /// Total tasks enqueued across all workers.
    pub tasks_enqueued: u64,
    /// Total tasks executed across all workers.
    pub tasks_executed: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Total chunks scanned.
    pub chunks_scanned: u64,
    /// Total objects completed.
    pub objects_completed: u64,

    /// Total local pops.
    pub local_pops: u64,
    /// Total steal attempts.
    pub steal_attempts: u64,
    /// Total successful steals.
    pub steal_successes: u64,
    /// Total injector pops.
    pub injector_pops: u64,

    /// Merged queue time histogram.
    pub queue_time_ns: Log2Hist,
    /// Merged task time histogram.
    pub task_time_ns: Log2Hist,

    /// Total idle spins.
    pub idle_spins: u64,
    /// Total park count.
    pub park_count: u64,
    /// Total I/O errors (file open, read, metadata failures).
    pub io_errors: u64,

    /// Number of workers merged.
    pub worker_count: u32,
    /// Run duration in nanoseconds (if tracked externally).
    pub duration_ns: u64,
}

impl MetricsSnapshot {
    /// Create a new empty snapshot.
    pub const fn new() -> Self {
        Self {
            tasks_enqueued: 0,
            tasks_executed: 0,
            bytes_scanned: 0,
            chunks_scanned: 0,
            objects_completed: 0,
            local_pops: 0,
            steal_attempts: 0,
            steal_successes: 0,
            injector_pops: 0,
            queue_time_ns: Log2Hist::new(),
            task_time_ns: Log2Hist::new(),
            idle_spins: 0,
            park_count: 0,
            io_errors: 0,
            worker_count: 0,
            duration_ns: 0,
        }
    }

    /// Merge a worker's local metrics into this aggregate snapshot.
    ///
    /// Accumulates all counters and merges histograms. Call once per worker
    /// after workers have joined. Increments `worker_count` automatically.
    ///
    /// # Performance
    ///
    /// O(1) for counters + O(64) for histogram merge. Total ~70 additions.
    pub fn merge_worker(&mut self, w: &WorkerMetricsLocal) {
        self.tasks_enqueued = self.tasks_enqueued.wrapping_add(w.tasks_enqueued);
        self.tasks_executed = self.tasks_executed.wrapping_add(w.tasks_executed);
        self.bytes_scanned = self.bytes_scanned.wrapping_add(w.bytes_scanned);
        self.chunks_scanned = self.chunks_scanned.wrapping_add(w.chunks_scanned);
        self.objects_completed = self.objects_completed.wrapping_add(w.objects_completed);

        self.local_pops = self.local_pops.wrapping_add(w.local_pops);
        self.steal_attempts = self.steal_attempts.wrapping_add(w.steal_attempts);
        self.steal_successes = self.steal_successes.wrapping_add(w.steal_successes);
        self.injector_pops = self.injector_pops.wrapping_add(w.injector_pops);

        self.queue_time_ns.merge(&w.queue_time_ns);
        self.task_time_ns.merge(&w.task_time_ns);

        self.idle_spins = self.idle_spins.wrapping_add(w.idle_spins);
        self.park_count = self.park_count.wrapping_add(w.park_count);
        self.io_errors = self.io_errors.wrapping_add(w.io_errors);

        self.worker_count = self.worker_count.wrapping_add(1);
    }

    /// Aggregate local hit rate: `local_pops / (local_pops + injector_pops + steal_successes)`.
    ///
    /// Higher values (>0.8) indicate good work locality - workers mostly consume
    /// their own spawned tasks. Low values suggest excessive stealing or reliance
    /// on the global injector queue.
    pub fn local_hit_rate(&self) -> f64 {
        let total = self
            .local_pops
            .wrapping_add(self.injector_pops)
            .wrapping_add(self.steal_successes);
        if total == 0 {
            0.0
        } else {
            self.local_pops as f64 / total as f64
        }
    }

    /// Aggregate steal success rate: `steal_successes / steal_attempts`.
    ///
    /// Low steal rates (<0.1) may indicate:
    /// - Workers are well-balanced (steals rarely needed)
    /// - Deques are often empty when stealing (potential idleness)
    ///
    /// Very high steal rates (>0.5) suggest work is poorly distributed.
    pub fn steal_rate(&self) -> f64 {
        if self.steal_attempts == 0 {
            0.0
        } else {
            self.steal_successes as f64 / self.steal_attempts as f64
        }
    }

    /// Tasks completed per second: `tasks_executed / (duration_ns / 1e9)`.
    ///
    /// Returns 0.0 if `duration_ns` is not set. Set `duration_ns` from your
    /// external timer after workers complete.
    pub fn tasks_per_sec(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.tasks_executed as f64 / (self.duration_ns as f64 / 1_000_000_000.0)
        }
    }

    /// Bytes scanned per second: `bytes_scanned / (duration_ns / 1e9)`.
    ///
    /// Returns 0.0 if `duration_ns` is not set.
    pub fn bytes_per_sec(&self) -> f64 {
        if self.duration_ns == 0 {
            0.0
        } else {
            self.bytes_scanned as f64 / (self.duration_ns as f64 / 1_000_000_000.0)
        }
    }

    /// Throughput in GiB/s (gibibytes, 1024³ bytes).
    ///
    /// Returns 0.0 if `duration_ns` is not set. Useful for comparing against
    /// disk/network bandwidth limits.
    pub fn gb_per_sec(&self) -> f64 {
        self.bytes_per_sec() / (1024.0 * 1024.0 * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_correctness() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 0);
        assert_eq!(bucket_index(2), 1);
        assert_eq!(bucket_index(3), 1);
        assert_eq!(bucket_index(4), 2);
        assert_eq!(bucket_index(7), 2);
        assert_eq!(bucket_index(8), 3);
        assert_eq!(bucket_index(1023), 9);
        assert_eq!(bucket_index(1024), 10);
        assert_eq!(bucket_index(u64::MAX), 63);
    }

    #[test]
    fn bucket_index_exhaustive_boundaries() {
        // Verify all bucket boundaries
        for b in 1..63 {
            let boundary = 1u64 << b;
            assert_eq!(
                bucket_index(boundary - 1),
                b - 1,
                "2^{}-1 should be in bucket {}",
                b,
                b - 1
            );
            assert_eq!(
                bucket_index(boundary),
                b,
                "2^{} should be in bucket {}",
                b,
                b
            );
        }
    }

    #[test]
    fn log2_hist_basic() {
        let mut h = Log2Hist::new();
        h.record(0);
        h.record(1);
        h.record(2);
        h.record(1000);

        assert_eq!(h.count, 4);
        assert_eq!(h.buckets[0], 2); // 0 and 1
        assert_eq!(h.buckets[1], 1); // 2
        assert_eq!(h.buckets[9], 1); // 1000
        assert_eq!(h.sum, 1 + 2 + 1000); // 0 + 1 + 2 + 1000
    }

    #[test]
    fn log2_hist_record_n() {
        let mut h = Log2Hist::new();
        h.record_n(100, 5); // 5 values of 100

        assert_eq!(h.count, 5);
        assert_eq!(h.buckets[6], 5); // 100 is in bucket 6 [64, 128)
        assert_eq!(h.sum, 500);
    }

    #[test]
    fn log2_hist_percentile_bounds() {
        let mut h = Log2Hist::new();
        // 100 values around 10
        for _ in 0..100 {
            h.record(10);
        }
        // 10 values around 1000
        for _ in 0..10 {
            h.record(1000);
        }

        let p50 = h.p50().unwrap();
        let p90 = h.percentile_lower_bound(0.90).unwrap();
        let p95 = h.p95().unwrap();
        let p99 = h.p99().unwrap();

        // p50 should be in the bucket containing 10 (bucket 3: [8, 16))
        assert_eq!(p50, 8, "p50 should be lower bound of bucket containing 10");

        // p90 = ceil(0.90 * 110) = 99, still in first 100 values
        assert_eq!(p90, 8, "p90 should still be in bucket containing 10");

        // p95 = ceil(0.95 * 110) = 105, which is past the first 100 values
        // So p95 lands in the bucket containing 1000 (bucket 9: [512, 1024))
        assert_eq!(p95, 512, "p95 crosses into bucket containing 1000");

        // p99 should be in the bucket containing 1000 (bucket 9: [512, 1024))
        assert_eq!(p99, 512, "p99 should be in bucket containing 1000");
    }

    #[test]
    fn log2_hist_merge() {
        let mut h1 = Log2Hist::new();
        let mut h2 = Log2Hist::new();

        h1.record(10);
        h1.record(100);
        h2.record(1000);
        h2.record(10000);

        h1.merge(&h2);

        assert_eq!(h1.count, 4);
        assert_eq!(h1.sum, 10 + 100 + 1000 + 10000);
    }

    #[test]
    fn worker_metrics_cache_alignment() {
        // Verify cache line alignment
        assert!(std::mem::align_of::<WorkerMetricsLocal>() >= 64);

        // Verify size is reasonable (should be multiple of 64 for clean array layout)
        let size = std::mem::size_of::<WorkerMetricsLocal>();
        assert!(size > 0);
        // Note: exact size depends on histogram size, just verify it's reasonable
    }

    #[test]
    fn worker_metrics_rates() {
        let mut wm = WorkerMetricsLocal::new();
        wm.local_pops = 80;
        wm.steal_attempts = 100;
        wm.steal_successes = 15;
        wm.injector_pops = 5;

        // local_hit_rate = 80 / (80 + 5 + 15) = 0.8
        assert!((wm.local_hit_rate() - 0.8).abs() < 0.001);

        // steal_rate = 15 / 100 = 0.15
        assert!((wm.steal_rate() - 0.15).abs() < 0.001);
    }

    #[test]
    fn snapshot_merge_workers() {
        let mut w1 = WorkerMetricsLocal::new();
        let mut w2 = WorkerMetricsLocal::new();

        w1.tasks_executed = 100;
        w1.bytes_scanned = 1000;
        w1.local_pops = 90;

        w2.tasks_executed = 150;
        w2.bytes_scanned = 2000;
        w2.local_pops = 140;

        let mut snap = MetricsSnapshot::new();
        snap.merge_worker(&w1);
        snap.merge_worker(&w2);

        assert_eq!(snap.tasks_executed, 250);
        assert_eq!(snap.bytes_scanned, 3000);
        assert_eq!(snap.local_pops, 230);
        assert_eq!(snap.worker_count, 2);
    }

    #[test]
    fn snapshot_throughput_calculations() {
        let mut snap = MetricsSnapshot::new();
        snap.tasks_executed = 1000;
        snap.bytes_scanned = 1_000_000_000; // 1 GB
        snap.duration_ns = 1_000_000_000; // 1 second

        assert!((snap.tasks_per_sec() - 1000.0).abs() < 0.001);
        assert!((snap.bytes_per_sec() - 1_000_000_000.0).abs() < 1.0);
        assert!((snap.gb_per_sec() - 0.931).abs() < 0.01); // ~0.93 GiB
    }

    #[test]
    fn false_sharing_prevention() {
        // Create an array of worker metrics (simulating multi-worker scenario)
        let workers: Vec<WorkerMetricsLocal> = (0..4).map(|_| WorkerMetricsLocal::new()).collect();

        // Verify each worker is on a different cache line
        for i in 0..workers.len() - 1 {
            let addr_a = &workers[i] as *const _ as usize;
            let addr_b = &workers[i + 1] as *const _ as usize;
            let distance = addr_b - addr_a;

            // Distance should be at least 64 bytes (cache line)
            assert!(
                distance >= 64,
                "Workers {} and {} are only {} bytes apart (should be >= 64)",
                i,
                i + 1,
                distance
            );
        }
    }
}
