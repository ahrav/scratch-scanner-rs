//! Optional performance counters for Git scanning instrumentation.
//!
//! Enable with the `git-perf` feature. When disabled, all functions are
//! no-ops and counters return zeroed snapshots.
//!
//! Counters use relaxed atomics for low overhead; snapshots are best-effort
//! and intended for coarse diagnostics rather than exact accounting.

#[cfg(feature = "git-perf")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "git-perf")]
use std::time::Instant;

/// Snapshot of Git scan performance counters.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitPerfStats {
    /// Total bytes inflated from pack entries (uncompressed size).
    pub pack_inflate_bytes: u64,
    /// Wall-clock nanoseconds spent inflating pack entries.
    pub pack_inflate_nanos: u64,
    /// Total bytes produced by delta application (uncompressed size).
    pub delta_apply_bytes: u64,
    /// Wall-clock nanoseconds spent applying deltas.
    pub delta_apply_nanos: u64,
    /// Total bytes scanned by the engine adapter.
    pub scan_bytes: u64,
    /// Wall-clock nanoseconds spent scanning blob bytes.
    pub scan_nanos: u64,
    /// Number of mapping-bridge calls recorded.
    pub mapping_calls: u64,
    /// Wall-clock nanoseconds spent in mapping-bridge calls.
    pub mapping_nanos: u64,
    /// Cache hit count for pack offsets.
    pub cache_hits: u64,
    /// Cache miss count for pack offsets.
    pub cache_misses: u64,
}

#[cfg(feature = "git-perf")]
static PACK_INFLATE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static PACK_INFLATE_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static DELTA_APPLY_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static DELTA_APPLY_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static SCAN_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static SCAN_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static MAPPING_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static MAPPING_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Reset all counters to zero.
///
/// This is a no-op when `git-perf` is disabled.
pub fn reset() {
    #[cfg(feature = "git-perf")]
    {
        PACK_INFLATE_BYTES.store(0, Ordering::Relaxed);
        PACK_INFLATE_NANOS.store(0, Ordering::Relaxed);
        DELTA_APPLY_BYTES.store(0, Ordering::Relaxed);
        DELTA_APPLY_NANOS.store(0, Ordering::Relaxed);
        SCAN_BYTES.store(0, Ordering::Relaxed);
        SCAN_NANOS.store(0, Ordering::Relaxed);
        MAPPING_CALLS.store(0, Ordering::Relaxed);
        MAPPING_NANOS.store(0, Ordering::Relaxed);
        CACHE_HITS.store(0, Ordering::Relaxed);
        CACHE_MISSES.store(0, Ordering::Relaxed);
    }
}

/// Snapshot current counters.
///
/// Returns zeros when `git-perf` is disabled.
#[must_use]
pub fn snapshot() -> GitPerfStats {
    #[cfg(feature = "git-perf")]
    {
        GitPerfStats {
            pack_inflate_bytes: PACK_INFLATE_BYTES.load(Ordering::Relaxed),
            pack_inflate_nanos: PACK_INFLATE_NANOS.load(Ordering::Relaxed),
            delta_apply_bytes: DELTA_APPLY_BYTES.load(Ordering::Relaxed),
            delta_apply_nanos: DELTA_APPLY_NANOS.load(Ordering::Relaxed),
            scan_bytes: SCAN_BYTES.load(Ordering::Relaxed),
            scan_nanos: SCAN_NANOS.load(Ordering::Relaxed),
            mapping_calls: MAPPING_CALLS.load(Ordering::Relaxed),
            mapping_nanos: MAPPING_NANOS.load(Ordering::Relaxed),
            cache_hits: CACHE_HITS.load(Ordering::Relaxed),
            cache_misses: CACHE_MISSES.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "git-perf"))]
    {
        GitPerfStats::default()
    }
}

/// Time a closure, returning `(result, nanos)`.
///
/// Returns `(result, 0)` when `git-perf` is disabled.
pub fn time<F, R>(f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    #[cfg(feature = "git-perf")]
    {
        let start = Instant::now();
        let out = f();
        let nanos = start.elapsed().as_nanos() as u64;
        (out, nanos)
    }

    #[cfg(not(feature = "git-perf"))]
    {
        (f(), 0)
    }
}

/// Record pack entry inflation metrics.
pub fn record_pack_inflate(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        PACK_INFLATE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        PACK_INFLATE_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record delta application metrics.
pub fn record_delta_apply(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        DELTA_APPLY_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        DELTA_APPLY_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record blob scan metrics.
pub fn record_scan(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        SCAN_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        SCAN_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record a mapping-bridge invocation.
pub fn record_mapping(nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        MAPPING_CALLS.fetch_add(1, Ordering::Relaxed);
        MAPPING_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = nanos;
    }
}

/// Record a cache hit for a pack offset.
pub fn record_cache_hit() {
    #[cfg(feature = "git-perf")]
    {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a cache miss for a pack offset.
pub fn record_cache_miss() {
    #[cfg(feature = "git-perf")]
    {
        CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}
