//! Optional performance counters for Git scanning instrumentation.
//!
//! When enabled, counters cover pack decode/scan, mapping, and tree-load
//! operations to isolate bottlenecks in commit-walk pipelines.
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
    /// Tree load calls (ObjectStore::load_tree).
    pub tree_load_calls: u64,
    /// Tree load bytes (payload length).
    pub tree_load_bytes: u64,
    /// Wall-clock nanoseconds spent in tree loads.
    pub tree_load_nanos: u64,
    /// Tree cache hits.
    pub tree_cache_hits: u64,
    /// Tree delta cache hits.
    pub tree_delta_cache_hits: u64,
    /// Tree delta cache misses.
    pub tree_delta_cache_misses: u64,
    /// Tree delta cache bytes reused.
    pub tree_delta_cache_bytes: u64,
    /// Wall-clock nanoseconds spent resolving delta bases from cache hits.
    pub tree_delta_cache_hit_nanos: u64,
    /// Wall-clock nanoseconds spent resolving delta bases after cache misses.
    pub tree_delta_cache_miss_nanos: u64,
    /// Tree delta chain length = 0.
    pub tree_delta_chain_0: u64,
    /// Tree delta chain length = 1.
    pub tree_delta_chain_1: u64,
    /// Tree delta chain length = 2..=3.
    pub tree_delta_chain_2_3: u64,
    /// Tree delta chain length = 4..=7.
    pub tree_delta_chain_4_7: u64,
    /// Tree delta chain length >= 8.
    pub tree_delta_chain_8_plus: u64,
    /// Tree spill index hits.
    pub tree_spill_hits: u64,
    /// Tree object loads (cache/spill misses).
    pub tree_object_loads: u64,
    /// Tree object bytes decoded.
    pub tree_object_bytes: u64,
    /// Wall-clock nanoseconds spent decoding tree objects.
    pub tree_object_nanos: u64,
    /// Tree inflate bytes (tree payloads or delta instruction streams).
    pub tree_inflate_bytes: u64,
    /// Wall-clock nanoseconds spent inflating tree payloads or delta streams.
    pub tree_inflate_nanos: u64,
    /// Tree delta apply bytes (post-delta output size).
    pub tree_delta_apply_bytes: u64,
    /// Wall-clock nanoseconds spent applying tree deltas.
    pub tree_delta_apply_nanos: u64,
    /// Tree objects loaded from pack files.
    pub tree_object_pack: u64,
    /// Tree objects loaded from loose objects.
    pub tree_object_loose: u64,
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
#[cfg(feature = "git-perf")]
static TREE_LOAD_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_LOAD_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_LOAD_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CACHE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CACHE_HIT_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CACHE_MISS_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CHAIN_0: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CHAIN_1: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CHAIN_2_3: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CHAIN_4_7: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_CHAIN_8_PLUS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_SPILL_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_OBJECT_LOADS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_OBJECT_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_OBJECT_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_INFLATE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_INFLATE_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_APPLY_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_DELTA_APPLY_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_OBJECT_PACK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "git-perf")]
static TREE_OBJECT_LOOSE: AtomicU64 = AtomicU64::new(0);

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
        TREE_LOAD_CALLS.store(0, Ordering::Relaxed);
        TREE_LOAD_BYTES.store(0, Ordering::Relaxed);
        TREE_LOAD_NANOS.store(0, Ordering::Relaxed);
        TREE_CACHE_HITS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_HITS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_MISSES.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_BYTES.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_HIT_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_MISS_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_0.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_1.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_2_3.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_4_7.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_8_PLUS.store(0, Ordering::Relaxed);
        TREE_SPILL_HITS.store(0, Ordering::Relaxed);
        TREE_OBJECT_LOADS.store(0, Ordering::Relaxed);
        TREE_OBJECT_BYTES.store(0, Ordering::Relaxed);
        TREE_OBJECT_NANOS.store(0, Ordering::Relaxed);
        TREE_INFLATE_BYTES.store(0, Ordering::Relaxed);
        TREE_INFLATE_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_APPLY_BYTES.store(0, Ordering::Relaxed);
        TREE_DELTA_APPLY_NANOS.store(0, Ordering::Relaxed);
        TREE_OBJECT_PACK.store(0, Ordering::Relaxed);
        TREE_OBJECT_LOOSE.store(0, Ordering::Relaxed);
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
            tree_load_calls: TREE_LOAD_CALLS.load(Ordering::Relaxed),
            tree_load_bytes: TREE_LOAD_BYTES.load(Ordering::Relaxed),
            tree_load_nanos: TREE_LOAD_NANOS.load(Ordering::Relaxed),
            tree_cache_hits: TREE_CACHE_HITS.load(Ordering::Relaxed),
            tree_delta_cache_hits: TREE_DELTA_CACHE_HITS.load(Ordering::Relaxed),
            tree_delta_cache_misses: TREE_DELTA_CACHE_MISSES.load(Ordering::Relaxed),
            tree_delta_cache_bytes: TREE_DELTA_CACHE_BYTES.load(Ordering::Relaxed),
            tree_delta_cache_hit_nanos: TREE_DELTA_CACHE_HIT_NANOS.load(Ordering::Relaxed),
            tree_delta_cache_miss_nanos: TREE_DELTA_CACHE_MISS_NANOS.load(Ordering::Relaxed),
            tree_delta_chain_0: TREE_DELTA_CHAIN_0.load(Ordering::Relaxed),
            tree_delta_chain_1: TREE_DELTA_CHAIN_1.load(Ordering::Relaxed),
            tree_delta_chain_2_3: TREE_DELTA_CHAIN_2_3.load(Ordering::Relaxed),
            tree_delta_chain_4_7: TREE_DELTA_CHAIN_4_7.load(Ordering::Relaxed),
            tree_delta_chain_8_plus: TREE_DELTA_CHAIN_8_PLUS.load(Ordering::Relaxed),
            tree_spill_hits: TREE_SPILL_HITS.load(Ordering::Relaxed),
            tree_object_loads: TREE_OBJECT_LOADS.load(Ordering::Relaxed),
            tree_object_bytes: TREE_OBJECT_BYTES.load(Ordering::Relaxed),
            tree_object_nanos: TREE_OBJECT_NANOS.load(Ordering::Relaxed),
            tree_inflate_bytes: TREE_INFLATE_BYTES.load(Ordering::Relaxed),
            tree_inflate_nanos: TREE_INFLATE_NANOS.load(Ordering::Relaxed),
            tree_delta_apply_bytes: TREE_DELTA_APPLY_BYTES.load(Ordering::Relaxed),
            tree_delta_apply_nanos: TREE_DELTA_APPLY_NANOS.load(Ordering::Relaxed),
            tree_object_pack: TREE_OBJECT_PACK.load(Ordering::Relaxed),
            tree_object_loose: TREE_OBJECT_LOOSE.load(Ordering::Relaxed),
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

/// Record a tree load (ObjectStore::load_tree).
pub fn record_tree_load(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        TREE_LOAD_CALLS.fetch_add(1, Ordering::Relaxed);
        TREE_LOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_LOAD_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record a tree-cache hit.
pub fn record_tree_cache_hit() {
    #[cfg(feature = "git-perf")]
    {
        TREE_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a tree delta-cache hit.
pub fn record_tree_delta_cache_hit(bytes: usize) {
    #[cfg(feature = "git-perf")]
    {
        TREE_DELTA_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        TREE_DELTA_CACHE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = bytes;
    }
}

/// Record time spent resolving delta bases from cache hits.
pub fn record_tree_delta_cache_hit_nanos(nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        TREE_DELTA_CACHE_HIT_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = nanos;
    }
}

/// Record a tree delta-cache miss.
pub fn record_tree_delta_cache_miss() {
    #[cfg(feature = "git-perf")]
    {
        TREE_DELTA_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record time spent resolving delta bases after cache misses.
pub fn record_tree_delta_cache_miss_nanos(nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        TREE_DELTA_CACHE_MISS_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = nanos;
    }
}

/// Record a tree delta chain length.
pub fn record_tree_delta_chain(chain_len: u8) {
    #[cfg(feature = "git-perf")]
    {
        match chain_len {
            0 => TREE_DELTA_CHAIN_0.fetch_add(1, Ordering::Relaxed),
            1 => TREE_DELTA_CHAIN_1.fetch_add(1, Ordering::Relaxed),
            2 | 3 => TREE_DELTA_CHAIN_2_3.fetch_add(1, Ordering::Relaxed),
            4..=7 => TREE_DELTA_CHAIN_4_7.fetch_add(1, Ordering::Relaxed),
            _ => TREE_DELTA_CHAIN_8_PLUS.fetch_add(1, Ordering::Relaxed),
        };
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = chain_len;
    }
}

/// Record a spill-index hit for a tree payload.
pub fn record_tree_spill_hit() {
    #[cfg(feature = "git-perf")]
    {
        TREE_SPILL_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a decoded tree object payload.
pub fn record_tree_object(bytes: usize, nanos: u64, from_pack: bool) {
    #[cfg(feature = "git-perf")]
    {
        TREE_OBJECT_LOADS.fetch_add(1, Ordering::Relaxed);
        TREE_OBJECT_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_OBJECT_NANOS.fetch_add(nanos, Ordering::Relaxed);
        if from_pack {
            TREE_OBJECT_PACK.fetch_add(1, Ordering::Relaxed);
        } else {
            TREE_OBJECT_LOOSE.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos, from_pack);
    }
}

/// Record tree inflate metrics (payload or delta instruction streams).
pub fn record_tree_inflate(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        TREE_INFLATE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_INFLATE_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record tree delta apply metrics.
pub fn record_tree_delta_apply(bytes: usize, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        TREE_DELTA_APPLY_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_DELTA_APPLY_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (bytes, nanos);
    }
}
