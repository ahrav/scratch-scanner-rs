# Investigation: HitAccPool Memory Sizing

**Status**: Open for future investigation  
**Priority**: Medium (optimization, not correctness)  
**Created**: 2025-02-02  
**Context**: Memory allocation analysis for multi-core scanning

## Problem Statement

The `HitAccPool` dominates per-worker memory allocation at **83.3%** (~15.68 MiB per worker).
This is sized for worst-case scenarios, but may be significantly over-provisioned for typical
workloads. Reducing this could cut scanner memory usage by 40-70%.

## Current Memory Breakdown

### Per-Worker Allocation (~18.8 MiB)

| Component | Size | % of Total | Notes |
|-----------|------|------------|-------|
| **HitAccPool.windows** | 15.68 MiB | 83.3% | Dominant allocation |
| FixedSet128 (seen_findings) | 768 KiB | 4.0% | |
| FindingRec buffers | 640 KiB | 3.3% | |
| DecodeSlab | 512 KiB | 2.6% | |
| Other | ~1.2 MiB | 6.8% | ByteRing, TimingWheel, etc. |

### System Total by Worker Count

| Workers | Per-Worker | Buffer Pool | Total |
|---------|------------|-------------|-------|
| 8 | 150.5 MiB | 10.0 MiB | **160.5 MiB** |
| 12 | 225.8 MiB | 15.0 MiB | **240.8 MiB** |
| 16 | 301.1 MiB | 20.0 MiB | **321.1 MiB** |

## Root Cause Analysis

### HitAccPool Allocation Formula

```
HitAccPool.windows = pair_count × max_anchor_hits × sizeof(SpanU32)
                   = 669 × 2048 × 12 bytes
                   = 16,441,344 bytes
                   = 15.68 MiB per worker
```

Where:
- `pair_count = 223 rules × 3 variants` (raw, UTF-16, stream) = **669 pairs**
- `max_anchor_hits = Tuning::max_anchor_hits_per_rule_variant` = **2048**
- `sizeof(SpanU32) = 12 bytes` (start: u32, end: u32, anchor_hint: u32)

### Key Tuning Parameter

```rust
// src/demo.rs - demo_tuning()
Tuning {
    max_anchor_hits_per_rule_variant: 2048,  // <-- This drives HitAccPool size
    // ...
}
```

### What Happens When max_hits Is Exceeded

From `src/engine/hit_pool.rs:180-225`:

```rust
/// Once the per-pair cap is exceeded, all hits are coalesced into a single
/// span that conservatively covers every hit seen so far.
pub(super) fn push_span(&mut self, pair: usize, span: SpanU32, ...) {
    // ...
    if len >= max_hits {
        // Overflow: coalesce everything into one span
        self.coalesced[pair] = SpanU32 {
            start: lo,      // min of all starts
            end: hi,        // max of all ends
            anchor_hint: min_anchor,
        };
        self.coalesced_set[pair] = 1;
    }
}
```

**Coalescing behavior**:
- Correctness is preserved (no findings are missed)
- A single large window replaces many small windows
- More regex work may be needed (larger search area)
- Potential performance degradation in anchor-dense content

## Optimization Potential

### Memory Savings by Reducing max_anchor_hits

| max_hits | HitAccPool | Per-Worker | 8-Worker System | Savings |
|----------|------------|------------|-----------------|---------|
| 2048 (current) | 15.68 MiB | 18.82 MiB | 160.6 MiB | baseline |
| 1024 | 7.84 MiB | 10.98 MiB | 97.8 MiB | **39%** |
| 512 | 3.92 MiB | 7.06 MiB | 66.5 MiB | **59%** |
| 256 | 1.96 MiB | 5.10 MiB | 50.8 MiB | **68%** |
| 128 | 0.98 MiB | 4.12 MiB | 43.0 MiB | **73%** |

## Investigation Plan

### Instrumentation

Add statistics tracking under the `stats` feature flag to measure actual usage:

```rust
// Suggested additions to ScanScratch or a new HitAccPoolStats struct
#[cfg(feature = "stats")]
pub struct HitAccPoolStats {
    /// Maximum hits seen for any single (rule, variant) pair
    pub max_hits_seen: u32,
    
    /// Number of times coalescing was triggered
    pub coalesce_count: u64,
    
    /// Distribution of hit counts (histogram buckets)
    pub hit_count_histogram: [u64; 12],  // 0, 1-2, 3-4, 5-8, 9-16, 17-32, 33-64, 65-128, 129-256, 257-512, 513-1024, 1025+
    
    /// Pairs that exceeded max_hits (for identifying problematic rules)
    pub overflow_pairs: Vec<(u32, u32)>,  // (rule_id, variant_idx)
}
```

**Instrumentation points**:
1. `HitAccPool::push_span()` - track hit counts per pair
2. Coalescing trigger point - increment counter and record pair
3. End of chunk scan - record max_hits_seen

### Large-Scale Benchmark

Scan a diverse corpus of repositories to gather statistics:

**Suggested test corpus**:
- Large open-source repos (Linux kernel, Chromium, etc.)
- Repos known to have many secrets (test fixtures)
- High-entropy content (minified JS, compiled artifacts)
- Configuration-heavy repos (many .env files, config directories)

**Metrics to collect**:
1. Per-scan maximum hits for any pair
2. 95th/99th percentile hit counts
3. Coalescing frequency
4. Correlation between coalescing and scan time

### Analysis

Questions to answer:
1. What is the maximum `max_hits` actually needed across all scans?
2. How often does coalescing occur with current settings?
3. What percentage of scans would be affected by reducing max_hits?
4. Is there a performance cliff at certain max_hits values?

### Decision Matrix

Based on results, choose one of:

| If max_hits rarely exceeds... | Recommendation |
|------------------------------|----------------|
| 256 | Reduce default to 512, save 59% memory |
| 512 | Reduce default to 1024, save 39% memory |
| 1024 | Keep current or reduce to 1536 |
| 2048 | Current sizing is appropriate |

Consider also:
- Making `max_anchor_hits_per_rule_variant` user-configurable
- Adding different defaults for "low-memory" vs "high-throughput" profiles

## Files to Modify

### For instrumentation:

1. `src/engine/hit_pool.rs` - Add stats tracking to `push_span()`
2. `src/engine/scratch.rs` - Add `HitAccPoolStats` field to `ScanScratch`
3. `src/demo.rs` - Expose stats in tuning or report

### For changing the default:

1. `src/demo.rs` - Modify `demo_tuning().max_anchor_hits_per_rule_variant`
2. `src/api.rs` - Update `Tuning` documentation
3. `docs/memory-management.md` - Update memory tables

## Verification

After any change, run:

```bash
# Memory allocation verification
cargo test --test diagnostic -- --ignored --nocapture --test-threads=1

# Performance regression check (compare before/after)
RUSTFLAGS="-C target-cpu=native" cargo build --release
./target/release/scanner-rs ../linux ../gitleaks ../tigerbeetle
```

## Related Code References

| File | Line | Purpose |
|------|------|---------|
| `src/engine/hit_pool.rs` | 101-145 | `HitAccPool::new()` allocation |
| `src/engine/hit_pool.rs` | 180-225 | `push_span()` with coalescing |
| `src/engine/scratch.rs` | 360-365 | ScanScratch creates HitAccPool |
| `src/demo.rs` | 89-101 | `demo_tuning()` default values |
| `src/api.rs` | ~400 | `Tuning` struct definition |
| `tests/diagnostic/alloc_after_startup.rs` | 397-540 | Memory allocation tests |
| `docs/memory-management.md` | 1-60 | Memory documentation |

## Success Criteria

1. **Data collected**: Statistics from scanning 10+ diverse large repositories
2. **Decision made**: Clear recommendation on optimal `max_anchor_hits` value
3. **Memory reduced**: If over-provisioned, achieve 30%+ memory reduction
4. **No regression**: Scan throughput and correctness unchanged
5. **Documentation updated**: Memory tables reflect new values
