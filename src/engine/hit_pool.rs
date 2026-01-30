//! Hot-path data structures for hit accumulation.
//!
//! Contains compact span types and the hit accumulator pool used during
//! prefilter scanning to collect candidate windows.

use crate::scratch_memory::ScratchVec;
use crate::stdx::DynamicBitSet;
use std::ops::Range;

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`. Spans are half-open
/// ranges (`start..end`).
///
/// # Invariants
/// - `start <= end` and both fit in `u32`.
/// - Only valid while the referenced buffer remains unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SpanU32 {
    pub(super) start: u32,
    pub(super) end: u32,
}

impl SpanU32 {
    pub(super) fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    pub(super) fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

/// Raw Vectorscan match used when direct regex capture is enabled.
///
/// Offsets are half-open byte ranges in the raw buffer.
#[derive(Clone, Copy, Debug)]
pub(super) struct RawHsMatch {
    pub(super) rule_id: u32,
    pub(super) start: u32,
    pub(super) end: u32,
}

/// Accumulates anchor hit windows across all (rule, variant) pairs.
///
/// Storage is fixed-stride: `windows` is laid out as `pair * max_hits + idx`.
/// Each pair starts as an append-only list. Once the hit count exceeds the cap,
/// it switches to a single "coalesced" window that covers the union of all hits
/// seen so far. The fallback is conservative (may over-expand) but guarantees
/// correctness while bounding memory growth.
///
/// Windows are pushed in non-decreasing order for anchor scans. When switching
/// to coalesced mode, ordering is no longer meaningful; downstream code must
/// not assume sorted windows unless it explicitly sorts them.
///
/// # Guarantees
/// - If `coalesced_set[pair] != 0`, `coalesced[pair]` is a superset of all hits
///   seen so far for that pair.
///
/// # Performance
/// - Per-pair memory is capped at `max_hits`; append stays O(1) until coalesced.
/// - Single allocation for all pairs; no per-(rule, variant) allocations.
pub(super) struct HitAccPool {
    max_hits: u32,
    pair_count: usize,

    // Fixed-stride storage: base = pair * max_hits
    windows: Vec<SpanU32>,
    lens: Vec<u32>,

    coalesced: Vec<SpanU32>,
    coalesced_set: Vec<u8>, // 0/1

    // Membership for touched pairs to keep touched_pairs unique.
    touched: DynamicBitSet,
}

impl HitAccPool {
    /// Allocate a pool for `pair_count` (rule, variant) pairs with a per-pair
    /// hit cap of `max_hits`.
    ///
    /// # Errors
    /// - Returns `Err` if `max_hits == 0` or if allocation sizes overflow.
    pub(super) fn new(pair_count: usize, max_hits: usize) -> Result<Self, String> {
        if max_hits == 0 {
            return Err("hit accumulator max_hits must be > 0".to_string());
        }
        let max_hits_u32 = u32::try_from(max_hits)
            .map_err(|_| "hit accumulator max_hits exceeds u32::MAX".to_string())?;
        let total = pair_count
            .checked_mul(max_hits)
            .ok_or_else(|| "HitAccPool windows size overflow".to_string())?;

        // SpanU32 is Copy; zero-init cost is one-time.
        let windows = vec![SpanU32 { start: 0, end: 0 }; total];
        let lens = vec![0u32; pair_count];
        let coalesced = vec![SpanU32 { start: 0, end: 0 }; pair_count];
        let coalesced_set = vec![0u8; pair_count];
        let touched = DynamicBitSet::empty(pair_count);

        Ok(Self {
            max_hits: max_hits_u32,
            pair_count,
            windows,
            lens,
            coalesced,
            coalesced_set,
            touched,
        })
    }

    #[inline]
    pub(super) fn pair_count(&self) -> usize {
        self.pair_count
    }

    #[inline]
    pub(super) fn max_hits(&self) -> u32 {
        self.max_hits
    }

    #[inline(always)]
    pub(super) fn reset_touched(&mut self, touched_pairs: &[u32]) {
        // Clear membership bits only for touched pairs (O(#touched)).
        for &p in touched_pairs {
            self.touched.unset(p as usize);
        }
    }

    #[inline(always)]
    pub(super) fn mark_touched(&mut self, pair: usize, touched_pairs: &mut ScratchVec<u32>) {
        // membership check
        if !self.touched.is_set(pair) {
            self.touched.set(pair);
            touched_pairs.push(pair as u32);
        }
    }

    #[inline(always)]
    /// Record a hit window for `pair`, preserving order until capped.
    ///
    /// Once the per-pair cap is exceeded, all hits are coalesced into a single
    /// span that conservatively covers every hit seen so far.
    pub(super) fn push_span(
        &mut self,
        pair: usize,
        span: SpanU32,
        touched_pairs: &mut ScratchVec<u32>,
    ) {
        self.mark_touched(pair, touched_pairs);

        if self.coalesced_set[pair] != 0 {
            // Expand coalesced window
            let c = &mut self.coalesced[pair];
            c.start = c.start.min(span.start);
            c.end = c.end.max(span.end);
            return;
        }

        let len = self.lens[pair] as usize;
        let max_hits = self.max_hits as usize;
        if len < max_hits {
            let base = pair * max_hits;
            self.windows[base + len] = span;
            self.lens[pair] = (len + 1) as u32;
            return;
        }

        // Overflow: coalesce everything into one span and drop the per-hit list.
        let base = pair * max_hits;
        let mut lo = span.start;
        let mut hi = span.end;
        for i in 0..len {
            let s = self.windows[base + i];
            lo = lo.min(s.start);
            hi = hi.max(s.end);
        }
        self.coalesced[pair] = SpanU32 { start: lo, end: hi };
        self.coalesced_set[pair] = 1;
        self.lens[pair] = 0;
    }

    #[inline(always)]
    /// Drain accumulated windows for `pair` into `out`.
    ///
    /// If the pair is coalesced, this returns a single span; otherwise, it
    /// returns the per-hit list in insertion order and resets the count.
    pub(super) fn take_into(&mut self, pair: usize, out: &mut ScratchVec<SpanU32>) {
        out.clear();

        if self.coalesced_set[pair] != 0 {
            out.push(self.coalesced[pair]);
            self.coalesced_set[pair] = 0;
            return;
        }

        let len = self.lens[pair] as usize;
        if len == 0 {
            return;
        }
        let max_hits = self.max_hits as usize;
        let base = pair * max_hits;
        for i in 0..len {
            out.push(self.windows[base + i]);
        }
        self.lens[pair] = 0;
    }

    #[inline(always)]
    /// Clears all accumulated state for `pair` without returning windows.
    pub(super) fn reset_pair(&mut self, pair: usize) {
        self.lens[pair] = 0;
        self.coalesced_set[pair] = 0;
    }

    // Test-only accessors for internal state verification
    #[cfg(test)]
    pub(super) fn coalesced_set(&self) -> &[u8] {
        &self.coalesced_set
    }

    #[cfg(test)]
    pub(super) fn coalesced(&self) -> &[SpanU32] {
        &self.coalesced
    }

    #[cfg(test)]
    pub(super) fn lens(&self) -> &[u32] {
        &self.lens
    }

    #[cfg(test)]
    pub(super) fn windows(&self) -> &[SpanU32] {
        &self.windows
    }
}
