//! Hot-path data structures for hit accumulation.
//!
//! Contains compact span types and the hit accumulator pool used during
//! prefilter scanning to collect candidate windows.
//!
//! # Performance design
//! All arrays are fixed-size after construction (pair count and max_hits are
//! invariant for the lifetime of a `ScanScratch`). The struct stores raw
//! pointers instead of `Vec` to eliminate bounds-check loads on the hot path.
//! Per-pair metadata (`len` + `coalesced` flag) is collocated into a 4-byte
//! `PairMeta` struct so that a single 32-bit load gives both fields and 16
//! consecutive pairs fit in one cache line.
//!
//! The overflow coalesce path is extracted as `#[cold] #[inline(never)]` to
//! keep the fast path compact and branch-predictor friendly.

use crate::scratch_memory::ScratchVec;
use std::ops::Range;

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`. Spans are half-open
/// ranges (`start..end`).
///
/// # Fields
/// - `anchor_hint`: Vectorscan's `from` match offset, clamped to `[start, end]`.
///   Used to start regex searches near the anchor instead of at window start.
///   When windows are merged, the earliest (smallest) anchor_hint is preserved.
///
/// # Invariants
/// - `start <= end` and both fit in `u32`.
/// - `anchor_hint` is in `[start, end]` (clamped during construction).
/// - Only valid while the referenced buffer remains unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SpanU32 {
    pub(super) start: u32,
    pub(super) end: u32,
    /// Anchor hint from Vectorscan's `from` offset, clamped to window bounds.
    pub(super) anchor_hint: u32,
}

impl SpanU32 {
    /// Creates a span with an explicit anchor hint.
    ///
    /// The anchor hint is clamped to `[start, end]` to maintain invariants.
    pub(super) fn new(start: usize, end: usize, anchor_hint: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        let clamped_hint = anchor_hint.clamp(start, end);
        Self {
            start: start as u32,
            end: end as u32,
            anchor_hint: clamped_hint as u32,
        }
    }

    /// Creates a span without an anchor hint (defaults to start).
    ///
    /// Used for backward compatibility and cases where anchor hints are unavailable.
    pub(super) fn new_no_hint(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
            anchor_hint: start as u32,
        }
    }

    pub(super) fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

// ---------------------------------------------------------------------------
// PairMeta: collocated per-pair hot metadata
// ---------------------------------------------------------------------------

/// Per-pair hot metadata, collocated for single-load access.
///
/// Packing `len` and `coalesced` into 4 bytes means a single 32-bit load
/// gives both fields. 16 consecutive pairs fit in one cache line.
///
/// # Invariants
/// - `len` is in `0..=max_hits` (max_hits ≤ 2048 in production, fits u16).
/// - `coalesced` is 0 or 1.
#[derive(Clone, Copy)]
#[repr(C)]
struct PairMeta {
    /// Number of windows accumulated for this pair.
    /// Max value is max_hits (≤ 2048 in production), fits in u16.
    len: u16,
    /// 1 if this pair has been coalesced, 0 otherwise.
    coalesced: u8,
    _pad: u8,
}

impl PairMeta {
    const ZERO: Self = Self {
        len: 0,
        coalesced: 0,
        _pad: 0,
    };
}

// ---------------------------------------------------------------------------
// HitAccPool: raw-pointer backed hit accumulator
// ---------------------------------------------------------------------------

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
/// - If `pair_meta[pair].coalesced != 0`, `coalesced[pair]` is a superset of
///   all hits seen so far for that pair.
///
/// # Performance
/// - Per-pair memory is capped at `max_hits`; append stays O(1) until coalesced.
/// - Single allocation for all pairs; no per-(rule, variant) allocations.
/// - All internal arrays are raw pointers — bounds are invariant after
///   construction so no runtime bounds checks are emitted on the fast path.
/// - Per-pair metadata (`len` + `coalesced`) is collocated into 4 bytes for
///   single-load access.
///
/// # Safety
/// - All raw pointer accesses are guarded by `debug_assert!(pair < pair_count)`.
/// - `Drop` reconstructs `Vec` from raw parts for correct deallocation.
/// - `unsafe impl Send`: raw pointers are exclusively owned (same pattern as
///   `ScratchVec`).
pub(super) struct HitAccPool {
    max_hits: u32,
    pair_count: u32,
    touched_word_count: u32,
    _pad: u32,
    // Raw pointers to exclusively-owned heap allocations.
    // All arrays are fixed-size after construction.
    pair_meta: *mut PairMeta,
    windows: *mut SpanU32,
    coalesced: *mut SpanU32,
    touched_words: *mut u64,
}

/// # Safety
/// All raw pointers in `HitAccPool` are exclusively owned heap allocations,
/// never aliased, and only accessed through `&self` / `&mut self`. This is
/// the same ownership model as `ScratchVec` which also implements `Send`.
unsafe impl Send for HitAccPool {}

impl Drop for HitAccPool {
    fn drop(&mut self) {
        let pair_count = self.pair_count as usize;
        let max_hits = self.max_hits as usize;
        let word_count = self.touched_word_count as usize;

        // Reconstruct Vecs from raw parts and let them drop.
        // SAFETY: Each pointer was obtained from Vec::into_raw_parts()-equivalent
        // (as_mut_ptr + mem::forget) with the exact capacity stored in the struct.
        // No other code has taken ownership of these allocations.
        unsafe {
            let total_windows = pair_count.saturating_mul(max_hits);
            drop(Vec::from_raw_parts(self.pair_meta, pair_count, pair_count));
            drop(Vec::from_raw_parts(
                self.windows,
                total_windows,
                total_windows,
            ));
            drop(Vec::from_raw_parts(self.coalesced, pair_count, pair_count));
            drop(Vec::from_raw_parts(
                self.touched_words,
                word_count,
                word_count,
            ));
        }
    }
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
        if max_hits > u16::MAX as usize {
            return Err(
                "hit accumulator max_hits exceeds u16::MAX (PairMeta.len is u16)".to_string(),
            );
        }
        let pair_count_u32 = u32::try_from(pair_count)
            .map_err(|_| "hit accumulator pair_count exceeds u32::MAX".to_string())?;
        let total = pair_count
            .checked_mul(max_hits)
            .ok_or_else(|| "HitAccPool windows size overflow".to_string())?;

        let word_count = pair_count.div_ceil(64);

        // Allocate via Vec, then take ownership of the raw pointer.
        let mut meta_vec = vec![PairMeta::ZERO; pair_count];
        let pair_meta = meta_vec.as_mut_ptr();
        std::mem::forget(meta_vec);

        let mut win_vec = vec![
            SpanU32 {
                start: 0,
                end: 0,
                anchor_hint: 0
            };
            total
        ];
        let windows = win_vec.as_mut_ptr();
        std::mem::forget(win_vec);

        let mut coal_vec = vec![
            SpanU32 {
                start: 0,
                end: 0,
                anchor_hint: 0
            };
            pair_count
        ];
        let coalesced = coal_vec.as_mut_ptr();
        std::mem::forget(coal_vec);

        let mut touched_vec = vec![0u64; word_count];
        let touched_words = touched_vec.as_mut_ptr();
        std::mem::forget(touched_vec);

        Ok(Self {
            max_hits: max_hits_u32,
            pair_count: pair_count_u32,
            touched_word_count: word_count as u32,
            _pad: 0,
            pair_meta,
            windows,
            coalesced,
            touched_words,
        })
    }

    #[inline]
    pub(super) fn pair_count(&self) -> usize {
        self.pair_count as usize
    }

    #[inline]
    pub(super) fn max_hits(&self) -> u32 {
        self.max_hits
    }

    #[inline(always)]
    pub(super) fn reset_touched(&mut self, touched_pairs: &[u32]) {
        let words = self.touched_words;
        for &p in touched_pairs {
            let idx = p as usize;
            // SAFETY: p < pair_count, so idx / 64 < touched_word_count.
            unsafe {
                let word = words.add(idx / 64);
                *word &= !(1u64 << (idx % 64));
            }
        }
    }

    #[inline(always)]
    pub(super) fn mark_touched(&mut self, pair: usize, touched_pairs: &mut ScratchVec<u32>) {
        debug_assert!((pair as u32) < self.pair_count);
        // SAFETY: pair < pair_count, so pair / 64 < touched_word_count.
        unsafe {
            let word = self.touched_words.add(pair / 64);
            let bit = 1u64 << (pair % 64);
            if (*word & bit) == 0 {
                *word |= bit;
                touched_pairs.push(pair as u32);
            }
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
        debug_assert!((pair as u32) < self.pair_count);
        self.mark_touched(pair, touched_pairs);

        // SAFETY: pair < pair_count, pointer arithmetic is in bounds.
        let meta = unsafe { &mut *self.pair_meta.add(pair) };

        if meta.coalesced != 0 {
            // Expand coalesced window, preserving the earliest anchor hint.
            // SAFETY: pair < pair_count.
            let c = unsafe { &mut *self.coalesced.add(pair) };
            c.start = c.start.min(span.start);
            c.end = c.end.max(span.end);
            c.anchor_hint = c.anchor_hint.min(span.anchor_hint);
            return;
        }

        let len = meta.len as usize;
        let max_hits = self.max_hits as usize;
        if len < max_hits {
            let base = pair * max_hits;
            // SAFETY: base + len < pair_count * max_hits (total window slots).
            unsafe {
                *self.windows.add(base + len) = span;
            }
            meta.len = (len + 1) as u16;
            return;
        }

        // Overflow: cold path extracted for branch predictor.
        self.coalesce_overflow(pair, span);
    }

    /// Coalesce all accumulated windows for `pair` into a single span.
    ///
    /// Called when the per-pair hit cap is exceeded. Extracted as a cold path
    /// to keep the fast path in `push_span` compact and branch-predictor
    /// friendly.
    #[cold]
    #[inline(never)]
    fn coalesce_overflow(&mut self, pair: usize, span: SpanU32) {
        let max_hits = self.max_hits as usize;
        // SAFETY: pair < pair_count (caller asserts).
        let meta = unsafe { &mut *self.pair_meta.add(pair) };
        let len = meta.len as usize;
        let base = pair * max_hits;

        let mut lo = span.start;
        let mut hi = span.end;
        let mut min_anchor = span.anchor_hint;

        // SAFETY: base..base+len is within the windows allocation.
        let windows = unsafe { std::slice::from_raw_parts(self.windows.add(base), len) };
        for s in windows {
            lo = lo.min(s.start);
            hi = hi.max(s.end);
            min_anchor = min_anchor.min(s.anchor_hint);
        }

        // SAFETY: pair < pair_count.
        unsafe {
            *self.coalesced.add(pair) = SpanU32 {
                start: lo,
                end: hi,
                anchor_hint: min_anchor,
            };
        }
        meta.coalesced = 1;
        meta.len = 0;
    }

    #[inline(always)]
    /// Drain accumulated windows for `pair` into `out`.
    ///
    /// If the pair is coalesced, this returns a single span; otherwise, it
    /// returns the per-hit list in insertion order and resets the count.
    pub(super) fn take_into(&mut self, pair: usize, out: &mut ScratchVec<SpanU32>) {
        debug_assert!((pair as u32) < self.pair_count);
        out.clear();

        // SAFETY: pair < pair_count.
        let meta = unsafe { &mut *self.pair_meta.add(pair) };

        if meta.coalesced != 0 {
            // SAFETY: pair < pair_count.
            out.push(unsafe { *self.coalesced.add(pair) });
            meta.coalesced = 0;
            return;
        }

        let len = meta.len as usize;
        if len == 0 {
            return;
        }
        let max_hits = self.max_hits as usize;
        let base = pair * max_hits;
        // SAFETY: base..base+len is within the windows allocation, and
        // SpanU32 is Copy so extend_from_slice is a single memcpy.
        let src = unsafe { std::slice::from_raw_parts(self.windows.add(base), len) };
        out.extend_from_slice(src);
        meta.len = 0;
    }

    #[inline(always)]
    /// Clears all accumulated state for `pair` without returning windows.
    pub(super) fn reset_pair(&mut self, pair: usize) {
        debug_assert!((pair as u32) < self.pair_count);
        // SAFETY: pair < pair_count.
        let meta = unsafe { &mut *self.pair_meta.add(pair) };
        meta.len = 0;
        meta.coalesced = 0;
    }

    // Test-only accessors for internal state verification
    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn is_coalesced(&self, pair: usize) -> bool {
        debug_assert!((pair as u32) < self.pair_count);
        unsafe { (*self.pair_meta.add(pair)).coalesced != 0 }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn pair_len(&self, pair: usize) -> u32 {
        debug_assert!((pair as u32) < self.pair_count);
        unsafe { (*self.pair_meta.add(pair)).len as u32 }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn coalesced_span(&self, pair: usize) -> SpanU32 {
        debug_assert!((pair as u32) < self.pair_count);
        unsafe { *self.coalesced.add(pair) }
    }

    #[cfg(all(test, feature = "stdx-proptest"))]
    pub(super) fn window_at(&self, pair: usize, idx: usize) -> SpanU32 {
        let base = pair * self.max_hits as usize;
        debug_assert!(base + idx < (self.pair_count as usize) * (self.max_hits as usize));
        unsafe { *self.windows.add(base + idx) }
    }
}

#[cfg(feature = "bench")]
pub struct BenchHitAccPool {
    pool: HitAccPool,
    touched: ScratchVec<u32>,
    output: ScratchVec<SpanU32>,
}

#[cfg(feature = "bench")]
impl BenchHitAccPool {
    pub fn new(pair_count: usize, max_hits: usize) -> Self {
        Self {
            pool: HitAccPool::new(pair_count, max_hits).expect("bench pool alloc"),
            touched: ScratchVec::with_capacity(pair_count).expect("bench touched alloc"),
            output: ScratchVec::with_capacity(max_hits).expect("bench output alloc"),
        }
    }

    #[inline(always)]
    pub fn push(&mut self, pair: usize, start: u32, end: u32, hint: u32) {
        self.pool.push_span(
            pair,
            SpanU32 {
                start,
                end,
                anchor_hint: hint,
            },
            &mut self.touched,
        );
    }

    #[inline(always)]
    pub fn take(&mut self, pair: usize) -> usize {
        self.pool.take_into(pair, &mut self.output);
        self.output.len()
    }

    pub fn reset(&mut self) {
        self.pool.reset_touched(self.touched.as_slice());
        self.touched.clear();
    }
}
