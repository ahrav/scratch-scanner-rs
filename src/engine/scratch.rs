//! Per-scan scratch state and entropy histogram.
//!
//! This module hosts `ScanScratch`, the primary allocation amortization vehicle
//! for scans, and `EntropyScratch` for entropy gating calculations. Scratch
//! state is single-threaded and reused across chunks to keep the hot path
//! allocation-free.

use crate::api::{DecodeStep, FindingRec};
use crate::scratch_memory::ScratchVec;
use crate::stdx::{ByteRing, FixedSet128, TimingWheel};

#[cfg(feature = "b64-stats")]
use crate::api::Base64DecodeStats;

use super::decode_state::{DecodeSlab, StepArena};
use super::helpers::pow2_at_least;
use super::hit_pool::{HitAccPool, SpanU32};
use super::transform::STREAM_DECODE_CHUNK_BYTES;
use super::vectorscan_prefilter::{VsScratch, VsStreamWindow};
use super::work_items::{PendingDecodeSpan, PendingWindow, SpanStreamEntry, WorkItem};

// Forward declaration for Engine (will be used via super::)
use super::Engine;

/// Scratch histogram for entropy gating.
///
/// # Performance
/// - Reset is O(distinct bytes) via the `used` list instead of O(256).
///
/// # Invariants
/// - `used_len` is the count of entries in `used` and is always <= 256.
/// - `used[0..used_len]` lists byte values whose counters were incremented
///   since the last reset; all other counters are expected to be zero.
#[derive(Clone, Copy)]
pub(super) struct EntropyScratch {
    // Histogram for byte frequencies (256 bins).
    pub(super) counts: [u32; 256],
    // List of "touched" byte values so we can reset in O(distinct) instead of O(256).
    pub(super) used: [u8; 256],
    pub(super) used_len: u16,
}

impl EntropyScratch {
    pub(super) fn new() -> Self {
        Self {
            counts: [0u32; 256],
            used: [0u8; 256],
            used_len: 0,
        }
    }

    /// Reset only the touched counters listed in `used`.
    #[inline]
    pub(super) fn reset(&mut self) {
        let used_len = self.used_len as usize;
        for i in 0..used_len {
            let b = self.used[i] as usize;
            self.counts[b] = 0;
        }
        self.used_len = 0;
    }
}

/// Per-scan scratch state reused across chunks.
///
/// This is the main allocation amortization vehicle: it owns buffers for window
/// accumulation, decode slabs, and work queues.
///
/// # Guarantees
/// - Steady-state scans reuse allocations; buffers may grow only if the engine's
///   rule set or tuning increases between scans.
/// - Findings are recorded as compact [`FindingRec`] entries until drained or
///   materialized.
///
/// # Invariants
/// - Not thread-safe; use by a single worker at a time.
/// - Contents (including slices from [`ScanScratch::findings`]) are invalidated
///   by `reset_for_scan` and any draining/mutation method.
///
/// # Performance
/// - Fixed-capacity buffers cap per-scan work; overflow increments
///   [`ScanScratch::dropped_findings`].
pub struct ScanScratch {
    /// Per-chunk finding records awaiting materialization.
    ///
    /// Compact records are stored here during scanning; they are expanded into
    /// full `Finding` structs with provenance during materialization. Fixed
    /// capacity prevents allocation in the hot path; overflow increments
    /// `findings_dropped` instead of reallocating.
    pub(super) out: ScratchVec<FindingRec>,
    pub(super) max_findings: usize,     // Per-chunk cap from tuning.
    pub(super) findings_dropped: usize, // Overflow counter when cap is exceeded.
    /// Work queue for breadth-first buffer traversal.
    ///
    /// Contains the root buffer plus any decoded buffers from transforms.
    /// Fixed capacity ensures no allocations during the scan loop; the tuning
    /// parameter `max_work_items` determines the upper bound.
    pub(super) work_q: ScratchVec<WorkItem>,
    pub(super) work_head: usize,                 // Cursor into work_q.
    pub(super) slab: DecodeSlab,                 // Decoded output storage.
    pub(super) seen: FixedSet128,                // Dedupe for decoded buffers.
    pub(super) total_decode_output_bytes: usize, // Global decode budget tracker.
    pub(super) work_items_enqueued: usize,       // Work queue budget tracker.
    /// Streaming decoded-byte ring buffer for window capture.
    pub(super) decode_ring: ByteRing,
    /// Temporary buffer for materializing decoded windows from the ring.
    pub(super) window_bytes: Vec<u8>,
    /// Pending window timing wheel (exact, G=1) keyed by `hi` for decoded stream verification.
    pub(super) pending_windows: TimingWheel<PendingWindow, 1>,
    /// Max window horizon used to size the timing wheel (max window radius + stream chunk).
    pub(super) pending_window_horizon_bytes: u64,
    /// Match windows produced by the Vectorscan stream callback.
    pub(super) vs_stream_matches: Vec<VsStreamWindow>,
    /// Pending decode spans captured during streaming decode.
    pub(super) pending_spans: Vec<PendingDecodeSpan>,
    /// Span detectors for nested transforms in decoded streams.
    pub(super) span_streams: Vec<SpanStreamEntry>,
    /// Temporary findings buffer for a decoded stream (dedupe-aware).
    pub(super) tmp_findings: Vec<FindingRec>,
    /// Per-rule stream hit counts for decoded-window seeding.
    ///
    /// Indexing is `rule_id * 3 + variant_idx` (Raw/Utf16Le/Utf16Be).
    pub(super) stream_hit_counts: Vec<u32>,
    /// Scratch list of touched stream hit counters for fast reset.
    pub(super) stream_hit_touched: ScratchVec<u32>,
    pub(super) hit_acc_pool: HitAccPool, // Per-(rule, variant) hit accumulator pool.
    pub(super) touched_pairs: ScratchVec<u32>, // Scratch list of touched pairs (unique).
    pub(super) windows: ScratchVec<SpanU32>, // Merged windows for a pair.
    pub(super) expanded: ScratchVec<SpanU32>, // Expanded windows for two-phase rules.
    pub(super) spans: ScratchVec<SpanU32>, // Transform span candidates.
    /// Decode provenance arena.
    ///
    /// Stores parent-linked decode steps so findings can reconstruct their
    /// full transform chain without per-finding allocation. Fixed capacity
    /// bounds memory usage; the arena is reset between chunks.
    pub(super) step_arena: StepArena,
    /// UTF-16 to UTF-8 transcoding buffer.
    ///
    /// Used when scanning UTF-16LE/BE variants of the input buffer. Fixed
    /// capacity sized to the maximum window size ensures no allocation during
    /// variant scanning.
    pub(super) utf16_buf: ScratchVec<u8>,
    pub(super) entropy_scratch: EntropyScratch, // Entropy histogram scratch.
    /// Scratch buffer for materializing decode step chains.
    ///
    /// When a finding is emitted, its `StepId` is traced through the arena to
    /// reconstruct the full decode path. This buffer holds the reversed chain
    /// during materialization. Capacity is bounded by `max_transform_depth`.
    pub(super) steps_buf: ScratchVec<DecodeStep>,

    /// Per-thread Vectorscan scratch space for the unified prefilter DB.
    ///
    /// Vectorscan requires each scanning thread to have its own scratch memory.
    /// Used for raw-buffer scanning (anchors + regex patterns in block mode).
    pub(super) vs_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 anchor prefiltering.
    /// Used for UTF-16 variant anchor scanning in block mode on raw buffers.
    pub(super) vs_utf16_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 stream anchor scanning.
    /// Used for streaming UTF-16 anchor detection in decoded byte streams.
    pub(super) vs_utf16_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for stream-mode scanning.
    /// Used for decoded-stream regex prefiltering in streaming mode.
    pub(super) vs_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for decoded gate scanning.
    /// Used for anchor gating in decoded transform output (e.g., base64 decoded bytes).
    pub(super) vs_gate_scratch: Option<VsScratch>,
    #[cfg(feature = "b64-stats")]
    pub(super) base64_stats: Base64DecodeStats, // Base64 decode/gate instrumentation.
}

impl ScanScratch {
    pub(super) fn new(engine: &Engine) -> Self {
        let rules_len = engine.rules.len();
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        let max_findings = engine.tuning.max_findings_per_chunk;
        let pair_count = rules_len.checked_mul(3).expect("rule pair count overflow");
        let hit_acc_pool =
            HitAccPool::new(pair_count, engine.tuning.max_anchor_hits_per_rule_variant)
                .expect("hit accumulator pool allocation failed");

        let max_steps = engine.tuning.max_work_items.saturating_add(
            rules_len.saturating_mul(2 * engine.tuning.max_windows_per_rule_variant),
        );
        let seen_cap = pow2_at_least(
            engine
                .tuning
                .max_work_items
                .next_power_of_two()
                .saturating_mul(2)
                .max(1024),
        );
        let stream_match_cap = engine.tuning.max_windows_per_rule_variant.max(16);
        let pending_window_cap = rules_len
            .saturating_mul(3)
            .saturating_mul(engine.tuning.max_windows_per_rule_variant)
            .max(16);
        let max_radius_bytes = (engine.max_window_diameter_bytes / 2) as u64;
        let pending_window_horizon_bytes =
            max_radius_bytes.saturating_add(STREAM_DECODE_CHUNK_BYTES as u64);

        Self {
            out: ScratchVec::with_capacity(max_findings).expect("scratch out allocation failed"),
            max_findings,
            findings_dropped: 0,
            work_q: ScratchVec::with_capacity(engine.tuning.max_work_items.saturating_add(1))
                .expect("scratch work_q allocation failed"),
            work_head: 0,
            slab: DecodeSlab::with_limit(engine.tuning.max_total_decode_output_bytes),
            seen: FixedSet128::with_pow2(seen_cap),
            total_decode_output_bytes: 0,
            work_items_enqueued: 0,
            decode_ring: ByteRing::with_capacity(engine.stream_ring_bytes),
            window_bytes: Vec::with_capacity(engine.stream_ring_bytes),
            pending_windows: TimingWheel::new(pending_window_horizon_bytes, pending_window_cap),
            pending_window_horizon_bytes,
            vs_stream_matches: Vec::with_capacity(stream_match_cap),
            pending_spans: Vec::with_capacity(max_spans.max(16)),
            span_streams: Vec::with_capacity(engine.transforms.len()),
            tmp_findings: Vec::with_capacity(max_findings),
            stream_hit_counts: vec![0u32; rules_len.saturating_mul(3)],
            stream_hit_touched: ScratchVec::with_capacity(rules_len.saturating_mul(3))
                .expect("scratch stream_hit_touched allocation failed"),
            hit_acc_pool,
            touched_pairs: ScratchVec::with_capacity(pair_count)
                .expect("scratch touched_pairs allocation failed"),
            windows: ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                .expect("scratch windows allocation failed"),
            expanded: ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed"),
            spans: ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed"),
            step_arena: StepArena {
                nodes: ScratchVec::with_capacity(max_steps)
                    .expect("scratch step_arena.nodes allocation failed"),
            },
            utf16_buf: ScratchVec::with_capacity(engine.tuning.max_utf16_decoded_bytes_per_window)
                .expect("scratch utf16_buf allocation failed"),
            entropy_scratch: EntropyScratch::new(),
            steps_buf: ScratchVec::with_capacity(
                engine.tuning.max_transform_depth.saturating_add(1),
            )
            .expect("scratch steps_buf allocation failed"),
            vs_scratch: engine.vs.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan scratch allocation failed")
            }),
            vs_utf16_scratch: engine.vs_utf16.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan utf16 scratch allocation failed")
            }),
            vs_utf16_stream_scratch: engine.vs_utf16_stream.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan utf16 stream scratch allocation failed")
            }),
            vs_stream_scratch: engine.vs_stream.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan stream scratch allocation failed")
            }),
            vs_gate_scratch: engine.vs_gate.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan gate scratch allocation failed")
            }),
            #[cfg(feature = "b64-stats")]
            base64_stats: Base64DecodeStats::default(),
        }
    }

    /// Clears per-scan state and revalidates scratch capacities against the engine.
    ///
    /// This may reallocate scratch buffers if the engine's tuning, rule set, or
    /// Vectorscan databases grew since the last scan. All previously returned
    /// slices into scratch buffers are invalid after this call.
    pub(super) fn reset_for_scan(&mut self, engine: &Engine) {
        self.out.clear();
        self.findings_dropped = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.decode_ring.reset();
        self.window_bytes.clear();
        self.pending_windows.reset();
        self.vs_stream_matches.clear();
        self.pending_spans.clear();
        self.span_streams.clear();
        self.tmp_findings.clear();
        for idx in self.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = self.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }
        self.step_arena.reset();
        self.utf16_buf.clear();
        self.entropy_scratch.reset();
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();

        match engine.vs.as_ref() {
            Some(db) => {
                let need_alloc = match self.vs_scratch.as_ref() {
                    Some(s) => s.bound_db_ptr() != db.db_ptr(),
                    None => true,
                };
                if need_alloc {
                    self.vs_scratch = Some(
                        db.alloc_scratch()
                            .expect("vectorscan scratch allocation failed"),
                    );
                }
            }
            None => {
                // Drop scratch if the engine no longer has vectorscan enabled.
                self.vs_scratch = None;
            }
        }
        match engine.vs_utf16.as_ref() {
            Some(db) => {
                let need_alloc = match self.vs_utf16_scratch.as_ref() {
                    Some(s) => s.bound_db_ptr() != db.db_ptr(),
                    None => true,
                };
                if need_alloc {
                    self.vs_utf16_scratch = Some(
                        db.alloc_scratch()
                            .expect("vectorscan utf16 scratch allocation failed"),
                    );
                }
            }
            None => {
                self.vs_utf16_scratch = None;
            }
        }
        match engine.vs_utf16_stream.as_ref() {
            Some(db) => {
                let need_alloc = match self.vs_utf16_stream_scratch.as_ref() {
                    Some(s) => s.bound_db_ptr() != db.db_ptr(),
                    None => true,
                };
                if need_alloc {
                    self.vs_utf16_stream_scratch = Some(
                        db.alloc_scratch()
                            .expect("vectorscan utf16 stream scratch allocation failed"),
                    );
                }
            }
            None => {
                self.vs_utf16_stream_scratch = None;
            }
        }
        match engine.vs_stream.as_ref() {
            Some(db) => {
                let need_alloc = match self.vs_stream_scratch.as_ref() {
                    Some(s) => s.bound_db_ptr() != db.db_ptr(),
                    None => true,
                };
                if need_alloc {
                    self.vs_stream_scratch = Some(
                        db.alloc_scratch()
                            .expect("vectorscan stream scratch allocation failed"),
                    );
                }
            }
            None => {
                self.vs_stream_scratch = None;
            }
        }
        match engine.vs_gate.as_ref() {
            Some(db) => {
                let need_alloc = match self.vs_gate_scratch.as_ref() {
                    Some(s) => s.bound_db_ptr() != db.db_ptr(),
                    None => true,
                };
                if need_alloc {
                    self.vs_gate_scratch = Some(
                        db.alloc_scratch()
                            .expect("vectorscan gate scratch allocation failed"),
                    );
                }
            }
            None => {
                self.vs_gate_scratch = None;
            }
        }
        self.hit_acc_pool
            .reset_touched(self.touched_pairs.as_slice());
        self.touched_pairs.clear();
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        let expected_pairs = engine.rules.len().saturating_mul(3);
        let max_hits_u32 =
            u32::try_from(engine.tuning.max_anchor_hits_per_rule_variant).unwrap_or(u32::MAX);
        let accs_need_rebuild = self.hit_acc_pool.pair_count() != expected_pairs
            || self.hit_acc_pool.max_hits() < max_hits_u32;
        if accs_need_rebuild {
            self.hit_acc_pool = HitAccPool::new(
                expected_pairs,
                engine.tuning.max_anchor_hits_per_rule_variant,
            )
            .expect("hit accumulator pool allocation failed");
        }
        if self.touched_pairs.capacity() < expected_pairs {
            self.touched_pairs = ScratchVec::with_capacity(expected_pairs)
                .expect("scratch touched_pairs allocation failed");
        }
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        if self.spans.capacity() < max_spans {
            self.spans =
                ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed");
        }
        if self.windows.capacity() < engine.tuning.max_anchor_hits_per_rule_variant {
            self.windows =
                ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                    .expect("scratch windows allocation failed");
        }
        if self.expanded.capacity() < engine.tuning.max_windows_per_rule_variant {
            self.expanded = ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed");
        }
        let stream_hits_len = engine.rules.len().saturating_mul(3);
        if self.stream_hit_counts.len() != stream_hits_len {
            self.stream_hit_counts = vec![0u32; stream_hits_len];
            self.stream_hit_touched =
                ScratchVec::with_capacity(stream_hits_len).expect("scratch stream hits");
        } else if self.stream_hit_touched.capacity() < stream_hits_len {
            self.stream_hit_touched =
                ScratchVec::with_capacity(stream_hits_len).expect("scratch stream hits");
        }
        if self.max_findings != engine.tuning.max_findings_per_chunk {
            self.max_findings = engine.tuning.max_findings_per_chunk;
        }
        if self.out.capacity() < self.max_findings {
            self.out = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch out allocation failed");
        }
        if self.work_q.capacity() < engine.tuning.max_work_items.saturating_add(1) {
            self.work_q = ScratchVec::with_capacity(engine.tuning.max_work_items.saturating_add(1))
                .expect("scratch work_q allocation failed");
        }
        let max_steps = engine.tuning.max_work_items.saturating_add(
            engine
                .rules
                .len()
                .saturating_mul(2 * engine.tuning.max_windows_per_rule_variant),
        );
        if self.step_arena.nodes.capacity() < max_steps {
            self.step_arena.nodes = ScratchVec::with_capacity(max_steps)
                .expect("scratch step_arena.nodes allocation failed");
        }
        if self.utf16_buf.capacity() < engine.tuning.max_utf16_decoded_bytes_per_window {
            self.utf16_buf =
                ScratchVec::with_capacity(engine.tuning.max_utf16_decoded_bytes_per_window)
                    .expect("scratch utf16_buf allocation failed");
        }
        let steps_buf_cap = engine.tuning.max_transform_depth.saturating_add(1);
        if self.steps_buf.capacity() < steps_buf_cap {
            self.steps_buf = ScratchVec::with_capacity(steps_buf_cap)
                .expect("scratch steps_buf allocation failed");
        }
        if self.decode_ring.capacity() < engine.stream_ring_bytes {
            self.decode_ring = ByteRing::with_capacity(engine.stream_ring_bytes);
        }
        if self.window_bytes.capacity() < engine.stream_ring_bytes {
            self.window_bytes
                .reserve(engine.stream_ring_bytes - self.window_bytes.capacity());
        }
        let stream_match_cap = engine.tuning.max_windows_per_rule_variant.max(16);
        let pending_window_cap = engine
            .rules
            .len()
            .saturating_mul(3)
            .saturating_mul(engine.tuning.max_windows_per_rule_variant)
            .max(16);
        let max_radius_bytes = (engine.max_window_diameter_bytes / 2) as u64;
        let pending_window_horizon_bytes =
            max_radius_bytes.saturating_add(STREAM_DECODE_CHUNK_BYTES as u64);
        if self.pending_windows.capacity() < pending_window_cap
            || self.pending_window_horizon_bytes < pending_window_horizon_bytes
        {
            self.pending_windows =
                TimingWheel::new(pending_window_horizon_bytes, pending_window_cap);
            self.pending_window_horizon_bytes = pending_window_horizon_bytes;
        }
        if self.vs_stream_matches.capacity() < stream_match_cap {
            self.vs_stream_matches
                .reserve(stream_match_cap - self.vs_stream_matches.capacity());
        }
        if self.pending_spans.capacity() < max_spans.max(16) {
            self.pending_spans
                .reserve(max_spans.max(16) - self.pending_spans.capacity());
        }
        if self.span_streams.capacity() < engine.transforms.len() {
            self.span_streams
                .reserve(engine.transforms.len() - self.span_streams.capacity());
        }
        if self.tmp_findings.capacity() < self.max_findings {
            self.tmp_findings
                .reserve(self.max_findings - self.tmp_findings.capacity());
        }
    }

    /// Returns per-scan base64 decode/gate stats.
    #[cfg(feature = "b64-stats")]
    pub fn base64_stats(&self) -> Base64DecodeStats {
        self.base64_stats
    }

    /// Moves all findings into `out` without allocating.
    ///
    /// # Panics
    /// Panics if `out.capacity()` is smaller than the number of findings.
    pub fn drain_findings(&mut self, out: &mut Vec<FindingRec>) {
        out.clear();
        assert!(
            out.capacity() >= self.out.len(),
            "output capacity too small"
        );
        out.extend(self.out.drain());
    }

    /// Returns the number of pending compact findings.
    pub fn pending_findings_len(&self) -> usize {
        self.out.len()
    }

    /// Moves all findings into `out`, reusing its allocation.
    ///
    /// See [`ScanScratch::drain_findings`] for capacity requirements.
    pub fn drain_findings_into(&mut self, out: &mut Vec<FindingRec>) {
        self.drain_findings(out);
    }

    /// Drops findings that end at or before the overlap prefix boundary.
    ///
    /// This is used with sliding-window or chunked scans: after advancing the
    /// scan window, remove findings wholly contained in the previous overlap
    /// prefix to avoid duplicate emission.
    ///
    /// # Preconditions
    /// - `new_bytes_start` is the absolute byte offset where the new, non-overlap
    ///   region begins (typically `base_offset + prefix_len`).
    ///
    /// # Effects
    /// - Compacts in place and preserves the relative order of remaining findings.
    pub fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        if new_bytes_start == 0 {
            return;
        }
        // Compact in place: keep only findings where root_hint_end > new_bytes_start.
        let mut write_idx = 0;
        let len = self.out.len();
        for read_idx in 0..len {
            if self.out[read_idx].root_hint_end > new_bytes_start {
                if write_idx != read_idx {
                    // Move the element to the write position.
                    // SAFETY: Both indices are in bounds and non-overlapping.
                    let src = &self.out[read_idx] as *const FindingRec;
                    let dst = &mut self.out[write_idx] as *mut FindingRec;
                    unsafe {
                        std::ptr::copy_nonoverlapping(src, dst, 1);
                    }
                }
                write_idx += 1;
            }
        }
        self.out.truncate(write_idx);
    }

    /// Returns a shared view of accumulated finding records.
    ///
    /// The slice is invalidated by the next scan or any call that drains
    /// or mutates the scratch buffers.
    ///
    /// Order reflects scan traversal and is not guaranteed to be sorted by span.
    pub fn findings(&self) -> &[FindingRec] {
        self.out.as_slice()
    }

    /// Returns the number of findings dropped due to the per-chunk cap.
    pub fn dropped_findings(&self) -> usize {
        self.findings_dropped
    }

    pub(super) fn push_finding(&mut self, rec: FindingRec) {
        if self.out.len() < self.max_findings {
            self.out.push(rec);
        } else {
            self.findings_dropped = self.findings_dropped.saturating_add(1);
        }
    }
}
