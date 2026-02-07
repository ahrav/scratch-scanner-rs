//! Per-scan scratch state, entropy histogram, and root-span coordinate mapping.
//!
//! This module hosts [`ScanScratch`], the primary allocation amortization
//! vehicle for scans, [`EntropyScratch`] for entropy gating calculations, and
//! [`RootSpanMapCtx`] for translating decoded-byte offsets back to root-buffer
//! coordinates during transform scans. Scratch state is single-threaded and
//! reused across chunks to keep the hot path allocation-free.

use crate::api::{DecodeStep, FileId, FindingRec, StepId, TransformConfig, TransformId, STEP_ROOT};
use crate::scratch_memory::ScratchVec;
use crate::stdx::{ByteRing, FixedSet128, TimingWheel};

#[cfg(feature = "b64-stats")]
use crate::api::Base64DecodeStats;

use super::decode_state::{DecodeSlab, StepArena};
use super::helpers::{hash128, pow2_at_least};
use super::hit_pool::{HitAccPool, SpanU32};
use super::transform::{is_url_trigger, map_decoded_offset, STREAM_DECODE_CHUNK_BYTES};
use super::vectorscan_prefilter::{VsScratch, VsStreamWindow};
use super::work_items::{PendingDecodeSpan, PendingWindow, SpanStreamEntry, WorkItem};
use regex::bytes::CaptureLocations;

use super::Engine;

/// Normalized secret hash bytes (BLAKE3 output).
pub type NormHash = [u8; 32];

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

/// Context for mapping decoded spans back to root (encoded) coordinates.
///
/// During transform scans, findings are reported in decoded-byte coordinates.
/// This context captures the encoded span being decoded so that decoded offsets
/// can be translated back to root-buffer offsets for deduplication and output.
///
/// # Safety
/// - `tc` points to an `Engine`-owned `TransformConfig` that outlives the scan.
/// - `encoded_ptr`/`encoded_len` describe the encoded span being decoded;
///   the referenced bytes must remain valid while this context is set.
/// - This context is only valid for the duration of a single scan; it is
///   cleared after each buffer scan completes.
#[derive(Clone, Copy)]
pub(super) struct RootSpanMapCtx {
    tc: *const TransformConfig,
    encoded_ptr: *const u8,
    encoded_len: usize,
    root_start: usize,
    // Minimum overlap (in bytes) guaranteed by chunked scans; used to decide
    // whether a trigger before the match would have appeared in the prior chunk.
    overlap_backscan: usize,
}

impl RootSpanMapCtx {
    /// Creates a new mapping context for the given transform and encoded span.
    ///
    /// The caller must ensure `tc` and `encoded` remain valid and unmodified
    /// for the lifetime of this context (typically one scan invocation).
    pub(super) fn new(
        tc: &TransformConfig,
        encoded: &[u8],
        root_start: usize,
        overlap_backscan: usize,
    ) -> Self {
        Self {
            tc: tc as *const TransformConfig,
            encoded_ptr: encoded.as_ptr(),
            encoded_len: encoded.len(),
            root_start,
            overlap_backscan,
        }
    }

    /// Maps a decoded-byte span back to absolute root-buffer coordinates.
    pub(super) fn map_span(&self, span: std::ops::Range<usize>) -> std::ops::Range<usize> {
        // Map decoded offsets back to absolute root-buffer offsets.
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };
        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let start = map_decoded_offset(tc, encoded, span.start);
        let end = map_decoded_offset(tc, encoded, span.end);
        let root_start = self.root_start;
        (root_start + start)..(root_start + end)
    }

    /// Returns whether a URL-percent trigger (`%` or `+`) appears within the
    /// match span or within the guaranteed overlap prefix preceding it.
    ///
    /// Returns `None` if this context is not for a URL-percent transform.
    pub(super) fn has_trigger_before_or_in_match(
        &self,
        root_span: std::ops::Range<usize>,
    ) -> Option<bool> {
        // Only applicable for URL-percent transforms.
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };
        if tc.id != TransformId::UrlPercent {
            return None;
        }

        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let plus_to_space = tc.plus_to_space;
        let span_start = root_span
            .start
            .saturating_sub(self.root_start)
            .min(self.encoded_len);
        let span_end = root_span
            .end
            .saturating_sub(self.root_start)
            .min(self.encoded_len);
        let scan_start = span_start
            .saturating_sub(self.overlap_backscan)
            .min(self.encoded_len);
        let scan_end = span_end.min(self.encoded_len);

        if scan_start >= scan_end {
            return Some(false);
        }

        let mut has_trigger = false;
        for &b in &encoded[scan_start..scan_end] {
            if is_url_trigger(b, plus_to_space) {
                has_trigger = true;
                break;
            }
        }
        Some(has_trigger)
    }

    /// Returns an extended drop boundary for URL-percent matches, or `None`.
    ///
    /// # Returns
    /// - `Some(offset)` if a trigger (`%` or `+`) exists after the match span
    ///   and no trigger appears within the overlap prefix before the match.
    ///   The returned offset extends past the first post-match trigger.
    /// - `None` if this is not a URL-percent transform, or if a trigger already
    ///   exists within the overlap window (which means the prior chunk would
    ///   have included this trigger, so no extension is needed).
    ///
    /// # Rationale
    /// URL-percent runs can begin with raw ASCII before the first `%` or `+`.
    /// If the match lands in that raw prefix, the normal match-end boundary
    /// would allow a later chunk (starting at the trigger) to re-emit the
    /// same match. Extending the drop boundary past the trigger prevents
    /// duplicate findings across chunk boundaries.
    pub(super) fn drop_hint_end_for_match(
        &self,
        match_span: std::ops::Range<usize>,
    ) -> Option<usize> {
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };
        if tc.id != TransformId::UrlPercent {
            return None;
        }

        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let plus_to_space = tc.plus_to_space;
        let span_end = match_span
            .end
            .saturating_sub(self.root_start)
            .min(self.encoded_len);

        // If a trigger is already within the overlap backscan window (or inside
        // the match), a prior chunk would have had a trigger too, so avoid
        // widening the dedupe boundary and risking duplicates.
        if self
            .has_trigger_before_or_in_match(match_span.clone())
            .unwrap_or(false)
        {
            return None;
        }

        for (idx, &b) in encoded[span_end..].iter().enumerate() {
            if is_url_trigger(b, plus_to_space) {
                return Some(self.root_start + span_end + idx + 1);
            }
        }

        None
    }
}

// SAFETY: RootSpanMapCtx stores raw const pointers to Engine-owned data
// (TransformConfig, encoded bytes). The Engine is immutable and outlives
// all scratch instances. The context is always None between scans
// (cleared after each buffer scan in core.rs).
unsafe impl Send for RootSpanMapCtx {}

impl EntropyScratch {
    /// Returns a zeroed histogram with no tracked byte values.
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
    /// Normalized hash for each finding (aligned with `out`).
    pub(super) norm_hash: ScratchVec<NormHash>,
    /// Drop boundary used by `drop_prefix_findings` (absolute offset in file).
    pub(super) drop_hint_end: ScratchVec<u64>,
    pub(super) max_findings: usize,     // Per-chunk cap from tuning.
    pub(super) findings_dropped: usize, // Overflow counter when cap is exceeded.
    /// Work queue for breadth-first buffer traversal.
    ///
    /// Contains the root buffer plus any decoded buffers from transforms.
    /// Fixed capacity ensures no allocations during the scan loop; the tuning
    /// parameter `max_work_items` determines the upper bound.
    pub(super) work_q: ScratchVec<WorkItem>,
    pub(super) work_head: usize,  // Cursor into work_q.
    pub(super) slab: DecodeSlab,  // Decoded output storage.
    pub(super) seen: FixedSet128, // Dedupe for decoded buffers.
    /// Bloom-style deduplication for output findings within a file.
    ///
    /// Prevents emitting the same finding multiple times when overlapping chunks
    /// or transform re-scans produce identical matches. The set is reset on file
    /// boundary transitions (new file or `base_offset == 0`).
    ///
    /// Key composition (32 bytes → 128-bit hash):
    /// - `file_id` (4 bytes) — scoped to current file
    /// - `rule_id` (4 bytes) — distinguishes rule matches
    /// - `span_start`, `span_end` (8 bytes) — root-level span (zeroed for mapped transforms)
    /// - `root_hint_start`, `root_hint_end` (16 bytes) — dedupe boundary in root coordinates
    ///
    /// Transform-derived findings use zeroed span coordinates when a precise
    /// root-span mapping exists because the same encoded region can decode to
    /// different offsets across chunk boundaries. When mapping is unavailable,
    /// the decoded span is included to keep distinct matches separate.
    pub(super) seen_findings: FixedSet128,
    /// Per-scan dedupe set used to detect duplicates within a single chunk scan.
    ///
    /// This resets every `scan_chunk_into` and lets us prefer more informative
    /// findings within a scan while suppressing repeats across chunks.
    pub(super) seen_findings_scan: FixedSet128,
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
    /// Drop boundaries aligned with `tmp_findings`.
    pub(super) tmp_drop_hint_end: Vec<u64>,
    /// Normalized hashes aligned with `tmp_findings`.
    pub(super) tmp_norm_hash: Vec<NormHash>,
    /// Per-rule regex capture locations (reused to avoid per-scan allocations).
    pub(super) capture_locs: Vec<Option<CaptureLocations>>,
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
    /// Active decoded→root coordinate mapping context (set during transform scans).
    ///
    /// Set by the scan loop before scanning a decoded buffer and cleared after
    /// each buffer scan completes. When `Some`, findings from decoded buffers
    /// use this context to map spans back to root-buffer offsets.
    pub(super) root_span_map_ctx: Option<RootSpanMapCtx>,
    /// Set by `scan_chunk_into` after running the Vectorscan prefilter on the
    /// root buffer. Consumed (one-shot) by the first `scan_rules_on_buffer`
    /// call so that the root buffer skips redundant prefiltering. Transform
    /// buffer calls see `false` and run the full prefilter as normal.
    pub(super) root_prefilter_done: bool,
    /// Whether the root prefilter detected UTF-16 anchor hits. Paired with
    /// `root_prefilter_done`; only meaningful when that flag is `true`.
    pub(super) root_prefilter_saw_utf16: bool,
    /// Overlap size inferred from the previous chunk in the same file.
    ///
    /// Used to determine whether a transform trigger before a match would have
    /// appeared in the prior chunk, so dedupe boundaries can be widened only
    /// when needed.
    pub(super) chunk_overlap_backscan: usize,
    /// Last scanned chunk metadata (used to infer overlap).
    pub(super) last_chunk_start: u64,
    pub(super) last_chunk_len: usize,
    pub(super) last_file_id: Option<FileId>,

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
    /// Set after the first `reset_for_scan` validates capacities.
    ///
    /// Since the `Engine` is immutable after construction, capacity checks
    /// are idempotent — they only matter on the first call. Subsequent calls
    /// skip the validation block for reduced per-chunk overhead.
    capacity_validated: bool,
}

impl ScanScratch {
    /// Allocates scratch state sized to the given engine's rules and tuning.
    ///
    /// All fixed-capacity buffers are pre-allocated here. Subsequent scans
    /// reuse these allocations unless the engine's configuration has grown.
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
        let findings_cap = pow2_at_least(max_findings.saturating_mul(4).max(64));
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
            norm_hash: ScratchVec::with_capacity(max_findings)
                .expect("scratch norm_hash allocation failed"),
            drop_hint_end: ScratchVec::with_capacity(max_findings)
                .expect("scratch drop_hint_end allocation failed"),
            max_findings,
            findings_dropped: 0,
            work_q: ScratchVec::with_capacity(engine.tuning.max_work_items.saturating_add(1))
                .expect("scratch work_q allocation failed"),
            work_head: 0,
            slab: DecodeSlab::with_limit(engine.tuning.max_total_decode_output_bytes),
            seen: FixedSet128::with_pow2(seen_cap),
            seen_findings: FixedSet128::with_pow2(findings_cap),
            seen_findings_scan: FixedSet128::with_pow2(findings_cap),
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
            tmp_drop_hint_end: Vec::with_capacity(max_findings),
            tmp_norm_hash: Vec::with_capacity(max_findings),
            capture_locs: engine
                .rules
                .iter()
                .map(|rule| Some(rule.re.capture_locations()))
                .collect(),
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
            root_span_map_ctx: None,
            root_prefilter_done: false,
            root_prefilter_saw_utf16: false,
            chunk_overlap_backscan: 0,
            last_chunk_start: 0,
            last_chunk_len: 0,
            last_file_id: None,
            #[cfg(feature = "b64-stats")]
            base64_stats: Base64DecodeStats::default(),
            capacity_validated: false,
        }
    }

    /// Clears per-scan state and revalidates scratch capacities against the engine.
    ///
    /// This may reallocate scratch buffers if the engine's tuning, rule set, or
    /// Vectorscan databases grew since the last scan. All previously returned
    /// slices into scratch buffers are invalid after this call.
    ///
    /// After the first successful call, capacity validation is skipped because
    /// `Engine` is immutable after construction — all checks are idempotent.
    #[allow(dead_code)] // Standalone reset entry point for external scratch consumers
    pub(super) fn reset_for_scan(&mut self, engine: &Engine) {
        // ── Per-scan state clears (must always run) ──────────────────────
        self.out.clear();
        self.norm_hash.clear();
        self.drop_hint_end.clear();
        self.findings_dropped = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.seen_findings_scan.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.decode_ring.reset();
        self.window_bytes.clear();
        self.pending_windows.reset();
        self.vs_stream_matches.clear();
        self.pending_spans.clear();
        self.span_streams.clear();
        self.tmp_findings.clear();
        self.tmp_drop_hint_end.clear();
        self.tmp_norm_hash.clear();
        for idx in self.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = self.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }
        self.step_arena.reset();
        self.utf16_buf.clear();
        self.entropy_scratch.reset();
        self.root_span_map_ctx = None;
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();

        // ── Per-scan accumulator resets (must always run) ────────────────
        self.hit_acc_pool
            .reset_touched(self.touched_pairs.as_slice());
        self.touched_pairs.clear();
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        self.ensure_capacity(engine);
    }

    /// Resets per-scan state like `reset_for_scan` but **preserves** the
    /// prefilter results already stored in `hit_acc_pool` and `touched_pairs`.
    ///
    /// Called on the hit path of `scan_chunk_into` after the hoisted
    /// Vectorscan prefilter has populated accumulator state. Everything else
    /// (output buffers, work queue, decode slab, etc.) is cleared normally.
    pub(super) fn reset_for_scan_after_prefilter(&mut self, engine: &Engine) {
        // ── Per-scan state clears (same as reset_for_scan) ──────────────
        self.out.clear();
        self.norm_hash.clear();
        self.drop_hint_end.clear();
        self.findings_dropped = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.seen_findings_scan.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.decode_ring.reset();
        self.window_bytes.clear();
        self.pending_windows.reset();
        self.vs_stream_matches.clear();
        self.pending_spans.clear();
        self.span_streams.clear();
        self.tmp_findings.clear();
        self.tmp_drop_hint_end.clear();
        self.tmp_norm_hash.clear();
        for idx in self.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = self.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }
        self.step_arena.reset();
        self.utf16_buf.clear();
        self.entropy_scratch.reset();
        self.root_span_map_ctx = None;
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();

        // ── Skip hit_acc_pool / touched_pairs reset ─────────────────────
        // Prefilter results are preserved; only clear the auxiliary buffers.
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        self.ensure_capacity(engine);
    }

    /// Idempotent capacity / Vectorscan-scratch validation.
    ///
    /// On the first call, validates and potentially reallocates all scratch
    /// buffers to match the engine's current tuning and rule set. Subsequent
    /// calls are no-ops because `Engine` is immutable after construction.
    pub(super) fn ensure_capacity(&mut self, engine: &Engine) {
        if self.capacity_validated {
            return;
        }

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
        if self.norm_hash.capacity() < self.max_findings {
            self.norm_hash = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch norm_hash allocation failed");
        }
        if self.drop_hint_end.capacity() < self.max_findings {
            self.drop_hint_end = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch drop_hint_end allocation failed");
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
        if self.tmp_drop_hint_end.capacity() < self.max_findings {
            self.tmp_drop_hint_end
                .reserve(self.max_findings - self.tmp_drop_hint_end.capacity());
        }
        if self.tmp_norm_hash.capacity() < self.max_findings {
            self.tmp_norm_hash
                .reserve(self.max_findings - self.tmp_norm_hash.capacity());
        }
        if self.capture_locs.len() != engine.rules.len() {
            self.capture_locs = engine
                .rules
                .iter()
                .map(|rule| Some(rule.re.capture_locations()))
                .collect();
        }

        self.capacity_validated = true;
    }

    /// Updates inferred overlap metadata for the current chunk.
    ///
    /// This infers the overlap length by comparing the current chunk start to
    /// the previous chunk end within the same file. Non-overlapping or
    /// out-of-order chunks set the overlap to zero.
    pub(super) fn update_chunk_overlap(
        &mut self,
        file_id: FileId,
        base_offset: u64,
        buf_len: usize,
    ) {
        // Reset finding dedup state on file transitions. This ensures findings
        // from a previous file don't suppress valid findings in the current file.
        //
        // Note: We do NOT reset when base_offset == 0 for the same file, as this
        // would break deduplication for chunked scans with large overlap where
        // base_offset = offset - tail_len can be 0 for continuation chunks.
        // Callers wanting to re-scan the same file should use reset_for_scan().
        if self.last_file_id != Some(file_id) {
            self.seen_findings.reset();
        }

        let mut overlap = 0usize;
        if self.last_file_id == Some(file_id) {
            let last_end = self
                .last_chunk_start
                .saturating_add(self.last_chunk_len as u64);
            if base_offset > self.last_chunk_start {
                if base_offset <= last_end {
                    overlap = (last_end - base_offset) as usize;
                }
            } else if base_offset == self.last_chunk_start && buf_len > self.last_chunk_len {
                // Growing-window case (overlap >= chunk): previous chunk is a prefix.
                overlap = self.last_chunk_len;
            }
        }

        self.chunk_overlap_backscan = overlap;
        self.last_file_id = Some(file_id);
        self.last_chunk_start = base_offset;
        self.last_chunk_len = buf_len;
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
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        assert!(
            out.capacity() >= self.out.len(),
            "output capacity too small"
        );
        out.extend(self.out.drain());
        self.norm_hash.clear();
        self.drop_hint_end.clear();
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

    /// Materialize decode steps for a finding into the scratch buffer.
    ///
    /// The returned slice is valid until the next call that materializes steps.
    #[allow(dead_code)] // Used by sim_scanner for finding provenance tracking
    pub(crate) fn materialize_decode_steps(&mut self, step_id: StepId) -> &[DecodeStep] {
        self.step_arena.materialize(step_id, &mut self.steps_buf);
        self.steps_buf.as_slice()
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
    ///
    /// For transform-derived findings, the drop boundary may be widened beyond
    /// the match span when a transform trigger occurs after the match and no
    /// trigger appears within the guaranteed overlap prefix before the match.
    /// This avoids dropping findings whose matches appear before late-appearing
    /// triggers (e.g., URL-percent runs with raw prefixes) while preventing
    /// duplicate emission when earlier triggers are already in the overlap.
    pub fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        if new_bytes_start == 0 {
            return;
        }
        debug_assert_eq!(
            self.out.len(),
            self.drop_hint_end.len(),
            "drop hint length mismatch"
        );
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        // Compact in place: keep only findings where the dedupe boundary is after
        // the new-bytes start.
        let mut write_idx = 0;
        let len = self.out.len();
        for read_idx in 0..len {
            let drop_end = {
                let slice = self.drop_hint_end.as_slice();
                slice[read_idx]
            };
            if drop_end > new_bytes_start {
                if write_idx != read_idx {
                    // Move the element to the write position.
                    // SAFETY: `write_idx <= read_idx` is maintained by the compaction
                    // loop (write_idx only increments when read_idx advances past it),
                    // so src and dst never alias the same element.
                    let src = &self.out[read_idx] as *const FindingRec;
                    let dst = &mut self.out[write_idx] as *mut FindingRec;
                    unsafe {
                        std::ptr::copy_nonoverlapping(src, dst, 1);
                    }
                }
                self.drop_hint_end.as_mut_slice()[write_idx] = drop_end;
                let hash = self.norm_hash.as_slice()[read_idx];
                self.norm_hash.as_mut_slice()[write_idx] = hash;
                write_idx += 1;
            }
        }
        self.out.truncate(write_idx);
        self.drop_hint_end.truncate(write_idx);
        self.norm_hash.truncate(write_idx);
    }

    /// Returns the drop-boundary offsets aligned 1:1 with [`findings()`].
    #[allow(dead_code)] // Used by sim_scanner for overlap deduplication
    pub(crate) fn drop_hint_end(&self) -> &[u64] {
        self.drop_hint_end.as_slice()
    }

    /// Returns the normalized secret hashes aligned 1:1 with [`findings()`].
    pub(crate) fn norm_hashes(&self) -> &[NormHash] {
        self.norm_hash.as_slice()
    }

    /// Returns a shared view of accumulated finding records.
    ///
    /// The slice is invalidated by the next scan or any call that drains
    /// or mutates the scratch buffers.
    ///
    /// Order reflects scan traversal and is not guaranteed to be sorted by span.
    pub fn findings(&self) -> &[FindingRec] {
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        self.out.as_slice()
    }

    /// Returns the number of findings dropped due to the per-chunk cap.
    pub fn dropped_findings(&self) -> usize {
        self.findings_dropped
    }

    /// Records a finding using `root_hint_end` as the default drop boundary.
    #[allow(dead_code)] // Convenience wrapper for push_finding_with_drop_hint
    pub(super) fn push_finding(&mut self, rec: FindingRec, norm_hash: NormHash) {
        self.push_finding_with_drop_hint(rec, norm_hash, rec.root_hint_end, rec.dedupe_with_span);
    }

    /// Records a finding with an explicit drop boundary, deduplicating against
    /// previously seen findings within the current file.
    ///
    /// # Deduplication Strategy
    ///
    /// Findings are keyed by a 32-byte composite:
    ///
    /// ```text
    /// ┌────────┬────────┬────────────┬──────────┬─────────────────┬───────────────┐
    /// │file_id │rule_id │ span_start │ span_end │ root_hint_start │ root_hint_end │
    /// │ 4B     │ 4B     │ 4B         │ 4B       │ 8B              │ 8B            │
    /// └────────┴────────┴────────────┴──────────┴─────────────────┴───────────────┘
    /// ```
    ///
    /// For transform-derived findings (`step_id != STEP_ROOT`), span coordinates
    /// are zeroed only when a precise root-span mapping is available. When
    /// mapping is unavailable (nested transforms with length-changing parents),
    /// the decoded span is included to avoid collapsing distinct matches that
    /// share the same coarse root hint window.
    ///
    /// # Why Not Just Span Coordinates?
    ///
    /// Chunked scanning with overlap can produce the "same" finding from different
    /// chunk perspectives. The root hint window captures the logical identity of
    /// where the secret lives in the original file, regardless of which chunk
    /// boundary happened to include it.
    ///
    /// # False Positives
    ///
    /// The underlying `FixedSet128` is a probabilistic structure (Bloom-like).
    /// Collisions may suppress distinct findings, but the capacity is sized to
    /// `4× max_findings` to keep collision probability low for typical scans.
    ///
    /// `include_span` controls whether `span_start`/`span_end` participate in
    /// the dedupe key (used when root-span mapping is unavailable).
    ///
    /// Dedupe is split into two layers:
    /// - A per-file set (`seen_findings`) that suppresses cross-chunk repeats.
    /// - A per-scan set (`seen_findings_scan`) that enables within-scan replacement
    ///   (e.g., prefer transform findings) without re-emitting earlier chunks.
    #[inline(always)]
    pub(super) fn push_finding_with_drop_hint(
        &mut self,
        rec: FindingRec,
        norm_hash: NormHash,
        drop_hint_end: u64,
        include_span: bool,
    ) {
        crate::git_scan::perf::record_scan_finding();
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        // For root-level findings, include the exact span in the dedup key.
        // For transform-derived findings with mapped root spans, zero the span
        // since decoded offsets can vary by chunk alignment. When mapping is
        // unavailable, include the span to preserve distinct matches.
        //
        // Additionally, normalize root_hint_end for base64 padding tolerance.
        // Base64 can decode correctly with or without padding (e.g., 18 or 20
        // chars for 13 bytes). Compute the minimum encoded length and clamp if
        // the actual encoded length is within padding tolerance (3 chars).
        // This ensures findings from the same decoded content with different
        // padding get deduplicated across chunk boundaries.
        let include_span = include_span || rec.step_id == STEP_ROOT;
        let (span_start, span_end) = if include_span {
            (rec.span_start, rec.span_end)
        } else {
            (0, 0)
        };
        let normalized_root_hint_end = if rec.step_id == STEP_ROOT {
            rec.root_hint_end
        } else {
            let decoded_len = rec.span_end.saturating_sub(rec.span_start) as u64;
            let min_encoded = (decoded_len * 4).div_ceil(3); // ceil(decoded * 4/3)
            let actual_encoded = rec.root_hint_end.saturating_sub(rec.root_hint_start);
            if actual_encoded > min_encoded && actual_encoded <= min_encoded.saturating_add(3) {
                rec.root_hint_start.saturating_add(min_encoded)
            } else {
                rec.root_hint_end
            }
        };

        // Build a 32-byte dedup key and hash to 128 bits.
        let mut key_bytes = [0u8; 32];
        key_bytes[0..4].copy_from_slice(&rec.file_id.0.to_le_bytes());
        key_bytes[4..8].copy_from_slice(&rec.rule_id.to_le_bytes());
        key_bytes[8..12].copy_from_slice(&span_start.to_le_bytes());
        key_bytes[12..16].copy_from_slice(&span_end.to_le_bytes());
        key_bytes[16..24].copy_from_slice(&rec.root_hint_start.to_le_bytes());
        key_bytes[24..32].copy_from_slice(&normalized_root_hint_end.to_le_bytes());

        let hash = hash128(&key_bytes);
        let seen_in_scan = !self.seen_findings_scan.insert(hash);
        let is_new = self.seen_findings.insert(hash);

        if !is_new && !seen_in_scan {
            // Seen in a prior scan/chunk; suppress to avoid cross-chunk duplicates.
            return;
        }

        if !is_new {
            // Duplicate key detected. Prefer findings with more information:
            // 1. Transform findings over RAW (transforms provide decoded content)
            // 2. For transform findings with base64 padding tolerance, prefer larger root_hint_end
            //
            // Search for the existing finding that matches this dedup key and potentially replace it.
            for (i, existing) in self.out.as_mut_slice().iter_mut().enumerate() {
                if existing.file_id != rec.file_id || existing.rule_id != rec.rule_id {
                    continue;
                }

                // Check if this existing finding matches the dedup key criteria.
                let existing_matches = if rec.step_id == STEP_ROOT {
                    // Incoming is RAW: match on span and root_hint
                    existing.span_start == rec.span_start
                        && existing.span_end == rec.span_end
                        && existing.root_hint_start == rec.root_hint_start
                        && existing.root_hint_end == rec.root_hint_end
                } else {
                    // Incoming is transform: match on root_hint_start and normalized_root_hint_end
                    if existing.step_id == STEP_ROOT {
                        // Existing is RAW, incoming is transform. They match if the RAW's
                        // root_hint overlaps with the transform's normalized root_hint.
                        existing.root_hint_start == rec.root_hint_start
                            && existing.root_hint_end <= normalized_root_hint_end.saturating_add(3)
                            && existing.root_hint_end >= normalized_root_hint_end
                    } else {
                        // Both are transforms: match on normalized root_hint
                        if existing.root_hint_start != rec.root_hint_start {
                            false
                        } else {
                            // Compute normalized_end for existing
                            let existing_decoded_len =
                                existing.span_end.saturating_sub(existing.span_start) as u64;
                            let existing_min_encoded = (existing_decoded_len * 4).div_ceil(3);
                            let existing_actual_encoded = existing
                                .root_hint_end
                                .saturating_sub(existing.root_hint_start);
                            let existing_normalized_end = if existing_actual_encoded
                                > existing_min_encoded
                                && existing_actual_encoded <= existing_min_encoded.saturating_add(3)
                            {
                                existing
                                    .root_hint_start
                                    .saturating_add(existing_min_encoded)
                            } else {
                                existing.root_hint_end
                            };
                            existing_normalized_end == normalized_root_hint_end
                        }
                    }
                };

                if existing_matches {
                    // Found the matching existing finding. Decide whether to replace it.
                    let should_replace =
                        if rec.step_id != STEP_ROOT && existing.step_id == STEP_ROOT {
                            // Incoming is transform, existing is RAW: prefer transform
                            true
                        } else if rec.step_id == STEP_ROOT && existing.step_id != STEP_ROOT {
                            // Incoming is RAW, existing is transform: keep transform
                            false
                        } else {
                            // Both same type: prefer larger root_hint_end
                            rec.root_hint_end > existing.root_hint_end
                        };

                    if should_replace {
                        *existing = rec;
                        self.drop_hint_end.as_mut_slice()[i] = drop_hint_end;
                        self.norm_hash.as_mut_slice()[i] = norm_hash;
                    }
                    return;
                }
            }
            return; // Already seen (or hash collision) and no update needed.
        }

        if self.out.len() < self.max_findings {
            self.out.push(rec);
            self.norm_hash.push(norm_hash);
            self.drop_hint_end.push(drop_hint_end);
        } else {
            self.findings_dropped = self.findings_dropped.saturating_add(1);
        }
    }
}
