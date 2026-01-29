//! Core scanning engine: rule compilation, prefilters, and scan execution.
//!
//! Purpose: compile rule specs into anchors and gates, then scan buffers with
//! bounded work and reuse scratch allocations.
//!
//! # Algorithm
//! 1. Compile rules into anchor patterns and fast gates (keywords/confirm-all).
//! 2. Prefilter input buffers and build candidate windows.
//! 3. Run validators, gates, and regexes inside those windows.
//! 4. Optionally decode transform spans into derived buffers and repeat (BFS).
//!
//! # Invariants
//! - The engine is immutable after construction; all mutable scan state lives in
//!   [`ScanScratch`], which is single-threaded and reused across scans.
//! - Scratch buffers are reused across scans and must be reset between scans.
//! - Decoded buffers are stored in an append-only slab; ranges and `StepId`
//!   references are only valid until the next `ScanScratch::reset_for_scan`.
//! - Offsets stored in hot paths use `u32`; callers must chunk inputs so buffer
//!   lengths fit in `u32`.
//! - `SpanU32` and `BufRef::Slab` ranges are only valid until the next reset.
//! - All per-scan work is bounded by tuning limits: windows, hits, findings,
//!   decode output bytes, transform depth, and work items.
//! - UTF-16 anchors always contain at least one NUL byte, enabling a raw-only
//!   fast path for NUL-free buffers.
//! - Vectorscan prefiltering is enabled by default but best-effort; if the
//!   prefilter DB fails to compile, we fall back to full-buffer windows.
//!
//! # Design Notes
//! - The engine favors predictable cost over perfect precision: span/anchor
//!   selection is permissive, while validation and gates enforce correctness.
//! - Prefilters (Vectorscan, base64 pre-gate) are conservative: they may admit
//!   false positives but must not drop true matches.

use crate::api::*;
use crate::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, PaddingPolicy, WhitespacePolicy};
use crate::regex2anchor::{
    compile_trigger_plan, AnchorDeriveConfig, ResidueGatePlan, TriggerPlan, UnfilterableReason,
};
use crate::scratch_memory::ScratchVec;
use crate::stdx::{ByteRing, DynamicBitSet, FixedSet128};
use ahash::AHashMap;
use memchr::{memchr, memmem};
use regex::bytes::Regex;
use std::collections::BinaryHeap;
use std::ops::{ControlFlow, Range};
#[cfg(feature = "stats")]
use std::sync::atomic::{AtomicU64, Ordering};

mod helpers;
mod transform;
mod validator;
mod vectorscan_prefilter;

use self::helpers::*;
use self::transform::*;
use self::vectorscan_prefilter::{
    gate_match_callback, stream_match_callback, utf16_stream_match_callback, VsAnchorDb, VsGateDb,
    VsPrefilterDb, VsScratch, VsStream, VsStreamDb, VsStreamMatchCtx, VsStreamWindow,
    VsUtf16StreamDb, VsUtf16StreamMatchCtx,
};

#[cfg(test)]
use crate::demo::*;
#[cfg(test)]
use crate::runtime::{ScannerConfig, ScannerRuntime};
// --------------------------
// Internal compiled representation
// --------------------------

/// Anchor variant used during matching and window scaling.
///
/// Raw anchors match input bytes directly. UTF-16 variants match byte-encoded
/// UTF-16LE/BE anchors and double window radii via `scale()` so windows are
/// sized in bytes, not code units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Variant {
    Raw,
    Utf16Le,
    Utf16Be,
}

impl Variant {
    fn idx(self) -> usize {
        match self {
            Variant::Raw => 0,
            Variant::Utf16Le => 1,
            Variant::Utf16Be => 2,
        }
    }

    fn from_idx(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(Variant::Raw),
            1 => Some(Variant::Utf16Le),
            2 => Some(Variant::Utf16Be),
            _ => None,
        }
    }

    fn scale(self) -> usize {
        match self {
            Variant::Raw => 1,
            Variant::Utf16Le | Variant::Utf16Be => 2,
        }
    }

    fn utf16_endianness(self) -> Option<Utf16Endianness> {
        match self {
            Variant::Raw => None,
            Variant::Utf16Le => Some(Utf16Endianness::Le),
            Variant::Utf16Be => Some(Utf16Endianness::Be),
        }
    }
}

/// Mapping entry from an anchor pattern id to a rule/variant accumulator.
///
/// Anchor patterns are deduped in a shared pattern table. Each pattern id can
/// fan out to multiple rules and variants; `pat_offsets` slices into the flat
/// `pat_targets` array. A `Target` is a compact (rule_id, variant) pair packed
/// into `u32` to keep the fanout table cache-friendly and avoid extra pointer
/// chasing.
///
/// Flags encoded in the low bits record whether the anchor is match-start
/// aligned (required by fast validators) and whether keyword gates are implied
/// by this specific anchor (so the validator can remain authoritative).
///
/// Layout (low bits): [variant (2)] [match_start] [keyword_implied] [rule_id...]
#[derive(Clone, Copy, Debug)]
struct Target(u32);

impl Target {
    const VARIANT_MASK: u32 = 0b11;
    const MATCH_START_MASK: u32 = 1 << 2;
    const KEYWORD_IMPLIED_MASK: u32 = 1 << 3;
    const VARIANT_SHIFT: u32 = 4;

    fn new(rule_id: u32, variant: Variant, match_start: bool, keyword_implied: bool) -> Self {
        assert!(rule_id <= (u32::MAX >> Self::VARIANT_SHIFT));
        let mut v = (rule_id << Self::VARIANT_SHIFT) | variant.idx() as u32;
        if match_start {
            v |= Self::MATCH_START_MASK;
        }
        if keyword_implied {
            v |= Self::KEYWORD_IMPLIED_MASK;
        }
        Self(v)
    }

    fn rule_id(self) -> usize {
        (self.0 >> Self::VARIANT_SHIFT) as usize
    }

    fn variant(self) -> Variant {
        match self.0 & Self::VARIANT_MASK {
            0 => Variant::Raw,
            1 => Variant::Utf16Le,
            2 => Variant::Utf16Be,
            _ => unreachable!("invalid variant tag"),
        }
    }

    fn match_start_aligned(self) -> bool {
        (self.0 & Self::MATCH_START_MASK) != 0
    }

    fn keyword_implied(self) -> bool {
        (self.0 & Self::KEYWORD_IMPLIED_MASK) != 0
    }
}

// Anchor scanning is handled by Vectorscan prefilters and UTF-16 anchor DBs.

/// Packed byte patterns with an offset table.
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm patterns contiguous for cache-friendly memmem checks (both ANY and
/// ALL gates).
///
/// Invariant: `offsets[0] == 0` and `bytes.len() <= u32::MAX`.
#[derive(Clone, Debug)]
struct PackedPatterns {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl PackedPatterns {
    fn with_capacity(patterns: usize, bytes: usize) -> Self {
        let mut offsets = Vec::with_capacity(patterns.saturating_add(1));
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(bytes),
            offsets,
        }
    }

    fn push_raw(&mut self, pat: &[u8]) {
        self.bytes.extend_from_slice(pat);
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    fn push_utf16le(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(b);
            self.bytes.push(0);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    fn push_utf16be(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(0);
            self.bytes.push(b);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }
}

/// Two-phase rule data compiled per variant for fast confirm checks.
///
/// Stores prepacked confirm patterns per variant so the scan loop can run
/// memmem without per-hit allocation or UTF-16 conversions.
#[derive(Clone, Debug)]
struct TwoPhaseCompiled {
    seed_radius: usize,
    full_radius: usize,

    // confirm patterns per variant (raw bytes for Raw, utf16-bytes for Utf16Le/Be)
    confirm: [PackedPatterns; 3],
}

#[derive(Clone, Debug)]
struct KeywordsCompiled {
    // Raw / Utf16Le / Utf16Be variants packed for fast memmem gating.
    // This mirrors anchor variant handling so keyword gating behaves consistently
    // across encodings and avoids per-window UTF-16 conversions.
    any: [PackedPatterns; 3],
}

/// Derived "confirm all" gate from mandatory literal islands.
///
/// Design intent:
/// - The longest literal is checked first as a single memmem search.
/// - The remaining literals are checked with AND semantics using PackedPatterns.
/// - UTF-16 variants are encoded the same way as anchors/keywords so we can
///   reject windows before decoding.
#[derive(Clone, Debug)]
struct ConfirmAllCompiled {
    primary: [Option<Vec<u8>>; 3],
    rest: [PackedPatterns; 3],
}

#[derive(Clone, Copy, Debug)]
struct EntropyCompiled {
    // Prevalidated config stored in compiled rules to avoid repeated lookups.
    // Lengths are measured in bytes of the candidate match.
    min_bits_per_byte: f32,
    min_len: usize,
    max_len: usize,
}

/// Compiled rule representation used during scanning.
///
/// This keeps precompiled regexes and optional two-phase data to minimize
/// work in the hot path.
#[derive(Clone, Debug)]
struct RuleCompiled {
    name: &'static str,
    radius: usize,
    validator: ValidatorKind,
    must_contain: Option<&'static [u8]>,
    // Derived AND gate: all literals must appear in the window before regex.
    confirm_all: Option<ConfirmAllCompiled>,
    keywords: Option<KeywordsCompiled>,
    entropy: Option<EntropyCompiled>,
    re: Regex,
    two_phase: Option<TwoPhaseCompiled>,
}

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`. Spans are half-open
/// ranges (`start..end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpanU32 {
    start: u32,
    end: u32,
}

impl SpanU32 {
    fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end);
        debug_assert!(start <= u32::MAX as usize);
        debug_assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

/// Accumulates anchor hit windows for a single (rule, variant).
///
/// Starts as an append-only list. If the hit count exceeds the configured cap,
/// it switches to a single "coalesced" window that covers the union of all hits
/// seen so far. The fallback is conservative (may over-expand) but guarantees
/// correctness while bounding memory growth.
///
/// Windows are pushed in non-decreasing order for anchor scans. When switching
/// to coalesced mode, ordering is no longer meaningful; downstream code must
/// not assume sorted windows unless it explicitly sorts them.
struct HitAccumulator {
    windows: ScratchVec<SpanU32>,
    coalesced: Option<SpanU32>,
}

impl HitAccumulator {
    fn with_capacity(cap: usize) -> Self {
        assert!(cap > 0, "hit accumulator capacity must be > 0");
        Self {
            windows: ScratchVec::with_capacity(cap)
                .expect("scratch hit accumulator allocation failed"),
            coalesced: None,
        }
    }

    fn push(&mut self, start: usize, end: usize, max_hits: usize) {
        debug_assert!(max_hits > 0, "max_hits must be > 0");
        let r = SpanU32::new(start, end);
        if let Some(c) = self.coalesced.as_mut() {
            // Once coalesced, we only widen the single window. This ensures
            // correctness (superset) while bounding per-rule memory.
            c.start = c.start.min(r.start);
            c.end = c.end.max(r.end);
            return;
        }

        if self.windows.len() < max_hits {
            self.windows.push(r);
            return;
        }

        // Switch to coalesced fallback once we exceed the hit cap.
        // This trades precision for deterministic memory usage.
        let mut c = self.windows[0];
        let win_len = self.windows.len();
        for i in 1..win_len {
            let w = self.windows[i];
            c.start = c.start.min(w.start);
            c.end = c.end.max(w.end);
        }
        c.start = c.start.min(r.start);
        c.end = c.end.max(r.end);

        self.windows.clear();
        self.coalesced = Some(c);
    }

    fn reset(&mut self) {
        self.windows.clear();
        self.coalesced = None;
    }

    fn capacity(&self) -> usize {
        self.windows.capacity()
    }

    fn take_into(&mut self, out: &mut ScratchVec<SpanU32>) {
        out.clear();
        if let Some(c) = self.coalesced.take() {
            out.push(c);
        } else {
            let len = self.windows.len();
            for i in 0..len {
                out.push(self.windows[i]);
            }
            self.windows.clear();
        }
    }
}

/// Node in the decode-step arena, linking to its parent step.
struct StepNode {
    parent: StepId,
    step: DecodeStep,
}

/// Arena for decode steps so findings store compact `StepId` references.
///
/// Why an arena?
/// - Decoding is recursive; each derived buffer adds provenance.
/// - Storing full `Vec<DecodeStep>` per finding would allocate and clone heavily.
/// - A parent-linked arena lets us store provenance once and share it across
///   findings, with O(length) reconstruction only when materializing output.
///
/// This is append-only and reset between scans. `StepId` values are only valid
/// while this arena is alive and not reset.
struct StepArena {
    /// Parent-linked decode step nodes.
    ///
    /// Each node records a single decode operation (transform ID, span) and
    /// points to its parent step. This compact representation enables sharing
    /// provenance across multiple findings from the same decoded buffer.
    nodes: ScratchVec<StepNode>,
}

impl StepArena {
    fn reset(&mut self) {
        self.nodes.clear();
    }

    fn push(&mut self, parent: StepId, step: DecodeStep) -> StepId {
        let id = StepId(self.nodes.len() as u32);
        self.nodes.push(StepNode { parent, step });
        id
    }

    /// Reconstructs the step chain from root to leaf.
    fn materialize(&self, mut id: StepId, out: &mut ScratchVec<DecodeStep>) {
        out.clear();
        while id != STEP_ROOT {
            let cur = id;
            let node = &self.nodes[cur.0 as usize];
            out.push(node.step.clone());
            id = node.parent;
        }
        // Reverse in place
        let len = out.len();
        for i in 0..len / 2 {
            out.as_mut_slice().swap(i, len - 1 - i);
        }
    }
}

/// Contiguous decoded-byte slab for derived buffers.
///
/// This is a monotonic append-only buffer:
/// - Decoders append into the slab and receive a `Range<usize>` back.
/// - Work items carry those ranges instead of owning new allocations.
/// - The slab never reallocates (capacity == global decode budget), so the
///   returned ranges remain valid for the lifetime of a scan.
///
/// The slab is cleared between scans, which invalidates all ranges at once.
struct DecodeSlab {
    buf: Vec<u8>,
    limit: usize,
}

impl DecodeSlab {
    fn with_limit(limit: usize) -> Self {
        let buf = Vec::with_capacity(limit);
        Self { buf, limit }
    }

    fn reset(&mut self) {
        self.buf.clear();
    }

    fn slice(&self, r: Range<usize>) -> &[u8] {
        &self.buf[r]
    }

    /// Append decoded bytes into the slab while enforcing per-transform and
    /// global decode budgets.
    ///
    /// On decode error, truncation, or zero output, the slab is rolled back to
    /// its pre-call length and `Err(())` is returned.
    fn append_stream_decode(
        &mut self,
        tc: &TransformConfig,
        input: &[u8],
        max_out: usize,
        ctx_total_decode_output_bytes: &mut usize,
        global_limit: usize,
    ) -> Result<Range<usize>, ()> {
        let start_len = self.buf.len();
        let start_ctx = *ctx_total_decode_output_bytes;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, input, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if ctx_total_decode_output_bytes.saturating_add(chunk.len()) > global_limit {
                truncated = true;
                return ControlFlow::Break(());
            }
            if self.buf.len().saturating_add(chunk.len()) > self.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            self.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            *ctx_total_decode_output_bytes =
                ctx_total_decode_output_bytes.saturating_add(chunk.len());

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            self.buf.truncate(start_len);
            *ctx_total_decode_output_bytes = start_ctx;
            return Err(());
        }

        Ok(start_len..(start_len + local_out))
    }
}

#[derive(Clone, Copy)]
struct EntropyScratch {
    // Histogram for byte frequencies (256 bins).
    counts: [u32; 256],
    // List of "touched" byte values so we can reset in O(distinct) instead of O(256).
    used: [u8; 256],
    used_len: u16,
}

impl EntropyScratch {
    fn new() -> Self {
        Self {
            counts: [0u32; 256],
            used: [0u8; 256],
            used_len: 0,
        }
    }

    #[inline]
    fn reset(&mut self) {
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
    out: ScratchVec<FindingRec>,
    max_findings: usize,     // Per-chunk cap from tuning.
    findings_dropped: usize, // Overflow counter when cap is exceeded.
    /// Work queue for breadth-first buffer traversal.
    ///
    /// Contains the root buffer plus any decoded buffers from transforms.
    /// Fixed capacity ensures no allocations during the scan loop; the tuning
    /// parameter `max_work_items` determines the upper bound.
    work_q: ScratchVec<WorkItem>,
    work_head: usize,                 // Cursor into work_q.
    slab: DecodeSlab,                 // Decoded output storage.
    seen: FixedSet128,                // Dedupe for decoded buffers.
    total_decode_output_bytes: usize, // Global decode budget tracker.
    work_items_enqueued: usize,       // Work queue budget tracker.
    /// Streaming decoded-byte ring buffer for window capture.
    decode_ring: ByteRing,
    /// Temporary buffer for materializing decoded windows from the ring.
    window_bytes: Vec<u8>,
    /// Pending window heap (min-heap by `hi`) for decoded stream verification.
    pending_windows: BinaryHeap<PendingWindow>,
    /// Match windows produced by the Vectorscan stream callback.
    vs_stream_matches: Vec<VsStreamWindow>,
    /// Pending decode spans captured during streaming decode.
    pending_spans: Vec<PendingDecodeSpan>,
    /// Span detectors for nested transforms in decoded streams.
    span_streams: Vec<SpanStreamEntry>,
    /// Temporary findings buffer for a decoded stream (dedupe-aware).
    tmp_findings: Vec<FindingRec>,
    /// Per-rule stream hit counts for decoded-window seeding.
    stream_hit_counts: Vec<u32>,
    /// Scratch list of touched stream hit counters for fast reset.
    stream_hit_touched: ScratchVec<u32>,
    accs: Vec<[HitAccumulator; 3]>, // Per (rule, variant) hit accumulators.
    touched_pairs: ScratchVec<u32>, // Scratch list of touched pairs.
    touched: DynamicBitSet,         // Bitset for touched pairs.
    touched_any: bool,              // Fast path for "none touched".
    windows: ScratchVec<SpanU32>,   // Merged windows for a pair.
    expanded: ScratchVec<SpanU32>,  // Expanded windows for two-phase rules.
    spans: ScratchVec<SpanU32>,     // Transform span candidates.
    /// Decode provenance arena.
    ///
    /// Stores parent-linked decode steps so findings can reconstruct their
    /// full transform chain without per-finding allocation. Fixed capacity
    /// bounds memory usage; the arena is reset between chunks.
    step_arena: StepArena,
    /// UTF-16 to UTF-8 transcoding buffer.
    ///
    /// Used when scanning UTF-16LE/BE variants of the input buffer. Fixed
    /// capacity sized to the maximum window size ensures no allocation during
    /// variant scanning.
    utf16_buf: ScratchVec<u8>,
    entropy_scratch: EntropyScratch, // Entropy histogram scratch.
    /// Scratch buffer for materializing decode step chains.
    ///
    /// When a finding is emitted, its `StepId` is traced through the arena to
    /// reconstruct the full decode path. This buffer holds the reversed chain
    /// during materialization. Capacity is bounded by `max_transform_depth`.
    steps_buf: ScratchVec<DecodeStep>,

    /// Per-thread Vectorscan scratch space (present when the prefilter DB is active).
    ///
    /// Vectorscan requires each scanning thread to have its own scratch memory.
    vs_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 anchor prefiltering.
    vs_utf16_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 stream anchor scanning.
    vs_utf16_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for stream-mode scanning.
    vs_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for decoded gate scanning.
    vs_gate_scratch: Option<VsScratch>,
    #[cfg(feature = "b64-stats")]
    base64_stats: Base64DecodeStats, // Base64 decode/gate instrumentation.
}

impl ScanScratch {
    fn new(engine: &Engine) -> Self {
        let rules_len = engine.rules.len();
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        let max_findings = engine.tuning.max_findings_per_chunk;
        let mut accs = Vec::with_capacity(rules_len);
        for _ in 0..rules_len {
            accs.push(std::array::from_fn(|_| {
                HitAccumulator::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
            }));
        }

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
        let pending_cap = engine.tuning.max_windows_per_rule_variant.max(16);

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
            pending_windows: BinaryHeap::with_capacity(pending_cap),
            vs_stream_matches: Vec::with_capacity(pending_cap),
            pending_spans: Vec::with_capacity(max_spans.max(16)),
            span_streams: Vec::with_capacity(engine.transforms.len()),
            tmp_findings: Vec::with_capacity(max_findings),
            stream_hit_counts: vec![0u32; rules_len.saturating_mul(3)],
            stream_hit_touched: ScratchVec::with_capacity(rules_len.saturating_mul(3))
                .expect("scratch stream_hit_touched allocation failed"),
            accs,
            touched_pairs: ScratchVec::with_capacity(rules_len.saturating_mul(3))
                .expect("scratch touched_pairs allocation failed"),
            touched: DynamicBitSet::empty(rules_len.saturating_mul(3)),
            touched_any: false,
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
    /// This may reallocate scratch buffers if the engine's tuning or rule set
    /// grew since the last scan.
    fn reset_for_scan(&mut self, engine: &Engine) {
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
        self.pending_windows.clear();
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
        self.touched_pairs.clear();
        self.touched_any = false;
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        let accs_need_rebuild = self.accs.len() != engine.rules.len()
            || self
                .accs
                .first()
                .map(|accs| accs[0].capacity() < engine.tuning.max_anchor_hits_per_rule_variant)
                .unwrap_or(true);
        if accs_need_rebuild {
            self.accs.clear();
            self.accs.reserve(engine.rules.len());
            for _ in 0..engine.rules.len() {
                self.accs.push(std::array::from_fn(|_| {
                    HitAccumulator::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                }));
            }
        }
        let expected_bits = engine.rules.len().saturating_mul(3);
        if self.touched.bit_length() != expected_bits {
            self.touched = DynamicBitSet::empty(expected_bits);
        } else {
            self.touched.clear();
        }
        if self.touched_pairs.capacity() < expected_bits {
            self.touched_pairs = ScratchVec::with_capacity(expected_bits)
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
        let pending_cap = engine.tuning.max_windows_per_rule_variant.max(16);
        if self.pending_windows.capacity() < pending_cap {
            self.pending_windows = BinaryHeap::with_capacity(pending_cap);
        }
        if self.vs_stream_matches.capacity() < pending_cap {
            self.vs_stream_matches
                .reserve(pending_cap - self.vs_stream_matches.capacity());
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

    fn mark_touched(&mut self, rule_id: usize, variant: Variant) {
        let idx = rule_id * 3 + variant.idx();
        self.touched.set(idx);
        self.touched_any = true;
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

    fn push_finding(&mut self, rec: FindingRec) {
        if self.out.len() < self.max_findings {
            self.out.push(rec);
        } else {
            self.findings_dropped = self.findings_dropped.saturating_add(1);
        }
    }
}

/// Reference to a buffer being scanned.
///
/// `Root` points to the input chunk. `Slab(range)` points into `DecodeSlab`.
/// Slab ranges are only valid until the slab is reset or truncated.
#[derive(Default, Clone)]
enum BufRef {
    #[default]
    Root,
    Slab(Range<usize>),
}

/// Reference to an encoded span to decode.
#[derive(Clone)]
enum EncRef {
    Root(Range<usize>),
    Slab(Range<usize>),
}

/// Pending decode span captured during streaming decode.
#[derive(Clone)]
struct PendingDecodeSpan {
    transform_idx: usize,
    range: Range<usize>,
    step_id: StepId,
    root_hint: Option<Range<usize>>,
    depth: usize,
}

#[derive(Eq, PartialEq)]
struct PendingWindow {
    hi: u64,
    lo: u64,
    rule_id: u32,
    variant: Variant,
}

impl Ord for PendingWindow {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .hi
            .cmp(&self.hi)
            .then_with(|| other.lo.cmp(&self.lo))
            .then_with(|| other.rule_id.cmp(&self.rule_id))
            .then_with(|| (other.variant.idx()).cmp(&self.variant.idx()))
    }
}

impl PartialOrd for PendingWindow {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

enum SpanStreamState {
    Url(UrlSpanStream),
    Base64(Base64SpanStream),
}

struct SpanStreamEntry {
    transform_idx: usize,
    mode: TransformMode,
    state: SpanStreamState,
    spans_emitted: usize,
    max_spans: usize,
}

/// Work item in the transform/scan queue.
///
/// Carries the decode provenance (StepId) and a root-span hint for reporting.
/// Depth enforces the transform recursion limit and keeps traversal iterative.
enum WorkItem {
    ScanBuf {
        buf: BufRef,
        step_id: StepId,
        root_hint: Option<Range<usize>>, // None for root buffer; Some for derived buffers
        depth: usize,
    },
    DecodeSpan {
        transform_idx: usize,
        enc_ref: EncRef,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
    },
}

impl Default for WorkItem {
    fn default() -> Self {
        WorkItem::ScanBuf {
            buf: BufRef::Root,
            step_id: STEP_ROOT,
            root_hint: None,
            depth: 0,
        }
    }
}

// --------------------------
// Engine
// --------------------------

/// Compiled scanning engine with derived anchors, rules, and transforms.
///
/// Build once, then reuse with per-scan scratch buffers to avoid allocations.
///
/// # Guarantees
/// - Immutable after construction; methods only borrow `&self`.
/// - `scan_chunk_*` methods reset the provided [`ScanScratch`] before use and
///   enforce per-scan tuning budgets.
///
/// # Invariants
/// - Input buffers must be chunked so `buf.len() <= u32::MAX`.
/// - [`ScanScratch`] is single-threaded; use one scratch per worker/thread.
///
/// # Performance
/// - Prefilters and gates bound work; regex validation runs only inside
///   candidate windows.
pub struct Engine {
    rules: Vec<RuleCompiled>,
    transforms: Vec<TransformConfig>,
    pub(crate) tuning: Tuning,

    // Log2 lookup table for entropy gating.
    entropy_log2: Vec<f32>,

    // Vectorscan/Hyperscan prefilter DB for raw scanning.
    //
    // Built by default, but stored as `None` when the prefilter DB fails to
    // compile (unsupported patterns, expression-info failures, etc.).
    // When present, this seeds candidate windows in a single `hs_scan` pass.
    vs: Option<VsPrefilterDb>,
    // Optional Vectorscan DB for UTF-16 anchor scanning.
    //
    // When present, this prefilters UTF-16 variants using literal anchors.
    vs_utf16: Option<VsAnchorDb>,
    // Vectorscan stream-mode DB for UTF-16 anchor scanning in decoded streams.
    vs_utf16_stream: Option<VsUtf16StreamDb>,
    // Vectorscan stream-mode DB for decoded-byte scanning.
    vs_stream: Option<VsStreamDb>,
    // Vectorscan stream-mode DB for decoded-space anchor gating.
    vs_gate: Option<VsGateDb>,
    // Base64 pre-decode gate built from anchor patterns.
    //
    // This runs in *encoded space* and is deliberately conservative:
    // if a decoded buffer contains an anchor, at least one YARA-style base64
    // permutation of that anchor must appear in the encoded stream. We still
    // perform the decoded-space gate for correctness; this pre-gate exists
    // purely to skip wasteful decodes when no anchor could possibly appear.
    b64_gate: Option<Base64YaraGate>,

    // Residue gates for rules without anchors (pass 2).
    residue_rules: Vec<(usize, ResidueGatePlan)>,
    unfilterable_rules: Vec<(usize, UnfilterableReason)>,
    #[cfg(feature = "stats")]
    anchor_plan_stats: AnchorPlanStats,
    #[cfg(feature = "stats")]
    vs_stats: VectorscanCounters,

    max_anchor_pat_len: usize,
    has_utf16_anchors: bool,
    max_window_diameter_bytes: usize,
    max_prefilter_width: usize,
    stream_ring_bytes: usize,
}

/// Summary of anchor derivation choices during engine build.
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorPlanStats {
    pub manual_rules: usize,
    pub derived_rules: usize,
    pub residue_rules: usize,
    pub unfilterable_rules: usize,
}

/// Vectorscan usage counters for a scan run (feature: `stats`).
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct VectorscanStats {
    /// Whether the Vectorscan DB compiled successfully.
    pub db_built: bool,
    /// Whether the UTF-16 Vectorscan DB compiled successfully.
    pub utf16_db_built: bool,
    /// Number of buffers where a Vectorscan scan was attempted.
    pub scans_attempted: u64,
    /// Number of Vectorscan scans that completed successfully.
    pub scans_ok: u64,
    /// Number of Vectorscan scans that errored.
    pub scans_err: u64,
    /// Number of buffers where a UTF-16 Vectorscan scan was attempted.
    pub utf16_scans_attempted: u64,
    /// Number of UTF-16 Vectorscan scans that completed successfully.
    pub utf16_scans_ok: u64,
    /// Number of UTF-16 Vectorscan scans that errored.
    pub utf16_scans_err: u64,
    /// Buffers scanned without the raw Vectorscan prefilter (full-buffer fallback).
    pub anchor_only: u64,
    /// Buffers that used raw Vectorscan and also ran a UTF-16 anchor scan.
    pub anchor_after_vs: u64,
    /// Buffers where raw Vectorscan was used and UTF-16 scan was skipped.
    pub anchor_skipped: u64,
    /// Stream decode spans that fell back to full decode.
    pub stream_force_full: u64,
    /// Stream decode spans that exceeded the per-rule window cap.
    pub stream_window_cap_exceeded: u64,
}

#[cfg(feature = "stats")]
#[derive(Default)]
struct VectorscanCounters {
    scans_attempted: AtomicU64,
    scans_ok: AtomicU64,
    scans_err: AtomicU64,
    utf16_scans_attempted: AtomicU64,
    utf16_scans_ok: AtomicU64,
    utf16_scans_err: AtomicU64,
    anchor_only: AtomicU64,
    anchor_after_vs: AtomicU64,
    anchor_skipped: AtomicU64,
    stream_force_full: AtomicU64,
    stream_window_cap_exceeded: AtomicU64,
}

#[cfg(feature = "stats")]
impl VectorscanCounters {
    fn snapshot(&self, db_built: bool, utf16_db_built: bool) -> VectorscanStats {
        VectorscanStats {
            db_built,
            utf16_db_built,
            scans_attempted: self.scans_attempted.load(Ordering::Relaxed),
            scans_ok: self.scans_ok.load(Ordering::Relaxed),
            scans_err: self.scans_err.load(Ordering::Relaxed),
            utf16_scans_attempted: self.utf16_scans_attempted.load(Ordering::Relaxed),
            utf16_scans_ok: self.utf16_scans_ok.load(Ordering::Relaxed),
            utf16_scans_err: self.utf16_scans_err.load(Ordering::Relaxed),
            anchor_only: self.anchor_only.load(Ordering::Relaxed),
            anchor_after_vs: self.anchor_after_vs.load(Ordering::Relaxed),
            anchor_skipped: self.anchor_skipped.load(Ordering::Relaxed),
            stream_force_full: self.stream_force_full.load(Ordering::Relaxed),
            stream_window_cap_exceeded: self.stream_window_cap_exceeded.load(Ordering::Relaxed),
        }
    }
}

impl Engine {
    /// Compiles rule specs into an engine with Vectorscan prefilters and gates.
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated.
    pub fn new(rules: Vec<RuleSpec>, transforms: Vec<TransformConfig>, tuning: Tuning) -> Self {
        Self::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::PreferDerived)
    }

    /// Compiles rule specs into an engine with a specific anchor policy.
    ///
    /// # Design Notes
    /// - `AnchorPolicy::ManualOnly` uses only explicit anchors provided by rules.
    /// - `AnchorPolicy::DerivedOnly` ignores manual anchors and relies on derived
    ///   anchors/residue gates; rules that cannot be gated are reported via
    ///   [`Engine::unfilterable_rules`].
    /// - `AnchorPolicy::PreferDerived` derives anchors when possible and falls
    ///   back to manual anchors when derivation is unavailable.
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated.
    pub fn new_with_anchor_policy(
        rules: Vec<RuleSpec>,
        transforms: Vec<TransformConfig>,
        tuning: Tuning,
        policy: AnchorPolicy,
    ) -> Self {
        tuning.assert_valid();
        assert!(
            tuning.max_transform_depth.saturating_add(1) <= MAX_DECODE_STEPS,
            "max_transform_depth exceeds MAX_DECODE_STEPS"
        );
        for r in &rules {
            r.assert_valid();
        }
        for tc in &transforms {
            tc.assert_valid();
        }

        let mut rules_compiled = rules.iter().map(compile_rule).collect::<Vec<_>>();
        let max_entropy_len = rules_compiled
            .iter()
            .filter_map(|r| r.entropy.map(|e| e.max_len))
            .max()
            .unwrap_or(0);
        let entropy_log2 = build_log2_table(max_entropy_len);

        let utf16_seed_radius_bytes = rules
            .iter()
            .map(|r| {
                let seed = if let Some(tp) = &r.two_phase {
                    tp.seed_radius
                } else {
                    r.radius
                };
                let bytes = seed.saturating_mul(2);
                if bytes > u32::MAX as usize {
                    u32::MAX
                } else {
                    bytes as u32
                }
            })
            .collect::<Vec<_>>();

        // Build deduped anchor patterns: pattern -> targets
        let mut pat_map_raw: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut pat_map_all: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut pat_map_utf16: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(2).max(16));
        let mut residue_rules: Vec<(usize, ResidueGatePlan)> = Vec::with_capacity(rules.len());
        let mut unfilterable_rules: Vec<(usize, UnfilterableReason)> =
            Vec::with_capacity(rules.len());
        #[cfg(feature = "stats")]
        let mut anchor_plan_stats = AnchorPlanStats::default();
        let derive_cfg = AnchorDeriveConfig {
            utf8: false,
            ..AnchorDeriveConfig::default()
        };
        let allow_manual = matches!(
            policy,
            AnchorPolicy::ManualOnly | AnchorPolicy::PreferDerived
        );
        let allow_derive = matches!(
            policy,
            AnchorPolicy::DerivedOnly | AnchorPolicy::PreferDerived
        );

        for (rid, r) in rules.iter().enumerate() {
            assert!(rid <= u32::MAX as usize);
            let rid_u32 = rid as u32;
            let validator_match_start = r.validator != ValidatorKind::None;
            let keyword_implied_for_anchor = |anchor: &[u8]| -> bool {
                match r.keywords_any {
                    None => true,
                    Some(kws) => kws.contains(&anchor),
                }
            };
            let mut manual_used = false;
            let mut add_manual =
                |pat_map_raw: &mut AHashMap<Vec<u8>, Vec<Target>>,
                 pat_map_all: &mut AHashMap<Vec<u8>, Vec<Target>>,
                 pat_map_utf16: &mut AHashMap<Vec<u8>, Vec<Target>>| {
                    if !allow_manual {
                        return;
                    }
                    if manual_used || r.anchors.is_empty() {
                        return;
                    }
                    manual_used = true;
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.manual_rules =
                            anchor_plan_stats.manual_rules.saturating_add(1);
                    }
                    for &a in r.anchors {
                        let keyword_implied = keyword_implied_for_anchor(a);
                        add_pat_raw(
                            pat_map_raw,
                            a,
                            Target::new(
                                rid_u32,
                                Variant::Raw,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_raw(
                            pat_map_all,
                            a,
                            Target::new(
                                rid_u32,
                                Variant::Raw,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_all,
                            utf16le_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Le,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_all,
                            utf16be_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Be,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16le_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Le,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16be_bytes(a),
                            Target::new(
                                rid_u32,
                                Variant::Utf16Be,
                                validator_match_start,
                                keyword_implied,
                            ),
                        );
                    }
                };

            if !allow_derive {
                add_manual(&mut pat_map_raw, &mut pat_map_all, &mut pat_map_utf16);
                continue;
            }

            let plan = match compile_trigger_plan(r.re.as_str(), &derive_cfg) {
                Ok(plan) => plan,
                Err(_) => {
                    unfilterable_rules.push((rid, UnfilterableReason::UnsupportedRegexFeatures));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_raw, &mut pat_map_all, &mut pat_map_utf16);
                    continue;
                }
            };

            match plan {
                TriggerPlan::Anchored {
                    anchors,
                    mut confirm_all,
                } => {
                    if let Some(needle) = r.must_contain {
                        confirm_all.retain(|c| c.as_slice() != needle);
                    }
                    if let Some(compiled) = compile_confirm_all(confirm_all) {
                        rules_compiled[rid].confirm_all = Some(compiled);
                    }
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.derived_rules =
                            anchor_plan_stats.derived_rules.saturating_add(1);
                    }
                    for anchor in anchors {
                        let keyword_implied = keyword_implied_for_anchor(&anchor);
                        add_pat_raw(
                            &mut pat_map_raw,
                            &anchor,
                            Target::new(rid_u32, Variant::Raw, false, keyword_implied),
                        );
                        add_pat_raw(
                            &mut pat_map_all,
                            &anchor,
                            Target::new(rid_u32, Variant::Raw, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le, false, keyword_implied),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be, false, keyword_implied),
                        );
                    }
                }
                TriggerPlan::Residue { gate } => {
                    residue_rules.push((rid, gate));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.residue_rules =
                            anchor_plan_stats.residue_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_raw, &mut pat_map_all, &mut pat_map_utf16);
                }
                TriggerPlan::Unfilterable { reason } => {
                    unfilterable_rules.push((rid, reason));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_raw, &mut pat_map_all, &mut pat_map_utf16);
                }
            }
        }

        let (_anchor_patterns_raw, _pat_targets_raw, _pat_offsets_raw) =
            map_to_patterns(pat_map_raw);
        let (anchor_patterns_all, _pat_targets_all, _pat_offsets_all) =
            map_to_patterns(pat_map_all);
        let (anchor_patterns_utf16, pat_targets_utf16, pat_offsets_utf16) =
            map_to_patterns(pat_map_utf16);
        let max_anchor_pat_len = anchor_patterns_all
            .iter()
            .map(|p| p.len())
            .max()
            .unwrap_or(0);

        // Build the base64 pre-gate from the same anchor universe as the decoded gate:
        // raw anchors plus UTF-16 variants. This keeps the pre-gate *sound* with
        // respect to anchor presence in decoded bytes, while allowing false positives.
        //
        // Padding/whitespace policy mirrors our span detection/decoder behavior:
        // - Stop at '=' (treat padding as end-of-span)
        // - Ignore RFC4648 whitespace (space is only allowed if the span finder allows it)
        let b64_gate = if anchor_patterns_all.is_empty() {
            None
        } else {
            Some(Base64YaraGate::build(
                anchor_patterns_all.iter().map(|p| p.as_slice()),
                Base64YaraGateConfig {
                    min_pattern_len: 0,
                    padding_policy: PaddingPolicy::StopAndHalt,
                    whitespace_policy: WhitespacePolicy::Rfc4648,
                },
            ))
        };

        // Warm regex caches at startup to avoid lazy allocations later.
        // `find_iter` always constructs the per-regex cache, so a tiny buffer
        // is sufficient here.
        let warm = [0u8; 1];
        for rule in &rules_compiled {
            let mut it = rule.re.find_iter(&warm);
            let _ = it.next();
        }

        let mut max_window_diameter_bytes = 0usize;
        for r in &rules {
            let base = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };
            for scale in [1usize, 2usize] {
                let diameter = base.saturating_mul(2).saturating_mul(scale);
                max_window_diameter_bytes = max_window_diameter_bytes.max(diameter);
            }
        }

        let max_decoded_cap = transforms
            .iter()
            .map(|tc| tc.max_decoded_bytes)
            .max()
            .unwrap_or(0);
        let max_encoded_len = transforms
            .iter()
            .map(|tc| tc.max_encoded_len)
            .max()
            .unwrap_or(0);

        // Optional optimization. If the DB can't be built (e.g. regex syntax
        // incompatibility), fall back to full-buffer raw windows.
        let vs = VsPrefilterDb::try_new(&rules, &tuning).ok();
        let max_prefilter_width = vs
            .as_ref()
            .and_then(|db| db.max_match_width_bounded())
            .map(|w| w as usize)
            .unwrap_or(max_anchor_pat_len);
        let vs_stream = VsStreamDb::try_new_stream(&rules, max_decoded_cap).ok();
        let needs_decoded_gate = transforms
            .iter()
            .any(|tc| tc.gate == Gate::AnchorsInDecoded);
        let vs_gate =
            if needs_decoded_gate && !anchor_patterns_all.is_empty() && vs_stream.is_some() {
                VsGateDb::try_new_gate(&anchor_patterns_all).ok()
            } else {
                None
            };
        let max_stream_window_bytes = vs_stream
            .as_ref()
            .and_then(|db| {
                db.meta()
                    .iter()
                    .map(|m| {
                        let maxw = m.max_width as usize;
                        let rad = m.radius as usize;
                        maxw.saturating_add(rad.saturating_mul(2))
                    })
                    .max()
            })
            .unwrap_or(0);
        let max_anchor_window_bytes = max_window_diameter_bytes.saturating_add(max_anchor_pat_len);
        let stream_ring_bytes = max_stream_window_bytes
            .max(max_encoded_len)
            .max(max_anchor_window_bytes)
            .max(1);
        let has_utf16_anchors = !anchor_patterns_utf16.is_empty();
        let vs_utf16 = if !has_utf16_anchors {
            None
        } else {
            match VsAnchorDb::try_new_utf16(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &utf16_seed_radius_bytes,
                &tuning,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 db build failed: {err}");
                    }
                    None
                }
            }
        };
        let vs_utf16_stream = if !has_utf16_anchors {
            None
        } else {
            match VsUtf16StreamDb::try_new_utf16_stream(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &utf16_seed_radius_bytes,
                &tuning,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 stream db build failed: {err}");
                    }
                    None
                }
            }
        };
        Self {
            rules: rules_compiled,
            transforms,
            tuning,
            entropy_log2,
            vs,
            vs_utf16,
            vs_utf16_stream,
            vs_stream,
            vs_gate,
            b64_gate,
            residue_rules,
            unfilterable_rules,
            #[cfg(feature = "stats")]
            anchor_plan_stats,
            #[cfg(feature = "stats")]
            vs_stats: VectorscanCounters::default(),
            max_anchor_pat_len,
            has_utf16_anchors,
            max_window_diameter_bytes,
            max_prefilter_width,
            stream_ring_bytes,
        }
    }

    /// Returns a summary of how anchors were chosen during compilation.
    #[cfg(feature = "stats")]
    pub fn anchor_plan_stats(&self) -> AnchorPlanStats {
        self.anchor_plan_stats
    }

    /// Returns Vectorscan usage counters (feature: `stats`).
    #[cfg(feature = "stats")]
    pub fn vectorscan_stats(&self) -> VectorscanStats {
        self.vs_stats
            .snapshot(self.vs.is_some(), self.vs_utf16.is_some())
    }

    /// Rules whose regex patterns could not be given a sound prefilter gate.
    ///
    /// The slice contains `(rule_index, reason)` pairs in original rule order.
    pub fn unfilterable_rules(&self) -> &[(usize, UnfilterableReason)] {
        &self.unfilterable_rules
    }

    /// Single-buffer scan helper (allocation-free after startup).
    ///
    /// Findings are stored in `scratch` and returned as a shared slice. The
    /// returned slice is valid until `scratch` is reused for another scan.
    ///
    /// Equivalent to `scan_chunk_into` with `file_id = 0` and `base_offset = 0`.
    pub fn scan_chunk<'a>(&self, hay: &[u8], scratch: &'a mut ScanScratch) -> &'a [FindingRec] {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        scratch.findings()
    }

    /// Single-buffer scan helper that materializes findings into `out`.
    ///
    /// `out` must have enough capacity to hold all findings; otherwise this will panic.
    /// Use `Vec::with_capacity(self.tuning.max_findings_per_chunk)` to pre-size.
    ///
    /// # Panics
    /// Panics if `out.capacity()` is smaller than the number of findings.
    pub fn scan_chunk_materialized(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        out: &mut Vec<Finding>,
    ) {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        let expected = scratch.findings().len();
        assert!(out.capacity() >= expected, "output capacity too small");
        out.clear();
        self.drain_findings_materialized(scratch, out);
    }

    /// Scans a buffer and appends findings into the provided scratch state.
    ///
    /// The scratch is reset before use and reuses its buffers to avoid per-call
    /// allocations. Findings are stored as compact [`FindingRec`] entries.
    /// When the per-chunk finding cap is exceeded, extra findings are dropped
    /// and counted in [`ScanScratch::dropped_findings`].
    ///
    /// `base_offset` is the absolute byte offset of `root_buf` within the file
    /// or stream and is used to compute `root_hint_*` fields for findings.
    ///
    /// # Preconditions
    /// - `root_buf.len() <= u32::MAX`.
    /// - `scratch` is exclusively owned for the duration of the call.
    ///
    /// # Effects
    /// - Resets `scratch`, overwriting any pending findings.
    /// - Enqueues decode work items and updates per-scan counters.
    pub fn scan_chunk_into(
        &self,
        root_buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        // High-level flow:
        // 1) Prefilter the current buffer and build windows.
        // 2) Run regex validation inside those windows (raw + UTF-16 variants).
        // 3) Optionally decode transforms into derived buffers (gated + deduped),
        //    enqueueing them into a work queue for recursive scanning.
        //
        // Budgets (decode bytes, work items, depth) are enforced on the fly so
        // no single input can force unbounded work.
        scratch.reset_for_scan(self);
        scratch.work_q.push(WorkItem::ScanBuf {
            buf: BufRef::Root,
            step_id: STEP_ROOT,
            root_hint: None,
            depth: 0,
        });

        while scratch.work_head < scratch.work_q.len() {
            // Work-queue traversal avoids recursion and makes transform depth
            // and total work item budgets explicit and enforceable.
            if scratch.total_decode_output_bytes >= self.tuning.max_total_decode_output_bytes {
                break;
            }

            let item = std::mem::take(&mut scratch.work_q[scratch.work_head]);
            scratch.work_head += 1;

            match item {
                WorkItem::ScanBuf {
                    buf,
                    step_id,
                    root_hint,
                    depth,
                } => {
                    let before = scratch.out.len();
                    let (buf_ptr, buf_len, buf_offset) = match &buf {
                        BufRef::Root => (root_buf.as_ptr(), root_buf.len(), 0usize),
                        BufRef::Slab(range) => unsafe {
                            debug_assert!(range.end <= scratch.slab.buf.len());
                            // SAFETY: `range` is sourced from decode output and stays in-bounds.
                            let ptr = scratch.slab.buf.as_ptr().add(range.start);
                            (ptr, range.end.saturating_sub(range.start), range.start)
                        },
                    };

                    // SAFETY: `buf_ptr` points into `root_buf` or the decode slab. The slab does
                    // not reallocate during a scan, and `buf_len` is bounded by the checked range.
                    let cur_buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len) };

                    self.scan_rules_on_buffer(
                        cur_buf,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                    let found_any_in_this_buf = scratch.out.len() > before;

                    if depth >= self.tuning.max_transform_depth {
                        continue;
                    }
                    if scratch.work_items_enqueued >= self.tuning.max_work_items {
                        continue;
                    }

                    for (tidx, tc) in self.transforms.iter().enumerate() {
                        if tc.mode == TransformMode::Disabled {
                            continue;
                        }
                        if tc.mode == TransformMode::IfNoFindingsInThisBuffer
                            && found_any_in_this_buf
                        {
                            continue;
                        }
                        if cur_buf.len() < tc.min_len {
                            continue;
                        }
                        if !transform_quick_trigger(tc, cur_buf) {
                            continue;
                        }

                        find_spans_into(tc, cur_buf, &mut scratch.spans);
                        if scratch.spans.is_empty() {
                            continue;
                        }

                        let span_len = scratch.spans.len().min(tc.max_spans_per_buffer);
                        for i in 0..span_len {
                            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                                break;
                            }
                            if scratch.total_decode_output_bytes
                                >= self.tuning.max_total_decode_output_bytes
                            {
                                break;
                            }

                            let enc_span = scratch.spans[i].to_range();
                            let enc = &cur_buf[enc_span.clone()];
                            if tc.id == TransformId::Base64 {
                                // Base64-only prefilter: cheap encoded-space gate.
                                // This is only used when the decoded gate is enabled, and it never
                                // replaces the decoded check. It exists to avoid paying decode cost
                                // when a span cannot possibly contain any anchor after decoding.
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.spans =
                                        scratch.base64_stats.spans.saturating_add(1);
                                    scratch.base64_stats.span_bytes = scratch
                                        .base64_stats
                                        .span_bytes
                                        .saturating_add(enc.len() as u64);
                                }
                                if tc.gate == Gate::AnchorsInDecoded {
                                    if let Some(gate) = &self.b64_gate {
                                        #[cfg(feature = "b64-stats")]
                                        {
                                            scratch.base64_stats.pre_gate_checks = scratch
                                                .base64_stats
                                                .pre_gate_checks
                                                .saturating_add(1);
                                        }
                                        if !gate.hits(enc) {
                                            #[cfg(feature = "b64-stats")]
                                            {
                                                scratch.base64_stats.pre_gate_skip = scratch
                                                    .base64_stats
                                                    .pre_gate_skip
                                                    .saturating_add(1);
                                                scratch.base64_stats.pre_gate_skip_bytes = scratch
                                                    .base64_stats
                                                    .pre_gate_skip_bytes
                                                    .saturating_add(enc.len() as u64);
                                            }
                                            continue;
                                        }
                                        #[cfg(feature = "b64-stats")]
                                        {
                                            scratch.base64_stats.pre_gate_pass = scratch
                                                .base64_stats
                                                .pre_gate_pass
                                                .saturating_add(1);
                                        }
                                    }
                                }
                            }

                            let child_step_id = scratch.step_arena.push(
                                step_id,
                                DecodeStep::Transform {
                                    transform_idx: tidx,
                                    parent_span: enc_span.clone(),
                                },
                            );

                            let child_root_hint = if root_hint.is_none() {
                                Some(enc_span.clone())
                            } else {
                                root_hint.clone()
                            };

                            let enc_ref = match &buf {
                                BufRef::Root => EncRef::Root(enc_span.clone()),
                                BufRef::Slab(_) => {
                                    let start = buf_offset.saturating_add(enc_span.start);
                                    let end = buf_offset.saturating_add(enc_span.end);
                                    EncRef::Slab(start..end)
                                }
                            };

                            scratch.work_q.push(WorkItem::DecodeSpan {
                                transform_idx: tidx,
                                enc_ref,
                                step_id: child_step_id,
                                root_hint: child_root_hint,
                                depth: depth + 1,
                            });
                            scratch.work_items_enqueued += 1;
                        }
                    }
                }
                WorkItem::DecodeSpan {
                    transform_idx,
                    enc_ref,
                    step_id,
                    root_hint,
                    depth,
                } => {
                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        continue;
                    }
                    let tc = &self.transforms[transform_idx];
                    if tc.mode == TransformMode::Disabled {
                        continue;
                    }

                    let (enc_ptr, enc_len) = match enc_ref {
                        EncRef::Root(r) => {
                            if r.end <= root_buf.len() {
                                // SAFETY: bounds are checked against `root_buf`.
                                let ptr = unsafe { root_buf.as_ptr().add(r.start) };
                                (ptr, r.end - r.start)
                            } else {
                                continue;
                            }
                        }
                        EncRef::Slab(r) => {
                            if r.end <= scratch.slab.buf.len() {
                                // SAFETY: bounds are checked against the slab; it does not
                                // reallocate during a scan.
                                let ptr = unsafe { scratch.slab.buf.as_ptr().add(r.start) };
                                (ptr, r.end - r.start)
                            } else {
                                continue;
                            }
                        }
                    };
                    // SAFETY: `enc_ptr` points into `root_buf` or the decode slab. Both remain
                    // valid for the duration of this scan and are not reallocated.
                    let enc = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };

                    if let Some(vs_stream) = self.vs_stream.as_ref() {
                        self.decode_stream_and_scan(
                            vs_stream,
                            tc,
                            transform_idx,
                            enc,
                            step_id,
                            root_hint,
                            depth,
                            base_offset,
                            file_id,
                            scratch,
                        );
                    } else {
                        self.decode_span_fallback(
                            tc,
                            transform_idx,
                            enc,
                            step_id,
                            root_hint,
                            depth,
                            base_offset,
                            file_id,
                            scratch,
                        );
                    }
                }
            }
        }
    }

    /// Scans a buffer and returns a shared view of finding records.
    ///
    /// The returned slice is valid until `scratch` is reused for another scan.
    pub fn scan_chunk_records<'a>(
        &self,
        buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &'a mut ScanScratch,
    ) -> &'a [FindingRec] {
        self.scan_chunk_into(buf, file_id, base_offset, scratch);
        scratch.findings()
    }

    /// Returns the required overlap between chunks for correctness.
    ///
    /// This ensures verification windows (including two-phase expansions) fit
    /// across chunk boundaries. When scanning overlapping chunks, call
    /// [`ScanScratch::drop_prefix_findings`] with the new start offset to avoid
    /// emitting duplicates from the overlap prefix.
    pub fn required_overlap(&self) -> usize {
        self.max_window_diameter_bytes
            .saturating_add(self.max_prefilter_width.saturating_sub(1))
    }

    /// Returns the rule name for a rule id used in [`FindingRec`].
    pub fn rule_name(&self, rule_id: u32) -> &str {
        self.rules
            .get(rule_id as usize)
            .map(|r| r.name)
            .unwrap_or("<unknown-rule>")
    }

    /// Allocates a fresh scratch state sized for this engine.
    pub fn new_scratch(&self) -> ScanScratch {
        ScanScratch::new(self)
    }

    /// Drains compact findings from scratch and materializes provenance.
    pub fn drain_findings_materialized(&self, scratch: &mut ScanScratch, out: &mut Vec<Finding>) {
        for rec in scratch.out.drain() {
            let rule = &self.rules[rec.rule_id as usize];
            scratch
                .step_arena
                .materialize(rec.step_id, &mut scratch.steps_buf);
            let mut steps = DecodeSteps::new();
            steps.extend_from_slice(scratch.steps_buf.as_slice());
            out.push(Finding {
                rule: rule.name,
                span: (rec.span_start as usize)..(rec.span_end as usize),
                root_span_hint: u64_to_usize(rec.root_hint_start)..u64_to_usize(rec.root_hint_end),
                decode_steps: steps,
            });
        }
    }

    fn scan_rules_on_buffer(
        &self,
        buf: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        debug_assert!(buf.len() <= u32::MAX as usize);
        debug_assert!(self.tuning.merge_gap <= u32::MAX as usize);
        debug_assert!(self.tuning.pressure_gap_start <= u32::MAX as usize);
        let hay_len = buf.len() as u32;
        let merge_gap = self.tuning.merge_gap as u32;
        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

        // Stage 1: Vectorscan prefilter on raw bytes (best-effort).
        let mut used_vectorscan = false;
        let mut saw_nul = false;

        if let Some(vs) = self.vs.as_ref() {
            if let Some(mut vs_scratch) = scratch.vs_scratch.take() {
                #[cfg(feature = "stats")]
                self.vs_stats
                    .scans_attempted
                    .fetch_add(1, Ordering::Relaxed);
                let result = vs.scan_raw(buf, scratch, &mut vs_scratch);
                scratch.vs_scratch = Some(vs_scratch);
                match result {
                    Ok(nul) => {
                        used_vectorscan = true;
                        saw_nul = nul;
                        #[cfg(feature = "stats")]
                        self.vs_stats.scans_ok.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_err) => {
                        #[cfg(feature = "stats")]
                        self.vs_stats.scans_err.fetch_add(1, Ordering::Relaxed);
                        // Roll back partial accumulator state on error.
                        if scratch.touched_any {
                            scratch.touched_pairs.clear();
                            for pair in scratch.touched.iter_set() {
                                scratch.touched_pairs.push(pair as u32);
                            }
                            scratch.touched.clear();
                            scratch.touched_any = false;
                            let touched_len = scratch.touched_pairs.len();
                            for i in 0..touched_len {
                                let pair = scratch.touched_pairs[i] as usize;
                                let rid = pair / 3;
                                let vidx = pair % 3;
                                scratch.accs[rid][vidx].reset();
                            }
                            scratch.touched_pairs.clear();
                        }
                    }
                }
            }
        }

        if !used_vectorscan {
            // Fallback: seed a full-buffer window for raw variants.
            let max_hits = self.tuning.max_anchor_hits_per_rule_variant;
            for rid in 0..self.rules.len() {
                scratch.accs[rid][Variant::Raw.idx()].push(0, hay_len as usize, max_hits);
                scratch.mark_touched(rid, Variant::Raw);
            }
        }

        // Decide whether we need the UTF-16 anchor scan.
        //
        // If Vectorscan ran, we avoid an extra full memchr pass by using the
        // NUL sentinel result from the same `hs_scan`.
        let need_utf16_anchor_scan = self.tuning.scan_utf16_variants
            && if used_vectorscan {
                saw_nul
            } else {
                memchr(0, buf).is_some()
            };

        let mut used_vectorscan_utf16 = false;

        if need_utf16_anchor_scan {
            if let Some(vs_utf16) = self.vs_utf16.as_ref() {
                if let Some(mut vs_scratch) = scratch.vs_utf16_scratch.take() {
                    #[cfg(feature = "stats")]
                    self.vs_stats
                        .utf16_scans_attempted
                        .fetch_add(1, Ordering::Relaxed);
                    let result = vs_utf16.scan_utf16(buf, scratch, &mut vs_scratch);
                    scratch.vs_utf16_scratch = Some(vs_scratch);
                    used_vectorscan_utf16 = true;
                    match result {
                        Ok(()) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats.utf16_scans_ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_err) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats
                                .utf16_scans_err
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        #[cfg(feature = "stats")]
        {
            if used_vectorscan {
                if used_vectorscan_utf16 {
                    self.vs_stats
                        .anchor_after_vs
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.vs_stats.anchor_skipped.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                self.vs_stats.anchor_only.fetch_add(1, Ordering::Relaxed);
            }
        }

        if !scratch.touched_any {
            return;
        }

        // Only process (rule, variant) pairs that were actually touched by a
        // prefilter hit in this buffer. This avoids O(rules * variants) work
        // when nothing matched, which is critical once rule counts grow.
        const VARIANTS: [Variant; 3] = [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
        scratch.touched_pairs.clear();
        for pair in scratch.touched.iter_set() {
            scratch.touched_pairs.push(pair as u32);
        }
        scratch.touched.clear();
        scratch.touched_any = false;
        let touched_len = scratch.touched_pairs.len();
        for i in 0..touched_len {
            let pair = scratch.touched_pairs[i] as usize;
            let rid = pair / 3;
            let vidx = pair % 3;
            let variant = VARIANTS[vidx];
            let rule = &self.rules[rid];

            {
                let acc = &mut scratch.accs[rid][vidx];
                acc.take_into(&mut scratch.windows);
            }
            if scratch.windows.is_empty() {
                continue;
            }

            // Anchor scans push windows in non-decreasing order of match positions.
            // Vectorscan callbacks are not guaranteed to be ordered, so we must
            // sort the raw variant windows when Vectorscan ran.
            if (used_vectorscan && variant == Variant::Raw && scratch.windows.len() > 1)
                || (used_vectorscan_utf16
                    && matches!(variant, Variant::Utf16Le | Variant::Utf16Be)
                    && scratch.windows.len() > 1)
            {
                scratch
                    .windows
                    .as_mut_slice()
                    .sort_unstable_by_key(|s| s.start);
            }

            // Windows are pushed in non-decreasing order of match positions.
            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
            coalesce_under_pressure_sorted(
                &mut scratch.windows,
                hay_len,
                pressure_gap_start,
                self.tuning.max_windows_per_rule_variant,
            );

            if let Some(tp) = &rule.two_phase {
                // Two-phase: confirm in seed windows, then expand.
                let seed_radius_bytes = tp.seed_radius.saturating_mul(variant.scale());
                let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                scratch.expanded.clear();
                let windows_len = scratch.windows.len();
                for i in 0..windows_len {
                    let seed = scratch.windows[i];
                    let seed_range = seed.to_range();
                    let win = &buf[seed_range.clone()];
                    if !contains_any_memmem(win, &tp.confirm[vidx]) {
                        continue;
                    }

                    let lo = seed_range.start.saturating_sub(extra);
                    let hi = (seed_range.end + extra).min(buf.len());
                    scratch.expanded.push(SpanU32::new(lo, hi));
                }

                if scratch.expanded.is_empty() {
                    continue;
                }

                merge_ranges_with_gap_sorted(&mut scratch.expanded, merge_gap);
                coalesce_under_pressure_sorted(
                    &mut scratch.expanded,
                    hay_len,
                    pressure_gap_start,
                    self.tuning.max_windows_per_rule_variant,
                );

                let expanded_len = scratch.expanded.len();
                for i in 0..expanded_len {
                    let w = scratch.expanded[i].to_range();
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                }
            } else {
                let win_len = scratch.windows.len();
                for i in 0..win_len {
                    let w = scratch.windows[i].to_range();
                    self.run_rule_on_window(
                        rid as u32,
                        rule,
                        variant,
                        buf,
                        w,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_window(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        w: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        match variant {
            Variant::Raw => {
                let window = &buf[w.clone()];

                if let Some(needle) = rule.must_contain {
                    if memmem::find(window, needle).is_none() {
                        return;
                    }
                }

                if let Some(confirm) = &rule.confirm_all {
                    let vidx = Variant::Raw.idx();
                    if let Some(primary) = &confirm.primary[vidx] {
                        if memmem::find(window, primary).is_none() {
                            return;
                        }
                    }
                    if !contains_all_memmem(window, &confirm.rest[vidx]) {
                        return;
                    }
                }

                if let Some(kws) = &rule.keywords {
                    // Keyword gate is a cheap pre-regex filter: if none of the
                    // keywords appear in this window, the regex cannot be relevant.
                    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                        return;
                    }
                }

                let entropy = rule.entropy;
                for rm in rule.re.find_iter(window) {
                    if let Some(ent) = entropy {
                        let mbytes = &window[rm.start()..rm.end()];
                        // Entropy is evaluated on the *matched* bytes, not the whole window.
                        // This keeps the signal tied to the candidate token itself.
                        if !entropy_gate_passes(
                            &ent,
                            mbytes,
                            &mut scratch.entropy_scratch,
                            &self.entropy_log2,
                        ) {
                            continue;
                        }
                    }

                    let span_in_buf = (w.start + rm.start())..(w.start + rm.end());
                    let root_span_hint = root_hint.clone().unwrap_or_else(|| span_in_buf.clone());

                    scratch.push_finding(FindingRec {
                        file_id,
                        rule_id,
                        span_start: span_in_buf.start as u32,
                        span_end: span_in_buf.end as u32,
                        root_hint_start: base_offset + root_span_hint.start as u64,
                        root_hint_end: base_offset + root_span_hint.end as u64,
                        step_id,
                    });
                }
            }

            Variant::Utf16Le | Variant::Utf16Be => {
                // Decode this window as UTF-16 and run the same validators on UTF-8 output.
                let remaining = self
                    .tuning
                    .max_total_decode_output_bytes
                    .saturating_sub(scratch.total_decode_output_bytes);
                if remaining == 0 {
                    return;
                }

                if let Some(confirm) = &rule.confirm_all {
                    // Confirm-all literals are encoded like anchors/keywords so we can
                    // cheaply reject UTF-16 windows before decoding.
                    let raw_win = &buf[w.clone()];
                    let vidx = variant.idx();
                    if let Some(primary) = &confirm.primary[vidx] {
                        if memmem::find(raw_win, primary).is_none() {
                            return;
                        }
                    }
                    if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                        return;
                    }
                }

                if let Some(kws) = &rule.keywords {
                    // For UTF-16 variants, apply the keyword gate on the raw UTF-16 bytes
                    // *before* decoding to avoid spending decode budget on windows that
                    // could never pass the keyword check.
                    let raw_win = &buf[w.clone()];
                    let vidx = variant.idx();
                    if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                        return;
                    }
                }

                let max_out = self
                    .tuning
                    .max_utf16_decoded_bytes_per_window
                    .min(remaining);

                let decoded = match variant {
                    Variant::Utf16Le => {
                        decode_utf16le_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    Variant::Utf16Be => {
                        decode_utf16be_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf)
                    }
                    _ => unreachable!(),
                };

                if decoded.is_err() {
                    return;
                }

                let decoded = scratch.utf16_buf.as_slice();
                if decoded.is_empty() {
                    return;
                }

                scratch.total_decode_output_bytes = scratch
                    .total_decode_output_bytes
                    .saturating_add(decoded.len());
                if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
                    return;
                }

                if let Some(needle) = rule.must_contain {
                    if memmem::find(decoded, needle).is_none() {
                        return;
                    }
                }

                let endianness = match variant {
                    Variant::Utf16Le => Utf16Endianness::Le,
                    Variant::Utf16Be => Utf16Endianness::Be,
                    Variant::Raw => unreachable!("raw variant in UTF-16 branch"),
                };
                let utf16_step_id = scratch.step_arena.push(
                    step_id,
                    DecodeStep::Utf16Window {
                        endianness,
                        parent_span: w.clone(),
                    },
                );

                let max_findings = scratch.max_findings;
                let out = &mut scratch.out;
                let dropped = &mut scratch.findings_dropped;
                let entropy = rule.entropy;
                for rm in rule.re.find_iter(decoded) {
                    let span = rm.start()..rm.end();

                    if let Some(ent) = entropy {
                        let mbytes = &decoded[span.clone()];
                        // Entropy gate runs on UTF-8 decoded bytes because the regex
                        // is evaluated there; this keeps thresholds consistent.
                        if !entropy_gate_passes(
                            &ent,
                            mbytes,
                            &mut scratch.entropy_scratch,
                            &self.entropy_log2,
                        ) {
                            continue;
                        }
                    }

                    let root_span_hint = root_hint.clone().unwrap_or_else(|| w.clone());

                    if out.len() < max_findings {
                        out.push(FindingRec {
                            file_id,
                            rule_id,
                            span_start: span.start as u32,
                            span_end: span.end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            step_id: utf16_step_id,
                        });
                    } else {
                        *dropped = dropped.saturating_add(1);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_raw_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        window: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        dropped: &mut usize,
        found_any: &mut bool,
    ) {
        if let Some(needle) = rule.must_contain {
            if memmem::find(window, needle).is_none() {
                return;
            }
        }

        if let Some(confirm) = &rule.confirm_all {
            let vidx = Variant::Raw.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(window, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(window, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = &rule.keywords {
            if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                return;
            }
        }

        let max_findings = scratch.max_findings;
        let out = &mut scratch.tmp_findings;
        let entropy = rule.entropy;
        for rm in rule.re.find_iter(window) {
            if let Some(ent) = entropy {
                let mbytes = &window[rm.start()..rm.end()];
                if !entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                ) {
                    continue;
                }
            }

            *found_any = true;
            let span_start = window_start.saturating_add(rm.start() as u64) as usize;
            let span_end = window_start.saturating_add(rm.end() as u64) as usize;
            let span_in_buf = span_start..span_end;
            let root_span_hint = root_hint.clone().unwrap_or_else(|| span_in_buf.clone());

            if out.len() < max_findings {
                out.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: span_in_buf.start as u32,
                    span_end: span_in_buf.end as u32,
                    root_hint_start: base_offset + root_span_hint.start as u64,
                    root_hint_end: base_offset + root_span_hint.end as u64,
                    step_id,
                });
            } else {
                *dropped = dropped.saturating_add(1);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_utf16_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        raw_win: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        dropped: &mut usize,
        found_any: &mut bool,
    ) {
        // Decode this window as UTF-16 and run the same validators on UTF-8 output.
        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }

        if let Some(confirm) = &rule.confirm_all {
            let vidx = variant.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(raw_win, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = &rule.keywords {
            let vidx = variant.idx();
            if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                return;
            }
        }

        let max_out = self
            .tuning
            .max_utf16_decoded_bytes_per_window
            .min(remaining);

        let decoded = match variant {
            Variant::Utf16Le => decode_utf16le_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Utf16Be => decode_utf16be_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        if decoded.is_err() {
            return;
        }

        let decoded = scratch.utf16_buf.as_slice();
        if decoded.is_empty() {
            return;
        }

        scratch.total_decode_output_bytes = scratch
            .total_decode_output_bytes
            .saturating_add(decoded.len());
        if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
            return;
        }

        if let Some(needle) = rule.must_contain {
            if memmem::find(decoded, needle).is_none() {
                return;
            }
        }

        let endianness = match variant {
            Variant::Utf16Le => Utf16Endianness::Le,
            Variant::Utf16Be => Utf16Endianness::Be,
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        let parent_span =
            window_start as usize..window_start.saturating_add(raw_win.len() as u64) as usize;
        let utf16_step_id = scratch.step_arena.push(
            step_id,
            DecodeStep::Utf16Window {
                endianness,
                parent_span: parent_span.clone(),
            },
        );

        let max_findings = scratch.max_findings;
        let out = &mut scratch.tmp_findings;
        let entropy = rule.entropy;
        for rm in rule.re.find_iter(decoded) {
            let span = rm.start()..rm.end();

            if let Some(ent) = entropy {
                let mbytes = &decoded[span.clone()];
                if !entropy_gate_passes(
                    &ent,
                    mbytes,
                    &mut scratch.entropy_scratch,
                    &self.entropy_log2,
                ) {
                    continue;
                }
            }

            *found_any = true;
            let root_span_hint = root_hint.clone().unwrap_or_else(|| parent_span.clone());

            if out.len() < max_findings {
                out.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: span.start as u32,
                    span_end: span.end as u32,
                    root_hint_start: base_offset + root_span_hint.start as u64,
                    root_hint_end: base_offset + root_span_hint.end as u64,
                    step_id: utf16_step_id,
                });
            } else {
                *dropped = dropped.saturating_add(1);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_span_fallback(
        &self,
        tc: &TransformConfig,
        transform_idx: usize,
        enc: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        if enc.len() < tc.min_len {
            return;
        }

        if tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded {
            if let Some(gate) = &self.b64_gate {
                if !gate.hits(enc) {
                    return;
                }
            }
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);

        let decoded_range = match scratch.slab.append_stream_decode(
            tc,
            enc,
            max_out,
            &mut scratch.total_decode_output_bytes,
            self.tuning.max_total_decode_output_bytes,
        ) {
            Ok(r) => r,
            Err(_) => return,
        };

        let decoded = scratch.slab.slice(decoded_range.clone());
        if decoded.is_empty() {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        let h = hash128(decoded);
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(decoded_range.start);
            return;
        }

        scratch.work_q.push(WorkItem::ScanBuf {
            buf: BufRef::Slab(decoded_range),
            step_id,
            root_hint,
            depth,
        });
        scratch.work_items_enqueued = scratch.work_items_enqueued.saturating_add(1);

        let _ = (base_offset, file_id, transform_idx);
    }

    fn redecode_window_into(
        &self,
        tc: &TransformConfig,
        encoded: &[u8],
        lo: u64,
        hi: u64,
        max_out: usize,
        out: &mut Vec<u8>,
    ) -> bool {
        if hi <= lo {
            return true;
        }
        let needed = match usize::try_from(hi.saturating_sub(lo)) {
            Ok(n) => n,
            Err(_) => return false,
        };
        out.clear();
        if needed > 0 {
            out.reserve(needed);
        }

        let mut decoded_offset: u64 = 0;
        let mut local_out = 0usize;
        let mut truncated = false;

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            local_out = local_out.saturating_add(chunk.len());

            let chunk_start = decoded_offset;
            let chunk_end = decoded_offset.saturating_add(chunk.len() as u64);
            if chunk_end > lo && chunk_start < hi {
                let copy_start = lo.saturating_sub(chunk_start) as usize;
                let copy_end = hi.min(chunk_end).saturating_sub(chunk_start) as usize;
                out.extend_from_slice(&chunk[copy_start..copy_end]);
            }
            decoded_offset = chunk_end;
            if decoded_offset >= hi {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });

        if res.is_err() || truncated {
            return false;
        }
        out.len() == needed
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_stream_and_scan(
        &self,
        vs_stream: &VsStreamDb,
        tc: &TransformConfig,
        transform_idx: usize,
        encoded: &[u8],
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        depth: usize,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        for idx in scratch.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = scratch.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }

        if encoded.is_empty() {
            return;
        }

        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }
        let max_out = tc.max_decoded_bytes.min(remaining);
        if max_out == 0 {
            return;
        }

        let total_decode_start = scratch.total_decode_output_bytes;
        let mut force_full = false;
        let gate_enabled = tc.gate == Gate::AnchorsInDecoded;
        let mut gate_hit: u8 = 0;
        let mut gate_db_active = false;
        let mut gate_db_failed = false;
        let mut gate_stream: Option<VsStream> = None;
        let mut gate_scratch: Option<VsScratch> = None;
        let gate_cb = gate_match_callback();

        #[cfg(feature = "b64-stats")]
        let is_b64_gate = tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded;

        scratch.decode_ring.reset();
        scratch.window_bytes.clear();
        scratch.pending_windows.clear();
        scratch.vs_stream_matches.clear();
        scratch.pending_spans.clear();
        scratch.span_streams.clear();
        scratch.tmp_findings.clear();

        let mut local_out = 0usize;
        let mut truncated = false;
        let mut prefilter_gate_hit = false;
        let mut found_any = false;
        let mut local_dropped = 0usize;

        if gate_enabled {
            if let Some(db) = self.vs_gate.as_ref() {
                let mut vs_gate_scratch = match scratch.vs_gate_scratch.take() {
                    Some(s) => Some(s),
                    None => db.alloc_scratch().ok(),
                };
                if let Some(vs_gate_scratch) = vs_gate_scratch.take() {
                    match db.open_stream() {
                        Ok(stream) => {
                            gate_db_active = true;
                            gate_stream = Some(stream);
                            gate_scratch = Some(vs_gate_scratch);
                        }
                        Err(_) => {
                            scratch.vs_gate_scratch = Some(vs_gate_scratch);
                        }
                    }
                }
            }
        }

        let slab_start = scratch.slab.buf.len();
        let want_utf16_scan = self.tuning.scan_utf16_variants && self.has_utf16_anchors;
        let use_utf16_stream = want_utf16_scan && self.vs_utf16_stream.is_some();
        let decoded_full_start = slab_start;
        let mut decoded_full_len = 0usize;
        let mut decoded_has_nul = false;
        let mut utf16_stream: Option<VsStream> = None;
        let mut utf16_stream_scratch: Option<VsScratch> = None;
        let mut utf16_stream_ctx: Option<VsUtf16StreamMatchCtx> = None;
        let utf16_stream_cb = utf16_stream_match_callback();

        let process_window = |win: PendingWindow,
                              hi: u64,
                              scratch: &mut ScanScratch,
                              found_any: &mut bool,
                              local_dropped: &mut usize,
                              force_full: &mut bool| {
            if *force_full {
                return;
            }
            let lo = win.lo;
            if hi <= lo {
                return;
            }
            scratch.window_bytes.clear();
            if !scratch
                .decode_ring
                .extend_range_to(lo, hi, &mut scratch.window_bytes)
                && !self.redecode_window_into(
                    tc,
                    encoded,
                    lo,
                    hi,
                    max_out,
                    &mut scratch.window_bytes,
                )
            {
                *force_full = true;
                return;
            }
            let (bytes_ptr, bytes_len) = {
                let bytes = &scratch.window_bytes;
                (bytes.as_ptr(), bytes.len())
            };
            // SAFETY: `bytes_ptr` comes from `scratch.window_bytes`. We materialize the slice
            // from a raw pointer to avoid borrowing `scratch` across calls that mutate other
            // scratch fields. `window_bytes` is not mutated until after this slice is consumed.
            let bytes = unsafe { std::slice::from_raw_parts(bytes_ptr, bytes_len) };
            let rule = &self.rules[win.rule_id as usize];
            match win.variant {
                Variant::Raw => {
                    self.run_rule_on_raw_window_into(
                        win.rule_id,
                        rule,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        local_dropped,
                        found_any,
                    );
                }
                Variant::Utf16Le | Variant::Utf16Be => {
                    self.run_rule_on_utf16_window_into(
                        win.rule_id,
                        rule,
                        win.variant,
                        bytes,
                        lo,
                        step_id,
                        &root_hint,
                        base_offset,
                        file_id,
                        scratch,
                        local_dropped,
                        found_any,
                    );
                }
            }
        };

        if depth < self.tuning.max_transform_depth {
            for (tidx, tcfg) in self.transforms.iter().enumerate() {
                if tcfg.mode == TransformMode::Disabled {
                    continue;
                }
                let state = match tcfg.id {
                    TransformId::UrlPercent => SpanStreamState::Url(UrlSpanStream::new(tcfg)),
                    TransformId::Base64 => SpanStreamState::Base64(Base64SpanStream::new(tcfg)),
                };
                scratch.span_streams.push(SpanStreamEntry {
                    transform_idx: tidx,
                    mode: tcfg.mode,
                    state,
                    spans_emitted: 0,
                    max_spans: tcfg.max_spans_per_buffer,
                });
            }
        }

        let mut vs_scratch = match scratch.vs_stream_scratch.take() {
            Some(s) => s,
            None => match vs_stream.alloc_scratch() {
                Ok(s) => s,
                Err(_) => return,
            },
        };

        let mut stream = match vs_stream.open_stream() {
            Ok(s) => s,
            Err(_) => {
                scratch.vs_stream_scratch = Some(vs_scratch);
                return;
            }
        };

        let mut ctx = VsStreamMatchCtx {
            pending: &mut scratch.vs_stream_matches as *mut Vec<VsStreamWindow>,
            meta: vs_stream.meta().as_ptr(),
            meta_len: vs_stream.meta().len() as u32,
        };

        let mut decoded_offset: u64 = 0;
        let key = [0u8; 16];
        let mut mac = aegis::aegis128l::Aegis128LMac::<16>::new(&key);

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decode_attempts =
                scratch.base64_stats.decode_attempts.saturating_add(1);
            scratch.base64_stats.decode_attempt_bytes = scratch
                .base64_stats
                .decode_attempt_bytes
                .saturating_add(encoded.len() as u64);
        }

        let res = stream_decode(tc, encoded, |chunk| {
            if local_out.saturating_add(chunk.len()) > max_out {
                truncated = true;
                return ControlFlow::Break(());
            }
            if scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len())
                > self.tuning.max_total_decode_output_bytes
            {
                truncated = true;
                return ControlFlow::Break(());
            }

            if want_utf16_scan && !use_utf16_stream {
                if scratch.slab.buf.len().saturating_add(chunk.len()) > scratch.slab.limit {
                    truncated = true;
                    return ControlFlow::Break(());
                }
                scratch.slab.buf.extend_from_slice(chunk);
                decoded_full_len = decoded_full_len.saturating_add(chunk.len());
                if !decoded_has_nul && memchr(0, chunk).is_some() {
                    decoded_has_nul = true;
                }
            }

            local_out = local_out.saturating_add(chunk.len());
            scratch.total_decode_output_bytes = scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len());

            mac.update(chunk);
            scratch.decode_ring.push(chunk);

            if vs_stream
                .scan_stream(
                    &mut stream,
                    chunk,
                    &mut vs_scratch,
                    stream_match_callback(),
                    (&mut ctx as *mut VsStreamMatchCtx).cast(),
                )
                .is_err()
            {
                truncated = true;
                return ControlFlow::Break(());
            }

            if gate_db_active && gate_hit == 0 {
                if let (Some(db), Some(gstream), Some(gscratch)) = (
                    self.vs_gate.as_ref(),
                    gate_stream.as_mut(),
                    gate_scratch.as_mut(),
                ) {
                    if db
                        .scan_stream(
                            gstream,
                            chunk,
                            gscratch,
                            gate_cb,
                            (&mut gate_hit as *mut u8).cast(),
                        )
                        .is_err()
                    {
                        gate_db_active = false;
                        gate_db_failed = true;
                    }
                }
            }

            if use_utf16_stream {
                if let Some(db) = self.vs_utf16_stream.as_ref() {
                    let mut scanned_chunk = false;
                    if utf16_stream.is_none() && memchr(0, chunk).is_some() {
                        let mut vs_utf16_scratch = match scratch.vs_utf16_stream_scratch.take() {
                            Some(s) => s,
                            None => match db.alloc_scratch() {
                                Ok(s) => s,
                                Err(_) => {
                                    truncated = true;
                                    return ControlFlow::Break(());
                                }
                            },
                        };
                        let mut ustream = match db.open_stream() {
                            Ok(s) => s,
                            Err(_) => {
                                scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                        };
                        let base_offset = scratch.decode_ring.start_offset();
                        let mut uctx = VsUtf16StreamMatchCtx {
                            pending: &mut scratch.vs_stream_matches as *mut Vec<VsStreamWindow>,
                            targets: db.targets().as_ptr(),
                            pat_offsets: db.pat_offsets().as_ptr(),
                            pat_lens: db.pat_lens().as_ptr(),
                            pat_count: db.pat_lens().len() as u32,
                            base_offset,
                        };
                        let (seg1, seg2) = scratch.decode_ring.segments();
                        if !seg1.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg1,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        if !seg2.is_empty()
                            && db
                                .scan_stream(
                                    &mut ustream,
                                    seg2,
                                    &mut vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                        {
                            truncated = true;
                            return ControlFlow::Break(());
                        }
                        utf16_stream = Some(ustream);
                        utf16_stream_scratch = Some(vs_utf16_scratch);
                        utf16_stream_ctx = Some(uctx);
                        scanned_chunk = true;
                    }

                    if !scanned_chunk {
                        if let (Some(ustream), Some(vs_utf16_scratch), Some(uctx)) = (
                            utf16_stream.as_mut(),
                            utf16_stream_scratch.as_mut(),
                            utf16_stream_ctx.as_mut(),
                        ) {
                            if db
                                .scan_stream(
                                    ustream,
                                    chunk,
                                    vs_utf16_scratch,
                                    utf16_stream_cb,
                                    (uctx as *mut VsUtf16StreamMatchCtx).cast(),
                                )
                                .is_err()
                            {
                                truncated = true;
                                return ControlFlow::Break(());
                            }
                        }
                    }
                }
            }

            if !scratch.vs_stream_matches.is_empty() {
                let max_hits = self.tuning.max_windows_per_rule_variant as u32;
                for win in scratch.vs_stream_matches.drain(..) {
                    if win.force_full {
                        force_full = true;
                        break;
                    }
                    let variant = match Variant::from_idx(win.variant_idx) {
                        Some(v) => v,
                        None => continue,
                    };
                    if variant == Variant::Raw {
                        prefilter_gate_hit = true;
                    }
                    let idx = win.rule_id as usize * 3 + variant.idx();
                    let hit = &mut scratch.stream_hit_counts[idx];
                    if *hit == 0 {
                        scratch.stream_hit_touched.push(idx as u32);
                    }
                    *hit = hit.saturating_add(1);
                    if *hit > max_hits {
                        #[cfg(feature = "stats")]
                        self.vs_stats
                            .stream_window_cap_exceeded
                            .fetch_add(1, Ordering::Relaxed);
                        force_full = true;
                        break;
                    }
                    scratch.pending_windows.push(PendingWindow {
                        hi: win.hi,
                        lo: win.lo,
                        rule_id: win.rule_id,
                        variant,
                    });
                }
                if force_full {
                    return ControlFlow::Break(());
                }
            }

            decoded_offset = decoded_offset.saturating_add(chunk.len() as u64);

            loop {
                let hi = match scratch.pending_windows.peek() {
                    Some(top) if top.hi <= decoded_offset => top.hi,
                    _ => break,
                };
                let win = scratch.pending_windows.pop().expect("pending window");
                process_window(
                    win,
                    hi,
                    scratch,
                    &mut found_any,
                    &mut local_dropped,
                    &mut force_full,
                );
                if force_full {
                    return ControlFlow::Break(());
                }
            }

            let chunk_start = decoded_offset.saturating_sub(chunk.len() as u64);
            if depth < self.tuning.max_transform_depth {
                for entry in scratch.span_streams.iter_mut() {
                    if entry.spans_emitted >= entry.max_spans {
                        continue;
                    }
                    let tcfg = &self.transforms[entry.transform_idx];
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            force_full = true;
                            return false;
                        }

                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let range = span_start..scratch.slab.buf.len();

                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }

                        let parent_span = lo as usize..hi as usize;
                        let child_step_id = scratch.step_arena.push(
                            step_id,
                            DecodeStep::Transform {
                                transform_idx: entry.transform_idx,
                                parent_span: parent_span.clone(),
                            },
                        );
                        let child_root_hint = root_hint.clone().unwrap_or(parent_span);

                        scratch.pending_spans.push(PendingDecodeSpan {
                            transform_idx: entry.transform_idx,
                            range,
                            step_id: child_step_id,
                            root_hint: Some(child_root_hint),
                            depth: depth + 1,
                        });
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.feed(chunk, chunk_start, &mut on_span),
                        SpanStreamState::Base64(state) => {
                            state.feed(chunk, chunk_start, &mut on_span)
                        }
                    }
                    if force_full {
                        return ControlFlow::Break(());
                    }
                }
            }

            ControlFlow::Continue(())
        });

        let _ = vs_stream.close_stream(
            stream,
            &mut vs_scratch,
            stream_match_callback(),
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        );
        scratch.vs_stream_scratch = Some(vs_scratch);

        if let Some(db) = self.vs_gate.as_ref() {
            if let (Some(gstream), Some(mut gscratch)) = (gate_stream.take(), gate_scratch.take()) {
                let _ = db.close_stream(
                    gstream,
                    &mut gscratch,
                    gate_cb,
                    (&mut gate_hit as *mut u8).cast(),
                );
                gate_scratch = Some(gscratch);
            }
        }
        if let Some(gscratch) = gate_scratch.take() {
            scratch.vs_gate_scratch = Some(gscratch);
        }

        if let Some(db) = self.vs_utf16_stream.as_ref() {
            if let (Some(ustream), Some(mut vs_utf16_scratch), Some(mut uctx)) = (
                utf16_stream.take(),
                utf16_stream_scratch.take(),
                utf16_stream_ctx.take(),
            ) {
                let _ = db.close_stream(
                    ustream,
                    &mut vs_utf16_scratch,
                    utf16_stream_cb,
                    (&mut uctx as *mut VsUtf16StreamMatchCtx).cast(),
                );
                utf16_stream_scratch = Some(vs_utf16_scratch);
            }
        }
        if let Some(vs_utf16_scratch) = utf16_stream_scratch.take() {
            scratch.vs_utf16_stream_scratch = Some(vs_utf16_scratch);
        }

        if force_full {
            #[cfg(feature = "stats")]
            self.vs_stats
                .stream_force_full
                .fetch_add(1, Ordering::Relaxed);
            scratch.slab.buf.truncate(slab_start);
            scratch.total_decode_output_bytes = total_decode_start;
            scratch.pending_windows.clear();
            scratch.vs_stream_matches.clear();
            scratch.pending_spans.clear();
            scratch.span_streams.clear();
            scratch.tmp_findings.clear();
            self.decode_span_fallback(
                tc,
                transform_idx,
                encoded,
                step_id,
                root_hint,
                depth,
                base_offset,
                file_id,
                scratch,
            );
            return;
        }

        if res.is_ok() {
            if !scratch.vs_stream_matches.is_empty() {
                let max_hits = self.tuning.max_windows_per_rule_variant as u32;
                for win in scratch.vs_stream_matches.drain(..) {
                    if win.force_full {
                        force_full = true;
                        break;
                    }
                    let variant = match Variant::from_idx(win.variant_idx) {
                        Some(v) => v,
                        None => continue,
                    };
                    if variant == Variant::Raw {
                        prefilter_gate_hit = true;
                    }
                    let idx = win.rule_id as usize * 3 + variant.idx();
                    let hit = &mut scratch.stream_hit_counts[idx];
                    if *hit == 0 {
                        scratch.stream_hit_touched.push(idx as u32);
                    }
                    *hit = hit.saturating_add(1);
                    if *hit > max_hits {
                        force_full = true;
                        break;
                    }
                    scratch.pending_windows.push(PendingWindow {
                        hi: win.hi,
                        lo: win.lo,
                        rule_id: win.rule_id,
                        variant,
                    });
                }
                if force_full {
                    scratch.vs_stream_matches.clear();
                }
            }
            if !force_full {
                for entry in scratch.span_streams.iter_mut() {
                    let end_offset = decoded_offset;
                    let mut on_span = |lo: u64, hi: u64| -> bool {
                        if entry.spans_emitted >= entry.max_spans {
                            return false;
                        }
                        if scratch.work_items_enqueued + scratch.pending_spans.len()
                            >= self.tuning.max_work_items
                        {
                            return false;
                        }
                        if hi <= lo {
                            return true;
                        }
                        if !scratch.decode_ring.has_range(lo, hi) {
                            force_full = true;
                            return false;
                        }
                        let span_start = scratch.slab.buf.len();
                        if !scratch
                            .decode_ring
                            .extend_range_to(lo, hi, &mut scratch.slab.buf)
                        {
                            scratch.slab.buf.truncate(span_start);
                            force_full = true;
                            return false;
                        }
                        let range = span_start..scratch.slab.buf.len();
                        let tcfg = &self.transforms[entry.transform_idx];
                        if tcfg.id == TransformId::Base64 && tcfg.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                if !gate.hits(&scratch.slab.buf[range.clone()]) {
                                    scratch.slab.buf.truncate(span_start);
                                    return true;
                                }
                            }
                        }
                        let parent_span = lo as usize..hi as usize;
                        let child_step_id = scratch.step_arena.push(
                            step_id,
                            DecodeStep::Transform {
                                transform_idx: entry.transform_idx,
                                parent_span: parent_span.clone(),
                            },
                        );
                        let child_root_hint = root_hint.clone().unwrap_or(parent_span);
                        scratch.pending_spans.push(PendingDecodeSpan {
                            transform_idx: entry.transform_idx,
                            range,
                            step_id: child_step_id,
                            root_hint: Some(child_root_hint),
                            depth: depth + 1,
                        });
                        entry.spans_emitted = entry.spans_emitted.saturating_add(1);
                        true
                    };

                    match &mut entry.state {
                        SpanStreamState::Url(state) => state.finish(end_offset, &mut on_span),
                        SpanStreamState::Base64(state) => state.finish(end_offset, &mut on_span),
                    }
                    if force_full {
                        break;
                    }
                }
            }
        }

        if res.is_ok() && !force_full {
            let final_offset = decoded_offset;
            while let Some(win) = scratch.pending_windows.pop() {
                let hi = win.hi.min(final_offset);
                process_window(
                    win,
                    hi,
                    scratch,
                    &mut found_any,
                    &mut local_dropped,
                    &mut force_full,
                );
                if force_full {
                    break;
                }
            }
        }

        if force_full {
            scratch.slab.buf.truncate(slab_start);
            scratch.total_decode_output_bytes = total_decode_start;
            scratch.pending_windows.clear();
            scratch.vs_stream_matches.clear();
            scratch.pending_spans.clear();
            scratch.span_streams.clear();
            scratch.tmp_findings.clear();
            self.decode_span_fallback(
                tc,
                transform_idx,
                encoded,
                step_id,
                root_hint,
                depth,
                base_offset,
                file_id,
                scratch,
            );
            return;
        }

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decode_errors =
                    scratch.base64_stats.decode_errors.saturating_add(1);
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_error = scratch
                    .base64_stats
                    .decoded_bytes_wasted_error
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        if want_utf16_scan && !use_utf16_stream && decoded_has_nul && decoded_full_len > 0 {
            if let Some(vs_utf16) = self.vs_utf16.as_ref() {
                if let Some(mut vs_utf16_scratch) = scratch.vs_utf16_scratch.take() {
                    #[cfg(feature = "stats")]
                    self.vs_stats
                        .utf16_scans_attempted
                        .fetch_add(1, Ordering::Relaxed);

                    scratch.touched.clear();
                    scratch.touched_pairs.clear();
                    scratch.touched_any = false;

                    let decoded_end = decoded_full_start.saturating_add(decoded_full_len);
                    let (decoded_ptr, decoded_len) = {
                        let decoded = &scratch.slab.buf[decoded_full_start..decoded_end];
                        (decoded.as_ptr(), decoded.len())
                    };
                    // SAFETY: `decoded_ptr` points to a slab range appended above. The slab does
                    // not reallocate during this scan, and we do not mutate the slab while
                    // `decoded` is in use.
                    let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
                    let result = vs_utf16.scan_utf16(decoded, scratch, &mut vs_utf16_scratch);
                    scratch.vs_utf16_scratch = Some(vs_utf16_scratch);

                    let used_vectorscan_utf16 = result.is_ok();
                    match result {
                        Ok(()) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats.utf16_scans_ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            #[cfg(feature = "stats")]
                            self.vs_stats
                                .utf16_scans_err
                                .fetch_add(1, Ordering::Relaxed);

                            if scratch.touched_any {
                                scratch.touched_pairs.clear();
                                for pair in scratch.touched.iter_set() {
                                    scratch.touched_pairs.push(pair as u32);
                                }
                                scratch.touched.clear();
                                scratch.touched_any = false;
                                let touched_len = scratch.touched_pairs.len();
                                for i in 0..touched_len {
                                    let pair = scratch.touched_pairs[i] as usize;
                                    let rid = pair / 3;
                                    let vidx = pair % 3;
                                    scratch.accs[rid][vidx].reset();
                                }
                                scratch.touched_pairs.clear();
                            }
                            // Skip UTF-16 scan on error.
                        }
                    }

                    if scratch.touched_any {
                        const VARIANTS: [Variant; 3] =
                            [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be];
                        scratch.touched_pairs.clear();
                        for pair in scratch.touched.iter_set() {
                            scratch.touched_pairs.push(pair as u32);
                        }
                        scratch.touched.clear();
                        scratch.touched_any = false;
                        let touched_len = scratch.touched_pairs.len();
                        let hay_len = decoded_len as u32;
                        let merge_gap = self.tuning.merge_gap as u32;
                        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

                        for i in 0..touched_len {
                            let pair = scratch.touched_pairs[i] as usize;
                            let rid = pair / 3;
                            let vidx = pair % 3;
                            let variant = VARIANTS[vidx];
                            if variant == Variant::Raw {
                                continue;
                            }
                            let rule = &self.rules[rid];

                            {
                                let acc = &mut scratch.accs[rid][vidx];
                                acc.take_into(&mut scratch.windows);
                            }
                            if scratch.windows.is_empty() {
                                continue;
                            }

                            if used_vectorscan_utf16 && scratch.windows.len() > 1 {
                                scratch
                                    .windows
                                    .as_mut_slice()
                                    .sort_unstable_by_key(|s| s.start);
                            }

                            merge_ranges_with_gap_sorted(&mut scratch.windows, merge_gap);
                            coalesce_under_pressure_sorted(
                                &mut scratch.windows,
                                hay_len,
                                pressure_gap_start,
                                self.tuning.max_windows_per_rule_variant,
                            );

                            if let Some(tp) = &rule.two_phase {
                                let seed_radius_bytes =
                                    tp.seed_radius.saturating_mul(variant.scale());
                                let full_radius_bytes =
                                    tp.full_radius.saturating_mul(variant.scale());
                                let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

                                scratch.expanded.clear();
                                let windows_len = scratch.windows.len();
                                for i in 0..windows_len {
                                    let seed = scratch.windows[i];
                                    let seed_range = seed.to_range();
                                    let win = &decoded[seed_range.clone()];
                                    if !contains_any_memmem(win, &tp.confirm[vidx]) {
                                        continue;
                                    }

                                    let lo = seed_range.start.saturating_sub(extra);
                                    let hi = (seed_range.end + extra).min(decoded.len());
                                    scratch.expanded.push(SpanU32::new(lo, hi));
                                }

                                if scratch.expanded.is_empty() {
                                    continue;
                                }

                                merge_ranges_with_gap_sorted(&mut scratch.expanded, merge_gap);
                                coalesce_under_pressure_sorted(
                                    &mut scratch.expanded,
                                    hay_len,
                                    pressure_gap_start,
                                    self.tuning.max_windows_per_rule_variant,
                                );

                                let expanded_len = scratch.expanded.len();
                                for i in 0..expanded_len {
                                    let w = scratch.expanded[i].to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut local_dropped,
                                        &mut found_any,
                                    );
                                }
                            } else {
                                let win_len = scratch.windows.len();
                                for i in 0..win_len {
                                    let w = scratch.windows[i].to_range();
                                    let win = &decoded[w.clone()];
                                    self.run_rule_on_utf16_window_into(
                                        rid as u32,
                                        rule,
                                        variant,
                                        win,
                                        w.start as u64,
                                        step_id,
                                        &root_hint,
                                        base_offset,
                                        file_id,
                                        scratch,
                                        &mut local_dropped,
                                        &mut found_any,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let gate_satisfied = if gate_db_active || gate_hit != 0 {
            gate_hit != 0
        } else {
            prefilter_gate_hit
        };
        let enforce_gate = if gate_enabled {
            if gate_db_failed {
                false
            } else if gate_db_active || gate_hit != 0 {
                true
            } else {
                !self.tuning.scan_utf16_variants || !self.has_utf16_anchors
            }
        } else {
            false
        };
        if enforce_gate && !gate_satisfied {
            #[cfg(feature = "b64-stats")]
            if is_b64_gate {
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_no_anchor = scratch
                    .base64_stats
                    .decoded_bytes_wasted_no_anchor
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        #[cfg(feature = "b64-stats")]
        if is_b64_gate {
            scratch.base64_stats.decoded_bytes_total = scratch
                .base64_stats
                .decoded_bytes_total
                .saturating_add(local_out as u64);
            scratch.base64_stats.decoded_bytes_kept = scratch
                .base64_stats
                .decoded_bytes_kept
                .saturating_add(local_out as u64);
        }

        let h = u128::from_le_bytes(mac.finalize());
        if !scratch.seen.insert(h) {
            scratch.slab.buf.truncate(slab_start);
            return;
        }

        if local_dropped > 0 {
            scratch.findings_dropped = scratch.findings_dropped.saturating_add(local_dropped);
        }
        let mut tmp_findings = std::mem::take(&mut scratch.tmp_findings);
        for rec in tmp_findings.drain(..) {
            scratch.push_finding(rec);
        }
        scratch.tmp_findings = tmp_findings;

        let found_any_in_buf = found_any;
        let mut enqueued = 0usize;
        for pending in scratch.pending_spans.drain(..) {
            let mode = self.transforms[pending.transform_idx].mode;
            if mode == TransformMode::IfNoFindingsInThisBuffer && found_any_in_buf {
                continue;
            }
            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                break;
            }
            scratch.work_q.push(WorkItem::DecodeSpan {
                transform_idx: pending.transform_idx,
                enc_ref: EncRef::Slab(pending.range),
                step_id: pending.step_id,
                root_hint: pending.root_hint,
                depth: pending.depth,
            });
            scratch.work_items_enqueued += 1;
            enqueued += 1;
        }

        let _ = enqueued;
        let _ = (transform_idx, base_offset, file_id);
    }
}
// --------------------------
// Compile helpers
// --------------------------

fn compile_rule(spec: &RuleSpec) -> RuleCompiled {
    let two_phase = spec.two_phase.as_ref().map(|tp| {
        let count = tp.confirm_any.len();
        let raw_bytes = tp.confirm_any.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);
        let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
        let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
        let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

        for &p in tp.confirm_any {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        TwoPhaseCompiled {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm: [raw, le, be],
        }
    });

    let keywords = spec.keywords_any.map(|kws| {
        let count = kws.len();
        let raw_bytes = kws.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);

        let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
        let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
        let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

        for &p in kws {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        KeywordsCompiled { any: [raw, le, be] }
    });

    let entropy = spec.entropy.as_ref().map(|e| EntropyCompiled {
        min_bits_per_byte: e.min_bits_per_byte,
        min_len: e.min_len,
        max_len: e.max_len,
    });

    RuleCompiled {
        name: spec.name,
        radius: spec.radius,
        validator: spec.validator,
        must_contain: spec.must_contain,
        confirm_all: None,
        keywords,
        entropy,
        re: spec.re.clone(),
        two_phase,
    }
}

fn compile_confirm_all(mut confirm_all: Vec<Vec<u8>>) -> Option<ConfirmAllCompiled> {
    if confirm_all.is_empty() {
        return None;
    }

    // Sort longest-first so the primary literal is maximally selective.
    confirm_all.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let primary = confirm_all.remove(0);
    let primary_raw = Some(primary.clone());
    let primary_le = Some(utf16le_bytes(&primary));
    let primary_be = Some(utf16be_bytes(&primary));

    let count = confirm_all.len();
    let raw_bytes = confirm_all.iter().map(|p| p.len()).sum::<usize>();
    let utf16_bytes = raw_bytes.saturating_mul(2);
    let mut raw = PackedPatterns::with_capacity(count, raw_bytes);
    let mut le = PackedPatterns::with_capacity(count, utf16_bytes);
    let mut be = PackedPatterns::with_capacity(count, utf16_bytes);

    for p in confirm_all {
        raw.push_raw(&p);
        le.push_utf16le(&p);
        be.push_utf16be(&p);
    }

    Some(ConfirmAllCompiled {
        primary: [primary_raw, primary_le, primary_be],
        rest: [raw, le, be],
    })
}

fn add_pat_raw(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: &[u8], target: Target) {
    if let Some(existing) = map.get_mut(pat) {
        existing.push(target);
    } else {
        map.insert(pat.to_vec(), vec![target]);
    }
}

fn add_pat_owned(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: Vec<u8>, target: Target) {
    if let Some(existing) = map.get_mut(pat.as_slice()) {
        existing.push(target);
    } else {
        map.insert(pat, vec![target]);
    }
}

fn map_to_patterns(map: AHashMap<Vec<u8>, Vec<Target>>) -> (Vec<Vec<u8>>, Vec<Target>, Vec<u32>) {
    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(map.len());
    let mut flat: Vec<Target> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(map.len().saturating_add(1));
    offsets.push(0);

    let mut total_targets = 0usize;
    for ts in map.values() {
        total_targets = total_targets.saturating_add(ts.len());
    }
    flat.reserve(total_targets);

    for (p, ts) in map {
        patterns.push(p);
        flat.extend(ts);
        assert!(flat.len() <= u32::MAX as usize);
        // Prefix-sum offsets: each pattern id maps to flat[start..end].
        offsets.push(flat.len() as u32);
    }

    (patterns, flat, offsets)
}

/// Benchmark helper to expose span detection for transform configs.
#[cfg(feature = "bench")]
pub fn bench_find_spans_into(tc: &TransformConfig, buf: &[u8], out: &mut Vec<Range<usize>>) {
    find_spans_into(tc, buf, out);
}

#[cfg(feature = "bench")]
pub use self::transform::{bench_stream_decode_base64, bench_stream_decode_url};

#[cfg(feature = "bench")]
pub use self::validator::{
    bench_is_word_byte, bench_tail_matches_charset, bench_validate_aws_access_key,
    bench_validate_prefix_bounded, bench_validate_prefix_fixed,
};

#[cfg(feature = "bench")]
impl Engine {}

#[cfg(test)]
mod tests;
