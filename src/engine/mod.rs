use crate::api::*;
use crate::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, PaddingPolicy, WhitespacePolicy};
use crate::regex2anchor::{
    compile_trigger_plan, AnchorDeriveConfig, ResidueGatePlan, TriggerPlan, UnfilterableReason,
};
use crate::scratch_memory::ScratchVec;
use crate::stdx::{DynamicBitSet, FixedSet128};
use ahash::AHashMap;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind};
use memchr::{memchr, memmem};
use regex::bytes::Regex;
use std::ops::{ControlFlow, Range};

mod helpers;
mod transform;
mod validator;

use self::helpers::*;
use self::transform::*;

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
/// Anchor patterns are deduped in the Aho-Corasick automaton. Each pattern id
/// can fan out to multiple rules and variants; `pat_offsets` slices into the
/// flat `pat_targets` array. A `Target` is a compact (rule_id, variant) pair
/// packed into `u32` to keep the fanout table cache-friendly and avoid extra
/// pointer chasing.
///
/// Flags encoded in the low bits record whether the anchor is match-start
/// aligned (required by fast validators) and whether keyword gates are implied
/// by this specific anchor (so the validator can remain authoritative).
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

/// Anchor automaton plus pattern->target fanout table.
///
/// The Aho-Corasick automaton yields pattern ids. `pat_offsets` slices into
/// `pat_targets` so each pattern id can fan out to multiple (rule, variant)
/// targets without per-pattern allocations.
struct AnchorIndex {
    ac: AhoCorasick,
    pat_targets: Vec<Target>,
    pat_offsets: Vec<u32>,
}

/// Anchor indexes used to select between raw-only and combined scans.
///
/// Invariant: every UTF-16 pattern contains at least one NUL byte, so a NUL-free
/// slice cannot match UTF-16LE/BE variants. This allows a fast raw-only path
/// for NUL-free buffers and a single-pass combined scan for NUL-heavy buffers.
struct Anchors {
    raw: AnchorIndex,
    all: AnchorIndex,
}

impl Anchors {
    #[inline]
    fn select(&self, hay: &[u8], scan_utf16_variants: bool) -> &AnchorIndex {
        if !scan_utf16_variants || memchr(0, hay).is_none() {
            &self.raw
        } else {
            &self.all
        }
    }
}

/// Packed byte patterns with an offset table.
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm-any patterns contiguous for cache-friendly memmem checks.
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

#[derive(Clone, Copy, Debug)]
struct EntropyCompiled {
    // Prevalidated config stored in compiled rules to avoid repeated lookups.
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
    keywords: Option<KeywordsCompiled>,
    entropy: Option<EntropyCompiled>,
    re: Regex,
    two_phase: Option<TwoPhaseCompiled>,
}

/// Compact span used in hot paths.
///
/// Uses `u32` offsets to reduce memory footprint and improve cache density.
/// Valid only for buffers whose length fits in `u32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpanU32 {
    start: u32,
    end: u32,
}

impl SpanU32 {
    fn new(start: usize, end: usize) -> Self {
        assert!(start <= end);
        assert!(start <= u32::MAX as usize);
        assert!(end <= u32::MAX as usize);
        Self {
            start: start as u32,
            end: end as u32,
        }
    }

    fn to_range(self) -> Range<usize> {
        self.start as usize..self.end as usize
    }
}

/// Accumulates anchor hit windows with optional coalesced fallback.
///
/// When hit counts exceed configured limits, this switches to a single merged
/// window to cap memory growth.
/// Accumulates raw anchor hit windows for a single (rule, variant).
///
/// This starts as a simple append-only list of windows. If the number of hits
/// exceeds a configured cap, it switches to a single "coalesced" window that
/// covers the union of all hits seen so far. That fallback is deliberately
/// conservative: it may make the window larger than necessary, but it prevents
/// unbounded memory growth and guarantees we still scan any true matches.
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
        assert!(max_hits > 0, "max_hits must be > 0");
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

/// Scratch buffers used by the streaming gate to detect anchors across boundaries.
///
/// `tail` preserves a small suffix of the prior chunk, and `scratch` holds the
/// current decode window so we can test anchors without full decoding.
///
/// The tail length is `max_anchor_pat_len - 1`, which is the minimum overlap
/// required to avoid missing an anchor that straddles two decode chunks.
struct GateScratch {
    /// Preserved suffix from prior decode chunk.
    ///
    /// Length is `max_anchor_pat_len - 1` to ensure any anchor straddling
    /// chunk boundaries is detected.
    tail: ScratchVec<u8>,

    /// Current decode window under gate evaluation.
    ///
    /// Sized to hold `tail` plus one decode chunk (1024 bytes), ensuring
    /// the sliding window never requires reallocation.
    scratch: ScratchVec<u8>,
}

impl GateScratch {
    fn reset(&mut self) {
        self.tail.clear();
        self.scratch.clear();
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
/// accumulation, decode slabs, and work queues. It is not thread-safe and should
/// be used by a single worker at a time.
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
    accs: Vec<[HitAccumulator; 3]>,   // Per (rule, variant) hit accumulators.
    touched_pairs: ScratchVec<u32>,   // Scratch list of touched pairs.
    touched: DynamicBitSet,           // Bitset for touched pairs.
    touched_any: bool,                // Fast path for "none touched".
    windows: ScratchVec<SpanU32>,     // Merged windows for a pair.
    expanded: ScratchVec<SpanU32>,    // Expanded windows for two-phase rules.
    spans: ScratchVec<SpanU32>,       // Transform span candidates.
    /// Streaming gate scratch buffers.
    ///
    /// Used by the base64 decoded-content gate to maintain a sliding window
    /// across chunk boundaries. `tail` preserves the suffix of the prior decode
    /// chunk; `scratch` holds the current window being checked.
    gate: GateScratch,
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
        let tail_keep = engine.max_anchor_pat_len.saturating_sub(1);
        let seen_cap = pow2_at_least(
            engine
                .tuning
                .max_work_items
                .next_power_of_two()
                .saturating_mul(2)
                .max(1024),
        );

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
            gate: GateScratch {
                tail: ScratchVec::with_capacity(tail_keep)
                    .expect("scratch gate.tail allocation failed"),
                scratch: ScratchVec::with_capacity(tail_keep.saturating_add(1024))
                    .expect("scratch gate.scratch allocation failed"),
            },
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
            #[cfg(feature = "b64-stats")]
            base64_stats: Base64DecodeStats::default(),
        }
    }

    /// Clears per-scan state and revalidates scratch capacities against the engine.
    fn reset_for_scan(&mut self, engine: &Engine) {
        self.out.clear();
        self.findings_dropped = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.gate.reset();
        self.step_arena.reset();
        self.utf16_buf.clear();
        self.entropy_scratch.reset();
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();
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
        let tail_keep = engine.max_anchor_pat_len.saturating_sub(1);
        if self.gate.tail.capacity() < tail_keep {
            self.gate.tail =
                ScratchVec::with_capacity(tail_keep).expect("scratch gate.tail allocation failed");
        }
        let gate_scratch_cap = tail_keep.saturating_add(1024);
        if self.gate.scratch.capacity() < gate_scratch_cap {
            self.gate.scratch = ScratchVec::with_capacity(gate_scratch_cap)
                .expect("scratch gate.scratch allocation failed");
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

    /// Drops findings that are fully contained in a chunk prefix.
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
    pub fn findings(&self) -> &[FindingRec] {
        self.out.as_slice()
    }

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
#[derive(Default)]
enum BufRef {
    #[default]
    Root,
    Slab(Range<usize>),
}

/// Work item in the transform/scan queue.
///
/// Carries the decode provenance (StepId) and a root-span hint for reporting.
/// Depth enforces the transform recursion limit.
#[derive(Default)]
struct WorkItem {
    buf: BufRef,
    step_id: StepId,
    root_hint: Option<Range<usize>>, // None for root buffer; Some for derived buffers
    depth: usize,
}

// --------------------------
// Engine
// --------------------------

/// Compiled scanning engine with anchor patterns, rules, and transforms.
pub struct Engine {
    rules: Vec<RuleCompiled>,
    transforms: Vec<TransformConfig>,
    pub(crate) tuning: Tuning,

    // Log2 lookup table for entropy gating.
    entropy_log2: Vec<f32>,

    // Anchor indexes for raw-only and combined (raw + UTF-16) scans.
    anchors: Anchors,
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
    anchor_plan_stats: AnchorPlanStats,

    max_anchor_pat_len: usize,
    max_window_diameter_bytes: usize,
}

/// Summary of anchor derivation choices during engine build.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorPlanStats {
    pub manual_rules: usize,
    pub derived_rules: usize,
    pub residue_rules: usize,
    pub unfilterable_rules: usize,
}

impl Engine {
    /// Compiles rule specs into an engine with prebuilt anchor automata.
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated.
    pub fn new(rules: Vec<RuleSpec>, transforms: Vec<TransformConfig>, tuning: Tuning) -> Self {
        Self::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::PreferDerived)
    }

    /// Compiles rule specs into an engine with a specific anchor policy.
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

        let rules_compiled = rules.iter().map(compile_rule).collect::<Vec<_>>();
        let max_entropy_len = rules_compiled
            .iter()
            .filter_map(|r| r.entropy.map(|e| e.max_len))
            .max()
            .unwrap_or(0);
        let entropy_log2 = build_log2_table(max_entropy_len);

        // Build deduped anchor patterns: pattern -> targets
        let mut pat_map_raw: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut pat_map_all: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut residue_rules: Vec<(usize, ResidueGatePlan)> = Vec::with_capacity(rules.len());
        let mut unfilterable_rules: Vec<(usize, UnfilterableReason)> =
            Vec::with_capacity(rules.len());
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
                 pat_map_all: &mut AHashMap<Vec<u8>, Vec<Target>>| {
                    if !allow_manual {
                        return;
                    }
                    if manual_used || r.anchors.is_empty() {
                        return;
                    }
                    manual_used = true;
                    anchor_plan_stats.manual_rules =
                        anchor_plan_stats.manual_rules.saturating_add(1);
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
                    }
                };

            if !allow_derive {
                add_manual(&mut pat_map_raw, &mut pat_map_all);
                continue;
            }

            let plan = match compile_trigger_plan(r.re.as_str(), &derive_cfg) {
                Ok(plan) => plan,
                Err(_) => {
                    unfilterable_rules.push((rid, UnfilterableReason::UnsupportedRegexFeatures));
                    anchor_plan_stats.unfilterable_rules =
                        anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    add_manual(&mut pat_map_raw, &mut pat_map_all);
                    continue;
                }
            };

            match plan {
                TriggerPlan::Anchored { anchors, .. } => {
                    anchor_plan_stats.derived_rules =
                        anchor_plan_stats.derived_rules.saturating_add(1);
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
                    }
                }
                TriggerPlan::Residue { gate } => {
                    residue_rules.push((rid, gate));
                    anchor_plan_stats.residue_rules =
                        anchor_plan_stats.residue_rules.saturating_add(1);
                    add_manual(&mut pat_map_raw, &mut pat_map_all);
                }
                TriggerPlan::Unfilterable { reason } => {
                    unfilterable_rules.push((rid, reason));
                    anchor_plan_stats.unfilterable_rules =
                        anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    add_manual(&mut pat_map_raw, &mut pat_map_all);
                }
            }
        }

        let (anchor_patterns_raw, pat_targets_raw, pat_offsets_raw) = map_to_patterns(pat_map_raw);
        let (anchor_patterns_all, pat_targets_all, pat_offsets_all) = map_to_patterns(pat_map_all);
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

        let build_anchor_ac = |patterns: &[Vec<u8>], label: &'static str| {
            let mut builder = AhoCorasickBuilder::new();
            builder.prefilter(true);
            if let Some(depth) = tuning.ac_dense_depth {
                builder.dense_depth(depth);
            }
            if let Some(yes) = tuning.ac_byte_classes {
                builder.byte_classes(yes);
            }

            match tuning.ac_kind {
                AnchorAcKind::Auto => {
                    builder.kind(None);
                    builder
                        .build(patterns.iter().map(|p| p.as_slice()))
                        .unwrap_or_else(|err| panic!("build {label} anchors AC: {err}"))
                }
                AnchorAcKind::DFA => {
                    builder.kind(Some(AhoCorasickKind::DFA));
                    match builder.build(patterns.iter().map(|p| p.as_slice())) {
                        Ok(ac) => ac,
                        Err(err) => {
                            // Safe fallback if DFA build fails (e.g., too large).
                            builder.kind(None);
                            builder
                                .build(patterns.iter().map(|p| p.as_slice()))
                                .unwrap_or_else(|auto_err| {
                                    panic!(
                                        "build {label} anchors AC: forced DFA failed: {err}; auto failed: {auto_err}"
                                    )
                                })
                        }
                    }
                }
                AnchorAcKind::ContiguousNFA => {
                    builder.kind(Some(AhoCorasickKind::ContiguousNFA));
                    builder
                        .build(patterns.iter().map(|p| p.as_slice()))
                        .unwrap_or_else(|err| panic!("build {label} anchors AC: {err}"))
                }
                AnchorAcKind::NoncontiguousNFA => {
                    builder.kind(Some(AhoCorasickKind::NoncontiguousNFA));
                    builder
                        .build(patterns.iter().map(|p| p.as_slice()))
                        .unwrap_or_else(|err| panic!("build {label} anchors AC: {err}"))
                }
            }
        };

        let ac_anchors_raw = build_anchor_ac(&anchor_patterns_raw, "raw");
        let ac_anchors_all = build_anchor_ac(&anchor_patterns_all, "all");

        // Warm regex and AC caches at startup to avoid lazy allocations later.
        // `find_iter` always constructs the per-regex cache, so a tiny buffer
        // is sufficient here.
        let warm = [0u8; 1];
        for rule in &rules_compiled {
            let mut it = rule.re.find_iter(&warm);
            let _ = it.next();
        }
        let _ = ac_anchors_raw.is_match(&warm);
        let _ = ac_anchors_all.is_match(&warm);

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

        Self {
            rules: rules_compiled,
            transforms,
            tuning,
            entropy_log2,
            anchors: Anchors {
                raw: AnchorIndex {
                    ac: ac_anchors_raw,
                    pat_targets: pat_targets_raw,
                    pat_offsets: pat_offsets_raw,
                },
                all: AnchorIndex {
                    ac: ac_anchors_all,
                    pat_targets: pat_targets_all,
                    pat_offsets: pat_offsets_all,
                },
            },
            b64_gate,
            residue_rules,
            unfilterable_rules,
            anchor_plan_stats,
            max_anchor_pat_len,
            max_window_diameter_bytes,
        }
    }

    /// Returns a summary of how anchors were chosen during compilation.
    pub fn anchor_plan_stats(&self) -> AnchorPlanStats {
        self.anchor_plan_stats
    }

    /// Rules that could not be given a sound gate from their regex pattern.
    pub fn unfilterable_rules(&self) -> &[(usize, UnfilterableReason)] {
        &self.unfilterable_rules
    }

    /// Single-buffer scan helper (allocation-free after startup).
    ///
    /// Findings are stored in `scratch` and returned as a shared slice. The
    /// returned slice is valid until `scratch` is reused for another scan.
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
    pub fn scan_chunk_into(
        &self,
        root_buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        // High-level flow:
        // 1) Scan anchors in the current buffer and build windows.
        // 2) Run regex validation inside those windows (raw + UTF-16 variants).
        // 3) Optionally decode transforms into derived buffers (gated + deduped),
        //    enqueueing them into a work queue for recursive scanning.
        //
        // Budgets (decode bytes, work items, depth) are enforced on the fly so
        // no single input can force unbounded work.
        scratch.reset_for_scan(self);
        scratch.work_q.push(WorkItem {
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

            let before = scratch.out.len();
            let (buf_ptr, buf_len) = match item.buf {
                BufRef::Root => (root_buf.as_ptr(), root_buf.len()),
                BufRef::Slab(range) => unsafe {
                    assert!(range.end <= scratch.slab.buf.len());
                    let ptr = scratch.slab.buf.as_ptr().add(range.start);
                    (ptr, range.end.saturating_sub(range.start))
                },
            };

            // SAFETY: slab buffer never reallocates (capacity fixed to limit), and we only append.
            let cur_buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len) };

            self.scan_rules_on_buffer(
                cur_buf,
                item.step_id,
                item.root_hint.clone(),
                base_offset,
                file_id,
                scratch,
            );
            let found_any_in_this_buf = scratch.out.len() > before;

            if item.depth >= self.tuning.max_transform_depth {
                continue;
            }
            if scratch.work_items_enqueued >= self.tuning.max_work_items {
                continue;
            }

            for (tidx, tc) in self.transforms.iter().enumerate() {
                if tc.mode == TransformMode::Disabled {
                    continue;
                }
                if tc.mode == TransformMode::IfNoFindingsInThisBuffer && found_any_in_this_buf {
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
                    let enc_span = scratch.spans[i].to_range();
                    if scratch.work_items_enqueued >= self.tuning.max_work_items {
                        break;
                    }
                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        break;
                    }

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
                                    scratch.base64_stats.pre_gate_checks =
                                        scratch.base64_stats.pre_gate_checks.saturating_add(1);
                                }
                                if !gate.hits(enc) {
                                    #[cfg(feature = "b64-stats")]
                                    {
                                        scratch.base64_stats.pre_gate_skip =
                                            scratch.base64_stats.pre_gate_skip.saturating_add(1);
                                        scratch.base64_stats.pre_gate_skip_bytes = scratch
                                            .base64_stats
                                            .pre_gate_skip_bytes
                                            .saturating_add(enc.len() as u64);
                                    }
                                    continue;
                                }
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.pre_gate_pass =
                                        scratch.base64_stats.pre_gate_pass.saturating_add(1);
                                }
                            }
                        }
                    }

                    let remaining = self
                        .tuning
                        .max_total_decode_output_bytes
                        .saturating_sub(scratch.total_decode_output_bytes);
                    if remaining == 0 {
                        break;
                    }
                    let max_out = tc.max_decoded_bytes.min(remaining);

                    let decoded_range = if tc.gate == Gate::AnchorsInDecoded {
                        match self.decode_stream_gated_into_slab(tc, enc, max_out, scratch) {
                            Some(r) => r,
                            None => continue,
                        }
                    } else {
                        match scratch.slab.append_stream_decode(
                            tc,
                            enc,
                            max_out,
                            &mut scratch.total_decode_output_bytes,
                            self.tuning.max_total_decode_output_bytes,
                        ) {
                            Ok(r) => r,
                            Err(_) => continue,
                        }
                    };

                    let decoded = scratch.slab.slice(decoded_range.clone());
                    // If we discard the decoded buffer (empty or duplicate), roll back
                    // the slab to its pre-append length. `decoded_range.start` is the
                    // slab length before this append, so truncation is safe and keeps
                    // memory and decode-budget accounting tight.
                    if decoded.is_empty() {
                        scratch.slab.buf.truncate(decoded_range.start);
                        continue;
                    }

                    let h = hash128(decoded);
                    if !scratch.seen.insert(h) {
                        scratch.slab.buf.truncate(decoded_range.start);
                        continue;
                    }

                    let child_step_id = scratch.step_arena.push(
                        item.step_id,
                        DecodeStep::Transform {
                            transform_idx: tidx,
                            parent_span: enc_span.clone(),
                        },
                    );

                    let child_root_hint = if item.root_hint.is_none() {
                        Some(enc_span.clone())
                    } else {
                        item.root_hint.clone()
                    };

                    scratch.work_q.push(WorkItem {
                        buf: BufRef::Slab(decoded_range),
                        step_id: child_step_id,
                        root_hint: child_root_hint,
                        depth: item.depth + 1,
                    });

                    scratch.work_items_enqueued += 1;
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
    /// This ensures anchor windows (including two-phase expansions) fit across
    /// chunk boundaries.
    pub fn required_overlap(&self) -> usize {
        self.max_window_diameter_bytes
            .saturating_add(self.max_anchor_pat_len.saturating_sub(1))
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

    #[allow(clippy::too_many_arguments)]
    fn scan_anchor_matches(
        &self,
        buf: &[u8],
        ac: &AhoCorasick,
        pat_targets: &[Target],
        pat_offsets: &[u32],
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
    ) {
        for m in ac.find_overlapping_iter(buf) {
            let pid = m.pattern().as_usize();
            let start = pat_offsets[pid] as usize;
            let end = pat_offsets[pid + 1] as usize;
            let targets = &pat_targets[start..end];

            for &t in targets {
                let rule_id = t.rule_id();
                let variant = t.variant();
                let rule = &self.rules[rule_id];

                // Fast validator path:
                // If the rule declares a match-start validator and this anchor hit is
                // match-start aligned, attempt to validate and emit immediately.
                //
                // We only take this path when any keyword gate is implied by the
                // matched anchor and no `must_contain` filter is required, so the
                // validator remains authoritative.
                //
                // On failure we skip window accumulation for this anchor hit,
                // avoiding regex work.
                if variant == Variant::Raw
                    && t.match_start_aligned()
                    && rule.validator.is_enabled()
                    && rule.must_contain.is_none()
                    && t.keyword_implied()
                {
                    if let Some(span) =
                        rule.validator
                            .validate_raw_at_anchor(buf, m.start(), m.end())
                    {
                        if let Some(ent) = rule.entropy {
                            let mbytes = &buf[span.clone()];
                            if !entropy_gate_passes(
                                &ent,
                                mbytes,
                                &mut scratch.entropy_scratch,
                                &self.entropy_log2,
                            ) {
                                continue;
                            }
                        }

                        let root_span_hint =
                            root_hint.as_ref().cloned().unwrap_or_else(|| span.clone());
                        scratch.push_finding(FindingRec {
                            file_id,
                            rule_id: rule_id as u32,
                            span_start: span.start as u32,
                            span_end: span.end as u32,
                            root_hint_start: base_offset + root_span_hint.start as u64,
                            root_hint_end: base_offset + root_span_hint.end as u64,
                            step_id,
                        });
                    }
                    continue;
                }

                // Seed radius depends on whether two-phase is used.
                let seed_r = if let Some(tp) = &rule.two_phase {
                    tp.seed_radius
                } else {
                    rule.radius
                };

                let scale = variant.scale();
                let seed_radius_bytes = seed_r.saturating_mul(scale);

                let lo = m.start().saturating_sub(seed_radius_bytes);
                let hi = (m.end() + seed_radius_bytes).min(buf.len());

                scratch.accs[rule_id][variant.idx()].push(
                    lo,
                    hi,
                    self.tuning.max_anchor_hits_per_rule_variant,
                );
                scratch.mark_touched(rule_id, variant);
            }
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
        assert!(buf.len() <= u32::MAX as usize);
        assert!(self.tuning.merge_gap <= u32::MAX as usize);
        assert!(self.tuning.pressure_gap_start <= u32::MAX as usize);
        let hay_len = buf.len() as u32;
        let merge_gap = self.tuning.merge_gap as u32;
        let pressure_gap_start = self.tuning.pressure_gap_start as u32;

        // L1: anchor scan.
        //
        // NUL-free buffers cannot match UTF-16 patterns, so we select a raw-only
        // automaton in that case. Otherwise we scan a combined raw+UTF-16 index
        // to avoid multiple full passes on binary-heavy buffers.
        let anchors = self.anchors.select(buf, self.tuning.scan_utf16_variants);
        self.scan_anchor_matches(
            buf,
            &anchors.ac,
            &anchors.pat_targets,
            &anchors.pat_offsets,
            step_id,
            &root_hint,
            base_offset,
            file_id,
            scratch,
        );

        if !scratch.touched_any {
            return;
        }

        // Only process (rule, variant) pairs that were actually touched by an
        // anchor hit in this buffer. This avoids O(rules * variants) work when
        // nothing matched, which is critical once rule counts grow.
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

            // Windows are pushed in non-decreasing order of anchor match positions.
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

    fn decode_stream_gated_into_slab(
        &self,
        tc: &TransformConfig,
        encoded: &[u8],
        max_out: usize,
        scratch: &mut ScanScratch,
    ) -> Option<Range<usize>> {
        if max_out == 0 {
            return None;
        }
        #[cfg(feature = "b64-stats")]
        let is_b64 = tc.id == TransformId::Base64;

        // Keep enough bytes to detect anchors that straddle decode chunk boundaries.
        let tail_keep = self.max_anchor_pat_len.saturating_sub(1);
        scratch.gate.reset();

        let start_len = scratch.slab.buf.len();
        let mut local_out = 0usize;
        let mut truncated = false;
        let mut hit = false;

        // Decode once while checking for anchors. If no anchors appear in the decoded
        // stream, the slab append is rolled back and the transform is skipped.
        //
        // We keep a small tail window so anchors that straddle decode chunk boundaries
        // are still detected without re-decoding or buffering the entire output.
        #[cfg(feature = "b64-stats")]
        if is_b64 {
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
            if scratch.slab.buf.len().saturating_add(chunk.len()) > scratch.slab.limit {
                truncated = true;
                return ControlFlow::Break(());
            }

            scratch.slab.buf.extend_from_slice(chunk);
            local_out = local_out.saturating_add(chunk.len());
            scratch.total_decode_output_bytes = scratch
                .total_decode_output_bytes
                .saturating_add(chunk.len());

            // Sliding decoded window: tail (prev chunk) + current chunk.
            scratch.gate.scratch.clear();
            scratch
                .gate
                .scratch
                .extend_from_slice(scratch.gate.tail.as_slice());
            scratch.gate.scratch.extend_from_slice(chunk);

            if !hit {
                let window = scratch.gate.scratch.as_slice();
                let anchors = self.anchors.select(window, self.tuning.scan_utf16_variants);
                if anchors.ac.is_match(window) {
                    hit = true;
                }
            }

            if tail_keep > 0 {
                let scratch_len = scratch.gate.scratch.len();
                let keep = tail_keep.min(scratch_len);
                let start = scratch_len - keep;
                scratch.gate.tail.clear();
                scratch
                    .gate
                    .tail
                    .extend_from_slice(&scratch.gate.scratch.as_slice()[start..]);
            }

            ControlFlow::Continue(())
        });

        if res.is_err() || truncated || local_out == 0 || local_out > max_out {
            #[cfg(feature = "b64-stats")]
            if is_b64 {
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
            scratch.slab.buf.truncate(start_len);
            return None;
        }

        if !hit {
            #[cfg(feature = "b64-stats")]
            if is_b64 {
                scratch.base64_stats.decoded_bytes_total = scratch
                    .base64_stats
                    .decoded_bytes_total
                    .saturating_add(local_out as u64);
                scratch.base64_stats.decoded_bytes_wasted_no_anchor = scratch
                    .base64_stats
                    .decoded_bytes_wasted_no_anchor
                    .saturating_add(local_out as u64);
            }
            scratch.slab.buf.truncate(start_len);
            return None;
        }

        #[cfg(feature = "b64-stats")]
        if is_b64 {
            scratch.base64_stats.decoded_bytes_total = scratch
                .base64_stats
                .decoded_bytes_total
                .saturating_add(local_out as u64);
            scratch.base64_stats.decoded_bytes_kept = scratch
                .base64_stats
                .decoded_bytes_kept
                .saturating_add(local_out as u64);
        }

        Some(start_len..(start_len + local_out))
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
        keywords,
        entropy,
        re: spec.re.clone(),
        two_phase,
    }
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

#[cfg(feature = "bench")]
pub fn bench_find_spans_into(tc: &TransformConfig, buf: &[u8], out: &mut Vec<Range<usize>>) {
    find_spans_into(tc, buf, out);
}

#[cfg(feature = "bench")]
impl Engine {
    pub fn bench_ac_anchors(&self) -> &AhoCorasick {
        &self.anchors.raw.ac
    }
}

#[cfg(test)]
mod tests;
