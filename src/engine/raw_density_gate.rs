//! Density gate for raw Vectorscan prefiltering.
//!
//! This mirrors the old byteset prefilter's density checks to avoid running
//! Vectorscan on buffers where anchor-byte hits are too dense to be selective.
//!
//! # Problem statement
//! Vectorscan is relatively expensive to invoke on large buffers. When the
//! anchor bytes for patterns are frequent in the buffer, the prefilter becomes
//! non-selective and wastes time. This module builds a lightweight, heuristic
//! gate that rejects such buffers up front.
//!
//! # High-level algorithm
//! 1. **Start-byte gate:** collect the first byte from every anchor pattern.
//! 2. **Rare-byte gate:** for each pattern, pick one "rare" byte using a
//!    frequency-and-span score, reusing already-picked bytes where possible.
//! 3. Sample up to 8KiB of the buffer, compute hit rates for each gate, and
//!    allow Vectorscan if *any* gate's hit rate is below its threshold.
//!
//! # Invariants and trade-offs
//! - Patterns must be non-empty; an empty pattern disables the gate.
//! - The gate is heuristic: it can admit false positives or reject true
//!   matches. The goal is to reduce costly Vectorscan calls on dense buffers.
//! - Rare-byte assignments are bounded by offset/span limits to keep bytes
//!   reasonably "anchored" within patterns (mirroring the legacy behavior).
//!
//! # Complexity
//! Build time is `O(P * (L + 256))` where `P` is patterns and `L` is pattern
//! length, dominated by per-pattern byte scans and scoring. Runtime gating is
//! linear in the sample size (up to 8KiB).

/// Fixed-size prefix sampled to estimate byte hit density.
const PREFILTER_SAMPLE_BYTES: usize = 8 * 1024;
/// Minimum buffer length before density gating applies.
const PREFILTER_MIN_LEN: usize = 64;
/// Max acceptable hit rate for start-byte gating.
const START_MAX_HIT_RATE: f32 = 0.45;
/// Max acceptable hit rate for rare-byte gating.
const RARE_MAX_HIT_RATE: f32 = 0.15;
/// Primary rare-byte set size budget.
const RARE_MAX_BYTES_PRIMARY: usize = 16;
/// Fallback rare-byte set size budget.
const RARE_MAX_BYTES_FALLBACK: usize = 32;
/// Maximum allowed offset for rare-byte assignments.
const RARE_MAX_OFFSET: u32 = 64;
/// Maximum span width allowed for rare-byte assignments.
const RARE_MAX_SPAN: u32 = 128;

/// Heuristic byte frequency ranks (lower = rarer).
///
/// This table mirrors the ranking used by the aho-corasick crate and provides
/// a rough proxy for "code-ish" text. Runtime density gating still decides
/// whether the gate is used for any particular buffer.
const BYTE_FREQ_RANK: [u8; 256] = [
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43, 42, 41, 40, 39, 38, 37, 36,
    35, 34, 33, 56, 32, 31, 30, 29, 28, 255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122,
    232, 202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174,
    126, 120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112,
    175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151, 249, 216, 238, 236,
    253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244, 231, 139, 245, 243, 251, 235, 201, 196,
    240, 214, 152, 182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,
    80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111, 82,
    108, 118, 141, 113, 129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166, 237, 163,
    199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
];

/// Fixed-size byte set with constant-time membership tests.
#[derive(Clone, Debug)]
struct ByteSet {
    table: [u8; 256],
    bytes: Vec<u8>,
}

impl ByteSet {
    fn empty() -> Self {
        Self {
            table: [0u8; 256],
            bytes: Vec::new(),
        }
    }

    fn insert(&mut self, b: u8) {
        let idx = b as usize;
        if self.table[idx] == 0 {
            self.table[idx] = 1;
            self.bytes.push(b);
        }
    }

    fn contains(&self, b: u8) -> bool {
        self.table[b as usize] != 0
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn finalize(&mut self) {
        self.bytes.sort_unstable();
    }

    fn count_hits(&self, hay: &[u8]) -> usize {
        let mut hits = 0usize;
        for &b in hay {
            if self.contains(b) {
                hits = hits.saturating_add(1);
            }
        }
        hits
    }
}

/// Density gate that estimates hit rate for a fixed byte set.
#[derive(Clone, Debug)]
struct ByteSetGate {
    set: ByteSet,
}

impl ByteSetGate {
    /// Returns the fraction of sampled bytes that are in the gate's set.
    ///
    /// Sampling is capped at `PREFILTER_SAMPLE_BYTES` to bound runtime cost.
    fn sample_hit_rate(&self, hay: &[u8]) -> f32 {
        let sample_len = hay.len().min(PREFILTER_SAMPLE_BYTES);
        if sample_len == 0 {
            return 0.0;
        }
        let hits = self.set.count_hits(&hay[..sample_len]);
        hits as f32 / sample_len as f32
    }
}

/// Density gate built from raw anchor patterns.
///
/// At least one of `start` or `rare` is present when constructed via `build`.
#[derive(Clone, Debug)]
pub(super) struct RawDensityGate {
    start: Option<ByteSetGate>,
    rare: Option<ByteSetGate>,
}

impl RawDensityGate {
    /// Builds a density gate from the anchor pattern universe.
    ///
    /// Returns `None` when patterns are empty, any pattern is empty, or no
    /// gate can be constructed under the configured heuristics.
    pub(super) fn build(patterns: &[Vec<u8>]) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }

        let start = build_start_gate(patterns);
        let rare = build_rare_gate(patterns);
        if start.is_none() && rare.is_none() {
            None
        } else {
            Some(Self { start, rare })
        }
    }

    /// Returns true when Vectorscan should run on this buffer.
    ///
    /// Buffers shorter than `PREFILTER_MIN_LEN` are always rejected because the
    /// density estimate is too noisy to be meaningful.
    pub(super) fn allows_hs(&self, hay: &[u8]) -> bool {
        if hay.len() < PREFILTER_MIN_LEN {
            return false;
        }

        let start_ok = self
            .start
            .as_ref()
            .map(|p| p.sample_hit_rate(hay) <= START_MAX_HIT_RATE)
            .unwrap_or(false);
        let rare_ok = self
            .rare
            .as_ref()
            .map(|p| p.sample_hit_rate(hay) <= RARE_MAX_HIT_RATE)
            .unwrap_or(false);

        start_ok || rare_ok
    }
}

/// Per-pattern byte candidate with scoring and span metadata.
#[derive(Clone, Copy, Debug)]
struct PatternByteInfo {
    byte: u8,
    min_offset: u32,
    max_offset: u32,
    tail: u32,
    span: u32,
    score: u32,
}

fn build_start_gate(patterns: &[Vec<u8>]) -> Option<ByteSetGate> {
    let mut set = ByteSet::empty();

    for pat in patterns {
        if pat.is_empty() {
            return None;
        }
        set.insert(pat[0]);
    }

    if set.is_empty() {
        return None;
    }

    set.finalize();
    Some(ByteSetGate { set })
}

fn build_rare_gate(patterns: &[Vec<u8>]) -> Option<ByteSetGate> {
    if patterns.is_empty() {
        return None;
    }

    let mut pattern_info = Vec::with_capacity(patterns.len());
    for pat in patterns {
        if pat.is_empty() {
            return None;
        }
        let len = pat.len() as u32;
        let mut min_off = [u32::MAX; 256];
        let mut max_off = [0u32; 256];
        let mut seen = [false; 256];

        for (i, &b) in pat.iter().enumerate() {
            let pos = i as u32;
            let idx = b as usize;
            seen[idx] = true;
            if pos < min_off[idx] {
                min_off[idx] = pos;
            }
            if pos > max_off[idx] {
                max_off[idx] = pos;
            }
        }

        let mut bytes = Vec::new();
        for idx in 0..256 {
            if !seen[idx] {
                continue;
            }
            let min_offset = min_off[idx];
            let max_offset = max_off[idx];
            // Tail is the suffix length after the earliest occurrence.
            let tail = len.saturating_sub(min_offset);
            // Span approximates how far the byte can appear within the pattern.
            let span = max_offset.saturating_add(tail);
            // Score favors rare bytes, then tighter spans.
            let freq = BYTE_FREQ_RANK[idx] as u32;
            let score = freq.saturating_add(span.saturating_mul(2));
            bytes.push(PatternByteInfo {
                byte: idx as u8,
                min_offset,
                max_offset,
                tail,
                span,
                score,
            });
        }
        if bytes.is_empty() {
            return None;
        }
        bytes.sort_unstable_by_key(|c| c.score);
        pattern_info.push(bytes);
    }

    let mut set = ByteSet::empty();
    let mut assignments: Vec<PatternByteInfo> = Vec::with_capacity(pattern_info.len());
    let mut order: Vec<usize> = (0..pattern_info.len()).collect();
    order.sort_unstable_by_key(|&i| pattern_info[i].len());

    if try_assign(
        &pattern_info,
        &order,
        RARE_MAX_BYTES_PRIMARY,
        &mut set,
        &mut assignments,
    ) {
        // keep primary size
    } else if try_assign(
        &pattern_info,
        &order,
        RARE_MAX_BYTES_FALLBACK,
        &mut set,
        &mut assignments,
    ) {
        // keep fallback size
    } else {
        return None;
    };

    set.finalize();

    let mut offsets = [0u32; 256];
    let mut tails = [0u32; 256];
    let mut max_span = 0u32;

    for info in assignments {
        let idx = info.byte as usize;
        if info.max_offset > offsets[idx] {
            offsets[idx] = info.max_offset;
        }
        if info.tail > tails[idx] {
            tails[idx] = info.tail;
        }
    }

    for idx in 0..256 {
        if offsets[idx] == 0 && tails[idx] == 0 {
            continue;
        }
        if offsets[idx] > RARE_MAX_OFFSET {
            return None;
        }
        let span = offsets[idx].saturating_add(tails[idx]);
        if span > max_span {
            max_span = span;
        }
    }

    if max_span > RARE_MAX_SPAN {
        return None;
    }

    if set.is_empty() {
        return None;
    }

    Some(ByteSetGate { set })
}

fn try_assign(
    pattern_info: &[Vec<PatternByteInfo>],
    order: &[usize],
    max_bytes: usize,
    set: &mut ByteSet,
    assignments: &mut Vec<PatternByteInfo>,
) -> bool {
    set.bytes.clear();
    set.table = [0u8; 256];
    assignments.clear();

    for &idx in order {
        let candidates = &pattern_info[idx];
        let mut chosen: Option<PatternByteInfo> = None;

        // Prefer reusing an existing byte to keep the set small.
        for cand in candidates {
            if set.contains(cand.byte) {
                chosen = Some(*cand);
                break;
            }
        }

        if chosen.is_none() {
            if set.len() >= max_bytes {
                return false;
            }
            // Otherwise pick the best-scoring candidate for this pattern.
            let cand = candidates[0];
            set.insert(cand.byte);
            chosen = Some(cand);
        }

        assignments.push(chosen.expect("candidate assignment missing"));
    }

    set.len() <= max_bytes
}
