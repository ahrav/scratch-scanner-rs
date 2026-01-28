//! Anchor prefilters built from bytesets.
//!
//! The anchor scanner uses a full Aho-Corasick pass to find every anchor hit
//! (overlapping matches required). Aho-Corasick's built-in prefilters are not
//! available for overlapping searches, so we implement a separate, sound
//! prefilter layer that can cheaply skip large buffers when anchors are
//! implausible.
//!
//! # Invariants
//! - Prefilters are sound: they must never skip a buffer that contains an anchor.
//! - Every pattern contributes at least one byte to the byteset (a hitting set).
//! - Candidate windows must fully cover all possible matches of assigned patterns.
//!
//! # Algorithm
//! - Build a byteset from the pattern universe.
//! - For each byte in the set, record conservative window offsets and tails.
//! - At scan time, convert byte hits into windows and merge overlaps.
//! - Disable prefiltering when a sample is too dense to avoid overlap storms.
//!
//! # Design Notes
//! - Two families are supported: start-byte (cheap, predictable) and rare-byte
//!   (smaller byteset, better selectivity).
//! - When prefiltering cannot be kept small or selective, we fall back to full
//!   scanning instead of risking false negatives.
#![cfg_attr(not(feature = "stats"), allow(unused_variables))]

use super::helpers::merge_ranges_with_gap_sorted;
use super::SpanU32;
use crate::scratch_memory::ScratchVec;

/// Prefilter selection and scanning thresholds.
///
/// These are conservative defaults tuned to avoid regressions on dense
/// code-like buffers while still allowing wins on sparse inputs.
const PREFILTER_SAMPLE_BYTES: usize = 8 * 1024;
const PREFILTER_MIN_LEN: usize = 64;
const START_MAX_HIT_RATE: f32 = 0.45;
const RARE_MAX_HIT_RATE: f32 = 0.15;
const PREFILTER_MAX_COVERAGE: f32 = 0.85;
const RARE_MAX_BYTES_PRIMARY: usize = 16;
const RARE_MAX_BYTES_FALLBACK: usize = 32;
const RARE_MAX_OFFSET: u32 = 64;
const RARE_MAX_SPAN: u32 = 128;

/// Heuristic byte frequency ranks (lower = rarer).
///
/// This table mirrors the ranking used by the aho-corasick crate and provides
/// a rough proxy for "code-ish" text. Runtime density gating still decides
/// whether a prefilter is actually used for any particular buffer.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrefilterKind {
    Start,
    Rare,
}

/// A compact set of bytes with O(1) membership checks.
///
/// # Invariants
/// - `table[b] != 0` if and only if `b` is present in `bytes`.
/// - `bytes` is kept sorted after `finalize()`.
#[derive(Clone, Debug)]
struct ByteSet {
    table: [u8; 256],
    bytes: Vec<u8>,
}

impl ByteSet {
    /// Creates an empty byteset.
    fn empty() -> Self {
        Self {
            table: [0u8; 256],
            bytes: Vec::new(),
        }
    }

    /// Inserts a byte if it is not already present.
    fn insert(&mut self, b: u8) {
        let idx = b as usize;
        if self.table[idx] == 0 {
            self.table[idx] = 1;
            self.bytes.push(b);
        }
    }

    /// Returns true when the byte is present in the set.
    fn contains(&self, b: u8) -> bool {
        self.table[b as usize] != 0
    }

    /// Returns the number of distinct bytes in the set.
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when the set is empty.
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Sorts the byte list for stable iteration and reproducibility.
    fn finalize(&mut self) {
        self.bytes.sort_unstable();
    }

    /// Counts how many bytes in `hay` are members of this set.
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

/// A byteset-based prefilter with conservative window metadata.
///
/// # Invariants
/// - `offsets[b]` and `tails[b]` are zero for bytes not in `set`.
/// - `max_span` is the maximum of `offsets[b] + tails[b]` for bytes in `set`.
#[derive(Clone, Debug)]
pub(super) struct ByteSetPrefilter {
    kind: PrefilterKind,
    set: ByteSet,
    /// Maximum offset of `b` within any assigned pattern.
    offsets: [u32; 256],
    /// Maximum tail length (`len - min_offset`) of `b` within any assigned pattern.
    tails: [u32; 256],
    /// Maximum window span (`offsets[b] + tails[b]`) across all bytes in the set.
    max_span: u32,
}

impl ByteSetPrefilter {
    /// Estimates the hit rate using a fixed-size prefix sample.
    ///
    /// The sample is intentionally small to keep the gate cheap.
    fn sample_hit_rate(&self, hay: &[u8]) -> f32 {
        let sample_len = hay.len().min(PREFILTER_SAMPLE_BYTES);
        if sample_len == 0 {
            return 0.0;
        }
        let hits = self.set.count_hits(&hay[..sample_len]);
        hits as f32 / sample_len as f32
    }

    /// Collects candidate windows that must include any possible match.
    ///
    /// # Effects
    /// - Clears and fills `out` with merged windows when a prefilter is used.
    ///
    /// # Returns
    /// - `Windows` when `out` contains candidate spans.
    /// - `NoCandidates` when the byteset never hit.
    /// - `FullScan` when the prefilter is disabled for safety or density.
    pub(super) fn collect_windows(
        &self,
        hay: &[u8],
        out: &mut ScratchVec<SpanU32>,
    ) -> PrefilterOutcome {
        out.clear();
        if hay.len() < PREFILTER_MIN_LEN {
            return PrefilterOutcome::FullScan;
        }

        for (pos, &b) in hay.iter().enumerate() {
            if !self.set.contains(b) {
                continue;
            }
            if out.len() >= out.capacity() {
                // Too many windows to be useful; fall back to full scan.
                out.clear();
                return PrefilterOutcome::FullScan;
            }
            let off = self.offsets[b as usize] as usize;
            let tail = self.tails[b as usize] as usize;
            let start = pos.saturating_sub(off);
            let end = (pos.saturating_add(tail)).min(hay.len());
            if start < end {
                out.push(SpanU32::new(start, end));
            }
        }

        if out.is_empty() {
            return PrefilterOutcome::NoCandidates;
        }

        out.as_mut_slice().sort_unstable_by_key(|s| s.start);
        merge_ranges_with_gap_sorted(out, 0);

        let mut covered = 0usize;
        for span in out.as_slice() {
            covered = covered.saturating_add((span.end - span.start) as usize);
        }
        if covered as f32 / hay.len().max(1) as f32 >= PREFILTER_MAX_COVERAGE {
            // Window coverage is too high; the prefilter would not be selective.
            out.clear();
            return PrefilterOutcome::FullScan;
        }

        PrefilterOutcome::Windows
    }
}

/// Result of collecting prefilter windows.
pub(super) enum PrefilterOutcome {
    /// No byteset hits were observed; skip the buffer safely.
    NoCandidates,
    /// Candidate windows are available in the output buffer.
    Windows,
    /// Prefiltering is disabled; caller should scan the full buffer.
    FullScan,
}

#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct AnchorPrefilterStatsInternal {
    pub pattern_count: usize,
    pub max_pattern_len: usize,
    pub start_bytes: usize,
    pub rare_bytes: usize,
    pub rare_max_offset: usize,
    pub rare_max_span: usize,
    pub start_available: bool,
    pub rare_available: bool,
}

#[cfg(not(feature = "stats"))]
pub(super) type AnchorPrefilterStatsInternal = ();

/// The compiled prefilter plan for a single anchor universe.
///
/// The plan may include both start-byte and rare-byte prefilters; selection is
/// made at runtime based on sample density.
#[derive(Clone, Debug)]
pub(super) struct AnchorPrefilterPlan {
    start: Option<ByteSetPrefilter>,
    rare: Option<ByteSetPrefilter>,
    #[cfg(feature = "stats")]
    stats: AnchorPrefilterStatsInternal,
}

impl AnchorPrefilterPlan {
    /// Builds a prefilter plan from the full pattern universe.
    ///
    /// # Returns
    /// - A plan with zero, one, or two prefilters depending on eligibility.
    pub(super) fn build(patterns: &[Vec<u8>]) -> Self {
        #[cfg(feature = "stats")]
        {
            let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
            let mut stats = AnchorPrefilterStatsInternal {
                pattern_count: patterns.len(),
                max_pattern_len,
                ..AnchorPrefilterStatsInternal::default()
            };

            let start = build_start_prefilter(patterns, &mut stats);
            let rare = build_rare_prefilter(patterns, &mut stats);

            Self { start, rare, stats }
        }

        #[cfg(not(feature = "stats"))]
        {
            let start = build_start_prefilter(patterns, &mut ());
            let rare = build_rare_prefilter(patterns, &mut ());
            Self { start, rare }
        }
    }

    #[cfg(feature = "stats")]
    pub(super) fn stats(&self) -> AnchorPrefilterStatsInternal {
        self.stats
    }

    pub(super) fn pick<'a>(&'a self, hay: &[u8]) -> Option<&'a ByteSetPrefilter> {
        if hay.len() < PREFILTER_MIN_LEN {
            return None;
        }

        let start = self.start.as_ref();
        let rare = self.rare.as_ref();

        let start_ok = start
            .map(|p| p.sample_hit_rate(hay) <= START_MAX_HIT_RATE)
            .unwrap_or(false);
        let rare_ok = rare
            .map(|p| p.sample_hit_rate(hay) <= RARE_MAX_HIT_RATE)
            .unwrap_or(false);

        match (start_ok, rare_ok) {
            (_, true) => rare,
            (true, false) => start,
            _ => None,
        }
    }
}

/// Per-pattern candidate byte data used by the rare-byte assignment.
#[derive(Clone, Copy, Debug)]
struct PatternByteInfo {
    byte: u8,
    min_offset: u32,
    max_offset: u32,
    tail: u32,
    span: u32,
    score: u32,
}

/// Builds a start-byte prefilter from the first byte of each pattern.
///
/// Returns `None` when any pattern is empty or when no bytes are available.
fn build_start_prefilter(
    patterns: &[Vec<u8>],
    stats: &mut AnchorPrefilterStatsInternal,
) -> Option<ByteSetPrefilter> {
    let mut set = ByteSet::empty();
    let offsets = [0u32; 256];
    let mut tails = [0u32; 256];

    for pat in patterns {
        if pat.is_empty() {
            #[cfg(feature = "stats")]
            {
                stats.start_available = false;
            }
            return None;
        }
        let b = pat[0];
        set.insert(b);
        let tail = pat.len() as u32;
        if tail > tails[b as usize] {
            tails[b as usize] = tail;
        }
    }

    if set.is_empty() {
        #[cfg(feature = "stats")]
        {
            stats.start_available = false;
        }
        return None;
    }

    set.finalize();
    #[cfg(feature = "stats")]
    {
        stats.start_bytes = set.len();
        stats.start_available = true;
    }

    let max_span = tails.iter().copied().max().unwrap_or(0);

    Some(ByteSetPrefilter {
        kind: PrefilterKind::Start,
        set,
        offsets,
        tails,
        max_span,
    })
}

/// Builds a rare-byte prefilter by assigning one byte per pattern.
///
/// The assignment is greedy and bounded by `RARE_MAX_BYTES_*`. If the byteset
/// would grow too large or the resulting windows are too wide, this returns
/// `None` and disables the rare prefilter.
fn build_rare_prefilter(
    patterns: &[Vec<u8>],
    stats: &mut AnchorPrefilterStatsInternal,
) -> Option<ByteSetPrefilter> {
    let disable = |stats: &mut AnchorPrefilterStatsInternal| {
        #[cfg(feature = "stats")]
        {
            stats.rare_available = false;
            stats.rare_bytes = 0;
            stats.rare_max_offset = 0;
            stats.rare_max_span = 0;
        }
    };

    if patterns.is_empty() {
        disable(stats);
        return None;
    }

    let mut pattern_info = Vec::with_capacity(patterns.len());
    for pat in patterns {
        if pat.is_empty() {
            disable(stats);
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
            let tail = len.saturating_sub(min_offset);
            let span = max_offset.saturating_add(tail);
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
            disable(stats);
            return None;
        }
        bytes.sort_unstable_by_key(|c| c.score);
        pattern_info.push(bytes);
    }

    // Greedy assignment: favor existing bytes to keep the set small, otherwise
    // pick the lowest-score byte for the pattern.
    let mut set = ByteSet::empty();
    let mut assignments: Vec<PatternByteInfo> = Vec::with_capacity(pattern_info.len());

    // Assign patterns with the fewest options first to avoid dead-ends.
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
        disable(stats);
        return None;
    };

    set.finalize();
    #[cfg(feature = "stats")]
    {
        stats.rare_bytes = set.len();
        stats.rare_available = true;
    }

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
            disable(stats);
            return None;
        }
        let span = offsets[idx].saturating_add(tails[idx]);
        if span > max_span {
            max_span = span;
        }
    }

    if max_span > RARE_MAX_SPAN {
        disable(stats);
        return None;
    }

    #[cfg(feature = "stats")]
    {
        stats.rare_max_offset = offsets.iter().copied().max().unwrap_or(0) as usize;
        stats.rare_max_span = max_span as usize;
    }

    if set.is_empty() {
        disable(stats);
        return None;
    }

    Some(ByteSetPrefilter {
        kind: PrefilterKind::Rare,
        set,
        offsets,
        tails,
        max_span,
    })
}

/// Greedily assigns one candidate byte per pattern under a size budget.
///
/// # Effects
/// - Clears and repopulates `set` and `assignments`.
/// - Returns `false` if the byteset would exceed `max_bytes`.
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
            let cand = candidates[0];
            set.insert(cand.byte);
            chosen = Some(cand);
        }

        assignments.push(chosen.expect("candidate assignment missing"));
    }

    set.len() <= max_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch_memory::ScratchVec;

    #[test]
    fn start_prefilter_windows_cover_match() {
        let patterns = vec![b"ab".to_vec(), b"cab".to_vec()];
        let plan = AnchorPrefilterPlan::build(&patterns);
        let pre = plan.start.as_ref().expect("start prefilter expected");

        let mut hay = vec![b'x'; PREFILTER_MIN_LEN + 16];
        let match_start = 32usize;
        hay[match_start..match_start + 3].copy_from_slice(b"cab");

        let mut windows =
            ScratchVec::with_capacity(64).expect("prefilter windows allocation failed");
        let outcome = pre.collect_windows(&hay, &mut windows);
        assert!(matches!(outcome, PrefilterOutcome::Windows));

        let match_end = match_start + 3;
        assert!(windows.as_slice().iter().any(|w| {
            let start = w.start as usize;
            let end = w.end as usize;
            start <= match_start && end >= match_end
        }));
    }

    #[test]
    fn rare_prefilter_is_hitting_set() {
        let patterns = vec![
            b"token_".to_vec(),
            b"sk-".to_vec(),
            b"AKIA".to_vec(),
            b"ghp_".to_vec(),
        ];
        let plan = AnchorPrefilterPlan::build(&patterns);
        let rare = plan.rare.as_ref().expect("rare prefilter expected");

        for pat in patterns {
            assert!(pat.iter().any(|&b| rare.set.contains(b)));
        }
    }
}
