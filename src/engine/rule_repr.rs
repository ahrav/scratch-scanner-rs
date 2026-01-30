//! Internal compiled rule representation.
//!
//! This module defines the data layout the scan loop consumes: anchor variants,
//! packed literal tables, and precompiled gates derived from a validated
//! [`RuleSpec`]. The emphasis is on cache-friendly layouts and variant-indexed
//! tables so the hot path avoids allocation and encoding conversion.
//!
//! Notes:
//! - UTF-16 helpers in this module are ASCII-only expansions (1 byte -> 1 code
//!   unit) used for literal gating. They are not general-purpose UTF-16 encoders.
//! - Variant ordering is stable and reused for packed arrays and bit layouts.

use crate::api::{RuleSpec, Utf16Endianness, ValidatorKind};
use ahash::AHashMap;
use regex::bytes::Regex;

// --------------------------
// Anchor variants
// --------------------------

/// Anchor variant used during matching and window scaling.
///
/// Raw anchors match input bytes directly. UTF-16 variants match byte-encoded
/// UTF-16LE/BE anchors and double window radii via `scale()` so windows are
/// sized in bytes, not code units.
///
/// # Invariants
/// - `idx()` ordering is stable and used for packed tables and array slots.
/// - `scale()` returns 1 for raw and 2 for UTF-16 variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Variant {
    Raw,
    Utf16Le,
    Utf16Be,
}

impl Variant {
    /// Stable index into per-variant arrays: Raw=0, Utf16Le=1, Utf16Be=2.
    pub(super) fn idx(self) -> usize {
        match self {
            Variant::Raw => 0,
            Variant::Utf16Le => 1,
            Variant::Utf16Be => 2,
        }
    }

    /// Convert the packed table index back to a variant.
    pub(super) fn from_idx(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(Variant::Raw),
            1 => Some(Variant::Utf16Le),
            2 => Some(Variant::Utf16Be),
            _ => None,
        }
    }

    /// Scale a character radius into a byte radius for this variant.
    pub(super) fn scale(self) -> usize {
        match self {
            Variant::Raw => 1,
            Variant::Utf16Le | Variant::Utf16Be => 2,
        }
    }

    /// Returns the UTF-16 endianness for UTF-16 variants.
    pub(super) fn utf16_endianness(self) -> Option<Utf16Endianness> {
        match self {
            Variant::Raw => None,
            Variant::Utf16Le => Some(Utf16Endianness::Le),
            Variant::Utf16Be => Some(Utf16Endianness::Be),
        }
    }
}

// --------------------------
// Target mapping
// --------------------------

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
///
/// # Invariants
/// - `rule_id` fits in the upper bits after `VARIANT_SHIFT`.
/// - The low-bit layout is stable and must match `variant()` and flag accessors.
#[derive(Clone, Copy, Debug)]
pub(super) struct Target(u32);

impl Target {
    const VARIANT_MASK: u32 = 0b11;
    const MATCH_START_MASK: u32 = 1 << 2;
    const KEYWORD_IMPLIED_MASK: u32 = 1 << 3;
    const VARIANT_SHIFT: u32 = 4;

    /// Pack a (rule_id, variant) and small flags into a single `u32`.
    pub(super) fn new(
        rule_id: u32,
        variant: Variant,
        match_start: bool,
        keyword_implied: bool,
    ) -> Self {
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

    pub(super) fn rule_id(self) -> usize {
        (self.0 >> Self::VARIANT_SHIFT) as usize
    }

    /// Extract the variant tag from the packed representation.
    pub(super) fn variant(self) -> Variant {
        match self.0 & Self::VARIANT_MASK {
            0 => Variant::Raw,
            1 => Variant::Utf16Le,
            2 => Variant::Utf16Be,
            _ => unreachable!("invalid variant tag"),
        }
    }

    pub(super) fn match_start_aligned(self) -> bool {
        (self.0 & Self::MATCH_START_MASK) != 0
    }

    /// Whether keyword gating is implied for this particular anchor.
    pub(super) fn keyword_implied(self) -> bool {
        (self.0 & Self::KEYWORD_IMPLIED_MASK) != 0
    }
}

// --------------------------
// Pattern storage
// --------------------------

/// Packed byte patterns with an offset table.
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm patterns contiguous for cache-friendly memmem checks (both ANY and
/// ALL gates).
///
/// # Invariants
/// - `offsets[0] == 0` and the last offset equals `bytes.len()`.
/// - `offsets` is monotonically non-decreasing.
/// - `bytes.len() <= u32::MAX`.
///
/// # Performance
/// - Contiguous storage enables cache-friendly `memmem` gates without
///   per-window allocations.
#[derive(Clone, Debug)]
pub(super) struct PackedPatterns {
    pub(super) bytes: Vec<u8>,
    pub(super) offsets: Vec<u32>,
}

impl PackedPatterns {
    /// Create a packed pattern table with capacities sized for fast filling.
    pub(super) fn with_capacity(patterns: usize, bytes: usize) -> Self {
        let mut offsets = Vec::with_capacity(patterns.saturating_add(1));
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(bytes),
            offsets,
        }
    }

    /// Append a raw pattern (byte-for-byte).
    pub(super) fn push_raw(&mut self, pat: &[u8]) {
        self.bytes.extend_from_slice(pat);
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    /// Append an ASCII pattern expanded to UTF-16LE code units.
    pub(super) fn push_utf16le(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(b);
            self.bytes.push(0);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    /// Append an ASCII pattern expanded to UTF-16BE code units.
    pub(super) fn push_utf16be(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(0);
            self.bytes.push(b);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }
}

// --------------------------
// Compiled rule gates
// --------------------------

/// Two-phase rule data compiled per variant for fast confirm checks.
///
/// Stores prepacked confirm patterns per variant so the scan loop can run
/// memmem without per-hit allocation or UTF-16 conversions.
///
/// # Guarantees
/// - `confirm` entries are encoded per variant and indexed by `Variant::idx()`.
///
/// # Invariants
/// - Radii and pattern lengths are validated by `RuleSpec::assert_valid`.
#[derive(Clone, Debug)]
pub(super) struct TwoPhaseCompiled {
    pub(super) seed_radius: usize,
    pub(super) full_radius: usize,

    // confirm patterns per variant (raw bytes for Raw, utf16-bytes for Utf16Le/Be)
    pub(super) confirm: [PackedPatterns; 3],
}

/// Keyword gate compiled per variant for fast "any keyword" checks.
///
/// # Guarantees
/// - `any` is encoded per variant and indexed by `Variant::idx()`.
#[derive(Clone, Debug)]
pub(super) struct KeywordsCompiled {
    // Raw / Utf16Le / Utf16Be variants packed for fast memmem gating.
    // This mirrors anchor variant handling so keyword gating behaves consistently
    // across encodings and avoids per-window UTF-16 conversions.
    pub(super) any: [PackedPatterns; 3],
}

/// Derived "confirm all" gate from mandatory literal islands.
///
/// Design intent:
/// - The longest literal is checked first as a single memmem search.
/// - The remaining literals are checked with AND semantics using PackedPatterns.
/// - UTF-16 variants are encoded the same way as anchors/keywords so we can
///   reject windows before decoding.
///
/// # Guarantees
/// - `primary` holds the longest literal (per `compile_confirm_all` sorting).
/// - `rest` is encoded per variant and indexed by `Variant::idx()`.
#[derive(Clone, Debug)]
pub(super) struct ConfirmAllCompiled {
    pub(super) primary: [Option<Vec<u8>>; 3],
    pub(super) rest: [PackedPatterns; 3],
}

/// Entropy gate parameters compiled into a rule.
///
/// # Invariants
/// - Values are validated by `RuleSpec::assert_valid`.
#[derive(Clone, Copy, Debug)]
pub(super) struct EntropyCompiled {
    // Prevalidated config stored in compiled rules to avoid repeated lookups.
    // Lengths are measured in bytes of the candidate match.
    pub(super) min_bits_per_byte: f32,
    pub(super) min_len: usize,
    pub(super) max_len: usize,
}

/// Compiled rule representation used during scanning.
///
/// This keeps precompiled regexes and optional two-phase data to minimize
/// work in the hot path.
///
/// # Invariants
/// - All fields are derived from a validated `RuleSpec`.
/// - Optional gates (`confirm_all`, `keywords`, `entropy`, `two_phase`) are
///   internally consistent with `variant` indexing.
#[derive(Clone, Debug)]
pub(super) struct RuleCompiled {
    pub(super) name: &'static str,
    pub(super) radius: usize,
    pub(super) validator: ValidatorKind,
    pub(super) must_contain: Option<&'static [u8]>,
    // Derived AND gate: all literals must appear in the window before regex.
    pub(super) confirm_all: Option<ConfirmAllCompiled>,
    pub(super) keywords: Option<KeywordsCompiled>,
    pub(super) entropy: Option<EntropyCompiled>,
    pub(super) re: Regex,
    pub(super) two_phase: Option<TwoPhaseCompiled>,
}

// --------------------------
// Compile helpers
// --------------------------

/// Compile a validated rule spec into the runtime representation.
///
/// `confirm_all` is intentionally left `None` and should be filled by the
/// caller after confirm-all literals are derived.
pub(super) fn compile_rule(spec: &RuleSpec) -> RuleCompiled {
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

/// Compile the derived "confirm all" gate from mandatory literal islands.
///
/// The longest literal becomes the `primary` selector; the remaining literals
/// are packed into AND-gated tables for the fast memmem pass.
pub(super) fn compile_confirm_all(mut confirm_all: Vec<Vec<u8>>) -> Option<ConfirmAllCompiled> {
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

/// Add a target to the anchor map keyed by a borrowed pattern.
pub(super) fn add_pat_raw(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: &[u8], target: Target) {
    if let Some(existing) = map.get_mut(pat) {
        existing.push(target);
    } else {
        map.insert(pat.to_vec(), vec![target]);
    }
}

/// Add a target to the anchor map keyed by an owned pattern.
pub(super) fn add_pat_owned(
    map: &mut AHashMap<Vec<u8>, Vec<Target>>,
    pat: Vec<u8>,
    target: Target,
) {
    if let Some(existing) = map.get_mut(pat.as_slice()) {
        existing.push(target);
    } else {
        map.insert(pat, vec![target]);
    }
}

/// Flatten a pattern->targets map into packed arrays used by the scan loop.
///
/// The returned `patterns` order is the map's iteration order and is therefore
/// not stable. The accompanying `offsets` vector provides the target slice for
/// each pattern id.
pub(super) fn map_to_patterns(
    map: AHashMap<Vec<u8>, Vec<Target>>,
) -> (Vec<Vec<u8>>, Vec<Target>, Vec<u32>) {
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

/// Convert ASCII bytes to UTF-16LE encoding (byte -> code unit).
pub(super) fn utf16le_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0);
    }
    out
}

/// Convert ASCII bytes to UTF-16BE encoding (byte -> code unit).
pub(super) fn utf16be_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(0);
        out.push(b);
    }
    out
}
