//! Internal compiled rule representation.
//!
//! This module defines the data layout the scan loop consumes: anchor variants,
//! packed literal tables, and precompiled gates derived from a validated
//! [`RuleSpec`]. The emphasis is on cache-friendly layouts and variant-indexed
//! tables so the hot path avoids allocation and encoding conversion.
//!
//! ## Two-tier compilation
//!
//! Compilation is split into two tiers to keep `RuleCompiled` compact:
//!
//! 1. [`compile_rule`] produces a `RuleCompiled` with all gate indices set to
//!    `None`, plus a [`CompiledGates`] bag holding the heavyweight gate objects.
//! 2. The caller (`Engine::new`) pools each gate into a type-specific `Vec` on
//!    `Engine` and patches the corresponding `Option<u32>` index back onto the
//!    rule. This indirection means `RuleCompiled` stays small enough for
//!    cache-friendly iteration while the (rarely accessed) gate data lives in
//!    separate, densely packed pools.
//!
//! `confirm_all` is a special case: its literals are derived from regex analysis
//! *after* `compile_rule` returns, so the caller must build it separately via
//! [`compile_confirm_all`] and pool it in a second pass.
//!
//! ## Notes
//!
//! - UTF-16 helpers in this module are ASCII-only expansions (1 byte → 1 code
//!   unit) used for literal gating. They are not general-purpose UTF-16 encoders.
//! - Variant ordering is stable and reused for packed arrays and bit layouts.

use crate::api::{LocalContextSpec, OfflineValidationSpec, RuleSpec};
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
/// Layout (low bits): `[variant (2 bits)] [rule_id (30 bits)]`
///
/// # Invariants
/// - `rule_id` fits in 30 bits (max ~1 billion rules).
/// - The low-bit layout is stable and must match `variant()`.
///
/// # Ordering
/// `Ord` is derived on the raw `u32`, which sorts by (rule_id, variant).
/// [`map_to_patterns`] sorts each pattern's target list by this order to
/// ensure deterministic output across compilations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Target(u32);

impl Target {
    const VARIANT_MASK: u32 = 0b11;
    const VARIANT_SHIFT: u32 = 2;

    /// Pack a (rule_id, variant) into a single `u32`.
    pub(super) fn new(rule_id: u32, variant: Variant) -> Self {
        assert!(rule_id <= (u32::MAX >> Self::VARIANT_SHIFT));
        Self((rule_id << Self::VARIANT_SHIFT) | variant.idx() as u32)
    }

    /// Extract the rule index from the packed representation.
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
}

// --------------------------
// Pattern storage
// --------------------------

/// Packed byte patterns with an offset table (immutable after construction).
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm patterns contiguous for cache-friendly memmem checks (both ANY and
/// ALL gates).
///
/// # Accessing patterns
///
/// Pattern `i` is `bytes[offsets[i] as usize .. offsets[i+1] as usize]`.
/// The number of patterns is `offsets.len() - 1`. Callers in `buffer_scan.rs`
/// and `window_validate.rs` iterate this way rather than through a method,
/// because the memmem inner loops inline the slice indexing directly.
///
/// # Invariants
/// - `offsets[0] == 0` and the last offset equals `bytes.len()`.
/// - `offsets` is monotonically non-decreasing.
/// - `bytes.len() <= u32::MAX`.
/// - Empty pattern sets are valid: `offsets == [0]`, `bytes == []`.
///
/// # Performance
/// - Contiguous storage enables cache-friendly `memmem` gates without
///   per-window allocations.
/// - Uses `Box<[T]>` instead of `Vec<T>` since data is immutable after
///   engine compilation, saving 8 bytes per field (no capacity word).
#[derive(Clone, Debug)]
pub(super) struct PackedPatterns {
    pub(super) bytes: Box<[u8]>,
    pub(super) offsets: Box<[u32]>,
}

// Compile-time size guard: 2 × Box<[T]> = 2 × 16 = 32 bytes.
const _: () = assert!(std::mem::size_of::<PackedPatterns>() == 32);

/// Builder for [`PackedPatterns`] that accumulates patterns using `Vec`
/// internally, then freezes into boxed slices.
///
/// # Invariants maintained during building
/// - `offsets[0] == 0` (established at construction).
/// - Each `push_*` call appends bytes and records a new offset.
/// - `bytes.len() <= u32::MAX` (asserted on each push).
pub(super) struct PackedPatternsBuilder {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl PackedPatternsBuilder {
    /// Create a builder with capacities sized for fast filling.
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

    /// Freeze into an immutable `PackedPatterns`.
    pub(super) fn build(self) -> PackedPatterns {
        debug_assert_eq!(
            *self.offsets.last().unwrap() as usize,
            self.bytes.len(),
            "PackedPatternsBuilder: last offset must equal bytes length"
        );
        PackedPatterns {
            bytes: self.bytes.into_boxed_slice(),
            offsets: self.offsets.into_boxed_slice(),
        }
    }
}

// --------------------------
// Compiled rule gates
// --------------------------

/// Two-phase rule data compiled per variant for fast confirm checks.
///
/// The two-phase algorithm reduces regex work by narrowing candidate windows:
///
/// 1. **Seed phase**: Vectorscan emits a seed window of `seed_radius` bytes
///    around each anchor hit.
/// 2. **Confirm phase**: the seed window is checked for at least one `confirm`
///    pattern via memmem (ANY semantics). Windows that lack a confirm pattern
///    are discarded without running the regex.
/// 3. **Expand phase**: confirmed seeds are widened to `full_radius` to give
///    the regex enough context for a full match.
///
/// # Guarantees
/// - `confirm` entries are encoded per variant and indexed by `Variant::idx()`.
///
/// # Invariants
/// - `seed_radius <= full_radius`.
/// - Radii and pattern lengths are validated by `RuleSpec::assert_valid`.
#[derive(Clone, Debug)]
pub(super) struct TwoPhaseCompiled {
    pub(super) seed_radius: usize,
    pub(super) full_radius: usize,

    /// Confirm patterns per variant, indexed by [`Variant::idx()`].
    ///
    /// Raw byte patterns for `Variant::Raw`, UTF-16-expanded patterns for
    /// `Variant::Utf16Le` and `Variant::Utf16Be`.
    pub(super) confirm: [PackedPatterns; 3],
}

/// Keyword gate compiled per variant for fast "any keyword" checks.
///
/// # Guarantees
/// - `any` is encoded per variant and indexed by `Variant::idx()`.
#[derive(Clone, Debug)]
pub(super) struct KeywordsCompiled {
    /// Keyword patterns per variant, indexed by [`Variant::idx()`].
    ///
    /// Mirrors anchor variant handling so keyword gating behaves consistently
    /// across encodings and avoids per-window UTF-16 conversions.
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
    pub(super) primary: [Option<Box<[u8]>>; 3],
    pub(super) rest: [PackedPatterns; 3],
}

/// Entropy gate parameters compiled into a rule.
///
/// Copied from the validated [`crate::api::EntropySpec`] at compile time to
/// avoid repeated lookups through the rule spec during scanning. See
/// `EntropySpec` for the entropy algorithm description.
///
/// # Invariants
/// - Values are validated by `RuleSpec::assert_valid`.
#[derive(Clone, Copy, Debug)]
pub(super) struct EntropyCompiled {
    /// Minimum Shannon entropy threshold in bits per byte.
    ///
    /// Candidates below this threshold are rejected as low-entropy
    /// (e.g., repeated characters, sequential digits).
    pub(super) min_bits_per_byte: f32,
    /// Minimum candidate length in bytes for the entropy check to apply.
    pub(super) min_len: usize,
    /// Maximum candidate length in bytes for the entropy check to apply.
    ///
    /// Also determines the size of the pre-computed `ln(i)/ln(2)` table
    /// in [`Engine::entropy_log2`](super::core::Engine).
    pub(super) max_len: usize,
}

/// Hot compiled rule representation used during scanning.
///
/// This keeps precompiled regexes and optional gate pool indices to minimize
/// work in the hot path. Large gate structures are stored in pool vectors on
/// `Engine` and accessed via `Option<u32>` indices here, keeping this struct
/// compact for cache-friendly iteration.
///
/// Cold per-rule metadata (e.g., rule name) is stored in the parallel
/// [`RuleCold`] array at `Engine::rules_cold`, indexed identically so that
/// `rules_hot[i]` and `rules_cold[i]` always describe the same rule.
///
/// # Field layout rationale
///
/// Fields are ordered by access frequency in the scan loop:
///
/// 1. **Every candidate**: `re`, `must_contain`, `needs_assignment_shape_check`
///    — touched for every merged window to decide if the regex runs.
/// 2. **Post-match only**: `secret_group` — read only when the regex matches.
/// 3. **Gate indices**: `confirm_all`, `keywords`, `value_suppressors`,
///    `entropy`, `local_context`, `two_phase`, `offline_validation` —
///    dereferenced through `Engine` pool accessors only when the
///    corresponding gate is present (`Some`). Most rules have 0–2 gates,
///    so these are cold for the majority of candidates.
///
/// # Gate pool access
///
/// Gate indices dereference through the corresponding pool on `Engine`:
///
/// | Field          | Pool on `Engine`          |
/// |----------------|---------------------------|
/// | `confirm_all`  | `confirm_all_gates`       |
/// | `keywords`     | `keyword_gates`           |
/// | `value_suppressors` | `value_suppressor_gates` |
/// | `entropy`      | `entropy_gates`           |
/// | `local_context`| `local_context_gates`     |
/// | `two_phase`    | `two_phase_gates`         |
/// | `offline_validation` | `offline_validation_gates` |
///
/// # Invariants
/// - All fields are derived from a validated `RuleSpec`.
/// - Gate indices, when `Some`, are valid into the corresponding pool vectors.
/// - `Option<u32>` is 8 bytes (niche optimization does not apply here because
///   `u32` has no niche — all bit patterns are valid values).
#[derive(Clone, Debug)]
pub(super) struct RuleCompiled {
    pub(super) re: Regex,
    pub(super) must_contain: Option<&'static [u8]>,
    pub(super) needs_assignment_shape_check: bool,
    pub(super) secret_group: Option<u16>,
    // Gate pool indices — dereference through Engine pool vectors.
    // See the "Gate pool access" table in the struct-level doc.
    pub(super) confirm_all: Option<u32>,
    pub(super) keywords: Option<u32>,
    pub(super) value_suppressors: Option<u32>,
    pub(super) entropy: Option<u32>,
    pub(super) local_context: Option<u32>,
    pub(super) two_phase: Option<u32>,
    pub(super) offline_validation: Option<u32>,
}

/// Cold rule metadata used outside the validation hot path.
///
/// Kept in a parallel array with [`RuleCompiled`] (`rules_hot`) to keep
/// scan-loop iteration focused on fields needed for gating and regex checks.
#[derive(Clone, Copy, Debug)]
pub(super) struct RuleCold {
    pub(super) name: &'static str,
}

// Compile-time size guard: gate index is 8 bytes (Option<u32> without niche).
const _: () = assert!(std::mem::size_of::<Option<u32>>() == 8);

// --------------------------
// Compile helpers
// --------------------------

/// Compiled gates returned alongside `RuleCompiled` for pooling into `Engine`.
///
/// `confirm_all` is intentionally absent here: its literals are derived from
/// regex analysis *after* compilation, so the caller builds it separately via
/// [`compile_confirm_all`] and adds it to `Engine::confirm_all_gates`.
pub(super) struct CompiledGates {
    pub(super) two_phase: Option<TwoPhaseCompiled>,
    pub(super) keywords: Option<KeywordsCompiled>,
    pub(super) value_suppressors: Option<PackedPatterns>,
    pub(super) entropy: Option<EntropyCompiled>,
    pub(super) local_context: Option<LocalContextSpec>,
    pub(super) offline_validation: Option<OfflineValidationSpec>,
}

/// Compile a validated rule spec into the runtime representation.
///
/// Returns the compact `RuleCompiled` (with `None` gate indices) and the
/// compiled gate objects. The caller is responsible for pooling gates into
/// `Engine` vectors and patching the indices on `RuleCompiled`.
///
/// `confirm_all` is intentionally left `None` and should be filled by the
/// caller after confirm-all literals are derived.
pub(super) fn compile_rule(spec: &RuleSpec) -> (RuleCompiled, CompiledGates) {
    let two_phase = spec.two_phase.as_ref().map(|tp| {
        let count = tp.confirm_any.len();
        let raw_bytes = tp.confirm_any.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);
        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
        let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

        for &p in tp.confirm_any {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        TwoPhaseCompiled {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm: [raw.build(), le.build(), be.build()],
        }
    });

    let keywords = spec.keywords_any.map(|kws| {
        let count = kws.len();
        let raw_bytes = kws.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);

        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
        let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

        for &p in kws {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        KeywordsCompiled {
            any: [raw.build(), le.build(), be.build()],
        }
    });

    // Value suppressors only need raw patterns: they are checked against
    // extracted secret bytes (post-regex), which are always in decoded byte
    // space, never raw UTF-16 window bytes.
    let value_suppressors = spec.value_suppressors_any.map(|suppressors| {
        let count = suppressors.len();
        let raw_bytes = suppressors.iter().map(|p| p.len()).sum::<usize>();
        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        for &p in suppressors {
            raw.push_raw(p);
        }
        raw.build()
    });

    let entropy = spec.entropy.as_ref().map(|e| EntropyCompiled {
        min_bits_per_byte: e.min_bits_per_byte,
        min_len: e.min_len,
        max_len: e.max_len,
    });

    // Enable assignment-shape precheck for rules with assignment-pattern regexes.
    // Currently only `generic-api-key` benefits from this optimization.
    let needs_assignment_shape_check = spec.name == "generic-api-key";

    let rule = RuleCompiled {
        re: spec.re.clone(),
        must_contain: spec.must_contain,
        needs_assignment_shape_check,
        secret_group: spec.secret_group,
        confirm_all: None,
        keywords: None,
        value_suppressors: None,
        entropy: None,
        local_context: None,
        two_phase: None,
        offline_validation: None,
    };

    let gates = CompiledGates {
        two_phase,
        keywords,
        value_suppressors,
        entropy,
        local_context: spec.local_context,
        offline_validation: spec.offline_validation,
    };

    (rule, gates)
}

/// Compile the derived "confirm all" gate from mandatory literal islands.
///
/// Returns `None` if `confirm_all` is empty (no mandatory literals derived).
///
/// The longest literal becomes the `primary` selector — checked first via a
/// single memmem search for early rejection. The remaining literals are packed
/// into AND-gated tables (all must match) for the fast memmem pass.
pub(super) fn compile_confirm_all(mut confirm_all: Vec<Vec<u8>>) -> Option<ConfirmAllCompiled> {
    if confirm_all.is_empty() {
        return None;
    }

    // Sort longest-first so the primary literal is maximally selective.
    confirm_all.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let primary = confirm_all.remove(0);
    let primary_raw: Option<Box<[u8]>> = Some(primary.clone().into_boxed_slice());
    let primary_le: Option<Box<[u8]>> = Some(utf16le_bytes(&primary).into_boxed_slice());
    let primary_be: Option<Box<[u8]>> = Some(utf16be_bytes(&primary).into_boxed_slice());

    let count = confirm_all.len();
    let raw_bytes = confirm_all.iter().map(|p| p.len()).sum::<usize>();
    let utf16_bytes = raw_bytes.saturating_mul(2);
    let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
    let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
    let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

    for p in confirm_all {
        raw.push_raw(&p);
        le.push_utf16le(&p);
        be.push_utf16be(&p);
    }

    Some(ConfirmAllCompiled {
        primary: [primary_raw, primary_le, primary_be],
        rest: [raw.build(), le.build(), be.build()],
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

/// Flatten a pattern→targets map into packed arrays used by the scan loop.
///
/// Returns `(patterns, flat_targets, offsets)` where:
/// - `patterns[i]` is the `i`-th anchor pattern (sorted lexicographically),
/// - `flat_targets[offsets[i]..offsets[i+1]]` are the targets for pattern `i`,
/// - `offsets` has length `patterns.len() + 1` (prefix-sum layout).
///
/// # Why deterministic ordering matters
///
/// Patterns are sorted by bytes and each pattern's target list is sorted by
/// packed `Target` value. This guarantees stable pattern-id assignment across
/// compilations, which is critical because Vectorscan pattern ids are
/// positional — the same pattern must always get the same id for the
/// prefilter callback to route hits to the correct rule/variant accumulator.
pub(super) fn map_to_patterns(
    map: AHashMap<Vec<u8>, Vec<Target>>,
) -> (Vec<Vec<u8>>, Vec<Target>, Vec<u32>) {
    let mut entries: Vec<(Vec<u8>, Vec<Target>)> = map.into_iter().collect();
    entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    let mut flat: Vec<Target> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(entries.len().saturating_add(1));
    offsets.push(0);

    let mut total_targets = 0usize;
    for (_, ts) in entries.iter() {
        total_targets = total_targets.saturating_add(ts.len());
    }
    flat.reserve(total_targets);

    for (p, mut ts) in entries {
        ts.sort_unstable();
        patterns.push(p);
        flat.extend(ts);
        assert!(flat.len() <= u32::MAX as usize);
        // Prefix-sum offsets: each pattern id maps to flat[start..end].
        offsets.push(flat.len() as u32);
    }

    (patterns, flat, offsets)
}

/// Convert ASCII bytes to UTF-16LE encoding (one byte → one code unit).
///
/// Input is assumed to be ASCII (bytes 0x00–0x7F). Non-ASCII input produces
/// technically invalid UTF-16 but is still useful for byte-level literal matching.
pub(super) fn utf16le_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0);
    }
    out
}

/// Convert ASCII bytes to UTF-16BE encoding (one byte → one code unit).
///
/// Input is assumed to be ASCII (bytes 0x00–0x7F). Non-ASCII input produces
/// technically invalid UTF-16 but is still useful for byte-level literal matching.
pub(super) fn utf16be_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(0);
        out.push(b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{RuleSpec, ValidatorKind};
    use regex::bytes::Regex;

    fn unpack_patterns(pats: &PackedPatterns) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let count = pats.offsets.len().saturating_sub(1);
        for i in 0..count {
            let start = pats.offsets[i] as usize;
            let end = pats.offsets[i + 1] as usize;
            out.push(pats.bytes[start..end].to_vec());
        }
        out
    }

    fn test_rule_spec(value_suppressors_any: Option<&'static [&'static [u8]]>) -> RuleSpec {
        RuleSpec {
            name: "compile-rule-test",
            anchors: &[b"TOK_"],
            radius: 32,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any,
            entropy: None,
            local_context: None,
            secret_group: Some(1),
            offline_validation: None,
            re: Regex::new(r"TOK_([A-Z0-9]{4})").unwrap(),
        }
    }

    #[test]
    fn map_to_patterns_sorts_patterns_and_targets() {
        let mut map: AHashMap<Vec<u8>, Vec<Target>> = AHashMap::new();
        map.insert(
            b"b".to_vec(),
            vec![Target::new(2, Variant::Raw), Target::new(1, Variant::Raw)],
        );
        map.insert(b"a".to_vec(), vec![Target::new(3, Variant::Utf16Le)]);
        map.insert(b"aa".to_vec(), vec![Target::new(1, Variant::Raw)]);

        let (patterns, flat, offsets) = map_to_patterns(map);

        assert_eq!(patterns, vec![b"a".to_vec(), b"aa".to_vec(), b"b".to_vec()]);
        assert_eq!(offsets, vec![0, 1, 2, 4]);
        assert_eq!(
            flat,
            vec![
                Target::new(3, Variant::Utf16Le),
                Target::new(1, Variant::Raw),
                Target::new(1, Variant::Raw),
                Target::new(2, Variant::Raw),
            ]
        );
    }

    #[test]
    fn compile_rule_builds_value_suppressor_patterns() {
        static SUPPRESSORS: &[&[u8]] = &[b"EXAMPLE", b"DUMMY_TOKEN"];
        let spec = test_rule_spec(Some(SUPPRESSORS));

        let (rule, gates) = compile_rule(&spec);
        assert!(rule.value_suppressors.is_none());
        let packed = gates
            .value_suppressors
            .as_ref()
            .expect("value suppressors should be compiled");
        assert_eq!(
            unpack_patterns(packed),
            vec![b"EXAMPLE".to_vec(), b"DUMMY_TOKEN".to_vec()]
        );
    }

    #[test]
    fn compile_rule_without_value_suppressors_has_no_gate() {
        let spec = test_rule_spec(None);
        let (rule, gates) = compile_rule(&spec);

        assert!(rule.value_suppressors.is_none());
        assert!(gates.value_suppressors.is_none());
    }
}
