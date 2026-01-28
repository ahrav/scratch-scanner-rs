//! Fast validators for anchor hits.
//!
//! # Scope
//! These helpers validate candidate matches directly against the raw byte
//! buffer when an anchor automaton reports a hit. The fast path can emit a
//! finding without building windows or running the full regex engine.
//!
//! # Invariants
//! - `anchor_start` and `anchor_end` are raw byte indices with
//!   `anchor_start <= anchor_end <= buf.len()`.
//! - The anchor hit is match-start aligned in the raw representation (the
//!   regex match starts at `anchor_start`).
//! - Prefix bytes are already validated by the anchor automaton; these
//!   validators only check tail bytes and delimiter semantics.
//! - Validation never reads outside `buf`; any out-of-bounds access yields
//!   `None`.
//!
//! # Semantics
//! - Word boundaries and character classes mirror `regex::bytes`: ASCII-only
//!   word bytes and ASCII classes, with non-ASCII treated as non-word.
//! - Tail charset checks are ASCII-only; non-ASCII bytes never match.
//! - Tail bytes are constrained by `TailCharset`.
//! - `DelimAfter::GitleaksTokenTerminator` requires a terminator byte (or
//!   end-of-input). When present, the returned span includes the terminator.
//!
//! # Algorithm sketch
//! - Fixed-length tails: optional word-boundary check, exact-length tail scan,
//!   optional delimiter check.
//! - Bounded tails: scan forward to the longest run within `max_tail`; ensure
//!   `min_tail`, then (if a delimiter is required) backtrack to the longest tail
//!   followed by a terminator, mirroring regex backtracking behavior.
//! - AWS access keys: verify the known prefixes and that the 16-byte tail is
//!   uppercase alphanumeric, yielding a 20-byte match.
//!
//! # Performance
//! - Character classification uses a 256-byte LUT for O(1) lookup.
//! - Work is linear in the scanned tail length; bounded validation can add a
//!   second linear backtrack when a delimiter is required.
//!
//! # Failure modes
//! - Returns `None` when anchor indices are invalid or out of bounds.
//! - Returns `None` when the tail violates charset or length constraints.
//! - Bounded validation returns `None` when `anchor_end == buf.len()` (no tail).
//! - Missing required delimiters cause validation to fail.

use crate::api::{DelimAfter, TailCharset, ValidatorKind};
use std::ops::Range;

// -----------------------------------------------------------------------------
// Lookup table for byte classification
// -----------------------------------------------------------------------------
//
// Each bit in the LUT entry indicates membership in a character class.
// This allows O(1) classification with a single memory lookup + bitwise AND.

/// Bit flag: ASCII word byte `[A-Za-z0-9_]` per regex semantics.
const WORD_BYTE: u8 = 1 << 0;
/// Bit flag: uppercase alphanumeric `[A-Z0-9]`.
const UPPER_ALNUM: u8 = 1 << 1;
/// Bit flag: lowercase alphanumeric `[a-z0-9]`.
const LOWER_ALNUM: u8 = 1 << 2;
/// Bit flag: dash or underscore `[-_]`.
const DASH_UNDER: u8 = 1 << 3;
/// Bit flag: Sendgrid66Set extra chars `[=._]` (dash/underscore via DASH_UNDER).
const SENDGRID_EXT: u8 = 1 << 4;
/// Bit flag: Databricks hex-ish `[a-hA-H]` (digits covered by UPPER_ALNUM/LOWER_ALNUM).
const DATABRICKS_HEX: u8 = 1 << 5;
/// Bit flag: Base64 standard extra chars `[+/]`.
const BASE64_EXTRA: u8 = 1 << 6;
/// Bit flag: Gitleaks token terminator `['"|` \t\n\r\x0B\x0C]`.
const GITLEAKS_TERM: u8 = 1 << 7;

/// Build the validator LUT at compile time.
const fn build_validator_lut() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        let mut flags = 0u8;

        // WORD_BYTE: [A-Za-z0-9_]
        let is_upper = b >= b'A' && b <= b'Z';
        let is_lower = b >= b'a' && b <= b'z';
        let is_digit = b >= b'0' && b <= b'9';
        let is_underscore = b == b'_';
        if is_upper || is_lower || is_digit || is_underscore {
            flags |= WORD_BYTE;
        }

        // UPPER_ALNUM: [A-Z0-9]
        if is_upper || is_digit {
            flags |= UPPER_ALNUM;
        }

        // LOWER_ALNUM: [a-z0-9]
        if is_lower || is_digit {
            flags |= LOWER_ALNUM;
        }

        // DASH_UNDER: [-_]
        if b == b'-' || is_underscore {
            flags |= DASH_UNDER;
        }

        // SENDGRID_EXT: [=.]
        if b == b'=' || b == b'.' {
            flags |= SENDGRID_EXT;
        }

        // DATABRICKS_HEX: [a-hA-H] (case-insensitive hex letters through H)
        if (b >= b'a' && b <= b'h') || (b >= b'A' && b <= b'H') {
            flags |= DATABRICKS_HEX;
        }

        // BASE64_EXTRA: [+/]
        if b == b'+' || b == b'/' {
            flags |= BASE64_EXTRA;
        }

        // GITLEAKS_TERM: ['"|` \t\n\r\x0B\x0C]
        if b == b'\''
            || b == b'"'
            || b == b'|'
            || b == b'`'
            || b == b' '
            || b == b'\t'
            || b == b'\n'
            || b == b'\r'
            || b == 0x0B
            || b == 0x0C
        {
            flags |= GITLEAKS_TERM;
        }

        table[i] = flags;
        i += 1;
    }
    table
}

/// Precomputed byte classification table for validator functions.
static VALIDATOR_LUT: [u8; 256] = build_validator_lut();

impl ValidatorKind {
    /// Returns true if this validator is enabled (i.e., not `None`).
    #[inline]
    pub(super) fn is_enabled(self) -> bool {
        !matches!(self, ValidatorKind::None)
    }

    /// Validate a rule at a raw anchor hit.
    ///
    /// `anchor_start` and `anchor_end` are the raw byte indices returned by the
    /// anchor automaton. On success, returns the matched span in raw bytes.
    pub(super) fn validate_raw_at_anchor(
        self,
        buf: &[u8],
        anchor_start: usize,
        anchor_end: usize,
    ) -> Option<Range<usize>> {
        if anchor_start > anchor_end || anchor_end > buf.len() {
            return None;
        }
        match self {
            ValidatorKind::None => None,
            ValidatorKind::AwsAccessKey => validate_aws_access_key(buf, anchor_start, anchor_end),
            ValidatorKind::PrefixFixed {
                tail_len,
                tail,
                require_word_boundary_before,
                delim_after,
            } => validate_prefix_fixed(
                buf,
                anchor_start,
                anchor_end,
                tail_len as usize,
                PrefixChecks {
                    tail,
                    require_word_boundary_before,
                    delim_after,
                },
            ),
            ValidatorKind::PrefixBounded {
                min_tail,
                max_tail,
                tail,
                require_word_boundary_before,
                delim_after,
            } => validate_prefix_bounded(
                buf,
                anchor_start,
                anchor_end,
                min_tail as usize,
                max_tail as usize,
                PrefixChecks {
                    tail,
                    require_word_boundary_before,
                    delim_after,
                },
            ),
        }
    }
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    // LUT lookup: single memory access + bitwise AND.
    // `regex::bytes` defines word bytes as ASCII `[A-Za-z0-9_]`.
    VALIDATOR_LUT[b as usize] & WORD_BYTE != 0
}

/// Returns true if there is an ASCII word boundary immediately before `start`.
///
/// `start == 0` is treated as a boundary (even for empty buffers). Other
/// out-of-range positions (`start > 0 && start >= buf.len()`) yield `false`.
#[inline]
fn has_word_boundary_before(buf: &[u8], start: usize) -> bool {
    if start == 0 || start >= buf.len() {
        return start == 0;
    }
    let prev = buf[start - 1];
    let cur = buf[start];
    is_word_byte(prev) != is_word_byte(cur)
}

/// Returns true for bytes that terminate gitleaks-style tokens.
#[inline]
fn is_gitleaks_token_terminator(b: u8) -> bool {
    // LUT lookup: single memory access + bitwise AND.
    VALIDATOR_LUT[b as usize] & GITLEAKS_TERM != 0
}

/// Apply delimiter rules and return the match end.
///
/// `tail_end` is the end of the validated tail (not including any delimiter).
/// For delimiter checks that read `buf`, out-of-range indices yield `None`.
/// When `delim` is `None`, the caller is responsible for `tail_end <= buf.len()`.
///
/// When a gitleaks terminator is required and present, the returned end
/// includes the terminator byte (`tail_end + 1`).
#[inline]
fn match_end_with_delim(buf: &[u8], tail_end: usize, delim: DelimAfter) -> Option<usize> {
    match delim {
        DelimAfter::None => Some(tail_end),
        DelimAfter::GitleaksTokenTerminator => {
            if tail_end == buf.len() {
                return Some(tail_end);
            }
            match buf.get(tail_end) {
                Some(&b) if is_gitleaks_token_terminator(b) => Some(tail_end + 1),
                _ => None,
            }
        }
    }
}

/// Returns true if `b` is in `charset` under ASCII-only semantics.
///
/// Non-ASCII bytes never match any charset.
#[inline]
fn tail_matches_charset(b: u8, charset: TailCharset) -> bool {
    // LUT-based classification: single lookup + bitwise operations.
    let flags = VALIDATOR_LUT[b as usize];
    match charset {
        // [A-Z0-9]
        TailCharset::UpperAlnum => flags & UPPER_ALNUM != 0,
        // [A-Za-z0-9] = UPPER_ALNUM | LOWER_ALNUM (digits are in both)
        TailCharset::Alnum => flags & (UPPER_ALNUM | LOWER_ALNUM) != 0,
        // [a-z0-9]
        TailCharset::LowerAlnum => flags & LOWER_ALNUM != 0,
        // [A-Za-z0-9_-] = Alnum | DASH_UNDER
        TailCharset::AlnumDashUnderscore => flags & (UPPER_ALNUM | LOWER_ALNUM | DASH_UNDER) != 0,
        // [A-Za-z0-9=_\-.]
        TailCharset::Sendgrid66Set => {
            flags & (UPPER_ALNUM | LOWER_ALNUM | DASH_UNDER | SENDGRID_EXT) != 0
        }
        // [a-hA-H0-9] - hex through H, case-insensitive
        TailCharset::DatabricksSet => {
            // Digits are in both UPPER_ALNUM and LOWER_ALNUM; hex letters a-h/A-H are in DATABRICKS_HEX
            let is_digit = b.is_ascii_digit();
            is_digit || flags & DATABRICKS_HEX != 0
        }
        // [A-Za-z0-9+/]
        TailCharset::Base64Std => flags & (UPPER_ALNUM | LOWER_ALNUM | BASE64_EXTRA) != 0,
    }
}

/// Shared configuration for prefix-based validators.
#[derive(Clone, Copy, Debug)]
struct PrefixChecks {
    /// Character set to apply to tail bytes immediately after the anchor.
    tail: TailCharset,
    /// Whether an ASCII word boundary must appear at `anchor_start`.
    require_word_boundary_before: bool,
    /// Optional delimiter rule applied at the end of the tail.
    delim_after: DelimAfter,
}

/// Validate a fixed-length tail immediately following the anchor.
///
/// Returns the matched span on success. This enforces an optional word boundary
/// before the anchor, validates that the tail length is exactly `tail_len`, and
/// applies any delimiter requirement after the tail.
///
/// Guarantees / invariants:
/// - `anchor_start <= anchor_end <= buf.len()`.
/// - The prefix bytes were already matched by the anchor automaton.
///
/// Complexity: O(`tail_len`) in the length of the tail.
fn validate_prefix_fixed(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    tail_len: usize,
    checks: PrefixChecks,
) -> Option<Range<usize>> {
    if checks.require_word_boundary_before && !has_word_boundary_before(buf, anchor_start) {
        return None;
    }

    let tail_start = anchor_end;
    let tail_end = tail_start.checked_add(tail_len)?;
    let tail_bytes = buf.get(tail_start..tail_end)?;

    if !tail_bytes
        .iter()
        .all(|&b| tail_matches_charset(b, checks.tail))
    {
        return None;
    }

    let match_end = match_end_with_delim(buf, tail_end, checks.delim_after)?;
    Some(anchor_start..match_end)
}

/// Validate a bounded-length tail following the anchor.
///
/// The tail is scanned up to `max_tail`, and the run must be at least
/// `min_tail` bytes. When a delimiter is required, this backtracks to the
/// longest tail that is immediately followed by a terminator or end-of-input,
/// mirroring regex backtracking semantics.
///
/// Guarantees / invariants:
/// - `anchor_start <= anchor_end <= buf.len()`.
/// - The prefix bytes were already matched by the anchor automaton.
/// - Empty tails are not accepted: `anchor_end == buf.len()` always fails.
///
/// Complexity: O(`max_tail`) for the scan, plus O(`max_tail`) backtracking when
/// a delimiter is required.
fn validate_prefix_bounded(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    min_tail: usize,
    max_tail: usize,
    checks: PrefixChecks,
) -> Option<Range<usize>> {
    if min_tail > max_tail {
        return None;
    }
    if checks.require_word_boundary_before && !has_word_boundary_before(buf, anchor_start) {
        return None;
    }

    let tail_start = anchor_end;
    if tail_start >= buf.len() {
        return None;
    }

    // Single bounds check: compute the maximum safe index upfront,
    // then iterate over a slice without per-iteration bounds checks.
    let max_idx = tail_start.saturating_add(max_tail).min(buf.len());
    let tail_slice = &buf[tail_start..max_idx];

    let mut run_len = 0usize;
    for &b in tail_slice {
        if !tail_matches_charset(b, checks.tail) {
            break;
        }
        run_len += 1;
    }

    if run_len < min_tail {
        return None;
    }

    let max_len = run_len.min(max_tail);
    match checks.delim_after {
        DelimAfter::None => Some(anchor_start..(tail_start + max_len)),
        DelimAfter::GitleaksTokenTerminator => {
            // Backtrack to the longest tail that is immediately followed by a
            // valid terminator (or end-of-input), mirroring regex backtracking.
            for len in (min_tail..=max_len).rev() {
                let tail_end = tail_start + len;
                if let Some(match_end) = match_end_with_delim(buf, tail_end, checks.delim_after) {
                    return Some(anchor_start..match_end);
                }
            }
            None
        }
    }
}

/// Returns true if byte is uppercase alphanumeric [A-Z0-9].
#[inline]
fn is_upper_alnum(b: u8) -> bool {
    VALIDATOR_LUT[b as usize] & UPPER_ALNUM != 0
}

/// Validate an AWS access key anchored at a known prefix.
///
/// The anchor length determines which prefixes are allowed (3-byte or 4-byte),
/// and the total match length must be exactly 20 bytes. The prefix bytes are
/// assumed to be validated by the anchor automaton; this function verifies the
/// tail bytes are uppercase alphanumeric.
///
/// Guarantees / invariants:
/// - `anchor_start <= anchor_end <= buf.len()`.
/// - The anchor slice corresponds to a valid AWS prefix pattern.
///
/// Complexity: O(20) with a fixed-sized byte scan.
fn validate_aws_access_key(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
) -> Option<Range<usize>> {
    let prefix_len = anchor_end.checked_sub(anchor_start)?;
    let end = anchor_start.checked_add(20)?;
    let block = buf.get(anchor_start..end)?;

    match prefix_len {
        // A3T + [A-Z0-9] + 16 tail chars
        3 => {
            if !is_upper_alnum(block[3]) {
                return None;
            }
            if !block[4..].iter().all(|&b| is_upper_alnum(b)) {
                return None;
            }
        }
        // AKIA / AIDA / ... + 16 tail chars
        4 => {
            if !block[4..].iter().all(|&b| is_upper_alnum(b)) {
                return None;
            }
        }
        _ => return None,
    }

    Some(anchor_start..end)
}

// -----------------------------------------------------------------------------
// Benchmark exports
// -----------------------------------------------------------------------------

/// Benchmark wrapper: classify a byte as a word byte.
#[cfg(feature = "bench")]
#[inline]
pub fn bench_is_word_byte(b: u8) -> bool {
    is_word_byte(b)
}

/// Benchmark wrapper: check if a byte matches a tail charset.
#[cfg(feature = "bench")]
#[inline]
pub fn bench_tail_matches_charset(b: u8, charset: TailCharset) -> bool {
    tail_matches_charset(b, charset)
}

/// Benchmark wrapper: validate prefix with fixed tail length.
#[cfg(feature = "bench")]
#[inline]
pub fn bench_validate_prefix_fixed(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    tail_len: usize,
    tail: TailCharset,
    require_word_boundary_before: bool,
    delim_after: DelimAfter,
) -> Option<Range<usize>> {
    validate_prefix_fixed(
        buf,
        anchor_start,
        anchor_end,
        tail_len,
        PrefixChecks {
            tail,
            require_word_boundary_before,
            delim_after,
        },
    )
}

/// Benchmark wrapper: validate prefix with bounded tail length.
#[cfg(feature = "bench")]
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn bench_validate_prefix_bounded(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
    min_tail: usize,
    max_tail: usize,
    tail: TailCharset,
    require_word_boundary_before: bool,
    delim_after: DelimAfter,
) -> Option<Range<usize>> {
    validate_prefix_bounded(
        buf,
        anchor_start,
        anchor_end,
        min_tail,
        max_tail,
        PrefixChecks {
            tail,
            require_word_boundary_before,
            delim_after,
        },
    )
}

/// Benchmark wrapper: validate AWS access key.
#[cfg(feature = "bench")]
#[inline]
pub fn bench_validate_aws_access_key(
    buf: &[u8],
    anchor_start: usize,
    anchor_end: usize,
) -> Option<Range<usize>> {
    validate_aws_access_key(buf, anchor_start, anchor_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // is_word_byte tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_word_byte_uppercase() {
        for b in b'A'..=b'Z' {
            assert!(is_word_byte(b), "uppercase letter {b} should be word byte");
        }
    }

    #[test]
    fn test_is_word_byte_lowercase() {
        for b in b'a'..=b'z' {
            assert!(is_word_byte(b), "lowercase letter {b} should be word byte");
        }
    }

    #[test]
    fn test_is_word_byte_digits() {
        for b in b'0'..=b'9' {
            assert!(is_word_byte(b), "digit {b} should be word byte");
        }
    }

    #[test]
    fn test_is_word_byte_underscore() {
        assert!(is_word_byte(b'_'), "underscore should be word byte");
    }

    #[test]
    fn test_is_word_byte_non_word() {
        let non_word = [
            b' ', b'\t', b'\n', b'\r', b'-', b'.', b',', b'!', b'@', b'#', b'$', b'%', b'^', b'&',
            b'*', b'(', b')', b'+', b'=', b'[', b']', b'{', b'}', b'|', b'\\', b'/', b':', b';',
            b'"', b'\'', b'<', b'>', b'?', b'`', b'~', 0x00, 0x7F, 0x80, 0xFF,
        ];
        for b in non_word {
            assert!(!is_word_byte(b), "byte {b:#04x} should not be word byte");
        }
    }

    #[test]
    fn test_is_word_byte_all_256() {
        for b in 0u8..=255 {
            let expected = b.is_ascii_alphanumeric() || b == b'_';
            assert_eq!(is_word_byte(b), expected, "mismatch for byte {b:#04x}");
        }
    }

    // -------------------------------------------------------------------------
    // has_word_boundary_before tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_word_boundary_start_of_buffer() {
        assert!(has_word_boundary_before(b"abc", 0));
        assert!(has_word_boundary_before(b"", 0));
        assert!(has_word_boundary_before(b"123", 0));
    }

    #[test]
    fn test_word_boundary_out_of_range() {
        assert!(!has_word_boundary_before(b"abc", 5));
        assert!(!has_word_boundary_before(b"", 1));
    }

    #[test]
    fn test_word_boundary_non_word_to_word() {
        // Space to letter = boundary
        assert!(has_word_boundary_before(b" abc", 1));
        // Dot to digit = boundary
        assert!(has_word_boundary_before(b".123", 1));
        // Newline to underscore = boundary
        assert!(has_word_boundary_before(b"\n_foo", 1));
    }

    #[test]
    fn test_word_boundary_word_to_non_word() {
        // Letter to space = boundary
        assert!(has_word_boundary_before(b"a b", 1));
        // Digit to dot = boundary
        assert!(has_word_boundary_before(b"1.2", 1));
    }

    #[test]
    fn test_word_boundary_no_boundary_word_to_word() {
        // Letter to letter = no boundary
        assert!(!has_word_boundary_before(b"abc", 1));
        // Digit to digit = no boundary
        assert!(!has_word_boundary_before(b"123", 1));
        // Letter to digit = no boundary
        assert!(!has_word_boundary_before(b"a1c", 1));
        // Underscore to letter = no boundary
        assert!(!has_word_boundary_before(b"_abc", 1));
    }

    #[test]
    fn test_word_boundary_no_boundary_non_word_to_non_word() {
        // Space to dot = no boundary
        assert!(!has_word_boundary_before(b" .x", 1));
        // Multiple non-word = no boundary
        assert!(!has_word_boundary_before(b"!@#", 1));
    }

    // -------------------------------------------------------------------------
    // is_gitleaks_token_terminator tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_gitleaks_terminators() {
        let terminators = [
            b'\'', b'"', b'|', b'`', b' ', b'\t', b'\n', b'\r', 0x0B, 0x0C,
        ];
        for b in terminators {
            assert!(
                is_gitleaks_token_terminator(b),
                "byte {b:#04x} should be terminator"
            );
        }
    }

    #[test]
    fn test_gitleaks_non_terminators() {
        let non_terminators = [
            b'a', b'Z', b'0', b'_', b'-', b'.', b'/', b'=', b'+', 0x00, 0xFF,
        ];
        for b in non_terminators {
            assert!(
                !is_gitleaks_token_terminator(b),
                "byte {b:#04x} should not be terminator"
            );
        }
    }

    // -------------------------------------------------------------------------
    // tail_matches_charset tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tail_charset_upper_alnum() {
        for b in b'A'..=b'Z' {
            assert!(tail_matches_charset(b, TailCharset::UpperAlnum));
        }
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::UpperAlnum));
        }
        for b in b'a'..=b'z' {
            assert!(!tail_matches_charset(b, TailCharset::UpperAlnum));
        }
        assert!(!tail_matches_charset(b'_', TailCharset::UpperAlnum));
    }

    #[test]
    fn test_tail_charset_alnum() {
        for b in b'A'..=b'Z' {
            assert!(tail_matches_charset(b, TailCharset::Alnum));
        }
        for b in b'a'..=b'z' {
            assert!(tail_matches_charset(b, TailCharset::Alnum));
        }
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::Alnum));
        }
        assert!(!tail_matches_charset(b'_', TailCharset::Alnum));
        assert!(!tail_matches_charset(b'-', TailCharset::Alnum));
    }

    #[test]
    fn test_tail_charset_lower_alnum() {
        for b in b'a'..=b'z' {
            assert!(tail_matches_charset(b, TailCharset::LowerAlnum));
        }
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::LowerAlnum));
        }
        for b in b'A'..=b'Z' {
            assert!(!tail_matches_charset(b, TailCharset::LowerAlnum));
        }
    }

    #[test]
    fn test_tail_charset_alnum_dash_underscore() {
        for b in b'A'..=b'Z' {
            assert!(tail_matches_charset(b, TailCharset::AlnumDashUnderscore));
        }
        for b in b'a'..=b'z' {
            assert!(tail_matches_charset(b, TailCharset::AlnumDashUnderscore));
        }
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::AlnumDashUnderscore));
        }
        assert!(tail_matches_charset(b'-', TailCharset::AlnumDashUnderscore));
        assert!(tail_matches_charset(b'_', TailCharset::AlnumDashUnderscore));
        assert!(!tail_matches_charset(
            b'.',
            TailCharset::AlnumDashUnderscore
        ));
    }

    #[test]
    fn test_tail_charset_sendgrid() {
        // Alphanumeric
        assert!(tail_matches_charset(b'A', TailCharset::Sendgrid66Set));
        assert!(tail_matches_charset(b'z', TailCharset::Sendgrid66Set));
        assert!(tail_matches_charset(b'5', TailCharset::Sendgrid66Set));
        // Special chars
        assert!(tail_matches_charset(b'=', TailCharset::Sendgrid66Set));
        assert!(tail_matches_charset(b'_', TailCharset::Sendgrid66Set));
        assert!(tail_matches_charset(b'-', TailCharset::Sendgrid66Set));
        assert!(tail_matches_charset(b'.', TailCharset::Sendgrid66Set));
        // Not included
        assert!(!tail_matches_charset(b'+', TailCharset::Sendgrid66Set));
        assert!(!tail_matches_charset(b'/', TailCharset::Sendgrid66Set));
    }

    #[test]
    fn test_tail_charset_databricks() {
        // Digits
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::DatabricksSet));
        }
        // a-h (case insensitive)
        for b in b'a'..=b'h' {
            assert!(tail_matches_charset(b, TailCharset::DatabricksSet));
        }
        for b in b'A'..=b'H' {
            assert!(tail_matches_charset(b, TailCharset::DatabricksSet));
        }
        // i-z should not match
        for b in b'i'..=b'z' {
            assert!(!tail_matches_charset(b, TailCharset::DatabricksSet));
        }
        for b in b'I'..=b'Z' {
            assert!(!tail_matches_charset(b, TailCharset::DatabricksSet));
        }
    }

    #[test]
    fn test_tail_charset_base64_std() {
        for b in b'A'..=b'Z' {
            assert!(tail_matches_charset(b, TailCharset::Base64Std));
        }
        for b in b'a'..=b'z' {
            assert!(tail_matches_charset(b, TailCharset::Base64Std));
        }
        for b in b'0'..=b'9' {
            assert!(tail_matches_charset(b, TailCharset::Base64Std));
        }
        assert!(tail_matches_charset(b'+', TailCharset::Base64Std));
        assert!(tail_matches_charset(b'/', TailCharset::Base64Std));
        // Padding and URL-safe variants not included
        assert!(!tail_matches_charset(b'=', TailCharset::Base64Std));
        assert!(!tail_matches_charset(b'-', TailCharset::Base64Std));
        assert!(!tail_matches_charset(b'_', TailCharset::Base64Std));
    }

    // -------------------------------------------------------------------------
    // validate_prefix_fixed tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_prefix_fixed_basic_match() {
        let buf = b"ghp_1234567890123456789012345678901234567890";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        let result = validate_prefix_fixed(buf, 0, 4, 40, checks);
        assert_eq!(result, Some(0..44));
    }

    #[test]
    fn test_prefix_fixed_with_word_boundary() {
        let buf = b" ghp_1234";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: true,
            delim_after: DelimAfter::None,
        };
        // Anchor starts at 1, boundary before ' ' to 'g'
        let result = validate_prefix_fixed(buf, 1, 5, 4, checks);
        assert_eq!(result, Some(1..9));
    }

    #[test]
    fn test_prefix_fixed_no_word_boundary_fails() {
        let buf = b"aghp_1234";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: true,
            delim_after: DelimAfter::None,
        };
        // 'a' to 'g' = no boundary (both word chars)
        let result = validate_prefix_fixed(buf, 1, 5, 4, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_fixed_tail_too_short() {
        let buf = b"ghp_123";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // Request 40 tail bytes but only 3 available
        let result = validate_prefix_fixed(buf, 0, 4, 40, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_fixed_invalid_tail_char() {
        let buf = b"ghp_12@45678";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // '@' is not in AlnumDashUnderscore
        let result = validate_prefix_fixed(buf, 0, 4, 8, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_fixed_with_gitleaks_terminator() {
        let buf = b"token_ABC123'rest";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        let result = validate_prefix_fixed(buf, 0, 6, 6, checks);
        // Match includes the terminator
        assert_eq!(result, Some(0..13));
    }

    #[test]
    fn test_prefix_fixed_gitleaks_at_eof() {
        let buf = b"token_ABC123";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        let result = validate_prefix_fixed(buf, 0, 6, 6, checks);
        // EOF is valid terminator
        assert_eq!(result, Some(0..12));
    }

    #[test]
    fn test_prefix_fixed_gitleaks_no_terminator() {
        let buf = b"token_ABC123more";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        // 'm' is not a terminator
        let result = validate_prefix_fixed(buf, 0, 6, 6, checks);
        assert_eq!(result, None);
    }

    // -------------------------------------------------------------------------
    // validate_prefix_bounded tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_prefix_bounded_basic() {
        let buf = b"ghp_12345678901234567890";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        let result = validate_prefix_bounded(buf, 0, 4, 10, 40, checks);
        // Should match all 20 tail chars
        assert_eq!(result, Some(0..24));
    }

    #[test]
    fn test_prefix_bounded_min_not_met() {
        let buf = b"ghp_123";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // min=10, but only 3 tail chars
        let result = validate_prefix_bounded(buf, 0, 4, 10, 40, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_bounded_max_respected() {
        let buf = b"ghp_12345678901234567890";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // max=10, should stop at 10 tail chars
        let result = validate_prefix_bounded(buf, 0, 4, 5, 10, checks);
        assert_eq!(result, Some(0..14));
    }

    #[test]
    fn test_prefix_bounded_stops_at_invalid() {
        let buf = b"ghp_12345@67890";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // '@' stops the run at 5 chars
        let result = validate_prefix_bounded(buf, 0, 4, 5, 20, checks);
        assert_eq!(result, Some(0..9));
    }

    #[test]
    fn test_prefix_bounded_invalid_range() {
        let buf = b"ghp_12345";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // min > max should fail
        let result = validate_prefix_bounded(buf, 0, 4, 20, 10, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_bounded_with_gitleaks_backtrack() {
        let buf = b"token_ABC123XYZ'rest";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        // Greedy would match ABC123XYZ (9 chars), but XYZ not followed by terminator
        // Backtrack to find ABC123 followed by X, then ABC12 followed by 3, etc.
        // Actually ABC123XYZ is followed by ', so full match works
        let result = validate_prefix_bounded(buf, 0, 6, 3, 20, checks);
        // ABC123XYZ (9) + terminator
        assert_eq!(result, Some(0..16));
    }

    #[test]
    fn test_prefix_bounded_backtrack_finds_terminator() {
        let buf = b"token_ABC'XYZ rest";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        // ABC is followed by ', valid terminator
        let result = validate_prefix_bounded(buf, 0, 6, 2, 20, checks);
        assert_eq!(result, Some(0..10)); // token_ABC + '
    }

    #[test]
    fn test_prefix_bounded_no_valid_terminator() {
        // Use a buffer where the tail ends with a non-terminator non-alnum char '@'.
        // This ensures: run_len >= min_tail, but no valid terminator at any backtrack position.
        let buf = b"token_ABCDEF@rest";
        let checks = PrefixChecks {
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        // Tail scan: "ABCDEF" (6 chars), stops at '@'.
        // Backtrack from len=6 to len=6, buf[12]='@' which is not a terminator.
        let result = validate_prefix_bounded(buf, 0, 6, 6, 20, checks);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefix_bounded_with_word_boundary() {
        let buf = b" ghp_12345";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: true,
            delim_after: DelimAfter::None,
        };
        let result = validate_prefix_bounded(buf, 1, 5, 3, 10, checks);
        assert_eq!(result, Some(1..10));
    }

    #[test]
    fn test_prefix_bounded_tail_at_buffer_end() {
        let buf = b"ghp_";
        let checks = PrefixChecks {
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // tail_start == buf.len(), should return None
        let result = validate_prefix_bounded(buf, 0, 4, 1, 10, checks);
        assert_eq!(result, None);
    }

    // -------------------------------------------------------------------------
    // validate_aws_access_key tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_aws_access_key_3byte_prefix() {
        // A3T + [A-Z0-9] + 16 uppercase alnum
        let buf = b"A3TABCDEFGHIJ12345678";
        let result = validate_aws_access_key(buf, 0, 3);
        assert_eq!(result, Some(0..20));
    }

    #[test]
    fn test_aws_access_key_4byte_prefix() {
        // AKIA + 16 uppercase alnum
        let buf = b"AKIAIOSFODNN7EXAMPLE";
        let result = validate_aws_access_key(buf, 0, 4);
        assert_eq!(result, Some(0..20));
    }

    #[test]
    fn test_aws_access_key_invalid_4th_byte_3prefix() {
        // 4th byte must be uppercase alnum for 3-byte prefix
        let buf = b"A3T_BCDEFGHIJ1234567";
        let result = validate_aws_access_key(buf, 0, 3);
        assert_eq!(result, None);
    }

    #[test]
    fn test_aws_access_key_lowercase_fails() {
        // Lowercase not allowed in tail
        let buf = b"AKIAabcdefghij123456";
        let result = validate_aws_access_key(buf, 0, 4);
        assert_eq!(result, None);
    }

    #[test]
    fn test_aws_access_key_too_short() {
        let buf = b"AKIAIOSFODNN7EXAMPL";
        let result = validate_aws_access_key(buf, 0, 4);
        assert_eq!(result, None);
    }

    #[test]
    fn test_aws_access_key_invalid_prefix_len() {
        let buf = b"AK1234567890123456789";
        // 2-byte prefix not valid
        let result = validate_aws_access_key(buf, 0, 2);
        assert_eq!(result, None);
        // 5-byte prefix not valid
        let result = validate_aws_access_key(buf, 0, 5);
        assert_eq!(result, None);
    }

    #[test]
    fn test_aws_access_key_with_offset() {
        let buf = b"xxx AKIAIOSFODNN7EXAMPLE yyy";
        let result = validate_aws_access_key(buf, 4, 8);
        assert_eq!(result, Some(4..24));
    }

    // -------------------------------------------------------------------------
    // ValidatorKind::validate_raw_at_anchor tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_validator_kind_none() {
        let buf = b"anything";
        let result = ValidatorKind::None.validate_raw_at_anchor(buf, 0, 4);
        assert_eq!(result, None);
    }

    #[test]
    fn test_validator_kind_aws() {
        let buf = b"AKIAIOSFODNN7EXAMPLE";
        let result = ValidatorKind::AwsAccessKey.validate_raw_at_anchor(buf, 0, 4);
        assert_eq!(result, Some(0..20));
    }

    #[test]
    fn test_validator_kind_prefix_fixed() {
        let buf = b"ghp_12345678901234567890123456789012345678901234";
        let validator = ValidatorKind::PrefixFixed {
            tail_len: 40,
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        let result = validator.validate_raw_at_anchor(buf, 0, 4);
        assert_eq!(result, Some(0..44));
    }

    #[test]
    fn test_validator_kind_prefix_bounded() {
        let buf = b"xoxb-12345678901234567890'";
        let validator = ValidatorKind::PrefixBounded {
            min_tail: 10,
            max_tail: 40,
            tail: TailCharset::AlnumDashUnderscore,
            require_word_boundary_before: false,
            delim_after: DelimAfter::GitleaksTokenTerminator,
        };
        let result = validator.validate_raw_at_anchor(buf, 0, 5);
        assert_eq!(result, Some(0..26));
    }

    #[test]
    fn test_validator_bounds_check() {
        let buf = b"test";
        let validator = ValidatorKind::PrefixFixed {
            tail_len: 4,
            tail: TailCharset::Alnum,
            require_word_boundary_before: false,
            delim_after: DelimAfter::None,
        };
        // anchor_start > anchor_end
        assert_eq!(validator.validate_raw_at_anchor(buf, 3, 2), None);
        // anchor_end > buf.len()
        assert_eq!(validator.validate_raw_at_anchor(buf, 0, 10), None);
    }

    // -------------------------------------------------------------------------
    // match_end_with_delim tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_match_end_none_delim() {
        let buf = b"abcdef";
        assert_eq!(match_end_with_delim(buf, 3, DelimAfter::None), Some(3));
        assert_eq!(match_end_with_delim(buf, 6, DelimAfter::None), Some(6));
    }

    #[test]
    fn test_match_end_gitleaks_at_eof() {
        let buf = b"abcdef";
        assert_eq!(
            match_end_with_delim(buf, 6, DelimAfter::GitleaksTokenTerminator),
            Some(6)
        );
    }

    #[test]
    fn test_match_end_gitleaks_with_terminator() {
        let buf = b"abc'def";
        assert_eq!(
            match_end_with_delim(buf, 3, DelimAfter::GitleaksTokenTerminator),
            Some(4)
        );
    }

    #[test]
    fn test_match_end_gitleaks_no_terminator() {
        let buf = b"abcdef";
        assert_eq!(
            match_end_with_delim(buf, 3, DelimAfter::GitleaksTokenTerminator),
            None
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Reference implementation for is_word_byte using regex semantics.
    fn ref_is_word_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// Reference implementation for UpperAlnum.
    fn ref_upper_alnum(b: u8) -> bool {
        matches!(b, b'A'..=b'Z' | b'0'..=b'9')
    }

    /// Reference implementation for LowerAlnum.
    fn ref_lower_alnum(b: u8) -> bool {
        matches!(b, b'a'..=b'z' | b'0'..=b'9')
    }

    /// Reference implementation for DatabricksSet (case-insensitive a-h + digits).
    fn ref_databricks(b: u8) -> bool {
        b.is_ascii_digit() || matches!(b.to_ascii_lowercase(), b'a'..=b'h')
    }

    proptest! {
        /// Verify is_word_byte matches regex semantics for all bytes.
        #[test]
        fn prop_is_word_byte_matches_ref(b: u8) {
            prop_assert_eq!(is_word_byte(b), ref_is_word_byte(b));
        }

        /// Verify UpperAlnum charset classification.
        #[test]
        fn prop_upper_alnum_matches_ref(b: u8) {
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::UpperAlnum),
                ref_upper_alnum(b)
            );
        }

        /// Verify LowerAlnum charset classification.
        #[test]
        fn prop_lower_alnum_matches_ref(b: u8) {
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::LowerAlnum),
                ref_lower_alnum(b)
            );
        }

        /// Verify Alnum charset = union of upper and lower alphanumeric.
        #[test]
        fn prop_alnum_is_union(b: u8) {
            let expected = b.is_ascii_alphanumeric();
            prop_assert_eq!(tail_matches_charset(b, TailCharset::Alnum), expected);
        }

        /// Verify DatabricksSet matches reference (case-insensitive).
        #[test]
        fn prop_databricks_matches_ref(b: u8) {
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::DatabricksSet),
                ref_databricks(b)
            );
        }

        /// Verify AlnumDashUnderscore = Alnum + dash + underscore.
        #[test]
        fn prop_alnum_dash_underscore(b: u8) {
            let expected = b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::AlnumDashUnderscore),
                expected
            );
        }

        /// Verify Base64Std charset.
        #[test]
        fn prop_base64_std(b: u8) {
            let expected = b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::Base64Std),
                expected
            );
        }

        /// Verify Sendgrid66Set charset.
        #[test]
        fn prop_sendgrid66_set(b: u8) {
            let expected = b.is_ascii_alphanumeric()
                || b == b'='
                || b == b'_'
                || b == b'-'
                || b == b'.';
            prop_assert_eq!(
                tail_matches_charset(b, TailCharset::Sendgrid66Set),
                expected
            );
        }

        /// Bounded validation respects min constraint.
        #[test]
        fn prop_bounded_respects_min(
            prefix_len in 1usize..8,
            tail_content in "[A-Za-z0-9]{0,50}",
            min_tail in 1usize..20,
            max_tail in 20usize..60,
        ) {
            let mut buf = vec![b'_'; prefix_len]; // prefix (word chars)
            buf.extend(tail_content.as_bytes());

            let checks = PrefixChecks {
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            };

            let result = validate_prefix_bounded(
                &buf,
                0,
                prefix_len,
                min_tail,
                max_tail,
                checks,
            );

            let actual_tail_len = tail_content.len();
            if actual_tail_len < min_tail {
                prop_assert!(result.is_none(), "should fail when tail < min");
            } else {
                prop_assert!(result.is_some(), "should succeed when tail >= min");
                let span = result.unwrap();
                let matched_tail = span.end - prefix_len;
                prop_assert!(
                    matched_tail >= min_tail,
                    "matched tail {} < min {}",
                    matched_tail,
                    min_tail
                );
            }
        }

        /// Bounded validation respects max constraint.
        #[test]
        fn prop_bounded_respects_max(
            prefix_len in 1usize..8,
            tail_content in "[A-Za-z0-9]{30,60}",
            max_tail in 10usize..25,
        ) {
            let mut buf = vec![b'_'; prefix_len];
            buf.extend(tail_content.as_bytes());

            let checks = PrefixChecks {
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            };

            let result = validate_prefix_bounded(
                &buf,
                0,
                prefix_len,
                1,
                max_tail,
                checks,
            );

            prop_assert!(result.is_some());
            let span = result.unwrap();
            let matched_tail = span.end - prefix_len;
            prop_assert!(
                matched_tail <= max_tail,
                "matched tail {} > max {}",
                matched_tail,
                max_tail
            );
        }

        /// Fixed validation produces exact tail length when buffer is sufficient.
        #[test]
        fn prop_fixed_exact_length(
            prefix_len in 1usize..8,
            tail_content in "[A-Za-z0-9]{20,40}",
            requested_tail in 5usize..15,
        ) {
            let mut buf = vec![b'_'; prefix_len];
            buf.extend(tail_content.as_bytes());

            let checks = PrefixChecks {
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            };

            let result = validate_prefix_fixed(
                &buf,
                0,
                prefix_len,
                requested_tail,
                checks,
            );

            prop_assert!(result.is_some());
            let span = result.unwrap();
            let matched_tail = span.end - prefix_len;
            prop_assert_eq!(matched_tail, requested_tail);
        }

        /// Word boundary detection is symmetric at transitions.
        #[test]
        fn prop_word_boundary_symmetric(a: u8, b_byte: u8) {
            let buf = vec![a, b_byte];
            let has_boundary = has_word_boundary_before(&buf, 1);
            let a_word = is_word_byte(a);
            let b_word = is_word_byte(b_byte);
            prop_assert_eq!(has_boundary, a_word != b_word);
        }

        /// Start of buffer is always a word boundary.
        #[test]
        fn prop_start_is_boundary(buf in proptest::collection::vec(any::<u8>(), 0..100)) {
            prop_assert!(has_word_boundary_before(&buf, 0));
        }

        /// Gitleaks terminator detection.
        #[test]
        fn prop_gitleaks_terminators(b: u8) {
            let expected = matches!(b, b'\'' | b'"' | b'|' | b'`')
                || matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
            prop_assert_eq!(is_gitleaks_token_terminator(b), expected);
        }
    }
}
