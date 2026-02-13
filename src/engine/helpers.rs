//! Helper routines for window merging, entropy gating, UTF-16 decode, and hashing.
//!
//! # Invariants
//! - Window merge helpers expect input ranges sorted by `start` and normalized
//!   (`start <= end`).
//! - Prefilter helpers must be conservative: they may allow false positives but
//!   must not drop candidates that could satisfy full rule validation.
//!
//! # Design Notes
//! - Window merging widens spans to trade small extra scanning for fewer passes.
//! - Entropy gating is conservative: short samples always pass.
//! - UTF-16 anchor helpers are byte-wise wideners (ASCII-focused), not general
//!   UTF-8 -> UTF-16 conversion.
//! - UTF-16 decoding uses replacement characters and enforces output limits.

use super::hit_pool::SpanU32;
use super::rule_repr::{EntropyCompiled, PackedPatterns};
use super::scratch::EntropyScratch;
use crate::scratch_memory::ScratchVec;
use memchr::memmem;

// --------------------------
// Window merge / coalesce (no repeated sorting)
// --------------------------

/// Merges sorted ranges in-place, allowing a soft merge gap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
/// - Each span is normalized (`start <= end`).
///
/// # Effects
/// - Adjacent or overlapping ranges within `gap` bytes are merged into a single window.
/// - Output remains sorted and non-overlapping.
/// - When merging, preserves the **earliest** (smallest) anchor hint to maintain
///   conservative correctness.
///
/// # Design Notes
/// - The soft gap reduces the number of regex runs at the cost of slightly
///   wider windows.
/// - `gap == 0` behaves like a standard overlap/adjacency merge.
///
/// # Complexity
/// - O(n) time, O(1) extra space.
pub(super) fn merge_ranges_with_gap_sorted(ranges: &mut ScratchVec<SpanU32>, gap: u32) {
    let len = ranges.len();
    if len <= 1 {
        return;
    }

    let s = ranges.as_mut_slice();
    let mut write = 0usize;
    let mut cur = s[0];

    for i in 1..len {
        // SAFETY: i < len and len == s.len().
        let r = unsafe { *s.get_unchecked(i) };
        debug_assert!(r.start >= cur.start);
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
            // Preserve the earliest anchor hint when merging.
            cur.anchor_hint = cur.anchor_hint.min(r.anchor_hint);
        } else {
            // SAFETY: write < i < len, so write is in bounds.
            unsafe { *s.get_unchecked_mut(write) = cur };
            write += 1;
            cur = r;
        }
    }
    // SAFETY: write <= len - 1 < len, so write is in bounds.
    unsafe { *s.get_unchecked_mut(write) = cur };
    write += 1;
    ranges.truncate(write);
}

/// Coalesces windows until their count is below a cap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
/// - Each span is normalized (`start <= end`) and bounded by `hay_len`.
/// - `ranges` should already be lightly merged with a small gap when possible.
///
/// # Effects
/// - Expands the merge gap exponentially to reduce the window count (capped at `hay_len`).
/// - If still over the cap, collapses to a single window spanning the first/last range
///   (clamped to `hay_len`).
/// - The final ranges are a superset of the original windows (given the preconditions).
/// - When collapsing, preserves the **earliest** (smallest) anchor hint.
///
/// # Complexity
/// - O(n log G) where G is the number of gap doublings, O(1) extra space.
pub(super) fn coalesce_under_pressure_sorted(
    ranges: &mut ScratchVec<SpanU32>,
    hay_len: u32,
    mut gap: u32,
    max_windows: usize,
) {
    if ranges.len() <= max_windows {
        return;
    }

    // Increase the merge gap until we fit the cap or hit the buffer length.
    while ranges.len() > max_windows && gap < hay_len {
        merge_ranges_with_gap_sorted(ranges, gap);
        gap = gap.saturating_mul(2);
    }

    if ranges.len() > max_windows && !ranges.is_empty() {
        // Hard fallback: collapse to a single window to bound work deterministically.
        // Preserve the earliest anchor hint across all windows.
        let start = ranges[0].start;
        let end = ranges[ranges.len() - 1].end;
        let mut min_anchor = start;
        for i in 0..ranges.len() {
            min_anchor = min_anchor.min(ranges[i].anchor_hint);
        }
        ranges.clear();
        ranges.push(SpanU32 {
            start: start.min(hay_len),
            end: end.min(hay_len),
            anchor_hint: min_anchor.min(hay_len),
        });
    }
}

// --------------------------
// Confirm helpers
// --------------------------

/// Returns true if any packed needle exists in the haystack.
///
/// # Preconditions
/// - `needles.offsets` indexes into `needles.bytes` and is monotonically
///   increasing. Each interval denotes one pattern.
/// - `needles` uses a prefix-sum offset table (last offset == `needles.bytes.len()`).
///
/// # Behavior
/// - Returns false when `needles` contains no patterns.
/// - Fast-paths the common single-needle case to avoid loop overhead.
pub(super) fn contains_any_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    if count == 1 {
        let end = needles.offsets[1] as usize;
        return memmem::find(hay, &needles.bytes[..end]).is_some();
    }
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        // SAFETY: PackedPatterns invariant guarantees offsets index into bytes.
        let needle = unsafe { needles.bytes.get_unchecked(start..end) };
        if memmem::find(hay, needle).is_some() {
            return true;
        }
    }
    false
}

/// Returns true only if every packed needle exists in the haystack.
///
/// # Preconditions
/// - `needles.offsets` indexes into `needles.bytes` and is monotonically
///   increasing. Each interval denotes one pattern.
/// - `needles` uses a prefix-sum offset table (last offset == `needles.bytes.len()`).
///
/// # Behavior
/// - Returns true when `needles` contains no patterns.
/// - Fast-paths the common single-needle case to avoid loop overhead.
pub(super) fn contains_all_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    if count == 1 {
        let end = needles.offsets[1] as usize;
        return memmem::find(hay, &needles.bytes[..end]).is_some();
    }
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        // SAFETY: PackedPatterns invariant guarantees offsets index into bytes.
        let needle = unsafe { needles.bytes.get_unchecked(start..end) };
        if memmem::find(hay, needle).is_none() {
            return false;
        }
    }
    true
}

// --------------------------
// Entropy helpers
// --------------------------

/// Precomputes log2 values for entropy calculations.
///
/// The table is sized to the maximum entropy window length across rules and
/// can be shared across entropy checks to avoid repeated `log2` calls.
/// Index 0 is unused; index 1 is log2(1) = 0.
pub(super) fn build_log2_table(max: usize) -> Vec<f32> {
    let len = max.saturating_add(1).max(2);
    let mut t = vec![0.0f32; len];
    for (i, val) in t.iter_mut().enumerate().skip(1) {
        *val = (i as f32).log2();
    }
    t
}

#[inline]
fn log2_lookup(table: &[f32], n: usize) -> f32 {
    if n < table.len() {
        table[n]
    } else {
        (n as f32).log2()
    }
}

/// Computes Shannon entropy in bits per byte for the given slice.
///
/// # Effects
/// - Uses and resets `scratch` for histogram bookkeeping.
/// - `scratch` contents are unspecified after return; it is meant for reuse.
///
/// # Returns
/// - 0.0 for empty input.
#[inline]
pub(super) fn shannon_entropy_bits_per_byte(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> f32 {
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }

    // Branchless histogram: unconditionally increment the bin for each byte.
    // No "first touch" tracking — the reset zeroes all 256 bins via memset.
    for &b in bytes {
        // SAFETY: b is u8, so b as usize is in 0..256; counts has exactly 256 entries.
        unsafe { *scratch.counts.get_unchecked_mut(b as usize) += 1 };
    }

    // Shannon entropy: H = log2(n) - (1/n) * sum(c_i * log2(c_i))
    // This rearrangement avoids repeated divisions.
    let log2_n = log2_lookup(log2_table, n);
    let mut sum_c_log2_c = 0.0f32;

    // Scan all 256 bins. For random data most bins are nonzero (predictable);
    // for short inputs most bins are zero (also predictable). Either way the
    // branch predictor handles this well, and we avoid the per-byte branch
    // that the previous "touched list" approach required in the hot histogram loop.
    for i in 0..256 {
        // SAFETY: loop bounds guarantee `i` is always in 0..256, which matches
        // the exact length of `counts`.
        let c = unsafe { *scratch.counts.get_unchecked(i) } as usize;
        if c > 0 {
            sum_c_log2_c += (c as f32) * log2_lookup(log2_table, c);
        }
    }

    scratch.reset();

    log2_n - (sum_c_log2_c / (n as f32))
}

/// Returns true when the entropy gate allows a buffer to proceed.
///
/// # Behavior
/// - Buffers shorter than `spec.min_len` always pass (entropy is noisy).
/// - Longer buffers are capped at `spec.max_len` for the computation.
///
/// # Preconditions
/// - `spec.min_len <= spec.max_len` and `spec.min_bits_per_byte` is in [0.0, 8.0].
#[inline]
pub(super) fn entropy_gate_passes(
    spec: &EntropyCompiled,
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> bool {
    let len = bytes.len();
    if len < spec.min_len {
        // For tiny samples entropy is noisy; let them pass rather than
        // discarding true positives.
        return true;
    }
    let capped = len.min(spec.max_len);
    let e = shannon_entropy_bits_per_byte(&bytes[..capped], scratch, log2_table);
    e >= spec.min_bits_per_byte
}

// --------------------------
// UTF-16 helpers
// --------------------------

#[derive(Debug)]
pub(super) enum Utf16DecodeError {
    /// Output would exceed the configured maximum or buffer capacity.
    OutputTooLarge,
}

#[cfg(test)]
/// Decodes UTF-16LE into a UTF-8 `Vec`, enforcing a maximum output size.
///
/// # Behavior
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
pub(super) fn decode_utf16le_to_vec(
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_vec_inner(input, max_out, true, &mut out)?;
    Ok(out)
}

#[cfg(test)]
/// Decodes UTF-16BE into a UTF-8 `Vec`, enforcing a maximum output size.
///
/// # Behavior
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
pub(super) fn decode_utf16be_to_vec(
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_vec_inner(input, max_out, false, &mut out)?;
    Ok(out)
}

#[cfg(test)]
fn decode_utf16_to_vec_inner(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut Vec<u8>,
) -> Result<(), Utf16DecodeError> {
    // Ignore a trailing odd byte; it cannot form a full UTF-16 code unit.
    let n = input.len() / 2;
    let iter = (0..n).map(|i| {
        let b0 = input[2 * i];
        let b1 = input[2 * i + 1];
        if le {
            u16::from_le_bytes([b0, b1])
        } else {
            u16::from_be_bytes([b0, b1])
        }
    });

    out.clear();
    for r in std::char::decode_utf16(iter) {
        let ch = r.unwrap_or('\u{FFFD}');
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if out.len() + s.len() > max_out {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

/// Decodes UTF-16LE into the provided scratch buffer.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
pub(super) fn decode_utf16le_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, true, out)
}

/// Decodes UTF-16BE into the provided scratch buffer.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
pub(super) fn decode_utf16be_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, false, out)
}

/// Reads one UTF-16 code unit from `input` at byte offset `off`.
#[inline(always)]
fn read_utf16_code_unit(input: &[u8], off: usize, le: bool) -> u16 {
    // SAFETY: caller guarantees `off + 1 < input.len()`.
    let b0 = unsafe { *input.get_unchecked(off) };
    // SAFETY: caller guarantees `off + 1 < input.len()`.
    let b1 = unsafe { *input.get_unchecked(off + 1) };
    if le {
        u16::from_le_bytes([b0, b1])
    } else {
        u16::from_be_bytes([b0, b1])
    }
}

/// Decodes one Unicode scalar value at UTF-16 code-unit index `i`.
///
/// Returns `(char, advance_units)` where `advance_units` is 1 for BMP or
/// replacement characters and 2 for valid surrogate pairs.
#[inline(always)]
fn decode_utf16_scalar_at(input: &[u8], i: usize, n: usize, le: bool) -> (char, usize) {
    debug_assert!(i < n, "caller must provide in-bounds UTF-16 index");
    let off = i * 2;
    let u = read_utf16_code_unit(input, off, le);

    if (0xD800..=0xDBFF).contains(&u) {
        // High surrogate — consume a pair only when followed by a valid low surrogate.
        if i + 1 < n {
            let off2 = (i + 1) * 2;
            // SAFETY: `i + 1 < n` and `n = input.len() / 2` imply
            // `off2 + 1 = 2*(i+1)+1 < 2*n <= input.len()`.
            let u2 = read_utf16_code_unit(input, off2, le);
            if (0xDC00..=0xDFFF).contains(&u2) {
                let high = (u - 0xD800) as u32;
                let low = (u2 - 0xDC00) as u32;
                let code = 0x10000 + ((high << 10) | low);
                // SAFETY: code is constructed from a valid surrogate pair.
                return (unsafe { char::from_u32_unchecked(code) }, 2);
            }
        }
        return ('\u{FFFD}', 1);
    }

    if (0xDC00..=0xDFFF).contains(&u) {
        // Lone low surrogate.
        ('\u{FFFD}', 1)
    } else {
        // SAFETY: non-surrogate BMP code units are valid scalar values.
        (unsafe { char::from_u32_unchecked(u as u32) }, 1)
    }
}

/// Maps a decoded UTF-8 offset back to the raw UTF-16 byte offset.
///
/// Returns the raw byte offset (half-open) such that decoding `input[0..offset]`
/// would produce at least `decoded_offset` UTF-8 bytes. The returned offset is
/// always aligned to complete UTF-16 scalar decoding steps (it never points
/// into the middle of a surrogate pair). If `decoded_offset` exceeds the
/// decoded length, returns the largest even byte offset.
///
/// Complexity is O(number of decoded scalars up to the target offset).
pub(super) fn map_utf16_decoded_offset(input: &[u8], decoded_offset: usize, le: bool) -> usize {
    if decoded_offset == 0 {
        return 0;
    }
    let n = input.len() / 2;
    let mut decoded = 0usize;
    let mut i = 0usize;

    while i < n {
        let (ch, advance) = decode_utf16_scalar_at(input, i, n, le);

        // `decoded` is monotonically increasing; saturating add keeps behavior
        // defined even for pathological inputs near `usize::MAX`.
        decoded = decoded.saturating_add(ch.len_utf8());
        i += advance;
        if decoded >= decoded_offset {
            return i * 2;
        }
    }

    n * 2
}

/// Decodes UTF-16 into a scratch buffer, using replacement characters for
/// invalid sequences.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - On error, `out` may contain a truncated prefix; treat its contents as unspecified.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
///
/// # Complexity
/// O(number of UTF-16 code units).
fn decode_utf16_to_buf(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    // Ignore a trailing odd byte; it cannot form a full UTF-16 code unit.
    let n = input.len() / 2;
    out.clear();

    // Manual decode loop — avoids std::char::decode_utf16 iterator/Result overhead.
    let mut i = 0usize;
    while i < n {
        let (ch, advance) = decode_utf16_scalar_at(input, i, n, le);

        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if out.len() + s.len() > max_out {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        if out.len() + s.len() > out.capacity() {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
        i += advance;
    }
    Ok(())
}

// --------------------------
// Hashing (decoded buffer dedupe)
// --------------------------

/// Zero key for AEGIS-128L MAC, stored in `.rodata` to avoid per-call stack init.
const ZERO_KEY: [u8; 16] = [0u8; 16];

/// Collision-resistant 128-bit hash using AEGIS-128L MAC.
///
/// Design intent:
/// - We need a *fast* but *low-collision* fingerprint for decoded buffers.
/// - SipHash is strong but slower; non-crypto hashes are fast but risky.
/// - AEGIS-128L uses AES-NI on modern CPUs and yields a 128-bit MAC.
///
/// By fixing the key to zero and authenticating `bytes` as the message, we get
/// a deterministic 128-bit tag that behaves like a PRF. This is not a general-
/// purpose cryptographic hash, but it is collision-resistant enough for
/// in-process deduplication and avoids an extra dependency.
pub(super) fn hash128(bytes: &[u8]) -> u128 {
    use aegis::aegis128l::Aegis128LMac;
    let mut mac = Aegis128LMac::<16>::new(&ZERO_KEY);
    mac.update(bytes);
    u128::from_le_bytes(mac.finalize())
}

/// Returns the smallest power of two greater than or equal to `v`.
///
/// # Behavior
/// - Returns 1 when `v == 0`.
pub(super) fn pow2_at_least(v: usize) -> usize {
    v.next_power_of_two()
}

/// Converts a `u64` to `usize` with saturation on overflow.
pub(super) fn u64_to_usize(v: u64) -> usize {
    if v > (usize::MAX as u64) {
        usize::MAX
    } else {
        v as usize
    }
}

/// Extracts the secret span from a regex match using capture group logic.
///
/// Many rules match more context than the actual secret (e.g., `KEY_([a-z0-9]+)`
/// matches `KEY_abc123` but the secret is just `abc123`). This function extracts
/// the narrowest meaningful span for deduplication and reporting.
///
/// # Priority
/// 1. **Configured group**: If `secret_group` is set and that group matched
///    non-empty content, use it. This allows rules with unconventional layouts.
/// 2. **First non-empty capture group**: Scan groups 1..N and use the first
///    one with non-empty content. This handles rules with alternation where
///    different groups fire depending on input (e.g., `curl-auth-header` has
///    8 groups for different auth types, only one fires per match).
/// 3. **Full match fallback**: Otherwise, use group 0 (the entire match).
///
/// Groups that did not participate in the match (`None`) or captured an empty
/// span are skipped, because some patterns have optional groups that may not
/// capture meaningful content (e.g., `([A-Z]*)` matching an empty string).
///
/// # Arguments
/// - `captures`: The regex Captures from a successful match.
/// - `secret_group`: Optional configured group index from `RuleSpec::secret_group`.
///
/// # Returns
/// `(start, end)` byte offsets of the secret span relative to the search haystack.
/// These offsets are in the same coordinate space as `Captures::get(0)`.
///
/// # Panics
/// Panics if group 0 does not exist (impossible for a successful match).
#[cfg(test)]
#[inline]
pub(super) fn extract_secret_span(
    captures: &regex::bytes::Captures<'_>,
    secret_group: Option<u16>,
) -> (usize, usize) {
    // Priority 1: Use configured secret_group if set.
    if let Some(gi) = secret_group {
        let group_idx = gi as usize;
        if let Some(m) = captures.get(group_idx) {
            if m.start() < m.end() {
                return (m.start(), m.end());
            }
            // Group exists but matched empty - fall through to other priorities.
        } else {
            // Configured group does not exist in this regex. This indicates a rule
            // configuration error that should have been caught by RuleSpec::assert_valid().
            debug_assert!(
                false,
                "secret_group {} does not exist in regex (only {} groups)",
                group_idx,
                captures.len()
            );
        }
    }

    // Priority 2: Use the first non-empty capture group (1..N).
    // Gitleaks convention places the secret in group 1, but rules with
    // alternation (e.g., curl-auth-header) may fire a higher group.
    for gi in 1..captures.len() {
        if let Some(m) = captures.get(gi) {
            if m.start() < m.end() {
                return (m.start(), m.end());
            }
        }
    }

    // Priority 3: Fall back to full match (group 0).
    let full = captures.get(0).expect("group 0 always exists");
    (full.start(), full.end())
}

/// Extracts the secret span from reusable capture locations.
///
/// Mirrors [`extract_secret_span`] but operates on `CaptureLocations` to avoid
/// per-match allocations in hot paths.
///
/// `has_secret_group_override` is carried separately so all `u16` values
/// (including `u16::MAX`) remain valid capture-group indices.
#[inline]
pub(super) fn extract_secret_span_locs_raw(
    locs: &regex::bytes::CaptureLocations,
    secret_group_raw: u16,
    has_secret_group_override: bool,
) -> (usize, usize) {
    if has_secret_group_override {
        let group_idx = secret_group_raw as usize;
        if let Some((start, end)) = locs.get(group_idx) {
            if start < end {
                return (start, end);
            }
        } else {
            debug_assert!(
                false,
                "secret_group {} does not exist in regex (only {} groups)",
                group_idx,
                locs.len()
            );
        }
    }

    // Fast path: group 1 (covers >90% of rules).
    if let Some((start, end)) = locs.get(1) {
        if start < end {
            return (start, end);
        }
    }

    // Slow path: scan groups 2..N for the first non-empty capture.
    for gi in 2..locs.len() {
        if let Some((start, end)) = locs.get(gi) {
            if start < end {
                return (start, end);
            }
        }
    }

    let (start, end) = locs.get(0).expect("group 0 always exists");
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::rule_repr::PackedPatternsBuilder;
    use crate::scratch_memory::ScratchVec;

    fn build_packed(patterns: &[&[u8]]) -> PackedPatterns {
        let byte_len: usize = patterns.iter().map(|p| p.len()).sum();
        let mut b = PackedPatternsBuilder::with_capacity(patterns.len(), byte_len);
        for &p in patterns {
            b.push_raw(p);
        }
        b.build()
    }

    // ---- contains_any_memmem ----

    #[test]
    fn contains_any_memmem_zero_needles() {
        let packed = build_packed(&[]);
        assert!(!contains_any_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_any_memmem_single_needle_present() {
        let packed = build_packed(&[b"world"]);
        assert!(contains_any_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_any_memmem_single_needle_absent() {
        let packed = build_packed(&[b"xyz"]);
        assert!(!contains_any_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_any_memmem_multiple_needles_one_present() {
        let packed = build_packed(&[b"xyz", b"world"]);
        assert!(contains_any_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_any_memmem_multiple_needles_none_present() {
        let packed = build_packed(&[b"xyz", b"abc"]);
        assert!(!contains_any_memmem(b"hello world", &packed));
    }

    // ---- contains_all_memmem ----

    #[test]
    fn contains_all_memmem_zero_needles() {
        let packed = build_packed(&[]);
        assert!(contains_all_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_all_memmem_single_needle_present() {
        let packed = build_packed(&[b"hello"]);
        assert!(contains_all_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_all_memmem_single_needle_absent() {
        let packed = build_packed(&[b"xyz"]);
        assert!(!contains_all_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_all_memmem_multiple_needles_all_present() {
        let packed = build_packed(&[b"hello", b"world"]);
        assert!(contains_all_memmem(b"hello world", &packed));
    }

    #[test]
    fn contains_all_memmem_multiple_needles_one_missing() {
        let packed = build_packed(&[b"hello", b"xyz"]);
        assert!(!contains_all_memmem(b"hello world", &packed));
    }

    fn expected_map_utf16_offset(input: &[u8], decoded_offset: usize, le: bool) -> usize {
        if decoded_offset == 0 {
            return 0;
        }

        let n = input.len() / 2;
        let mut decoded = 0usize;
        let mut i = 0usize;

        while i < n {
            let off = i * 2;
            let u = if le {
                u16::from_le_bytes([input[off], input[off + 1]])
            } else {
                u16::from_be_bytes([input[off], input[off + 1]])
            };

            let (utf8_len, advance) = if (0xD800..=0xDBFF).contains(&u) {
                if i + 1 < n {
                    let off2 = (i + 1) * 2;
                    let u2 = if le {
                        u16::from_le_bytes([input[off2], input[off2 + 1]])
                    } else {
                        u16::from_be_bytes([input[off2], input[off2 + 1]])
                    };
                    if (0xDC00..=0xDFFF).contains(&u2) {
                        (4usize, 2usize)
                    } else {
                        (3usize, 1usize)
                    }
                } else {
                    (3usize, 1usize)
                }
            } else if (0xDC00..=0xDFFF).contains(&u) {
                (3usize, 1usize)
            } else {
                let ch = char::from_u32(u as u32).expect("non-surrogate BMP scalar");
                (ch.len_utf8(), 1usize)
            };

            decoded = decoded.saturating_add(utf8_len);
            i += advance;
            if decoded >= decoded_offset {
                return i * 2;
            }
        }

        n * 2
    }

    #[test]
    fn decode_utf16_to_buf_errors_when_capacity_is_too_small() {
        // "AB" in UTF-16LE.
        let input = [b'A', 0, b'B', 0];
        let mut out = ScratchVec::with_capacity(1).expect("scratch alloc");

        let err = decode_utf16le_to_buf(&input, 8, &mut out)
            .expect_err("decode should map capacity overflow to Utf16DecodeError::OutputTooLarge");
        assert!(matches!(err, Utf16DecodeError::OutputTooLarge));
    }

    #[test]
    fn decode_utf16_to_buf_succeeds_when_capacity_is_sufficient() {
        // "AB" in UTF-16LE.
        let input = [b'A', 0, b'B', 0];
        let mut out = ScratchVec::with_capacity(2).expect("scratch alloc");

        decode_utf16le_to_buf(&input, 8, &mut out).expect("decode should succeed");
        assert_eq!(out.as_slice(), b"AB");
    }

    #[test]
    fn map_utf16_decoded_offset_matches_bruteforce_utf16le() {
        // "A" + U+10000 surrogate pair + lone low surrogate + "z".
        let input = [0x41, 0x00, 0x00, 0xD8, 0x00, 0xDC, 0x00, 0xDC, 0x7A, 0x00];
        let full = decode_utf16le_to_vec(&input, usize::MAX).expect("decode");

        for decoded_offset in 0..=(full.len() + 3) {
            let mapped = map_utf16_decoded_offset(&input, decoded_offset, true);
            let expected = expected_map_utf16_offset(&input, decoded_offset, true);
            assert_eq!(mapped, expected, "decoded_offset={decoded_offset}");
        }
    }

    #[test]
    fn map_utf16_decoded_offset_matches_bruteforce_utf16be() {
        // Same scalar sequence as LE test but in BE encoding.
        let input = [0x00, 0x41, 0xD8, 0x00, 0xDC, 0x00, 0xDC, 0x00, 0x00, 0x7A];
        let full = decode_utf16be_to_vec(&input, usize::MAX).expect("decode");

        for decoded_offset in 0..=(full.len() + 3) {
            let mapped = map_utf16_decoded_offset(&input, decoded_offset, false);
            let expected = expected_map_utf16_offset(&input, decoded_offset, false);
            assert_eq!(mapped, expected, "decoded_offset={decoded_offset}");
        }
    }
}
