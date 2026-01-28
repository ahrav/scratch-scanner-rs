//! Helper routines for window merging, entropy gating, UTF-16 decode, and hashing.
//!
//! # Invariants
//! - Window merge helpers expect input ranges sorted by `start`.
//! - Prefilter and entropy helpers must never drop true positives.
//!
//! # Design Notes
//! - Window merging widens spans to trade small extra scanning for fewer passes.
//! - Entropy gating is conservative: short samples always pass.
//! - UTF-16 decoding uses replacement characters and enforces output limits.

use super::{EntropyCompiled, EntropyScratch, PackedPatterns, SpanU32};
use crate::scratch_memory::ScratchVec;
use memchr::memmem;

// --------------------------
// Window merge / coalesce (no repeated sorting)
// --------------------------

/// Merges sorted ranges in-place, allowing a soft merge gap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
///
/// # Effects
/// - Adjacent ranges within `gap` bytes are merged into a single window.
/// - Output remains sorted and non-overlapping.
///
/// # Design Notes
/// - The soft gap reduces the number of regex runs at the cost of slightly
///   wider windows.
///
/// # Complexity
/// - O(n) time, O(1) extra space.
pub(super) fn merge_ranges_with_gap_sorted(ranges: &mut ScratchVec<SpanU32>, gap: u32) {
    if ranges.len() <= 1 {
        return;
    }

    let mut write = 0usize;
    let mut cur = ranges[0];
    let len = ranges.len();

    for i in 1..len {
        let r = ranges[i];
        debug_assert!(r.start >= cur.start);
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
        } else {
            ranges[write] = cur;
            write += 1;
            cur = r;
        }
    }
    ranges[write] = cur;
    write += 1;
    ranges.truncate(write);
}

/// Coalesces windows until their count is below a cap.
///
/// # Preconditions
/// - `ranges` must be sorted by `start` ascending.
/// - `ranges` should already be lightly merged with a small gap when possible.
///
/// # Effects
/// - Expands the merge gap exponentially to reduce the window count.
/// - If still over the cap, collapses to a single window.
/// - The final ranges are a superset of the original windows.
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
        let start = ranges[0].start;
        let end = ranges[ranges.len() - 1].end;
        ranges.clear();
        ranges.push(SpanU32 {
            start: start.min(hay_len),
            end: end.min(hay_len),
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
pub(super) fn contains_any_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        if memmem::find(hay, &needles.bytes[start..end]).is_some() {
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
pub(super) fn contains_all_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        if memmem::find(hay, &needles.bytes[start..end]).is_none() {
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
/// The table is sized to the maximum entropy window length across rules.
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
///
/// # Returns
/// - 0.0 for empty input.
#[inline]
fn shannon_entropy_bits_per_byte(
    bytes: &[u8],
    scratch: &mut EntropyScratch,
    log2_table: &[f32],
) -> f32 {
    let n = bytes.len();
    if n == 0 {
        return 0.0;
    }

    // Build a histogram using a "touched list" so reset cost is proportional
    // to the number of distinct byte values, not 256.
    for &b in bytes {
        let idx = b as usize;
        let c = scratch.counts[idx];
        if c == 0 {
            let used_len = scratch.used_len as usize;
            if used_len < scratch.used.len() {
                scratch.used[used_len] = b;
                scratch.used_len = (used_len + 1) as u16;
            }
        }
        scratch.counts[idx] = c + 1;
    }

    // Shannon entropy: H = log2(n) - (1/n) * sum(c_i * log2(c_i))
    // This rearrangement avoids repeated divisions.
    let log2_n = log2_lookup(log2_table, n);
    let mut sum_c_log2_c = 0.0f32;

    let used_len = scratch.used_len as usize;
    for i in 0..used_len {
        let idx = scratch.used[i] as usize;
        let c = scratch.counts[idx] as usize;
        sum_c_log2_c += (c as f32) * log2_lookup(log2_table, c);
    }

    scratch.reset();

    log2_n - (sum_c_log2_c / (n as f32))
}

/// Returns true when the entropy gate allows a buffer to proceed.
///
/// # Behavior
/// - Buffers shorter than `spec.min_len` always pass (entropy is noisy).
/// - Longer buffers are capped at `spec.max_len` for the computation.
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

/// Produces the UTF-16LE byte sequence for a UTF-8 anchor.
pub(super) fn utf16le_bytes(anchor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchor.len() * 2);
    for &b in anchor {
        out.push(b);
        out.push(0);
    }
    out
}

/// Produces the UTF-16BE byte sequence for a UTF-8 anchor.
pub(super) fn utf16be_bytes(anchor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(anchor.len() * 2);
    for &b in anchor {
        out.push(0);
        out.push(b);
    }
    out
}

#[derive(Debug)]
pub(super) enum Utf16DecodeError {
    /// Output would exceed the configured maximum or buffer capacity.
    OutputTooLarge,
}

#[cfg(test)]
/// Decodes UTF-16LE into a UTF-8 `Vec`, enforcing a maximum output size.
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
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
pub(super) fn decode_utf16be_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, false, out)
}

/// Decodes UTF-16 into a scratch buffer, using replacement characters for
/// invalid sequences.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
fn decode_utf16_to_buf(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut ScratchVec<u8>,
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
        // Check capacity before extending to avoid panic.
        if out.len() + s.len() > out.capacity() {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

// --------------------------
// Hashing (decoded buffer dedupe)
// --------------------------

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
    let key = [0u8; 16];
    let mut mac = Aegis128LMac::<16>::new(&key);
    mac.update(bytes);
    u128::from_le_bytes(mac.finalize())
}

/// Returns the smallest power of two greater than or equal to `v`.
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
