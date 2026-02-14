//! Reusable JSON writing primitives (no serde).
//!
//! All sinks that produce JSON output (JSONL, JSON array, SARIF) share
//! these helpers for escaping strings, formatting numbers, and writing
//! raw byte paths. The functions append directly to a caller-owned
//! `Vec<u8>` buffer — no intermediate `String` allocation.
//!
//! **None of the functions write surrounding `"`** — callers are expected
//! to emit quotes themselves as part of the larger JSON structure. This
//! avoids double-quoting when composing nested objects by hand.
//!
//! # Optimizations
//!
//! - **`write_u64`**: Two-digits-at-a-time lookup table (like `itoa` crate).
//!   Halves division count and eliminates the reverse pass.
//! - **`write_oid_hex`**: 256-entry byte-to-hex-pair lookup table with a
//!   single `reserve` + bulk write (unsafe `ptr::write` + `set_len`).
//! - **`write_json_str`** / **`write_json_bytes`**: SIMD fast path on
//!   aarch64 (NEON) and x86_64 (SSE2) — loads 16 bytes at a time, checks
//!   all-safe in parallel, and bulk-copies safe runs. Falls back to scalar
//!   for chunks containing characters that need escaping.
//!
//! # SIMD dispatch threshold
//!
//! Strings shorter than 16 bytes always take the scalar path — SIMD requires
//! at least one full 16-byte load. The threshold is checked at the call site
//! in [`write_json_str`] and [`write_json_bytes`].
//!
//! # Visibility
//!
//! Primitives here are crate-internal (`pub(crate)`). Benchmarks and fuzz
//! targets use the feature-gated `unified::harness_api` facade.
//!
//! # Caller responsibility
//!
//! **None of the string-writing functions emit surrounding `"` quotes.**
//! Callers must write quotes themselves:
//!
//! ```rust,ignore
//! buf.push(b'"');
//! write_json_str(my_string, &mut buf);
//! buf.push(b'"');
//! ```
//!
//! Forgetting quotes produces syntactically invalid JSON with no runtime error.

use crate::git_scan::object_id::OidBytes;

// ============================================================================
// Lookup tables
// ============================================================================

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Two-character decimal digit pairs for 00..99.
///
/// Used by `write_u64` to emit two digits per division, halving the number
/// of `udiv` instructions compared to one-digit-at-a-time.
const DIGIT_PAIRS: [[u8; 2]; 100] = {
    let mut table = [[0u8; 2]; 100];
    let mut i = 0u8;
    while i < 100 {
        table[i as usize] = [b'0' + i / 10, b'0' + i % 10];
        i += 1;
    }
    table
};

/// Byte-to-hex-pair lookup table: maps each byte 0x00..0xff to its
/// two-character lowercase hex representation.
///
/// Used by `write_oid_hex` to avoid per-nibble indexing into `HEX_DIGITS`.
const HEX_PAIRS: [[u8; 2]; 256] = {
    let mut table = [[0u8; 2]; 256];
    let digits = b"0123456789abcdef";
    let mut i = 0u16;
    while i < 256 {
        table[i as usize] = [digits[(i >> 4) as usize], digits[(i & 0xf) as usize]];
        i += 1;
    }
    table
};

// ============================================================================
// Primitives
// ============================================================================

/// Write an [`OidBytes`] as lowercase hex (without surrounding quotes).
///
/// Produces 40 hex characters for SHA-1 (20 bytes) and 64 for SHA-256
/// (32 bytes), matching `git log --format=%H` output.
///
/// Uses a 256-entry byte-to-hex-pair lookup table with a single `reserve`
/// and bulk `MaybeUninit::write` calls to eliminate per-byte bounds checks.
#[inline]
pub fn write_oid_hex(oid: &OidBytes, buf: &mut Vec<u8>) {
    let src = oid.as_slice();
    let out_len = src.len() * 2;
    buf.reserve(out_len);
    let base = buf.len();
    // SAFETY: `reserve` above guarantees at least `out_len` bytes of spare
    // capacity. We write exactly `out_len` bytes via `MaybeUninit::write`,
    // which is bounds-checked in debug builds, then advance the length.
    let spare = &mut buf.spare_capacity_mut()[..out_len];
    for (i, &b) in src.iter().enumerate() {
        let pair = HEX_PAIRS[b as usize];
        spare[i * 2].write(pair[0]);
        spare[i * 2 + 1].write(pair[1]);
    }
    // SAFETY: We wrote exactly `out_len` initialized bytes into spare capacity.
    unsafe {
        buf.set_len(base + out_len);
    }
}

/// Integer approximation of `log10(2) * 256 ~ 77.06`, used by [`digit_count`]
/// to convert a bit-width (from CLZ) into a digit-count estimate.
const LOG10_2_TIMES_256: usize = 77;

/// Count the number of decimal digits in a `u64`.
///
/// Uses a CLZ (count-leading-zeros) based approximation of log10:
///
///   `digit_estimate = (63 - clz(n)) * LOG10_2_TIMES_256 >> 8`
///
/// where `LOG10_2_TIMES_256 = 77` (the integer approximation of
/// `log10(2) * 256 ~ 77.06`). The estimate can be off by at most 1,
/// so a single comparison against the exact power-of-10 boundary corrects it.
#[inline(always)]
fn digit_count(n: u64) -> usize {
    // Powers of 10 for each digit count threshold.
    const P: [u64; 19] = [
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_000_000_000_000_000_000,
    ];
    // Count leading zeros to estimate digit count, then correct with a
    // comparison against the exact power-of-10 boundary.
    if n == 0 {
        return 1;
    }
    // log10(n) ~ (63 - clz(n)) * LOG10_2_TIMES_256 / 256
    let approx = ((63 - n.leading_zeros() as usize) * LOG10_2_TIMES_256) >> 8;
    // The approximation can be off by 1, so compare against the boundary.
    if approx < 19 && n >= P[approx] {
        approx + 2
    } else {
        approx + 1
    }
}

/// Write a u64 as decimal ASCII.
///
/// Uses a two-digits-at-a-time lookup table to halve the number of divisions.
/// Pre-computes the digit count via [`digit_count`], writes digits forward
/// into a stack buffer (two at a time from the least-significant end), then
/// copies to `buf` with a single `extend_from_slice` (memcpy).
#[inline]
pub fn write_u64(n: u64, buf: &mut Vec<u8>) {
    if n == 0 {
        buf.push(b'0');
        return;
    }

    let digits = digit_count(n);
    let mut tmp = [0u8; 20]; // u64::MAX is 20 digits
    let mut pos = digits;
    let mut v = n;

    // Process two digits at a time from the least-significant end.
    while v >= 100 {
        let rem = (v % 100) as usize;
        v /= 100;
        pos -= 2;
        tmp[pos] = DIGIT_PAIRS[rem][0];
        tmp[pos + 1] = DIGIT_PAIRS[rem][1];
    }

    // Handle remaining 1 or 2 digits.
    if v >= 10 {
        let rem = v as usize;
        tmp[0] = DIGIT_PAIRS[rem][0];
        tmp[1] = DIGIT_PAIRS[rem][1];
    } else {
        tmp[0] = b'0' + v as u8;
    }

    buf.extend_from_slice(&tmp[..digits]);
}

/// Write an `f64` as decimal with exactly 2 fractional digits.
///
/// The fractional part is obtained via `round((abs - trunc) * 100)`.
/// When rounding pushes the fraction to 100 (e.g. `1.995` → frac 100),
/// the integer part is incremented and the fraction reset to 0, so the
/// output is always well-formed (`"2.00"`, not `"1.100"`).
///
/// NaN and infinity are written as `0.00` to keep the output valid JSON.
///
/// Values with absolute magnitude above `u64::MAX` are clamped to
/// `u64::MAX.00` so carry handling cannot overflow.
#[inline]
pub fn write_f64(n: f64, buf: &mut Vec<u8>) {
    if n.is_nan() || n.is_infinite() {
        debug_assert!(
            false,
            "write_f64 called with non-finite value: {n}; emitting 0.00 as fallback"
        );
        buf.extend_from_slice(b"0.00");
        return;
    }
    let negative = n < 0.0;
    let abs = n.abs();
    // Clamp large finite values up-front so carry logic cannot overflow/wrap.
    if abs >= u64::MAX as f64 {
        if negative {
            buf.push(b'-');
        }
        write_u64(u64::MAX, buf);
        buf.extend_from_slice(b".00");
        return;
    }
    let trunc = abs.trunc();
    let mut integer = trunc as u64;
    let mut frac = ((abs - trunc) * 100.0).round() as u64;
    if frac >= 100 {
        integer = integer.saturating_add(1);
        frac -= 100;
    }

    if negative {
        buf.push(b'-');
    }
    write_u64(integer, buf);
    buf.push(b'.');
    if frac < 10 {
        buf.push(b'0');
    }
    write_u64(frac, buf);
}

/// Write a `bool` as `true` or `false`.
#[cfg(test)]
#[inline]
pub(crate) fn write_bool(v: bool, buf: &mut Vec<u8>) {
    if v {
        buf.extend_from_slice(b"true");
    } else {
        buf.extend_from_slice(b"false");
    }
}

// ============================================================================
// BufCursor — eliminate per-field bounds checks in encode functions
// ============================================================================

/// A write cursor over a `Vec<u8>` that defers `set_len` updates.
///
/// Pre-reserves a known amount of capacity, then writes static byte slices
/// and individual bytes via raw pointer arithmetic with no per-write bounds
/// check. Callers must [`commit`](Self::commit) before any operation that
/// might reallocate the underlying `Vec` (e.g. calling `write_json_str`),
/// and [`resume`](Self::resume) afterwards to re-acquire a valid pointer.
///
/// This pattern is already proven safe in [`write_oid_hex`] (which reserves
/// then writes via `ptr::write` + `set_len`). `BufCursor` generalizes it
/// for multi-field JSON encoding.
///
/// # Safety invariants
///
/// - `ptr` always points within `[buf.as_mut_ptr() + buf.len(), buf.as_mut_ptr() + buf.capacity())`
///   or is equal to `end` (no remaining capacity).
/// - `ptr <= end` at all times.
/// - `commit()` is called before any external mutation of `buf`.
pub(crate) struct BufCursor<'a> {
    buf: &'a mut Vec<u8>,
    ptr: *mut u8,
    end: *mut u8,
}

impl<'a> BufCursor<'a> {
    /// Reserve `additional` bytes and create a cursor positioned at `buf.len()`.
    #[inline(always)]
    pub(crate) fn new(buf: &'a mut Vec<u8>, additional: usize) -> Self {
        buf.reserve(additional);
        // SAFETY: `buf.reserve(additional)` above guarantees capacity >= len + additional.
        // `as_mut_ptr().add(len)` points to the first uninitialized byte, within the allocation.
        let ptr = unsafe { buf.as_mut_ptr().add(buf.len()) };
        // SAFETY: `as_mut_ptr().add(capacity)` is the one-past-end pointer of the allocation,
        // valid for comparison but not dereference.
        let end = unsafe { buf.as_mut_ptr().add(buf.capacity()) };
        Self { buf, ptr, end }
    }

    /// Write a fixed-content byte slice. Debug-asserts remaining capacity.
    ///
    /// "Static" refers to content whose length is known at the call site
    /// (JSON key literals, punctuation), not the Rust `'static` lifetime.
    #[inline(always)]
    pub(crate) fn push_static(&mut self, s: &[u8]) {
        debug_assert!(
            (self.end as usize) - (self.ptr as usize) >= s.len(),
            "BufCursor overflow: need {} bytes, have {}",
            s.len(),
            (self.end as usize) - (self.ptr as usize),
        );
        // SAFETY: Caller reserved sufficient capacity via `new()` or
        // `re_reserve()`. Debug-assert verifies in debug builds.
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr, s.len());
            self.ptr = self.ptr.add(s.len());
        }
    }

    /// Write a single byte. Debug-asserts remaining capacity.
    #[inline(always)]
    pub(crate) fn push_byte(&mut self, b: u8) {
        debug_assert!(
            self.ptr < self.end,
            "BufCursor overflow: need 1 byte, have 0",
        );
        // SAFETY: Same invariant as push_static.
        unsafe {
            *self.ptr = b;
            self.ptr = self.ptr.add(1);
        }
    }

    /// Write a u64 as decimal ASCII directly into the cursor.
    ///
    /// Requires at most 20 bytes of remaining capacity.
    #[inline(always)]
    pub(crate) fn push_u64(&mut self, n: u64) {
        debug_assert!(
            (self.end as usize) - (self.ptr as usize) >= 20,
            "BufCursor overflow: need 20 bytes for u64, have {}",
            (self.end as usize) - (self.ptr as usize),
        );
        if n == 0 {
            // SAFETY: debug_assert above guarantees >= 20 bytes of capacity; writing 1 byte.
            unsafe {
                *self.ptr = b'0';
                self.ptr = self.ptr.add(1);
            }
            return;
        }

        let digits = digit_count(n);
        // SAFETY: digit_count returns 1..=20, and we asserted capacity >= 20.
        unsafe {
            let base = self.ptr;
            let mut pos = digits;
            let mut v = n;

            while v >= 100 {
                let rem = (v % 100) as usize;
                v /= 100;
                pos -= 2;
                *base.add(pos) = DIGIT_PAIRS[rem][0];
                *base.add(pos + 1) = DIGIT_PAIRS[rem][1];
            }

            if v >= 10 {
                let rem = v as usize;
                *base = DIGIT_PAIRS[rem][0];
                *base.add(1) = DIGIT_PAIRS[rem][1];
            } else {
                *base = b'0' + v as u8;
            }

            self.ptr = self.ptr.add(digits);
        }
    }

    /// Commit cursor writes and return a mutable reference to the underlying
    /// buffer for external operations (e.g. `write_json_str`).
    ///
    /// This is the safe way to interleave cursor writes with dynamic content:
    /// ```ignore
    /// cur.push_static(b"prefix");
    /// let buf = cur.commit_to_buf();
    /// write_json_str("dynamic", buf);
    /// cur.resume(32);
    /// ```
    ///
    /// The returned reference borrows through `self`, so the cursor cannot be
    /// used until the reference is dropped. With NLL, this works naturally when
    /// the reference is consumed by a function call before `resume()`.
    #[inline(always)]
    pub(crate) fn commit_to_buf(&mut self) -> &mut Vec<u8> {
        self.commit();
        self.buf
    }

    /// Commit written bytes: updates the Vec's length to cover everything
    /// written via the cursor. Must be called before any operation that
    /// might reallocate the Vec (like `write_json_str`).
    #[inline(always)]
    pub(crate) fn commit(&mut self) {
        let new_len = self.ptr as usize - self.buf.as_ptr() as usize;
        debug_assert!(new_len <= self.buf.capacity());
        // SAFETY: All bytes between old len and new_len were initialized
        // by push_static / push_byte / push_u64.
        unsafe {
            self.buf.set_len(new_len);
        }
    }

    /// Re-acquire the write pointer after an external operation that may
    /// have reallocated the Vec (e.g. `write_json_str`). Also re-reserves
    /// `additional` bytes for subsequent cursor writes.
    #[inline(always)]
    pub(crate) fn resume(&mut self, additional: usize) {
        self.buf.reserve(additional);
        // SAFETY: reserve() guarantees capacity >= len + additional.
        // Both `len` and `capacity` are within the allocation, so the
        // resulting pointers are valid for the Vec's backing buffer.
        unsafe {
            self.ptr = self.buf.as_mut_ptr().add(self.buf.len());
            self.end = self.buf.as_mut_ptr().add(self.buf.capacity());
        }
    }
}

// ============================================================================
// JSON string escaping — scalar path
// ============================================================================

/// Scalar JSON string escaping (per-byte scan with bulk-copy of safe runs).
///
/// This is the fallback for all platforms and for strings shorter than 16 bytes
/// on aarch64 and x86_64.
#[inline(always)]
fn write_json_str_scalar(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let mut safe_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if needs_json_escape(b) {
            if safe_start < i {
                buf.extend_from_slice(&bytes[safe_start..i]);
            }
            escape_json_byte(b, buf);
            safe_start = i + 1;
        }
    }
    if safe_start < bytes.len() {
        buf.extend_from_slice(&bytes[safe_start..]);
    }
}

/// Scalar JSON byte-slice escaping.
///
/// Walks bytes left-to-right with three cases per byte:
///
/// - **ASCII special / control** (`"`, `\`, `0x00..=0x1f`) — JSON-escape.
/// - **ASCII printable** (`0x20..=0x7e`) — pass through verbatim.
/// - **High byte** (`0x80..=0xff`) — run `from_utf8` on the *entire*
///   remainder to decide how much is valid UTF-8. If the valid prefix is
///   non-empty, delegate it to [`write_json_str`] (which may use SIMD),
///   then advance `i` past the valid prefix and continue. If the byte at
///   `i` itself is invalid, escape it as `\u00XX` and advance by one.
fn write_json_bytes_scalar(bytes: &[u8], buf: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x00..=0x1f => {
                escape_json_byte(b, buf);
            }
            // ASCII printable: pass through.
            0x20..=0x7e => buf.push(b),
            // Potential multi-byte UTF-8 start: validate and pass through if valid.
            _ => {
                let remaining = &bytes[i..];
                match std::str::from_utf8(remaining) {
                    Ok(s) => {
                        write_json_str(s, buf);
                        return;
                    }
                    Err(e) => {
                        let valid_up_to = e.valid_up_to();
                        if valid_up_to > 0 {
                            // SAFETY: `from_utf8` returned `Err(e)` with
                            // `e.valid_up_to() == valid_up_to > 0`. Per the
                            // `Utf8Error::valid_up_to` API contract, the input
                            // up to that index is guaranteed to be valid UTF-8.
                            let valid =
                                unsafe { std::str::from_utf8_unchecked(&remaining[..valid_up_to]) };
                            write_json_str(valid, buf);
                            i += valid_up_to;
                            continue;
                        }
                        // Invalid byte: escape as \u00XX.
                        buf.extend_from_slice(b"\\u00");
                        buf.push(HEX_DIGITS[(b >> 4) as usize]);
                        buf.push(HEX_DIGITS[(b & 0xf) as usize]);
                    }
                }
            }
        }
        i += 1;
    }
}

/// Escape or pass-through a single byte — the universal per-byte handler.
///
/// Unlike [`escape_json_byte`] (which requires `needs_json_escape(byte)`),
/// this function handles *all* byte values: JSON-special bytes are escaped,
/// and everything else (printable ASCII, UTF-8 continuation bytes) is
/// pushed verbatim. Used by the SIMD tail loop where `i` may land
/// mid-codepoint, so the caller cannot distinguish safe-vs-unsafe up front.
#[inline(always)]
fn escape_single_byte(byte: u8, buf: &mut Vec<u8>) {
    match byte {
        b'"' => buf.extend_from_slice(b"\\\""),
        b'\\' => buf.extend_from_slice(b"\\\\"),
        b'\n' => buf.extend_from_slice(b"\\n"),
        b'\r' => buf.extend_from_slice(b"\\r"),
        b'\t' => buf.extend_from_slice(b"\\t"),
        0x00..=0x1f => {
            buf.extend_from_slice(b"\\u00");
            buf.push(HEX_DIGITS[(byte >> 4) as usize]);
            buf.push(HEX_DIGITS[(byte & 0xf) as usize]);
        }
        _ => buf.push(byte),
    }
}

// ============================================================================
// Escape helper functions
// ============================================================================

/// Returns `true` if `byte` requires JSON escaping.
///
/// Bytes that need escaping: `"`, `\`, and control characters 0x00..=0x1f.
/// All other bytes (printable ASCII 0x20..=0x7e excluding the two above,
/// and high bytes 0x80..=0xff for UTF-8 continuations) pass through verbatim
/// in valid JSON strings.
#[inline(always)]
fn needs_json_escape(byte: u8) -> bool {
    byte == b'"' || byte == b'\\' || byte < 0x20
}

/// Write the JSON escape sequence for a single byte.
///
/// # Precondition
///
/// Callers must ensure `needs_json_escape(byte)` is `true`. The fallthrough
/// arm (`_ => buf.push(byte)`) exists only as a defensive catch-all; in
/// correct usage it is unreachable. See [`escape_single_byte`] for the
/// variant that handles all byte values without a precondition.
#[inline(always)]
fn escape_json_byte(byte: u8, buf: &mut Vec<u8>) {
    match byte {
        b'"' => buf.extend_from_slice(b"\\\""),
        b'\\' => buf.extend_from_slice(b"\\\\"),
        b'\n' => buf.extend_from_slice(b"\\n"),
        b'\r' => buf.extend_from_slice(b"\\r"),
        b'\t' => buf.extend_from_slice(b"\\t"),
        0x00..=0x1f => {
            buf.extend_from_slice(b"\\u00");
            buf.push(HEX_DIGITS[(byte >> 4) as usize]);
            buf.push(HEX_DIGITS[(byte & 0xf) as usize]);
        }
        _ => buf.push(byte),
    }
}

// ============================================================================
// NEON SIMD fast path (aarch64 only)
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod neon {
    //! NEON (128-bit SIMD) fast path for JSON string escaping on AArch64.
    //!
    //! Each function loads 16 bytes at a time via `vld1q_u8`, classifies all
    //! lanes in parallel with [`is_all_safe_neon`], and either bulk-copies
    //! the chunk or bails to the scalar path for the remainder. The bail-out
    //! delegates the *entire* tail (not just 16 bytes) so that
    //! `write_json_bytes_scalar` can run its UTF-8 validation without
    //! splitting a multi-byte codepoint.

    use std::arch::aarch64::*;

    /// Check whether all 16 bytes in `chunk` are "safe" for JSON output:
    /// printable ASCII (0x20..=0x7e) excluding `"` (0x22) and `\` (0x5c),
    /// and no control characters.
    ///
    /// Returns `true` if every byte can be copied verbatim into a JSON string.
    ///
    /// # Safety
    ///
    /// Requires aarch64 NEON support (guaranteed on all AArch64 targets).
    #[inline(always)]
    pub(super) unsafe fn is_all_safe_neon(chunk: uint8x16_t) -> bool {
        // SAFETY: All intrinsics below require NEON, which is guaranteed on aarch64.
        unsafe {
            // Range check: byte >= 0x20 && byte <= 0x7e
            let lo = vdupq_n_u8(0x20);
            let hi = vdupq_n_u8(0x7e);
            let ge_lo = vcgeq_u8(chunk, lo);
            let le_hi = vcleq_u8(chunk, hi);
            let in_range = vandq_u8(ge_lo, le_hi);

            // Exclude quote and backslash
            let quote = vdupq_n_u8(b'"');
            let backslash = vdupq_n_u8(b'\\');
            let not_quote = vmvnq_u8(vceqq_u8(chunk, quote));
            let not_backslash = vmvnq_u8(vceqq_u8(chunk, backslash));

            // All conditions must hold for every lane
            let safe = vandq_u8(in_range, vandq_u8(not_quote, not_backslash));

            // Horizontal minimum: if the minimum lane is 0xff, all lanes are safe.
            vminvq_u8(safe) == 0xff
        }
    }

    /// NEON-accelerated JSON string escaping for `&str`.
    ///
    /// Processes 16 bytes at a time. If all 16 are safe, bulk-copies the chunk
    /// via pre-reserved unsafe pointer write (no per-chunk capacity check).
    /// When an escape-worthy byte is found in a chunk, the safe prefix of that
    /// chunk is copied, the unsafe byte is escaped via scalar, and SIMD scanning
    /// resumes from the next position.
    ///
    /// # Safety
    ///
    /// - `s` must be a valid `&str` (guaranteed by type system).
    /// - Requires aarch64 NEON support (guaranteed on all AArch64 targets).
    #[inline]
    pub(super) unsafe fn write_json_str_neon(s: &str, buf: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        // Pre-reserve for the no-escape case (input length). Escapes expand,
        // but write_json_str_scalar handles its own growth for those bytes.
        buf.reserve(bytes.len());
        let mut i = 0;

        // Process 16-byte chunks.
        while i + 16 <= bytes.len() {
            let chunk = vld1q_u8(bytes.as_ptr().add(i));
            if is_all_safe_neon(chunk) {
                // SAFETY: We pre-reserved `bytes.len()` bytes. At this point
                // we have written at most `i` bytes (all safe, 1:1 copy), and
                // are about to write 16 more. Since `i + 16 <= bytes.len()`
                // and we reserved `bytes.len()`, capacity is sufficient.
                let dst = buf.as_mut_ptr().add(buf.len());
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                buf.set_len(buf.len() + 16);
                i += 16;
            } else {
                // Find first JSON-escapable byte in this chunk. High bytes
                // (>= 0x80) are valid UTF-8 in a &str and can be copied
                // verbatim — only control chars, quote, and backslash need
                // escaping.
                let chunk_bytes = &bytes[i..i + 16];
                let mut j = 0;
                while j < 16 {
                    let b = chunk_bytes[j];
                    if b < 0x20 || b == b'"' || b == b'\\' {
                        break;
                    }
                    j += 1;
                }
                if j == 16 {
                    // No escape-worthy byte; the chunk was flagged only for
                    // high bytes (valid UTF-8). Bulk-copy the whole chunk.
                    let dst = buf.as_mut_ptr().add(buf.len());
                    std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                    buf.set_len(buf.len() + 16);
                    i += 16;
                } else {
                    // Copy safe prefix, escape the bad byte, resume.
                    if j > 0 {
                        let dst = buf.as_mut_ptr().add(buf.len());
                        std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, j);
                        buf.set_len(buf.len() + j);
                    }
                    super::escape_single_byte(chunk_bytes[j], buf);
                    i += j + 1;
                    // Re-reserve for remaining bytes (escapes may expand output).
                    buf.reserve(bytes.len() - i);
                }
            }
        }

        // Scalar tail for remaining < 16 bytes. Use byte-level escaping
        // to avoid requiring `i` to be on a char boundary (it might be
        // mid-codepoint after copying a chunk containing multi-byte UTF-8).
        for &b in &bytes[i..] {
            super::escape_single_byte(b, buf);
        }
    }

    /// NEON-accelerated JSON byte-slice escaping.
    ///
    /// Like `write_json_str_neon` but for arbitrary `&[u8]`. When a non-safe
    /// chunk is encountered, the *entire remainder* is delegated to the scalar
    /// path because the scalar path's UTF-8 validation for high bytes needs
    /// to see the full remaining slice to avoid splitting mid-codepoint.
    ///
    /// Safe chunks use pre-reserved unsafe pointer copy to eliminate per-chunk
    /// capacity checks.
    ///
    /// # Safety
    ///
    /// - `bytes` is a valid byte slice (trivially true).
    /// - Requires aarch64 NEON support (guaranteed on all AArch64 targets).
    #[inline]
    pub(super) unsafe fn write_json_bytes_neon(bytes: &[u8], buf: &mut Vec<u8>) {
        buf.reserve(bytes.len());
        let mut i = 0;

        while i + 16 <= bytes.len() {
            let chunk = vld1q_u8(bytes.as_ptr().add(i));
            if is_all_safe_neon(chunk) {
                // SAFETY: Pre-reserved bytes.len(). Safe chunks copy 1:1.
                let dst = buf.as_mut_ptr().add(buf.len());
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                buf.set_len(buf.len() + 16);
                i += 16;
            } else {
                // Non-safe byte found: delegate entire remainder to scalar.
                // (High bytes may be multi-byte UTF-8; scalar needs full tail.)
                super::write_json_bytes_scalar(&bytes[i..], buf);
                return;
            }
        }

        // Scalar tail for remaining < 16 bytes.
        if i < bytes.len() {
            super::write_json_bytes_scalar(&bytes[i..], buf);
        }
    }
}

// ============================================================================
// SSE2 SIMD fast path (x86_64 only)
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod sse2 {
    //! SSE2 (128-bit SIMD) fast path for JSON string escaping on x86_64.
    //!
    //! Mirrors the NEON module: 16-byte `_mm_loadu_si128` loads, parallel
    //! classification via [`is_all_safe_sse2`], bulk copy or bail to scalar.
    //! SSE2 is baseline on all x86_64 targets, so no runtime feature check
    //! is needed.

    use std::arch::x86_64::*;

    /// Check whether all 16 bytes in `chunk` are "safe" for JSON output:
    /// printable ASCII (0x20..=0x7e) excluding `"` (0x22) and `\` (0x5c),
    /// and no control characters.
    ///
    /// Returns `true` if every byte can be copied verbatim into a JSON string.
    ///
    /// # Safety
    ///
    /// Requires SSE2 support (guaranteed on all x86_64 targets).
    ///
    /// # SSE2 signed-comparison trick
    ///
    /// SSE2 only provides signed byte comparisons (`_mm_cmpgt_epi8`,
    /// `_mm_cmplt_epi8`). For the range we care about (0x20..=0x7e),
    /// all bytes are positive in two's complement (0x00..0x7f), so signed
    /// comparisons produce correct results:
    /// - `byte > 0x1f` is true for 0x20..0x7f (correct: includes our range)
    /// - `byte < 0x7f` is true for 0x00..0x7e (correct: excludes DEL)
    /// - High bytes (0x80..0xff) are negative, so `> 0x1f` is false (correct)
    #[inline(always)]
    pub(super) unsafe fn is_all_safe_sse2(chunk: __m128i) -> bool {
        // SAFETY: All intrinsics below require SSE2, which is guaranteed on x86_64.
        unsafe {
            // Range check: byte > 0x1f && byte < 0x7f  →  0x20..=0x7e
            let lo = _mm_set1_epi8(0x1f);
            let hi = _mm_set1_epi8(0x7f_u8 as i8);
            let gt_lo = _mm_cmpgt_epi8(chunk, lo); // byte > 0x1f
            let lt_hi = _mm_cmplt_epi8(chunk, hi); // byte < 0x7f
            let in_range = _mm_and_si128(gt_lo, lt_hi);

            // Exclude quote (0x22) and backslash (0x5c)
            let quote = _mm_set1_epi8(b'"' as i8);
            let backslash = _mm_set1_epi8(b'\\' as i8);
            let is_quote = _mm_cmpeq_epi8(chunk, quote);
            let is_backslash = _mm_cmpeq_epi8(chunk, backslash);
            let is_special = _mm_or_si128(is_quote, is_backslash);

            // safe = in_range AND NOT is_special
            let safe = _mm_andnot_si128(is_special, in_range);

            // Extract high bit of each byte. If all lanes are 0xff, movemask = 0xffff.
            _mm_movemask_epi8(safe) == 0xffff_i32
        }
    }

    /// SSE2-accelerated JSON string escaping for `&str`.
    ///
    /// Processes 16 bytes at a time. Safe chunks are bulk-copied via
    /// pre-reserved unsafe pointer write. When an escape-worthy byte is found,
    /// the safe prefix is copied, the byte is escaped via scalar, and SIMD
    /// scanning resumes.
    ///
    /// # Safety
    ///
    /// - `s` must be a valid `&str` (guaranteed by type system).
    /// - Requires SSE2 support (guaranteed on all x86_64 targets).
    #[inline]
    pub(super) unsafe fn write_json_str_sse2(s: &str, buf: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        buf.reserve(bytes.len());
        let mut i = 0;

        while i + 16 <= bytes.len() {
            let chunk = _mm_loadu_si128(bytes.as_ptr().add(i) as *const __m128i);
            if is_all_safe_sse2(chunk) {
                // SAFETY: Pre-reserved bytes.len(). Safe chunks copy 1:1.
                let dst = buf.as_mut_ptr().add(buf.len());
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                buf.set_len(buf.len() + 16);
                i += 16;
            } else {
                // Find first JSON-escapable byte. High bytes (>= 0x80) are
                // valid UTF-8 in a &str and can be copied verbatim.
                let chunk_bytes = &bytes[i..i + 16];
                let mut j = 0;
                while j < 16 {
                    let b = chunk_bytes[j];
                    if b < 0x20 || b == b'"' || b == b'\\' {
                        break;
                    }
                    j += 1;
                }
                if j == 16 {
                    // No escape-worthy byte; chunk flagged for high bytes only.
                    let dst = buf.as_mut_ptr().add(buf.len());
                    std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                    buf.set_len(buf.len() + 16);
                    i += 16;
                } else {
                    if j > 0 {
                        let dst = buf.as_mut_ptr().add(buf.len());
                        std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, j);
                        buf.set_len(buf.len() + j);
                    }
                    super::escape_single_byte(chunk_bytes[j], buf);
                    i += j + 1;
                    buf.reserve(bytes.len() - i);
                }
            }
        }

        // Scalar tail: byte-level to avoid char-boundary requirement on `i`.
        for &b in &bytes[i..] {
            super::escape_single_byte(b, buf);
        }
    }

    /// SSE2-accelerated JSON byte-slice escaping.
    ///
    /// Like `write_json_str_sse2` but for arbitrary `&[u8]`. When a non-safe
    /// chunk is encountered, the *entire remainder* is delegated to the scalar
    /// path to avoid splitting mid-codepoint in UTF-8 validation.
    ///
    /// Safe chunks use pre-reserved unsafe pointer copy.
    ///
    /// # Safety
    ///
    /// - `bytes` is a valid byte slice (trivially true).
    /// - Requires SSE2 support (guaranteed on all x86_64 targets).
    #[inline]
    pub(super) unsafe fn write_json_bytes_sse2(bytes: &[u8], buf: &mut Vec<u8>) {
        buf.reserve(bytes.len());
        let mut i = 0;

        while i + 16 <= bytes.len() {
            let chunk = _mm_loadu_si128(bytes.as_ptr().add(i) as *const __m128i);
            if is_all_safe_sse2(chunk) {
                // SAFETY: Pre-reserved bytes.len(). Safe chunks copy 1:1.
                let dst = buf.as_mut_ptr().add(buf.len());
                std::ptr::copy_nonoverlapping(bytes.as_ptr().add(i), dst, 16);
                buf.set_len(buf.len() + 16);
                i += 16;
            } else {
                // Non-safe byte: delegate entire remainder to scalar.
                super::write_json_bytes_scalar(&bytes[i..], buf);
                return;
            }
        }

        if i < bytes.len() {
            super::write_json_bytes_scalar(&bytes[i..], buf);
        }
    }
}

// ============================================================================
// Public dispatch functions
// ============================================================================

/// Write a JSON-escaped UTF-8 string (without surrounding quotes).
///
/// On aarch64, uses NEON SIMD to bulk-copy runs of safe ASCII characters.
/// On x86_64, uses SSE2 for the same 16-byte vectorized scan.
/// Falls back to scalar per-byte escaping for short strings or when
/// escape-worthy characters are encountered.
#[inline]
pub fn write_json_str(s: &str, buf: &mut Vec<u8>) {
    buf.reserve(s.len());
    #[cfg(target_arch = "aarch64")]
    {
        if s.len() >= 16 {
            // SAFETY: NEON is guaranteed on aarch64. The function operates on
            // a valid &str and writes only to the caller-owned Vec<u8>.
            unsafe {
                neon::write_json_str_neon(s, buf);
            }
            return;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if s.len() >= 16 {
            // SAFETY: SSE2 is guaranteed on x86_64. The function operates on
            // a valid &str and writes only to the caller-owned Vec<u8>.
            unsafe {
                sse2::write_json_str_sse2(s, buf);
            }
            return;
        }
    }
    write_json_str_scalar(s, buf);
}

/// Write raw bytes as a JSON string value (without surrounding quotes).
///
/// The algorithm walks `bytes` left-to-right:
///
/// 1. **ASCII control / special** (`0x00..=0x1f`, `"`, `\`) — JSON-escape.
/// 2. **ASCII printable** (`0x20..=0x7e`) — pass through verbatim.
/// 3. **High byte** (`0x80..=0xff`) — attempt UTF-8 validation on the
///    *remainder* of the slice:
///    - If the entire remainder is valid UTF-8, delegate to [`write_json_str`]
///      (which handles escaping of control chars within valid UTF-8) and return.
///    - Otherwise, copy the valid prefix via `write_json_str`, advance `i`
///      past it, and escape the first invalid byte as `\u00XX`. The loop then
///      continues from the next byte.
///
/// On aarch64 (NEON) and x86_64 (SSE2), a SIMD fast path scans 16 bytes at a
/// time for safe ASCII runs.
pub fn write_json_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    buf.reserve(bytes.len());
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() >= 16 {
            // SAFETY: NEON is guaranteed on aarch64. The function reads from a
            // valid byte slice and writes only to the caller-owned Vec<u8>.
            unsafe {
                neon::write_json_bytes_neon(bytes, buf);
            }
            return;
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if bytes.len() >= 16 {
            // SAFETY: SSE2 is guaranteed on x86_64. The function reads from a
            // valid byte slice and writes only to the caller-owned Vec<u8>.
            unsafe {
                sse2::write_json_bytes_sse2(bytes, buf);
            }
            return;
        }
    }
    write_json_bytes_scalar(bytes, buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // write_u64 tests
    // ========================================================================

    #[test]
    fn u64_values() {
        let mut buf = Vec::new();
        write_u64(0, &mut buf);
        assert_eq!(&buf, b"0");

        buf.clear();
        write_u64(42, &mut buf);
        assert_eq!(&buf, b"42");

        buf.clear();
        write_u64(u64::MAX, &mut buf);
        assert_eq!(std::str::from_utf8(&buf).unwrap(), u64::MAX.to_string());
    }

    #[test]
    fn u64_boundary_values() {
        let cases: &[(u64, &str)] = &[
            (0, "0"),
            (1, "1"),
            (9, "9"),
            (10, "10"),
            (99, "99"),
            (100, "100"),
            (999, "999"),
            (10000, "10000"),
            (u32::MAX as u64, "4294967295"),
            (u64::MAX, "18446744073709551615"),
        ];
        let mut buf = Vec::new();
        for &(val, expected) in cases {
            buf.clear();
            write_u64(val, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf).unwrap(),
                expected,
                "write_u64({val}) mismatch"
            );
        }
    }

    #[test]
    fn u64_matches_to_string() {
        let mut buf = Vec::new();
        // Test a spread of values across the entire u64 range.
        let values = [
            0,
            1,
            9,
            10,
            11,
            99,
            100,
            101,
            999,
            1000,
            9999,
            10000,
            99999,
            100000,
            999999,
            1000000,
            9999999,
            10000000,
            123456789,
            1000000000,
            1700000000,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            10_000_000_000,
            100_000_000_000,
            1_000_000_000_000,
            999_999_999_999_999,
            10_000_000_000_000_000,
            u64::MAX - 1,
            u64::MAX,
        ];
        for &n in &values {
            buf.clear();
            write_u64(n, &mut buf);
            assert_eq!(
                std::str::from_utf8(&buf).unwrap(),
                n.to_string(),
                "write_u64({n}) mismatch"
            );
        }
    }

    #[test]
    fn digit_count_correctness() {
        assert_eq!(digit_count(0), 1);
        assert_eq!(digit_count(1), 1);
        assert_eq!(digit_count(9), 1);
        assert_eq!(digit_count(10), 2);
        assert_eq!(digit_count(99), 2);
        assert_eq!(digit_count(100), 3);
        assert_eq!(digit_count(999), 3);
        assert_eq!(digit_count(9999), 4);
        assert_eq!(digit_count(10000), 5);
        assert_eq!(digit_count(u32::MAX as u64), 10);
        assert_eq!(digit_count(u64::MAX), 20);

        // Verify every power-of-10 boundary.
        let mut p: u64 = 1;
        for expected_digits in 1..=19 {
            assert_eq!(
                digit_count(p - 1),
                if p == 1 { 1 } else { expected_digits - 1 },
                "digit_count({}) should be {}",
                p - 1,
                if p == 1 { 1 } else { expected_digits - 1 }
            );
            assert_eq!(
                digit_count(p),
                expected_digits,
                "digit_count({p}) should be {expected_digits}"
            );
            if let Some(next) = p.checked_mul(10) {
                p = next;
            } else {
                break;
            }
        }
    }

    // ========================================================================
    // write_f64 tests
    // ========================================================================

    #[test]
    fn f64_values() {
        let mut buf = Vec::new();
        write_f64(0.0, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(81.23, &mut buf);
        assert_eq!(&buf, b"81.23");

        buf.clear();
        write_f64(-2.50, &mut buf);
        assert_eq!(&buf, b"-2.50");

        buf.clear();
        write_f64(-0.0, &mut buf);
        assert_eq!(&buf, b"0.00");
    }

    /// In release builds the debug_assert is compiled out and non-finite
    /// values silently fall back to `"0.00"`.
    #[cfg(not(debug_assertions))]
    #[test]
    fn f64_non_finite_fallback() {
        let mut buf = Vec::new();
        write_f64(f64::NAN, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(f64::INFINITY, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(f64::NEG_INFINITY, &mut buf);
        assert_eq!(&buf, b"0.00");
    }

    /// In debug builds, non-finite values trigger a debug_assert.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "non-finite value")]
    fn f64_nan_debug_assert() {
        let mut buf = Vec::new();
        write_f64(f64::NAN, &mut buf);
    }

    /// In debug builds, infinity triggers a debug_assert.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "non-finite value")]
    fn f64_infinity_debug_assert() {
        let mut buf = Vec::new();
        write_f64(f64::INFINITY, &mut buf);
    }

    /// In debug builds, negative infinity triggers a debug_assert.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "non-finite value")]
    fn f64_neg_infinity_debug_assert() {
        let mut buf = Vec::new();
        write_f64(f64::NEG_INFINITY, &mut buf);
    }

    #[test]
    fn f64_frac_rounds_to_100() {
        let mut buf = Vec::new();
        write_f64(99.996, &mut buf);
        assert_eq!(&buf, b"100.00");

        buf.clear();
        write_f64(1.995, &mut buf);
        assert_eq!(&buf, b"2.00");

        buf.clear();
        write_f64(0.999, &mut buf);
        assert_eq!(&buf, b"1.00");

        buf.clear();
        write_f64(-0.999, &mut buf);
        assert_eq!(&buf, b"-1.00");
    }

    #[test]
    fn f64_large_finite_values_clamp_without_overflow() {
        let mut buf = Vec::new();
        write_f64(1e20, &mut buf);
        assert_eq!(&buf, b"18446744073709551615.00");

        buf.clear();
        write_f64(-1e20, &mut buf);
        assert_eq!(&buf, b"-18446744073709551615.00");

        buf.clear();
        write_f64(f64::MAX, &mut buf);
        assert_eq!(&buf, b"18446744073709551615.00");
    }

    // ========================================================================
    // write_bool tests
    // ========================================================================

    #[test]
    fn bool_values() {
        let mut buf = Vec::new();
        write_bool(true, &mut buf);
        assert_eq!(&buf, b"true");

        buf.clear();
        write_bool(false, &mut buf);
        assert_eq!(&buf, b"false");
    }

    // ========================================================================
    // write_oid_hex tests
    // ========================================================================

    #[test]
    fn write_oid_hex_sha1() {
        let oid = OidBytes::sha1([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
            0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ]);
        let mut buf = Vec::new();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "deadbeef0123456789abcdeffedcba9876543210"
        );
        assert_eq!(buf.len(), 40);
    }

    #[test]
    fn write_oid_hex_sha256() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let oid = OidBytes::sha256(bytes);
        let mut buf = Vec::new();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn write_oid_hex_all_zero() {
        let oid = OidBytes::sha1([0x00; 20]);
        let mut buf = Vec::new();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn write_oid_hex_all_ff() {
        let oid = OidBytes::sha1([0xff; 20]);
        let mut buf = Vec::new();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "ffffffffffffffffffffffffffffffffffffffff"
        );
    }

    // ========================================================================
    // write_json_str tests
    // ========================================================================

    #[test]
    fn json_str_escaping() {
        let mut buf = Vec::new();
        write_json_str("path=\"foo\\bar\"\nnewline", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("\\\""));
        assert!(s.contains("\\\\"));
        assert!(s.contains("\\n"));
    }

    #[test]
    fn json_str_control_chars() {
        let mut buf = Vec::new();
        write_json_str("\x00\x1f", &mut buf);
        assert_eq!(&buf, b"\\u0000\\u001f");
    }

    #[test]
    fn json_str_simd_boundary_lengths() {
        // Verify correctness at lengths around SIMD boundaries (0, 1, 15, 16, 17, 31, 32, 33, 48, 64).
        let mut buf_new = Vec::new();
        let mut buf_scalar = Vec::new();
        for &len in &[0, 1, 15, 16, 17, 31, 32, 33, 48, 64] {
            let s: String = (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect();
            buf_new.clear();
            buf_scalar.clear();
            write_json_str(&s, &mut buf_new);
            write_json_str_scalar(&s, &mut buf_scalar);
            assert_eq!(buf_new, buf_scalar, "write_json_str mismatch at len={len}");
        }
    }

    #[test]
    fn json_str_escape_at_every_position() {
        // Place escape chars at positions 0..31 in a 32-byte string.
        let escape_chars = [b'"', b'\\', b'\n', 0x01];
        let mut buf_new = Vec::new();
        let mut buf_scalar = Vec::new();
        for &esc in &escape_chars {
            for pos in 0..32 {
                let mut bytes = vec![b'a'; 32];
                bytes[pos] = esc;
                // For control chars, make sure we build a valid str.
                let s = String::from_utf8(bytes).unwrap_or_else(|_| {
                    let mut bytes = vec![b'a'; 32];
                    bytes[pos] = esc;
                    // SAFETY: Every byte is either `b'a'` (ASCII) or `esc` which is a
                    // control char or ASCII punctuation — all valid single-byte UTF-8.
                    unsafe { String::from_utf8_unchecked(bytes) }
                });
                buf_new.clear();
                buf_scalar.clear();
                write_json_str(&s, &mut buf_new);
                write_json_str_scalar(&s, &mut buf_scalar);
                assert_eq!(
                    buf_new, buf_scalar,
                    "mismatch for esc=0x{esc:02x} at pos={pos}"
                );
            }
        }
    }

    // ========================================================================
    // write_json_bytes tests
    // ========================================================================

    #[test]
    fn json_bytes_valid_utf8() {
        let mut buf = Vec::new();
        write_json_bytes(b"hello world", &mut buf);
        assert_eq!(&buf, b"hello world");
    }

    #[test]
    fn json_bytes_invalid_utf8() {
        let mut buf = Vec::new();
        write_json_bytes(b"src/\xff/bad.rs", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert_eq!(s, "src/\\u00ff/bad.rs");
    }

    #[test]
    fn json_bytes_simd_then_scalar() {
        // 16 clean ASCII bytes + 0xff + rest — SIMD handles first chunk, scalar handles rest.
        let mut input = vec![b'a'; 16];
        input.push(0xff);
        input.extend_from_slice(b"/rest.rs");

        let mut buf_new = Vec::new();
        let mut buf_scalar = Vec::new();
        write_json_bytes(&input, &mut buf_new);
        write_json_bytes_scalar(&input, &mut buf_scalar);
        assert_eq!(buf_new, buf_scalar);
    }

    #[test]
    fn json_bytes_simd_boundary_lengths() {
        let mut buf_new = Vec::new();
        let mut buf_scalar = Vec::new();
        for &len in &[0, 1, 15, 16, 17, 31, 32, 33, 48, 64] {
            let input: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            buf_new.clear();
            buf_scalar.clear();
            write_json_bytes(&input, &mut buf_new);
            write_json_bytes_scalar(&input, &mut buf_scalar);
            assert_eq!(
                buf_new, buf_scalar,
                "write_json_bytes mismatch at len={len}"
            );
        }
    }

    // ========================================================================
    // Miri-targeted edge-case tests for unsafe paths
    // ========================================================================

    /// Exercise the `from_utf8_unchecked` path in `write_json_bytes_scalar`
    /// with invalid UTF-8 bytes at various positions. Miri validates the
    /// `from_utf8_unchecked` precondition (the prefix up to `valid_up_to`
    /// is genuinely valid UTF-8).
    #[test]
    fn miri_write_json_bytes_invalid_utf8_boundary() {
        let mut buf = Vec::new();

        // Invalid byte at position 0: no valid UTF-8 prefix.
        buf.clear();
        write_json_bytes(b"\xff hello", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.starts_with("\\u00ff"));

        // Invalid byte after a valid multi-byte sequence:
        // "é" = [0xc3, 0xa9], then 0xff forces scalar fallback with a
        // valid_up_to of 2.
        buf.clear();
        write_json_bytes(b"\xc3\xa9\xff rest", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("\\u00ff"), "output was: {s}");

        // Invalid byte splitting a multi-byte sequence: 0xc3 without
        // its continuation byte. `from_utf8` returns valid_up_to = 0,
        // so we skip the `from_utf8_unchecked` path entirely.
        buf.clear();
        write_json_bytes(b"\xc3\xff rest", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.starts_with("\\u00c3\\u00ff"), "output was: {s}");

        // Invalid byte at the end of a long run. The high byte (0x80+)
        // triggers the UTF-8 validation branch after ASCII processing.
        buf.clear();
        let mut input = b"abcdef1234567890".to_vec(); // 16 bytes (SIMD chunk)
        input.extend_from_slice(b"\xc3\xa9"); // valid 2-byte UTF-8
        input.push(0xff); // invalid
        input.extend_from_slice(b"tail");
        write_json_bytes(&input, &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("\\u00ff"), "output was: {s}");
        assert!(s.ends_with("tail"), "output was: {s}");

        // Multiple consecutive invalid bytes.
        buf.clear();
        write_json_bytes(b"\xfe\xff\x80\x81", &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert_eq!(s, "\\u00fe\\u00ff\\u0080\\u0081");
    }

    /// Exercise `write_oid_hex` under Miri with SHA-256 all-0xff (maximum
    /// byte values) to stress the ptr::write path with the highest table
    /// indices.
    #[test]
    fn miri_write_oid_hex_sha256_all_ff() {
        let oid = OidBytes::sha256([0xff; 32]);
        let mut buf = Vec::new();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(buf.len(), 64);
        assert!(buf.iter().all(|&b| b == b'f'));
    }

    /// Verify `write_oid_hex` into a non-empty buffer (offset != 0).
    /// This exercises the `base = buf.len()` path with a nonzero base
    /// pointer offset.
    #[test]
    fn miri_write_oid_hex_appends_to_nonempty() {
        let oid = OidBytes::sha1([0xab; 20]);
        let mut buf = Vec::from(b"prefix:" as &[u8]);
        write_oid_hex(&oid, &mut buf);
        assert_eq!(buf.len(), 7 + 40);
        assert_eq!(&buf[..7], b"prefix:");
        assert_eq!(
            std::str::from_utf8(&buf[7..]).unwrap(),
            "abababababababababababababababababababab"
        );
    }

    // ========================================================================
    // BufCursor tests
    // ========================================================================

    #[test]
    fn bufcursor_push_static_and_byte() {
        let mut buf = Vec::new();
        {
            let mut cur = BufCursor::new(&mut buf, 32);
            cur.push_static(b"hello ");
            cur.push_byte(b'w');
            cur.push_static(b"orld");
            cur.commit();
        }
        assert_eq!(&buf, b"hello world");
    }

    #[test]
    fn bufcursor_push_u64_values() {
        let cases: &[(u64, &str)] = &[
            (0, "0"),
            (1, "1"),
            (42, "42"),
            (100, "100"),
            (1_700_000_000, "1700000000"),
            (u64::MAX, "18446744073709551615"),
        ];
        for &(val, expected) in cases {
            let mut buf = Vec::new();
            {
                let mut cur = BufCursor::new(&mut buf, 20);
                cur.push_u64(val);
                cur.commit();
            }
            assert_eq!(
                std::str::from_utf8(&buf).unwrap(),
                expected,
                "BufCursor::push_u64({val}) mismatch"
            );
        }
    }

    #[test]
    fn bufcursor_commit_and_resume() {
        let mut buf = Vec::new();
        {
            let mut cur = BufCursor::new(&mut buf, 16);
            cur.push_static(b"abc");
            // Simulate an external write that may reallocate.
            cur.commit_to_buf().extend_from_slice(b"DEF");
            cur.resume(16);
            cur.push_static(b"ghi");
            cur.commit();
        }
        assert_eq!(&buf, b"abcDEFghi");
    }

    #[test]
    fn bufcursor_appends_to_nonempty() {
        let mut buf = Vec::from(b"prefix:" as &[u8]);
        {
            let mut cur = BufCursor::new(&mut buf, 16);
            cur.push_static(b"suffix");
            cur.commit();
        }
        assert_eq!(&buf, b"prefix:suffix");
    }

    #[test]
    fn bufcursor_push_u64_matches_write_u64() {
        let values = [
            0,
            1,
            9,
            10,
            99,
            100,
            999,
            1000,
            9999,
            10000,
            u32::MAX as u64,
            u64::MAX,
        ];
        for &n in &values {
            let mut buf_cursor = Vec::new();
            {
                let mut cur = BufCursor::new(&mut buf_cursor, 20);
                cur.push_u64(n);
                cur.commit();
            }
            let mut buf_write = Vec::new();
            write_u64(n, &mut buf_write);
            assert_eq!(
                buf_cursor, buf_write,
                "BufCursor::push_u64 vs write_u64 mismatch for n={n}"
            );
        }
    }

    // ========================================================================
    // SIMD classifier boundary tests
    // ========================================================================

    /// Test that the SIMD classifier correctly accepts/rejects boundary bytes
    /// at every lane position in a 16-byte window.
    #[test]
    fn simd_classifier_boundary_bytes() {
        // Bytes that must be JSON-escaped (backslash sequences):
        let escape_bytes = [
            0x00u8, 0x01, 0x0a, 0x0d, 0x09, 0x1f,  // control chars
            b'"',  // quote
            b'\\', // backslash
        ];
        // Bytes rejected by SIMD but handled by the scalar UTF-8 path
        // (not necessarily backslash-escaped -- 0x7f is valid UTF-8 and
        // passes through; 0x80/0xff are invalid standalone and get \u00XX):
        let simd_rejected_non_escape = [
            0x7fu8, // DEL: valid UTF-8, passes through verbatim
            0x80,   // first high byte: invalid standalone, gets \u00XX
            0xff,   // max byte: invalid standalone, gets \u00XX
        ];
        // Bytes that must be ACCEPTED by SIMD (pass through verbatim):
        let accept_bytes = [
            0x20u8, // space (first printable)
            b'a', b'z', b'A', b'Z', b'0', b'9', b'!',
            b'~', // 0x21, 0x7e (edges of printable range)
        ];

        let mut buf_dispatch = Vec::new();
        let mut buf_scalar = Vec::new();

        // Test each escape byte at every position 0..16 in a 16+ byte string
        for &b in &escape_bytes {
            for pos in 0..16 {
                let mut input = vec![b'a'; 32]; // safe baseline
                input[pos] = b;
                buf_dispatch.clear();
                buf_scalar.clear();
                write_json_bytes(&input, &mut buf_dispatch);
                write_json_bytes_scalar(&input, &mut buf_scalar);
                assert_eq!(
                    buf_dispatch, buf_scalar,
                    "escape byte 0x{b:02x} at lane {pos}: dispatch vs scalar mismatch"
                );
                // Verify the byte was actually escaped with a backslash
                let output = std::str::from_utf8(&buf_dispatch).unwrap();
                assert!(
                    output.contains('\\'),
                    "escape byte 0x{b:02x} at lane {pos} was not escaped: {output:?}"
                );
            }
        }

        // Test SIMD-rejected but non-escape bytes: just verify dispatch matches scalar
        for &b in &simd_rejected_non_escape {
            for pos in 0..16 {
                let mut input = vec![b'a'; 32]; // safe baseline
                input[pos] = b;
                buf_dispatch.clear();
                buf_scalar.clear();
                write_json_bytes(&input, &mut buf_dispatch);
                write_json_bytes_scalar(&input, &mut buf_scalar);
                assert_eq!(
                    buf_dispatch, buf_scalar,
                    "SIMD-rejected byte 0x{b:02x} at lane {pos}: dispatch vs scalar mismatch"
                );
            }
        }

        for &b in &accept_bytes {
            for pos in 0..16 {
                let mut input = vec![b'x'; 32]; // safe baseline
                input[pos] = b;
                buf_dispatch.clear();
                buf_scalar.clear();
                write_json_bytes(&input, &mut buf_dispatch);
                write_json_bytes_scalar(&input, &mut buf_scalar);
                assert_eq!(
                    buf_dispatch, buf_scalar,
                    "accept byte 0x{b:02x} at lane {pos}: dispatch vs scalar mismatch"
                );
            }
        }
    }

    // ========================================================================
    // write_f64 edge case tests
    // ========================================================================

    #[test]
    fn f64_edge_cases() {
        let mut buf = Vec::new();

        // Very small positive
        buf.clear();
        write_f64(0.01, &mut buf);
        assert_eq!(&buf, b"0.01");

        // Subnormal-like: very small fraction
        buf.clear();
        write_f64(0.001, &mut buf);
        assert_eq!(&buf, b"0.00"); // rounds to 0.00

        // Large value near u64 boundary
        buf.clear();
        write_f64(1_000_000_000.99, &mut buf);
        assert_eq!(&buf, b"1000000000.99");

        // Rounding boundary: 0.005 rounds to 0.01 (banker's rounding may vary)
        buf.clear();
        write_f64(0.005, &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s == "0.00" || s == "0.01", "0.005 rounded to {s}");

        // Rounding boundary: 0.015
        buf.clear();
        write_f64(0.015, &mut buf);
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s == "0.01" || s == "0.02", "0.015 rounded to {s}");

        // Negative fractional rounding
        buf.clear();
        write_f64(-99.999, &mut buf);
        assert_eq!(&buf, b"-100.00");
    }

    // ========================================================================
    // UTF-8 multibyte at SIMD boundary tests
    // ========================================================================

    /// Test multi-byte UTF-8 codepoints starting at byte 14 or 15 of a 16-byte
    /// SIMD window — ensures the SIMD->scalar handoff doesn't split a codepoint.
    #[test]
    fn utf8_multibyte_at_simd_boundary() {
        let mut buf_dispatch = Vec::new();
        let mut buf_scalar = Vec::new();

        // 2-byte UTF-8 (e = 0xC3 0xA9) starting at byte 14 of first 16-byte window
        let mut s = String::from("aaaaaaaaaaaaaa"); // 14 'a's
        s.push('\u{00e9}'); // 2 bytes: positions 14-15
        s.push_str("bbbbbbbbbbbbbbbb"); // 16 more bytes
        buf_dispatch.clear();
        buf_scalar.clear();
        write_json_str(&s, &mut buf_dispatch);
        write_json_str_scalar(&s, &mut buf_scalar);
        assert_eq!(buf_dispatch, buf_scalar, "2-byte UTF-8 at byte 14");

        // 3-byte UTF-8 (euro sign = 0xE2 0x82 0xAC) starting at byte 14 -- spans boundary
        let mut s = String::from("aaaaaaaaaaaaaa"); // 14 'a's
        s.push('\u{20ac}'); // 3 bytes: positions 14-16
        s.push_str("bbbbbbbbbbbbbbbb");
        buf_dispatch.clear();
        buf_scalar.clear();
        write_json_str(&s, &mut buf_dispatch);
        write_json_str_scalar(&s, &mut buf_scalar);
        assert_eq!(buf_dispatch, buf_scalar, "3-byte UTF-8 at byte 14");

        // 4-byte UTF-8 (U+1F389 = 0xF0 0x9F 0x8E 0x89) starting at byte 15
        let mut s = String::from("aaaaaaaaaaaaaaa"); // 15 'a's
        s.push('\u{1f389}'); // 4 bytes: positions 15-18
        s.push_str("bbbbbbbbbbbbbbbb");
        buf_dispatch.clear();
        buf_scalar.clear();
        write_json_str(&s, &mut buf_dispatch);
        write_json_str_scalar(&s, &mut buf_scalar);
        assert_eq!(buf_dispatch, buf_scalar, "4-byte UTF-8 at byte 15");
    }

    /// Regression: multi-byte codepoint straddling the last SIMD window into
    /// the < 16-byte tail.  Before the fix, the tail called
    /// `write_json_str_scalar(&s[i..])` where `i` was not a char boundary.
    #[test]
    fn utf8_multibyte_straddles_into_tail() {
        let mut buf_dispatch = Vec::new();
        let mut buf_scalar = Vec::new();

        // 14 ASCII + 4-byte codepoint (bytes 14-17) + 2 ASCII = 20 bytes.
        // SIMD processes window 0-15 byte-by-byte (non-ASCII at 14).
        // After: i=16, remaining tail = bytes 16-19 (4 bytes).
        // Byte 16 is a UTF-8 continuation byte, NOT a char boundary.
        let mut s = String::from("aaaaaaaaaaaaaa"); // 14 'a's
        s.push('\u{10B5E}'); // 4-byte: 0xF0 0x90 0xAD 0x9E
        s.push_str("bb"); // total = 20 bytes
        assert_eq!(s.len(), 20);
        assert!(!s.is_char_boundary(16)); // confirm the problematic position

        buf_dispatch.clear();
        buf_scalar.clear();
        write_json_str(&s, &mut buf_dispatch);
        write_json_str_scalar(&s, &mut buf_scalar);
        assert_eq!(
            buf_dispatch, buf_scalar,
            "4-byte codepoint straddling SIMD window into tail"
        );
    }
}

// ============================================================================
// Property-based tests (proptest)
// ============================================================================

#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1024,
            .. ProptestConfig::default()
        })]

        /// For any u64, `write_u64(n)` produces the same bytes as `n.to_string()`.
        #[test]
        fn prop_write_u64_matches_std(n: u64) {
            let mut buf = Vec::new();
            write_u64(n, &mut buf);
            let got = std::str::from_utf8(&buf).unwrap();
            prop_assert_eq!(got, &n.to_string());
        }

        /// For any valid UTF-8 string, `write_json_str` (which dispatches to
        /// the SIMD path on supported architectures) produces identical output
        /// to the scalar-only path.
        #[test]
        fn prop_write_json_str_simd_matches_scalar(s in "\\PC{0,256}") {
            let mut buf_dispatch = Vec::new();
            let mut buf_scalar = Vec::new();
            write_json_str(&s, &mut buf_dispatch);
            write_json_str_scalar(&s, &mut buf_scalar);
            prop_assert_eq!(buf_dispatch, buf_scalar);
        }

        /// For any byte slice, `write_json_bytes` (SIMD dispatch) produces
        /// identical output to `write_json_bytes_scalar`.
        #[test]
        fn prop_write_json_bytes_simd_matches_scalar(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut buf_dispatch = Vec::new();
            let mut buf_scalar = Vec::new();
            write_json_bytes(&bytes, &mut buf_dispatch);
            write_json_bytes_scalar(&bytes, &mut buf_scalar);
            prop_assert_eq!(buf_dispatch, buf_scalar);
        }

        /// For any 20-byte array, `write_oid_hex` produces the same hex
        /// string as per-byte `format!("{:02x}")`.
        #[test]
        fn prop_write_oid_hex_matches_format(raw in proptest::collection::vec(any::<u8>(), 20..=20)) {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&raw);
            let oid = OidBytes::sha1(arr);
            let mut buf = Vec::new();
            write_oid_hex(&oid, &mut buf);
            let expected: String = arr.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert_eq!(std::str::from_utf8(&buf).unwrap(), &expected);
        }

        /// For any u64, `BufCursor::push_u64` produces the same bytes as
        /// `write_u64`.
        #[test]
        fn prop_bufcursor_push_u64_matches_write_u64(n: u64) {
            let mut buf_cursor = Vec::new();
            {
                let mut cur = BufCursor::new(&mut buf_cursor, 20);
                cur.push_u64(n);
                cur.commit();
            }
            let mut buf_write = Vec::new();
            write_u64(n, &mut buf_write);
            prop_assert_eq!(buf_cursor, buf_write);
        }
    }
}

// ============================================================================
// Kani model-checking proofs
// ============================================================================

#[cfg(kani)]
mod verification {
    use super::*;

    // Kani proofs use concrete OID sizes (20 or 32) to avoid symbolic Vec
    // allocation blowup. The byte *values* remain symbolic, which is what
    // matters: Kani proves the pointer arithmetic in `write_oid_hex` is
    // safe for any byte content at both SHA-1 and SHA-256 lengths.

    /// Proves `write_oid_hex` pointer arithmetic stays within the
    /// allocated region for SHA-1 (20-byte) OIDs.
    ///
    /// Kani verifies:
    /// - `buf.as_mut_ptr().add(base + i*2)` is within allocation for all `i`
    /// - `buf.as_mut_ptr().add(base + i*2 + 1)` is within allocation for all `i`
    /// - `set_len(base + out_len)` does not exceed capacity
    #[kani::proof]
    #[kani::unwind(22)] // 20 iterations + 1
    fn verify_write_oid_hex_sha1_bounds() {
        let mut raw = [0u8; 20];
        for b in raw.iter_mut() {
            *b = kani::any();
        }
        let oid = OidBytes::sha1(raw);
        let mut buf = Vec::with_capacity(64);
        write_oid_hex(&oid, &mut buf);
        assert_eq!(buf.len(), 40);
    }

    /// Proves `write_oid_hex` pointer arithmetic stays within the
    /// allocated region for SHA-256 (32-byte) OIDs.
    #[kani::proof]
    #[kani::unwind(34)] // 32 iterations + 1
    fn verify_write_oid_hex_sha256_bounds() {
        let mut raw = [0u8; 32];
        for b in raw.iter_mut() {
            *b = kani::any();
        }
        let oid = OidBytes::sha256(raw);
        let mut buf = Vec::with_capacity(64);
        write_oid_hex(&oid, &mut buf);
        assert_eq!(buf.len(), 64);
    }

    /// Proves `write_oid_hex` appended to a non-empty buffer does not
    /// corrupt prior content or write out of bounds.
    #[kani::proof]
    #[kani::unwind(22)]
    fn verify_write_oid_hex_nonempty_buf() {
        let mut raw = [0u8; 20];
        for b in raw.iter_mut() {
            *b = kani::any();
        }
        let oid = OidBytes::sha1(raw);
        // Start with some existing content in the buffer.
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"prefix");
        let prefix_len = buf.len();
        write_oid_hex(&oid, &mut buf);
        assert_eq!(buf.len(), prefix_len + 40);
        // Verify prefix was not overwritten.
        assert_eq!(&buf[..prefix_len], b"prefix");
    }

    /// Proves `BufCursor::push_u64` writes exactly `digit_count(n)` bytes
    /// and stays within the pre-reserved capacity for any u64 value.
    #[kani::proof]
    #[kani::unwind(22)]
    fn verify_bufcursor_push_u64_bounds() {
        let n: u64 = kani::any();
        let mut buf = Vec::with_capacity(20);
        let mut cur = BufCursor::new(&mut buf, 20);
        cur.push_u64(n);
        cur.commit();
        assert_eq!(buf.len(), digit_count(n));
    }

    /// Proves `BufCursor` commit/resume cycle preserves buffer contents
    /// and pointer arithmetic stays within bounds.
    #[kani::proof]
    #[kani::unwind(2)]
    fn verify_bufcursor_commit_resume_bounds() {
        let extra: usize = kani::any();
        kani::assume(extra <= 256);
        let mut buf = Vec::with_capacity(64);
        let mut cur = BufCursor::new(&mut buf, 32);
        cur.push_static(b"test");
        cur.commit();
        assert_eq!(buf.len(), 4);
        cur.resume(extra);
        cur.push_byte(b'!');
        cur.commit();
        assert_eq!(buf.len(), 5);
    }
}
