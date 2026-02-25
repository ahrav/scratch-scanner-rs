//! Shared encoding functions for deterministic mutation testing.
//!
//! Real-world secrets are often stored behind one or more encoding layers
//! (base64, percent-encoding, UTF-16, or combinations thereof). This module
//! provides a minimal, self-contained set of encoders that produce bit-identical
//! output for any given input, so that test cases built on top of them are fully
//! reproducible from a single seed.
//!
//! All functions are **pure** (no internal state or I/O), **deterministic**
//! (same input always yields the same output byte-for-byte), and
//! **allocation-aware** (capacity is pre-computed via `Vec::with_capacity` to
//! avoid redundant reallocations in hot loops).
//!
//! These encoders intentionally avoid pulling in external base64/percent-encoding
//! crates. Using our own implementations guarantees output stability across
//! dependency updates and keeps the test oracle self-contained.

use serde::{Deserialize, Serialize};

/// Encoding layer applied to a secret before it appears in a file.
///
/// The detection engine must see through these layers to find the underlying
/// token. Each variant corresponds to a transform the engine is expected to
/// reverse during scanning. `Nested` models the real-world pattern of
/// double- or triple-encoded credentials (e.g. base64-inside-percent-encoding).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SecretRepr {
    /// No encoding -- the raw token bytes appear verbatim.
    Raw,
    /// Standard base-64 with `=` padding (RFC 4648 section 4).
    Base64,
    /// Every byte percent-encoded as `%XX` with uppercase hex.
    UrlPercent,
    /// ASCII widened to UTF-16 little-endian (zero high byte, value low byte).
    Utf16Le,
    /// ASCII widened to UTF-16 big-endian (zero high byte first).
    Utf16Be,
    /// Alternating base64 and percent-encoding layers, applied `depth` times.
    /// Depth 0 is equivalent to `Raw`.
    Nested { depth: u8 },
}

/// Standard base-64 alphabet (RFC 4648 §4).
pub const BASE64_STD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Uppercase-alphanumeric token alphabet used by the sim scanner generator.
pub const TOKEN_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Base-62 character table in GMP ordering: `0-9`, `A-Z`, `a-z`.
///
/// Matches `BASE62_LUT` in `engine/offline_validate.rs`.
pub const BASE62_CHARS: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Encode a `u32` as a base-62 string into a caller-provided buffer.
///
/// Writes exactly `buf.len()` characters, zero-padding from the left with `'0'`
/// (the base-62 digit for zero). If `val` is too large to fit in `buf.len()`
/// digits, the high-order digits are silently lost -- callers must ensure the
/// buffer is wide enough for the value range they use (6 chars suffice for any
/// `u32`, since 62^6 > 2^32).
pub fn base62_encode_u32(mut val: u32, buf: &mut [u8]) {
    for slot in buf.iter_mut().rev() {
        *slot = BASE62_CHARS[(val % 62) as usize];
        val /= 62;
    }
}

/// Dispatch raw token bytes through the encoding layer described by `repr`.
///
/// This is the top-level entry point used by mutation operators and the
/// scenario generator to wrap a token in its target encoding.
pub fn encode_secret(raw: &[u8], repr: &SecretRepr) -> Vec<u8> {
    match repr {
        SecretRepr::Raw => raw.to_vec(),
        SecretRepr::Base64 => base64_encode_std(raw),
        SecretRepr::UrlPercent => percent_encode_all(raw),
        SecretRepr::Utf16Le => encode_utf16(raw, false),
        SecretRepr::Utf16Be => encode_utf16(raw, true),
        SecretRepr::Nested { depth } => encode_nested(raw, *depth, super::op::MAX_OUTPUT_BYTES),
    }
}

/// Base64-encode with the standard alphabet and `=` padding (RFC 4648 section 4).
///
/// Processes input in 3-byte groups, each producing 4 output characters.
/// A 1-byte remainder yields 2 characters plus `==`; a 2-byte remainder
/// yields 3 characters plus `=`. Empty input produces empty output.
pub fn base64_encode_std(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(BASE64_STD[(n & 63) as usize]);
        i += 3;
    }

    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(b'=');
    }

    out
}

/// Percent-encode **every** byte as `%XX` using uppercase hex digits.
///
/// Unlike standard URL percent-encoding, which leaves unreserved characters
/// (alphanumerics, `-._~`) unencoded, this function encodes all bytes
/// unconditionally. This worst-case encoding is needed to exercise the
/// detection engine's percent-decoding path on every byte position.
pub fn percent_encode_all(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().saturating_mul(3));
    for &b in input {
        out.push(b'%');
        out.push(hex_nibble((b >> 4) & 0x0f));
        out.push(hex_nibble(b & 0x0f));
    }
    out
}

/// Apply alternating base64 and percent-encoding layers `depth` times.
///
/// The layering pattern (even layers = base64, odd layers = percent) mimics
/// credentials that have been encoded multiple times by different systems
/// (e.g. a base64 token stored in a URL query parameter that is itself
/// percent-encoded).
///
/// After each layer, the intermediate size is checked against `max_bytes`.
/// If exceeded, the function returns the last result that fit within the
/// limit. This prevents transient multi-megabyte allocations when deep
/// nesting is applied to large inputs.
///
/// Depth 0 returns the raw bytes unchanged.
pub fn encode_nested(raw: &[u8], depth: u8, max_bytes: usize) -> Vec<u8> {
    if depth == 0 {
        return raw.to_vec();
    }
    let mut cur = raw.to_vec();
    for i in 0..depth {
        let next = if i % 2 == 0 {
            base64_encode_std(&cur)
        } else {
            percent_encode_all(&cur)
        };
        if next.len() > max_bytes {
            return cur;
        }
        cur = next;
    }
    cur
}

/// Widen ASCII bytes into UTF-16 code units.
///
/// Each input byte is zero-extended to a 16-bit code unit. This is only correct
/// for code points in the ASCII range (0x00-0x7F); it is **not** a general
/// Unicode encoder. That limitation is fine here because all generated tokens
/// consist exclusively of ASCII characters.
pub fn encode_utf16(bytes: &[u8], be: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        let hi = 0u8;
        let lo = b;
        if be {
            out.push(hi);
            out.push(lo);
        } else {
            out.push(lo);
            out.push(hi);
        }
    }
    out
}

/// Base64url-encode without padding (RFC 4648 §5, no `=`).
///
/// Transforms standard base64 output: `+` → `-`, `/` → `_`, strip `=`.
pub fn base64url_encode_nopad(input: &[u8]) -> Vec<u8> {
    let mut out = base64_encode_std(input);
    for b in out.iter_mut() {
        match *b {
            b'+' => *b = b'-',
            b'/' => *b = b'_',
            _ => {}
        }
    }
    // Strip trailing '=' padding.
    while out.last() == Some(&b'=') {
        out.pop();
    }
    out
}

/// Convert a nibble (0--15) to an uppercase hex ASCII byte (`'0'`--`'F'`).
///
/// Panics in debug builds if `n >= 16`.
pub fn hex_nibble(n: u8) -> u8 {
    debug_assert!(n < 16);
    match n {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Serde roundtrip regression for SecretRepr --

    #[test]
    fn secret_repr_serde_roundtrip() {
        let cases: &[(&str, SecretRepr)] = &[
            (r#""Raw""#, SecretRepr::Raw),
            (r#""Base64""#, SecretRepr::Base64),
            (r#""UrlPercent""#, SecretRepr::UrlPercent),
            (r#""Utf16Le""#, SecretRepr::Utf16Le),
            (r#""Utf16Be""#, SecretRepr::Utf16Be),
            (r#"{"Nested":{"depth":2}}"#, SecretRepr::Nested { depth: 2 }),
        ];
        for (json, expected) in cases {
            let de: SecretRepr = serde_json::from_str(json).unwrap();
            let re = serde_json::to_string(&de).unwrap();
            let re_de: SecretRepr = serde_json::from_str(&re).unwrap();
            // Compare via JSON to avoid needing PartialEq.
            assert_eq!(
                serde_json::to_string(&expected).unwrap(),
                serde_json::to_string(&re_de).unwrap(),
                "roundtrip failed for {json}",
            );
        }
    }

    // -- Encoding output stability --

    #[test]
    fn base64_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode_std(b""), b"");
        assert_eq!(base64_encode_std(b"f"), b"Zg==");
        assert_eq!(base64_encode_std(b"fo"), b"Zm8=");
        assert_eq!(base64_encode_std(b"foo"), b"Zm9v");
        assert_eq!(base64_encode_std(b"foob"), b"Zm9vYg==");
        assert_eq!(base64_encode_std(b"fooba"), b"Zm9vYmE=");
        assert_eq!(base64_encode_std(b"foobar"), b"Zm9vYmFy");
    }

    #[test]
    fn percent_encode_known() {
        assert_eq!(percent_encode_all(b"AB"), b"%41%42");
        assert_eq!(percent_encode_all(b"\x00\xff"), b"%00%FF");
    }

    #[test]
    fn utf16_le_known() {
        assert_eq!(encode_utf16(b"AB", false), &[b'A', 0, b'B', 0]);
    }

    #[test]
    fn utf16_be_known() {
        assert_eq!(encode_utf16(b"AB", true), &[0, b'A', 0, b'B']);
    }

    #[test]
    fn nested_depth_zero_is_identity() {
        let raw = b"hello";
        assert_eq!(encode_nested(raw, 0, usize::MAX), raw);
    }

    #[test]
    fn nested_depth_two() {
        let raw = b"hi";
        let d1 = base64_encode_std(raw); // base64 layer
        let d2 = percent_encode_all(&d1); // percent layer
        assert_eq!(encode_nested(raw, 2, usize::MAX), d2);
    }

    // -- base64url --

    #[test]
    fn base64url_replaces_plus_slash_strips_padding() {
        // Input that produces '+' and '/' in standard base64.
        let input = &[0xFB, 0xFF, 0xFE];
        let std = base64_encode_std(input);
        let url = base64url_encode_nopad(input);

        assert!(std.contains(&b'+') || std.contains(&b'/'));
        assert!(!url.contains(&b'+'));
        assert!(!url.contains(&b'/'));
        assert!(!url.contains(&b'='));
    }

    #[test]
    fn base64url_no_padding() {
        // "f" base64 = "Zg==" → base64url = "Zg"
        assert_eq!(base64url_encode_nopad(b"f"), b"Zg");
        // "fo" base64 = "Zm8=" → base64url = "Zm8"
        assert_eq!(base64url_encode_nopad(b"fo"), b"Zm8");
        // "foo" base64 = "Zm9v" → base64url = "Zm9v"
        assert_eq!(base64url_encode_nopad(b"foo"), b"Zm9v");
    }

    // -- base62 --

    #[test]
    fn base62_encode_known_values() {
        let mut buf = [0u8; 6];
        base62_encode_u32(0, &mut buf);
        assert_eq!(&buf, b"000000");

        base62_encode_u32(1, &mut buf);
        assert_eq!(&buf, b"000001");

        // 62 decimal = "000010" in base-62 (1*62 + 0)
        base62_encode_u32(62, &mut buf);
        assert_eq!(&buf, b"000010");

        // Verify single digit "A" in 1-char buffer.
        let mut buf1 = [0u8; 1];
        base62_encode_u32(10, &mut buf1);
        assert_eq!(&buf1, b"A");
    }

    #[test]
    fn base62_roundtrip() {
        // Inline a minimal decode for test verification.
        fn decode(bytes: &[u8]) -> u32 {
            let mut acc: u64 = 0;
            for &b in bytes {
                let v = match b {
                    b'0'..=b'9' => (b - b'0') as u64,
                    b'A'..=b'Z' => (b - b'A') as u64 + 10,
                    b'a'..=b'z' => (b - b'a') as u64 + 36,
                    _ => panic!("invalid base62 char"),
                };
                acc = acc * 62 + v;
            }
            acc as u32
        }

        for val in [0u32, 1, 61, 62, 3843, 100_000, u32::MAX] {
            let mut buf = [0u8; 6];
            base62_encode_u32(val, &mut buf);
            assert_eq!(decode(&buf), val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn encode_nested_respects_max_bytes() {
        // ~100KB input at depth 4: base64 (~133KB) → percent (~400KB) → base64 (~533KB) → percent (~1.6MB).
        // With a 512KB cap, the function should stop before the final percent layer.
        let input = vec![0xABu8; 100_000];
        let max = 512 * 1024;
        let result = encode_nested(&input, 4, max);
        assert!(
            result.len() <= max,
            "encode_nested exceeded max_bytes: {} > {max}",
            result.len(),
        );
        // Should have applied at least one layer (base64 of 100KB ≈ 133KB < 512KB).
        assert_ne!(
            result, input,
            "at least one encoding layer should have been applied"
        );
    }
}
