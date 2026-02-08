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

use super::SourceKind;

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Write a [`SourceKind`] as its JSON string value (`fs` or `git`), without quotes.
#[inline(always)]
pub(crate) fn write_source(kind: SourceKind, buf: &mut Vec<u8>) {
    match kind {
        SourceKind::Fs => buf.extend_from_slice(b"fs"),
        SourceKind::Git => buf.extend_from_slice(b"git"),
    }
}

/// Write a u64 as decimal ASCII.
#[inline(always)]
pub(crate) fn write_u64(n: u64, buf: &mut Vec<u8>) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let start = buf.len();
    let mut v = n;
    while v > 0 {
        buf.push(b'0' + (v % 10) as u8);
        v /= 10;
    }
    buf[start..].reverse();
}

/// Write an f64 with 2 decimal places.
///
/// Handles NaN/Inf as `0.00` to avoid invalid JSON.
#[inline(always)]
pub(crate) fn write_f64(n: f64, buf: &mut Vec<u8>) {
    if n.is_nan() || n.is_infinite() {
        buf.extend_from_slice(b"0.00");
        return;
    }
    let negative = n < 0.0;
    let abs = n.abs();
    let mut integer = abs as u64;
    let mut frac = ((abs - integer as f64) * 100.0).round() as u64;
    if frac >= 100 {
        integer += 1;
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
#[inline(always)]
pub(crate) fn write_bool(v: bool, buf: &mut Vec<u8>) {
    if v {
        buf.extend_from_slice(b"true");
    } else {
        buf.extend_from_slice(b"false");
    }
}

/// Write a JSON-escaped UTF-8 string (without surrounding quotes).
#[inline(always)]
pub(crate) fn write_json_str(s: &str, buf: &mut Vec<u8>) {
    for byte in s.bytes() {
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
/// This avoids a full `from_utf8` over the entire input upfront while still
/// emitting valid multi-byte codepoints (e.g. emoji, CJK) as-is rather than
/// escaping each byte individually.
pub(crate) fn write_json_bytes(bytes: &[u8], buf: &mut Vec<u8>) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                buf.extend_from_slice(b"\\u00");
                buf.push(HEX_DIGITS[(b >> 4) as usize]);
                buf.push(HEX_DIGITS[(b & 0xf) as usize]);
            }
            // ASCII printable: pass through.
            0x20..=0x7e => buf.push(b),
            // Potential multi-byte UTF-8 start: validate and pass through if valid.
            _ => {
                let remaining = &bytes[i..];
                match std::str::from_utf8(remaining) {
                    Ok(s) => {
                        // Rest is valid UTF-8 — write it and done.
                        write_json_str(s, buf);
                        return;
                    }
                    Err(e) => {
                        let valid_up_to = e.valid_up_to();
                        if valid_up_to > 0 {
                            // Write the valid prefix.
                            // SAFETY: `from_utf8` proved `remaining[..valid_up_to]`
                            // is valid UTF-8.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn f64_values() {
        let mut buf = Vec::new();
        write_f64(0.0, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(81.23, &mut buf);
        assert_eq!(&buf, b"81.23");

        buf.clear();
        write_f64(f64::NAN, &mut buf);
        assert_eq!(&buf, b"0.00");

        buf.clear();
        write_f64(-2.50, &mut buf);
        assert_eq!(&buf, b"-2.50");
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
    fn bool_values() {
        let mut buf = Vec::new();
        write_bool(true, &mut buf);
        assert_eq!(&buf, b"true");

        buf.clear();
        write_bool(false, &mut buf);
        assert_eq!(&buf, b"false");
    }

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
}
