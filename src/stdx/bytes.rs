//! Byte-slice ASCII whitespace trimming.
//!
//! Free-function equivalents of [`[u8]::trim_ascii*`][std] (stable since
//! Rust 1.80). Kept as free functions so call sites that receive an
//! intermediate `&[u8]` from a chain can pass it directly without rebinding.
//!
//! "ASCII whitespace" is the set recognised by [`u8::is_ascii_whitespace`]:
//! space (`0x20`), horizontal tab (`0x09`), newline (`0x0A`), vertical tab
//! (`0x0B`), form feed (`0x0C`), and carriage return (`0x0D`). Non-ASCII
//! bytes (including UTF-8 multi-byte whitespace like `\u{00A0}`) are never
//! stripped — this is intentional because callers operate on raw `&[u8]`
//! streams that have not been validated as UTF-8.
//!
//! All functions return borrowed subslices and never allocate.
//!
//! [std]: https://doc.rust-lang.org/std/primitive.slice.html#method.trim_ascii

/// Returns `bytes` with leading ASCII whitespace removed.
///
/// Returns an empty slice when the input is empty or entirely whitespace.
#[inline]
pub fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Returns `bytes` with trailing ASCII whitespace removed.
///
/// Returns an empty slice when the input is empty or entirely whitespace.
#[inline]
pub fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        // None means every byte is whitespace → empty slice.
        .map_or(0, |p| p + 1);
    &bytes[..end]
}

/// Returns `bytes` with both leading and trailing ASCII whitespace removed.
///
/// Equivalent to `trim_ascii_end(trim_ascii_start(bytes))`.
/// Returns an empty slice when the input is empty or entirely whitespace.
#[inline]
pub fn trim_ascii(bytes: &[u8]) -> &[u8] {
    trim_ascii_end(trim_ascii_start(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_start_removes_leading_whitespace() {
        assert_eq!(trim_ascii_start(b"  hello"), b"hello");
        assert_eq!(trim_ascii_start(b"\t\n x"), b"x");
    }

    #[test]
    fn trim_end_removes_trailing_whitespace() {
        assert_eq!(trim_ascii_end(b"hello  "), b"hello");
        assert_eq!(trim_ascii_end(b"x \t\n"), b"x");
    }

    #[test]
    fn trim_both_sides() {
        assert_eq!(trim_ascii(b"  hello  "), b"hello");
    }

    #[test]
    fn all_whitespace_yields_empty() {
        assert_eq!(trim_ascii(b"   \t\n "), b"" as &[u8]);
        assert_eq!(trim_ascii_start(b"  "), b"" as &[u8]);
        assert_eq!(trim_ascii_end(b"  "), b"" as &[u8]);
    }

    #[test]
    fn empty_input() {
        assert_eq!(trim_ascii(b""), b"" as &[u8]);
        assert_eq!(trim_ascii_start(b""), b"" as &[u8]);
        assert_eq!(trim_ascii_end(b""), b"" as &[u8]);
    }

    #[test]
    fn no_whitespace_is_noop() {
        assert_eq!(trim_ascii(b"hello"), b"hello");
    }
}
