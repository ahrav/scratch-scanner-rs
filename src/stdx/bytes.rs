//! Byte-slice trimming utilities.
//!
//! ASCII-only equivalents of the nightly `[u8]::trim_ascii*` methods,
//! provided here so callers across the crate share one implementation
//! instead of defining local helpers.

/// Returns `bytes` with leading ASCII whitespace removed.
#[inline]
pub fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Returns `bytes` with trailing ASCII whitespace removed.
#[inline]
pub fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    &bytes[..end]
}

/// Returns `bytes` with leading and trailing ASCII whitespace removed.
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
