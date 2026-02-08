//! Content classification for binary-aware scanning.
//!
//! Provides a unified policy for deciding whether file content should be
//! scanned as text, skipped as binary, or have text extracted from a known
//! binary format (`.ipynb`, `.class`, `.jar`/`.war`, `.pyc`).
//!
//! The primary entry point is [`classify_content`], which combines a NUL-byte
//! heuristic with extension matching to produce a [`ContentVerdict`].
//!
//! # Design
//!
//! - No heap allocation.
//! - Extension matching is case-insensitive on ASCII bytes.
//! - The NUL-byte heuristic mirrors Git's `buffer_is_binary` and uses
//!   `memchr` for SIMD-accelerated scanning.

#[cfg(feature = "binary-extract")]
pub mod extract;
#[cfg(feature = "binary-extract")]
pub mod ipynb;
#[cfg(feature = "binary-extract")]
pub mod jar_war;
#[cfg(feature = "binary-extract")]
pub mod java_class;
#[cfg(feature = "binary-extract")]
pub mod pyc;

/// Number of leading bytes to inspect for the NUL-byte heuristic.
pub const CHECK_LEN: usize = 8192;

/// Classification verdict for file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentVerdict {
    /// Content appears to be text — scan normally.
    Text,
    /// Content appears to be binary — skip unless `--scan-binary` is set.
    Binary,
    /// Content is a known binary format from which text can be extracted.
    BinaryExtractable(ExtractableFormat),
}

/// Binary formats that have a known text-extraction strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractableFormat {
    /// Jupyter Notebook (JSON with code cells).
    Ipynb,
    /// Compiled Java class file.
    JavaClass,
    /// Java archive (JAR/WAR) containing `.class` files.
    JarWar,
    /// Python compiled bytecode.
    Pyc,
}

/// Returns `true` if the first `check_len` bytes of `data` contain a NUL byte,
/// indicating the content is likely binary (images, compiled objects, etc.).
///
/// Uses `memchr` for SIMD-accelerated scanning, matching Git's own
/// `buffer_is_binary` heuristic. Empty data is not considered binary.
#[inline]
pub fn is_likely_binary(data: &[u8], check_len: usize) -> bool {
    if data.is_empty() {
        return false;
    }
    let end = data.len().min(check_len);
    memchr::memchr(0, &data[..end]).is_some()
}

/// Classify content by inspecting bytes and the file path extension.
///
/// 1. If no NUL byte is found in the first `check_len` bytes → [`ContentVerdict::Text`].
/// 2. If NUL bytes are present but the extension matches a known extractable
///    format → [`ContentVerdict::BinaryExtractable`].
/// 3. Otherwise → [`ContentVerdict::Binary`].
///
/// Empty data always returns [`ContentVerdict::Text`] (nothing to skip).
#[inline]
pub fn classify_content(data: &[u8], path: &[u8], check_len: usize) -> ContentVerdict {
    if !is_likely_binary(data, check_len) {
        // .ipynb files are JSON (text) but we still want to classify them as
        // extractable so the extractor can pull code cells only (ignoring
        // output blobs). Check extension even for text content.
        if let Some(fmt) = match_extractable_extension(path) {
            return ContentVerdict::BinaryExtractable(fmt);
        }
        return ContentVerdict::Text;
    }

    // Binary content — check if we know how to extract text from it.
    match match_extractable_extension(path) {
        Some(fmt) => ContentVerdict::BinaryExtractable(fmt),
        None => ContentVerdict::Binary,
    }
}

/// Match a file path's extension against known extractable binary formats.
fn match_extractable_extension(path: &[u8]) -> Option<ExtractableFormat> {
    let ext = file_extension(path)?;
    if eq_ignore_ascii_case(ext, b"ipynb") {
        return Some(ExtractableFormat::Ipynb);
    }
    if eq_ignore_ascii_case(ext, b"class") {
        return Some(ExtractableFormat::JavaClass);
    }
    if eq_ignore_ascii_case(ext, b"jar") || eq_ignore_ascii_case(ext, b"war") {
        return Some(ExtractableFormat::JarWar);
    }
    if eq_ignore_ascii_case(ext, b"pyc") {
        return Some(ExtractableFormat::Pyc);
    }
    None
}

/// Extract the file extension from a byte path (after the last `.` in the filename).
///
/// Returns `None` for dotfiles, paths ending in `.`, or paths with no extension.
fn file_extension(path: &[u8]) -> Option<&[u8]> {
    let name_start = memchr::memrchr(b'/', path).map(|idx| idx + 1).unwrap_or(0);
    let name = &path[name_start..];
    let dot = memchr::memrchr(b'.', name)?;
    if dot == 0 {
        return None;
    }
    let ext = &name[dot + 1..];
    if ext.is_empty() {
        None
    } else {
        Some(ext)
    }
}

/// Case-insensitive ASCII byte comparison.
///
/// `b` must be all-lowercase for correct results.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(&x, &y)| x.to_ascii_lowercase() == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_likely_binary ----

    #[test]
    fn empty_data_is_not_binary() {
        assert!(!is_likely_binary(b"", CHECK_LEN));
    }

    #[test]
    fn pure_text_is_not_binary() {
        assert!(!is_likely_binary(b"hello world\n", CHECK_LEN));
    }

    #[test]
    fn nul_at_start_is_binary() {
        assert!(is_likely_binary(b"\0hello", CHECK_LEN));
    }

    #[test]
    fn nul_beyond_check_len_not_detected() {
        let mut data = vec![b'a'; 100];
        data.push(0);
        assert!(!is_likely_binary(&data, 100));
    }

    #[test]
    fn nul_at_exact_boundary_detected() {
        let mut data = vec![b'a'; 99];
        data.push(0);
        assert!(is_likely_binary(&data, 100));
    }

    // ---- classify_content ----

    #[test]
    fn text_file_classified_as_text() {
        let data = b"fn main() { println!(\"hello\"); }";
        assert_eq!(
            classify_content(data, b"src/main.rs", CHECK_LEN),
            ContentVerdict::Text
        );
    }

    #[test]
    fn binary_file_classified_as_binary() {
        let mut data = vec![b'a'; 100];
        data[50] = 0;
        assert_eq!(
            classify_content(&data, b"image.png", CHECK_LEN),
            ContentVerdict::Binary
        );
    }

    #[test]
    fn ipynb_text_content_classified_as_extractable() {
        let data = b"{\"cells\": []}";
        assert_eq!(
            classify_content(data, b"notebook.ipynb", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::Ipynb)
        );
    }

    #[test]
    fn ipynb_binary_content_classified_as_extractable() {
        let mut data = vec![b'{'; 100];
        data[50] = 0;
        assert_eq!(
            classify_content(&data, b"notebook.ipynb", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::Ipynb)
        );
    }

    #[test]
    fn class_file_classified_as_extractable() {
        let data = b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34";
        assert_eq!(
            classify_content(data, b"Foo.class", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JavaClass)
        );
    }

    #[test]
    fn jar_file_classified_as_extractable() {
        let data = b"PK\x03\x04some jar content\x00\x00";
        assert_eq!(
            classify_content(data, b"app.jar", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JarWar)
        );
    }

    #[test]
    fn war_file_classified_as_extractable() {
        let data = b"PK\x03\x04some war content\x00\x00";
        assert_eq!(
            classify_content(data, b"app.war", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JarWar)
        );
    }

    #[test]
    fn pyc_file_classified_as_extractable() {
        let data = b"\x42\x0d\x0d\x0a\x00\x00\x00\x00";
        assert_eq!(
            classify_content(data, b"module.pyc", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::Pyc)
        );
    }

    // ---- case-insensitive extension matching ----

    #[test]
    fn uppercase_extension_matches() {
        let data = b"PK\x03\x04\x00";
        assert_eq!(
            classify_content(data, b"app.JAR", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JarWar)
        );
    }

    #[test]
    fn mixed_case_extension_matches() {
        let data = b"\xCA\xFE\xBA\xBE\x00";
        assert_eq!(
            classify_content(data, b"Foo.ClAsS", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JavaClass)
        );
    }

    // ---- file_extension helper ----

    #[test]
    fn extension_from_simple_path() {
        assert_eq!(file_extension(b"foo.txt"), Some(b"txt".as_slice()));
    }

    #[test]
    fn extension_from_nested_path() {
        assert_eq!(
            file_extension(b"src/main/Foo.java"),
            Some(b"java".as_slice())
        );
    }

    #[test]
    fn no_extension() {
        assert_eq!(file_extension(b"Makefile"), None);
    }

    #[test]
    fn dotfile_no_extension() {
        assert_eq!(file_extension(b".gitignore"), None);
    }

    #[test]
    fn trailing_dot_no_extension() {
        assert_eq!(file_extension(b"foo."), None);
    }

    #[test]
    fn double_extension_takes_last() {
        assert_eq!(file_extension(b"archive.tar.gz"), Some(b"gz".as_slice()));
    }

    // ---- empty / edge cases ----

    #[test]
    fn empty_data_classifies_as_text() {
        assert_eq!(
            classify_content(b"", b"empty.txt", CHECK_LEN),
            ContentVerdict::Text
        );
    }

    #[test]
    fn empty_path_with_binary_data() {
        let data = b"\x00\x01\x02";
        assert_eq!(
            classify_content(data, b"", CHECK_LEN),
            ContentVerdict::Binary
        );
    }
}
