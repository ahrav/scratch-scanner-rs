//! Path policy classifier for tree diff candidates.
//!
//! Emits a compact bitfield that marks paths as source/test/vendor/generated/
//! binary-ish/unknown using prefix and extension tables only. The classifier
//! is intentionally shallow: it does not inspect file contents and does not
//! allocate. Multiple bits may be set for the same path (for example a test
//! file is both `TEST` and `SOURCE`).

use core::ops::{BitOr, BitOrAssign};

use memchr::memrchr;

/// Bitfield classification for candidate paths.
///
/// This is a bitset, not a single-choice enum. The classifier will set
/// multiple bits if a path matches more than one heuristic.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathClass(u8);

impl PathClass {
    pub const SOURCE: Self = Self(1 << 0);
    pub const TEST: Self = Self(1 << 1);
    pub const VENDOR: Self = Self(1 << 2);
    pub const GENERATED: Self = Self(1 << 3);
    pub const BINARY: Self = Self(1 << 4);
    pub const UNKNOWN: Self = Self(1 << 5);

    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0 as u16
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for PathClass {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        PathClass(self.0 | rhs.0)
    }
}

impl BitOrAssign for PathClass {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Classifies a path into `PathClass` bitflags.
///
/// The classifier is case-insensitive and treats only `/` as a separator
/// (Git tree paths are normalized to `/`, even on Windows).
///
/// This function performs no heap allocation and operates on raw bytes.
#[must_use]
pub fn classify_path(path: &[u8]) -> PathClass {
    let mut class = PathClass::empty();

    if contains_segment(path, TEST_DIRS) {
        class |= PathClass::TEST;
    }
    if contains_segment(path, VENDOR_DIRS) {
        class |= PathClass::VENDOR;
    }
    if contains_segment(path, GENERATED_DIRS) {
        class |= PathClass::GENERATED;
    }
    if has_extension(path, BINARY_EXTS) {
        class |= PathClass::BINARY;
    }
    if has_extension(path, SOURCE_EXTS) {
        class |= PathClass::SOURCE;
    }

    if class.is_empty() {
        PathClass::UNKNOWN
    } else {
        class
    }
}

const TEST_DIRS: &[&[u8]] = &[
    b"test",
    b"tests",
    b"__tests__",
    b"spec",
    b"specs",
    b"fixture",
    b"fixtures",
    b"__fixtures__",
];

const VENDOR_DIRS: &[&[u8]] = &[
    b"vendor",
    b"third_party",
    b"third-party",
    b"thirdparty",
    b"deps",
    b"external",
    b"extern",
    b"node_modules",
];

const GENERATED_DIRS: &[&[u8]] = &[
    b"generated",
    b"gen",
    b"autogen",
    b"auto",
    b"build",
    b"dist",
    b"out",
    b"target",
    b"bazel-bin",
    b"bazel-out",
    b"buck-out",
];

const SOURCE_EXTS: &[&[u8]] = &[
    b"rs", b"c", b"h", b"cc", b"cpp", b"hpp", b"m", b"mm", b"go", b"java", b"kt", b"swift", b"py",
    b"js", b"jsx", b"ts", b"tsx", b"rb", b"php", b"cs", b"fs", b"scala", b"clj", b"groovy",
    b"dart", b"lua", b"sh", b"bash", b"zsh", b"ps1", b"toml", b"yaml", b"yml", b"json", b"xml",
    b"html", b"htm", b"css", b"scss", b"less", b"md", b"txt", b"cfg", b"ini", b"conf", b"sql",
    b"proto", b"gradle",
];

const BINARY_EXTS: &[&[u8]] = &[
    b"png", b"jpg", b"jpeg", b"gif", b"bmp", b"ico", b"tiff", b"webp", b"zip", b"gz", b"tgz",
    b"xz", b"bz2", b"7z", b"rar", b"tar", b"zst", b"pdf", b"doc", b"docx", b"ppt", b"pptx", b"xls",
    b"xlsx", b"mp3", b"wav", b"flac", b"ogg", b"mp4", b"mov", b"avi", b"mkv", b"woff", b"woff2",
    b"ttf", b"otf", b"exe", b"dll", b"so", b"dylib", b"bin", b"dat", b"db", b"sqlite", b"class",
    b"jar", b"war", b"wasm",
];

fn contains_segment(path: &[u8], table: &[&[u8]]) -> bool {
    let mut start = 0usize;
    while start <= path.len() {
        let end = match memchr::memchr(b'/', &path[start..]) {
            Some(idx) => start + idx,
            None => path.len(),
        };
        let seg = &path[start..end];
        if !seg.is_empty() {
            for &name in table {
                if eq_ignore_ascii_case(seg, name) {
                    return true;
                }
            }
        }
        if end == path.len() {
            break;
        }
        start = end + 1;
    }
    false
}

fn has_extension(path: &[u8], table: &[&[u8]]) -> bool {
    let ext = match file_extension(path) {
        Some(ext) => ext,
        None => return false,
    };
    for &candidate in table {
        if eq_ignore_ascii_case(ext, candidate) {
            return true;
        }
    }
    false
}

fn file_extension(path: &[u8]) -> Option<&[u8]> {
    let name_start = memrchr(b'/', path).map(|idx| idx + 1).unwrap_or(0);
    let name = &path[name_start..];
    let dot = memrchr(b'.', name)?;
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

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(&x, &y)| x.to_ascii_lowercase() == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_vendor_source() {
        let class = classify_path(b"vendor/lib/foo.rs");
        assert!(class.contains(PathClass::VENDOR));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_test_source() {
        let class = classify_path(b"tests/foo_test.py");
        assert!(class.contains(PathClass::TEST));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_generated_source() {
        let class = classify_path(b"generated/foo.go");
        assert!(class.contains(PathClass::GENERATED));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_binary() {
        let class = classify_path(b"assets/logo.png");
        assert!(class.contains(PathClass::BINARY));
        assert!(!class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_unknown() {
        let class = classify_path(b"data/blob.xyz");
        assert!(class.contains(PathClass::UNKNOWN));
    }
}
