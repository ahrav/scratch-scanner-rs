//! Archive kind detection.
//!
//! # Invariants
//! - Detection is case-insensitive and suffix-based.
//! - `.tar.gz` and `.tgz` are treated as a chain kind `TarGz`.
//!
//! # Algorithm
//! - Prefer extension-based detection (cheap, no I/O).
//! - Optionally sniff magic bytes when a header slice is available.
//!
//! # Design Notes
//! - Magic sniffing cannot distinguish `.tar.gz` from `.gz` without decompressing,
//!   so extensions always win for `TarGz`.

use std::path::Path;

use super::formats::{is_gzip_magic, is_ustar_header, is_zip_magic};

/// Archive container kind.
///
/// `TarGz` represents a gzip-compressed tar stream (container semantics),
/// while `Gzip` represents a standalone gzip stream.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveKind {
    Gzip = 0,
    Tar = 1,
    Zip = 2,
    TarGz = 3,
}

impl ArchiveKind {
    #[inline(always)]
    pub const fn is_container(self) -> bool {
        matches!(
            self,
            ArchiveKind::Tar | ArchiveKind::Zip | ArchiveKind::TarGz
        )
    }
}

/// Detect by path filename suffixes, without allocating.
///
/// Returns None if no recognized suffix matches.
pub fn detect_kind_from_path(path: &Path) -> Option<ArchiveKind> {
    let name = path.file_name()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        detect_kind_from_name_bytes(name.as_bytes())
    }

    #[cfg(not(unix))]
    {
        // NOTE: non-UTF8 filenames are treated as "unknown" to avoid
        // allocations on platforms without byte-level path access.
        let s = name.to_str()?;
        detect_kind_from_name(s)
    }
}

/// Detect by a filename string (lossy or real).
pub fn detect_kind_from_name(name: &str) -> Option<ArchiveKind> {
    let b = name.as_bytes();

    // Prefer multi-suffix first.
    if ends_with_ignore_ascii_case(b, b".tar.gz") || ends_with_ignore_ascii_case(b, b".tgz") {
        return Some(ArchiveKind::TarGz);
    }
    if ends_with_ignore_ascii_case(b, b".gz") {
        return Some(ArchiveKind::Gzip);
    }
    if ends_with_ignore_ascii_case(b, b".tar") {
        return Some(ArchiveKind::Tar);
    }
    if ends_with_ignore_ascii_case(b, b".zip") {
        return Some(ArchiveKind::Zip);
    }
    None
}

/// Sniff by magic bytes in a header buffer.
///
/// This is only reliable for gzip and zip. For tar, it detects ustar only if
/// the first 512 bytes are available.
pub fn sniff_kind_from_header(header: &[u8]) -> Option<ArchiveKind> {
    if is_gzip_magic(header) {
        return Some(ArchiveKind::Gzip);
    }
    if is_zip_magic(header) {
        return Some(ArchiveKind::Zip);
    }
    if is_ustar_header(header) {
        return Some(ArchiveKind::Tar);
    }
    None
}

/// Combined detection:
/// - extension first
/// - fallback to sniff if extension yields None
pub fn detect_kind(path: &Path, header_opt: Option<&[u8]>) -> Option<ArchiveKind> {
    if let Some(k) = detect_kind_from_path(path) {
        return Some(k);
    }
    header_opt.and_then(sniff_kind_from_header)
}

/// Detect archive kind from an *archive entry name* (raw bytes).
///
/// This is used for nested expansion inside streaming containers (tar/gz).
/// We intentionally do not allocate and do not require valid UTF-8.
///
/// Order matters: check `.tar.gz` / `.tgz` before `.gz`.
pub fn detect_kind_from_name_bytes(name: &[u8]) -> Option<ArchiveKind> {
    let name = strip_trailing_slashes(name);

    if ends_with_ignore_ascii_case(name, b".tar.gz") || ends_with_ignore_ascii_case(name, b".tgz") {
        return Some(ArchiveKind::TarGz);
    }
    if ends_with_ignore_ascii_case(name, b".tar") {
        return Some(ArchiveKind::Tar);
    }
    if ends_with_ignore_ascii_case(name, b".gz") {
        return Some(ArchiveKind::Gzip);
    }
    if ends_with_ignore_ascii_case(name, b".zip") {
        return Some(ArchiveKind::Zip);
    }
    None
}

#[inline]
fn strip_trailing_slashes(mut s: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = s.split_last() {
        if last == b'/' || last == b'\\' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn ends_with_ignore_ascii_case(hay: &[u8], suf: &[u8]) -> bool {
    if suf.len() > hay.len() {
        return false;
    }
    let start = hay.len() - suf.len();
    for i in 0..suf.len() {
        if !hay[start + i].eq_ignore_ascii_case(&suf[i]) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect_kind_from_name("a.tar.gz"), Some(ArchiveKind::TarGz));
        assert_eq!(detect_kind_from_name("a.TGZ"), Some(ArchiveKind::TarGz));
        assert_eq!(detect_kind_from_name("a.gz"), Some(ArchiveKind::Gzip));
        assert_eq!(detect_kind_from_name("a.tar"), Some(ArchiveKind::Tar));
        assert_eq!(detect_kind_from_name("a.zip"), Some(ArchiveKind::Zip));
        assert_eq!(detect_kind_from_name("a.bin"), None);
    }

    #[test]
    fn sniff_magic_gzip_zip() {
        assert_eq!(
            sniff_kind_from_header(&[0x1f, 0x8b, 0x08, 0x00]),
            Some(ArchiveKind::Gzip)
        );
        assert_eq!(
            sniff_kind_from_header(b"PK\x03\x04xxxx"),
            Some(ArchiveKind::Zip)
        );
        assert_eq!(sniff_kind_from_header(&[0, 1, 2, 3]), None);
    }

    #[test]
    fn extension_wins_over_sniff_for_targz() {
        use std::path::PathBuf;
        let p = PathBuf::from("x.tar.gz");
        // header indicates gzip; combined detection should still return TarGz.
        assert_eq!(
            detect_kind(&p, Some(&[0x1f, 0x8b, 0x08, 0x00])),
            Some(ArchiveKind::TarGz)
        );
    }

    #[test]
    fn detect_from_name_bytes_handles_case_and_trailing_slash() {
        assert_eq!(
            detect_kind_from_name_bytes(b"foo.TAR.GZ"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"bar.tgz/"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"/path/inner.TAR"),
            Some(ArchiveKind::Tar)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"data.GZ"),
            Some(ArchiveKind::Gzip)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"bundle.zip"),
            Some(ArchiveKind::Zip)
        );
        assert_eq!(detect_kind_from_name_bytes(b"nope.bin"), None);
    }
}
