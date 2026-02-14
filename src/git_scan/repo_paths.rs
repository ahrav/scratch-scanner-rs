//! Shared repository path utilities for pack and loose object discovery.
//!
//! This module consolidates directory-listing and pack-resolution helpers that
//! were previously duplicated across `object_store`, `runner_exec`, `pack_io`,
//! and `commit_loader`. All functions return `io::Error` (or no error) so
//! callers can convert to their domain error type with `.map_err()` or `?`
//! (when `From<io::Error>` is implemented).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::midx::MidxView;
use super::object_id::OidBytes;
use super::repo::GitRepoPaths;

// ---------------------------------------------------------------------------
// Directory collection (infallible)
// ---------------------------------------------------------------------------

/// Collect pack directories from the primary and alternate object dirs.
///
/// The primary `pack_dir` is returned first, followed by `<alternate>/pack`
/// for each alternate objects directory. Alternates equal to the main objects
/// dir are skipped to avoid duplicate scanning.
pub fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

/// Collect loose object directories from the primary and alternate object dirs.
///
/// The primary objects dir is returned first, followed by each alternate.
/// Alternates equal to the main objects dir are skipped to avoid duplicate
/// scanning.
pub fn collect_loose_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.objects_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.clone());
    }
    dirs
}

// ---------------------------------------------------------------------------
// Pack file listing (fallible — returns io::Error)
// ---------------------------------------------------------------------------

/// List pack file names from the provided pack directories.
///
/// Returns raw file names (as bytes) for `.pack` files. Names are converted
/// through [`std::ffi::OsStr::to_string_lossy`], so non-UTF-8 bytes are
/// replaced with U+FFFD — acceptable because git pack file names are always
/// ASCII hex. Missing pack directories are ignored; other IO errors are
/// returned.
pub(super) fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, io::Error> {
    let mut names = Vec::new();

    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }

    Ok(names)
}

/// Resolve pack file paths referenced by a multi-pack-index.
///
/// The MIDX stores pack basenames (with `.idx` suffix); this function strips
/// the suffix, appends `.pack`, and searches `pack_dirs` in order. The first
/// match wins, so `pack_dirs` order is significant (primary before alternates).
///
/// # Errors
///
/// Returns `io::Error` with `NotFound` kind if any MIDX-referenced pack
/// cannot be located in the provided directories.
pub(super) fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, io::Error> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);

    for name in midx.pack_names() {
        let mut base = strip_pack_suffix(name);
        base.extend_from_slice(b".pack");
        let file_name = String::from_utf8_lossy(&base).into_owned();

        let mut found = None;
        for dir in pack_dirs {
            let candidate = dir.join(&file_name);
            if is_file(&candidate) {
                found = Some(candidate);
                break;
            }
        }

        match found {
            Some(path) => paths.push(path),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("pack file not found for {}", String::from_utf8_lossy(name)),
                ))
            }
        }
    }

    Ok(paths)
}

// ---------------------------------------------------------------------------
// Byte-level utilities (infallible)
// ---------------------------------------------------------------------------

/// Strip a `.pack` or `.idx` suffix from a pack-related file name.
///
/// Both suffixes are handled because the MIDX stores pack basenames with
/// `.idx` suffixes, while we need `.pack` paths for mmap. Returns the
/// input unchanged (as a new `Vec`) if neither suffix matches.
pub(super) fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") {
        name[..name.len() - 5].to_vec()
    } else if name.ends_with(b".idx") {
        name[..name.len() - 4].to_vec()
    } else {
        name.to_vec()
    }
}

/// Encode a nibble (0--15) as a lowercase hex ASCII byte.
pub(super) fn hex_digit(val: u8) -> u8 {
    match val {
        0..=9 => b'0' + val,
        10..=15 => b'a' + (val - 10),
        _ => b'?',
    }
}

/// Encode an OID as a hex byte vector.
///
/// Each byte of the OID is expanded to two lowercase hex ASCII bytes.
pub(super) fn oid_to_hex(oid: &OidBytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() as usize * 2);
    for &b in oid.as_slice() {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the file name has a `.pack` extension.
fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

/// Returns `true` if `path` exists and is a regular file.
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
