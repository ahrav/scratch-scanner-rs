//! Pack decode primitives for bounded object inflation.
//!
//! This module provides thin wrappers around pack header parsing and zlib
//! inflation with explicit size caps. It does not perform delta resolution
//! on its own; callers should use `pack_delta` to apply deltas and enforce
//! depth limits at a higher level.
//!
//! For delta entries, `EntryHeader.size` is the uncompressed delta payload
//! size; the delta stream itself encodes base and result sizes.
//!
//! The helpers here do not verify pack checksums; they operate on already
//! loaded pack bytes and return precise errors for size and parsing issues.

use std::fmt;

use super::pack_inflate::{inflate_exact, inflate_limited, EntryHeader, EntryKind, PackFile};
use super::pack_inflate::{InflateError, PackParseError};

/// Limits for pack object decoding.
///
/// `max_delta_bytes` caps the inflated delta stream (not the final object).
/// Callers typically set it to the same value as `max_object_bytes` to keep
/// delta buffers bounded.
#[derive(Clone, Copy, Debug)]
pub struct PackDecodeLimits {
    /// Maximum header bytes to parse for an entry.
    pub max_header_bytes: usize,
    /// Maximum object size (inflated) allowed for any entry.
    pub max_object_bytes: usize,
    /// Maximum delta payload size (inflated) for delta entries.
    ///
    /// This cap applies to the delta stream itself, not the final object.
    pub max_delta_bytes: usize,
}

impl PackDecodeLimits {
    /// Creates a new limits struct.
    #[must_use]
    pub const fn new(
        max_header_bytes: usize,
        max_object_bytes: usize,
        max_delta_bytes: usize,
    ) -> Self {
        Self {
            max_header_bytes,
            max_object_bytes,
            max_delta_bytes,
        }
    }
}

/// Pack decode error taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum PackDecodeError {
    /// Pack header parsing failed.
    PackParse(PackParseError),
    /// Zlib inflation failed or exceeded a limit.
    Inflate(InflateError),
    /// Object size exceeds the configured cap.
    ObjectTooLarge { size: u64, max: usize },
    /// Delta payload size exceeds the configured cap (delta stream size).
    DeltaTooLarge { size: u64, max: usize },
}

impl fmt::Display for PackDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::Inflate(err) => write!(f, "{err}"),
            Self::ObjectTooLarge { size, max } => {
                write!(f, "object size {size} exceeds cap {max}")
            }
            Self::DeltaTooLarge { size, max } => {
                write!(f, "delta payload size {size} exceeds cap {max}")
            }
        }
    }
}

impl std::error::Error for PackDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            Self::Inflate(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PackParseError> for PackDecodeError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<InflateError> for PackDecodeError {
    fn from(err: InflateError) -> Self {
        Self::Inflate(err)
    }
}

/// Parses an entry header and enforces the object size cap.
///
/// # Errors
/// - `PackDecodeError::PackParse` on invalid header data.
/// - `PackDecodeError::ObjectTooLarge` if a non-delta entry exceeds the limit.
/// - `PackDecodeError::DeltaTooLarge` if a delta payload exceeds the limit.
pub fn entry_header_at(
    pack: &PackFile<'_>,
    offset: u64,
    limits: &PackDecodeLimits,
) -> Result<EntryHeader, PackDecodeError> {
    let header = pack.entry_header_at(offset, limits.max_header_bytes)?;
    match header.kind {
        EntryKind::NonDelta { .. } => {
            if header.size > limits.max_object_bytes as u64 {
                return Err(PackDecodeError::ObjectTooLarge {
                    size: header.size,
                    max: limits.max_object_bytes,
                });
            }
        }
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => {
            if header.size > limits.max_delta_bytes as u64 {
                return Err(PackDecodeError::DeltaTooLarge {
                    size: header.size,
                    max: limits.max_delta_bytes,
                });
            }
        }
    }
    Ok(header)
}

/// Inflates the payload for an entry header.
///
/// For non-delta entries, this inflates exactly `header.size` bytes.
/// For delta entries, this inflates the delta stream up to `max_delta_bytes`.
///
/// Returns the number of compressed bytes consumed from the pack slice.
///
/// # Errors
/// - `PackDecodeError::Inflate` on zlib errors or limit overruns.
pub fn inflate_entry_payload(
    pack: &PackFile<'_>,
    header: &EntryHeader,
    out: &mut Vec<u8>,
    limits: &PackDecodeLimits,
) -> Result<usize, PackDecodeError> {
    match header.kind {
        EntryKind::NonDelta { .. } => {
            let expected = header.size as usize;
            let consumed = inflate_exact(pack.slice_from(header.data_start), out, expected)?;
            Ok(consumed)
        }
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => {
            let consumed = inflate_limited(
                pack.slice_from(header.data_start),
                out,
                limits.max_delta_bytes,
            )?;
            Ok(consumed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn inflate_limited_errors_on_overrun() {
        let input = b"hello world hello world";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut out = Vec::with_capacity(4);
        let err = inflate_limited(&compressed, &mut out, 4).unwrap_err();
        assert_eq!(err, InflateError::LimitExceeded);
    }
}
