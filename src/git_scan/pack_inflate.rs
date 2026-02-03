//! Pack object decoding for tree loading.
//!
//! Provides bounded inflate helpers, pack header parsing, and delta
//! application needed to read tree objects from pack files.
//!
//! # Scope
//! - Parses pack headers and entry headers.
//! - Inflates zlib-compressed object data with strict size caps.
//! - Applies Git's delta encoding (OFS_DELTA and REF_DELTA).
//! - Does **not** verify pack checksums or object CRCs.
//!
//! # Caller Expectations
//! - Offsets passed to `entry_header_at` must point to entry headers
//!   (typically from MIDX/IDX offsets).
//! - Size caps must be enforced by the caller before allocating outputs.
//! - The pack trailer hash is ignored; integrity checks happen elsewhere.

use std::fmt;

use super::object_id::OidBytes;

/// Pack header size: magic(4) + version(4) + object_count(4).
const PACK_HEADER_SIZE: usize = 12;

/// Maximum OFS encoding bytes (negative offset varint).
const MAX_OFS_BYTES: usize = 10; // ceil(64/7)

/// Internal inflate buffer size.
const INFLATE_BUF_SIZE: usize = 8192;

/// Parsed object kind for non-delta entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

/// Parsed pack entry kind from header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// Non-delta object (commit, tree, blob, tag).
    NonDelta { kind: ObjectKind },
    /// OFS_DELTA: base at backward offset in same pack.
    OfsDelta { base_offset: u64 },
    /// REF_DELTA: base identified by OID.
    RefDelta { base_oid: OidBytes },
}

/// Pack header parse error taxonomy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackParseError {
    TooSmall,
    BadSignature,
    UnsupportedVersion(u32),
    OffsetOutOfRange(u64),
    HeaderTooLong,
    Truncated,
    BadObjType(u8),
    BadOfsEncoding,
    OfsUnderflow,
    BadOidLen(usize),
}

impl fmt::Display for PackParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "pack too small"),
            Self::BadSignature => write!(f, "bad pack signature"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported pack version {v}"),
            Self::OffsetOutOfRange(o) => write!(f, "offset {o} out of range"),
            Self::HeaderTooLong => write!(f, "header exceeded safety bound"),
            Self::Truncated => write!(f, "truncated pack data"),
            Self::BadObjType(t) => write!(f, "bad object type {t}"),
            Self::BadOfsEncoding => write!(f, "bad OFS_DELTA encoding"),
            Self::OfsUnderflow => write!(f, "OFS_DELTA base underflow"),
            Self::BadOidLen(n) => write!(f, "invalid OID length {n}"),
        }
    }
}

impl std::error::Error for PackParseError {}

/// Inflate error taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    LimitExceeded,
    TruncatedInput,
    Stalled,
    Backend,
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded => write!(f, "inflate limit exceeded"),
            Self::TruncatedInput => write!(f, "truncated input"),
            Self::Stalled => write!(f, "inflate stalled"),
            Self::Backend => write!(f, "inflate backend error"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Delta apply error taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    VarintOverflow,
    BaseSizeMismatch,
    ResultSizeMismatch,
    BadCommandZero,
    CopyOutOfRange,
    OutputOverrun,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "delta truncated"),
            Self::VarintOverflow => write!(f, "delta varint overflow"),
            Self::BaseSizeMismatch => write!(f, "delta base size mismatch"),
            Self::ResultSizeMismatch => write!(f, "delta result size mismatch"),
            Self::BadCommandZero => write!(f, "delta command zero"),
            Self::CopyOutOfRange => write!(f, "delta copy out of range"),
            Self::OutputOverrun => write!(f, "delta output overrun"),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Errors from pack object decoding.
#[derive(Debug)]
pub enum PackObjectError {
    PackParse(PackParseError),
    Inflate(InflateError),
    Delta(DeltaError),
}

impl fmt::Display for PackObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::Inflate(err) => write!(f, "{err}"),
            Self::Delta(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PackObjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            Self::Inflate(err) => Some(err),
            Self::Delta(err) => Some(err),
        }
    }
}

impl From<PackParseError> for PackObjectError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<InflateError> for PackObjectError {
    fn from(err: InflateError) -> Self {
        Self::Inflate(err)
    }
}

impl From<DeltaError> for PackObjectError {
    fn from(err: DeltaError) -> Self {
        Self::Delta(err)
    }
}

/// Entry header parsed from a pack file.
///
/// The `data_start` offset points to the beginning of the zlib stream
/// within the pack. The header itself is variable length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryHeader {
    /// Uncompressed size of the object (or delta result size).
    pub size: u64,
    /// Byte offset where the zlib stream begins.
    pub data_start: usize,
    /// Entry kind (non-delta or delta with base reference).
    pub kind: EntryKind,
}

/// Zero-copy view over pack file bytes.
///
/// The trailing hash (20 or 32 bytes) is excluded from `data_end` to prevent
/// misparsing the checksum as object data. No checksum verification is done.
#[derive(Debug)]
pub struct PackFile<'a> {
    bytes: &'a [u8],
    oid_len: usize,
    data_end: usize,
}

impl<'a> PackFile<'a> {
    /// Parse and validate a pack file header.
    ///
    /// Expects the full pack bytes including the trailing hash.
    pub fn parse(bytes: &'a [u8], oid_len: usize) -> Result<Self, PackParseError> {
        debug_assert!(oid_len == 20 || oid_len == 32, "oid_len must be 20 or 32");

        let min_size = PACK_HEADER_SIZE + oid_len;
        if bytes.len() < min_size {
            return Err(PackParseError::TooSmall);
        }
        if &bytes[0..4] != b"PACK" {
            return Err(PackParseError::BadSignature);
        }
        let ver = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ver != 2 && ver != 3 {
            return Err(PackParseError::UnsupportedVersion(ver));
        }

        let data_end = bytes.len() - oid_len;
        debug_assert!(data_end >= PACK_HEADER_SIZE);

        Ok(Self {
            bytes,
            oid_len,
            data_end,
        })
    }

    /// Parse the entry header at `offset`.
    ///
    /// `max_header_bytes` is a safety bound to prevent runaway parsing on
    /// corrupt data.
    pub fn entry_header_at(
        &self,
        offset: u64,
        max_header_bytes: usize,
    ) -> Result<EntryHeader, PackParseError> {
        let mut pos = offset as usize;
        if pos < PACK_HEADER_SIZE || pos >= self.data_end {
            return Err(PackParseError::OffsetOutOfRange(offset));
        }

        let start = pos;

        let first = self.byte_at(pos)?;
        pos += 1;

        let obj_type = (first >> 4) & 0x07;
        let mut size: u64 = (first & 0x0f) as u64;
        let mut shift: u32 = 4;

        let mut byte = first;
        while (byte & 0x80) != 0 {
            if pos - start >= max_header_bytes {
                return Err(PackParseError::HeaderTooLong);
            }
            byte = self.byte_at(pos)?;
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift = shift.saturating_add(7);
            if shift > 63 {
                return Err(PackParseError::HeaderTooLong);
            }
        }

        let kind = match obj_type {
            1 => EntryKind::NonDelta {
                kind: ObjectKind::Commit,
            },
            2 => EntryKind::NonDelta {
                kind: ObjectKind::Tree,
            },
            3 => EntryKind::NonDelta {
                kind: ObjectKind::Blob,
            },
            4 => EntryKind::NonDelta {
                kind: ObjectKind::Tag,
            },
            6 => {
                let (base_offset, new_pos) =
                    self.parse_ofs_base(offset, pos, start, max_header_bytes)?;
                pos = new_pos;
                EntryKind::OfsDelta { base_offset }
            }
            7 => {
                let end = pos + self.oid_len;
                if end > self.data_end {
                    return Err(PackParseError::Truncated);
                }
                let base_oid = OidBytes::try_from_slice(&self.bytes[pos..end])
                    .ok_or(PackParseError::BadOidLen(self.oid_len))?;
                pos = end;
                EntryKind::RefDelta { base_oid }
            }
            x => return Err(PackParseError::BadObjType(x)),
        };

        Ok(EntryHeader {
            size,
            data_start: pos,
            kind,
        })
    }

    /// Raw bytes from `start` to end of data region.
    ///
    /// The returned slice excludes the trailing pack hash.
    #[inline]
    pub fn slice_from(&self, start: usize) -> &'a [u8] {
        debug_assert!(start <= self.data_end, "slice_from out of range");
        &self.bytes[start..self.data_end]
    }

    #[inline]
    fn byte_at(&self, pos: usize) -> Result<u8, PackParseError> {
        self.bytes
            .get(pos)
            .copied()
            .ok_or(PackParseError::Truncated)
    }

    /// Parses OFS_DELTA base offset encoding.
    ///
    /// The encoding stores a negative offset as a variable-length base-128
    /// number with a continuation bit; see `gitformat-pack(5)`.
    fn parse_ofs_base(
        &self,
        delta_offset: u64,
        mut pos: usize,
        start: usize,
        max_header_bytes: usize,
    ) -> Result<(u64, usize), PackParseError> {
        let ofs_start = pos;
        let mut c = self.byte_at(pos)?;
        pos += 1;

        let mut val: u64 = (c & 0x7f) as u64;
        let mut bytes_read = 1usize;

        while (c & 0x80) != 0 {
            if bytes_read >= MAX_OFS_BYTES || pos - start >= max_header_bytes {
                return Err(PackParseError::HeaderTooLong);
            }
            c = self.byte_at(pos)?;
            pos += 1;
            bytes_read += 1;
            val = (val + 1) << 7;
            val |= (c & 0x7f) as u64;
        }

        if val >= delta_offset {
            return Err(PackParseError::OfsUnderflow);
        }

        let base_offset = delta_offset - val;
        Ok((base_offset, ofs_start + bytes_read))
    }
}

/// Inflate a zlib stream with a hard output cap.
///
/// Returns the number of input bytes consumed from `input`.
///
/// This does not enforce that the stream ends exactly at the end of `input`;
/// callers should use the returned byte count to advance within a pack.
pub fn inflate_limited(
    input: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<usize, InflateError> {
    use flate2::{Decompress, FlushDecompress, Status};

    debug_assert!(out.capacity() >= max_out || max_out == 0);
    out.clear();

    let mut de = Decompress::new(true);
    let mut buf = [0u8; INFLATE_BUF_SIZE];
    let mut in_pos: usize = 0;

    loop {
        let before_in = de.total_in() as usize;
        let before_out = de.total_out() as usize;

        let status = de
            .decompress(&input[in_pos..], &mut buf, FlushDecompress::None)
            .map_err(|_| InflateError::Backend)?;

        let consumed = de.total_in() as usize - before_in;
        let produced = de.total_out() as usize - before_out;
        in_pos += consumed;

        if produced != 0 {
            if out.len() + produced > max_out {
                return Err(InflateError::LimitExceeded);
            }
            out.extend_from_slice(&buf[..produced]);
        }

        match status {
            Status::StreamEnd => return Ok(in_pos),
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    if in_pos >= input.len() {
                        return Err(InflateError::TruncatedInput);
                    }
                    return Err(InflateError::Stalled);
                }
            }
            Status::BufError => {
                if in_pos >= input.len() {
                    return Err(InflateError::TruncatedInput);
                }
            }
        }
    }
}

/// Inflate a zlib stream expecting exactly `expected` output bytes.
///
/// Returns the number of input bytes consumed from `input`.
///
/// If the stream ends early or produces fewer bytes than expected, returns
/// `TruncatedInput`.
pub fn inflate_exact(
    input: &[u8],
    out: &mut Vec<u8>,
    expected: usize,
) -> Result<usize, InflateError> {
    let consumed = inflate_limited(input, out, expected)?;
    if out.len() != expected {
        return Err(InflateError::TruncatedInput);
    }
    Ok(consumed)
}

/// Reads a Git delta varint (LEB128-like) as u64.
fn read_leb128_u64(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut shift: u32 = 0;
    let mut result: u64 = 0;

    for _ in 0..10 {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated);
        }
        let b = data[*pos];
        *pos += 1;

        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return Err(DeltaError::VarintOverflow);
        }
    }
    Err(DeltaError::VarintOverflow)
}

/// Apply a git delta buffer to `base`, producing `expected_result_size` bytes.
///
/// The caller supplies `max_out` as a hard safety cap to prevent allocating
/// unbounded output on corrupt deltas.
///
/// The delta format encodes both base size and result size as varints at the
/// head of the stream; both are validated.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    out: &mut Vec<u8>,
    expected_result_size: usize,
    max_out: usize,
) -> Result<(), DeltaError> {
    let mut pos = 0usize;

    let base_size = read_leb128_u64(delta, &mut pos)? as usize;
    if base_size != base.len() {
        return Err(DeltaError::BaseSizeMismatch);
    }

    let result_size = read_leb128_u64(delta, &mut pos)? as usize;
    if result_size != expected_result_size {
        return Err(DeltaError::ResultSizeMismatch);
    }
    if result_size > max_out {
        return Err(DeltaError::OutputOverrun);
    }

    out.clear();

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;

        if (cmd & 0x80) != 0 {
            let (off, size) = decode_copy_params(delta, &mut pos, cmd)?;

            if off.checked_add(size).is_none_or(|end| end > base.len()) {
                return Err(DeltaError::CopyOutOfRange);
            }
            if out.len() + size > result_size {
                return Err(DeltaError::OutputOverrun);
            }

            out.extend_from_slice(&base[off..off + size]);
        } else if cmd != 0 {
            let size = cmd as usize;
            if pos + size > delta.len() {
                return Err(DeltaError::Truncated);
            }
            if out.len() + size > result_size {
                return Err(DeltaError::OutputOverrun);
            }

            out.extend_from_slice(&delta[pos..pos + size]);
            pos += size;
        } else {
            return Err(DeltaError::BadCommandZero);
        }
    }

    if out.len() != result_size {
        return Err(DeltaError::ResultSizeMismatch);
    }
    Ok(())
}

/// Decodes copy parameters for a delta copy instruction.
///
/// A zero size encodes 0x10000, per Git's delta format.
///
/// Bit layout follows the Git delta specification:
/// - Low bits select which offset bytes are present (little-endian).
/// - High bits select which size bytes are present.
fn decode_copy_params(
    delta: &[u8],
    pos: &mut usize,
    cmd: u8,
) -> Result<(usize, usize), DeltaError> {
    let mut off: usize = 0;
    let mut size: usize = 0;

    if (cmd & 0x01) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        off |= delta[*pos] as usize;
        *pos += 1;
    }
    if (cmd & 0x02) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        off |= (delta[*pos] as usize) << 8;
        *pos += 1;
    }
    if (cmd & 0x04) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        off |= (delta[*pos] as usize) << 16;
        *pos += 1;
    }
    if (cmd & 0x08) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        off |= (delta[*pos] as usize) << 24;
        *pos += 1;
    }

    if (cmd & 0x10) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        size |= delta[*pos] as usize;
        *pos += 1;
    }
    if (cmd & 0x20) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        size |= (delta[*pos] as usize) << 8;
        *pos += 1;
    }
    if (cmd & 0x40) != 0 {
        if *pos >= delta.len() {
            return Err(DeltaError::Truncated);
        }
        size |= (delta[*pos] as usize) << 16;
        *pos += 1;
    }

    if size == 0 {
        size = 0x10000;
    }

    Ok((off, size))
}
