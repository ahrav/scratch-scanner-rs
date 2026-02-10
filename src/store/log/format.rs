//! On-disk frame format for append-only FS persistence logs.
//!
//! # Wire format
//!
//! Each segment starts with a fixed header and then stores framed records.
//! Two frame layouts are supported on read:
//!
//! - **V1 (legacy)** body = `type || payload`
//! - **V2 (current)** body = `frame_seq || segment_id || type || payload`
//!
//! V2 is encoded by setting the high bit of `frame_len`.
//!
//! ```text
//! V2 segment envelope:
//! ┌──────────────┬────────────────────┬──────────────┐
//! │ seg header   │ framed records...  │ seg trailer  │
//! │ SCRHDRv2     │ V1/V2 frame layout │ SCRSEGv2     │
//! └──────────────┴────────────────────┴──────────────┘
//!
//! V1 body:
//! ┌──────────────┬──────────────┬──────────┬─────────────────────┐
//! │ frame_len    │ crc32        │ type     │ payload             │
//! │ u32_le (4B)  │ u32_le (4B)  │ u8 (1B)  │ [frame_len - 1] B   │
//! └──────────────┴──────────────┴──────────┴─────────────────────┘
//!
//! V2 body:
//! ┌──────────────┬──────────────┬───────────┬────────────┬──────────┬──────────┐
//! │ frame_len|F2 │ crc32        │ frame_seq │ segment_id │ type     │ payload  │
//! │ u32_le (4B)  │ u32_le (4B)  │ u64_le    │ u64_le     │ u8       │ ...      │
//! └──────────────┴──────────────┴───────────┴────────────┴──────────┴──────────┘
//! ```
//!
//! - **`frame_len`** — byte count of body bytes (excluding the 8-byte header).
//!   For V2, the high bit is set and the remaining bits store the body length.
//! - **`crc32`** — CRC-32/ISO-HDLC (polynomial 0x04C11DB7, same as zlib)
//!   over the full body bytes. In V2 this binds `frame_seq` + `segment_id`
//!   into the checksum region.
//! - **`type`** — [`FrameType`] discriminant identifying the payload schema.
//! - **`payload`** — record-specific bytes; see the per-variant encode/decode
//!   functions below.
//!
//! # Invariants
//!
//! - All multi-byte integers are **little-endian**.
//! - Variable-length byte fields (e.g. `object_path`, `rule_name`) are
//!   length-prefixed with a `u32_le` count.
//! - Finalized V2 segments end with a fixed-size trailer carrying
//!   `frame_count`, `total_frame_bytes`, and a BLAKE3 chain over per-frame CRCs.
//! - V2 segments also carry a fixed header with `segment_id` and
//!   `prev_segment_hash` for cross-segment chain verification.
//! - Frame payloads must not exceed [`DEFAULT_MAX_FRAME_PAYLOAD_BYTES`]
//!   (configurable at the writer level) to bound memory allocation on read.

use crate::store::keys::{CorrelationMode, KeySource};
use std::fmt;
use std::io::{self, Read};

/// Latest log format version for run metadata payloads.
pub const LOG_FORMAT_VERSION: u16 = 2;
/// Legacy log format version still accepted by readers.
pub const LEGACY_LOG_FORMAT_VERSION: u16 = 1;
/// Default hard cap for frame payload bytes.
pub const DEFAULT_MAX_FRAME_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;

pub(crate) const FRAME_HEADER_BYTES: usize = 8;
pub(crate) const FRAME_V2_LEN_FLAG: u32 = 1 << 31;
pub(crate) const FRAME_V2_POSITION_BYTES: usize = 16;
pub(crate) const FRAME_V2_MIN_BODY_BYTES: u32 = (FRAME_V2_POSITION_BYTES as u32) + 1;
pub(crate) const FRAME_V2_SEQ_OFFSET: usize = FRAME_HEADER_BYTES;
pub(crate) const FRAME_V2_SEGMENT_ID_OFFSET: usize = FRAME_V2_SEQ_OFFSET + 8;
pub(crate) const FRAME_V2_TYPE_OFFSET: usize = FRAME_V2_SEGMENT_ID_OFFSET + 8;

pub(crate) const SEGMENT_HEADER_MAGIC: [u8; 8] = *b"SCRHDRv2";
pub(crate) const SEGMENT_HEADER_BYTES: usize = 8 + 8 + 32;
pub(crate) const SEGMENT_TRAILER_MAGIC: [u8; 8] = *b"SCRSEGv2";
pub(crate) const SEGMENT_TRAILER_BYTES: usize = 8 + 8 + 8 + 8 + 32;

/// Position metadata bound into V2 frame CRCs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FramePosition {
    pub frame_seq: u64,
    pub segment_id: u64,
}

/// Header written at the beginning of each V2 segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    pub segment_id: u64,
    pub prev_segment_hash: [u8; 32],
}

/// Integrity trailer written at the end of finalized V2 segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentTrailer {
    pub segment_id: u64,
    pub frame_count: u64,
    pub total_frame_bytes: u64,
    pub frame_crc_chain: [u8; 32],
}

/// Parsed layout metadata for a single frame header.
///
/// Produced by [`parse_frame_layout`] from the raw `frame_len` word. Captures
/// whether the frame is V1 or V2, the body and payload lengths, and the byte
/// offsets within the body where the type byte and payload begin. This lets
/// callers navigate the body without re-deriving version-dependent offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameLayout {
    pub(crate) is_v2: bool,
    /// Body length as stored in the header (low 31 bits of `frame_len`).
    pub(crate) body_len_u32: u32,
    /// Body length as `usize` for indexing.
    pub(crate) body_len: usize,
    /// Payload length excluding the type byte and V2 position prefix.
    pub(crate) payload_len: u32,
    /// Byte offset of the type byte within the body (0 for V1, 16 for V2).
    pub(crate) type_offset: usize,
    /// Byte offset of the first payload byte within the body.
    pub(crate) payload_offset: usize,
}

/// Derive a [`FrameLayout`] from the raw `frame_len` word in a frame header.
///
/// The high bit of `frame_len_word` selects V1 vs V2 (see [`FRAME_V2_LEN_FLAG`]).
/// The low 31 bits give the body length, from which this function computes
/// the payload size and byte offsets for the type tag and payload within the
/// body. Returns [`FormatError::InvalidFrameLength`] for zero-length or
/// undersized bodies, and [`FormatError::FrameTooLarge`] if the payload
/// exceeds `max_payload_bytes`.
#[inline]
pub(crate) fn parse_frame_layout(
    frame_len_word: u32,
    max_payload_bytes: u32,
) -> Result<FrameLayout, FormatError> {
    let is_v2 = (frame_len_word & FRAME_V2_LEN_FLAG) != 0;
    let body_len_u32 = frame_len_word & !FRAME_V2_LEN_FLAG;
    if body_len_u32 == 0 {
        return Err(FormatError::InvalidFrameLength {
            len: frame_len_word,
        });
    }

    let min_body = if is_v2 { FRAME_V2_MIN_BODY_BYTES } else { 1 };
    if body_len_u32 < min_body {
        return Err(FormatError::InvalidFrameLength {
            len: frame_len_word,
        });
    }
    let payload_len = body_len_u32 - min_body;
    if payload_len > max_payload_bytes {
        return Err(FormatError::FrameTooLarge {
            len: payload_len,
            max: max_payload_bytes,
        });
    }

    let body_len = usize::try_from(body_len_u32).map_err(|_| FormatError::InvalidFrameLength {
        len: frame_len_word,
    })?;
    let type_offset = if is_v2 { FRAME_V2_POSITION_BYTES } else { 0 };
    let payload_offset = type_offset + 1;
    Ok(FrameLayout {
        is_v2,
        body_len_u32,
        body_len,
        payload_len,
        type_offset,
        payload_offset,
    })
}

/// Extract the CRC-32 stored in bytes 4..8 of a frame header.
///
/// The frame header layout is `[frame_len: u32-LE, crc: u32-LE]`; this
/// function reads the second word. Returns [`FormatError::TruncatedHeader`]
/// if `frame_bytes` is shorter than [`FRAME_HEADER_BYTES`] (8).
#[inline]
pub(crate) fn frame_crc_from_header(frame_bytes: &[u8]) -> Result<u32, FormatError> {
    if frame_bytes.len() < FRAME_HEADER_BYTES {
        return Err(FormatError::TruncatedHeader {
            got: frame_bytes.len(),
        });
    }
    Ok(u32::from_le_bytes([
        frame_bytes[4],
        frame_bytes[5],
        frame_bytes[6],
        frame_bytes[7],
    ]))
}

/// Advance the rolling BLAKE3 CRC chain by one frame.
///
/// Computes `BLAKE3(prev || frame_crc_le)` where `frame_crc_le` is the
/// per-frame CRC-32 in little-endian. The chain starts from 32 zero bytes
/// and is extended once per frame; the final value is stored in the
/// [`SegmentTrailer::frame_crc_chain`] field to authenticate the segment's
/// frame sequence.
#[inline]
pub(crate) fn extend_frame_crc_chain(prev: &[u8; 32], frame_crc: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev);
    hasher.update(&frame_crc.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Serialize a [`SegmentHeader`] and append it to `out`.
pub(crate) fn append_segment_header(out: &mut Vec<u8>, header: &SegmentHeader) {
    out.extend_from_slice(&SEGMENT_HEADER_MAGIC);
    out.extend_from_slice(&header.segment_id.to_le_bytes());
    out.extend_from_slice(&header.prev_segment_hash);
}

/// Decode a [`SegmentHeader`] from an exact [`SEGMENT_HEADER_BYTES`]-length
/// slice.
pub(crate) fn decode_segment_header(buf: &[u8]) -> Result<SegmentHeader, FormatError> {
    if buf.len() != SEGMENT_HEADER_BYTES {
        return Err(FormatError::InvalidSegmentHeader {
            detail: "segment header length mismatch",
        });
    }
    if buf[..8] != SEGMENT_HEADER_MAGIC {
        return Err(FormatError::InvalidSegmentHeader {
            detail: "segment header magic mismatch",
        });
    }
    let segment_id = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let mut prev_segment_hash = [0u8; 32];
    prev_segment_hash.copy_from_slice(&buf[16..48]);
    Ok(SegmentHeader {
        segment_id,
        prev_segment_hash,
    })
}

/// Serialize a [`SegmentTrailer`] and append it to `out`.
///
/// Writes the fixed 64-byte trailer: 8-byte magic (`SCRSEGv2`), then
/// `segment_id`, `frame_count`, and `total_frame_bytes` as little-endian
/// u64s, followed by the 32-byte `frame_crc_chain` digest. The writer calls
/// this just before finalizing (`.open` → `.bin` rename) so readers can
/// verify segment integrity without re-scanning every frame.
pub(crate) fn append_segment_trailer(out: &mut Vec<u8>, trailer: &SegmentTrailer) {
    out.extend_from_slice(&SEGMENT_TRAILER_MAGIC);
    out.extend_from_slice(&trailer.segment_id.to_le_bytes());
    out.extend_from_slice(&trailer.frame_count.to_le_bytes());
    out.extend_from_slice(&trailer.total_frame_bytes.to_le_bytes());
    out.extend_from_slice(&trailer.frame_crc_chain);
}

/// Decode a [`SegmentTrailer`] from an exact [`SEGMENT_TRAILER_BYTES`]-length
/// slice.
///
/// Validates the 8-byte magic prefix and deserializes the remaining fields.
/// Returns [`FormatError::InvalidSegmentTrailer`] on length mismatch or
/// magic mismatch. This is the inverse of [`append_segment_trailer`].
pub(crate) fn decode_segment_trailer(buf: &[u8]) -> Result<SegmentTrailer, FormatError> {
    if buf.len() != SEGMENT_TRAILER_BYTES {
        return Err(FormatError::InvalidSegmentTrailer {
            detail: "segment trailer length mismatch",
        });
    }
    if buf[..8] != SEGMENT_TRAILER_MAGIC {
        return Err(FormatError::InvalidSegmentTrailer {
            detail: "segment trailer magic mismatch",
        });
    }

    let mut cursor = 8usize;
    let take_u64 = |s: &[u8], idx: &mut usize| -> u64 {
        let start = *idx;
        *idx += 8;
        u64::from_le_bytes([
            s[start],
            s[start + 1],
            s[start + 2],
            s[start + 3],
            s[start + 4],
            s[start + 5],
            s[start + 6],
            s[start + 7],
        ])
    };
    let segment_id = take_u64(buf, &mut cursor);
    let frame_count = take_u64(buf, &mut cursor);
    let total_frame_bytes = take_u64(buf, &mut cursor);
    let mut frame_crc_chain = [0u8; 32];
    frame_crc_chain.copy_from_slice(&buf[cursor..cursor + 32]);
    Ok(SegmentTrailer {
        segment_id,
        frame_count,
        total_frame_bytes,
        frame_crc_chain,
    })
}

/// Derive a deterministic digest for one finalized segment.
///
/// The digest is chained across segments via
/// [`SegmentHeader::prev_segment_hash`].
pub(crate) fn derive_segment_hash(header: &SegmentHeader, trailer: &SegmentTrailer) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scanner.store.log.v2.segment_hash");
    hasher.update(&header.segment_id.to_le_bytes());
    hasher.update(&header.prev_segment_hash);
    hasher.update(&trailer.frame_count.to_le_bytes());
    hasher.update(&trailer.total_frame_bytes.to_le_bytes());
    hasher.update(&trailer.frame_crc_chain);
    *hasher.finalize().as_bytes()
}

/// Frame discriminants written on disk.
///
/// A well-formed run begins with [`RunStart`](Self::RunStart) in the first
/// segment, followed by zero or more [`RuleDef`](Self::RuleDef) frames in
/// sorted fingerprint order, then zero or more interleaved
/// [`FindingBatch`](Self::FindingBatch) frames (which may span multiple
/// segments due to rotation), and is sealed by a single
/// [`RunEnd`](Self::RunEnd) in the final segment. The writer enforces this
/// ordering; the reader does **not** — it decodes frames in whatever order
/// they appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Run metadata emitted once at the start of the run (first segment).
    RunStart = 1,
    /// Declares one detection rule active during this run. Emitted in
    /// ascending `rule_fingerprint` order immediately after `RunStart`.
    RuleDef = 2,
    /// One or more findings for a single scanned object path.
    FindingBatch = 3,
    /// Final frame closing the run. Contains loss counters and an
    /// `incomplete` flag indicating whether the run finished cleanly.
    RunEnd = 4,
}

impl FrameType {
    #[inline]
    fn from_u8(raw: u8) -> Result<Self, FormatError> {
        match raw {
            1 => Ok(Self::RunStart),
            2 => Ok(Self::RuleDef),
            3 => Ok(Self::FindingBatch),
            4 => Ok(Self::RunEnd),
            _ => Err(FormatError::UnknownFrameType { raw }),
        }
    }
}

/// Durability semantics recorded in [`LogRunStart`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LogDurabilityMode {
    /// `sync_data` at segment close/rotation only.
    SegmentClose = 0,
    /// `sync_data` after every finding batch frame.
    Batch = 1,
}

impl LogDurabilityMode {
    #[inline]
    fn from_u8(raw: u8) -> Result<Self, FormatError> {
        match raw {
            0 => Ok(Self::SegmentClose),
            1 => Ok(Self::Batch),
            _ => Err(FormatError::InvalidEnum {
                field: "durability",
                value: raw,
            }),
        }
    }
}

/// Run-start metadata frame.
///
/// Written once at the beginning of a run (first segment). Captures the
/// writer configuration snapshot so that a reader can validate compatibility
/// and reconstruct the backpressure parameters that were active during the
/// run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRunStart {
    /// Log format version ([`LOG_FORMAT_VERSION`]). Readers should reject
    /// segments whose version they do not support.
    pub version: u16,
    /// Unique identifier for this scan run, derived from wall-clock time
    /// combined with a monotonic counter via `wrapping_add`.
    pub run_id: u64,
    /// Wall-clock milliseconds since Unix epoch when the run began.
    pub started_unix_ms: u64,
    /// Fsync strategy used during writing.
    pub durability: LogDurabilityMode,
    /// Whether finding correlation keys are stable across runs
    /// (persistent secret key) or ephemeral.
    pub correlation_mode: CorrelationMode,
    /// How the secret key was obtained (env var, missing, invalid).
    pub key_source: KeySource,
    /// Writer backpressure: max queued finding-batch frames.
    pub max_inflight_batches: u32,
    /// Writer backpressure: max queued encoded bytes.
    pub max_inflight_bytes: u64,
    /// Codec hard cap on a single frame's payload size.
    pub max_frame_payload_bytes: u32,
}

/// Rule-definition metadata frame.
///
/// Emitted once per active rule, in ascending `rule_fingerprint` order, so
/// that readers can reconstruct the rule table without needing access to the
/// original rule YAML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRuleDef {
    /// Engine-internal rule index (0-based). Maps to the position in the
    /// `rules` slice passed to the engine constructor.
    pub rule_id: u32,
    /// BLAKE3-keyed fingerprint of the rule specification. Deterministic
    /// for a given rule + store key pair; used as a stable correlation key
    /// across runs.
    pub rule_fingerprint: [u8; 32],
    /// Human-readable rule name (UTF-8, length-prefixed on disk).
    pub rule_name: Vec<u8>,
}

/// One persisted finding in a [`LogFindingBatch`].
///
/// Fixed-size (132 bytes on disk) per finding. All byte-offset fields refer
/// to positions within the scanned object's content buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFindingRecord {
    /// Engine rule index that matched.
    pub rule_id: u32,
    /// BLAKE3-keyed rule fingerprint (redundant with [`LogRuleDef`] but
    /// included per-finding so each record is self-describing).
    pub rule_fingerprint: [u8; 32],
    /// BLAKE3-keyed hash of the normalised secret value. Enables
    /// cross-object deduplication without storing the raw secret.
    pub secret_hash: [u8; 32],
    /// Deterministic finding identifier derived from (object_path,
    /// rule_fingerprint, secret_hash, hint range, span range) via
    /// BLAKE3-keyed hashing. Stable across runs when using a persistent
    /// secret key.
    pub finding_id: [u8; 32],
    /// Byte offset where the engine's root-level scan window begins
    /// (inclusive). Together with `root_hint_end`, this brackets the
    /// anchor region that triggered the rule.
    pub root_hint_start: u64,
    /// Byte offset where the root-level scan window ends (exclusive).
    pub root_hint_end: u64,
    /// Byte offset where the matched secret value begins (inclusive).
    pub span_start: u64,
    /// Byte offset where the matched secret value ends (exclusive).
    pub span_end: u64,
}

/// Batch of findings for one scanned object path.
///
/// Each scanned file that produces at least one finding generates exactly
/// one `FindingBatch` frame. The `object_path` is the raw byte path as
/// seen by the scanner (typically a relative path from the scan root).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFindingBatch {
    /// Scanned object path (length-prefixed on disk). Byte content, not
    /// necessarily valid UTF-8 on all platforms.
    pub object_path: Vec<u8>,
    /// Findings within this object, in the order the engine emitted them.
    pub findings: Vec<LogFindingRecord>,
}

/// Run-end metadata frame.
///
/// Exactly one per run, written as the final frame before segment
/// finalization. Contains loss counters that let readers detect whether
/// any findings were dropped during the scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRunEnd {
    /// Wall-clock milliseconds since Unix epoch when the run ended.
    pub ended_unix_ms: u64,
    /// Number of findings that the engine produced but were not persisted
    /// (e.g. engine max-findings cap or scheduler-side filtering).
    pub dropped_findings: u64,
    /// Number of `emit_fs_batch` calls that returned an error from the
    /// persistence backend.
    pub persistence_emit_failures: u64,
    /// `true` when `dropped_findings > 0 || persistence_emit_failures > 0`,
    /// indicating the persisted log does not capture every finding.
    pub incomplete: bool,
}

/// Decoded log record — the in-memory representation of one frame's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogRecord {
    RunStart(LogRunStart),
    RuleDef(LogRuleDef),
    FindingBatch(LogFindingBatch),
    RunEnd(LogRunEnd),
}

impl LogRecord {
    #[inline]
    fn frame_type(&self) -> FrameType {
        match self {
            Self::RunStart(_) => FrameType::RunStart,
            Self::RuleDef(_) => FrameType::RuleDef,
            Self::FindingBatch(_) => FrameType::FindingBatch,
            Self::RunEnd(_) => FrameType::RunEnd,
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) -> Result<(), FormatError> {
        match self {
            Self::RunStart(rec) => encode_run_start(rec, out),
            Self::RuleDef(rec) => encode_rule_def(rec, out),
            Self::FindingBatch(rec) => encode_finding_batch(rec, out),
            Self::RunEnd(rec) => encode_run_end(rec, out),
        }
    }

    fn decode_payload(frame_type: FrameType, payload: &[u8]) -> Result<Self, FormatError> {
        match frame_type {
            FrameType::RunStart => Ok(Self::RunStart(decode_run_start(payload)?)),
            FrameType::RuleDef => Ok(Self::RuleDef(decode_rule_def(payload)?)),
            FrameType::FindingBatch => Ok(Self::FindingBatch(decode_finding_batch(payload)?)),
            FrameType::RunEnd => Ok(Self::RunEnd(decode_run_end(payload)?)),
        }
    }
}

/// Frame-format validation errors.
///
/// Returned during encoding (payload too large) or decoding (corruption,
/// truncation, unknown discriminants). The [`Io`](Self::Io) variant wraps
/// transport-level errors from the underlying reader.
#[derive(Debug)]
pub enum FormatError {
    Io(io::Error),
    FrameTooLarge {
        len: u32,
        max: u32,
    },
    InvalidFrameLength {
        len: u32,
    },
    TruncatedHeader {
        got: usize,
    },
    TruncatedFrame {
        expected: usize,
        got: usize,
    },
    CrcMismatch {
        expected: u32,
        actual: u32,
    },
    UnknownFrameType {
        raw: u8,
    },
    InvalidEnum {
        field: &'static str,
        value: u8,
    },
    InvalidBool {
        field: &'static str,
        value: u8,
    },
    InvalidRecord {
        frame_type: FrameType,
        detail: &'static str,
    },
    InvalidSegmentHeader {
        detail: &'static str,
    },
    InvalidSegmentTrailer {
        detail: &'static str,
    },
    LengthTooLarge {
        field: &'static str,
        len: usize,
        max: usize,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "frame payload too large: {len} > {max}")
            }
            Self::InvalidFrameLength { len } => {
                write!(
                    f,
                    "invalid frame length: {len} (must include frame type and any required v2 prefix)"
                )
            }
            Self::TruncatedHeader { got } => write!(f, "truncated frame header: got {got} bytes"),
            Self::TruncatedFrame { expected, got } => {
                write!(f, "truncated frame body: expected {expected}, got {got}")
            }
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "frame CRC mismatch: expected 0x{expected:08x}, got 0x{actual:08x}"
                )
            }
            Self::UnknownFrameType { raw } => write!(f, "unknown frame type: {raw}"),
            Self::InvalidEnum { field, value } => {
                write!(f, "invalid enum value for {field}: {value}")
            }
            Self::InvalidBool { field, value } => {
                write!(f, "invalid bool value for {field}: {value}")
            }
            Self::InvalidRecord { frame_type, detail } => {
                write!(f, "invalid {frame_type:?} payload: {detail}")
            }
            Self::InvalidSegmentHeader { detail } => {
                write!(f, "invalid segment header: {detail}")
            }
            Self::InvalidSegmentTrailer { detail } => {
                write!(f, "invalid segment trailer: {detail}")
            }
            Self::LengthTooLarge { field, len, max } => {
                write!(f, "{field} length too large: {len} > {max}")
            }
        }
    }
}

impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for FormatError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Encode one log record as a **legacy V1** framed blob and append to `out`.
///
/// Writes the 8-byte header (`frame_len` + `crc32`) followed by the type
/// byte and encoded payload. Returns [`FormatError::FrameTooLarge`] if the
/// serialised payload exceeds `max_payload_bytes`.
///
/// `out` is **not** cleared before writing; the frame is appended so that
/// callers can build multi-frame buffers incrementally.
///
/// New on-disk segments should use [`encode_record_with_position`].
pub fn encode_record(
    record: &LogRecord,
    max_payload_bytes: u32,
    out: &mut Vec<u8>,
) -> Result<(), FormatError> {
    let mut payload = Vec::with_capacity(256);
    record.encode_payload(&mut payload)?;

    if payload.len() > max_payload_bytes as usize {
        return Err(FormatError::FrameTooLarge {
            len: payload.len() as u32,
            max: max_payload_bytes,
        });
    }

    let body_len = payload
        .len()
        .checked_add(1)
        .ok_or(FormatError::InvalidFrameLength { len: u32::MAX })?;
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| FormatError::InvalidFrameLength { len: u32::MAX })?;

    let frame_type = record.frame_type() as u8;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&[frame_type]);
    crc.update(&payload);
    let crc32 = crc.finalize();

    out.reserve(FRAME_HEADER_BYTES + body_len);
    out.extend_from_slice(&body_len_u32.to_le_bytes());
    out.extend_from_slice(&crc32.to_le_bytes());
    out.push(frame_type);
    out.extend_from_slice(&payload);
    Ok(())
}

/// Encode one log record using the V2 wire layout and append to `out`.
///
/// V2 frames add a 16-byte position prefix (`frame_seq`, `segment_id`)
/// ahead of the type byte and payload, then bind those bytes into the CRC.
pub fn encode_record_with_position(
    record: &LogRecord,
    max_payload_bytes: u32,
    position: FramePosition,
    out: &mut Vec<u8>,
) -> Result<(), FormatError> {
    let mut payload = Vec::with_capacity(256);
    record.encode_payload(&mut payload)?;

    if payload.len() > max_payload_bytes as usize {
        return Err(FormatError::FrameTooLarge {
            len: payload.len() as u32,
            max: max_payload_bytes,
        });
    }

    let body_len = payload
        .len()
        .checked_add(1 + FRAME_V2_POSITION_BYTES)
        .ok_or(FormatError::InvalidFrameLength { len: u32::MAX })?;
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| FormatError::InvalidFrameLength { len: u32::MAX })?;
    let frame_len_word = FRAME_V2_LEN_FLAG | body_len_u32;

    let frame_type = record.frame_type() as u8;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&position.frame_seq.to_le_bytes());
    crc.update(&position.segment_id.to_le_bytes());
    crc.update(&[frame_type]);
    crc.update(&payload);
    let crc32 = crc.finalize();

    out.reserve(FRAME_HEADER_BYTES + body_len);
    out.extend_from_slice(&frame_len_word.to_le_bytes());
    out.extend_from_slice(&crc32.to_le_bytes());
    out.extend_from_slice(&position.frame_seq.to_le_bytes());
    out.extend_from_slice(&position.segment_id.to_le_bytes());
    out.push(frame_type);
    out.extend_from_slice(&payload);
    Ok(())
}

/// Patch a pre-built V2 frame in place with final position metadata and CRC.
///
/// `frame` must already contain the full body and use a V2 `frame_len` word.
pub fn finalize_v2_frame_in_place(
    frame: &mut [u8],
    position: FramePosition,
) -> Result<u32, FormatError> {
    if frame.len() < FRAME_HEADER_BYTES + FRAME_V2_POSITION_BYTES + 1 {
        return Err(FormatError::TruncatedFrame {
            expected: FRAME_HEADER_BYTES + FRAME_V2_POSITION_BYTES + 1,
            got: frame.len(),
        });
    }
    let frame_len_word = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let layout = parse_frame_layout(frame_len_word, u32::MAX)?;
    if !layout.is_v2 {
        return Err(FormatError::InvalidFrameLength {
            len: frame_len_word,
        });
    }
    let expected_total_len =
        FRAME_HEADER_BYTES
            .checked_add(layout.body_len)
            .ok_or(FormatError::InvalidFrameLength {
                len: frame_len_word,
            })?;
    if frame.len() != expected_total_len {
        return Err(FormatError::TruncatedFrame {
            expected: expected_total_len,
            got: frame.len(),
        });
    }

    frame[FRAME_V2_SEQ_OFFSET..FRAME_V2_SEGMENT_ID_OFFSET]
        .copy_from_slice(&position.frame_seq.to_le_bytes());
    frame[FRAME_V2_SEGMENT_ID_OFFSET..FRAME_V2_TYPE_OFFSET]
        .copy_from_slice(&position.segment_id.to_le_bytes());
    let crc32 = crc32fast::hash(&frame[FRAME_HEADER_BYTES..]);
    frame[4..FRAME_HEADER_BYTES].copy_from_slice(&crc32.to_le_bytes());
    Ok(crc32)
}

/// Decode one framed record from `frame_bytes`.
///
/// `frame_bytes` must contain exactly one complete frame (header + body).
/// The CRC is verified before any payload parsing. Supports both legacy V1
/// and current V2 frame layouts.
///
/// Returns [`FormatError::FrameTooLarge`] if the declared payload exceeds
/// `max_payload_bytes`, and [`FormatError::CrcMismatch`] on data corruption.
pub fn decode_record(frame_bytes: &[u8], max_payload_bytes: u32) -> Result<LogRecord, FormatError> {
    if frame_bytes.len() < FRAME_HEADER_BYTES + 1 {
        return Err(FormatError::TruncatedHeader {
            got: frame_bytes.len().min(FRAME_HEADER_BYTES),
        });
    }

    let frame_len_word = u32::from_le_bytes([
        frame_bytes[0],
        frame_bytes[1],
        frame_bytes[2],
        frame_bytes[3],
    ]);
    let crc_expected = u32::from_le_bytes([
        frame_bytes[4],
        frame_bytes[5],
        frame_bytes[6],
        frame_bytes[7],
    ]);
    decode_frame_body(
        frame_len_word,
        crc_expected,
        &frame_bytes[FRAME_HEADER_BYTES..],
        max_payload_bytes,
    )
}

/// Streaming frame reader over any [`Read`] source.
///
/// Reads frames sequentially, verifying the CRC of each before returning
/// the decoded [`LogRecord`]. Reuses an internal buffer across frames to
/// avoid per-frame allocation.
///
/// EOF handling: a clean EOF (zero bytes read at the start of a new header)
/// returns `Ok(None)`. A partial header or truncated body is an error.
/// When a V2 segment trailer is encountered, it is validated against the
/// accumulated frame counters and CRC-chain state before returning EOF.
pub struct LogRecordReader<R: Read> {
    reader: R,
    frame_buf: Vec<u8>,
    max_payload_bytes: u32,
    segment_preamble_checked: bool,
    segment_header: Option<SegmentHeader>,
    frame_count: u64,
    total_frame_bytes: u64,
    frame_crc_chain: [u8; 32],
}

impl<R: Read> LogRecordReader<R> {
    pub fn new(reader: R, max_payload_bytes: u32) -> Self {
        Self {
            reader,
            frame_buf: Vec::new(),
            max_payload_bytes,
            segment_preamble_checked: false,
            segment_header: None,
            frame_count: 0,
            total_frame_bytes: 0,
            frame_crc_chain: [0u8; 32],
        }
    }

    fn read_exact_into(&mut self, dst: &mut [u8]) -> Result<(), FormatError> {
        let mut got = 0usize;
        while got < dst.len() {
            let n = self.reader.read(&mut dst[got..])?;
            if n == 0 {
                return Err(FormatError::TruncatedFrame {
                    expected: dst.len(),
                    got,
                });
            }
            got += n;
        }
        Ok(())
    }

    fn read_segment_trailer_after_magic(&mut self, magic: [u8; 8]) -> Result<(), FormatError> {
        let mut trailer_buf = [0u8; SEGMENT_TRAILER_BYTES];
        trailer_buf[..8].copy_from_slice(&magic);
        self.read_exact_into(&mut trailer_buf[8..])?;
        let trailer = decode_segment_trailer(&trailer_buf)?;
        if let Some(header) = self.segment_header {
            if trailer.segment_id != header.segment_id {
                return Err(FormatError::InvalidSegmentTrailer {
                    detail: "segment_id mismatch",
                });
            }
        }
        if trailer.frame_count != self.frame_count {
            return Err(FormatError::InvalidSegmentTrailer {
                detail: "frame_count mismatch",
            });
        }
        if trailer.total_frame_bytes != self.total_frame_bytes {
            return Err(FormatError::InvalidSegmentTrailer {
                detail: "total_frame_bytes mismatch",
            });
        }
        if trailer.frame_crc_chain != self.frame_crc_chain {
            return Err(FormatError::InvalidSegmentTrailer {
                detail: "frame_crc_chain mismatch",
            });
        }
        Ok(())
    }

    fn next_record_from_header(
        &mut self,
        header: [u8; FRAME_HEADER_BYTES],
    ) -> Result<Option<LogRecord>, FormatError> {
        if header == SEGMENT_TRAILER_MAGIC {
            self.read_segment_trailer_after_magic(header)?;
            return Ok(None);
        }

        let frame_len_word = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let crc_expected = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let layout = parse_frame_layout(frame_len_word, self.max_payload_bytes)?;

        let want = layout.body_len;
        self.frame_buf.resize(want, 0);
        let mut read = 0usize;
        while read < want {
            let n = self.reader.read(&mut self.frame_buf[read..])?;
            if n == 0 {
                return Err(FormatError::TruncatedFrame {
                    expected: want,
                    got: read,
                });
            }
            read += n;
        }

        decode_frame_body(
            frame_len_word,
            crc_expected,
            &self.frame_buf,
            self.max_payload_bytes,
        )
        .map(|record| {
            self.frame_count = self.frame_count.saturating_add(1);
            self.total_frame_bytes = self
                .total_frame_bytes
                .saturating_add((FRAME_HEADER_BYTES + layout.body_len) as u64);
            self.frame_crc_chain = extend_frame_crc_chain(&self.frame_crc_chain, crc_expected);
            Some(record)
        })
    }

    /// Decode the next record.
    ///
    /// Returns `Ok(None)` on clean EOF before a new frame header starts.
    pub fn next_record(&mut self) -> Result<Option<LogRecord>, FormatError> {
        if !self.segment_preamble_checked {
            let mut prelude = [0u8; FRAME_HEADER_BYTES];
            let mut got = 0usize;
            while got < FRAME_HEADER_BYTES {
                let n = self.reader.read(&mut prelude[got..])?;
                if n == 0 {
                    if got == 0 {
                        return Ok(None);
                    }
                    return Err(FormatError::TruncatedHeader { got });
                }
                got += n;
            }
            if prelude == SEGMENT_HEADER_MAGIC {
                let mut header_buf = [0u8; SEGMENT_HEADER_BYTES];
                header_buf[..FRAME_HEADER_BYTES].copy_from_slice(&prelude);
                self.read_exact_into(&mut header_buf[FRAME_HEADER_BYTES..])?;
                self.segment_header = Some(decode_segment_header(&header_buf)?);
                self.segment_preamble_checked = true;
                return self.next_record();
            }
            self.segment_preamble_checked = true;
            return self.next_record_from_header(prelude);
        }

        let mut header = [0u8; FRAME_HEADER_BYTES];
        let mut got = 0usize;
        while got < FRAME_HEADER_BYTES {
            let n = self.reader.read(&mut header[got..])?;
            if n == 0 {
                if got == 0 {
                    return Ok(None);
                }
                return Err(FormatError::TruncatedHeader { got });
            }
            got += n;
        }
        self.next_record_from_header(header)
    }
}

fn decode_frame_body(
    frame_len_word: u32,
    crc_expected: u32,
    body: &[u8],
    max_payload_bytes: u32,
) -> Result<LogRecord, FormatError> {
    let layout = parse_frame_layout(frame_len_word, max_payload_bytes)?;
    if body.len() != layout.body_len {
        return Err(FormatError::TruncatedFrame {
            expected: layout.body_len,
            got: body.len(),
        });
    }

    let mut crc = crc32fast::Hasher::new();
    crc.update(body);
    let crc_actual = crc.finalize();
    if crc_actual != crc_expected {
        return Err(FormatError::CrcMismatch {
            expected: crc_expected,
            actual: crc_actual,
        });
    }

    let payload = &body[layout.payload_offset..];
    if payload.len() != layout.payload_len as usize {
        return Err(FormatError::InvalidFrameLength {
            len: frame_len_word,
        });
    }
    let frame_type = FrameType::from_u8(body[layout.type_offset])?;
    LogRecord::decode_payload(frame_type, payload)
}

fn encode_run_start(rec: &LogRunStart, out: &mut Vec<u8>) -> Result<(), FormatError> {
    push_u16(out, rec.version);
    push_u64(out, rec.run_id);
    push_u64(out, rec.started_unix_ms);
    out.push(rec.durability as u8);
    out.push(encode_correlation_mode(rec.correlation_mode));
    out.push(encode_key_source(rec.key_source));
    push_u32(out, rec.max_inflight_batches);
    push_u64(out, rec.max_inflight_bytes);
    push_u32(out, rec.max_frame_payload_bytes);
    Ok(())
}

fn decode_run_start(payload: &[u8]) -> Result<LogRunStart, FormatError> {
    let mut c = Cursor::new(payload);
    let version = c.take_u16(FrameType::RunStart, "version")?;
    let run_id = c.take_u64(FrameType::RunStart, "run_id")?;
    let started_unix_ms = c.take_u64(FrameType::RunStart, "started_unix_ms")?;
    let durability = LogDurabilityMode::from_u8(c.take_u8(FrameType::RunStart, "durability")?)?;
    let correlation_mode = decode_correlation_mode(
        c.take_u8(FrameType::RunStart, "correlation_mode")?,
        FrameType::RunStart,
    )?;
    let key_source = decode_key_source(
        c.take_u8(FrameType::RunStart, "key_source")?,
        FrameType::RunStart,
    )?;
    let max_inflight_batches = c.take_u32(FrameType::RunStart, "max_inflight_batches")?;
    let max_inflight_bytes = c.take_u64(FrameType::RunStart, "max_inflight_bytes")?;
    let max_frame_payload_bytes = c.take_u32(FrameType::RunStart, "max_frame_payload_bytes")?;
    c.require_finished(FrameType::RunStart)?;
    Ok(LogRunStart {
        version,
        run_id,
        started_unix_ms,
        durability,
        correlation_mode,
        key_source,
        max_inflight_batches,
        max_inflight_bytes,
        max_frame_payload_bytes,
    })
}

fn encode_rule_def(rec: &LogRuleDef, out: &mut Vec<u8>) -> Result<(), FormatError> {
    push_u32(out, rec.rule_id);
    out.extend_from_slice(&rec.rule_fingerprint);
    push_len_prefixed_bytes(out, &rec.rule_name, "rule_name")?;
    Ok(())
}

fn decode_rule_def(payload: &[u8]) -> Result<LogRuleDef, FormatError> {
    let mut c = Cursor::new(payload);
    let rule_id = c.take_u32(FrameType::RuleDef, "rule_id")?;
    let rule_fingerprint = c.take_array_32(FrameType::RuleDef, "rule_fingerprint")?;
    let rule_name = c.take_bytes(FrameType::RuleDef, "rule_name")?.to_vec();
    c.require_finished(FrameType::RuleDef)?;
    Ok(LogRuleDef {
        rule_id,
        rule_fingerprint,
        rule_name,
    })
}

fn encode_finding_batch(rec: &LogFindingBatch, out: &mut Vec<u8>) -> Result<(), FormatError> {
    push_len_prefixed_bytes(out, &rec.object_path, "object_path")?;
    let findings_len =
        u32::try_from(rec.findings.len()).map_err(|_| FormatError::LengthTooLarge {
            field: "findings",
            len: rec.findings.len(),
            max: u32::MAX as usize,
        })?;
    push_u32(out, findings_len);
    for finding in &rec.findings {
        push_u32(out, finding.rule_id);
        out.extend_from_slice(&finding.rule_fingerprint);
        out.extend_from_slice(&finding.secret_hash);
        out.extend_from_slice(&finding.finding_id);
        push_u64(out, finding.root_hint_start);
        push_u64(out, finding.root_hint_end);
        push_u64(out, finding.span_start);
        push_u64(out, finding.span_end);
    }
    Ok(())
}

fn decode_finding_batch(payload: &[u8]) -> Result<LogFindingBatch, FormatError> {
    let mut c = Cursor::new(payload);
    let object_path = c
        .take_bytes(FrameType::FindingBatch, "object_path")?
        .to_vec();
    let count = c.take_u32(FrameType::FindingBatch, "findings_count")? as usize;
    // Each finding is at least 132 bytes on disk (see finding_record_on_disk_size_is_132_bytes).
    // Cap pre-allocation to avoid OOM from malformed count fields.
    const MIN_FINDING_BYTES: usize = 132;
    let max_possible = c.remaining() / MIN_FINDING_BYTES;
    let mut findings = Vec::with_capacity(count.min(max_possible));
    for _ in 0..count {
        let rule_id = c.take_u32(FrameType::FindingBatch, "rule_id")?;
        let rule_fingerprint = c.take_array_32(FrameType::FindingBatch, "rule_fingerprint")?;
        let secret_hash = c.take_array_32(FrameType::FindingBatch, "secret_hash")?;
        let finding_id = c.take_array_32(FrameType::FindingBatch, "finding_id")?;
        let root_hint_start = c.take_u64(FrameType::FindingBatch, "root_hint_start")?;
        let root_hint_end = c.take_u64(FrameType::FindingBatch, "root_hint_end")?;
        let span_start = c.take_u64(FrameType::FindingBatch, "span_start")?;
        let span_end = c.take_u64(FrameType::FindingBatch, "span_end")?;
        findings.push(LogFindingRecord {
            rule_id,
            rule_fingerprint,
            secret_hash,
            finding_id,
            root_hint_start,
            root_hint_end,
            span_start,
            span_end,
        });
    }
    c.require_finished(FrameType::FindingBatch)?;
    Ok(LogFindingBatch {
        object_path,
        findings,
    })
}

fn encode_run_end(rec: &LogRunEnd, out: &mut Vec<u8>) -> Result<(), FormatError> {
    push_u64(out, rec.ended_unix_ms);
    push_u64(out, rec.dropped_findings);
    push_u64(out, rec.persistence_emit_failures);
    out.push(u8::from(rec.incomplete));
    Ok(())
}

fn decode_run_end(payload: &[u8]) -> Result<LogRunEnd, FormatError> {
    let mut c = Cursor::new(payload);
    let ended_unix_ms = c.take_u64(FrameType::RunEnd, "ended_unix_ms")?;
    let dropped_findings = c.take_u64(FrameType::RunEnd, "dropped_findings")?;
    let persistence_emit_failures = c.take_u64(FrameType::RunEnd, "persistence_emit_failures")?;
    let incomplete = decode_bool(c.take_u8(FrameType::RunEnd, "incomplete")?, "incomplete")?;
    c.require_finished(FrameType::RunEnd)?;
    Ok(LogRunEnd {
        ended_unix_ms,
        dropped_findings,
        persistence_emit_failures,
        incomplete,
    })
}

#[inline]
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_len_prefixed_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
    field: &'static str,
) -> Result<(), FormatError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FormatError::LengthTooLarge {
        field,
        len: bytes.len(),
        max: u32::MAX as usize,
    })?;
    push_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

#[inline]
fn encode_correlation_mode(mode: CorrelationMode) -> u8 {
    match mode {
        CorrelationMode::Persistent => 0,
        CorrelationMode::Ephemeral => 1,
    }
}

fn decode_correlation_mode(raw: u8, frame_type: FrameType) -> Result<CorrelationMode, FormatError> {
    match raw {
        0 => Ok(CorrelationMode::Persistent),
        1 => Ok(CorrelationMode::Ephemeral),
        _ => Err(FormatError::InvalidRecord {
            frame_type,
            detail: "invalid correlation_mode",
        }),
    }
}

#[inline]
fn encode_key_source(source: KeySource) -> u8 {
    match source {
        KeySource::EnvVar => 0,
        KeySource::MissingEnvVar => 1,
        KeySource::InvalidEnvVar => 2,
    }
}

fn decode_key_source(raw: u8, frame_type: FrameType) -> Result<KeySource, FormatError> {
    match raw {
        0 => Ok(KeySource::EnvVar),
        1 => Ok(KeySource::MissingEnvVar),
        2 => Ok(KeySource::InvalidEnvVar),
        _ => Err(FormatError::InvalidRecord {
            frame_type,
            detail: "invalid key_source",
        }),
    }
}

fn decode_bool(raw: u8, field: &'static str) -> Result<bool, FormatError> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FormatError::InvalidBool { field, value: raw }),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn take_exact(
        &mut self,
        n: usize,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<&'a [u8], FormatError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(FormatError::InvalidRecord { frame_type, detail })?;
        if end > self.bytes.len() {
            return Err(FormatError::InvalidRecord { frame_type, detail });
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    #[inline]
    fn take_u8(&mut self, frame_type: FrameType, detail: &'static str) -> Result<u8, FormatError> {
        Ok(self.take_exact(1, frame_type, detail)?[0])
    }

    fn take_u16(
        &mut self,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<u16, FormatError> {
        let bytes = self.take_exact(2, frame_type, detail)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(
        &mut self,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<u32, FormatError> {
        let bytes = self.take_exact(4, frame_type, detail)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(
        &mut self,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<u64, FormatError> {
        let bytes = self.take_exact(8, frame_type, detail)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn take_bytes(
        &mut self,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<&'a [u8], FormatError> {
        let len = self.take_u32(frame_type, detail)? as usize;
        self.take_exact(len, frame_type, detail)
    }

    fn take_array_32(
        &mut self,
        frame_type: FrameType,
        detail: &'static str,
    ) -> Result<[u8; 32], FormatError> {
        let bytes = self.take_exact(32, frame_type, detail)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn require_finished(&self, frame_type: FrameType) -> Result<(), FormatError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(FormatError::InvalidRecord {
                frame_type,
                detail: "trailing bytes",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor as IoCursor;

    fn sample_run_start() -> LogRunStart {
        LogRunStart {
            version: LOG_FORMAT_VERSION,
            run_id: 42,
            started_unix_ms: 1234,
            durability: LogDurabilityMode::SegmentClose,
            correlation_mode: CorrelationMode::Persistent,
            key_source: KeySource::EnvVar,
            max_inflight_batches: 16,
            max_inflight_bytes: 1 << 20,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
        }
    }

    fn sample_rule_def() -> LogRuleDef {
        LogRuleDef {
            rule_id: 7,
            rule_fingerprint: [0xAB; 32],
            rule_name: b"demo-rule".to_vec(),
        }
    }

    fn sample_finding_batch() -> LogFindingBatch {
        LogFindingBatch {
            object_path: b"src/main.rs".to_vec(),
            findings: vec![
                LogFindingRecord {
                    rule_id: 7,
                    rule_fingerprint: [0x11; 32],
                    secret_hash: [0x22; 32],
                    finding_id: [0x33; 32],
                    root_hint_start: 10,
                    root_hint_end: 20,
                    span_start: 11,
                    span_end: 19,
                },
                LogFindingRecord {
                    rule_id: 8,
                    rule_fingerprint: [0x44; 32],
                    secret_hash: [0x55; 32],
                    finding_id: [0x66; 32],
                    root_hint_start: 30,
                    root_hint_end: 40,
                    span_start: 31,
                    span_end: 39,
                },
            ],
        }
    }

    fn sample_run_end() -> LogRunEnd {
        LogRunEnd {
            ended_unix_ms: 9999,
            dropped_findings: 3,
            persistence_emit_failures: 1,
            incomplete: true,
        }
    }

    #[test]
    fn roundtrip_all_frame_types() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::FindingBatch(sample_finding_batch()),
            LogRecord::RunEnd(sample_run_end()),
        ];

        let mut bytes = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();
        }

        let mut reader =
            LogRecordReader::new(IoCursor::new(bytes), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let mut decoded = Vec::new();
        while let Some(rec) = reader.next_record().unwrap() {
            decoded.push(rec);
        }
        assert_eq!(decoded, records);
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let huge_name = vec![b'x'; (DEFAULT_MAX_FRAME_PAYLOAD_BYTES as usize) + 1];
        let rec = LogRecord::RuleDef(LogRuleDef {
            rule_id: 1,
            rule_fingerprint: [0u8; 32],
            rule_name: huge_name,
        });

        let mut out = Vec::new();
        let err = encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut out).unwrap_err();
        assert!(matches!(err, FormatError::FrameTooLarge { .. }));
    }

    #[test]
    fn crc_mismatch_is_detected() {
        let rec = LogRecord::RunEnd(sample_run_end());
        let mut bytes = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();

        // Flip one payload bit.
        let idx = FRAME_HEADER_BYTES + 1;
        bytes[idx] ^= 0x01;

        let err = decode_record(&bytes, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        assert!(matches!(err, FormatError::CrcMismatch { .. }));
    }

    // ================================================================
    // Codec edge cases
    // ================================================================

    #[test]
    fn decode_truncated_header_various_lengths() {
        // Byte slices of length 0..=8 should all fail with TruncatedHeader.
        for len in 0..=8 {
            let buf = vec![0u8; len];
            let err = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
            assert!(
                matches!(err, FormatError::TruncatedHeader { .. }),
                "len={len}: expected TruncatedHeader, got: {err}"
            );
        }
    }

    #[test]
    fn decode_frame_with_zero_frame_len() {
        // Construct 9+ bytes with frame_len=0.
        let mut buf = vec![0u8; 16];
        // frame_len = 0 (first 4 bytes, already zero)
        // crc = 0 (bytes 4-7, already zero)
        // body bytes (bytes 8+) - interpreted as V1 because the V2 flag is not set.
        buf[8] = 1; // RunStart type byte

        let err = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        // Header bytes are present, so this should fail at frame-length validation.
        assert!(
            matches!(
                err,
                FormatError::TruncatedHeader { .. } | FormatError::InvalidFrameLength { .. }
            ),
            "expected TruncatedHeader or InvalidFrameLength, got: {err}"
        );
    }

    #[test]
    fn decode_unknown_frame_type() {
        // Craft valid-CRC frames with unknown type bytes.
        for type_byte in [0u8, 5, 255] {
            // Build a frame with the unknown type byte.
            let payload = []; // empty payload
            let frame_len: u32 = 1; // just the type byte

            let mut crc = crc32fast::Hasher::new();
            crc.update(&[type_byte]);
            crc.update(&payload);
            let crc32 = crc.finalize();

            let mut buf = Vec::new();
            buf.extend_from_slice(&frame_len.to_le_bytes());
            buf.extend_from_slice(&crc32.to_le_bytes());
            buf.push(type_byte);

            let err = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
            assert!(
                matches!(err, FormatError::UnknownFrameType { raw } if raw == type_byte),
                "type_byte={type_byte}: expected UnknownFrameType, got: {err}"
            );
        }
    }

    #[test]
    fn decode_run_end_invalid_bool() {
        // Craft a RunEnd frame where the `incomplete` byte = 2 (invalid bool).
        let mut payload = Vec::new();
        // ended_unix_ms
        payload.extend_from_slice(&9999u64.to_le_bytes());
        // dropped_findings
        payload.extend_from_slice(&0u64.to_le_bytes());
        // persistence_emit_failures
        payload.extend_from_slice(&0u64.to_le_bytes());
        // incomplete = 2 (invalid)
        payload.push(2);

        let type_byte = FrameType::RunEnd as u8;
        let frame_len = (payload.len() + 1) as u32; // +1 for type byte

        let mut body = vec![type_byte];
        body.extend_from_slice(&payload);

        let mut crc = crc32fast::Hasher::new();
        crc.update(&body);
        let crc32 = crc.finalize();

        let mut buf = Vec::new();
        buf.extend_from_slice(&frame_len.to_le_bytes());
        buf.extend_from_slice(&crc32.to_le_bytes());
        buf.extend_from_slice(&body);

        let err = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        assert!(
            matches!(
                err,
                FormatError::InvalidBool {
                    field: "incomplete",
                    value: 2
                }
            ),
            "expected InvalidBool for incomplete=2, got: {err}"
        );
    }

    #[test]
    fn decode_run_start_invalid_durability() {
        // Craft a RunStart frame where durability byte = 3 (invalid).
        let mut payload = Vec::new();
        // version
        payload.extend_from_slice(&1u16.to_le_bytes());
        // run_id
        payload.extend_from_slice(&42u64.to_le_bytes());
        // started_unix_ms
        payload.extend_from_slice(&1234u64.to_le_bytes());
        // durability = 3 (invalid)
        payload.push(3);
        // correlation_mode = 0 (valid)
        payload.push(0);
        // key_source = 0 (valid)
        payload.push(0);
        // max_inflight_batches
        payload.extend_from_slice(&16u32.to_le_bytes());
        // max_inflight_bytes
        payload.extend_from_slice(&(1u64 << 20).to_le_bytes());
        // max_frame_payload_bytes
        payload.extend_from_slice(&DEFAULT_MAX_FRAME_PAYLOAD_BYTES.to_le_bytes());

        let type_byte = FrameType::RunStart as u8;
        let frame_len = (payload.len() + 1) as u32;

        let mut body = vec![type_byte];
        body.extend_from_slice(&payload);

        let mut crc = crc32fast::Hasher::new();
        crc.update(&body);
        let crc32 = crc.finalize();

        let mut buf = Vec::new();
        buf.extend_from_slice(&frame_len.to_le_bytes());
        buf.extend_from_slice(&crc32.to_le_bytes());
        buf.extend_from_slice(&body);

        let err = decode_record(&buf, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        assert!(
            matches!(
                err,
                FormatError::InvalidEnum {
                    field: "durability",
                    value: 3
                }
            ),
            "expected InvalidEnum for durability=3, got: {err}"
        );
    }

    #[test]
    fn decode_finding_batch_trailing_bytes_rejected() {
        // Encode a valid finding batch, then append extra bytes.
        let rec = LogRecord::FindingBatch(sample_finding_batch());
        let mut bytes = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();

        // Append extra bytes inside the frame (modify frame_len and recompute CRC).
        // Read original frame_len.
        let orig_frame_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let new_frame_len = orig_frame_len + 2;

        // Rebuild: take body, append 2 bytes, recompute CRC.
        let mut body = bytes[FRAME_HEADER_BYTES..].to_vec();
        body.push(0xDE);
        body.push(0xAD);

        let mut crc = crc32fast::Hasher::new();
        crc.update(&body);
        let crc32 = crc.finalize();

        let mut new_bytes = Vec::new();
        new_bytes.extend_from_slice(&new_frame_len.to_le_bytes());
        new_bytes.extend_from_slice(&crc32.to_le_bytes());
        new_bytes.extend_from_slice(&body);

        let err = decode_record(&new_bytes, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap_err();
        assert!(
            matches!(
                err,
                FormatError::InvalidRecord {
                    detail: "trailing bytes",
                    ..
                }
            ),
            "expected InvalidRecord with 'trailing bytes', got: {err}"
        );
    }

    #[test]
    fn finding_batch_with_zero_findings_roundtrips() {
        let batch = LogFindingBatch {
            object_path: b"empty-findings.txt".to_vec(),
            findings: vec![],
        };
        let rec = LogRecord::FindingBatch(batch.clone());
        let mut bytes = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();

        let decoded = decode_record(&bytes, DEFAULT_MAX_FRAME_PAYLOAD_BYTES).unwrap();
        assert_eq!(decoded, LogRecord::FindingBatch(batch));
    }

    /// A reader that returns exactly 1 byte per `read()` call.
    struct OneByteReader<R: Read> {
        inner: R,
    }

    impl<R: Read> Read for OneByteReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }

    #[test]
    fn streaming_reader_one_byte_at_a_time() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::FindingBatch(sample_finding_batch()),
            LogRecord::RunEnd(sample_run_end()),
        ];

        let mut bytes = Vec::new();
        for rec in &records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();
        }

        let reader = OneByteReader {
            inner: IoCursor::new(bytes),
        };
        let mut lr = LogRecordReader::new(reader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let mut decoded = Vec::new();
        while let Some(rec) = lr.next_record().unwrap() {
            decoded.push(rec);
        }
        assert_eq!(decoded, records);
    }

    #[test]
    fn streaming_reader_eof_mid_header() {
        // Provide exactly 4 bytes (partial header).
        let buf = [0x01, 0x00, 0x00, 0x00];
        let mut reader =
            LogRecordReader::new(IoCursor::new(buf.to_vec()), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let err = reader.next_record().unwrap_err();
        assert!(
            matches!(err, FormatError::TruncatedHeader { got: 4 }),
            "expected TruncatedHeader with got=4, got: {err}"
        );
    }

    #[test]
    fn streaming_reader_eof_mid_body() {
        // Encode a valid frame, then truncate by 2 bytes.
        let rec = LogRecord::RunEnd(sample_run_end());
        let mut bytes = Vec::new();
        encode_record(&rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut bytes).unwrap();

        // Remove last 2 bytes.
        bytes.truncate(bytes.len() - 2);

        let mut reader =
            LogRecordReader::new(IoCursor::new(bytes), DEFAULT_MAX_FRAME_PAYLOAD_BYTES);
        let err = reader.next_record().unwrap_err();
        assert!(
            matches!(err, FormatError::TruncatedFrame { .. }),
            "expected TruncatedFrame, got: {err}"
        );
    }

    #[test]
    fn encode_appends_to_existing_buffer() {
        let prefix = vec![0xDE, 0xAD];
        let mut buf = prefix.clone();

        let rec1 = LogRecord::RunEnd(sample_run_end());
        let rec2 = LogRecord::RuleDef(sample_rule_def());
        encode_record(&rec1, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();
        encode_record(&rec2, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut buf).unwrap();

        // Prefix preserved.
        assert_eq!(&buf[..2], &prefix[..]);

        // Both frames decodable from offset 2.
        let mut reader = LogRecordReader::new(
            IoCursor::new(buf[2..].to_vec()),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
        );
        let d1 = reader.next_record().unwrap().unwrap();
        let d2 = reader.next_record().unwrap().unwrap();
        assert_eq!(d1, rec1);
        assert_eq!(d2, rec2);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn decode_finding_batch_huge_count_does_not_oom() {
        // Craft a FindingBatch frame with count = u32::MAX but only a few
        // bytes of actual payload. Without a cap on pre-allocation, this
        // would attempt a ~500 GiB allocation.
        let mut payload = Vec::new();
        // object_path: length-prefixed empty
        payload.extend_from_slice(&0u32.to_le_bytes());
        // findings_count = u32::MAX
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        // No actual finding data follows — the loop should error
        // on the first take_u32 for "rule_id".

        let type_byte = FrameType::FindingBatch as u8;
        let frame_len = (payload.len() + 1) as u32;

        let mut body = vec![type_byte];
        body.extend_from_slice(&payload);

        let mut crc = crc32fast::Hasher::new();
        crc.update(&body);
        let crc32 = crc.finalize();

        let mut buf = Vec::new();
        buf.extend_from_slice(&frame_len.to_le_bytes());
        buf.extend_from_slice(&crc32.to_le_bytes());
        buf.extend_from_slice(&body);

        // Should return a decode error (truncated/invalid), NOT OOM.
        let err = decode_record(&buf, u32::MAX).unwrap_err();
        assert!(
            matches!(err, FormatError::InvalidRecord { .. }),
            "expected InvalidRecord from truncated finding data, got: {err}"
        );
    }

    #[test]
    fn finding_record_on_disk_size_is_132_bytes() {
        // Per-finding payload: rule_id(4) + rule_fingerprint(32) + secret_hash(32)
        //   + finding_id(32) + root_hint_start(8) + root_hint_end(8)
        //   + span_start(8) + span_end(8) = 132 bytes.
        let batch_1 = LogFindingBatch {
            object_path: b"x".to_vec(),
            findings: vec![LogFindingRecord {
                rule_id: 0,
                rule_fingerprint: [0; 32],
                secret_hash: [0; 32],
                finding_id: [0; 32],
                root_hint_start: 0,
                root_hint_end: 0,
                span_start: 0,
                span_end: 0,
            }],
        };
        let batch_2 = LogFindingBatch {
            object_path: b"x".to_vec(),
            findings: vec![
                LogFindingRecord {
                    rule_id: 0,
                    rule_fingerprint: [0; 32],
                    secret_hash: [0; 32],
                    finding_id: [0; 32],
                    root_hint_start: 0,
                    root_hint_end: 0,
                    span_start: 0,
                    span_end: 0,
                },
                LogFindingRecord {
                    rule_id: 1,
                    rule_fingerprint: [1; 32],
                    secret_hash: [1; 32],
                    finding_id: [1; 32],
                    root_hint_start: 1,
                    root_hint_end: 1,
                    span_start: 1,
                    span_end: 1,
                },
            ],
        };

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();
        encode_record(
            &LogRecord::FindingBatch(batch_1),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut buf1,
        )
        .unwrap();
        encode_record(
            &LogRecord::FindingBatch(batch_2),
            DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            &mut buf2,
        )
        .unwrap();

        // The difference in encoded size between 1 finding and 2 findings
        // is exactly the per-finding record size.
        let per_finding_bytes = buf2.len() - buf1.len();
        assert_eq!(
            per_finding_bytes, 132,
            "per-finding on-disk size should be 132 bytes, got {per_finding_bytes}"
        );
    }

    // ── decode_correlation_mode / decode_key_source invalid-value paths ──

    #[test]
    fn decode_correlation_mode_invalid_value_returns_error() {
        for invalid in [2, 128, 255] {
            let result = decode_correlation_mode(invalid, FrameType::RunStart);
            assert!(
                matches!(result, Err(FormatError::InvalidRecord { .. })),
                "expected InvalidRecord for correlation_mode={invalid}, got {result:?}"
            );
        }
    }

    #[test]
    fn decode_key_source_invalid_value_returns_error() {
        for invalid in [3, 128, 255] {
            let result = decode_key_source(invalid, FrameType::RunStart);
            assert!(
                matches!(result, Err(FormatError::InvalidRecord { .. })),
                "expected InvalidRecord for key_source={invalid}, got {result:?}"
            );
        }
    }

    // ── LogRecordReader FrameTooLarge streaming path ────────────────────

    #[test]
    fn log_record_reader_frame_too_large_returns_error() {
        // Craft a raw frame whose declared payload exceeds max_payload_bytes.
        let max_payload: u32 = 256;
        // frame_len = payload_len + 1 (type byte). Set payload_len > max_payload.
        let frame_len: u32 = max_payload + 100 + 1;
        let crc: u32 = 0; // doesn't matter, check happens before CRC

        let mut data = Vec::new();
        data.extend_from_slice(&frame_len.to_le_bytes());
        data.extend_from_slice(&crc.to_le_bytes());
        // We don't need to write the body — the reader should reject before reading it.

        let cursor = IoCursor::new(data);
        let mut reader = LogRecordReader::new(cursor, max_payload);
        let result = reader.next_record();
        assert!(
            matches!(result, Err(FormatError::FrameTooLarge { .. })),
            "expected FrameTooLarge, got {result:?}"
        );
    }
}
