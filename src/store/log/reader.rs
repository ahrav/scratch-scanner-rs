//! Streaming log reader with reason-coded failures.
//!
//! This module layers a query/recovery-facing API on top of
//! [`super::format`]. Where `format` operates on single frame buffers,
//! `LogReader` drives an [`std::io::Read`] source frame-by-frame and
//! provides:
//!
//! - **Streaming iteration** over framed records without loading full files.
//! - **Bounded allocation** via a reusable internal frame buffer (`frame_buf`).
//! - **Position tracking** (`frame_index`, `frame_offset`) so recovery callers
//!   can truncate a corrupt `.open` file at the last valid byte boundary.
//! - **Reason-coded errors** ([`LogReadErrorReason`]) enabling deterministic
//!   policy (e.g. stop-at-first-bad-frame, skip-and-continue, truncate).
//!
//! # Failure model
//!
//! `LogReader::next_record` returns a three-state result:
//!
//! | Return value           | Meaning                                        |
//! |------------------------|------------------------------------------------|
//! | `Ok(Some(record))`     | Successfully decoded frame; cursor advanced.   |
//! | `Ok(None)`             | Clean EOF at a frame boundary.                 |
//! | `Err(LogReadError)`    | Decode failure; see `reason()` for category.   |
//!
//! Both `Ok(None)` and `Err` are **terminal**: the reader latches into a
//! `terminated` state and all subsequent calls return `Ok(None)`. This
//! guarantees callers never silently skip corruption.
//!
//! # Version policy
//!
//! `RunStart.version` must equal [`LOG_FORMAT_VERSION`]. Mismatches surface as
//! [`LogReadErrorReason::UnsupportedVersion`] and terminate the reader.

use super::format::{
    decode_record, FormatError, LogRecord, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, FRAME_HEADER_BYTES,
    LOG_FORMAT_VERSION,
};
use std::fmt;
use std::io::Read;

/// High-level reason code for a log read failure.
///
/// Each variant maps to a policy-relevant category rather than a specific
/// codec error, letting callers branch on *what happened* without matching
/// the full [`FormatError`] surface. See [`classify_reason`] for the mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogReadErrorReason {
    /// CRC-32 validation failed — the frame body was corrupted after write.
    CrcMismatch,
    /// EOF arrived mid-header or mid-body — the segment was not fully flushed.
    Truncated,
    /// Frame type discriminant is unknown to this build (forward-compat gap).
    UnsupportedFrame,
    /// `RunStart.version` exceeds what this build can decode.
    UnsupportedVersion,
    /// Frame decoded structurally but its content is invalid (zero-length
    /// body, oversized payload, bad enum/bool value, etc.).
    MalformedFrame,
    /// Underlying transport returned an `io::Error`.
    Io,
}

#[derive(Debug)]
enum LogReadErrorDetail {
    Format(FormatError),
    UnsupportedVersion { found: u16, supported: u16 },
}

/// Rich read failure carrying a reason code and the exact frame location.
///
/// `frame_index` (zero-based ordinal) and `frame_offset` (byte position of
/// the frame header from stream start) together let recovery callers
/// truncate a corrupt segment at the right boundary or report a precise
/// location for diagnostics.
#[derive(Debug)]
pub struct LogReadError {
    reason: LogReadErrorReason,
    frame_index: u64,
    frame_offset: u64,
    detail: LogReadErrorDetail,
}

impl LogReadError {
    #[inline]
    fn from_format(frame_index: u64, frame_offset: u64, err: FormatError) -> Self {
        Self {
            reason: classify_reason(&err),
            frame_index,
            frame_offset,
            detail: LogReadErrorDetail::Format(err),
        }
    }

    #[inline]
    fn unsupported_version(
        frame_index: u64,
        frame_offset: u64,
        found: u16,
        supported: u16,
    ) -> Self {
        Self {
            reason: LogReadErrorReason::UnsupportedVersion,
            frame_index,
            frame_offset,
            detail: LogReadErrorDetail::UnsupportedVersion { found, supported },
        }
    }

    /// Reason-code category for this failure.
    #[inline]
    pub const fn reason(&self) -> LogReadErrorReason {
        self.reason
    }

    /// Zero-based frame index where decoding failed.
    #[inline]
    pub const fn frame_index(&self) -> u64 {
        self.frame_index
    }

    /// Byte offset of the failed frame header (or partial header) from stream start.
    #[inline]
    pub const fn frame_offset(&self) -> u64 {
        self.frame_offset
    }

    /// Access the underlying codec error when one exists.
    #[inline]
    pub const fn format_error(&self) -> Option<&FormatError> {
        match &self.detail {
            LogReadErrorDetail::Format(err) => Some(err),
            LogReadErrorDetail::UnsupportedVersion { .. } => None,
        }
    }

    /// Returns `(found, supported)` for unsupported-version failures.
    #[inline]
    pub const fn unsupported_version_values(&self) -> Option<(u16, u16)> {
        match self.detail {
            LogReadErrorDetail::UnsupportedVersion { found, supported } => Some((found, supported)),
            LogReadErrorDetail::Format(_) => None,
        }
    }
}

impl fmt::Display for LogReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            LogReadErrorDetail::Format(err) => write!(
                f,
                "log read failed at frame {} (offset {}): {:?}: {}",
                self.frame_index, self.frame_offset, self.reason, err
            ),
            LogReadErrorDetail::UnsupportedVersion { found, supported } => write!(
                f,
                "log read failed at frame {} (offset {}): {:?}: run_start version {} is unsupported (expected {})",
                self.frame_index, self.frame_offset, self.reason, found, supported
            ),
        }
    }
}

impl std::error::Error for LogReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            LogReadErrorDetail::Format(err) => Some(err),
            LogReadErrorDetail::UnsupportedVersion { .. } => None,
        }
    }
}

/// Map a codec-level [`FormatError`] to a policy-level [`LogReadErrorReason`].
///
/// The mapping is intentionally many-to-one: several structural errors
/// (e.g. `FrameTooLarge`, `InvalidEnum`, `LengthTooLarge`) all collapse
/// into [`LogReadErrorReason::MalformedFrame`] because a recovery caller
/// treats them identically — the frame is unreadable but the stream
/// position is known.
#[inline]
fn classify_reason(err: &FormatError) -> LogReadErrorReason {
    match err {
        FormatError::CrcMismatch { .. } => LogReadErrorReason::CrcMismatch,
        FormatError::TruncatedHeader { .. } | FormatError::TruncatedFrame { .. } => {
            LogReadErrorReason::Truncated
        }
        FormatError::UnknownFrameType { .. } => LogReadErrorReason::UnsupportedFrame,
        FormatError::Io(_) => LogReadErrorReason::Io,
        FormatError::FrameTooLarge { .. }
        | FormatError::InvalidFrameLength { .. }
        | FormatError::InvalidEnum { .. }
        | FormatError::InvalidBool { .. }
        | FormatError::InvalidRecord { .. }
        | FormatError::LengthTooLarge { .. } => LogReadErrorReason::MalformedFrame,
    }
}

/// Stream decoder for framed FS log records.
///
/// Wraps any [`Read`] source and yields [`LogRecord`] values one frame at a
/// time, tracking the running frame index and byte offset for recovery.
///
/// # Design
///
/// - **Bounded allocation**: a single `frame_buf` is reused across calls.
///   It grows to fit the largest frame seen so far but is never shrunk,
///   keeping allocator churn O(distinct-sizes) rather than O(frames).
/// - **Terminal latch**: once `terminated` is set (on clean EOF *or* any
///   error), every subsequent `next_record` call returns `Ok(None)`.
///   This prevents callers from accidentally advancing past corruption.
/// - **Short-read tolerance**: header and body reads loop until the
///   requested byte count is satisfied, so the reader works correctly on
///   sources that return partial buffers (pipes, network streams, etc.).
pub struct LogReader<R: Read> {
    reader: R,
    /// Reused across calls to avoid per-frame allocation.
    frame_buf: Vec<u8>,
    max_payload_bytes: u32,
    next_frame_index: u64,
    next_frame_offset: u64,
    /// Latched on clean EOF or any decode/IO error; see "Terminal latch" above.
    terminated: bool,
}

impl<R: Read> LogReader<R> {
    /// Construct a reader with an explicit frame payload cap.
    #[inline]
    pub fn new(reader: R, max_payload_bytes: u32) -> Self {
        Self {
            reader,
            frame_buf: Vec::new(),
            max_payload_bytes,
            next_frame_index: 0,
            next_frame_offset: 0,
            terminated: false,
        }
    }

    /// Construct a reader using [`DEFAULT_MAX_FRAME_PAYLOAD_BYTES`].
    #[inline]
    pub fn with_default_limit(reader: R) -> Self {
        Self::new(reader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES)
    }

    /// Return the wrapped reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Max payload limit enforced for each frame.
    #[inline]
    pub const fn max_payload_bytes(&self) -> u32 {
        self.max_payload_bytes
    }

    /// Frame index that will be attempted on the next `next_record` call.
    #[inline]
    pub const fn next_frame_index(&self) -> u64 {
        self.next_frame_index
    }

    /// Byte offset where the next frame header is expected.
    ///
    /// After successfully decoding a frame, this advances by the exact frame
    /// byte length (`8 + frame_len`).
    #[inline]
    pub const fn next_frame_offset(&self) -> u64 {
        self.next_frame_offset
    }

    /// Decode the next record from the underlying stream.
    ///
    /// # Algorithm
    ///
    /// 1. Read the 8-byte frame header (looping on short reads).
    /// 2. Parse `frame_len` and read exactly that many body bytes.
    /// 3. Delegate to [`decode_record`] for CRC check + payload decode.
    /// 4. If the frame is a `RunStart`, enforce the version gate.
    /// 5. Advance `next_frame_index` and `next_frame_offset`.
    ///
    /// Any failure at steps 1-4 latches `terminated = true`.
    pub fn next_record(&mut self) -> Result<Option<LogRecord>, LogReadError> {
        if self.terminated {
            return Ok(None);
        }

        let frame_index = self.next_frame_index;
        let frame_offset = self.next_frame_offset;

        // Read the 8-byte header, looping because `Read::read` may return
        // fewer bytes than requested (pipes, TLS streams, partial OS buffers).
        let mut header = [0u8; FRAME_HEADER_BYTES];
        let mut got = 0usize;
        while got < FRAME_HEADER_BYTES {
            let n = self
                .reader
                .read(&mut header[got..])
                .map_err(FormatError::Io)
                .map_err(|err| {
                    self.terminated = true;
                    LogReadError::from_format(frame_index, frame_offset, err)
                })?;
            if n == 0 {
                self.terminated = true;
                if got == 0 {
                    return Ok(None);
                }
                return Err(LogReadError::from_format(
                    frame_index,
                    frame_offset,
                    FormatError::TruncatedHeader { got },
                ));
            }
            got += n;
        }

        // frame_len covers `type + payload`; zero is invalid because at least
        // the 1-byte type discriminant must be present.
        let frame_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if frame_len == 0 {
            self.terminated = true;
            return Err(LogReadError::from_format(
                frame_index,
                frame_offset,
                FormatError::InvalidFrameLength { len: frame_len },
            ));
        }
        let body_len = usize::try_from(frame_len).map_err(|_| {
            self.terminated = true;
            LogReadError::from_format(
                frame_index,
                frame_offset,
                FormatError::InvalidFrameLength { len: frame_len },
            )
        })?;
        let total_len = body_len.checked_add(FRAME_HEADER_BYTES).ok_or_else(|| {
            self.terminated = true;
            LogReadError::from_format(
                frame_index,
                frame_offset,
                FormatError::InvalidFrameLength { len: frame_len },
            )
        })?;

        self.frame_buf.resize(total_len, 0);
        self.frame_buf[..FRAME_HEADER_BYTES].copy_from_slice(&header);

        let mut read = 0usize;
        while read < body_len {
            let n = self
                .reader
                .read(&mut self.frame_buf[FRAME_HEADER_BYTES + read..total_len])
                .map_err(FormatError::Io)
                .map_err(|err| {
                    self.terminated = true;
                    LogReadError::from_format(frame_index, frame_offset, err)
                })?;
            if n == 0 {
                self.terminated = true;
                return Err(LogReadError::from_format(
                    frame_index,
                    frame_offset,
                    FormatError::TruncatedFrame {
                        expected: body_len,
                        got: read,
                    },
                ));
            }
            read += n;
        }

        // Delegate CRC verification and payload parsing to the format codec.
        let record = decode_record(&self.frame_buf, self.max_payload_bytes).map_err(|err| {
            self.terminated = true;
            LogReadError::from_format(frame_index, frame_offset, err)
        })?;
        // Version gate: only RunStart carries a version field. Non-RunStart
        // frames inherit the version from the run they belong to, so the
        // check fires at most once per well-formed segment.
        if let LogRecord::RunStart(run_start) = &record {
            if run_start.version != LOG_FORMAT_VERSION {
                self.terminated = true;
                return Err(LogReadError::unsupported_version(
                    frame_index,
                    frame_offset,
                    run_start.version,
                    LOG_FORMAT_VERSION,
                ));
            }
        }

        self.next_frame_index = self.next_frame_index.saturating_add(1);
        self.next_frame_offset = self.next_frame_offset.saturating_add(total_len as u64);
        Ok(Some(record))
    }
}

/// Bridges [`next_record`](LogReader::next_record)'s `Result<Option<T>, E>`
/// into the standard `Iterator` `Option<Result<T, E>>` shape.
///
/// The first `Err` is yielded as `Some(Err(..))`, after which the terminal
/// latch causes `next_record` to return `Ok(None)` — so the iterator
/// naturally ends.
impl<R: Read> Iterator for LogReader<R> {
    type Item = Result<LogRecord, LogReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_record() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::keys::{CorrelationMode, KeySource};
    use std::io::Cursor as IoCursor;

    use super::super::format::{
        encode_record, FrameType, LogDurabilityMode, LogRecord, LogRuleDef, LogRunEnd, LogRunStart,
    };

    fn sample_run_start() -> LogRunStart {
        LogRunStart {
            version: LOG_FORMAT_VERSION,
            run_id: 7,
            started_unix_ms: 11,
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
            rule_id: 1,
            rule_fingerprint: [0xAA; 32],
            rule_name: b"demo".to_vec(),
        }
    }

    fn sample_run_end() -> LogRunEnd {
        LogRunEnd {
            ended_unix_ms: 99,
            dropped_findings: 0,
            persistence_emit_failures: 0,
            incomplete: false,
        }
    }

    fn encode_records(records: &[LogRecord]) -> Vec<u8> {
        let mut out = Vec::new();
        for rec in records {
            encode_record(rec, DEFAULT_MAX_FRAME_PAYLOAD_BYTES, &mut out).unwrap();
        }
        out
    }

    fn unknown_type_frame(type_byte: u8) -> Vec<u8> {
        let frame_len: u32 = 1;
        let mut crc = crc32fast::Hasher::new();
        crc.update(&[type_byte]);
        let crc32 = crc.finalize();

        let mut out = Vec::new();
        out.extend_from_slice(&frame_len.to_le_bytes());
        out.extend_from_slice(&crc32.to_le_bytes());
        out.push(type_byte);
        out
    }

    #[test]
    fn reader_streams_records_and_tracks_offsets() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunEnd(sample_run_end()),
        ];
        let bytes = encode_records(&records);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        assert_eq!(reader.next_frame_index(), 0);
        assert_eq!(reader.next_frame_offset(), 0);

        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert_eq!(reader.next_frame_index(), 1);
        let after_first = reader.next_frame_offset();
        assert!(after_first > 0);

        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RuleDef(_))
        ));
        assert_eq!(reader.next_frame_index(), 2);
        assert!(reader.next_frame_offset() > after_first);

        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunEnd(_))
        ));
        assert_eq!(reader.next_frame_index(), 3);
        assert!(reader.next_record().unwrap().is_none());
        // Terminal EOF: subsequent calls stay at None.
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn reason_crc_mismatch() {
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes[FRAME_HEADER_BYTES] ^= 0x01;

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::CrcMismatch);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn reason_truncated() {
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes.pop();

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::Truncated);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn reason_unsupported_frame() {
        let bytes = unknown_type_frame(99);
        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::UnsupportedFrame);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn reason_unsupported_version() {
        let mut start = sample_run_start();
        start.version = LOG_FORMAT_VERSION.wrapping_add(1);
        let bytes = encode_records(&[LogRecord::RunStart(start)]);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::UnsupportedVersion);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
        assert_eq!(
            err.unsupported_version_values(),
            Some((LOG_FORMAT_VERSION.wrapping_add(1), LOG_FORMAT_VERSION))
        );
    }

    #[test]
    fn iterator_returns_error_once_then_ends() {
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes[FRAME_HEADER_BYTES] ^= 0x01;
        let mut iter = LogReader::with_default_limit(IoCursor::new(bytes));

        let first = iter.next();
        assert!(matches!(first, Some(Err(_))));
        assert!(iter.next().is_none());
    }

    #[test]
    fn malformed_zero_length_header_is_reason_coded() {
        let frame_len = 0u32;
        let crc = 0u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame_len.to_le_bytes());
        bytes.extend_from_slice(&crc.to_le_bytes());
        // Keep at least one extra byte so header+body read succeeds and decode sees len=0.
        bytes.push(FrameType::RunEnd as u8);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::MalformedFrame);
    }
}
