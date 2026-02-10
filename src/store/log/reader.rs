//! Streaming log reader with reason-coded failures.
//!
//! This module layers a query/recovery-facing API on top of
//! [`super::format`]. Where `format` provides a basic streaming decoder
//! ([`super::format::LogRecordReader`]) without position tracking or
//! reason codes, `LogReader` drives an [`std::io::Read`] source
//! frame-by-frame and adds:
//!
//! - **Streaming iteration** over framed records without loading full files.
//! - **Bounded allocation** via a reusable internal frame buffer (`frame_buf`).
//! - **Position tracking** (`frame_index`, `frame_offset`) so recovery callers
//!   can truncate a corrupt `.open` file at the last valid byte boundary.
//! - **V2 segment-trailer verification** of `frame_count`, `total_frame_bytes`,
//!   and the BLAKE3 frame-CRC chain when reading finalized `.bin` segments.
//! - **V2 segment-header/trailer chaining** via `prev_segment_hash` plus
//!   derived per-segment hash material for cross-segment continuity checks.
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
//! `RunStart.version` must be in the supported range
//! `[LEGACY_LOG_FORMAT_VERSION, LOG_FORMAT_VERSION]`. Mismatches surface as
//! [`LogReadErrorReason::UnsupportedVersion`] and terminate the reader.

use super::format::{
    decode_record, decode_segment_header, decode_segment_trailer, derive_segment_hash,
    extend_frame_crc_chain, parse_frame_layout, FormatError, FrameType, LogRecord, SegmentHeader,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES, FRAME_HEADER_BYTES, LEGACY_LOG_FORMAT_VERSION,
    LOG_FORMAT_VERSION, SEGMENT_HEADER_BYTES, SEGMENT_HEADER_MAGIC, SEGMENT_TRAILER_BYTES,
    SEGMENT_TRAILER_MAGIC,
};
use std::fmt;
use std::io::Read;

/// High-level reason code for a log read failure.
///
/// Each variant maps to a policy-relevant category rather than a specific
/// codec error, letting callers branch on *what happened* without matching
/// the full [`FormatError`] surface. See [`classify_reason`] for the mapping.
///
/// # Recovery semantics
///
/// For all variants except [`Io`](Self::Io) and
/// [`UnsupportedVersion`](Self::UnsupportedVersion), the accompanying
/// [`LogReadError::frame_offset`] is the exact byte position of the failed
/// frame header. Recovery callers can safely truncate an `.open` segment at
/// that offset to discard the corrupt tail while preserving every frame
/// before it. `UnsupportedVersion` should be surfaced as a hard error so
/// startup recovery does not mutate forward-version segments, and `Io`
/// errors may leave the stream position indeterminate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogReadErrorReason {
    /// CRC-32 validation failed — the frame body was corrupted after write.
    CrcMismatch,
    /// EOF arrived mid-header or mid-body — the segment was not fully flushed.
    Truncated,
    /// Frame type discriminant is unknown to this build (forward-compat gap).
    UnsupportedFrame,
    /// `RunStart.version` does not match what this build can decode.
    UnsupportedVersion,
    /// Frame decoded structurally but its content is invalid (zero-length
    /// body, oversized payload, bad enum/bool value, etc.).
    MalformedFrame,
    /// Underlying transport returned an `io::Error`.
    Io,
}

/// Internal detail behind a [`LogReadError`].
///
/// Separates codec-level failures (anything [`decode_record`] can produce)
/// from the reader-level version gate, which fires *after* a structurally
/// valid `RunStart` has been decoded.
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
    /// Wrap a codec-level [`FormatError`], classifying it into a reason code.
    #[inline]
    fn from_format(frame_index: u64, frame_offset: u64, err: FormatError) -> Self {
        Self {
            reason: classify_reason(&err),
            frame_index,
            frame_offset,
            detail: LogReadErrorDetail::Format(err),
        }
    }

    /// Construct a reader-level version-mismatch error (not a codec error).
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
        | FormatError::InvalidSegmentHeader { .. }
        | FormatError::InvalidSegmentTrailer { .. }
        | FormatError::LengthTooLarge { .. } => LogReadErrorReason::MalformedFrame,
    }
}

#[inline]
fn is_supported_log_version(version: u16) -> bool {
    (LEGACY_LOG_FORMAT_VERSION..=LOG_FORMAT_VERSION).contains(&version)
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
    segment_preamble_checked: bool,
    segment_header: Option<SegmentHeader>,
    segment_hash: Option<[u8; 32]>,
    segment_frame_count: u64,
    segment_total_frame_bytes: u64,
    segment_frame_crc_chain: [u8; 32],
    /// Latched on clean EOF or any decode/IO error; see "Terminal latch" above.
    terminated: bool,
}

impl<R: Read> LogReader<R> {
    /// Construct a reader with an explicit frame payload cap.
    ///
    /// `max_payload_bytes` is forwarded to [`decode_record`] on every frame
    /// and caps the payload *after* the 1-byte type discriminant. Frames
    /// whose declared payload exceeds this limit are rejected as
    /// [`LogReadErrorReason::MalformedFrame`]. The value should match the
    /// `max_frame_payload_bytes` recorded in the segment's `RunStart`.
    ///
    /// **Performance note**: Each frame requires at least two `read()` calls
    /// (header + body). When `R` is an unbuffered source such as a raw
    /// [`std::fs::File`] or pipe, every call is a kernel syscall. For
    /// file-backed sources, wrap in [`std::io::BufReader`] or use the
    /// [`buffered`](Self::buffered) convenience constructor.
    #[inline]
    pub fn new(reader: R, max_payload_bytes: u32) -> Self {
        Self {
            reader,
            // Pre-allocate for a typical small frame (header + modest payload)
            // to avoid the first reallocation on the initial `next_record` call.
            frame_buf: Vec::with_capacity(FRAME_HEADER_BYTES + 256),
            max_payload_bytes,
            next_frame_index: 0,
            next_frame_offset: 0,
            segment_preamble_checked: false,
            segment_header: None,
            segment_hash: None,
            segment_frame_count: 0,
            segment_total_frame_bytes: 0,
            segment_frame_crc_chain: [0u8; 32],
            terminated: false,
        }
    }

    /// Construct a reader using [`DEFAULT_MAX_FRAME_PAYLOAD_BYTES`].
    ///
    /// See [`new`](Self::new) for performance notes on unbuffered sources.
    #[inline]
    pub fn with_default_limit(reader: R) -> Self {
        Self::new(reader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES)
    }

    /// Wrap `reader` in a [`std::io::BufReader`] and construct a `LogReader`
    /// with an explicit payload cap.
    ///
    /// This is the recommended constructor for file-backed or pipe-backed
    /// sources where the caller has not already applied buffering. The
    /// internal 8 KiB buffer amortizes syscalls so that most frames are
    /// served entirely from user-space memory.
    #[inline]
    pub fn buffered(reader: R, max_payload_bytes: u32) -> LogReader<std::io::BufReader<R>> {
        LogReader::new(std::io::BufReader::new(reader), max_payload_bytes)
    }

    /// Convenience: [`buffered`](Self::buffered) with
    /// [`DEFAULT_MAX_FRAME_PAYLOAD_BYTES`].
    #[inline]
    pub fn buffered_with_default_limit(reader: R) -> LogReader<std::io::BufReader<R>> {
        Self::buffered(reader, DEFAULT_MAX_FRAME_PAYLOAD_BYTES)
    }

    /// Return the wrapped reader, consuming the `LogReader`.
    ///
    /// The underlying `R` will have been advanced past all successfully
    /// decoded frames (and any partially-read bytes from a failed frame).
    /// Its exact position depends on where the reader stopped — callers
    /// should use [`next_frame_offset`](Self::next_frame_offset) to know
    /// how many bytes were consumed successfully.
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
    /// byte length (`8 + body_len`).
    #[inline]
    pub const fn next_frame_offset(&self) -> u64 {
        self.next_frame_offset
    }

    /// Parsed V2 segment header, if one was present at stream start.
    #[inline]
    pub const fn segment_header(&self) -> Option<SegmentHeader> {
        self.segment_header
    }

    /// Deterministic V2 segment hash derived after a valid trailer is read.
    #[inline]
    pub const fn segment_hash(&self) -> Option<[u8; 32]> {
        self.segment_hash
    }

    fn read_exact_or_err(
        &mut self,
        dst: &mut [u8],
        frame_index: u64,
        frame_offset: u64,
    ) -> Result<(), LogReadError> {
        let mut got = 0usize;
        while got < dst.len() {
            let n = self
                .reader
                .read(&mut dst[got..])
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
                        expected: dst.len(),
                        got,
                    },
                ));
            }
            got += n;
        }
        Ok(())
    }

    fn read_header_or_eof(
        &mut self,
        header: &mut [u8; FRAME_HEADER_BYTES],
        frame_index: u64,
        frame_offset: u64,
    ) -> Result<Option<()>, LogReadError> {
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
        Ok(Some(()))
    }

    /// Read the next frame's header and body into `self.frame_buf`.
    ///
    /// Returns `Ok(Some(total_len))` on success (header + body bytes in
    /// `frame_buf[..total_len]`), `Ok(None)` on clean EOF at a frame
    /// boundary, or `Err` on any I/O or structural failure.
    ///
    /// On error the terminal latch is set; callers must not retry.
    fn read_next_frame(&mut self) -> Result<Option<usize>, LogReadError> {
        let frame_index = self.next_frame_index;
        let frame_offset = self.next_frame_offset;

        // Parse optional V2 segment header once at stream start.
        if !self.segment_preamble_checked {
            let mut prelude = [0u8; FRAME_HEADER_BYTES];
            if self
                .read_header_or_eof(&mut prelude, frame_index, frame_offset)?
                .is_none()
            {
                return Ok(None);
            }
            if prelude == SEGMENT_HEADER_MAGIC {
                let mut header_buf = [0u8; SEGMENT_HEADER_BYTES];
                header_buf[..FRAME_HEADER_BYTES].copy_from_slice(&prelude);
                self.read_exact_or_err(
                    &mut header_buf[FRAME_HEADER_BYTES..],
                    frame_index,
                    frame_offset,
                )?;
                let header = decode_segment_header(&header_buf).map_err(|err| {
                    self.terminated = true;
                    LogReadError::from_format(frame_index, frame_offset, err)
                })?;
                self.segment_header = Some(header);
                self.segment_preamble_checked = true;
                self.next_frame_offset = SEGMENT_HEADER_BYTES as u64;
                return self.read_next_frame();
            } else {
                self.segment_preamble_checked = true;
                // No segment header: treat the prelude as the first frame header.
                let mut header = [0u8; FRAME_HEADER_BYTES];
                header.copy_from_slice(&prelude);
                return self.read_next_frame_from_header(header, frame_index, frame_offset);
            }
        }

        let mut header = [0u8; FRAME_HEADER_BYTES];
        if self
            .read_header_or_eof(&mut header, frame_index, frame_offset)?
            .is_none()
        {
            return Ok(None);
        }
        self.read_next_frame_from_header(header, frame_index, frame_offset)
    }

    fn read_next_frame_from_header(
        &mut self,
        header: [u8; FRAME_HEADER_BYTES],
        frame_index: u64,
        frame_offset: u64,
    ) -> Result<Option<usize>, LogReadError> {
        if header == SEGMENT_TRAILER_MAGIC {
            let mut trailer_buf = [0u8; SEGMENT_TRAILER_BYTES];
            trailer_buf[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            let mut trailer_got = FRAME_HEADER_BYTES;
            while trailer_got < SEGMENT_TRAILER_BYTES {
                let n = self
                    .reader
                    .read(&mut trailer_buf[trailer_got..])
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
                            expected: SEGMENT_TRAILER_BYTES,
                            got: trailer_got,
                        },
                    ));
                }
                trailer_got += n;
            }
            let trailer = decode_segment_trailer(&trailer_buf).map_err(|err| {
                self.terminated = true;
                LogReadError::from_format(frame_index, frame_offset, err)
            })?;
            if let Some(header) = self.segment_header {
                if trailer.segment_id != header.segment_id {
                    self.terminated = true;
                    return Err(LogReadError::from_format(
                        frame_index,
                        frame_offset,
                        FormatError::InvalidSegmentTrailer {
                            detail: "segment_id mismatch",
                        },
                    ));
                }
            }
            if trailer.frame_count != self.segment_frame_count {
                self.terminated = true;
                return Err(LogReadError::from_format(
                    frame_index,
                    frame_offset,
                    FormatError::InvalidSegmentTrailer {
                        detail: "frame_count mismatch",
                    },
                ));
            }
            if trailer.total_frame_bytes != self.segment_total_frame_bytes {
                self.terminated = true;
                return Err(LogReadError::from_format(
                    frame_index,
                    frame_offset,
                    FormatError::InvalidSegmentTrailer {
                        detail: "total_frame_bytes mismatch",
                    },
                ));
            }
            if trailer.frame_crc_chain != self.segment_frame_crc_chain {
                self.terminated = true;
                return Err(LogReadError::from_format(
                    frame_index,
                    frame_offset,
                    FormatError::InvalidSegmentTrailer {
                        detail: "frame_crc_chain mismatch",
                    },
                ));
            }
            if let Some(header) = self.segment_header {
                self.segment_hash = Some(derive_segment_hash(&header, &trailer));
            }
            self.terminated = true;
            return Ok(None);
        }

        let frame_len_word = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let layout = parse_frame_layout(frame_len_word, self.max_payload_bytes).map_err(|err| {
            self.terminated = true;
            LogReadError::from_format(frame_index, frame_offset, err)
        })?;
        let body_len = layout.body_len;
        let total_len = body_len.checked_add(FRAME_HEADER_BYTES).ok_or_else(|| {
            self.terminated = true;
            LogReadError::from_format(
                frame_index,
                frame_offset,
                FormatError::InvalidFrameLength {
                    len: frame_len_word,
                },
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

        Ok(Some(total_len))
    }

    /// Check the version field in `RunStart` frames only, using the raw body
    /// bytes in `frame_buf`. Returns `Err` (and latches terminated) on
    /// mismatch.
    fn check_version_gate(&mut self) -> Result<(), LogReadError> {
        let frame_index = self.next_frame_index;
        let frame_offset = self.next_frame_offset;
        let frame_len_word = u32::from_le_bytes([
            self.frame_buf[0],
            self.frame_buf[1],
            self.frame_buf[2],
            self.frame_buf[3],
        ]);
        let layout = parse_frame_layout(frame_len_word, self.max_payload_bytes).map_err(|err| {
            self.terminated = true;
            LogReadError::from_format(frame_index, frame_offset, err)
        })?;
        let body = &self.frame_buf[FRAME_HEADER_BYTES..];

        if body[layout.type_offset] == FrameType::RunStart as u8 {
            let version_offset = layout.payload_offset;
            if body.len() >= version_offset + 2 {
                let found = u16::from_le_bytes([body[version_offset], body[version_offset + 1]]);
                if !is_supported_log_version(found) {
                    self.terminated = true;
                    return Err(LogReadError::unsupported_version(
                        frame_index,
                        frame_offset,
                        found,
                        LOG_FORMAT_VERSION,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify the CRC of the frame currently in `frame_buf`.
    ///
    /// Returns `Err` (and latches terminated) on mismatch.
    fn check_crc(&mut self) -> Result<(), LogReadError> {
        let frame_index = self.next_frame_index;
        let frame_offset = self.next_frame_offset;

        let crc_expected = u32::from_le_bytes([
            self.frame_buf[4],
            self.frame_buf[5],
            self.frame_buf[6],
            self.frame_buf[7],
        ]);
        let body = &self.frame_buf[FRAME_HEADER_BYTES..];
        let mut crc = crc32fast::Hasher::new();
        crc.update(body);
        let crc_actual = crc.finalize();

        if crc_actual != crc_expected {
            self.terminated = true;
            return Err(LogReadError::from_format(
                frame_index,
                frame_offset,
                FormatError::CrcMismatch {
                    expected: crc_expected,
                    actual: crc_actual,
                },
            ));
        }
        Ok(())
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

        let total_len = match self.read_next_frame()? {
            Some(n) => n,
            None => return Ok(None),
        };

        // Delegate CRC verification and payload parsing to the format codec.
        let record = decode_record(&self.frame_buf, self.max_payload_bytes).map_err(|err| {
            self.terminated = true;
            LogReadError::from_format(frame_index, frame_offset, err)
        })?;
        // Version gate: only RunStart carries a version field. Non-RunStart
        // frames inherit the version from the run they belong to, so the
        // check fires once per RunStart frame, which appears at most once
        // in a well-formed segment.
        if let LogRecord::RunStart(run_start) = &record {
            if !is_supported_log_version(run_start.version) {
                self.terminated = true;
                return Err(LogReadError::unsupported_version(
                    frame_index,
                    frame_offset,
                    run_start.version,
                    LOG_FORMAT_VERSION,
                ));
            }
        }

        match self.next_frame_index.checked_add(1) {
            Some(v) => self.next_frame_index = v,
            None => self.terminated = true,
        }
        match self.next_frame_offset.checked_add(total_len as u64) {
            Some(v) => self.next_frame_offset = v,
            None => self.terminated = true,
        }
        let frame_crc = u32::from_le_bytes([
            self.frame_buf[4],
            self.frame_buf[5],
            self.frame_buf[6],
            self.frame_buf[7],
        ]);
        self.segment_frame_count = self.segment_frame_count.saturating_add(1);
        self.segment_total_frame_bytes = self
            .segment_total_frame_bytes
            .saturating_add(total_len as u64);
        self.segment_frame_crc_chain =
            extend_frame_crc_chain(&self.segment_frame_crc_chain, frame_crc);
        Ok(Some(record))
    }

    /// Validate the next frame without decoding its payload.
    ///
    /// Reads the frame header and body, verifies the CRC-32, and enforces the
    /// version gate on `RunStart` frames — but skips the full payload decode
    /// (`decode_record`), avoiding all per-frame allocations (Vec fields in
    /// `FindingBatch`, `RuleDef`, etc.).
    ///
    /// Returns `Ok(Some(()))` when the frame is structurally valid,
    /// `Ok(None)` on clean EOF, or `Err` on any failure. The terminal latch
    /// and offset semantics are identical to [`next_record`].
    ///
    /// # When to use
    ///
    /// Use this for recovery scans that only need byte boundaries and
    /// stop-reasons — not the decoded record contents.
    pub fn next_frame_validated(&mut self) -> Result<Option<()>, LogReadError> {
        if self.terminated {
            return Ok(None);
        }

        let total_len = match self.read_next_frame()? {
            Some(n) => n,
            None => return Ok(None),
        };

        // CRC check over the full body:
        // - V1: type + payload
        // - V2: frame_seq + segment_id + type + payload
        self.check_crc()?;

        // Version gate for RunStart frames.
        self.check_version_gate()?;

        match self.next_frame_index.checked_add(1) {
            Some(v) => self.next_frame_index = v,
            None => self.terminated = true,
        }
        match self.next_frame_offset.checked_add(total_len as u64) {
            Some(v) => self.next_frame_offset = v,
            None => self.terminated = true,
        }
        let frame_crc = u32::from_le_bytes([
            self.frame_buf[4],
            self.frame_buf[5],
            self.frame_buf[6],
            self.frame_buf[7],
        ]);
        self.segment_frame_count = self.segment_frame_count.saturating_add(1);
        self.segment_total_frame_bytes = self
            .segment_total_frame_bytes
            .saturating_add(total_len as u64);
        self.segment_frame_crc_chain =
            extend_frame_crc_chain(&self.segment_frame_crc_chain, frame_crc);
        Ok(Some(()))
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
    use std::io::{self, Cursor as IoCursor};

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

    fn rewrite_body_byte_and_recompute_crc(frame: &mut [u8], body_offset: usize, value: u8) {
        let body_idx = FRAME_HEADER_BYTES + body_offset;
        frame[body_idx] = value;

        let mut crc = crc32fast::Hasher::new();
        crc.update(&frame[FRAME_HEADER_BYTES..]);
        let crc32 = crc.finalize();
        frame[4..FRAME_HEADER_BYTES].copy_from_slice(&crc32.to_le_bytes());
    }

    fn decode_with_incomplete_policy(
        bytes: Vec<u8>,
    ) -> (Vec<LogRecord>, bool, Option<LogReadErrorReason>) {
        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let mut records = Vec::new();
        let mut stop_reason = None;

        loop {
            match reader.next_record() {
                Ok(Some(record)) => records.push(record),
                Ok(None) => break,
                Err(err) => {
                    stop_reason = Some(err.reason());
                    break;
                }
            }
        }

        let has_clean_run_end = records
            .iter()
            .any(|record| matches!(record, LogRecord::RunEnd(run_end) if !run_end.incomplete));
        let incomplete = stop_reason.is_some() || !has_clean_run_end;
        (records, incomplete, stop_reason)
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

    struct HeaderThenIoError {
        header: IoCursor<Vec<u8>>,
    }

    impl std::io::Read for HeaderThenIoError {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.header.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            Err(io::Error::other("body read attempted"))
        }
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

    #[test]
    fn oversized_frame_is_rejected_before_body_read() {
        const MAX_PAYLOAD_BYTES: u32 = 64;
        // frame_len = type(1) + payload(65): exceeds MAX_PAYLOAD_BYTES by 1.
        let frame_len = MAX_PAYLOAD_BYTES + 2;
        let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
        header.extend_from_slice(&frame_len.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        let source = HeaderThenIoError {
            header: IoCursor::new(header),
        };
        let mut reader = LogReader::new(source, MAX_PAYLOAD_BYTES);
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::MalformedFrame);
        assert!(matches!(
            err.format_error(),
            Some(FormatError::FrameTooLarge { len, max })
                if *len == MAX_PAYLOAD_BYTES + 1 && *max == MAX_PAYLOAD_BYTES
        ));
    }

    #[test]
    fn truncated_tail_policy_treats_terminal_error_as_incomplete_eof() {
        let mut bytes = encode_records(&[
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunEnd(sample_run_end()),
        ]);
        bytes.truncate(bytes.len() - 4);

        let (records, incomplete, stop_reason) = decode_with_incomplete_policy(bytes);
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0], LogRecord::RunStart(_)));
        assert!(matches!(records[1], LogRecord::RuleDef(_)));
        assert!(incomplete);
        assert_eq!(stop_reason, Some(LogReadErrorReason::Truncated));
    }

    #[test]
    fn crc_failure_stops_at_first_bad_frame_and_marks_incomplete() {
        let mut bad_run_end = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bad_run_end[FRAME_HEADER_BYTES] ^= 0x01;

        let mut bytes = encode_records(&[
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
        ]);
        bytes.extend_from_slice(&bad_run_end);
        bytes.extend_from_slice(&encode_records(&[LogRecord::RunEnd(sample_run_end())]));

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes.clone()));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RuleDef(_))
        ));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::CrcMismatch);
        assert!(reader.next_record().unwrap().is_none());

        let (records, incomplete, stop_reason) = decode_with_incomplete_policy(bytes);
        assert_eq!(records.len(), 2);
        assert!(incomplete);
        assert_eq!(stop_reason, Some(LogReadErrorReason::CrcMismatch));
    }

    /// Verify that `next_frame_offset()` after a decode error equals the byte
    /// position immediately after the last successfully decoded frame — i.e.
    /// the start of the *bad* frame, not the start of the last *good* frame.
    ///
    /// Reviewer claim (PR #50): truncating at `next_frame_offset()` on error
    /// discards the last valid frame. This test proves the claim is false:
    /// `next_frame_offset()` is advanced only on success, so it already sits
    /// at the correct recovery boundary.
    #[test]
    fn next_frame_offset_on_error_is_end_of_last_good_frame() {
        let good_frames = [
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
        ];
        let good_bytes = encode_records(&good_frames);
        let expected_boundary = good_bytes.len() as u64;

        // Append a corrupt RunEnd (flip a body byte to break CRC).
        let mut bad_run_end = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bad_run_end[FRAME_HEADER_BYTES] ^= 0x01;

        let mut stream = good_bytes.clone();
        stream.extend_from_slice(&bad_run_end);

        let mut reader = LogReader::with_default_limit(IoCursor::new(stream));
        // Consume both good frames.
        assert!(reader.next_record().unwrap().is_some());
        assert!(reader.next_record().unwrap().is_some());
        // Third frame fails with CRC mismatch.
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::CrcMismatch);

        // The critical assertion: next_frame_offset sits at the first byte of
        // the bad frame, which is the first byte AFTER the last good frame.
        assert_eq!(reader.next_frame_offset(), expected_boundary);
        // And err.frame_offset() matches (both captured before the failed read).
        assert_eq!(err.frame_offset(), expected_boundary);

        // Verify the boundary is correct by re-reading only the good prefix.
        let truncated = good_bytes[..expected_boundary as usize].to_vec();
        let mut verify = LogReader::with_default_limit(IoCursor::new(truncated));
        assert!(matches!(
            verify.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert!(matches!(
            verify.next_record().unwrap(),
            Some(LogRecord::RuleDef(_))
        ));
        // Clean EOF — no data lost.
        assert!(verify.next_record().unwrap().is_none());
    }

    /// Verify that the payload-cap check fires before the frame buffer is
    /// resized, preventing OOM from corrupted headers declaring huge payloads.
    ///
    /// Reviewer claim (PR #50): `frame_buf.resize()` runs before the
    /// `max_payload_bytes` guard. This test proves the claim is false: the
    /// existing `HeaderThenIoError` reader would return an I/O error on any
    /// body read, but the reader never reaches the body — it rejects the
    /// oversized frame at the header-parsing stage.
    #[test]
    fn oversized_payload_rejected_without_allocation() {
        const MAX: u32 = 64;
        // Declare a frame with payload = MAX + 1 (just over the limit).
        let frame_len = MAX + 2; // type(1) + payload(MAX+1)
        let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
        header.extend_from_slice(&frame_len.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // dummy CRC

        let source = HeaderThenIoError {
            header: IoCursor::new(header),
        };
        let mut reader = LogReader::new(source, MAX);
        let err = reader.next_record().unwrap_err();
        // Error is FrameTooLarge / MalformedFrame, NOT Io — proving the body
        // was never read and the buffer was never resized.
        assert_eq!(err.reason(), LogReadErrorReason::MalformedFrame);
        assert!(matches!(
            err.format_error(),
            Some(FormatError::FrameTooLarge { len, max }) if *len == MAX + 1 && *max == MAX
        ));
    }

    #[test]
    fn reserved_identity_metadata_violation_is_reason_coded_malformed() {
        // RunStart payload layout:
        // version(2) + run_id(8) + started(8) + durability(1) + correlation_mode(1)
        // + key_source(1) + max_inflight_batches(4) + max_inflight_bytes(8)
        // + max_frame_payload_bytes(4)
        const RUN_START_KEY_SOURCE_BODY_OFFSET: usize = 1 + 2 + 8 + 8 + 1 + 1;

        let mut invalid_run_start = encode_records(&[LogRecord::RunStart(sample_run_start())]);
        // key_source uses a small fixed domain; 0xFF exercises reserved/unknown value handling.
        rewrite_body_byte_and_recompute_crc(
            &mut invalid_run_start,
            RUN_START_KEY_SOURCE_BODY_OFFSET,
            0xFF,
        );

        let mut bytes = encode_records(&[
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
        ]);
        bytes.extend_from_slice(&invalid_run_start);
        bytes.extend_from_slice(&encode_records(&[LogRecord::RunEnd(sample_run_end())]));

        let (records, incomplete, stop_reason) = decode_with_incomplete_policy(bytes);
        assert_eq!(records.len(), 2);
        assert!(incomplete);
        assert_eq!(stop_reason, Some(LogReadErrorReason::MalformedFrame));
    }

    // ================================================================
    // Test helpers: I/O fault injection
    // ================================================================

    /// Reader that delivers `limit` bytes from an inner cursor, then returns
    /// `io::ErrorKind::Other` on every subsequent read.
    struct FailAfterNBytes {
        inner: IoCursor<Vec<u8>>,
        limit: usize,
        delivered: usize,
    }

    impl FailAfterNBytes {
        fn new(data: Vec<u8>, limit: usize) -> Self {
            Self {
                inner: IoCursor::new(data),
                limit,
                delivered: 0,
            }
        }
    }

    impl io::Read for FailAfterNBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.delivered >= self.limit {
                return Err(io::Error::other("injected I/O failure"));
            }
            let remaining = self.limit - self.delivered;
            let max_read = buf.len().min(remaining);
            let n = self.inner.read(&mut buf[..max_read])?;
            self.delivered += n;
            Ok(n)
        }
    }

    /// Reader that delivers at most 1 byte per `read` call, exercising
    /// the short-read loop in header and body reads.
    struct OneByteReader<R: io::Read> {
        inner: R,
    }

    impl<R: io::Read> OneByteReader<R> {
        fn new(inner: R) -> Self {
            Self { inner }
        }
    }

    impl<R: io::Read> io::Read for OneByteReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }

    #[test]
    fn empty_source_returns_clean_eof() {
        let mut reader = LogReader::with_default_limit(IoCursor::new(Vec::new()));
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.next_frame_offset(), 0);
        assert_eq!(reader.next_frame_index(), 0);
        // Subsequent calls stay at None (terminal latch).
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn truncated_header_partial_bytes() {
        for partial_len in 1..FRAME_HEADER_BYTES {
            let bytes = vec![0xAA; partial_len];
            let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
            let err = reader.next_record().unwrap_err();
            assert_eq!(
                err.reason(),
                LogReadErrorReason::Truncated,
                "expected Truncated for {partial_len}-byte header stub"
            );
            assert_eq!(err.frame_index(), 0);
            assert_eq!(err.frame_offset(), 0);
        }
    }

    #[test]
    fn io_error_during_header_read() {
        let bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        // Fail after 4 bytes: mid-header (header is 8 bytes).
        let source = FailAfterNBytes::new(bytes, 4);
        let mut reader = LogReader::with_default_limit(source);
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::Io);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn io_error_during_body_read() {
        let bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        // Fail after FRAME_HEADER_BYTES + 1: first byte of body read succeeds,
        // then I/O error.
        let source = FailAfterNBytes::new(bytes, FRAME_HEADER_BYTES + 1);
        let mut reader = LogReader::with_default_limit(source);
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::Io);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn short_read_source_one_byte_at_a_time() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunEnd(sample_run_end()),
        ];
        let bytes = encode_records(&records);
        let total_len = bytes.len() as u64;

        let source = OneByteReader::new(IoCursor::new(bytes));
        let mut reader = LogReader::with_default_limit(source);

        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RuleDef(_))
        ));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunEnd(_))
        ));
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.next_frame_offset(), total_len);
        assert_eq!(reader.next_frame_index(), 3);
    }

    #[test]
    fn second_run_start_wrong_version_stops_reader() {
        let mut bad_start = sample_run_start();
        bad_start.version = 99;
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunStart(bad_start),
        ];
        let bytes = encode_records(&records);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RunStart(_))
        ));
        assert!(matches!(
            reader.next_record().unwrap(),
            Some(LogRecord::RuleDef(_))
        ));
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::UnsupportedVersion);
        assert_eq!(err.frame_index(), 2);
        assert!(err.frame_offset() > 0);
    }

    /// Offset overflow must terminate the reader rather than freezing at
    /// `u64::MAX` (which `saturating_add` would do).
    #[test]
    fn offset_overflow_terminates_reader() {
        let record = LogRecord::RunEnd(sample_run_end());
        let bytes = encode_records(&[record]);
        let total_len = bytes.len();

        // Place next_frame_offset near u64::MAX so that adding total_len
        // would overflow. The reader should still return this record
        // (it was decoded successfully) but latch terminated for the
        // *next* call.
        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        reader.next_frame_offset = u64::MAX - (total_len as u64) + 1;

        // First call succeeds (the record itself is valid).
        let rec = reader.next_record().unwrap();
        assert!(rec.is_some(), "should decode the record before terminating");

        // Terminal latch must be set due to offset overflow.
        assert!(
            reader.next_record().unwrap().is_none(),
            "reader should be terminated after offset overflow"
        );
    }

    /// Index overflow terminates the reader independently of offset overflow.
    #[test]
    fn index_overflow_terminates_reader() {
        let record = LogRecord::RunEnd(sample_run_end());
        let bytes = encode_records(&[record]);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        reader.next_frame_index = u64::MAX;

        let rec = reader.next_record().unwrap();
        assert!(rec.is_some());

        assert!(
            reader.next_record().unwrap().is_none(),
            "reader should be terminated after index overflow"
        );
    }

    #[test]
    fn frame_buffer_reuse_large_then_small() {
        let big_rule = LogRuleDef {
            rule_id: 42,
            rule_fingerprint: [0xBB; 32],
            rule_name: vec![0x41; 8192],
        };
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(big_rule.clone()),
            LogRecord::RunEnd(sample_run_end()),
        ];
        let bytes = encode_records(&records);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let r1 = reader.next_record().unwrap().unwrap();
        assert!(matches!(r1, LogRecord::RunStart(_)));
        let r2 = reader.next_record().unwrap().unwrap();
        assert_eq!(r2, LogRecord::RuleDef(big_rule));
        let r3 = reader.next_record().unwrap().unwrap();
        assert_eq!(r3, LogRecord::RunEnd(sample_run_end()));
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn into_inner_returns_consumed_reader() {
        let records = vec![LogRecord::RunStart(sample_run_start())];
        let bytes = encode_records(&records);
        let total_len = bytes.len() as u64;

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        assert!(reader.next_record().unwrap().is_some());

        let offset_before = reader.next_frame_offset();
        assert_eq!(offset_before, total_len);

        let cursor = reader.into_inner();
        assert_eq!(cursor.position(), total_len);
    }

    #[test]
    fn log_read_error_display_and_source() {
        // Format variant: CRC mismatch.
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes[FRAME_HEADER_BYTES] ^= 0x01;
        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();

        let display = format!("{err}");
        assert!(display.contains("frame 0"));
        assert!(display.contains("offset 0"));
        assert!(display.contains("CrcMismatch"));
        assert!(std::error::Error::source(&err).is_some());

        // Version variant.
        let mut start = sample_run_start();
        start.version = LOG_FORMAT_VERSION.wrapping_add(1);
        let bytes = encode_records(&[LogRecord::RunStart(start)]);
        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_record().unwrap_err();

        let display = format!("{err}");
        assert!(display.contains("frame 0"));
        assert!(display.contains("offset 0"));
        assert!(display.contains("UnsupportedVersion"));
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn max_payload_enforcement_through_reader() {
        let bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        let mut reader = LogReader::new(IoCursor::new(bytes), 4);
        let err = reader.next_record().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::MalformedFrame);
    }

    #[test]
    fn finding_batch_zero_findings_through_reader() {
        use super::super::format::LogFindingBatch;
        let batch = LogFindingBatch {
            object_path: b"empty.txt".to_vec(),
            findings: vec![],
        };
        let records = vec![LogRecord::FindingBatch(batch.clone())];
        let bytes = encode_records(&records);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let rec = reader.next_record().unwrap().unwrap();
        assert_eq!(rec, LogRecord::FindingBatch(batch));
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn reader_does_not_enforce_frame_ordering() {
        use super::super::format::LogFindingBatch;
        let records = vec![
            LogRecord::RunEnd(sample_run_end()),
            LogRecord::FindingBatch(LogFindingBatch {
                object_path: b"x.txt".to_vec(),
                findings: vec![],
            }),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunStart(sample_run_start()),
        ];
        let bytes = encode_records(&records);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        for expected in &records {
            let rec = reader.next_record().unwrap().unwrap();
            assert_eq!(&rec, expected);
        }
        assert!(reader.next_record().unwrap().is_none());
    }

    // ================================================================
    // next_frame_validated — skip-decode path
    // ================================================================

    #[test]
    fn validated_streams_and_tracks_offsets_same_as_next_record() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunEnd(sample_run_end()),
        ];
        let bytes = encode_records(&records);
        let total_len = bytes.len() as u64;

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        assert_eq!(reader.next_frame_index(), 0);
        assert_eq!(reader.next_frame_offset(), 0);

        assert!(reader.next_frame_validated().unwrap().is_some());
        assert_eq!(reader.next_frame_index(), 1);
        let after_first = reader.next_frame_offset();
        assert!(after_first > 0);

        assert!(reader.next_frame_validated().unwrap().is_some());
        assert_eq!(reader.next_frame_index(), 2);
        assert!(reader.next_frame_offset() > after_first);

        assert!(reader.next_frame_validated().unwrap().is_some());
        assert_eq!(reader.next_frame_index(), 3);
        assert_eq!(reader.next_frame_offset(), total_len);

        // Clean EOF + terminal latch.
        assert!(reader.next_frame_validated().unwrap().is_none());
        assert!(reader.next_frame_validated().unwrap().is_none());
    }

    #[test]
    fn validated_crc_mismatch() {
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes[FRAME_HEADER_BYTES] ^= 0x01;

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_frame_validated().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::CrcMismatch);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
        // Terminal latch.
        assert!(reader.next_frame_validated().unwrap().is_none());
    }

    #[test]
    fn validated_truncated() {
        let mut bytes = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bytes.pop();

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_frame_validated().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::Truncated);
    }

    #[test]
    fn validated_unsupported_version() {
        let mut start = sample_run_start();
        start.version = LOG_FORMAT_VERSION.wrapping_add(1);
        let bytes = encode_records(&[LogRecord::RunStart(start)]);

        let mut reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let err = reader.next_frame_validated().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::UnsupportedVersion);
        assert_eq!(err.frame_index(), 0);
        assert_eq!(err.frame_offset(), 0);
    }

    #[test]
    fn validated_oversized_frame() {
        const MAX: u32 = 64;
        let frame_len = MAX + 2;
        let mut header = Vec::with_capacity(FRAME_HEADER_BYTES);
        header.extend_from_slice(&frame_len.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        let source = HeaderThenIoError {
            header: IoCursor::new(header),
        };
        let mut reader = LogReader::new(source, MAX);
        let err = reader.next_frame_validated().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::MalformedFrame);
    }

    #[test]
    fn validated_empty_source_returns_clean_eof() {
        let mut reader = LogReader::with_default_limit(IoCursor::new(Vec::new()));
        assert!(reader.next_frame_validated().unwrap().is_none());
        assert_eq!(reader.next_frame_offset(), 0);
        assert_eq!(reader.next_frame_index(), 0);
    }

    /// The critical property: `next_frame_validated` and `next_record` agree
    /// on frame offsets and error boundaries for the same byte stream.
    #[test]
    fn validated_offset_parity_with_next_record() {
        let records = vec![
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
            LogRecord::RunEnd(sample_run_end()),
        ];
        let bytes = encode_records(&records);

        // Collect offsets via next_record.
        let mut decode_reader = LogReader::with_default_limit(IoCursor::new(bytes.clone()));
        let mut decode_offsets = Vec::new();
        while decode_reader.next_record().unwrap().is_some() {
            decode_offsets.push(decode_reader.next_frame_offset());
        }

        // Collect offsets via next_frame_validated.
        let mut validate_reader = LogReader::with_default_limit(IoCursor::new(bytes));
        let mut validate_offsets = Vec::new();
        while validate_reader.next_frame_validated().unwrap().is_some() {
            validate_offsets.push(validate_reader.next_frame_offset());
        }

        assert_eq!(decode_offsets, validate_offsets);
    }

    /// On CRC error, `next_frame_validated` stops at the same boundary as
    /// `next_record`.
    #[test]
    fn validated_error_boundary_parity() {
        let good_frames = [
            LogRecord::RunStart(sample_run_start()),
            LogRecord::RuleDef(sample_rule_def()),
        ];
        let good_bytes = encode_records(&good_frames);
        let expected_boundary = good_bytes.len() as u64;

        let mut bad_run_end = encode_records(&[LogRecord::RunEnd(sample_run_end())]);
        bad_run_end[FRAME_HEADER_BYTES] ^= 0x01;

        let mut stream = good_bytes;
        stream.extend_from_slice(&bad_run_end);

        let mut reader = LogReader::with_default_limit(IoCursor::new(stream));
        assert!(reader.next_frame_validated().unwrap().is_some());
        assert!(reader.next_frame_validated().unwrap().is_some());
        let err = reader.next_frame_validated().unwrap_err();
        assert_eq!(err.reason(), LogReadErrorReason::CrcMismatch);
        assert_eq!(reader.next_frame_offset(), expected_boundary);
        assert_eq!(err.frame_offset(), expected_boundary);
    }
}
