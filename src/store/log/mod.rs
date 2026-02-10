//! Append-only log persistence backend for filesystem findings.
//!
//! Persists scan findings to a local directory tree of CRC-protected binary
//! segment files. The on-disk layout is:
//!
//! ```text
//! <store_root>/
//!   run-<hex_id>/
//!     segments/
//!       segment-00000000000000000000.bin   # finalized
//!       segment-00000000000000000001.bin   # finalized
//! ```
//!
//! # Submodules
//!
//! - [`mod@format`] — deterministic framed codec (legacy V1 + position-bound V2)
//!   for `RunStart`, `RuleDef`, `FindingBatch`, and `RunEnd` records, plus
//!   V2 segment integrity trailers.
//! - [`reader`] — streaming, position-tracking iterator over framed records
//!   with reason-coded errors. This is the primary entry point for offline
//!   query and segment recovery (e.g. truncating a corrupt `.open` file at
//!   the last valid frame boundary via [`LogReader::next_frame_offset`]).
//! - [`writer`] — bounded single-writer runtime that implements
//!   [`StoreProducer`](crate::store::StoreProducer) with backpressure,
//!   segment rotation, and durable `.open` → `.bin` finalization.

pub mod format;
pub mod reader;
mod secret_cache;
pub mod writer;

pub use format::{
    decode_record, encode_record, encode_record_with_position, finalize_v2_frame_in_place,
    FormatError, FramePosition, FrameType, LogDurabilityMode, LogFindingBatch, LogFindingRecord,
    LogRecord, LogRecordReader, LogRuleDef, LogRunEnd, LogRunStart, SegmentTrailer,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES, LEGACY_LOG_FORMAT_VERSION, LOG_FORMAT_VERSION,
};
pub use reader::{LogReadError, LogReadErrorReason, LogReader};
#[cfg(feature = "bench")]
pub use secret_cache::SecretHashCache;
pub use writer::{
    default_fs_log_root, list_finalized_segment_files, recover_open_segments,
    AppendLogStoreProducer, LogWriterConfig, OpenSegmentRecoveryEntry, OpenSegmentRecoveryOutcome,
    OpenSegmentRecoveryReport, SCANNER_FS_LOG_DIR_ENV,
};
