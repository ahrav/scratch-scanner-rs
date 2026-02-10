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
//! - [`format`] — deterministic framed codec (`len + crc32 + type + payload`)
//!   for `RunStart`, `RuleDef`, `FindingBatch`, and `RunEnd` records.
//! - [`writer`] — bounded single-writer runtime that implements
//!   [`StoreProducer`](crate::store::StoreProducer) with backpressure,
//!   segment rotation, and durable `.open` → `.bin` finalization.

pub mod format;
pub mod writer;

pub use format::{
    decode_record, encode_record, FormatError, FrameType, LogDurabilityMode, LogFindingBatch,
    LogFindingRecord, LogRecord, LogRecordReader, LogRuleDef, LogRunEnd, LogRunStart,
    DEFAULT_MAX_FRAME_PAYLOAD_BYTES, LOG_FORMAT_VERSION,
};
pub use writer::{
    default_fs_log_root, list_finalized_segment_files, AppendLogStoreProducer, LogWriterConfig,
    SCANNER_FS_LOG_DIR_ENV,
};
