//! Error types for Git scanning stages.
//!
//! Errors are stage-specific to keep diagnostics precise and avoid a
//! single monolithic error enum that grows unbounded.

use std::fmt;
use std::io;

/// Errors from repo discovery and open.
#[derive(Debug)]
#[non_exhaustive]
pub enum Phase1Error {
    /// I/O error during file operations.
    Io(io::Error),
    /// Path canonicalization failed.
    Canonicalization(io::Error),
    /// Not a Git repository (no .git dir/file, not bare).
    NotARepository,
    /// The .git file is malformed (bad gitdir pointer).
    MalformedGitdirFile,
    /// The gitdir target doesn't exist or isn't a directory.
    GitdirTargetNotDir,
    /// The commondir file is malformed.
    MalformedCommondirFile,
    /// The common directory doesn't exist or isn't a directory.
    CommonDirNotDir,
    /// The objects directory doesn't exist or isn't a directory.
    ObjectsDirNotDir,
    /// An alternate object directory doesn't exist or isn't a directory.
    AlternateNotDir,
    /// File exceeds size limit.
    FileTooLarge { size: u64, limit: u32 },
    /// Start set has too many refs.
    StartSetTooLarge { count: usize, max: usize },
    /// Ref name exceeds length limit.
    RefNameTooLong { len: usize, max: usize },
    /// Arena capacity exceeded.
    ArenaOverflow,
    /// Watermark store returned wrong number of results.
    WatermarkCountMismatch { got: usize, expected: usize },
    /// Config file contains invalid UTF-8.
    InvalidUtf8Config,
}

impl Phase1Error {
    /// Creates an I/O error variant.
    #[inline]
    pub fn io(err: io::Error) -> Self {
        Self::Io(err)
    }

    /// Creates a canonicalization error variant.
    #[inline]
    pub fn canonicalization(err: io::Error) -> Self {
        Self::Canonicalization(err)
    }
}

impl fmt::Display for Phase1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Canonicalization(err) => write!(f, "path canonicalization failed: {err}"),
            Self::NotARepository => write!(f, "not a Git repository"),
            Self::MalformedGitdirFile => {
                write!(f, "malformed .git file (expected 'gitdir: <path>')")
            }
            Self::GitdirTargetNotDir => write!(f, "gitdir target is not a directory"),
            Self::MalformedCommondirFile => write!(f, "malformed commondir file"),
            Self::CommonDirNotDir => write!(f, "common directory is not a directory"),
            Self::ObjectsDirNotDir => write!(f, "objects directory is not a directory"),
            Self::AlternateNotDir => write!(f, "alternate object directory is not a directory"),
            Self::FileTooLarge { size, limit } => {
                write!(f, "file too large: {size} bytes (limit: {limit})")
            }
            Self::StartSetTooLarge { count, max } => {
                write!(f, "start set too large: {count} refs (max: {max})")
            }
            Self::RefNameTooLong { len, max } => {
                write!(f, "ref name too long: {len} bytes (max: {max})")
            }
            Self::ArenaOverflow => write!(f, "arena overflow"),
            Self::WatermarkCountMismatch { got, expected } => {
                write!(
                    f,
                    "watermark count mismatch: got {got}, expected {expected}"
                )
            }
            Self::InvalidUtf8Config => write!(f, "config file contains invalid UTF-8"),
        }
    }
}

impl std::error::Error for Phase1Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) | Self::Canonicalization(err) => Some(err),
            _ => None,
        }
    }
}

/// Errors from tree diff and candidate collection.
#[derive(Debug)]
#[non_exhaustive]
pub enum Phase2Error {
    /// Tree object not found.
    TreeNotFound,
    /// Object exists but is not a tree.
    NotATree,
    /// Tree object is corrupt or malformed.
    CorruptTree { detail: &'static str },
    /// OID has invalid length.
    InvalidOidLength { len: usize, expected: usize },
    /// Maximum tree recursion depth exceeded.
    MaxTreeDepthExceeded { max_depth: u16 },
    /// Total tree bytes budget exceeded.
    TreeBytesBudgetExceeded { loaded: u64, budget: u64 },
    /// Path exceeds length limit.
    PathTooLong { len: usize, max: usize },
    /// Candidate buffer is full.
    CandidateBufferFull,
    /// Path arena capacity exceeded.
    PathArenaFull,
}

impl fmt::Display for Phase2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TreeNotFound => write!(f, "tree not found"),
            Self::NotATree => write!(f, "object is not a tree"),
            Self::CorruptTree { detail } => write!(f, "corrupt tree: {detail}"),
            Self::InvalidOidLength { len, expected } => {
                write!(f, "invalid OID length: {len} (expected {expected})")
            }
            Self::MaxTreeDepthExceeded { max_depth } => {
                write!(f, "max tree depth exceeded: {max_depth}")
            }
            Self::TreeBytesBudgetExceeded { loaded, budget } => {
                write!(
                    f,
                    "tree bytes budget exceeded: loaded {loaded}, budget {budget}"
                )
            }
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max: {max})")
            }
            Self::CandidateBufferFull => write!(f, "candidate buffer full"),
            Self::PathArenaFull => write!(f, "path arena full"),
        }
    }
}

impl std::error::Error for Phase2Error {}

/// Errors from spill and dedupe.
#[derive(Debug)]
#[non_exhaustive]
pub enum Phase3Error {
    /// I/O error during spill file operations.
    Io(io::Error),
    /// Maximum number of spill run files exceeded.
    SpillRunLimitExceeded { runs: usize, max: usize },
    /// Total spill bytes exceeded budget.
    SpillBytesExceeded { bytes: u64, max: u64 },
    /// Spill run file has invalid header.
    InvalidRunHeader,
    /// Spill run file is corrupt.
    CorruptRunFile { detail: &'static str },
    /// OID length in run file doesn't match expected.
    OidLengthMismatch { got: u8, expected: u8 },
    /// Path in run file exceeds safety limit.
    RunPathTooLong { len: usize, max: usize },
    /// Seen-blob store returned wrong number of results.
    SeenResponseMismatch { got: usize, expected: usize },
    /// Arena capacity exceeded.
    ArenaOverflow,
    /// Path exceeds length limit.
    PathTooLong { len: usize, max: usize },
}

impl fmt::Display for Phase3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::SpillRunLimitExceeded { runs, max } => {
                write!(f, "spill run limit exceeded: {runs} runs (max: {max})")
            }
            Self::SpillBytesExceeded { bytes, max } => {
                write!(f, "spill bytes exceeded: {bytes} bytes (max: {max})")
            }
            Self::InvalidRunHeader => write!(f, "invalid run file header"),
            Self::CorruptRunFile { detail } => write!(f, "corrupt run file: {detail}"),
            Self::OidLengthMismatch { got, expected } => {
                write!(
                    f,
                    "OID length mismatch in run: got {got}, expected {expected}"
                )
            }
            Self::RunPathTooLong { len, max } => {
                write!(f, "path in run file too long: {len} bytes (max: {max})")
            }
            Self::SeenResponseMismatch { got, expected } => {
                write!(
                    f,
                    "seen-blob response length mismatch: got {got}, expected {expected}"
                )
            }
            Self::ArenaOverflow => write!(f, "arena overflow"),
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max: {max})")
            }
        }
    }
}

impl std::error::Error for Phase3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Phase3Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase1_error_display() {
        let err = Phase1Error::StartSetTooLarge {
            count: 100,
            max: 50,
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn phase2_error_display() {
        let err = Phase2Error::MaxTreeDepthExceeded { max_depth: 256 };
        let msg = format!("{err}");
        assert!(msg.contains("256"));
    }

    #[test]
    fn phase3_error_display() {
        let err = Phase3Error::SpillRunLimitExceeded { runs: 10, max: 8 };
        let msg = format!("{err}");
        assert!(msg.contains("10"));
        assert!(msg.contains("8"));
    }

    #[test]
    fn phase3_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "test");
        let phase3_err: Phase3Error = io_err.into();
        assert!(matches!(phase3_err, Phase3Error::Io(_)));
    }
}
