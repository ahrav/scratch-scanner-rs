//! Spill run writer.
//!
//! Writes `RunRecord`s into a stable on-disk encoding. The caller is
//! responsible for sorting and deduping records before writing, and for
//! providing a header with an accurate `record_count`.

use std::io::Write;

use super::errors::SpillError;
use super::run_format::{RunContext, RunHeader, RunRecord};
use super::tree_candidate::ResolvedCandidate;

/// Spill run writer.
pub struct RunWriter<W: Write> {
    writer: W,
    header: RunHeader,
    remaining: u32,
}

impl<W: Write> RunWriter<W> {
    /// Creates a new run writer and writes the header.
    pub fn new(mut writer: W, header: RunHeader) -> Result<Self, SpillError> {
        let bytes = header.encode();
        writer.write_all(&bytes).map_err(SpillError::from)?;
        Ok(Self {
            writer,
            header,
            remaining: header.record_count,
        })
    }

    /// Writes a record.
    ///
    /// # Errors
    /// - `OidLengthMismatch` if the record OID length doesn't match the header
    /// - `RunPathTooLong` if the path exceeds `u16::MAX`
    /// - `CorruptRunFile` if the header record count is exceeded
    pub fn write_record(&mut self, record: &RunRecord) -> Result<(), SpillError> {
        if self.remaining == 0 {
            return Err(SpillError::CorruptRunFile {
                detail: "record count exceeded",
            });
        }
        if record.oid.len() != self.header.oid_len {
            return Err(SpillError::OidLengthMismatch {
                got: record.oid.len(),
                expected: self.header.oid_len,
            });
        }
        if record.path.len() > u16::MAX as usize {
            return Err(SpillError::RunPathTooLong {
                len: record.path.len(),
                max: u16::MAX as usize,
            });
        }

        self.writer
            .write_all(record.oid.as_slice())
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&record.ctx.commit_id.to_be_bytes())
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&[record.ctx.parent_idx])
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&[record.ctx.change_kind.as_u8()])
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&record.ctx.ctx_flags.to_be_bytes())
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&record.ctx.cand_flags.to_be_bytes())
            .map_err(SpillError::from)?;

        let path_len = record.path.len() as u16;
        self.writer
            .write_all(&path_len.to_be_bytes())
            .map_err(SpillError::from)?;
        self.writer
            .write_all(&record.path)
            .map_err(SpillError::from)?;

        self.remaining -= 1;
        Ok(())
    }

    /// Writes a resolved candidate as a record.
    ///
    /// This performs a path copy into a temporary `RunRecord`.
    pub fn write_resolved(&mut self, cand: &ResolvedCandidate<'_>) -> Result<(), SpillError> {
        let ctx = RunContext {
            commit_id: cand.commit_id,
            parent_idx: cand.parent_idx,
            change_kind: cand.change_kind,
            ctx_flags: cand.ctx_flags,
            cand_flags: cand.cand_flags,
        };
        let record = RunRecord {
            oid: cand.oid,
            ctx,
            path: cand.path.to_vec(),
        };
        self.write_record(&record)
    }

    /// Finalizes the run writer.
    ///
    /// Returns an error if fewer records were written than declared by the header.
    pub fn finish(mut self) -> Result<W, SpillError> {
        if self.remaining != 0 {
            return Err(SpillError::CorruptRunFile {
                detail: "record count mismatch",
            });
        }
        self.writer.flush().map_err(SpillError::from)?;
        Ok(self.writer)
    }
}
