//! Spill orchestrator for candidate runs.
//!
//! Collects candidates into in-memory chunks, spills sorted runs to disk
//! when limits are exceeded, and performs a k-way merge to produce a
//! globally sorted, deduped stream.
//!
//! # Workflow
//! - Accumulate candidates into a `CandidateChunk`.
//! - On overflow, sort+dedupe and write a run to disk.
//! - At finish, spill any remaining chunk and merge all runs.

use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::run_format::{RunHeader, RunRecord};
use super::run_reader::RunReader;
use super::run_writer::RunWriter;
use super::spill_chunk::CandidateChunk;
use super::spill_limits::SpillLimits;
use super::spill_merge::merge_all;
use super::tree_candidate::{ChangeKind, ResolvedCandidate};

/// Orchestrates spill runs and merge/dedupe.
///
/// The spiller is single-threaded and owns the temporary spill files.
#[derive(Debug)]
pub struct Spiller {
    limits: SpillLimits,
    oid_len: u8,
    spill_dir: PathBuf,
    runs: Vec<PathBuf>,
    spill_bytes: u64,
    chunk: CandidateChunk,
}

impl Spiller {
    /// Creates a new spiller for a repository job.
    ///
    /// The spill directory is created if it does not exist.
    pub fn new(limits: SpillLimits, oid_len: u8, spill_dir: &Path) -> Result<Self, SpillError> {
        limits.validate();
        if oid_len != 20 && oid_len != 32 {
            return Err(SpillError::OidLengthMismatch {
                got: oid_len,
                expected: 20,
            });
        }
        fs::create_dir_all(spill_dir).map_err(SpillError::from)?;
        Ok(Self {
            limits,
            oid_len,
            spill_dir: spill_dir.to_path_buf(),
            runs: Vec::new(),
            spill_bytes: 0,
            chunk: CandidateChunk::new(&limits, oid_len),
        })
    }

    /// Pushes a candidate, spilling the chunk if required.
    ///
    /// If the chunk is full, this spills the current chunk and retries once.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), SpillError> {
        match self.chunk.push(
            oid,
            path,
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
        ) {
            Ok(()) => Ok(()),
            Err(SpillError::ArenaOverflow) => {
                self.spill_chunk()?;
                self.chunk.push(
                    oid,
                    path,
                    commit_id,
                    parent_idx,
                    change_kind,
                    ctx_flags,
                    cand_flags,
                )
            }
            Err(err) => Err(err),
        }
    }

    /// Spills the current chunk to disk if it contains data.
    ///
    /// This writes a sorted, deduped run file and updates the spill byte budget.
    pub fn spill_chunk(&mut self) -> Result<(), SpillError> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        if self.runs.len() >= self.limits.max_spill_runs as usize {
            return Err(SpillError::SpillRunLimitExceeded {
                runs: self.runs.len(),
                max: self.limits.max_spill_runs as usize,
            });
        }

        self.chunk.sort_and_dedupe();
        let run_path = self
            .spill_dir
            .join(format!("spill-{}.run", self.runs.len()));
        let file = File::create(&run_path).map_err(SpillError::from)?;
        let writer = BufWriter::new(file);
        let header = RunHeader::new(self.oid_len, self.chunk.len() as u32)?;
        let mut run_writer = RunWriter::new(writer, header)?;

        for cand in self.chunk.iter_resolved() {
            run_writer.write_resolved(&cand)?;
        }
        let writer = run_writer.finish()?;
        let bytes = writer
            .into_inner()
            .map_err(|err| err.into_error())?
            .metadata()?
            .len();

        self.spill_bytes = self.spill_bytes.saturating_add(bytes);
        if self.spill_bytes > self.limits.max_spill_bytes {
            return Err(SpillError::SpillBytesExceeded {
                bytes: self.spill_bytes,
                max: self.limits.max_spill_bytes,
            });
        }

        self.runs.push(run_path);
        self.chunk.clear();
        Ok(())
    }

    /// Finalizes the spill process, returning globally sorted unique records.
    ///
    /// If no runs were spilled, this returns a sorted+deduped in-memory vector.
    /// Run files are left on disk in `spill_dir`; the caller is responsible
    /// for cleanup once the merged output is consumed.
    pub fn finish(mut self) -> Result<Vec<RunRecord>, SpillError> {
        if self.runs.is_empty() {
            self.chunk.sort_and_dedupe();
            return Ok(self
                .chunk
                .iter_resolved()
                .map(|cand| resolved_to_record(&cand))
                .collect());
        }

        self.spill_chunk()?;

        let mut readers = Vec::new();
        for path in &self.runs {
            let file = File::open(path).map_err(SpillError::from)?;
            let reader = RunReader::new(file, self.limits.max_path_len)?;
            readers.push(reader);
        }

        merge_all(readers)
    }
}

fn resolved_to_record(cand: &ResolvedCandidate<'_>) -> RunRecord {
    RunRecord {
        oid: cand.oid,
        ctx: super::run_format::RunContext {
            commit_id: cand.commit_id,
            parent_idx: cand.parent_idx,
            change_kind: cand.change_kind,
            ctx_flags: cand.ctx_flags,
            cand_flags: cand.cand_flags,
        },
        path: cand.path.to_vec(),
    }
}
