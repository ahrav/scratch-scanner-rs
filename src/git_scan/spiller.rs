//! Spill orchestrator for candidate runs.
//!
//! Collects candidates into in-memory chunks, spills sorted runs to disk
//! when limits are exceeded, and emits globally sorted unique blobs after
//! seen-store filtering.
//!
//! # Workflow
//! - Accumulate candidates into a `CandidateChunk`.
//! - On overflow, sort+dedupe and write a run to disk.
//! - At finalize, merge runs (if any), choose canonical context per OID,
//!   batch seen-store queries, and emit unseen blobs to the sink.

use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::SpillError;
use super::object_id::OidBytes;
use super::run_format::{RunContext, RunHeader, RunRecord};
use super::run_reader::RunReader;
use super::run_writer::RunWriter;
use super::seen_store::SeenBlobStore;
use super::spill_chunk::CandidateChunk;
use super::spill_limits::SpillLimits;
use super::spill_merge::RunMerger;
use super::tree_candidate::{CandidateContext, ChangeKind, ResolvedCandidate};
use super::unique_blob::{UniqueBlob, UniqueBlobSink};

/// I/O buffer size for run files (256 KB).
const IO_BUFFER_SIZE: usize = 256 * 1024;

/// Statistics from spill + seen filtering.
#[derive(Debug, Clone, Default)]
pub struct SpillStats {
    /// Total candidates received.
    pub candidates_received: u64,
    /// Unique OIDs after global dedupe.
    pub unique_blobs: u64,
    /// Spill runs written to disk.
    pub spill_runs: usize,
    /// Total spill bytes written.
    pub spill_bytes: u64,
    /// OIDs filtered out as already seen.
    pub seen_blobs: u64,
    /// OIDs emitted to the sink.
    pub emitted_blobs: u64,
}

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
    candidates_received: u64,
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
            candidates_received: 0,
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
            Ok(()) => {
                self.candidates_received += 1;
                Ok(())
            }
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
                )?;
                self.candidates_received += 1;
                Ok(())
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
        let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, file);
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

    /// Finalizes spill processing, emitting unseen unique blobs to the sink.
    pub fn finalize<S: SeenBlobStore, B: UniqueBlobSink>(
        mut self,
        seen_store: &S,
        sink: &mut B,
    ) -> Result<SpillStats, SpillError> {
        let mut stats = SpillStats {
            candidates_received: self.candidates_received,
            unique_blobs: 0,
            spill_runs: self.runs.len(),
            spill_bytes: self.spill_bytes,
            seen_blobs: 0,
            emitted_blobs: 0,
        };

        if self.runs.is_empty() {
            self.chunk.sort_and_dedupe();
            self.process_chunk_only(seen_store, sink, &mut stats)?;
        } else {
            self.spill_chunk()?;
            stats.spill_runs = self.runs.len();
            stats.spill_bytes = self.spill_bytes;
            self.process_with_merge(seen_store, sink, &mut stats)?;
        }

        sink.finish()?;
        self.cleanup_runs();
        Ok(stats)
    }

    fn process_chunk_only<S: SeenBlobStore, B: UniqueBlobSink>(
        &self,
        seen_store: &S,
        sink: &mut B,
        stats: &mut SpillStats,
    ) -> Result<(), SpillError> {
        let mut batch = BatchBuffer::new(
            self.limits.seen_batch_max_oids as usize,
            self.limits.seen_batch_max_path_bytes,
        );

        let mut current_oid: Option<OidBytes> = None;
        let mut canonical_ctx: Option<RunContext> = None;
        let mut canonical_path: Option<&[u8]> = None;

        for cand in self.chunk.iter_resolved() {
            let ctx = resolved_to_context(&cand);
            match current_oid {
                None => {
                    current_oid = Some(cand.oid);
                    canonical_ctx = Some(ctx);
                    canonical_path = Some(cand.path);
                }
                Some(oid) if oid != cand.oid => {
                    let ctx = canonical_ctx.expect("canonical ctx missing");
                    let path = canonical_path.expect("canonical path missing");
                    self.push_unique(&mut batch, oid, ctx, path, stats, seen_store, sink)?;
                    current_oid = Some(cand.oid);
                    canonical_ctx = Some(ctx);
                    canonical_path = Some(cand.path);
                }
                Some(_) => {
                    let best_ctx = canonical_ctx.expect("canonical ctx missing");
                    let best_path = canonical_path.expect("canonical path missing");
                    if is_more_canonical(ctx, cand.path, best_ctx, best_path) {
                        canonical_ctx = Some(ctx);
                        canonical_path = Some(cand.path);
                    }
                }
            }
        }

        if let Some(oid) = current_oid {
            let ctx = canonical_ctx.expect("canonical ctx missing");
            let path = canonical_path.expect("canonical path missing");
            self.push_unique(&mut batch, oid, ctx, path, stats, seen_store, sink)?;
        }

        if !batch.is_empty() {
            self.flush_batch(&batch, stats, seen_store, sink)?;
            batch.clear();
        }

        Ok(())
    }

    fn process_with_merge<S: SeenBlobStore, B: UniqueBlobSink>(
        &self,
        seen_store: &S,
        sink: &mut B,
        stats: &mut SpillStats,
    ) -> Result<(), SpillError> {
        let mut readers = Vec::with_capacity(self.runs.len());
        for path in &self.runs {
            let file = File::open(path).map_err(SpillError::from)?;
            let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
            let run_reader = RunReader::new(reader, self.limits.max_path_len)?;
            readers.push(run_reader);
        }

        let mut merger = RunMerger::new(readers)?;
        let mut batch = BatchBuffer::new(
            self.limits.seen_batch_max_oids as usize,
            self.limits.seen_batch_max_path_bytes,
        );

        let mut current_oid: Option<OidBytes> = None;
        let mut canonical: Option<RunRecord> = None;

        while let Some(record) = merger.next_unique()? {
            match current_oid {
                None => {
                    current_oid = Some(record.oid);
                    canonical = Some(record);
                }
                Some(oid) if oid != record.oid => {
                    let best = canonical.take().expect("canonical record missing");
                    self.push_unique(
                        &mut batch, oid, best.ctx, &best.path, stats, seen_store, sink,
                    )?;
                    current_oid = Some(record.oid);
                    canonical = Some(record);
                }
                Some(_) => {
                    let best = canonical.as_ref().expect("canonical record missing");
                    if is_more_canonical(record.ctx, &record.path, best.ctx, &best.path) {
                        canonical = Some(record);
                    }
                }
            }
        }

        if let Some(oid) = current_oid {
            let best = canonical.expect("canonical record missing");
            self.push_unique(
                &mut batch, oid, best.ctx, &best.path, stats, seen_store, sink,
            )?;
        }

        if !batch.is_empty() {
            self.flush_batch(&batch, stats, seen_store, sink)?;
            batch.clear();
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn push_unique<S: SeenBlobStore, B: UniqueBlobSink>(
        &self,
        batch: &mut BatchBuffer,
        oid: OidBytes,
        ctx: RunContext,
        path: &[u8],
        stats: &mut SpillStats,
        seen_store: &S,
        sink: &mut B,
    ) -> Result<(), SpillError> {
        stats.unique_blobs += 1;

        if !batch.can_fit(path.len()) {
            self.flush_batch(batch, stats, seen_store, sink)?;
            batch.clear();
        }

        batch.push(oid, ctx, path)?;

        if batch.len() >= batch.max_oids() {
            self.flush_batch(batch, stats, seen_store, sink)?;
            batch.clear();
        }

        Ok(())
    }

    fn flush_batch<S: SeenBlobStore, B: UniqueBlobSink>(
        &self,
        batch: &BatchBuffer,
        stats: &mut SpillStats,
        seen_store: &S,
        sink: &mut B,
    ) -> Result<(), SpillError> {
        if batch.is_empty() {
            return Ok(());
        }

        let seen_flags = seen_store.batch_check_seen(batch.oids())?;
        if seen_flags.len() != batch.len() {
            return Err(SpillError::SeenResponseMismatch {
                got: seen_flags.len(),
                expected: batch.len(),
            });
        }

        for (idx, blob) in batch.blobs().iter().enumerate() {
            if seen_flags[idx] {
                stats.seen_blobs += 1;
            } else {
                sink.emit(blob, batch.paths())?;
                stats.emitted_blobs += 1;
            }
        }

        Ok(())
    }

    fn cleanup_runs(&mut self) {
        for path in self.runs.drain(..) {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for Spiller {
    fn drop(&mut self) {
        self.cleanup_runs();
    }
}

fn resolved_to_context(cand: &ResolvedCandidate<'_>) -> RunContext {
    RunContext {
        commit_id: cand.commit_id,
        parent_idx: cand.parent_idx,
        change_kind: cand.change_kind,
        ctx_flags: cand.ctx_flags,
        cand_flags: cand.cand_flags,
    }
}

/// Returns true if `a` should win canonical selection for the same OID.
///
/// Ordering: commit id, path bytes, parent index, change kind, ctx flags,
/// then candidate flags.
#[inline]
fn is_more_canonical(a_ctx: RunContext, a_path: &[u8], b_ctx: RunContext, b_path: &[u8]) -> bool {
    match a_ctx.commit_id.cmp(&b_ctx.commit_id) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_path.cmp(b_path) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.parent_idx.cmp(&b_ctx.parent_idx) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.change_kind.as_u8().cmp(&b_ctx.change_kind.as_u8()) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.ctx_flags.cmp(&b_ctx.ctx_flags) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    a_ctx.cand_flags < b_ctx.cand_flags
}

struct BatchBuffer {
    oids: Vec<OidBytes>,
    blobs: Vec<UniqueBlob>,
    path_arena: ByteArena,
    max_oids: usize,
    max_path_bytes: u32,
}

impl BatchBuffer {
    fn new(max_oids: usize, max_path_bytes: u32) -> Self {
        Self {
            oids: Vec::with_capacity(max_oids),
            blobs: Vec::with_capacity(max_oids),
            path_arena: ByteArena::with_capacity(max_path_bytes),
            max_oids,
            max_path_bytes,
        }
    }

    fn len(&self) -> usize {
        self.oids.len()
    }

    fn is_empty(&self) -> bool {
        self.oids.is_empty()
    }

    fn max_oids(&self) -> usize {
        self.max_oids
    }

    fn oids(&self) -> &[OidBytes] {
        &self.oids
    }

    fn blobs(&self) -> &[UniqueBlob] {
        &self.blobs
    }

    fn paths(&self) -> &ByteArena {
        &self.path_arena
    }

    fn can_fit(&self, path_len: usize) -> bool {
        self.oids.len() < self.max_oids && self.path_arena.remaining() as usize >= path_len
    }

    fn push(&mut self, oid: OidBytes, ctx: RunContext, path: &[u8]) -> Result<(), SpillError> {
        debug_assert!(
            self.oids.last().map(|prev| prev <= &oid).unwrap_or(true),
            "batch OIDs must be sorted"
        );

        if self.oids.len() >= self.max_oids {
            return Err(SpillError::ArenaOverflow);
        }

        let path_ref = if path.is_empty() {
            ByteRef::new(0, 0)
        } else if path.len() > ByteRef::MAX_LEN as usize {
            return Err(SpillError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN as usize,
            });
        } else {
            self.path_arena
                .intern(path)
                .ok_or(SpillError::ArenaOverflow)?
        };

        let ctx = CandidateContext {
            commit_id: ctx.commit_id,
            parent_idx: ctx.parent_idx,
            change_kind: ctx.change_kind,
            ctx_flags: ctx.ctx_flags,
            cand_flags: ctx.cand_flags,
            path_ref,
        };

        self.oids.push(oid);
        self.blobs.push(UniqueBlob { oid, ctx });
        Ok(())
    }

    fn clear(&mut self) {
        self.oids.clear();
        self.blobs.clear();
        self.path_arena = ByteArena::with_capacity(self.max_path_bytes);
    }
}
