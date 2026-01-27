#![allow(dead_code)]
//! Single-threaded staged pipeline for scanning file trees.
//!
//! Why a staged pipeline in a single thread?
//! - It makes backpressure explicit (rings are fixed-capacity).
//! - It keeps memory usage bounded and easy to reason about.
//! - It cleanly separates IO, scanning, and output without allocations.
//!
//! Stages are executed in a tight suggest/pump loop using fixed-capacity rings:
//! Walker -> Reader -> Scanner -> Output.

use crate::stdx::RingBuffer;
use crate::{
    BufferPool, Chunk, Engine, FileId, FileTable, FindingRec, ScanScratch, BUFFER_ALIGN,
    BUFFER_LEN_MAX,
};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Default chunk size used by the pipeline (bytes).
///
/// A value of 0 means "auto", resolved to the maximum buffer size minus overlap
/// (aligned down to `BUFFER_ALIGN`).
pub const DEFAULT_CHUNK_SIZE: usize = 0;

/// Default file ring capacity.
pub const PIPE_FILE_RING_CAP: usize = 1024;
/// Default chunk ring capacity.
pub const PIPE_CHUNK_RING_CAP: usize = 128;
/// Default output ring capacity.
pub const PIPE_OUT_RING_CAP: usize = 8192;
/// Default buffer pool capacity for the pipeline.
pub const PIPE_POOL_CAP: usize = PIPE_CHUNK_RING_CAP + 8;

/// Default maximum number of files to scan.
pub const PIPE_MAX_FILES: usize = 1_000_000;

/// Configuration for the high-level pipeline scanner.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Bytes read per chunk (excluding overlap). Use 0 for the maximum size.
    pub chunk_size: usize,
    /// Maximum number of files to queue.
    pub max_files: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_files: PIPE_MAX_FILES,
        }
    }
}

/// Summary counters for a pipeline run.
#[derive(Clone, Copy, Debug, Default)]
pub struct PipelineStats {
    /// Number of files enqueued.
    pub files: u64,
    /// Number of chunks scanned.
    pub chunks: u64,
    /// Total bytes scanned (excludes overlap).
    pub bytes_scanned: u64,
    /// Total number of findings emitted.
    pub findings: u64,
    /// Errors encountered while walking directories.
    pub walk_errors: u64,
    /// Errors encountered while opening files.
    pub open_errors: u64,
    /// Errors encountered while reading files.
    pub errors: u64,
    /// Base64 decode/gate instrumentation.
    #[cfg(feature = "b64-stats")]
    pub base64: crate::Base64DecodeStats,
}

/// Simple single-producer, single-consumer ring wrapper.
///
/// We keep the pipeline single-threaded, but the SPSC abstraction still helps:
/// - It makes backpressure explicit (capacity is a hard bound).
/// - It separates stage responsibilities cleanly without allocation.
struct SpscRing<T, const N: usize> {
    ring: RingBuffer<T, N>,
}

impl<T, const N: usize> SpscRing<T, N> {
    fn new() -> Self {
        Self {
            ring: RingBuffer::new(),
        }
    }

    fn is_full(&self) -> bool {
        self.ring.is_full()
    }

    fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    fn push(&mut self, value: T) -> Result<(), T> {
        self.ring.push_back(value)
    }

    fn push_assume_capacity(&mut self, value: T) {
        self.ring.push_back_assume_capacity(value);
    }

    fn pop(&mut self) -> Option<T> {
        self.ring.pop_front()
    }
}

enum WalkEntry {
    Path(PathBuf),
    Dir(fs::ReadDir),
}

/// Depth-first directory walker that feeds the file ring.
///
/// DFS keeps memory proportional to directory depth rather than total file count,
/// and it naturally yields paths in a locality-friendly order for disk reads.
struct Walker {
    stack: Vec<WalkEntry>,
    done: bool,
    max_files: usize,
}

impl Walker {
    fn new(root: PathBuf, max_files: usize) -> Self {
        let mut stack = Vec::with_capacity(max_files.max(1));
        stack.push(WalkEntry::Path(root));
        Self {
            stack,
            done: false,
            max_files,
        }
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn pump<const FILE_CAP: usize>(
        &mut self,
        files: &mut FileTable,
        file_ring: &mut SpscRing<FileId, FILE_CAP>,
        stats: &mut PipelineStats,
    ) -> io::Result<bool> {
        let mut progressed = false;

        while !file_ring.is_full() {
            let entry = match self.stack.pop() {
                Some(entry) => entry,
                None => {
                    self.done = true;
                    break;
                }
            };

            match entry {
                WalkEntry::Path(path) => {
                    let meta = match fs::symlink_metadata(&path) {
                        Ok(meta) => meta,
                        Err(_) => {
                            stats.walk_errors += 1;
                            stats.errors += 1;
                            continue;
                        }
                    };

                    let ty = meta.file_type();
                    if ty.is_symlink() {
                        continue;
                    }

                    if ty.is_dir() {
                        match fs::read_dir(&path) {
                            Ok(rd) => self.stack.push(WalkEntry::Dir(rd)),
                            Err(_) => {
                                stats.walk_errors += 1;
                                stats.errors += 1;
                            }
                        }
                        continue;
                    }

                    if !ty.is_file() {
                        continue;
                    }

                    if files.len() >= self.max_files {
                        self.done = true;
                        break;
                    }

                    let size = meta.len();
                    let dev_inode = dev_inode(&meta);
                    let id = files.push(path, size, dev_inode, 0);
                    file_ring.push_assume_capacity(id);
                    stats.files += 1;
                    progressed = true;
                }
                WalkEntry::Dir(mut rd) => match rd.next() {
                    Some(Ok(entry)) => {
                        self.stack.push(WalkEntry::Dir(rd));
                        self.stack.push(WalkEntry::Path(entry.path()));
                    }
                    Some(Err(_)) => {
                        stats.walk_errors += 1;
                        stats.errors += 1;
                        self.stack.push(WalkEntry::Dir(rd));
                    }
                    None => {}
                },
            }
        }

        Ok(progressed)
    }
}

/// Stateful reader for a single file, preserving overlap across chunks.
///
/// The overlap is sized by `Engine::required_overlap()` so any anchor window
/// (including UTF-16 and two-phase expansion) can straddle chunk boundaries
/// without missed matches.
struct FileReader {
    file_id: FileId,
    file: File,
    offset: u64,
}

impl FileReader {
    fn new(file_id: FileId, file: File) -> Self {
        Self {
            file_id,
            file,
            offset: 0,
        }
    }

    fn read_next_chunk(
        &mut self,
        mut handle: crate::BufferHandle,
        chunk_size: usize,
        overlap: usize,
        tail: &mut [u8],
        tail_len: &mut usize,
    ) -> io::Result<Option<Chunk>> {
        let buf = handle.as_mut_slice();
        debug_assert!(buf.len() >= *tail_len + chunk_size);

        if *tail_len > 0 {
            buf[..*tail_len].copy_from_slice(&tail[..*tail_len]);
        }

        let read = self
            .file
            .read(&mut buf[*tail_len..*tail_len + chunk_size])?;
        if read == 0 {
            return Ok(None);
        }

        let total_len = *tail_len + read;
        let next_tail_len = overlap.min(total_len);
        let start = total_len - next_tail_len;
        tail[..next_tail_len].copy_from_slice(&buf[start..total_len]);

        let base_offset = self.offset.saturating_sub(*tail_len as u64);
        let chunk = Chunk {
            file_id: self.file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: *tail_len as u32,
            buf: handle,
        };

        *tail_len = next_tail_len;
        self.offset = self.offset.saturating_add(read as u64);

        Ok(Some(chunk))
    }
}

/// Stage that turns file ids into buffered chunks.
struct ReaderStage {
    overlap: usize,
    chunk_size: usize,
    active: Option<FileReader>,
    tail: Vec<u8>,
    tail_len: usize,
}

impl ReaderStage {
    fn new(overlap: usize, chunk_size: usize) -> Self {
        Self {
            overlap,
            chunk_size,
            active: None,
            tail: vec![0u8; overlap],
            tail_len: 0,
        }
    }

    fn is_idle(&self) -> bool {
        self.active.is_none()
    }

    fn pump<const FILE_CAP: usize, const CHUNK_CAP: usize>(
        &mut self,
        file_ring: &mut SpscRing<FileId, FILE_CAP>,
        chunk_ring: &mut SpscRing<Chunk, CHUNK_CAP>,
        pool: &BufferPool,
        files: &FileTable,
        stats: &mut PipelineStats,
    ) -> io::Result<bool> {
        let mut progressed = false;

        while !chunk_ring.is_full() {
            let handle = match pool.try_acquire() {
                Some(handle) => handle,
                None => break,
            };

            if self.active.is_none() {
                let file_id = match file_ring.pop() {
                    Some(id) => id,
                    None => break,
                };

                self.tail_len = 0;
                let path = files.path(file_id);
                let file = match File::open(path) {
                    Ok(file) => file,
                    Err(_) => {
                        stats.open_errors += 1;
                        stats.errors += 1;
                        continue;
                    }
                };

                self.active = Some(FileReader::new(file_id, file));
                progressed = true;
            }

            let reader = self.active.as_mut().expect("reader active");
            match reader.read_next_chunk(
                handle,
                self.chunk_size,
                self.overlap,
                &mut self.tail,
                &mut self.tail_len,
            )? {
                Some(chunk) => {
                    let new_bytes = u64::from(chunk.len.saturating_sub(chunk.prefix_len));
                    stats.bytes_scanned = stats.bytes_scanned.saturating_add(new_bytes);
                    chunk_ring.push_assume_capacity(chunk);
                    stats.chunks += 1;
                    progressed = true;
                }
                None => {
                    self.active = None;
                    self.tail_len = 0;
                }
            }
        }

        Ok(progressed)
    }
}

/// Stage that scans chunks and buffers findings for output.
struct ScanStage {
    scratch: ScanScratch,
    pending: Vec<FindingRec>,
    pending_idx: usize,
}

impl ScanStage {
    fn new(engine: &Engine) -> Self {
        Self {
            scratch: engine.new_scratch(),
            pending: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            pending_idx: 0,
        }
    }

    fn has_pending(&self) -> bool {
        self.pending_idx < self.pending.len()
    }

    fn flush_pending<const OUT_CAP: usize>(
        &mut self,
        out_ring: &mut SpscRing<FindingRec, OUT_CAP>,
    ) -> bool {
        let mut progressed = false;

        while self.pending_idx < self.pending.len() {
            if out_ring.push(self.pending[self.pending_idx]).is_err() {
                break;
            }
            self.pending_idx += 1;
            progressed = true;
        }

        if self.pending_idx >= self.pending.len() {
            self.pending.clear();
            self.pending_idx = 0;
        }

        progressed
    }

    fn pump<const CHUNK_CAP: usize, const OUT_CAP: usize>(
        &mut self,
        engine: &Engine,
        chunk_ring: &mut SpscRing<Chunk, CHUNK_CAP>,
        out_ring: &mut SpscRing<FindingRec, OUT_CAP>,
        stats: &mut PipelineStats,
    ) -> bool {
        let mut progressed = false;

        if self.has_pending() {
            // Backpressure: if output is full, we keep draining pending findings
            // before scanning another chunk. This prevents unbounded buffering.
            return self.flush_pending(out_ring);
        }

        let chunk = match chunk_ring.pop() {
            Some(chunk) => chunk,
            None => return progressed,
        };

        engine.scan_chunk_into(
            chunk.data(),
            chunk.file_id,
            chunk.base_offset,
            &mut self.scratch,
        );
        let new_bytes_start = chunk.base_offset + chunk.prefix_len as u64;
        self.scratch.drop_prefix_findings(new_bytes_start);
        #[cfg(feature = "b64-stats")]
        stats.base64.add(&self.scratch.base64_stats());
        self.scratch.drain_findings_into(&mut self.pending);
        progressed = true;

        progressed |= self.flush_pending(out_ring);

        progressed
    }
}

/// Stage that formats findings to stdout.
struct OutputStage {
    out: BufWriter<io::Stdout>,
}

impl OutputStage {
    fn new() -> Self {
        Self {
            out: BufWriter::new(io::stdout()),
        }
    }

    fn pump<const OUT_CAP: usize>(
        &mut self,
        engine: &Engine,
        files: &FileTable,
        out_ring: &mut SpscRing<FindingRec, OUT_CAP>,
        stats: &mut PipelineStats,
    ) -> io::Result<bool> {
        let mut progressed = false;

        while let Some(rec) = out_ring.pop() {
            let path = files.path(rec.file_id);
            let rule = engine.rule_name(rec.rule_id);
            writeln!(
                self.out,
                "{}:{}-{} {}",
                path.display(),
                rec.root_hint_start,
                rec.root_hint_end,
                rule
            )?;
            stats.findings += 1;
            progressed = true;
        }

        Ok(progressed)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Pipeline scanner with fixed ring capacities for files, chunks, and findings.
pub struct Pipeline<const FILE_CAP: usize, const CHUNK_CAP: usize, const OUT_CAP: usize> {
    engine: Arc<Engine>,
    config: PipelineConfig,
    overlap: usize,
    pool: BufferPool,
}

impl<const FILE_CAP: usize, const CHUNK_CAP: usize, const OUT_CAP: usize>
    Pipeline<FILE_CAP, CHUNK_CAP, OUT_CAP>
{
    fn max_aligned_chunk_size(overlap: usize) -> usize {
        let max_chunk = BUFFER_LEN_MAX.saturating_sub(overlap);
        max_chunk & !(BUFFER_ALIGN - 1)
    }

    /// Creates a pipeline with a fixed-capacity buffer pool and overlap settings.
    pub fn new(engine: Arc<Engine>, config: PipelineConfig) -> Self {
        let overlap = engine.required_overlap();
        let mut config = config;
        if config.chunk_size == 0 {
            let max_chunk = Self::max_aligned_chunk_size(overlap);
            assert!(max_chunk > 0, "overlap exceeds buffer size");
            config.chunk_size = max_chunk;
        }

        let buf_len = overlap.saturating_add(config.chunk_size);
        assert!(buf_len <= BUFFER_LEN_MAX);

        let pool = BufferPool::new(PIPE_POOL_CAP);
        Self {
            engine,
            config,
            overlap,
            pool,
        }
    }

    /// Scans a path (file or directory) and returns summary stats.
    pub fn scan_path(&self, path: &Path) -> io::Result<PipelineStats> {
        let mut stats = PipelineStats::default();

        let mut files = FileTable::with_capacity(self.config.max_files);
        let mut file_ring: SpscRing<FileId, FILE_CAP> = SpscRing::new();
        let mut chunk_ring: SpscRing<Chunk, CHUNK_CAP> = SpscRing::new();
        let mut out_ring: SpscRing<FindingRec, OUT_CAP> = SpscRing::new();

        let mut walker = Walker::new(path.to_path_buf(), self.config.max_files);
        let mut reader = ReaderStage::new(self.overlap, self.config.chunk_size);
        let mut scanner = ScanStage::new(&self.engine);
        let mut output = OutputStage::new();

        loop {
            let mut progressed = false;

            progressed |= output.pump(&self.engine, &files, &mut out_ring, &mut stats)?;
            progressed |= scanner.pump(&self.engine, &mut chunk_ring, &mut out_ring, &mut stats);
            progressed |= reader.pump(
                &mut file_ring,
                &mut chunk_ring,
                &self.pool,
                &files,
                &mut stats,
            )?;
            progressed |= walker.pump(&mut files, &mut file_ring, &mut stats)?;

            let done = walker.is_done()
                && reader.is_idle()
                && file_ring.is_empty()
                && chunk_ring.is_empty()
                && !scanner.has_pending()
                && out_ring.is_empty();

            if done {
                break;
            }

            if !progressed {
                // No stage made progress and we're not done: this indicates a
                // logic bug (e.g., a ring is full/empty deadlock). Fail fast so
                // it is visible rather than silently spinning.
                return Err(io::Error::other("pipeline stalled"));
            }
        }

        output.flush()?;
        Ok(stats)
    }
}

/// Convenience wrapper using pipeline defaults and fixed ring capacities.
pub fn scan_path_default(path: &Path, engine: Arc<Engine>) -> io::Result<PipelineStats> {
    let pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
        Pipeline::new(engine, PipelineConfig::default());
    pipeline.scan_path(path)
}

fn dev_inode(meta: &std::fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn make_temp_dir(prefix: &str) -> io::Result<TempDir> {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("{}_{}_{}", prefix, std::process::id(), stamp));
        fs::create_dir(&path)?;
        Ok(TempDir { path })
    }

    #[cfg(unix)]
    struct RestorePerm {
        path: PathBuf,
        mode: u32,
    }

    #[cfg(unix)]
    impl RestorePerm {
        fn new(path: PathBuf, restore_mode: u32) -> io::Result<Self> {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000))?;
            Ok(Self {
                path,
                mode: restore_mode,
            })
        }
    }

    #[cfg(unix)]
    impl Drop for RestorePerm {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
        }
    }

    #[test]
    #[cfg(unix)]
    fn pipeline_counts_walk_and_open_errors() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_walk_err")?;
        let denied = tmp.path().join("denied");
        fs::create_dir(&denied)?;

        let unreadable = tmp.path().join("no_read.txt");
        fs::write(&unreadable, b"secret")?;

        let _deny_guard = RestorePerm::new(denied, 0o700)?;
        let _file_guard = RestorePerm::new(unreadable, 0o600)?;

        let engine = Arc::new(crate::demo_engine());
        let pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(engine, PipelineConfig::default());

        let stats = pipeline.scan_path(tmp.path())?;

        assert!(stats.walk_errors > 0);
        assert!(stats.open_errors > 0);
        assert!(stats.errors >= stats.walk_errors + stats.open_errors);

        Ok(())
    }
}
