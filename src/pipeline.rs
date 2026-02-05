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
//!
//! # Archive scanning
//! - When enabled, archive detection runs in the reader stage (extension first,
//!   then magic sniff) and scanning is performed via streaming decoders.
//! - Archive findings bypass the chunk ring and are emitted directly to output,
//!   while archive outcomes are recorded in `PipelineStats`.
//!
//! # Candidate-only lexical pass
//! - When `PipelineConfig.context_mode != Off`, findings are buffered per file.
//! - A second pass tokenizes the file to apply lexical context rules, failing
//!   open on unknown language, size changes, or tokenization errors.
//!
//! # Invariants and budgets
//! - Rings are fixed-capacity; every stage must tolerate backpressure.
//! - Chunk overlap is set to `Engine::required_overlap()` to avoid missed
//!   matches across chunk boundaries.
//! - On Unix, path storage is a fixed-size arena; exceeding it is a hard error.
//! - The pipeline is single-threaded and not Sync/Send by design.

use crate::archive::formats::tar::TAR_BLOCK_LEN;
use crate::archive::scan::{
    scan_gzip_stream, scan_tar_stream, scan_targz_stream, scan_zip_source, ArchiveEnd,
    ArchiveEntrySink, ArchiveScratch as ArchiveCoreScratch, EntryChunk, EntryMeta,
};
use crate::archive::{
    detect_kind_from_path, sniff_kind_from_header, ArchiveConfig, ArchiveKind, ArchiveSkipReason,
    ArchiveStats,
};
use crate::git_scan::path_policy::lexical_family_for_path;
use crate::lexical::{LexRuns, DEFAULT_LEX_RUN_CAP};
#[cfg(unix)]
use crate::runtime::PathSpan;
use crate::scheduler::lexical_pass::{apply_lexical_context, tokenize_for_lexical};
#[cfg(unix)]
use crate::scratch_memory::ScratchVec;
use crate::stdx::RingBuffer;
use crate::{
    BufferPool, Chunk, ContextMode, Engine, FileId, FileTable, FindingRec, ScanScratch,
    BUFFER_ALIGN, BUFFER_LEN_MAX,
};
#[cfg(not(unix))]
use std::fs;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::ffi::CStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::io::RawFd;

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
/// Target aggregate bytes for the pipeline buffer pool.
///
/// Pool capacity is derived from this budget and `BUFFER_LEN_MAX`, so larger
/// buffers automatically reduce the number of pooled slots.
pub const PIPE_POOL_TARGET_BYTES: usize = 256 * 1024 * 1024;
/// Minimum buffer pool capacity for the pipeline.
pub const PIPE_POOL_MIN: usize = 16;

fn default_pool_capacity() -> usize {
    let mut cap = PIPE_POOL_TARGET_BYTES / BUFFER_LEN_MAX;
    if cap == 0 {
        cap = 1;
    }
    cap = cap.min(PIPE_CHUNK_RING_CAP + 8);
    cap.max(PIPE_POOL_MIN)
}

/// Default maximum number of files to scan.
///
/// This bounds the `FileTable` allocation. Increase for very large scans;
/// decrease if memory is constrained.
pub const PIPE_MAX_FILES: usize = 100_000;
/// Default per-file path byte budget for the pipeline.
pub const PIPE_PATH_BYTES_PER_FILE: usize = 256;

/// Maximum depth for the DFS walker stack.
///
/// Filesystem paths are bounded by depth (~255 components on most systems),
/// NOT by file count. 1024 handles any realistic directory tree.
const WALKER_STACK_CAP: usize = 1024;

/// Configuration for the high-level pipeline scanner.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Bytes read per chunk (excluding overlap). Use 0 for the maximum size.
    ///
    /// A value of 0 is resolved to the largest aligned chunk that fits within
    /// `BUFFER_LEN_MAX` after accounting for overlap.
    pub chunk_size: usize,
    /// Maximum number of files to queue.
    pub max_files: usize,
    /// Total byte capacity reserved for path storage (0 = auto).
    ///
    /// On Unix this is the fixed-size path arena budget; on non-Unix it is
    /// ignored. Exceeding the arena is treated as a configuration bug and will
    /// fail fast rather than allocate.
    pub path_bytes_cap: usize,
    /// Context mode for candidate-only lexical filtering.
    pub context_mode: ContextMode,
    /// Archive scanning configuration.
    pub archive: ArchiveConfig,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let max_files = PIPE_MAX_FILES;
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_files,
            path_bytes_cap: max_files.saturating_mul(PIPE_PATH_BYTES_PER_FILE),
            context_mode: ContextMode::Off,
            archive: ArchiveConfig::default(),
        }
    }
}

/// Summary counters for a pipeline run.
///
/// These counters are always compiled in for lightweight performance and health
/// reporting (throughput, error rates) and are monotonic within a run.
/// `errors` is an aggregate that includes `walk_errors` and `open_errors`.
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
    /// Optional Base64 decode/gate instrumentation (feature: `b64-stats`).
    #[cfg(feature = "b64-stats")]
    pub base64: crate::Base64DecodeStats,
    /// Archive scanning outcomes (when enabled).
    pub archive: ArchiveStats,
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

    fn clear(&mut self) {
        while self.pop().is_some() {}
    }
}

/// Scanner work item: either a data chunk or an end-of-file marker.
enum ScanItem {
    Chunk(Chunk),
    FileDone(FileId),
}

#[cfg(not(unix))]
enum WalkEntry {
    Path(PathBuf),
    Dir(fs::ReadDir),
}

/// Depth-first directory walker that feeds the file ring.
///
/// DFS keeps memory proportional to directory depth rather than total file count,
/// and it naturally yields paths in a locality-friendly order for disk reads.
#[cfg(not(unix))]
struct Walker {
    stack: Vec<WalkEntry>,
    done: bool,
    max_files: usize,
}

#[cfg(not(unix))]
impl Walker {
    fn new(max_files: usize) -> Self {
        Self {
            stack: Vec::with_capacity(WALKER_STACK_CAP),
            done: true,
            max_files,
        }
    }

    fn abort(&mut self) {
        self.stack.clear();
        self.done = true;
    }

    fn reset(
        &mut self,
        root: &Path,
        _files: &mut FileTable,
        _stats: &mut PipelineStats,
    ) -> io::Result<()> {
        self.stack.clear();
        self.stack.push(WalkEntry::Path(root.to_path_buf()));
        self.done = false;
        Ok(())
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

#[cfg(unix)]
struct DirState {
    /// DIR* opened via fdopendir; closed in Drop.
    dirp: *mut libc::DIR,
    /// Raw fd backing `dirp`, used for openat/fstatat.
    fd: RawFd,
    /// Path span for this directory in the file table arena.
    path: PathSpan,
}

#[cfg(unix)]
impl Drop for DirState {
    fn drop(&mut self) {
        // SAFETY: `dirp` is owned by this `DirState` and was created by
        // `fdopendir`. It is closed exactly once here.
        unsafe {
            libc::closedir(self.dirp);
        }
    }
}

/// Depth-first directory walker that feeds the file ring (Unix, allocation-free).
///
/// Uses a fixed-capacity stack and a path arena in the `FileTable` to avoid
/// per-entry allocations.
#[cfg(unix)]
struct Walker {
    stack: ScratchVec<DirState>,
    done: bool,
    max_files: usize,
    // Root file staged until the file ring has capacity.
    pending: Option<FileId>,
}

#[cfg(unix)]
impl Walker {
    fn new(max_files: usize) -> Self {
        let stack = ScratchVec::with_capacity(WALKER_STACK_CAP)
            .expect("pipeline walker stack allocation failed");
        Self {
            stack,
            done: true,
            max_files,
            pending: None,
        }
    }

    fn abort(&mut self) {
        self.stack.clear();
        self.pending = None;
        self.done = true;
    }

    fn reset(
        &mut self,
        root: &Path,
        files: &mut FileTable,
        stats: &mut PipelineStats,
    ) -> io::Result<()> {
        self.stack.clear();
        self.pending = None;
        self.done = false;

        let root_bytes = root.as_os_str().as_bytes();
        if root_bytes.is_empty() {
            self.done = true;
            return Ok(());
        }

        let root_span = files.alloc_path_span(root_bytes);
        let st = with_c_path(root, |c_path| {
            // SAFETY: `c_path` is a NUL-terminated buffer valid for this call.
            unsafe {
                let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::lstat(c_path, st.as_mut_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(st.assume_init())
            }
        })?;

        let mode = st.st_mode & libc::S_IFMT;
        if mode == libc::S_IFLNK {
            self.done = true;
            return Ok(());
        }

        if mode == libc::S_IFDIR {
            let dir_state = with_c_path(root, |c_path| open_dir(c_path, root_span))?;
            self.stack.push(dir_state);
            return Ok(());
        }

        if mode == libc::S_IFREG {
            if files.len() >= self.max_files {
                self.done = true;
                return Ok(());
            }
            let id = files.push_span(root_span, st.st_size as u64, dev_inode_from_stat(&st), 0);
            stats.files += 1;
            self.pending = Some(id);
            return Ok(());
        }

        self.done = true;
        Ok(())
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

        if let Some(id) = self.pending {
            if file_ring.is_full() {
                return Ok(progressed);
            }
            self.pending = None;
            file_ring.push_assume_capacity(id);
            progressed = true;
        }

        while !file_ring.is_full() {
            let Some(top) = self.stack.len().checked_sub(1) else {
                self.done = true;
                break;
            };

            let (dirp, dirfd, dir_path) = {
                let entry = self.stack.get(top).expect("walker stack entry");
                (entry.dirp, entry.fd, entry.path)
            };

            // SAFETY: `dirp` is a live DIR* created by `fdopendir`. We call
            // `readdir` serially on this thread, and consume the returned
            // `dirent` immediately before the next `readdir` call.
            unsafe {
                set_errno(0);
                let ent = libc::readdir(dirp);
                if ent.is_null() {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error().unwrap_or(0) != 0 {
                        stats.walk_errors += 1;
                        stats.errors += 1;
                    }
                    self.stack.pop();
                    continue;
                }

                let name = CStr::from_ptr((*ent).d_name.as_ptr());
                let name_bytes = name.to_bytes();
                if is_dot_or_dotdot(name_bytes) {
                    continue;
                }

                let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::fstatat(
                    dirfd,
                    name.as_ptr(),
                    st.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                ) != 0
                {
                    stats.walk_errors += 1;
                    stats.errors += 1;
                    continue;
                }
                let st = st.assume_init();
                let mode = st.st_mode & libc::S_IFMT;
                if mode == libc::S_IFLNK {
                    continue;
                }

                if mode == libc::S_IFDIR {
                    let child_span = files.join_path_span(dir_path, name_bytes);
                    let child = open_dir_at(dirfd, name.as_ptr(), child_span);
                    if let Ok(child) = child {
                        self.stack.push(child);
                    } else {
                        stats.walk_errors += 1;
                        stats.errors += 1;
                    }
                    continue;
                }

                if mode != libc::S_IFREG {
                    continue;
                }

                if files.len() >= self.max_files {
                    self.done = true;
                    break;
                }

                let file_span = files.join_path_span(dir_path, name_bytes);
                let id = files.push_span(file_span, st.st_size as u64, dev_inode_from_stat(&st), 0);
                file_ring.push_assume_capacity(id);
                stats.files += 1;
                progressed = true;
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
        // `tail`/`tail_len` preserve the suffix of the previous chunk so the
        // resulting buffer is `[overlap bytes][new bytes]`.
        debug_assert!(*tail_len <= tail.len());
        debug_assert!(overlap == tail.len());
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

        // `base_offset` points to the logical start of the chunk including overlap.
        let base_offset = self.offset.saturating_sub(*tail_len as u64);
        let chunk = Chunk {
            file_id: self.file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: *tail_len as u32,
            buf: handle,
            buf_offset: 0,
        };

        *tail_len = next_tail_len;
        self.offset = self.offset.saturating_add(read as u64);

        Ok(Some(chunk))
    }
}

/// Reusable scratch state for archive scanning inside the pipeline.
///
/// # Invariants
/// - All buffers are preallocated and reused; per-entry allocations are avoided.
/// - `next_virtual_file_id` stays in the high-bit namespace to avoid collisions
///   with real file ids.
struct ArchiveScratch {
    core: ArchiveCoreScratch<File>,
    scan_scratch: ScanScratch,
    pending: Vec<FindingRec>,
    entry_path_buf: Vec<u8>,
    /// Monotonic virtual `FileId` generator for archive entries.
    next_virtual_file_id: u32,
}

impl ArchiveScratch {
    fn new(engine: &Engine, archive: &ArchiveConfig, chunk_size: usize) -> Self {
        let overlap = engine.required_overlap();
        let entry_path_cap = archive.max_virtual_path_len_per_entry;

        Self {
            core: ArchiveCoreScratch::new(archive, chunk_size, overlap),
            scan_scratch: engine.new_scratch(),
            pending: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            entry_path_buf: Vec::with_capacity(entry_path_cap),
            next_virtual_file_id: 0x8000_0000,
        }
    }
}

/// Allocate a virtual `FileId` for archive entries (high-bit namespace).
///
/// Wraps within the high-bit range; after ~2^31 entries, ids may repeat.
#[inline]
fn alloc_virtual_file_id(next_virtual_file_id: &mut u32) -> FileId {
    const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
    const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

    let id = *next_virtual_file_id;
    let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
    *next_virtual_file_id = next;
    FileId(id)
}

struct PipelineArchiveSink<'a> {
    engine: &'a Engine,
    output: &'a mut OutputStage,
    findings: &'a mut u64,
    chunks: &'a mut u64,
    bytes_scanned: &'a mut u64,
    scan_scratch: &'a mut ScanScratch,
    pending: &'a mut Vec<FindingRec>,
    entry_path_buf: &'a mut Vec<u8>,
    next_virtual_file_id: &'a mut u32,
    current_file_id: Option<FileId>,
}

impl<'a> PipelineArchiveSink<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        engine: &'a Engine,
        output: &'a mut OutputStage,
        findings: &'a mut u64,
        chunks: &'a mut u64,
        bytes_scanned: &'a mut u64,
        scan_scratch: &'a mut ScanScratch,
        pending: &'a mut Vec<FindingRec>,
        entry_path_buf: &'a mut Vec<u8>,
        next_virtual_file_id: &'a mut u32,
    ) -> Self {
        Self {
            engine,
            output,
            findings,
            chunks,
            bytes_scanned,
            scan_scratch,
            pending,
            entry_path_buf,
            next_virtual_file_id,
            current_file_id: None,
        }
    }
}

impl ArchiveEntrySink for PipelineArchiveSink<'_> {
    type Error = io::Error;

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        let file_id = alloc_virtual_file_id(self.next_virtual_file_id);
        self.current_file_id = Some(file_id);

        debug_assert!(
            self.entry_path_buf.capacity() >= meta.display_path.len(),
            "entry path buffer too small for display path"
        );
        self.entry_path_buf.clear();
        self.entry_path_buf.extend_from_slice(meta.display_path);
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        let file_id = self
            .current_file_id
            .expect("archive entry chunk before start");

        self.engine
            .scan_chunk_into(chunk.data, file_id, chunk.base_offset, self.scan_scratch);
        self.scan_scratch
            .drop_prefix_findings(chunk.new_bytes_start);

        self.pending.clear();
        self.scan_scratch.drain_findings_into(self.pending);

        self.output.emit_findings_direct(
            self.engine,
            self.entry_path_buf.as_slice(),
            self.pending,
            self.findings,
        )?;

        *self.chunks = self.chunks.saturating_add(1);
        *self.bytes_scanned = self
            .bytes_scanned
            .saturating_add(chunk.new_bytes_len as u64);
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        self.current_file_id = None;
        Ok(())
    }
}

fn scan_gzip_file(
    path: &Path,
    _file_id: FileId,
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
) -> io::Result<ArchiveEnd> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let ArchiveScratch {
        core,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    } = scratch;
    let stats_archive = &mut stats.archive;
    let stats_findings = &mut stats.findings;
    let stats_chunks = &mut stats.chunks;
    let stats_bytes_scanned = &mut stats.bytes_scanned;
    let mut sink = PipelineArchiveSink::new(
        engine,
        output,
        stats_findings,
        stats_chunks,
        stats_bytes_scanned,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    );
    scan_gzip_stream(file, parent_bytes, archive, core, &mut sink, stats_archive)
}

fn scan_tar_file(
    path: &Path,
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
) -> io::Result<ArchiveEnd> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let ArchiveScratch {
        core,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    } = scratch;
    let stats_archive = &mut stats.archive;
    let stats_findings = &mut stats.findings;
    let stats_chunks = &mut stats.chunks;
    let stats_bytes_scanned = &mut stats.bytes_scanned;
    let mut sink = PipelineArchiveSink::new(
        engine,
        output,
        stats_findings,
        stats_chunks,
        stats_bytes_scanned,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    );
    scan_tar_stream(
        &mut file,
        parent_bytes,
        archive,
        core,
        &mut sink,
        stats_archive,
        false,
    )
}

/// Process a `.tar.gz` file via gzip+tar streaming.
fn scan_targz_file(
    path: &Path,
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
) -> io::Result<ArchiveEnd> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let ArchiveScratch {
        core,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    } = scratch;
    let stats_archive = &mut stats.archive;
    let stats_findings = &mut stats.findings;
    let stats_chunks = &mut stats.chunks;
    let stats_bytes_scanned = &mut stats.bytes_scanned;
    let mut sink = PipelineArchiveSink::new(
        engine,
        output,
        stats_findings,
        stats_chunks,
        stats_bytes_scanned,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    );
    scan_targz_stream(file, parent_bytes, archive, core, &mut sink, stats_archive)
}

/// Scan a ZIP file using file-backed random access.
///
/// # Design Notes
/// - Central directory parsing is bounded by metadata budgets.
/// - Only stored/deflated entries are scanned; others are skipped explicitly.
fn scan_zip_file(
    path: &Path,
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
) -> io::Result<ArchiveEnd> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let ArchiveScratch {
        core,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    } = scratch;
    let stats_archive = &mut stats.archive;
    let stats_findings = &mut stats.findings;
    let stats_chunks = &mut stats.chunks;
    let stats_bytes_scanned = &mut stats.bytes_scanned;
    let mut sink = PipelineArchiveSink::new(
        engine,
        output,
        stats_findings,
        stats_chunks,
        stats_bytes_scanned,
        scan_scratch,
        pending,
        entry_path_buf,
        next_virtual_file_id,
    );
    scan_zip_source(file, parent_bytes, archive, core, &mut sink, stats_archive)
}

/// Stage that turns file ids into buffered chunks.
///
/// Maintains a single active reader and a fixed overlap tail to keep IO
/// sequential and memory bounded.
///
/// When archive scanning is enabled, this stage detects archive containers and
/// routes them through the archive dispatch entrypoint instead of emitting
/// chunks.
struct ReaderStage {
    overlap: usize,
    chunk_size: usize,
    active: Option<FileReader>,
    pending_done: Option<FileId>,
    tail: Vec<u8>,
    tail_len: usize,
}

/// Dispatch archive scanning by kind.
///
/// Currently gzip/tar/tar.gz are supported; other formats are skipped.
///
/// The caller is responsible for recording archive stats based on the result.
#[allow(clippy::too_many_arguments)]
fn dispatch_archive_scan(
    path: &Path,
    file_id: FileId,
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
    kind: ArchiveKind,
) -> io::Result<ArchiveEnd> {
    match kind {
        ArchiveKind::Gzip => scan_gzip_file(path, file_id, engine, archive, scratch, output, stats),
        ArchiveKind::Tar => scan_tar_file(path, engine, archive, scratch, output, stats),
        ArchiveKind::TarGz => scan_targz_file(path, engine, archive, scratch, output, stats),
        ArchiveKind::Zip => scan_zip_file(path, engine, archive, scratch, output, stats),
    }
}

impl ReaderStage {
    fn new(overlap: usize, chunk_size: usize) -> Self {
        Self {
            overlap,
            chunk_size,
            active: None,
            pending_done: None,
            tail: vec![0u8; overlap],
            tail_len: 0,
        }
    }

    fn reset(&mut self) {
        self.active = None;
        self.pending_done = None;
        self.tail_len = 0;
    }

    fn is_idle(&self) -> bool {
        self.active.is_none() && self.pending_done.is_none()
    }

    fn is_waiting(&self) -> bool {
        // Sync reader never has in-flight IO. Async backends can override this
        // to signal "waiting on completion" without tripping the stall detector.
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn pump<const FILE_CAP: usize, const CHUNK_CAP: usize>(
        &mut self,
        file_ring: &mut SpscRing<FileId, FILE_CAP>,
        chunk_ring: &mut SpscRing<ScanItem, CHUNK_CAP>,
        pool: &BufferPool,
        files: &FileTable,
        engine: &Engine,
        archive: &ArchiveConfig,
        archive_scratch: &mut ArchiveScratch,
        output: &mut OutputStage,
        stats: &mut PipelineStats,
    ) -> io::Result<bool> {
        let mut progressed = false;

        if archive_scratch.core.abort_run() {
            self.active = None;
            self.tail_len = 0;
            return Ok(progressed);
        }

        while !chunk_ring.is_full() {
            if let Some(done_id) = self.pending_done {
                if chunk_ring.push(ScanItem::FileDone(done_id)).is_err() {
                    break;
                }
                self.pending_done = None;
                progressed = true;
                continue;
            }

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
                let path_bytes = path.as_os_str().as_encoded_bytes();
                let ext_kind = if archive.enabled {
                    detect_kind_from_path(path)
                } else {
                    None
                };
                if let Some(kind) = ext_kind {
                    stats.archive.record_archive_seen();
                    let outcome = dispatch_archive_scan(
                        path,
                        file_id,
                        engine,
                        archive,
                        archive_scratch,
                        output,
                        stats,
                        kind,
                    )?;
                    match outcome {
                        ArchiveEnd::Scanned => stats.archive.record_archive_scanned(),
                        ArchiveEnd::Skipped(r) => {
                            stats.archive.record_archive_skipped(r, path_bytes, false);
                        }
                        ArchiveEnd::Partial(r) => {
                            stats.archive.record_archive_partial(r, path_bytes, false);
                        }
                    }
                    if archive_scratch.core.abort_run() {
                        return Ok(true);
                    }
                    continue;
                }

                let mut file = match File::open(path) {
                    Ok(file) => file,
                    Err(_) => {
                        stats.open_errors += 1;
                        stats.errors += 1;
                        continue;
                    }
                };

                if archive.enabled {
                    let mut header = [0u8; TAR_BLOCK_LEN];
                    let n = match file.read(&mut header) {
                        Ok(n) => n,
                        Err(_) => {
                            stats.errors += 1;
                            continue;
                        }
                    };
                    if n > 0 {
                        if let Some(kind) = sniff_kind_from_header(&header[..n]) {
                            stats.archive.record_archive_seen();
                            let outcome = dispatch_archive_scan(
                                path,
                                file_id,
                                engine,
                                archive,
                                archive_scratch,
                                output,
                                stats,
                                kind,
                            )?;
                            match outcome {
                                ArchiveEnd::Scanned => stats.archive.record_archive_scanned(),
                                ArchiveEnd::Skipped(r) => {
                                    stats.archive.record_archive_skipped(r, path_bytes, false);
                                }
                                ArchiveEnd::Partial(r) => {
                                    stats.archive.record_archive_partial(r, path_bytes, false);
                                }
                            }
                            if archive_scratch.core.abort_run() {
                                return Ok(true);
                            }
                            continue;
                        }
                    }
                    if file.seek(SeekFrom::Start(0)).is_err() {
                        stats.errors += 1;
                        continue;
                    }
                }

                self.active = Some(FileReader::new(file_id, file));
            }

            let reader = self.active.as_mut().expect("reader active");
            let file_id = reader.file_id;
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
                    chunk_ring.push_assume_capacity(ScanItem::Chunk(chunk));
                    stats.chunks += 1;
                    progressed = true;
                }
                None => {
                    self.active = None;
                    self.tail_len = 0;
                    self.pending_done = Some(file_id);
                    progressed = true;
                }
            }
        }

        Ok(progressed)
    }
}

/// Stage that scans chunks and buffers findings for output.
///
/// When `context_mode` is enabled, findings are buffered per file until a
/// `FileDone` marker arrives, at which point lexical filtering is applied.
struct ScanStage {
    scratch: ScanScratch,
    pending_emit: Vec<FindingRec>,
    pending_idx: usize,
    chunk_buf: Vec<FindingRec>,
    file_findings: Vec<FindingRec>,
    active_file: Option<FileId>,
    lex_runs: LexRuns,
    lex_buf: Vec<u8>,
    context_mode: ContextMode,
}

impl ScanStage {
    fn new(engine: &Engine, context_mode: ContextMode, lex_buf_len: usize) -> Self {
        Self {
            scratch: engine.new_scratch(),
            pending_emit: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            pending_idx: 0,
            chunk_buf: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            file_findings: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            active_file: None,
            lex_runs: LexRuns::with_capacity(DEFAULT_LEX_RUN_CAP)
                .expect("lexical run buffer allocation failed"),
            lex_buf: vec![0u8; lex_buf_len],
            context_mode,
        }
    }

    fn reset(&mut self) {
        self.pending_emit.clear();
        self.pending_idx = 0;
        self.chunk_buf.clear();
        self.file_findings.clear();
        self.active_file = None;
    }

    fn has_pending_emit(&self) -> bool {
        self.pending_idx < self.pending_emit.len()
    }

    fn has_buffered_file(&self) -> bool {
        self.active_file.is_some() || !self.file_findings.is_empty()
    }

    fn has_pending(&self) -> bool {
        self.has_pending_emit() || self.has_buffered_file()
    }

    fn flush_pending<const OUT_CAP: usize>(
        &mut self,
        out_ring: &mut SpscRing<FindingRec, OUT_CAP>,
    ) -> bool {
        let mut progressed = false;

        while self.pending_idx < self.pending_emit.len() {
            if out_ring.push(self.pending_emit[self.pending_idx]).is_err() {
                break;
            }
            self.pending_idx += 1;
            progressed = true;
        }

        if self.pending_idx >= self.pending_emit.len() {
            self.pending_emit.clear();
            self.pending_idx = 0;
        }

        progressed
    }

    fn finalize_file(&mut self, engine: &Engine, files: &FileTable, file_id: FileId) -> bool {
        if self.active_file.is_some() && self.active_file != Some(file_id) {
            debug_assert!(false, "file ordering violated in pipeline scan ring");
        }
        self.active_file = None;

        if self.file_findings.is_empty() {
            return false;
        }

        if self.context_mode != ContextMode::Off {
            let mut needs_lexical = false;
            for rec in &self.file_findings {
                if engine.rule_lexical_context(rec.rule_id).is_some() {
                    needs_lexical = true;
                    break;
                }
            }

            if needs_lexical {
                let path = files.path(file_id);
                #[cfg(unix)]
                let family = lexical_family_for_path(path.as_os_str().as_bytes());
                #[cfg(not(unix))]
                let family = {
                    let path = path.to_string_lossy();
                    lexical_family_for_path(path.as_bytes())
                };

                if let Some(family) = family {
                    if let Ok(mut file) = File::open(path) {
                        if let Ok(meta) = file.metadata() {
                            // Only apply lexical filtering if the file still
                            // matches the size we scanned (stable offsets).
                            let file_size = files.size(file_id);
                            if meta.len() == file_size
                                && tokenize_for_lexical(
                                    &mut file,
                                    file_size,
                                    family,
                                    &mut self.lex_buf,
                                    &mut self.lex_runs,
                                )
                                .is_ok()
                            {
                                apply_lexical_context(
                                    engine,
                                    &mut self.file_findings,
                                    &self.lex_runs,
                                    file_size,
                                    self.context_mode,
                                );
                            }
                        }
                    }
                }
            }
        }

        if !self.file_findings.is_empty() {
            self.pending_emit.append(&mut self.file_findings);
            return true;
        }

        false
    }

    fn pump<const CHUNK_CAP: usize, const OUT_CAP: usize>(
        &mut self,
        engine: &Engine,
        files: &FileTable,
        chunk_ring: &mut SpscRing<ScanItem, CHUNK_CAP>,
        out_ring: &mut SpscRing<FindingRec, OUT_CAP>,
        stats: &mut PipelineStats,
    ) -> bool {
        #[cfg(not(feature = "b64-stats"))]
        let _ = stats;
        let mut progressed = false;

        if self.has_pending_emit() {
            // Backpressure: if output is full, we keep draining pending findings
            // before scanning another chunk. This prevents unbounded buffering.
            return self.flush_pending(out_ring);
        }

        let item = match chunk_ring.pop() {
            Some(item) => item,
            None => return progressed,
        };

        match item {
            ScanItem::Chunk(chunk) => {
                if self.context_mode != ContextMode::Off {
                    if let Some(active) = self.active_file {
                        debug_assert!(
                            active == chunk.file_id,
                            "pipeline scan ring interleaved file ids"
                        );
                    } else {
                        self.active_file = Some(chunk.file_id);
                    }
                }

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
                self.chunk_buf.clear();
                self.scratch.drain_findings_into(&mut self.chunk_buf);

                if self.context_mode == ContextMode::Off {
                    if !self.chunk_buf.is_empty() {
                        self.pending_emit.append(&mut self.chunk_buf);
                    }
                    progressed = true;
                    progressed |= self.flush_pending(out_ring);
                } else if !self.chunk_buf.is_empty() {
                    self.file_findings.append(&mut self.chunk_buf);
                    progressed = true;
                } else {
                    progressed = true;
                }
            }
            ScanItem::FileDone(file_id) => {
                if self.context_mode != ContextMode::Off {
                    progressed |= self.finalize_file(engine, files, file_id);
                    progressed |= self.flush_pending(out_ring);
                } else {
                    progressed = true;
                }
            }
        }

        progressed
    }
}

/// Writes a path to the output stream.
///
/// On Unix we write raw bytes to avoid UTF-8 validation and allocation; output
/// may not be valid UTF-8 for unusual paths.
fn write_path<W: Write>(out: &mut W, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        out.write_all(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        write!(out, "{}", path.display())
    }
}

#[inline]
fn write_path_bytes<W: Write>(out: &mut W, bytes: &[u8]) -> io::Result<()> {
    out.write_all(bytes)
}

/// Stage that formats findings to stdout.
///
/// Output format: `path:start-end rule` (one finding per line).
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
            write_path(&mut self.out, path)?;
            write!(
                self.out,
                ":{}-{} {}",
                rec.root_hint_start, rec.root_hint_end, rule
            )?;
            self.out.write_all(b"\n")?;
            stats.findings += 1;
            progressed = true;
        }

        Ok(progressed)
    }

    /// Emit findings for an already-canonicalized display path.
    ///
    /// Used by archive scanning to bypass `FileTable` lookups; `display_path`
    /// is treated as a pre-bounded byte slice (not necessarily UTF-8).
    fn emit_findings_direct(
        &mut self,
        engine: &Engine,
        display_path: &[u8],
        findings: &[FindingRec],
        findings_count: &mut u64,
    ) -> io::Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        for rec in findings {
            let rule = engine.rule_name(rec.rule_id);
            write_path_bytes(&mut self.out, display_path)?;
            write!(
                self.out,
                ":{}-{} {}",
                rec.root_hint_start, rec.root_hint_end, rule
            )?;
            self.out.write_all(b"\n")?;
            *findings_count = findings_count.wrapping_add(1);
        }

        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Pipeline scanner with fixed ring capacities for files, chunks, and findings.
///
/// This is single-threaded; all backpressure is handled via ring fullness and
/// the scan loop's stall detection.
pub struct Pipeline<const FILE_CAP: usize, const CHUNK_CAP: usize, const OUT_CAP: usize> {
    engine: Arc<Engine>,
    config: PipelineConfig,
    overlap: usize,
    pool: BufferPool,
    files: FileTable,
    file_ring: SpscRing<FileId, FILE_CAP>,
    chunk_ring: SpscRing<ScanItem, CHUNK_CAP>,
    out_ring: SpscRing<FindingRec, OUT_CAP>,
    walker: Walker,
    reader: ReaderStage,
    scanner: ScanStage,
    archive_scratch: ArchiveScratch,
    output: OutputStage,
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
        if config.path_bytes_cap == 0 {
            config.path_bytes_cap = config.max_files.saturating_mul(PIPE_PATH_BYTES_PER_FILE);
        }
        if let Err(err) = config.archive.validate() {
            panic!("archive config invalid: {err}");
        }

        let buf_len = overlap.saturating_add(config.chunk_size);
        assert!(buf_len <= BUFFER_LEN_MAX);

        let chunk_size = config.chunk_size;
        let max_files = config.max_files;
        let path_bytes_cap = config.path_bytes_cap;
        let scanner = ScanStage::new(&engine, config.context_mode, buf_len);
        let archive_scratch = ArchiveScratch::new(&engine, &config.archive, chunk_size);
        let pool = BufferPool::new(default_pool_capacity());
        Self {
            engine,
            config,
            overlap,
            pool,
            files: FileTable::with_capacity_and_path_bytes(max_files, path_bytes_cap),
            file_ring: SpscRing::new(),
            chunk_ring: SpscRing::new(),
            out_ring: SpscRing::new(),
            walker: Walker::new(max_files),
            reader: ReaderStage::new(overlap, chunk_size),
            scanner,
            archive_scratch,
            output: OutputStage::new(),
        }
    }

    fn scan_path_inner(&mut self, path: &Path, stats: &mut PipelineStats) -> io::Result<()> {
        self.files.clear();
        self.file_ring.clear();
        self.chunk_ring.clear();
        self.out_ring.clear();
        self.archive_scratch.core.clear_abort();
        self.walker.reset(path, &mut self.files, stats)?;
        self.reader.reset();
        self.scanner.reset();

        loop {
            let mut progressed = false;

            progressed |= self
                .output
                .pump(&self.engine, &self.files, &mut self.out_ring, stats)?;
            progressed |= self.scanner.pump(
                &self.engine,
                &self.files,
                &mut self.chunk_ring,
                &mut self.out_ring,
                stats,
            );
            if !self.archive_scratch.core.abort_run() {
                progressed |= self.reader.pump(
                    &mut self.file_ring,
                    &mut self.chunk_ring,
                    &self.pool,
                    &self.files,
                    self.engine.as_ref(),
                    &self.config.archive,
                    &mut self.archive_scratch,
                    &mut self.output,
                    stats,
                )?;
                progressed |= self
                    .walker
                    .pump(&mut self.files, &mut self.file_ring, stats)?;
            } else {
                self.reader.reset();
                self.walker.abort();
                self.file_ring.clear();
                self.chunk_ring.clear();
            }

            let aborting = self.archive_scratch.core.abort_run();
            let done = if aborting {
                !self.scanner.has_pending() && self.out_ring.is_empty()
            } else {
                self.walker.is_done()
                    && self.reader.is_idle()
                    && self.file_ring.is_empty()
                    && self.chunk_ring.is_empty()
                    && !self.scanner.has_pending()
                    && self.out_ring.is_empty()
            };

            if done {
                break;
            }

            if !progressed {
                if self.reader.is_waiting() {
                    // Reader backend has in-flight IO; yield to avoid a tight
                    // spin loop while the kernel completes requests.
                    std::thread::yield_now();
                    continue;
                }
                // No stage made progress and we're not done: this indicates a
                // logic bug (e.g., a ring is full/empty deadlock). Fail fast so
                // it is visible rather than silently spinning.
                return Err(io::Error::other("pipeline stalled"));
            }
        }

        self.output.flush()?;
        Ok(())
    }

    /// Scans a path (file or directory) and returns summary stats.
    ///
    /// The pipeline reuses internal buffers and stage state across scans.
    /// Capacity limits are hard bounds; the Unix path arena will panic if
    /// exhausted rather than allocating.
    pub fn scan_path(&mut self, path: &Path) -> io::Result<PipelineStats> {
        let mut stats = PipelineStats::default();
        self.scan_path_inner(path, &mut stats)?;
        Ok(stats)
    }
}

/// Convenience wrapper using pipeline defaults and fixed ring capacities.
///
/// This allocates a fresh pipeline and runs a single scan.
pub fn scan_path_default(path: &Path, engine: Arc<Engine>) -> io::Result<PipelineStats> {
    let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
        Pipeline::new(engine, PipelineConfig::default());
    pipeline.scan_path(path)
}

/// Fixed-size stack buffer limit for Unix C-path conversions.
#[cfg(unix)]
const PATH_MAX: usize = 4096;

#[cfg(unix)]
fn is_dot_or_dotdot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn dev_inode_from_stat(st: &libc::stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino)
}

#[cfg(unix)]
fn errno_ptr() -> *mut libc::c_int {
    #[cfg(target_os = "macos")]
    // SAFETY: libc provides a thread-local errno pointer on this platform.
    unsafe {
        libc::__error()
    }
    #[cfg(target_os = "linux")]
    // SAFETY: libc provides a thread-local errno pointer on this platform.
    unsafe {
        libc::__errno_location()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    // SAFETY: libc provides a thread-local errno pointer on this platform.
    unsafe {
        libc::__errno_location()
    }
}

#[cfg(unix)]
fn set_errno(value: libc::c_int) {
    // SAFETY: writing thread-local errno is safe and confined to this thread.
    unsafe {
        *errno_ptr() = value;
    }
}

/// Calls `f` with a NUL-terminated copy of `path` in a fixed stack buffer.
///
/// Rejects paths containing NUL or longer than `PATH_MAX` to avoid heap
/// allocation when invoking libc APIs.
///
/// # Safety
/// The pointer passed to `f` is only valid for the duration of the call; `f`
/// must not store it or use it after returning.
#[cfg(unix)]
fn with_c_path<T>(
    path: &Path,
    f: impl FnOnce(*const libc::c_char) -> io::Result<T>,
) -> io::Result<T> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(io::Error::other("path contains NUL"));
    }
    if bytes.len() >= PATH_MAX {
        return Err(io::Error::other("path too long"));
    }

    let mut buf = [0u8; PATH_MAX + 1];
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    let ptr = buf.as_ptr().cast::<libc::c_char>();
    f(ptr)
}

#[cfg(unix)]
fn open_dir(path: *const libc::c_char, span: PathSpan) -> io::Result<DirState> {
    // SAFETY: `path` is expected to be NUL-terminated. The returned DIR* and fd
    // are owned by the `DirState` and closed on drop.
    unsafe {
        let fd = libc::open(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let dirp = libc::fdopendir(fd);
        if dirp.is_null() {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        Ok(DirState {
            dirp,
            fd,
            path: span,
        })
    }
}

#[cfg(unix)]
fn open_dir_at(dirfd: RawFd, name: *const libc::c_char, span: PathSpan) -> io::Result<DirState> {
    // SAFETY: `name` is expected to be NUL-terminated and relative to `dirfd`.
    // The returned DIR* and fd are owned by the `DirState` and closed on drop.
    unsafe {
        let fd = libc::openat(
            dirfd,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let dirp = libc::fdopendir(fd);
        if dirp.is_null() {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        Ok(DirState {
            dirp,
            fd,
            path: span,
        })
    }
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
    use crate::api::{LexicalClassSet, LexicalContextSpec, RuleSpec, ValidatorKind};
    use crate::archive::PartialReason;
    use crate::demo::demo_tuning;
    use crate::scheduler::output_sink::VecSink;
    use crate::scheduler::{scan_local, LocalConfig, LocalFile, VecFileSource};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use regex::bytes::Regex;
    use std::fs;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn pipeline_config_defaults_context_mode_off() {
        let cfg = PipelineConfig::default();
        assert_eq!(cfg.context_mode, ContextMode::Off);
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

    fn engine_with_lexical_rule() -> Arc<Engine> {
        let rule = RuleSpec {
            name: "secret",
            anchors: &[b"SECRET"],
            radius: 0,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            local_context: None,
            lexical_context: Some(LexicalContextSpec {
                require_any: Some(LexicalClassSet::STRING),
                prefer_any: LexicalClassSet::STRING,
                deny_any: LexicalClassSet::COMMENT,
            }),
            secret_group: None,
            re: Regex::new("SECRET").unwrap(),
        };
        Arc::new(Engine::new(vec![rule], Vec::new(), demo_tuning()))
    }

    fn drain_out_ring<const FILE_CAP: usize, const CHUNK_CAP: usize, const OUT_CAP: usize>(
        pipeline: &mut Pipeline<FILE_CAP, CHUNK_CAP, OUT_CAP>,
        out: &mut Vec<String>,
    ) -> bool {
        let mut progressed = false;
        while let Some(rec) = pipeline.out_ring.pop() {
            let path = pipeline.files.path(rec.file_id);
            let rule = pipeline.engine.rule_name(rec.rule_id);
            out.push(format!(
                "{}:{}-{} {}",
                path.display(),
                rec.root_hint_start,
                rec.root_hint_end,
                rule
            ));
            progressed = true;
        }
        progressed
    }

    fn scan_path_collect_lines(path: &Path, engine: Arc<Engine>) -> io::Result<Vec<String>> {
        let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(
                Arc::clone(&engine),
                PipelineConfig {
                    context_mode: ContextMode::Filter,
                    ..PipelineConfig::default()
                },
            );

        let mut stats = PipelineStats::default();
        pipeline.files.clear();
        pipeline.file_ring.clear();
        pipeline.chunk_ring.clear();
        pipeline.out_ring.clear();
        pipeline
            .walker
            .reset(path, &mut pipeline.files, &mut stats)?;
        pipeline.reader.reset();
        pipeline.scanner.reset();

        let mut lines = Vec::new();

        loop {
            let mut progressed = false;

            progressed |= drain_out_ring(&mut pipeline, &mut lines);
            progressed |= pipeline.scanner.pump(
                &pipeline.engine,
                &pipeline.files,
                &mut pipeline.chunk_ring,
                &mut pipeline.out_ring,
                &mut stats,
            );
            progressed |= pipeline.reader.pump(
                &mut pipeline.file_ring,
                &mut pipeline.chunk_ring,
                &pipeline.pool,
                &pipeline.files,
                &pipeline.engine,
                &pipeline.config.archive,
                &mut pipeline.archive_scratch,
                &mut pipeline.output,
                &mut stats,
            )?;
            progressed |=
                pipeline
                    .walker
                    .pump(&mut pipeline.files, &mut pipeline.file_ring, &mut stats)?;

            let aborting = pipeline.archive_scratch.core.abort_run();
            let done = if aborting {
                !pipeline.scanner.has_pending() && pipeline.out_ring.is_empty()
            } else {
                pipeline.walker.is_done()
                    && pipeline.reader.is_idle()
                    && pipeline.file_ring.is_empty()
                    && pipeline.chunk_ring.is_empty()
                    && !pipeline.scanner.has_pending()
                    && pipeline.out_ring.is_empty()
            };

            if done {
                break;
            }

            if !progressed {
                if pipeline.reader.is_waiting() {
                    std::thread::yield_now();
                    continue;
                }
                return Err(io::Error::other("pipeline stalled"));
            }
        }

        Ok(lines)
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
    #[cfg(feature = "stats")]
    fn pipeline_counts_walk_and_open_errors() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_walk_err")?;
        let denied = tmp.path().join("denied");
        fs::create_dir(&denied)?;

        let unreadable = tmp.path().join("no_read.txt");
        fs::write(&unreadable, b"secret")?;

        let _deny_guard = RestorePerm::new(denied, 0o700)?;
        let _file_guard = RestorePerm::new(unreadable, 0o600)?;

        let engine = Arc::new(crate::demo_engine());
        let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(engine, PipelineConfig::default());

        let stats = pipeline.scan_path(tmp.path())?;

        assert!(stats.walk_errors > 0);
        assert!(stats.open_errors > 0);
        assert!(stats.errors >= stats.walk_errors + stats.open_errors);

        Ok(())
    }

    #[test]
    fn pipeline_matches_scheduler_local_with_lexical_filtering() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_parity")?;
        let file_path = tmp.path().join("sample.rs");
        let contents = b"let a = \"SECRET\"; // SECRET\n";
        fs::write(&file_path, contents)?;

        let engine = engine_with_lexical_rule();

        let mut pipeline_lines = scan_path_collect_lines(&file_path, Arc::clone(&engine))?;
        pipeline_lines.sort();

        let file_size = fs::metadata(&file_path)?.len();
        let source = VecFileSource::new(vec![LocalFile {
            path: file_path.clone(),
            size: file_size,
        }]);
        let cfg = LocalConfig {
            context_mode: ContextMode::Filter,
            ..LocalConfig::default()
        };
        let sink = Arc::new(VecSink::new());
        scan_local(Arc::clone(&engine), source, cfg, sink.clone());

        let out = sink.take();
        let mut scheduler_lines: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .map(str::to_string)
            .collect();
        scheduler_lines.sort();

        assert_eq!(pipeline_lines, scheduler_lines);
        Ok(())
    }

    #[test]
    fn pipeline_skips_archive_when_enabled() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_archive_skip")?;
        let path = tmp.path().join("sample.zip");
        fs::write(&path, b"SECRET")?;

        let engine = Arc::new(crate::demo_engine());
        let mut cfg = PipelineConfig::default();
        cfg.archive.enabled = true;
        let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(engine, cfg);

        let stats = pipeline.scan_path(&path)?;

        assert_eq!(stats.archive.archives_seen, 1);
        assert_eq!(stats.archive.archives_partial, 1);
        assert_eq!(
            stats.archive.partial_reasons[PartialReason::MalformedZip.as_usize()],
            1
        );
        assert_eq!(stats.bytes_scanned, 0);
        Ok(())
    }

    #[test]
    fn pipeline_scans_archive_extension_when_disabled() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_archive_disabled")?;
        let path = tmp.path().join("sample.zip");
        let payload = b"plain bytes with SECRET marker";
        fs::write(&path, payload)?;

        let engine = Arc::new(crate::demo_engine());
        let mut cfg = PipelineConfig::default();
        cfg.archive.enabled = false;
        let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(engine, cfg);

        let stats = pipeline.scan_path(&path)?;

        assert_eq!(stats.archive.archives_seen, 0);
        assert_eq!(stats.archive.archives_skipped, 0);
        assert!(stats.bytes_scanned >= payload.len() as u64);
        Ok(())
    }

    #[test]
    fn pipeline_scans_gzip_when_enabled() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_gzip_scan")?;
        let path = tmp.path().join("payload.txt.gz");

        let payload = b"payload SECRET inside";
        let f = fs::File::create(&path)?;
        let mut enc = GzEncoder::new(f, Compression::default());
        enc.write_all(payload)?;
        enc.finish()?;

        let engine = Arc::new(crate::demo_engine());
        let mut cfg = PipelineConfig::default();
        cfg.archive.enabled = true;
        let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
            Pipeline::new(engine, cfg);

        let stats = pipeline.scan_path(&path)?;

        assert_eq!(stats.archive.archives_seen, 1);
        assert_eq!(stats.archive.archives_scanned, 1);
        assert!(stats.archive.entries_scanned > 0);
        assert!(stats.bytes_scanned > 0);
        Ok(())
    }
}
