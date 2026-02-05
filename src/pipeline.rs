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
//! # Invariants and budgets
//! - Rings are fixed-capacity; every stage must tolerate backpressure.
//! - Chunk overlap is set to `Engine::required_overlap()` to avoid missed
//!   matches across chunk boundaries.
//! - On Unix, path storage is a fixed-size arena; exceeding it is a hard error.
//! - The pipeline is single-threaded and not Sync/Send by design.

use crate::archive::formats::zip::LimitedRead;
use crate::archive::formats::{
    tar::TAR_BLOCK_LEN, GzipStream, TarCursor, TarInput, TarNext, TarRead, ZipCursor, ZipEntryMeta,
    ZipNext, ZipOpen,
};
use crate::archive::path::apply_hash_suffix_truncation;
use crate::archive::{
    detect_kind_from_name_bytes, detect_kind_from_path, sniff_kind_from_header, ArchiveBudgets,
    ArchiveConfig, ArchiveKind, ArchiveSkipReason, ArchiveStats, BudgetHit, ChargeResult,
    EntryPathCanonicalizer, EntrySkipReason, PartialReason, VirtualPathBuilder,
    DEFAULT_MAX_COMPONENTS,
};
#[cfg(unix)]
use crate::runtime::PathSpan;
#[cfg(unix)]
use crate::scratch_memory::ScratchVec;
use crate::stdx::RingBuffer;
use crate::{
    BufferPool, Chunk, Engine, FileId, FileTable, FindingRec, ScanScratch, BUFFER_ALIGN,
    BUFFER_LEN_MAX,
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

/// Hard cap on per-read output for archive streams.
const ARCHIVE_STREAM_READ_MAX: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchiveEnd {
    Scanned,
    Skipped(ArchiveSkipReason),
    Partial(PartialReason),
}

/// Reusable scratch state for archive scanning inside the pipeline.
///
/// # Invariants
/// - All buffers are preallocated and reused; per-entry allocations are avoided.
/// - Per-depth vectors (`vpaths`, `tar_cursors`, `path_budget_used`) are sized
///   to `max_archive_depth + 2` and indexed by depth.
/// - `next_virtual_file_id` stays in the high-bit namespace to avoid collisions
///   with real file ids.
struct ArchiveScratch {
    scan_scratch: ScanScratch,
    pending: Vec<FindingRec>,
    canon: EntryPathCanonicalizer,
    vpaths: Vec<VirtualPathBuilder>,
    path_budget_used: Vec<usize>,
    budgets: ArchiveBudgets,
    /// Per-depth TAR cursors (one per nested depth).
    tar_cursors: Vec<TarCursor>,
    /// Reused ZIP cursor with preallocated buffers.
    zip_cursor: ZipCursor,
    /// Scratch buffer for entry display bytes when we need to append a hash suffix.
    entry_display_buf: Vec<u8>,
    gzip_header_buf: Vec<u8>,
    gzip_name_buf: Vec<u8>,
    stream_buf: Vec<u8>,
    chunk_size: usize,
    /// Monotonic virtual `FileId` generator for archive entries.
    next_virtual_file_id: u32,
    /// Set to true when `FailRun` policy triggers.
    abort_run: bool,
}

impl ArchiveScratch {
    fn new(engine: &Engine, archive: &ArchiveConfig, chunk_size: usize) -> Self {
        let depth_cap = archive.max_archive_depth as usize + 2;
        let mut vpaths = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            vpaths.push(VirtualPathBuilder::with_capacity(
                archive.max_virtual_path_len_per_entry,
            ));
        }
        let mut tar_cursors = Vec::with_capacity(depth_cap);
        for _ in 0..depth_cap {
            tar_cursors.push(TarCursor::with_capacity(archive));
        }
        let entry_display_cap = archive.max_virtual_path_len_per_entry;
        let path_budget_used = vec![0usize; depth_cap];
        let gzip_name_cap = archive.max_virtual_path_len_per_entry;
        let gzip_header_cap = archive
            .max_virtual_path_len_per_entry
            .saturating_add(256)
            .min(archive.max_archive_metadata_bytes as usize)
            .clamp(64, 64 * 1024);
        let overlap = engine.required_overlap();
        let buf_len = chunk_size.saturating_add(overlap).max(overlap + 1);

        Self {
            scan_scratch: engine.new_scratch(),
            pending: Vec::with_capacity(engine.tuning.max_findings_per_chunk),
            canon: EntryPathCanonicalizer::with_capacity(
                DEFAULT_MAX_COMPONENTS,
                archive.max_virtual_path_len_per_entry,
            ),
            vpaths,
            path_budget_used,
            budgets: ArchiveBudgets::new(archive),
            tar_cursors,
            zip_cursor: ZipCursor::with_capacity(archive),
            entry_display_buf: Vec::with_capacity(entry_display_cap),
            gzip_header_buf: vec![0u8; gzip_header_cap],
            gzip_name_buf: Vec::with_capacity(gzip_name_cap),
            stream_buf: vec![0u8; buf_len],
            chunk_size,
            next_virtual_file_id: 0x8000_0000,
            abort_run: false,
        }
    }
}

#[inline(always)]
fn map_archive_skip_to_partial(reason: ArchiveSkipReason) -> PartialReason {
    match reason {
        ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
        ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
        ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
        ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
            PartialReason::ArchiveOutputBudgetExceeded
        }
        ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
        ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
        ArchiveSkipReason::UnsupportedFeature => PartialReason::UnsupportedFeature,
        _ => PartialReason::MalformedZip,
    }
}

#[inline(always)]
fn budget_hit_to_partial_reason(hit: BudgetHit) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => map_archive_skip_to_partial(r),
        BudgetHit::SkipEntry(_) => PartialReason::EntryOutputBudgetExceeded,
    }
}

#[inline(always)]
fn budget_hit_to_archive_end(hit: BudgetHit) -> ArchiveEnd {
    match hit {
        BudgetHit::SkipArchive(r) => ArchiveEnd::Skipped(r),
        BudgetHit::PartialArchive(r) => ArchiveEnd::Partial(r),
        BudgetHit::StopRoot(r) => ArchiveEnd::Partial(r),
        BudgetHit::SkipEntry(_) => ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded),
    }
}

/// Shared scratch references for archive scanning (pipeline path).
///
/// # Invariants
/// - All buffers are preallocated in `ArchiveScratch` and must not grow.
/// - Nested scans borrow disjoint slices of scratch buffers (no aliasing).
/// - `budgets` is shared across nested scans to enforce global caps.
/// - `path_budget_used` tracks per-archive virtual path byte usage.
/// - `abort_run` is set when `FailRun` policies trigger.
struct ArchiveScanCtx<'a> {
    engine: &'a Engine,
    output: &'a mut OutputStage,
    stats: &'a mut PipelineStats,
    scan_scratch: &'a mut ScanScratch,
    pending: &'a mut Vec<FindingRec>,
    budgets: &'a mut ArchiveBudgets,
    canon: &'a mut EntryPathCanonicalizer,
    vpaths: &'a mut [VirtualPathBuilder],
    path_budget_used: &'a mut [usize],
    tar_cursors: &'a mut [TarCursor],
    gzip_header_buf: &'a mut Vec<u8>,
    gzip_name_buf: &'a mut Vec<u8>,
    stream_buf: &'a mut Vec<u8>,
    next_virtual_file_id: &'a mut u32,
    archive: &'a ArchiveConfig,
    chunk_size: usize,
    abort_run: &'a mut bool,
}

impl<'a> ArchiveScanCtx<'a> {
    fn new(
        engine: &'a Engine,
        archive: &'a ArchiveConfig,
        scratch: &'a mut ArchiveScratch,
        output: &'a mut OutputStage,
        stats: &'a mut PipelineStats,
    ) -> Self {
        Self {
            engine,
            output,
            stats,
            scan_scratch: &mut scratch.scan_scratch,
            pending: &mut scratch.pending,
            budgets: &mut scratch.budgets,
            canon: &mut scratch.canon,
            vpaths: scratch.vpaths.as_mut_slice(),
            path_budget_used: scratch.path_budget_used.as_mut_slice(),
            tar_cursors: scratch.tar_cursors.as_mut_slice(),
            gzip_header_buf: &mut scratch.gzip_header_buf,
            gzip_name_buf: &mut scratch.gzip_name_buf,
            stream_buf: &mut scratch.stream_buf,
            next_virtual_file_id: &mut scratch.next_virtual_file_id,
            archive,
            chunk_size: scratch.chunk_size,
            abort_run: &mut scratch.abort_run,
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

const LOCATOR_LEN: usize = 18;

#[inline(always)]
fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
    debug_assert_eq!(out16.len(), 16);
    for (i, out) in out16.iter_mut().enumerate().take(16) {
        let shift = (15 - i) * 4;
        let nyb = ((x >> shift) & 0xF) as u8;
        *out = match nyb {
            0..=9 => b'0' + nyb,
            _ => b'a' + (nyb - 10),
        };
    }
}

#[inline]
fn build_locator(out: &mut [u8; LOCATOR_LEN], kind: u8, value: u64) -> &[u8] {
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

/// Charge decompressed bytes that were read but not scanned (entry truncation).
#[inline(always)]
fn charge_discarded_bytes(budgets: &mut ArchiveBudgets, bytes: u64) -> Result<(), PartialReason> {
    if bytes == 0 {
        return Ok(());
    }
    match budgets.charge_discarded_out(bytes) {
        ChargeResult::Ok => Ok(()),
        ChargeResult::Clamp { hit, .. } => Err(budget_hit_to_partial_reason(hit)),
    }
}

/// Apply decompressed-output budgeting for a read of `n` bytes.
///
/// Returns `(allowed, clamped)` where:
/// - `allowed` is the prefix length to scan/emits.
/// - `clamped` signals the caller must stop after this iteration.
///
/// If the decoder produced more bytes than allowed, the extra bytes are charged
/// as discarded output so archive/root caps remain accurate.
#[inline(always)]
fn apply_entry_budget_clamp(
    budgets: &mut ArchiveBudgets,
    n: usize,
    entry_partial_reason: &mut Option<PartialReason>,
    outcome: &mut ArchiveEnd,
    stop_archive: &mut bool,
) -> (u64, bool) {
    let mut allowed = n as u64;
    if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
        let r = budget_hit_to_partial_reason(hit);
        allowed = a;
        *entry_partial_reason = Some(r);
        if !matches!(hit, BudgetHit::SkipEntry(_)) {
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
    }

    if allowed == 0 {
        if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (0, true);
    }

    if allowed < n as u64 {
        let extra = (n as u64).saturating_sub(allowed);
        if let Err(r) = charge_discarded_bytes(budgets, extra) {
            if entry_partial_reason.is_none() {
                *entry_partial_reason = Some(r);
            }
            *outcome = ArchiveEnd::Partial(r);
            *stop_archive = true;
        }
        return (allowed, true);
    }

    (allowed, false)
}

/// Drain remaining tar entry payload bytes to realign the stream.
fn discard_remaining_payload(
    input: &mut dyn TarRead,
    budgets: &mut ArchiveBudgets,
    buf: &mut [u8],
    mut remaining: u64,
) -> Result<(), PartialReason> {
    while remaining > 0 {
        let step = buf.len().min(remaining as usize);
        let n = match input.read(&mut buf[..step]) {
            Ok(n) => n,
            Err(_) => return Err(PartialReason::MalformedTar),
        };
        if n == 0 {
            return Err(PartialReason::MalformedTar);
        }
        budgets.charge_compressed_in(input.take_compressed_delta());
        charge_discarded_bytes(budgets, n as u64)?;
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(())
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
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.vpaths.len() > 1);
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let (mut gz, name_len) = match GzipStream::new_with_header(
        file,
        &mut scratch.gzip_header_buf,
        &mut scratch.gzip_name_buf,
        max_len,
    ) {
        Ok(v) => v,
        Err(_) => {
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    let entry_name_bytes = if let Some(len) = name_len {
        let c = scratch.canon.canonicalize(
            &scratch.gzip_name_buf[..len],
            DEFAULT_MAX_COMPONENTS,
            max_len,
        );
        if c.had_traversal {
            stats.archive.record_path_had_traversal();
        }
        if c.component_cap_exceeded {
            stats.archive.record_component_cap_exceeded();
        }
        if c.truncated {
            stats.archive.record_path_truncated();
        }
        c.bytes
    } else {
        b"<gunzip>"
    };

    let path_bytes = scratch.vpaths[1]
        .build(parent_bytes, entry_name_bytes, max_len)
        .bytes;
    let need = path_bytes.len();
    if scratch.path_budget_used[1].saturating_add(need) > archive.max_virtual_path_bytes_per_archive
    {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return Ok(ArchiveEnd::Partial(PartialReason::PathBudgetExceeded));
    }
    scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return Ok(budget_hit_to_archive_end(hit));
    }
    if let Err(hit) = scratch.budgets.begin_entry() {
        scratch.budgets.exit_archive();
        let (_inner, hdr_buf) = gz.into_inner().into_parts();
        scratch.gzip_header_buf = hdr_buf;
        return Ok(budget_hit_to_archive_end(hit));
    }

    let buf = &mut scratch.stream_buf;

    let entry_file_id = alloc_virtual_file_id(&mut scratch.next_virtual_file_id);
    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.copy_within(have - carry..have, 0);
        }

        let allowance = scratch
            .budgets
            .remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf[carry..carry + read_max];
        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        scratch
            .budgets
            .charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } =
            scratch.budgets.charge_decompressed_out(allowed)
        {
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf[..read_len];

        engine.scan_chunk_into(data, entry_file_id, base_offset, &mut scratch.scan_scratch);
        if !entry_scanned {
            stats.archive.record_entry_scanned();
            entry_scanned = true;
        }

        let new_bytes_start = offset;
        scratch.scan_scratch.drop_prefix_findings(new_bytes_start);

        scratch.pending.clear();
        scratch
            .scan_scratch
            .drain_findings_into(&mut scratch.pending);

        output.emit_findings_direct(engine, path_bytes, &scratch.pending, stats)?;

        stats.chunks = stats.chunks.saturating_add(1);
        stats.bytes_scanned = stats.bytes_scanned.saturating_add(allowed);

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    scratch.budgets.end_entry(offset > 0);
    scratch.budgets.exit_archive();

    let (_inner, hdr_buf) = gz.into_inner().into_parts();
    scratch.gzip_header_buf = hdr_buf;

    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }

    if let Some(r) = entry_partial_reason {
        stats.archive.record_entry_partial(r, path_bytes, false);
    }

    Ok(outcome)
}

/// Scan a gzip stream as a single virtual entry.
fn scan_gzip_stream_nested<R: Read>(
    scan: &mut ArchiveScanCtx<'_>,
    gz: &mut GzipStream<R>,
    display: &[u8],
) -> io::Result<ArchiveEnd> {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.engine.required_overlap();
    let file_id = alloc_virtual_file_id(scan.next_virtual_file_id);

    if let Err(hit) = budgets.begin_entry() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let buf = &mut scan.stream_buf;

    let mut offset: u64 = 0;
    let mut carry: usize = 0;
    let mut have: usize = 0;
    let mut outcome = ArchiveEnd::Scanned;
    let mut entry_scanned = false;
    let mut entry_partial_reason: Option<PartialReason> = None;

    loop {
        if carry > 0 && have > 0 {
            buf.copy_within(have - carry..have, 0);
        }

        let allowance = budgets.remaining_decompressed_allowance_with_ratio_probe(true);
        if allowance == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(allowance.min(u64::from(u32::MAX)) as usize);

        if read_max == 0 {
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                let r = budget_hit_to_partial_reason(hit);
                outcome = ArchiveEnd::Partial(r);
                entry_partial_reason = Some(r);
            }
            break;
        }

        let dst = &mut buf[carry..carry + read_max];
        let n = match gz.read(dst) {
            Ok(n) => n,
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
                entry_partial_reason = Some(PartialReason::GzipCorrupt);
                break;
            }
        };

        if n == 0 {
            break;
        }

        budgets.charge_compressed_in(gz.take_compressed_delta());

        let mut allowed = n as u64;
        if let ChargeResult::Clamp { allowed: a, hit } = budgets.charge_decompressed_out(allowed) {
            let r = budget_hit_to_partial_reason(hit);
            allowed = a;
            outcome = ArchiveEnd::Partial(r);
            entry_partial_reason = Some(r);
        }

        if allowed == 0 {
            break;
        }

        let allowed_usize = allowed as usize;
        let read_len = carry + allowed_usize;

        let base_offset = offset.saturating_sub(carry as u64);
        let data = &buf[..read_len];

        scan.engine
            .scan_chunk_into(data, file_id, base_offset, scan.scan_scratch);
        if !entry_scanned {
            scan.stats.archive.record_entry_scanned();
            entry_scanned = true;
        }

        debug_assert_eq!(
            base_offset.saturating_add(carry as u64),
            offset,
            "expected new-bytes start to align with base_offset + carry"
        );
        let new_bytes_start = base_offset.saturating_add(carry as u64);
        scan.scan_scratch.drop_prefix_findings(new_bytes_start);

        scan.pending.clear();
        scan.scan_scratch.drain_findings_into(scan.pending);

        scan.output
            .emit_findings_direct(scan.engine, display, scan.pending, scan.stats)?;

        scan.stats.chunks = scan.stats.chunks.saturating_add(1);
        scan.stats.bytes_scanned = scan.stats.bytes_scanned.saturating_add(allowed);

        offset = offset.saturating_add(allowed);
        have = read_len;
        carry = overlap.min(read_len);

        if allowed_usize < n {
            break;
        }
    }

    budgets.end_entry(offset > 0);
    if !entry_scanned && outcome == ArchiveEnd::Scanned {
        outcome = ArchiveEnd::Partial(PartialReason::GzipCorrupt);
        entry_partial_reason = Some(PartialReason::GzipCorrupt);
    }
    if let Some(r) = entry_partial_reason {
        scan.stats.archive.record_entry_partial(r, display, false);
    }

    Ok(outcome)
}

/// Scan a tar stream (plain or gzip-wrapped) as sequential entries.
///
/// # Invariants
/// - Entry payloads are scanned with chunk+overlap semantics.
/// - Non-regular entries are skipped explicitly.
/// - Malformed headers or payload reads yield `PartialReason::MalformedTar`.
/// - When `ratio_active` is true, decompressed allowance includes ratio probing.
#[allow(clippy::too_many_arguments)]
fn scan_tar_stream<R: TarRead>(
    input: &mut R,
    parent_bytes: &[u8],
    engine: &Engine,
    archive: &ArchiveConfig,
    scratch: &mut ArchiveScratch,
    output: &mut OutputStage,
    stats: &mut PipelineStats,
    ratio_active: bool,
) -> io::Result<ArchiveEnd> {
    let mut scan = ArchiveScanCtx::new(engine, archive, scratch, output, stats);

    scan.budgets.reset();
    if let Err(hit) = scan.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let outcome = scan_tar_stream_nested(&mut scan, input, parent_bytes, 1, ratio_active);
    scan.budgets.exit_archive();
    outcome
}

/// Scan a tar stream (plain or gzip-wrapped), optionally recursing into nested archives.
///
/// # Invariants
/// - Entry payloads are scanned with chunk+overlap semantics.
/// - Non-regular entries are skipped explicitly.
/// - Malformed headers or payload reads yield `PartialReason::MalformedTar`.
/// - Caller has already entered the archive budget for this container.
/// - `depth` is 1-based; nested expansion stops at `max_archive_depth`.
#[allow(clippy::too_many_arguments)]
fn scan_tar_stream_nested(
    scan: &mut ArchiveScanCtx<'_>,
    input: &mut dyn TarRead,
    container_display: &[u8],
    depth: u8,
    ratio_active: bool,
) -> io::Result<ArchiveEnd> {
    let budgets = &mut *scan.budgets;
    let chunk_size = scan.chunk_size.min(ARCHIVE_STREAM_READ_MAX);
    let overlap = scan.engine.required_overlap();
    let max_len = scan.archive.max_virtual_path_len_per_entry;
    let max_depth = scan.archive.max_archive_depth;

    let (cur_vpath, rest_vpaths) = scan
        .vpaths
        .split_first_mut()
        .expect("vpath scratch exhausted");
    let (cur_path_used, rest_path_used) = scan
        .path_budget_used
        .split_first_mut()
        .expect("path budget scratch exhausted");
    let (cur_cursor, rest_cursors) = scan
        .tar_cursors
        .split_first_mut()
        .expect("tar cursor scratch exhausted");

    cur_cursor.reset();
    *cur_path_used = 0;

    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (entry_display, entry_size, entry_pad, entry_typeflag, nested_kind) = {
            let meta = match cur_cursor.next_entry(input, budgets, scan.archive) {
                Ok(TarNext::End) => break,
                Ok(TarNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(TarNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            };

            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, b't', meta.header_block_index);
            let entry_display = {
                let c = scan
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    scan.stats.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    scan.stats.archive.record_component_cap_exceeded();
                }
                if c.truncated {
                    scan.stats.archive.record_path_truncated();
                }
                cur_vpath
                    .build_with_suffix(container_display, c.bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if cur_path_used.saturating_add(need) > scan.archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            *cur_path_used = cur_path_used.saturating_add(need);

            let nested_kind = detect_kind_from_name_bytes(meta.name);

            (
                entry_display,
                meta.size,
                meta.pad,
                meta.typeflag,
                nested_kind,
            )
        };

        let is_regular = entry_typeflag == 0 || entry_typeflag == b'0';
        if !is_regular {
            scan.stats.archive.record_entry_skipped(
                EntrySkipReason::NonRegular,
                entry_display,
                false,
            );
            match cur_cursor.skip_payload_and_pad(input, budgets, entry_size, entry_pad) {
                Ok(Ok(())) => continue,
                _ => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    break;
                }
            }
        }

        budgets.begin_entry_scan();
        let mut stop_archive = false;

        if let Some(kind) = nested_kind {
            match kind {
                ArchiveKind::Zip => {
                    scan.stats.archive.record_archive_skipped(
                        ArchiveSkipReason::NeedsRandomAccessNoSpill,
                        entry_display,
                        false,
                    );
                    match scan.archive.unsupported_policy {
                        crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                            // Fall back to scanning raw bytes.
                        }
                        crate::archive::UnsupportedPolicy::FailArchive => {
                            scan.stats.archive.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                        crate::archive::UnsupportedPolicy::FailRun => {
                            *scan.abort_run = true;
                            scan.stats.archive.record_entry_skipped(
                                EntrySkipReason::UnsupportedFeature,
                                entry_display,
                                false,
                            );
                            budgets.end_entry(false);
                            outcome =
                                ArchiveEnd::Skipped(ArchiveSkipReason::NeedsRandomAccessNoSpill);
                            break;
                        }
                    }
                }
                ArchiveKind::Gzip | ArchiveKind::Tar | ArchiveKind::TarGz => {
                    if depth >= max_depth {
                        scan.stats.archive.record_archive_skipped(
                            ArchiveSkipReason::DepthExceeded,
                            entry_display,
                            false,
                        );
                    } else if let Err(hit) = budgets.enter_archive() {
                        let r = budget_hit_to_archive_end(hit);
                        match r {
                            ArchiveEnd::Skipped(reason) => scan
                                .stats
                                .archive
                                .record_archive_skipped(reason, entry_display, false),
                            ArchiveEnd::Partial(reason) => scan
                                .stats
                                .archive
                                .record_archive_partial(reason, entry_display, false),
                            _ => {}
                        }
                    } else {
                        scan.stats.archive.record_archive_seen();
                        scan.stats.archive.record_entry_scanned();

                        let nested_outcome = match kind {
                            ArchiveKind::Gzip => {
                                let (gunzip_vpath, vpaths_tail) = rest_vpaths
                                    .split_first_mut()
                                    .expect("vpath scratch exhausted");
                                let (gunzip_path_used, path_used_tail) = rest_path_used
                                    .split_first_mut()
                                    .expect("path budget scratch exhausted");
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    output: scan.output,
                                    stats: scan.stats,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: vpaths_tail,
                                    path_budget_used: path_used_tail,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };

                                let (mut gz, name_len) = match GzipStream::new_with_header(
                                    LimitedRead::new(input, entry_size),
                                    child.gzip_header_buf,
                                    child.gzip_name_buf,
                                    max_len,
                                ) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                        budgets.exit_archive();
                                        budgets.end_entry(true);
                                        break;
                                    }
                                };
                                let entry_name_bytes = if let Some(len) = name_len {
                                    let c = child.canon.canonicalize(
                                        &child.gzip_name_buf[..len],
                                        DEFAULT_MAX_COMPONENTS,
                                        max_len,
                                    );
                                    if c.had_traversal {
                                        child.stats.archive.record_path_had_traversal();
                                    }
                                    if c.component_cap_exceeded {
                                        child.stats.archive.record_component_cap_exceeded();
                                    }
                                    if c.truncated {
                                        child.stats.archive.record_path_truncated();
                                    }
                                    c.bytes
                                } else {
                                    b"<gunzip>"
                                };
                                let gunzip_display = gunzip_vpath
                                    .build(entry_display, entry_name_bytes, max_len)
                                    .bytes;
                                *gunzip_path_used = 0;
                                let need = gunzip_display.len();
                                if gunzip_path_used.saturating_add(need)
                                    > scan.archive.max_virtual_path_bytes_per_archive
                                {
                                    outcome =
                                        ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                                    budgets.exit_archive();
                                    budgets.end_entry(true);
                                    break;
                                }
                                *gunzip_path_used = gunzip_path_used.saturating_add(need);

                                let out =
                                    scan_gzip_stream_nested(&mut child, &mut gz, gunzip_display)?;
                                let (entry_reader, hdr_buf) = gz.into_inner().into_parts();
                                *child.gzip_header_buf = hdr_buf;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Tar => {
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    output: scan.output,
                                    stats: scan.stats,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };
                                let mut entry_reader = LimitedRead::new(input, entry_size);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut entry_reader,
                                    entry_display,
                                    depth + 1,
                                    ratio_active,
                                )?;
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::TarGz => {
                                let mut child = ArchiveScanCtx {
                                    engine: scan.engine,
                                    output: scan.output,
                                    stats: scan.stats,
                                    scan_scratch: scan.scan_scratch,
                                    pending: scan.pending,
                                    budgets,
                                    canon: scan.canon,
                                    vpaths: rest_vpaths,
                                    path_budget_used: rest_path_used,
                                    tar_cursors: rest_cursors,
                                    gzip_header_buf: scan.gzip_header_buf,
                                    gzip_name_buf: scan.gzip_name_buf,
                                    stream_buf: scan.stream_buf,
                                    next_virtual_file_id: scan.next_virtual_file_id,
                                    archive: scan.archive,
                                    chunk_size: scan.chunk_size,
                                    abort_run: scan.abort_run,
                                };
                                let entry_reader = LimitedRead::new(input, entry_size);
                                let mut gz = GzipStream::new(entry_reader);
                                let out = scan_tar_stream_nested(
                                    &mut child,
                                    &mut gz,
                                    entry_display,
                                    depth + 1,
                                    true,
                                )?;
                                let entry_reader = gz.into_inner();
                                (out, entry_reader.remaining())
                            }
                            ArchiveKind::Zip => unreachable!(),
                        };

                        budgets.exit_archive();

                        let mut entry_partial_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };

                        match nested_outcome.0 {
                            ArchiveEnd::Scanned => scan.stats.archive.record_archive_scanned(),
                            ArchiveEnd::Skipped(r) => {
                                scan.stats
                                    .archive
                                    .record_archive_skipped(r, entry_display, false)
                            }
                            ArchiveEnd::Partial(r) => {
                                scan.stats
                                    .archive
                                    .record_archive_partial(r, entry_display, false);
                            }
                        }

                        budgets.end_entry(true);

                        let stop_reason = match nested_outcome.0 {
                            ArchiveEnd::Partial(r) => Some(r),
                            ArchiveEnd::Skipped(r) => Some(map_archive_skip_to_partial(r)),
                            ArchiveEnd::Scanned => None,
                        };
                        if let Some(r) = stop_reason {
                            if matches!(r, PartialReason::RootOutputBudgetExceeded) {
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if !stop_archive && nested_outcome.1 > 0 {
                            if entry_partial_reason.is_none() {
                                entry_partial_reason = Some(PartialReason::MalformedTar);
                            }
                            if let Err(r) = discard_remaining_payload(
                                input,
                                budgets,
                                scan.stream_buf.as_mut_slice(),
                                nested_outcome.1,
                            ) {
                                if entry_partial_reason.is_none() {
                                    entry_partial_reason = Some(r);
                                }
                                outcome = ArchiveEnd::Partial(r);
                                stop_archive = true;
                            }
                        }

                        if let Some(r) = entry_partial_reason {
                            scan.stats
                                .archive
                                .record_entry_partial(r, entry_display, false);
                        }

                        if !stop_archive {
                            match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
                                Ok(Ok(())) => {}
                                _ => {
                                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                                    stop_archive = true;
                                }
                            }
                        }

                        if stop_archive {
                            break;
                        }

                        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
                        continue;
                    }
                }
            }
        }

        let entry_file_id = alloc_virtual_file_id(scan.next_virtual_file_id);
        let mut remaining = entry_size;
        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;

        while remaining > 0 {
            if carry > 0 && have > 0 {
                scan.stream_buf.copy_within(have - carry..have, 0);
            }

            let allow = budgets.remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allow == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(scan.stream_buf.len().saturating_sub(carry))
                .min(allow.min(remaining).min(u64::from(u32::MAX)) as usize);
            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = budgets.charge_decompressed_out(1) {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut scan.stream_buf[carry..carry + read_max];
            let n = match input.read(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                    entry_partial_reason = Some(PartialReason::MalformedTar);
                    stop_archive = true;
                    break;
                }
            };
            budgets.charge_compressed_in(input.take_compressed_delta());
            if n == 0 {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                entry_partial_reason = Some(PartialReason::MalformedTar);
                stop_archive = true;
                break;
            }
            remaining = remaining.saturating_sub(n as u64);

            let mut allowed = n as u64;
            if let ChargeResult::Clamp { allowed: a, hit } =
                budgets.charge_decompressed_out(allowed)
            {
                let r = budget_hit_to_partial_reason(hit);
                allowed = a;
                entry_partial_reason = Some(r);
                if !matches!(hit, BudgetHit::SkipEntry(_)) {
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
            }
            if allowed == 0 {
                if let Err(r) = charge_discarded_bytes(budgets, n as u64) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;
            let base_offset = offset.saturating_sub(carry as u64);
            let data = &scan.stream_buf[..read_len];

            scan.engine
                .scan_chunk_into(data, entry_file_id, base_offset, scan.scan_scratch);
            if !entry_scanned {
                scan.stats.archive.record_entry_scanned();
                entry_scanned = true;
            }

            debug_assert_eq!(
                base_offset.saturating_add(carry as u64),
                offset,
                "expected new-bytes start to align with base_offset + carry"
            );
            let new_bytes_start = base_offset.saturating_add(carry as u64);
            scan.scan_scratch.drop_prefix_findings(new_bytes_start);

            scan.pending.clear();
            scan.scan_scratch.drain_findings_into(scan.pending);

            scan.output.emit_findings_direct(
                scan.engine,
                entry_display,
                scan.pending,
                scan.stats,
            )?;

            scan.stats.chunks = scan.stats.chunks.saturating_add(1);
            scan.stats.bytes_scanned = scan.stats.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            if allowed_usize < n {
                let extra = (n - allowed_usize) as u64;
                if let Err(r) = charge_discarded_bytes(budgets, extra) {
                    if entry_partial_reason.is_none() {
                        entry_partial_reason = Some(r);
                    }
                    outcome = ArchiveEnd::Partial(r);
                    stop_archive = true;
                }
                break;
            }
        }

        if !stop_archive && remaining > 0 {
            if let Err(r) =
                discard_remaining_payload(input, budgets, scan.stream_buf.as_mut_slice(), remaining)
            {
                if entry_partial_reason.is_none() {
                    entry_partial_reason = Some(r);
                }
                outcome = ArchiveEnd::Partial(r);
                stop_archive = true;
            }
        }

        budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            scan.stats
                .archive
                .record_entry_partial(r, entry_display, false);
        }

        if stop_archive {
            break;
        }

        match cur_cursor.skip_padding_only(input, budgets, entry_pad) {
            Ok(Ok(())) => {}
            Ok(Err(r)) => {
                outcome = ArchiveEnd::Partial(r);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Partial(PartialReason::MalformedTar);
                break;
            }
        }
        cur_cursor.advance_entry_blocks(entry_size, entry_pad);
    }

    Ok(outcome)
}

fn scan_tar_file(
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
    let mut input = TarInput::Plain(file);
    scan_tar_stream(
        &mut input,
        parent_bytes,
        engine,
        archive,
        scratch,
        output,
        stats,
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
    let mut input = TarInput::Gzip(GzipStream::new(file));
    scan_tar_stream(
        &mut input,
        parent_bytes,
        engine,
        archive,
        scratch,
        output,
        stats,
        true,
    )
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
    let overlap = engine.required_overlap();
    let chunk_size = scratch.chunk_size.min(ARCHIVE_STREAM_READ_MAX);

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            stats.open_errors = stats.open_errors.saturating_add(1);
            stats.errors = stats.errors.saturating_add(1);
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    scratch.budgets.reset();
    if let Err(hit) = scratch.budgets.enter_archive() {
        return Ok(budget_hit_to_archive_end(hit));
    }

    let cursor = &mut scratch.zip_cursor;
    let open = match cursor.open(file, &mut scratch.budgets, archive) {
        Ok(open) => open,
        Err(_) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Skipped(ArchiveSkipReason::IoError));
        }
    };

    match open {
        ZipOpen::Ready => {}
        ZipOpen::Skip(r) => {
            scratch.budgets.exit_archive();
            if r == ArchiveSkipReason::UnsupportedFeature {
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry
                    | crate::archive::UnsupportedPolicy::FailArchive => {
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        return Ok(ArchiveEnd::Skipped(r));
                    }
                }
            }
            return Ok(ArchiveEnd::Skipped(r));
        }
        ZipOpen::Stop(r) => {
            scratch.budgets.exit_archive();
            return Ok(ArchiveEnd::Partial(r));
        }
    }

    let parent_bytes = path.as_os_str().as_encoded_bytes();
    let max_len = archive.max_virtual_path_len_per_entry;
    debug_assert!(scratch.path_budget_used.len() > 1);
    scratch.path_budget_used[1] = 0;

    let buf = &mut scratch.stream_buf;
    let mut outcome = ArchiveEnd::Scanned;

    loop {
        let (
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
            entry_display,
        ) = {
            let meta = match cursor.next_entry(&mut scratch.budgets, archive) {
                Ok(ZipNext::End) => break,
                Ok(ZipNext::Stop(r)) => {
                    outcome = ArchiveEnd::Partial(r);
                    break;
                }
                Ok(ZipNext::Entry(m)) => m,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    break;
                }
            };

            let (locator_kind, locator_value) = if meta.lfh_offset_valid {
                (b'z', meta.local_header_offset)
            } else {
                (b'c', meta.cdfh_offset)
            };
            let mut locator_buf = [0u8; LOCATOR_LEN];
            let locator = build_locator(&mut locator_buf, locator_kind, locator_value);
            let entry_display = {
                let c = scratch
                    .canon
                    .canonicalize(meta.name, DEFAULT_MAX_COMPONENTS, max_len);
                if c.had_traversal {
                    stats.archive.record_path_had_traversal();
                }
                if c.component_cap_exceeded {
                    stats.archive.record_component_cap_exceeded();
                }
                let entry_bytes = if meta.name_truncated {
                    stats.archive.record_path_truncated();
                    scratch.entry_display_buf.clear();
                    scratch.entry_display_buf.extend_from_slice(c.bytes);
                    apply_hash_suffix_truncation(
                        &mut scratch.entry_display_buf,
                        meta.name_hash64,
                        max_len,
                    );
                    scratch.entry_display_buf.as_slice()
                } else {
                    if c.truncated {
                        stats.archive.record_path_truncated();
                    }
                    c.bytes
                };
                scratch.vpaths[1]
                    .build_with_suffix(parent_bytes, entry_bytes, locator, max_len)
                    .bytes
            };

            let need = entry_display.len();
            if scratch.path_budget_used[1].saturating_add(need)
                > archive.max_virtual_path_bytes_per_archive
            {
                outcome = ArchiveEnd::Partial(PartialReason::PathBudgetExceeded);
                break;
            }
            scratch.path_budget_used[1] = scratch.path_budget_used[1].saturating_add(need);

            if meta.is_dir {
                stats.archive.record_entry_skipped(
                    EntrySkipReason::NonRegular,
                    entry_display,
                    false,
                );
                continue;
            }

            if meta.is_encrypted() {
                stats.archive.record_entry_skipped(
                    EntrySkipReason::EncryptedEntry,
                    entry_display,
                    false,
                );
                match archive.encrypted_policy {
                    crate::archive::EncryptedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::EncryptedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                    crate::archive::EncryptedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::EncryptedArchive);
                        break;
                    }
                }
            }
            if !meta.compression_supported() {
                stats.archive.record_entry_skipped(
                    EntrySkipReason::UnsupportedCompression,
                    entry_display,
                    false,
                );
                match archive.unsupported_policy {
                    crate::archive::UnsupportedPolicy::SkipWithTelemetry => {
                        continue;
                    }
                    crate::archive::UnsupportedPolicy::FailArchive => {
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                    crate::archive::UnsupportedPolicy::FailRun => {
                        scratch.abort_run = true;
                        outcome = ArchiveEnd::Skipped(ArchiveSkipReason::UnsupportedFeature);
                        break;
                    }
                }
            }

            (
                meta.flags,
                meta.method,
                meta.compressed_size,
                meta.uncompressed_size,
                meta.local_header_offset,
                meta.cdfh_offset,
                meta.lfh_offset_valid,
                meta.is_dir,
                meta.name_truncated,
                meta.name_hash64,
                entry_display,
            )
        };

        let meta = ZipEntryMeta {
            name: b"",
            flags,
            method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
        };

        scratch.budgets.begin_entry_scan();

        let mut reader = match cursor.open_entry_reader(&meta, &mut scratch.budgets) {
            Ok(Ok(r)) => r,
            Ok(Err(r)) => {
                if r == PartialReason::MalformedZip {
                    stats.archive.record_entry_skipped(
                        EntrySkipReason::CorruptEntry,
                        entry_display,
                        false,
                    );
                    scratch.budgets.end_entry(false);
                    continue;
                }
                outcome = ArchiveEnd::Partial(r);
                scratch.budgets.end_entry(false);
                break;
            }
            Err(_) => {
                outcome = ArchiveEnd::Skipped(ArchiveSkipReason::IoError);
                scratch.budgets.end_entry(false);
                break;
            }
        };

        let path_bytes = entry_display;
        let entry_file_id = alloc_virtual_file_id(&mut scratch.next_virtual_file_id);

        let mut last_comp = 0u64;
        let ratio_active = meta.method == 8;

        let mut offset: u64 = 0;
        let mut carry: usize = 0;
        let mut have: usize = 0;
        let mut entry_scanned = false;
        let mut entry_partial_reason: Option<PartialReason> = None;
        let mut stop_archive = false;

        loop {
            if carry > 0 && have > 0 {
                buf.copy_within(have - carry..have, 0);
            }

            let allowance = scratch
                .budgets
                .remaining_decompressed_allowance_with_ratio_probe(ratio_active);
            if allowance == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let read_max = chunk_size
                .min(buf.len().saturating_sub(carry))
                .min(allowance.min(u64::from(u32::MAX)) as usize);

            if read_max == 0 {
                if let ChargeResult::Clamp { hit, .. } = scratch.budgets.charge_decompressed_out(1)
                {
                    let r = budget_hit_to_partial_reason(hit);
                    entry_partial_reason = Some(r);
                    if !matches!(hit, BudgetHit::SkipEntry(_)) {
                        outcome = ArchiveEnd::Partial(r);
                        stop_archive = true;
                    }
                }
                break;
            }

            let dst = &mut buf[carry..carry + read_max];

            let n = match reader.read_decompressed(dst) {
                Ok(n) => n,
                Err(_) => {
                    outcome = ArchiveEnd::Partial(PartialReason::MalformedZip);
                    entry_partial_reason = Some(PartialReason::MalformedZip);
                    break;
                }
            };

            let now = reader.total_compressed();
            let delta = now.saturating_sub(last_comp);
            last_comp = now;
            if delta > 0 {
                scratch.budgets.charge_compressed_in(delta);
            }

            if n == 0 {
                break;
            }

            let (allowed, clamped) = apply_entry_budget_clamp(
                &mut scratch.budgets,
                n,
                &mut entry_partial_reason,
                &mut outcome,
                &mut stop_archive,
            );
            if allowed == 0 {
                break;
            }

            let allowed_usize = allowed as usize;
            let read_len = carry + allowed_usize;

            let base_offset = offset.saturating_sub(carry as u64);
            let data = &buf[..read_len];

            engine.scan_chunk_into(data, entry_file_id, base_offset, &mut scratch.scan_scratch);
            if !entry_scanned {
                stats.archive.record_entry_scanned();
                entry_scanned = true;
            }

            let new_bytes_start = offset;
            scratch.scan_scratch.drop_prefix_findings(new_bytes_start);

            scratch.pending.clear();
            scratch
                .scan_scratch
                .drain_findings_into(&mut scratch.pending);

            output.emit_findings_direct(engine, path_bytes, &scratch.pending, stats)?;

            stats.chunks = stats.chunks.saturating_add(1);
            stats.bytes_scanned = stats.bytes_scanned.saturating_add(allowed);

            offset = offset.saturating_add(allowed);
            have = read_len;
            carry = overlap.min(read_len);

            if clamped {
                break;
            }
        }

        scratch.budgets.end_entry(offset > 0);
        if let Some(r) = entry_partial_reason {
            stats.archive.record_entry_partial(r, path_bytes, false);
        }
        if stop_archive {
            break;
        }
    }

    scratch.budgets.exit_archive();
    Ok(outcome)
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
            tail: vec![0u8; overlap],
            tail_len: 0,
        }
    }

    fn reset(&mut self) {
        self.active = None;
        self.tail_len = 0;
    }

    fn is_idle(&self) -> bool {
        self.active.is_none()
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
        chunk_ring: &mut SpscRing<Chunk, CHUNK_CAP>,
        pool: &BufferPool,
        files: &FileTable,
        engine: &Engine,
        archive: &ArchiveConfig,
        archive_scratch: &mut ArchiveScratch,
        output: &mut OutputStage,
        stats: &mut PipelineStats,
    ) -> io::Result<bool> {
        let mut progressed = false;

        if archive_scratch.abort_run {
            self.active = None;
            self.tail_len = 0;
            return Ok(progressed);
        }

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
                    if archive_scratch.abort_run {
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
                            if archive_scratch.abort_run {
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
///
/// Findings are buffered in `pending` to honor output backpressure without
/// stalling chunk consumption permanently.
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

    fn reset(&mut self) {
        self.pending.clear();
        self.pending_idx = 0;
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
        #[cfg(not(feature = "b64-stats"))]
        let _ = stats;
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
        stats: &mut PipelineStats,
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
            stats.findings = stats.findings.wrapping_add(1);
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
    chunk_ring: SpscRing<Chunk, CHUNK_CAP>,
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
        let scanner = ScanStage::new(&engine);
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
        self.archive_scratch.abort_run = false;
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
                &mut self.chunk_ring,
                &mut self.out_ring,
                stats,
            );
            if !self.archive_scratch.abort_run {
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

            let aborting = self.archive_scratch.abort_run;
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
    use crate::archive::{ArchiveBudgets, ArchiveConfig, PartialReason};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
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

    #[test]
    fn pipeline_zip_budget_clamp_charges_discarded_bytes() {
        let cfg = ArchiveConfig {
            max_uncompressed_bytes_per_entry: 4,
            max_total_uncompressed_bytes_per_archive: 5,
            max_total_uncompressed_bytes_per_root: 5,
            ..ArchiveConfig::default()
        };

        let mut budgets = ArchiveBudgets::new(&cfg);
        assert!(budgets.enter_archive().is_ok());
        budgets.begin_entry_scan();

        let mut entry_partial_reason = None;
        let mut outcome = ArchiveEnd::Scanned;
        let mut stop_archive = false;

        let (allowed, clamped) = apply_entry_budget_clamp(
            &mut budgets,
            6,
            &mut entry_partial_reason,
            &mut outcome,
            &mut stop_archive,
        );

        assert_eq!(allowed, 4);
        assert!(clamped);
        assert!(stop_archive);
        assert_eq!(budgets.root_decompressed_out(), 5);
        assert_eq!(
            outcome,
            ArchiveEnd::Partial(PartialReason::ArchiveOutputBudgetExceeded)
        );
    }
}
