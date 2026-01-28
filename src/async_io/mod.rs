//! Asynchronous IO backends for single-threaded, overlapped scan + read.
//!
//! This module provides:
//! - Linux io_uring with aligned payload offsets (O_DIRECT-ready).
//! - macOS POSIX AIO with read-ahead and overlap preservation.
//!
//! Both backends keep the scan loop single-threaded while overlapping IO.
//!
//! # Invariants and budgets
//! - `chunk_size` is aligned and sized to leave room for overlap in
//!   `BUFFER_LEN_MAX`.
//! - Queue depth must be >= 2 to overlap read/scan without stalling.
//! - Unix path storage uses a fixed-size arena; overruns are treated as
//!   configuration errors to keep allocation predictable.

use crate::pipeline::PipelineStats;
use crate::scratch_memory::ScratchVec;
use crate::{FileId, FileTable, BUFFER_ALIGN, BUFFER_LEN_MAX};
#[cfg(not(unix))]
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;

#[cfg(unix)]
use crate::runtime::PathSpan;
#[cfg(unix)]
use std::ffi::CStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::io::RawFd;

/// Default chunk size for async IO scanners (bytes).
///
/// A value of 0 means "auto", resolved to the maximum aligned size that still
/// leaves room for the overlap prefix within `BUFFER_LEN_MAX`.
pub const ASYNC_DEFAULT_CHUNK_SIZE: usize = 0;

/// Default queue depth for async submissions.
///
/// The Linux implementation uses a **single in-flight read** plus the current
/// scan buffer; macOS uses a small read-ahead window. A depth of 2 is the
/// minimal setting for overlap.
pub const ASYNC_DEFAULT_QUEUE_DEPTH: u32 = 2;

/// Default maximum number of files to scan.
pub const ASYNC_MAX_FILES: usize = crate::pipeline::PIPE_MAX_FILES;
/// Default per-file path byte budget for async scanners.
pub const ASYNC_PATH_BYTES_PER_FILE: usize = 256;

/// Maximum depth for the DFS walker stack.
///
/// Filesystem paths are bounded by depth (~255 components on most systems),
/// NOT by file count. 1024 handles any realistic directory tree.
const WALKER_STACK_CAP: usize = 1024;

/// Configuration shared by async backends.
#[derive(Clone, Debug)]
pub struct AsyncIoConfig {
    /// Bytes read per chunk (excluding overlap). Use 0 for the maximum size.
    ///
    /// A value of 0 is resolved to the largest aligned chunk that fits after
    /// reserving overlap bytes.
    pub chunk_size: usize,
    /// Maximum number of files to scan from a path walk.
    pub max_files: usize,
    /// Total byte capacity reserved for path storage (0 = auto).
    ///
    /// On Unix this is the fixed-size path arena budget; on non-Unix it is
    /// ignored. Exceeding the arena is treated as a configuration bug and will
    /// fail fast rather than allocate.
    pub path_bytes_cap: usize,
    /// Submission queue depth (io_uring) / read-ahead depth (macOS AIO).
    pub queue_depth: u32,
    /// Enable O_DIRECT for the aligned portion of reads on Linux.
    pub use_o_direct: bool,
}

impl Default for AsyncIoConfig {
    fn default() -> Self {
        let max_files = ASYNC_MAX_FILES;
        Self {
            chunk_size: ASYNC_DEFAULT_CHUNK_SIZE,
            max_files,
            path_bytes_cap: max_files.saturating_mul(ASYNC_PATH_BYTES_PER_FILE),
            queue_depth: ASYNC_DEFAULT_QUEUE_DEPTH,
            use_o_direct: true,
        }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

fn align_down(value: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    value & !(align - 1)
}

fn align_down_u64(value: u64, align: u64) -> u64 {
    assert!(align.is_power_of_two());
    value & !(align - 1)
}

fn max_aligned_chunk_size(overlap: usize) -> usize {
    let max_chunk = BUFFER_LEN_MAX.saturating_sub(overlap);
    align_down(max_chunk, BUFFER_ALIGN)
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
    unsafe {
        libc::__error()
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::__errno_location()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    unsafe {
        libc::__errno_location()
    }
}

#[cfg(unix)]
fn set_errno(value: libc::c_int) {
    unsafe {
        *errno_ptr() = value;
    }
}

/// Calls `f` with a NUL-terminated copy of `path` in a fixed stack buffer.
///
/// Rejects paths containing NUL or longer than `PATH_MAX` to avoid heap
/// allocation when invoking libc APIs.
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

// --------------------------
// Path walking (async)
// --------------------------

#[cfg(not(unix))]
enum WalkEntry {
    Path(PathBuf),
    Dir(fs::ReadDir),
}

/// Depth-first walker that yields files in a locality-friendly order.
///
/// This mirrors the pipeline walk behavior but exposes a `next_file` iterator
/// for sequential async scanners.
#[cfg(not(unix))]
struct Walker {
    stack: ScratchVec<WalkEntry>,
    done: bool,
    max_files: usize,
}

#[cfg(not(unix))]
impl Walker {
    fn new(max_files: usize) -> io::Result<Self> {
        let stack = ScratchVec::with_capacity(WALKER_STACK_CAP)
            .map_err(|_| io::Error::other("async walker stack allocation failed"))?;
        Ok(Self {
            stack,
            done: false,
            max_files,
        })
    }

    fn reset(
        &mut self,
        root: &Path,
        _files: &mut FileTable,
        _stats: &mut PipelineStats,
    ) -> io::Result<()> {
        self.stack.clear();
        self.done = false;
        self.push_entry(WalkEntry::Path(root.to_path_buf()))
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn next_file(
        &mut self,
        files: &mut FileTable,
        stats: &mut PipelineStats,
    ) -> io::Result<Option<FileId>> {
        while let Some(entry) = self.stack.pop() {
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
                            Ok(rd) => self.push_entry(WalkEntry::Dir(rd))?,
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
                        return Ok(None);
                    }

                    let size = meta.len();
                    let dev_inode = dev_inode(&meta);
                    let id = files.push(path, size, dev_inode, 0);
                    stats.files += 1;
                    return Ok(Some(id));
                }
                WalkEntry::Dir(mut rd) => match rd.next() {
                    Some(Ok(entry)) => {
                        self.push_entry(WalkEntry::Dir(rd))?;
                        self.push_entry(WalkEntry::Path(entry.path()))?;
                    }
                    Some(Err(_)) => {
                        stats.walk_errors += 1;
                        stats.errors += 1;
                        self.push_entry(WalkEntry::Dir(rd))?;
                    }
                    None => {}
                },
            }
        }

        self.done = true;
        Ok(None)
    }

    fn push_entry(&mut self, entry: WalkEntry) -> io::Result<()> {
        if self.stack.len() >= self.stack.capacity() {
            return Err(io::Error::other("async walker stack overflow"));
        }
        self.stack.push(entry);
        Ok(())
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
        unsafe {
            libc::closedir(self.dirp);
        }
    }
}

/// Unix walker that avoids per-entry heap allocations.
///
/// Paths are stored in the `FileTable` arena and assembled with `openat` +
/// `readdir`, so the hot path stays allocation-free after startup.
/// The walker emits files in a DFS order and stops once `max_files` is reached.
#[cfg(unix)]
struct Walker {
    stack: ScratchVec<DirState>,
    done: bool,
    max_files: usize,
    // Root file staged until the caller drains it.
    pending: Option<FileId>,
}

#[cfg(unix)]
impl Walker {
    fn new(max_files: usize) -> io::Result<Self> {
        let stack = ScratchVec::with_capacity(WALKER_STACK_CAP)
            .map_err(|_| io::Error::other("async walker stack allocation failed"))?;
        Ok(Self {
            stack,
            done: true,
            max_files,
            pending: None,
        })
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
        let st = with_c_path(root, |c_path| unsafe {
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            if libc::lstat(c_path, st.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(st.assume_init())
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

    fn next_file(
        &mut self,
        files: &mut FileTable,
        stats: &mut PipelineStats,
    ) -> io::Result<Option<FileId>> {
        if let Some(id) = self.pending {
            self.pending = None;
            return Ok(Some(id));
        }

        while let Some(top) = self.stack.len().checked_sub(1) {
            let (dirp, dirfd, dir_path) = {
                let entry = self.stack.get(top).expect("walker stack entry");
                (entry.dirp, entry.fd, entry.path)
            };

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
                    return Ok(None);
                }

                let file_span = files.join_path_span(dir_path, name_bytes);
                let id = files.push_span(file_span, st.st_size as u64, dev_inode_from_stat(&st), 0);
                stats.files += 1;
                return Ok(Some(id));
            }
        }

        self.done = true;
        Ok(None)
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

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Platform-selected async scanner type.
///
/// - Linux: io_uring implementation.
/// - macOS: POSIX AIO implementation.
#[cfg(target_os = "linux")]
pub type AsyncScanner = linux::UringScanner;

#[cfg(target_os = "macos")]
pub type AsyncScanner = macos::MacosAioScanner;

#[cfg(target_os = "linux")]
pub use linux::UringScanner;

#[cfg(target_os = "macos")]
pub use macos::{AioScanner, MacosAioScanner};
