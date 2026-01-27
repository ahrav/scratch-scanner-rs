//! Asynchronous IO backends for single-threaded, overlapped scan + read.
//!
//! This module provides:
//! - Linux io_uring with aligned payload offsets (O_DIRECT-ready).
//! - macOS POSIX AIO with read-ahead and overlap preservation.
//!
//! Both backends keep the scan loop single-threaded while overlapping IO.

use crate::pipeline::PipelineStats;
use crate::scratch_memory::ScratchVec;
use crate::{FileId, FileTable, BUFFER_ALIGN, BUFFER_LEN_MAX};
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

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
    pub chunk_size: usize,
    /// Maximum number of files to scan from a path walk.
    pub max_files: usize,
    /// Total byte capacity reserved for path storage (0 = auto).
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

// --------------------------
// Path walking (async)
// --------------------------

enum WalkEntry {
    Path(PathBuf),
    Dir(fs::ReadDir),
}

/// Depth-first walker that yields files in a locality-friendly order.
///
/// This mirrors the pipeline walk behavior but exposes a `next_file` iterator
/// for sequential async scanners.
struct Walker {
    stack: ScratchVec<WalkEntry>,
    done: bool,
    max_files: usize,
}

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

    fn reset(&mut self, root: PathBuf) -> io::Result<()> {
        self.stack.clear();
        self.done = false;
        self.push_entry(WalkEntry::Path(root))
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
