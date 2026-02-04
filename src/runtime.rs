//! Runtime utilities for scanning: file tables, buffer pools, and chunk readers.
//!
//! # Scope
//! This module provides the single-threaded building blocks used by the
//! pipeline and synchronous scanner: a columnar file table, a fixed-size buffer
//! pool, and helpers to read files into overlap-preserving chunks.
//!
//! # Invariants and trade-offs
//! - Buffers are fixed-size and aligned; chunk + overlap must fit in
//!   `BUFFER_LEN_MAX`.
//! - The buffer pool is intentionally single-threaded (`Rc` + `UnsafeCell`).
//! - On Unix, paths live in a fixed-capacity byte arena; overflow is a hard
//!   error to keep allocations predictable. Archive expansion should use the
//!   fallible `try_*` APIs to avoid panics on hostile inputs.
//! - `Chunk::base_offset` always refers to the start of the chunk including
//!   overlap, which keeps span reporting consistent across boundaries.
//!
//! # Concurrency
//! The types in this module are not thread-safe. `BufferPool` and
//! `ScannerRuntime` are `Rc`-backed and assume single-threaded access. If the
//! pipeline becomes multi-threaded, use per-thread runtimes or a synchronized
//! buffer pool.

use crate::api::{FileId, Finding};
use crate::engine::{Engine, ScanScratch};
use crate::pool::NodePoolType;
#[cfg(unix)]
use crate::scratch_memory::ScratchVec;
use std::cell::{Cell, UnsafeCell};
use std::fs::File;
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::rc::Rc;
use std::slice;
use std::sync::Arc;

// --------------------------
// Pipeline data types
// --------------------------

/// File table flag: input appears to be binary.
pub const FILE_FLAG_BINARY: u32 = 1 << 0;
/// File table flag: file was skipped by the pipeline.
pub const FILE_FLAG_SKIPPED: u32 = 1 << 1;

/// Columnar file metadata store used by the pipeline.
///
/// Uses parallel vectors (SoA) to keep memory usage simple and allow stable
/// indexing via [`FileId`]. On Unix, paths are stored in a fixed-capacity
/// byte arena referenced by [`PathSpan`] to avoid per-file heap allocation
/// after startup. The arena never grows; capacity overruns are treated as
/// configuration bugs and will panic.
///
/// `FileId` values are stable indices into the current table. The table is
/// append-only between calls to [`clear`](Self::clear); clearing invalidates
/// all prior `FileId`s and any `Path`/`PathSpan` references.
///
/// On Unix, [`FileTable::path`] returns a `Path` backed by the arena. Those
/// borrows are only valid until the table is cleared for the next scan.
pub struct FileTable {
    #[cfg(unix)]
    path_spans: Vec<PathSpan>,
    #[cfg(unix)]
    path_bytes: ScratchVec<u8>,
    #[cfg(not(unix))]
    paths: Vec<PathBuf>,
    sizes: Vec<u64>,
    dev_inodes: Vec<(u64, u64)>,
    flags: Vec<u32>,
}

impl FileTable {
    /// Creates a table with capacity hints for the parallel arrays.
    pub fn with_capacity(cap: usize) -> Self {
        let path_bytes_cap = cap.saturating_mul(FILETABLE_PATH_BYTES_PER_FILE_DEFAULT);
        Self::with_capacity_and_path_bytes(cap, path_bytes_cap)
    }

    /// Creates a table with explicit capacity for path storage.
    ///
    /// `path_bytes_cap` is the total byte budget for the Unix path arena; it is
    /// ignored on non-Unix platforms. The arena stores raw bytes (not
    /// NUL-terminated) and must fit within `u32::MAX`.
    ///
    /// # Panics
    /// Panics if `path_bytes_cap` exceeds `u32::MAX`, or if allocating the Unix
    /// path arena fails.
    pub fn with_capacity_and_path_bytes(cap: usize, path_bytes_cap: usize) -> Self {
        #[cfg(unix)]
        {
            assert!(
                path_bytes_cap <= u32::MAX as usize,
                "path byte capacity exceeds u32::MAX"
            );
            let path_bytes = ScratchVec::with_capacity(path_bytes_cap)
                .expect("file table path bytes allocation failed");
            Self {
                path_spans: Vec::with_capacity(cap),
                path_bytes,
                sizes: Vec::with_capacity(cap),
                dev_inodes: Vec::with_capacity(cap),
                flags: Vec::with_capacity(cap),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path_bytes_cap;
            Self {
                paths: Vec::with_capacity(cap),
                sizes: Vec::with_capacity(cap),
                dev_inodes: Vec::with_capacity(cap),
                flags: Vec::with_capacity(cap),
            }
        }
    }

    /// Inserts a new file record and returns its [`FileId`].
    ///
    /// On Unix, the path bytes are appended to the internal arena; on non-Unix
    /// platforms the `PathBuf` is stored directly.
    ///
    /// # Panics
    /// Panics if the table capacity is exceeded or if the Unix path arena would
    /// overflow.
    pub fn push(&mut self, path: PathBuf, size: u64, dev_inode: (u64, u64), flags: u32) -> FileId {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let bytes = path.as_os_str().as_bytes();
            self.push_path_bytes(bytes, size, dev_inode, flags)
        }
        #[cfg(not(unix))]
        {
            assert!(
                self.sizes.len() < self.sizes.capacity(),
                "file table capacity exceeded"
            );
            assert!(self.sizes.len() < u32::MAX as usize);
            let id = FileId(self.sizes.len() as u32);
            self.paths.push(path);
            self.sizes.push(size);
            self.dev_inodes.push(dev_inode);
            self.flags.push(flags);
            id
        }
    }

    /// Inserts a new file record from raw path bytes (Unix only).
    ///
    /// # Panics
    /// Panics if the path arena would overflow or if table capacity is
    /// exceeded.
    #[cfg(unix)]
    pub(crate) fn push_path_bytes(
        &mut self,
        bytes: &[u8],
        size: u64,
        dev_inode: (u64, u64),
        flags: u32,
    ) -> FileId {
        let span = self.alloc_path_span(bytes);
        self.push_span(span, size, dev_inode, flags)
    }

    /// Attempts to reserve space for path bytes and returns a span (Unix only).
    ///
    /// This is the non-panicking variant used by archive expansion.
    /// Returns `None` if the path arena would overflow or if spans would
    /// not fit in `u32`.
    #[cfg(unix)]
    pub(crate) fn try_push_path_bytes(&mut self, bytes: &[u8]) -> Option<PathSpan> {
        self.try_alloc_path_span(bytes)
    }

    /// Reserves space for a path and returns its span (Unix only).
    ///
    /// Bytes are appended verbatim to the arena (no separators inserted).
    /// Panics if the arena would overflow; callers should pre-size
    /// `path_bytes_cap` for worst-case scans.
    ///
    /// # Panics
    /// Panics if the arena would overflow or if the resulting span would not
    /// fit in `u32`.
    #[cfg(unix)]
    pub(crate) fn alloc_path_span(&mut self, bytes: &[u8]) -> PathSpan {
        let start = self.path_bytes.len();
        let new_len = start.saturating_add(bytes.len());
        assert!(
            new_len <= self.path_bytes.capacity(),
            "path arena exhausted"
        );
        assert!(new_len <= u32::MAX as usize, "path bytes overflow u32");
        self.path_bytes.extend_from_slice(bytes);
        PathSpan {
            offset: start as u32,
            len: bytes.len() as u32,
        }
    }

    /// Fallible variant of `alloc_path_span` (Unix only).
    #[cfg(unix)]
    fn try_alloc_path_span(&mut self, bytes: &[u8]) -> Option<PathSpan> {
        let start = self.path_bytes.len();
        let new_len = start.saturating_add(bytes.len());
        if new_len > self.path_bytes.capacity() {
            return None;
        }
        if new_len > u32::MAX as usize {
            return None;
        }
        if bytes.len() > u32::MAX as usize {
            return None;
        }
        self.path_bytes.extend_from_slice(bytes);
        Some(PathSpan {
            offset: start as u32,
            len: bytes.len() as u32,
        })
    }

    /// Appends `parent` + "/" + `name` into the path arena (Unix only).
    ///
    /// This mirrors `Path::join` without normalization: it inserts a `/` only
    /// when `parent` is non-empty and does not already end with `/`.
    /// Panics if the arena would overflow.
    ///
    /// # Panics
    /// Panics if `parent` does not refer to bytes inside this arena or if the
    /// arena would overflow.
    #[cfg(unix)]
    pub(crate) fn join_path_span(&mut self, parent: PathSpan, name: &[u8]) -> PathSpan {
        let parent_start = parent.offset as usize;
        let parent_len = parent.len as usize;
        assert!(
            parent_start.saturating_add(parent_len) <= self.path_bytes.len(),
            "parent path span out of bounds"
        );

        let need_sep = if parent_len == 0 {
            false
        } else {
            let last = *self
                .path_bytes
                .get(parent_start + parent_len - 1)
                .expect("parent path span empty");
            last != b'/'
        };

        let start = self.path_bytes.len();
        let extra = if need_sep { 1 } else { 0 };
        let new_len = start
            .saturating_add(parent_len)
            .saturating_add(extra)
            .saturating_add(name.len());
        assert!(
            new_len <= self.path_bytes.capacity(),
            "path arena exhausted"
        );
        assert!(new_len <= u32::MAX as usize, "path bytes overflow u32");

        self.path_bytes
            .extend_from_self_range(parent_start, parent_len);
        if need_sep {
            self.path_bytes.push(b'/');
        }
        self.path_bytes.extend_from_slice(name);

        PathSpan {
            offset: start as u32,
            len: (parent_len + extra + name.len()) as u32,
        }
    }

    /// Inserts a new file record using a previously allocated span (Unix only).
    ///
    /// `span` must refer to bytes in this table's path arena.
    ///
    /// # Panics
    /// Panics if table capacity is exceeded.
    #[cfg(unix)]
    pub(crate) fn push_span(
        &mut self,
        span: PathSpan,
        size: u64,
        dev_inode: (u64, u64),
        flags: u32,
    ) -> FileId {
        assert!(
            self.sizes.len() < self.sizes.capacity(),
            "file table capacity exceeded"
        );
        assert!(
            self.path_spans.len() < self.path_spans.capacity(),
            "file table path span capacity exceeded"
        );
        assert!(self.sizes.len() < u32::MAX as usize);
        let id = FileId(self.sizes.len() as u32);
        self.path_spans.push(span);
        self.sizes.push(size);
        self.dev_inodes.push(dev_inode);
        self.flags.push(flags);
        id
    }

    /// Non-panicking variant of `push_span` (Unix only).
    ///
    /// Returns `None` if the table capacity is exceeded or if the span is invalid.
    #[cfg(unix)]
    pub(crate) fn try_push_span(
        &mut self,
        span: PathSpan,
        size: u64,
        dev_inode: (u64, u64),
        flags: u32,
    ) -> Option<FileId> {
        let start = span.offset as usize;
        let end = start.saturating_add(span.len as usize);
        if end > self.path_bytes.len() {
            return None;
        }
        if self.sizes.len() >= self.sizes.capacity() {
            return None;
        }
        if self.path_spans.len() >= self.path_spans.capacity() {
            return None;
        }
        if self.sizes.len() >= u32::MAX as usize {
            return None;
        }
        let id = FileId(self.sizes.len() as u32);
        self.path_spans.push(span);
        self.sizes.push(size);
        self.dev_inodes.push(dev_inode);
        self.flags.push(flags);
        Some(id)
    }

    /// Inserts a "virtual file" (for example an archive entry) with explicit display bytes.
    ///
    /// This is used by archive scanning so output formatting can still read
    /// a path from `FileTable` without panicking on path arena overflow.
    ///
    /// Callers that bypass `FileTable` should still ensure virtual `FileId` values
    /// are unique and isolated from real files (for example, by using a high-bit
    /// namespace) to avoid cross-file engine state leakage.
    pub fn try_insert_virtual(
        &mut self,
        display_bytes: &[u8],
        size_hint: u64,
        flags: u32,
    ) -> Option<FileId> {
        let dev_inode = (0u64, 0u64);

        #[cfg(unix)]
        {
            let span = self.try_alloc_path_span(display_bytes)?;
            self.try_push_span(span, size_hint, dev_inode, flags)
        }

        #[cfg(not(unix))]
        {
            if self.sizes.len() >= self.sizes.capacity() {
                return None;
            }
            if self.paths.len() >= self.paths.capacity() {
                return None;
            }
            if self.sizes.len() >= u32::MAX as usize {
                return None;
            }

            let path_str = std::str::from_utf8(display_bytes)
                .map(|s| s.to_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(display_bytes).to_string());
            let id = FileId(self.sizes.len() as u32);
            self.paths.push(PathBuf::from(path_str));
            self.sizes.push(size_hint);
            self.dev_inodes.push(dev_inode);
            self.flags.push(flags);
            Some(id)
        }
    }

    /// Returns the number of tracked files.
    pub fn len(&self) -> usize {
        self.sizes.len()
    }

    /// Clears all tracked files while retaining allocated capacity.
    ///
    /// This invalidates all previously returned `FileId`s. On Unix, it also
    /// invalidates any `Path`/`PathSpan` references into the arena.
    pub fn clear(&mut self) {
        #[cfg(unix)]
        {
            self.path_spans.clear();
            self.path_bytes.clear();
        }
        #[cfg(not(unix))]
        {
            self.paths.clear();
        }
        self.sizes.clear();
        self.dev_inodes.clear();
        self.flags.clear();
    }

    /// Returns true when the table is empty.
    pub fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }

    /// Returns the path for a given file id.
    ///
    /// On Unix, the returned `Path` borrows from the internal arena and may
    /// contain non-UTF8 bytes. It is only valid until the next `clear`.
    ///
    /// # Panics
    /// Panics if `id` does not refer to an entry in this table.
    pub fn path(&self, id: FileId) -> &Path {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let span = self.path_spans[id.0 as usize];
            let start = span.offset as usize;
            let end = start + span.len as usize;
            let bytes = &self.path_bytes.as_slice()[start..end];
            Path::new(OsStr::from_bytes(bytes))
        }
        #[cfg(not(unix))]
        {
            &self.paths[id.0 as usize]
        }
    }

    /// Returns the file size for a given file id.
    pub fn size(&self, id: FileId) -> u64 {
        self.sizes[id.0 as usize]
    }

    /// Returns stored flags for a given file id.
    pub fn flags(&self, id: FileId) -> u32 {
        self.flags[id.0 as usize]
    }
}

impl Default for FileTable {
    fn default() -> Self {
        Self::with_capacity_and_path_bytes(0, 0)
    }
}

/// Byte span into the Unix path arena stored by [`FileTable`].
///
/// `offset` and `len` are byte indices into the arena; the bytes are not
/// NUL-terminated and may be non-UTF8. Spans are only valid until the table
/// is cleared for reuse.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PathSpan {
    offset: u32,
    len: u32,
}

/// Default path byte budget per file for `FileTable::with_capacity`.
const FILETABLE_PATH_BYTES_PER_FILE_DEFAULT: usize = 256;

/// A chunk of file data plus its overlap prefix.
///
/// `prefix_len` indicates how many bytes at the front are overlap from the
/// previous chunk. `payload()` excludes that prefix.
///
/// Invariants:
/// - `prefix_len <= len`
/// - `buf_offset + len <= BUFFER_LEN_MAX`
/// - `base_offset` points to the first byte in `data()`
pub struct Chunk {
    /// File identifier for this chunk.
    pub file_id: FileId,
    /// File offset where this chunk begins, including the overlap prefix.
    pub base_offset: u64,
    /// Total byte length of this chunk, including the overlap prefix.
    pub len: u32,
    /// Number of prefix bytes copied from the previous chunk.
    ///
    /// Invariants: `prefix_len <= len` and `len - prefix_len` is the payload
    /// length for newly read bytes.
    pub prefix_len: u32,
    /// Backing buffer for the chunk. Returned to the pool when dropped.
    pub buf: BufferHandle,
    /// Starting offset into `buf` where the chunk data begins.
    ///
    /// This is usually zero for buffered reads. For O_DIRECT reads with an
    /// aligned payload offset, it can be non-zero so the overlap prefix
    /// remains contiguous without scanning alignment padding.
    pub buf_offset: u32,
}

impl Chunk {
    /// Full data slice, including the overlap prefix.
    ///
    /// The slice length is `len` and starts at `buf_offset` into the backing
    /// buffer.
    pub fn data(&self) -> &[u8] {
        let start = self.buf_offset as usize;
        let end = start + self.len as usize;
        &self.buf.as_slice()[start..end]
    }

    /// Payload slice excluding the overlap prefix.
    ///
    /// The slice length is `len - prefix_len` and contains only newly read
    /// bytes from the file.
    pub fn payload(&self) -> &[u8] {
        let start = self.buf_offset as usize + self.prefix_len as usize;
        let end = self.buf_offset as usize + self.len as usize;
        &self.buf.as_slice()[start..end]
    }
}

/// Maximum chunk buffer length (bytes).
pub const BUFFER_LEN_MAX: usize = 8 * 1024 * 1024;
/// Alignment for pooled buffers (bytes).
pub const BUFFER_ALIGN: usize = 4096;

const _: () = {
    assert!(BUFFER_LEN_MAX > 0);
    assert!(BUFFER_LEN_MAX.is_power_of_two());
    assert!(BUFFER_ALIGN.is_power_of_two());
    assert!(BUFFER_ALIGN <= 4096);
    assert!(BUFFER_LEN_MAX.is_multiple_of(BUFFER_ALIGN));
};

/// Shared pool state with interior mutability for allocation-free chunk buffers.
///
/// This is intentionally single-threaded: we use `Rc` + `Cell` + `UnsafeCell`
/// for zero-overhead access. If/when the pipeline becomes multi-threaded, this
/// must be replaced with a thread-safe pool or per-thread pools.
struct BufferPoolInner {
    pool: UnsafeCell<NodePoolType<BUFFER_LEN_MAX, BUFFER_ALIGN>>,
    // Fast-path availability check to avoid touching the bitset on empty pools.
    available: Cell<u32>,
    capacity: u32,
}

impl BufferPoolInner {
    fn acquire_slot(&self) -> NonNull<u8> {
        let avail = self.available.get();
        debug_assert!(avail > 0, "buffer pool exhausted");

        // SAFETY: BufferPoolInner is single-threaded; this is the only
        // mutable access to the underlying pool for this call.
        let ptr = unsafe { (&mut *self.pool.get()).acquire() };
        self.available.set(avail - 1);

        ptr
    }

    fn release_slot(&self, ptr: NonNull<u8>) {
        // SAFETY: BufferPoolInner is single-threaded; `ptr` was obtained
        // from this pool and is not aliased after the handle drop.
        unsafe { (&mut *self.pool.get()).release(ptr) };

        let avail = self.available.get();
        let new_avail = avail + 1;
        debug_assert!(new_avail <= self.capacity);
        self.available.set(new_avail);
    }
}

/// Fixed-capacity pool of aligned buffers used for file chunks.
///
/// Each acquired buffer is returned to the pool when its [`BufferHandle`] drops.
/// This pool is `Rc`-backed and intended for single-threaded use.
///
/// Buffers are always `BUFFER_LEN_MAX` bytes and aligned to `BUFFER_ALIGN`.
#[derive(Clone)]
pub struct BufferPool(Rc<BufferPoolInner>);

impl BufferPool {
    /// Creates a buffer pool with `capacity` buffers.
    ///
    /// # Panics
    /// Panics if `capacity` is zero or exceeds `u32::MAX`.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        assert!(capacity <= u32::MAX as usize);

        let pool = NodePoolType::<BUFFER_LEN_MAX, BUFFER_ALIGN>::init(capacity as u32);

        Self(Rc::new(BufferPoolInner {
            pool: UnsafeCell::new(pool),
            available: Cell::new(capacity as u32),
            capacity: capacity as u32,
        }))
    }

    /// Attempts to acquire a buffer; returns `None` if the pool is exhausted.
    pub fn try_acquire(&self) -> Option<BufferHandle> {
        if self.0.available.get() == 0 {
            return None;
        }

        let ptr = self.0.acquire_slot();
        Some(BufferHandle {
            pool: Rc::clone(&self.0),
            ptr,
        })
    }

    /// Acquires a buffer, panicking if the pool is exhausted.
    pub fn acquire(&self) -> BufferHandle {
        self.try_acquire().expect("buffer pool exhausted")
    }

    /// Returns the fixed buffer length for this pool.
    pub fn buf_len(&self) -> usize {
        BUFFER_LEN_MAX
    }
}

/// RAII handle to a pool buffer, returned to the pool on drop.
///
/// The buffer contents are not automatically cleared between uses; call
/// [`clear`](Self::clear) if you need zeroed memory.
///
/// This handle is not `Send`/`Sync` because the underlying pool is `Rc`-backed.
pub struct BufferHandle {
    pool: Rc<BufferPoolInner>,
    ptr: NonNull<u8>,
}

impl BufferHandle {
    /// Returns a shared view over the entire buffer.
    ///
    /// The slice length is always `BUFFER_LEN_MAX`. The bytes may contain
    /// leftover data from previous uses.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to a `BUFFER_LEN_MAX`-byte allocation owned
        // by the pool and is valid for the lifetime of this handle.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Returns a mutable view over the entire buffer.
    ///
    /// The slice length is always `BUFFER_LEN_MAX`.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is uniquely borrowed via `&mut self` for this call.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Zeroes the entire buffer.
    ///
    /// This is O(`BUFFER_LEN_MAX`) and may be skipped when overwriting the
    /// whole buffer anyway.
    pub fn clear(&mut self) {
        self.as_mut_slice().fill(0);
    }
}

impl Drop for BufferHandle {
    fn drop(&mut self) {
        let ptr = self.ptr;
        self.pool.release_slot(ptr);
    }
}

/// Reads a file in fixed-size chunks, preserving overlap between chunks.
///
/// The overlap allows anchor windows to extend across chunk boundaries without
/// missing matches. Each emitted `Chunk` includes:
/// - `prefix_len`: bytes copied from the previous chunk tail
/// - `base_offset`: file offset where the chunk *starts* in the original file
///
/// This makes span reporting consistent even when a match begins in the overlap.
///
/// The caller provides the overlap `tail` buffer to avoid per-scan allocations.
///
/// # Behavior
/// - Calls `emit` once per non-empty chunk; empty files emit nothing.
/// - The final chunk may be shorter than `chunk_size`.
/// - If `emit` returns `ControlFlow::Break`, reading stops early and returns
///   `Ok(())`.
/// - `tail` is used as scratch storage; its contents after return are
///   unspecified.
/// - If the `emit` closure retains chunks, the buffer pool must be sized
///   accordingly to avoid exhausting available buffers.
///
/// # Errors
/// Returns any I/O error from opening or reading the file.
///
/// # Panics
/// Panics if `chunk_size` is zero, if `chunk_size + overlap > BUFFER_LEN_MAX`,
/// or if `overlap > tail.len()`.
pub fn read_file_chunks(
    file_id: FileId,
    path: &Path,
    pool: &BufferPool,
    chunk_size: usize,
    overlap: usize,
    tail: &mut [u8],
    mut emit: impl FnMut(Chunk) -> ControlFlow<()>,
) -> io::Result<()> {
    assert!(chunk_size > 0);
    assert!(chunk_size.saturating_add(overlap) <= BUFFER_LEN_MAX);
    assert!(
        overlap <= tail.len(),
        "overlap exceeds provided tail buffer"
    );
    let mut file = File::open(path)?;
    let mut tail_len = 0usize;
    let mut offset = 0u64;

    loop {
        let mut handle = pool.acquire();
        let buf = handle.as_mut_slice();
        debug_assert!(tail_len <= tail.len());
        debug_assert!(buf.len() >= tail_len + chunk_size);

        if tail_len > 0 {
            buf[..tail_len].copy_from_slice(&tail[..tail_len]);
        }

        let read = file.read(&mut buf[tail_len..tail_len + chunk_size])?;
        if read == 0 {
            break;
        }

        let total_len = tail_len + read;
        let base_offset = offset.saturating_sub(tail_len as u64);
        let next_tail_len = if overlap > 0 {
            let keep = overlap.min(total_len);
            tail[..keep].copy_from_slice(&buf[total_len - keep..total_len]);
            keep
        } else {
            0
        };

        let chunk = Chunk {
            file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: tail_len as u32,
            buf: handle,
            buf_offset: 0,
        };

        if let ControlFlow::Break(()) = emit(chunk) {
            break;
        }

        tail_len = next_tail_len;

        offset = offset.saturating_add(read as u64);
    }

    Ok(())
}

/// Configuration for synchronous, in-process scanning.
///
/// Callers are responsible for choosing values that keep
/// `chunk_size + overlap <= BUFFER_LEN_MAX` (overlap is derived from the
/// [`Engine`]) and yield a non-zero [`pool_capacity`](Self::pool_capacity).
pub struct ScannerConfig {
    /// Bytes per chunk read from disk (excluding overlap).
    ///
    /// Must be > 0 and sized so `chunk_size + overlap <= BUFFER_LEN_MAX`.
    pub chunk_size: usize,
    /// Number of in-flight I/O buffers.
    ///
    /// Used only for sizing the internal buffer pool.
    pub io_queue: usize,
    /// Reader thread count used by the caller (for pool sizing).
    ///
    /// The runtime itself is single-threaded; this is a sizing hint.
    pub reader_threads: usize,
    /// Scan thread count used by the caller (for pool sizing).
    ///
    /// The runtime itself is single-threaded; this is a sizing hint.
    pub scan_threads: usize,
    /// Maximum number of findings retained per file.
    ///
    /// If exceeded, scanning stops early and returns an error.
    pub max_findings_per_file: usize,
}

impl ScannerConfig {
    /// Computes the backing buffer pool capacity needed for this configuration.
    ///
    /// The formula reserves enough buffers for IO + scan staging and avoids
    /// allocations during steady-state scanning.
    pub fn pool_capacity(&self) -> usize {
        self.io_queue
            .saturating_add(self.scan_threads.saturating_mul(2))
            .saturating_add(self.reader_threads)
    }
}

/// Single-process scanner that reuses buffers and scratch state.
///
/// This runtime uses `Rc`-backed pools internally and is intended for
/// single-threaded use. Results are stored in an internal buffer with a fixed
/// capacity set at construction time.
///
/// The slice returned by [`scan_file_sync`](Self::scan_file_sync) is borrowed
/// from this internal buffer and is only valid until the next scan.
pub struct ScannerRuntime {
    engine: Arc<Engine>,
    config: ScannerConfig,
    overlap: usize,
    pool: BufferPool,
    scratch: ScanScratch,
    out: Vec<Finding>,
    tail: Vec<u8>,
}

impl ScannerRuntime {
    /// Creates a scanner runtime with its own buffer pool and overlap settings.
    ///
    /// # Panics
    /// Panics if `config.chunk_size + engine.required_overlap()` exceeds
    /// `BUFFER_LEN_MAX` or if the computed pool capacity is zero.
    pub fn new(engine: Arc<Engine>, config: ScannerConfig) -> Self {
        let overlap = engine.required_overlap();
        let buf_len = overlap.saturating_add(config.chunk_size);
        assert!(
            buf_len <= BUFFER_LEN_MAX,
            "chunk_size + overlap exceeds BUFFER_LEN_MAX"
        );
        let pool = BufferPool::new(config.pool_capacity());
        let scratch = engine.new_scratch();
        let out = Vec::with_capacity(config.max_findings_per_file);
        let tail = vec![0u8; overlap];
        Self {
            engine,
            config,
            overlap,
            pool,
            scratch,
            out,
            tail,
        }
    }

    /// Scans a single file synchronously, returning findings with provenance.
    ///
    /// Findings are stored in an internal fixed-capacity buffer sized at
    /// startup. If the capacity is exceeded, scanning stops early and an error
    /// is returned; callers should treat the results as incomplete.
    ///
    /// # Errors
    /// Returns any I/O error from reading the file. If the findings buffer
    /// overflows, returns `io::ErrorKind::Other` after stopping the scan early.
    pub fn scan_file_sync(&mut self, file_id: FileId, path: &Path) -> io::Result<&[Finding]> {
        self.out.clear();
        let mut overflow = false;

        let engine = &self.engine;
        let pool = &self.pool;
        let chunk_size = self.config.chunk_size;
        let overlap = self.overlap;
        let tail = &mut self.tail;
        let scratch = &mut self.scratch;
        let out = &mut self.out;

        read_file_chunks(file_id, path, pool, chunk_size, overlap, tail, |chunk| {
            engine.scan_chunk_into(chunk.data(), chunk.file_id, chunk.base_offset, scratch);
            let new_bytes_start = chunk.base_offset + chunk.prefix_len as u64;
            scratch.drop_prefix_findings(new_bytes_start);

            let pending = scratch.pending_findings_len();
            if out.len().saturating_add(pending) > out.capacity() {
                overflow = true;
                return ControlFlow::Break(());
            }

            engine.drain_findings_materialized(scratch, out);
            ControlFlow::Continue(())
        })?;

        if overflow {
            return Err(io::Error::from(io::ErrorKind::Other));
        }

        Ok(self.out.as_slice())
    }
}

#[cfg(all(test, unix))]
mod tests_filetable_try {
    use super::*;

    #[test]
    fn try_push_path_bytes_respects_arena_budget() {
        let mut t = FileTable::with_capacity_and_path_bytes(1, 4);
        assert!(t.try_push_path_bytes(b"abcd").is_some());
        assert!(t.try_push_path_bytes(b"e").is_none());
    }

    #[test]
    fn try_insert_virtual_respects_file_capacity() {
        let mut t = FileTable::with_capacity_and_path_bytes(2, 64);
        let a = t.try_insert_virtual(b"a", 1, 0);
        let b = t.try_insert_virtual(b"b", 1, 0);
        let c = t.try_insert_virtual(b"c", 1, 0);
        assert!(a.is_some());
        assert!(b.is_some());
        assert!(c.is_none());
    }
}
