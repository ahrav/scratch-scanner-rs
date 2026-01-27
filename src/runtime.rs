use crate::api::{FileId, Finding};
use crate::engine::{Engine, ScanScratch};
use crate::pool::NodePoolType;
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
/// Uses parallel vectors (SoA) to keep memory note simple and allow stable
/// indexing via [`FileId`].
#[derive(Default)]
pub struct FileTable {
    paths: Vec<PathBuf>,
    sizes: Vec<u64>,
    dev_inodes: Vec<(u64, u64)>,
    flags: Vec<u32>,
}

impl FileTable {
    /// Creates a table with capacity hints for the parallel arrays.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            paths: Vec::with_capacity(cap),
            sizes: Vec::with_capacity(cap),
            dev_inodes: Vec::with_capacity(cap),
            flags: Vec::with_capacity(cap),
        }
    }

    /// Inserts a new file record and returns its [`FileId`].
    pub fn push(&mut self, path: PathBuf, size: u64, dev_inode: (u64, u64), flags: u32) -> FileId {
        assert!(self.paths.len() < u32::MAX as usize);
        let id = FileId(self.paths.len() as u32);
        self.paths.push(path);
        self.sizes.push(size);
        self.dev_inodes.push(dev_inode);
        self.flags.push(flags);
        id
    }

    /// Returns the number of tracked files.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Clears all tracked files while retaining allocated capacity.
    pub fn clear(&mut self) {
        self.paths.clear();
        self.sizes.clear();
        self.dev_inodes.clear();
        self.flags.clear();
    }

    /// Returns true when the table is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Returns the path for a given file id.
    pub fn path(&self, id: FileId) -> &PathBuf {
        &self.paths[id.0 as usize]
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

/// A chunk of file data plus its overlap prefix.
///
/// `prefix_len` indicates how many bytes at the front are overlap from the
/// previous chunk. `payload()` excludes that prefix.
pub struct Chunk {
    pub file_id: FileId,
    pub base_offset: u64,
    pub len: u32,
    pub prefix_len: u32,
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
    pub fn data(&self) -> &[u8] {
        let start = self.buf_offset as usize;
        let end = start + self.len as usize;
        &self.buf.as_slice()[start..end]
    }

    /// Payload slice excluding the overlap prefix.
    pub fn payload(&self) -> &[u8] {
        let start = self.buf_offset as usize + self.prefix_len as usize;
        let end = self.buf_offset as usize + self.len as usize;
        &self.buf.as_slice()[start..end]
    }
}

/// Maximum chunk buffer length (bytes).
pub const BUFFER_LEN_MAX: usize = 2 * 1024 * 1024;
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
        assert!(avail > 0, "buffer pool exhausted");

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
        assert!(new_avail <= self.capacity);
        self.available.set(new_avail);
    }
}

/// Fixed-capacity pool of aligned buffers used for file chunks.
///
/// Each acquired buffer is returned to the pool when its [`BufferHandle`] drops.
/// This pool is `Rc`-backed and intended for single-threaded use.
#[derive(Clone)]
pub struct BufferPool(Rc<BufferPoolInner>);

impl BufferPool {
    /// Creates a buffer pool with `capacity` buffers.
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
pub struct BufferHandle {
    pool: Rc<BufferPoolInner>,
    ptr: NonNull<u8>,
}

impl BufferHandle {
    /// Returns a shared view over the entire buffer.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to a `BUFFER_LEN_MAX`-byte allocation owned
        // by the pool and is valid for the lifetime of this handle.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Returns a mutable view over the entire buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `ptr` is uniquely borrowed via `&mut self` for this call.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), BUFFER_LEN_MAX) }
    }

    /// Zeroes the entire buffer.
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
        assert!(tail_len <= tail.len());
        assert!(buf.len() >= tail_len + chunk_size);

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
pub struct ScannerConfig {
    /// Bytes per chunk read from disk (excluding overlap).
    pub chunk_size: usize,
    /// Number of in-flight I/O buffers.
    pub io_queue: usize,
    /// Reader thread count used by the caller (for pool sizing).
    pub reader_threads: usize,
    /// Scan thread count used by the caller (for pool sizing).
    pub scan_threads: usize,
    /// Maximum number of findings retained per file.
    pub max_findings_per_file: usize,
}

impl ScannerConfig {
    /// Computes the backing buffer pool capacity needed for this configuration.
    pub fn pool_capacity(&self) -> usize {
        self.io_queue
            .saturating_add(self.scan_threads.saturating_mul(2))
            .saturating_add(self.reader_threads)
    }
}

/// Single-process scanner that reuses buffers and scratch state.
///
/// This runtime uses `Rc`-backed pools internally and is intended for
/// single-threaded use.
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
    /// startup. If the capacity is exceeded, an error is returned.
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
