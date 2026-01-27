use super::*;
use crate::{BufferPool, Chunk, Engine, FindingRec, ScanScratch};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

mod aio {
    use super::*;
    use std::io;
    use std::ptr;

    #[cfg(test)]
    use std::cell::Cell;
    #[cfg(test)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(test)]
    thread_local! {
        static READ_EAGAIN_COUNT: Cell<usize> = const { Cell::new(0) };
        static SUSPEND_EINTR_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    #[cfg(test)]
    static RETURN_CALLS: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn read(cb: &mut libc::aiocb) -> io::Result<()> {
        #[cfg(test)]
        {
            let injected = READ_EAGAIN_COUNT.with(|count| {
                let remaining = count.get();
                if remaining > 0 {
                    count.set(remaining - 1);
                    true
                } else {
                    false
                }
            });
            if injected {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
        }

        // SAFETY: caller guarantees `cb` is valid and fully initialized.
        let ret = unsafe { libc::aio_read(cb) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn error(cb: &libc::aiocb) -> io::Result<i32> {
        // SAFETY: caller guarantees `cb` is valid and still in scope.
        let err = unsafe { libc::aio_error(cb) };
        if err == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(err)
    }

    pub(super) fn ret(cb: &mut libc::aiocb) -> io::Result<isize> {
        // SAFETY: caller guarantees the request has completed.
        let res = unsafe { libc::aio_return(cb) };
        #[cfg(test)]
        {
            RETURN_CALLS.fetch_add(1, Ordering::SeqCst);
        }
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(res)
    }

    pub(super) fn suspend(list: &[*const libc::aiocb]) -> io::Result<()> {
        #[cfg(test)]
        {
            let injected = SUSPEND_EINTR_COUNT.with(|count| {
                let remaining = count.get();
                if remaining > 0 {
                    count.set(remaining - 1);
                    true
                } else {
                    false
                }
            });
            if injected {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
        }

        // SAFETY: all aiocb pointers are valid for the duration of the call.
        let ret = unsafe { libc::aio_suspend(list.as_ptr(), list.len() as i32, ptr::null()) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn cancel(fd: RawFd, cb: &libc::aiocb) -> io::Result<i32> {
        // SAFETY: caller guarantees `cb` is valid and still in scope. The
        // kernel treats the aiocb as read-only for cancellation.
        let ret = unsafe { libc::aio_cancel(fd, cb as *const libc::aiocb as *mut libc::aiocb) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret)
    }

    #[cfg(test)]
    pub(super) fn inject_read_eagain(count: usize) {
        READ_EAGAIN_COUNT.with(|cell| cell.set(count));
    }

    #[cfg(test)]
    pub(super) fn inject_suspend_eintr(count: usize) {
        SUSPEND_EINTR_COUNT.with(|cell| cell.set(count));
    }

    #[cfg(test)]
    pub(super) fn return_call_count() -> usize {
        RETURN_CALLS.load(Ordering::SeqCst)
    }
}

// --------------------------
// macOS AIO design notes
// --------------------------
//
// Buffer layout for each read:
//   [prefix (overlap bytes)][payload]
//
// The payload is read into `payload_off`. The overlap prefix is stitched
// in after completion (right-aligned) so the scanner sees a contiguous
// prefix+payload slice without copying the payload or scanning padding.
//
// Ordering:
// - Each submission gets a monotonically increasing `seq`.
// - We emit chunks strictly in `seq` order even if completions are out of order.

/// macOS async scanner powered by POSIX AIO.
///
/// The scanner stays single-threaded and uses a fixed read-ahead depth
/// to overlap IO and scanning without unbounded buffering.
pub struct MacosAioScanner {
    engine: Arc<Engine>,
    config: AsyncIoConfig,
    overlap: usize,
    payload_off: usize,
    pool: BufferPool,
    scratch: ScanScratch,
    pending: Vec<FindingRec>,
    files: FileTable,
    walker: Walker,
    out: BufWriter<io::Stdout>,
}

impl MacosAioScanner {
    /// Creates a macOS AIO scanner with bounded buffers and overlap settings.
    pub fn new(engine: Arc<Engine>, mut config: AsyncIoConfig) -> io::Result<Self> {
        if config.queue_depth < 2 {
            return Err(io::Error::other(
                "queue_depth must be >= 2 for overlapped reads",
            ));
        }
        if config.path_bytes_cap == 0 {
            config.path_bytes_cap = config
                .max_files
                .saturating_mul(super::ASYNC_PATH_BYTES_PER_FILE);
        }

        let overlap = engine.required_overlap();
        if config.chunk_size == 0 {
            let max_chunk = max_aligned_chunk_size(overlap);
            if max_chunk == 0 {
                return Err(io::Error::other("overlap exceeds buffer size"));
            }
            config.chunk_size = max_chunk;
        }

        let payload_off = overlap;
        let buf_len = payload_off.saturating_add(config.chunk_size);
        if buf_len > BUFFER_LEN_MAX {
            return Err(io::Error::other("chunk_size + overlap exceeds buffer size"));
        }

        let pool = BufferPool::new(config.queue_depth as usize + 1);
        let scratch = engine.new_scratch();
        let pending = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
        let files =
            FileTable::with_capacity_and_path_bytes(config.max_files, config.path_bytes_cap);
        let walker = Walker::new(config.max_files)?;
        let out = BufWriter::new(io::stdout());

        Ok(Self {
            engine,
            config,
            overlap,
            payload_off,
            pool,
            scratch,
            pending,
            files,
            walker,
            out,
        })
    }

    /// Scans a path (file or directory) using POSIX AIO reads.
    pub fn scan_path(&mut self, path: &Path) -> io::Result<PipelineStats> {
        let mut stats = PipelineStats::default();
        let engine = Arc::clone(&self.engine);
        self.files.clear();
        self.pending.clear();
        self.walker.reset(path.to_path_buf())?;

        while !self.walker.is_done() {
            let Some(file_id) = self.walker.next_file(&mut self.files, &mut stats)? else {
                continue;
            };

            let file_path = self.files.path(file_id);
            let file_size = self.files.size(file_id);

            match scan_file(
                &self.pool,
                self.payload_off,
                self.overlap,
                self.config.chunk_size,
                self.config.queue_depth,
                &engine,
                &mut self.scratch,
                &mut self.pending,
                file_id,
                file_path,
                file_size,
                &mut self.out,
                &mut stats,
            ) {
                Ok(()) => {}
                Err(err) => {
                    if err.kind() == io::ErrorKind::NotFound {
                        stats.open_errors += 1;
                        stats.errors += 1;
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        self.out.flush()?;
        Ok(stats)
    }
}

#[allow(clippy::too_many_arguments)]
// Keep scan dependencies explicit so the hot path has no hidden state
// and the call site shows all mutable resources.
fn scan_file(
    pool: &BufferPool,
    payload_off: usize,
    overlap: usize,
    chunk_size: usize,
    queue_depth: u32,
    engine: &Engine,
    scratch: &mut ScanScratch,
    pending: &mut Vec<FindingRec>,
    file_id: FileId,
    path: &Path,
    file_size: u64,
    out: &mut BufWriter<io::Stdout>,
    stats: &mut PipelineStats,
) -> io::Result<()> {
    let mut reader = AioFileReader::new(
        pool,
        file_id,
        path,
        file_size,
        payload_off,
        overlap,
        chunk_size,
        queue_depth,
    )?;

    while let Some(chunk) = reader.next_chunk(pool)? {
        let payload_len = chunk.len.saturating_sub(chunk.prefix_len) as u64;
        stats.bytes_scanned = stats.bytes_scanned.saturating_add(payload_len);
        stats.chunks += 1;

        engine.scan_chunk_into(chunk.data(), chunk.file_id, chunk.base_offset, scratch);
        let new_bytes_start = chunk.base_offset + chunk.prefix_len as u64;
        scratch.drop_prefix_findings(new_bytes_start);
        scratch.drain_findings_into(pending);

        for rec in pending.drain(..) {
            let rule = engine.rule_name(rec.rule_id);
            write_path(out, path)?;
            write!(
                out,
                ":{}-{} {}",
                rec.root_hint_start, rec.root_hint_end, rule
            )?;
            out.write_all(b"\n")?;
            stats.findings += 1;
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AioSlotState {
    Empty,
    InFlight,
    Completed,
}

/// One in-flight AIO request slot.
struct AioSlot {
    cb: libc::aiocb,
    state: AioSlotState,
    handle: Option<crate::BufferHandle>,
    offset: u64,
    seq: u64,
    req_len: usize,
    read_len: usize,
}

impl AioSlot {
    fn new() -> Self {
        // SAFETY: aiocb is a C struct with no invalid bit patterns.
        let cb = unsafe { mem::zeroed() };
        Self {
            cb,
            state: AioSlotState::Empty,
            handle: None,
            offset: 0,
            seq: 0,
            req_len: 0,
            read_len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.state == AioSlotState::Empty
    }

    fn is_in_flight(&self) -> bool {
        self.state == AioSlotState::InFlight
    }

    fn is_completed(&self) -> bool {
        self.state == AioSlotState::Completed
    }

    fn submit(
        &mut self,
        fd: RawFd,
        mut handle: crate::BufferHandle,
        payload_off: usize,
        offset: u64,
        req_len: usize,
        seq: u64,
    ) -> io::Result<()> {
        assert!(self.is_empty());
        assert!(req_len > 0);

        let buf = handle.as_mut_slice();
        assert!(buf.len() >= payload_off + req_len);

        // Read payload into the fixed payload offset. The overlap prefix is
        // stitched in after completion so we can submit read-ahead without
        // waiting on prior chunks.
        let payload_ptr = unsafe { buf.as_mut_ptr().add(payload_off) };

        // SAFETY: aiocb is fully overwritten before use.
        self.cb = unsafe { mem::zeroed() };
        self.cb.aio_fildes = fd;
        self.cb.aio_offset = i64::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?
            as libc::off_t;
        self.cb.aio_buf = payload_ptr as *mut libc::c_void;
        self.cb.aio_nbytes = req_len as libc::size_t;
        self.cb.aio_sigevent.sigev_notify = libc::SIGEV_NONE;

        // SAFETY: `self.cb` lives until completion, and `payload_ptr` remains
        // valid because `handle` owns the buffer until we emit the chunk.
        aio::read(&mut self.cb)?;

        self.handle = Some(handle);
        self.offset = offset;
        self.seq = seq;
        self.req_len = req_len;
        self.read_len = 0;
        self.state = AioSlotState::InFlight;

        Ok(())
    }

    fn poll_complete(&mut self) -> io::Result<bool> {
        if !self.is_in_flight() {
            return Ok(false);
        }

        // Non-blocking completion check.
        // SAFETY: `self.cb` was initialized by submit() and has not been freed.
        let err = aio::error(&self.cb)?;
        if err == libc::EINPROGRESS {
            return Ok(false);
        }

        if err != 0 {
            // Ensure the kernel reaps the request even on error.
            let _ = aio::ret(&mut self.cb);
            self.read_len = 0;
            self.state = AioSlotState::Completed;
            return Err(io::Error::from_raw_os_error(err));
        }

        // SAFETY: aio_return is called once after completion.
        let res = aio::ret(&mut self.cb)?;
        self.read_len = res as usize;
        self.state = AioSlotState::Completed;
        Ok(true)
    }

    fn reset(&mut self) {
        self.state = AioSlotState::Empty;
        self.handle = None;
        self.offset = 0;
        self.seq = 0;
        self.req_len = 0;
        self.read_len = 0;
    }
}

/// File-local AIO reader with read-ahead and ordered chunk emission.
///
/// This reader:
/// - keeps a fixed number of in-flight reads (read-ahead window)
/// - preserves overlap across chunks without payload copies
/// - emits chunks strictly in order
struct AioFileReader {
    file_id: FileId,
    file: File,
    fd: RawFd,
    file_len: u64,
    chunk_size: usize,
    overlap: usize,
    payload_off: usize,
    tail: Vec<u8>,
    tail_len: usize,
    slots: Vec<AioSlot>,
    // Free slot indices held in a fixed-capacity stack. Capacity is `queue_depth`,
    // so push/pop never reallocates after initialization.
    free_slots: Vec<usize>,
    // Ready table keyed by `seq % queue_depth` so we can find the next emit in O(1).
    // This avoids hashing while preserving out-of-order completion handling.
    // The table is fixed-size and mutated in place; no hot-path allocations.
    ready_seq: Vec<u64>,
    ready_slot: Vec<usize>,
    next_offset: u64,
    next_seq: u64,
    next_emit_seq: u64,
    end_seq: u64,
    wait_list: Vec<*const libc::aiocb>,
}

impl AioFileReader {
    #[allow(clippy::too_many_arguments)]
    // The reader constructor is intentionally explicit to keep call sites
    // obvious and avoid bundling transient values into an extra struct.
    fn new(
        pool: &BufferPool,
        file_id: FileId,
        path: &Path,
        file_len: u64,
        payload_off: usize,
        overlap: usize,
        chunk_size: usize,
        queue_depth: u32,
    ) -> io::Result<Self> {
        let file = File::open(path)?;
        let fd = file.as_raw_fd();

        let queue_depth = queue_depth as usize;
        if queue_depth == 0 {
            return Err(io::Error::other("queue_depth must be > 0"));
        }

        let total_chunks = if file_len == 0 {
            0
        } else {
            file_len.saturating_add(chunk_size as u64 - 1) / chunk_size as u64
        };

        if pool.buf_len() < payload_off + chunk_size {
            return Err(io::Error::other("buffer pool too small for payload layout"));
        }

        let slots: Vec<AioSlot> = (0..queue_depth).map(|_| AioSlot::new()).collect();
        let free_slots: Vec<usize> = (0..queue_depth).rev().collect();
        let ready_seq = vec![u64::MAX; queue_depth];
        let ready_slot = vec![0; queue_depth];

        Ok(Self {
            file_id,
            file,
            fd,
            file_len,
            chunk_size,
            overlap,
            payload_off,
            tail: vec![0u8; overlap],
            tail_len: 0,
            slots,
            free_slots,
            ready_seq,
            ready_slot,
            next_offset: 0,
            next_seq: 0,
            next_emit_seq: 0,
            end_seq: total_chunks,
            wait_list: Vec::with_capacity(queue_depth),
        })
    }

    fn is_done(&self) -> bool {
        let slots_empty = self.slots.iter().all(|slot| slot.is_empty());
        self.next_emit_seq >= self.end_seq && self.next_seq >= self.end_seq && slots_empty
    }

    fn is_retryable_submit_error(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(code)
                if code == libc::EAGAIN
                    || code == libc::EWOULDBLOCK
                    || code == libc::ENOMEM
                    || code == libc::EINTR
        )
    }

    fn submit_reads(&mut self, pool: &BufferPool) -> io::Result<bool> {
        let mut progressed = false;

        while self.next_seq < self.end_seq {
            let Some(slot_idx) = self.free_slots.pop() else {
                break;
            };

            let remaining = self.file_len.saturating_sub(self.next_offset);
            if remaining == 0 {
                self.end_seq = self.next_seq;
                self.free_slots.push(slot_idx);
                break;
            }
            let req_len = remaining.min(self.chunk_size as u64) as usize;

            let handle = match pool.try_acquire() {
                Some(handle) => handle,
                None => {
                    self.free_slots.push(slot_idx);
                    break;
                }
            };

            // Submit in increasing file offset order. Each submission gets a
            // strictly increasing sequence number so we can emit in order.
            let slot = &mut self.slots[slot_idx];
            assert!(slot.is_empty());
            match slot.submit(
                self.fd,
                handle,
                self.payload_off,
                self.next_offset,
                req_len,
                self.next_seq,
            ) {
                Ok(()) => {}
                Err(err) if Self::is_retryable_submit_error(&err) => {
                    // Back off on transient resource exhaustion and retry after completions.
                    self.free_slots.push(slot_idx);
                    break;
                }
                Err(err) => {
                    self.free_slots.push(slot_idx);
                    return Err(err);
                }
            }

            self.next_offset = self.next_offset.saturating_add(req_len as u64);
            self.next_seq = self.next_seq.saturating_add(1);
            progressed = true;
        }

        Ok(progressed)
    }

    fn poll_completions(&mut self) -> io::Result<bool> {
        let mut progressed = false;
        let ready_len = self.ready_seq.len();

        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if !slot.is_in_flight() {
                continue;
            }
            if slot.poll_complete()? {
                let pos = (slot.seq as usize) % ready_len;
                assert!(
                    self.ready_seq[pos] == u64::MAX,
                    "ready ring collision for seq {}",
                    slot.seq
                );
                self.ready_seq[pos] = slot.seq;
                self.ready_slot[pos] = idx;
                progressed = true;
            }
        }

        self.discard_completed_beyond_end();

        Ok(progressed)
    }

    fn discard_completed_beyond_end(&mut self) {
        if self.next_seq <= self.end_seq {
            return;
        }

        let ready_len = self.ready_seq.len();
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_completed() && slot.seq >= self.end_seq {
                let pos = (slot.seq as usize) % ready_len;
                if self.ready_seq[pos] == slot.seq {
                    self.ready_seq[pos] = u64::MAX;
                }
                slot.reset();
                self.free_slots.push(idx);
            }
        }
    }

    fn wait_for_completion(&mut self) -> io::Result<()> {
        self.wait_list.clear();
        for slot in &self.slots {
            if slot.is_in_flight() {
                self.wait_list.push(&slot.cb as *const libc::aiocb);
            }
        }

        if self.wait_list.is_empty() {
            return Ok(());
        }

        loop {
            match aio::suspend(&self.wait_list) {
                Ok(()) => return Ok(()),
                Err(err)
                    if err.kind() == io::ErrorKind::Interrupted
                        || err.raw_os_error() == Some(libc::EINTR) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn drain_in_flight(&mut self) {
        if !self.slots.iter().any(|slot| slot.is_in_flight()) {
            return;
        }

        // Best-effort cancellation to trigger completion and release resources.
        for slot in &self.slots {
            if slot.is_in_flight() {
                let _ = aio::cancel(self.fd, &slot.cb);
            }
        }

        loop {
            self.wait_list.clear();
            for slot in &self.slots {
                if slot.is_in_flight() {
                    self.wait_list.push(&slot.cb as *const libc::aiocb);
                }
            }

            if self.wait_list.is_empty() {
                break;
            }

            // Drain completions without spinning; EINTR is safe to retry.
            loop {
                match aio::suspend(&self.wait_list) {
                    Ok(()) => break,
                    Err(err)
                        if err.kind() == io::ErrorKind::Interrupted
                            || err.raw_os_error() == Some(libc::EINTR) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }

            for slot in &mut self.slots {
                if !slot.is_in_flight() {
                    continue;
                }
                match aio::error(&slot.cb) {
                    Ok(libc::EINPROGRESS) => continue,
                    Ok(_) | Err(_) => {
                        let _ = aio::ret(&mut slot.cb);
                        slot.reset();
                    }
                }
            }
        }
    }

    fn emit_ready(&mut self) -> io::Result<Option<Chunk>> {
        if self.next_emit_seq >= self.end_seq {
            return Ok(None);
        }

        let ready_len = self.ready_seq.len();
        let pos = (self.next_emit_seq as usize) % ready_len;
        if self.ready_seq[pos] != self.next_emit_seq {
            return Ok(None);
        }

        let idx = self.ready_slot[pos];
        self.ready_seq[pos] = u64::MAX;

        let slot = &mut self.slots[idx];
        assert!(slot.is_completed());
        let read_len = slot.read_len;
        let req_len = slot.req_len;
        let offset = slot.offset;
        let seq = slot.seq;
        let mut handle = slot
            .handle
            .take()
            .expect("completed slot must hold a buffer");
        slot.reset();
        self.free_slots.push(idx);

        if read_len == 0 {
            self.end_seq = self.end_seq.min(seq);
            self.next_emit_seq = self.end_seq;
            self.discard_completed_beyond_end();
            return Ok(None);
        }

        let buf = handle.as_mut_slice();
        // Right-align the prefix so the scan slice is contiguous even when
        // `prefix_len < overlap` (first chunk or very small files).
        let prefix_start = self.payload_off.saturating_sub(self.tail_len);
        if self.tail_len > 0 {
            let prefix_end = prefix_start + self.tail_len;
            buf[prefix_start..prefix_end].copy_from_slice(&self.tail[..self.tail_len]);
        }

        let total_len = self.tail_len.saturating_add(read_len);
        let keep = self.overlap.min(total_len);
        if keep > 0 {
            let data_end = self.payload_off + read_len;
            let tail_start = data_end - keep;
            self.tail[..keep].copy_from_slice(&buf[tail_start..data_end]);
        }

        let base_offset = offset.saturating_sub(self.tail_len as u64);
        let chunk = Chunk {
            file_id: self.file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: self.tail_len as u32,
            // Start of the contiguous prefix+payload slice.
            buf_offset: prefix_start as u32,
            buf: handle,
        };

        self.tail_len = keep;
        self.next_emit_seq = self.next_emit_seq.saturating_add(1);

        if read_len < req_len {
            self.end_seq = self.end_seq.min(seq.saturating_add(1));
            self.discard_completed_beyond_end();
        }

        Ok(Some(chunk))
    }

    fn next_chunk(&mut self, pool: &BufferPool) -> io::Result<Option<Chunk>> {
        loop {
            let mut progressed = false;
            progressed |= self.submit_reads(pool)?;
            progressed |= self.poll_completions()?;

            if let Some(chunk) = self.emit_ready()? {
                // Keep the read-ahead window full while the caller scans this chunk.
                let _ = self.submit_reads(pool)?;
                return Ok(Some(chunk));
            }

            if self.is_done() {
                return Ok(None);
            }

            if !progressed {
                self.wait_for_completion()?;
            }
        }
    }
}

impl Drop for AioFileReader {
    fn drop(&mut self) {
        // Ensure aiocb buffers stay alive until each request is reaped.
        self.drain_in_flight();
    }
}

/// Preferred alias for the macOS POSIX AIO scanner.
pub type AioScanner = MacosAioScanner;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &PathBuf {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn make_temp_dir(prefix: &str) -> io::Result<TempDir> {
        let mut path = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        path.push(format!("{}_{}_{}", prefix, std::process::id(), stamp));
        std::fs::create_dir(&path)?;
        Ok(TempDir { path })
    }

    #[test]
    fn aio_reader_preserves_overlap() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_async_reader")?;
        let path = tmp.path().join("sample.txt");
        let data = b"abcdefghijklmnopqrstuvwxyz";
        std::fs::write(&path, data)?;

        let engine = Arc::new(crate::demo_engine());
        let config = AsyncIoConfig {
            chunk_size: 8,
            queue_depth: 2,
            ..AsyncIoConfig::default()
        };

        let scanner = MacosAioScanner::new(engine, config)?;
        let file_id = FileId(0);

        let mut reader = AioFileReader::new(
            &scanner.pool,
            file_id,
            &path,
            data.len() as u64,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.queue_depth,
        )?;

        let mut chunks = Vec::new();
        let start = std::time::Instant::now();
        loop {
            if let Some(chunk) = reader.next_chunk(&scanner.pool)? {
                chunks.push(chunk.data().to_vec());
            } else {
                break;
            }

            if start.elapsed() > Duration::from_secs(5) {
                return Err(io::Error::other("aio reader stalled"));
            }
        }

        let mut expected = Vec::new();
        let mut tail: Vec<u8> = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + scanner.config.chunk_size).min(data.len());
            let payload = &data[offset..end];
            let mut chunk = Vec::with_capacity(tail.len() + payload.len());
            chunk.extend_from_slice(&tail);
            chunk.extend_from_slice(payload);
            expected.push(chunk.clone());

            let keep = scanner.overlap.min(chunk.len());
            tail = chunk[chunk.len() - keep..].to_vec();
            offset = offset.saturating_add(scanner.config.chunk_size);
        }

        assert_eq!(chunks, expected);

        Ok(())
    }

    #[test]
    fn aio_reader_retries_suspend_on_eintr() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_async_reader_eintr")?;
        let path = tmp.path().join("sample.bin");
        let data = vec![0x5Au8; 1024 * 1024];
        std::fs::write(&path, &data)?;

        let engine = Arc::new(crate::demo_engine());
        let config = AsyncIoConfig {
            chunk_size: 64 * 1024,
            queue_depth: 2,
            ..AsyncIoConfig::default()
        };

        let scanner = MacosAioScanner::new(engine, config)?;
        let mut reader = AioFileReader::new(
            &scanner.pool,
            FileId(0),
            &path,
            data.len() as u64,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.queue_depth,
        )?;

        assert!(reader.submit_reads(&scanner.pool)?);
        assert!(reader.slots.iter().any(|slot| slot.is_in_flight()));

        aio::inject_suspend_eintr(1);
        reader.wait_for_completion()?;

        Ok(())
    }

    #[test]
    fn aio_reader_backoffs_on_submit_eagain() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_async_reader_eagain")?;
        let path = tmp.path().join("sample.bin");
        let data = vec![0xC3u8; 128 * 1024];
        std::fs::write(&path, &data)?;

        let engine = Arc::new(crate::demo_engine());
        let config = AsyncIoConfig {
            chunk_size: 32 * 1024,
            queue_depth: 2,
            ..AsyncIoConfig::default()
        };

        let scanner = MacosAioScanner::new(engine, config)?;
        let mut reader = AioFileReader::new(
            &scanner.pool,
            FileId(0),
            &path,
            data.len() as u64,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.queue_depth,
        )?;

        aio::inject_read_eagain(1);
        let progressed = reader.submit_reads(&scanner.pool)?;
        assert!(!progressed);
        assert_eq!(reader.next_seq, 0);
        assert_eq!(reader.next_offset, 0);
        assert!(reader.slots.iter().all(|slot| slot.is_empty()));

        aio::inject_read_eagain(0);
        assert!(reader.submit_reads(&scanner.pool)?);

        Ok(())
    }

    #[test]
    fn aio_reader_drop_reaps_in_flight() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_async_reader_drop")?;
        let path = tmp.path().join("sample.bin");
        let data = vec![0xA5u8; 256 * 1024];
        std::fs::write(&path, &data)?;

        let engine = Arc::new(crate::demo_engine());
        let config = AsyncIoConfig {
            chunk_size: 64 * 1024,
            queue_depth: 2,
            ..AsyncIoConfig::default()
        };

        let scanner = MacosAioScanner::new(engine, config)?;
        let mut reader = AioFileReader::new(
            &scanner.pool,
            FileId(0),
            &path,
            data.len() as u64,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.queue_depth,
        )?;

        assert!(reader.submit_reads(&scanner.pool)?);
        let in_flight = reader
            .slots
            .iter()
            .filter(|slot| slot.is_in_flight())
            .count();
        assert!(in_flight > 0);

        let before = aio::return_call_count();
        drop(reader);
        let after = aio::return_call_count();

        assert!(after >= before + in_flight);

        Ok(())
    }

    #[test]
    fn aio_reader_hot_path_does_not_grow_buffers() -> io::Result<()> {
        let tmp = make_temp_dir("scanner_async_reader_allocs")?;
        let path = tmp.path().join("sample.bin");
        let data = vec![0x11u8; 512 * 1024];
        std::fs::write(&path, &data)?;

        let engine = Arc::new(crate::demo_engine());
        let config = AsyncIoConfig {
            chunk_size: 64 * 1024,
            queue_depth: 4,
            ..AsyncIoConfig::default()
        };

        let scanner = MacosAioScanner::new(engine, config)?;
        let mut reader = AioFileReader::new(
            &scanner.pool,
            FileId(0),
            &path,
            data.len() as u64,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.queue_depth,
        )?;

        let caps = (
            reader.free_slots.capacity(),
            reader.ready_seq.capacity(),
            reader.ready_slot.capacity(),
            reader.wait_list.capacity(),
            reader.tail.capacity(),
        );

        while let Some(_chunk) = reader.next_chunk(&scanner.pool)? {}

        assert_eq!(reader.free_slots.capacity(), caps.0);
        assert_eq!(reader.ready_seq.capacity(), caps.1);
        assert_eq!(reader.ready_slot.capacity(), caps.2);
        assert_eq!(reader.wait_list.capacity(), caps.3);
        assert_eq!(reader.tail.capacity(), caps.4);

        Ok(())
    }
}
