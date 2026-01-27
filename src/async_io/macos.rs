use super::*;
use crate::{BufferPool, Chunk, Engine, FindingRec, ScanScratch};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::Arc;

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
}

impl MacosAioScanner {
    /// Creates a macOS AIO scanner with bounded buffers and overlap settings.
    pub fn new(engine: Arc<Engine>, mut config: AsyncIoConfig) -> io::Result<Self> {
        if config.queue_depth < 2 {
            return Err(io::Error::other(
                "queue_depth must be >= 2 for overlapped reads",
            ));
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

        Ok(Self {
            engine,
            config,
            overlap,
            payload_off,
            pool,
        })
    }

    /// Scans a path (file or directory) using POSIX AIO reads.
    pub fn scan_path(&mut self, path: &Path) -> io::Result<PipelineStats> {
        let mut stats = PipelineStats::default();
        let mut files = FileTable::with_capacity(self.config.max_files);
        let mut walker = Walker::new(path.to_path_buf(), self.config.max_files);
        let mut out = BufWriter::new(io::stdout());

        let engine = Arc::clone(&self.engine);
        let mut scratch = engine.new_scratch();
        let mut pending: Vec<FindingRec> = Vec::with_capacity(engine.tuning.max_findings_per_chunk);

        while !walker.is_done() {
            let Some(file_id) = walker.next_file(&mut files, &mut stats) else {
                continue;
            };

            let file_path = files.path(file_id);
            let file_size = files.size(file_id);

            match self.scan_file(
                &engine,
                &mut scratch,
                &mut pending,
                file_id,
                file_path,
                file_size,
                &mut out,
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

        out.flush()?;
        Ok(stats)
    }

    #[allow(clippy::too_many_arguments)]
    // Keep scan dependencies explicit so the hot path has no hidden state
    // and the call site shows all mutable resources.
    fn scan_file(
        &mut self,
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
            &self.pool,
            file_id,
            path,
            file_size,
            self.payload_off,
            self.overlap,
            self.config.chunk_size,
            self.config.queue_depth,
        )?;

        while let Some(chunk) = reader.next_chunk(&self.pool)? {
            let payload_len = chunk.len.saturating_sub(chunk.prefix_len) as u64;
            stats.bytes_scanned = stats.bytes_scanned.saturating_add(payload_len);
            stats.chunks += 1;

            engine.scan_chunk_into(chunk.data(), chunk.file_id, chunk.base_offset, scratch);
            let new_bytes_start = chunk.base_offset + chunk.prefix_len as u64;
            scratch.drop_prefix_findings(new_bytes_start);
            scratch.drain_findings_into(pending);

            let path_display = path.display();
            for rec in pending.drain(..) {
                let rule = engine.rule_name(rec.rule_id);
                writeln!(
                    out,
                    "{}:{}-{} {}",
                    path_display, rec.root_hint_start, rec.root_hint_end, rule
                )?;
                stats.findings += 1;
            }
        }

        Ok(())
    }
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
        debug_assert!(self.is_empty());
        debug_assert!(req_len > 0);

        let buf = handle.as_mut_slice();
        debug_assert!(buf.len() >= payload_off + req_len);

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
        let ret = unsafe { libc::aio_read(&mut self.cb) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

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
        let err = unsafe { libc::aio_error(&self.cb) };
        if err == libc::EINPROGRESS {
            return Ok(false);
        }
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }

        // SAFETY: aio_return is called once after completion.
        let res = unsafe { libc::aio_return(&mut self.cb) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

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
            slots: (0..queue_depth).map(|_| AioSlot::new()).collect(),
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

    fn submit_reads(&mut self, pool: &BufferPool) -> io::Result<bool> {
        let mut progressed = false;

        while self.next_seq < self.end_seq {
            let slot = match self.slots.iter_mut().find(|slot| slot.is_empty()) {
                Some(slot) => slot,
                None => break,
            };

            let remaining = self.file_len.saturating_sub(self.next_offset);
            if remaining == 0 {
                self.end_seq = self.next_seq;
                break;
            }
            let req_len = remaining.min(self.chunk_size as u64) as usize;

            let handle = match pool.try_acquire() {
                Some(handle) => handle,
                None => break,
            };

            // Submit in increasing file offset order. Each submission gets a
            // strictly increasing sequence number so we can emit in order.
            slot.submit(
                self.fd,
                handle,
                self.payload_off,
                self.next_offset,
                req_len,
                self.next_seq,
            )?;

            self.next_offset = self.next_offset.saturating_add(req_len as u64);
            self.next_seq = self.next_seq.saturating_add(1);
            progressed = true;
        }

        Ok(progressed)
    }

    fn poll_completions(&mut self) -> io::Result<bool> {
        let mut progressed = false;

        for slot in &mut self.slots {
            if !slot.is_in_flight() {
                continue;
            }
            if slot.poll_complete()? {
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

        for slot in &mut self.slots {
            if slot.is_completed() && slot.seq >= self.end_seq {
                slot.reset();
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

        // SAFETY: all aiocb pointers are valid while slots remain in flight.
        let ret = unsafe {
            libc::aio_suspend(
                self.wait_list.as_ptr(),
                self.wait_list.len() as i32,
                ptr::null(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn emit_ready(&mut self) -> io::Result<Option<Chunk>> {
        if self.next_emit_seq >= self.end_seq {
            return Ok(None);
        }

        let slot_idx = self
            .slots
            .iter()
            .position(|slot| slot.is_completed() && slot.seq == self.next_emit_seq);
        let Some(idx) = slot_idx else {
            return Ok(None);
        };

        let slot = &mut self.slots[idx];
        let read_len = slot.read_len;
        let req_len = slot.req_len;
        let offset = slot.offset;
        let seq = slot.seq;
        let mut handle = slot
            .handle
            .take()
            .expect("completed slot must hold a buffer");
        slot.reset();

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

/// Back-compat alias: `--io=dispatch` maps to the POSIX AIO backend.
pub type DispatchScanner = MacosAioScanner;

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
}
