use super::*;
use crate::{BufferPool, Chunk, Engine, FindingRec, ScanScratch};
use io_uring::{opcode, types, IoUring};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

/// Linux async scanner powered by io_uring.
///
/// This implementation uses a two-buffer pipeline: while one chunk is
/// scanned, the next payload read is in flight. Overlap bytes are copied
/// into the next buffer before submission so the scanner sees a contiguous
/// slice without redundant overlap scanning.
pub struct UringScanner {
    engine: Arc<Engine>,
    config: AsyncIoConfig,
    overlap: usize,
    payload_off: usize,
    pool: BufferPool,
    ring: IoUring,
    scratch: ScanScratch,
    pending: Vec<FindingRec>,
    files: FileTable,
    walker: Walker,
    out: BufWriter<io::Stdout>,
}

impl UringScanner {
    /// Creates a Linux io_uring scanner with aligned buffers and queue setup.
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
        } else {
            config.chunk_size = align_down(config.chunk_size, BUFFER_ALIGN);
            if config.chunk_size == 0 {
                return Err(io::Error::other("chunk_size must be >= BUFFER_ALIGN"));
            }
        }

        let payload_off = align_up(overlap, BUFFER_ALIGN);
        let buf_len = payload_off.saturating_add(config.chunk_size);
        if buf_len > BUFFER_LEN_MAX {
            return Err(io::Error::other(
                "chunk_size + aligned overlap exceeds buffer size",
            ));
        }

        let pool = BufferPool::new(config.queue_depth as usize);
        let ring = IoUring::new(config.queue_depth)?;
        let scratch = engine.new_scratch();
        let pending = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
        let files = FileTable::with_capacity(config.max_files);
        let walker = Walker::new(config.max_files)?;
        let out = BufWriter::new(io::stdout());

        Ok(Self {
            engine,
            config,
            overlap,
            payload_off,
            pool,
            ring,
            scratch,
            pending,
            files,
            walker,
            out,
        })
    }

    /// Scans a path (file or directory) using io_uring reads.
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
                &mut self.ring,
                &self.pool,
                self.payload_off,
                self.overlap,
                self.config.chunk_size,
                self.config.use_o_direct,
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
fn scan_file<W: Write>(
    ring: &mut IoUring,
    pool: &BufferPool,
    payload_off: usize,
    overlap: usize,
    chunk_size: usize,
    use_o_direct: bool,
    engine: &Engine,
    scratch: &mut ScanScratch,
    pending: &mut Vec<FindingRec>,
    file_id: FileId,
    path: &Path,
    file_size: u64,
    out: &mut W,
    stats: &mut PipelineStats,
) -> io::Result<()> {
    let mut reader = UringFileReader::new(
        ring,
        pool,
        file_id,
        path,
        file_size,
        payload_off,
        overlap,
        chunk_size,
        use_o_direct,
    )?;

    let mut current = match reader.read_first()? {
        Some(chunk) => chunk,
        None => return Ok(()),
    };

    loop {
        let submitted = reader.submit_next_from_current(&current)?;

        let payload_len = current.len.saturating_sub(current.prefix_len) as u64;
        stats.bytes_scanned = stats.bytes_scanned.saturating_add(payload_len);
        stats.chunks += 1;

        engine.scan_chunk_into(
            current.data(),
            current.file_id,
            current.base_offset,
            scratch,
        );
        let new_bytes_start = current.base_offset + current.prefix_len as u64;
        scratch.drop_prefix_findings(new_bytes_start);
        scratch.drain_findings_into(pending);

        // Reap the next chunk before any fallible output so we never drop a
        // reader that still has a kernel read in flight.
        let next = if submitted { reader.wait_next()? } else { None };

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

        match next {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(())
}

struct ReadPlan {
    fd: RawFd,
    offset: u64,
    len: usize,
}

struct PendingRead {
    handle: crate::BufferHandle,
    prefix_len: usize,
    buf_offset: usize,
    payload_file_offset: u64,
    read_len: usize,
}

/// File-local io_uring reader with aligned payload offsets and overlap prefixing.
struct UringFileReader<'a> {
    ring: &'a mut IoUring,
    pool: &'a BufferPool,
    file_id: FileId,
    overlap: usize,
    payload_off: usize,
    chunk_size: usize,
    file_size: u64,
    next_offset: u64,
    direct_end: u64,
    direct_file: Option<File>,
    buffered_file: File,
    in_flight: Option<PendingRead>,
}

impl<'a> UringFileReader<'a> {
    fn new(
        ring: &'a mut IoUring,
        pool: &'a BufferPool,
        file_id: FileId,
        path: &Path,
        file_size: u64,
        payload_off: usize,
        overlap: usize,
        chunk_size: usize,
        use_o_direct: bool,
    ) -> io::Result<Self> {
        let buffered_file = File::open(path)?;
        let mut direct_file = None;

        let direct_end = if use_o_direct {
            align_down_u64(file_size, BUFFER_ALIGN as u64)
        } else {
            0
        };

        if use_o_direct && direct_end > 0 {
            match open_direct(path) {
                Ok(file) => {
                    direct_file = Some(file);
                }
                Err(err) if is_direct_unsupported(&err) => {
                    // Fall back to buffered-only reads if O_DIRECT is not supported.
                }
                Err(err) => return Err(err),
            }
        }

        let direct_end = if direct_file.is_some() { direct_end } else { 0 };

        Ok(Self {
            ring,
            pool,
            file_id,
            overlap,
            payload_off,
            chunk_size,
            file_size,
            next_offset: 0,
            direct_end,
            direct_file,
            buffered_file,
            in_flight: None,
        })
    }

    fn read_first(&mut self) -> io::Result<Option<Chunk>> {
        // Prime the pipeline: read the first payload synchronously so we
        // have bytes to scan before issuing the overlapped read.
        let handle = self.pool.acquire();
        if !self.submit_read(handle, &[], 0)? {
            return Ok(None);
        }
        self.wait_next()
    }

    fn submit_next_from_current(&mut self, current: &Chunk) -> io::Result<bool> {
        let overlap_len = self.overlap.min(current.len as usize);
        let total_len = current.len as usize;
        let prefix = if overlap_len > 0 {
            &current.data()[total_len - overlap_len..total_len]
        } else {
            &[]
        };
        let handle = self.pool.acquire();
        self.submit_read(handle, prefix, overlap_len)
    }

    fn submit_read(
        &mut self,
        mut handle: crate::BufferHandle,
        prefix: &[u8],
        prefix_len: usize,
    ) -> io::Result<bool> {
        if self.in_flight.is_some() {
            return Err(io::Error::other("io_uring read already in flight"));
        }

        let plan = match self.next_read_plan() {
            Some(plan) => plan,
            None => return Ok(false),
        };

        if prefix_len > 0 {
            // Place the true overlap bytes immediately before the aligned
            // payload slot so the scan slice stays contiguous.
            let start = self.payload_off.saturating_sub(prefix_len);
            let end = start + prefix_len;
            handle.as_mut_slice()[start..end].copy_from_slice(prefix);
        }

        let ptr = unsafe { handle.as_mut_slice().as_mut_ptr().add(self.payload_off) };
        let entry = opcode::Read::new(types::Fd(plan.fd), ptr, plan.len as u32)
            .offset(plan.offset)
            .build()
            .user_data(0);

        unsafe {
            self.ring
                .submission()
                .push(&entry)
                .map_err(|_| io::Error::other("io_uring submission queue full"))?;
        }

        self.ring.submit()?;

        self.in_flight = Some(PendingRead {
            handle,
            prefix_len,
            buf_offset: self.payload_off.saturating_sub(prefix_len),
            payload_file_offset: plan.offset,
            read_len: plan.len,
        });

        self.next_offset = self.next_offset.saturating_add(plan.len as u64);
        Ok(true)
    }

    fn wait_next(&mut self) -> io::Result<Option<Chunk>> {
        let pending = match self.in_flight.take() {
            Some(pending) => pending,
            None => return Ok(None),
        };

        let mut cqe = {
            let mut cq = self.ring.completion();
            cq.next()
        };

        if cqe.is_none() {
            self.ring.submit_and_wait(1)?;
            let mut cq = self.ring.completion();
            cqe = cq.next();
        }

        let cqe = cqe.ok_or_else(|| io::Error::other("io_uring completion missing"))?;

        let result = cqe.result();
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }

        let payload_len = result as usize;
        if payload_len == 0 {
            return Ok(None);
        }

        if payload_len < pending.read_len {
            let observed = pending
                .payload_file_offset
                .saturating_add(payload_len as u64);
            self.clamp_file_size(observed);
        }

        let total_len = pending.prefix_len.saturating_add(payload_len);
        let base_offset = pending
            .payload_file_offset
            .saturating_sub(pending.prefix_len as u64);

        let chunk = Chunk {
            file_id: self.file_id,
            base_offset,
            len: total_len as u32,
            prefix_len: pending.prefix_len as u32,
            buf: pending.handle,
            buf_offset: pending.buf_offset as u32,
        };

        Ok(Some(chunk))
    }

    fn next_read_plan(&self) -> Option<ReadPlan> {
        if self.next_offset >= self.file_size {
            return None;
        }

        if self.direct_end > 0 && self.next_offset < self.direct_end {
            // Aligned, direct-read portion of the file.
            let remaining = (self.direct_end - self.next_offset) as usize;
            let len = remaining.min(self.chunk_size);
            let fd = self
                .direct_file
                .as_ref()
                .expect("direct fd missing")
                .as_raw_fd();
            return Some(ReadPlan {
                fd,
                offset: self.next_offset,
                len,
            });
        }

        // Buffered tail (unaligned) after the direct section.
        let remaining = (self.file_size - self.next_offset) as usize;
        let len = remaining.min(self.chunk_size);
        let fd = self.buffered_file.as_raw_fd();
        Some(ReadPlan {
            fd,
            offset: self.next_offset,
            len,
        })
    }

    fn clamp_file_size(&mut self, observed_size: u64) {
        if observed_size < self.file_size {
            self.file_size = observed_size;
            self.direct_end = align_down_u64(self.file_size, BUFFER_ALIGN as u64);
            if self.next_offset > self.file_size {
                self.next_offset = self.file_size;
            }
        }
    }
}

#[cfg(test)]
impl<'a> Drop for UringFileReader<'a> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Avoid double-panics in tests; we only want to flag clean drops
            // that leave an in-flight read behind.
            return;
        }
        assert!(
            self.in_flight.is_none(),
            "io_uring reader dropped with an in-flight read; drain before returning"
        );
    }
}

fn open_direct(path: &Path) -> io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_DIRECT | libc::O_CLOEXEC);
    opts.open(path)
}

fn is_direct_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{AnchorPolicy, RuleSpec, ValidatorKind};
    use crate::demo::demo_tuning;
    use crate::engine::Engine;
    use regex::bytes::Regex;
    use std::fs;
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(bytes: &[u8]) -> io::Result<Self> {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "scratch-scanner-uring-test-{}-{}.bin",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            fs::write(&path, bytes)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    struct FailingWriter {
        writes: usize,
    }

    impl FailingWriter {
        fn new() -> Self {
            Self { writes: 0 }
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated output failure",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn scan_file_does_not_drop_in_flight_on_output_error() -> io::Result<()> {
        // Build a tiny engine that will definitely emit a finding in the
        // first chunk so we exercise the output path.
        const ANCHOR: &[&[u8]] = &[b"SECRET"];
        let rule = RuleSpec {
            name: "test-secret",
            anchors: ANCHOR,
            radius: 16,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            re: Regex::new("SECRET").unwrap(),
        };
        let engine = Arc::new(Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        ));

        let mut config = AsyncIoConfig::default();
        config.chunk_size = BUFFER_ALIGN;
        config.queue_depth = 2;
        config.max_files = 1;
        config.use_o_direct = false;

        let mut scanner = UringScanner::new(Arc::clone(&engine), config)?;

        let mut bytes = vec![b'a'; BUFFER_ALIGN * 2];
        bytes[..ANCHOR[0].len()].copy_from_slice(ANCHOR[0]);
        let temp = TempFile::new(&bytes)?;

        let mut scratch = engine.new_scratch();
        let mut pending = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
        let mut stats = PipelineStats::default();
        let mut writer = FailingWriter::new();

        let err = scan_file(
            &mut scanner.ring,
            &scanner.pool,
            scanner.payload_off,
            scanner.overlap,
            scanner.config.chunk_size,
            scanner.config.use_o_direct,
            &engine,
            &mut scratch,
            &mut pending,
            FileId(0),
            temp.path(),
            bytes.len() as u64,
            &mut writer,
            &mut stats,
        )
        .expect_err("expected writer failure");

        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(writer.writes > 0, "writer should be invoked at least once");
        Ok(())
    }
}
