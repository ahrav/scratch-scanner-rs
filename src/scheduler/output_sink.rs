//! Output Sink for Parallel Scanning (Phase 4)
//!
//! # Design
//!
//! Workers format findings into a reusable `Vec<u8>` (per-worker, no alloc in steady state),
//! then call `write_all(bytes)` which takes a lock only for the actual I/O.
//!
//! This avoids "lock held while formatting" which would serialize workers.
//!
//! # Correctness Guarantees
//!
//! - **Serialized batches**: Each `write_all` acquires a mutex, so batches from different
//!   workers cannot interleave at the byte level. However, batch *ordering* depends on
//!   lock acquisition order (non-deterministic).
//!
//! - **Partial output on error**: If `write_all` fails mid-write, some bytes may have
//!   already been written. The implementation panics on error (fail-fast), but partial
//!   output is possible.
//!
//! - **External interleaving**: If other code writes to stdout concurrently (e.g., `println!`),
//!   interleaving can occur because stdout has its own internal lock separate from the sink's mutex.
//!
//! - **Flush semantics**: `flush()` flushes buffered data to the OS at the moment of the call.
//!   If workers continue writing after `flush()` returns, more buffered data will accumulate.
//!   Call `flush()` only after workers have been joined/quiesced.
//!
//! - **No durability guarantee**: `flush()` pushes data to the OS, not to stable storage.
//!   For crash-consistent output, the caller would need `File::sync_all()` (overkill for scanner output).
//!
//! # Performance Characteristics
//!
//! | Operation    | Cost                          |
//! |--------------|-------------------------------|
//! | write_all    | Lock + memcpy to BufWriter    |
//! | flush        | Lock + syscall                |
//!
//! Workers should batch multiple findings into a single `write_all` call
//! (format all findings from one chunk, then write once).
//!
//! # When to Use a Different Architecture
//!
//! This implementation is appropriate when:
//! - Findings are sparse (typical for secret scanning)
//! - Simplicity and correctness are prioritized over maximum throughput
//!
//! Consider a writer thread + bounded MPSC queue if:
//! - Findings are frequent (output becomes the bottleneck)
//! - Workers must never block on I/O
//! - You need explicit backpressure on output

use std::io::{self, BufWriter, ErrorKind, Write};
use std::sync::Mutex;

/// Default buffer size for output sinks (64 KiB).
///
/// # Rationale
///
/// - **8× standard `BufWriter`**: The default 8 KiB buffer causes ~8 syscalls per 64 KiB
///   of output. With N workers contending, lock hold time dominates; fewer, larger writes
///   reduce total lock acquisitions.
///
/// - **Why not larger?** 64 KiB is the typical L1 cache size. Larger buffers risk evicting
///   hot scanner data. Also, stdout is rarely the bottleneck for secret scanning (findings
///   are sparse), so over-optimizing here yields diminishing returns.
///
/// - **Worst case**: If all workers flush simultaneously, peak memory is `N × 64 KiB`.
///   For 32 workers, that's 2 MiB—negligible compared to scanner memory budgets.
const DEFAULT_BUF_CAPACITY: usize = 64 * 1024;

// ============================================================================
// Trait
// ============================================================================

/// Lowest common denominator output sink.
///
/// Workers format into a reusable `Vec<u8>` and then call `write_all(bytes)`.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` (called from multiple worker threads).
///
/// # Panic Policy
///
/// Implementations panic on I/O errors (fail-fast), except for `BrokenPipe` on stdout
/// which is silently ignored (standard CLI behavior for `scanner | head`).
///
/// # Mutex Poisoning
///
/// Uses `std::sync::Mutex`, so one panic while holding the lock poisons it.
/// Subsequent calls will also panic. This matches the fail-fast policy.
pub trait OutputSink: Send + Sync + 'static {
    /// Write a batch of bytes.
    ///
    /// Batches from different workers are serialized (no byte-level interleaving),
    /// but ordering between batches is non-deterministic.
    ///
    /// # Complexity
    ///
    /// O(n) where n = `bytes.len()`. Lock acquisition is O(1) uncontended,
    /// O(workers) under contention.
    ///
    /// # Panics
    ///
    /// Panics on I/O error, except `BrokenPipe` which may be silently ignored.
    fn write_all(&self, bytes: &[u8]);

    /// Flush any buffered data to the OS.
    ///
    /// Call only after workers have been joined/quiesced.
    ///
    /// # Panics
    ///
    /// Panics on I/O error, except `BrokenPipe` which may be silently ignored.
    fn flush(&self);
}

// ============================================================================
// StdoutSink
// ============================================================================

/// Stdout sink with internal buffering + a mutex.
///
/// Lock is taken only for the actual write, not formatting.
///
/// # BrokenPipe Handling
///
/// When stdout is piped to a process that exits early (e.g., `scanner | head -n 5`),
/// subsequent writes return `BrokenPipe`. This sink silently ignores such errors
/// rather than panicking, which is standard CLI behavior.
///
/// # Buffer Size
///
/// Uses 64 KiB buffer by default to reduce syscall frequency under contention.
/// Customize with `with_capacity()` if needed.
pub struct StdoutSink {
    out: Mutex<BufWriter<io::Stdout>>,
}

impl StdoutSink {
    /// Create a new stdout sink with default 64 KiB buffer.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BUF_CAPACITY)
    }

    /// Create a stdout sink with a custom buffer size.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            out: Mutex::new(BufWriter::with_capacity(cap, io::stdout())),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSink for StdoutSink {
    fn write_all(&self, bytes: &[u8]) {
        let mut out = self.out.lock().expect("stdout sink mutex poisoned");
        if let Err(e) = out.write_all(bytes) {
            if e.kind() == ErrorKind::BrokenPipe {
                // Silently ignore: standard behavior for `scanner | head`
                return;
            }
            panic!("stdout write failed: {}", e);
        }
    }

    fn flush(&self) {
        let mut out = self.out.lock().expect("stdout sink mutex poisoned");
        if let Err(e) = out.flush() {
            if e.kind() == ErrorKind::BrokenPipe {
                return;
            }
            panic!("stdout flush failed: {}", e);
        }
    }
}

// ============================================================================
// VecSink (for testing)
// ============================================================================

/// Test sink: captures all bytes in memory.
///
/// Use `take()` to extract captured bytes after scanning completes.
pub struct VecSink {
    buf: Mutex<Vec<u8>>,
}

impl VecSink {
    /// Create a new empty test sink.
    pub fn new() -> Self {
        Self {
            buf: Mutex::new(Vec::new()),
        }
    }

    /// Create a test sink with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Mutex::new(Vec::with_capacity(cap)),
        }
    }

    /// Extract captured bytes, leaving the internal buffer empty.
    ///
    /// # Thread Safety
    ///
    /// Safe to call during scanning, but results are non-deterministic
    /// (may capture partial output). Intended for use after `flush()`.
    pub fn take(&self) -> Vec<u8> {
        let mut g = self.buf.lock().expect("vec sink mutex poisoned");
        std::mem::take(&mut *g)
    }

    /// Get current byte count without extracting.
    pub fn len(&self) -> usize {
        self.buf.lock().expect("vec sink mutex poisoned").len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for VecSink {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSink for VecSink {
    fn write_all(&self, bytes: &[u8]) {
        self.buf
            .lock()
            .expect("vec sink mutex poisoned")
            .extend_from_slice(bytes);
    }

    fn flush(&self) {
        // No-op: VecSink has no underlying buffer to flush
    }
}

// ============================================================================
// NullSink (for benchmarking)
// ============================================================================

/// Null sink: discards all output.
///
/// Use for benchmarking scheduler overhead without I/O costs.
pub struct NullSink;

impl NullSink {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullSink {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputSink for NullSink {
    fn write_all(&self, _bytes: &[u8]) {
        // Discard
    }

    fn flush(&self) {
        // No-op
    }
}

// ============================================================================
// FileSink
// ============================================================================

/// File sink: writes to a file with buffering.
///
/// # When to Use
///
/// Prefer `FileSink` over shell redirection (`scanner > out.txt`) when:
/// - You need atomic flush semantics (shell redirection may buffer unpredictably)
/// - You want explicit error handling on file creation
/// - You're writing from multiple processes (each needs its own file)
///
/// Shell redirection is fine for simple cases where you don't need these guarantees.
///
/// # Buffering
///
/// Uses the same 64 KiB buffer as `StdoutSink`. The buffer lives in userspace;
/// actual disk writes happen on flush or when the buffer fills.
pub struct FileSink {
    out: Mutex<BufWriter<std::fs::File>>,
}

impl FileSink {
    /// Create a new file sink (creates/truncates file).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or opened.
    pub fn create(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::create_with_capacity(path, DEFAULT_BUF_CAPACITY)
    }

    /// Create with custom buffer capacity.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or opened.
    pub fn create_with_capacity(path: impl AsRef<std::path::Path>, cap: usize) -> io::Result<Self> {
        let file = std::fs::File::create(path)?;
        Ok(Self {
            out: Mutex::new(BufWriter::with_capacity(cap, file)),
        })
    }
}

impl OutputSink for FileSink {
    fn write_all(&self, bytes: &[u8]) {
        let mut out = self.out.lock().expect("file sink mutex poisoned");
        out.write_all(bytes).expect("file write failed");
    }

    fn flush(&self) {
        let mut out = self.out.lock().expect("file sink mutex poisoned");
        out.flush().expect("file flush failed");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn vec_sink_captures_writes() {
        let sink = VecSink::new();
        sink.write_all(b"hello ");
        sink.write_all(b"world");
        assert_eq!(sink.take(), b"hello world");
        assert!(sink.is_empty());
    }

    #[test]
    fn vec_sink_take_clears() {
        let sink = VecSink::new();
        sink.write_all(b"test");
        let _ = sink.take();
        sink.write_all(b"new");
        assert_eq!(sink.take(), b"new");
    }

    #[test]
    fn null_sink_discards() {
        let sink = NullSink::new();
        sink.write_all(b"discarded");
        sink.flush();
        // No way to verify discarded, but ensures no panic
    }

    #[test]
    fn concurrent_vec_sink_writes() {
        let sink = Arc::new(VecSink::with_capacity(1024 * 1024));
        let n_threads = 8;
        let writes_per_thread = 1000;

        let handles: Vec<_> = (0..n_threads)
            .map(|tid| {
                let sink = Arc::clone(&sink);
                thread::spawn(move || {
                    let msg = format!("thread-{}\n", tid);
                    for _ in 0..writes_per_thread {
                        sink.write_all(msg.as_bytes());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        sink.flush();
        let output = sink.take();

        // Parse lines and verify each is well-formed
        let lines: Vec<&[u8]> = output
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();

        assert_eq!(
            lines.len(),
            n_threads * writes_per_thread,
            "expected {} lines, got {}",
            n_threads * writes_per_thread,
            lines.len()
        );

        // Verify each line matches expected format "thread-N"
        let mut counts = vec![0usize; n_threads];
        for line in &lines {
            let s = std::str::from_utf8(line).expect("line should be valid UTF-8");
            assert!(s.starts_with("thread-"), "malformed line: {:?}", s);
            let tid: usize = s
                .strip_prefix("thread-")
                .unwrap()
                .parse()
                .expect("should parse thread id");
            assert!(tid < n_threads, "thread id {} out of range", tid);
            counts[tid] += 1;
        }

        // Each thread should have written exactly writes_per_thread lines
        for (tid, &count) in counts.iter().enumerate() {
            assert_eq!(
                count, writes_per_thread,
                "thread {} wrote {} lines, expected {}",
                tid, count, writes_per_thread
            );
        }
    }

    #[test]
    fn stdout_sink_basic() {
        // Just verify construction and that methods don't panic
        let sink = StdoutSink::new();
        sink.write_all(b""); // Empty write
        sink.flush();
    }

    #[test]
    fn file_sink_roundtrip() {
        // Use process ID + thread ID to avoid collision with parallel test runs
        let unique_name = format!(
            "output_sink_test_{}_{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        );
        let path = std::env::temp_dir().join(unique_name);

        {
            let sink = FileSink::create(&path).unwrap();
            sink.write_all(b"line1\n");
            sink.write_all(b"line2\n");
            sink.flush();
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "line1\nline2\n");

        std::fs::remove_file(&path).ok();
    }
}
