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
/// Larger than the standard 8 KiB to reduce syscall frequency while holding the lock.
/// Tuned for parallel scanning where multiple workers contend on output.
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
/// Uses