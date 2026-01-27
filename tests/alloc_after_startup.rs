//! Allocation-after-startup audit tests.
//!
//! These tests install a counting global allocator and are therefore ignored
//! by default. Run with:
//! `cargo test --test alloc_after_startup -- --ignored --nocapture`

use scanner_rs::pipeline::{
    Pipeline, PipelineConfig, PIPE_CHUNK_RING_CAP, PIPE_FILE_RING_CAP, PIPE_OUT_RING_CAP,
};
use scanner_rs::{demo_engine, ScannerConfig, ScannerRuntime};
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Global allocator that counts allocation events and bytes.
struct CountingAlloc;

static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static REALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: This allocator delegates to `System` and only records statistics.
// It preserves the required layout/size contracts of the global allocator API.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            REALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Snapshot of allocation counters for reporting.
#[derive(Clone, Copy, Debug)]
struct Counts {
    alloc_calls: usize,
    alloc_bytes: usize,
    realloc_calls: usize,
    realloc_bytes: usize,
    dealloc_calls: usize,
}

impl Counts {
    fn total_alloc_calls(self) -> usize {
        self.alloc_calls + self.realloc_calls
    }
}

fn reset_counts() {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    REALLOC_CALLS.store(0, Ordering::Relaxed);
    REALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOC_CALLS.store(0, Ordering::Relaxed);
}

fn snapshot_counts() -> Counts {
    Counts {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
        realloc_bytes: REALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
    }
}

/// Temp directory that cleans itself up on drop.
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
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("{}_{}_{}", prefix, std::process::id(), stamp));
    fs::create_dir(&path)?;
    Ok(TempDir { path })
}

fn write_sample_file(dir: &TempDir, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = dir.path().join(name);
    fs::write(&path, bytes)?;
    Ok(path)
}

#[test]
#[ignore]
fn allocs_after_startup_in_engine_scan_chunk() {
    let engine = demo_engine();
    let hay = b"sk_live_0123456789abcdef";
    let mut scratch = engine.new_scratch();

    // Warm up external caches (e.g., regex internals) before counting allocations.
    let _ = engine.scan_chunk(hay, &mut scratch);

    reset_counts();
    let _ = engine.scan_chunk(hay, &mut scratch);
    let counts = snapshot_counts();

    eprintln!(
        "engine.scan_chunk allocs: calls={} bytes={} reallocs={} realloc_bytes={} deallocs={}",
        counts.alloc_calls,
        counts.alloc_bytes,
        counts.realloc_calls,
        counts.realloc_bytes,
        counts.dealloc_calls
    );

    assert_eq!(
        counts.total_alloc_calls(),
        0,
        "expected zero allocations after warm-up during scan_chunk"
    );
}

#[test]
#[ignore]
fn allocs_after_startup_in_scanner_runtime_scan_file_sync() -> io::Result<()> {
    let tmp = make_temp_dir("scanner_alloc_sync")?;
    let file = write_sample_file(&tmp, "sample.txt", b"ghp_0123456789abcdef0123456789abcdef")?;

    let engine = Arc::new(demo_engine());
    let mut runtime = ScannerRuntime::new(
        engine,
        ScannerConfig {
            chunk_size: 64,
            io_queue: 2,
            reader_threads: 1,
            scan_threads: 1,
            max_findings_per_file: 128,
        },
    );

    // Warm up external caches before counting allocations.
    let _ = runtime.scan_file_sync(scanner_rs::FileId(0), &file)?;

    reset_counts();
    let _ = runtime.scan_file_sync(scanner_rs::FileId(0), &file)?;
    let counts = snapshot_counts();

    eprintln!(
        "ScannerRuntime::scan_file_sync allocs: calls={} bytes={} reallocs={} realloc_bytes={} deallocs={}",
        counts.alloc_calls,
        counts.alloc_bytes,
        counts.realloc_calls,
        counts.realloc_bytes,
        counts.dealloc_calls
    );

    assert_eq!(
        counts.total_alloc_calls(),
        0,
        "expected zero allocations after warm-up during scan_file_sync"
    );

    Ok(())
}

#[test]
#[ignore]
fn allocs_after_startup_in_pipeline_scan_path() -> io::Result<()> {
    let tmp = make_temp_dir("scanner_alloc_pipe")?;
    let _ = write_sample_file(&tmp, "sample.txt", b"xoxr-1234567890abcdef")?;

    let engine = Arc::new(demo_engine());
    let mut pipeline: Pipeline<PIPE_FILE_RING_CAP, PIPE_CHUNK_RING_CAP, PIPE_OUT_RING_CAP> =
        Pipeline::new(engine, PipelineConfig::default());

    // Warm up external caches before counting allocations.
    let _ = pipeline.scan_path(tmp.path())?;

    reset_counts();
    let _ = pipeline.scan_path(tmp.path())?;
    let counts = snapshot_counts();

    eprintln!(
        "Pipeline::scan_path allocs: calls={} bytes={} reallocs={} realloc_bytes={} deallocs={}",
        counts.alloc_calls,
        counts.alloc_bytes,
        counts.realloc_calls,
        counts.realloc_bytes,
        counts.dealloc_calls
    );

    assert_eq!(
        counts.total_alloc_calls(),
        0,
        "expected zero allocations after warm-up during pipeline scan"
    );

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn allocs_after_startup_in_macos_aio_scan_path() -> io::Result<()> {
    let tmp = make_temp_dir("scanner_alloc_aio")?;
    let _ = write_sample_file(&tmp, "sample.txt", b"xoxa-1234567890abcdef")?;

    let engine = Arc::new(demo_engine());
    let mut scanner = scanner_rs::AioScanner::new(engine, scanner_rs::AsyncIoConfig::default())?;

    // Warm up external caches before counting allocations.
    let _ = scanner.scan_path(tmp.path())?;

    reset_counts();
    let _ = scanner.scan_path(tmp.path())?;
    let counts = snapshot_counts();

    eprintln!(
        "MacosAioScanner::scan_path allocs: calls={} bytes={} reallocs={} realloc_bytes={} deallocs={}",
        counts.alloc_calls,
        counts.alloc_bytes,
        counts.realloc_calls,
        counts.realloc_bytes,
        counts.dealloc_calls
    );

    assert_eq!(
        counts.total_alloc_calls(),
        0,
        "expected zero allocations after warm-up during macOS AIO scan"
    );

    Ok(())
}
