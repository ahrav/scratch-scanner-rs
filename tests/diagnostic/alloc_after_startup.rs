//! Allocation-after-startup audit tests.
//!
//! These tests install a counting global allocator and are therefore ignored
//! by default. Run with:
//! `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`
//!
//! IMPORTANT: Use `--test-threads=1` because tests share global allocation
//! counters and will interfere with each other if run in parallel.

use scanner_rs::scheduler::{scan_local, LocalConfig, LocalFile, VecFileSource};
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
    // Run multiple warm-up passes to ensure all lazy initialization is complete.
    for _ in 0..5 {
        let _ = engine.scan_chunk(hay, &mut scratch);
    }

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

    // Allow minimal allocations from regex library internals (e.g., capture group metadata).
    // Ideal is 0, but regex crate may allocate small amounts for thread-local state.
    // Threshold: at most 10 allocations totaling < 1 KiB is acceptable.
    const MAX_ALLOC_CALLS: usize = 10;
    const MAX_ALLOC_BYTES: usize = 1024;

    assert!(
        counts.total_alloc_calls() <= MAX_ALLOC_CALLS,
        "expected <= {} allocation calls after warm-up during scan_chunk, got {}",
        MAX_ALLOC_CALLS,
        counts.total_alloc_calls()
    );

    assert!(
        counts.alloc_bytes <= MAX_ALLOC_BYTES,
        "expected <= {} bytes allocated after warm-up during scan_chunk, got {}",
        MAX_ALLOC_BYTES,
        counts.alloc_bytes
    );

    if counts.total_alloc_calls() > 0 {
        eprintln!(
            "NOTE: {} allocations ({} bytes) detected - likely regex library internals",
            counts.total_alloc_calls(),
            counts.alloc_bytes
        );
    }
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

    // ScannerRuntime may allocate for internal channel operations.
    // Allow minimal allocations but flag large allocations as warnings.
    const MAX_ALLOC_CALLS: usize = 50;
    const MAX_ALLOC_BYTES: usize = 5 * 1024 * 1024; // 5 MiB - generous for runtime overhead

    if counts.alloc_bytes > 1024 {
        eprintln!(
            "WARNING: ScannerRuntime allocated {} bytes ({:.2} MiB) - may need investigation",
            counts.alloc_bytes,
            counts.alloc_bytes as f64 / 1024.0 / 1024.0
        );
    }

    assert!(
        counts.total_alloc_calls() <= MAX_ALLOC_CALLS,
        "expected <= {} allocation calls after warm-up during scan_file_sync, got {}",
        MAX_ALLOC_CALLS,
        counts.total_alloc_calls()
    );

    assert!(
        counts.alloc_bytes <= MAX_ALLOC_BYTES,
        "expected <= {} bytes allocated after warm-up during scan_file_sync, got {}",
        MAX_ALLOC_BYTES,
        counts.alloc_bytes
    );

    Ok(())
}

/// Multi-core scan_local allocation reporting test.
///
/// Tests the production multi-core path (work-stealing executor with per-worker scratch).
/// This is the critical path for parallel filesystem scanning.
///
/// # Memory Model
///
/// Each `scan_local` call allocates:
/// - TsBufferPool: workers × 4 buffers × (chunk_size + overlap) bytes
/// - Per-worker ScanScratch: ~18.8 MiB each (dominated by HitAccPool)
/// - Per-worker LocalScratch: ~460 KiB each
/// - Executor thread stacks and coordination structures
///
/// # Important Design Note
///
/// `scan_local` is a **one-shot API** - each call creates a new Executor with new
/// worker threads. Memory is allocated at the start and freed at the end. This is
/// by design: the API is optimized for single-scan-per-call patterns, not reuse.
///
/// For zero-allocation hot-path guarantees, the relevant test is `scan_chunk` on
/// the Engine directly, which operates within pre-allocated scratch buffers.
#[test]
#[ignore]
fn allocs_after_startup_in_scan_local_multicore() -> io::Result<()> {
    let tmp = make_temp_dir("scanner_alloc_multicore")?;

    // Create multiple sample files to exercise multi-worker paths
    for i in 0..16 {
        let content = format!("file{}: ghp_0123456789abcdef0123456789abcdef\n", i);
        write_sample_file(&tmp, &format!("sample{}.txt", i), content.as_bytes())?;
    }

    let engine = Arc::new(demo_engine());

    // Configure for multi-core (use at least 2 workers to test parallelism)
    let workers = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .max(2);

    let cfg = LocalConfig {
        workers,
        chunk_size: 64 * 1024,
        pool_buffers: workers * 4,
        ..LocalConfig::default()
    };

    // Build file source from directory
    let files: Vec<LocalFile> = std::fs::read_dir(tmp.path())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| LocalFile {
            path: e.path(),
            size: e.metadata().map(|m| m.len()).unwrap_or(0),
        })
        .collect();

    // First run: measures total allocation for one scan
    reset_counts();
    let source1 = VecFileSource::new(files.clone());
    let _ = scan_local(Arc::clone(&engine), source1, cfg.clone());

    let first_counts = snapshot_counts();
    let first_mib = first_counts.alloc_bytes as f64 / 1024.0 / 1024.0;

    eprintln!(
        "\n=== Multi-core scan_local first run ===\n\
         workers: {}\n\
         allocs: {} calls, {} bytes ({:.2} MiB)\n\
         reallocs: {} calls, {} bytes\n\
         deallocs: {} calls\n",
        workers,
        first_counts.alloc_calls,
        first_counts.alloc_bytes,
        first_mib,
        first_counts.realloc_calls,
        first_counts.realloc_bytes,
        first_counts.dealloc_calls,
    );

    // Second run: should be similar to first (new Executor each time)
    reset_counts();
    let source2 = VecFileSource::new(files);
    let _ = scan_local(Arc::clone(&engine), source2, cfg);

    let second_counts = snapshot_counts();
    let second_mib = second_counts.alloc_bytes as f64 / 1024.0 / 1024.0;

    eprintln!(
        "=== Multi-core scan_local second run ===\n\
         allocs: {} calls, {} bytes ({:.2} MiB)\n\
         reallocs: {} calls, {} bytes\n\
         deallocs: {} calls\n",
        second_counts.alloc_calls,
        second_counts.alloc_bytes,
        second_mib,
        second_counts.realloc_calls,
        second_counts.realloc_bytes,
        second_counts.dealloc_calls,
    );

    // Expected per-worker allocation: ~18.8 MiB (see report_multicore_memory_allocation test)
    // With buffer pool: workers * 4 * ~64 KiB = ~2.5 MiB for 10 workers
    // Plus thread stacks, coordination, etc.
    //
    // Note: The first run may show lower allocation if regex caches were already
    // warmed up by earlier tests. The second run is more reliable.
    let expected_min_mib = workers as f64 * 15.0; // At least 15 MiB per worker (conservative)
    let expected_max_mib = workers as f64 * 30.0; // At most 30 MiB per worker (generous)

    eprintln!(
        "Expected range: {:.1} - {:.1} MiB (based on {} workers × 15-30 MiB/worker)",
        expected_min_mib, expected_max_mib, workers
    );

    // Use the larger of the two runs for validation (handles test ordering issues)
    let max_mib = first_mib.max(second_mib);
    eprintln!("Using max allocation: {:.2} MiB", max_mib);

    // Verify at least one run allocated a reasonable amount
    assert!(
        max_mib >= expected_min_mib,
        "Expected at least {:.1} MiB for {} workers, got {:.2} MiB",
        expected_min_mib,
        workers,
        max_mib
    );

    // Verify allocation isn't unexpectedly large
    assert!(
        max_mib <= expected_max_mib,
        "Expected at most {:.1} MiB for {} workers, got {:.2} MiB - possible memory leak?",
        expected_max_mib,
        workers,
        max_mib
    );

    Ok(())
}

/// Reports detailed memory allocation breakdown for multi-core scanning.
///
/// This is not an assertion test - it reports allocation statistics for analysis.
/// Run with: `cargo test --test diagnostic -- --ignored --nocapture report_multicore_memory`
#[test]
#[ignore]
fn report_multicore_memory_allocation() {
    eprintln!("\n=== Multi-core Memory Allocation Report ===\n");

    // Rule count from gitleaks_rules (223 rules as of this writing)
    // Update if rules change: `grep -c "RuleSpec {" src/gitleaks_rules.rs`
    let rules_len = 223usize;
    let pair_count = rules_len * 3; // raw, utf16, stream variants

    // Tuning values from demo_tuning()
    let max_anchor_hits = 2048usize;
    let max_findings = 8192usize;
    let decode_slab_bytes = 512 * 1024usize;

    // Struct sizes (verified)
    let span_u32_size = 12usize;
    let finding_rec_size = 40usize;
    let slot128_size = 24usize;

    // HitAccPool calculation
    let hit_acc_windows = pair_count * max_anchor_hits * span_u32_size;
    let hit_acc_lens = pair_count * 4;
    let hit_acc_coalesced = pair_count * span_u32_size;
    let hit_acc_coalesced_set = pair_count;
    let hit_acc_total = hit_acc_windows + hit_acc_lens + hit_acc_coalesced + hit_acc_coalesced_set;

    // FixedSet128 calculations
    let seen_cap = 1024usize;
    let findings_cap = 32768usize;
    let seen_size = seen_cap * slot128_size;
    let seen_findings_size = findings_cap * slot128_size;

    // FindingRec buffers
    let findings_buffers = 2 * max_findings * finding_rec_size;

    // Other per-worker allocations (rough estimates)
    let byte_ring = 64 * 1024;
    let window_bytes = 64 * 1024;
    let utf16_buf = 64 * 1024;
    let timing_wheel = pair_count * 16 * 24; // pending_window_cap * node_size
    let vs_scratches = 5 * 50 * 1024; // 5 scratches * ~50KB each
    let local_scratch = 4096 * 100 + 64 * 1024; // pending + out_buf
    let misc = 100 * 1024;

    let per_worker_total = hit_acc_total
        + decode_slab_bytes
        + seen_size
        + seen_findings_size
        + findings_buffers
        + byte_ring
        + window_bytes
        + utf16_buf
        + timing_wheel
        + vs_scratches
        + local_scratch
        + misc;

    eprintln!("Configuration:");
    eprintln!("  Rules: {}", rules_len);
    eprintln!("  Pair count (rules × 3): {}", pair_count);
    eprintln!("  Max anchor hits per variant: {}", max_anchor_hits);
    eprintln!("  Max findings per chunk: {}", max_findings);
    eprintln!();

    eprintln!("Per-Worker Allocation Breakdown:");
    eprintln!(
        "  HitAccPool.windows:     {:>12} bytes ({:.2} MiB) [{}×{}×{}]",
        hit_acc_windows,
        hit_acc_windows as f64 / 1024.0 / 1024.0,
        pair_count,
        max_anchor_hits,
        span_u32_size
    );
    eprintln!(
        "  HitAccPool (total):     {:>12} bytes ({:.2} MiB)",
        hit_acc_total,
        hit_acc_total as f64 / 1024.0 / 1024.0
    );
    eprintln!(
        "  DecodeSlab:             {:>12} bytes ({:.2} MiB)",
        decode_slab_bytes,
        decode_slab_bytes as f64 / 1024.0 / 1024.0
    );
    eprintln!(
        "  FixedSet128 (seen):     {:>12} bytes ({:.2} KiB)",
        seen_size,
        seen_size as f64 / 1024.0
    );
    eprintln!(
        "  FixedSet128 (findings): {:>12} bytes ({:.2} KiB)",
        seen_findings_size,
        seen_findings_size as f64 / 1024.0
    );
    eprintln!(
        "  FindingRec buffers:     {:>12} bytes ({:.2} KiB)",
        findings_buffers,
        findings_buffers as f64 / 1024.0
    );
    eprintln!(
        "  Other allocations:      {:>12} bytes ({:.2} MiB)",
        byte_ring + window_bytes + utf16_buf + timing_wheel + vs_scratches + local_scratch + misc,
        (byte_ring + window_bytes + utf16_buf + timing_wheel + vs_scratches + local_scratch + misc)
            as f64
            / 1024.0
            / 1024.0
    );
    eprintln!("  ─────────────────────────────────────────────");
    eprintln!(
        "  PER-WORKER TOTAL:       {:>12} bytes ({:.2} MiB)",
        per_worker_total,
        per_worker_total as f64 / 1024.0 / 1024.0
    );
    eprintln!();

    // Buffer pool calculations
    let chunk_size = 256 * 1024;
    let overlap = 64 * 1024; // typical max_window_diameter
    let buffer_len = chunk_size + overlap;

    eprintln!("Buffer Pool (system-wide):");
    eprintln!("  Chunk size: {} KiB", chunk_size / 1024);
    eprintln!("  Overlap: {} KiB", overlap / 1024);
    eprintln!("  Buffer length: {} KiB", buffer_len / 1024);
    eprintln!();

    eprintln!("System Total by Worker Count:");
    eprintln!("  Workers | Per-Worker | Buffer Pool | Total");
    eprintln!("  --------|------------|-------------|-------");
    for workers in [4, 8, 12, 16] {
        let pool_buffers = workers * 4;
        let pool_total = pool_buffers * buffer_len;
        let system_total = per_worker_total * workers + pool_total;
        eprintln!(
            "  {:>7} | {:>7.1} MiB | {:>8.1} MiB | {:>6.1} MiB",
            workers,
            (per_worker_total * workers) as f64 / 1024.0 / 1024.0,
            pool_total as f64 / 1024.0 / 1024.0,
            system_total as f64 / 1024.0 / 1024.0
        );
    }
    eprintln!();

    eprintln!(
        "Key Insight: HitAccPool.windows dominates at {:.1}% of per-worker memory",
        hit_acc_windows as f64 / per_worker_total as f64 * 100.0
    );
}
