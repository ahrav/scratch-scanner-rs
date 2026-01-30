//! Memory Bandwidth & Throughput Ceiling Experiments
//!
//! This benchmark suite measures theoretical maximum memory bandwidth on Apple Silicon
//! (M1/M2/M3 with unified memory). Based on McCalpin's STREAM benchmark and extended
//! with cache hierarchy probing, random access patterns, and byte scanning ceilings.
//!
//! **All benchmarks run on a single core** to measure per-core throughput limits.
//!
//! # Expected Results by Cache Level (Single Core)
//!
//! | Level | Size Range | Expected Read BW |
//! |-------|------------|------------------|
//! | L1D   | < 64KB     | 150-300 GB/s     |
//! | L2    | 128KB-16MB | 80-150 GB/s      |
//! | RAM   | > 32MB     | 50-100 GB/s      |
//!
//! # Running
//!
//! ```bash
//! cargo bench --bench memory_bandwidth
//! cargo bench --bench memory_bandwidth -- stream
//! cargo bench --bench memory_bandwidth -- cache_hierarchy
//! cargo bench --bench memory_bandwidth -- memcpy
//! cargo bench --bench memory_bandwidth -- byte_scan
//! cargo bench --bench memory_bandwidth -- simd_vs_scalar
//! ```
//!
//! Note: Criterion runs benchmarks single-threaded by default, so these results
//! represent single-core throughput ceilings.

// Allow explicit index loops - we want predictable memory access patterns in benchmarks,
// not iterator optimizations that might hide the actual memory traffic.
#![allow(clippy::needless_range_loop)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::alloc::{alloc, dealloc, Layout};

// ============================================================================
// Aligned Allocation Helpers
// ============================================================================

/// Cache line alignment for Apple Silicon (128 bytes).
///
/// Apple M-series chips use 128-byte cache lines (vs 64 bytes on x86).
/// Aligning buffers to this boundary prevents false sharing and ensures
/// clean cache line boundaries for accurate bandwidth measurements.
const CACHE_LINE_ALIGN: usize = 128;

/// Allocate a cache-line-aligned buffer of `n` elements.
/// Returns a raw pointer; caller must deallocate with `aligned_dealloc`.
#[inline]
fn aligned_alloc<T: Copy + Default>(n: usize) -> *mut T {
    let size = n * std::mem::size_of::<T>();
    let layout = Layout::from_size_align(size, CACHE_LINE_ALIGN).expect("Invalid layout");
    let ptr = unsafe { alloc(layout) as *mut T };
    assert!(!ptr.is_null(), "Allocation failed");
    // Initialize with default values
    for i in 0..n {
        unsafe { ptr.add(i).write(T::default()) };
    }
    ptr
}

/// Deallocate a buffer allocated with `aligned_alloc`.
#[inline]
fn aligned_dealloc<T>(ptr: *mut T, n: usize) {
    let size = n * std::mem::size_of::<T>();
    let layout = Layout::from_size_align(size, CACHE_LINE_ALIGN).expect("Invalid layout");
    unsafe { dealloc(ptr as *mut u8, layout) };
}

/// RAII wrapper for aligned allocations.
///
/// Manages cache-line-aligned memory for benchmark buffers.
/// Uses raw pointers internally to guarantee alignment that `Vec<T>`
/// cannot provide (Vec aligns to `align_of::<T>()`, not cache lines).
///
/// # Safety
/// - `ptr` is always non-null and valid for `len` elements
/// - Memory is initialized with `T::default()` on construction
/// - Proper deallocation is handled by `Drop`
struct AlignedBuffer<T: Copy + Default> {
    ptr: *mut T,
    len: usize,
}

impl<T: Copy + Default> AlignedBuffer<T> {
    fn new(len: usize) -> Self {
        Self {
            ptr: aligned_alloc(len),
            len,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Copy + Default> Drop for AlignedBuffer<T> {
    fn drop(&mut self) {
        aligned_dealloc(self.ptr, self.len);
    }
}

// ============================================================================
// Buffer Sizes for Cache Hierarchy Probing
// ============================================================================

/// Buffer sizes spanning L1 → L2 → RAM.
/// 4KB, 32KB, 128KB, 512KB, 2MB, 8MB, 32MB, 128MB
const CACHE_PROBE_SIZES: &[(u64, &str)] = &[
    (4 * 1024, "4KB"),
    (32 * 1024, "32KB"),
    (128 * 1024, "128KB"),
    (512 * 1024, "512KB"),
    (2 * 1024 * 1024, "2MB"),
    (8 * 1024 * 1024, "8MB"),
    (32 * 1024 * 1024, "32MB"),
    (128 * 1024 * 1024, "128MB"),
];

// ============================================================================
// 1. STREAM Benchmarks (Classic Memory Bandwidth)
// ============================================================================
//
// Based on McCalpin's STREAM benchmark (https://www.cs.virginia.edu/stream/).
// These kernels measure sustainable memory bandwidth for simple operations.
// The "bytes moved" calculation accounts for both reads and writes to memory.
//
// Copy/Scale: 2N bytes (read src, write dst)
// Add/Triad:  3N bytes (read src1, read src2, write dst)

/// STREAM Copy: a[i] = b[i] (2N bytes moved)
fn bench_stream_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream/copy");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<f64>();
        let bytes_moved = 2 * size; // read b, write a
        group.throughput(Throughput::Bytes(bytes_moved));

        group.bench_with_input(BenchmarkId::new("f64", name), &n, |b, &n| {
            let mut a: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src: AlignedBuffer<f64> = AlignedBuffer::new(n);
            // Initialize source
            for (i, v) in src.as_mut_slice().iter_mut().enumerate() {
                *v = i as f64;
            }

            b.iter(|| {
                let src_slice = src.as_slice();
                let dst_slice = a.as_mut_slice();
                for i in 0..n {
                    dst_slice[i] = black_box(src_slice[i]);
                }
                black_box(dst_slice[0])
            })
        });
    }

    group.finish();
}

/// STREAM Scale: a[i] = scalar * b[i] (2N bytes moved)
fn bench_stream_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream/scale");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    let scalar: f64 = 3.0;

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<f64>();
        let bytes_moved = 2 * size;
        group.throughput(Throughput::Bytes(bytes_moved));

        group.bench_with_input(BenchmarkId::new("f64", name), &n, |b, &n| {
            let mut a: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src: AlignedBuffer<f64> = AlignedBuffer::new(n);
            for (i, v) in src.as_mut_slice().iter_mut().enumerate() {
                *v = i as f64;
            }

            b.iter(|| {
                let src_slice = src.as_slice();
                let dst_slice = a.as_mut_slice();
                let s = black_box(scalar);
                for i in 0..n {
                    dst_slice[i] = s * src_slice[i];
                }
                black_box(dst_slice[0])
            })
        });
    }

    group.finish();
}

/// STREAM Add: a[i] = b[i] + c[i] (3N bytes moved)
fn bench_stream_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream/add");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<f64>();
        let bytes_moved = 3 * size; // read b, read c, write a
        group.throughput(Throughput::Bytes(bytes_moved));

        group.bench_with_input(BenchmarkId::new("f64", name), &n, |b, &n| {
            let mut a: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src_b: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src_c: AlignedBuffer<f64> = AlignedBuffer::new(n);
            for (i, v) in src_b.as_mut_slice().iter_mut().enumerate() {
                *v = i as f64;
            }
            for (i, v) in src_c.as_mut_slice().iter_mut().enumerate() {
                *v = (i * 2) as f64;
            }

            b.iter(|| {
                let b_slice = src_b.as_slice();
                let c_slice = src_c.as_slice();
                let dst_slice = a.as_mut_slice();
                for i in 0..n {
                    dst_slice[i] = b_slice[i] + c_slice[i];
                }
                black_box(dst_slice[0])
            })
        });
    }

    group.finish();
}

/// STREAM Triad: a[i] = b[i] + scalar * c[i] (3N bytes moved)
fn bench_stream_triad(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream/triad");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    let scalar: f64 = 3.0;

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<f64>();
        let bytes_moved = 3 * size;
        group.throughput(Throughput::Bytes(bytes_moved));

        group.bench_with_input(BenchmarkId::new("f64", name), &n, |b, &n| {
            let mut a: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src_b: AlignedBuffer<f64> = AlignedBuffer::new(n);
            let mut src_c: AlignedBuffer<f64> = AlignedBuffer::new(n);
            for (i, v) in src_b.as_mut_slice().iter_mut().enumerate() {
                *v = i as f64;
            }
            for (i, v) in src_c.as_mut_slice().iter_mut().enumerate() {
                *v = (i * 2) as f64;
            }

            b.iter(|| {
                let b_slice = src_b.as_slice();
                let c_slice = src_c.as_slice();
                let dst_slice = a.as_mut_slice();
                let s = black_box(scalar);
                for i in 0..n {
                    dst_slice[i] = b_slice[i] + s * c_slice[i];
                }
                black_box(dst_slice[0])
            })
        });
    }

    group.finish();
}

// ============================================================================
// 2. Cache Hierarchy Probing
// ============================================================================
//
// These benchmarks reveal cache level transitions by varying buffer size.
// Apple M-series typical hierarchy:
//   - L1D: ~128KB per P-core (192 KB on M3), ~64KB per E-core
//   - L2:  ~16MB shared (varies by chip)
//   - RAM: Unified memory, 100-400 GB/s aggregate bandwidth
//
// Expect distinct "knees" in throughput as working set exceeds each cache level.

/// Sequential read of u64 values.
fn bench_cache_sequential_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hierarchy/seq_read");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<u64>();
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("u64", name), &n, |b, &n| {
            let mut buf: AlignedBuffer<u64> = AlignedBuffer::new(n);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = i as u64;
            }

            b.iter(|| {
                let mut sum: u64 = 0;
                let slice = buf.as_slice();
                for i in 0..n {
                    sum = sum.wrapping_add(black_box(slice[i]));
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

/// Sequential write of u64 values.
fn bench_cache_sequential_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hierarchy/seq_write");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<u64>();
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("u64", name), &n, |b, &n| {
            let mut buf: AlignedBuffer<u64> = AlignedBuffer::new(n);

            b.iter(|| {
                let slice = buf.as_mut_slice();
                for i in 0..n {
                    slice[i] = black_box(i as u64);
                }
                black_box(slice[0])
            })
        });
    }

    group.finish();
}

/// Read-modify-write of u64 values.
fn bench_cache_read_modify_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hierarchy/read_modify_write");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        let n = size as usize / std::mem::size_of::<u64>();
        // Read + Write = 2N bytes
        group.throughput(Throughput::Bytes(2 * size));

        group.bench_with_input(BenchmarkId::new("u64", name), &n, |b, &n| {
            let mut buf: AlignedBuffer<u64> = AlignedBuffer::new(n);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = i as u64;
            }

            b.iter(|| {
                let slice = buf.as_mut_slice();
                for i in 0..n {
                    slice[i] = slice[i].wrapping_add(black_box(1));
                }
                black_box(slice[0])
            })
        });
    }

    group.finish();
}

// ============================================================================
// 3. Random Access Patterns
// ============================================================================
//
// Random access benchmarks reveal memory latency rather than bandwidth.
// Sequential access hides latency via prefetching; random access cannot.
//
// Key insights:
// - Small buffers (< L2): Random ≈ sequential due to cache residency
// - Large buffers (> L2): Random degrades dramatically (each access = cache miss)
// - Useful for sizing data structures that benefit from cache locality

/// Linear Congruential Generator for deterministic random indices.
///
/// Uses Knuth's MMIX LCG constants (multiplier: 6364136223846793005, increment: 1).
/// Full 64-bit period ensures no repeated indices within benchmark iteration counts.
/// Deterministic seeding guarantees reproducible access patterns across runs.
#[inline]
fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

const RANDOM_ACCESS_COUNT: usize = 1_000_000;

/// Random read pattern - measures cache miss latency effects.
fn bench_random_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_access/read");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    // Only test larger sizes where random access matters
    let large_sizes: &[(u64, &str)] = &[
        (512 * 1024, "512KB"),
        (2 * 1024 * 1024, "2MB"),
        (8 * 1024 * 1024, "8MB"),
        (32 * 1024 * 1024, "32MB"),
        (128 * 1024 * 1024, "128MB"),
    ];

    for &(size, name) in large_sizes {
        let n = size as usize / std::mem::size_of::<u64>();
        // Each access reads 8 bytes
        group.throughput(Throughput::Bytes(RANDOM_ACCESS_COUNT as u64 * 8));

        group.bench_with_input(BenchmarkId::new("u64", name), &n, |b, &n| {
            let mut buf: AlignedBuffer<u64> = AlignedBuffer::new(n);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = i as u64;
            }

            // Pre-generate random indices
            let mut indices = Vec::with_capacity(RANDOM_ACCESS_COUNT);
            let mut rng_state = 12345u64;
            for _ in 0..RANDOM_ACCESS_COUNT {
                indices.push((lcg_next(&mut rng_state) as usize) % n);
            }

            b.iter(|| {
                let slice = buf.as_slice();
                let mut sum: u64 = 0;
                for &idx in &indices {
                    sum = sum.wrapping_add(black_box(slice[idx]));
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

/// Random write pattern.
fn bench_random_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_access/write");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    let large_sizes: &[(u64, &str)] = &[
        (512 * 1024, "512KB"),
        (2 * 1024 * 1024, "2MB"),
        (8 * 1024 * 1024, "8MB"),
        (32 * 1024 * 1024, "32MB"),
        (128 * 1024 * 1024, "128MB"),
    ];

    for &(size, name) in large_sizes {
        let n = size as usize / std::mem::size_of::<u64>();
        group.throughput(Throughput::Bytes(RANDOM_ACCESS_COUNT as u64 * 8));

        group.bench_with_input(BenchmarkId::new("u64", name), &n, |b, &n| {
            let mut buf: AlignedBuffer<u64> = AlignedBuffer::new(n);

            // Pre-generate random indices
            let mut indices = Vec::with_capacity(RANDOM_ACCESS_COUNT);
            let mut rng_state = 12345u64;
            for _ in 0..RANDOM_ACCESS_COUNT {
                indices.push((lcg_next(&mut rng_state) as usize) % n);
            }

            b.iter(|| {
                let slice = buf.as_mut_slice();
                for (i, &idx) in indices.iter().enumerate() {
                    slice[idx] = black_box(i as u64);
                }
                black_box(slice[0])
            })
        });
    }

    group.finish();
}

// ============================================================================
// 4. memcpy/memmove Baseline
// ============================================================================

/// std::ptr::copy_nonoverlapping (memcpy)
fn bench_memcpy(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcpy/copy_nonoverlapping");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        // 2x size: read source, write dest
        group.throughput(Throughput::Bytes(2 * size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut src: AlignedBuffer<u8> = AlignedBuffer::new(size);
            let dst: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in src.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                unsafe {
                    std::ptr::copy_nonoverlapping(black_box(src.ptr), dst.ptr, size);
                }
                black_box(dst.as_slice()[0])
            })
        });
    }

    group.finish();
}

/// std::ptr::copy (memmove, handles overlap)
fn bench_memmove(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcpy/memmove");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(2 * size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut src: AlignedBuffer<u8> = AlignedBuffer::new(size);
            let dst: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in src.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                unsafe {
                    std::ptr::copy(black_box(src.ptr), dst.ptr, size);
                }
                black_box(dst.as_slice()[0])
            })
        });
    }

    group.finish();
}

/// slice::copy_from_slice (idiomatic Rust)
fn bench_copy_from_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcpy/copy_from_slice");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(2 * size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut src: AlignedBuffer<u8> = AlignedBuffer::new(size);
            let mut dst: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in src.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                dst.as_mut_slice()
                    .copy_from_slice(black_box(src.as_slice()));
                black_box(dst.as_slice()[0])
            })
        });
    }

    group.finish();
}

// ============================================================================
// 5. Byte Scanning Ceiling
// ============================================================================
//
// These benchmarks establish the theoretical maximum speed for byte-by-byte
// operations - the "ceiling" that any scanner/parser/decoder cannot exceed.
//
// Compare your actual scanner throughput against these baselines:
// - If scanner < 50% of sum_scalar: significant optimization opportunity
// - If scanner ≈ memchr throughput: likely memory-bound, well optimized
// - If scanner > memchr: verify benchmark methodology (shouldn't be possible)

/// Sum all bytes (scalar).
fn bench_byte_scan_sum(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_scan/sum_scalar");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                let slice = buf.as_slice();
                let mut sum: u64 = 0;
                for &byte in slice {
                    sum = sum.wrapping_add(black_box(byte) as u64);
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

/// Find byte (scalar).
fn bench_byte_find_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_scan/find_scalar");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFE) as u8; // Never 0xFF
            }
            // Place target at end
            buf.as_mut_slice()[size - 1] = 0xFF;

            b.iter(|| {
                let slice = buf.as_slice();
                let target = black_box(0xFFu8);
                for (i, &byte) in slice.iter().enumerate() {
                    if byte == target {
                        return black_box(Some(i));
                    }
                }
                black_box(None)
            })
        });
    }

    group.finish();
}

/// Find byte using memchr.
fn bench_byte_find_memchr(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_scan/find_memchr");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFE) as u8;
            }
            buf.as_mut_slice()[size - 1] = 0xFF;

            b.iter(|| {
                let slice = buf.as_slice();
                black_box(memchr::memchr(black_box(0xFF), slice))
            })
        });
    }

    group.finish();
}

/// Count byte occurrences (scalar).
fn bench_byte_count_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_scan/count_scalar");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                let slice = buf.as_slice();
                let target = black_box(0x42u8);
                let mut count = 0usize;
                for &byte in slice {
                    if byte == target {
                        count += 1;
                    }
                }
                black_box(count)
            })
        });
    }

    group.finish();
}

// ============================================================================
// 6. SIMD vs Scalar (aarch64/NEON)
// ============================================================================
//
// Direct comparison between hand-written NEON intrinsics and scalar loops.
// On Apple Silicon, LLVM auto-vectorization is often excellent, so these
// benchmarks answer: "Is manual SIMD worth the complexity?"
//
// Typical findings:
// - Small buffers (L1): SIMD overhead may hurt; scalar is fine
// - Large buffers (RAM-bound): Both hit memory ceiling; SIMD helps less
// - Mid-size (L2): SIMD shines with 2-4x speedup

/// NEON sum_bytes (64 bytes/iteration using 4x 128-bit registers).
///
/// # Strategy
/// - **4x unrolling**: Processes 64 bytes per loop iteration (4 × 16-byte vectors).
///   This saturates the memory bus and hides instruction latency.
/// - **u16 accumulators**: Uses `vpadalq_u8` (pairwise add and accumulate) to widen
///   u8 values to u16, preventing overflow until final reduction.
/// - **Separate accumulators**: Four independent `acc0..acc3` avoid data dependencies
///   between loop iterations, enabling out-of-order execution.
///
/// Expected throughput: Near memory bandwidth ceiling for large buffers.
#[cfg(target_arch = "aarch64")]
fn bench_simd_sum_bytes(c: &mut Criterion) {
    use std::arch::aarch64::*;

    let mut group = c.benchmark_group("simd_vs_scalar/sum_neon");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                let slice = buf.as_slice();
                let ptr = slice.as_ptr();
                let chunks = size / 64;
                let remainder = size % 64;

                unsafe {
                    // Accumulate in u16 to avoid overflow, then reduce
                    let mut acc0 = vdupq_n_u16(0);
                    let mut acc1 = vdupq_n_u16(0);
                    let mut acc2 = vdupq_n_u16(0);
                    let mut acc3 = vdupq_n_u16(0);

                    for i in 0..chunks {
                        let base = ptr.add(i * 64);
                        // Load 4x 16-byte chunks
                        let v0 = vld1q_u8(base);
                        let v1 = vld1q_u8(base.add(16));
                        let v2 = vld1q_u8(base.add(32));
                        let v3 = vld1q_u8(base.add(48));

                        // Pairwise add to u16 accumulators
                        acc0 = vpadalq_u8(acc0, v0);
                        acc1 = vpadalq_u8(acc1, v1);
                        acc2 = vpadalq_u8(acc2, v2);
                        acc3 = vpadalq_u8(acc3, v3);
                    }

                    // Reduce accumulators
                    acc0 = vaddq_u16(acc0, acc1);
                    acc2 = vaddq_u16(acc2, acc3);
                    acc0 = vaddq_u16(acc0, acc2);

                    // Final reduction to scalar
                    let mut sum = vaddvq_u16(acc0) as u64;

                    // Handle remainder
                    for i in 0..remainder {
                        sum += *ptr.add(chunks * 64 + i) as u64;
                    }

                    black_box(sum)
                }
            })
        });
    }

    group.finish();
}

/// NEON find_byte using vectorized comparison.
///
/// # Strategy
/// - **16-byte chunks**: Compares 16 bytes simultaneously using `vceqq_u8`.
/// - **Fast bailout**: Uses `vmaxvq_u8` to check if any lane matched (non-zero = found).
///   This avoids extracting individual lane results on every iteration.
/// - **Fallback scan**: On match detection, scalar loop finds exact position within chunk.
///   This is rare (target at end), so cold-path overhead is acceptable.
///
/// Trade-off: Less sophisticated than memchr's multi-needle optimizations,
/// but demonstrates raw NEON comparison throughput ceiling.
#[cfg(target_arch = "aarch64")]
fn bench_simd_find_byte(c: &mut Criterion) {
    use std::arch::aarch64::*;

    let mut group = c.benchmark_group("simd_vs_scalar/find_neon");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFE) as u8;
            }
            buf.as_mut_slice()[size - 1] = 0xFF;

            b.iter(|| {
                let slice = buf.as_slice();
                let ptr = slice.as_ptr();
                let target = black_box(0xFFu8);
                let chunks = size / 16;
                let remainder = size % 16;

                unsafe {
                    let needle = vdupq_n_u8(target);

                    for i in 0..chunks {
                        let v = vld1q_u8(ptr.add(i * 16));
                        let cmp = vceqq_u8(v, needle);
                        let mask = vmaxvq_u8(cmp);
                        if mask != 0 {
                            // Found in this chunk, find exact position
                            for j in 0..16 {
                                if *ptr.add(i * 16 + j) == target {
                                    return black_box(Some(i * 16 + j));
                                }
                            }
                        }
                    }

                    // Check remainder
                    for i in 0..remainder {
                        if *ptr.add(chunks * 16 + i) == target {
                            return black_box(Some(chunks * 16 + i));
                        }
                    }

                    black_box(None)
                }
            })
        });
    }

    group.finish();
}

/// Scalar sum_bytes for comparison.
fn bench_scalar_sum_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_vs_scalar/sum_scalar");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for &(size, name) in CACHE_PROBE_SIZES {
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(BenchmarkId::new("bytes", name), &size, |b, &size| {
            let size = size as usize;
            let mut buf: AlignedBuffer<u8> = AlignedBuffer::new(size);
            for (i, v) in buf.as_mut_slice().iter_mut().enumerate() {
                *v = (i & 0xFF) as u8;
            }

            b.iter(|| {
                let slice = buf.as_slice();
                let mut sum: u64 = 0;
                for &byte in slice {
                    sum = sum.wrapping_add(byte as u64);
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    stream_benches,
    bench_stream_copy,
    bench_stream_scale,
    bench_stream_add,
    bench_stream_triad,
);

criterion_group!(
    cache_hierarchy_benches,
    bench_cache_sequential_read,
    bench_cache_sequential_write,
    bench_cache_read_modify_write,
);

criterion_group!(random_access_benches, bench_random_read, bench_random_write,);

criterion_group!(
    memcpy_benches,
    bench_memcpy,
    bench_memmove,
    bench_copy_from_slice,
);

criterion_group!(
    byte_scan_benches,
    bench_byte_scan_sum,
    bench_byte_find_scalar,
    bench_byte_find_memchr,
    bench_byte_count_scalar,
);

#[cfg(target_arch = "aarch64")]
criterion_group!(
    simd_benches,
    bench_simd_sum_bytes,
    bench_simd_find_byte,
    bench_scalar_sum_bytes,
);

#[cfg(not(target_arch = "aarch64"))]
criterion_group!(simd_benches, bench_scalar_sum_bytes,);

criterion_main!(
    stream_benches,
    cache_hierarchy_benches,
    random_access_benches,
    memcpy_benches,
    byte_scan_benches,
    simd_benches,
);
