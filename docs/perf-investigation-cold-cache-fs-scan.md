# Performance Investigation: Cold-Cache FS Scan Bottleneck

**Date:** 2026-02-09
**Workload:** `scanner-rs scan fs --path="../linux" --null-sink` (Linux kernel source tree)
**Platform:** Amazon Linux 2 (aarch64), 16 CPUs, likely EBS-backed storage

## Observations

| Metric | Run 1 (cold) | Run 2 (warm VS cache) | Run 3 (warm VS + page cache) |
|--------|-------------|----------------------|------------------------------|
| init_ms | 5,055 | 233 | 196 |
| scan_ms | 35,355 | 37,822 | 865 |
| elapsed_ms | 40,410 | 38,055 | 1,061 |
| throughput MiB/s | 41.80 | 39.07 | 1,708.17 |
| CPU utilization | 51% | 42% | 1200% |

Common across all runs:
- files=92,138, chunks=93,990, bytes=1,549,666,830 (~1.55 GB)
- findings=2,894, errors=0, binary_skipped=6, workers=16

## Root Causes

### 1. Vectorscan DB cache explains init_ms (5,055 → 196 ms)

The engine compiles 223 regex rules into multiple Vectorscan/Hyperscan
databases via `hs_compile_multi()`. On first run, this takes ~5 seconds.
After compilation, databases are serialized to `~/.cache/scanner-rs/vsdb/*.hsdb`
with BLAKE3 key derivation and AEGIS-128L integrity tags (`vs_cache.rs`).

Subsequent runs deserialize from cache in ~200ms. **This is working as
designed and is not a problem.**

### 2. Page cache explains scan_ms (37,822 → 865 ms) — but 38s is too slow

With warm page cache, all 1.55 GB is served from RAM. Workers saturate
16 CPUs (1200%) doing regex matching. **The warm-cache throughput of
1,708 MiB/s is good.**

With cold page cache, throughput drops to ~40 MiB/s at 42% CPU. Workers
spend ~58% of their time blocked on I/O syscalls. **This 43x gap is the
problem under investigation.**

## Architecture Confirmation: Design A is in place

The codebase already implements the recommended "single walker + file tasks"
architecture:

| Component | Implementation | File |
|-----------|---------------|------|
| Discovery | `IterWalker` wrapping `ignore::Walk` (single-threaded DFS) | `parallel_scan.rs:411-413` |
| File source | `FileSource` trait, inline on caller thread, no background thread | `parallel_scan.rs:430-446` |
| Work distribution | `Executor<FileTask>` work-stealing (Chase-Lev deques) | `local_fs_owner.rs:3116` |
| Backpressure | `CountBudget` (max 1,024 in-flight files) | `local_fs_owner.rs:3100` |
| Buffer pool | `TsBufferPool` (64 × 256 KB = 16 MB, lock-free) | `local_fs_owner.rs:3092` |

No `build_parallel()`, no bounded channel, no background walker thread.
The architecture is correct. The inefficiency is in the I/O hot path.

## File Characteristics

- Average file size: 1,549,666,830 / 92,138 ≈ **16.8 KB**
- Chunks per file: 93,990 / 92,138 ≈ **1.02** (nearly every file fits in one 256 KB buffer)
- The workload is many-small-files, not few-large-files

## Per-File Syscall Sequence (hot path)

From `local_fs_owner.rs:2687-2990`, each file incurs:

```
1. open(path)              ← line 2687        syscall
2. fstat(fd)               ← line 2701        syscall (metadata for size)
3. read(fd, 512)           ← line 2733        syscall (archive/binary probe)
4. seek(fd, 0)             ← line 2790        syscall (rewind after probe)
5. pool.acquire()          ← line 2849        may block (buffer contention)
6. read(fd, 256KB)         ← line 2878        syscall (actual scan data)
7. engine.scan_chunk()     ← line 2916        CPU work
8. close(fd)               ← implicit drop    syscall
```

**6 syscalls per file × 92K files = ~550K syscalls**, spread across 16 workers.

## Identified Bottlenecks

### B1: No readahead hints (high impact, easy fix)

The kernel has no indication that file reads are sequential or that
the next file will be read soon. No `posix_fadvise(POSIX_FADV_SEQUENTIAL)`
calls exist anywhere in the codebase (confirmed via grep).

On cold cache with many small files, the kernel's default readahead
heuristic is unlikely to help because:
- Each file is opened, read once, and closed
- 16 threads create an unpredictable access pattern
- Readahead window has no time to ramp up for 16 KB files

### B2: Redundant probe read + seek on every file (medium impact, easy fix)

Steps 3-4 (archive/binary sniffing) add 2 syscalls per file. For the
92K files in the Linux tree, only 6 are binary. The probe read could
be folded into the first real read:

- Read the first 256 KB chunk
- Use the first 512 bytes for archive/binary classification
- If text, scan the already-loaded buffer (no seek needed)

This would eliminate ~184K syscalls (2 per file × 92K files).

### B3: No I/O pipelining between files (high impact, harder fix)

Each worker processes files sequentially: open → read → scan → next.
While scanning file N, the worker could be issuing `open()` + `readahead()`
for file N+1. This double-buffering pattern would hide I/O latency
behind CPU work.

### B4: Single-threaded directory discovery (low-medium impact)

`ignore::Walk` is single-threaded. For the Linux kernel tree (~5K
directories), discovery of 92K entries with gitignore filtering takes
a non-trivial amount of time. Workers may starve early in the run
while the walker builds up the batch queue.

The code comments explain why `WalkParallel` was rejected (pathological
behavior on large flat directories). This is a valid concern, but the
trade-off may be worth revisiting with a capped thread count.

### B5: io_uring path exists but is not wired into `scan fs` (high impact, significant work)

`local_fs_uring.rs` implements a full io_uring-based scanner with:
- Batched syscalls (open + read combined)
- CPU workers never block on I/O
- Separate I/O and CPU thread pools

This is feature-gated behind `io-uring` and not integrated into the
`scan fs` CLI path. It was designed exactly for this cold-cache scenario.

## Estimated Impact

| Fix | Syscalls saved | Expected improvement | Effort |
|-----|---------------|---------------------|--------|
| B2: Fold probe into first read | ~184K (33%) | 5-15% scan time | Small |
| B1: posix_fadvise per file | 0 (adds 1) | 10-30% on cold cache | Trivial |
| B3: Double-buffer I/O pipeline | 0 | 20-40% on cold cache | Medium |
| B5: Wire io_uring into CLI | All batched | 50-70% on cold cache | Large |

## Recommended Next Steps

1. **Profile first**: Run with `perf stat` and/or `strace -c` to get
   actual syscall counts and I/O wait breakdown. This doc is based on
   code reading, not measurement.

2. **B2 + B1** are quick wins that can be validated independently.

3. **B5** (io_uring integration) is the real solution for cold-cache
   performance but requires wiring an existing implementation into the
   CLI path.

---

## Phase 2: io_uring Integration & Profiling (2026-02-09)

### Changes Made

B1 (readahead) and B2 (fold probe into first read) were implemented in a
prior session and reduced cold-cache scan from 38s to 31.5s (17%). B5
(io_uring integration) was then wired as the default FS scanner on Linux:

| Change | File(s) |
|--------|---------|
| Remove `io-uring` feature gate, compile unconditionally on Linux | `Cargo.toml`, `local_fs_uring.rs`, `mod.rs` |
| cfg-gated dispatch: uring on Linux, blocking elsewhere | `orchestrator.rs` |
| Fix pool_buffers starvation (was at exact minimum, no CPU headroom) | `orchestrator.rs` |
| Rewrite discovery walker to use `d_type` instead of `symlink_metadata` | `local_fs_uring.rs` |

### Measured Results

**Workload**: 92,138 files, 94,205 chunks, 1.6 GB (Linux kernel tree)

| Scanner | Cold-cache wall time | Throughput | Avg IOPS |
|---------|---------------------|------------|----------|
| Blocking (16 workers) | 31.5s | 48.3 MiB/s | ~8,800 |
| io_uring (4 IO threads × 128 depth) | 28.6s | 53.9 MiB/s | ~9,800 |
| **Improvement** | **2.9s (9.2%)** | | |

### Root Cause: EBS IOPS Ceiling

The bottleneck is the EBS GP3 volume's IOPS limit, not software I/O
strategy. Higher io_uring queue depth cannot overcome the storage device's
throughput ceiling.

**Raw IOPS measurement** (10K random files, open+fstat+read per file):

| Queue Depth | Measured IOPS | Method |
|-------------|---------------|--------|
| QD=1 (serial, cold cache) | 4,487 | Python open+fstat+read loop |
| QD=1 (serial, warm cache) | 97,199 | Same, page cache hot |
| QD=16 (blocking scanner) | ~8,800 | 278K ops / 31.5s |
| QD=128 (io_uring scanner) | ~9,800 | 278K ops / 28.5s |

EBS GP3 shows **diminishing IOPS returns past QD=16**. Going from QD=16
to QD=128 yields only ~11% more IOPS. Both scanners perform ~278K I/O ops
(92K opens + 92K stats + 94K reads) and are bounded by the same device.

### Bug Found: Redundant Stat Syscalls in Discovery Walker

The original `walk_and_send_files` called `fs::symlink_metadata()` (statx
syscall) for every entry — 98,349 blocking syscalls on one thread. This was:

1. **Unnecessary**: `DirEntry::file_type()` uses `d_type` from `getdents64`
   (zero-cost, no syscall on ext4/xfs/btrfs)
2. **Duplicated**: The IO thread already does statx via io_uring for each file
3. **Serialized**: Single-threaded blocking on cold cache

**Syscall counts (via `sudo perf stat -e syscalls:*`):**

| Syscall | Before fix | After fix |
|---------|-----------|-----------|
| `statx` (discovery, blocking) | 98,349 | 7 |
| `getdents64` (discovery) | 12,232 | 12,232 |
| `io_uring_enter` (IO threads) | 140,221 | 130,885 |

The fix eliminated 98K blocking stat calls but only improved wall time by
~1.5s because **discovery was throttled by IO pipeline backpressure**, not
by its own syscall overhead. The `CountBudget` (1024 permits) and bounded
channel (256 cap) block discovery when the IO pipeline can't drain fast
enough.

### Phase Timing Evidence

With instrumentation added to `scan_local_fs_uring`:

```
PHASE_TIMING: discovery=28.727s  io_join=0.006s  cpu_join=0.000s
```

Discovery accounts for 100% of wall time. IO threads finish in 6ms after
discovery completes. CPU executor finishes instantly. This confirms discovery
is blocked on backpressure from the IO pipeline, which is itself IOPS-bound.

### CPU Profile (`perf record -g --call-graph dwarf`)

```
94.5%  scanner-worker-   scan_chunk_into, find_spans_into, Hyperscan
 5.5%  scanner-rs        main thread (discovery walk)
 ~0%   io threads        all time in kernel (io_uring_enter)
```

CPU executor threads are never the bottleneck. They drain the IO pipeline
faster than IO can fill it (~0.18ms per chunk scan vs ~0.1ms per chunk IO
at 10K IOPS).

### io_uring Pipeline Analysis

Each file traverses 3 sequential io_uring stages:

```
OPENAT (disk) → STATX (in-memory after open) → READ (disk)
```

With `io_depth=128` shared across stages and the STATX stage being
essentially free (inode cached after open), effective concurrent **disk**
operations per thread is ~85 (128 × 2/3). Total disk concurrency across
4 threads: ~340.

**io_uring_enter batching**: 130K enters for 278K ops = ~2.1 ops per enter.
This is low, driven by the IO pipeline processing only ~3K files/sec
(IOPS-limited), so few completions accumulate between enter calls.

### Storage Device Details

```
Device:      Amazon Elastic Block Store (NVMe)
Size:        560 GB
Filesystem:  ext4
Scheduler:   none (NVMe passthrough)
nr_requests: 63
max_hw_sectors_kb: 256
```

### What Would Help Further

| Optimization | Expected Impact | Rationale |
|---|---|---|
| Faster storage (io2, local NVMe) | Large | NVMe scales linearly to QD=128+; EBS plateaus at QD=16 |
| Eliminate io_uring STATX stage | ~5-10% | Use blocking fstat after open (free from inode cache); deepens read pipeline |
| Parallel discovery | Marginal on EBS | Helps on local NVMe where discovery could be the bottleneck |
| io_uring SQE linking (open→stat) | Small | Reduces io_uring_enter count; marginal on this workload |

### Conclusion

The io_uring integration is working correctly (verified via `perf-stats`
debug build: all 92K opens, 92K stats, 94K reads go through io_uring).
The ~9% cold-cache improvement is close to the ceiling for this EBS volume.
On local NVMe storage where IOPS scale with queue depth, the improvement
should be substantially larger.
