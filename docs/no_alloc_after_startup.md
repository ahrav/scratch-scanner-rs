# No-Allocation-After-Startup Investigation (Async Scanners)

This document records the current findings on eliminating allocations after startup
for the async scanning paths. "Startup" here means construction of the scanner
(e.g., `UringScanner::new` / `MacosAioScanner::new`). Allocations during setup
are acceptable; allocations during `scan_path` and the scan loop are not.

## Current Status (as of 2026-01-27)

Already addressed:
- Async scanner state is hoisted into the scanner struct so `scan_path` does not
  allocate `FileTable`, `Walker`, `ScanScratch`, `pending`, or `BufWriter` on
  each scan.
- Async walker stack uses a fixed-capacity `ScratchVec` to avoid growth.

Still allocating during scans:
- **Path handling**: per-entry `PathBuf` allocation via `DirEntry::path()` and
  storage in `FileTable`.
- **macOS AIO per-file buffers**: `AioFileReader::new` allocates per file
  (`slots`, `free_slots`, `ready_seq`, `ready_slot`, `tail`, `wait_list`).
- **Output formatting**: `path.display()` can allocate for non-UTF8 paths.

## Root Causes

1) **Path ownership via std::fs::read_dir**
   - `read_dir` yields `DirEntry`, and calling `path()` constructs a new
     `PathBuf` per entry.
   - Storing `PathBuf` in `FileTable` necessarily allocates per file.

2) **macOS AIO reader instantiation**
   - The reader owns several `Vec`s created per file. Even with capacities set,
     these allocations occur inside the scan loop.

3) **Display formatting**
   - `path.display()` may allocate to create a lossy UTF-8 representation.

## What "Zero Allocations Mid-Scan" Would Entail

### A) Path Storage Without `PathBuf`

To remove path allocations entirely during scans, the walk must avoid
`DirEntry::path()` and store path bytes in preallocated memory.

The only strictly allocation-free approach is to replace `std::fs::read_dir`
with `openat` + `fdopendir` + `readdir` so we can read raw `dirent` names
without allocating `OsString`/`PathBuf`.

#### Options for path storage

1) **Fixed-size path slots (simpler, more memory)**
   - Allocate a fixed number of `PATH_SLOT_SIZE` slots from a pool.
   - Store `(slot_id, len)` in `FileTable` instead of `PathBuf`.
   - Pros: simple, deterministic, no per-scan allocation.
   - Cons: memory heavy; long paths may require a larger slot size or truncation.

2) **Block-chained arena (moderate memory, higher complexity)**
   - Use `NodePoolType<BLOCK_SIZE>` and chain blocks to store arbitrary-length
     paths.
   - Store `(head_block, len)` in `FileTable`.
   - Pros: lower memory than fixed slots, still deterministic.
   - Cons: more complex; needs careful lifetime and traversal logic.

3) **Partial reduction (not strictly zero allocations)**
   - Use a preallocated arena for path bytes but still call `DirEntry::path()`.
   - This reduces allocations but does not eliminate them.

### B) macOS AIO Reuse

Make `AioFileReader` a lightweight view over scanner-owned buffers:
- Move `slots`, `free_slots`, `ready_seq`, `ready_slot`, `tail`, and `wait_list`
  into `MacosAioScanner`.
- Convert `AioFileReader::new` into a `reset_for_file` that rewinds state.
- Use `ScratchVec` or fixed arrays sized at startup.

### C) Output Without Allocation

For Unix, use `OsStrExt::as_bytes()` and write raw bytes. If a printable or
escaped form is required, write into a preallocated `ScratchVec<u8>` and reuse
it across outputs.

## Leveraging Existing Data Structures

- `scratch_memory::ScratchVec`
  - Best fit for fixed-capacity vectors used in walkers and AIO bookkeeping.
  - Already used for the async walker stack.

- `stdx::RingBuffer`
  - Good for fixed-capacity queues/stacks with compile-time capacity.
  - Useful if `queue_depth` becomes a compile-time constant.

- `stdx::Queue` (intrusive)
  - Useful for free lists when using block pools for the path arena.

- `stdx::ReleasedSet` / `FixedSet`
  - Useful for tracking released IDs or deduping without allocations.

- `pool::NodePoolType`
  - Best suited for fixed-size blocks; good for:
    - path slot pools
    - block-chained path arena
    - any deterministic, reusable byte storage

## Recommended Next Steps (If Zero Allocations Mid-Scan Is Required)

1) **Decide on path storage strategy**
   - Fixed-slot pool (simpler, larger memory) vs block-chained arena (smaller
     memory, more complexity).

2) **Switch async walker to `openat` + `readdir`**
   - This is required to avoid per-entry `PathBuf`/`OsString` allocations.
   - Keep the rest of the pipeline intact by storing paths as `(id, len)` and
     reconstructing `&Path` views from arena bytes when needed.

3) **Refactor macOS AIO reader to reuse buffers**
   - Move per-file allocations into `MacosAioScanner` and reset between files.

4) **Review output path formatting**
   - Avoid `path.display()` in hot output; write bytes directly or via
     preallocated scratch buffers.

## Files Touched or Related

- `src/async_io/linux.rs`
- `src/async_io/macos.rs`
- `src/async_io/mod.rs`
- `src/runtime.rs`
- `src/pool/node_pool.rs`
- `src/stdx/*`
- `src/scratch_memory.rs`
