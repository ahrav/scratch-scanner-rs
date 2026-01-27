# TigerStyle Allocation-After-Startup Audit

Date: 2026-01-27

## TigerStyle Requirement (Relevant Excerpt)

From `docs/TIGER_STYLE.md`:

"All memory must be statically allocated at startup. **No memory may be dynamically allocated (or
freed and reallocated) after initialization.**"

## Scope and Definition

Scope: `src/` production code (tests excluded). This audit treats **startup** as the point where the
engine/scanner/pipeline object is constructed. Any heap allocation during `scan_*` methods or
per-file/per-chunk processing is considered a violation.

## Findings: Allocations After Startup

### Engine API surface (allocation-free if scratch/output reused)

- `src/engine/mod.rs`:
  - `Engine::scan_chunk` now takes `&mut ScanScratch` and returns `&[FindingRec]`.
    - Allocation-free after startup if the caller reuses the scratch.
  - `Engine::scan_chunk_materialized` writes into a caller-supplied `Vec<Finding>`.
    - Allocation-free if `out` is pre-sized (e.g., `with_capacity(max_findings_per_chunk)`).
  - `Engine::scan_chunk_records` returns a shared slice into the scratch buffer.
  - `Finding.decode_steps` is now `FixedVec` (inline storage), removing per-finding heap allocs.

Impact: The engine can be allocation-free after startup, but allocations still
occur if callers construct scratch/output buffers per call or allow `Vec` growth.

### Regex crate allocations (out of scope for this pass)

We are not modifying the `regex` crate or vendoring patches for this task. Any
allocations that occur inside regex internals (e.g., cache growth) are treated as
external and out of scope. We warm caches once before measurement to focus on
allocations under our control.

### Sync runtime (allocation-free after startup)

- `src/runtime.rs`:
  - `ScannerRuntime` now owns `ScanScratch`, an output buffer, and the overlap `tail` buffer.
  - `ScannerRuntime::scan_file_sync` takes `&mut self` and returns a slice into the internal
    output buffer.
  - `read_file_chunks` now uses a caller-provided `tail` buffer to avoid per-scan allocation.
  - `ScannerConfig::max_findings_per_file` bounds the output buffer size; the scan returns an
    error if capacity is exceeded.

Impact: The sync runtime is allocation-free after startup when `max_findings_per_file` is sized
for expected workloads.

### Pipeline (per scan allocations inside `scan_path`)

- `src/pipeline.rs`:
  - `Pipeline::scan_path` constructs these each call:
    - `FileTable::with_capacity` (allocates 4 Vecs)
    - `Walker::new` (allocates DFS stack)
    - `ReaderStage::new` (allocates overlap `tail` vec)
    - `ScanStage::new` (allocates `pending` vec)
    - `OutputStage::new` (allocates `BufWriter` buffer)
  - `Walker` uses `fs::read_dir` and `DirEntry::path()` which allocates a `PathBuf` per entry.
  - Output formatting uses `path.display()` inside the output loop (may allocate for non-UTF8 paths).

Impact: Pipeline scans allocate per invocation and per file.

### Async scanners (shared walker + path handling)

- `src/async_io/mod.rs` walker:
  - `Walker::reset(path.to_path_buf())` allocates per scan.
  - `DirEntry::path()` allocates a `PathBuf` per entry.
  - `FileTable::push` stores `PathBuf` per file (alloc per file).

Impact: Async scanners allocate per scan and per file from path handling alone.

### macOS AIO (per file allocations in reader)

- `src/async_io/macos.rs`:
  - `AioFileReader::new` allocates per file:
    - `slots: Vec<AioSlot>`
    - `free_slots: Vec<usize>`
    - `ready_seq: Vec<u64>`
    - `ready_slot: Vec<usize>`
    - `tail: Vec<u8>`
    - `wait_list: Vec<*const aiocb>`

Impact: Even with a pre-built `MacosAioScanner`, each file scanned allocates multiple vectors.

### Output formatting (implicit allocations)

- `src/async_io/linux.rs`, `src/async_io/macos.rs`, `src/pipeline.rs`:
  - `path.display()` may allocate for non-UTF8 paths.

Impact: Per-finding output can allocate depending on path contents.

### Potential capacity-growth allocations (edge case)

- `src/engine/mod.rs` `ScanScratch::reset_for_scan` can allocate if capacity mismatches are detected
  (e.g., scratch reused across engines or tuning changes).

Impact: Not expected in typical usage, but possible and not forbidden by API.

## Empirical Evidence (Cargo-based)

A counting allocator is implemented in `tests/alloc_after_startup.rs` and run with:

```
cargo test --test alloc_after_startup -- --ignored --nocapture --test-threads=1
```

Observed output on macOS (Darwin) will vary by machine and build. The
`engine.scan_chunk` test asserts **zero** allocations; other tests currently
expect allocations until their call paths are made allocation-free.

```
engine.scan_chunk allocs: calls=0 bytes=0 reallocs=0 realloc_bytes=0 deallocs=0
MacosAioScanner::scan_path allocs: calls=66 bytes=70661 reallocs=15 realloc_bytes=16348 deallocs=15
Pipeline::scan_path allocs: calls=750 bytes=17849302 reallocs=15 realloc_bytes=16350 deallocs=700
ScannerRuntime::scan_file_sync allocs: calls=0 bytes=0 reallocs=0 realloc_bytes=0 deallocs=0
```

Interpretation:
- Engine scan path is **allocation-free after warm-up**.
- Pipeline and macOS AIO paths still allocate per scan and per file.
- macOS AIO path remains dominated by per-file `AioFileReader::new` allocations.

## Removal Approaches (Performance + Correctness)

### 1) Engine APIs: make allocation-free paths the primary surface

- `Engine::scan_chunk`/`scan_chunk_records` now take `&mut ScanScratch` and return slices,
  making the default path allocation-free after startup.
- `Finding.decode_steps` now uses a fixed-capacity `FixedVec` (`MAX_DECODE_STEPS`), removing
  per-finding heap allocation.
- Remaining: ensure callers reuse `ScanScratch` and pre-size output `Vec<Finding>` when using
  `scan_chunk_materialized`.

### 2) Sync runtime: hoist buffers into the runtime (done)

- `ScannerRuntime` now owns `ScanScratch`, `tail`, and a fixed-capacity output buffer.
- `scan_file_sync` returns a slice into the internal buffer and errors on capacity overflow.

### 3) Pipeline: persist stage state inside `Pipeline`

- Store `FileTable`, `Walker`, `ReaderStage`, `ScanStage`, and `OutputStage` as fields in
  `Pipeline`, created at `Pipeline::new` and reused.
- Replace `Walker`’s heap `Vec` stack with `ScratchVec` (as in async walker).
- Replace `ReaderStage.tail` Vec with `ScratchVec` sized at startup.

### 4) Path storage without per-entry allocation

- Use a preallocated arena to store path bytes and keep `(offset, len)` in `FileTable`.
- Options using existing constructs:
  - **Fixed-size slots** using `NodePoolType` blocks (simple, larger memory).
  - **Block-chained arena** using `NodePoolType` blocks and an intrusive free list.
- For strict zero allocation, `std::fs::read_dir` must be replaced with `openat` + `readdir`
  to avoid `DirEntry::path()` allocations.

### 5) macOS AIO: reuse per-file buffers

- Move `AioFileReader` storage into `MacosAioScanner`:
  - `slots`, `free_slots`, `ready_seq`, `ready_slot`, `tail`, `wait_list` allocated once.
  - Convert `AioFileReader::new` to `reset_for_file`.
  - Use `ScratchVec` for fixed-capacity vectors.

### 6) Output formatting without allocation

- On Unix, write raw path bytes via `OsStrExt::as_bytes()` into a reusable scratch buffer.
- Avoid `path.display()` and `format!` in hot output paths.

### 7) Guardrails

- Keep the allocation-counting test (ignored by default) to catch regressions.
- Add debug-only counters or a compile-time feature to assert zero allocations during scan.

## Summary

The codebase does not currently meet TigerStyle’s “no allocation after startup” rule. The
allocations are concentrated in:
- Per-scan pipeline construction.
- Per-file async macOS AIO reader allocations.
- Path handling and output formatting.

Engine chunk scans are now allocation-free when callers reuse `ScanScratch`
and pre-sized output buffers; remaining work is in runtime/pipeline layers.

The fixes above focus on reusing preallocated buffers (`ScratchVec`, `NodePoolType`, `RingBuffer`)
and redesigning APIs to make allocation-free paths the default.
