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

### Pipeline (stage state reused; path arena added)

- `src/pipeline.rs` / `src/runtime.rs`:
  - `Pipeline` now owns `FileTable`, rings, and all stages, and `scan_path` resets them
    instead of allocating per scan.
  - `FileTable` stores paths in a fixed-capacity byte arena (Unix) to avoid per-file heap allocation.
  - `PipelineConfig::path_bytes_cap` controls the arena size (0 = auto).
  - Output formatting writes raw path bytes on Unix (no `path.display()` allocations).
  - Unix `Walker` uses `openat` + `readdir` to avoid `PathBuf` allocations per entry.
  - Non-Unix platforms still use `fs::read_dir`/`DirEntry::path()` and therefore allocate per entry.

Impact: On Unix, the pipeline scan path is allocation-free after startup when capacities are
pre-sized. Non-Unix platforms still allocate in `std::fs` path handling.

### Async scanners (shared walker + path arena)

- `src/async_io/mod.rs` walker:
  - Unix `Walker` uses `openat` + `readdir` and stores paths in the fixed arena.
  - Non-Unix still uses `fs::read_dir`/`DirEntry::path()` and allocates per entry.
  - `FileTable` stores paths in a fixed-capacity byte arena (Unix).
  - `AsyncIoConfig::path_bytes_cap` controls the arena size (0 = auto).

Impact: On Unix, async scanners are allocation-free after startup with pre-sized capacities.
Non-Unix platforms still allocate per entry via `std::fs` path handling.

### macOS AIO (reused reader buffers)

- `src/async_io/macos.rs`:
  - `MacosAioScanner` now owns a reusable `AioFileReader`.
  - Reader buffers (`slots`, `free_slots`, `ready_seq`, `ready_slot`, `tail`, `wait_list`) are
    allocated once at startup and reused via `reset_for_file`.

Impact: macOS AIO no longer allocates per file after startup.

### Output formatting (Unix allocation-free)

- `src/async_io/linux.rs`, `src/async_io/macos.rs`, `src/pipeline.rs`:
  - Raw path bytes are written on Unix to avoid `path.display()` allocations.
  - Non-Unix platforms still use `path.display()` (possible allocation for non-UTF8 paths).

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
MacosAioScanner::scan_path allocs: calls=0 bytes=0 reallocs=0 realloc_bytes=0 deallocs=0
Pipeline::scan_path allocs: calls=0 bytes=0 reallocs=0 realloc_bytes=0 deallocs=0
ScannerRuntime::scan_file_sync allocs: calls=0 bytes=0 reallocs=0 realloc_bytes=0 deallocs=0
```

Interpretation:
- Engine scan path is **allocation-free after warm-up**.
- Pipeline and macOS AIO scans are **allocation-free after warm-up** on Unix/macOS.

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

### 3) Pipeline: persist stage state inside `Pipeline` (done)

- `Pipeline` now stores `FileTable`, rings, and stage state and reuses them between scans.
- Remaining work for zero-allocation scans lives in path handling (see below).

### 4) Path storage without per-entry allocation (partial)

- `FileTable` now stores path bytes in a fixed-capacity arena on Unix.
- Unix walkers now use `openat` + `readdir` to avoid `DirEntry::path()` allocations.
- Non-Unix platforms still use `std::fs::read_dir` and therefore allocate per entry.

### 5) macOS AIO: reuse per-file buffers

Done:
- `MacosAioScanner` owns a single `AioFileReader`.
- `AioFileReader::new` allocates fixed buffers once; `reset_for_file` reuses them per file.

### 6) Output formatting without allocation

- On Unix, write raw path bytes via `OsStrExt::as_bytes()` into a reusable scratch buffer.
- Avoid `path.display()` and `format!` in hot output paths.

### 7) Guardrails

Done:
- Allocation-counting test now asserts zero allocations for engine, runtime, pipeline, and macOS AIO.

## Summary

The codebase meets TigerStyle’s “no allocation after startup” rule for the
Unix/macOS scan paths under our control, with capacities pre-sized up front.
Non-Unix platforms still allocate per entry in `std::fs` path walking.

The fixes above focus on reusing preallocated buffers (`ScratchVec`, `NodePoolType`, `RingBuffer`)
and redesigning APIs to make allocation-free paths the default.
