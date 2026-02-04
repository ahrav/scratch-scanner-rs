**Title**  
Git Scanning Spill + Streaming Implementation Guide for `scanner-rs`

**Short Summary of Performance Strategy**  
Remove cumulative tree-byte limits, add a preallocated spill arena backed by `mmap`, and introduce streaming tree diffs so trees are never fully materialized in RAM. This keeps RAM allocations fixed at startup while allowing arbitrarily large repositories to scan efficiently on all OSs. Performance is gated against the Kingfisher Linux baseline (~4 minutes on `../linux`).

**Scope and Source of Truth**  
This guide is a staged implementation checklist focused on tree diff + object-store memory behavior. The canonical behavior is defined by the code and architecture docs (especially `docs/architecture-overview.md` and `docs/memory-management.md`). Use this guide to plan and track work, not as a normative spec.

**File Naming Convention**  
Avoid numbered filenames (no `*_0.rs`, `*_1.rs`, etc.). Use domain-specific names that describe responsibility (`spill_arena.rs`, `tree_stream.rs`, `spill_index.rs`, etc.). The paths listed below follow this convention.

**Progress Note**  
After completing a unit of work, mark it as complete (`[x]`) in this guide.

**Inputs**  
Primary template: `docs/git-scanning-performance-implementation-guide.md`.  
Reference index (use these to cross-check this plan):  
- `docs/architecture-overview.md` (pipeline boundaries + repo artifacts)  
- `docs/memory-management.md` (budgeting + caches)  
- `docs/detection-engine.md` (candidate semantics + correctness)  
- `docs/throughput_bottleneck_analysis.md` (baseline reporting)  
- Kingfisher Linux repo baseline (~4 minutes on `../linux`)

**Assumptions and Decisions**  
Assumptions: RAM allocations are fixed at startup; disk spill is allowed and must be efficient; `mmap` is acceptable across OSs; correctness contract stays unchanged (candidate sets + canonical context). Determinism preserved. Performance is benchmark-driven with falsifiable results.

Decisions:  
- Default path is hybrid: buffered/cached for small trees, streaming for large or spilled trees.  
- Spill file is fixed-size and configurable; default size is 8 GB with streaming fallback on exhaustion.  
- Linux-only io_uring prefetch is deferred unless `mmap` baseline misses the Kingfisher target.

**Phase P0 - Baseline + Targets**  
[x] Capture Linux baseline (Kingfisher + `git_scan`).  
Purpose: Establish performance and memory targets before refactoring.  
Files: `docs/throughput_bottleneck_analysis.md`.  
Dependencies: none.  
Acceptance: baseline runtime + memory recorded for Kingfisher and `git_scan` on `../linux`.  
Tests: none.  
Docs: update `docs/throughput_bottleneck_analysis.md` with baseline table.  
Reference: Kingfisher baseline (~4 minutes on `../linux`).  
Note: Kingfisher runtime is assumed to be 4 minutes per user guidance. Current `git_scan` baseline fails due to the tree-bytes budget and is recorded as a failure mode in Phase P0.  
Workflow:

- [x] Run Kingfisher baseline command (team standard) on `../linux` and record runtime (assumed 4 minutes)
- [x] Run `./target/release/git_scan ../linux --debug` and record runtime + metrics (current failure: tree bytes budget exceeded)
- [x] Record hardware + OS details for baseline reproducibility

**Phase P1 - Budget Model Fix (In-Flight Only)**  
[x] Replace cumulative tree-byte budget with in-flight tracking.  
Purpose: Prevent large repos from failing due to cumulative counters while keeping RAM bounded.  
Files: `src/git_scan/tree_diff.rs`, `src/git_scan/tree_diff_limits.rs`, `src/git_scan/object_store.rs`.  
Dependencies: P0 baseline captured.  
Acceptance: No `tree bytes budget exceeded` error for large history; memory bounded by in-flight budget.  
Tests: tree diff unit tests; set-equivalence tests for candidates.  
Docs: `docs/memory-management.md` update budgeting model.  
Reference: baseline error observed on Linux repo.  
Workflow:

- [x] Add `max_tree_bytes_in_flight` limit and remove cumulative enforcement
- [x] Track in-flight bytes with RAII (increment on load, decrement on drop)
- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code

**Phase P2 - Spill Arena (mmap, preallocated)**  
[x] Implement preallocated spill arena + index for tree payloads.  
Purpose: Allow disk spill while keeping RAM fixed and syscalls minimal.  
Files: new `src/git_scan/spill_arena.rs` (or similar), `src/git_scan/object_store.rs`, `src/git_scan/tree_diff.rs`.  
Dependencies: P1 budget model fix.  
Acceptance: tree payloads can be spilled and read without heap growth; `TreeBytes::Spilled` works; spill exhaustion disables new spills and falls back to buffered loads (streaming fallback added in P3).  
Tests: new unit tests for spill arena append/read; tree diff integration smoke.  
Docs: `docs/memory-management.md`, `docs/architecture-overview.md` update spill path.  
Reference: spill design in this guide.  
Workflow:

- [x] Preallocate spill file at startup (configurable size)
- [x] `mmap` spill file once; append bytes and store `(offset, len)`  
- [x] Add preallocated spill index keyed by tree OID  
- [x] Add `TreeBytes::Spilled { offset, len }`  
- [x] Define spill exhaustion behavior: disable new spills and fall back to buffered loads  
- [x] Run `cargo fmt --all`  
- [x] Run `cargo check`  
- [x] Run `cargo clippy --all-targets --all-features`  
- [x] Run the `doc-rigor` skill on new code

**Phase P3 - Streaming Tree Parser + Diff**  
[x] Add streaming tree entry parser and merge-walk diff.  
Purpose: Avoid materializing giant trees while preserving correctness.  
Files: `src/git_scan/tree_entry.rs`, `src/git_scan/tree_diff.rs`, `src/git_scan/object_store.rs`.  
Dependencies: P2 spill arena (stream input may come from spill).  
Acceptance: streaming diff yields identical candidates to buffered diff; spill-backed or large trees are parsed with a fixed-size buffer to keep the diff working set bounded.  
Tests: buffered vs streaming equivalence; property tests for partition invariance.  
Docs: `docs/detection-engine.md`, `docs/memory-management.md` update streaming path.  
Reference: merge-walk algorithm in `tree_diff.rs`.  
Workflow:

- [x] Add `TreeStream` parser backed by ring buffer  
- [x] Support both in-memory and spill-backed streams  
- [x] Integrate streaming merge-walk into tree diff  
- [x] Define threshold: stream when tree payload exceeds cache size or is spill-backed  
- [x] Run `cargo fmt --all`  
- [x] Run `cargo check`  
- [x] Run `cargo clippy --all-targets --all-features`  
- [x] Run the `doc-rigor` skill on new code

**Phase P4 - IO Tuning (Cross-Platform)**  
[x] Add OS-friendly access hints for spill reads.  
Purpose: Reduce I/O overhead and improve sequential throughput.  
Files: `src/git_scan/spill_arena.rs`, `src/git_scan/object_store.rs`.  
Dependencies: P2 spill arena.  
Acceptance: hints are optional, guarded, and do not regress performance.  
Tests: none (perf only).  
Docs: `docs/memory-management.md` update IO hints.  
Reference: OS docs for `madvise` / `posix_fadvise`.  
Workflow:

- [x] Add `madvise(MADV_SEQUENTIAL)` where supported
- [x] Add `posix_fadvise` hints where supported
- [x] Add Windows stubs or no-ops behind cfg guards

**Phase P5 - Correctness Tests**  
[x] Add tests that force spill + streaming and verify set-equivalence.  
Purpose: Ensure no correctness regressions across buffered/streaming paths.  
Files: `tests/integration/git_tree_diff.rs`, `tests/property/git_tree_diff.rs`.  
Dependencies: P2 spill arena, P3 streaming diff.  
Acceptance: tests pass and show identical candidates across modes.  
Tests: `cargo test`.  
Docs: none.  
Reference: existing buffered vs streaming tests in `tests/integration`.  
Workflow:

- [x] Add integration test that forces spill path
- [x] Add integration test that forces streaming path
- [x] Add property test for partition invariance under streaming
- [x] Run `cargo test`

**Phase P6 - Performance Gate (Linux Baseline)**  
[ ] Beat or match Kingfisher on `../linux`.  
Purpose: Validate real-world performance against the baseline.  
Files: none.  
Dependencies: P1–P5.  
Acceptance: `git_scan` runtime < Kingfisher baseline, or documented justification + next steps.  
Tests: `./target/release/git_scan ../linux --debug`.  
Docs: update `docs/throughput_bottleneck_analysis.md` with results.  
Reference: Kingfisher baseline (~4 minutes on `../linux`).  
Workflow:

- [ ] Run `./target/release/git_scan ../linux --debug`
- [ ] Compare runtime to Kingfisher baseline
- [ ] If slower, profile and decide whether Linux-only io_uring prefetch is warranted
