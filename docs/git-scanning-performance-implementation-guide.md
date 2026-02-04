**Title**  
Git Scanning Performance Implementation Guide for `scanner-rs`

**Short Summary of Performance Strategy**  
Convert the verified hotspot findings into a staged, benchmark-backed checklist. Eliminate hot-loop allocations, remove wasted work, and reduce per-blob overhead without changing correctness or determinism. Every change is gated by set-equivalence tests and reproducible benchmarks.

**Scope and Source of Truth**  
This guide is a task tracker and implementation checklist derived from `git_perf_agent_md/` and current Git scanning docs. The canonical behavior is defined by the code and architecture docs (especially `docs/architecture-overview.md`). Use this guide to plan and track work, not as a normative spec.

**File Naming Convention**  
Avoid numbered filenames (no `*_0.rs`, `*_1.rs`, etc.). Use domain-specific names that describe the responsibility (`candidate_sink.rs`, `mapping_join.rs`, `spill_record.rs`, etc.). The paths listed below follow this convention.

**Progress Note**  
After completing a unit of work, mark it as complete (`[x]`) in this guide.

**Inputs**  
Primary reference bundle: `git_perf_agent_md/01_pipeline_hot_path_map.md` through `git_perf_agent_md/07_agent_task_checklist.md`.  
Reference index (use these to cross-check this plan):  
- `git_perf_agent_md/01_pipeline_hot_path_map.md` (pipeline boundaries + hot loops)  
- `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (verified hotspots A–L)  
- `git_perf_agent_md/03_allocation_audit.md` (alloc evidence + fixes)  
- `git_perf_agent_md/04_wasted_work_sources.md` (waste sources + fix list)  
- `git_perf_agent_md/05_perf_phases_p0_p6.md` (phase ordering)  
- `git_perf_agent_md/06_benchmark_suite.md` (metrics + methodology)  
- `git_perf_agent_md/07_agent_task_checklist.md` (acceptance gates)

**Assumptions and Open Questions**  
Assumptions: correctness contract stays unchanged (unique blob OID set, canonical context per OID, findings set). Determinism preserved (set-equal outcomes across chunking and scheduling). Bounded resources (zero allocations in hot loops after warmup; budgets explicit). Performance work is benchmark-driven with falsifiable results.

Open questions:  
- Should spill OID-run reduction be applied before writing runs, or in the merge stage only?  
- Are `pack_plan.rs` clusters truly unused by exec? If unused, should they be removed entirely or retained behind a feature gate?  
- Do we want a permanent streaming diff -> spiller path, or keep buffered path as an option for debugging?  
- What is the smallest safe mapping arena lifetime to avoid re-interning paths in `engine_adapter`?

**Phase P0 - Baseline + Instrumentation**  
[x] Stage timers + allocation counters.  
Purpose: Add per-stage timing (diff, spill, mapping, plan, exec, scan) and allocator counters to get a stable baseline.  
Files: `src/git_scan/runner.rs`, `src/git_scan/pack_exec.rs`, `src/git_scan/engine_adapter.rs`, `src/git_scan/mapping_bridge.rs`, `src/git_scan/spiller.rs`.  
Dependencies: none.  
Acceptance: metrics emitted for cycles/byte, bytes/s, spill bytes, run count, allocations after warmup.  
Tests: deterministic golden tests for metrics output format (no repo-specific values).  
Docs: `docs/throughput_bottleneck_analysis.md` updated with metric definitions + example output.  
Reference: `git_perf_agent_md/06_benchmark_suite.md`.  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Benchmark harness + reproducibility protocol.  
Purpose: Make benchmarks reproducible and comparable across runs.  
Files: `benches/` (as needed), `docs/throughput_bottleneck_analysis.md`.  
Dependencies: stage timers + alloc counters.  
Acceptance: ≥10 iterations, warmup discarded, median + MAD reported, CPU pinning recorded.  
Tests: none (benchmarks only).  
Docs: `docs/throughput_bottleneck_analysis.md` updated.  
Reference: `git_perf_agent_md/06_benchmark_suite.md`.  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P1 - Hot-Loop Cleanup (Scan + Pack Exec)**  
[x] Reuse ring chunker across blobs + optional small-blob fast path.  
Purpose: Remove per-blob ring allocation/zero fill and reduce scan overhead.  
Files: `src/git_scan/engine_adapter.rs`.  
Dependencies: P0 instrumentation.  
Acceptance: scan loop allocations == 0 after warmup; scanned bytes/s improves or holds.  
Tests: allocation guard for scan loop; set-equivalence tests for findings/context.  
Docs: `docs/memory-management.md` update scan loop allocation policy.  
Reference: `git_perf_agent_md/03_allocation_audit.md` (scan loop), `git_perf_agent_md/07_agent_task_checklist.md` (P1 gates).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Stop adapter path re-interning; plumb mapping arena.  
Purpose: Remove redundant path interning in `engine_adapter`.  
Files: `src/git_scan/engine_adapter.rs`, `src/git_scan/mapping_bridge.rs`, `src/git_scan/finalize.rs` (if finalize needs the arena).  
Dependencies: P0 instrumentation.  
Acceptance: no path re-interning in adapter; set-equivalence preserved.  
Tests: set-equivalence for canonical context per OID.  
Docs: `docs/architecture-overview.md` path handling note if changed.  
Reference: `git_perf_agent_md/03_allocation_audit.md` (adapter path).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Pack exec repeated cache lookup removal.  
Purpose: Avoid duplicate `cache.get(offset)` per object decode.  
Files: `src/git_scan/pack_exec.rs`.  
Dependencies: P0 instrumentation.  
Acceptance: identical decode output; fewer cache lookups per offset.  
Tests: pack exec regression tests; set-equivalence.  
Docs: none.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (K).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P2 - Spill System Overhaul (Alloc + Dedupe)**  
[x] ByteArena `clear_keep_capacity()` + reuse in hot paths.  
Purpose: Stop arena re-init churn between flushes.  
Files: `src/stdx/byte_ring.rs` or `src/git_scan/byte_arena.rs` (where `ByteArena` lives), `src/git_scan/spill_chunk.rs`, `src/git_scan/spiller.rs`, `src/git_scan/tree_candidate.rs`.  
Dependencies: P0 instrumentation.  
Acceptance: arena capacity retained across clears; allocation rate drops in spill-heavy runs.  
Tests: allocation guard in spill merge and chunking.  
Docs: `docs/memory-management.md` arena reuse notes.  
Reference: `git_perf_agent_md/03_allocation_audit.md` (arena churn).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] RunWriter / RunReader / SpillMerger allocation removal.  
Purpose: Eliminate per-record heap allocations and record clones in spill IO.  
Files: `src/git_scan/run_writer.rs`, `src/git_scan/run_reader.rs`, `src/git_scan/spill_merge.rs`.  
Dependencies: ByteArena reuse.  
Acceptance: spill merge allocations scale with #runs only; zero per-record allocs after warmup.  
Tests: allocation guard for spill merge; set-equivalence across chunk sizes.  
Docs: `docs/memory-management.md` spill IO notes.  
Reference: `git_perf_agent_md/03_allocation_audit.md`, `git_perf_agent_md/07_agent_task_checklist.md` (P2 gates).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] OID-run reduction to one canonical record.  
Purpose: Remove duplicates-by-OID before writing runs or during merge.  
Files: `src/git_scan/spill_chunk.rs`, `src/git_scan/spill_merge.rs`, `src/git_scan/spiller.rs`.  
Dependencies: spill IO changes.  
Acceptance: spill bytes/records drop on dup-heavy benchmarks; canonical context per OID stable.  
Tests: partition invariance property tests for canonical context; set-equivalence across chunk sizes.  
Docs: `docs/architecture-overview.md` update dedupe description.  
Reference: `git_perf_agent_md/04_wasted_work_sources.md` (9), `git_perf_agent_md/07_agent_task_checklist.md` (P2 gates).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Seen-store key building without per-key `Vec`.  
Purpose: Reduce heap churn in `batch_check_seen`.  
Files: `src/git_scan/persist_rocksdb.rs`.  
Dependencies: spill IO changes.  
Acceptance: key construction uses contiguous buffer or fixed-size arrays.  
Tests: unit test for key formatting unchanged.  
Docs: none.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (G).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P3 - Tree Diff + Cache**  
[x] Remove `Action.name_copy` allocations in tree diff.  
Purpose: Remove per-entry `Vec` allocs in diff inner loop.  
Files: `src/git_scan/tree_diff.rs`.  
Dependencies: P0 instrumentation.  
Acceptance: tree diff inner loop allocations == 0 after warmup.  
Tests: allocation guard for diff; candidate set equivalence.  
Docs: none.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (A), `git_perf_agent_md/03_allocation_audit.md` (tree diff).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Tree cache pinned/handle API for hit path.  
Purpose: Avoid `bytes.to_vec()` on cache hits by lending tree bytes.  
Files: `src/git_scan/object_store.rs`, `src/git_scan/tree_cache.rs`.  
Dependencies: diff allocation removal.  
Acceptance: cache hits avoid heap copy; diff still valid.  
Tests: unit test for cache hit path; diff equivalence.  
Docs: `docs/memory-management.md` cache hit notes.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (I), `git_perf_agent_md/03_allocation_audit.md` (tree cache).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P4 - Stream Tree Diff -> Spiller**  
[x] Add `CandidateSink` streaming interface; optional buffered fallback.  
Purpose: Remove CandidateBuffer extra pass and double path interning.  
Files: `src/git_scan/tree_diff.rs`, `src/git_scan/tree_candidate.rs`, `src/git_scan/spiller.rs`, `src/git_scan/runner.rs`.  
Dependencies: P3 diff/cache improvements.  
Acceptance: buffered vs streaming output sets identical; reduced candidate buffering.  
Tests: set-equivalence with buffered vs streaming; partition invariance.  
Docs: `docs/architecture-overview.md` update candidate stage description.  
Reference: `git_perf_agent_md/03_allocation_audit.md` (candidate staging), `git_perf_agent_md/04_wasted_work_sources.md` (3,4), `git_perf_agent_md/07_agent_task_checklist.md` (P4 gates).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P5 - MIDX Mapping Optimization**  
[x] Merge-join / galloping mapper for sorted unique OIDs.  
Purpose: Replace per-blob binary search with streaming mapping.  
Files: `src/git_scan/mapping_bridge.rs`, `src/git_scan/midx.rs`.  
Dependencies: P4 streaming (optional) or P2 spill dedupe.  
Acceptance: mapping results identical to `find_oid` oracle; cycles/oid improved on large runs.  
Tests: oracle equivalence vs `find_oid` on sampled OIDs; property tests for mapping stability.  
Docs: `docs/throughput_bottleneck_analysis.md` update mapping methodology.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (F), `git_perf_agent_md/05_perf_phases_p0_p6.md` (P5).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Phase P6 - Pack Plan + Mmap Scope**  
[x] Replace `BTreeMap` bucketing with sort/group; move candidates (no clone).  
Purpose: Reduce pointer-heavy DS and candidate cloning in pack plan.  
Files: `src/git_scan/pack_plan.rs`.  
Dependencies: P5 mapping improvements.  
Acceptance: plan build allocations reduced; identical pack plan output.  
Tests: plan equivalence tests; regression on pack plan fixtures.  
Docs: `docs/architecture-overview.md` pack plan section update if data structures change.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (J), `git_perf_agent_md/05_perf_phases_p0_p6.md` (P6).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Remove unused clusters (or gate behind feature).  
Purpose: Avoid computing/allocating clusters that are not used by exec.  
Files: `src/git_scan/pack_plan.rs`.  
Dependencies: bucketing refactor.  
Acceptance: no cluster computations unless required by exec; perf improved or unchanged.  
Tests: plan equivalence tests.  
Docs: `docs/architecture-overview.md` update if clusters removed.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (J).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Mmap only used packs after mapping.  
Purpose: Avoid mmapping packs that will not be scanned.  
Files: `src/git_scan/runner.rs`.  
Dependencies: mapping is finalized.  
Acceptance: mmapped pack ids == used pack ids.  
Tests: integration test verifies unused packs not mmapped; set-equivalence unchanged.  
Docs: `docs/memory-management.md` update mapping/mmap notes.  
Reference: `git_perf_agent_md/02_inventory_and_verified_hotspots.md` (L), `git_perf_agent_md/04_wasted_work_sources.md` (14).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

[x] Reuse per-plan scratch buffers in pack exec.  
Purpose: Reduce per-plan temporary allocations.  
Files: `src/git_scan/pack_exec.rs`.  
Dependencies: P6 plan refactor.  
Acceptance: pack exec allocations reduced; decode output unchanged.  
Tests: pack exec regression tests; allocation guard.  
Docs: `docs/memory-management.md` update if new scratch buffers introduced.  
Reference: `git_perf_agent_md/05_perf_phases_p0_p6.md` (P6).  
Workflow:

- [x] Run `cargo fmt --all`
- [x] Run `cargo check`
- [x] Run `cargo clippy --all-targets --all-features`
- [x] Run the `doc-rigor` skill on new code
- [x] Update docs if new components are added

**Tests and Validation Matrix**  
All scenarios must be deterministic. Do not log raw secrets, raw blob bytes, or full paths.

1. Set-equivalence tests for blob OID set across baseline vs new implementation.  
2. Canonical context per OID invariance across chunk sizes and spill partitioning.  
3. Findings set invariance across buffered vs streaming paths.  
4. Allocation guard tests for: tree diff loop, spill merge, scan loop.  
5. Mapping oracle equivalence vs `find_oid`.  
6. Pack exec regression tests for identical decoded bytes (oracle samples).  
7. Mmap scope test: used packs == mmapped packs.  
8. Benchmarks reproducibility: warmup discarded, ≥10 runs, median + MAD recorded.

**Performance Benchmarks to Run**  
Reference: `git_perf_agent_md/06_benchmark_suite.md`.

Microbenchmarks:  
- Tree diff loop: ns/entry, alloc counts.  
- Spill chunk + writer: records/s, bytes written, alloc counts.  
- Run reader + merge: records/s, allocs scale with #runs only.  
- MIDX mapping: cycles/oid + cache misses, compare strategies.  
- Engine adapter scan: cycles/scanned-byte, allocs per blob.

End-to-end strata:  
1. Small range, low candidates (constant overhead).  
2. Medium range, many tree entries, moderate duplicates (spill dominates).  
3. Large history, high duplicate blobs (dedupe + mapping dominates).

**Gates and Acceptance Criteria**  
All phases must satisfy:  
- Correctness contract unchanged (unique blob set, canonical context, findings set).  
- Determinism preserved across chunking and scheduling.  
- Allocation invariants for targeted hot loops after warmup.  
- Benchmark improvements or “no regression” with explicit justification.

Phase gates (from `git_perf_agent_md/07_agent_task_checklist.md`):  
- P1: scan loop allocations == 0 after warmup; no change in findings/context sets.  
- P2: spill merge allocations scale with #runs only; spill bytes/records drop on dup-heavy case; set-equivalence across chunk sizes.  
- P3: tree diff inner loop allocations == 0 after warmup; candidate set equivalence.  
- P4: buffered vs streaming output sets identical.  
- P5: mapping oracle equivalence vs `find_oid`.  
- P6: mmapped packs == used packs; plan build allocations reduced.

**Performance Regression Workflow (Hot Paths)**  
Before merging changes touching `src/git_scan/`, follow the existing workflow in `AGENTS.md` (baseline build, scan loops, benchmarks, delta analysis). Include in PR: average throughput delta per test repo, benchmark comparison summary, and justification for any regression >2%.

**Docs Update Plan**  
Update `docs/architecture-overview.md` to reflect pipeline changes (streaming diff, spill dedupe, mapping).  
Update `docs/memory-management.md` for arena reuse, mmap scope, and allocation guard policies.  
Update `docs/throughput_bottleneck_analysis.md` with instrumentation details and benchmark protocol.  
Update `docs/git-scanning.md` only if pipeline semantics or stage boundaries change.
