# Git Scan In-Memory Artifact Findings Tracker (Commit-Graph, MIDX, and Execution Paths)

This tracker captures the current findings for the in-memory commit-graph/MIDX approach and the adjacent execution paths that consume those artifacts.
Each item is structured so we can tackle one issue at a time with clear scope, rationale, and direction.

> **Status:** Active  
> **Last Updated:** 2026-02-05

## Scope

- `src/git_scan/commit_graph_mem.rs`
- `src/git_scan/commit_graph.rs`
- `src/git_scan/midx.rs`
- `src/git_scan/midx_build.rs`
- `src/git_scan/runner.rs`
- `src/bin/git_scan.rs`
- `src/git_scan/tree_diff.rs`

## Legend

- Severity: `High`, `Medium`, `Low`
- Status: `Todo`, `In Progress`, `Done`, `Validated`

## Concurrency Policy (Project Direction)

- [x] `CP1` - Eliminate unintended single-threaded diff-history behavior
- Severity: `High`
- Status: `Done`
- Policy statement: All pack execution concurrency should be controlled by CLI/config (`pack_exec_workers`), including diff-history mode.
- Why this matters:
- Today the behavior is mode-dependent: ODB blob scan honors worker settings, while diff-history currently does not.
- That mismatch is both a performance issue and a usability issue because the concurrency knob becomes non-authoritative.
- Direction:
- Treat `pack_exec_workers` as the source of truth for both modes.
- Use the same worker orchestration model in diff-history where feasible.
- If a temporary limitation exists, fail fast or warn loudly rather than silently forcing single-thread mode.
- Affected code:
- `src/git_scan/runner.rs`
- Implementation notes (2026-02-05):
- Diff-history pack execution now selects `Serial` / `PackParallel` / `IntraPackSharded` from `pack_exec_workers` and plan count.
- Multi-worker execution reassembles per-pack/per-shard outputs by deterministic sequence before finalize.

## Correctness and Safety Findings

### [x] C1 - `max_midx_total_bytes` is estimate-gated, not strictly enforced on final bytes

- Severity: `Medium`
- Status: `Done`
- Context:
- MIDX build currently relies on an estimate to decide whether construction is allowed.
- Final serialized size can exceed this estimate when pack names are long or when large-offset usage is high.
- Why this is an issue:
- Configured byte limits are expected to be hard guardrails for memory/safety.
- Non-strict enforcement can produce surprising memory growth and violate operator expectations.
- Direction:
- Enforce limits against exact output size (precomputed exact accounting or post-build hard check on final serialized buffer).
- If build is streaming/chunked, apply monotonic checks before appending each chunk.
- Affected code:
- `src/git_scan/midx_build.rs`
- Validation guidance:
- Add near-limit and over-limit tests that prove hard rejection once real serialized size exceeds `max_midx_total_bytes`.
- Validation completed (2026-02-05):
- Unit tests:
- `git_scan::midx_build::tests::build_midx_bytes_checks_actual_serialized_size_cap`
- `git_scan::midx_build::tests::build_midx_bytes_allows_exact_size_limit`
- Enforcement now includes post-build hard check against serialized `midx_bytes.len()`.

### [x] C2 - Tree-diff in-flight byte budget may leak on early error paths

- Severity: `Medium`
- Status: `Done`
- Context:
- Tree walk accounting tracks bytes in-flight.
- On some error exits, stack/budget cleanup may not fully unwind before return.
- Why this is an issue:
- A leaked in-flight budget can poison subsequent calls on the same walker instance.
- Recoverable/retry workflows can fail immediately despite otherwise valid limits.
- Direction:
- Guarantee cleanup on all exits (scope guard or explicit unwind/drain before returning errors).
- Keep bookkeeping invariants true regardless of success/error.
- Affected code:
- `src/git_scan/tree_diff.rs`
- Validation guidance:
- Add a test that intentionally triggers budget/depth error, then retries with a trivial diff and confirms success.
- Validation completed (2026-02-05):
- Unit tests:
- `git_scan::tree_diff::tests::budget_error_releases_in_flight_bytes_for_retry`
- `git_scan::tree_diff::tests::depth_error_releases_in_flight_bytes_for_retry`
- `diff_trees` now guarantees post-call cleanup of stack/path and in-flight tree-byte accounting on success and early-error exits.

### [ ] C3 - Fallback generation assignment (`gen=1`) can understate ordering quality in invalid/cyclic history

- Severity: `Low`
- Status: `Todo`
- Context:
- Unresolved commits are currently assigned generation 1 in fallback paths.
- Why this is an issue:
- In malformed history, this can under-estimate generation and reduce pruning quality for generation-based heuristics.
- It is edge-case behavior, but correctness should degrade predictably, not arbitrarily.
- Direction:
- Compute best-effort fallback generation from resolved parents (`max(parent_gen)+1`) when possible, even if some dependencies remain unresolved.
- Preserve deterministic behavior for invalid inputs.
- Affected code:
- `src/git_scan/commit_graph_mem.rs`
- Validation guidance:
- Add malformed-history fixture tests to confirm deterministic fallback and no regressions on valid DAGs.

## Performance Findings

### [x] P1 - MIDX fanout construction is O(256*N) in hot path

- Severity: `High`
- Status: `Done`
- Context:
- Fanout update currently writes all trailing fanout slots for each emitted OID.
- Why this is an issue:
- For large object counts this amplifies CPU work massively and slows in-memory MIDX builds.
- The algorithmic cost is avoidable.
- Direction:
- Use a two-phase fanout build:
- Count first-byte frequencies during merge emit (`O(N)`).
- Prefix-sum once across 256 buckets (`O(256)`).
- Affected code:
- `src/git_scan/midx_build.rs`
- Validation guidance:
- Add a large synthetic build benchmark and verify fanout chunk equivalence against current behavior/spec expectations.
- Validation completed (2026-02-05):
- Unit tests:
- `git_scan::midx_build::tests::build_midx_fanout_varying_first_byte_distribution`
- `git_scan::midx_build::tests::build_midx_fanout_and_dedup_with_duplicate_oids`
- Implementation now uses per-byte counting during merge plus one prefix-sum pass.

### [x] P2 - Commit generation pass can degrade to O(N^2)

- Severity: `Medium`
- Status: `Done`
- Context:
- Generation assignment repeatedly scans unresolved/pending commits until dependencies settle.
- Why this is an issue:
- Deep or large commit DAGs can make this phase disproportionately expensive.
- It delays pipeline startup before any scanning work begins.
- Direction:
- Move to topological/Kahn-style propagation over in-set parent edges to target `O(N + E)`.
- Preserve current deterministic output ordering guarantees.
- Affected code:
- `src/git_scan/commit_graph_mem.rs`
- Validation guidance:
- Add scaling benchmarks for chain and merge-heavy DAG shapes; assert generation values/ordering stability.
- Validation completed (2026-02-05):
- Unit tests:
- `git_scan::commit_graph_mem::tests::non_trivial_dag_generations_and_missing_parent_semantics`
- `git_scan::commit_graph_mem::tests::deterministic_positions_on_non_trivial_dag`
- `git_scan::commit_graph_mem::tests::cycle_falls_back_to_generation_one`
- Generation assignment now uses topological parent->child propagation (`O(N+E)`) while preserving deterministic `(generation, oid)` position ordering.

### [ ] P3 - Pack cache budget can scale as `workers * configured_bytes`

- Severity: `High`
- Status: `Todo`
- Context:
- Parallel pack execution paths can treat configured cache bytes as per-worker allocation.
- Why this is an issue:
- Total memory footprint grows linearly with worker count and can exceed intended caps.
- Memory pressure can erase concurrency gains and trigger instability.
- Direction:
- Define one clear budget contract:
- Either split configured budget across workers, or
- Use a shared cache with explicit global cap.
- Ensure docs/config language matches implementation semantics.
- Affected code:
- `src/git_scan/runner.rs`
- Validation guidance:
- Add tests that assert total effective cache budget remains bounded as worker count increases.

### [ ] P4 - Loose-only scans still execute pack verification/mapping work

- Severity: `Medium`
- Status: `Todo`
- Context:
- Paths with `packed_len == 0` still perform pack discovery/verification/mapping setup.
- Why this is an issue:
- Extra work adds latency and can produce irrelevant failures when pack data is absent but not required.
- Direction:
- Short-circuit pack-specific setup when there are no packed objects to scan.
- Ensure loose-object path can proceed independently.
- Affected code:
- `src/git_scan/runner.rs`
- Validation guidance:
- Add fixture where loose objects exist and pack directories are missing; scan should still succeed.

### [x] P5 - Diff-history path does not currently honor configured parallel pack execution

- Severity: `High`
- Status: `Done`
- Context:
- Diff-history mode currently executes pack decode path single-threaded.
- Why this is an issue:
- Leaves substantial performance on the table for large repos.
- Violates desired concurrency policy where CLI/config should control parallelism uniformly.
- Direction:
- Implement diff-history parallel pack execution via the same worker/sharding strategy used by ODB blob path.
- Keep `pack_exec_workers=1` as deterministic fallback, but never silently force single-thread when higher workers are configured.
- Affected code:
- `src/git_scan/runner.rs`
- Validation guidance:
- Add mode-specific tests that prove worker setting is honored and execution strategy is observable in perf/report output.
- Validation completed (2026-02-05):
- Unit test: `git_scan::runner::tests::diff_history_pack_exec_strategy_honors_worker_setting`
- Integration test: `git_scan_validation::diff_history_pack_exec_workers_preserve_deterministic_output`

## Suggested Attack Order

- [ ] 1. `P3` (memory safety/perf guardrail): make cache budget semantics explicit and bounded.
- [x] 2. `C1` (hard limit correctness): enforce strict MIDX size cap.
- [x] 3. `P5` + `CP1` (policy alignment): make diff-history obey `pack_exec_workers`.
- [x] 4. `P1` (largest pure CPU hotspot): optimize fanout construction.
- [x] 5. `C2` (retry correctness): fix tree-diff budget cleanup on errors.
- [ ] 6. `P4` (mode fast-path): short-circuit pack setup for loose-only scans.
- [x] 7. `P2` (scaling): replace O(N^2) generation pass.
- [ ] 8. `C3` (edge-case resilience): improve fallback generation semantics for malformed history.

## Evidence to Record Per Item

- [ ] Reproducer or benchmark command used
- [ ] Before/after measurements or behavioral proof
- [ ] Test coverage added (unit/integration/benchmark)
- [ ] Any intentional trade-offs accepted
