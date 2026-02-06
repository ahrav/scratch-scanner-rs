# Git Scan Findings Tracker (Correctness, Performance, and Test Gaps)

This document tracks findings from a prior review session and converts them into actionable work items.  
Status should be updated in-place as items are investigated and fixed.

## Legend

- Severity: `High`, `Medium`, `Low`
- Status: `Todo`, `In Progress`, `Done`, `Validated`

## Correctness Findings

### [ ] C1 - Empty start set can produce a no-op in-memory commit graph

- Severity: `High`
- Status: `Todo`
- Finding summary: In-memory artifact flow can produce an empty commit graph when artifacts are missing because `repo_open` can return an empty `start_set`, and `acquire_commit_graph` treats "no tips" as "empty graph."
- Affected code:
- `src/git_scan/repo_open.rs`
- `src/git_scan/artifact_acquire.rs`

Investigation plan:

- [ ] Reproduce with a repository fixture where artifact files are missing but refs exist.
- [ ] Trace `resolver.resolve(...)` and watermark loading behavior to confirm whether empty `start_set` is expected vs accidental.
- [ ] Define desired contract for empty `start_set` in the in-memory path (hard error vs fallback start-set resolution).
- [ ] Implement guardrail (error or fallback path) so scan cannot silently become a no-op.
- [ ] Add end-to-end regression test asserting non-empty graph (or explicit failure) when refs are present.

Expected benefit:

- Correctness: prevents silent false-negative scans caused by accidental empty traversal roots.
- Operational impact: converts hidden no-op behavior into deterministic success/failure semantics.

Success criteria:

- [ ] In-memory path cannot silently return empty graph when repository has reachable refs.
- [ ] Test reproducer fails before fix and passes after fix.

### [ ] C2 - In-memory commit loading is pack-only; loose tips can fail with `CommitNotFound`

- Severity: `High`
- Status: `Todo`
- Finding summary: In-memory commit loading currently uses MIDX lookup only. Tips that exist as loose objects can fail `midx.find_oid(...)` and abort graph build with `CommitNotFound`.
- Affected code:
- `src/git_scan/commit_loader.rs`
- `src/git_scan/artifact_acquire.rs`

Investigation plan:

- [ ] Reproduce with a fixture containing loose-only tip commits and no corresponding packed object.
- [ ] Confirm current behavior in mixed histories (packed parents, loose head).
- [ ] Decide fallback policy for missing MIDX entries (load loose object by OID vs explicit unsupported-mode error).
- [ ] Implement fallback or clear-mode error with actionable diagnostics.
- [ ] Add tests for loose-only and mixed loose+pack commit chains.

Expected benefit:

- Correctness: prevents aborts on valid repositories that have not recently run maintenance.
- Reliability: reduces mode-dependent behavior differences between fresh and GC-maintained repos.

Success criteria:

- [ ] Loose-only tips are either successfully loaded or rejected with a deterministic, documented error.
- [ ] Mixed packed+loose history path is covered by tests.

### [ ] C3 - Delta inflate limit uses result size instead of delta payload bound

- Severity: `Medium`
- Status: `Todo`
- Finding summary: Delta inflate uses `inflate_limit = size.min(max_bytes)`, but pack entry header size for deltas is the result object size, not the compressed delta payload size. Valid streams can exceed this bound and raise false `InflateError`.
- Affected code:
- `src/git_scan/commit_loader.rs`

Investigation plan:

- [ ] Build/reuse a fixture with valid delta payload larger than result-size bound.
- [ ] Verify failure path currently surfaces as `InflateError`.
- [ ] Redefine inflate bound for delta payload (separate delta-stream cap from final object-size cap).
- [ ] Keep `apply_delta` output bounded by existing `max_commit_object_bytes`.
- [ ] Add regression test covering valid large delta stream.

Expected benefit:

- Correctness: eliminates false-negative decode failures on well-formed packfiles.
- Compatibility: improves robustness across diverse pack encoding patterns.

Success criteria:

- [ ] Fixture no longer fails inflate phase for valid deltas.
- [ ] Result size limits remain enforced after the change.

### [ ] C4 - `max_midx_total_bytes` currently enforced via heuristic estimate

- Severity: `Medium`
- Status: `Todo`
- Finding summary: `estimate_midx_size(...)` can under-estimate actual output (pack name length and LOFF density variance), so configured max bytes are not a strict cap.
- Affected code:
- `src/git_scan/midx_build.rs`

Investigation plan:

- [ ] Construct worst-case fixtures (long pack names, high LOFF usage) to measure estimate error.
- [ ] Quantify underestimate/overestimate envelope in tests.
- [ ] Replace heuristic gate with exact or monotonic upper-bound accounting during build.
- [ ] Enforce hard cap before each chunk append (PNAM, OIDL, OOFF, LOFF, checksum).
- [ ] Add limit-enforcement test cases for near-limit and over-limit builds.

Expected benefit:

- Correctness and safety: configured memory cap becomes deterministic and enforceable.
- Operational: prevents unexpected peak allocations above user-configured limits.

Success criteria:

- [ ] No code path can emit final MIDX bytes larger than `max_midx_total_bytes`.
- [ ] Tests validate both acceptance and rejection boundaries.

## Performance Findings

### [ ] P1 - `CommitGraphMem::build` generation pass is O(N^2) on deep histories

- Severity: `High`
- Status: `Todo`
- Finding summary: Generation computation repeatedly scans pending commits until dependencies resolve, degrading to O(N^2) for long chains/deep DAGs.
- Affected code:
- `src/git_scan/commit_graph_mem.rs`

Investigation plan:

- [ ] Add benchmark fixture for long linear chains and deep/wide DAGs.
- [ ] Replace iterative pending-scan approach with topological/dynamic programming pass with indegree tracking (target O(N + E)).
- [ ] Preserve deterministic `(generation, oid)` final ordering and current missing-parent semantics.
- [ ] Compare before/after on synthetic and real repository traces.
- [ ] Add regression test for generation correctness on non-trivial DAGs.

Expected performance gain:

- Asymptotic: O(N^2) to O(N + E).
- Practical estimate: 2x-20x faster generation phase on very large or deep commit graphs (depends on topology).

Success criteria:

- [ ] Benchmark confirms sub-quadratic scaling as history depth grows.
- [ ] No behavioral regression in generation values or ordering guarantees.

### [ ] P2 - MIDX fanout update is O(256*N) during merge output

- Severity: `High`
- Status: `Todo`
- Finding summary: Fanout table is updated by writing all suffix slots per emitted OID, producing O(256*N) work.
- Affected code:
- `src/git_scan/midx_build.rs`

Investigation plan:

- [ ] Add micro-benchmark for MIDX build across 1M+ synthetic objects.
- [ ] Replace per-object suffix fill with two-phase method:
- Count first-byte buckets during emit (O(N)).
- Prefix-sum once across 256 buckets (O(256)).
- [ ] Validate chunk byte-for-byte equivalence for representative inputs.
- [ ] Benchmark CPU time and cache behavior before/after.

Expected performance gain:

- Asymptotic: O(256*N) to O(N + 256).
- Practical estimate: 1.5x-4x faster fanout construction on large object sets; larger wins at multi-million scale.

Success criteria:

- [ ] Fanout chunk remains spec-correct.
- [ ] End-to-end MIDX build time improves on large fixtures.

### [ ] P3 - BFS frontier can contain duplicates before visit marking

- Severity: `Medium`
- Status: `Todo`
- Finding summary: Parents are enqueued when not yet visited but may already be queued, inflating queue size and repeated set lookups.
- Affected code:
- `src/git_scan/commit_loader.rs`

Investigation plan:

- [ ] Add instrumentation for frontier max length, enqueue count, and duplicate enqueue count.
- [ ] Add "seen-or-queued" tracking to prevent duplicate frontier entries.
- [ ] Benchmark on merge-heavy DAGs where parent overlap is high.
- [ ] Validate traversal output remains identical.

Expected performance gain:

- Practical estimate: 5%-20% reduction in commit-loading CPU and queue memory on overlap-heavy histories.
- Worst-case asymptotics unchanged, but constant factors should improve.

Success criteria:

- [ ] Duplicate enqueue metric drops to ~0 by design.
- [ ] Commit set and order guarantees remain unchanged.

### [ ] P4 - `PackFile::parse` is repeated per object load

- Severity: `Low`
- Status: `Todo`
- Finding summary: `PackFile::parse` is re-run for each object decode instead of cached per pack in loader state.
- Affected code:
- `src/git_scan/commit_loader.rs`

Investigation plan:

- [ ] Add profiling counters for parse invocations per pack/object.
- [ ] Cache parsed pack metadata alongside loaded pack bytes in `CommitLoader`.
- [ ] Ensure cache invalidation semantics are straightforward (immutable pack bytes).
- [ ] Benchmark decode-heavy workloads to quantify impact.

Expected performance gain:

- Practical estimate: 1%-8% faster commit loading, with better effect on workloads with many small objects.

Success criteria:

- [ ] Parse count trends toward one parse per pack (plus negligible setup overhead).
- [ ] No change in decode correctness.

## Test Gaps (New Coverage Work)

### [ ] T1 - End-to-end coverage for missing artifacts + non-empty start-set resolution

- Severity: `High`
- Status: `Todo`
- Gap: No end-to-end test for in-memory path when artifacts are missing to ensure a valid start set still yields non-empty commit graph.

Checklist:

- [ ] Add fixture and test harness case for missing artifacts with resolvable refs.
- [ ] Assert graph is non-empty or explicit error is raised (per decided contract).

### [ ] T2 - Coverage for loose-only tips and mixed loose+pack histories

- Severity: `High`
- Status: `Todo`
- Gap: No tests verifying behavior when tips are loose objects.

Checklist:

- [ ] Add loose-only tip scenario.
- [ ] Add mixed packed-parent + loose-head scenario.
- [ ] Assert behavior matches documented policy.

### [ ] T3 - Coverage for large valid delta payload streams

- Severity: `Medium`
- Status: `Todo`
- Gap: No tests validating inflate limits when delta stream inflates beyond result object size.

Checklist:

- [ ] Add crafted delta fixture with valid large delta stream.
- [ ] Assert no false `InflateError` under valid bounds.

### [ ] T4 - Performance characterization for large commit graphs and large MIDX builds

- Severity: `Medium`
- Status: `Todo`
- Gap: No characterization tests exposing O(N^2) generation and O(256*N) fanout costs.

Checklist:

- [ ] Add synthetic scaling benchmarks for commit graph generation.
- [ ] Add synthetic scaling benchmarks for MIDX merge/fanout build.
- [ ] Record baseline and post-change deltas in this file.

## Recommended Execution Order

- [ ] 1. Fix correctness blockers first: `C1`, `C2`, `C3`, `C4`.
- [ ] 2. Add minimum tests for each corrected behavior: `T1`, `T2`, `T3`.
- [ ] 3. Land high-impact performance fixes: `P1`, `P2`.
- [ ] 4. Land medium/low constant-factor improvements: `P3`, `P4`.
- [ ] 5. Add/refresh performance characterization: `T4`.

## Tracking Notes

- For performance work, capture baseline vs after metrics in this document using the project performance workflow from `AGENTS.md`.
- For each completed item, include:
- Commit/PR link or hash.
- Benchmark/test evidence.
- Any correctness/performance trade-offs accepted.
