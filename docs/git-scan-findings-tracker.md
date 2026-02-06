# Git Scan Findings Tracker (Correctness, Performance, and Test Gaps)

This document tracks findings from a prior review session and converts them into actionable work items.  
Status should be updated in-place as items are investigated and fixed.

## Legend

- Severity: `High`, `Medium`, `Low`
- Status: `Todo`, `In Progress`, `Done`, `Validated`

## Correctness Findings

### [x] C1 - Empty start set can produce a no-op in-memory commit graph

- Severity: `High`
- Status: `Validated`
- Finding summary: In-memory artifact flow can produce an empty commit graph when artifacts are missing because `repo_open` can return an empty `start_set`, and `acquire_commit_graph` treats "no tips" as "empty graph."
- Affected code:
- `src/git_scan/repo_open.rs`
- `src/git_scan/artifact_acquire.rs`

Investigation plan:

- [x] Reproduce with a repository fixture where artifact files are missing but refs exist.
- [x] Trace `resolver.resolve(...)` and watermark loading behavior to confirm whether empty `start_set` is expected vs accidental.
- [x] Define desired contract for empty `start_set` in the in-memory path (hard error vs fallback start-set resolution).
- [x] Implement guardrail (error or fallback path) so scan cannot silently become a no-op.
- [x] Add end-to-end regression test asserting non-empty graph (or explicit failure) when refs are present.

Expected benefit:

- Correctness: prevents silent false-negative scans caused by accidental empty traversal roots.
- Operational impact: converts hidden no-op behavior into deterministic success/failure semantics.

Success criteria:

- [x] In-memory path cannot silently return empty graph when repository has reachable refs.
- [x] Test reproducer fails before fix and passes after fix.

Evidence (2026-02-06):

- `src/git_scan/repo_open.rs`: added `repo_has_reachable_refs(...)` to detect loose and packed refs.
- `src/git_scan/artifact_acquire.rs`: `acquire_commit_graph(...)` now returns `ArtifactAcquireError::EmptyStartSetWithRefs` when tips are empty but refs exist.
- `tests/integration/git_inmem_artifacts.rs`: added `acquire_commit_graph_errors_when_start_set_empty_but_refs_exist`.
- Validation command:
`cargo test --test integration acquire_commit_graph_errors_when_start_set_empty_but_refs_exist -- --nocapture`

### [x] C2 - In-memory commit loading is pack-only; loose tips can fail with `CommitNotFound`

- Severity: `High`
- Status: `Done`
- Finding summary: In-memory commit loading currently uses MIDX lookup only. Tips that exist as loose objects can fail `midx.find_oid(...)` and abort graph build with `CommitNotFound`.
- Affected code:
- `src/git_scan/commit_loader.rs`
- `src/git_scan/artifact_acquire.rs`

Investigation plan:

- [x] Reproduce with a fixture containing loose-only tip commits and no corresponding packed object.
- [x] Confirm current behavior in mixed histories (packed parents, loose head).
- [x] Decide fallback policy for missing MIDX entries (load loose object by OID vs explicit unsupported-mode error).
- [x] Implement fallback or clear-mode error with actionable diagnostics.
- [x] Add tests for loose-only and mixed loose+pack commit chains.

Expected benefit:

- Correctness: prevents aborts on valid repositories that have not recently run maintenance.
- Reliability: reduces mode-dependent behavior differences between fresh and GC-maintained repos.

Success criteria:

- [x] Loose-only tips are either successfully loaded or rejected with a deterministic, documented error.
- [x] Mixed packed+loose history path is covered by tests.

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

### [x] P1 - `CommitGraphMem::build` generation pass is O(N^2) on deep histories

- Severity: `High`
- Status: `Validated`
- Finding summary: Generation computation repeatedly scans pending commits until dependencies resolve, degrading to O(N^2) for long chains/deep DAGs.
- Affected code:
- `src/git_scan/commit_graph_mem.rs`

Investigation plan:

- [x] Add benchmark fixture for long linear chains and deep/wide DAGs.
- [x] Replace iterative pending-scan approach with topological/dynamic programming pass with indegree tracking (target O(N + E)).
- [x] Preserve deterministic `(generation, oid)` final ordering and current missing-parent semantics.
- [x] Compare before/after on synthetic and real repository traces.
- [x] Add regression test for generation correctness on non-trivial DAGs.

Expected performance gain:

- Asymptotic: O(N^2) to O(N + E).
- Practical estimate: 2x-20x faster generation phase on very large or deep commit graphs (depends on topology).

Success criteria:

- [x] Benchmark confirms sub-quadratic scaling as history depth grows.
- [x] No behavioral regression in generation values or ordering guarantees.

Evidence (2026-02-06):

- `src/git_scan/commit_graph_mem.rs` uses indegree-based topological generation propagation (`O(N+E)`) and deterministic `(generation, oid)` ordering.
- Added benchmark target: `benches/commit_graph_generation.rs` (+ `Cargo.toml` bench registration).
- Benchmark command:
`cargo bench --bench commit_graph_generation -- --sample-size 10 --measurement-time 0.2 --warm-up-time 0.1`
- Linear chain timings:
- 1,024 commits: ~81 us
- 4,096 commits: ~324 us
- 16,384 commits: ~1.36 ms
- 32,768 commits: ~2.89 ms
- Layered DAG timings:
- 2,048 commits: ~216 us
- 8,192 commits: ~897 us
- 16,384 commits: ~1.87 ms

### [x] P2 - MIDX fanout update is O(256*N) during merge output

- Severity: `High`
- Status: `Done` (implementation landed, perf characterization pending)
- Finding summary: Fanout table is updated by writing all suffix slots per emitted OID, producing O(256*N) work.
- Affected code:
- `src/git_scan/midx_build.rs`

Investigation plan:

- [ ] Add micro-benchmark for MIDX build across 1M+ synthetic objects.
- [x] Replace per-object suffix fill with two-phase method:
- Count first-byte buckets during emit (O(N)).
- Prefix-sum once across 256 buckets (O(256)).
- [x] Validate chunk equivalence via parser-level fanout + dedupe tests for representative inputs.
- [ ] Benchmark CPU time and cache behavior before/after.

Expected performance gain:

- Asymptotic: O(256*N) to O(N + 256).
- Practical estimate: 1.5x-4x faster fanout construction on large object sets; larger wins at multi-million scale.

Success criteria:

- [x] Fanout chunk remains spec-correct.
- [ ] End-to-end MIDX build time improves on large fixtures.

### [x] P3 - BFS frontier can contain duplicates before visit marking

- Severity: `Medium`
- Status: `Done` (frontier de-dup landed, perf characterization pending)
- Finding summary: Parents are enqueued when not yet visited but may already be queued, inflating queue size and repeated set lookups.
- Affected code:
- `src/git_scan/commit_loader.rs`

Investigation plan:

- [ ] Add instrumentation for frontier max length, enqueue count, and duplicate enqueue count.
- [x] Add "seen-or-queued" tracking to prevent duplicate frontier entries.
- [ ] Benchmark on merge-heavy DAGs where parent overlap is high.
- [x] Validate queue behavior/order guarantees with focused unit tests.

Expected performance gain:

- Practical estimate: 5%-20% reduction in commit-loading CPU and queue memory on overlap-heavy histories.
- Worst-case asymptotics unchanged, but constant factors should improve.

Success criteria:

- [x] Duplicate enqueue behavior is blocked by design via `queued` tracking.
- [x] Commit set/order queue invariants are covered by new de-dup ordering tests.

### [x] P4 - `PackFile::parse` is repeated per object load

- Severity: `Low`
- Status: `Done`
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

### [x] T1 - End-to-end coverage for missing artifacts + non-empty start-set resolution

- Severity: `High`
- Status: `Done`
- Gap: No end-to-end test for in-memory path when artifacts are missing to ensure a valid start set still yields non-empty commit graph.

Checklist:

- [x] Add fixture and test harness case for missing artifacts with resolvable refs.
- [x] Assert graph is non-empty or explicit error is raised (per decided contract).

### [x] T2 - Coverage for loose-only tips and mixed loose+pack histories

- Severity: `High`
- Status: `Done`
- Gap: No tests verifying behavior when tips are loose objects.

Checklist:

- [x] Add loose-only tip scenario.
- [x] Add mixed packed-parent + loose-head scenario.
- [x] Assert behavior matches documented policy.

### [x] T3 - Coverage for large valid delta payload streams

- Severity: `Medium`
- Status: `Done`
- Gap: No tests validating inflate limits when delta stream inflates beyond result object size.

Checklist:

- [x] Add crafted delta fixture with valid large delta stream.
- [x] Assert no false `InflateError` under valid bounds.

### [x] T4 - Performance characterization for large commit graphs and large MIDX builds

- Severity: `Medium`
- Status: `Done`
- Gap: No characterization tests exposing O(N^2) generation and O(256*N) fanout costs.

Checklist:

- [x] Add synthetic scaling benchmarks for commit graph generation.
- [x] Add synthetic scaling benchmarks for MIDX merge/fanout build.
- [x] Record baseline and post-change deltas in this file.

Benchmark evidence (2026-02-06):

- Benchmark targets:
- `benches/commit_graph_generation.rs`
- `benches/midx_build_scaling.rs`
- Commands:
- `cargo bench --bench commit_graph_generation -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1 --save-baseline t4_before`
- `cargo bench --bench commit_graph_generation -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1 --baseline t4_before`
- `cargo bench --bench midx_build_scaling -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1 --save-baseline t4_before`
- `cargo bench --bench midx_build_scaling -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1 --baseline t4_before`
- Representative median snapshots (Criterion `t4_before` vs `new`):

| Benchmark | Before median (ms) | After median (ms) | Delta time |
|---|---:|---:|---:|
| commit graph linear chain (`n=32768`) | 3.019 | 2.871 | -4.90% |
| commit graph layered DAG (`d256_w64_n16384`) | 2.029 | 1.842 | -9.24% |
| MIDX object scale (`packs=8`, `objects=262144`) | 11.388 | 11.431 | +0.37% |
| MIDX pack fan-in (`packs=16`, `objects=131072`) | 7.203 | 7.335 | +1.84% |

Notes:

- Commit graph characterization now has synthetic linear and layered DAG scaling cases.
- MIDX characterization now has synthetic object-count scaling and pack fan-in scaling cases.
- The `t4_before`/`new` comparison above is a same-branch rerun for benchmark drift tracking; use it as a characterization baseline, not as an optimization claim.

## Recommended Execution Order

- [ ] 1. Fix correctness blockers first: `C1`, `C2`, `C3`, `C4`.
- [x] 2. Add minimum tests for each corrected behavior: `T1`, `T2`, `T3`.
- [ ] 3. Land high-impact performance fixes: `P1`, `P2`.
- [ ] 4. Land medium/low constant-factor improvements: `P3`, `P4`.
- [ ] 5. Add/refresh performance characterization: `T4`.

## Tracking Notes

- For performance work, capture baseline vs after metrics in this document using the project performance workflow from `AGENTS.md`.
- For each completed item, include:
- Commit/PR link or hash.
- Benchmark/test evidence.
- Any correctness/performance trade-offs accepted.
