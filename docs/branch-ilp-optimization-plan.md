# Branchiness + ILP Optimization Plan (Engine + Git Scan Adapter, Apple Silicon First)

## Summary
Identify and reduce avoidable branch mispredicts and serial dependency chains in the scanner's hottest loops using a source+ASM workflow, then validate with throughput and correctness gates.
Scope includes `src/engine/*` hot paths plus `src/git_scan/*` adapter overhead that impacts end-to-end runs.

## Grounded Findings (current state)
- ASM tooling is available: `cargo-asm` present.
- `llvm-mca` is not installed, so ILP verification will rely on assembly inspection + runtime perf counters/throughput.
- Hot loops confirmed from code + counters:
1. `scan_chunk_into` dispatch/work loop in `src/engine/core.rs`.
2. Window accumulation/merge path in `src/engine/buffer_scan.rs` and `src/engine/helpers.rs`.
3. Stream decode closure in `decode_stream_and_scan` (`src/engine/stream_decode.rs`) with dense branch fan-out.
4. Rule validation path `run_rule_on_window` (`src/engine/window_validate.rs`) with deep gate chain.
5. Git adapter chunk/scan orchestration in `src/git_scan/engine_adapter.rs`.

## Public API / Interface Impact
- Default: no public API changes required.
- Any changes should remain internal to engine/git-scan modules unless a measured win requires API-level tuning knobs.
- If a tuning knob is introduced, it must be additive and default-preserving (no behavior change for existing callers).

## Optimization Strategy

### Phase 1: Baseline and hotspot ranking
1. Capture baseline timing split with existing counters:
- `scan_vs_prefilter_nanos`, `scan_validate_nanos`, `scan_transform_nanos`, `scan_reset_nanos`.
2. Run representative benchmarks/repo scans to rank loops by wall time:
- `cargo bench --bench scanner_throughput`
- `cargo bench --bench vectorscan_overhead`
- repo scans via release binary on representative corpora.
3. Record branch-sensitive proxies:
- Linux: existing `benchmark_scanner` perf_event counters (branch misses, IPC, frontend/backend stalls).
- Apple Silicon: throughput deltas + ASM pattern analysis (no local PMU integration in repo today).

### Phase 2: ASM-guided branch/ILP audit
For each hot function, inspect emitted assembly (`cargo asm`) and annotate:
1. Hard branches in loop bodies (`b.*`, `cbz/cbnz`, loop-exit tests).
2. Conditional-select opportunities already exploited (`csel/csinv`) vs remaining branchy decisions.
3. Long dependency chains:
- Repeated saturating-add/check/update on shared counters per iteration.
- Serial "gate ladder" where each check blocks later useful work.
4. Call-heavy branch sites (`memmem`, stream scan callbacks) that cause unpredictable control flow.

Targeted audit list:
1. `scanner_rs::engine::helpers::merge_ranges_with_gap_sorted`
2. `scanner_rs::engine::helpers::coalesce_under_pressure_sorted`
3. `scanner_rs::engine::helpers::contains_any_memmem`
4. `scanner_rs::engine::window_validate::<impl ...>::run_rule_on_window`
5. `scanner_rs::engine::stream_decode::<impl ...>::decode_stream_and_scan::{{closure}}`
6. Git adapter scan loop around `engine.scan_chunk_into` in `src/git_scan/engine_adapter.rs`.

### Phase 3: Refactor plan for branch reduction and higher ILP
Apply changes in small, benchmarked steps:

1. Stream decode loop (`src/engine/stream_decode.rs`)
- Split fast-path chunk handling from rare fallback/error paths into separate helper fns.
- Hoist invariant feature/gate flags out of per-chunk loop.
- Convert frequently-checked flags into compact bitflags and use straight-line tests.
- Break dependency chains by using local accumulators per chunk and committing shared counters once per iteration.

2. Rule validation (`src/engine/window_validate.rs`)
- Specialize by variant/gate configuration earlier to reduce mixed-logic branching in one mega-path.
- Separate cold checks (context/entropy/extended mapping logic) from first-pass fast reject checks.
- Reorder predicates by (cheap + high reject rate) first, but keep measured ordering per workload tier.

3. Window merge/coalesce (`src/engine/helpers.rs`)
- Keep compiler-emitted `csel`-friendly min/max style where effective.
- Evaluate branchless overlap/merge update form for common-case sorted windows.
- Consider SoA scratch for starts/ends/hints only if measured to help (not assumed).

4. Git scan adapter (`src/git_scan/engine_adapter.rs`)
- Reduce branchy per-chunk adapter overhead around empty/no-hit cases.
- Hoist invariant checks outside tight chunk loops where possible.
- Keep engine call boundaries stable to avoid broad regression risk.

5. Intrinsics policy (allowed)
- Use intrinsics only when ASM demonstrates persistent branch/dependency bottlenecks the compiler does not resolve.
- No inline asm in this pass.

### Phase 4: Verification and acceptance
1. Correctness gates (mandatory):
- `cargo test`
- `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features`
- Targeted tests for transform streaming, dedupe semantics, UTF-16 paths, and chunk boundary behavior.

2. Performance gates (mandatory):
- Repeat baseline/after measurements with same corpus and benchmark settings.
- Report per-stage nanoseconds and throughput.
- Acceptance thresholds:
  - <2%: ship
  - 2-5%: document rationale
  - >5% regression in any primary workload: rework before merge

3. ASM regression checks:
- Re-capture `cargo asm` for audited functions.
- Confirm intended effects: fewer unpredictable branches in hot loops, shorter serial counter-update chains, improved straight-line fast path.

## Deliverables
1. Branch/ILP hotspot report (markdown) with:
- before/after assembly snippets,
- rationale per changed function,
- measured perf impact.
2. Code changes in engine + git adapter.
3. Updated docs via `/doc-rigor` for changed hot-path behavior and measurement workflow.
4. Optional follow-up task: add Apple-specific profiling workflow doc (Instruments/xctrace) for branch/ILP evidence.

## Assumptions and defaults
- Priority CPU: Apple Silicon (`aarch64-apple-darwin`).
- Scope includes engine and git scan adapter only (not scheduler/archive internals in this pass).
- Intrinsics are permitted; inline assembly is out of scope.
- `llvm-mca` is currently unavailable locally; plan does not depend on it.
