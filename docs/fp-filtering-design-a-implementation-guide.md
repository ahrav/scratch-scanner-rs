# False Positive Filtering (Design A) Implementation Guide

## Short Summary of Strategy

Implement rule-selective, bounded micro-context gates inside the engine hot path
so false positives are reduced without adding a second pass or allocations after
warm-up. Gates must fail open on incomplete context to preserve correctness.

## Scope and Source of Truth

This guide is a task tracker and implementation checklist derived from:
- `docs/fp-filtering-brainstorm.md`
- `docs/fp-filtering-review.md`
- `docs/architecture-overview.md`
- `docs/engine-window-validation.md`

Canonical behavior is defined by code and architecture docs. Use this guide to
plan and track work, not as a normative spec.

## Progress Note

After completing a unit of work, mark it as complete with `[x]` in this guide.

## Assumptions and Open Questions

Assumptions:
- The existing `Engine` remains the only blob scanner.
- No allocations after warm-up in the hot path remain a hard requirement.
- Micro-context gates must fail open when context is incomplete in the window.
- Design A is engine-level only, so all scan paths inherit the same behavior.

Open questions:
- Do we want scoring (`ContextMode::Score`) or filter-only for Design A?
- Which rules are initially opted into micro-context gates?
- Should any micro-context gates apply to UTF-16 decoded windows?

## Phase 0 - Guardrails and Decisions

### Work Unit 0.1 - Context Mode Semantics

Purpose: Decide whether Design A is filter-only or includes scoring metadata.
Files: `src/api.rs`, `docs/fp-filtering-review.md`
Dependencies: none
Definition of done: Decision recorded in docs; API change plan captured if scoring is chosen.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Decision: Filter-only for Design A (no scoring). Rationale: avoid widening the
hot-path output surface (`FindingRec`) and keep Design A minimal; scoring can be
revisited once we have FP data to justify the API changes.

Checklist:
- [x] Decide whether Design A is filter-only or includes scoring metadata.
- [x] If scoring is chosen, draft an API change plan for `FindingRec` (N/A for filter-only).
- [x] Record the decision in `docs/fp-filtering-review.md`.

### Work Unit 0.2 - Rule Opt-In List

Purpose: Establish an initial list of rules that will use micro-context gates.
Files: `src/gitleaks_rules.rs`, `docs/fp-filtering-review.md`
Dependencies: Work Unit 0.1
Definition of done: A short list of rules is chosen and recorded with rationale.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Initial opt-in list (Design A):
- `generic-api-key` (high-FP, broad anchors; already uses assignment-shape precheck)

Rationale: start with the noisiest, most generic rule where a conservative
precheck is already in place. Expand this list after gathering FP data.
Checklist:
- [x] Identify initial high-FP rules to opt into Design A gates.
- [x] Record the rule list and rationale in this guide.
- [x] Record the rule list and rationale in `docs/fp-filtering-review.md`.

## Phase 1 - Config Surface and Compilation

### Work Unit 1.1 - RuleSpec Local Context Config

Purpose: Add a rule-level configuration surface for micro-context gates.
Files: `src/api.rs`, `src/engine/rule_repr.rs`
Dependencies: Phase 0 decisions
Definition of done: `RuleSpec` and `RuleCompiled` carry local context config and validation.
Tests: unit tests for invalid config shapes (if applicable)
Docs impacted: `docs/engine-window-validation.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add `LocalContextSpec` (or equivalent) to `RuleSpec` in `src/api.rs`.
- [x] Validate `LocalContextSpec` in `RuleSpec::assert_valid`.
- [x] Carry local context config into `RuleCompiled` in `src/engine/rule_repr.rs`.
- [x] Add or update unit tests for invalid config shapes.
- [x] Update `docs/engine-window-validation.md` to describe the new gate type.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

## Phase 2 - Hot Path Gate Implementation

### Work Unit 2.1 - Micro-Context Gate Helpers

Purpose: Implement bounded, allocation-free helpers for micro-context checks.
Files: `src/engine/window_validate.rs`
Dependencies: Work Unit 1.1
Definition of done: Helpers are bounded, allocation-free, and fail open on incomplete context.
Tests: new unit tests in `src/engine/window_validate.rs`
Docs impacted: `docs/engine-window-validation.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add bounded, allocation-free helper functions in `src/engine/window_validate.rs`.
- [x] Ensure helpers fail open when line boundaries are not found in the lookaround range.
- [x] Add unit tests for same-line assignment checks.
- [x] Add unit tests for quoted-value checks.
- [x] Update `docs/engine-window-validation.md` with the helper summary.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 2.2 - Apply Gates in Raw and UTF-16 Paths

Purpose: Invoke micro-context gates in both raw and UTF-16 validation flows.
Files: `src/engine/window_validate.rs`
Dependencies: Work Unit 2.1
Definition of done: Gates are applied before findings are emitted in all window paths.
Tests: new tests for UTF-16 cases
Docs impacted: `docs/engine-window-validation.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Apply micro-context gates in `run_rule_on_window` (raw).
- [x] Apply micro-context gates in `run_rule_on_raw_window_into`.
- [x] Apply micro-context gates in UTF-16 paths on decoded UTF-8 bytes.
- [x] Add or update UTF-16 unit tests for gated rules.
- [x] Update `docs/engine-window-validation.md` gate sequence.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 2.3 - Apply Gates in Stream Decode Path

Purpose: Ensure transform-derived findings also use micro-context gates.
Files: `src/engine/stream_decode.rs`, `src/engine/window_validate.rs`
Dependencies: Work Unit 2.2
Definition of done: Stream decode validation uses the same micro-context gate.
Tests: stream decode tests in `src/engine/tests.rs`
Docs impacted: `docs/engine-window-validation.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Apply micro-context gates in stream decode validation paths.
- [x] Add or update stream decode tests to cover micro-context gating.
- [x] Update `docs/engine-window-validation.md` for stream decode parity.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

## Phase 3 - Rule Wiring

### Work Unit 3.1 - Opt-In Rules in gitleaks_rules

Purpose: Enable micro-context gates on a small, high-FP rule set.
Files: `src/gitleaks_rules.rs`
Dependencies: Phase 0 decisions and Phase 2 implementation
Definition of done: Selected rules opt into local context gates with rationale.
Tests: `cargo test` and relevant engine tests
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Apply local context config to the selected rules in `src/gitleaks_rules.rs`.
- [x] Add inline comments where gate choices are non-obvious.
- [x] Update `docs/fp-filtering-review.md` with the selected rules.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

## Phase 4 - Tests and Correctness Guarantees

### Work Unit 4.1 - Boundary and Fail-Open Tests

Purpose: Prove micro-context gates do not introduce false negatives at boundaries.
Files: `src/engine/tests.rs`
Dependencies: Phase 2 implementation
Definition of done: Tests cover boundary conditions where context is incomplete.
Tests: `cargo test -p scanner-rs engine` or targeted test selection
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add tests where assignment separators are outside lookaround range.
- [x] Add tests where key names are outside lookaround range.
- [x] Add tests for quoted and unquoted secrets in same-line assignments.
- [x] Update `docs/fp-filtering-review.md` with test rationale.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 4.2 - Allocation Audit Pass

Purpose: Ensure micro-context gates do not introduce allocations in hot paths.
Files: `tests/diagnostic/alloc_after_startup.rs`
Dependencies: Phase 2 implementation
Definition of done: Allocation audit tests pass without threshold changes.
Tests: `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Run allocation audit tests.
- [x] Investigate and remove any new allocations.
- [x] Record allocation audit results in `docs/fp-filtering-review.md` if changes occur.

## Phase 5 - Performance and Documentation

### Work Unit 5.1 - Micro-Context Performance Check

Purpose: Validate perf impact of Design A within acceptable bounds.
Files: `benches/`, `src/bin/benchmark_scanner.rs`
Dependencies: Phase 2 implementation
Definition of done: Throughput regression is <= 2% on scanner throughput bench.
Tests: `cargo bench --bench scanner_throughput`
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Run `cargo bench --bench scanner_throughput`.
- [x] Record performance results in `docs/fp-filtering-review.md`.
- [x] Decide if a microbench is needed for per-match gate cost.

### Work Unit 5.2 - Documentation Updates

Purpose: Ensure docs reflect the new micro-context gate behavior.
Files: `docs/engine-window-validation.md`, `docs/detection-engine.md`, `docs/fp-filtering-review.md`
Dependencies: Phase 2 implementation
Definition of done: Docs updated with gate sequence, invariants, and failure modes.
Tests: none
Docs impacted: all listed docs
References: `docs/fp-filtering-brainstorm.md`, `docs/fp-filtering-review.md`

Checklist:
- [x] Update `docs/engine-window-validation.md` with the micro-context gate.
- [x] Update `docs/detection-engine.md` with micro-context gate semantics.
- [x] Update `docs/fp-filtering-review.md` with final behavior and results.
- [x] Cross-link this guide from `docs/fp-filtering-review.md`.
