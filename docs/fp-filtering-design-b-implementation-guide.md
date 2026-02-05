# False Positive Filtering (Design B) Implementation Guide

## Short Summary of Strategy

Implement a candidate-only, second-pass lexical tokenizer that classifies byte
ranges as code/comment/string and applies rule-selective filters without adding
allocations after warm-up. The tokenizer emits run-length segments into a fixed
scratch buffer and always fails open when context is unknown or incomplete.

## Scope and Source of Truth

This guide is a task tracker and implementation checklist derived from:
- `docs/fp-filtering-brainstorm.md`
- `docs/fp-filtering-review.md`
- `docs/pipeline-flow.md`
- `docs/pipeline-state-machine.md`
- `docs/scheduler-local.md`
- `docs/scheduler-local-fs-uring.md`
- `docs/scheduler-remote-backend.md`

Canonical behavior is defined by code and architecture docs. Use this guide to
plan and track work, not as a normative spec.

## Progress Note

After completing a unit of work, mark it as complete with `[x]` in this guide.

## Assumptions and Initial Decisions

Assumptions:
- Design A micro-context gates are complete and remain always-on.
- Design B runs only on candidate files (files with findings) to preserve
  hot-path throughput.
- The tokenizer is allocation-free after warm-up and uses fixed-capacity
  scratch buffers.
- Context evaluation fails open on unknown state, run-cap overflow, or missing
  lexical coverage.
- Lexical context is evaluated against root-file bytes using root-span hints.
- Transform-derived findings with coarse root-span hints are treated as
  unknown lexical context and fail open (no filtering).

Initial decisions (Phase 0):
- Context mode: `ContextMode::Score` + `ContextMode::Filter` semantics.
- Parity scope: all scan entry points (scheduler, pipeline, runtime, async IO).
- Language families: C-like, Python-like, Shell-like, Config.

## Phase 0 - Guardrails and Decisions

### Work Unit 0.1 - Context Mode + Output Semantics

Purpose: Decide whether Design B is filter-only or includes scoring metadata.
Files: `src/api.rs`, `src/scheduler/findings.rs`, `docs/fp-filtering-review.md`
Dependencies: none
Definition of done: Decision recorded and API change plan captured if scoring
is chosen.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Decision: Use `ContextMode::Score` + `ContextMode::Filter` semantics. Rationale:
leading scanners separate detection from verification/validity and allow users
to include only verified/valid results or keep unverified results for triage.
We mirror this by attaching lexical confidence/classification and filtering
only when context is definitive, while preserving recall when context is
unknown. This yields a stronger FP reduction path without forcing false
negatives. References:
- [TruffleHog verification states and result selection](https://github.com/trufflesecurity/trufflehog)
- [detect-secrets verification filters](https://github.com/Yelp/detect-secrets)
- [GitGuardian validity checks](https://docs.gitguardian.com/secrets-detection/customize-detection/validity-checks)

Checklist:
- [x] Decide whether Design B uses filter-only or scoring semantics.
- [x] If scoring is chosen, draft an API change plan for `FindingRec` and
  output sinks (pipeline/runtime/scheduler).
- [x] Record the decision in `docs/fp-filtering-review.md`.

### Work Unit 0.2 - Candidate-Only Second Pass Strategy

Purpose: Commit to the second-pass control flow and emission timing for all
scan entry points.
Files: `src/pipeline.rs`, `src/runtime.rs`, `src/async_io/`,
`src/scheduler/local.rs`, `src/scheduler/local_fs_uring.rs`,
`src/scheduler/remote.rs`
Dependencies: Work Unit 0.1
Definition of done: Candidate-only second pass is selected with explicit
buffering and fail-open rules for each entry point.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`, `docs/pipeline-flow.md`,
`docs/scheduler-local.md`, `docs/scheduler-local-fs-uring.md`
References: `docs/fp-filtering-brainstorm.md`, `docs/fp-filtering-review.md`

Decision: Implement candidate-only lexical filtering in all scan entry points.
Buffer per-file findings, then re-open or re-read the file/object to tokenize
the full contents. If re-open/re-read fails, file size changes, or the source
is non-seekable, treat lexical context as unknown and emit unfiltered
findings. Prefer re-opening to avoid holding file handles across scans and to
keep the chunk scan path unchanged.

Checklist:
- [x] Decide how findings are buffered per file before lexical filtering.
- [x] Decide whether to reuse the open file handle or re-open for pass two.
- [x] Define fail-open behavior when the second pass cannot run (I/O errors,
  non-seekable handles, size changes).
- [x] Record decisions in `docs/fp-filtering-review.md`.

### Work Unit 0.3 - Language Family Matrix + Extension Mapping

Purpose: Define the initial language families and how file paths map to a
lexer family.
Files: `src/git_scan/path_policy.rs`, `docs/fp-filtering-review.md`
Dependencies: Work Unit 0.1
Definition of done: A language-family matrix and extension mapping are
documented and wired into a configuration surface.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Decision: Initial tokenizer coverage focuses on four families that map to the
most common languages across major usage measures. C-like includes TypeScript
and C explicitly: TypeScript is #1 on GitHub in 2025, and GitHub’s 2024 top-10
list includes TypeScript (#3) and C (#9). Stack Overflow’s 2025 survey also
shows TypeScript and C among the most-used languages. We therefore prioritize
C-like (TypeScript/JavaScript/Java/C#/C++/C/Go/Rust/Swift/Kotlin), Python-like
(Python/Ruby), Shell-like (sh/bash/zsh/ps1), and Config (HCL/JSON/YAML/TOML/
INI/.env). This maximizes coverage with a small set of lexers while aligning to
the top language distributions. References:
- [GitHub Octoverse 2025 top languages](https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/)
- [GitHub Octoverse 2024 top languages](https://github.blog/news-insights/octoverse/octoverse-2024/)
- [Stack Overflow 2025 Developer Survey (Technology)](https://survey.stackoverflow.co/2025/technology/)

Checklist:
- [x] Decide the initial language families (C-like, Python-like, Shell-like,
  config formats).
- [x] Define extension/path mapping rules (including fallbacks for unknown).
- [x] Record the mapping in `docs/fp-filtering-review.md`.

## Phase 1 - Config Surface and Rule Opt-In

### Work Unit 1.1 - Lexical Context Spec in RuleSpec

Purpose: Add rule-level configuration for lexical context requirements.
Files: `src/api.rs`, `src/engine/rule_repr.rs`, `src/lib.rs`
Dependencies: Phase 0 decisions
Definition of done: `RuleSpec` and `RuleCompiled` carry lexical context config
with validation.
Tests: unit tests for invalid config shapes
Docs impacted: `docs/detection-engine.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add a `LexicalContextSpec` (or equivalent) to `RuleSpec` in `src/api.rs`.
- [x] Validate the spec in `RuleSpec::assert_valid`.
- [x] Carry lexical context config into `RuleCompiled`.
- [x] Add or update unit tests for invalid config shapes.
- [x] Update `docs/detection-engine.md` with lexical context semantics.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 1.2 - Context Mode Config Plumbing

Purpose: Expose context mode toggles and defaults across scan entry points.
Files: `src/runtime.rs`, `src/pipeline.rs`, `src/async_io/mod.rs`,
`src/scheduler/mod.rs`, `src/api.rs`
Dependencies: Work Unit 1.1
Definition of done: Context mode is configurable and consistent across all
scan paths.
Tests: config/unit tests for default behavior
Docs impacted: `docs/architecture-overview.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Add context mode fields to scan configs (pipeline/runtime/scheduler/AIO).
- [x] Wire defaults to `ContextMode::Off` unless explicitly enabled.
- [x] Add tests for default off behavior.
- [x] Update `docs/architecture-overview.md` with the new mode switch.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 1.3 - Initial Rule Opt-In List (Design B)

Purpose: Choose a small, high-FP rule set for lexical context filtering.
Files: `src/gitleaks_rules.rs`, `docs/fp-filtering-review.md`
Dependencies: Work Unit 1.1
Definition of done: Initial rule list is selected and documented with
rationale.
Tests: none
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Identify the initial high-FP rules to opt into lexical context.
- [x] Add inline comments where lexical requirements are non-obvious.
- [x] Record the rule list and rationale in `docs/fp-filtering-review.md`.

## Phase 2 - Tokenizer Core

### Work Unit 2.1 - Run-Length Lexical Runs + Scratch

Purpose: Implement allocation-free run-length segments for lexical classes.
Files: `src/scratch_memory.rs`, `src/lib.rs`, new module (e.g. `src/lexical.rs`)
Dependencies: Phase 1 config surface
Definition of done: Tokenizer emits `LexRun` segments into fixed-capacity
scratch with fail-open behavior on overflow.
Tests: unit tests for run overflow and unknown context
Docs impacted: `docs/memory-management.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Define `LexClass` and `LexRun` types and a fixed-capacity run buffer.
- [x] Implement run-cap overflow handling (mark context as unknown and fail
  open).
- [x] Add unit tests for overflow and unknown-context behavior.
- [x] Update `docs/memory-management.md` with the run-cap policy.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 2.2 - C-Like Tokenizer

Purpose: Tokenize C-like languages with line/block comments and quoted strings.
Files: new module (e.g. `src/lexical.rs`)
Dependencies: Work Unit 2.1
Definition of done: C-like tokenizer handles `//`, `/* */`, `'`, `"`, and
escape rules with deterministic state transitions.
Tests: unit tests covering single-line, block, and nested delimiter cases
Docs impacted: `docs/detection-engine.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Implement a C-like lexical state machine with escape handling.
- [x] Emit runs for code, comment, and string segments.
- [x] Add unit tests for multiline strings and comment boundaries.
- [x] Update `docs/detection-engine.md` with C-like tokenizer semantics.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 2.3 - Python/Shell/Config Tokenizers

Purpose: Add language-family tokenizers for Python-like, shell-like, and
configuration formats.
Files: new module (e.g. `src/lexical.rs`)
Dependencies: Work Unit 2.1
Definition of done: Tokenizers handle `#` comments, triple quotes, and
config-style string semantics.
Tests: unit tests for triple-quote and heredoc-like edge cases
Docs impacted: `docs/detection-engine.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Implement Python-like tokenizer (line comments, triple-quote strings).
- [x] Implement shell-like tokenizer (line comments, single/double quotes).
- [x] Implement config tokenizer (JSON/TOML/INI string semantics).
- [x] Add unit tests for each language family.
- [x] Update `docs/detection-engine.md` with language-family coverage.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 2.4 - Context Lookup + Fail-Open Rules

Purpose: Map findings to lexical runs and apply rule-level requirements.
Files: new module (e.g. `src/lexical.rs`), `src/api.rs`
Dependencies: Work Unit 2.2 and 2.3
Definition of done: Findings are classified by lexical context with clear
fail-open rules for unknown or ambiguous context.
Tests: unit tests for mapping near run boundaries
Docs impacted: `docs/detection-engine.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Implement run lookup (binary search or linear scan with small caps).
- [x] Apply lexical context requirements from `RuleSpec`.
- [x] Fail open on unknown context or run-cap overflow.
- [x] Add unit tests for boundary conditions and unknown context.
- [x] Update `docs/detection-engine.md` with lookup semantics.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

## Phase 3 - Candidate-Only Integration

### Work Unit 3.1 - Scheduler Local Second Pass

Purpose: Buffer per-file findings and apply lexical filtering before emission.
Files: `src/scheduler/local.rs`
Dependencies: Phase 2 tokenizer
Definition of done: `scheduler/local.rs` buffers findings per file, runs the
second-pass tokenizer, and filters or scores findings before emit.
Tests: scheduler integration tests
Docs impacted: `docs/scheduler-local.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Buffer findings per file until scan completion.
- [x] Re-read file and run tokenizer for candidate files only.
- [x] Apply lexical context rules and emit filtered findings.
- [x] Update `docs/scheduler-local.md` with the new pass.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 3.2 - Scheduler io_uring + Remote Paths

Purpose: Apply the same candidate-only lexical pass in io_uring and remote
scanners.
Files: `src/scheduler/local_fs_uring.rs`, `src/scheduler/remote.rs`
Dependencies: Work Unit 3.1
Definition of done: io_uring and remote paths buffer findings per file/object
and apply the lexical pass before emit.
Tests: scheduler integration tests
Docs impacted: `docs/scheduler-local-fs-uring.md`, `docs/scheduler-remote-backend.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Add per-file findings buffers to io_uring path.
- [x] Add per-object findings buffers to remote path.
- [x] Apply lexical filtering before output emission.
- [x] Update scheduler docs for both paths.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 3.3 - Pipeline + Runtime Second Pass

Purpose: Apply the lexical pass in the pipeline and runtime scanners.
Files: `src/pipeline.rs`, `src/runtime.rs`
Dependencies: Phase 2 tokenizer
Definition of done: pipeline and runtime buffer findings per file and apply the
lexical pass before formatting output.
Tests: pipeline/runtime integration tests
Docs impacted: `docs/pipeline-flow.md`, `docs/pipeline-state-machine.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Buffer findings per file in pipeline before output stage.
- [x] Re-read candidate files and apply lexical filtering.
- [x] Apply lexical filtering to `ScannerRuntime::scan_file_sync` results.
- [x] Update pipeline docs with the second pass.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 3.4 - Async IO Scanners

Purpose: Apply lexical filtering in platform async scanners.
Files: `src/async_io/linux.rs`, `src/async_io/macos.rs`
Dependencies: Phase 2 tokenizer
Definition of done: async scanners buffer findings per file and apply lexical
filtering before emission.
Tests: async scanner integration tests
Docs impacted: `docs/architecture-overview.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Buffer findings per file in async scanners.
- [x] Re-read candidate files and apply lexical filtering.
- [x] Update async scanning docs for the new pass.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

## Phase 4 - Tests and Correctness Guarantees

### Work Unit 4.1 - Lexer Correctness Tests

Purpose: Prove lexical classification matches expected string/comment behavior.
Files: new tests in tokenizer module
Dependencies: Phase 2 tokenizer
Definition of done: Tests cover escape handling, multiline spans, and delimiter
edges for each language family.
Tests: `cargo test` (targeted module tests)
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add unit tests for comment and string classification.
- [x] Add tests for escape sequences and quote termination.
- [x] Add tests for multiline and boundary conditions.
- [x] Update `docs/fp-filtering-review.md` with test coverage notes.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 4.2 - Fail-Open Guarantees

Purpose: Ensure unknown context never drops findings.
Files: tokenizer tests, scan entry point tests
Dependencies: Phase 3 integration
Definition of done: Tests demonstrate fail-open for overflow, missing language,
and I/O errors during the second pass.
Tests: targeted `cargo test` selections
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Add tests for run-cap overflow (must keep findings).
- [x] Add tests for unsupported language (must keep findings).
- [x] Add tests for second-pass I/O failure (must keep findings).
- [x] Update `docs/fp-filtering-review.md` with fail-open rationale.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 4.3 - Cross-Path Parity Tests

Purpose: Ensure scheduler, pipeline, runtime, and AIO produce consistent output.
Files: integration tests or harnesses in `src/engine/tests.rs` or new tests
Dependencies: Phase 3 integration
Definition of done: Findings filtered identically across scan entry points.
Tests: `cargo test` (targeted integration tests)
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Add parity tests for scheduler local and pipeline paths.
- [x] Add parity tests for runtime and async IO paths.
- [x] Update `docs/fp-filtering-review.md` with parity test notes.
- [x] Run `cargo fmt --all`.
- [x] Run `cargo check`.
- [x] Run `cargo clippy --all-targets --all-features`.
- [x] Run the `doc-rigor` skill on new code.

### Work Unit 4.4 - Allocation Audit Pass

Purpose: Ensure the lexical pass introduces no allocations after warm-up.
Files: `tests/diagnostic/alloc_after_startup.rs`
Dependencies: Phase 3 integration
Definition of done: Allocation audit tests pass without threshold changes.
Tests: `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-review.md`

Checklist:
- [x] Run allocation audit tests.
- [x] Investigate and remove any new allocations.
- [x] Record allocation audit results in `docs/fp-filtering-review.md` if
  changes occur.

## Phase 5 - Performance and Documentation

### Work Unit 5.1 - Tokenizer Performance + Throughput

Purpose: Validate perf impact of Design B within acceptable bounds.
Files: `benches/`, `src/bin/benchmark_scanner.rs`
Dependencies: Phase 3 integration
Definition of done: Candidate-only second pass shows acceptable overhead on
scanner throughput benchmarks.
Tests: `cargo bench --bench scanner_throughput`
Docs impacted: `docs/fp-filtering-review.md`
References: `docs/fp-filtering-brainstorm.md`

Checklist:
- [x] Add or update a tokenizer microbench (cycles/byte).
- [x] Run `cargo bench --bench scanner_throughput`.
- [x] Record performance results in `docs/fp-filtering-review.md`.

### Work Unit 5.2 - Documentation Updates

Purpose: Ensure docs reflect lexical context filtering and second-pass flow.
Files: `docs/detection-engine.md`, `docs/pipeline-flow.md`,
`docs/pipeline-state-machine.md`, `docs/scheduler-local.md`,
`docs/scheduler-local-fs-uring.md`, `docs/scheduler-remote-backend.md`,
`docs/architecture-overview.md`, `docs/memory-management.md`,
`docs/transform-chain.md`, `docs/fp-filtering-review.md`
Dependencies: Phase 3 integration
Definition of done: Docs updated with tokenizer flow, invariants, and failure
modes. Cross-link this guide from the review doc.
Tests: none
Docs impacted: all listed docs
References: `docs/fp-filtering-brainstorm.md`, `docs/fp-filtering-review.md`

Checklist:
- [x] Update architecture and pipeline docs with second-pass flow.
- [x] Update `docs/detection-engine.md` with lexical context semantics.
- [x] Update `docs/memory-management.md` with run-cap and scratch usage.
- [x] Update `docs/transform-chain.md` if transform-derived findings are
  filtered by lexical context.
- [x] Update `docs/fp-filtering-review.md` with final behavior and results.
- [x] Cross-link this guide from `docs/fp-filtering-review.md`.
