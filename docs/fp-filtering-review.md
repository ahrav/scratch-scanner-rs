# False Positive Filtering Review (Feasibility + Constraints)

This document summarizes feasibility and engineering constraints for the ideas in
`docs/fp-filtering-brainstorm.md`. It is intended to complement (not replace)
the brainstorm and to provide a concrete, codebase-aware assessment of what is
practical in the current architecture.

## Scope

- Evaluate feasibility of the three proposed designs (A/B/C).
- Map each design to actual integration points in the codebase.
- Call out correctness and performance constraints that must be preserved.
- Identify minimal changes required to move forward with implementation plans.

## Current Engine + Runtime Constraints

1. **No-alloc after warm-up in hot paths**
   - Allocation audits exist for engine scan, pipeline, runtime, AIO, and
     scheduler paths.
   - Any context filtering must be allocation-free after warm-up, or these tests
     will fail.

2. **Findings are compact records**
   - `FindingRec` has no place for confidence, score, or context metadata.
   - If we want scoring ("ContextMode::Score"), the output type must expand.

3. **Multiple scan entry points**
   - Findings are emitted via several paths (scheduler, pipeline, AIO, runtime).
   - A filter in only one path yields inconsistent behavior.

4. **Chunked scanning + overlap semantics**
   - Any context gate must fail open when its required context is incomplete
     within the current window to avoid false negatives.

## Feasibility Summary

### Design A: Rule-local micro-context gates

**Feasibility: High**

Why:
- The engine already has per-window validation and access to secret spans.
- There is an existing assignment-shape precheck used for one rule.
- This path is already bounded and runs only on matches.

Constraints:
- Must be **rule-selective** and **fail open** when context is incomplete.
- If implemented as a hard filter, it risks false negatives and must be opt-in.
- If implemented as a score, we must expand `FindingRec` or add a side channel.

Integration points:
- `src/engine/window_validate.rs` (raw + UTF-16 windows)
- `src/engine/stream_decode.rs` (stream-decoded windows)

Minimal changes:
- Extend `RuleSpec` or per-rule config to express local-context requirements.
- Plumb the new gate into both raw and decoded validation paths.

### Design B: Streaming tokenizer / lexical context

**Feasibility: Medium**

Why:
- Requires new file-level control flow (second pass or streaming lexer).
- Current output is emitted per chunk; lexical context needs file-level state.

Constraints:
- Must be allocation-free after warm-up.
- Must fail open on unknown context or insufficient lexer state.
- Must cover multiple output paths for consistent behavior.

Integration options:
- **Second pass for candidate files**: buffer findings per file, re-read file,
  apply tokenizer, then emit.
- **Streaming lexer in read loop**: maintain lexical state across chunks, but
  requires integration into file read pipeline.

Impact:
- Requires new per-worker scratch for lexer state (scheduler/pipeline/runtime).
- Requires output buffering per file (or delayed emission).

### Design C: Tree-sitter second pass

**Feasibility: Low**

Why:
- New dependency + global allocator shim are required to preserve allocation
  guarantees.
- Still needs file-level buffering or a second pass (same infra as Design B).

Constraints:
- Must be feature-gated (precision mode), not default.
- Must fail open on OOM, parse errors, or unsupported languages.

## Why Design A is the First Practical Step

- Minimal architectural disruption.
- Works with existing hot-path scanning mechanics.
- Can be introduced with clear rule-level opt-in.
- Low allocation risk (bounded lookaround + memchr-style scanning).

## Phase 0 Decisions (Design A)

- **Context mode**: Filter-only for Design A (no scoring). Rationale: avoid
  widening `FindingRec` and keep the hot path unchanged; revisit scoring after
  FP data supports the additional API surface.
- **Initial opt-in list**: `generic-api-key` (high-FP, broad anchors; now gated
  with same-line assignment + key-name context to reduce token-only matches).

## Gaps to Resolve Before Planning a Design B/C Implementation

1. **Output semantics**: Do we want a score/confidence field? If yes, change
   `FindingRec` and all output sinks.
2. **Emission timing**: Are we willing to buffer findings per file to enable
   a second pass? If not, Design B/C are blocked.
3. **Scope of change**: Do we need parity across scheduler, pipeline, runtime,
   and AIO paths, or can we explicitly scope to the parallel scheduler only?

## Recommended Next Step

1. Implement and measure Design A as a rule-selective, fail-open micro-context
   gate. If it yields meaningful FP reduction with minimal perf impact, it can
   be a standalone improvement and a baseline for future phases.

## Design A Test Coverage (Current)

- Boundary fail-open checks when line bounds are missing in the lookaround.
- Same-line assignment required vs missing assignment behavior.
- Key-name requirement on same line, including fail-open when bounds are absent.
- Local context gate applies in Base64 stream decode validation paths.
- Local context gate applies in UTF-16 window validation (quoted vs unquoted).

## Allocation Audit (Diagnostic)

- Ran `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`.
- No new allocations attributed to micro-context gating; `engine.scan_chunk` still
  reports the baseline regex-library allocations.
- Multi-core allocation stayed within the expected range (~269.7 MiB at 12
  workers); `HitAccPool.windows` remains the dominant cost.

## Performance Check (scanner_throughput)

Command: `cargo bench --bench scanner_throughput` (single run, no baseline).

Selected results (median throughput):
- `tier1_ceiling/random/64KB`: ~11.45 GiB/s (range 11.36–11.55 GiB/s)
- `tier1_ceiling/clean_ascii/64KB`: ~32.66 GiB/s (range 29.59–36.08 GiB/s)
- `workload_comparison/full_engine/mixed_realistic`: ~1.55 GiB/s (range 1.54–1.57 GiB/s)
- `workload_comparison/full_engine/clean_ascii`: ~509.6 MiB/s (range 506–513 MiB/s)
- `workload_comparison/full_engine/random_bytes`: ~150.6 MiB/s (range 149–152 MiB/s)
- `workload_comparison/full_engine/base64_secrets`: ~373.5 MiB/s (range 369–379 MiB/s)
- `workload_comparison/full_engine/base64_noise`: ~280.4 MiB/s (range 275–285 MiB/s)

Note: This run provides a baseline snapshot only. For regression tracking,
compare against a saved baseline or prior recorded values.

## Microbench Decision

No dedicated per-match micro-context microbench needed yet. Revisit if future
bench comparisons show >2% regressions or if we add more complex context checks.

## Design B Initial Decisions (Post-Design A)

1. **Context mode: Score + Filter**
   - Add lexical confidence/classification metadata and allow filtering only
     when the lexical context is definitive. Unknown context must fail open.
   - Rationale: leading scanners separate detection from validity/verification
     and allow users to include only verified/valid results or keep unverified
     ones for triage. References:
     - [TruffleHog verification states and result selection](https://github.com/trufflesecurity/trufflehog)
     - [detect-secrets verification filters](https://github.com/Yelp/detect-secrets)
     - [GitGuardian validity checks](https://docs.gitguardian.com/secrets-detection/customize-detection/validity-checks)

2. **Parity scope: all scan entry points**
   - Apply candidate-only lexical filtering in scheduler, pipeline, runtime,
     and async IO paths to keep behavior consistent.
   - Implementation choice: buffer findings per file, then re-open/re-read the
     file or object for the lexical pass. If the second pass fails (I/O error,
     non-seekable handle, size change), treat context as unknown and emit
     unfiltered findings.

3. **Language families: C-like + Python-like + Shell-like + Config**
   - Coverage targets the most common languages across multiple measures with
     a small number of lexer families. References:
     - [GitHub Octoverse 2025 top languages](https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/)
     - [GitHub Octoverse 2024 top languages](https://github.blog/news-insights/octoverse/octoverse-2024/)
     - [Stack Overflow 2025 Developer Survey (Technology)](https://survey.stackoverflow.co/2025/technology/)
   - C-like: C/C++/Java/C#/Go/JS/TS/Rust/Swift/Kotlin (TypeScript #1 on GitHub
     2025; GitHub 2024 top-10 includes TypeScript and C; Stack Overflow 2025
     lists TypeScript and C among the most-used languages)
   - Python-like: Python/Ruby
   - Shell-like: sh/bash/zsh/ps1
   - Config: HCL/JSON/YAML/TOML/INI/.env

4. **Transform-derived findings with coarse root hints**
   - If root-span mapping is coarse or missing, lexical context is treated as
     unknown and filtering must fail open.

5. **Initial lexical-context opt-in list (Design B)**
   - Rules: `generic-api-key`, `github-app-token`, `github-fine-grained-pat`,
     `github-oauth`, `github-pat`, `github-refresh-token`,
     `slack-legacy-workspace-token`, `npm-access-token`.
   - Rationale: token-like rules with high FP rates and common appearances in
     docs/comments. Lexical gating drops definitive comment-only matches and
     prefers string/config contexts while failing open on unknown context.

## Phase 4 Test Coverage (Complete)

- Added tokenizer unit tests for C-like, Python-like, Shell-like, and Config
  families covering comment/string classification, escape handling, multiline
  spans across chunks, and delimiter termination at newlines.

## Fail-Open Guarantees (Complete)

- Added tests that ensure lexical filtering never drops findings when:
  - Lexical run storage overflows (run-cap overflow).
  - File language family is unknown/unsupported.
  - Second-pass tokenization returns an I/O error (unexpected EOF).

## Cross-Path Parity (Complete)

- Added parity tests comparing:
  - Scheduler local output vs pipeline output under lexical filtering.
  - Async I/O output vs `ScannerRuntime` output under lexical filtering.

## Allocation Audit (Complete)

- Ran `cargo test --test diagnostic -- --ignored --nocapture --test-threads=1`;
  no threshold adjustments required.

## Design B Performance Check (scanner_throughput)

Command: `cargo bench --bench scanner_throughput` (single run, no baseline).

Selected results (median throughput):
- `tier1_ceiling/random/64KB`: ~12.004 GiB/s (range 11.999–12.008 GiB/s)
- `tier1_ceiling/clean_ascii/64KB`: ~44.366 GiB/s (range 43.806–44.865 GiB/s)
- `workload_comparison/full_engine/mixed_realistic`: ~1.821 GiB/s (range 1.814–1.827 GiB/s)
- `workload_comparison/full_engine/clean_ascii`: ~581.40 MiB/s (range 580.28–582.46 MiB/s)
- `workload_comparison/full_engine/random_bytes`: ~172.53 MiB/s (range 172.12–172.97 MiB/s)
- `workload_comparison/full_engine/base64_secrets`: ~449.71 MiB/s (range 448.15–450.91 MiB/s)
- `workload_comparison/full_engine/base64_noise`: ~327.84 MiB/s (range 326.99–328.67 MiB/s)

Note: This run provides a snapshot only. For regression tracking, compare
against a saved baseline or prior recorded values.

## Lexical Tokenizer Microbench (Design B)

Command: `cargo bench --bench lexical_tokenizer --features bench`.
Input: 4 MiB buffer, 64 KiB chunks, run-cap = 4096 (default).

Selected results (median throughput):
- C-like: ~1008 MiB/s (range 1005–1012 MiB/s)
- Python-like: ~1.121 GiB/s (range 1.116–1.125 GiB/s)
- Shell-like: ~1.362 GiB/s (range 1.359–1.365 GiB/s)
- Config: ~1.116 GiB/s (range 1.110–1.122 GiB/s)

## References

- Implementation guide: `docs/fp-filtering-design-a-implementation-guide.md`
- Implementation guide: `docs/fp-filtering-design-b-implementation-guide.md`

Next step: Design B implementation guide is complete. Consider running the
regression workflow and expanding lexical opt-in rules once FP data is
available.
