**NEVER auto-commit, auto-add, or auto-push code to git. Only perform git operations when explicitly asked by the user.**

# Repository Guidance

When working in plan mode, always include bd status updates
in the plan (update to in_progress at start, close at end).

## Task Management

This project uses `bd` (Beads) for issue tracking. Issues live in `.beads/`.

At session start: run `bd ready` to find work.
Track status with `bd update <id> --status in_progress`.
At session end: close finished work, file new issues, run `bd sync`, then `git push`.

For graph-aware triage: `bv --robot-triage` (never bare `bv`).

## Project Overview

Rust-based secret scanning engine with pattern matching, transforms (URL/Base64), and streaming decode.

## Key Directories

- `src/engine/` - Core scanning engine (scratch.rs, stream_decode.rs, work_items.rs)
- `src/stdx/` - Utility data structures (timing_wheel, bitset, ring_buffer, byte_ring)
- `docs/` - Architecture documentation with Mermaid diagrams

<!-- task-quality-standard-v1 -->

## Task Quality Standard — MANDATORY for All Task Creation

Every beads task must be **self-contained**: an LLM agent reading it should
have 90% of the information needed to complete it. The remaining 10% must
have explicit pointers to where to look.

### How to Create Tasks

Use `/create-task` for all task creation. It auto-researches the codebase
and produces a complete task description.

    /create-task "Fix off-by-one in window boundary check" --type=bug --priority=1
    /create-task --quick "..." --type=task --priority=2
    /create-task --from-plan docs/plans/2026-02-23-feature-v3.md --step=3

### Mandatory Sections (ALL Tasks)

1. **Context** — Why this task exists
2. **Current State** — What exists today (with code snippets and file:line refs)
3. **Desired State** — What should exist after
4. **Implementation Guidance** — Files to modify, patterns to follow, utilities to reuse
5. **Code References** — Inline snippets of relevant current code
6. **Related Work** — Links to related beads tasks (or "None found")
7. **Acceptance Criteria** — Specific, verifiable conditions (always include cargo test/fmt/clippy)
8. **Pointers** — Where to look for the remaining 10%

### Never Do

- Create a task with no description
- Write "see review for details" or "see PR #N" instead of inlining context
- Reference code without file paths and line numbers
- Write acceptance criteria like "it works" — must be specific and verifiable
- Skip the Related Work search — always check for existing related/duplicate tasks

### Enforcement

Tasks created with empty or stub descriptions will be flagged during review.
When creating tasks outside `/create-task` (e.g., inside `/execute-review-findings`),
include all mandatory sections in the description.

<!-- end-task-quality-standard -->

<!-- duplication-prevention-v1 -->

## Duplication Prevention — MANDATORY Pre-Coding Check

**Before writing ANY new function, struct, trait, method, or module, you MUST
verify the functionality does not already exist in the codebase.**

This is non-negotiable. Duplicated logic is a bug — it creates drift, increases
maintenance burden, and undermines the single-source-of-truth principle.

### Required Steps

1. **Search before you write.** Use Grep/Glob to search for existing
   implementations that match the intent of what you are about to create.
   Search by concept (e.g., "retry", "timeout", "base64 decode"), not just
   by the exact name you plan to use.
2. **Check neighboring modules.** Read the module and its siblings. If you are
   adding a helper to `engine/core.rs`, read the other files in `engine/` and
   `stdx/` first.
3. **Check utility crates.** `src/stdx/` contains shared data structures and
   helpers. Confirm your functionality is not already there before creating
   a new one.
4. **If similar logic exists, extend or reuse it.** Do not create a parallel
   implementation. Refactor the existing code to be more general if needed.
5. **If you are unsure, ask.** It is always better to ask "does X already
   exist?" than to introduce a duplicate.

### What Counts as Duplication

- A second function that does the same thing with a different name.
- A method that reimplements logic already available in a trait or utility.
- A new struct that is structurally identical to an existing one.
- Copy-pasted blocks with minor variations (extract a shared helper instead).
- A new constant/sentinel that duplicates an existing one.

### Enforcement

If during review a duplicate is found that could have been caught by searching
the codebase first, the change will be rejected. No exceptions.

<!-- end-duplication-prevention -->

<!-- comment-policy-v1 -->

## Comment Policy — Code Comments Are About Code

Comments in source files must describe the code they annotate — its behavior,
invariants, edge cases, or non-obvious reasoning. They must not reference
external tracking systems.

### Rules

1. **No issue/tracking IDs in comments.** Do not embed beads IDs, finding
   numbers (F4, C3, H9), priority tags (P0–P4), or any other external tracker
   references in code comments. These belong in the tracker, not the source.
2. **Descriptive text stays.** Section headers like `// -- Exact boundary tests --`
   are fine. The tracking ID portion is what gets removed.
3. **Code-internal naming schemes are fine.** Stable identifiers that exist
   purely to cross-reference within the codebase (e.g., invariant labels S1–S7
   in the simulation checker) are documentation, not tracking noise.
4. **Comments explain *why*, not *what*.** Prefer comments that explain
   non-obvious reasoning, invariants, or edge cases over comments that restate
   what the code already says.

### Enforcement

Any PR that introduces external tracking IDs in code comments will be
rejected. If a comment only makes sense when paired with an external tracker,
rewrite it to stand on its own.

<!-- end-comment-policy -->

## Rust Code Modification Workflow

After modifying Rust code, ALWAYS run these steps:

1. `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
2. Run `/doc-rigor` skill on the new code to keep documentation updated
3. If adding new components, update relevant docs: `architecture-overview.md`, `detection-engine.md`, `memory-management.md`, `transform-chain.md`

## Documentation Consistency

When changes touch any of these source files, verify the corresponding docs
are updated in the same PR:

| Source file | Doc files to check |
|---|---|
| `src/api.rs` (RuleSpec fields) | `docs/detection-rules.md` (Rule Anatomy diagram, YAML template), `docs/data-types.md` (RuleSpec class) |
| `src/engine/rule_repr.rs` (RuleCompiled gate fields) | `docs/data-types.md` (RuleCompiled class), `docs/engine-window-validation.md` (gate pool table) |
| `src/engine/window_validate.rs` (gate sequence in module doc) | `docs/engine-window-validation.md` (Gate sequence, gate ordering) |
| `src/engine/core.rs` (Engine gate pool vectors) | `docs/data-types.md` (Engine class), `docs/detection-engine.md` (flow diagram) |
| `default_rules.yaml` (rule additions/removals) | `docs/detection-rules.md` (Current Snapshot counts) |

The `cargo test --test integration doc_consistency` suite enforces structural
invariants automatically. Semantic accuracy of explanations must be reviewed
manually or by code review.

## File Sync

- Keep `CLAUDE.md` and `AGENTS.md` identical for cross-tool compatibility

## Documentation Patterns

- Mermaid flowcharts/sequence diagrams in markdown
- ASCII art diagrams in code comments (see timing_wheel.rs for examples)
- Cross-reference between doc files with relative links
- Component tables with `| Component | Location | Purpose |` format

## Code Patterns

- `G` const generic for granularity parameters (e.g., `TimingWheel<T, G>`)
- `NONE_U32 = u32::MAX` as sentinel for invalid indices
- `#[inline(always)]` on hot-path functions
- `debug_assert!` for invariant checks only in debug builds
- `#[cfg(debug_assertions)]` for debug-only code paths

## Testing

- Unit tests in same file under `#[cfg(test)] mod tests`
- Property tests in sibling `*_tests.rs` files with feature gate `#[cfg(all(test, feature = "stdx-proptest"))]`

## Build & Test

- `cargo build` - Build the project
- `cargo test` - Fast unit tests only (~15-30s)
- `cargo test --test integration` - Integration tests
- `cargo test --test smoke` - End-to-end smoke tests
- `cargo test --test property` - Property-based tests (proptest)
- `cargo test --features scheduler-sim --test simulation` - Scheduler simulation tests
- `cargo test --test diagnostic -- --ignored --nocapture` - Diagnostic/audit tools
- `cargo test --features stdx-proptest` - Unit + stdx property tests (~3-5 min)
- `cargo kani --features kani` - Kani model checking
- `cargo +nightly miri test --lib` - Miri undefined behavior detection (skips FFI-dependent modules)
- `cargo +nightly fuzz run <target>` - Fuzz testing (targets in `/fuzz/`)
- Benchmarks in `benches/` directory, run with `cargo bench`
- See `tests/README.md` for full test organization details

## Rule Optimization Workflow

After modifying rules in `default_rules.yaml` (loaded by `src/rules/`):

1. Run `cargo test` to verify no regressions
2. Build release: `RUSTFLAGS="-C target-cpu=native" cargo build --release`
3. Benchmark against test repos: `./target/release/scanner-rs ../linux ../RustyPixels ../gitleaks ../tigerbeetle ../trufflehog ../kingfisher`
4. Compare throughput/findings against baseline

## Rule Patterns

- Add comments for rules with non-obvious anchor/keyword choices (see vault, sourcegraph rules)
- Avoid generic patterns like `[a-fA-F0-9]{40}` that match git SHAs
- Prefer structured prefixes (e.g., `sgp_`, `hvs.`) over keyword anchors like service names

## Performance Regression Workflow

Before merging any feature that touches hot paths (`src/engine/`, regex changes, validation logic):

### 1. Stash Changes and Build Baseline

```bash
git stash push -m "feature-name"
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 2. Run Baseline Scans (3x each)

```bash
for i in 1 2 3; do
  ./target/release/scanner-rs ../gitleaks 2>&1 | tail -1
  ./target/release/scanner-rs ../linux 2>&1 | tail -1
  ./target/release/scanner-rs ../tigerbeetle 2>&1 | tail -1
done
```

### 3. Run Baseline Benchmarks

```bash
cargo bench --bench scanner_throughput -- --save-baseline before
cargo bench --bench vectorscan_overhead -- --save-baseline before
```

### 4. Restore Changes and Rebuild

```bash
git stash pop
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 5. Run Comparison Scans and Benchmarks

```bash
# Same scan loop as step 2
cargo bench --bench scanner_throughput -- --baseline before
cargo bench --bench vectorscan_overhead -- --baseline before
```

### 6. Analyze Results

Calculate average throughput delta per repository:

```
% change = (after_throughput - baseline_throughput) / baseline_throughput * 100
```

### Acceptance Criteria

| Regression Level | Action                                      |
| ---------------- | ------------------------------------------- |
| None (<2%)       | Ship as-is                                  |
| Minor (2-5%)     | Document reason, acceptable for correctness |
| Moderate (5-10%) | Requires compelling justification           |
| Major (>10%)     | Must investigate and optimize               |

### PR Documentation

- Average throughput delta per test repository
- Criterion benchmark comparison summary
- Justification for any regression >2%

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git branch --show-current  # MUST be a user-created feature branch (never main)
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**

- Work is NOT complete until `git push` succeeds
- NEVER push to `main`
- ALWAYS work from a user-created feature branch in a user-created git worktree
- If current branch is `main` (or not a user-created feature branch), stop and ask the user before continuing
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
  Use 'bd' for task tracking

<!-- bv-agent-instructions-v1 -->

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects (.beads/beads.jsonl). Instead of parsing JSONL or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles _what to work on_ (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use [MCP Agent Mail](https://github.com/Dicklesworthstone/mcp_agent_mail).

**⚠️ CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:

- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

bv --robot-triage # THE MEGA-COMMAND: start here
bv --robot-next # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:

bv --robot-triage --format toon
export BV_OUTPUT_FORMAT=toon
bv --robot-next

#### Other Commands

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS (hubs/authorities), eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level` (healthy\|warning\|critical), `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels by: (pagerank × staleness × block_impact) / velocity |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations: `stats`, `histories` (per-bead events/commits/milestones), `commit_index` |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles introduced/resolved |

**Other Commands:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Self-contained interactive HTML visualization |

#### Scoping & Filtering

bv --robot-plan --label backend # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30 # Historical point-in-time
bv --recipe actionable --robot-plan # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage # Pre-filter: top PageRank scores
bv --robot-triage --robot-triage-by-track # Group by parallel work streams
bv --robot-triage --robot-triage-by-label # Group by domain

#### Understanding Robot Output

**All robot JSON includes:**

- `data_hash` — Fingerprint of source beads.jsonl (verify consistency across calls)
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`; contains ref and resolved SHA

**Two-step analysis:**

- **Immediate pass (instant):** degree, topo sort, density — always available immediately
- **Deferred pass (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles — check `status` flags

**For large graphs (>500 nodes):** Some metrics may be approximated or skipped. Always check `status`.

#### jq Quick Reference

bv --robot-triage | jq '.quick_ref' # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]' # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact' # Best unblock target
bv --robot-insights | jq '.status' # Check metric readiness
bv --robot-insights | jq '.Cycles' # Circular deps (must fix!)
bv --robot-label-health | jq '.results.labels[] | select(.health_level == "critical")'

**Performance:** Immediate pass is instant; deferred pass is async (500ms timeout). Prefer `--robot-plan` over `--robot-insights` when speed matters. Results cached by data hash.

Use bv instead of parsing beads.jsonl—it computes PageRank, critical paths, cycles, and parallel tracks deterministically.

---

## Beads Workflow Integration

This project uses [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
bd ready              # Show issues ready to work (no blockers)
bd list --status=open # All open issues
bd show <id>          # Full issue details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id> --reason="Completed"
bd close <id1> <id2>  # Close multiple issues at once
bd sync               # Commit and push changes
```

### Workflow Pattern

1. **Start**: Run `bd ready` to find actionable work
2. **Claim**: Use `bd update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `bd close <id>`
5. **Sync**: Always run `bd sync` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `bd ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `bd dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
bd sync                 # Commit beads changes
```

### Best Practices

- Check `bd ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `bd create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `bd sync` before ending session

<!-- end-bv-agent-instructions -->
