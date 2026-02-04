# Git Simulation Harness Guide

This guide describes the deterministic Git simulation harness used to exercise
Git scanning stages without relying on OS scheduling, wall-clock time, or a real
repository layout.

## Purpose

- Provide deterministic stage execution under `SimExecutor`.
- Capture bounded trace events for replay and debugging.
- Enforce stability across schedule seeds.
- Validate correctness and gating invariants with structured oracles.

## Runner Lifecycle

The Git simulation runner models the Git scan pipeline as a sequence of stage
tasks. Each stage runs to completion in a single deterministic step, and the
scheduler decides which task to run next via a seed-driven RNG.

Stages:
1. Repo open (build simulated start set, commit graph, tree source)
2. Commit walk (plan commits)
3. Tree diff (emit candidates)
4. Pack exec (optional, uses in-memory artifacts if present)
5. Finalize (determine complete vs partial outcome)

Stage boundaries emit trace events so failures can be replayed and minimized.
Each step also records the scheduler decision so trace hashes capture the
deterministic interleaving.

## Invariants

- Determinism: identical inputs and seeds yield identical trace + outputs.
- Stability: changing only the schedule seed yields identical normalized output.
- Watermark gating: any skipped candidate yields `Partial` and suppresses
  watermark advancement.
- Ordering: refs are processed in lexicographic order by raw refname bytes.
- Output sets: scanned and skipped OIDs are sorted, unique, and disjoint.

## Oracles

- Termination: runs complete within `max_steps` or return `FailureKind::Hang`.
- Determinism: identical `{scenario, seed}` yields identical trace hash.
- Stability: multiple schedule seeds compare normalized outputs and outcome.
- Gating: `FinalizeOutcome::Complete` requires zero skips; `Partial` requires
  non-zero skips.

## Failure Taxonomy

- `Panic`: unexpected panic in runner logic.
- `Hang`: no runnable tasks or exceeded `max_steps`.
- `InvariantViolation`: ordering or structural invariants failed.
- `OracleMismatch`: correctness oracle failed (gating, overlap, mismatch).
- `StabilityMismatch`: output differed across schedule seeds.

## Running Tests

The Git simulation tests are wired behind the `sim-harness` feature alongside
scanner simulation tests. As the harness expands, the following commands will
become the primary entry points:

```bash
# Random Git simulation runs (bounded)
cargo test --features sim-harness --test simulation git_scan_random

# Replay minimized Git simulation corpus
cargo test --features sim-harness --test simulation git_scan_corpus
```

## Related Docs

- `docs/architecture-overview.md`
- `docs/git_simulation_tester_design.md`
- `docs/scanner_test_harness_guide.md`
