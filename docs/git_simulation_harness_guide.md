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

## Fault Plan

Faults are keyed by logical resources and per-read index so injected failures
are deterministic and schedule-independent.

Resources:
- `CommitGraph`
- `Midx`
- `Pack { pack_id }`
- `Persist`
- `Other(String)` for non-core resources

Faults:
- `ErrKind { kind }` (simulated I/O error)
- `PartialRead { max_len }` (short read)
- `EIntrOnce` (interrupted read)

Corruption:
- `TruncateTo { new_len }`
- `FlipBit { offset, mask }`
- `Overwrite { offset, bytes }`

Each fault is consumed in read-index order (`0`, `1`, …). When a fault or
corruption is applied, the runner emits a `FaultInjected` trace event that
captures the resource id, read index, and fault kind.

## Persistence Safety

The simulation persistence store (`SimPersistStore`) logs operations in the
order they are issued and enforces the two-phase contract:

- Data ops are always written first.
- Watermark ops are written only for `FinalizeOutcome::Complete`.
- Faults injected on the persistence resource abort the phase and prevent
  watermark writes, preserving partial-run gating.

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
