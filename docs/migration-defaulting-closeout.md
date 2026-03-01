# Execution Mode Defaulting & Migration Closeout

## Purpose

This document defines the Phase 6 policy for deciding when execution mode can
change from `direct` to `connector`, and records the closeout checklist for epic
`scratch-0g6a`.

## Current Default Status (March 1, 2026)

- CLI default execution mode is still `direct` for both `scan fs` and `scan git`.
- `connector` remains opt-in through `--execution-mode=connector`.
- No default-mode flip is allowed until sustained-green policy passes.

## Sustained-Green Policy

The policy requires **all** of the following:

| Gate | Requirement |
|---|---|
| Consecutive CI health | At least 7 consecutive completed `ci.yml` runs on `main` are green |
| Time coverage | Those consecutive green runs span at least 3.0 days |
| Required jobs | `Execution Mode Parity`, `Clippy`, `Test`, and `Test (aarch64)` are all `success` in each run |
| Parity thresholds | Execution mode parity test enforces median delta <= 2% and per-case delta <= 5% |

The threshold logic itself is enforced by
`tests/integration/execution_mode_parity.rs`.

## Automated Gate Evaluation

Run the sustained-green evaluator:

```bash
# Report-only mode (writes artifacts, does not fail on policy miss)
python3 tools/migration-parity/sustained_green_gate.py \
  --repo <owner>/<repo> \
  --workflow ci.yml \
  --branch main \
  --output-json tools/migration-parity/results/sustained_green_report.json \
  --output-markdown tools/migration-parity/results/sustained_green_report.md

# Enforcing mode for release/default-switch decisions
python3 tools/migration-parity/sustained_green_gate.py \
  --repo <owner>/<repo> \
  --workflow ci.yml \
  --branch main \
  --require-pass
```

## Standalone CLI Compatibility Contract

The standalone scanner CLI must remain first-class throughout migration.

Supported compatibility command:

```bash
/usr/bin/time target/release/scanner-rs scan fs --path="../linux" --null-sink
```

Compatibility tests:

- `tests/integration/execution_mode_parity.rs`: `execution_mode_parity_standalone_fs_command_without_execution_mode_flag_still_succeeds`
- `tests/smoke/scanner.rs`: `scanner_binary_finds_secrets`

## Benchmark Surface Contract

The migration keeps benchmark tooling available and documented:

- `tools/bench-compare/run_benchmarks.sh` (full + smoke benchmark modes)
- `tools/bench-compare/run_perf_benchmarks.sh` (perf counters)

Recommended verification:

```bash
# Full quality + parity checks
cargo fmt --all
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --features integration-tests --test integration execution_mode_parity_ -- --nocapture

# Benchmark surface sanity
tools/bench-compare/run_benchmarks.sh --smoke --no-cold
```

## Phase 6 Closeout Checklist

1. Sustained-green report shows policy pass in enforcing mode.
2. Standalone CLI compatibility tests pass.
3. Parity thresholds remain green in CI and local reproduction.
4. Benchmark scripts execute successfully on the benchmark host.
5. Child migration tasks are closed.
6. Epic `scratch-0g6a` is closed with final summary and artifact pointers.

## Artifact Locations

- Baseline capture artifacts: `../baseline-artifacts/`
- Sustained-green reports: `tools/migration-parity/results/`
- Parity gate implementation: `tests/integration/execution_mode_parity.rs`
- Sustained-green evaluator: `tools/migration-parity/sustained_green_gate.py`
