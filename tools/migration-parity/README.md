# Migration Parity Baseline Capture

`capture_baseline.py` generates a direct-mode baseline artifact pack for migration work:

- scanner-rs `scan fs` and `scan git` runs
- fixed repo matrix defaults (with env/CLI overrides)
- deterministic findings snapshots plus perf and summary artifacts

## Default Repo Matrix

Defaults match the migration plan and resolve relative to this repository root:

- `../linux`
- `../gossip-rs`
- `../tigerbeetle`
- `../trufflehog`
- `../gitleaks`
- `../scratch-scanner-rs`

## Usage

```bash
# Full baseline capture with defaults
python3 tools/migration-parity/capture_baseline.py

# Override repo matrix with CLI flags (repeat --repo)
python3 tools/migration-parity/capture_baseline.py \
  --repo ../scratch-scanner-rs \
  --repo ../gitleaks

# Override via environment variables
MIGRATION_REPOS="../linux,../scratch-scanner-rs" \
MIGRATION_SCANNER_BIN=./target/release/scanner-rs \
MIGRATION_ARTIFACT_ROOT=../baseline-artifacts \
python3 tools/migration-parity/capture_baseline.py
```

## Environment Variables

- `MIGRATION_REPOS`: comma-separated repo paths (used when `--repo` is omitted)
- `MIGRATION_SCANNER_BIN`: scanner binary path
- `MIGRATION_ARTIFACT_ROOT`: artifact output root
- `MIGRATION_DECODE_DEPTH`: decode depth passed to scans (default `2`)
- `MIGRATION_TRANSFORMS`: transforms value passed to scans (default `all`)
- `MIGRATION_TIMEOUT`: per-scan timeout in seconds (default `3600`)

## Output Layout

The script writes:

- `../baseline-artifacts/findings/<repo>/<mode>.jsonl`
- `../baseline-artifacts/perf/<timestamp>.csv`
- `../baseline-artifacts/summary.md`

`summary.md` includes:

- scanner commit SHA
- scanner binary metadata
- exact invocation and scan command templates
- throughput and findings summaries

## Notes

- Findings JSONL files are canonicalized and sorted for stable diffs.
- Non-zero scanner exit codes are recorded in CSV/summary; script exits non-zero if any run fails.

## Sustained-Green Policy Gate

`sustained_green_gate.py` evaluates recent CI runs to determine whether the
execution-mode migration is eligible for default-mode cutover.

Policy defaults:

- minimum consecutive green runs: `7`
- minimum time span covered by those runs: `3` days

Required jobs per run:

- `Execution Mode Parity`
- `Clippy`
- `Test`
- `Test (aarch64)`

### Usage

```bash
# Report-only mode (always exits 0 unless API/config errors occur)
python3 tools/migration-parity/sustained_green_gate.py \
  --repo owner/repo \
  --workflow ci.yml \
  --branch main \
  --output-json tools/migration-parity/results/sustained_green_report.json \
  --output-markdown tools/migration-parity/results/sustained_green_report.md

# Enforcing mode (exit 1 when policy is not yet satisfied)
python3 tools/migration-parity/sustained_green_gate.py \
  --repo owner/repo \
  --workflow ci.yml \
  --branch main \
  --require-pass
```

### Offline / Fixture Mode

```bash
python3 tools/migration-parity/sustained_green_gate.py \
  --input-runs-json /tmp/workflow_runs.json \
  --input-jobs-dir /tmp/jobs_payloads
```

Each jobs payload file is named `<run_id>.json` and can be either:

- `{ "jobs": [...] }`
- or a raw JSON array `[...]`
