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
MIGRATION_ARTIFACT_ROOT=artifacts/baseline \
python3 tools/migration-parity/capture_baseline.py
```

## Environment Variables

- `MIGRATION_REPOS`: comma-separated repo paths (used when `--repo` is omitted)
- `MIGRATION_SCANNER_BIN`: scanner binary path
- `MIGRATION_ARTIFACT_ROOT`: artifact output root
- `MIGRATION_DECODE_DEPTH`: decode depth passed to scans (default `2`)
- `MIGRATION_TRANSFORMS`: transforms value passed to scans (default `all`)

## Output Layout

The script writes:

- `artifacts/baseline/findings/<repo>/<mode>.jsonl`
- `artifacts/baseline/perf/<timestamp>.csv`
- `artifacts/baseline/summary.md`

`summary.md` includes:

- scanner commit SHA
- scanner binary metadata
- exact invocation and scan command templates
- throughput and findings summaries

## Notes

- Findings JSONL files are canonicalized and sorted for stable diffs.
- Non-zero scanner exit codes are recorded in CSV/summary; script exits non-zero if any run fails.
