# Cross-Rule Dedup Final Default Recommendation

Date: 2026-02-24  
Task: `scratch-1a0l.1`  
Epic: `scratch-1a0l`

## Decision

**Recommended default policy: enable cross-rule dedup in both layers.**

- Scanner layer default: **ON**
- Eval-harness default: **ON**

This recommendation is now backed by synthetic evidence plus representative non-synthetic 2x2 evidence.

## 1) Synthetic Evidence Summary (Prior Completed Tasks)

### Overlap corpus (`scratch-zruj`)
- OFF/OFF underperformed.
- Any dedup-enabled path (scanner or eval) converged to the same better outcome.

### `norm_hash` divergence corpus (`scratch-0j4k`)
- Scanner ON + Eval OFF preserved one same-span FP in that fixture.
- Eval ON removed that residual FP.

Takeaway: eval dedup can provide a useful normalization layer even when scanner dedup is on.

## 2) Representative Non-Synthetic 2x2 (CredData subset)

### Corpus and setup
- Truth labels: `../CredData/meta.subset` (12-repo subset)
- Corpus: `../CredData/data`
- Mode: live scan through eval-harness `creddata`

### Full matrix results

| Cell | Scanner dedup | Eval dedup | TP | FP | FN | Unlabeled | Precision | Recall | F1 | AP |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | OFF | OFF | 7 | 8 | 228 | 9 | 0.4667 | 0.0298 | 0.0560 | 0.0129 |
| 2 | ON  | OFF | 7 | 8 | 228 | 9 | 0.4667 | 0.0298 | 0.0560 | 0.0129 |
| 3 | OFF | ON  | 7 | 8 | 228 | 9 | 0.4667 | 0.0298 | 0.0560 | 0.0129 |
| 4 | ON  | ON  | 7 | 8 | 228 | 9 | 0.4667 | 0.0298 | 0.0560 | 0.0129 |

Result: **all four representative cells were identical** on this subset.

## 3) How Scanner OFF Cells Were Measured (Temporary Toggle)

A temporary measurement-only scanner OFF switch was introduced during this run and removed immediately after collecting results.

- Mechanism used for the measurement pass: `SCANNER_NO_CROSS_RULE_DEDUP=1`
- Scope: scanner scheduler cross-rule dedupe application path
- Cleanup: toggle code removed in the same session
- Final source state: scanner default behavior remains cross-rule dedup **ON** only

## 4) Representative Repo-Scale Prevalence / Perf (ON vs OFF)

Release scans on required repos (`linux`, `RustyPixels`, `gitleaks`, `trufflehog`, `kingfisher`, `tigerbeetle-fun`) produced:

- **Finding-count deltas (ON vs OFF): all zero**
- No scan-health errors in either mode

| Repo | Findings OFF | Findings ON | Δ Findings |
|---|---:|---:|---:|
| linux | 2465 | 2465 | 0 |
| RustyPixels | 0 | 0 | 0 |
| gitleaks | 622 | 622 | 0 |
| trufflehog | 456 | 456 | 0 |
| kingfisher | 3487 | 3487 | 0 |
| tigerbeetle-fun | 128 | 128 | 0 |

Throughput differed between passes, but these were single-run sequential measurements and are treated as noisy perf signals rather than dedup-effect proof.

## 5) Linux uring Parity Status

Status: **validated in Linux container**.

- Host: `Darwin arm64`
- Parity tests executed in Docker Linux (`rust:1.90`) with privileged mode:
  - `scheduler::local_fs_uring::tests::uring_open_stat_parity_with_blocking`
  - `scheduler::local_fs_uring::tests::uring_cross_rule_mode_uses_hash_aware_winner_pass`
- Both tests passed.
- Note: non-privileged container runs can fail under Docker seccomp defaults because `io_uring` syscalls may be restricted.

## 6) Recommendation and Migration Steps

1. Keep scanner cross-rule dedup **ON** by default.
2. Enable eval-harness cross-rule dedup as default (retain explicit opt-out for diagnostics).
3. Keep the temporary scanner OFF control out of production code (done).
4. Keep Linux uring parity checks in CI on a Linux runner (to avoid Docker seccomp false negatives).
5. Extend representative labeled validation from subset to fuller CredData coverage when practical.

## 7) Reproducible Commands (Executed)

```bash
# Representative CredData subset cells (scanner OFF via temporary toggle)
SCANNER_NO_CROSS_RULE_DEDUP=1 cargo run --manifest-path tools/eval-harness/Cargo.toml -- creddata \
  --meta-dir ../CredData/meta.subset \
  --corpus-root ../CredData \
  --scan-corpus ../CredData/data \
  --format json \
  --output eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-1-scanner-off-eval-off.json

SCANNER_NO_CROSS_RULE_DEDUP=1 cargo run --manifest-path tools/eval-harness/Cargo.toml -- creddata \
  --meta-dir ../CredData/meta.subset \
  --corpus-root ../CredData \
  --scan-corpus ../CredData/data \
  --cross-rule-dedup \
  --format json \
  --output eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-3-scanner-off-eval-on.json

# Scanner ON cells
cargo run --manifest-path tools/eval-harness/Cargo.toml -- creddata \
  --meta-dir ../CredData/meta.subset \
  --corpus-root ../CredData \
  --scan-corpus ../CredData/data \
  --format json \
  --output eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-2-scanner-on-eval-off.json

cargo run --manifest-path tools/eval-harness/Cargo.toml -- creddata \
  --meta-dir ../CredData/meta.subset \
  --corpus-root ../CredData \
  --scan-corpus ../CredData/data \
  --cross-rule-dedup \
  --format json \
  --output eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-4-scanner-on-eval-on.json

# Representative repo scans
RUSTFLAGS="-C target-cpu=native" cargo build --release --bin scanner-rs
./target/release/scanner-rs scan fs ../linux --null-sink
SCANNER_NO_CROSS_RULE_DEDUP=1 ./target/release/scanner-rs scan fs ../linux --null-sink

# Linux uring parity checks (Docker; privileged needed for io_uring syscalls)
docker run --rm --privileged -v "$PWD":/work -w /work rust:1.90 bash -lc '
  source /usr/local/cargo/env
  cargo test -p scanner-rs --lib uring_open_stat_parity_with_blocking -- --nocapture
  cargo test -p scanner-rs --lib uring_cross_rule_mode_uses_hash_aware_winner_pass -- --nocapture
'
```

## Artifacts

- `eval-results/2026-02-24-cross-rule-dedup-final-default-recommendation.md`
- `eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-1-scanner-off-eval-off.json`
- `eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-2-scanner-on-eval-off.json`
- `eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-3-scanner-off-eval-on.json`
- `eval-results/2026-02-24-cross-rule-final/creddata-subset/cell-4-scanner-on-eval-on.json`
- `eval-results/2026-02-24-cross-rule-final/repo-scan-default.tsv`
- `eval-results/2026-02-24-cross-rule-final/repo-scan-off.tsv`
- `eval-results/2026-02-24-cross-rule-final/repo-scan-on-off-delta.tsv`
- `eval-results/2026-02-24-cross-rule-final/linux-uring-parity/2026-02-24-linux-uring-parity-summary.md`
- `eval-results/2026-02-24-cross-rule-final/linux-uring-parity/uring-parity-tests-privileged.log`
