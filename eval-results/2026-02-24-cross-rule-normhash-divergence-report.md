# Cross-Rule Dedup Divergence Report (`norm_hash` vs Position-Only Keys)

Date: 2026-02-24
Task: scratch-0j4k
Corpus: `tools/eval-harness/testdata/synthetic/cross_rule_normhash_divergence`

## Context

This corpus models a same-span divergence case where scanner dedup can preserve
multiple findings because its key includes `norm_hash`, while eval-harness
cross-rule dedup collapses by position only (`path`, `byte_start`, `byte_end`).

## 1) 2x2 Matrix Metrics (Synthetic JSONL)

| Cell | Scanner dedup | Eval dedup | Findings | TP | FP | FN | Precision | Recall | F1 | AP |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | OFF | OFF | 6 | 3 | 3 | 0 | 0.5000 | 1.0000 | 0.6667 | 0.9167 |
| 2 | ON | OFF | 4 | 3 | 1 | 0 | 0.7500 | 1.0000 | 0.8571 | 1.0000 |
| 3 | OFF | ON | 3 | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| 4 | ON | ON | 3 | 3 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## 2) Delta vs Cell 1 Baseline

| Cell | Δ Findings | Δ TP | Δ FP | Δ FN | Δ Precision | Δ Recall | Δ F1 | Δ AP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | -2 (-33.3%) | 0 | -2 (-66.7%) | 0 | +0.2500 (+50.0%) | +0.0000 | +0.1905 (+28.6%) | +0.0833 (+9.1%) |
| 3 | -3 (-50.0%) | 0 | -3 (-100%) | 0 | +0.5000 (+100%) | +0.0000 | +0.3333 (+50.0%) | +0.0833 (+9.1%) |
| 4 | -3 (-50.0%) | 0 | -3 (-100%) | 0 | +0.5000 (+100%) | +0.0000 | +0.3333 (+50.0%) | +0.0833 (+9.1%) |

## 3) Distinctness and Divergence Signal

- Cells 3 and 4 are identical (eval dedup ON dominates final span-level set).
- Cell 2 differs from Cell 4 (4 findings vs 3; FP 1 vs 0), which is the key
  divergence signal: a same-span pair preserved by scanner-ON fixture is
  collapsed by eval cross-rule dedup.

## 4) Per-Rule Precision Deltas (Only Changed Rules)

| Rule | Cell 1 | Cell 2 | Cells 3/4 | Notes |
|---|---:|---:|---:|---|
| `generic-secret` | 0.0000 (FP=1) | 0.0000 (FP=1) | N/A | Removed when eval dedup ON |
| `github-pat` | 0.0000 (FP=2) | N/A | N/A | Removed by scanner dedup model (Cell 2) and eval dedup (Cells 3/4) |

## 5) Live-Scan Gate Outcome

Status: **not informative** (Cells 3/4 skipped)

| Cell | Scanner dedup | Eval dedup | Findings | TP | FP | FN | Precision | Recall |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | OFF | OFF | 2 | 2 | 0 | 1 | 1.0000 | 0.6667 |
| 2 | ON | OFF | 2 | 2 | 0 | 1 | 1.0000 | 0.6667 |

Gate rule: finding counts equal (`2 == 2`) so ON/OFF provides no measurable
scanner-layer signal for this corpus in live-scan mode.

## 6) Backend Consistency Note

- Blocking + uring local pipelines both call `apply_cross_rule_dedupe` in
  `src/scheduler/local_fs_owner.rs`.
- Remote scheduler continues to use `dedupe_pending_in_place` in
  `src/scheduler/remote.rs`.
- Linux CI remains required for full uring end-to-end validation.

## 7) Pipeline Config Mismatch Note

No baseline comparison was used in this run set; no pipeline mismatch warnings
were emitted.

## 8) Reproducible Commands

```bash
CORPUS=tools/eval-harness/testdata/synthetic/cross_rule_normhash_divergence
OUT=eval-results/normhash-divergence-jsonl
mkdir -p $OUT

cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json \
  --findings $CORPUS/findings_normhash_off.jsonl \
  --corpus-root $CORPUS/corpus \
  --format json --output $OUT/cell-1-scanner-off-eval-off.json

cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json \
  --findings $CORPUS/findings_normhash_scanner_deduped.jsonl \
  --corpus-root $CORPUS/corpus \
  --format json --output $OUT/cell-2-scanner-on-eval-off.json

cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json \
  --findings $CORPUS/findings_normhash_off.jsonl \
  --corpus-root $CORPUS/corpus \
  --cross-rule-dedup \
  --format json --output $OUT/cell-3-scanner-off-eval-on.json

cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json \
  --findings $CORPUS/findings_normhash_scanner_deduped.jsonl \
  --corpus-root $CORPUS/corpus \
  --cross-rule-dedup \
  --format json --output $OUT/cell-4-scanner-on-eval-on.json
```

Live-scan gate commands:

```bash
OUT=eval-results/normhash-divergence-live
mkdir -p $OUT

SCANNER_NO_CROSS_RULE_DEDUP=1 cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json --scan-corpus $CORPUS/corpus --corpus-root $CORPUS/corpus \
  --format json --output $OUT/cell-1-scanner-off-eval-off.json

SCANNER_NO_CROSS_RULE_DEDUP=0 cargo run --manifest-path tools/eval-harness/Cargo.toml -- synthetic \
  --manifest $CORPUS/truth.json --scan-corpus $CORPUS/corpus --corpus-root $CORPUS/corpus \
  --format json --output $OUT/cell-2-scanner-on-eval-off.json
```

## 9) Recommendation Scope

- This corpus successfully demonstrates a divergence mode between scanner-style
  dedup semantics (hash-aware) and eval cross-rule dedup (position-only).
- Do **not** set production defaults from this synthetic evidence alone.
- Next decision gate should combine this divergence fixture with representative
  real corpora and Linux uring validation before changing default layer policy.

## Artifacts

- `eval-results/normhash-divergence-jsonl/cell-1-scanner-off-eval-off.json`
- `eval-results/normhash-divergence-jsonl/cell-2-scanner-on-eval-off.json`
- `eval-results/normhash-divergence-jsonl/cell-3-scanner-off-eval-on.json`
- `eval-results/normhash-divergence-jsonl/cell-4-scanner-on-eval-on.json`
- `eval-results/normhash-divergence-live/cell-1-scanner-off-eval-off.json`
- `eval-results/normhash-divergence-live/cell-2-scanner-on-eval-off.json`
