# Cross-Rule Dedup 2x2 Evaluation Report

Date: 2026-02-24
Task: scratch-zruj
Scope: Synthetic overlap corpus (`tools/eval-harness/testdata/synthetic/cross_rule_overlap`)

## 1) Per-Cell Metrics (Synthetic JSONL Matrix)

| Cell | Scanner dedup | Eval dedup | Findings | TP | FP | FN | Precision | Recall | F1 | AP |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | OFF | OFF | 9 | 6 | 3 | 0 | 0.6667 | 1.0000 | 0.8000 | 0.9524 |
| 2 | ON | OFF | 6 | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| 3 | OFF | ON | 6 | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| 4 | ON | ON | 6 | 6 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

## 2) Delta vs Cell 1 Baseline

| Cell | Δ Findings | Δ TP | Δ FP | Δ FN | Δ Precision | Δ Recall | Δ F1 | Δ AP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | -3 (-33.3%) | 0 | -3 (-100%) | 0 | +0.3333 (+50.0%) | +0.0000 | +0.2000 (+25.0%) | +0.0476 (+5.0%) |
| 3 | -3 (-33.3%) | 0 | -3 (-100%) | 0 | +0.3333 (+50.0%) | +0.0000 | +0.2000 (+25.0%) | +0.0476 (+5.0%) |
| 4 | -3 (-33.3%) | 0 | -3 (-100%) | 0 | +0.3333 (+50.0%) | +0.0000 | +0.2000 (+25.0%) | +0.0476 (+5.0%) |

## 3) Cell Distinctness / Idempotency

- Cells 2, 3, and 4 are metrically identical.
- Interpretation: on this corpus, scanner-layer dedup and eval-layer dedup are idempotent and interchangeable for metric outcomes.

## 4) Per-Rule Precision Deltas (Only Where Different)

Baseline (Cell 1) includes extra false positives from overlapping rules:

| Rule | Cell 1 Precision | Cells 2/3/4 Precision | Delta |
|---|---:|---:|---:|
| `generic-secret` | 0.0000 | N/A (rule removed by dedup winner selection) | Removed FP-only rule |
| `github-pat` | 0.0000 | N/A (rule removed by dedup winner selection) | Removed FP-only rule |

All surviving rules in Cells 2/3/4 have precision 1.0.

## 5) Live-Scan Outcome (Conditional Gate)

Status: **not informative**

Gate runs executed:

| Cell | Scanner dedup | Eval dedup | Findings | TP | FP | FN |
|---|---|---|---:|---:|---:|---:|
| 1 | OFF | OFF | 0 | 0 | 0 | 6 |
| 2 | ON | OFF | 0 | 0 | 0 | 6 |

Because Cell 1 and Cell 2 finding counts are identical (both 0), live-scan provides no measurable ON/OFF signal for this corpus. Per plan gate, Cells 3/4 were skipped.

## 6) Backend Consistency Note

- Local blocking and local uring paths share `apply_cross_rule_dedupe` in `src/scheduler/local_fs_owner.rs`.
- Remote path uses separate pending-buffer dedupe logic (`src/scheduler/remote.rs`, `dedupe_pending_in_place`).
- End-to-end uring validation remains a Linux CI follow-up.

## 7) Conditional-Span Validation

Confirmed by prerequisite tests:

- `scheduler::local_fs_owner::tests::cross_rule_dedupe_preserves_distinct_spans_when_dedupe_with_span_is_true`
- `scheduler::local_fs_owner::tests::cross_rule_dedupe_mixed_span_modes_form_separate_groups`
- `finding_parser::tests::cross_rule_dedup_preserves_overlapping_non_identical_spans`

These validate that span-sensitive findings are not over-collapsed.

## 8) Key Divergence Note

Scanner dedup key includes `norm_hash`; eval dedup key does not. They are equivalent on this synthetic corpus, but can diverge in multi-chunk scenarios where different secrets share position-like projections.

## 9) Pipeline Config Mismatch Note

No pipeline-config mismatch warning surfaced in this run set. Reports were generated per-cell with explicit `cross_rule_dedup` mode in each output's `pipeline_config` field.

## 10) Recommendation (Synthetic Scope Only)

- Synthetic evidence shows dedup idempotency and layer equivalence for this corpus: enabling scanner dedup, eval dedup, or both yields the same final metrics (Cells 2/3/4).
- Do **not** infer production defaults from this synthetic dataset alone.
- Required escalation for production-default decisions: measure on representative corpora containing multi-chunk files and scenarios that exercise `norm_hash` divergence behavior.
- Live-scan results here are not informative and are excluded from layer-default recommendations.

## Artifacts

- `eval-results/synthetic-jsonl/cell-1-scanner-off-eval-off.json`
- `eval-results/synthetic-jsonl/cell-2-scanner-on-eval-off.json`
- `eval-results/synthetic-jsonl/cell-3-scanner-off-eval-on.json`
- `eval-results/synthetic-jsonl/cell-4-scanner-on-eval-on.json`
- `eval-results/synthetic-live/cell-1-scanner-off-eval-off.json`
- `eval-results/synthetic-live/cell-2-scanner-on-eval-off.json`
