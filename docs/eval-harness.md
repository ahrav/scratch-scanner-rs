# Eval Harness

Accuracy measurement tool for scanner-rs. Compares scanner findings against labeled ground-truth corpora to compute precision, recall, Average Precision (AP), and related metrics. Designed for regression gating in CI and iterative rule development.

## Motivation

Secret scanners need quantitative accuracy tracking. Without measurement, rule changes might improve detection of one secret type while silently breaking another. The eval harness answers concrete questions:

- **What is the scanner's precision and recall against known corpora?** The position-based pipeline computes these from byte-level overlap between scanner findings and ground-truth annotations.
- **Did this rule change make things worse?** Baseline comparison with CI-gated regression verdicts catches regressions before they ship.
- **Which rules produce the most false positives?** The error book surfaces the top FP/FN by rule for targeted debugging.
- **How confident are we in the AP estimate?** Bootstrap confidence intervals quantify sampling uncertainty.

Use the harness after modifying detection rules, before releases, in CI pipelines, when adding new secret types, or when tuning confidence thresholds.

## Architecture

### Module Map

The harness lives in `tools/eval-harness/` as a standalone crate (14 source files, ~10,700 lines) with its own `Cargo.toml`. It depends on `scanner-rs` for the engine and path normalization utilities.

| Module | Role |
|--------|------|
| `main.rs` | CLI entry point, subcommand dispatch, pipeline orchestration |
| `types.rs` | Core domain types: `NormalizedFinding`, `TruthItem`, `TruthLabel`, `ClassifiedFinding`, `FindingClass` |
| `creddata.rs` | CredData CSV truth loader |
| `synthetic.rs` | Synthetic JSON manifest truth loader |
| `leaky_repo.rs` | LeakyRepo CSV expectations and count-based comparison |
| `finding_parser.rs` | Scanner JSONL output parser, deduplication |
| `line_index.rs` | Byte-offset to line-number conversion (O(log n) binary search) |
| `fs_walk.rs` | Recursive file collection (internal utility) |
| `matching.rs` | Position-based finding-to-truth matching (greedy, confidence-sorted) |
| `metrics.rs` | Precision, recall, F1, F2, AP, P@R, R@P, bootstrap CI, per-rule breakdown |
| `provenance.rs` | BLAKE3 corpus/binary/ruleset hashing for reproducibility |
| `regression.rs` | Baseline comparison with CI overlap gating and two-tier verdicts |
| `report.rs` | Report assembly, JSON/table rendering, error book generation |
| `lib.rs` | Module re-exports |

### Data Flow

Both pipelines follow a **load-match-measure-report** pattern:

```text
Position-based (creddata / synthetic):
  truth loader ──► TruthItem[]
                               ├─► match_findings ──► ClassifiedFinding[]
  finding source ──► NormalizedFinding[]              ├─► compute_metrics ──► EvalMetrics
  corpus files ──► HashMap<path, bytes>               ├─► hash_corpus_snapshot ──► Provenance
                                                      ├─► bootstrap_ap_ci ──► CI
                                                      ├─► check_regression ──► Verdict
                                                      └─► build_error_book [JSON only] ──► ErrorBook
                                                                  └─► EvalReport ──► JSON / table

Count-based (leaky-repo):
  expectations CSV ──► FileExpectation[]
                                   ├─► compare_counts ──► per-file TP/FP/FN
  findings JSONL ──► NormalizedFinding[]                  └─► aggregate ──► EvalMetrics
                                                               └─► EvalReport ──► JSON / table
```

### Key Types

**`NormalizedFinding`** — A scanner finding normalized for comparison. Identity is `(path, byte_start, byte_end, rule)`; confidence is excluded from equality so duplicates at the same location collapse correctly. Byte offsets use half-open `[byte_start, byte_end)` convention.

**`TruthItem`** — A ground-truth annotation using 1-indexed inclusive line numbers (`line_start`, `line_end`). Each item carries a `TruthLabel` (Positive, Negative, or Placeholder) and a rule name.

**`ClassifiedFinding`** — A finding paired with its `FindingClass` (TruePositive, FalsePositive, or Unlabeled). FalseNegative is intentionally not a `FindingClass` variant because false negatives are truth-derived, not finding-derived.

**`EvalMetrics`** — Aggregate metrics: AP, precision, recall, F1, F2, baseline AP, P@R targets, R@P targets, bootstrap CI, per-rule breakdown (`BTreeMap<String, RuleMetrics>`).

**`EvalReport`** — Top-level serializable artifact combining `EvalMetrics`, `Provenance`, optional `RegressionResult`, and optional `ErrorBook`.

### Matching Algorithm

The matching layer uses **confidence-sorted greedy matching**, the same strategy as COCO and PASCAL VOC evaluation protocols:

1. Sort findings by confidence descending (deterministic tiebreak via `NormalizedFinding::Ord`).
2. Group truth items by file path; sort each group by `line_start`.
3. For each finding (highest confidence first):
   - Convert byte range to line range via `LineIndex`.
   - Binary search for overlapping truth items in the same file.
   - Apply label priority: Positive > Negative > Placeholder.
   - Consume matched Positive truths (one-to-one TP counting).
   - Negative truths are **not** consumed (multiple findings at a negative region all classify as FP).
   - Placeholder truths are **not** consumed (multiple findings at an ignore region all classify as Unlabeled).

Greedy matching is required for valid PRC-AUC: it produces nested TP sets across confidence thresholds, ensuring recall is monotonically non-decreasing.

### Metrics Computed

| Metric | Description |
|--------|-------------|
| Average Precision (AP) | Step-function AP with tie collapsing (matches sklearn's `average_precision_score`) |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | Harmonic mean of precision and recall |
| F2 | Recall-weighted F-score (β=2); weights recall 4x more than precision |
| Baseline AP | Class prevalence among scored items (`tp / (tp + fp)`); the expected AP of a random ranker |
| P@R | Precision at fixed recall targets (default: 0.80, 0.90, 0.95) |
| R@P | Recall at fixed precision targets (default: 0.95) |
| Bootstrap CI | Percentile-based confidence interval for AP via stratified resampling (default: 1000 iterations, α=0.05, seed=42) |
| Per-rule breakdown | TP, FP, and precision per detection rule |

## CLI Usage

### Subcommands

The harness provides three subcommands, each targeting a different corpus format:

#### `creddata` — Position-based evaluation against CredData

```
eval-harness creddata \
  --meta-dir <DIR>       \   # CredData CSV directory with ground-truth annotations
  --corpus-root <DIR>    \   # Path normalization root (stripped from finding/truth paths)
  --findings <JSONL>     \   # Pre-computed findings JSONL file
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>        \   # Write JSON to file instead of stdout
  --baseline <JSON>          # Baseline report for regression comparison
```

#### `synthetic` — Position-based evaluation against synthetic manifests

```
eval-harness synthetic \
  --manifest <JSON>      \   # Synthetic corpus JSON manifest
  --corpus-root <DIR>    \   # Path normalization root
  --findings <JSONL>     \   # Pre-computed findings JSONL file   ─┐ mutually
  --scan-corpus <DIR>    \   # OR: directory to live-scan          ─┘ exclusive
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>        \   # Write JSON to file instead of stdout
  --baseline <JSON>          # Baseline report for regression comparison
```

#### `leaky-repo` — Count-based evaluation against LeakyRepo

```
eval-harness leaky-repo \
  --secrets-csv <CSV>    \   # LeakyRepo secrets CSV (per-file expected counts)
  --findings <JSONL>     \   # Pre-computed findings JSONL file
  --corpus-root <DIR>    \   # Path normalization root
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>            # Write JSON to file instead of stdout
```

### Finding Input Modes

Position-based subcommands (`creddata`, `synthetic`) accept findings from two mutually exclusive sources:

- **`--findings <path>`** — Pre-computed JSONL from a previous scanner run. Each line is a JSON object with `path`, `start_byte`, `end_byte`, `rule`, and optional `confidence` fields.
- **`--scan-corpus <dir>`** — Live-scan a directory using the embedded `scanner_rs::demo_engine()` with the default ruleset. Findings are collected via an in-memory event sink and re-parsed through the same JSONL path. Intended for quick iteration during rule development on small-to-medium corpora.

The `leaky-repo` subcommand only supports `--findings` (no live scan).

### Output Formats

- **`--format json`** (default) — Machine-readable pretty-printed JSON. Supports `--output <path>` for file persistence. This is the format used for baseline comparison.
- **`--format table`** — Fixed-width ASCII table for terminal display. Shows aggregate metrics, per-rule breakdown, and regression verdict. Cannot be combined with `--output` (rejected at validation time).

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass or Warn — metrics meet thresholds (or no baseline provided) |
| 1 | Block — regression detected against `--baseline` report |
| 2 | Argument or runtime error |

## Quick Start

### Evaluate against CredData with pre-computed findings

```bash
# Run the scanner separately and save findings as JSONL:
scanner-rs scan --output findings.jsonl /path/to/creddata/corpus

# Evaluate:
eval-harness creddata \
  --meta-dir /path/to/creddata/meta \
  --corpus-root /path/to/creddata/corpus \
  --findings findings.jsonl
```

### Evaluate a synthetic corpus with live scan

```bash
eval-harness synthetic \
  --manifest tests/synthetic/manifest.json \
  --corpus-root tests/synthetic/corpus \
  --scan-corpus tests/synthetic/corpus
```

### Regression gating with baseline comparison

```bash
# Save a baseline report:
eval-harness creddata \
  --meta-dir /path/to/creddata/meta \
  --corpus-root /path/to/creddata/corpus \
  --findings baseline-findings.jsonl \
  --output baseline.json

# Compare a new run against the baseline:
eval-harness creddata \
  --meta-dir /path/to/creddata/meta \
  --corpus-root /path/to/creddata/corpus \
  --findings new-findings.jsonl \
  --baseline baseline.json

# Exit code 0 = pass/warn, 1 = block (regression detected)
echo "Exit code: $?"
```

## Interpreting Results

### Reading AP Scores

Average Precision (AP) is the primary ranking-quality metric. It measures how well the scanner's confidence scores separate true secrets from false positives:

- **AP = 1.0** — Perfect ranking: all true positives are ranked above all false positives.
- **AP = baseline_ap** — Confidence scores add no value; ranking is equivalent to random.
- **AP < baseline_ap** — Confidence scores are anti-correlated with truth (unusual in practice).

For secret scanning, AP above 0.90 is generally strong. Compare AP against `baseline_ap` to gauge whether confidence ranking adds value beyond the raw detection rate.

### Precision vs Recall Trade-offs

Secret scanning typically prioritizes recall (missed secrets are dangerous) over precision (false positives are annoying but not dangerous). The F2 score reflects this: it weights recall 4x more than precision.

- **High precision, low recall** — The scanner is conservative: it reports few false positives but misses real secrets. Consider lowering confidence thresholds or relaxing rule patterns.
- **Low precision, high recall** — The scanner is aggressive: it catches most secrets but generates noise. Consider tightening rule patterns or raising confidence thresholds.
- **P@R and R@P targets** — Check `precision_at_recall` to see what precision is achievable at 80%/90%/95% recall. Check `recall_at_precision` to see what recall is achievable at 95% precision.

### Regression Verdicts

When a `--baseline` is provided, the harness compares current metrics against the baseline:

| Verdict | Meaning | Default Threshold |
|---------|---------|-------------------|
| **Pass** | No meaningful regression detected | AP drop < 0.5pp AND precision drop < 0.5pp |
| **Warn** | Small regression detected (non-blocking) | AP drop 0.5pp–2pp OR precision drop 0.5pp–2pp |
| **Block** | Significant regression detected | AP drop ≥ 2pp OR precision drop ≥ 2pp |

The **CI overlap gate** (enabled by default) provides a safety valve: if the baseline AP falls within the current run's bootstrap confidence interval, the drop is attributable to sampling noise and the check returns Pass regardless of the raw delta.

### Error Book

In JSON output mode, the `error_book` field lists the top false positives and false negatives grouped by rule, sorted by frequency descending. Each FP entry includes a context window around the detection span (optionally BLAKE3-redacted). Use this to identify:

- **Recurring FP patterns** — Rules that consistently fire on non-secrets (e.g., placeholder tokens, test fixtures).
- **Missing detections** — Truth items that no finding matched, indicating gaps in rule coverage.

### Bootstrap Confidence Intervals

The bootstrap CI quantifies uncertainty in the AP estimate from finite-sample effects. A wide CI (e.g., `[0.82, 0.96]`) means the AP estimate is unstable — small changes to the corpus could shift it substantially. A narrow CI (e.g., `[0.93, 0.95]`) means the estimate is reliable.

When comparing runs, check whether the CIs overlap. Overlapping CIs suggest the difference may not be statistically meaningful, which is why the regression gate uses CI overlap as a safety valve.

Default configuration: 1000 iterations, α=0.05 (95% CI), seed=42 (deterministic). For publication-quality intervals, increase iterations to 10,000.
