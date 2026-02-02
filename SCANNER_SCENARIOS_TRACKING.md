# Scanner Test Scenarios Tracking Document

**Purpose**: Track the scanner corpus scenarios present on disk and their harness verification status.

**Location**: This document is internal and excluded from version control via `.gitignore`.

**Progress**: **41/41 scenarios verified** ✅

---

## Quick Reference

### Commands

```bash
# Run all scanner corpus tests
cargo test --features sim-harness --test simulation scanner_corpus

# Run specific category (example)
cargo test --features sim-harness --test simulation scanner_corpus -- raw_

# Debug failing scenario (dumps artifacts to tests/failures/)
DUMP_SIM_FAIL=1 cargo test --features sim-harness --test simulation scanner_corpus -- <scenario_name>

# View test output
cat tests/failures/<scenario_name>/

# Clean up failure artifacts
rm -rf tests/failures/
```

### Files

- **Test runner**: `tests/simulation/scanner_corpus.rs` (auto-discovers `*.case.json` files)
- **Corpus directory**: `tests/corpus/scanner/` (41 total scenarios)
- **Harness guide**: `docs/scanner_test_harness_guide.md`

---

## Integration Summary

Current corpus size: **41 scenarios** (all present in `tests/corpus/scanner/`).

Last verified: **February 2, 2026** with:
```bash
cargo test --features sim-harness --test simulation scanner_corpus
```

### Coverage Breakdown (41 Total)

| Category | Count | Files |
|----------|-------|-------|
| **Raw Matching** | 6 | raw_start_boundary, raw_split_across_chunks, raw_secret_at_eof, raw_back_to_back, raw_boundary, mf_parallel |
| **Overlap Configuration** | 2 | overlap_eq_required, overlap_gt_required |
| **Base64 Transform** | 8 | b64_pad_eqeq, b64_pad_eq, b64_no_padding, b64_spans_eq_cap_16, b64_spans_gt_cap_17, b64_truncated_quantum, b64_invalid_padding, max_transform_depth0_no_decode |
| **URL Percent Encoding** | 5 | urlpct_upper, urlpct_lower, urlpct_min_len_edges, urlpct_spans_eq_cap_16, urlpct_spans_gt_cap_17 |
| **Mixed Transforms** | 1 | transforms |
| **Nested Transforms** | 4 | nested_depth2, nested_depth3, nested_depth4, nested_depth4_cap3_expected_empty |
| **UTF-16 Variants** | 8 | utf16, utf16_mixed_endianness, utf16be_aligned, utf16be_mixed_parity, utf16be_mixed_parity_tiny_chunks, utf16le_aligned, utf16le_truncated_odd_len_tail, utf16le_with_bom |
| **Path Edge Cases** | 4 | empty_path, path_nul_slashslash, longpath, badutf8 |
| **Adversarial** | 1 | near_miss_only |
| **Regex Variants** | 1 | case_insensitive_regex_jwt |
| **Deterministic Replay** | 1 | deterministic_replay_stability_runs |
| **TOTAL** | **41** | - |

---

## Coverage Verification

### ✅ Completed Coverage

- [x] **Raw matching** (6 scenarios)
- [x] **Overlap configuration** (2 scenarios)
- [x] **Base64 transform** (8 scenarios)
- [x] **URL percent encoding** (5 scenarios)
- [x] **Mixed transforms** (1 scenario)
- [x] **Nested transform depth** (4 scenarios)
- [x] **UTF-16 variants** (8 scenarios)
- [x] **Path edge cases** (4 scenarios)
- [x] **Regex variants** (1 scenario)
- [x] **Adversarial false positives** (1 scenario)
- [x] **Deterministic replay** (1 scenario)
- [x] **Transform depth=0** (1 scenario)

### Out of Corpus (Schema Unsupported)

These are intentionally **not** in the corpus because their schemas are not supported by the current ReproArtifact format:
- `base_offset_raw_late_match`
- `base_offset_decoded_match`
- Fault-injection scenarios (open/read failures, latency, cancel_after_reads, corruption) that require `FaultPlan.per_file` map keys incompatible with JSON string keys.

---

## File Structure

All corpus files are located in `tests/corpus/scanner/` with naming pattern `<category>_<description>.case.json`.

### Files by Category

**Raw Matching (6)**:
- `raw_start_boundary.case.json`
- `raw_split_across_chunks.case.json`
- `raw_secret_at_eof.case.json`
- `raw_back_to_back.case.json`
- `raw_boundary.case.json`
- `mf_parallel.case.json`

**Overlap Configuration (2)**:
- `overlap_eq_required.case.json`
- `overlap_gt_required.case.json`

**Base64 Transform (8)**:
- `b64_pad_eqeq.case.json`
- `b64_pad_eq.case.json`
- `b64_no_padding.case.json`
- `b64_spans_eq_cap_16.case.json`
- `b64_spans_gt_cap_17.case.json`
- `b64_truncated_quantum.case.json`
- `b64_invalid_padding.case.json`
- `max_transform_depth0_no_decode.case.json`

**URL Percent Encoding (5)**:
- `urlpct_upper.case.json`
- `urlpct_lower.case.json`
- `urlpct_min_len_edges.case.json`
- `urlpct_spans_eq_cap_16.case.json`
- `urlpct_spans_gt_cap_17.case.json`

**Mixed Transforms (1)**:
- `transforms.case.json`

**Nested Transforms (4)**:
- `nested_depth2.case.json`
- `nested_depth3.case.json`
- `nested_depth4.case.json`
- `nested_depth4_cap3_expected_empty.case.json`

**UTF-16 Variants (8)**:
- `utf16.case.json`
- `utf16_mixed_endianness.case.json`
- `utf16be_aligned.case.json`
- `utf16be_mixed_parity.case.json`
- `utf16be_mixed_parity_tiny_chunks.case.json`
- `utf16le_aligned.case.json`
- `utf16le_truncated_odd_len_tail.case.json`
- `utf16le_with_bom.case.json`

**Path Edge Cases (4)**:
- `empty_path.case.json`
- `path_nul_slashslash.case.json`
- `longpath.case.json`
- `badutf8.case.json`

**Adversarial (1)**:
- `near_miss_only.case.json`

**Regex Variants (1)**:
- `case_insensitive_regex_jwt.case.json`

**Deterministic Replay (1)**:
- `deterministic_replay_stability_runs.case.json`

---

## Verification Runs

### Full Corpus

Command:
```bash
cargo test --features sim-harness --test simulation scanner_corpus
```

Result:
- **Pass** (41 scenarios, 0 failures)

### Seed / Argument Overrides

No CLI seed overrides were used. All scenarios run with the `scenario_seed` and `schedule_seed` embedded in their `.case.json` artifacts. No additional arguments were required.
