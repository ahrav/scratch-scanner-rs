# Scanner Test Scenarios Tracking Document

**Purpose**: Track the scanner corpus scenarios present on disk and their harness verification status.

**Location**: This document is internal and excluded from version control via `.gitignore`.

**Progress**: **52/52 scenarios verified** ✅

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
ls tests/failures/<scenario_name>/

# Clean up failure artifacts
rm -rf tests/failures/
```

### Files

- **Test runner**: `tests/simulation/scanner_corpus.rs` (auto-discovers `*.case.json` files)
- **Corpus directory**: `tests/corpus/scanner/` (52 total scenarios)
- **Harness guide**: `docs/scanner_test_harness_guide.md`

---

## Integration Summary

Current corpus size: **52 scenarios** (all present in `tests/corpus/scanner/`).

Last verified: **February 2, 2026** with:
```bash
cargo test --features sim-harness --test simulation scanner_corpus
```

### Coverage Breakdown (52 Total)

| Category | Count | Files |
|----------|-------|-------|
| **Raw Matching** | 8 | raw_start_boundary, raw_split_across_chunks, raw_secret_at_eof, raw_back_to_back, raw_boundary, raw_cross_chunk_end_boundary, raw_nonascii_padding, mf_parallel |
| **Raw No-Match Stress** | 3 | raw_many_anchor_hits_no_match, raw_high_entropy_0_255, raw_repetitive_a_200 |
| **Overlap Configuration** | 2 | overlap_eq_required, overlap_gt_required |
| **Base64 Transform** | 10 | b64_pad_eqeq, b64_pad_eq, b64_no_padding, b64_padding_seed17, b64_spans_eq_cap_16, b64_spans_gt_cap_17, b64_truncated_quantum, b64_invalid_padding, b64_internal_newline, b64_split_across_chunk_boundary |
| **URL Percent Encoding** | 7 | urlpct_upper, urlpct_lower, urlpct_min_len_edges, urlpct_spans_eq_cap_16, urlpct_spans_gt_cap_17, urlpct_end_on_boundary, urlpct_invalid_tail |
| **Mixed Transforms** | 1 | transforms |
| **UTF-16 Variants** | 10 | utf16, utf16_mixed_endianness, utf16be_aligned, utf16be_mixed_parity, utf16be_mixed_parity_tiny_chunks, utf16le_aligned, utf16le_misaligned, utf16le_truncated_odd_len_tail, utf16le_with_bom, utf16_mix_two_secrets |
| **Path Edge Cases** | 5 | empty_path, path_nul_slashslash, longpath, badutf8, path_weird_bytes_with_secret |
| **Adversarial** | 1 | near_miss_only |
| **Regex Variants** | 1 | case_insensitive_regex_jwt |
| **Deterministic Replay** | 1 | deterministic_replay_stability_runs |
| **Transform Depth=0** | 1 | max_transform_depth0_no_decode |
| **Fault Injection** | 2 | duplicate_finding_seed1, extra_expected_root_seed728 |
| **TOTAL** | **52** | - |

---

## Coverage Verification

### ✅ Completed Coverage

- [x] **Raw matching** (8 scenarios)
- [x] **Raw no-match stress** (3 scenarios)
- [x] **Overlap configuration** (2 scenarios)
- [x] **Base64 transform** (10 scenarios)
- [x] **URL percent encoding** (7 scenarios)
- [x] **Mixed transforms** (1 scenario)
- [x] **UTF-16 variants** (10 scenarios)
- [x] **Path edge cases** (5 scenarios)
- [x] **Regex variants** (1 scenario)
- [x] **Adversarial false positives** (1 scenario)
- [x] **Deterministic replay** (1 scenario)
- [x] **Transform depth=0** (1 scenario)
- [x] **Fault injection** (2 scenarios)

### Out of Corpus (Schema Unsupported)

These are intentionally **not** in the corpus because their schemas are not supported by the current ReproArtifact format:
- `base_offset_raw_late_match`
- `base_offset_decoded_match`

---

## Scanner Verified Cases Intake (Feb 2, 2026)

### Added to Corpus

- `base64_internal_newline.case.json` -> `b64_internal_newline.case.json`
- `base64_split_across_chunk_boundary.case.json` -> `b64_split_across_chunk_boundary.case.json`
- `urlpercent_end_on_boundary.case.json` -> `urlpct_end_on_boundary.case.json`
- `urlpercent_invalid_tail.case.json` -> `urlpct_invalid_tail.case.json`
- `raw_nonascii_padding.case.json` -> `raw_nonascii_padding.case.json`
- `raw_many_anchor_hits_no_match.case.json` -> `raw_many_anchor_hits_no_match.case.json`
- `raw_cross_chunk_end_boundary.case.json` -> `raw_cross_chunk_end_boundary.case.json`
- `high_entropy_0_255.case.json` -> `raw_high_entropy_0_255.case.json`
- `repetitive_A_200.case.json` -> `raw_repetitive_a_200.case.json`
- `weird_path_bytes_with_secret.case.json` -> `path_weird_bytes_with_secret.case.json`
- `utf16le_misaligned.case.json` -> `utf16le_misaligned.case.json`
- `utf16_mix_two_secrets.case.json` -> `utf16_mix_two_secrets.case.json`

### Skipped (Duplicate Coverage)

- `base64_simple.case.json` (covered by `b64_pad_eqeq.case.json` and `b64_no_padding.case.json`)
- `urlpercent_simple.case.json` (covered by `urlpct_upper.case.json`)
- `urlpercent_lower_hex.case.json` (covered by `urlpct_lower.case.json`)
- `raw_start.case.json` (covered by `raw_start_boundary.case.json`)
- `raw_end.case.json` (covered by `raw_secret_at_eof.case.json`)
- `raw_adjacent.case.json` (covered by `raw_back_to_back.case.json`)
- `near_miss.case.json` (covered by `near_miss_only.case.json`)
- `multi_file_two_rules.case.json` (covered by `mf_parallel.case.json`)
- `utf16le_start.case.json` (covered by `utf16le_aligned.case.json` and `utf16.case.json`)
- `utf16be_misaligned.case.json` (covered by `utf16be_mixed_parity.case.json`)

---

## Regression Seed Capture (Feb 2, 2026)

### Added to Corpus

- `scanner_seed_1.case.json` -> `duplicate_finding_seed1.case.json` (deep random + faults; duplicate finding regression)
- `scanner_seed_17.case.json` -> `b64_padding_seed17.case.json` (deep random + partial reads; base64 padding drift tolerance)
- `scanner_seed_728.case.json` -> `extra_expected_root_seed728.case.json` (deep random; reference scan misses expected raw span)

---

## File Structure

All corpus files are located in `tests/corpus/scanner/` with naming pattern `<category>_<description>.case.json`.

### Files by Category

**Raw Matching (8)**:
- `raw_start_boundary.case.json`
- `raw_split_across_chunks.case.json`
- `raw_secret_at_eof.case.json`
- `raw_back_to_back.case.json`
- `raw_boundary.case.json`
- `raw_cross_chunk_end_boundary.case.json`
- `raw_nonascii_padding.case.json`
- `mf_parallel.case.json`

**Raw No-Match Stress (3)**:
- `raw_many_anchor_hits_no_match.case.json`
- `raw_high_entropy_0_255.case.json`
- `raw_repetitive_a_200.case.json`

**Overlap Configuration (2)**:
- `overlap_eq_required.case.json`
- `overlap_gt_required.case.json`

**Base64 Transform (10)**:
- `b64_pad_eqeq.case.json`
- `b64_pad_eq.case.json`
- `b64_no_padding.case.json`
- `b64_padding_seed17.case.json`
- `b64_spans_eq_cap_16.case.json`
- `b64_spans_gt_cap_17.case.json`
- `b64_truncated_quantum.case.json`
- `b64_invalid_padding.case.json`
- `b64_internal_newline.case.json`
- `b64_split_across_chunk_boundary.case.json`

**URL Percent Encoding (7)**:
- `urlpct_upper.case.json`
- `urlpct_lower.case.json`
- `urlpct_min_len_edges.case.json`
- `urlpct_spans_eq_cap_16.case.json`
- `urlpct_spans_gt_cap_17.case.json`
- `urlpct_end_on_boundary.case.json`
- `urlpct_invalid_tail.case.json`

**Mixed Transforms (1)**:
- `transforms.case.json`

**UTF-16 Variants (10)**:
- `utf16.case.json`
- `utf16_mixed_endianness.case.json`
- `utf16be_aligned.case.json`
- `utf16be_mixed_parity.case.json`
- `utf16be_mixed_parity_tiny_chunks.case.json`
- `utf16le_aligned.case.json`
- `utf16le_misaligned.case.json`
- `utf16le_truncated_odd_len_tail.case.json`
- `utf16le_with_bom.case.json`
- `utf16_mix_two_secrets.case.json`

**Path Edge Cases (5)**:
- `empty_path.case.json`
- `path_nul_slashslash.case.json`
- `longpath.case.json`
- `badutf8.case.json`
- `path_weird_bytes_with_secret.case.json`

**Adversarial (1)**:
- `near_miss_only.case.json`

**Regex Variants (1)**:
- `case_insensitive_regex_jwt.case.json`

**Deterministic Replay (1)**:
- `deterministic_replay_stability_runs.case.json`

**Transform Depth=0 (1)**:
- `max_transform_depth0_no_decode.case.json`

**Fault Injection (2)**:
- `duplicate_finding_seed1.case.json`
- `extra_expected_root_seed728.case.json`

---

## Verification Runs

### Full Corpus

Command:
```bash
cargo test --features sim-harness --test simulation scanner_corpus
```

Result:
- **Pass** (52 scenarios, 0 failures)

### Seed / Argument Overrides

No CLI seed overrides were used. All scenarios run with the `scenario_seed` and `schedule_seed` embedded in their `.case.json` artifacts. No additional arguments were required.
