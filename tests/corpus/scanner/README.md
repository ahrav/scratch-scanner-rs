# Scanner Corpus Index

This directory contains deterministic scanner simulation scenarios. Each `*.case.json` file is a complete ReproArtifact used by the sim harness.

## Scenarios

| File | Description |
|---|---|
| `b64_invalid_padding.case.json` | Base64 transform with invalid padding; ensures decoder rejects/handles bad padding safely. |
| `b64_no_padding.case.json` | Base64 transform without `=` padding; verifies decode and match still succeed. |
| `b64_pad_eq.case.json` | Base64 transform with single `=` padding; verifies decode and match. |
| `b64_pad_eqeq.case.json` | Base64 transform with double `==` padding; verifies decode and match. |
| `b64_spans_eq_cap_16.case.json` | Base64 span detection exactly at span cap (16) for a buffer. |
| `b64_spans_gt_cap_17.case.json` | Base64 span detection above cap (17); verifies cap enforcement. |
| `b64_truncated_quantum.case.json` | Base64 truncated quantum at end of input; ensures safe handling. |
| `badutf8.case.json` | File path contains invalid UTF-8; ensures path handling stays robust. |
| `case_insensitive_regex_jwt.case.json` | Case-insensitive JWT bearer regex (lowercase bearer) in raw data. |
| `deterministic_replay_stability_runs.case.json` | Same scenario replayed with multiple schedules; results must be stable. |
| `empty_path.case.json` | Empty path bytes; ensures path edge case is handled safely. |
| `longpath.case.json` | Very long path; validates path handling and hashing stability. |
| `max_transform_depth0_no_decode.case.json` | Depth limit set to 0; encoded content must not be decoded. |
| `mf_parallel.case.json` | Multi-file corpus; verifies parallel discovery/scan ordering invariants. |
| `near_miss_only.case.json` | Adversarial near-miss anchors; ensures no false positives. |
| `nested_depth2.case.json` | Nested transform chain depth 2; expected to decode and match. |
| `nested_depth3.case.json` | Nested transform chain depth 3; expected to decode and match. |
| `nested_depth4.case.json` | Nested transform chain depth 4; expected to decode and match. |
| `nested_depth4_cap3_expected_empty.case.json` | Depth cap < required; expected to produce no matches. |
| `overlap_eq_required.case.json` | Overlap equals required overlap; verifies dedupe/window correctness. |
| `overlap_gt_required.case.json` | Overlap greater than required; verifies dedupe/window correctness. |
| `path_nul_slashslash.case.json` | Path with NUL and `//` sequences; validates path normalization robustness. |
| `raw_back_to_back.case.json` | Two raw secrets adjacent in one file; both must be found. |
| `raw_boundary.case.json` | Raw secrets at chunk boundary across multiple files. |
| `raw_secret_at_eof.case.json` | Raw secret ends at EOF; must still be detected. |
| `raw_split_across_chunks.case.json` | Raw secret split across chunk boundary; must still be detected. |
| `raw_start_boundary.case.json` | Raw secret begins at chunk boundary; must still be detected. |
| `transforms.case.json` | Mixed Base64 and URL-percent transforms in one file. |
| `urlpct_lower.case.json` | URL-percent encoding with lowercase hex; must decode correctly. |
| `urlpct_min_len_edges.case.json` | URL-percent spans at min length boundaries. |
| `urlpct_spans_eq_cap_16.case.json` | URL-percent span detection exactly at span cap (16). |
| `urlpct_spans_gt_cap_17.case.json` | URL-percent span detection above cap (17); verifies cap enforcement. |
| `urlpct_upper.case.json` | URL-percent encoding with uppercase hex; must decode correctly. |
| `utf16.case.json` | UTF-16LE/BE secrets in separate files. |
| `utf16_mixed_endianness.case.json` | Mixed UTF-16 endianness content in one corpus. |
| `utf16be_aligned.case.json` | UTF-16BE secret aligned on even boundary. |
| `utf16be_mixed_parity.case.json` | UTF-16BE secret across parity; verifies handling. |
| `utf16be_mixed_parity_tiny_chunks.case.json` | UTF-16BE parity case under tiny chunk sizes. |
| `utf16le_aligned.case.json` | UTF-16LE secret aligned on even boundary. |
| `utf16le_truncated_odd_len_tail.case.json` | UTF-16LE with truncated odd-length tail; must not mis-detect. |
| `utf16le_with_bom.case.json` | UTF-16LE content with BOM; must decode correctly. |

