# Documentation Verification Report: src/git_scan/midx.rs

## Summary
| Metric | Count |
|--------|-------|
| Files verified | 4 |
| Claims extracted | 27 |
| Verified correct | 21 |
| BLOCK | 0 |
| WARN | 3 |
| INFO | 3 |

**Verdict**: PASS WITH WARNINGS

### Files examined
- `src/git_scan/midx.rs` (target)
- `src/git_scan/midx_error.rs` (error types)
- `src/git_scan/object_id.rs` (OID types)
- `src/git_scan/midx_build.rs` (builder, cross-reference)

## Findings

| # | Severity | File:Line | Category | Claim | Verdict | Evidence |
|---|----------|-----------|----------|-------|---------|----------|
| 1 | WARN | midx.rs:14-15 | Complexity | `find_oid_sorted` is `O(k)` over the traversed fanout bucket | Imprecise | Galloping search is O(log d) per lookup; amortized total is O(k log(N/k)), not O(k) |
| 2 | WARN | midx.rs:241-242 | Precondition | "Panics in debug builds if `idx` is out of range" | Incomplete | Slice access at line 248 can also panic in release builds via bounds check |
| 3 | WARN | midx.rs:257-258 | Behavioral | `# Errors` section only lists `LoffIndexOutOfBounds` | Incomplete | `offset_at` can also return `PackPosOutOfBounds` (line 269) and `MidxCorrupt` (from `resolve_loff` line 476) |
| 4 | INFO | midx.rs:47 | Count | "Maximum MIDX file size (4 GB)" | Imprecise | Value is 4 GiB (4,294,967,296 bytes), not 4 GB (4,000,000,000 bytes) |
| 5 | INFO | midx.rs:503 | External | "The final sentinel entry (all-zero chunk ID)" | Unverified | Format claim is correct per Git spec, but parser does not validate that sentinel ID is all zeros |
| 6 | INFO | midx.rs:1 | Behavioral | "Zero-copy multi-pack index (MIDX) parser" | Imprecise | The `MidxView` struct is zero-copy, but `parse()` allocates a `Vec<ChunkLoc>` internally; line 95 correctly qualifies this |

## Detailed Findings

### WARN-1: `find_oid_sorted` complexity claim is overstated
- **Location**: `src/git_scan/midx.rs:14-15`
- **Claim**: "`find_oid_sorted` is `O(k)` over the traversed fanout bucket with galloping search, reusing a cursor for sorted input."
- **Reality**: The `seek_oid_from` method (line 409) uses galloping search (exponential doubling at line 439, `step = step.saturating_mul(2)`), followed by binary search within the narrowed range (line 456). Each individual lookup costs O(log d) where d is the distance from the cursor to the target. For k lookups across a bucket of size N, the amortized total is O(k log(N/k)), which only reduces to O(k) when inputs are dense enough that d is O(1) on average (i.e., nearly every element in the bucket is queried).
- **Evidence**: Lines 427-469 show galloping (doubling step) + binary search, not a linear scan.
- **Suggested fix**: Change to: `` `find_oid_sorted` is amortized `O(log d)` per lookup (where `d` is the gap from the cursor) via galloping search, reusing a cursor for sorted input. ``

### WARN-2: `oid_at` panic doc omits release-mode behavior
- **Location**: `src/git_scan/midx.rs:241-242`
- **Claim**: "Panics in debug builds if `idx` is out of range."
- **Reality**: Line 245 uses `debug_assert!` which only fires in debug builds. However, the slice indexing at line 248 (`&self.oidl[start..start + oid_len]`) will panic in both debug and release builds if `idx` is out of range, because `start` will exceed `self.oidl.len()`. The doc implies the function is safe in release builds, which is not the case.
- **Evidence**: Line 248: `&self.oidl[start..start + oid_len]` -- standard slice bounds check panics in all build modes.
- **Suggested fix**: Change to: "Panics if `idx` is out of range. In debug builds, a `debug_assert` provides an earlier diagnostic."

### WARN-3: `offset_at` Errors section is incomplete
- **Location**: `src/git_scan/midx.rs:257-258`
- **Claim**: "Returns `LoffIndexOutOfBounds` if the LOFF indirection is invalid."
- **Reality**: The function can return three distinct error variants:
  1. `PackPosOutOfBounds` if `pack_pos >= self.pack_count` (line 268-272)
  2. `MidxCorrupt` with detail "LOFF indirection but no LOFF" if `self.loff` is `None` but LOFF flag is set (line 476)
  3. `LoffIndexOutOfBounds` if the LOFF index exceeds the LOFF table size (line 480-483)
- **Evidence**: Lines 268-272 (`PackPosOutOfBounds`), line 476 (`MidxCorrupt`), lines 480-483 (`LoffIndexOutOfBounds`).
- **Suggested fix**: Replace the Errors section with:
  ```
  /// # Errors
  /// - `PackPosOutOfBounds` if the OOFF entry references a non-existent pack.
  /// - `MidxCorrupt` if LOFF indirection is flagged but no LOFF chunk exists.
  /// - `LoffIndexOutOfBounds` if the LOFF index exceeds the LOFF table.
  ```

### INFO-1: "4 GB" should be "4 GiB"
- **Location**: `src/git_scan/midx.rs:47`
- **Claim**: "Maximum MIDX file size (4 GB)."
- **Reality**: `MAX_MIDX_SIZE = 4 * 1024 * 1024 * 1024` = 4,294,967,296 bytes = 4 GiB, not 4 GB (4,000,000,000). The distinction matters in systems contexts. Colloquial use often conflates the two, so this is informational only.
- **Suggested fix**: Change to "Maximum MIDX file size (4 GiB)."

### INFO-2: Sentinel ID not validated
- **Location**: `src/git_scan/midx.rs:503`
- **Claim**: "The final sentinel entry (all-zero chunk ID) defines the end of the last chunk."
- **Reality**: The parser processes the sentinel entry to compute the last chunk's length (line 550: `chunks[prev_idx].len = offset - prev_off`), but does not verify that the sentinel's chunk ID is all zeros. The format description is correct per the Git multi-pack-index specification, but the code is more permissive than the doc implies.
- **Evidence**: The sentinel's `id` field is parsed at line 523 but never checked for `[0,0,0,0]`.
- **Suggested fix**: No change needed; the doc describes the format, not an enforcement guarantee. Optionally add: "(the sentinel ID is not validated)".

### INFO-3: Module header says "parser" is zero-copy
- **Location**: `src/git_scan/midx.rs:1`
- **Claim**: "Zero-copy multi-pack index (MIDX) parser."
- **Reality**: The resulting `MidxView` is zero-copy (all fields are references or scalars). However, `parse()` internally allocates a `Vec<ChunkLoc>` (line 516) for chunk table parsing. The doc at line 95 correctly qualifies this: "This routine performs no allocation beyond small vectors." The module header is a slight overstatement since "parser" implies the process, not just the result.
- **Evidence**: Line 516: `let mut chunks = Vec::with_capacity(chunk_count as usize);`
- **Suggested fix**: No change required; the qualification at line 95 is sufficient, and "zero-copy" commonly refers to the result rather than internal temporaries.

## Verified Correct Claims (selected)

| Claim | Location | Evidence |
|-------|----------|----------|
| "Supports MIDX version 1 only" | line 8 | Version check at line 114: `version != MIDX_VERSION` where `MIDX_VERSION = 1` |
| "Does not validate pack checksums or the trailing MIDX checksum" | line 10 | No checksum code in `parse()` |
| "`find_oid` is `O(log N)` via fanout-bucketed binary search" | line 13 | Fanout narrows bucket (lines 340-345), standard binary search within (lines 349-357) |
| "`offset_at` is `O(1)` and may follow a LOFF indirection" | line 16 | Direct index into `ooff` (line 262), optional LOFF lookup (lines 276-281) |
| "All chunk slices are validated to lie within the MIDX buffer" | line 53 | `slice_chunk` checks bounds at lines 575-576 |
| "`object_count` equals the last value in the fanout table" | line 54 | `validate_fanout` returns last entry (line 596), assigned at line 165 |
| "Base MIDX layers are not supported" | line 56 | `_base_count` read but ignored at line 133 |
| "MIDX header size (12 bytes)" | line 27 | 4 (magic) + 1 (version) + 1 (hash) + 1 (chunk count) + 1 (base count) + 4 (pack count) = 12 |
| "Chunk table entry size (12 bytes: 4 ID + 8 offset)" | line 29 | Confirmed by parse_chunk_table: 4 bytes ID + 8 bytes offset |
| "MSB mask for detecting LOFF indirection in OOFF entries" | line 45 | `LOFF_FLAG = 0x8000_0000` used at line 276 |
| "Fanout table entries" = 256 | line 42 | Standard Git fanout table; 256 first-byte buckets |
| "Parses the chunk table, enforcing monotonic offsets and unique IDs" | line 501 | Monotonicity check at line 532-534, uniqueness at line 535 |
| "Validates that the fanout table is non-decreasing" | line 581 | Loop at lines 586-597 checks `val < prev` |
| "Names are raw bytes (not validated UTF-8) and exclude the trailing NUL" | line 288 | `split(|&b| b == 0).filter(|s| !s.is_empty())` at line 290 |
| "The comparison is normalized to strip .pack/.idx suffixes" | line 295 | Both sides go through `normalize_pack_name` (lines 302, 309) |
