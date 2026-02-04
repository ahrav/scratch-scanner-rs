# Engine Window Validation Module

**File**: `src/engine/window_validate.rs`

## Module Purpose

The window validation module executes compiled detection rules against fixed-size byte windows extracted from scanned data. It performs the critical "hot path" validation where patterns are matched, gates are enforced, and findings are recorded. The module handles both raw binary data and UTF-16 encoded content, applying progressive filtering through cheap gates before expensive regex matching.

Two entry styles are supported:
- **Engine hot path**: `run_rule_on_window` writes findings directly into `ScanScratch` and performs dedupe bookkeeping immediately.
- **Scheduler adapters**: `run_rule_on_raw_window_into` / `run_rule_on_utf16_window_into` accumulate findings into scratch staging buffers so the caller can commit results and track drops.

### Key Responsibilities

- **Gate-based filtering**: Apply cost-effective byte-level checks before regex execution
- **Coordinate space management**: Maintain separate coordinate systems for raw bytes, UTF-16 variants, and decoded UTF-8 output
- **Budget enforcement**: Track and limit UTF-16 decoding resource consumption
- **Finding extraction**: Record matches with proper span information and secret data extraction
- **Entropy validation**: Gate findings on Shannon entropy of matched tokens

---

## Window Building Algorithm

Windows are provided externally (typically from anchor hits detected by Vectorscan) and represent fixed byte ranges within a buffer. The module does not build windows but validates them according to this pattern:

```
Input: Window [w.start..w.end) in buffer
  ↓
[Gate 1] Apply cheap byte gates (must-contain, confirm-all, keywords)
  ↓
[Gate 2] For UTF-16: Check decode budget + decode to UTF-8
  ↓
[Gate 3] Apply assignment-shape precheck (if rule-specific)
  ↓
[Gate 4] Run regex with capture groups
  ↓
[Gate 5] Check entropy on full match
  ↓
[Gate 6] Extract secret span from capture groups
  ↓
[Gate 7] Apply local context checks (bounded, fail-open)
  ↓
Output: FindingRec with spans in appropriate coordinate space
```

### Anchor Hint Processing

The `anchor_hint` parameter indicates where Vectorscan detected a match start. The validator applies a **back-scan margin** (`BACK_SCAN_MARGIN = 64` bytes) to allow patterns that may have backward context:

```rust
let hint_in_window = anchor_hint.saturating_sub(w.start);
let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
let search_window = &window[search_start..];
```

This margin accounts for patterns where the anchor may appear in the middle of the full regex match (e.g., backward-looking patterns like `(?<=[A-Z])secret[a-z]+`).

---

## Merge and Coalesce Strategies

This module does not implement merge or coalesce operations. Those are handled in separate modules (e.g., window build/merge stages). The window validation module receives pre-built windows (which may overlap) and focuses only on validation and finding extraction.

---

## run_rule_on_window: The Hot Path Validation Function

```rust
pub(super) fn run_rule_on_window(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    variant: Variant,
    buf: &[u8],
    w: Range<usize>,
    step_id: StepId,
    root_hint: Option<Range<usize>>,
    base_offset: u64,
    file_id: FileId,
    scratch: &mut ScanScratch,
    anchor_hint: usize,
)
```

This is the primary entry point for window validation. It:

1. Extracts the window slice from the buffer
2. Routes to variant-specific logic (Raw, UTF-16LE, UTF-16BE)
3. Runs all gates in sequence
4. Executes regex matching
5. Records findings into scratch space

### Coordinate Space Handling

The function maintains invariants about coordinate spaces:

- **Raw variant**: All spans are expressed in raw buffer byte offsets
- **UTF-16 variants**:
  - Spans in findings are in decoded UTF-8 byte space
  - Root hints use the **full match span** mapped back to raw UTF-16 byte offsets, and then (when available) through `root_span_map_ctx`
  - A `DecodeStep::Utf16Window` is attached to findings to enable mapping back to parent raw offsets

### Return Behavior

Early returns occur when:
- Any gate fails (must-contain, confirm-all, keywords, assignment-shape)
- Decode budget is exhausted (UTF-16 variants)
- Decoding fails (UTF-16 variants)
- Regex produces no matches

Late returns occur when:
- Entropy gates reject a match (continues to next match, not full return)
- Finding buffer capacity is reached (finding is dropped but processing continues)

---

## Gate Checks

Gates are applied in strict sequence. Each gate is a cheap byte-level check that eliminates impossible windows before expensive regex execution.

### 1. must_contain Gate

```rust
if let Some(needle) = rule.must_contain {
    if memmem::find(window, needle).is_none() {
        return;
    }
}
```

**Purpose**: Reject windows that lack a required literal byte sequence.

**Performance**: O(window.len()) byte search using `memchr::memmem`

**Use case**: High-confidence anchor literal that must appear for any regex match to be possible.

### 2. confirm_all Gate

```rust
if let Some(confirm) = &rule.confirm_all {
    let vidx = Variant::Raw.idx();
    if let Some(primary) = &confirm.primary[vidx] {
        if memmem::find(window, primary).is_none() {
            return;
        }
    }
    if !contains_all_memmem(window, &confirm.rest[vidx]) {
        return;
    }
}
```

**Purpose**: Require all specified literal byte sequences to be present in the window.

**Components**:
- `primary`: Main required literal (fast-path)
- `rest`: Additional required literals that must all be found

**Performance**: Early exit on first missing literal; typically O(window.len()) total.

**Use case**: Context validation (e.g., "window must contain 'secret' AND 'key' AND 'password'")

### 3. keywords_any Gate

```rust
if let Some(kws) = &rule.keywords {
    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
        return;
    }
}
```

**Purpose**: Cheap pre-regex filter: window must contain at least one of the specified keyword literals.

**Performance**: Returns on first match found; efficient early exit.

**Variant handling**:
- Raw variant: Check against raw window directly
- UTF-16 variants: Check against raw UTF-16 bytes *before* decoding to avoid wasting decode budget

**Use case**: Eliminate windows that could never match the rule's regex regardless of structure.

### 4. Assignment-Shape Precheck

```rust
if rule.needs_assignment_shape_check && !has_assignment_value_shape(window) {
    return;
}
```

**Purpose**: Reject windows that lack the basic structure for assignment patterns (e.g., `key=value`).

**When enabled**: When the rule regex expects an assignment-like structure.

### 5. Local Context Gate (Design A)

Local context gates run **after** regex matching and secret extraction. They
inspect a bounded lookaround slice (same line) to validate micro-context such as
assignment separators, quoting, or key-name hints. These checks are:

- **Bounded**: O(k) for small lookbehind/lookahead windows
- **Allocation-free**: byte scans only
- **Fail-open**: when line boundaries are not found inside the lookaround range

Local context gates are rule-selective and opt-in via rule config.
They apply uniformly in raw, UTF-16, and stream-decoded validation paths.

---

## has_assignment_value_shape: Assignment Structure Validation

```rust
fn has_assignment_value_shape(window: &[u8]) -> bool
```

A specialized precheck for patterns like `api_key=AKIAIOSFODNN7EXAMPLE` that detects assignment structure without regex overhead.

### Algorithm

1. **Find separator**: Search for `=`, `:`, or `>` (for `=>`)
2. **Skip whitespace/quotes**: After separator, skip spaces, tabs, quotes (`"`, `'`, `` ` ``), and extra separators
3. **Validate token length**: Count consecutive alphanumeric/underscore/hyphen/dot characters; require minimum 10 characters

### Examples

✓ `api_key=AKIAIOSFODNN7EXAMPLE` (22-char token after `=`)

✓ `token: abcdefghij1234567890` (20-char token after `:`)

✓ `key="longtokenvalue"` (14-char token, quotes skipped)

✗ `key=short` (4-char token, < 10 minimum)

✗ `token=` (no token after separator)

✗ `api_key AKIAIOSFODNN7EXAMPLE` (no separator)

### Performance

O(window.len()) byte scan; conservative filter that only produces true rejections (no false negatives).

---

## Regex Execution

The regex engine is Hyperscan/Vectorscan, accessed via `rule.re.captures_iter()`:

```rust
for caps in rule.re.captures_iter(search_window) {
    let full_match = caps.get(0).expect("group 0 always exists");
    let match_start = search_start + full_match.start();
    let match_end = search_start + full_match.end();

    // Process match...
}
```

### Key Points

- **Capture groups**: The regex stores named and positional capture groups
- **Full match**: Group 0 (accessed via `caps.get(0)`) always contains the complete match
- **Search window**: For Raw variant, regex starts at `search_start` (anchor hint minus back-scan margin)
- **Multiple matches**: `captures_iter()` yields all non-overlapping matches

### Coordinate Adjustment

Regex offsets are relative to `search_window`, so they must be re-based to window coordinates:

```rust
let match_start = search_start + full_match.start();
let match_end = search_start + full_match.end();
```

Then again adjusted to buffer coordinates for finding recording:

```rust
let match_span_in_buf = (w.start + match_start)..(w.start + match_end);
```

---

## Entropy Checking: entropy_gate_passes Implementation

Entropy gating filters matches based on Shannon entropy of the matched bytes, eliminating highly repetitive or structured tokens that are unlikely to be credentials.

### Invocation

```rust
if let Some(ent) = entropy {
    let mbytes = &window[match_start..match_end];
    if !entropy_gate_passes(
        &ent,
        mbytes,
        &mut scratch.entropy_scratch,
        &self.entropy_log2,
    ) {
        continue;  // Skip to next match, not full return
    }
}
```

### Parameters

- `ent`: Entropy threshold configuration (bits per byte, minimum token length, etc.)
- `mbytes`: The matched bytes (full match, not secret span) to evaluate
- `entropy_scratch`: Mutable scratch space for frequency tables
- `entropy_log2`: Pre-computed log2 lookup table for efficiency

### Behavior

- Evaluates entropy only on the **full regex match** (group 0), not the secret span or window
- Rejects matches with entropy below configured threshold
- Rejects matches shorter than configured minimum length (often 5-8 bytes)
- On failure, **continues to next match** (not an early return) via `continue`

### Rationale

Entropy gating kept separate from gate checks because:
1. It's only applied to matches, not the whole window
2. Multiple matches per window may pass/fail independently
3. Failure doesn't invalidate other potential matches in the window

---

## Secret Span Extraction

The `extract_secret_span()` helper extracts the sensitive portion of the match using a priority hierarchy:

### Extraction Priority

1. **Configured secret_group**: If rule specifies `secret_group` and that capture group is non-empty
2. **Capture group 1**: Gitleaks convention; if non-empty (e.g., regex like `secret\s*=\s*([\w\-]+)` captures the token in group 1)
3. **Full match (group 0)**: Fallback when no capture groups are configured or group 1 is empty

### Example

For regex pattern `api_key\s*=\s*([\w-]+)`:

- Full match (group 0): `api_key = AKIAIOSFODNN7EXAMPLE`
- Capture group 1: `AKIAIOSFODNN7EXAMPLE` ← used as secret span

### Recording Invariant

The `root_hint_*` fields use the **full match span** (not secret span), not the window span:

```rust
let root_span_hint = root_hint.clone().unwrap_or(match_span_in_buf);

scratch.push_finding(FindingRec {
    span_start: secret_start,  // Secret portion
    span_end: secret_end,
    root_hint_start: base_offset + root_span_hint.start as u64,  // Full match
    root_hint_end: base_offset + root_span_hint.end as u64,
});
```

**Why?** The `drop_prefix_findings()` deduplication logic (in parent modules) uses `root_hint_end` to determine whether a finding should be kept during chunked scans. Using the full match span handles trailing context correctly (e.g., delimiter `;` extending into new bytes).

---

## Finding Recording

Findings are recorded into the provided `ScanScratch` structure with drop-hint and normalization data to support dedupe and chunk-boundary safety. The engine hot path uses `scratch.push_finding_with_drop_hint(...)`, while the scheduler adapters stage data in `scratch.tmp_findings` plus companion arrays (`tmp_drop_hint_end`, `tmp_norm_hash`) for the caller to commit.

```rust
scratch.push_finding_with_drop_hint(
    FindingRec {
    file_id,
    rule_id,
    span_start: span_in_buf.start as u32,
    span_end: span_in_buf.end as u32,
    root_hint_start: base_offset + root_span_hint.start as u64,
    root_hint_end: base_offset + root_span_hint.end as u64,
    step_id,
    },
    norm_hash,
    drop_hint_end,
    dedupe_with_span,
);
```

### FindingRec Fields

| Field | Type | Meaning |
|-------|------|---------|
| `file_id` | `FileId` | File identifier for finding source |
| `rule_id` | `u32` | Rule that matched |
| `span_start` | `u32` | Secret span start in decoded-stream or buffer |
| `span_end` | `u32` | Secret span end (exclusive) |
| `root_hint_start` | `u64` | Full match start (file offset for deduplication) |
| `root_hint_end` | `u64` | Full match end (file offset for deduplication) |
| `step_id` | `StepId` | Decode chain reference (enables span mapping) |
| `dedupe_with_span` | `bool` | Whether `span_start`/`span_end` participate in dedupe |

### Capacity Management

Findings are stored in scratch buffers with configurable limits:

```rust
if out.len() < max_findings {
    out.push(FindingRec { ... });
} else {
    *dropped = dropped.saturating_add(1);
}
```

Excess findings are counted in `dropped` for metrics but not stored.

### Coordinate Spaces

**Raw variant**: Spans are in raw buffer byte offsets

**UTF-16 variants**:
- `span_start`/`span_end`: Decoded UTF-8 byte space
- `root_hint_*`: Full match span mapped back into raw UTF-16 byte offsets, then (when present) through `root_span_map_ctx` for transform-derived buffers
- `step_id`: Points to `DecodeStep::Utf16Window` that stores endianness and parent span for later mapping

---

## UTF-16 Handling

The module supports UTF-16LE and UTF-16BE variants through a unified code path that scans both byte parities when anchors can land on either boundary.

### Decode Budget Enforcement

```rust
let remaining = self.tuning.max_total_decode_output_bytes
    .saturating_sub(scratch.total_decode_output_bytes);
if remaining == 0 {
    return;
}

let max_out = self.tuning.max_utf16_decoded_bytes_per_window
    .min(remaining);
```

Two budget limits:
1. Per-window maximum
2. Total accumulated decoding output limit (across all windows in scan)

### Decoding Process

```rust
let decoded = match variant {
    Variant::Utf16Le => decode_utf16le_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf),
    Variant::Utf16Be => decode_utf16be_to_buf(&buf[w.clone()], max_out, &mut scratch.utf16_buf),
    _ => unreachable!(),
};
```

Decoding:
- Outputs to reusable scratch buffer (`scratch.utf16_buf`) to avoid allocation
- Returns on error (invalid UTF-16 sequences)
- Returns if output is empty (no valid data decoded)

### Gate Ordering for UTF-16

Gates are applied in a specific order to minimize decode work:

```
[1] Check decode budget remaining
    ↓
[2] Run confirm_all gate on raw UTF-16 bytes (before decode)
    ↓
[3] Run keywords gate on raw UTF-16 bytes (before decode)
    ↓
[4] Decode UTF-16 → UTF-8
    ↓
[5] Check must_contain gate on decoded UTF-8
    ↓
[6] Apply assignment-shape check on decoded UTF-8
    ↓
[7] Run regex on decoded UTF-8
```

This ordering ensures:
- Cheap gates run before expensive decoding
- Keyword/confirm gates reject windows before wasting decode budget
- must_contain gate runs on decoded UTF-8 (must check decoded content)

---

## Alternative Entry Points

Two additional functions support the decode-then-validate pattern used by other engine components:

### run_rule_on_raw_window_into

```rust
pub(super) fn run_rule_on_raw_window_into(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    window: &[u8],
    window_start: u64,
    ...
    found_any: &mut bool,
)
```

For externally-managed windows (already extracted from buffer). Used when:
- Window buffer is managed by caller
- Caller tracks window starting offset
- Caller needs to know if any match passed gates

Returns via output parameters rather than scratches.

### run_rule_on_utf16_window_into

```rust
pub(super) fn run_rule_on_utf16_window_into(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    variant: Variant,
    raw_win: &[u8],
    window_start: u64,
    ...
    found_any: &mut bool,
)
```

Similar to above but for UTF-16 windows. Handles decoding and validation within caller's window management context.

---

## Testing

The module includes comprehensive tests for `has_assignment_value_shape`:

- ✓ Basic assignment with `=`, `:`, `=>`
- ✓ Quoted tokens: `"..."`, `'...'`, `` `...` ``
- ✓ Special chars in tokens: `_`, `-`, `.`
- ✓ Boundary conditions: exactly 10 chars passes, 9 chars fails
- ✓ Negative cases: no separator, short tokens, empty values

Located at `/src/engine/window_validate.rs:648-724`

---

## Design Rationale

### Back-Scan Margin (64 bytes)

Accounts for patterns with backward context or mid-match anchors. 64 bytes balances correctness against overhead for most secret patterns.

### Gate Ordering

Gates progress from cheapest (memmem) to most expensive (regex):
1. must_contain / confirm_all: O(n) byte search
2. keywords: O(n) byte search with early exit
3. assignment-shape: O(n) byte scan
4. regex: O(n × complexity)

Early failures save expensive regex compilation/execution.

### Entropy on Full Match

Applied to group 0 (full match), not secret span, because:
- Maintains entropy threshold relative to entire token structure
- Prevents false positives on low-entropy delimiters
- Consistent with gitleaks conventions

### UTF-16 Budget Enforcement

Two limits prevent DoS via massive UTF-16 expansion:
- Per-window prevents single huge window from consuming all budget
- Total accumulated prevents many small windows from accumulating

### Scratch-Based Recording

Findings written to scratch buffers (not directly to results) because:
- Allows findings to be filtered/deduplicated in parent modules
- Supports per-window finding caps without allocating separate buffers
- Enables post-processing (e.g., sorting, merging)

---

## Invariants and Guarantees

1. Window ranges must be valid for the provided buffer
2. For Raw variant, match spans are in raw byte space
3. For UTF-16 variants, match spans are in decoded UTF-8 byte space
4. root_hint (when present) is in the same coordinate space as base_offset
5. anchor_hint is in buffer coordinates for Raw variant
6. All early returns occur before findings are recorded
7. Findings are appended to scratch (never removed or reordered during function execution)
8. Entropy gates continue to next match (not early return)
9. Finding capacity overflow increments drop counter but doesn't invalidate other findings
