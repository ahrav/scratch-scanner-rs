# Throughput Investigation: 10x Performance Gap Analysis

## Problem Statement

We have a Rust-based secret scanning engine that uses Vectorscan (Hyperscan) as a prefilter. When we benchmark raw Vectorscan FFI with our complete gitleaks anchor set (696 unique anchors from 223 rules), we achieve **3.8 GiB/s** throughput. However, when we run through our full `Engine::scan_chunk()` pipeline, throughput drops to **445 MiB/s** on clean ASCII data - roughly a **10x regression**.

While some overhead is expected from window validation, regex execution, and entropy checks, an order of magnitude seems excessive. What's causing this, and how can we fix it?

**Critical observation:** Commenting out just 2 rules (`generic-api-key` and `sourcegraph-access-token`) yields approximately 50% throughput improvement, suggesting these rules dominate the performance profile.

---

## Investigation Already Conducted

### 1. Layer-by-Layer Benchmark Results

We ran `cargo bench --bench vectorscan_overhead --features bench` and `cargo bench --bench throughput_comparison` to isolate throughput at each layer of the stack. Results on a 4 MiB buffer:

| Layer | Data Type | Throughput | Notes |
|-------|-----------|------------|-------|
| L1: memchr (ceiling) | ASCII | 54.1 GiB/s | Theoretical SIMD max |
| L2: Raw Vectorscan (1 pattern) | ASCII | 29.5 GiB/s | Single impossible pattern |
| L2: Raw Vectorscan (10 patterns) | ASCII | 21.4 GiB/s | 10 impossible patterns |
| L2.5: Raw Vectorscan (gitleaks) | ASCII | 3.8 GiB/s | 696 unique anchors, 223 rules |
| L3: Minimal Engine (1 rule) | ASCII | 29.6 GiB/s | Engine wrapper, no matches |
| L3: Minimal Engine (10 rules) | ASCII | 44.0 GiB/s | Impossible patterns |
| L4: Full Gitleaks Engine | ASCII | 445 MiB/s | 223 rules, derived anchors |
| L4: Full Gitleaks Engine | Random | 164 MiB/s | Higher anchor hit rate |
| L4: Full Gitleaks Engine | Realistic | 293 MiB/s | Source code patterns |

**The key gap:**

```
Layer 2.5 (raw VS gitleaks anchors): 3.8 GiB/s
Layer 4 (full engine):               0.44 GiB/s
─────────────────────────────────────────────────
Gap:                                 ~8.6x slower
```

This gap represents the combined cost of: window formation/merging, gate checks (`must_contain`, `keywords_any`, `confirm_all`), regex execution on candidate windows, and entropy calculation.

---

### 2. Problematic Rules Identified

#### 2.1 generic-api-key (Primary Offender)

**Location:** `src/gitleaks_rules.rs:1258-1316`

```rust
RuleSpec {
    name: "generic-api-key",
    anchors: &[
        b"access", b"ACCESS",
        b"api", b"API",
        b"auth", b"AUTH",
        b"key", b"KEY",
        b"credential", b"CREDENTIAL",
        b"creds", b"CREDS",
        b"passwd", b"PASSWD",
        b"password", b"PASSWORD",
        b"secret", b"SECRET",
        b"token", b"TOKEN",
    ],  // 20 anchors (10 keywords × 2 case variants)
    radius: 256,
    validator: ValidatorKind::None,
    two_phase: None,
    must_contain: None,
    keywords_any: Some(&[
        b"access", b"ACCESS",
        b"api", b"API",
        b"auth", b"AUTH",
        b"key", b"KEY",
        b"credential", b"CREDENTIAL",
        b"creds", b"CREDS",
        b"passwd", b"PASSWD",
        b"password", b"PASSWORD",
        b"secret", b"SECRET",
        b"token", b"TOKEN",
    ]),
    entropy: Some(EntropySpec {
        min_bits_per_byte: 3.5,
        min_len: 16,
        max_len: 256,
    }),
    re: build_regex(
        r#"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"#,
    ),
}
```

**Why this rule is expensive:**

1. **20 generic word anchors** - Words like `key`, `api`, `token` match frequently in normal source code
2. **High anchor hit rate** - Common programming vocabulary appears in variable names, comments, documentation
3. **Complex regex** - Case-insensitivity (`(?i)`), alternations, lazy quantifiers (`{0,50}?`)
4. **Large radius (256 bytes)** - Creates large validation windows
5. **Despite having keywords_any gate** - The gate doesn't filter much since it uses the same generic keywords as anchors

**Profiling data** from real repository scan (`bench_repos --profile-rules`):

| Metric | Value |
|--------|-------|
| Total validation time | 1606 ms (rank #1) |
| Windows processed | 8861 |
| Regex matches | 72350 |

#### 2.2 sourcegraph-access-token (Secondary Offender)

**Location:** `src/gitleaks_rules.rs:3416-3432`

```rust
RuleSpec {
    name: "sourcegraph-access-token",
    anchors: &[b"sgp_", b"SGP_"],  // Specific prefix anchors only
    radius: 256,
    validator: ValidatorKind::None,
    two_phase: None,
    must_contain: None,
    keywords_any: Some(&[b"sgp_", b"SGP_"]),
    entropy: Some(EntropySpec {
        min_bits_per_byte: 3.0,
        min_len: 16,
        max_len: 256,
    }),
    re: build_regex(
        r#"(?i)\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b(?:[\x60'"\s;]|\\[nr]|$)"#,
    ),
}
```

**Note:** This rule was previously slower due to generic `sourcegraph`/`SOURCEGRAPH` keyword anchors and a regex with `[a-fA-F0-9]{40}` that matched git SHAs. The current optimized version uses only the `sgp_` prefix anchors and a more specific regex pattern.

**Why this rule could still be expensive:**

1. **Relatively short anchors** - `sgp_` is only 4 characters
2. **Common prefix pattern** - May appear in code, though less frequently than generic keywords
3. **Profiling shows:** 893 windows processed, 30695 regex matches (rank #3 by validation time in older versions)

---

### 3. Scanning Pipeline Architecture Traced

#### Entry Point: `Engine::scan_chunk_into`

**File:** `src/engine/core.rs:743-997`

```
scan_chunk_into()
    │
    ├─► WorkItem::ScanBuf
    │       │
    │       └─► scan_rules_on_buffer() [src/engine/buffer_scan.rs:41]
    │               │
    │               ├─► VsPrefilterDb::scan_raw() [vectorscan FFI]
    │               │       └─► vs_on_match callback [vectorscan_prefilter.rs:1762]
    │               │               └─► scratch.hit_acc_pool.push_span()
    │               │
    │               ├─► For each touched (rule, variant) pair:
    │               │       ├─► Sort windows by start offset
    │               │       ├─► merge_ranges_with_gap_sorted()
    │               │       ├─► coalesce_under_pressure_sorted()
    │               │       │
    │               │       └─► run_rule_on_window() [window_validate.rs:51]
    │               │               ├─► must_contain gate (memmem)
    │               │               ├─► confirm_all gate (memmem)
    │               │               ├─► keywords_any gate (memmem)
    │               │               ├─► regex.find_iter()  ← EXPENSIVE
    │               │               └─► entropy_gate_passes() ← EXPENSIVE
    │               │
    │               └─► Transform span detection (if depth allows)
    │
    └─► WorkItem::DecodeSpan (for base64/URL transforms)
```

#### Hot Path: `run_rule_on_window`

**File:** `src/engine/window_validate.rs:51-124`

```rust
pub(super) fn run_rule_on_window(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    variant: Variant,
    buf: &[u8],
    w: Range<usize>,
    // ... other params
) {
    let window = &buf[w.clone()];

    // Gate 1: must_contain (cheap memmem)
    if let Some(needle) = rule.must_contain {
        if memmem::find(window, needle).is_none() {
            return;
        }
    }

    // Gate 2: confirm_all (cheap memmem)
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

    // Gate 3: keywords_any (cheap memmem)
    if let Some(kws) = &rule.keywords {
        let raw_keywords = &kws.any[Variant::Raw.idx()];
        if !contains_any_memmem(window, raw_keywords) {
            return;
        }
    }

    // EXPENSIVE: Regex execution on every surviving window
    let entropy = rule.entropy;
    for rm in rule.re.find_iter(window) {
        if let Some(ent) = entropy {
            let mbytes = &window[rm.start()..rm.end()];
            // Entropy check is also moderately expensive
            if !entropy_gate_passes(&ent, mbytes, &mut scratch.entropy_scratch, &self.entropy_log2) {
                continue;
            }
        }
        // Record finding...
        scratch.push_finding(...);
    }
}
```

#### Vectorscan Callback: `vs_on_match`

**File:** `src/engine/vectorscan_prefilter.rs:1762-1846`

```rust
extern "C" fn vs_on_match(id: c_uint, _from: u64, to: u64, _flags: c_uint, ctx: *mut c_void) -> c_int {
    let c = unsafe { &mut *(ctx as *mut VsMatchCtx) };

    // For raw rule patterns (regex prefilter hits)
    if id < c.raw_rule_count {
        let raw_idx = id as usize;
        let rid = unsafe { *c.raw_rule_ids.add(raw_idx) as usize };
        let scratch = unsafe { &mut *c.scratch };

        let end = to as u32;
        let max_width = unsafe { *c.raw_match_widths.add(raw_idx) };
        let start = if max_width == u32::MAX { 0 } else { end.saturating_sub(max_width) };
        let seed = unsafe { *c.raw_seed_radius.add(raw_idx) };
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(c.hay_len);

        let pair = rid * 3 + 0;  // rule_id * 3 + variant_index (Raw = 0)
        scratch.hit_acc_pool.push_span(pair, SpanU32 { start: lo, end: hi }, &mut scratch.touched_pairs);
        return 0;
    }

    // For anchor literal patterns
    if c.anchor_pat_count > 0 && id >= c.anchor_id_base {
        let pid = (id - c.anchor_id_base) as usize;
        let len = unsafe { *c.anchor_pat_lens.add(pid) };
        let end = to as u32;
        let start = end.saturating_sub(len);

        let off_start = unsafe { *c.anchor_pat_offsets.add(pid) } as usize;
        let off_end = unsafe { *c.anchor_pat_offsets.add(pid + 1) } as usize;
        let scratch = unsafe { &mut *c.scratch };

        for i in off_start..off_end {
            let target = unsafe { *c.anchor_targets.add(i) };
            let seed = target.seed_radius_bytes;
            let lo = start.saturating_sub(seed);
            let hi = end.saturating_add(seed).min(c.hay_len);

            let rid = target.rule_id as usize;
            let vidx = target.variant_idx as usize;
            let pair = rid * 3 + vidx;
            scratch.hit_acc_pool.push_span(pair, SpanU32 { start: lo, end: hi }, &mut scratch.touched_pairs);
        }
    }
    0
}
```

---

### 4. Key Data Structures

#### RuleCompiled (`src/engine/rule_repr.rs:268-277`)

```rust
pub(super) struct RuleCompiled {
    pub(super) name: &'static str,
    pub(super) must_contain: Option<&'static [u8]>,
    pub(super) confirm_all: Option<ConfirmAllCompiled>,
    pub(super) keywords: Option<KeywordsCompiled>,
    pub(super) entropy: Option<EntropyCompiled>,
    pub(super) re: Regex,
    pub(super) two_phase: Option<TwoPhaseCompiled>,
}
```

#### Scratch State Components

- `hit_acc_pool`: Accumulates windows per (rule, variant) pair during Vectorscan scan
- `touched_pairs`: Tracks which (rule, variant) pairs received at least one window
- `windows`: Reusable vector for per-rule window processing
- `out`: Finding output buffer

---

### 5. Existing Documentation Findings

**From `docs/throughput_analysis.md`:**

- `generic-api-key` dominates validation time - 1606ms vs 62ms for runner-up (`private-key`)
- Two distinct bottlenecks exist:
  - Clean data: Vectorscan automaton complexity from anchor diversity
  - Realistic data: Validation cost from high anchor hit rates
- 13 rules are marked "unfilterable" - Cannot derive good anchors automatically

**From `docs/throughput_bottleneck_analysis.md`:**

- 6.5x slowdown from anchor diversity alone (uniform 4-char vs variable gitleaks anchors)
- 8x slowdown on realistic source code vs clean data
- Generic word anchors (`secret`, `token`, `api_key`) cause high false candidate rates

---

## Hypotheses to Test

### Hypothesis 1: Regex Complexity Dominates

**Rationale:** The `generic-api-key` regex is complex with case-insensitivity, alternations, and lazy quantifiers.

**Test:** Create variant with simplified regex:

```rust
// Original (complex)
r#"(?i)(?:access|auth|api|...)(?:[ \t\w.-]{0,20})..."#

// Simplified
r#"[A-Za-z0-9_]{10,150}"#  // Just capture the value
```

**Expected result:** If regex is the bottleneck, simplified version should be 3-5x faster.

### Hypothesis 2: Anchor Hit Rate Drives Cost

**Rationale:** Generic word anchors (`key`, `api`, `token`) match frequently in source code.

**Test:** Replace generic word anchors with impossible anchors:

```rust
// Instead of: "key=", "api:", "token "
// Use: "\xFF\xFE=", "\xFD\xFC:"
```

**Expected result:** If anchor hit rate is the issue, throughput should approach L3 baseline (29 GiB/s).

### Hypothesis 3: Missing `keywords_any` Gate Matters

**Rationale:** `generic-api-key` has `keywords_any: None`, so every anchor hit proceeds directly to regex.

**Test:** Add keyword gate:

```rust
keywords_any: Some(&[b"key=", b"api=", b"token=", ...]),
```

**Expected result:** Should reduce regex invocations by filtering non-matching windows early.

### Hypothesis 4: Window Size Amplification

**Rationale:** `radius: 256` creates 512-byte validation windows, amplifying regex cost.

**Test:** Reduce radius:

```rust
radius: 64,  // Instead of 256
```

**Expected result:** Smaller windows = faster regex execution, but may miss edge-case matches.

---

## Benchmark Commands

```bash
# Layer-by-layer throughput analysis
cargo bench --bench vectorscan_overhead --features bench

# Full engine throughput comparison
cargo bench --bench throughput_comparison

# Per-rule profiling on real repositories
cargo run --bin bench_repos --features rule-profile -- --profile-rules --profile-top 50

# Unfilterable rule analysis
cargo test --test analyze_unfilterable -- --nocapture
```

---

## Files to Modify for Experiments

| File | Purpose |
|------|---------|
| `src/gitleaks_rules.rs` | Rule definitions, anchors, regex patterns |
| `src/engine/window_validate.rs` | Window-level validation, gates, regex execution |
| `src/engine/buffer_scan.rs` | Window formation, merging, rule dispatch |
| `src/engine/vectorscan_prefilter.rs` | Vectorscan FFI, callback, window seeding |
| `benches/throughput_comparison.rs` | Main throughput benchmark |
| `benches/rule_isolation.rs` | Rule-specific impact testing (needs `harness = false` in Cargo.toml) |

---

## Success Criteria

| Metric | Current | Target | Stretch Goal |
|--------|---------|--------|--------------|
| Clean ASCII throughput | 445 MiB/s | 1-2 GiB/s | 5 GiB/s |
| Realistic code throughput | 293 MiB/s | 800 MiB/s | 2 GiB/s |
| `generic-api-key` validation time | 1606 ms | <400 ms | <100 ms |

---

## Constraints

1. **Must not break detection** - All existing true positives must still be found
2. **Minimal anchor changes** - Prefer gating/optimization over anchor redesign
3. **Backward compatible API** - `RuleSpec` structure should remain stable
4. **No external dependencies** - Solution should not require new crates
