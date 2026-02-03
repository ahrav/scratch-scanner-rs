# Throughput Bottleneck Analysis

## Executive Summary

**Two distinct bottlenecks exist, depending on workload:**

| Scenario | Primary Bottleneck | Secondary |
|----------|-------------------|-----------|
| Clean data (no anchor matches) | Vectorscan automaton complexity | Engine overhead |
| Realistic data (anchor matches) | **Validation cost (regex execution)** | Anchor hit volume |

The 98% throughput drop from simple rules to full gitleaks is **workload-dependent**.

---

## Benchmark Results Summary

### Layer-by-Layer Throughput

| Layer | Clean ASCII | Realistic Source | Notes |
|-------|-------------|------------------|-------|
| memchr baseline | 38 GiB/s | 38 GiB/s | Ceiling |
| Minimal engine (1 rule) | 17.5 GiB/s | 17.5 GiB/s | -54% from memchr |
| 50 simple anchors + complex regex | 28 GiB/s | **3.6 GiB/s** | 8x diff! |
| 50 gitleaks rules | 5.1 GiB/s | 5.4 GiB/s | Similar (gitleaks anchors selective) |
| 223 gitleaks rules (minimal) | 435 MiB/s | ~300 MiB/s | Full ruleset |
| 223 gitleaks rules (full demo) | 313 MiB/s | ~250 MiB/s | With transforms |

### Raw Vectorscan Isolation (no validation)

| Pattern Set | Throughput | Notes |
|-------------|-----------|-------|
| 436 simple 4-char anchors | **13.1 GiB/s** | Uniform prefixes |
| 436 gitleaks anchors | **2.0 GiB/s** | Variable length (3-34 chars), case-insensitive |

**6.5× slowdown from anchor diversity alone**, before any validation.

---

## Key Finding: The Real Bottleneck Depends on Anchor Hit Rate

### On Clean Data (Few Anchor Matches)

```
memchr:          38 GiB/s  ─┬─ -54%: Engine overhead (scratch, callbacks)
Minimal engine:  17.5 GiB/s ─┤
                            ├─ -85%: Anchor diversity in Vectorscan
Raw VS gitleaks: 2.0 GiB/s  ─┤       (case-insensitive, variable length)
                            ├─ -78%: Window formation + minimal regex
Full engine:     435 MiB/s  ─┘
```

### On Realistic Data (Many Anchor Matches)

**The data pattern comparison reveals the validation cost:**

| Data Pattern | 50 gitleaks-style rules | Anchor hits (est.) |
|--------------|------------------------|-------------------|
| clean_ascii | 28 GiB/s | ~0-5 |
| keyword_heavy | 28.4 GiB/s | ~50-100 |
| **realistic_source** | **3.6 GiB/s** | ~500+ |

**Why realistic_source is 8x slower:**
- Contains patterns matching anchors: "api_key", "secret", "token", etc.
- Each anchor hit triggers: window formation → gate checks → **regex execution**
- ~100+ regex evaluations per 4 MiB buffer vs ~0 for clean data

### Generic Word Anchors in Gitleaks

The gitleaks ruleset uses many **dictionary words** as anchors:
- `"secret"`, `"token"`, `"password"`, `"api_key"` - appear in typical code
- `"<add key="` - XML pattern, very common
- `"github"`, `"gitlab"` - appear in comments/URLs

These generic anchors cause **high false candidate rates** in real source code.

---

## Validation Pipeline Cost Breakdown

### Gate Progression (per anchor hit)

| Stage | Cost | Notes |
|-------|------|-------|
| Window formation | O(hits) | Negligible |
| must_contain | O(window_size) memmem | Cheap |
| keywords_any | O(window_size) memmem | Cheap |
| **Regex execution** | **O(complexity × window_size)** | **DOMINANT** |
| entropy | O(match_size) | Cheap, post-regex |

### Benchmark Evidence

From `validation_cost/pipeline_stages` (clean ASCII, 50 rules):

| Pipeline Stage | Throughput |
|----------------|-----------|
| Anchor only | 12.9 GiB/s |
| + keywords | 13.0 GiB/s |
| + entropy | 13.2 GiB/s |
| **+ complex regex** | **4.6 GiB/s** |

Gates add negligible cost. The **3× drop** when adding complex regex confirms regex execution dominates.

---

## Root Cause Analysis

### Bottleneck 1: Vectorscan Automaton Complexity (Clean Data)

**Cause:** Diverse anchor lengths (3-34 chars) + case-insensitivity

**Evidence:**
- 436 simple 4-char anchors: 13.1 GiB/s
- 436 gitleaks anchors: 2.0 GiB/s
- **6.5× slowdown** from anchor diversity alone

**Why this happens:**
- Vectorscan builds a DFA/NFA for pattern matching
- Variable-length patterns increase automaton state space
- Case-insensitivity doubles the effective pattern count
- Longer anchors require more states to track

**Impact:** 6.5× slowdown (13 GiB/s → 2 GiB/s in raw Vectorscan)

### Bottleneck 2: Validation Cost (Realistic Data)

**Cause:** Generic word anchors match frequently → many regex executions

**Evidence:**
- clean_ascii: 28 GiB/s (no anchor matches)
- realistic_source: 3.6 GiB/s (500+ anchor matches)
- **8× slowdown** from validation on realistic data

**Why this happens:**
- Anchors like "secret", "token", "api_key" appear in normal source code
- Each anchor hit triggers the full validation pipeline
- Complex gitleaks regexes are expensive to evaluate
- ~100+ regex evaluations per 4 MiB buffer on realistic data

**Impact:** 8× slowdown on realistic source code

### Bottleneck 3: Rule Count Cliff at 200+ (Both Workloads)

**Cause:** Vectorscan automaton state explosion

**Evidence:**
- 200 rules: 2.5 GiB/s
- 223 rules: 435 MiB/s
- **5× throughput cliff** at ~200 rule boundary

**Why this happens:**
- Vectorscan automaton complexity is non-linear
- State explosion occurs when pattern diversity exceeds threshold
- Cache pressure from larger DFA tables
- More potential match candidates to track simultaneously

**Impact:** Throughput cliff at ~200 rules

---

## Actionable Recommendations

### High Impact

#### 1. Improve Anchor Selectivity

**Problem:** Generic anchors ("secret", "token") match too frequently

**Solution:** Replace generic words with provider-specific prefixes

**Example:**
```
Before: anchor = "stripe" + "secret"
After:  anchor = "sk_live_" (Stripe live secret key prefix)
```

**Expected gain:** 2-5× on realistic data

**Implementation:**
- Audit all rules using generic word anchors
- Replace with provider-specific prefixes where possible
- Use keyword constraints as secondary filter, not anchor

#### 2. Add Two-Phase Confirmation for Broad Anchors

**Problem:** Rules with generic anchors trigger expensive regex on every hit

**Solution:** Add cheap confirmation check before expensive regex

**Example:**
```rust
// Before: anchor hit → immediate regex
// After:  anchor hit → cheap check → regex only if confirmed

fn validate_candidate(window: &[u8], rule: &Rule) -> bool {
    // Seed confirmation: cheap format hint
    if !has_required_format_hint(window, rule) {
        return false;  // Skip expensive regex
    }

    // Full regex (only if seed confirmation passes)
    rule.regex.is_match(window)
}
```

**Expected gain:** 3-5× on noisy data

**Implementation:**
- Identify rules with high false-positive anchors
- Add format hints (e.g., "=" after key, specific delimiters)
- Gate expensive regex behind cheap memmem check

### Medium Impact

#### 3. Normalize Anchor Lengths

**Problem:** Variable anchor lengths (3-34 chars) increase Vectorscan complexity

**Solution:** Standardize anchors to 4-8 character literals

**Example:**
```
Before: anchors = ["sk", "SK", "sk_live_", "secret_key_..."]
After:  anchors = ["sk_l", "SK_L"]  // Normalized 4-char
```

**Expected gain:** 3-6× on clean data

**Implementation:**
- Extend short anchors (2-3 chars) to 4+ chars
- Truncate very long anchors to 8 chars with confirmation
- Remove case-insensitivity where possible (use explicit variants)

#### 4. Consolidate Rules with Shared Anchors

**Problem:** Multiple rules trigger separate validation for same anchor

**Solution:** Group rules by anchor, share validation work

**Example:**
```
// Before: 10 Twitter rules × 10 anchor hits = 100 validations
// After:  1 Twitter group × 10 anchor hits = 10 validations

anchors["twitter"] → [twitter_rule_1, twitter_rule_2, ...]
```

**Expected gain:** 1.5-2× overall

**Implementation:**
- Group rules by primary anchor
- Share window formation and keyword checks
- Run rule-specific regex only within group

### Lower Priority

#### 5. Tier Rules by Anchor Quality

**Solution:** Fast path for selective anchors, slow path for generic

```rust
enum AnchorTier {
    Selective,  // AKIA, ghp_, sk_live_ → fast path
    Generic,    // secret, token, password → slow path with confirmation
}
```

**Expected gain:** 1.2-1.5× overall

**Trade-off:** Adds complexity, marginal improvement

---

## Benchmark Command Reference

### Full Benchmark Suite

```bash
# All benchmarks
cargo bench

# Specific benchmark groups
cargo bench --bench gitleaks_scaling
cargo bench --bench prefilter_tradeoffs
cargo bench --bench validation_cost_breakdown
cargo bench --bench regex_complexity_isolation
```

### Layer Isolation Benchmarks

```bash
# Raw Vectorscan throughput (no validation)
cargo bench --bench prefilter_simplification -- "raw_vs"

# Validation pipeline stages
cargo bench --bench validation_cost_breakdown -- "pipeline_stages"

# Rule count scaling
cargo bench --bench gitleaks_scaling -- "rule_count"
```

### Workload-Specific Tests

```bash
# Clean data (baseline)
cargo bench --bench prefilter_tradeoffs -- "clean"

# Anchor-heavy data (stress validation)
cargo bench --bench prefilter_tradeoffs -- "anchor_flood"

# Realistic source code patterns
cargo bench --bench prefilter_tradeoffs -- "realistic"
```

### Rule Profiling

```bash
# Per-rule profiling on real repositories
cargo run --bin bench_repos --features rule-profile -- \
    --profile-rules --profile-top 50

# With specific root directory
cargo run --bin bench_repos --features rule-profile -- \
    --root /path/to/repos --profile-rules
```

---

## Verification Checklist

Benchmarks implemented and validated:

- [x] `benches/regex_complexity_isolation.rs` - Isolates regex cost
- [x] `benches/gitleaks_scaling.rs` - Rule count scaling
- [x] `benches/prefilter_simplification.rs` - Anchor normalization impact
- [x] `benches/validation_cost_breakdown.rs` - Pipeline stage costs

---

## Future Investigation

### Immediate

1. **Identify "hot" anchors** - Which generic words cause most false candidates?
   - Add per-anchor hit counters to profiling harness
   - Rank anchors by hit rate on realistic corpus

2. **Prototype two-phase confirmation** - Test on top 10 noisiest rules
   - Measure validation skip rate
   - Verify no false negatives introduced

### Medium Term

3. **Measure anchor hit rates** - Profile on real-world corpus
   - Use production scan data if available
   - Identify workload-specific tuning opportunities

4. **Evaluate anchor normalization** - Impact on detection accuracy
   - Compare detection rates before/after normalization
   - Quantify false negative risk

### Long Term

5. **Alternative prefilter architectures**
   - Evaluate SIMD-accelerated literal matching as first pass
   - Consider rule tiering by detection value

---

## Summary

| Bottleneck | Workload | Root Cause | Primary Fix | Expected Gain |
|------------|----------|------------|-------------|---------------|
| Vectorscan complexity | Clean data | Anchor diversity | Normalize lengths | 3-6× |
| Validation cost | Realistic data | Generic anchors | Two-phase confirmation | 3-5× |
| Rule count cliff | Both | Automaton explosion | Consolidate/tier rules | 2-3× |

**Key insight:** The 98% gap from simple rules to gitleaks is not a single bottleneck—it's two distinct problems requiring different solutions depending on workload characteristics.
