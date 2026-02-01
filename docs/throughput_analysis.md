# Scanner Throughput Analysis

## Current Performance Summary (Post-Optimization)

| Layer                             | Data Type | Throughput     | vs Theoretical Max |
| --------------------------------- | --------- | -------------- | ------------------ |
| **L1: memchr (ceiling)**          | ASCII     | **54.6 GiB/s** | 100% (baseline)    |
| **L1: memchr (ceiling)**          | Random    | **54.3 GiB/s** | 100% (baseline)    |
| **L2: Minimal Engine (1 rule)**   | ASCII     | **29.8 GiB/s** | 55% of memchr      |
| **L2: Minimal Engine (1 rule)**   | Random    | **29.7 GiB/s** | 55% of memchr      |
| **L2: Simple 50 Rules**           | ASCII     | **21.4 GiB/s** | 39% of memchr      |
| **L3: Full Gitleaks (223 rules)** | ASCII     | **489 MiB/s**  | 0.9% of memchr     |
| **L3: Full Gitleaks (223 rules)** | Random    | **170 MiB/s**  | 0.3% of memchr     |
| **L3: Full Gitleaks (223 rules)** | Realistic | **296 MiB/s**  | 0.5% of memchr     |

## Performance Gap Analysis

```
Throughput Stack (4 MiB buffer, ASCII data):

memchr ceiling:     ████████████████████████████████████████████████████████  54.6 GiB/s (100%)
                                          │
                                          │ -45% (Vectorscan automaton overhead)
                                          ▼
Minimal engine:     █████████████████████████████████                         29.8 GiB/s (55%)
                                          │
                                          │ -28% (Rule count, anchor diversity)
                                          ▼
50 simple rules:    ██████████████████████                                    21.4 GiB/s (39%)
                                          │
                                          │ -98% (Complex regexes, entropy, validators)
                                          ▼
Full gitleaks:      █                                                          0.5 GiB/s (0.9%)
```

## Where Is the Time Going?

### Gap 1: memchr → Minimal Vectorscan (-45%)

**Cause:** Vectorscan automaton overhead

- memchr uses hand-optimized SIMD for single-byte search
- Vectorscan builds a DFA/NFA for pattern matching
- Even with "impossible" patterns, the automaton traversal has overhead
- FFI boundary crossing (Rust → C)

**Optimization potential:** Limited

- This is fundamental Vectorscan overhead
- Could potentially be reduced with different Vectorscan flags/modes
- Alternative: Use memchr as first-pass filter for very common anchors

### Gap 2: Minimal → 50 Simple Rules (-28%)

**Cause:** Automaton complexity scales with pattern diversity

- More patterns = larger automaton state space
- Cache pressure from larger DFA tables
- More potential match candidates to track

**Optimization potential:** Moderate

- Already seen: prefix grouping helps (gl*, gh*, xox\*)
- Diminishing returns after anchor optimization

### Gap 3: 50 Simple Rules → Full Gitleaks (-98%)

**THIS IS THE BIGGEST BOTTLENECK**

**Causes:**

1. **Complex regex validation** - Each anchor hit triggers regex evaluation
   - Gitleaks regexes are complex with alternations, lazy quantifiers
   - Many regexes are 50-100+ chars with multiple capture groups
2. **Entropy calculation** - Many rules have entropy requirements
   - Requires scanning the matched region byte-by-byte
   - Computing Shannon entropy is O(n) per match
3. **Keyword checks** - `keywords_any` field triggers substring searches
4. **Anchor hit rate** - Gitleaks anchors hit frequently
   - Generic keywords (twitter, discord, etc.) appear in normal text
   - Short anchors (ey, sk) match frequently
   - Each hit = expensive validation path

5. **13 unfilterable rules** - Rules with no good anchor
   - Must scan entire buffer with regex
   - Extremely expensive

## Post-Optimization Improvements

### JWT Anchor (ey → eyJ): ✅ Implemented

- **Before:** 8.4 GiB/s on JWT-heavy data
- **After:** 20.4 GiB/s on JWT-heavy data
- **Improvement:** 2.4×

### Vault Token Split (s. → hvs. + two-phase): ✅ Implemented

- Eliminates noise from decimals/abbreviations
- Legacy tokens require "vault" keyword context

### Full Engine Improvement

- **Before optimization:** ~455 MiB/s (ASCII), ~164 MiB/s (random)
- **After optimization:** ~489 MiB/s (ASCII), ~170 MiB/s (random)
- **Improvement:** ~7-9%

## Understanding "Unfilterable" Rules

The engine reports 13 rules as "unfilterable" with `OnlyWeakAnchors`. This is a **diagnostic label**, not a functional problem:

**What "unfilterable" means:**

- The regex pattern cannot derive anchors ≥3 chars via automated analysis
- The rule still works - it falls back to manual anchors specified in `RuleSpec`

**Why these rules are marked unfilterable:**

| Category                                | Rules                                                                                          | Reason                                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Short literal prefix**                | twilio-api-key (`SK`), azure-ad-client-secret (`Q~`)                                           | 2-char prefix < min_anchor_len=3                                                                |
| **Keyword-based patterns**              | facebook-access-token, generic-api-key, hashicorp-tf-password, jfrog-\*, kraken, snyk, nytimes | Pattern `[\w.-]{0,50}?(?:keyword)` has optional prefix making keyword not strictly required     |
| **Two-phase patterns**                  | vault-service-token-legacy                                                                     | Uses `s.` confirm anchor (2 chars)                                                              |
| **Good regex but labeled unfilterable** | grafana-service-account-token, sourcegraph-access-token                                        | Regex derives good anchors (`glsa_`, `sgp_`) but something in the rule config triggers fallback |

**Fixes applied:**

- **twilio-api-key:** Extended `SK` → `SK[0-9a-fA-F]` (22 three-char anchors)
- **azure-ad-client-secret:** Extended `Q~` → `[0-9]Q~` (10 three-char anchors)

**No fix needed for keyword-based rules:**

- These rules use keyword anchors (facebook, jfrog, etc.) which ARE ≥3 chars
- The "unfilterable" label just means regex derivation failed, not that the rule is broken

## Remaining Optimization Opportunities

### High Impact (Would require significant changes)

1. **Simplify gitleaks regexes** - Many are overly complex
   - Remove lazy quantifiers (`{0,50}?`) where possible
   - Simplify alternations
   - Use possessive quantifiers where supported
   - **Estimated impact:** 2-5× improvement on validation phase

2. **Prefilter vs Full Regex Architecture**
   - Currently: Full regex compiled into Vectorscan with `HS_FLAG_PREFILTER`
   - Potential: Use simpler literal anchors for Vectorscan, run full regex only on candidates
   - **Estimated impact:** Could approach the 21 GiB/s "50 simple rules" baseline

3. **Lazy entropy calculation** - Only compute when needed
   - Skip entropy for high-confidence matches
   - Use approximate entropy first, full computation only if close
   - **Estimated impact:** 1.2-1.5× improvement

### Medium Impact

4. **More anchor extensions** - Several short anchors remain
   - `A3-` (3 chars) for 1password
   - `sk`/`SK` for Twilio (intentionally kept for broad detection)
   - AWS anchors (a3t, akia, etc.) are already good

5. **Keyword anchor deduplication**
   - 10× `twitter`/`TWITTER` anchors
   - 6× `discord`, `dropbox`, `mailgun`, etc.
   - Consolidation showed only 6-7% improvement (diminishing returns)

### Low Impact (Diminishing Returns)

6. **UTF-16 scanning** - Already optimized
   - Distinctive byte patterns make UTF-16 actually faster

7. **Rule count reduction** - Minimal impact
   - 1-250 rules showed <5% throughput difference
   - Pattern structure matters more than count

## New Experiments (2026-01-30)

We added a focused benchmark (`benches/prefilter_tradeoffs.rs`) and a new tuning
knob (`raw_prefilter_mode`) to separate **prefilter cost** from **validation
cost**.

### Hypotheses to Test

1. **Regex complexity dominates clean-data throughput**
   - Run `prefilter/clean` in `prefilter_tradeoffs`
   - Compare simple vs complex regexes across rule counts
   - Expect larger deltas from complexity than from count

2. **Anchor hit rate drives validation cost**
   - Run `validation/anchor_flood`
   - Expect throughput to drop sharply when anchor density is high

3. **Anchors-only prefilter recovers throughput when anchors are selective**
   - Compare `RegexAndAnchors` vs `AnchorsOnlyForAnchoredRules` in
     `prefilter/mode_comparison`
   - Repeat on `gitleaks_derived_*` to see impact on the real rule set

### Suggested Tuning for Isolation

Use these tuning settings for apples-to-apples comparisons:

- `max_transform_depth = 0` (disable transforms)
- `scan_utf16_variants = false` (raw-only)
- `raw_prefilter_mode = AnchorsOnlyForAnchoredRules` (experimental toggle)

`raw_prefilter_mode` is **experimental**: it skips raw regex prefilters for
anchored rules and relies on anchor selectivity. Unanchored rules still use
regex prefilters to avoid false negatives.

### Prefilter Tradeoffs Results (this machine)

All results are from `cargo bench --bench prefilter_tradeoffs` on a 4 MiB buffer.
These numbers will vary by hardware but the relative trends should hold.

**Clean data (no anchor hits):**

| Rule Set | 1 rule | 10 rules | 50 rules | 200 rules |
| --- | --- | --- | --- | --- |
| Simple regex | 14.9 GiB/s | 12.6 GiB/s | 12.8 GiB/s | 12.7 GiB/s |
| Complex regex | 12.6 GiB/s | 9.3 GiB/s | 4.3 GiB/s | 4.2 GiB/s |

**Anchor-flood data (high hit rate, no true matches):**

| Rule Set | 10 rules | 50 rules | 200 rules |
| --- | --- | --- | --- |
| Simple regex | 3.6 GiB/s | 2.4 GiB/s | 2.4 GiB/s |
| Complex regex | 0.88 GiB/s | 0.80 GiB/s | 0.79 GiB/s |

**Prefilter mode comparison (clean data):**

| Configuration | Throughput |
| --- | --- |
| Synthetic 200 complex, regex+anchors | 4.39 GiB/s |
| Synthetic 200 complex, anchor-only | 13.15 GiB/s |
| Gitleaks derived, regex+anchors | 443 MiB/s |
| Gitleaks derived, anchor-only | 288 MiB/s |

**Takeaway:**
- Complex regex prefiltering is a real cost on clean data.
- The full gitleaks suite is dominated by **validation cost under high anchor hit rates**.
- Raw regex prefiltering *helps* gitleaks by reducing candidate volume; anchor-only hurts.

### Repo Profiling Harness

For per-rule profiling across real repositories, use:

```bash
cargo run --bin bench_repos --features rule-profile -- --profile-rules --profile-top 50
```

Notes:
- The harness skips `.git` (and other common build dirs) via `should_skip_dir`.
- Use `--root <path>` to point at the parent directory containing repos.

### Repo Profiling Results (2026-01-30)

Profile run: `bench_repos --profile-rules` across 29 sibling repos under
`/Users/ahrav/Projects` (default root). Overall throughput was ~44 MiB/s.

Top offenders by total validation time:

| Rank | Rule | Time (ms) | Windows in | Matches |
| --- | --- | ---: | ---: | ---: |
| 1 | `generic-api-key` | 1606 | 8861 | 72350 |
| 2 | `private-key` | 62 | 66 | 1727 |
| 3 | `sourcegraph-access-token` | 49 | 893 | 30695 |
| 4 | `jwt` | 7 | 41 | 2131 |
| 5 | `facebook-page-access-token` | 7 | 20 | 32 |

Early takeaway: **`generic-api-key` dominates**. It has a very high window and
match count relative to other rules, making it the first candidate for anchor
and regex simplification.

### Repo Profiling Results (Derived Anchors)

Profile run: `bench_repos --anchors=derived --profile-rules` across 26 sibling
repos under `/Users/ahrav/Projects` (default root). Overall throughput was
~44 MiB/s.

Top offenders by total validation time:

| Rank | Rule | Time (ms) | Windows in | Matches |
| --- | --- | ---: | ---: | ---: |
| 1 | `generic-api-key` | 1521 | 8841 | 72302 |
| 2 | `private-key` | 62 | 63 | 1724 |
| 3 | `sourcegraph-access-token` | 48 | 891 | 30695 |
| 4 | `jwt` | 7 | 41 | 2131 |
| 5 | `facebook-page-access-token` | 7 | 20 | 32 |

Derived vs manual results are effectively the same for the top offenders, which
reinforces that **validation cost + hit rate** (not anchor derivation policy)
is the primary bottleneck in real repos.

## Recommended Next Steps

### Priority 1: Investigate Unfilterable Rules

```
13 rules have no good anchor and require full-buffer regex scans.
Identify these rules and see if better anchors can be derived.
```

### Priority 2: Profile Regex Validation

```
The 98% gap between simple rules and gitleaks is mostly regex/entropy cost.
Profile to identify the most expensive regexes and simplify them.
```

### Priority 3: Lazy Evaluation

```
Add early-exit paths for obvious non-matches.
Skip expensive entropy calculation when other checks fail.
```

## Throughput Targets (Revised)

| Scenario       | Current   | Realistic Target | Stretch Goal |
| -------------- | --------- | ---------------- | ------------ |
| Clean ASCII    | 489 MiB/s | 1-2 GiB/s        | 5 GiB/s      |
| Random data    | 170 MiB/s | 500 MiB/s        | 1 GiB/s      |
| Realistic code | 296 MiB/s | 800 MiB/s        | 2 GiB/s      |

Reaching 5+ GiB/s would require fundamental changes to either:

- The gitleaks rule complexity
- The validation pipeline architecture
- Or both

## Related Documentation

For detailed root cause analysis and actionable recommendations, see:
- [Throughput Bottleneck Analysis](./throughput_bottleneck_analysis.md) - Deep dive into the two primary bottlenecks (Vectorscan complexity vs validation cost) with benchmark evidence and fix strategies
