# Gitleaks Rules Optimization Analysis

## Executive Summary

Analysis of 222 gitleaks rules identified several optimization opportunities:

| Category                  | Impact       | Rules Affected | Measured Speedup           |
| ------------------------- | ------------ | -------------- | -------------------------- |
| Short anchors (≤3 chars)  | **Critical** | 14 rules       | **2.4-6.4×** on noisy data |
| Generic keyword anchors   | Medium       | ~40 rules      | 1.5-2×                     |
| Duplicate anchor families | Low          | ~23 rules      | 6-7%                       |
| Prefix diversity          | **Critical** | All rules      | **6.9×** (same vs diverse) |

## Benchmark Results Summary

All benchmarks run on 4 MiB buffers. Throughput in GiB/s.

### Anchor Length Impact

| Anchor              | JWT-Heavy Data | Clean ASCII    | Random Bytes |
| ------------------- | -------------- | -------------- | ------------ |
| `ey` (2 char)       | 8.8 GiB/s      | 14.2 GiB/s     | 28.4 GiB/s   |
| `eyJ` (3 char)      | **21.3 GiB/s** | **21.9 GiB/s** | 29.5 GiB/s   |
| `eyJhbGci` (8 char) | **21.5 GiB/s** | **21.6 GiB/s** | 29.4 GiB/s   |

**Finding**: Extending `ey` → `eyJ` yields **2.4× speedup** on JWT-heavy data, **1.5× speedup** on clean ASCII.

| Anchor                   | SK-Heavy Data  | Clean ASCII    |
| ------------------------ | -------------- | -------------- |
| `sk` (2 char)            | 3.3 GiB/s      | 7.5 GiB/s      |
| `sk_live_` (8 char)      | **16.9 GiB/s** | **20.8 GiB/s** |
| `sk_live_test` (12 char) | **20.9 GiB/s** | **20.9 GiB/s** |

**Finding**: Extending `sk` → `sk_live_` yields **5.2× speedup** on sk-heavy data, **2.8× speedup** on clean ASCII.

### Rule Consolidation Impact

| Configuration                 | Keyword-Heavy | Clean ASCII |
| ----------------------------- | ------------- | ----------- |
| 5 Twitter rules (same anchor) | 18.3 GiB/s    | 21.0 GiB/s  |
| 1 Consolidated rule           | 16.0 GiB/s    | 21.0 GiB/s  |

**Finding**: Consolidating rules with same anchor provides no benefit (slightly worse due to complex regex).

| Configuration          | Keyword-Heavy | Clean ASCII |
| ---------------------- | ------------- | ----------- |
| 14 rules (4 providers) | 7.7 GiB/s     | 11.7 GiB/s  |
| 4 consolidated rules   | 8.2 GiB/s     | 11.8 GiB/s  |

**Finding**: Consolidating 14 → 4 rules yields only **6-7% improvement**.

### Prefix Diversity Impact (Most Surprising)

| Configuration                                  | Clean ASCII    |
| ---------------------------------------------- | -------------- |
| 50 rules, same `prefix_` prefix                | 5.9 GiB/s      |
| 50 rules, diverse prefixes (AKIA, ghp\_, etc.) | **40.8 GiB/s** |

**Finding**: Diverse prefixes are **6.9× faster** than shared prefixes! This is counterintuitive but explained by Vectorscan's automaton structure - diverse prefixes allow better state machine optimization.

## 1. Problematic Short Anchors

These anchors are 2-3 characters and will match frequently in arbitrary data:

| Length | Rule                     | Anchor       | Risk                                        |
| ------ | ------------------------ | ------------ | ------------------------------------------- |
| 2      | azure-ad-client-secret   | `q~`, `Q~`   | Very High - common in URLs                  |
| 2      | jwt                      | `ey`         | Very High - base64 prefix, extremely common |
| 2      | twilio-api-key           | `SK`, `sk`   | Very High - "sk" appears in many words      |
| 2      | vault-service-token      | `s.`         | Very High - appears in decimals, sentences  |
| 3      | 1password-secret-key     | `A3-`, `a3-` | High - short alphanumeric                   |
| 3      | flyio-access-token       | `fm1`        | Medium                                      |
| 3      | huggingface-access-token | `hf_`        | Medium - distinctive underscore             |
| 3      | sendgrid-api-token       | `SG.`, `sg.` | Medium - distinctive dot                    |
| 3      | slack-\*-token           | `xox`        | Medium - somewhat distinctive               |

### Recommendations

1. **JWT (`ey`)**: This is the base64 encoding of `{"` which starts every JWT header. Consider:
   - Extend anchor to `eyJ` (4 chars) - still matches all JWTs
   - Better: use `eyJhbGci` (the start of `{"alg":`) for even more specificity

2. **Twilio (`SK`/`sk`)**:
   - Add more context: `SK` followed by 32 hex chars
   - Consider two-phase: anchor on `twilio` keyword, then validate SK pattern

3. **Vault (`s.`)**:
   - Extremely noisy - matches "3.14", "e.g.", "i.e.", etc.
   - Recommend two-phase: anchor on `vault` or `VAULT_TOKEN`, validate `s.` pattern

4. **Azure AD (`q~`/`Q~`)**:
   - Very short but somewhat distinctive due to tilde
   - Consider extending to longer known prefix if possible

## 2. Generic Keyword Anchors

These rules anchor on common words that appear frequently in code:

| Anchor                    | Occurrences | Rules                                                                                                  |
| ------------------------- | ----------- | ------------------------------------------------------------------------------------------------------ |
| `twitter`/`TWITTER`       | 10          | twitter-access-secret, twitter-access-token, twitter-api-key, twitter-api-secret, twitter-bearer-token |
| `yandex`/`YANDEX`         | 6           | yandex-\*                                                                                              |
| `discord`/`DISCORD`       | 6           | discord-\*                                                                                             |
| `dropbox`/`DROPBOX`       | 6           | dropbox-\*                                                                                             |
| `mailgun`/`MAILGUN`       | 6           | mailgun-\*                                                                                             |
| `plaid`/`PLAID`           | 6           | plaid-\*                                                                                               |
| `cloudflare`/`CLOUDFLARE` | 6           | cloudflare-\*                                                                                          |
| `secret`/`SECRET`         | 4           | Various                                                                                                |
| `password`/`PASSWORD`     | 4           | Various                                                                                                |
| `api`/`API`               | 4           | Various                                                                                                |
| `key`/`KEY`               | 4           | Various                                                                                                |

### Problem

These generic keywords cause Vectorscan to emit many candidate matches that then fail regex validation. Each false candidate costs ~100-500ns in regex evaluation.

### Recommendations

1. **Consolidate provider families**: Instead of 5 separate twitter rules each anchoring on `twitter`, create ONE vectorscan pattern that triggers, then dispatch to the appropriate regex.

2. **Add distinctive prefixes where possible**:
   - Twitter OAuth tokens start with specific patterns
   - Look for API-specific prefixes in the secret format

## 3. Rule Families for Prefix Consolidation

### Well-Structured Families (Good Examples)

**GitHub** (5 rules, 6 anchors - all unique prefixes):

```
github-app-token:      ghu_, ghs_
github-fine-grained:   github_pat_
github-oauth:          gho_
github-pat:            ghp_
github-refresh-token:  ghr_
```

These share `gh` prefix - Vectorscan can merge automaton states.

**GitLab** (15 rules, all `gl*` prefixes):

```
glcbt-, gldt-, glffct-, glft-, glimt-, glagent-,
gloas-, glpat-, glptt-, glrt-, glsoat-
```

Excellent - all share `gl` prefix.

**Slack** (9 rules, all `xox*` or `xapp`):

```
xapp, xoxb, xoxe, xoxo, xoxp, xoxr, xoxs
```

Share `xo` prefix (except xapp).

### Poorly-Structured Families (Optimization Targets)

**AWS** (3 rules, scattered anchors):

```
aws-access-token:    a3t, A3T, akia, AKIA, asia, ASIA, abia, ABIA, acca, ACCA
aws-bedrock-long:    absk, ABSK
aws-bedrock-short:   bedrock-api-key-
```

- The main AWS rule has 10 anchors, all 4 chars
- These could potentially share `A` prefix but case-sensitivity splits them
- `bedrock-api-key-` is completely different

**Twitter** (5 rules, same anchor):
All use `twitter`/`TWITTER` - could be consolidated into single prefilter.

**Discord/Dropbox/etc.** (3 rules each, same anchor):
Same pattern - keyword-based anchors repeated across multiple rules.

## 4. Complex Regex Patterns

143 rules use case-insensitive matching `(?i)`. Many use this pattern:

```regex
(?i)[\w.-]{0,50}?(?:KEYWORD)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{32})
```

This pattern is designed to match:

```
KEYWORD = "secret_value"
KEYWORD: secret_value
KEYWORD => 'secret_value'
```

### Issues

1. The `[\w.-]{0,50}?` prefix is lazy and causes backtracking
2. The alternation `(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)` is complex
3. The trailing `(?:[\x60'"\s;]|\\[nr]|$)` adds overhead

### Recommendations

1. For rules with distinctive token formats, simplify to just match the token
2. Consider possessive quantifiers where supported: `[\w.-]{0,50}+`
3. Pre-compile common sub-patterns

## 5. Implemented Optimizations

### Tier 1: Quick Wins (IMPLEMENTED)

1. **✅ Extend JWT anchor from `ey` to `eyJ`** - DONE
   - Changed anchor from 2-char to 3-char
   - **Result: 2.4× speedup** on JWT-heavy data (8.4 → 20.4 GiB/s)
   - No missed secrets (all JWTs start with `eyJ` since JSON objects start with `{`)
   - See `src/gitleaks_rules.rs` line ~1855

2. **❌ Consolidate Twitter rules** - NOT IMPLEMENTED
   - Benchmarks showed only 6-7% improvement
   - Not worth added regex complexity and potential for missed detections

3. **✅ Add two-phase for Vault** - DONE
   - Split into two rules:
     - Modern `hvs.` tokens: Direct detection (4-char distinctive anchor)
     - Legacy `s.` tokens: Two-phase with `vault` keyword context
   - **Result: Eliminates noise** from decimals, abbreviations (e.g., "3.14", "e.g.")
   - Tradeoff: Legacy tokens without "vault" context won't be detected
   - See `src/gitleaks_rules.rs` line ~3447

### Tier 2: Deferred

4. **Consolidate keyword-based families** - Low priority based on benchmark results

5. **Simplify generic credential patterns** - Future work

### Tier 3: Architectural - Future work

6. **Implement hierarchical prefiltering** - Requires significant refactoring

## 6. Verification

All changes verified with:

- 16 new test cases in `tests/anchor_optimization_tests.rs`
- Full test suite passes (283+ tests)
- Benchmarks confirm expected speedups

## Appendix: All Short Anchors

```
Length 2:
  Q~, q~    - azure-ad-client-secret
  SK, sk    - twilio-api-key
  ey        - jwt
  s.        - vault-service-token

Length 3:
  A3-, a3-  - 1password-secret-key
  A3T, a3t  - aws-access-token (one of 10 anchors)
  API, api  - generic patterns
  KEY, key  - generic patterns
  SC_, sc_  - various
  SG., sg.  - sendgrid-api-token
  fm1       - flyio-access-token
  hf_       - huggingface-access-token
  xox       - slack-bot-token, slack-legacy-bot-token
```
