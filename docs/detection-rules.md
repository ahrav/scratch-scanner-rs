# Detection Rules

Mind map of rule coverage in scanner-rs's `demo_engine()`.

```mermaid
mindmap
    root((Detection Rules))
        Cloud
            AWS
                aws-access-token
                    Anchors: A3T, AKIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA, ASIA
                    Radius: 64 bytes
                    Pattern: [A3T[A-Z0-9]|AKIA|...])[A-Z0-9]{16}
        Source Control
            GitHub
                github-pat
                    Anchor: ghp_
                    Radius: 96 bytes
                    Pattern: ghp_[0-9a-zA-Z]{36}
                github-oauth
                    Anchor: gho_
                    Radius: 96 bytes
                    Pattern: gho_[0-9a-zA-Z]{36}
                github-app-token
                    Anchors: ghu_, ghs_
                    Radius: 96 bytes
                    Pattern: [ghu|ghs]_[0-9a-zA-Z]{36}
            GitLab
                gitlab-pat
                    Anchor: glpat-
                    Radius: 64 bytes
                    Pattern: glpat-[0-9a-zA-Z\\-\\_]{20}
        Communication
            Slack
                slack-access-token
                    Anchors: xoxb-, xoxa-, xoxp-, xoxr-, xoxs-
                    Radius: 96 bytes
                    Pattern: xox[baprs]-[0-9a-zA-Z]{10,48}
                slack-web-hook
                    Anchor: hooks.slack.com/services/
                    Radius: 160 bytes
                    Pattern: https://hooks.slack.com/services/[A-Za-z0-9+/]{44,46}
        Payment
            Stripe
                stripe-access-token
                    Anchors: sk_test_, sk_live_, pk_test_, pk_live_
                    Radius: 96 bytes
                    Pattern: [sk|pk]_[test|live]_[0-9a-z]{10,32}
        Email
            SendGrid
                sendgrid-api-token
                    Anchors: SG., sg.
                    Radius: 128 bytes
                    Pattern: SG\\.[a-z0-9=_\\-\\.]{66}
        Package Managers
            npm
                npm-access-token
                    Anchor: npm_
                    Radius: 96 bytes
                    Pattern: npm_[a-z0-9]{36}
        Data Platforms
            Databricks
                databricks-api-token
                    Anchors: dapi, DAPI
                    Radius: 96 bytes
                    Pattern: dapi[a-h0-9]{32}
        Cryptographic
            Private Keys
                private-key
                    Anchor: -----BEGIN
                    Two-Phase: Yes
                    Seed: 256 bytes
                    Full: 16KB
                    Confirm: PRIVATE KEY
                    Pattern: -----BEGIN...PRIVATE KEY-----...-----END...PRIVATE KEY-----
```

## Rule Table

| Rule Name | Category | Anchors | Radius | Two-Phase | Notes |
|-----------|----------|---------|--------|-----------|-------|
| `aws-access-token` | Cloud | A3T, AKIA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA, ASIA | 64 | No | Standard AWS access key prefixes |
| `github-pat` | Source Control | ghp_ | 96 | No | GitHub personal access tokens |
| `github-oauth` | Source Control | gho_ | 96 | No | GitHub OAuth tokens |
| `github-app-token` | Source Control | ghu_, ghs_ | 96 | No | GitHub App installation tokens |
| `gitlab-pat` | Source Control | glpat- | 64 | No | GitLab personal access tokens |
| `slack-access-token` | Communication | xoxb-, xoxa-, xoxp-, xoxr-, xoxs- | 96 | No | Slack bot/user tokens |
| `slack-web-hook` | Communication | hooks.slack.com/services/ | 160 | No | Slack incoming webhooks |
| `stripe-access-token` | Payment | sk_test_, sk_live_, pk_test_, pk_live_ | 96 | No | Stripe API keys |
| `sendgrid-api-token` | Email | SG., sg. | 128 | No | SendGrid API tokens |
| `npm-access-token` | Package Managers | npm_ | 96 | No | npm authentication tokens |
| `databricks-api-token` | Data Platforms | dapi, DAPI | 96 | No | Databricks personal access tokens |
| `private-key` | Cryptographic | -----BEGIN | seed=256, full=16KB | Yes | PEM-encoded private keys |

## Rule Anatomy

```mermaid
graph TB
    subgraph RuleSpec["RuleSpec Structure"]
        Name["name: &'static str"]
        Anchors["anchors: &'static [&'static [u8]]"]
        Radius["radius: usize"]
        TwoPhase["two_phase: Option&lt;TwoPhaseSpec&gt;"]
        MustContain["must_contain: Option&lt;&'static [u8]&gt;"]
        Regex["re: Regex"]
    end

    subgraph TwoPhaseSpec["TwoPhaseSpec (optional)"]
        SeedRadius["seed_radius: usize"]
        FullRadius["full_radius: usize"]
        ConfirmAny["confirm_any: &'static [&'static [u8]]"]
    end

    TwoPhase --> TwoPhaseSpec

    style RuleSpec fill:#e3f2fd
    style TwoPhaseSpec fill:#fff3e0
```

## Two-Phase Detection (Private Keys)

```mermaid
sequenceDiagram
    participant AC as AhoCorasick
    participant Seed as Seed Window (256B)
    participant Confirm as Confirmation
    participant Full as Full Window (16KB)
    participant Regex as Regex

    Note over AC: Anchor "-----BEGIN" found at offset 1000
    AC->>Seed: Extract bytes 1000-256..1000+256

    Seed->>Confirm: Search for "PRIVATE KEY"
    alt Found
        Confirm->>Full: Expand to bytes 1000-16KB..1000+16KB
        Full->>Regex: Match BEGIN...END block
        alt Regex matches
            Regex-->>Output: FindingRec
        end
    else Not found
        Confirm--xSeed: Skip (false positive)
    end
```

**Why two-phase?**
- `-----BEGIN` is a common header (certificates, public keys, etc.)
- Only `-----BEGIN ... PRIVATE KEY-----` is sensitive
- Seed window (256B) quickly confirms before expensive 16KB regex

## Anchor Variants

Each anchor is compiled into three variants for detection:

```mermaid
graph LR
    subgraph Variants["Anchor: ghp_"]
        Raw["Raw: ghp_<br/>(4 bytes)"]
        LE["UTF-16LE: g\\0h\\0p\\0_\\0<br/>(8 bytes)"]
        BE["UTF-16BE: \\0g\\0h\\0p\\0_<br/>(8 bytes)"]
    end

    AC["AhoCorasick<br/>Automaton"] --> Raw
    AC --> LE
    AC --> BE

    style Variants fill:#e8f5e9
```

This enables detection in:
- Plain text files (Raw)
- UTF-16LE encoded files (Windows default)
- UTF-16BE encoded files (some network protocols)

## Transform Detection

Secrets may be encoded. The demo engine handles:

```mermaid
graph TB
    subgraph Encoding["Encoded Secret"]
        Original["ghp_abc123...xyz"]
        URLEnc["ghp%5Fabc123...xyz"]
        B64Enc["Z2hwX2FiYzEyMy4uLnh5eg=="]
    end

    subgraph Detection["Detection Flow"]
        URL["URL Percent Decode"]
        B64["Base64 Decode"]
        Scan["Anchor Scan"]
    end

    URLEnc --> URL
    B64Enc --> B64
    URL --> Scan
    B64 --> Scan
    Original --> Scan

    Scan --> |"ghp_ found"| Rule["github-pat rule"]

    style Encoding fill:#ffebee
    style Detection fill:#e8f5e9
```

## Regex Patterns

| Rule | Pattern | Notes |
|------|---------|-------|
| `aws-access-token` | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` | 20-char uppercase |
| `github-pat` | `ghp_[0-9a-zA-Z]{36}` | 40-char total |
| `github-oauth` | `gho_[0-9a-zA-Z]{36}` | 40-char total |
| `github-app-token` | `(ghu\|ghs)_[0-9a-zA-Z]{36}` | 40-char total |
| `gitlab-pat` | `glpat-[0-9a-zA-Z\-\_]{20}` | 26-char total |
| `slack-access-token` | `xox[baprs]-([0-9a-zA-Z]{10,48})` | Variable length |
| `slack-web-hook` | `https://hooks.slack.com/services/[A-Za-z0-9+/]{44,46}` | Full URL |
| `stripe-access-token` | `(?i)(sk\|pk)_(test\|live)_[0-9a-z]{10,32}` | Case insensitive |
| `sendgrid-api-token` | `(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})` | 69-char total |
| `npm-access-token` | `(?i)\b(npm_[a-z0-9]{36})` | 40-char total |
| `databricks-api-token` | `(?i)\b(dapi[a-h0-9]{32})` | 36-char total |
| `private-key` | `(?is)-----BEGIN...PRIVATE KEY-----.*?-----END...PRIVATE KEY-----` | Multi-line PEM |

## Adding New Rules

To add a new rule to `demo_engine()`:

```rust
RuleSpec {
    name: "my-new-token",
    // Unique byte sequences that appear in the token
    anchors: &[b"mytoken_"],
    // Search radius around anchor hits
    radius: 64,
    // Optional two-phase for noisy anchors
    two_phase: None,
    // Optional fast filter before regex
    must_contain: None,
    // Final validation regex
    re: Regex::new(r"mytoken_[a-z0-9]{32}").unwrap(),
}
```

Guidelines:
1. **Anchors**: Choose distinctive prefixes (4+ bytes)
2. **Radius**: 2x expected token length is usually safe
3. **Two-phase**: Use for anchors that appear in non-sensitive contexts
4. **must_contain**: Fast filter if token has additional required substrings
5. **Regex**: Should be anchored (no `.*` prefix) for performance
