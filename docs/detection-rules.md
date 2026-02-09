# Detection Rules

Representative view of the current built-in detection rules used by scanner-rs.

## Source of Truth

- [default_rules.yaml](../default_rules.yaml)
- [src/rules/yaml.rs](../src/rules/yaml.rs)
- [src/rules/mod.rs](../src/rules/mod.rs)
- [src/demo.rs](../src/demo.rs)
- [src/unified/orchestrator.rs](../src/unified/orchestrator.rs)

## Current Snapshot

The values below are from the current repository snapshot:

- Built-in rules: `223`
- `two_phase` enabled: `2` rules (`private-key`, `vault-service-token-legacy`)
- `entropy` enabled: `131` rules
- `local_context` enabled: `1` rule (`generic-api-key`)
- `value_suppressors_any` enabled: `0` rules
- `secret_group` enabled: `2` rules (`microsoft-teams-webhook`, `sonar-api-token`)
- `must_contain` enabled: `0` rules
- `keywords_any` enabled: `223` rules

Rule loading order:

1. Explicit `--rules=<path>`
2. `default_rules.yaml` next to the scanner binary
3. Compiled-in fallback (`include_str!("../../default_rules.yaml")`)

## Rule Families (Representative Only)

Categories in this document are organizational only. The YAML schema does not
contain a category field.

```mermaid
mindmap
    root((Detection Rules))
        Cloud
            aws-access-token
                Anchors: A3T, AKIA, ASIA, ABIA, ACCA
                Radius: 256 bytes
                Pattern: (?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}
        Source Control
            github-pat
                Anchor: ghp_
                Radius: 256 bytes
            github-oauth
                Anchor: gho_
                Radius: 256 bytes
            github-app-token
                Anchors: ghu_, ghs_
                Radius: 256 bytes
            gitlab-pat
                Anchor: glpat-
                Radius: 256 bytes
        Communication
            slack-bot-token
                Anchor: xoxb
                Radius: 2048 bytes
            slack-webhook-url
                Anchor: hooks.slack.com
                Radius: 256 bytes
        Payment
            stripe-access-token
                Anchors: sk_test, sk_live, sk_prod, rk_test, rk_live, rk_prod
                Radius: 256 bytes
        Data Platforms
            databricks-api-token
                Anchor: dapi
                Radius: 256 bytes
        Package Managers
            npm-access-token
                Anchors: npm_, NPM_
                Radius: 256 bytes
        Cryptographic
            private-key
                Anchors: -----begin, -----BEGIN
                Two-Phase: Yes
                Seed: 256 bytes
                Full: 16KB
            vault-service-token-legacy
                Anchors: vault, VAULT, Vault
                Two-Phase: Yes
                Seed: 128 bytes
                Full: 512 bytes
```

## Rule Table (Representative)

| Rule Name | Category (doc-only) | Anchors | Radius | Two-Phase | Notes |
|-----------|---------------------|---------|--------|-----------|-------|
| `aws-access-token` | Cloud | A3T, AKIA, ASIA, ABIA, ACCA | 256 | No | AWS access key id variants |
| `github-pat` | Source Control | ghp_ | 256 | No | GitHub personal access token |
| `github-oauth` | Source Control | gho_ | 256 | No | GitHub OAuth token |
| `github-app-token` | Source Control | ghu_, ghs_ | 256 | No | GitHub app token |
| `gitlab-pat` | Source Control | glpat- | 256 | No | GitLab personal access token |
| `slack-bot-token` | Communication | xoxb | 2048 | No | Slack bot token |
| `slack-webhook-url` | Communication | hooks.slack.com | 256 | No | Slack incoming webhook URL |
| `stripe-access-token` | Payment | sk_test, sk_live, sk_prod, rk_test, rk_live, rk_prod | 256 | No | Stripe API token |
| `sendgrid-api-token` | Email | SG. | 256 | No | SendGrid API token |
| `npm-access-token` | Package Managers | npm_, NPM_ | 256 | No | npm token |
| `databricks-api-token` | Data Platforms | dapi | 256 | No | Databricks PAT |
| `private-key` | Cryptographic | -----begin, -----BEGIN | 0 | Yes (`256`/`16384`) | PEM private key |
| `vault-service-token-legacy` | Secrets Management | vault, VAULT, Vault | 512 | Yes (`128`/`512`) | Legacy Vault service token |

## Rule Anatomy

```mermaid
graph TB
    subgraph RuleSpec["RuleSpec"]
        Name["name: &'static str"]
        Anchors["anchors: &'static [&'static [u8]]"]
        Radius["radius: usize"]
        Validator["validator: ValidatorKind"]
        TwoPhase["two_phase: Option<TwoPhaseSpec>"]
        MustContain["must_contain: Option<&'static [u8]>"]
        KeywordsAny["keywords_any: Option<&'static [&'static [u8]]>"]
        ValueSuppressorsAny["value_suppressors_any: Option<&'static [&'static [u8]]>"]
        Entropy["entropy: Option<EntropySpec>"]
        LocalContext["local_context: Option<LocalContextSpec>"]
        SecretGroup["secret_group: Option<u16>"]
        Regex["re: Regex"]
    end

    subgraph TwoPhaseSpec["TwoPhaseSpec (optional)"]
        SeedRadius["seed_radius: usize"]
        FullRadius["full_radius: usize"]
        ConfirmAny["confirm_any: &'static [&'static [u8]]"]
    end

    subgraph EntropySpec["EntropySpec (optional)"]
        MinBpb["min_bits_per_byte: f32"]
        MinLen["min_len: usize"]
        MaxLen["max_len: usize"]
    end

    subgraph LocalContextSpec["LocalContextSpec (optional)"]
        Lookbehind["lookbehind: usize"]
        Lookahead["lookahead: usize"]
        SameLine["require_same_line_assignment: bool"]
        Quoted["require_quoted: bool"]
        KeyNames["key_names_any: Option<&'static [&'static [u8]]>"]
    end
```

`ValidatorKind` is intentionally not part of the YAML schema today. YAML-loaded
rules default to `ValidatorKind::None`.

## Two-Phase Detection

Current two-phase rules:

| Rule | Seed Radius | Full Radius | Confirm Literals |
|------|-------------|-------------|------------------|
| `private-key` | 256 | 16384 | `PRIVATE KEY` |
| `vault-service-token-legacy` | 128 | 512 | `s.` |

```mermaid
sequenceDiagram
    participant VS as Vectorscan
    participant Seed as Seed Window
    participant Confirm as confirm_any check
    participant Full as Expanded Window
    participant Regex as Regex

    VS->>Seed: Anchor hit seeds initial window
    Seed->>Confirm: Search confirm_any literals
    alt Confirmed
        Confirm->>Full: Expand to full_radius
        Full->>Regex: Validate full pattern
        Regex-->>Output: FindingRec
    else Not confirmed
        Confirm--xSeed: Drop candidate
    end
```

## Anchor Variants

Each anchor is compiled into three byte variants for matching:

```mermaid
graph LR
    subgraph Variants["Anchor: ghp_"]
        Raw["Raw: ghp_"]
        LE["UTF-16LE: g\\0h\\0p\\0_\\0"]
        BE["UTF-16BE: \\0g\\0h\\0p\\0_"]
    end
```

This allows the same rule to detect plain ASCII and UTF-16 encoded content.

## Why Anchors and Radii Matter

Anchors are the primary cost-control mechanism. Regex validation only runs in
windows around anchor hits.

- Too small radius: can miss valid matches
- Too large radius: increases regex cost on noisy inputs

Current radius distribution is heavily centered at `256` bytes (`202` of `223`
rules), with targeted outliers for long/noisy formats.

## Transform Detection

Demo transforms (from `src/demo.rs`) decode:

- URL percent-encoding
- Base64

Both use decoded-anchor gating (`Gate::AnchorsInDecoded`) to limit unnecessary
secondary scans.

## Regex Patterns (Representative, Exact)

| Rule | Pattern |
|------|---------|
| `aws-access-token` | `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b` |
| `github-pat` | `ghp_[0-9a-zA-Z]{36}` |
| `gitlab-pat` | `glpat-[\w-]{20}` |
| `slack-webhook-url` | `(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}` |
| `stripe-access-token` | `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)` |
| `sendgrid-api-token` | `\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]|\\[nr]|$)` |
| `npm-access-token` | `(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)` |
| `databricks-api-token` | `\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)` |
| `private-key` | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----` |

## Adding New Rules

Built-in rule changes are made in `default_rules.yaml` (not in `demo_engine()`,
which now just returns `builtin_rules()`).

YAML template:

```yaml
rules:
- name: my-new-token
  regex: \b(mytok_[A-Za-z0-9]{32})\b
  anchors:
  - mytok_
  radius: 256
  must_contain: null
  keywords_any:
  - mytok_
  value_suppressors_any: null
  entropy: null
  two_phase: null
  local_context: null
  secret_group: null
```

Guidelines:

1. Use distinctive anchors to reduce noisy windows.
2. Set radius to cover expected anchor-to-secret distance.
3. Use `two_phase` only when anchors are noisy.
4. Keep `keywords_any` aligned with reliable context tokens.
5. Use `value_suppressors_any` to suppress known placeholder or example values
   (e.g., `EXAMPLE`, `DUMMY_TOKEN`) that regex and entropy cannot distinguish
   from real secrets. Patterns are case-sensitive and matched on extracted secret bytes.
6. Set `secret_group` when the secret is not the full match.
6. Derived anchors are enabled by default (`AnchorPolicy::PreferDerived`) and
   may produce a compiled `confirm_all` gate from regex literal islands.
