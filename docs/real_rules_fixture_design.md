# Real Ruleset Fixture Corpus Design

## Purpose

Define a robust, comprehensive fixture corpus for the real ruleset harness
(Mode 2). The harness lives or dies by the quality of these fixtures, so we
document our reasoning and a proposed fixture list *before* implementation.

This is separate from the synthetic engine stress harness.
See `scanner_harness_modes.md` and `real_rules_harness_plan.md`.

## Reference Patterns

We surveyed how other scanners validate rulesets:

- **Annotated fixtures** (Semgrep): fixtures embed `ruleid` / `ok` markers to
  assert expected matches and non-matches in-line with the test code.
- **Baseline snapshot** (detect-secrets): a baseline file captures expected
  findings and is updated explicitly when rules change.
- **Fixture repos** (TruffleHog): a public test repo (`test_keys`) is used as a
  stable corpus for verifying verified detections.
- **Project testdata** (Gitleaks): the upstream repo ships a `testdata/` tree
  (including archive examples) to exercise detection paths.

References are recorded here and in `real_rules_harness_plan.md`.

## Additional References (New)

To broaden our design inputs, we gathered more concrete examples of how
secret-scanning tools structure their test artifacts and expectations:

1. **TruffleHog documents scanning the public `test_keys` repository** as an
   example target. This is a strong precedent for a dedicated fixture repo or
   fixture directory used as a known-good target.
2. **Gitleaks documents archive scanning with `testdata/archives` examples**
   (including nested archives) and inner path reporting. This suggests
   fixtures should cover archive handling and nested path reporting.
3. **detect-secrets centers workflows around a baseline file** that snapshots
   expected findings and can be updated in place. This supports a baseline
   snapshot approach for our ruleset harness.
4. **Trivy documents built-in secret rule families and allow rules** that
   control false positives. This implies our fixture list should include both
   positive detections and near‑miss/allowlisted cases.
5. **git-secrets emphasizes allowed patterns** (to suppress false positives)
   and encourages users to test their patterns; this reinforces the need for
   explicit negative fixtures and allowlist coverage.

## Additional References (More)

To be more thorough, we looked at more concrete examples of fixture layouts,
golden outputs, and rule-family catalogs:

1. **[detect-secrets README](https://github.com/Yelp/detect-secrets) demonstrates
   scanning `test_data/` and writing a `.secrets.baseline`**, showing a baseline
   workflow coupled with a dedicated test data tree.
2. **[Trivy integration tests](https://fossies.org/linux/trivy/integration/repo_test.go)
   reference `testdata/fixtures/repo/secrets` and `testdata/secrets.json.golden`**,
   demonstrating fixture repos paired with golden expected outputs.
3. **[Secretlint's Node package README](https://www.npmjs.com/package/@secretlint/node)
   uses `fixtures/valid-config` and `fixtures/SECRET.txt`** in its usage example,
   showing a simple fixture directory layout for secrets.
4. **[Gitleaks README](https://github.com/gitleaks/gitleaks) shows a
   `testdata/report/jsonextra.tmpl` example** for report templates, suggesting
   repo-shipped report fixtures/templates that can serve as golden output
   references.
5. **[GitHub's supported secret scanning patterns list](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns)**
   provides a broad catalog of secret types that can guide initial fixture
   coverage by rule family.

## Design Goals

1. **Safe**: no real secrets, ever.
2. **Representative**: cover the most important rule families.
3. **Coverage by axis**: representation, context, and boundary cases.
4. **Deterministic**: stable expected outputs across runs.
5. **Compact**: small enough to run in CI without long runtimes.
6. **Expandable**: easy to add fixtures when new rules are added.

## Coverage Axes

We should cover each axis with at least one positive and one near-miss.

### Representation
- Raw
- Base64-encoded
- URL-percent-encoded
- UTF-16LE / UTF-16BE
- Multi-line blocks (PEM)

### Context / File Types
- .env
- JSON / YAML / TOML
- Source code (JS, Python, Go, etc.)
- Infra (Terraform, CloudFormation)
- Logs and docs

### Rule Families (examples)
- Cloud provider keys (AWS, GCP, Azure)
- VCS tokens (GitHub, GitLab)
- Messaging/notifications (Slack, Twilio)
- Payments (Stripe, PayPal)
- Private keys / PEM blocks
- Generic API keys / passwords

## Coverage Matrix (Draft)

This matrix maps the proposed fixture list below to rule families and
coverage axes. "X" means we have at least one draft fixture covering that
cell. "-" means the cell is not yet covered.

### Rule Family x Representation

| Rule Family | Raw | Base64 | URL-enc | UTF-16 | PEM/Multi |
|---|---|---|---|---|---|
| Cloud (AWS/GCP/Azure) | X | - | - | X | X |
| VCS (GitHub/GitLab) | X | X | X | X | - |
| Messaging (Slack) | X | - | - | - | - |
| Payments (Stripe) | X | - | - | - | - |
| Basic auth / user:pass | X | X | - | - | - |
| Private keys (RSA/EC) | - | X | - | - | X |
| JWT | X | - | - | - | - |
| Generic passwords | X | - | - | - | - |

### Rule Family x Context

| Rule Family | .env | JSON | YAML | Source | Infra | Config (toml/ini) | Docs/Logs |
|---|---|---|---|---|---|---|---|
| Cloud (AWS/GCP/Azure) | X | X | - | - | X | - | - |
| VCS (GitHub/GitLab) | X | - | X | X | - | - | - |
| Messaging (Slack) | X | X | - | - | - | - | - |
| Payments (Stripe) | X | - | - | X | - | - | - |
| Basic auth / user:pass | - | X | X | - | - | X | - |
| Private keys (RSA/EC) | - | X | X | - | - | - | - |
| JWT | - | - | - | - | - | - | X |
| Generic passwords | - | - | - | - | - | X | - |

### Gaps and Follow-ups

- Consider adding URL-encoded or UTF-16 variants for messaging/payments if the
  ruleset includes such formats in practice.
- Private keys appear in PEM, JSON, and YAML; consider a source-embedded key if
  we need to exercise comment/string parsing with PEM blocks.

### Boundary Conditions
- At start/end of file
- Adjacent tokens (back-to-back)
- Mixed line endings (LF/CRLF)
- Large lines / long JSON values
- Comment and string literal placement

## Fixture Structure (Proposed)

```
tests/corpus/real_rules/
  fixtures/
    env/
    json/
    yaml/
    source/
    infra/
    encoding/
    multiline/
    boundary/
    noise/
  expected/
    findings.json
  README.md
```

## Proposed Fixture List (Draft)

This is a *draft* list for review. Each file should include a short header
comment describing its intent and the rule families it targets.

| Fixture | Coverage | Notes |
|---|---|---|
| `fixtures/env/basic.env` | Raw tokens in env format | AWS, GitHub, GitLab, Slack, Stripe |
| `fixtures/env/near_miss.env` | Negative controls | Similar prefixes, invalid lengths |
| `fixtures/json/gcp_service_account.json` | Cloud + PEM | Fake SA JSON with PEM private_key |
| `fixtures/json/azure_connection.json` | Cloud | Azure storage connection string |
| `fixtures/json/slack_webhook.json` | Messaging + JSON | Webhook URL in JSON config |
| `fixtures/json/docker_config.json` | Base64 in JSON | Encoded `user:pass` auth entries |
| `fixtures/yaml/k8s_secret.yaml` | Base64 + YAML | Encoded token in `data:` field |
| `fixtures/yaml/k8s_tls_secret.yaml` | PEM + YAML | Base64-encoded private key in `tls.key` |
| `fixtures/yaml/github_actions.yml` | VCS tokens | Tokens in workflow env |
| `fixtures/source/js/config.js` | Source literals | Template strings + comments |
| `fixtures/source/python/settings.py` | Source literals | Assignments and dicts |
| `fixtures/source/python/stripe_config.py` | Payments + source | Stripe key in code config |
| `fixtures/source/go/config.go` | Source literals | Raw string literal (backticks) |
| `fixtures/source/ruby/secrets.rb` | Source literals | Hash literals |
| `fixtures/infra/terraform.tf` | Infra | Provider keys + variables |
| `fixtures/infra/cloudformation.yml` | Infra | Parameters with secrets |
| `fixtures/toml/app.toml` | Config | Basic credential fields |
| `fixtures/ini/app.ini` | Config | Username/password sections |
| `fixtures/doc/readme.md` | Docs | Code blocks + prose |
| `fixtures/logs/app.log` | Logs | Tokens in log lines |
| `fixtures/multiline/private_key.pem` | PEM blocks | RSA + EC fake keys |
| `fixtures/multiline/jwt.txt` | JWT | Multiple JWT formats |
| `fixtures/encoding/base64_in_text.txt` | Base64 transform | Encoded GitHub token |
| `fixtures/encoding/urlpercent_in_text.txt` | URL-percent transform | URL-encoded GitHub token |
| `fixtures/encoding/utf16le.txt` | UTF-16LE transform | AWS key encoded in UTF-16LE |
| `fixtures/encoding/utf16be.txt` | UTF-16BE transform | GitHub token encoded in UTF-16BE |
| `fixtures/boundary/start_end.txt` | Boundaries | Tokens at file start/end |
| `fixtures/boundary/adjacent.txt` | Boundaries | Back-to-back tokens |
| `fixtures/noise/large_hex.txt` | Negative control | Long hashes/base64 blobs |
| `fixtures/noise/package_lock.json` | Negative control | Known high-entropy noise |
| `fixtures/archive/simple.zip` | Archives | Zip with one file containing token |
| `fixtures/archive/nested.tar.gz` | Archives | Tar.gz containing nested zip with token |
| `fixtures/report/template.json.tmpl` | Report templates | Sample JSON report template |
| `expected/secrets.json.golden` | Golden output | Golden expected findings snapshot |

## Fixture Review Checklist

Before adding fixtures, confirm:
- Each rule family has at least one positive and one near-miss.
- Encoded fixtures decode to a real token that matches a real rule.
- No real secrets are used; all values are synthetic.
- Large/noise fixtures do not explode runtime.
- Each fixture has a clear intent statement at top.

## Open Questions

- Do we want a small “golden” curated set or a broader real-world set?
- Which rules are highest priority for initial coverage?
- Do we include allowlist cases (only if the engine supports them)?
