#!/usr/bin/env python3
"""Generate cross-scanner rule mapping from scanner-rs baseline (223 rules).

Parses rule definitions from all four scanners, fuzzy-matches by
provider/service name, and outputs:
  - configs/rule-mapping.csv
  - configs/trufflehog-detectors.txt
  - configs/gitleaks-config.toml
  - configs/unmapped-rules.txt
"""
from __future__ import annotations

import csv
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIGS_DIR = SCRIPT_DIR / "configs"
CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

# ── Paths ──────────────────────────────────────────────────────────────
SCANNER_RS_RULES = SCRIPT_DIR.parent.parent / "default_rules.yaml"
KINGFISHER_RULES = Path("/local/home/ahrav/scratch/kingfisher/crates/kingfisher-rules/data/rules")
TRUFFLEHOG_PB = Path("/local/home/ahrav/scratch/trufflehog/pkg/pb/detectorspb/detectors.pb.go")
GITLEAKS_RULES = Path("/local/home/ahrav/scratch/gitleaks/cmd/generate/config/rules")
GITLEAKS_DEFAULT_TOML = Path("/local/home/ahrav/scratch/gitleaks/config/gitleaks.toml")


def parse_scanner_rs_rules(path: Path) -> list[str]:
    """Extract rule names from default_rules.yaml."""
    names = []
    with open(path) as f:
        for line in f:
            m = re.match(r"^- name:\s+['\"]?(.+?)['\"]?\s*$", line)
            if m:
                names.append(m.group(1))
    return sorted(names)


def parse_kingfisher_rules(rules_dir: Path) -> dict[str, list[str]]:
    """Return {filename_stem: [rule_id, ...]} from Kingfisher YAML rules."""
    result: dict[str, list[str]] = {}
    for yml in sorted(rules_dir.glob("*.yml")):
        ids = []
        with open(yml) as f:
            for line in f:
                m = re.match(r"\s+id:\s+(.+)", line)
                if m:
                    ids.append(m.group(1).strip())
        if ids:
            result[yml.stem] = ids
    return result


def parse_trufflehog_detectors(pb_path: Path) -> list[str]:
    """Extract DetectorType names from detectors.pb.go (skip 'not implemented')."""
    names = set()
    with open(pb_path) as f:
        for line in f:
            if "Not yet implemented" in line:
                continue
            m = re.match(r"\s+DetectorType_(\w+)\s+DetectorType\s*=\s*\d+", line)
            if m:
                name = m.group(1)
                if name not in ("Test",):
                    names.add(name)
    return sorted(names)


def parse_gitleaks_rule_ids(rules_dir: Path) -> list[str]:
    """Extract RuleID values from Gitleaks Go source files."""
    ids = []
    for gofile in sorted(rules_dir.glob("*.go")):
        with open(gofile) as f:
            for line in f:
                m = re.match(r'\s+RuleID:\s+"(.+)"', line)
                if m:
                    ids.append(m.group(1))
    return sorted(ids)


# ── Normalisation helpers ──────────────────────────────────────────────

def normalise(name: str) -> str:
    """Lowercase, strip common suffixes, collapse separators."""
    s = name.lower()
    s = re.sub(r"[-_\s.]+", "", s)
    # strip trailing type hints
    for suffix in (
        "apikey", "apitoken", "accesstoken", "accesskey", "secretkey",
        "clientid", "clientsecret", "oauthsecret", "token", "secret",
        "key", "webhook", "pat", "personaltoken",
    ):
        if s.endswith(suffix) and len(s) > len(suffix):
            s = s[: -len(suffix)]
    return s


# ── Mapping: scanner-rs → TruffleHog ──────────────────────────────────

# Hand-curated overrides for cases fuzzy matching can't handle.
# scanner-rs rule name → TruffleHog DetectorType name
TRUFFLEHOG_MANUAL: dict[str, str | None] = {
    "1password-secret-key": None,  # TruffleHog has no 1Password detector
    "1password-service-account-token": None,
    "aws-access-token": "AWS",
    "aws-amazon-bedrock-api-key-long-lived": None,
    "aws-amazon-bedrock-api-key-short-lived": None,
    "azure-ad-client-secret": "Azure",
    "curl-auth-header": None,
    "curl-auth-user": None,
    "discord-api-token": "DiscordBotToken",
    "discord-client-id": None,
    "discord-client-secret": None,
    "dropbox-api-token": "Dropbox",
    "dropbox-long-lived-api-token": "Dropbox",
    "dropbox-short-lived-api-token": "Dropbox",
    "facebook-access-token": "FacebookOAuth",
    "facebook-page-access-token": "FacebookOAuth",
    "facebook-secret": "FacebookOAuth",
    "gcp-api-key": "GCP",
    "generic-api-key": None,  # scanner-rs has its own generic, TH too different
    "github-app-token": "GitHubApp",
    "github-fine-grained-pat": "Github",
    "github-oauth": "Github",
    "github-pat": "Github",
    "github-refresh-token": "Github",
    "gitlab-cicd-job-token": "Gitlab",
    "gitlab-deploy-token": "Gitlab",
    "gitlab-feature-flag-client-token": "Gitlab",
    "gitlab-feed-token": "Gitlab",
    "gitlab-incoming-mail-token": "Gitlab",
    "gitlab-kubernetes-agent-token": "Gitlab",
    "gitlab-oauth-app-secret": "Gitlab",
    "gitlab-pat": "Gitlab",
    "gitlab-pat-routable": "Gitlab",
    "gitlab-ptt": "Gitlab",
    "gitlab-rrt": "Gitlab",
    "gitlab-runner-authentication-token": "Gitlab",
    "gitlab-runner-authentication-token-routable": "Gitlab",
    "gitlab-scim-token": "Gitlab",
    "gitlab-session-cookie": "Gitlab",
    "heroku-api-key": "Heroku",
    "heroku-api-key-v2": "Heroku",
    "jwt": None,  # TruffleHog doesn't have a JWT detector in the same sense
    "jwt-base64": None,
    "kubernetes-secret-yaml": None,
    "new-relic-browser-api-token": "NewRelicPersonalApiKey",
    "new-relic-insert-key": "NewRelicPersonalApiKey",
    "new-relic-user-api-id": "NewRelicPersonalApiKey",
    "new-relic-user-api-key": "NewRelicPersonalApiKey",
    "nuget-config-password": None,
    "openshift-user-token": None,
    "pkcs12-file": None,
    "private-key": "PrivateKey",
    "privateai-api-token": None,
    "settlemint-application-access-token": None,
    "settlemint-personal-access-token": None,
    "settlemint-service-access-token": None,
    "sidekiq-secret": None,
    "sidekiq-sensitive-url": None,
    "slack-app-token": "Slack",
    "slack-bot-token": "Slack",
    "slack-config-access-token": "Slack",
    "slack-config-refresh-token": "Slack",
    "slack-legacy-bot-token": "Slack",
    "slack-legacy-token": "Slack",
    "slack-legacy-workspace-token": "Slack",
    "slack-user-token": "Slack",
    "slack-webhook-url": "SlackWebhook",
    "square-access-token": "Square",
    "squarespace-access-token": "Squarespace",
    "stripe-access-token": "Stripe",
    "travisci-access-token": "TravisCI",
    "twitter-access-secret": None,
    "twitter-access-token": None,
    "twitter-api-key": None,
    "twitter-api-secret": None,
    "twitter-bearer-token": None,
    "vault-batch-token": "HashiCorpVaultAuth",
    "vault-service-token": "HashiCorpVaultAuth",
    "vault-service-token-legacy": "HashiCorpVaultAuth",
    "yandex-access-token": None,
    "yandex-api-key": None,
    "yandex-aws-access-token": None,
}


def match_trufflehog(scanner_rs_name: str, th_detectors: list[str]) -> str | None:
    """Return TruffleHog detector name matching a scanner-rs rule, or None."""
    if scanner_rs_name in TRUFFLEHOG_MANUAL:
        return TRUFFLEHOG_MANUAL[scanner_rs_name]

    norm = normalise(scanner_rs_name)
    # Try exact normalised match first
    for det in th_detectors:
        if normalise(det) == norm:
            return det

    # Try prefix match (e.g. "datadog" in "DatadogToken")
    for det in th_detectors:
        det_norm = normalise(det)
        if norm.startswith(det_norm) or det_norm.startswith(norm):
            return det

    # Try substring: if the provider name appears in the TH detector
    provider = scanner_rs_name.split("-")[0].lower()
    if len(provider) >= 4:
        candidates = [d for d in th_detectors if provider in d.lower()]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # Pick the one with shortest normalised distance
            best = min(candidates, key=lambda c: abs(len(normalise(c)) - len(norm)))
            return best

    return None


# ── Mapping: scanner-rs → Gitleaks ─────────────────────────────────────

def match_gitleaks(scanner_rs_name: str, gl_rule_ids: list[str]) -> str | None:
    """Match scanner-rs rule name to Gitleaks RuleID (nearly 1:1)."""
    if scanner_rs_name in gl_rule_ids:
        return scanner_rs_name
    # Try normalised match for minor spelling diffs
    norm = normalise(scanner_rs_name)
    for rid in gl_rule_ids:
        if normalise(rid) == norm:
            return rid
    return None


def _parse_gitleaks_toml_blocks(toml_path: Path) -> tuple[str, list[tuple[str, str]]]:
    """Parse the default gitleaks.toml into (preamble, [(rule_id, block), ...]).

    The preamble is everything before the first [[rules]] line.
    Each block is the text from [[rules]] up to (but not including) the next
    [[rules]] or end of file.
    """
    with open(toml_path) as f:
        text = f.read()

    # Split on [[rules]] boundaries
    parts = re.split(r"(?=^\[\[rules\]\]\s*$)", text, flags=re.MULTILINE)
    preamble = parts[0]
    blocks: list[tuple[str, str]] = []
    for part in parts[1:]:
        # Extract the rule id from the block
        m = re.search(r'^id\s*=\s*"([^"]+)"', part, re.MULTILINE)
        if m:
            blocks.append((m.group(1), part))
    return preamble, blocks


def _write_filtered_gitleaks_toml(
    default_toml: Path,
    output_path: Path,
    keep_ids: set[str],
) -> None:
    """Write a gitleaks config containing only rules whose id is in keep_ids."""
    preamble, blocks = _parse_gitleaks_toml_blocks(default_toml)
    with open(output_path, "w") as f:
        # Write preamble (title, allowlists, etc.) but replace the title
        preamble_lines = preamble.split("\n")
        for line in preamble_lines:
            if line.startswith("title"):
                f.write('title = "gitleaks benchmark config (scanner-rs baseline)"\n')
            else:
                f.write(line + "\n")
        # Write only matching rule blocks
        for rule_id, block in blocks:
            if rule_id in keep_ids:
                f.write(block)
                if not block.endswith("\n"):
                    f.write("\n")


def main():
    print("Parsing scanner-rs rules...")
    sr_rules = parse_scanner_rs_rules(SCANNER_RS_RULES)
    print(f"  → {len(sr_rules)} rules")

    print("Parsing Kingfisher rules...")
    kf_rules = parse_kingfisher_rules(KINGFISHER_RULES)
    kf_all_ids = [rid for ids in kf_rules.values() for rid in ids]
    print(f"  → {len(kf_all_ids)} rules across {len(kf_rules)} files")

    print("Parsing TruffleHog detectors...")
    th_detectors = parse_trufflehog_detectors(TRUFFLEHOG_PB)
    print(f"  → {len(th_detectors)} detectors")

    print("Parsing Gitleaks rules...")
    gl_rules = parse_gitleaks_rule_ids(GITLEAKS_RULES)
    print(f"  → {len(gl_rules)} rules")

    # ── Build mapping ──────────────────────────────────────────────────
    rows = []
    th_matched = set()
    gl_matched = set()
    unmapped_lines = []

    for rule in sr_rules:
        th = match_trufflehog(rule, th_detectors)
        gl = match_gitleaks(rule, gl_rules)

        if th:
            th_matched.add(th)
        if gl:
            gl_matched.add(gl)

        missing_in = []
        if not th:
            missing_in.append("trufflehog")
        if not gl:
            missing_in.append("gitleaks")
        # Kingfisher is a superset — note if missing for documentation
        kf_match = "yes"  # assume superset, Kingfisher runs all rules

        rows.append({
            "scanner_rs": rule,
            "kingfisher": kf_match,
            "trufflehog": th or "",
            "gitleaks": gl or "",
        })

        if missing_in:
            unmapped_lines.append(f"{rule}: missing in {', '.join(missing_in)}")

    # ── Write rule-mapping.csv ─────────────────────────────────────────
    csv_path = CONFIGS_DIR / "rule-mapping.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["scanner_rs", "kingfisher", "trufflehog", "gitleaks"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {csv_path} ({len(rows)} rows)")

    # ── Write trufflehog-detectors.txt ─────────────────────────────────
    th_include = sorted(th_matched)
    th_path = CONFIGS_DIR / "trufflehog-detectors.txt"
    with open(th_path, "w") as f:
        f.write(",".join(th_include) + "\n")
    print(f"Wrote {th_path} ({len(th_include)} detectors)")

    # ── Write gitleaks-config.toml ─────────────────────────────────────
    # Filter the default Gitleaks TOML to include only rules matching
    # the scanner-rs baseline. This preserves exact regex, keywords,
    # entropy, secretGroup, and allowlists from the default config.
    gl_config_path = CONFIGS_DIR / "gitleaks-config.toml"
    matched_gl_ids = {row["gitleaks"] for row in rows if row["gitleaks"]}
    _write_filtered_gitleaks_toml(GITLEAKS_DEFAULT_TOML, gl_config_path, matched_gl_ids)
    print(f"Wrote {gl_config_path} ({len(matched_gl_ids)} rules)")

    # ── Write unmapped-rules.txt ───────────────────────────────────────
    unmapped_path = CONFIGS_DIR / "unmapped-rules.txt"
    with open(unmapped_path, "w") as f:
        f.write(f"# Rules from scanner-rs with no match in at least one scanner\n")
        f.write(f"# Total scanner-rs rules: {len(sr_rules)}\n")
        f.write(f"# Matched in TruffleHog: {len(th_matched)}\n")
        f.write(f"# Matched in Gitleaks: {len(gl_matched)}\n")
        f.write(f"# Kingfisher: superset (277 rules), runs with defaults\n\n")
        for line in sorted(unmapped_lines):
            f.write(line + "\n")
    print(f"Wrote {unmapped_path} ({len(unmapped_lines)} unmapped)")

    # ── Summary ────────────────────────────────────────────────────────
    th_count = sum(1 for r in rows if r["trufflehog"])
    gl_count = sum(1 for r in rows if r["gitleaks"])
    print(f"\n{'='*60}")
    print(f"scanner-rs baseline: {len(sr_rules)} rules")
    print(f"  → TruffleHog matched:  {th_count}/{len(sr_rules)} ({100*th_count//len(sr_rules)}%)")
    print(f"  → Gitleaks matched:    {gl_count}/{len(sr_rules)} ({100*gl_count//len(sr_rules)}%)")
    print(f"  → Kingfisher: superset (runs defaults)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
