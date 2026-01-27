use crate::api::{
    AnchorPolicy, DelimAfter, EntropySpec, Gate, RuleSpec, TailCharset, TransformConfig,
    TransformId, TransformMode, Tuning, TwoPhaseSpec, ValidatorKind,
};
use crate::engine::Engine;
use regex::bytes::Regex;

// --------------------------
// Demo engine (rules + transforms)
// --------------------------

/// Anchor selection mode for demo rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorMode {
    /// Use the hand-curated anchors on each rule.
    Manual,
    /// Derive anchors from regex patterns (empty anchors trigger derivation).
    Derived,
}

/// Builds a demo engine with a representative subset of secret rules.
pub fn demo_engine() -> Engine {
    Engine::new(demo_rules(), demo_transforms(), demo_tuning())
}

/// Builds a demo engine with either manual or derived anchors.
pub fn demo_engine_with_anchor_mode(mode: AnchorMode) -> Engine {
    let policy = match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    Engine::new_with_anchor_policy(demo_rules(), demo_transforms(), demo_tuning(), policy)
}

pub(crate) fn demo_rules() -> Vec<RuleSpec> {
    // Subset of gitleaks rules translated into RuleSpec (anchors/radius/two_phase/etc).
    // (Rule ids/regexes taken from gitleaks default config; ported as a representative subset.)
    //
    // Families covered:
    // - AWS
    // - GitHub (PAT/OAuth/App)
    // - GitLab
    // - Slack (token + webhook)
    // - Stripe
    // - SendGrid
    // - npm
    // - Databricks
    // - Private key (PEM-ish)

    const AWS_ACCESS_TOKEN_ANCHORS: &[&[u8]] = &[
        b"A3T", b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA", b"ANPA", b"ANVA", b"ASIA",
    ];

    const GITHUB_PAT_ANCHORS: &[&[u8]] = &[b"ghp_"];
    const GITHUB_OAUTH_ANCHORS: &[&[u8]] = &[b"gho_"];
    const GITHUB_APP_ANCHORS: &[&[u8]] = &[b"ghu_", b"ghs_"];
    const GITLAB_PAT_ANCHORS: &[&[u8]] = &[b"glpat-"];

    const SLACK_TOKEN_ANCHORS: &[&[u8]] = &[b"xoxb-", b"xoxa-", b"xoxp-", b"xoxr-", b"xoxs-"];
    const SLACK_WEBHOOK_ANCHORS: &[&[u8]] = &[b"hooks.slack.com/services/"];

    const STRIPE_TOKEN_ANCHORS: &[&[u8]] = &[
        b"sk_test_",
        b"sk_live_",
        b"sk_prod_",
        b"rk_test_",
        b"rk_live_",
        b"rk_prod_",
    ];

    const SENDGRID_TOKEN_ANCHORS: &[&[u8]] = &[b"SG.", b"sg."];

    const NPM_TOKEN_ANCHORS: &[&[u8]] = &[b"npm_"];

    const DATABRICKS_TOKEN_ANCHORS: &[&[u8]] = &[b"dapi", b"DAPI"];

    const PRIVATE_KEY_ANCHORS: &[&[u8]] = &[b"-----BEGIN"];
    const PRIVATE_KEY_CONFIRM: &[&[u8]] = &[b"PRIVATE KEY"];

    vec![
        RuleSpec {
            name: "aws-access-token",
            anchors: AWS_ACCESS_TOKEN_ANCHORS,
            radius: 64,
            validator: ValidatorKind::AwsAccessKey,
            two_phase: None,
            must_contain: None,
            keywords_any: Some(AWS_ACCESS_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
        },
        RuleSpec {
            name: "github-pat",
            anchors: GITHUB_PAT_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 36,
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(GITHUB_PAT_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "github-oauth",
            anchors: GITHUB_OAUTH_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 36,
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(GITHUB_OAUTH_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "github-app-token",
            anchors: GITHUB_APP_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 36,
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(GITHUB_APP_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"(ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
        },
        RuleSpec {
            name: "gitlab-pat",
            anchors: GITLAB_PAT_ANCHORS,
            radius: 64,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 20,
                tail: TailCharset::AlnumDashUnderscore,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(GITLAB_PAT_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"glpat-[0-9a-zA-Z\-\_]{20}").unwrap(),
        },
        RuleSpec {
            name: "slack-access-token",
            anchors: SLACK_TOKEN_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixBounded {
                min_tail: 10,
                max_tail: 48,
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(SLACK_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 2.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"xox[baprs]-([0-9a-zA-Z]{10,48})").unwrap(),
        },
        RuleSpec {
            name: "slack-web-hook",
            anchors: SLACK_WEBHOOK_ANCHORS,
            radius: 160,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: Some(SLACK_WEBHOOK_ANCHORS),
            entropy: None,
            re: Regex::new(r"https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,46}").unwrap(),
        },
        RuleSpec {
            name: "stripe-access-token",
            anchors: STRIPE_TOKEN_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixBounded {
                min_tail: 10,
                max_tail: 99,
                tail: TailCharset::Alnum,
                require_word_boundary_before: false,
                delim_after: DelimAfter::None,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(STRIPE_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 2.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r"(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}").unwrap(),
        },
        RuleSpec {
            name: "sendgrid-api-token",
            anchors: SENDGRID_TOKEN_ANCHORS,
            radius: 128,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 66,
                tail: TailCharset::Sendgrid66Set,
                require_word_boundary_before: true,
                delim_after: DelimAfter::GitleaksTokenTerminator,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(SENDGRID_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 2.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(
                r#"(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\"|\n|\r|\s|\x60]|$)"#,
            )
            .unwrap(),
        },
        RuleSpec {
            name: "npm-access-token",
            anchors: NPM_TOKEN_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 36,
                tail: TailCharset::Alnum,
                require_word_boundary_before: true,
                delim_after: DelimAfter::GitleaksTokenTerminator,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(NPM_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 2.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r#"(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60]|$)"#).unwrap(),
        },
        RuleSpec {
            name: "databricks-api-token",
            anchors: DATABRICKS_TOKEN_ANCHORS,
            radius: 96,
            validator: ValidatorKind::PrefixFixed {
                tail_len: 32,
                tail: TailCharset::DatabricksSet,
                require_word_boundary_before: true,
                delim_after: DelimAfter::GitleaksTokenTerminator,
            },
            two_phase: None,
            must_contain: None,
            keywords_any: Some(DATABRICKS_TOKEN_ANCHORS),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.0,
                min_len: 16,
                max_len: 256,
            }),
            re: Regex::new(r#"(?i)\b(dapi[a-h0-9]{32})(?:['|\"|\n|\r|\s|\x60]|$)"#).unwrap(),
        },
        RuleSpec {
            name: "private-key",
            anchors: PRIVATE_KEY_ANCHORS,
            radius: 0, // unused when two_phase is set
            validator: ValidatorKind::None,
            two_phase: Some(TwoPhaseSpec {
                seed_radius: 256,
                full_radius: 16 * 1024,
                confirm_any: PRIVATE_KEY_CONFIRM,
            }),
            must_contain: None,
            keywords_any: None,
            entropy: None,
            // Require a complete BEGIN..END block for "PRIVATE KEY" to avoid ultra-noisy partial matches.
            re: Regex::new(
                r"(?is)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----.*?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY-----",
            )
            .unwrap(),
        },
    ]
}

pub(crate) fn demo_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            // Performance-first: gate base64 by anchors in decoded output.
            gate: Gate::AnchorsInDecoded,
            min_len: 32,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

pub(crate) fn demo_tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 16,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 2048,
        max_utf16_decoded_bytes_per_window: 64 * 1024,
        max_transform_depth: 3,
        max_total_decode_output_bytes: 512 * 1024,
        max_work_items: 256,
        max_findings_per_chunk: 8192,
    }
}
