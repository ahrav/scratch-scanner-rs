//! Rule Isolation Benchmark
//!
//! This benchmark identifies which individual rules cause the most throughput damage.
//! It tests the full engine with specific rules disabled to measure their impact.
//!
//! Run with: cargo bench --bench rule_isolation

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use regex::bytes::Regex;
use scanner_rs::{AnchorMode, AnchorPolicy, Engine, EntropySpec, RuleSpec, Tuning, ValidatorKind};

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Generate realistic code-like content that will trigger common anchors.
fn gen_realistic_code(size: usize) -> Vec<u8> {
    let code_snippets = [
        b"const apiKey = process.env.API_KEY;\n".as_slice(),
        b"let token = getAccessToken();\n".as_slice(),
        b"const secret = config.secret;\n".as_slice(),
        b"password: ${PASSWORD}\n".as_slice(),
        b"authorization: Bearer token123\n".as_slice(),
        b"import { api } from './api';\n".as_slice(),
        b"function authenticate(credentials) {\n".as_slice(),
        b"const KEY = 'some-key-value';\n".as_slice(),
        b"export const ACCESS_TOKEN = '';\n".as_slice(),
        b"// This is a comment with key mention\n".as_slice(),
        b"def get_api_response(api_url):\n".as_slice(),
        b"    return requests.get(api_url)\n".as_slice(),
        b"class TokenManager:\n".as_slice(),
        b"    def refresh_token(self):\n".as_slice(),
        b"        pass\n".as_slice(),
        b"DISCORD_TOKEN=your_token_here\n".as_slice(),
        b"SLACK_API_KEY=xoxb-placeholder\n".as_slice(),
        b"aws_secret_access_key = placeholder\n".as_slice(),
        b"github_token: ghp_placeholder\n".as_slice(),
        b"stripe_secret_key: sk_test_placeholder\n".as_slice(),
    ];

    let mut data = Vec::with_capacity(size);
    let mut idx = 0;
    while data.len() < size {
        data.extend_from_slice(code_snippets[idx % code_snippets.len()]);
        idx += 1;
    }
    data.truncate(size);
    data
}

/// Generate clean ASCII that won't match anchors.
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

fn build_regex(pattern: &str) -> Regex {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(32 * 1024 * 1024)
        .build()
        .expect("invalid regex")
}

/// The problematic generic-api-key rule.
fn generic_api_key_rule() -> RuleSpec {
    RuleSpec {
        name: "generic-api-key",
        anchors: &[
            b"access",
            b"ACCESS",
            b"api",
            b"API",
            b"auth",
            b"AUTH",
            b"key",
            b"KEY",
            b"credential",
            b"CREDENTIAL",
            b"creds",
            b"CREDS",
            b"passwd",
            b"PASSWD",
            b"password",
            b"PASSWORD",
            b"secret",
            b"SECRET",
            b"token",
            b"TOKEN",
        ],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[
            b"access",
            b"ACCESS",
            b"api",
            b"API",
            b"auth",
            b"AUTH",
            b"key",
            b"KEY",
            b"credential",
            b"CREDENTIAL",
            b"creds",
            b"CREDS",
            b"passwd",
            b"PASSWD",
            b"password",
            b"PASSWORD",
            b"secret",
            b"SECRET",
            b"token",
            b"TOKEN",
        ]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.5,
            min_len: 16,
            max_len: 256,
        }),
        local_context: None,
        secret_group: None,
        re: build_regex(
            r#"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
    }
}

/// Create a minimal rule that won't match anything (baseline).
fn impossible_rule(name: &'static str) -> RuleSpec {
    RuleSpec {
        name,
        anchors: &[b"\xFF\xFE\xFD\xFC"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        local_context: None,
        secret_group: None,
        re: build_regex(r"\xFF\xFE\xFD\xFC[a-z]{10}"),
    }
}

/// A simple, well-anchored rule (GitHub PAT).
fn github_pat_rule() -> RuleSpec {
    RuleSpec {
        name: "github-pat",
        anchors: &[b"ghp_"],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"ghp_"]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 16,
            max_len: 256,
        }),
        local_context: None,
        secret_group: None,
        re: build_regex(r"ghp_[0-9a-zA-Z]{36}"),
    }
}

/// AWS access key rule (well-anchored).
fn aws_rule() -> RuleSpec {
    RuleSpec {
        name: "aws-access-key",
        anchors: &[b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA"],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA"]),
        entropy: None,
        local_context: None,
        secret_group: None,
        re: build_regex(r"(?:AKIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}"),
    }
}

/// Benchmark comparing engines with and without generic-api-key.
fn bench_generic_api_key_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("generic_api_key_impact");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    let tuning = Tuning {
        max_transform_depth: 0,
        ..scanner_rs::demo_tuning()
    };

    // Engine with just impossible rules (baseline)
    let baseline_rules: Vec<RuleSpec> = (0..10)
        .map(|i| {
            let name: &'static str = Box::leak(format!("impossible_{}", i).into_boxed_str());
            impossible_rule(name)
        })
        .collect();
    let baseline_engine = Engine::new_with_anchor_policy(
        baseline_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut baseline_scratch = baseline_engine.new_scratch();

    // Engine with 10 well-anchored rules (no generic-api-key)
    let good_rules = vec![
        github_pat_rule(),
        aws_rule(),
        impossible_rule("placeholder_1"),
        impossible_rule("placeholder_2"),
        impossible_rule("placeholder_3"),
        impossible_rule("placeholder_4"),
        impossible_rule("placeholder_5"),
        impossible_rule("placeholder_6"),
        impossible_rule("placeholder_7"),
        impossible_rule("placeholder_8"),
    ];
    let good_engine = Engine::new_with_anchor_policy(
        good_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut good_scratch = good_engine.new_scratch();

    // Engine with generic-api-key ONLY
    let generic_only = vec![generic_api_key_rule()];
    let generic_engine = Engine::new_with_anchor_policy(
        generic_only,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut generic_scratch = generic_engine.new_scratch();

    // Engine with good rules + generic-api-key
    let mixed_rules = vec![
        github_pat_rule(),
        aws_rule(),
        generic_api_key_rule(),
        impossible_rule("placeholder_1"),
        impossible_rule("placeholder_2"),
        impossible_rule("placeholder_3"),
        impossible_rule("placeholder_4"),
        impossible_rule("placeholder_5"),
        impossible_rule("placeholder_6"),
        impossible_rule("placeholder_7"),
    ];
    let mixed_engine = Engine::new_with_anchor_policy(
        mixed_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut mixed_scratch = mixed_engine.new_scratch();

    // Benchmark on clean data (few anchor hits)
    group.bench_function("baseline_10_impossible_clean", |b| {
        b.iter(|| {
            let hits = baseline_engine.scan_chunk(black_box(&clean_data), &mut baseline_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_rules_only_clean", |b| {
        b.iter(|| {
            let hits = good_engine.scan_chunk(black_box(&clean_data), &mut good_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("generic_api_key_only_clean", |b| {
        b.iter(|| {
            let hits = generic_engine.scan_chunk(black_box(&clean_data), &mut generic_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_plus_generic_clean", |b| {
        b.iter(|| {
            let hits = mixed_engine.scan_chunk(black_box(&clean_data), &mut mixed_scratch);
            black_box(hits.len())
        })
    });

    // Benchmark on realistic data (many anchor hits)
    group.bench_function("baseline_10_impossible_realistic", |b| {
        b.iter(|| {
            let hits =
                baseline_engine.scan_chunk(black_box(&realistic_data), &mut baseline_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_rules_only_realistic", |b| {
        b.iter(|| {
            let hits = good_engine.scan_chunk(black_box(&realistic_data), &mut good_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("generic_api_key_only_realistic", |b| {
        b.iter(|| {
            let hits = generic_engine.scan_chunk(black_box(&realistic_data), &mut generic_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_plus_generic_realistic", |b| {
        b.iter(|| {
            let hits = mixed_engine.scan_chunk(black_box(&realistic_data), &mut mixed_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Test the full gitleaks engine.
fn bench_full_gitleaks_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_gitleaks_engine");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    // Full gitleaks engine with manual anchors
    let full_engine = scanner_rs::demo_engine_with_anchor_mode(AnchorMode::Manual);
    let mut full_scratch = full_engine.new_scratch();

    group.bench_function("full_gitleaks_clean", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&clean_data), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("full_gitleaks_realistic", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&realistic_data), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Test anchor density impact - how many times do common anchors appear?
fn bench_anchor_density(c: &mut Criterion) {
    let mut group = c.benchmark_group("anchor_density");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    // Count anchor hits in realistic data
    let common_anchors = [
        "api", "API", "key", "KEY", "token", "TOKEN", "secret", "SECRET", "password", "PASSWORD",
        "access", "ACCESS", "auth", "AUTH",
    ];

    let tuning = Tuning {
        max_transform_depth: 0,
        ..scanner_rs::demo_tuning()
    };

    // Test with increasing numbers of common anchors
    for anchor_count in [2, 4, 8, 14] {
        let anchors: Vec<&'static [u8]> = common_anchors[..anchor_count]
            .iter()
            .map(|s| s.as_bytes() as &'static [u8])
            .collect();
        let anchors_static: &'static [&'static [u8]] = Box::leak(anchors.into_boxed_slice());

        let rule = RuleSpec {
            name: Box::leak(format!("test_{}_anchors", anchor_count).into_boxed_str()),
            anchors: anchors_static,
            radius: 256,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: Some(anchors_static),
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.5,
                min_len: 16,
                max_len: 256,
            }),
            local_context: None,
            secret_group: None,
            re: build_regex(
                r#"(?i)[\w.-]{0,50}?(?:access|auth|api|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150})(?:[\x60'"\s;]|\\[nr]|$)"#,
            ),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            vec![],
            tuning.clone(),
            AnchorPolicy::ManualOnly,
        );
        let mut scratch = engine.new_scratch();

        group.bench_function(format!("{}_common_anchors", anchor_count), |b| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(&realistic_data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

criterion_group!(
    rule_isolation,
    bench_generic_api_key_impact,
    bench_full_gitleaks_engine,
    bench_anchor_density,
);

criterion_main!(rule_isolation);
