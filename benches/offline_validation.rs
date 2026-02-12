use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine as _;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use scanner_rs::{bench_offline_validate_aws_access_key, bench_offline_validate_sentry_org_token};
use std::time::Duration;

const SENTRY_PREFIX: &[u8] = b"sntrys_";
const SENTRY_SIGNATURE_LEN: usize = 43;

fn build_sentry_token(payload_json: &[u8]) -> Vec<u8> {
    let payload_b64 = B64_STD.encode(payload_json);
    let mut token =
        Vec::with_capacity(SENTRY_PREFIX.len() + payload_b64.len() + 1 + SENTRY_SIGNATURE_LEN);
    token.extend_from_slice(SENTRY_PREFIX);
    token.extend_from_slice(payload_b64.as_bytes());
    token.push(b'_');
    token.extend_from_slice(&[b'A'; SENTRY_SIGNATURE_LEN]);
    token
}

fn make_payload(prefix: &[u8], decoded_len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(decoded_len.max(prefix.len()));
    payload.extend_from_slice(prefix);
    while payload.len() < decoded_len {
        payload.push(b'0');
    }
    payload
}

fn token_with_invalid_payload_char(mut token: Vec<u8>) -> Vec<u8> {
    let sep_pos = token
        .iter()
        .rposition(|&b| b == b'_')
        .expect("sentry token must include payload separator");
    if sep_pos > SENTRY_PREFIX.len() {
        token[sep_pos - 1] = b'@';
    }
    token
}

fn bench_aws(c: &mut Criterion) {
    let mut group = c.benchmark_group("offline_validate_aws_access_key");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(2));

    let cases: [(&str, &[u8]); 4] = [
        ("valid_akia", b"AKIAIOSFODNN7EXAMPLE"),
        ("valid_a3t", b"A3TXABCDEFGHIJKLMNOP"),
        ("invalid_charset", b"AKIAiosfodnn7example"),
        ("invalid_prefix", b"XXXX1234567890123456"),
    ];

    for (name, token) in cases {
        group.throughput(Throughput::Bytes(token.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| black_box(bench_offline_validate_aws_access_key(black_box(token))))
        });
    }

    group.finish();
}

fn bench_sentry(c: &mut Criterion) {
    let mut group = c.benchmark_group("offline_validate_sentry_org_token");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(2));

    let valid_small = build_sentry_token(br#"{"iat":1234567890}"#);
    let valid_large = build_sentry_token(&make_payload(b"{\"iat\":", 480));
    let invalid_prefix = build_sentry_token(&make_payload(b"{\"iss\":", 480));
    let invalid_char = token_with_invalid_payload_char(valid_large.clone());
    let oversized = build_sentry_token(&make_payload(b"{\"iat\":", 640));

    let cases: [(&str, &[u8]); 5] = [
        ("valid_small", valid_small.as_slice()),
        ("valid_large", valid_large.as_slice()),
        ("invalid_prefix", invalid_prefix.as_slice()),
        ("invalid_char", invalid_char.as_slice()),
        ("oversized_payload", oversized.as_slice()),
    ];

    for (name, token) in cases {
        group.throughput(Throughput::Bytes(token.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| black_box(bench_offline_validate_sentry_org_token(black_box(token))))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_aws, bench_sentry);
criterion_main!(benches);
