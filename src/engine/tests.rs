//! Engine tests and property checks.
//!
//! These tests exercise anchor selection, transform gating, and provenance
//! tracking. A slow reference scanner is included to validate correctness
//! across transforms and UTF-16 variants.

use super::*;
use proptest::prelude::*;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// Helper that uses the allocation-free scan API and materializes findings.
fn scan_chunk_findings(engine: &Engine, hay: &[u8]) -> Vec<Finding> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut out);
    out
}

// Tiny base64 encoder for tests (standard alphabet, with '=' padding).
fn b64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;

    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        let c0 = ((n >> 18) & 63) as usize;
        let c1 = ((n >> 12) & 63) as usize;
        let c2 = ((n >> 6) & 63) as usize;
        let c3 = (n & 63) as usize;

        out.push(ALPH[c0] as char);
        out.push(ALPH[c1] as char);

        if i + 1 < input.len() {
            out.push(ALPH[c2] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(ALPH[c3] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }

    out
}

#[test]
fn hash128_deterministic() {
    let data = b"hello world";
    let h1 = hash128(data);
    let h2 = hash128(data);
    assert_eq!(h1, h2);

    // Different inputs produce different hashes.
    let h3 = hash128(b"hello worlD");
    assert_ne!(h1, h3);
}

#[test]
fn hash128_collision_resistant() {
    // Verify that small changes produce different hashes.
    let base = b"AKIAIOSFODNN7EXAMPLE";
    let h_base = hash128(base);

    // Single byte change.
    let mut modified = *base;
    modified[0] ^= 1;
    assert_ne!(h_base, hash128(&modified));

    // Append a byte.
    let mut appended = base.to_vec();
    appended.push(0);
    assert_ne!(h_base, hash128(&appended));

    // Empty input has distinct hash.
    let h_empty = hash128(b"");
    assert_ne!(h_base, h_empty);
}

#[test]
fn url_span_includes_prefix_and_finds_ghp() {
    let eng = demo_engine();
    // ghp_ + 36 chars
    let token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let url = token.replace("_", "%5F"); // ghp%5F...
    let hay = format!("token={}", url).into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(hits.iter().any(|h| h.rule == "github-pat"));
}

#[test]
fn base64_utf16_aws_key_is_detected() {
    let eng = demo_engine();

    let aws = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
    let utf16le = super::utf16le_bytes(aws);
    let b64 = b64_encode(&utf16le);

    let hay = format!("prefix {} suffix", b64).into_bytes();
    let hits = scan_chunk_findings(&eng, &hay);

    assert!(hits.iter().any(|h| h.rule == "aws-access-token"));
}

#[test]
fn keyword_gate_filters_without_keyword() {
    const ANCHORS: &[&[u8]] = &[b"ANCH"];
    const KEYWORDS: &[&[u8]] = &[b"kw"];
    let rule = RuleSpec {
        name: "keyword-gate",
        anchors: ANCHORS,
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(KEYWORDS),
        entropy: None,
        re: Regex::new("secret").unwrap(),
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"ANCHsecret";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(!hits.iter().any(|h| h.rule == "keyword-gate"));

    let hay = b"ANCHkwsecret";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(hits.iter().any(|h| h.rule == "keyword-gate"));
}

#[test]
fn entropy_gate_filters_low_entropy_matches() {
    const ANCHORS: &[&[u8]] = &[b"TOK_"];
    let rule = RuleSpec {
        name: "entropy-gate",
        anchors: ANCHORS,
        radius: 8,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 32,
        }),
        re: Regex::new(r"TOK_[A-Za-z0-9]{8}").unwrap(),
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let low = b"TOK_AAAAAAAA";
    let hits = scan_chunk_findings(&eng, low);
    assert!(!hits.iter().any(|h| h.rule == "entropy-gate"));

    let high = b"TOK_A1b2C3d4";
    let hits = scan_chunk_findings(&eng, high);
    assert!(hits.iter().any(|h| h.rule == "entropy-gate"));
}

#[test]
fn anchor_policy_prefers_derived_over_manual() {
    const MANUAL: &[&[u8]] = &[b"bar"];
    let rule = RuleSpec {
        name: "derived-prefers",
        anchors: MANUAL,
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("foo").unwrap(),
    };

    let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
    let stats = eng.anchor_plan_stats();
    assert_eq!(stats.derived_rules, 1);
    assert_eq!(stats.manual_rules, 0);

    let hits = scan_chunk_findings(&eng, b"barfoo");
    assert!(hits.iter().any(|h| h.rule == "derived-prefers"));
}

#[test]
fn anchor_policy_falls_back_to_manual_on_unfilterable() {
    const MANUAL: &[&[u8]] = &[b"Z"];
    let rule = RuleSpec {
        name: "manual-fallback",
        anchors: MANUAL,
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new(".*").unwrap(),
    };

    let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
    let stats = eng.anchor_plan_stats();
    assert_eq!(stats.manual_rules, 1);
    assert_eq!(stats.derived_rules, 0);
    assert_eq!(stats.unfilterable_rules, 1);

    let hits = scan_chunk_findings(&eng, b"Z");
    assert!(hits.iter().any(|h| h.rule == "manual-fallback"));
}

#[test]
fn nested_encoding_is_skipped_in_gated_mode() {
    let eng = demo_engine();

    // URL-encoded underscore inside base64.
    let token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let url = token.replace("_", "%5F"); // ghp%5F...
    let b64 = b64_encode(url.as_bytes());

    let hay = format!("X{}Y", b64).into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(!hits.iter().any(|h| h.rule == "github-pat"));
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_temp_file(bytes: &[u8]) -> std::io::Result<TempFile> {
    let mut path = std::env::temp_dir();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("scanner_rs_test_{}_{}", std::process::id(), stamp));
    std::fs::write(&path, bytes)?;
    Ok(TempFile { path })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum StepKind {
    Transform { idx: usize },
    Utf16 { le: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FindingKey {
    rule: &'static str,
    span: Range<usize>,
    steps: Vec<StepKind>,
}

// Normalize findings into a hashable form for equivalence checks.
fn findings_to_keys(findings: &[Finding]) -> HashSet<FindingKey> {
    findings
        .iter()
        .map(|f| {
            let steps = f
                .decode_steps
                .iter()
                .map(|step| match step {
                    DecodeStep::Transform { transform_idx, .. } => StepKind::Transform {
                        idx: *transform_idx,
                    },
                    DecodeStep::Utf16Window { endianness, .. } => StepKind::Utf16 {
                        le: matches!(endianness, Utf16Endianness::Le),
                    },
                })
                .collect();
            FindingKey {
                rule: f.rule,
                span: f.span.clone(),
                steps,
            }
        })
        .collect()
}

#[derive(Clone)]
struct RefWorkItem {
    buf: Vec<u8>,
    steps: Vec<StepKind>,
    depth: usize,
}

// Slow, allocation-heavy reference scan that mirrors the engine's semantics.
fn reference_scan_keys(engine: &Engine, rules: &[RuleSpec], buf: &[u8]) -> HashSet<FindingKey> {
    let mut out = HashSet::new();
    let mut entropy_scratch = EntropyScratch::new();
    let mut work_q = Vec::new();
    work_q.push(RefWorkItem {
        buf: buf.to_vec(),
        steps: Vec::new(),
        depth: 0,
    });

    let mut work_head = 0usize;
    let mut total_decode_output_bytes = 0usize;
    let mut work_items_enqueued = 0usize;
    let mut seen = HashSet::<u128>::new();

    while work_head < work_q.len() {
        let item = work_q[work_head].clone();
        work_head += 1;

        let found_any = scan_rules_reference(
            engine,
            rules,
            &item.buf,
            &item.steps,
            &mut out,
            &mut total_decode_output_bytes,
            &mut entropy_scratch,
        );

        if item.depth >= engine.tuning.max_transform_depth {
            continue;
        }
        if work_items_enqueued >= engine.tuning.max_work_items {
            continue;
        }

        for (tidx, tc) in engine.transforms.iter().enumerate() {
            if tc.mode == TransformMode::Disabled {
                continue;
            }
            if tc.mode == TransformMode::IfNoFindingsInThisBuffer && found_any {
                continue;
            }
            if item.buf.len() < tc.min_len {
                continue;
            }
            if !transform_quick_trigger(tc, &item.buf) {
                continue;
            }

            let mut spans = Vec::new();
            find_spans_into(tc, &item.buf, &mut spans);
            if spans.is_empty() {
                continue;
            }

            let span_len = spans.len().min(tc.max_spans_per_buffer);
            for enc_span in spans.iter().take(span_len) {
                if work_items_enqueued >= engine.tuning.max_work_items {
                    break;
                }
                if total_decode_output_bytes >= engine.tuning.max_total_decode_output_bytes {
                    break;
                }

                let enc_span = enc_span.clone();
                let enc = &item.buf[enc_span.clone()];

                let remaining = engine
                    .tuning
                    .max_total_decode_output_bytes
                    .saturating_sub(total_decode_output_bytes);
                if remaining == 0 {
                    break;
                }
                let max_out = tc.max_decoded_bytes.min(remaining);

                let decoded = match decode_to_vec(tc, enc, max_out) {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };
                if decoded.is_empty() {
                    continue;
                }

                total_decode_output_bytes = total_decode_output_bytes.saturating_add(decoded.len());
                if total_decode_output_bytes > engine.tuning.max_total_decode_output_bytes {
                    break;
                }

                if tc.gate == Gate::AnchorsInDecoded && !engine.ac_anchors.is_match(&decoded) {
                    continue;
                }

                let h = hash128(&decoded);
                if !seen.insert(h) {
                    continue;
                }

                let mut steps = item.steps.clone();
                steps.push(StepKind::Transform { idx: tidx });

                work_q.push(RefWorkItem {
                    buf: decoded,
                    steps,
                    depth: item.depth + 1,
                });
                work_items_enqueued += 1;
            }
        }
    }

    out
}

// Reference rule scan over raw + UTF-16 variants for a single buffer.
fn scan_rules_reference(
    engine: &Engine,
    rules: &[RuleSpec],
    buf: &[u8],
    steps: &[StepKind],
    out: &mut HashSet<FindingKey>,
    total_decode_output_bytes: &mut usize,
    entropy_scratch: &mut EntropyScratch,
) -> bool {
    let mut found_any = false;

    for rule in rules {
        for variant in [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be] {
            let windows = collect_windows_for_variant(buf, rule, variant, &engine.tuning);
            if windows.is_empty() {
                continue;
            }

            match variant {
                Variant::Raw => {
                    for w in windows {
                        let window = &buf[w.clone()];
                        for rm in rule.re.find_iter(window) {
                            if let Some(spec) = rule.entropy.as_ref() {
                                let ent = EntropyCompiled {
                                    min_bits_per_byte: spec.min_bits_per_byte,
                                    min_len: spec.min_len,
                                    max_len: spec.max_len,
                                };
                                let mbytes = &window[rm.start()..rm.end()];
                                if !entropy_gate_passes(
                                    &ent,
                                    mbytes,
                                    entropy_scratch,
                                    &engine.entropy_log2,
                                ) {
                                    continue;
                                }
                            }
                            let span = (w.start + rm.start())..(w.start + rm.end());
                            out.insert(FindingKey {
                                rule: rule.name,
                                span,
                                steps: steps.to_vec(),
                            });
                            found_any = true;
                        }
                    }
                }
                Variant::Utf16Le | Variant::Utf16Be => {
                    for w in windows {
                        if *total_decode_output_bytes >= engine.tuning.max_total_decode_output_bytes
                        {
                            return found_any;
                        }

                        let remaining = engine
                            .tuning
                            .max_total_decode_output_bytes
                            .saturating_sub(*total_decode_output_bytes);
                        if remaining == 0 {
                            return found_any;
                        }
                        let max_out = engine
                            .tuning
                            .max_utf16_decoded_bytes_per_window
                            .min(remaining);

                        let decoded = match variant {
                            Variant::Utf16Le => decode_utf16le_to_vec(&buf[w.clone()], max_out),
                            Variant::Utf16Be => decode_utf16be_to_vec(&buf[w.clone()], max_out),
                            _ => unreachable!(),
                        };

                        let decoded = match decoded {
                            Ok(bytes) => bytes,
                            Err(_) => continue,
                        };

                        if decoded.is_empty() {
                            continue;
                        }

                        *total_decode_output_bytes =
                            total_decode_output_bytes.saturating_add(decoded.len());
                        if *total_decode_output_bytes > engine.tuning.max_total_decode_output_bytes
                        {
                            return found_any;
                        }

                        let mut steps = steps.to_vec();
                        steps.push(StepKind::Utf16 {
                            le: matches!(variant.utf16_endianness().unwrap(), Utf16Endianness::Le),
                        });

                        for rm in rule.re.find_iter(&decoded) {
                            if let Some(spec) = rule.entropy.as_ref() {
                                let ent = EntropyCompiled {
                                    min_bits_per_byte: spec.min_bits_per_byte,
                                    min_len: spec.min_len,
                                    max_len: spec.max_len,
                                };
                                let span = rm.start()..rm.end();
                                let mbytes = &decoded[span.clone()];
                                if !entropy_gate_passes(
                                    &ent,
                                    mbytes,
                                    entropy_scratch,
                                    &engine.entropy_log2,
                                ) {
                                    continue;
                                }
                            }
                            let span = rm.start()..rm.end();
                            out.insert(FindingKey {
                                rule: rule.name,
                                span,
                                steps: steps.clone(),
                            });
                            found_any = true;
                        }
                    }
                }
            }
        }
    }

    found_any
}

// Build windows using the same merge/pressure logic as the engine.
fn collect_windows_for_variant(
    buf: &[u8],
    rule: &RuleSpec,
    variant: Variant,
    tuning: &Tuning,
) -> Vec<Range<usize>> {
    let anchors = rule
        .anchors
        .iter()
        .map(|a| match variant {
            Variant::Raw => a.to_vec(),
            Variant::Utf16Le => utf16le_bytes(a),
            Variant::Utf16Be => utf16be_bytes(a),
        })
        .collect::<Vec<_>>();

    let seed_radius = match rule.two_phase.as_ref() {
        Some(tp) => tp.seed_radius,
        None => rule.radius,
    };
    let seed_radius_bytes = seed_radius.saturating_mul(variant.scale());

    let mut windows = Vec::new();
    push_anchor_windows(buf, &anchors, seed_radius_bytes, &mut windows);
    if windows.is_empty() {
        return windows;
    }

    merge_ranges_with_gap(&mut windows, tuning.merge_gap);
    coalesce_under_pressure(
        &mut windows,
        buf.len(),
        tuning.pressure_gap_start,
        tuning.max_windows_per_rule_variant,
    );

    let Some(tp) = rule.two_phase.as_ref() else {
        return windows;
    };

    let confirm = tp
        .confirm_any
        .iter()
        .map(|c| match variant {
            Variant::Raw => c.to_vec(),
            Variant::Utf16Le => utf16le_bytes(c),
            Variant::Utf16Be => utf16be_bytes(c),
        })
        .collect::<Vec<_>>();

    let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
    let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

    let mut expanded = Vec::new();
    for seed in windows {
        let win = &buf[seed.clone()];
        if !confirm.iter().any(|c| memmem::find(win, c).is_some()) {
            continue;
        }

        let lo = seed.start.saturating_sub(extra);
        let hi = (seed.end + extra).min(buf.len());
        expanded.push(lo..hi);
    }

    if expanded.is_empty() {
        return expanded;
    }

    merge_ranges_with_gap(&mut expanded, tuning.merge_gap);
    coalesce_under_pressure(
        &mut expanded,
        buf.len(),
        tuning.pressure_gap_start,
        tuning.max_windows_per_rule_variant,
    );

    expanded
}

fn push_anchor_windows(
    buf: &[u8],
    anchors: &[Vec<u8>],
    radius: usize,
    out: &mut Vec<Range<usize>>,
) {
    for anchor in anchors {
        if anchor.is_empty() {
            continue;
        }

        let mut start = 0usize;
        while start < buf.len() {
            let hay = &buf[start..];
            let Some(pos) = memmem::find(hay, anchor) else {
                break;
            };
            let idx = start + pos;
            let lo = idx.saturating_sub(radius);
            let hi = (idx + anchor.len() + radius).min(buf.len());
            out.push(lo..hi);
            start = idx + 1;
        }
    }
}

fn merge_ranges_with_gap(ranges: &mut Vec<Range<usize>>, gap: usize) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_by_key(|r| r.start);
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0].clone();

    for r in ranges.iter().skip(1) {
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
        } else {
            merged.push(cur);
            cur = r.clone();
        }
    }

    merged.push(cur);
    *ranges = merged;
}

fn coalesce_under_pressure(
    ranges: &mut Vec<Range<usize>>,
    hay_len: usize,
    mut gap: usize,
    max_windows: usize,
) {
    if ranges.len() <= max_windows {
        return;
    }

    while ranges.len() > max_windows && gap < hay_len {
        merge_ranges_with_gap(ranges, gap);
        gap = gap.saturating_mul(2);
    }

    if ranges.len() > max_windows && !ranges.is_empty() {
        let start = ranges.first().unwrap().start;
        let end = ranges.last().unwrap().end;
        ranges.clear();
        ranges.push(start.min(hay_len)..end.min(hay_len));
    }
}

#[derive(Clone, Debug)]
struct TokenCase {
    rule_name: &'static str,
    token: Vec<u8>,
}

#[derive(Clone, Debug)]
struct InputCase {
    rule_name: &'static str,
    buf: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum BaseEncoding {
    Raw,
    Utf16Le,
    Utf16Be,
}

#[derive(Clone, Copy, Debug)]
enum TransformChain {
    None,
    Url,
    Base64,
    UrlThenBase64,
    Base64ThenUrl,
}

const TOKEN_RULE_NAMES: &[&str] = &[
    "aws-access-token",
    "github-pat",
    "github-oauth",
    "github-app-token",
    "gitlab-pat",
    "slack-legacy-workspace-token",
    "slack-webhook-url",
    "stripe-access-token",
    "sendgrid-api-token",
    "npm-access-token",
    "databricks-api-token",
    "private-key",
];

fn token_strategy() -> BoxedStrategy<TokenCase> {
    const ALNUM_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const ALNUM_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const ALNUM_MIXED: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const GITLAB_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const SENDGRID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789=_-.";
    const DATABRICKS_CHARS: &[u8] = b"abcdefgh0123456789";

    let aws = prop::collection::vec(any::<u8>(), 16).prop_map(|bytes| {
        let mut token = b"AKIA".to_vec();
        token.extend(map_bytes(&bytes, ALNUM_UPPER));
        TokenCase {
            rule_name: "aws-access-token",
            token,
        }
    });

    let github_pat = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "github-pat",
        token: [b"ghp_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
    });

    let github_oauth = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "github-oauth",
        token: [b"gho_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
    });

    let github_app = prop::collection::vec(any::<u8>(), 37).prop_map(|bytes| {
        let prefixes = [b"ghu_".as_slice(), b"ghs_".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
        TokenCase {
            rule_name: "github-app-token",
            token,
        }
    });

    let gitlab_pat = prop::collection::vec(any::<u8>(), 20).prop_map(|bytes| TokenCase {
        rule_name: "gitlab-pat",
        token: [b"glpat-".as_slice(), &map_bytes(&bytes, GITLAB_CHARS)].concat(),
    });

    let slack_workspace = prop::collection::vec(any::<u8>(), 21).prop_map(|bytes| {
        let prefixes = [b"xoxa-".as_slice(), b"xoxr-".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
        TokenCase {
            rule_name: "slack-legacy-workspace-token",
            token,
        }
    });

    let slack_webhook = prop::collection::vec(any::<u8>(), 44).prop_map(|bytes| TokenCase {
        rule_name: "slack-webhook-url",
        token: [
            b"https://hooks.slack.com/services/".as_slice(),
            &map_bytes(&bytes, BASE64_CHARS),
        ]
        .concat(),
    });

    let stripe = prop::collection::vec(any::<u8>(), 17).prop_map(|bytes| {
        let prefixes = [
            b"sk_test_".as_slice(),
            b"sk_live_".as_slice(),
            b"pk_test_".as_slice(),
            b"pk_live_".as_slice(),
        ];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_LOWER));
        TokenCase {
            rule_name: "stripe-access-token",
            token,
        }
    });

    let sendgrid = prop::collection::vec(any::<u8>(), 67).prop_map(|bytes| {
        let prefixes = [b"SG.".as_slice(), b"sg.".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], SENDGRID_CHARS));
        TokenCase {
            rule_name: "sendgrid-api-token",
            token,
        }
    });

    let npm = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "npm-access-token",
        token: [b"npm_".as_slice(), &map_bytes(&bytes, ALNUM_LOWER)].concat(),
    });

    let databricks = prop::collection::vec(any::<u8>(), 33).prop_map(|bytes| {
        let prefixes = [b"dapi".as_slice(), b"DAPI".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], DATABRICKS_CHARS));
        TokenCase {
            rule_name: "databricks-api-token",
            token,
        }
    });

    let private_key = prop::collection::vec(any::<u8>(), 64).prop_map(|bytes| {
        let mut token = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
        token.extend(map_bytes(&bytes, BASE64_CHARS));
        token.extend(b"\n-----END PRIVATE KEY-----");
        TokenCase {
            rule_name: "private-key",
            token,
        }
    });

    prop_oneof![
        aws,
        github_pat,
        github_oauth,
        github_app,
        gitlab_pat,
        slack_workspace,
        slack_webhook,
        stripe,
        sendgrid,
        npm,
        databricks,
        private_key,
    ]
    .boxed()
}

fn base_encoding_strategy() -> BoxedStrategy<BaseEncoding> {
    prop_oneof![
        Just(BaseEncoding::Raw),
        Just(BaseEncoding::Utf16Le),
        Just(BaseEncoding::Utf16Be),
    ]
    .boxed()
}

fn transform_chain_strategy() -> BoxedStrategy<TransformChain> {
    prop_oneof![
        Just(TransformChain::None),
        Just(TransformChain::Url),
        Just(TransformChain::Base64),
        Just(TransformChain::UrlThenBase64),
        Just(TransformChain::Base64ThenUrl),
    ]
    .boxed()
}

fn input_case_strategy() -> BoxedStrategy<InputCase> {
    (
        token_strategy(),
        base_encoding_strategy(),
        transform_chain_strategy(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(token_case, base, chain, prefix, suffix)| {
            let mut token = token_case.token;
            if requires_trailing_delimiter(token_case.rule_name) {
                token.push(b' ');
            }
            let encoded = apply_encoding(&token, base, chain);
            let mut buf = Vec::new();
            buf.extend(prefix);
            buf.extend(encoded);
            buf.extend(suffix);
            InputCase {
                rule_name: token_case.rule_name,
                buf,
            }
        })
        .boxed()
}

fn map_bytes(bytes: &[u8], charset: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|b| charset[*b as usize % charset.len()])
        .collect()
}

fn apply_encoding(token: &[u8], base: BaseEncoding, chain: TransformChain) -> Vec<u8> {
    let bytes = match base {
        BaseEncoding::Raw => token.to_vec(),
        BaseEncoding::Utf16Le => utf16le_bytes(token),
        BaseEncoding::Utf16Be => utf16be_bytes(token),
    };

    match chain {
        TransformChain::None => bytes,
        TransformChain::Url => url_percent_encode_all(&bytes),
        TransformChain::Base64 => b64_encode(&bytes).into_bytes(),
        TransformChain::UrlThenBase64 => {
            let url = url_percent_encode_all(&bytes);
            b64_encode(&url).into_bytes()
        }
        TransformChain::Base64ThenUrl => {
            let b64 = b64_encode(&bytes);
            url_percent_encode_all(b64.as_bytes())
        }
    }
}

fn url_percent_encode_all(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len().saturating_mul(3));
    for &b in input {
        out.push(b'%');
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
    }
    out
}

fn requires_trailing_delimiter(rule_name: &str) -> bool {
    matches!(
        rule_name,
        "sendgrid-api-token" | "npm-access-token" | "databricks-api-token"
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RecKey {
    rule_id: u32,
    span_start: u32,
    span_end: u32,
}

fn scan_in_chunks_with_overlap(
    engine: &Engine,
    buf: &[u8],
    chunk_size: usize,
    overlap: usize,
) -> Vec<FindingRec> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();
    let mut batch = Vec::with_capacity(engine.tuning.max_findings_per_chunk);

    let mut tail = Vec::new();
    let mut tail_len = 0usize;
    let mut offset = 0usize;

    while offset < buf.len() {
        let read = (buf.len() - offset).min(chunk_size);
        let mut chunk = vec![0u8; tail_len + read];
        if tail_len > 0 {
            chunk[..tail_len].copy_from_slice(&tail[..tail_len]);
        }
        chunk[tail_len..tail_len + read].copy_from_slice(&buf[offset..offset + read]);

        let base_offset = offset.saturating_sub(tail_len) as u64;
        engine.scan_chunk_into(&chunk, FileId(0), base_offset, &mut scratch);
        scratch.drop_prefix_findings(offset as u64);
        scratch.drain_findings_into(&mut batch);
        out.append(&mut batch);

        let total_len = tail_len + read;
        let next_tail_len = overlap.min(total_len);
        if tail.len() < next_tail_len {
            tail.resize(next_tail_len, 0);
        }
        if next_tail_len > 0 {
            tail[..next_tail_len].copy_from_slice(&chunk[total_len - next_tail_len..total_len]);
        }
        tail_len = next_tail_len;
        offset += read;
    }

    out
}

fn scan_in_chunks(engine: &Engine, buf: &[u8], chunk_size: usize) -> Vec<FindingRec> {
    scan_in_chunks_with_overlap(engine, buf, chunk_size, engine.required_overlap())
}

fn recs_to_keys(recs: &[FindingRec]) -> HashSet<RecKey> {
    recs.iter()
        .map(|rec| RecKey {
            rule_id: rec.rule_id,
            span_start: rec.span_start,
            span_end: rec.span_end,
        })
        .collect()
}

fn replay_steps(engine: &Engine, root: &[u8], steps: &[DecodeStep]) -> Option<Vec<u8>> {
    let mut cur = root.to_vec();

    for step in steps {
        match step {
            DecodeStep::Transform {
                transform_idx,
                parent_span,
            } => {
                if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                    return None;
                }
                let tc = engine.transforms.get(*transform_idx)?;
                let decoded =
                    decode_to_vec(tc, &cur[parent_span.clone()], tc.max_decoded_bytes).ok()?;
                cur = decoded;
            }
            DecodeStep::Utf16Window {
                endianness,
                parent_span,
            } => {
                if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                    return None;
                }
                let max_out = engine.tuning.max_utf16_decoded_bytes_per_window;
                let decoded = match endianness {
                    Utf16Endianness::Le => {
                        decode_utf16le_to_vec(&cur[parent_span.clone()], max_out).ok()?
                    }
                    Utf16Endianness::Be => {
                        decode_utf16be_to_vec(&cur[parent_span.clone()], max_out).ok()?
                    }
                };
                cur = decoded;
            }
        }
    }

    Some(cur)
}

fn validate_findings(engine: &Engine, root: &[u8], findings: &[Finding]) -> Result<(), String> {
    for finding in findings {
        let buf = replay_steps(engine, root, &finding.decode_steps)
            .ok_or_else(|| format!("decode steps failed for {}", finding.rule))?;

        if finding.span.end > buf.len() {
            return Err(format!(
                "span out of bounds for {} ({} > {})",
                finding.rule,
                finding.span.end,
                buf.len()
            ));
        }

        let rule = engine
            .rules
            .iter()
            .find(|r| r.name == finding.rule)
            .ok_or_else(|| format!("rule not found: {}", finding.rule))?;

        let mut matched = false;
        for rm in rule.re.find_iter(&buf) {
            if rm.start() == finding.span.start && rm.end() == finding.span.end {
                matched = true;
                break;
            }
        }

        if !matched {
            return Err(format!(
                "span not aligned with regex for {} at {:?}",
                finding.rule, finding.span
            ));
        }
    }

    Ok(())
}

#[test]
fn token_strategy_covers_demo_rules() {
    let expected: HashSet<&str> = demo_rules().iter().map(|r| r.name).collect();
    let provided: HashSet<&str> = TOKEN_RULE_NAMES.iter().copied().collect();
    let missing: Vec<&str> = provided.difference(&expected).copied().collect();
    assert!(
        missing.is_empty(),
        "token strategy rules missing from demo rules: {missing:?}"
    );
}

#[test]
fn scan_file_sync_materializes_provenance_across_chunks() -> std::io::Result<()> {
    let engine = Arc::new(demo_engine());
    let runtime = ScannerRuntime::new(
        engine.clone(),
        ScannerConfig {
            chunk_size: 32,
            io_queue: 2,
            reader_threads: 1,
            scan_threads: 1,
        },
    );

    let aws = b"AKIAIOSFODNN7EXAMPLE"; // 20 bytes
    let utf16le = super::utf16le_bytes(aws);
    let b64 = b64_encode(&utf16le);

    let mut buf = vec![b'!'; 17];
    buf.extend_from_slice(b64.as_bytes());
    buf.extend(vec![b'!'; 17]);

    let tmp = write_temp_file(&buf)?;
    let findings = runtime.scan_file_sync(FileId(0), tmp.path())?;

    assert!(findings.iter().any(|f| f.rule == "aws-access-token"));
    if let Err(msg) = validate_findings(&engine, &buf, &findings) {
        panic!("{}", msg);
    }

    Ok(())
}

#[test]
fn scan_file_sync_drops_prefix_duplicates() -> std::io::Result<()> {
    const ANCHORS: &[&[u8]] = &[b"X"];
    let rules = vec![RuleSpec {
        name: "toy-token",
        anchors: ANCHORS,
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("X").unwrap(),
    }];
    let engine = Arc::new(Engine::new(rules, Vec::new(), demo_tuning()));
    let runtime = ScannerRuntime::new(
        engine,
        ScannerConfig {
            chunk_size: 4,
            io_queue: 1,
            reader_threads: 1,
            scan_threads: 1,
        },
    );

    let mut buf = vec![b'A'; 6];
    buf[3] = b'X'; // last byte of chunk 1, also prefix of chunk 2

    let tmp = write_temp_file(&buf)?;
    let findings = runtime.scan_file_sync(FileId(0), tmp.path())?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].root_span_hint, 3..4);

    Ok(())
}

#[test]
fn utf16_overlap_accounts_for_scaled_radius() {
    let rule = RuleSpec {
        name: "utf16-boundary",
        anchors: &[b"tok_"],
        radius: 12,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new(r"aaatok_[0-9]{8}bbbb").unwrap(),
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let anchor_len_utf16 = b"tok_".len() * 2;
    let radius = 12usize;
    let old_overlap = radius
        .saturating_mul(2)
        .saturating_add(anchor_len_utf16)
        .saturating_sub(1);
    let expected_overlap = anchor_len_utf16 + radius.saturating_mul(4) - 1;

    assert_eq!(engine.required_overlap(), expected_overlap);
    assert!(old_overlap < engine.required_overlap());

    let token = b"aaatok_12345678bbbb";
    let utf16 = utf16le_bytes(token);

    let mut buf = vec![b'!'; 30];
    buf.extend_from_slice(&utf16);
    buf.extend(vec![b'!'; 12]);

    let chunk_size = 67;

    let bad = scan_in_chunks_with_overlap(&engine, &buf, chunk_size, old_overlap);
    assert!(
        !bad.iter()
            .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
        "expected miss with undersized overlap"
    );

    let good = scan_in_chunks(&engine, &buf, chunk_size);
    assert!(
        good.iter()
            .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
        "expected match with required_overlap"
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_engine_matches_reference(case in input_case_strategy()) {
        let engine = demo_engine();
        let rules = demo_rules();

        let findings = scan_chunk_findings(&engine, &case.buf);
        let engine_keys = findings_to_keys(&findings);
        let ref_keys = reference_scan_keys(&engine, &rules, &case.buf);

        prop_assert_eq!(engine_keys, ref_keys);

        if let Err(msg) = validate_findings(&engine, &case.buf, &findings) {
            prop_assert!(false, "{}", msg);
        }
    }

    #[test]
    fn prop_chunked_matches_full(case in input_case_strategy(), chunk_size in 1usize..256) {
        let engine = demo_engine();
        let mut scratch = engine.new_scratch();
        let full = engine.scan_chunk_records(&case.buf, FileId(0), 0, &mut scratch);
        let chunked = scan_in_chunks(&engine, &case.buf, chunk_size);

        let full_keys = recs_to_keys(full);
        let chunked_keys = recs_to_keys(&chunked);

        prop_assert!(chunked_keys.is_superset(&full_keys));
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;

    const PROPTEST_CASES: u32 = 32;
    const PROPTEST_FUZZ_MULTIPLIER: u32 = 1;

    fn proptest_config() -> ProptestConfig {
        let cases = crate::test_utils::proptest_cases(PROPTEST_CASES);
        let mult = crate::test_utils::proptest_fuzz_multiplier(PROPTEST_FUZZ_MULTIPLIER);
        ProptestConfig::with_cases(cases.saturating_mul(mult))
    }

    proptest! {
        #![proptest_config(proptest_config())]

        #[test]
        fn prop_scan_chunk_reuse_scratch_matches_fresh(
            case_a in input_case_strategy(),
            case_b in input_case_strategy(),
        ) {
            let engine = demo_engine();
            let mut scratch = engine.new_scratch();
            let mut out = Vec::new();

            engine.scan_chunk_into(&case_a.buf, FileId(0), 0, &mut scratch);
            engine.drain_findings_materialized(&mut scratch, &mut out);
            let keys_a = findings_to_keys(&out);
            let fresh_a = findings_to_keys(&scan_chunk_findings(&engine, &case_a.buf));
            prop_assert_eq!(keys_a, fresh_a);

            out.clear();
            engine.scan_chunk_into(&case_b.buf, FileId(0), 0, &mut scratch);
            engine.drain_findings_materialized(&mut scratch, &mut out);
            let keys_b = findings_to_keys(&out);
            let fresh_b = findings_to_keys(&scan_chunk_findings(&engine, &case_b.buf));
            prop_assert_eq!(keys_b, fresh_b);
        }

        #[test]
        fn prop_hit_accumulator_coalesces(
            ranges in prop::collection::vec((0u32..512, 0u32..512), 0..128),
            max_hits in 1usize..32
        ) {
            let mut acc = HitAccumulator::with_capacity(max_hits);
            let mut ref_windows: Vec<SpanU32> = Vec::new();
            let mut ref_coalesced: Option<SpanU32> = None;

            for (a, b) in ranges {
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                let start = start as usize;
                let end = end as usize;
                acc.push(start, end, max_hits);

                let r = SpanU32::new(start, end);
                if let Some(c) = ref_coalesced.as_mut() {
                    c.start = c.start.min(r.start);
                    c.end = c.end.max(r.end);
                } else if ref_windows.len() < max_hits {
                    ref_windows.push(r);
                } else {
                    let mut c = ref_windows[0];
                    for w in &ref_windows[1..] {
                        c.start = c.start.min(w.start);
                        c.end = c.end.max(w.end);
                    }
                    c.start = c.start.min(r.start);
                    c.end = c.end.max(r.end);
                    ref_windows.clear();
                    ref_coalesced = Some(c);
                }
            }

            match (acc.coalesced, ref_coalesced) {
                (Some(actual), Some(expected)) => {
                    prop_assert_eq!(actual, expected);
                    prop_assert_eq!(acc.windows.len(), 0);
                }
                (None, None) => {
                    prop_assert_eq!(acc.windows.len(), ref_windows.len());
                    for (i, expected) in ref_windows.iter().enumerate() {
                        prop_assert_eq!(acc.windows[i], *expected);
                    }
                }
                _ => {
                    prop_assert!(false, "coalesced state mismatch");
                }
            }
        }

        #[test]
        fn prop_span_finders_match_vec_vs_scratch(
            buf in prop::collection::vec(any::<u8>(), 0..256),
            min_len in 1usize..32,
            max_len in 1usize..96,
            max_spans in 0usize..32,
            plus_to_space in any::<bool>(),
            allow_space_ws in any::<bool>(),
        ) {
            let max_len = max_len.max(min_len);
            let mut vec_out: Vec<Range<usize>> = Vec::new();
            let mut scratch_out: ScratchVec<Range<usize>> =
                ScratchVec::with_capacity(max_spans).unwrap();

            find_url_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                plus_to_space,
                &mut vec_out,
            );
            find_url_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                plus_to_space,
                &mut scratch_out,
            );
            prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());

            vec_out.clear();
            scratch_out.clear();
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut vec_out,
            );
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut scratch_out,
            );
            prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());
        }
    }
}
