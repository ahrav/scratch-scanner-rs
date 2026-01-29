//! Engine tests and property checks.
//!
//! These tests exercise anchor selection, transform gating, and provenance
//! tracking. A slow reference scanner is included to validate correctness
//! across transforms and UTF-16 variants.

use super::*;
use crate::tiger_harness::{
    check_oracle_covered, correctness_engine, load_regressions_from_dir, maybe_write_regression,
    scan_chunked_records, scan_one_chunk_records, ChunkPattern, ChunkPlan,
};
use proptest::prelude::*;
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::vectorscan_prefilter::{
    gate_match_callback, stream_match_callback, VsStreamMatchCtx, VsStreamWindow,
};

fn decoded_prefilter_hit(engine: &Engine, decoded: &[u8]) -> bool {
    if let Some(vs_gate) = engine.vs_gate.as_ref() {
        let mut scratch = match vs_gate.alloc_scratch() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut stream = match vs_gate.open_stream() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut hit: u8 = 0;
        let cb = gate_match_callback();
        if vs_gate
            .scan_stream(
                &mut stream,
                decoded,
                &mut scratch,
                cb,
                (&mut hit as *mut u8).cast(),
            )
            .is_err()
        {
            let _ = vs_gate.close_stream(stream, &mut scratch, cb, (&mut hit as *mut u8).cast());
            return false;
        }
        if vs_gate
            .close_stream(stream, &mut scratch, cb, (&mut hit as *mut u8).cast())
            .is_err()
        {
            return false;
        }
        return hit != 0;
    }

    let Some(vs_stream) = engine.vs_stream.as_ref() else {
        return true;
    };

    let mut scratch = match vs_stream.alloc_scratch() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut stream = match vs_stream.open_stream() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut pending: Vec<VsStreamWindow> = Vec::new();
    let mut ctx = VsStreamMatchCtx {
        pending: &mut pending as *mut Vec<VsStreamWindow>,
        meta: vs_stream.meta().as_ptr(),
        meta_len: vs_stream.meta().len() as u32,
    };
    let cb = stream_match_callback();

    if vs_stream
        .scan_stream(
            &mut stream,
            decoded,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        )
        .is_err()
    {
        let _ = vs_stream.close_stream(
            stream,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        );
        return false;
    }
    let mut hit = !pending.is_empty();
    pending.clear();

    if vs_stream
        .close_stream(
            stream,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        )
        .is_err()
    {
        return false;
    }
    if !pending.is_empty() {
        hit = true;
    }

    hit
}

// Helper that uses the allocation-free scan API and materializes findings.
fn scan_chunk_findings(engine: &Engine, hay: &[u8]) -> Vec<Finding> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut out);
    out
}

fn unpack_patterns(pats: &PackedPatterns) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let count = pats.offsets.len().saturating_sub(1);
    for i in 0..count {
        let start = pats.offsets[i] as usize;
        let end = pats.offsets[i + 1] as usize;
        out.push(pats.bytes[start..end].to_vec());
    }
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

fn is_b64_char_ref(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_')
}

fn is_b64_ws_ref(b: u8, allow_space_ws: bool) -> bool {
    matches!(b, b'\n' | b'\r' | b'\t') || (allow_space_ws && b == b' ')
}

fn is_b64_or_ws_ref(b: u8, allow_space_ws: bool) -> bool {
    is_b64_char_ref(b) || is_b64_ws_ref(b, allow_space_ws)
}

fn find_base64_spans_reference(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
) -> Vec<Range<usize>> {
    assert!(max_len >= min_chars);
    let mut spans: Vec<Range<usize>> = Vec::new();
    if max_spans == 0 {
        return spans;
    }

    let mut i = 0usize;
    while i < hay.len() && spans.len() < max_spans {
        while i < hay.len() && !is_b64_or_ws_ref(hay[i], allow_space_ws) {
            i += 1;
        }
        if i >= hay.len() {
            break;
        }

        let start = i;
        let mut b64_chars = 0usize;
        let mut last_b64 = None::<usize>;

        while i < hay.len() && (i - start) < max_len {
            let b = hay[i];
            if !is_b64_or_ws_ref(b, allow_space_ws) {
                break;
            }
            if is_b64_char_ref(b) {
                b64_chars += 1;
                last_b64 = Some(i);
            }
            i += 1;
        }

        if b64_chars >= min_chars {
            if let Some(last) = last_b64 {
                spans.push(start..(last + 1));
            }
        }
    }

    spans
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
fn base64_span_trims_trailing_space_when_allowed() {
    let hay = b"AAAA   ";
    let mut spans = Vec::new();
    find_base64_spans_into(hay, 2, 32, 8, true, &mut spans);
    assert_eq!(spans, vec![0..4]);
}

#[test]
fn base64_span_includes_leading_space_when_allowed() {
    let hay = b"  AAAA";
    let mut spans = Vec::new();
    find_base64_spans_into(hay, 2, 32, 8, true, &mut spans);
    assert_eq!(spans, vec![0..6]);
}

#[test]
fn base64_span_disallows_space_when_flag_false() {
    let hay = b"AA AA";
    let mut spans = Vec::new();
    find_base64_spans_into(hay, 1, 32, 8, false, &mut spans);
    assert_eq!(spans, vec![0..2, 3..5]);
}

#[test]
fn base64_span_respects_min_chars() {
    let hay = b"A \tA";
    let mut spans = Vec::new();
    find_base64_spans_into(hay, 3, 32, 8, true, &mut spans);
    assert!(spans.is_empty());
}

#[test]
fn base64_span_respects_max_len() {
    let hay = b"AAAAAAAAAA";
    let mut spans = Vec::new();
    find_base64_spans_into(hay, 1, 4, 8, false, &mut spans);
    assert_eq!(spans, vec![0..4, 4..8, 8..10]);
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
fn derived_confirm_all_is_compiled() {
    let rule = RuleSpec {
        name: "confirm-all",
        anchors: &[],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new(r"foo\d+bar").unwrap(),
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::DerivedOnly,
    );

    let derive_cfg = AnchorDeriveConfig {
        utf8: false,
        ..AnchorDeriveConfig::default()
    };
    let expected = match compile_trigger_plan(r"foo\d+bar", &derive_cfg).unwrap() {
        TriggerPlan::Anchored { confirm_all, .. } => confirm_all,
        other => panic!("expected anchored plan, got {other:?}"),
    };

    let compiled = &eng.rules[0];
    let compiled_confirm = compiled.confirm_all.as_ref();
    if expected.is_empty() {
        assert!(
            compiled_confirm.is_none(),
            "confirm_all should be omitted when no extra literals are required"
        );
    } else {
        let confirm = compiled_confirm.expect("confirm_all should be compiled");
        let primary = confirm.primary[Variant::Raw.idx()]
            .as_ref()
            .expect("confirm_all primary must be set");
        let mut literals = vec![primary.clone()];
        literals.extend(unpack_patterns(&confirm.rest[Variant::Raw.idx()]));

        let expected_set: HashSet<Vec<u8>> = expected.into_iter().collect();
        let actual_set: HashSet<Vec<u8>> = literals.into_iter().collect();
        assert_eq!(
            actual_set, expected_set,
            "confirm_all literals should match"
        );
    }

    let hay = b"zzzfoo123barzzz";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(hits.iter().any(|h| h.rule == "confirm-all"));
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
    #[cfg(feature = "stats")]
    {
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.derived_rules, 1);
        assert_eq!(stats.manual_rules, 0);
    }

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
    #[cfg(feature = "stats")]
    {
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.manual_rules, 1);
        assert_eq!(stats.derived_rules, 0);
        assert_eq!(stats.unfilterable_rules, 1);
    }

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

                if tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded {
                    if let Some(gate) = &engine.b64_gate {
                        if !gate.hits(enc) {
                            continue;
                        }
                    }
                }

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

                if tc.gate == Gate::AnchorsInDecoded {
                    let gate_satisfied = decoded_prefilter_hit(engine, &decoded);
                    let enforce_gate = if engine.vs_gate.is_some() {
                        true
                    } else {
                        !engine.tuning.scan_utf16_variants || !engine.has_utf16_anchors
                    };
                    if enforce_gate && !gate_satisfied {
                        continue;
                    }
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
    let mut runtime = ScannerRuntime::new(
        engine.clone(),
        ScannerConfig {
            chunk_size: 32,
            io_queue: 2,
            reader_threads: 1,
            scan_threads: 1,
            max_findings_per_file: 1024,
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
    if let Err(msg) = validate_findings(&engine, &buf, findings) {
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
    let mut runtime = ScannerRuntime::new(
        engine,
        ScannerConfig {
            chunk_size: 4,
            io_queue: 1,
            reader_threads: 1,
            scan_threads: 1,
            max_findings_per_file: 64,
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
    let expected_overlap = engine
        .max_prefilter_width
        .saturating_add(radius.saturating_mul(4))
        .saturating_sub(1);

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

// --------------------------
// Tiger-style chunking nondeterminism harness
// --------------------------

proptest! {
    // Keep this relatively small: each case runs multiple chunking plans.
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_tiger_chunk_plans_cover_oracle(
        case in input_case_strategy(),
        seed in any::<u64>(),
    ) {
        let engine = correctness_engine();
        let oracle = scan_one_chunk_records(&engine, &case.buf);

        // A small set of "interesting" sizes that tends to shake out edge cases.
        const SIZES: &[usize] = &[
            1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
        ];

        let pick = |shift: u32| -> usize { SIZES[((seed >> shift) as usize) % SIZES.len()] };

        let s0 = pick(0);
        let s1 = pick(8);
        let s2 = pick(16);
        let s3 = pick(24);

        // Force at least one plan where the chunk size exceeds required overlap.
        // Otherwise very small chunks can overlap the whole previous chunk, which
        // is correct but less stressful.
        let overlap = engine.required_overlap();
        let big = overlap.saturating_add(1).saturating_add(seed as usize % 512);

        // Shift boundaries by making the first chunk a different size.
        let first_shift = 1 + ((seed >> 32) as usize % 64);

        let plans: Vec<ChunkPlan> = vec![
            ChunkPlan::fixed(s0),
            ChunkPlan::fixed_shifted(s0, first_shift),
            ChunkPlan::alternating(s1, s2),
            ChunkPlan::random_range(seed, 1, s3.max(1)).with_first_chunk(first_shift),
            ChunkPlan {
                pattern: ChunkPattern::Sequence(vec![1, s0, 2, s1, 3, s2, 5, s3]),
                seed: 0,
                first_chunk_len: None,
            },
            ChunkPlan::fixed(big).with_first_chunk(first_shift),
        ];

        for plan in plans {
            let plan_dbg = format!("{plan:?}");
            // Preserve the exact plan for regression capture before it is consumed.
            let plan_for_regression = plan.clone();
            let chunked = scan_chunked_records(&engine, &case.buf, plan);
            if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
                maybe_write_regression(
                    "tiger_chunk_plans_cover_oracle",
                    seed,
                    &plan_for_regression,
                    &case.buf,
                );
                prop_assert!(false, "plan={}: {}", plan_dbg, msg);
            }
        }
    }
}

proptest! {
    // Focused boundary-alignment property: ensure a secret instance that
    // straddles a chunk boundary is still reported.
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_tiger_boundary_crossing_not_dropped(
        token_case in token_strategy(),
        base in base_encoding_strategy(),
        chain in transform_chain_strategy(),
        seed in any::<u64>(),
    ) {
        let engine = correctness_engine();
        let overlap = engine.required_overlap();

        // Build an encoded secret instance with safe surrounding bytes so
        // word-boundary + delimiter validators are more likely to pass.
        let mut token = token_case.token;
        if requires_trailing_delimiter(token_case.rule_name) {
            token.push(b' ');
        }

        let encoded = apply_encoding(&token, base, chain);
        prop_assume!(encoded.len() >= 2);

        // Choose a chunk size > overlap so we are testing the contract
        // "overlap is sufficient", not the degenerate case where overlap equals
        // the whole previous chunk.
        let chunk_size = overlap.saturating_add(1).saturating_add(seed as usize % 256);

        let k_max = overlap.min(encoded.len() - 1);
        prop_assume!(k_max >= 1);

        // Try a handful of k alignments that hit:
        // - base64 quanta boundaries (mod 4)
        // - url-percent triplets (mod 3)
        // - utf16 odd/even boundaries (mod 2)
        let ks = [1usize, 2, 3, 4, 7, 8, 15];

        for &k in ks.iter() {
            if k > k_max {
                continue;
            }

            // Place the token so that it starts `k` bytes before the boundary at
            // `chunk_size`. That makes the token start within the overlap prefix
            // of chunk 2, and finish in its payload.
            let start = chunk_size - k;

            let mut buf = vec![b'A'; start];
            // Force a non-word byte right before the secret; this satisfies rules with
            // require_word_boundary_before=true more often than random bytes.
            if start > 0 {
                buf[start - 1] = b' ';
            }

            buf.extend_from_slice(&encoded);
            buf.push(b' ');
            buf.extend_from_slice(b"ZZZ");

            let oracle = scan_one_chunk_records(&engine, &buf);
            prop_assume!(!oracle.is_empty());

            let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
            if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
                let plan = ChunkPlan::fixed(chunk_size);
                maybe_write_regression(
                    "tiger_boundary_crossing_not_dropped",
                    seed,
                    &plan,
                    &buf,
                );
                prop_assert!(false, "chunk_size={} k={}: {}", chunk_size, k, msg);
            }
        }
    }
}

#[test]
fn tiger_regressions_replay() {
    // Replays any captured regressions to keep failures sticky and reproducible.
    // The directory is optional so CI can run even when no regressions exist.
    let dir = Path::new("tests/regressions/tiger_chunking");
    let cases = match load_regressions_from_dir(dir) {
        Ok(cases) => cases,
        Err(err) => panic!("failed to load tiger regressions: {}", err),
    };

    if cases.is_empty() {
        return;
    }

    let engine = correctness_engine();
    for case in cases {
        let oracle = scan_one_chunk_records(&engine, &case.input);
        let chunked = scan_chunked_records(&engine, &case.input, case.plan.clone());
        if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
            panic!(
                "regression {:?} ({:?}) failed: {}",
                case.path, case.label, msg
            );
        }
    }
}

#[test]
fn tiger_boundary_percent_triplet_split() {
    // Explicitly split a `%AB` percent triplet so '%' ends a chunk and the
    // two hex digits begin the next chunk. This exercises URL-percent decoding
    // across chunk boundaries.
    let engine = correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let encoded = url_percent_encode_all(token);
    assert_eq!(encoded.first(), Some(&b'%'));

    let chunk_size = overlap.saturating_add(1);
    let start = chunk_size.saturating_sub(1);

    let mut buf = vec![b'A'; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.push(b' ');
    buf.extend_from_slice(b"ZZZ");

    assert_eq!(buf[chunk_size - 1], b'%');

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for percent triplet split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("percent triplet split failed: {}", msg);
    }
}

#[test]
fn tiger_boundary_base64_padding_split() {
    // Ensure base64 '=' padding is split across the chunk boundary so the
    // decoder must carry padding state across chunks.
    let engine = correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let encoded = b64_encode(token).into_bytes();
    assert!(encoded.len() >= 2);
    assert_eq!(&encoded[encoded.len() - 2..], b"==");

    let mut chunk_size = overlap.saturating_add(1);
    if chunk_size < encoded.len() {
        chunk_size = encoded.len();
    }
    let start = chunk_size.saturating_sub(encoded.len().saturating_sub(1));

    let mut buf = vec![b'A'; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.push(b' ');
    buf.extend_from_slice(b"ZZZ");

    assert!(buf.len() > chunk_size);
    assert_eq!(buf[chunk_size - 1], b'=');
    assert_eq!(buf[chunk_size], b'=');

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for base64 padding split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("base64 padding split failed: {}", msg);
    }
}

#[test]
fn base64_gate_utf16be_anchor_straddles_stream_boundary() {
    // The base64 stream decoder flushes output in ~1KB chunks (1020 bytes),
    // so we place a UTF-16BE anchor so its final byte lands in a 1-byte tail
    // chunk. The gate must inspect tail+chunk to see the NULs and match.
    let rule = RuleSpec {
        name: "utf16be-gate-boundary",
        anchors: &[b"TOK"],
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("TOK").unwrap(),
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 8 * 1024,
        max_decoded_bytes: 8 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);
    tuning.scan_utf16_variants = true;

    let engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);

    let utf16 = utf16be_bytes(b"TOK");
    let flush_len = 1020usize; // stream_decode_base64 flush threshold
    let prefix_len = flush_len - (utf16.len().saturating_sub(1));

    let mut decoded = vec![b'A'; prefix_len];
    decoded.extend_from_slice(&utf16);
    assert_eq!(decoded.len(), flush_len + 1);

    let encoded = b64_encode(&decoded).into_bytes();
    let hits = scan_chunk_findings(&engine, &encoded);

    assert!(
        hits.iter().any(|h| h.rule == "utf16be-gate-boundary"),
        "expected utf16be match to survive base64 gate boundary"
    );
}

#[test]
fn stream_window_recovers_after_ring_eviction() {
    let rule = RuleSpec {
        name: "ring-evict-window",
        anchors: &[b"TOK"],
        radius: 128,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("TOK").unwrap(),
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 8,
        max_spans_per_buffer: 4,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);

    let mut engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }
    engine.stream_ring_bytes = 32;

    let mut decoded = vec![b'A'; 256];
    decoded.extend_from_slice(b"TOK");
    decoded.extend(std::iter::repeat_n(b'B', 256));
    let encoded = b64_encode(&decoded).into_bytes();

    let hits = scan_chunk_findings(&engine, &encoded);
    assert!(
        hits.iter().any(|h| h.rule == "ring-evict-window"),
        "expected match to survive ring eviction"
    );
}

#[test]
fn stream_hit_cap_forces_full_fallback() {
    let rule = RuleSpec {
        name: "stream-hit-cap-fallback",
        anchors: &[b"TOK"],
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("TOK").unwrap(),
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 8,
        max_spans_per_buffer: 4,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_windows_per_rule_variant = 1;
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);

    let engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let mut decoded = Vec::new();
    decoded.extend_from_slice(b"TOK");
    decoded.extend(std::iter::repeat_n(b'A', 512));
    decoded.extend_from_slice(b"TOK");
    let encoded = b64_encode(&decoded).into_bytes();

    let hits = scan_chunk_findings(&engine, &encoded);
    let count = hits
        .iter()
        .filter(|h| h.rule == "stream-hit-cap-fallback")
        .count();
    assert!(count >= 2, "expected >=2 matches, got {count}");
}

#[test]
fn stream_nested_span_fallback_recovers() {
    let rule = RuleSpec {
        name: "nested-span-fallback",
        anchors: &[b"TOK"],
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        re: Regex::new("TOK").unwrap(),
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 4,
        max_spans_per_buffer: 8,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(16 * 1024);

    let mut engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }
    engine.stream_ring_bytes = 32;

    let inner = b64_encode(b"TOK");
    let mut outer_decoded = Vec::new();
    outer_decoded.extend(std::iter::repeat_n(b'A', 128));
    outer_decoded.extend_from_slice(inner.as_bytes());
    outer_decoded.extend(std::iter::repeat_n(b'B', 128));

    let outer_encoded = b64_encode(&outer_decoded).into_bytes();
    let hits = scan_chunk_findings(&engine, &outer_encoded);
    assert!(
        hits.iter().any(|h| h.rule == "nested-span-fallback"),
        "expected nested span to be recovered via fallback"
    );
}

#[test]
fn tiger_boundary_utf16_odd_byte_split() {
    // Split a UTF-16LE encoded anchor on an odd byte boundary so the decoder
    // must reconstruct code units across chunks.
    let engine = correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"AKIAIOSFODNN7EXAMPLE";
    let encoded = utf16le_bytes(token);
    assert!(encoded.len() >= 2);

    let chunk_size = overlap.saturating_add(1);
    let start = chunk_size.saturating_sub(1);

    let mut buf = vec![0u8; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.extend_from_slice(&[b' ', 0]);
    buf.extend_from_slice(b"ZZZ");

    assert_eq!(buf[chunk_size - 1], encoded[0]);
    assert_eq!(buf[chunk_size], encoded[1]);

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for utf16 odd-byte split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("utf16 odd-byte split failed: {}", msg);
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

        #[test]
        fn prop_base64_spans_match_reference(
            buf in prop::collection::vec(any::<u8>(), 0..256),
            min_len in 1usize..32,
            max_len in 1usize..96,
            max_spans in 0usize..32,
            allow_space_ws in any::<bool>(),
        ) {
            let max_len = max_len.max(min_len);
            let mut actual = Vec::new();
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut actual,
            );

            let expected = find_base64_spans_reference(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
            );

            prop_assert_eq!(actual.as_slice(), expected.as_slice());
        }
    }
}
