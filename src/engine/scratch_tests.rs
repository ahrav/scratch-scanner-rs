use super::{normalize_root_hint_end_for_dedup, CachelineBoundary, ScanScratch};
use crate::api::{
    FileId, FindingRec, RuleSpec, StepId, TransformConfig, TransformId, Tuning, STEP_ROOT,
};
use crate::engine::Engine;
use regex::bytes::Regex;

#[test]
fn scanscratch_cold_region_is_cacheline_aligned() {
    assert_eq!(std::mem::align_of::<CachelineBoundary>(), 64);
    assert_eq!(std::mem::align_of::<ScanScratch>() % 64, 0);

    let cold_boundary_offset = std::mem::offset_of!(ScanScratch, _cold_boundary);
    let slab_offset = std::mem::offset_of!(ScanScratch, slab);

    assert_eq!(cold_boundary_offset % 64, 0);
    assert_eq!(slab_offset % 64, 0);
    assert!(slab_offset >= cold_boundary_offset);

    // Key hot fields must live before the cold boundary.
    let out_offset = std::mem::offset_of!(ScanScratch, out);
    let work_q_offset = std::mem::offset_of!(ScanScratch, work_q);
    let steps_buf_offset = std::mem::offset_of!(ScanScratch, steps_buf);

    assert!(
        out_offset < cold_boundary_offset,
        "out (findings) must be in the hot region"
    );
    assert!(
        work_q_offset < cold_boundary_offset,
        "work_q must be in the hot region"
    );
    assert!(
        steps_buf_offset < cold_boundary_offset,
        "steps_buf must be in the hot region"
    );
}

fn make_rec(
    step_id: StepId,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
) -> FindingRec {
    FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start,
        span_end,
        root_hint_start,
        root_hint_end,
        dedupe_with_span: false,
        step_id,
    }
}

fn test_tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 64,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 256,
        max_utf16_decoded_bytes_per_window: 4096,
        max_transform_depth: 2,
        max_total_decode_output_bytes: 1024 * 1024,
        max_work_items: 64,
        max_findings_per_chunk: 4096,
        scan_utf16_variants: true,
    }
}

fn simple_rule() -> RuleSpec {
    RuleSpec {
        name: "test-secret",
        anchors: &[b"SECRET"],
        radius: 32,
        validator: crate::api::ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        local_context: None,
        secret_group: None,
        offline_validation: None,
        re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
    }
}

fn new_test_scratch() -> ScanScratch {
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    engine.new_scratch()
}

#[test]
fn engine_normalize_url_percent_not_snapped() {
    // decoded_len=13, min_encoded(base64)=18
    // root_hint_end = root_hint_start + 19 (min+1, in padding window)
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::UrlPercent));
    // UrlPercent must NOT snap — returns original root_hint_end
    assert_eq!(result, 1019);
}

#[test]
fn engine_normalize_base64_snaps() {
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::Base64));
    // Base64: decoded_len=13, min_encoded=18, actual=19, snap to 1018
    assert_eq!(result, 1018);
}

#[test]
fn engine_normalize_root_unchanged() {
    let rec = make_rec(STEP_ROOT, 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::Base64));
    assert_eq!(result, 1019);
}

#[test]
fn engine_normalize_none_transform_not_snapped() {
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, None);
    assert_eq!(result, 1019);
}

#[test]
fn drain_findings_with_hashes_preserves_alignment_and_order() {
    let mut scratch = new_test_scratch();
    let rec_a = make_rec(STEP_ROOT, 10, 16, 100, 106);
    let rec_b = make_rec(STEP_ROOT, 20, 26, 200, 206);
    let hash_a = [0xA1; 32];
    let hash_b = [0xB2; 32];

    scratch.push_finding(rec_a, hash_a);
    scratch.push_finding(rec_b, hash_b);

    let mut findings_out = Vec::with_capacity(2);
    let mut hash_out = Vec::with_capacity(2);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);

    assert_eq!(findings_out, vec![rec_a, rec_b]);
    assert_eq!(hash_out, vec![hash_a, hash_b]);
    assert_eq!(scratch.pending_findings_len(), 0);
    assert!(scratch.norm_hashes().is_empty());
    assert!(scratch.drop_hint_end().is_empty());
}

#[test]
#[should_panic(expected = "findings output capacity too small")]
fn drain_findings_with_hashes_panics_when_findings_capacity_too_small() {
    let mut scratch = new_test_scratch();
    scratch.push_finding(make_rec(STEP_ROOT, 10, 16, 100, 106), [0x11; 32]);
    scratch.push_finding(make_rec(STEP_ROOT, 20, 26, 200, 206), [0x22; 32]);

    let mut findings_out = Vec::with_capacity(1);
    let mut hash_out = Vec::with_capacity(2);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);
}

#[test]
#[should_panic(expected = "norm-hash output capacity too small")]
fn drain_findings_with_hashes_panics_when_hash_capacity_too_small() {
    let mut scratch = new_test_scratch();
    scratch.push_finding(make_rec(STEP_ROOT, 10, 16, 100, 106), [0x11; 32]);
    scratch.push_finding(make_rec(STEP_ROOT, 20, 26, 200, 206), [0x22; 32]);

    let mut findings_out = Vec::with_capacity(2);
    let mut hash_out = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);
}

#[test]
fn cross_chunk_dedupe_tracks_candidates_beyond_emit_cap() {
    let mut tuning = test_tuning();
    tuning.max_findings_per_chunk = 8;
    let engine = Engine::new(vec![simple_rule()], Vec::<TransformConfig>::new(), tuning);
    let mut scratch = engine.new_scratch();

    let make_candidate = |idx: u32| {
        make_rec(
            STEP_ROOT,
            idx.saturating_mul(2),
            idx.saturating_mul(2).saturating_add(1),
            1_000u64.saturating_add(u64::from(idx).saturating_mul(10)),
            1_004u64.saturating_add(u64::from(idx).saturating_mul(10)),
        )
    };

    scratch.update_chunk_overlap(FileId(0), 0, 1024);
    for idx in 0..80u32 {
        let rec = make_candidate(idx);
        let mut norm_hash = [0u8; 32];
        norm_hash[0] = idx as u8;
        scratch.push_finding_with_drop_hint(
            rec,
            norm_hash,
            rec.root_hint_end,
            rec.dedupe_with_span,
        );
    }
    assert_eq!(
        scratch.pending_findings_len(),
        8,
        "emit cap should keep only the first eight pending findings"
    );

    scratch.reset_for_scan_after_prefilter(&engine);
    scratch.update_chunk_overlap(FileId(0), 768, 1024);

    let duplicate = make_candidate(79);
    scratch.push_finding_with_drop_hint(
        duplicate,
        [79u8; 32],
        duplicate.root_hint_end,
        duplicate.dedupe_with_span,
    );

    assert_eq!(
        scratch.pending_findings_len(),
        0,
        "cross-chunk duplicate should be suppressed even when first sighting exceeded emit cap"
    );
}
