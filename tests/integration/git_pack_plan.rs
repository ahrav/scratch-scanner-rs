//! Integration tests for pack planning against synthetic pack bytes.
//!
//! These tests construct minimal PACK buffers with explicit delta chains so
//! the pack planner can be validated without relying on real repositories.
//! The PACK trailers are dummy-sized (OID length only); checksums are not
//! verified by the planner.

use std::collections::HashMap;

use scanner_rs::git_scan::{
    build_pack_plans, BaseLoc, ByteRef, CandidateContext, ChangeKind, DeltaKind, OidBytes,
    PackCandidate, PackPlanConfig, PackPlanError, PackView,
};
use scanner_rs::git_scan::{OidResolver, PackPlan};

struct NoopResolver;

impl OidResolver for NoopResolver {
    fn resolve(&self, _oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(None)
    }
}

struct TestResolver {
    map: HashMap<OidBytes, (u16, u64)>,
}

impl OidResolver for TestResolver {
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(self.map.get(oid).copied())
    }
}

fn ctx() -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    }
}

/// Encodes a minimal pack object header for the given type/size.
fn encode_obj_header(obj_type: u8, mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = ((obj_type & 0x07) << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size != 0 {
        first |= 0x80;
    }
    out.push(first);
    while size != 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

/// Encodes an OFS_DELTA base distance using Git's pack format.
fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
    assert!(dist > 0);
    let mut bytes = Vec::new();
    bytes.push((dist & 0x7f) as u8);
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(((dist & 0x7f) as u8) | 0x80);
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Builds a minimal PACK buffer with room for the trailing checksum bytes.
fn build_pack(oid_len: usize, entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut max_end = 12u64;
    for (offset, bytes) in entries {
        let end = offset + bytes.len() as u64;
        if end > max_end {
            max_end = end;
        }
    }
    let total_len = max_end as usize + oid_len;
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(b"PACK");
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf[8..12].copy_from_slice(&(entries.len() as u32).to_be_bytes());
    for (offset, bytes) in entries {
        let start = *offset as usize;
        buf[start..start + bytes.len()].copy_from_slice(bytes);
    }
    buf
}

fn unpack_plan(plans: Vec<PackPlan>) -> PackPlan {
    assert_eq!(plans.len(), 1);
    plans.into_iter().next().unwrap()
}

#[test]
fn ofs_delta_chain_includes_base_closure() {
    let base_offset = 12u64;
    let delta1_offset = 32u64;
    let delta2_offset = 52u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta1_header = encode_obj_header(6, 1);
    delta1_header.extend_from_slice(&encode_ofs_distance(delta1_offset - base_offset));
    let mut delta2_header = encode_obj_header(6, 1);
    delta2_header.extend_from_slice(&encode_ofs_distance(delta2_offset - delta1_offset));

    let pack_bytes = build_pack(
        20,
        &[
            (base_offset, base_header),
            (delta1_offset, delta1_header),
            (delta2_offset, delta2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x11; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 2,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );
    assert_eq!(
        plan.need_offsets,
        vec![base_offset, delta1_offset, delta2_offset]
    );
}

#[test]
fn ofs_delta_chain_respects_depth_limit() {
    let base_offset = 12u64;
    let delta1_offset = 32u64;
    let delta2_offset = 52u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta1_header = encode_obj_header(6, 1);
    delta1_header.extend_from_slice(&encode_ofs_distance(delta1_offset - base_offset));
    let mut delta2_header = encode_obj_header(6, 1);
    delta2_header.extend_from_slice(&encode_ofs_distance(delta2_offset - delta1_offset));

    let pack_bytes = build_pack(
        20,
        &[
            (base_offset, base_header),
            (delta1_offset, delta1_header),
            (delta2_offset, delta2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xaa; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 1,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );
    assert_eq!(plan.need_offsets, vec![delta1_offset, delta2_offset]);
}

#[test]
fn worklist_limit_exceeded_on_delta_expansion() {
    let base_offset = 12u64;
    let delta_offset = 32u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta_header = encode_obj_header(6, 1);
    delta_header.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));

    let pack_bytes = build_pack(
        20,
        &[(base_offset, base_header), (delta_offset, delta_header)],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xbb; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 1,
        max_worklist_entries: 1,
        ..Default::default()
    };

    let err = build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap_err();
    assert!(matches!(
        err,
        PackPlanError::WorklistLimitExceeded {
            limit: 1,
            observed: 2
        }
    ));
}

#[test]
fn ref_delta_inside_pack_is_resolved() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x22; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let mut map = HashMap::new();
    map.insert(base_oid, (0u16, base_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x33; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &resolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets, vec![base_offset, ref_offset]);

    let dep = plan
        .delta_deps
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::Offset(o) if o == base_offset));
}

#[test]
fn ref_delta_outside_pack_is_external() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x44; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let mut map = HashMap::new();
    map.insert(base_oid, (1u16, base_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x55; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &resolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets, vec![ref_offset]);
    assert_eq!(plan.stats.external_bases, 1);

    let dep = plan
        .delta_deps
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::External { oid } if oid == base_oid));
}

#[test]
fn ref_delta_missing_base_is_external() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x66; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x77; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &NoopResolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets, vec![ref_offset]);
    assert_eq!(plan.stats.external_bases, 1);

    let dep = plan
        .delta_deps
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::External { oid } if oid == base_oid));
}

#[test]
fn ref_delta_base_lookup_limit_enforced() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x88; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x99; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let config = PackPlanConfig {
        max_base_lookups: 0,
        ..Default::default()
    };

    let err = build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap_err();
    assert!(matches!(
        err,
        PackPlanError::BaseLookupLimitExceeded {
            limit: 0,
            observed: 1
        }
    ));
}
