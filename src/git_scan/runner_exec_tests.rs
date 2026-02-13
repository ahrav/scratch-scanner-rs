use super::*;
use crate::git_scan::object_id::OidBytes;
use crate::git_scan::pack_decode::PackDecodeLimits;
use crate::git_scan::pack_plan_model::{BaseLoc, DeltaDep, DeltaKind, PackPlanStats, NONE_U32};
use crate::git_scan::{ByteRef, CandidateContext, ChangeKind};
use crate::{
    demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId, TransformMode,
    ValidatorKind,
};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use regex::bytes::Regex;
use std::io::Write;
use tempfile::tempdir;

use crate::git_scan::engine_adapter::{EngineAdapter, EngineAdapterConfig};
use crate::git_scan::midx::MidxView;
use crate::git_scan::object_id::ObjectFormat;
use crate::git_scan::pack_candidates::PackCandidate;
use crate::git_scan::pack_io::{PackIo, PackIoError, PackIoLimits};

fn synthetic_plan(
    pack_id: u16,
    need_count: usize,
    span_bytes: u64,
    forward_deps: usize,
    external_deps: usize,
) -> PackPlan {
    let effective_span = span_bytes.max(need_count.saturating_sub(1) as u64);
    let step = if need_count <= 1 {
        0
    } else {
        (effective_span / (need_count as u64 - 1)).max(1)
    };
    let need_offsets: Vec<u64> = (0..need_count)
        .map(|idx| (idx as u64).saturating_mul(step))
        .collect();

    let mut delta_deps = Vec::with_capacity(forward_deps.saturating_add(external_deps));
    for idx in 0..forward_deps {
        let offset = idx as u64;
        delta_deps.push(DeltaDep {
            offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(offset.saturating_add(1)),
            data_start: 0,
            delta_size: 0,
        });
    }
    for idx in 0..external_deps {
        let offset = forward_deps.saturating_add(idx) as u64;
        delta_deps.push(DeltaDep {
            offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::External {
                oid: OidBytes::default(),
            },
            data_start: 0,
            delta_size: 0,
        });
    }
    delta_deps.sort_by_key(|dep| dep.offset);
    let mut delta_dep_index = vec![NONE_U32; need_count];
    for (dep_idx, dep) in delta_deps.iter().enumerate() {
        if let Ok(need_idx) = need_offsets.binary_search(&dep.offset) {
            delta_dep_index[need_idx] = dep_idx as u32;
        }
    }

    PackPlan {
        pack_id,
        oid_len: 20,
        max_delta_depth: 64,
        candidates: Vec::<PackCandidate>::new(),
        candidate_offsets: Vec::new(),
        need_offsets,
        delta_deps,
        delta_dep_index,
        exec_order: None,
        stats: PackPlanStats::empty(),
    }
}

fn synthetic_locality_plan(
    pack_id: u16,
    need_count: usize,
    span_bytes: u64,
    dep_gap: usize,
) -> PackPlan {
    let mut plan = synthetic_plan(pack_id, need_count, span_bytes, 0, 0);
    if dep_gap == 0 || dep_gap >= need_count {
        return plan;
    }

    let mut delta_deps = Vec::with_capacity(need_count.saturating_sub(dep_gap));
    for dep_need_idx in dep_gap..need_count {
        delta_deps.push(DeltaDep {
            offset: plan.need_offsets[dep_need_idx],
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(plan.need_offsets[dep_need_idx - dep_gap]),
            data_start: 0,
            delta_size: 0,
        });
    }
    let mut delta_dep_index = vec![NONE_U32; need_count];
    for (dep_idx, dep) in delta_deps.iter().enumerate() {
        if let Ok(need_idx) = plan.need_offsets.binary_search(&dep.offset) {
            delta_dep_index[need_idx] = dep_idx as u32;
        }
    }

    plan.delta_deps = delta_deps;
    plan.delta_dep_index = delta_dep_index;
    plan
}

#[test]
fn select_pack_exec_strategy_handles_serial_boundaries() {
    let empty: Vec<PackPlan> = Vec::new();
    assert_eq!(
        select_pack_exec_strategy(0, &empty),
        PackExecStrategy::Serial,
        "empty plans should remain serial",
    );

    let single = vec![synthetic_plan(0, 2_048, 64 * 1024 * 1024, 0, 0)];
    assert_eq!(
        select_pack_exec_strategy(1, &single),
        PackExecStrategy::Serial,
        "worker=1 must remain serial",
    );
    assert_eq!(
        select_pack_exec_strategy(8, &[synthetic_plan(0, 100, 4 * 1024 * 1024, 0, 0)]),
        PackExecStrategy::Serial,
        "tiny total work should stay serial",
    );
}

#[test]
fn select_pack_exec_strategy_prefers_pack_parallel_with_enough_plans() {
    let plans = vec![
        synthetic_plan(0, 1_500, 64 * 1024 * 1024, 0, 0),
        synthetic_plan(1, 1_500, 64 * 1024 * 1024, 0, 0),
        synthetic_plan(2, 1_500, 64 * 1024 * 1024, 0, 0),
    ];
    assert_eq!(
        select_pack_exec_strategy(3, &plans),
        PackExecStrategy::PackParallel,
        "plans>=workers should use pack-parallel",
    );
}

#[test]
fn select_pack_exec_strategy_assigns_adaptive_shards() {
    let plans = vec![
        synthetic_plan(7, 8_192, 256 * 1024 * 1024, 0, 0),
        synthetic_plan(8, 200, 512 * 1024, 0, 0),
    ];
    match select_pack_exec_strategy(8, &plans) {
        PackExecStrategy::IntraPackSharded { shard_counts } => {
            assert_eq!(shard_count_for_pack(&shard_counts, 7), 8);
            assert_eq!(shard_count_for_pack(&shard_counts, 8), 1);
        }
        other => panic!("expected IntraPackSharded, got {other:?}"),
    }
}

#[test]
fn select_plan_shard_count_caps_dependency_heavy_plans() {
    let dependency_heavy = synthetic_plan(0, 4_096, 64 * 1024 * 1024, 2_200, 0);
    assert_eq!(
        select_plan_shard_count(8, &dependency_heavy),
        2,
        "dependency pressure should cap shard fan-out",
    );
}

#[test]
fn select_plan_shard_count_caps_locality_pressure_without_forward_or_external_deps() {
    let locality_heavy = synthetic_locality_plan(0, 8_192, 512 * 1024 * 1024, 2_048);
    let hint = build_plan_cost_hint(&locality_heavy);
    assert_eq!(hint.forward_deps, 0);
    assert_eq!(hint.external_deps, 0);
    assert_eq!(
        select_plan_shard_count(8, &locality_heavy),
        2,
        "wide backward deps should reduce shard fan-out for locality",
    );
}

#[test]
fn build_scheduler_shard_exec_plan_uses_natural_range_for_monotone_plans() {
    let plan = synthetic_plan(0, 2_048, 64 * 1024 * 1024, 0, 0);
    match build_scheduler_shard_exec_plan(&plan) {
        SchedulerShardExecPlan::Natural { len } => assert_eq!(len, plan.need_offsets.len()),
        SchedulerShardExecPlan::Explicit(indices) => {
            panic!(
                "expected natural shard plan, got explicit len={}",
                indices.len()
            )
        }
    }
}

#[test]
fn build_scheduler_shard_exec_plan_uses_indices_for_exec_ordered_plans() {
    let mut plan = synthetic_plan(0, 4, 16 * 1024 * 1024, 0, 0);
    plan.exec_order = Some(vec![2, 0, 3, 1]);
    match build_scheduler_shard_exec_plan(&plan) {
        SchedulerShardExecPlan::Natural { .. } => panic!("expected explicit shard plan"),
        SchedulerShardExecPlan::Explicit(indices) => {
            assert_eq!(indices, vec![2, 0, 3, 1]);
        }
    }
}

#[test]
fn auto_tree_delta_cache_bytes_small_repo() {
    let bytes = auto_tree_delta_cache_bytes(3_000, 128 * 1024 * 1024);
    assert_eq!(bytes, 8 * 1024 * 1024, "small repos clamp to floor");
}

#[test]
fn auto_tree_delta_cache_bytes_mid_range() {
    let bytes = auto_tree_delta_cache_bytes(40_000, 128 * 1024 * 1024);
    assert_eq!(
        bytes, 49_152_000,
        "mid-sized repos scale proportionally under ceiling"
    );
}

#[test]
fn auto_tree_delta_cache_bytes_large_repo_respects_cap() {
    let bytes = auto_tree_delta_cache_bytes(1_000_000, 32 * 1024 * 1024);
    assert_eq!(bytes, 32 * 1024 * 1024, "result must honor configured cap");
}

#[test]
fn auto_tree_delta_cache_bytes_allows_cap_below_floor() {
    let bytes = auto_tree_delta_cache_bytes(3_000, 4 * 1024 * 1024);
    assert_eq!(
        bytes,
        4 * 1024 * 1024,
        "configured cap below floor should not panic and must be honored",
    );
}

/// Helper for constructing a minimal SHA-1 MIDX buffer.
///
/// Only the chunks needed by `MidxView` lookups are populated.
#[derive(Default)]
struct MidxBuilder {
    pack_names: Vec<Vec<u8>>,
    objects: Vec<([u8; 20], u16, u64)>,
}

impl MidxBuilder {
    fn add_pack(&mut self, name: &[u8]) {
        self.pack_names.push(name.to_vec());
    }

    fn build(&self) -> Vec<u8> {
        const MIDX_MAGIC: [u8; 4] = *b"MIDX";
        const VERSION: u8 = 1;
        const HEADER_SIZE: usize = 12;
        const CHUNK_ENTRY_SIZE: usize = 12;
        const CHUNK_PNAM: [u8; 4] = *b"PNAM";
        const CHUNK_OIDF: [u8; 4] = *b"OIDF";
        const CHUNK_OIDL: [u8; 4] = *b"OIDL";
        const CHUNK_OOFF: [u8; 4] = *b"OOFF";

        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| a.0.cmp(&b.0));

        let pack_count = self.pack_names.len() as u32;

        let mut pnam = Vec::new();
        for name in &self.pack_names {
            pnam.extend_from_slice(name);
            pnam.push(0);
        }

        let mut oidf = vec![0u8; 256 * 4];
        let mut counts = [0u32; 256];
        for (oid, _, _) in &objects {
            counts[oid[0] as usize] += 1;
        }
        let mut running = 0u32;
        for (i, count) in counts.iter().enumerate() {
            running += count;
            let off = i * 4;
            oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
        }

        let mut oidl = Vec::with_capacity(objects.len() * 20);
        for (oid, _, _) in &objects {
            oidl.extend_from_slice(oid);
        }

        let mut ooff = Vec::with_capacity(objects.len() * 8);
        for (_, pack_id, offset) in &objects {
            ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
            ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        let chunk_count = 4u8;
        let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
        let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
        let oidf_off = pnam_off + pnam.len() as u64;
        let oidl_off = oidf_off + oidf.len() as u64;
        let ooff_off = oidl_off + oidl.len() as u64;
        let end_off = ooff_off + ooff.len() as u64;

        let mut out = Vec::new();
        out.extend_from_slice(&MIDX_MAGIC);
        out.push(VERSION);
        out.push(1); // SHA-1
        out.push(chunk_count);
        out.push(0); // base count
        out.extend_from_slice(&pack_count.to_be_bytes());

        let mut push_chunk = |id: [u8; 4], off: u64| {
            out.extend_from_slice(&id);
            out.extend_from_slice(&off.to_be_bytes());
        };

        push_chunk(CHUNK_PNAM, pnam_off);
        push_chunk(CHUNK_OIDF, oidf_off);
        push_chunk(CHUNK_OIDL, oidl_off);
        push_chunk(CHUNK_OOFF, ooff_off);
        push_chunk([0, 0, 0, 0], end_off);

        out.extend_from_slice(&pnam);
        out.extend_from_slice(&oidf);
        out.extend_from_slice(&oidl);
        out.extend_from_slice(&ooff);

        out
    }
}

fn test_engine() -> Engine {
    let rule = RuleSpec {
        name: "tok",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        local_context: None,
        secret_group: Some(1),
        offline_validation: None,
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn oid_to_hex(oid: &OidBytes) -> String {
    let mut out = String::with_capacity(oid.len() as usize * 2);
    for &b in oid.as_slice() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn write_loose_blob(objects_dir: &Path, oid: OidBytes, payload: &[u8]) {
    let mut header = Vec::new();
    header.extend_from_slice(b"blob ");
    header.extend_from_slice(payload.len().to_string().as_bytes());
    header.push(0);
    header.extend_from_slice(payload);

    let compressed = compress(&header);
    let hex = oid_to_hex(&oid);
    let (dir, file) = hex.split_at(2);
    let dir_path = objects_dir.join(dir);
    fs::create_dir_all(&dir_path).unwrap();
    fs::write(dir_path.join(file), &compressed).unwrap();
}

fn build_pack_io(objects_dir: &Path) -> PackIo<'static> {
    let mut builder = MidxBuilder::default();
    builder.add_pack(b"pack-test");
    let midx_bytes = builder.build();
    // Leak the bytes for the duration of the test to satisfy `MidxView` lifetimes.
    let midx_bytes: &'static [u8] = Box::leak(midx_bytes.into_boxed_slice());
    let midx = MidxView::parse(midx_bytes, ObjectFormat::Sha1).unwrap();

    let pack_paths = vec![objects_dir.join("pack-test.pack")];
    let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024), 2);
    PackIo::from_parts(midx, pack_paths, vec![objects_dir.to_path_buf()], limits).unwrap()
}

fn scheduler_pack_shared_for_runtime(pack_paths: Vec<PathBuf>) -> SchedulerPackShared {
    let mut midx_builder = MidxBuilder::default();
    midx_builder.add_pack(b"pack-test");
    let midx_bytes = BytesView::from_vec(midx_builder.build());

    let decode = PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024);
    SchedulerPackShared {
        engine: Arc::new(test_engine()),
        event_sink: Arc::new(crate::unified::events::NullEventSink),
        midx_bytes,
        object_format: ObjectFormat::Sha1,
        pack_paths: Arc::new(pack_paths),
        loose_dirs: Arc::new(Vec::new()),
        pack_mmaps: Arc::new(Vec::new()),
        path_arena: Arc::new(ByteArena::with_capacity(16)),
        spill_dir: Arc::new(PathBuf::from(".")),
        pack_decode: decode,
        pack_io: PackIoLimits::new(decode, 2),
        adapter_cfg: EngineAdapterConfig::default(),
        plans: Arc::new(Vec::new()),
        shard_meta: None,
        commit_graph: Arc::new(crate::git_scan::commit_graph::CommitGraphIndex::empty()),
        commit_meta_seen: Arc::new(crate::stdx::AtomicBitSet::empty(1)),
    }
}

fn loose_candidate(path_ref: ByteRef, oid: OidBytes) -> LooseCandidate {
    LooseCandidate {
        oid,
        ctx: CandidateContext {
            commit_id: 1,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        },
    }
}

#[test]
fn scheduler_worker_runtime_is_initialized_once() {
    let shared = scheduler_pack_shared_for_runtime(vec![PathBuf::from("pack-test.pack")]);
    let mut runtime = None;

    ensure_scheduler_worker_runtime(&mut runtime, &shared).expect("first init should succeed");
    let first = runtime.as_ref().expect("runtime initialized");
    let first_external = &*first.external as *const PackIo<'static>;
    let first_adapter = &*first.adapter as *const EngineAdapter<'static>;

    ensure_scheduler_worker_runtime(&mut runtime, &shared)
        .expect("second init should reuse existing runtime");
    let second = runtime.as_ref().expect("runtime still present");
    let second_external = &*second.external as *const PackIo<'static>;
    let second_adapter = &*second.adapter as *const EngineAdapter<'static>;

    assert_eq!(
        first_external, second_external,
        "PackIo instance should be reused per worker"
    );
    assert_eq!(
        first_adapter, second_adapter,
        "EngineAdapter instance should be reused per worker"
    );
}

#[test]
fn scheduler_worker_runtime_init_preserves_pack_io_error_mapping() {
    let shared = scheduler_pack_shared_for_runtime(Vec::new());
    let mut runtime = None;

    let err = ensure_scheduler_worker_runtime(&mut runtime, &shared).expect_err("must fail");
    assert!(
        matches!(
            err,
            GitScanError::PackIo(PackIoError::PackCountMismatch {
                expected: 1,
                actual: 0,
            })
        ),
        "expected pack count mismatch from PackIo::from_parts"
    );
}

#[test]
fn loose_blob_with_secret_is_scanned() {
    let engine = test_engine();
    let temp = tempdir().unwrap();
    let objects_dir = temp.path().join("objects");

    let oid = OidBytes::sha1([0xAB; 20]);
    write_loose_blob(&objects_dir, oid, b"hello TOK_ABCDEFGH");

    let mut pack_io = build_pack_io(&objects_dir);
    let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
    adapter.reserve_results(1);
    adapter.reserve_findings(4);
    adapter.reserve_findings_buf(4);

    let mut paths = ByteArena::with_capacity(64);
    let path_ref = paths.intern(b"src/lib.rs").unwrap();
    let candidate = loose_candidate(path_ref, oid);
    let mut skipped = Vec::new();

    scan_loose_candidates(
        &[candidate],
        &paths,
        &mut adapter,
        &mut pack_io,
        &mut skipped,
    )
    .unwrap();

    assert!(skipped.is_empty());
    let scanned = adapter.take_results();
    assert_eq!(scanned.blobs.len(), 1);
    assert!(!scanned.finding_arena.is_empty());
}

#[test]
fn missing_loose_object_is_skipped() {
    let engine = test_engine();
    let temp = tempdir().unwrap();
    let objects_dir = temp.path().join("objects");

    let oid = OidBytes::sha1([0xCD; 20]);
    let mut pack_io = build_pack_io(&objects_dir);
    let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
    let mut paths = ByteArena::with_capacity(64);
    let path_ref = paths.intern(b"src/lib.rs").unwrap();
    let candidate = loose_candidate(path_ref, oid);
    let mut skipped = Vec::new();

    scan_loose_candidates(
        &[candidate],
        &paths,
        &mut adapter,
        &mut pack_io,
        &mut skipped,
    )
    .unwrap();

    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].oid, oid);
    assert_eq!(skipped[0].reason, CandidateSkipReason::LooseMissing);
    let scanned = adapter.take_results();
    assert!(scanned.blobs.is_empty());
}

#[test]
fn shard_id_for_exec_position_10_by_3() {
    // 10 items, 3 shards: extra=1, sizes [4,3,3]
    let assignments: Vec<usize> = (0..10)
        .map(|p| shard_id_for_exec_position(p, 10, 3))
        .collect();
    assert_eq!(assignments, vec![0, 0, 0, 0, 1, 1, 1, 2, 2, 2]);
}

#[test]
fn shard_id_for_exec_position_9_by_3() {
    // 9 items, 3 shards: extra=0, sizes [3,3,3]
    let assignments: Vec<usize> = (0..9)
        .map(|p| shard_id_for_exec_position(p, 9, 3))
        .collect();
    assert_eq!(assignments, vec![0, 0, 0, 1, 1, 1, 2, 2, 2]);
}

#[test]
fn shard_id_for_exec_position_5_by_1() {
    // 5 items, 1 shard: all in shard 0
    let assignments: Vec<usize> = (0..5)
        .map(|p| shard_id_for_exec_position(p, 5, 1))
        .collect();
    assert_eq!(assignments, vec![0, 0, 0, 0, 0]);
}

#[test]
fn shard_id_for_exec_position_4_by_4() {
    // 4 items, 4 shards: one per shard
    let assignments: Vec<usize> = (0..4)
        .map(|p| shard_id_for_exec_position(p, 4, 4))
        .collect();
    assert_eq!(assignments, vec![0, 1, 2, 3]);
}

#[test]
fn shard_id_for_exec_position_7_by_4() {
    // 7 items, 4 shards: extra=3, sizes [2,2,2,1]
    let assignments: Vec<usize> = (0..7)
        .map(|p| shard_id_for_exec_position(p, 7, 4))
        .collect();
    assert_eq!(assignments, vec![0, 0, 1, 1, 2, 2, 3]);
}

#[test]
fn estimate_locality_pressure_known_deps() {
    // 8 need_offsets with backward offset deps every 4 positions.
    // dep_gap=4: deps at indices 4,5,6,7 depending on 0,1,2,3.
    let plan = synthetic_locality_plan(0, 8, 700, 4);
    assert_eq!(plan.delta_deps.len(), 4, "should have 4 offset deps");

    let p2 = estimate_locality_pressure(&plan, 2);
    assert_eq!(p2.offset_deps, 4, "all 4 deps are offset-based");
    assert_eq!(p2.unresolved_offset_bases, 0, "all bases in need_offsets");
    // With 2 shards: positions 0..4 → shard 0, positions 4..8 → shard 1.
    // All 4 deps cross the shard boundary.
    assert_eq!(
        p2.cross_shard_offset_deps, 4,
        "all deps cross shard boundary"
    );

    let p4 = estimate_locality_pressure(&plan, 4);
    assert_eq!(p4.offset_deps, 4);
    assert_eq!(p4.unresolved_offset_bases, 0);
    // With 4 shards: [0,1], [2,3], [4,5], [6,7].
    // dep 4→0 crosses, dep 5→1 crosses, dep 6→2 crosses, dep 7→3 crosses.
    assert_eq!(
        p4.cross_shard_offset_deps, 4,
        "all deps cross shard boundaries"
    );
}
