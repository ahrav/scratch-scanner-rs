//! Git scanning pipeline modules.
//!
//! The preflight module performs a repository maintenance check: resolve repo
//! layout, verify required artifacts (commit-graph and MIDX), and enforce pack
//! count limits. Preflight must not read object contents.
//!
//! The repo_open module produces `RepoJobState`: it resolves repo paths,
//! detects object format, memory-maps commit-graph and MIDX, and loads the
//! start set plus watermarks needed for incremental Git scanning.
//!
//! Pipeline overview:
//! 1. `preflight` verifies repository layout and artifacts.
//! 2. `repo_open` loads commit-graph/MIDX metadata and start set state.
//! 3. `commit_walk` builds the commit plan.
//! 4. `tree_diff` extracts candidate blobs and paths.
//! 5. `spill` dedupes and filters candidates against the seen store.
//! 6. `mapping_bridge` maps unique blobs to pack/loose candidates.
//! 7. `pack_plan` builds per-pack decode plans from pack candidates.
//!
//! # Invariants
//! - No blob reads (metadata only).
//! - File reads are bounded by explicit limits.
//! - Outputs are deterministic for identical repo state.

pub mod byte_arena;
pub mod commit_walk;
pub mod commit_walk_limits;
pub mod engine_adapter;
pub mod errors;
pub mod limits;
pub mod mapping_bridge;
pub mod midx;
pub mod midx_error;
pub mod object_id;
pub mod object_store;
pub mod pack_amq;
pub mod pack_cache;
pub mod pack_candidates;
pub mod pack_decode;
pub mod pack_delta;
pub mod pack_exec;
pub mod pack_inflate;
pub mod pack_io;
pub mod pack_plan;
pub mod pack_plan_model;
pub mod pack_strategy;
pub mod path_policy;
pub mod persist_rocksdb;
pub mod policy_hash;
pub mod preflight;
pub mod preflight_error;
pub mod preflight_limits;
pub mod repo;
pub mod repo_open;
pub mod run_format;
pub mod run_reader;
pub mod run_writer;
pub mod seen_store;
pub mod snapshot_plan;
pub mod spill_chunk;
pub mod spill_limits;
pub mod spill_merge;
pub mod spiller;
pub mod start_set;
pub mod tree_cache;
pub mod tree_candidate;
pub mod tree_diff;
pub mod tree_diff_limits;
pub mod tree_entry;
pub mod tree_order;
pub mod unique_blob;
pub mod watermark_keys;
pub mod work_items;

pub use byte_arena::{ByteArena, ByteRef};
pub use commit_walk::{
    introduced_by_plan, topo_order_positions, CommitGraph, CommitGraphView, CommitPlanIter,
    ParentScratch, PlannedCommit,
};
pub use commit_walk_limits::CommitWalkLimits;
pub use engine_adapter::{
    scan_blob_chunked, EngineAdapter, EngineAdapterConfig, EngineAdapterError, FindingKey,
    ScannedBlob, DEFAULT_CHUNK_BYTES, DEFAULT_PATH_ARENA_BYTES,
};
pub use errors::{CommitPlanError, RepoOpenError, SpillError, TreeDiffError};
pub use limits::RepoOpenLimits;
pub use mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
pub use midx::MidxView;
pub use object_id::{ObjectFormat, OidBytes};
pub use object_store::{ObjectStore, TreeSource};
pub use pack_amq::PackAmq;
pub use pack_cache::{CachedObject, PackCache};
pub use pack_candidates::{
    CollectingPackCandidateSink, LooseCandidate, PackCandidate, PackCandidateSink,
};
pub use pack_decode::{entry_header_at, inflate_entry_payload, PackDecodeError, PackDecodeLimits};
pub use pack_delta::{apply_delta, DeltaError};
pub use pack_exec::{
    execute_pack_plan, execute_pack_plan_with_strategy, ExternalBase, ExternalBaseProvider,
    PackExecError, PackExecReport, PackExecStats, PackObjectSink, SkipReason, SkipRecord,
};
pub use pack_io::{PackIo, PackIoError, PackIoLimits};
pub use pack_plan::{build_pack_plans, OidResolver, PackPlanConfig, PackPlanError, PackView};
pub use pack_plan_model::{
    BaseLoc, CandidateAtOffset, Cluster, DeltaDep, DeltaKind, PackPlan, PackPlanStats,
    CLUSTER_GAP_BYTES,
};
pub use pack_strategy::{cluster_offsets, select_pack_strategy, PackStrategy};
pub use path_policy::PathClass;
pub use policy_hash::{policy_hash, MergeDiffMode, PolicyHash};
pub use preflight::{preflight, ArtifactPaths, ArtifactStatus, PreflightReport};
pub use preflight_error::PreflightError;
pub use preflight_limits::PreflightLimits;
pub use repo::{GitRepoPaths, RepoKind};
pub use repo_open::{
    repo_open, RefWatermarkStore, RepoArtifactMmaps, RepoArtifactPaths, RepoArtifactStatus,
    RepoJobState, StartSetRef, StartSetResolver,
};
pub use run_format::{RunContext, RunHeader, RunRecord};
pub use run_reader::RunReader;
pub use run_writer::RunWriter;
pub use seen_store::{AlwaysSeenStore, InMemorySeenStore, NeverSeenStore, SeenBlobStore};
pub use snapshot_plan::snapshot_plan;
pub use spill_chunk::CandidateChunk;
pub use spill_limits::SpillLimits;
pub use spill_merge::{merge_all, RunMerger};
pub use spiller::{SpillStats, Spiller};
pub use start_set::{StartSetConfig, StartSetId};
pub use tree_candidate::{
    CandidateBuffer, CandidateContext, ChangeKind, ResolvedCandidate, TreeCandidate,
};
pub use tree_diff::{TreeDiffStats, TreeDiffWalker};
pub use tree_diff_limits::TreeDiffLimits;
pub use tree_entry::{EntryKind, TreeEntry, TreeEntryIter};
pub use tree_order::{git_tree_file_name_cmp, git_tree_name_cmp};
pub use unique_blob::{CollectedUniqueBlob, CollectingUniqueBlobSink, UniqueBlob, UniqueBlobSink};
pub use watermark_keys::{
    decode_ref_watermark_value, encode_ref_watermark_value, KeyArena, KeyRef, NS_REF_WATERMARK,
};
pub use work_items::WorkItems;
