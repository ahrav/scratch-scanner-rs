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
//! # Invariants
//! - No blob reads (metadata only).
//! - File reads are bounded by explicit limits.
//! - Outputs are deterministic for identical repo state.

pub mod byte_arena;
pub mod commit_walk;
pub mod commit_walk_limits;
pub mod errors;
pub mod limits;
pub mod object_id;
pub mod object_store;
pub mod path_policy;
pub mod policy_hash;
pub mod preflight;
pub mod preflight_error;
pub mod preflight_limits;
pub mod repo;
pub mod repo_open;
pub mod snapshot_plan;
pub mod start_set;
pub mod tree_cache;
pub mod tree_candidate;
pub mod tree_diff;
pub mod tree_diff_limits;
pub mod tree_entry;
pub mod tree_order;
pub mod watermark_keys;

pub use byte_arena::{ByteArena, ByteRef};
pub use commit_walk::{
    introduced_by_plan, topo_order_positions, CommitGraph, CommitGraphView, CommitPlanIter,
    ParentScratch, PlannedCommit,
};
pub use commit_walk_limits::CommitWalkLimits;
pub use errors::{CommitPlanError, RepoOpenError, SpillError, TreeDiffError};
pub use limits::RepoOpenLimits;
pub use object_id::{ObjectFormat, OidBytes};
pub use object_store::{ObjectStore, TreeSource};
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
pub use snapshot_plan::snapshot_plan;
pub use start_set::{StartSetConfig, StartSetId};
pub use tree_candidate::{
    CandidateBuffer, CandidateContext, ChangeKind, ResolvedCandidate, TreeCandidate,
};
pub use tree_diff::{TreeDiffStats, TreeDiffWalker};
pub use tree_diff_limits::TreeDiffLimits;
pub use tree_entry::{EntryKind, TreeEntry, TreeEntryIter};
pub use tree_order::{git_tree_file_name_cmp, git_tree_name_cmp};
pub use watermark_keys::{
    decode_ref_watermark_value, encode_ref_watermark_value, KeyArena, KeyRef, NS_REF_WATERMARK,
};
