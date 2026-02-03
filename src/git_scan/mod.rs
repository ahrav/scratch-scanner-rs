//! Git scanning pipeline modules.
//!
//! The preflight module performs a repository maintenance check: resolve repo
//! layout, verify required artifacts (commit-graph and MIDX), and enforce pack
//! count limits. Preflight must not read object contents.
//!
//! # Invariants
//! - No blob reads (metadata only).
//! - File reads are bounded by explicit limits.
//! - Outputs are deterministic for identical repo state.

pub mod byte_arena;
pub mod errors;
pub mod limits;
pub mod object_id;
pub mod preflight;
pub mod preflight_error;
pub mod preflight_limits;
pub mod repo;

pub use byte_arena::{ByteArena, ByteRef};
pub use errors::{Phase1Error, Phase2Error, Phase3Error};
pub use limits::Phase1Limits;
pub use object_id::{ObjectFormat, OidBytes};
pub use preflight::{preflight, ArtifactPaths, ArtifactStatus, PreflightReport};
pub use preflight_error::PreflightError;
pub use preflight_limits::PreflightLimits;
pub use repo::{GitRepoPaths, RepoKind};
