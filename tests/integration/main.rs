//! Integration tests for scanner-rs detection engine.
//!
//! Run with: `cargo test --test integration`

mod anchor_optimization;
mod git_commit_walk;
mod git_engine_adapter;
mod git_mapping_bridge;
mod git_pack_exec;
mod git_pack_plan;
mod git_preflight;
mod git_repo_open;
mod git_run_format;
mod git_seen_unique;
mod git_snapshot;
mod git_tree_diff;
mod manual_anchors;
