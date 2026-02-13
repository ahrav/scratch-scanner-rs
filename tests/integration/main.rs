//! Integration tests for scanner-rs detection engine.
//!
//! Run with: `cargo test --test integration`

mod anchor_optimization;
mod archive_scanning;
mod bench_guards;
mod binary_awareness;
mod fs_cli_archives;
// Log-based persistence removed in favor of SQLite. See src/store/db/.
// mod fs_persist_log;
// mod fs_persist_log_edge_cases;
mod git_commit_walk;
mod git_engine_adapter;
mod git_inmem_artifacts;
mod git_mapping_bridge;
mod git_pack_exec;
mod git_pack_inflate;
mod git_pack_inflate_corpus;
mod git_pack_plan;
mod git_persist;
mod git_preflight;
mod git_repo_open;
mod git_run_format;
mod git_scan_validation;
mod git_seen_unique;
mod git_snapshot;
mod git_tree_diff;
mod manual_anchors;
mod sqlite_persistence;
