//! Property-based and exhaustive soundness tests.
//!
//! Run with: `cargo test --test property`

mod archive_path_canonicalization;
mod archive_sliding_window;
mod binary_classification;
mod entropy_threshold_soundness;
// Log-based persistence removed in favor of SQLite. See src/store/db/.
// mod fs_log_codec;
// mod fs_log_reader;
mod git_commit_meta;
mod git_commit_walk;
mod git_engine_adapter;
mod git_pack_delta;
mod git_pack_plan;
mod git_spill_dedupe;
mod git_tree_diff;
mod regex2anchor_soundness;
mod value_suppressor_soundness;
