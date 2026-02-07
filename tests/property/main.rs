//! Property-based and exhaustive soundness tests.
//!
//! Run with: `cargo test --test property`

mod archive_path_canonicalization;
mod git_commit_walk;
mod git_engine_adapter;
mod git_spill_dedupe;
mod git_tree_diff;
mod regex2anchor_soundness;
