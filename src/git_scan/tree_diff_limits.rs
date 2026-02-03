//! Hard caps and tunables for tree diff and candidate collection.
//!
//! All limits are explicit and enforced. Exceeding a limit produces an
//! explicit error, never silent truncation or data loss.
//!
//! # Design Principles
//!
//! - Every buffer has a hard cap to prevent unbounded memory growth
//! - Caps are chosen to handle large monorepos while preventing DoS
//! - Only fields actually used by the implementation are included
//!
//! # Memory Budget Breakdown (defaults)
//!
//! | Component        | Default Cap | Typical Usage                       |
//! |------------------|-------------|-------------------------------------|
//! | Candidate buffer | 1M entries x ~50 bytes = 50 MB | Per-repo job |
//! | Path arena       | 64 MB       | Shared across all candidates        |
//! | Diff stack       | 256 frames x ~100 bytes = 25 KB | Per-diff operation |
//!
//! Total default budget: ~115 MB per repo job (excluding mmapped data).

/// Hard caps for tree diff and candidate collection.
///
/// # Layout
///
/// Fields ordered for optimal packing (largest alignment first).
/// Size: 24 bytes (verified at compile time).
#[derive(Clone, Copy, Debug)]
pub struct TreeDiffLimits {
    /// Maximum total tree bytes loaded during a repo job.
    ///
    /// This bounds the total amount of tree object data that can be loaded
    /// during a single repository scan. Prevents runaway memory usage on
    /// repositories with exceptionally large or numerous trees.
    ///
    /// Default: 2 GB.
    pub max_tree_bytes_per_job: u64,

    /// Maximum candidates in the in-memory buffer.
    ///
    /// When this limit is reached, tree diffing must either:
    /// - Return an error (current behavior)
    /// - Spill to disk (spill + dedupe stages add this capability)
    ///
    /// Default: 1,048,576 (1M candidates ~= 50 MB).
    pub max_candidates: u32,

    /// Maximum bytes for the path arena.
    ///
    /// All candidate paths are interned into this arena. The arena
    /// must be large enough to hold paths for all candidates.
    ///
    /// Default: 64 MB.
    pub max_path_arena_bytes: u32,

    /// Maximum tree recursion depth.
    ///
    /// Limits how deep the tree diff walker can recurse into nested
    /// directories. This protects against:
    /// - Stack overflow (explicit stack, but still bounded)
    /// - DoS via deeply nested directory structures
    /// - Pathological repositories
    ///
    /// Default: 256.
    pub max_tree_depth: u16,
}

impl TreeDiffLimits {
    /// Safe defaults suitable for large monorepos.
    ///
    /// Memory budget: ~115 MB per repo job (excluding mmapped data).
    pub const DEFAULT: Self = Self {
        max_tree_bytes_per_job: 2 * 1024 * 1024 * 1024, // 2 GB
        max_candidates: 1_048_576,                      // 1M
        max_path_arena_bytes: 64 * 1024 * 1024,         // 64 MB
        max_tree_depth: 256,
    };

    /// Restrictive limits for testing or memory-constrained environments.
    ///
    /// Memory budget: ~2 MB per repo job.
    pub const RESTRICTIVE: Self = Self {
        max_tree_bytes_per_job: 64 * 1024 * 1024, // 64 MB
        max_candidates: 16_384,                   // 16K
        max_path_arena_bytes: 1024 * 1024,        // 1 MB
        max_tree_depth: 64,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        // Minimum bounds (must allow functionality)
        assert!(self.max_candidates > 0, "must allow at least 1 candidate");
        assert!(self.max_tree_depth > 0, "must allow at least depth 1");
        assert!(
            self.max_path_arena_bytes > 0,
            "path arena must have capacity"
        );
        assert!(
            self.max_tree_bytes_per_job > 0,
            "tree bytes budget must be > 0"
        );

        // Upper bounds (prevent misconfigurations)
        assert!(
            self.max_candidates <= 100_000_000,
            "candidate limit > 100M is unreasonable"
        );
        assert!(
            self.max_tree_depth <= 4096,
            "tree depth > 4096 is unreasonable"
        );
        assert!(
            self.max_path_arena_bytes <= 1024 * 1024 * 1024,
            "path arena > 1GB is unreasonable"
        );
        assert!(
            self.max_tree_bytes_per_job <= 64_u64 * 1024 * 1024 * 1024,
            "tree bytes budget > 64GB is unreasonable"
        );

        // Consistency checks
        assert!(
            self.max_path_arena_bytes as u64 >= self.max_candidates as u64 * 8,
            "path arena too small for candidate count"
        );
    }

    /// Non-panicking validation for runtime configuration.
    ///
    /// Returns `Ok(())` if valid, or a short static error message if invalid.
    pub const fn try_validate(&self) -> Result<(), &'static str> {
        if self.max_candidates == 0 {
            return Err("must allow at least 1 candidate");
        }
        if self.max_tree_depth == 0 {
            return Err("must allow at least depth 1");
        }
        if self.max_path_arena_bytes == 0 {
            return Err("path arena must have capacity");
        }
        if self.max_tree_bytes_per_job == 0 {
            return Err("tree bytes budget must be > 0");
        }
        if self.max_candidates > 100_000_000 {
            return Err("candidate limit > 100M is unreasonable");
        }
        if self.max_tree_depth > 4096 {
            return Err("tree depth > 4096 is unreasonable");
        }
        if self.max_path_arena_bytes > 1024 * 1024 * 1024 {
            return Err("path arena > 1GB is unreasonable");
        }
        if self.max_tree_bytes_per_job > 64 * 1024 * 1024 * 1024 {
            return Err("tree bytes budget > 64GB is unreasonable");
        }
        if (self.max_path_arena_bytes as u64) < (self.max_candidates as u64) * 8 {
            return Err("path arena too small for candidate count");
        }
        Ok(())
    }
}

impl Default for TreeDiffLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = TreeDiffLimits::DEFAULT.validate();
const _: () = TreeDiffLimits::RESTRICTIVE.validate();
const _: () = assert!(std::mem::size_of::<TreeDiffLimits>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_valid() {
        TreeDiffLimits::DEFAULT.validate();
    }

    #[test]
    fn restrictive_limits_valid() {
        TreeDiffLimits::RESTRICTIVE.validate();
    }
}
