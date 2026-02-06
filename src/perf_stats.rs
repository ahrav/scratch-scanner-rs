//! Compile-time gated helpers for scan-time perf/stat counters.
//!
//! Every stats struct in the codebase (`PipelineStats`, `PackExecStats`,
//! `ArchiveStats`, `WorkerMetricsLocal`, etc.) is updated exclusively through
//! the functions in this module.  When the `perf-stats` feature is **off** (or
//! the build is `--release`), every function here compiles to a no-op — the
//! counter fields stay at their `Default` value and the optimizer eliminates
//! the dead stores entirely.
//!
//! # Gate
//!
//! `cfg!(all(feature = "perf-stats", debug_assertions))`
//!
//! A `compile_error!` in `lib.rs` prevents accidentally shipping stat
//! instrumentation in release binaries.
//!
//! # Why wrapping vs. saturating?
//!
//! * **`sat_add_*`** — most counters: clamping at `MAX` is safer than silent
//!   wrap-around for values displayed to operators.
//! * **`wrap_add_u64`** — finding counts that are later differenced
//!   (`after - before`), where wrapping arithmetic produces the correct delta
//!   even on overflow.
//! * **`max_*`** — high-water-mark tracking (peak in-flight bytes, max depth).
//! * **`set_*`** — final-value assignment (e.g. total op counts known after a
//!   batch completes).

/// Returns `true` when perf-stat recording is active (debug + feature flag).
///
/// Callers that need a runtime branch (e.g. for `max` updates that cannot use
/// a separate `#[cfg]` body) should use this.  For the common case of a
/// single counter bump, prefer the helper functions below — they already
/// contain the `#[cfg]` gate and avoid the branch entirely.
#[inline(always)]
pub const fn enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

/// Saturating add for a `u64` counter. No-op when stats are disabled.
#[inline(always)]
pub fn sat_add_u64(counter: &mut u64, delta: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Saturating add for a `u32` counter. No-op when stats are disabled.
#[inline(always)]
pub fn sat_add_u32(counter: &mut u32, delta: u32) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Saturating add for a `usize` counter. No-op when stats are disabled.
#[inline(always)]
pub fn sat_add_usize(counter: &mut usize, delta: usize) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Wrapping add for a `u64` counter. No-op when stats are disabled.
///
/// Use for counters where overflow is expected or where the consumer
/// computes deltas (`after.wrapping_sub(before)`) that remain correct
/// under wrap-around (e.g. cumulative finding counts).
#[inline(always)]
pub fn wrap_add_u64(counter: &mut u64, delta: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.wrapping_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// High-water-mark update for a `u64` counter. No-op when stats are disabled.
#[inline(always)]
pub fn max_u64(counter: &mut u64, value: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// High-water-mark update for a `u32` counter. No-op when stats are disabled.
#[inline(always)]
pub fn max_u32(counter: &mut u32, value: u32) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `u64` counter. No-op when stats are disabled.
///
/// Use when the final value is known (e.g. total op count after a batch).
#[inline(always)]
pub fn set_u64(counter: &mut u64, value: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = value;
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `usize` counter. No-op when stats are disabled.
#[inline(always)]
pub fn set_usize(counter: &mut usize, value: usize) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = value;
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}
