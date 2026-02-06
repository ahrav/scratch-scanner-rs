//! Small arithmetic helpers for scan-time counters.
//!
//! These helpers centralize saturating/wrapping/max/set update patterns so
//! hot paths stay concise and consistent.
//! They only mutate counters when
//! `all(feature = "perf-stats", debug_assertions)` is enabled; otherwise all
//! helpers compile to no-ops.
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

/// Saturating add for a `u64` counter.
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

/// Saturating add for a `u32` counter.
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

/// Saturating add for a `usize` counter.
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

/// Saturating add for a `u16` counter.
#[inline(always)]
pub fn sat_add_u16(counter: &mut u16, delta: u16) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Wrapping add for a `u64` counter.
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

/// High-water-mark update for a `u64` counter.
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

/// High-water-mark update for a `u32` counter.
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

/// High-water-mark update for a `u16` counter.
#[inline(always)]
pub fn max_u16(counter: &mut u16, value: u16) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `u64` counter.
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

/// Unconditional assignment for a `usize` counter.
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
