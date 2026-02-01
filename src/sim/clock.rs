//! Monotonic simulated clock for deterministic scheduling.
//!
//! The clock only advances when the simulation explicitly moves time forward.
//! This keeps time-based logic deterministic and replayable.

/// Tick-based simulated clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SimClock {
    now: u64,
}

impl SimClock {
    /// Create a new clock at tick 0.
    pub fn new() -> Self {
        Self { now: 0 }
    }

    /// Current time in ticks.
    #[inline(always)]
    pub fn now_ticks(&self) -> u64 {
        self.now
    }

    /// Advance to an absolute tick.
    #[inline(always)]
    pub fn advance_to(&mut self, t: u64) {
        debug_assert!(t >= self.now);
        self.now = t;
    }

    /// Advance by a delta, saturating on overflow.
    #[inline(always)]
    pub fn advance_by(&mut self, dt: u64) {
        self.now = self.now.saturating_add(dt);
    }
}
