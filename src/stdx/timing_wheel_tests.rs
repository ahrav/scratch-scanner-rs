//! Property-based tests for TimingWheel.
//!
//! This module provides a reference implementation (Model) and property-based tests
//! to verify the TimingWheel implementation.

use std::collections::{BTreeMap, VecDeque};

// ============================================================================
// Reference Model
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MErr {
    PoolExhausted,
    TooFarInFuture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MOutcome<T> {
    Scheduled,
    Ready(T),
}

/// Ceiling division without overflow (matches the fixed implementation)
#[inline(always)]
fn ceil_div_u64(x: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    let q = x / d;
    let r = x % d;
    q + (r != 0) as u64
}

#[inline(always)]
fn wheel_size_for(max_horizon_bytes: u64, g: u64) -> u64 {
    // Same sizing rule as the wheel:
    // W_required = ceil((max_horizon + (G-1))/G) + 1; W = next_pow2(W_required)
    let worst = max_horizon_bytes.saturating_add(g - 1);
    let w_required = ceil_div_u64(worst, g).saturating_add(1).max(2);
    w_required.next_power_of_two()
}

/// Reference model that mirrors TimingWheel semantics using simple data structures.
pub struct Model<T: Copy> {
    g: u64,
    wheel_size: u64,
    cap: usize,

    // Contract-visible state:
    now_bucket: u64,
    base: u64, // "cursor_abs": next bucket key > any processed/eligible bucket

    len: usize,
    map: BTreeMap<u64, VecDeque<T>>, // key -> FIFO
}

impl<T: Copy> Model<T> {
    pub fn new(max_horizon_bytes: u64, cap: usize, g: u64) -> Self {
        Self {
            g,
            wheel_size: wheel_size_for(max_horizon_bytes, g),
            cap,
            now_bucket: 0,
            base: 0,
            len: 0,
            map: BTreeMap::new(),
        }
    }

    #[inline(always)]
    fn key(&self, hi_end: u64) -> u64 {
        ceil_div_u64(hi_end, self.g)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, hi_end: u64, val: T) -> Result<MOutcome<T>, MErr> {
        let k = self.key(hi_end);

        // Mirror the wheel's "already due relative to base" behavior.
        if k < self.base {
            return Ok(MOutcome::Ready(val));
        }

        if k >= self.base.saturating_add(self.wheel_size) {
            return Err(MErr::TooFarInFuture);
        }
        if self.len == self.cap {
            return Err(MErr::PoolExhausted);
        }

        self.map.entry(k).or_default().push_back(val);
        self.len += 1;
        Ok(MOutcome::Scheduled)
    }

    pub fn advance_and_drain(&mut self, now_offset: u64, out: &mut Vec<T>) {
        let nb = now_offset / self.g;
        assert!(nb >= self.now_bucket, "time must be monotone");

        // Fix: mirror the corrected early-return logic
        if nb == self.now_bucket && self.base > nb {
            return;
        }
        self.now_bucket = nb;

        // Drain all keys <= now_bucket in key order, FIFO within key.
        let drain_to = self.now_bucket;
        let keys: Vec<u64> = self.map.range(..=drain_to).map(|(&k, _)| k).collect();

        for k in keys {
            if let Some(mut q) = self.map.remove(&k) {
                while let Some(v) = q.pop_front() {
                    out.push(v);
                    self.len -= 1;
                }
            }
        }

        // Mirror wheel behavior: after advancing time, base is at least now_bucket+1.
        let target_base = self.now_bucket.saturating_add(1);
        if self.base < target_base {
            self.base = target_base;
        }
    }
}

// ============================================================================
// Property Tests (requires proptest crate and stdx-proptest feature)
// ============================================================================

#[cfg(feature = "stdx-proptest")]
mod proptests {
    use super::{MErr, MOutcome, Model};
    use crate::stdx::{PushError, PushOutcome, TimingWheel};
    use proptest::prelude::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Ev {
        id: u32,
        hi_end: u64,
    }

    #[derive(Clone, Debug)]
    struct OpSpec {
        tag: u8, // 0=adv, 1=push_in_range, 2=push_too_far, 3=push_past
        val: u32,
    }

    fn norm_err(e: &PushError) -> u8 {
        match e {
            PushError::PoolExhausted => 0,
            PushError::TooFarInFuture { .. } => 1,
            #[cfg(debug_assertions)]
            PushError::SlotCollision { .. } => 2,
        }
    }

    fn norm_model_err(e: &MErr) -> u8 {
        match e {
            MErr::PoolExhausted => 0,
            MErr::TooFarInFuture => 1,
        }
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<OpSpec>> {
        let op = (any::<u8>(), any::<u32>()).prop_map(|(t, v)| OpSpec { tag: t % 4, val: v });
        proptest::collection::vec(op, 0..2000)
    }

    fn run_prop<const G: u32>(max_horizon: u64, cap: usize, ops: Vec<OpSpec>) {
        let mut wheel: TimingWheel<Ev, G> = TimingWheel::new(max_horizon, cap);
        let mut model: Model<Ev> = Model::new(max_horizon, cap, G as u64);

        let mut now: u64 = 0;
        let mut next_id: u32 = 0;

        for op in ops {
            match op.tag {
                0 => {
                    // advance
                    let delta = (op.val as u64) % (4 * (G as u64) + 1);
                    now = now.saturating_add(delta);

                    let mut out_w = Vec::new();
                    let drained_w = wheel.advance_and_drain(now, |e| out_w.push(e));
                    let mut out_m = Vec::new();
                    model.advance_and_drain(now, &mut out_m);

                    assert_eq!(drained_w, out_w.len());
                    assert_eq!(out_w, out_m);

                    // Never early (strong safety property)
                    for e in &out_w {
                        assert!(
                            e.hi_end <= now,
                            "fired early: hi_end={} now={}",
                            e.hi_end,
                            now
                        );
                    }

                    // Bounded lateness check:
                    // Item with hi_end fires when ceil(hi_end/G) <= floor(now/G).
                    // The worst case is when hi_end = k*G (exactly on boundary),
                    // key = k, and now = (k+1)*G - 1 (just before next boundary).
                    // This gives lateness of G-1 bytes.
                    // However, this test advances time coarsely, so items may be
                    // drained at now > hi_end + G - 1 if we didn't call advance
                    // between hi_end and now. The important invariant is that
                    // items never fire early and the model matches the wheel.
                    // The model match is already checked above.

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();
                }
                1..=3 => {
                    // push
                    let raw = op.val as u64;
                    next_id = next_id.wrapping_add(1);

                    let hi_end = match op.tag {
                        // in range: now + [0..max_horizon]
                        1 => now.saturating_add(raw % (max_horizon.saturating_add(1))),
                        // too far: now + (max_horizon+1) + [0..max_horizon]
                        2 => now
                            .saturating_add(max_horizon.saturating_add(1))
                            .saturating_add(raw % (max_horizon.saturating_add(1))),
                        // past: now - [0..max_horizon]
                        _ => now.saturating_sub(raw % (max_horizon.saturating_add(1))),
                    };

                    // Force boundary cases often.
                    let hi_end = if (op.val & 1) == 0 {
                        // snap to multiple of G occasionally
                        hi_end - (hi_end % (G as u64))
                    } else {
                        hi_end
                    };

                    let ev = Ev {
                        id: next_id,
                        hi_end,
                    };

                    let rw = wheel.push(hi_end, ev);
                    let rm = model.push(hi_end, ev);

                    match (&rw, &rm) {
                        (Ok(PushOutcome::Scheduled), Ok(MOutcome::Scheduled)) => {}
                        (Ok(PushOutcome::Ready(a)), Ok(MOutcome::Ready(b))) => {
                            assert_eq!(a, b)
                        }
                        (Err(e), Err(me)) => {
                            #[cfg(debug_assertions)]
                            {
                                // SlotCollision must never occur under correct sizing
                                assert_ne!(
                                    norm_err(e),
                                    2,
                                    "SlotCollision indicates sizing bug: {e:?}"
                                );
                            }
                            assert_eq!(norm_err(e), norm_model_err(me));
                        }
                        (a, b) => panic!("wheel/model mismatch: wheel={a:?} model={b:?}"),
                    }

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();

                    // Contract check: after pushing something already eligible,
                    // calling advance at same now must drain it.
                    let mut out_w = Vec::new();
                    wheel.advance_and_drain(now, |e| out_w.push(e));
                    let mut out_m = Vec::new();
                    model.advance_and_drain(now, &mut out_m);
                    assert_eq!(out_w, out_m);

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();
                }
                _ => unreachable!(),
            }
        }
    }

    proptest! {
        #[test]
        fn timing_wheel_prop_g8(
            max_horizon in 0u16..512,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<8>(max_horizon as u64, cap, ops);
        }

        #[test]
        fn timing_wheel_prop_g1(
            max_horizon in 0u16..256,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<1>(max_horizon as u64, cap, ops);
        }

        #[test]
        fn timing_wheel_prop_g64(
            max_horizon in 0u16..4096,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<64>(max_horizon as u64, cap, ops);
        }
    }
}

// ============================================================================
// Bitset Property Tests
// ============================================================================

#[cfg(feature = "stdx-proptest")]
mod bitset_tests {
    use crate::stdx::Bitset2;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn bitset2_matches_naive(
            bits in 1usize..1024,
            ops in proptest::collection::vec(
                (any::<usize>(), any::<bool>(), any::<usize>()),
                0..5000
            )
        ) {
            let mut bs = Bitset2::new(bits);
            let mut naive = vec![false; bits];

            for (i, set, from) in ops {
                let idx = i % bits;
                let from = from % bits;

                if set {
                    bs.set(idx);
                    naive[idx] = true;
                } else {
                    bs.clear(idx);
                    naive[idx] = false;
                }

                assert_eq!(bs.any(), naive.iter().any(|&b| b));

                // Next set >= from
                let exp_ge = (from..bits).find(|&j| naive[j]);
                assert_eq!(bs.find_next_set_ge(from), exp_ge);

                // Cyclic
                let exp_cyc = exp_ge.or_else(|| (0..from).find(|&j| naive[j]));
                assert_eq!(bs.find_next_set_cyclic(from), exp_cyc);
            }
        }
    }
}
