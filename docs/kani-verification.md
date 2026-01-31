# Kani Bounded Model Checking

This document describes how scanner-rs uses [Kani](https://model-checking.github.io/kani/) for formal verification of data structure invariants.

## What is Kani?

Kani is a bit-precise model checker for Rust that uses symbolic execution to verify program properties. Unlike traditional testing:

| Approach | Coverage | Guarantees |
|----------|----------|------------|
| Unit tests | Specific cases | None beyond tested inputs |
| Property tests (proptest) | Random sampling | Probabilistic (high confidence) |
| **Kani (bounded model checking)** | **Exhaustive within bounds** | **Mathematical proof within bounds** |

Kani explores *all possible* states within configured bounds, converting Rust code to a SAT/SMT problem and using solvers to find counterexamples. If no counterexample exists within bounds, the property is proven for that bounded state space.

## Installation

```bash
# Install Kani
cargo install kani-verifier

# Complete setup (downloads CBMC and other dependencies)
kani setup
```

Requirements:
- Rust 1.70+ (nightly recommended for full feature support)
- ~2GB disk space for solver dependencies

## Running Proofs

```bash
# Run all Kani proofs
cargo kani --features kani

# Run a specific proof harness
cargo kani --features kani --harness verify_never_fires_early

# Run with verbose output
cargo kani --features kani --harness verify_pool_coherence --verbose
```

## Verified Properties

### TimingWheel Proofs

Located in `src/stdx/timing_wheel.rs` under `#[cfg(kani)] mod kani_proofs`.

| Proof Harness | Property Verified | Bounds | Unwind |
|---------------|-------------------|--------|--------|
| `verify_never_fires_early` | Items never fire before their `hi_end` time (core correctness) | wheel_size=16, cap=8, hi_end<=56 | 10 |
| `verify_pool_coherence` | Every node is free XOR in-use (no corruption) | 4 pushes, partial drain | 12 |
| `verify_horizon_enforcement` | `TooFarInFuture` returned for items beyond horizon | Single push beyond limit | - |
| `verify_slot_occupancy_consistency` | `head[slot] == NONE` iff occupancy bit is clear | 1 push + drain | 10 |
| `verify_fifo_ordering` | Items in same bucket drain in insertion order | 3 items, same bucket | 8 |
| `verify_monotonicity_no_corruption` | Time going backwards is no-op, no state corruption | Forward then backward | 6 |
| `verify_reset` | Reset restores wheel to initial state | 2 pushes + reset | 10 |

### Bitset2 Proofs

`Bitset2` is the two-level occupancy bitmap used internally by `TimingWheel`.

| Proof Harness | Property Verified | Bounds |
|---------------|-------------------|--------|
| `verify_bitset_set_find_consistency` | `set()` then `find_next_set_ge()` finds the bit | 64 bits, symbolic index |
| `verify_bitset_clear` | `clear()` removes bit correctly | 64 bits, symbolic index |
| `verify_bitset_any_count` | `any()` accurately tracks whether bits are set | 64 bits, set/clear cycle |
| `verify_bitset_clear_all` | `clear_all()` resets all state | 64 bits, 2 symbolic indices |
| `verify_bitset_find_ordering` | `find_next_set_ge()` returns smallest index >= from | 64 bits, 2 ordered indices |

## Bounded Sizes Rationale

Kani proofs use small bounds (e.g., `wheel_size=16`, `cap=8`, `bits=64`) because:

1. **Exponential state space**: Kani exhaustively explores all states. Doubling size can square the state space, making verification intractable.

2. **Code path coverage**: Small sizes still exercise all code paths - the same push/drain/wrap logic runs regardless of size.

3. **Complementary coverage**: Property tests (proptest) provide probabilistic coverage at realistic sizes.

### Coverage Strategy

```
        Small bounds                    Large bounds
        (exhaustive)                    (probabilistic)
             |                               |
             v                               v
    +----------------+              +------------------+
    |     Kani       |              |     Proptest     |
    | wheel_size=16  |              | wheel_size=1024+ |
    | cap=8          |              | cap=10000        |
    | PROVES within  |              | Tests across     |
    | bounds         |              | random inputs    |
    +----------------+              +------------------+
             |                               |
             +-------------------------------+
                            |
                            v
              High confidence in correctness
```

The combination provides:
- **Kani**: Mathematical certainty for core invariants within bounds
- **Proptest**: Empirical confidence that invariants scale to production sizes

## Adding New Proofs

### Basic Structure

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(N)]  // Required for loops; N = max iterations + 1
    fn verify_my_property() {
        // Setup
        let mut data_structure = MyType::new(...);

        // Symbolic inputs (Kani explores all values)
        let x: u32 = kani::any();
        kani::assume(x < 100);  // Constrain input space

        // Exercise code
        data_structure.operation(x);

        // Assert invariants
        kani::assert(data_structure.invariant_holds(), "Invariant violated!");
    }
}
```

### Guidelines

1. **Unwind hints**: Required for any code with loops. Set to max loop iterations + 1.
   ```rust
   #[kani::unwind(10)]  // For loops that iterate at most 9 times
   ```

2. **Use `kani::assume()`** to constrain symbolic inputs to valid ranges:
   ```rust
   let idx: usize = kani::any();
   kani::assume(idx < vec.len());  // Prevent out-of-bounds
   ```

3. **Use `kani::assert()`** for properties to verify:
   ```rust
   kani::assert(result.is_ok(), "Should not fail");
   kani::assert(x <= y, "Ordering violated");
   ```

4. **Keep bounds small** - start with minimal sizes that exercise the code path.

5. **Use `debug_validate()`** when available - comprehensive internal consistency checks.

### Common Patterns

**Testing state machine transitions:**
```rust
#[kani::proof]
fn verify_state_transitions() {
    let mut sm = StateMachine::new();
    let action: Action = kani::any();

    let old_state = sm.state();
    sm.apply(action);

    // Verify valid transition
    kani::assert(valid_transition(old_state, sm.state()), "Invalid transition");
}
```

**Testing invariant preservation:**
```rust
#[kani::proof]
#[kani::unwind(5)]
fn verify_invariant_preserved() {
    let mut container = Container::new(8);

    // Arbitrary sequence of operations
    for _ in 0..4 {
        let op: Op = kani::any();
        container.apply(op);
        container.debug_validate();  // Check invariants after each op
    }
}
```

## Troubleshooting

### "unwinding assertion failed"

Increase the unwind bound:
```rust
#[kani::unwind(20)]  // Was too small, increase
```

### "verification timed out"

Reduce bounds or add more `kani::assume()` constraints to limit state space.

### "CBMC error: ... out of memory"

- Reduce data structure sizes
- Add tighter constraints with `kani::assume()`
- Consider splitting into multiple smaller proofs

## References

- [Kani Documentation](https://model-checking.github.io/kani/)
- [Kani Tutorial](https://model-checking.github.io/kani/tutorial.html)
- Source: `src/stdx/timing_wheel.rs` (proofs in `mod kani_proofs`)
- Related: `src/stdx/timing_wheel_tests.rs` (proptest coverage)
