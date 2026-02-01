---
name: test-strategy
description: Assess and recommend the appropriate testing strategy for Rust code - unit tests, property-based tests, fuzz tests, or Kani model checking
---

# Test Strategy Assessment

Analyze code and recommend the optimal testing approach from this project's testing toolkit.

## Testing Toolkit Available

| Type | Tool | Feature Flag | Best For |
|------|------|--------------|----------|
| **Unit Tests** | `#[test]` | None | Specific behavior, edge cases, regression tests |
| **Property Tests** | proptest | `stdx-proptest` | Invariants over input domains, mathematical properties |
| **Fuzz Tests** | cargo-fuzz | External | Security-critical parsing, untrusted input handling |
| **Model Checking** | Kani | `kani` | Memory safety proofs, absence of panics, formal verification |

## Decision Framework

### Use Unit Tests When:
- Testing specific, known edge cases
- Verifying exact output for exact input
- Regression tests for fixed bugs
- Simple function behavior verification
- Fast feedback during development

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn specific_edge_case() {
        assert_eq!(function(edge_input), expected_output);
    }
}
```

### Use Property-Based Tests (proptest) When:
- Function should satisfy invariants for ALL valid inputs
- Testing mathematical properties (commutativity, associativity, idempotence)
- Round-trip properties (encode/decode, serialize/deserialize)
- Relationship between functions (e.g., `parse` and `format` are inverses)
- Exploring large input spaces systematically

```rust
#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_property(input in any::<ValidInput>()) {
            let encoded = encode(&input);
            let decoded = decode(&encoded).unwrap();
            prop_assert_eq!(input, decoded);
        }
    }
}
```

**Run with**: `cargo test --features stdx-proptest`

### Use Fuzz Tests When:
- Parsing untrusted or external input (files, network data)
- Security-critical code paths
- Looking for crashes, panics, or undefined behavior
- Complex state machines with many paths
- Finding inputs that cause pathological performance

```rust
// In fuzz/fuzz_targets/
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_untrusted(data);
});
```

**Run with**: `cargo +nightly fuzz run <target>`

### Use Kani Model Checking When:
- Proving absence of panics/undefined behavior
- Verifying memory safety in unsafe code
- Proving loop bounds and termination
- Exhaustive verification of small input spaces
- Critical algorithms where bugs are unacceptable

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_no_panic() {
        let x: u32 = kani::any();
        kani::assume(x < 1000);
        let result = critical_function(x);
        // Kani proves this never panics
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_loop_bounds() {
        let arr: [u8; 8] = kani::any();
        process_array(&arr); // Prove no out-of-bounds
    }
}
```

**Run with**: `cargo kani --features kani`

## Assessment Checklist

When analyzing code for test strategy, consider:

1. **Input Domain**
   - [ ] Fixed, known inputs → Unit tests
   - [ ] Large/infinite input space → Property tests
   - [ ] Untrusted/adversarial input → Fuzz tests
   - [ ] Small but critical input space → Kani

2. **Properties to Verify**
   - [ ] Specific behavior → Unit tests
   - [ ] Invariants over all inputs → Property tests
   - [ ] "Never crashes" → Fuzz tests + Kani
   - [ ] Memory safety → Kani (especially for unsafe)

3. **Code Characteristics**
   - [ ] Pure functions → Property tests
   - [ ] Parsers/decoders → Fuzz tests
   - [ ] Unsafe blocks → Kani proofs
   - [ ] State machines → Property tests + Fuzz

4. **Existing Patterns in This Codebase**
   - Unit tests: Same file under `#[cfg(test)] mod tests`
   - Property tests: Sibling `*_tests.rs` files with `stdx-proptest` feature
   - Kani proofs: `#[cfg(kani)]` blocks, see `docs/kani-verification.md`

## Example Assessment Output

```markdown
## Test Strategy for `WindowValidator`

### Recommended Approach: Property Tests + Kani

**Rationale:**
- Operates on sliding windows over byte streams (large input space)
- Has invariant: validated windows never exceed buffer bounds
- Contains unsafe pointer arithmetic

**Specific Tests:**

1. **Property Test**: Window position invariants
   - Property: `window.end <= buffer.len()` for all inputs
   - Property: Windows never overlap incorrectly

2. **Kani Proof**: Memory safety of unsafe block
   - Prove: No out-of-bounds access in `unsafe` pointer ops
   - Bound: Unwind factor based on max window size

3. **Unit Tests**: Known edge cases
   - Empty buffer
   - Single-byte buffer
   - Window at buffer boundary
```

## Quick Reference

| Scenario | Primary | Secondary |
|----------|---------|-----------|
| New data structure | Property tests | Unit tests for edges |
| Parser/decoder | Fuzz tests | Property tests for roundtrip |
| Unsafe code | Kani proofs | Property tests for API |
| Algorithm correctness | Property tests | Unit tests for examples |
| Bug fix | Unit test (regression) | - |
| Performance-critical loop | Kani (bounds) | Property tests |
