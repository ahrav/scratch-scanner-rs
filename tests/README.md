# Test Directory Structure

This directory organizes tests by type for clarity and easier navigation.

| Directory | Purpose | Command |
|-----------|---------|---------|
| `integration/` | Feature-level integration tests | `cargo test --test integration` |
| `smoke/` | End-to-end smoke tests | `cargo test --test smoke` |
| `property/` | Property-based soundness tests (proptest) | `cargo test --test property` |
| `simulation/` | Scheduler simulation harness | `cargo test --features scheduler-sim --test simulation` |
| `diagnostic/` | Analysis and audit tools | `cargo test --test diagnostic -- --ignored --nocapture` |
| `failures/` | Generated stress test failures (gitignored) | N/A |

## Quick Reference

### Run all fast tests
```bash
cargo test
```

### Run property-based tests
```bash
cargo test --test property
```

### Run scheduler simulation
```bash
cargo test --features scheduler-sim --test simulation
```

### Run diagnostic tools
```bash
cargo test --test diagnostic -- --ignored --nocapture
```

## Directory Details

### `integration/`
Standard integration tests that exercise multiple components together. Tests anchor optimization, manual anchor patterns, and other detection engine features.

### `smoke/`
End-to-end tests that run the scanner binary against test data. These catch regressions in the full scanning pipeline.

### `property/`
Property-based tests using proptest for exhaustive soundness verification. The `regex2anchor_soundness` tests mathematically verify the correctness of regex-to-anchor derivation.

### `simulation/`
Scheduler simulation harness for deterministic testing of concurrent scheduler behavior. Uses JSON corpus files in `corpus/` for reproducible test cases. See `corpus/README.md` for corpus format documentation.

### `diagnostic/`
Analysis and audit tools that are `#[ignore]` by default because they have special requirements (e.g., custom allocators) or produce verbose output. Run manually when investigating specific issues.

### `failures/`
Generated directory for stress test failure artifacts. When simulation stress tests find invariant violations, they write reproducible JSON artifacts here. This directory is gitignored.
