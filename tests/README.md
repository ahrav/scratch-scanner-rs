# Test Directory Structure

This directory organizes tests by type for clarity and easier navigation.

| Directory | Purpose | Command |
|-----------|---------|---------|
| `integration/` | Feature-level integration tests | `cargo test --test integration` |
| `smoke/` | End-to-end smoke tests | `cargo test --test smoke` |
| `property/` | Property-based soundness tests (proptest) | `cargo test --test property` |
| `simulation/` | Scanner and scheduler simulation harnesses | See below |
| `diagnostic/` | Analysis and audit tools | `cargo test --test diagnostic -- --ignored --nocapture` |
| `corpus/` | Regression test corpus for simulations | N/A (loaded by simulation tests) |
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

### Run simulation harnesses
```bash
# Run all simulation tests
cargo test --features sim-harness,scheduler-sim --test simulation

# Run scanner simulation only
cargo test --features sim-harness --test simulation

# Run scheduler simulation only
cargo test --features scheduler-sim --test simulation

# Scale random tests via environment variables
SIM_SCANNER_SEED_COUNT=100 cargo test --features sim-harness --test simulation
SCHEDULER_SIM_STRESS_SEEDS=100 cargo test --features scheduler-sim --test simulation
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
Deterministic simulation harnesses for both scanner and scheduler testing.

**Scanner Simulation** (`sim-harness` feature):
- Tests chunked scanning, overlap deduplication, and fault tolerance
- Uses `tests/corpus/scanner/*.case.json` for regression tests
- See `docs/scanner_test_harness_guide.md` for full documentation

**Scheduler Simulation** (`scheduler-sim` feature):
- Tests work-stealing policy, parking, and resource accounting
- Uses `tests/simulation/corpus/*.json` for regression tests
- See `docs/scheduler_test_harness_guide.md` for full documentation

**Git Simulation** (`sim-harness` feature):
- Tests Git scan stage ordering, determinism, and fault injection
- Uses `tests/corpus/git_scan/*.case.json` for regression tests
- See `docs/git_simulation_harness_guide.md` for full documentation

### `corpus/`
Regression test corpus organized by simulation type:
- `corpus/scanner/` - Scanner simulation artifacts (`.case.json`)
- `corpus/scheduler/` - Scheduler simulation artifacts (`.case.json`)
- `corpus/git_scan/` - Git simulation artifacts (`.case.json`)

### `diagnostic/`
Analysis and audit tools that are `#[ignore]` by default because they have special requirements (e.g., custom allocators) or produce verbose output. Run manually when investigating specific issues.

### `failures/`
Generated directory for stress test failure artifacts. When simulation stress tests find invariant violations, they write reproducible JSON artifacts here. This directory is gitignored.
