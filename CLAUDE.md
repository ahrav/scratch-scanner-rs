# CLAUDE.md

## Project Overview
Rust-based secret scanning engine with pattern matching, transforms (URL/Base64), and streaming decode.

## Key Directories
- `src/engine/` - Core scanning engine (scratch.rs, stream_decode.rs, work_items.rs)
- `src/stdx/` - Utility data structures (timing_wheel, bitset, ring_buffer, byte_ring)
- `docs/` - Architecture documentation with Mermaid diagrams

## Rust Code Modification Workflow
After modifying Rust code, ALWAYS run these steps:
1. `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features`
2. Run `/doc-rigor` skill on the new code to keep documentation updated
3. If adding new components, update relevant docs: `architecture-overview.md`, `detection-engine.md`, `memory-management.md`, `transform-chain.md`

## File Sync
- Keep `CLAUDE.md` and `AGENTS.md` identical for cross-tool compatibility

## Documentation Patterns
- Mermaid flowcharts/sequence diagrams in markdown
- ASCII art diagrams in code comments (see timing_wheel.rs for examples)
- Cross-reference between doc files with relative links
- Component tables with `| Component | Location | Purpose |` format

## Code Patterns
- `G` const generic for granularity parameters (e.g., `TimingWheel<T, G>`)
- `NONE_U32 = u32::MAX` as sentinel for invalid indices
- `#[inline(always)]` on hot-path functions
- `debug_assert!` for invariant checks only in debug builds
- `#[cfg(debug_assertions)]` for debug-only code paths

## Testing
- Unit tests in same file under `#[cfg(test)] mod tests`
- Property tests in sibling `*_tests.rs` files with feature gate `#[cfg(all(test, feature = "stdx-proptest"))]`

## Build & Test
- `cargo build` - Build the project
- `cargo test` - Fast unit tests only (~15-30s)
- `cargo test --features stdx-proptest` - Unit + property tests (~3-5 min)
- `cargo test --features scheduler-sim` - Unit + scheduler simulation tests
- `cargo kani --features kani` - Kani model checking
- `cargo +nightly fuzz run <target>` - Fuzz testing (targets in `/fuzz/`)
- Benchmarks in `benches/` directory, run with `cargo bench`

## Rule Optimization Workflow
After modifying rules in `src/gitleaks_rules.rs`:
1. Run `cargo test` to verify no regressions
2. Build release: `RUSTFLAGS="-C target-cpu=native" cargo build --release`
3. Benchmark against test repos: `./target/release/scanner-rs ../linux ../RustyPixels ../gitleaks ../tigerbeetle ../trufflehog ../kingfisher`
4. Compare throughput/findings against baseline

## Gitleaks Rules Patterns
- Add inline comments for rules with non-obvious anchor/keyword choices (see vault, sourcegraph rules)
- Avoid generic patterns like `[a-fA-F0-9]{40}` that match git SHAs
- Prefer structured prefixes (e.g., `sgp_`, `hvs.`) over keyword anchors like service names

## Performance Regression Workflow

Before merging any feature that touches hot paths (`src/engine/`, regex changes, validation logic):

### 1. Stash Changes and Build Baseline
```bash
git stash push -m "feature-name"
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 2. Run Baseline Scans (3x each)
```bash
for i in 1 2 3; do
  ./target/release/scanner-rs ../gitleaks 2>&1 | tail -1
  ./target/release/scanner-rs ../linux 2>&1 | tail -1
  ./target/release/scanner-rs ../tigerbeetle 2>&1 | tail -1
done
```

### 3. Run Baseline Benchmarks
```bash
cargo bench --bench scanner_throughput -- --save-baseline before
cargo bench --bench vectorscan_overhead -- --save-baseline before
```

### 4. Restore Changes and Rebuild
```bash
git stash pop
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 5. Run Comparison Scans and Benchmarks
```bash
# Same scan loop as step 2
cargo bench --bench scanner_throughput -- --baseline before
cargo bench --bench vectorscan_overhead -- --baseline before
```

### 6. Analyze Results
Calculate average throughput delta per repository:
```
% change = (after_throughput - baseline_throughput) / baseline_throughput * 100
```

### Acceptance Criteria
| Regression Level | Action |
|------------------|--------|
| None (<2%) | Ship as-is |
| Minor (2-5%) | Document reason, acceptable for correctness |
| Moderate (5-10%) | Requires compelling justification |
| Major (>10%) | Must investigate and optimize |

### PR Documentation
Include in PR description:
- Average throughput delta per test repository
- Criterion benchmark comparison summary
- Justification for any regression >2%
