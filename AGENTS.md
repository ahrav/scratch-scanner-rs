# AGENTS.md

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
- `cargo build` / `cargo test`
- `cargo test --features stdx-proptest` for property tests
- Benchmarks in `benches/` directory
