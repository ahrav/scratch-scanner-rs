//! Diagnostic and analysis tools (most #[ignore] by default).
//!
//! Run with: `cargo test --test diagnostic -- --ignored --nocapture`

mod alloc_after_startup;
mod analyze_unfilterable;
mod print_unfilterable;
