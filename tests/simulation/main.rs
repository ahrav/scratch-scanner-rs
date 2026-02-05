//! Simulation harness tests for scheduler and scanner.
//!
//! Feature gates:
//! - `scheduler-sim` compiles scheduler-only simulations.
//! - `sim-harness` compiles scanner and Git scan simulations.
//!
//! Run with:
//!   cargo test --features scheduler-sim --test simulation  # scheduler only
//!   cargo test --features sim-harness --test simulation    # scanner + git
//!   cargo test --features scheduler-sim,sim-harness --test simulation  # both

#[cfg(feature = "scheduler-sim")]
mod scheduler_sim;

#[cfg(feature = "sim-harness")]
mod scanner_random;

#[cfg(feature = "sim-harness")]
mod scanner_corpus;

#[cfg(feature = "sim-harness")]
mod scanner_archive_corpus;

#[cfg(feature = "sim-harness")]
mod scanner_archive_random;

#[cfg(feature = "sim-harness")]
mod scanner_discovery;

#[cfg(feature = "sim-harness")]
mod scanner_max_file_size;

#[cfg(feature = "sim-harness")]
mod scanner_budget_invariance;

#[cfg(feature = "sim-harness")]
mod git_scan_corpus;

#[cfg(feature = "sim-harness")]
mod git_scan_random;
