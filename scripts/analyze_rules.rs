#!/usr/bin/env -S cargo +nightly -Zscript
//! Analyze gitleaks rules for optimization opportunities.
//!
//! Run with: cargo +nightly -Zscript scripts/analyze_rules.rs
//! Or: rustc scripts/analyze_rules.rs -o analyze_rules && ./analyze_rules

// This is a placeholder - we'll use a benchmark instead
fn main() {
    println!("Use cargo bench --bench rule_scaling --features stats -- diagnostics");
}
