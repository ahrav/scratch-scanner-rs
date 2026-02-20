//! Eval-harness binary — measures scanner-rs accuracy against labeled corpora.
//!
//! This tool will compare scanner findings (from a JSONL file or a live scan)
//! against ground-truth annotations from labeled corpora (CredData, LeakyRepo,
//! synthetic) and compute precision, recall, and PRC-AUC. It will optionally
//! compare results against a baseline to detect regressions.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Pass or warn — metrics are acceptable |
//! | 1    | Block — a regression was detected against the baseline |
//! | 2    | Argument or runtime error |
//!
//! # Status
//!
//! Stub. The binary depends on corpus parsers, finding-to-truth matching,
//! metrics computation, and report generation modules that have not yet been
//! implemented. Once those are in place, this file will be replaced with the
//! full CLI entry point using subcommands for each corpus type.

fn main() {
    eprintln!("eval-harness: not yet implemented");
    std::process::exit(2);
}
