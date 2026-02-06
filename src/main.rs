//! Unified Secret Scanner CLI
//!
//! Routes to filesystem or git scanning via subcommands:
//!
//! ```text
//! scanner-rs scan fs --path <dir|file> [OPTIONS]
//! scanner-rs scan git --repo <path>    [OPTIONS]
//! ```
//!
//! See `scanner-rs scan fs --help` or `scanner-rs scan git --help` for
//! source-specific options.
//!
//! # Exit Codes
//!
//! - `0`: Success (regardless of findings count)
//! - `2`: Invalid arguments or scan error

use std::io;

fn main() -> io::Result<()> {
    let config = scanner_rs::unified::cli::parse_args()?;
    scanner_rs::unified::orchestrator::run(config)
}
