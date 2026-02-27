//! Fuzz target for DotEnvExtractor.
//!
//! Feeds arbitrary bytes to the `.env` extractor and verifies structural
//! invariants beyond "no panics":
//!
//! - Output length never exceeds [`EXTRACT_OUTPUT_CAP`].
//! - Every non-empty line in the output contains `=` with a non-empty key.
//! - Extraction is idempotent for single-line output (re-extracting the
//!   output produces identical bytes).
//!
//! Multiline quoted values produce output lines that are value continuations
//! (no `=`), so the idempotency check is skipped when such lines are detected.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_dotenv_extract -- -runs=10000
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_rs::content_policy::dotenv::DotEnvExtractor;
use scanner_rs::content_policy::extract::{Extractor, EXTRACT_OUTPUT_CAP};

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::with_capacity(1024);
    let _ = DotEnvExtractor.extract(data, &mut out, &mut Vec::new());

    // Invariant 1: output length never exceeds the extraction budget.
    assert!(
        out.len() <= EXTRACT_OUTPUT_CAP,
        "output length {} exceeds cap {}",
        out.len(),
        EXTRACT_OUTPUT_CAP,
    );

    // Invariant 2: every non-empty output line has `=` with a non-empty key.
    // Track whether all lines are single-line assignments (no multiline
    // value continuations) for the idempotency check below.
    let mut all_lines_have_eq = true;
    for line in out.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        match line.iter().position(|&b| b == b'=') {
            Some(eq_pos) => {
                assert!(eq_pos > 0, "empty key in output line");
            }
            None => {
                // Continuation line from a multiline quoted value.
                all_lines_have_eq = false;
            }
        }
    }

    // Invariant 3: idempotency — re-extracting the output yields identical
    // bytes. Skipped when multiline value continuations are present (the
    // output format uses bare `\n` for both line separation and embedded
    // literals, so multiline values inherently lose structure on re-parse).
    if all_lines_have_eq && !out.is_empty() {
        let mut out2 = Vec::with_capacity(out.len());
        let _ = DotEnvExtractor.extract(&out, &mut out2, &mut Vec::new());
        assert_eq!(out, out2, "extraction is not idempotent");
    }
});
