//! Fuzz target for DotEnvExtractor.
//!
//! Feeds arbitrary bytes to the `.env` extractor and asserts it never panics.
//! The parser handles unquoted, single-quoted, and double-quoted multiline
//! values with escape processing, making it a good candidate for fuzz testing.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_dotenv_extract -- -runs=10000
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_rs::content_policy::dotenv::DotEnvExtractor;
use scanner_rs::content_policy::extract::Extractor;

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::with_capacity(1024);
    let _ = DotEnvExtractor.extract(data, &mut out, &mut Vec::new());
});
