#![no_main]

//! Fuzz target for the `sanitize_path` function in the text sink module.
//!
//! Feeds arbitrary byte sequences through `sanitize_path` and verifies:
//!
//! 1. **No raw control characters**: the output contains no C0 control
//!    characters (0x00..=0x1f) or DEL (0x7f). The replacement character
//!    U+FFFD is permitted (it comes from lossy UTF-8 decoding).
//! 2. **One-line invariant**: the output contains no raw newlines (`\n`,
//!    `\r`). Embedded newlines in the input must be escaped as `\x0a` /
//!    `\x0d`.
//! 3. **No panics**: the function handles all byte patterns without panicking.

use libfuzzer_sys::fuzz_target;

use scanner_rs::unified::harness_api::sanitize_path;

fuzz_target!(|data: &[u8]| {
    let output = sanitize_path(data);

    // The output must be valid UTF-8 (it's a String, so this is guaranteed
    // by construction, but we check the bytes explicitly for defense-in-depth).
    assert!(
        std::str::from_utf8(output.as_bytes()).is_ok(),
        "sanitize_path output is not valid UTF-8: {:?}",
        output.as_bytes(),
    );

    // No raw C0 control characters (0x00..=0x1f) or DEL (0x7f) may appear.
    // The replacement character U+FFFD is allowed (three UTF-8 bytes: EF BF BD).
    for ch in output.chars() {
        if ch == '\u{FFFD}' {
            // Replacement character from lossy UTF-8 decoding — allowed.
            continue;
        }
        assert!(
            !ch.is_control(),
            "raw control character U+{:04X} found in sanitize_path output for input {:?}: {:?}",
            ch as u32,
            data,
            output,
        );
    }

    // One-line invariant: no raw newlines in the output.
    assert!(
        !output.contains('\n'),
        "raw newline found in sanitize_path output for input {:?}: {:?}",
        data,
        output,
    );
    assert!(
        !output.contains('\r'),
        "raw carriage return found in sanitize_path output for input {:?}: {:?}",
        data,
        output,
    );
});
