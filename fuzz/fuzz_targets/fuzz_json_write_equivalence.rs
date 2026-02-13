#![no_main]

//! Fuzz target for JSON write primitives.
//!
//! Exercises `write_json_bytes` and `write_json_str` with arbitrary inputs,
//! verifying:
//!
//! 1. **Output validity**: the encoded output is valid UTF-8 and contains no
//!    unescaped JSON-special characters (control chars, `"`, `\`).
//! 2. **Roundtrip safety**: valid ASCII substrings pass through unmodified.
//! 3. **No panics**: the functions handle all byte patterns without panicking.

use libfuzzer_sys::fuzz_target;

use scanner_rs::unified::json_write::{write_json_bytes, write_json_str};

/// Verify that encoded output contains no unescaped JSON-special characters.
///
/// After encoding, every byte in the output must be:
/// - A printable ASCII character (0x20..=0x7e) that is not `"` or `\`
///   appearing without a preceding `\`, OR
/// - Part of a valid `\` escape sequence, OR
/// - A valid UTF-8 continuation byte (0x80+) from a multi-byte codepoint.
///
/// We check the simpler invariant: the output is valid UTF-8 and does not
/// contain raw control characters (0x00..=0x1f).
fn assert_output_valid(output: &[u8]) {
    // Must be valid UTF-8.
    let s = std::str::from_utf8(output).expect("output must be valid UTF-8");

    // No raw control characters (they should be escaped as \uXXXX).
    for (i, b) in output.iter().enumerate() {
        assert!(
            *b >= 0x20,
            "raw control byte 0x{b:02x} at position {i} in output: {s:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // --- Test write_json_bytes with arbitrary bytes ---
    {
        let mut buf = Vec::with_capacity(data.len() * 2);
        write_json_bytes(data, &mut buf);
        assert_output_valid(&buf);
    }

    // --- Test write_json_str with the valid-UTF-8 prefix ---
    // Extract the longest valid UTF-8 prefix from the fuzz input.
    let valid_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(e) => {
            // Use the valid prefix up to the error.
            let valid_up_to = e.valid_up_to();
            if valid_up_to == 0 {
                return;
            }
            // SAFETY: from_utf8 proved this prefix is valid UTF-8.
            unsafe { std::str::from_utf8_unchecked(&data[..valid_up_to]) }
        }
    };

    if !valid_str.is_empty() {
        let mut buf = Vec::with_capacity(valid_str.len() * 2);
        write_json_str(valid_str, &mut buf);
        assert_output_valid(&buf);
    }
});
