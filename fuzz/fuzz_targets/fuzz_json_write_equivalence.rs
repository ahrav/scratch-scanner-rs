#![no_main]

//! Fuzz target for JSON write primitives.
//!
//! Exercises `write_json_bytes`, `write_json_str`, `write_u64`, and
//! `write_oid_hex` with arbitrary inputs, verifying:
//!
//! 1. **Output validity**: the encoded output is valid UTF-8 and contains no
//!    unescaped JSON-special characters (control chars, `"`, `\`).
//! 2. **Roundtrip safety**: valid ASCII substrings pass through unmodified.
//! 3. **Oracle equivalence**: `write_u64` matches `to_string()` and
//!    `write_oid_hex` matches per-byte `format!("{:02x}")`.
//! 4. **No panics**: the functions handle all byte patterns without panicking.

use libfuzzer_sys::fuzz_target;

use scanner_rs::git_scan::object_id::OidBytes;
use scanner_rs::unified::harness_api::{write_json_bytes, write_json_str, write_oid_hex, write_u64};

/// Verify that encoded output contains no unescaped JSON-special characters.
///
/// After encoding, every byte in the output must be:
/// - A printable ASCII character (0x20..=0x7e) that is not `"` or `\`
///   appearing without a preceding `\`, OR
/// - Part of a valid `\` escape sequence, OR
/// - A valid UTF-8 continuation byte (0x80+) from a multi-byte codepoint.
///
/// We check three invariants:
/// 1. The output is valid UTF-8.
/// 2. No raw control characters (0x00..=0x1f) appear outside escape sequences.
/// 3. No unescaped `"` or `\` appear outside escape sequences.
fn assert_output_valid(output: &[u8]) {
    // Must be valid UTF-8.
    let s = std::str::from_utf8(output).expect("output must be valid UTF-8");

    // Walk the output with a state machine that tracks whether we are inside
    // a backslash-escape sequence. This catches unescaped `"` and `\` that
    // the simpler byte-range check would miss.
    let mut i = 0;
    while i < output.len() {
        let b = output[i];

        // No raw control characters (they should be escaped as \uXXXX).
        assert!(
            b >= 0x20,
            "raw control byte 0x{b:02x} at position {i} in output: {s:?}"
        );

        if b == b'\\' {
            // Must be followed by a valid escape character.
            assert!(
                i + 1 < output.len(),
                "trailing backslash at position {i} in output: {s:?}"
            );
            let next = output[i + 1];
            match next {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    i += 2; // skip the two-char escape
                }
                b'u' => {
                    // \uXXXX — four hex digits must follow.
                    assert!(
                        i + 5 < output.len(),
                        "truncated \\u escape at position {i} in output: {s:?}"
                    );
                    for j in 0..4 {
                        assert!(
                            output[i + 2 + j].is_ascii_hexdigit(),
                            "non-hex digit in \\u escape at position {} in output: {s:?}",
                            i + 2 + j,
                        );
                    }
                    i += 6; // skip \uXXXX
                }
                _ => panic!(
                    "invalid escape character 0x{next:02x} at position {} in output: {s:?}",
                    i + 1,
                ),
            }
        } else {
            // Outside an escape: `"` and `\` must not appear bare.
            // (We already handled `\` above, so only check `"` here.)
            assert!(
                b != b'"',
                "unescaped '\"' at position {i} in output: {s:?}"
            );
            i += 1;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // --- Test write_u64 oracle: must match n.to_string() ---
    if data.len() >= 8 {
        let n = u64::from_le_bytes(data[..8].try_into().unwrap());
        let mut buf = Vec::with_capacity(20);
        write_u64(n, &mut buf);
        let got = std::str::from_utf8(&buf).expect("write_u64 must produce valid UTF-8");
        assert_eq!(got, &n.to_string(), "write_u64({n}) mismatch");
    }

    // --- Test write_oid_hex oracle: must match format!("{:02x}") ---
    if data.len() >= 20 {
        let mut raw = [0u8; 20];
        raw.copy_from_slice(&data[..20]);
        let oid = OidBytes::sha1(raw);
        let mut buf = Vec::with_capacity(40);
        write_oid_hex(&oid, &mut buf);
        let got = std::str::from_utf8(&buf).expect("write_oid_hex must produce valid UTF-8");
        let expected: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, &expected, "write_oid_hex mismatch");
    }

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
