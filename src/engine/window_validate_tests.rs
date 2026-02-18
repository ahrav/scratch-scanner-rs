use super::*;

#[test]
fn has_assignment_value_shape_cases() {
    let cases: &[(&str, &[u8], bool)] = &[
        // ---- separators ----
        ("equals basic", b"api_key=AKIAIOSFODNN7EXAMPLE", true),
        ("equals with space", b"token = abcdefghij1234567890", true),
        (
            "equals with quoted value",
            b"secret=\"longtoken1234\"",
            true,
        ),
        (
            "colon JSON-style",
            b"\"api_key\": \"AKIAIOSFODNN7EXAMPLE\"",
            true,
        ),
        ("colon bare", b"token: abcdefghij1234567890", true),
        ("arrow =>", b"key => longtoken1234567890", true),
        ("arrow => short-ish", b"secret => AKIAIOSFODNN7EX", true),
        // ---- special chars in token ----
        ("underscore/hyphen/dot", b"key=abc_def-ghi.jkl", true),
        ("hyphen token", b"token: some-long-token-value", true),
        ("dotted token", b"id = user.name.domain", true),
        // ---- boundary: exactly 10 chars ----
        ("10-char token passes", b"key=0123456789", true),
        // ---- skip whitespace and quotes ----
        ("spaces after sep", b"key=  longtokenvalue", true),
        ("double-quoted value", b"key=\"longtokenvalue\"", true),
        ("single-quoted value", b"key='longtokenvalue'", true),
        ("backtick-quoted value", b"key=`longtokenvalue`", true),
        // ---- false: short token (<10 chars) ----
        ("short token 'short'", b"key=short", false),
        ("short colon token", b"x: abc", false),
        ("9-char token fails", b"token = 123456789", false),
        ("9-char boundary", b"key=012345678", false),
        // ---- false: no separator ----
        (
            "prose without separator",
            b"some random text without assignment",
            false,
        ),
        (
            "space instead of sep",
            b"api_key AKIAIOSFODNN7EXAMPLE",
            false,
        ),
        // ---- false: no token after separator ----
        ("empty after equals", b"key=", false),
        ("whitespace after colon", b"token:   ", false),
        ("empty quotes after sep", b"secret = \"\"", false),
    ];

    for (label, input, expected) in cases {
        assert_eq!(
            has_assignment_value_shape(input),
            *expected,
            "case: {label}"
        );
    }
}

#[test]
fn test_local_context_same_line_assignment_passes() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix\nkey = SECRET\nsuffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));
}

#[test]
fn test_local_context_same_line_assignment_fails_when_missing() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix\nnope SECRET\nsuffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(!local_context_passes(
        window,
        secret_start,
        secret_end,
        spec
    ));
}

#[test]
fn test_local_context_same_line_assignment_fail_open_without_bounds() {
    let spec = LocalContextSpec {
        lookbehind: 4,
        lookahead: 4,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix SECRET suffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));
}

#[test]
fn test_local_context_requires_quotes() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: false,
        require_quoted: true,
        key_names_any: None,
    };
    let window = b"key='SECRET' ";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));

    let window = b"key=SECRET ";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(!local_context_passes(
        window,
        secret_start,
        secret_end,
        spec
    ));
}

// ---- char_class_gate_passes tests ----

#[test]
fn char_class_gate_cases() {
    let cases: Vec<(&str, CharClassCompiled, Vec<u8>, bool)> = vec![
        (
            "short window fails open",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            vec![b'a'; 31],
            true,
        ),
        (
            "all-lowercase rejected",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            vec![b'a'; 40],
            false,
        ),
        (
            "mixed case passes",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            {
                let mut w = vec![b'a'; 19];
                w.extend_from_slice(&[b'A'; 19]);
                w.extend_from_slice(&[b'0'; 2]);
                w
            },
            true,
        ),
        (
            "exact boundary (95%) passes",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 20,
            },
            {
                let mut w = vec![b'a'; 19];
                w.push(b'A');
                w
            },
            true,
        ),
        (
            "zero tolerance rejects lowercase",
            CharClassCompiled {
                max_lower_pct: 0,
                min_window_len: 1,
            },
            b"a".to_vec(),
            false,
        ),
        (
            "zero tolerance allows uppercase",
            CharClassCompiled {
                max_lower_pct: 0,
                min_window_len: 1,
            },
            b"ABCDEF".to_vec(),
            true,
        ),
    ];

    for (label, spec, window, expected) in &cases {
        assert_eq!(
            char_class_gate_passes(window, *spec),
            *expected,
            "case: {label}"
        );
    }
}
