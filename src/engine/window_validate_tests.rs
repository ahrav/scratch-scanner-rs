use super::*;

#[test]
fn test_has_assignment_value_shape_separators() {
    // Equals
    assert!(has_assignment_value_shape(b"api_key=AKIAIOSFODNN7EXAMPLE"));
    assert!(has_assignment_value_shape(b"token = abcdefghij1234567890"));
    assert!(has_assignment_value_shape(b"secret=\"longtoken1234\""));
    // Colon (JSON-style)
    assert!(has_assignment_value_shape(
        b"\"api_key\": \"AKIAIOSFODNN7EXAMPLE\""
    ));
    assert!(has_assignment_value_shape(b"token: abcdefghij1234567890"));
    // Arrow (=> becomes > after =)
    assert!(has_assignment_value_shape(b"key => longtoken1234567890"));
    assert!(has_assignment_value_shape(b"secret => AKIAIOSFODNN7EX"));
}

#[test]
fn test_has_assignment_value_shape_short_token() {
    // Token too short (less than 10 chars)
    assert!(!has_assignment_value_shape(b"key=short"));
    assert!(!has_assignment_value_shape(b"x: abc"));
    assert!(!has_assignment_value_shape(b"token = 123456789")); // exactly 9 chars
}

#[test]
fn test_has_assignment_value_shape_no_separator() {
    // No assignment separator at all
    assert!(!has_assignment_value_shape(
        b"some random text without assignment"
    ));
    assert!(!has_assignment_value_shape(b"api_key AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn test_has_assignment_value_shape_no_token_after_separator() {
    // Separator but no token after it
    assert!(!has_assignment_value_shape(b"key="));
    assert!(!has_assignment_value_shape(b"token:   "));
    assert!(!has_assignment_value_shape(b"secret = \"\""));
}

#[test]
fn test_has_assignment_value_shape_with_special_chars_in_token() {
    // Token with allowed special chars (underscore, hyphen, dot)
    assert!(has_assignment_value_shape(b"key=abc_def-ghi.jkl"));
    assert!(has_assignment_value_shape(b"token: some-long-token-value"));
    assert!(has_assignment_value_shape(b"id = user.name.domain"));
}

#[test]
fn test_has_assignment_value_shape_boundary_10_chars() {
    // Exactly 10 chars should pass
    assert!(has_assignment_value_shape(b"key=0123456789"));
    // 9 chars should fail
    assert!(!has_assignment_value_shape(b"key=012345678"));
}

#[test]
fn test_has_assignment_value_shape_skips_whitespace_and_quotes() {
    // Whitespace and quotes after separator should be skipped
    assert!(has_assignment_value_shape(b"key=  longtokenvalue"));
    assert!(has_assignment_value_shape(b"key=\"longtokenvalue\""));
    assert!(has_assignment_value_shape(b"key='longtokenvalue'"));
    assert!(has_assignment_value_shape(b"key=`longtokenvalue`"));
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
