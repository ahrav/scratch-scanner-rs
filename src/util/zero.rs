//! Zero-content helpers.

/// Returns true if every byte is zero.
pub fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod tests {
    use super::is_all_zeros;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 16;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn zero_filled_vectors_pass(len in 0usize..65) {
            let bytes = vec![0u8; len];
            prop_assert!(is_all_zeros(&bytes));
        }

        #[test]
        fn vectors_with_any_non_zero_fail(bytes in proptest::collection::vec(any::<u8>(), 1..65)) {
            prop_assume!(bytes.iter().any(|&b| b != 0));
            prop_assert!(!is_all_zeros(&bytes));
        }
    }
}
