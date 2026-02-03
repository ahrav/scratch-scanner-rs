//! Property tests for PackAmq.

use super::PackAmq;
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 256;

fn proptest_config() -> ProptestConfig {
    ProptestConfig::with_cases(crate::test_utils::proptest_cases(PROPTEST_CASES))
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn no_false_negatives(offsets in proptest::collection::vec(any::<u64>(), 0..128)) {
        let filter = PackAmq::build(&offsets);
        for offset in offsets {
            prop_assert!(filter.maybe_contains(offset));
        }
    }
}
