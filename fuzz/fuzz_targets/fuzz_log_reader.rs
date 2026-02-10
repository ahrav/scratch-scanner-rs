#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_rs::store::log::LogReader;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut reader = LogReader::with_default_limit(Cursor::new(data.to_vec()));

    // Drain until terminal state.
    loop {
        match reader.next_record() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Post-terminal latch: must return Ok(None).
    assert!(
        reader.next_record().unwrap().is_none(),
        "post-terminal call must return Ok(None)"
    );
});
