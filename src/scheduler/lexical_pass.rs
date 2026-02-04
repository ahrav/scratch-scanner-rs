//! Helpers for candidate-only lexical context filtering in scheduler backends.
//!
//! These helpers consolidate the second-pass logic used by non-local schedulers:
//! buffer findings per file/object, re-read content for lexical tokenization,
//! and apply contextual rules before emitting. Callers are expected to treat
//! tokenization failures as fail-open (emit unfiltered findings).

use crate::api::LexicalClass;
use crate::lexical::{class_at, evaluate_lexical, LexRuns, LexicalFamily, LexicalTokenizer};
use crate::scheduler::engine_trait::{FindingRecord, ScanEngine};
use std::fs::File;
use std::io::{self, Read};

/// Determine lexical class for a root-span hint (half-open).
///
/// Returns `Unknown` when spans are out of bounds or cross class boundaries.
#[inline]
pub(crate) fn lexical_class_for_span(
    runs: &LexRuns,
    start: u64,
    end: u64,
    file_size: u64,
) -> LexicalClass {
    if start >= end || end > file_size {
        return LexicalClass::Unknown;
    }
    let start_class = class_at(runs, start);
    if start_class == LexicalClass::Unknown {
        return LexicalClass::Unknown;
    }
    let end_class = class_at(runs, end.saturating_sub(1));
    if start_class == end_class {
        start_class
    } else {
        LexicalClass::Unknown
    }
}

/// Apply lexical context rules in place, optionally filtering findings.
///
/// Findings without precise root spans remain unfiltered (fail-open).
/// In `ContextMode::Filter`, definitive mismatches are dropped. In
/// `ContextMode::Score`, findings are retained; callers can compute scores
/// using [`evaluate_lexical`] if needed.
pub(crate) fn apply_lexical_context<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    findings: &mut Vec<F>,
    runs: &LexRuns,
    file_size: u64,
    mode: crate::ContextMode,
) {
    if mode == crate::ContextMode::Off || findings.is_empty() {
        return;
    }
    if runs.is_overflowed() {
        return;
    }

    let should_filter = mode == crate::ContextMode::Filter;
    findings.retain(|rec| {
        let spec = match engine.rule_lexical_context(rec.rule_id()) {
            Some(spec) => spec,
            None => return true,
        };
        if !rec.lexical_root_span_precise() {
            return true;
        }
        let class =
            lexical_class_for_span(runs, rec.root_hint_start(), rec.root_hint_end(), file_size);
        let verdict = evaluate_lexical(&spec, class);
        if should_filter {
            verdict.passes
        } else {
            true
        }
    });
}

/// Tokenize a file for lexical context using a streaming tokenizer.
///
/// Callers should verify the file size matches their snapshot before invoking
/// this function to ensure offsets remain stable. Returns `UnexpectedEof` if
/// the file truncated mid-read. Errors should be treated as a signal to skip
/// lexical filtering (fail-open).
pub(crate) fn tokenize_for_lexical(
    file: &mut File,
    file_size: u64,
    family: LexicalFamily,
    buf: &mut [u8],
    runs: &mut LexRuns,
) -> io::Result<()> {
    runs.clear();
    let mut tokenizer = LexicalTokenizer::new(family);
    let mut offset: u64 = 0;
    while offset < file_size {
        let remaining = file_size.saturating_sub(offset);
        let read_len = (remaining as usize).min(buf.len());
        let n = read_some(file, &mut buf[..read_len])?;
        if n == 0 {
            if offset < file_size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "lexical re-read truncated",
                ));
            }
            break;
        }
        tokenizer.process_chunk(&buf[..n], offset, runs);
        offset = offset.saturating_add(n as u64);
        if runs.is_overflowed() {
            break;
        }
    }
    tokenizer.finish(offset, runs);
    Ok(())
}

fn read_some(file: &mut File, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        FileId, FindingRec, LexicalClass, LexicalClassSet, LexicalContextSpec, RuleSpec,
        ValidatorKind, STEP_ROOT,
    };
    use crate::demo::demo_tuning;
    use crate::engine::Engine;
    use regex::bytes::Regex;
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::Arc;

    fn test_engine() -> Arc<Engine> {
        let rule = RuleSpec {
            name: "secret",
            anchors: &[b"SECRET"],
            radius: 0,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            entropy: None,
            local_context: None,
            lexical_context: Some(LexicalContextSpec {
                require_any: Some(LexicalClassSet::STRING),
                prefer_any: LexicalClassSet::STRING,
                deny_any: LexicalClassSet::COMMENT,
            }),
            secret_group: None,
            re: Regex::new("SECRET").unwrap(),
        };
        Arc::new(Engine::new(vec![rule], Vec::new(), demo_tuning()))
    }

    #[test]
    fn apply_lexical_context_fails_open_on_overflow() {
        let engine = test_engine();
        let mut runs = LexRuns::with_capacity(1).unwrap();
        assert!(runs.push_run(0, 1, LexicalClass::Code));
        assert!(!runs.push_run(1, 2, LexicalClass::Comment));
        assert!(runs.is_overflowed());

        let mut findings = vec![FindingRec {
            file_id: FileId(0),
            rule_id: 0,
            span_start: 0,
            span_end: 6,
            root_hint_start: 0,
            root_hint_end: 6,
            dedupe_with_span: true,
            step_id: STEP_ROOT,
        }];

        apply_lexical_context(
            engine.as_ref(),
            &mut findings,
            &runs,
            2,
            crate::ContextMode::Filter,
        );

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn tokenize_for_lexical_unexpected_eof_fails_open() -> std::io::Result<()> {
        let engine = test_engine();
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(b"SECRET")?;
        file.as_file_mut().seek(SeekFrom::Start(0))?;

        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut buf = vec![0u8; 4];
        let mut findings = vec![FindingRec {
            file_id: FileId(0),
            rule_id: 0,
            span_start: 0,
            span_end: 6,
            root_hint_start: 0,
            root_hint_end: 6,
            dedupe_with_span: true,
            step_id: STEP_ROOT,
        }];

        let res = tokenize_for_lexical(
            file.as_file_mut(),
            1024,
            LexicalFamily::CLike,
            &mut buf,
            &mut runs,
        );
        assert!(res.is_err());

        if res.is_ok() {
            apply_lexical_context(
                engine.as_ref(),
                &mut findings,
                &runs,
                1024,
                crate::ContextMode::Filter,
            );
        }

        assert_eq!(findings.len(), 1);
        Ok(())
    }
}
