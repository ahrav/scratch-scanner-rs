//! Allocation-free lexical tokenizers for candidate-only context filtering.
//!
//! The tokenizers classify byte ranges as code/comment/string/config without
//! building an AST. Output is stored as run-length segments in fixed-capacity
//! scratch buffers and must fail open on overflow or unknown state.
//!
//! Invariants and trade-offs:
//! - Runs are emitted in order and never overlap.
//! - On overflow or unknown context, callers must treat the class as
//!   [`LexicalClass::Unknown`] (fail-open).
//! - Triple-quote detection is conservative at chunk boundaries (only handled
//!   when all three quotes are visible in the same buffer) to avoid false
//!   negatives from over-classifying code as string.

use crate::api::{LexicalClass, LexicalClassSet, LexicalContextSpec};
use crate::scratch_memory::{ScratchMemoryError, ScratchVec};

/// Run-length segment for a lexical class.
///
/// Offsets are absolute, byte-based, and use a half-open interval:
/// `[start, end)`. Runs are emitted in order and never overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LexRun {
    /// Absolute start offset (inclusive).
    pub start: u64,
    /// Absolute end offset (exclusive).
    pub end: u64,
    /// Lexical class assigned to this span.
    pub class: LexicalClass,
}

/// Fixed-capacity run buffer with overflow tracking.
///
/// When capacity is exceeded, the buffer is cleared, `overflowed` is set, and
/// callers must treat lexical context as unknown (fail-open).
pub struct LexRuns {
    runs: ScratchVec<LexRun>,
    overflowed: bool,
}

/// Default capacity for lexical run buffers.
pub const DEFAULT_LEX_RUN_CAP: usize = 4096;

impl LexRuns {
    /// Allocate a new run buffer with the given capacity.
    pub fn with_capacity(cap: usize) -> Result<Self, ScratchMemoryError> {
        Ok(Self {
            runs: ScratchVec::with_capacity(cap)?,
            overflowed: false,
        })
    }

    #[inline]
    pub fn clear(&mut self) {
        self.runs.clear();
        self.overflowed = false;
    }

    #[inline]
    pub fn is_overflowed(&self) -> bool {
        self.overflowed
    }

    #[inline]
    pub fn as_slice(&self) -> &[LexRun] {
        self.runs.as_slice()
    }

    /// Push a run if capacity allows; merge with the last run when possible.
    #[inline]
    pub fn push_run(&mut self, start: u64, end: u64, class: LexicalClass) -> bool {
        if self.overflowed {
            return false;
        }
        if start >= end {
            return true;
        }
        if let Some(last) = self.runs.as_mut_slice().last_mut() {
            if last.class == class && last.end == start {
                last.end = end;
                return true;
            }
        }
        if self.runs.len() >= self.runs.capacity() {
            self.overflowed = true;
            self.runs.clear();
            return false;
        }
        self.runs.push(LexRun { start, end, class });
        true
    }
}

/// Lexical language families supported by the tokenizer.
///
/// These are coarse syntax families used for comment/string detection; they
/// are not full parsers and intentionally ignore language-specific edge cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexicalFamily {
    /// C-like syntax with `//` and `/* */` comments plus `'`/`"`/`` ` `` strings.
    CLike,
    /// Python/Ruby-like syntax with `#` line comments and `'`/`"` strings.
    /// Triple quotes are detected conservatively within a single chunk.
    PythonLike,
    /// Shell-like syntax with `#` line comments and `'`/`"` strings.
    ShellLike,
    /// Config-like syntax with `#`, `;`, or `//` line comments and quoted values.
    Config,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CLikeMode {
    Code,
    LineComment,
    BlockComment,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CLikeState {
    mode: CLikeMode,
    quote: u8,
    escape: bool,
    pending_slash: bool,
    pending_star: bool,
}

impl CLikeState {
    fn new() -> Self {
        Self {
            mode: CLikeMode::Code,
            quote: 0,
            escape: false,
            pending_slash: false,
            pending_star: false,
        }
    }

    fn class(&self) -> LexicalClass {
        match self.mode {
            CLikeMode::Code => LexicalClass::Code,
            CLikeMode::LineComment | CLikeMode::BlockComment => LexicalClass::Comment,
            CLikeMode::String => LexicalClass::String,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PyMode {
    Code,
    LineComment,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PythonState {
    mode: PyMode,
    quote: u8,
    escape: bool,
    triple: bool,
    triple_count: u8,
}

impl PythonState {
    fn new() -> Self {
        Self {
            mode: PyMode::Code,
            quote: 0,
            escape: false,
            triple: false,
            triple_count: 0,
        }
    }

    fn class(&self) -> LexicalClass {
        match self.mode {
            PyMode::Code => LexicalClass::Code,
            PyMode::LineComment => LexicalClass::Comment,
            PyMode::String => LexicalClass::String,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellMode {
    Code,
    LineComment,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ShellState {
    mode: ShellMode,
    quote: u8,
    escape: bool,
}

impl ShellState {
    fn new() -> Self {
        Self {
            mode: ShellMode::Code,
            quote: 0,
            escape: false,
        }
    }

    fn class(&self) -> LexicalClass {
        match self.mode {
            ShellMode::Code => LexicalClass::Code,
            ShellMode::LineComment => LexicalClass::Comment,
            ShellMode::String => LexicalClass::String,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigMode {
    Code,
    LineComment,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConfigState {
    mode: ConfigMode,
    quote: u8,
    escape: bool,
    pending_slash: bool,
}

impl ConfigState {
    fn new() -> Self {
        Self {
            mode: ConfigMode::Code,
            quote: 0,
            escape: false,
            pending_slash: false,
        }
    }

    fn class(&self) -> LexicalClass {
        match self.mode {
            ConfigMode::Code => LexicalClass::Config,
            ConfigMode::LineComment => LexicalClass::Comment,
            ConfigMode::String => LexicalClass::String,
        }
    }
}

/// Streaming lexical tokenizer with state preserved across chunks.
///
/// The tokenizer expects chunks from a single file in ascending offset order.
/// Call [`reset`](Self::reset) between files and [`finish`](Self::finish) at
/// EOF to flush the last run.
#[derive(Clone, Debug)]
pub struct LexicalTokenizer {
    family: LexicalFamily,
    run_start: u64,
    run_class: LexicalClass,
    started: bool,
    c_like: CLikeState,
    python: PythonState,
    shell: ShellState,
    config: ConfigState,
}

impl LexicalTokenizer {
    /// Construct a tokenizer for a specific language family.
    pub fn new(family: LexicalFamily) -> Self {
        Self {
            family,
            run_start: 0,
            run_class: LexicalClass::Unknown,
            started: false,
            c_like: CLikeState::new(),
            python: PythonState::new(),
            shell: ShellState::new(),
            config: ConfigState::new(),
        }
    }

    /// Reset tokenizer state for a new file.
    ///
    /// This clears all mode tracking but does not clear any existing runs.
    pub fn reset(&mut self) {
        self.run_start = 0;
        self.run_class = LexicalClass::Unknown;
        self.started = false;
        self.c_like = CLikeState::new();
        self.python = PythonState::new();
        self.shell = ShellState::new();
        self.config = ConfigState::new();
    }

    /// Process a chunk starting at the given absolute offset.
    ///
    /// Chunks must be processed in order with a monotonic `base` that matches
    /// the absolute file offset of `buf[0]`.
    pub fn process_chunk(&mut self, buf: &[u8], base: u64, runs: &mut LexRuns) {
        if runs.is_overflowed() {
            return;
        }
        if !self.started {
            self.started = true;
            self.run_start = base;
            self.run_class = self.current_class();
        }
        match self.family {
            LexicalFamily::CLike => self.process_c_like(buf, base, runs),
            LexicalFamily::PythonLike => self.process_python_like(buf, base, runs),
            LexicalFamily::ShellLike => self.process_shell_like(buf, base, runs),
            LexicalFamily::Config => self.process_config(buf, base, runs),
        }
    }

    /// Finish tokenization at end-of-file.
    ///
    /// This flushes the final run. Safe to call multiple times.
    pub fn finish(&mut self, end_offset: u64, runs: &mut LexRuns) {
        if !self.started || runs.is_overflowed() {
            return;
        }
        let _ = runs.push_run(self.run_start, end_offset, self.run_class);
    }

    #[inline]
    fn current_class(&self) -> LexicalClass {
        match self.family {
            LexicalFamily::CLike => self.c_like.class(),
            LexicalFamily::PythonLike => self.python.class(),
            LexicalFamily::ShellLike => self.shell.class(),
            LexicalFamily::Config => self.config.class(),
        }
    }

    #[inline]
    fn transition(&mut self, at: u64, next_class: LexicalClass, runs: &mut LexRuns) -> bool {
        if self.run_class == next_class {
            return true;
        }
        if !runs.push_run(self.run_start, at, self.run_class) {
            return false;
        }
        self.run_start = at;
        self.run_class = next_class;
        true
    }

    fn process_c_like(&mut self, buf: &[u8], base: u64, runs: &mut LexRuns) {
        let mut i = 0usize;
        if self.c_like.pending_slash {
            self.c_like.pending_slash = false;
            // Previous chunk ended with '/', resolve '//' or '/*' now.
            if let Some(&b0) = buf.first() {
                if b0 == b'/' {
                    if !self.transition(base - 1, LexicalClass::Comment, runs) {
                        return;
                    }
                    self.c_like.mode = CLikeMode::LineComment;
                    i = 1;
                } else if b0 == b'*' {
                    if !self.transition(base - 1, LexicalClass::Comment, runs) {
                        return;
                    }
                    self.c_like.mode = CLikeMode::BlockComment;
                    i = 1;
                }
            }
        }
        if self.c_like.pending_star {
            self.c_like.pending_star = false;
            // Previous chunk ended with '*', resolve '*/' now.
            if let Some(&b0) = buf.first() {
                if b0 == b'/' {
                    if !self.transition(base + 1, LexicalClass::Code, runs) {
                        return;
                    }
                    self.c_like.mode = CLikeMode::Code;
                    i = 1;
                }
            }
        }

        while i < buf.len() {
            if runs.is_overflowed() {
                return;
            }
            match self.c_like.mode {
                CLikeMode::Code => {
                    let b = buf[i];
                    if b == b'/' {
                        if i + 1 >= buf.len() {
                            self.c_like.pending_slash = true;
                            return;
                        }
                        let b2 = buf[i + 1];
                        if b2 == b'/' {
                            if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                                return;
                            }
                            self.c_like.mode = CLikeMode::LineComment;
                            i += 2;
                            continue;
                        }
                        if b2 == b'*' {
                            if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                                return;
                            }
                            self.c_like.mode = CLikeMode::BlockComment;
                            i += 2;
                            continue;
                        }
                    }
                    if matches!(b, b'\'' | b'"' | b'`') {
                        if !self.transition(base + i as u64, LexicalClass::String, runs) {
                            return;
                        }
                        self.c_like.mode = CLikeMode::String;
                        self.c_like.quote = b;
                        self.c_like.escape = false;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                CLikeMode::LineComment => {
                    if buf[i] == b'\n' {
                        if !self.transition(base + i as u64, LexicalClass::Code, runs) {
                            return;
                        }
                        self.c_like.mode = CLikeMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                CLikeMode::BlockComment => {
                    if buf[i] == b'*' {
                        if i + 1 >= buf.len() {
                            self.c_like.pending_star = true;
                            return;
                        }
                        if buf[i + 1] == b'/' {
                            if !self.transition(base + i as u64 + 2, LexicalClass::Code, runs) {
                                return;
                            }
                            self.c_like.mode = CLikeMode::Code;
                            i += 2;
                            continue;
                        }
                    }
                    i += 1;
                }
                CLikeMode::String => {
                    let b = buf[i];
                    if self.c_like.escape {
                        self.c_like.escape = false;
                        i += 1;
                        continue;
                    }
                    if b == b'\\' {
                        self.c_like.escape = true;
                        i += 1;
                        continue;
                    }
                    if b == self.c_like.quote {
                        if !self.transition(base + i as u64 + 1, LexicalClass::Code, runs) {
                            return;
                        }
                        self.c_like.mode = CLikeMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
            }
        }
    }

    fn process_python_like(&mut self, buf: &[u8], base: u64, runs: &mut LexRuns) {
        let mut i = 0usize;
        while i < buf.len() {
            if runs.is_overflowed() {
                return;
            }
            match self.python.mode {
                PyMode::Code => {
                    let b = buf[i];
                    if b == b'#' {
                        if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                            return;
                        }
                        self.python.mode = PyMode::LineComment;
                        i += 1;
                        continue;
                    }
                    if b == b'\'' || b == b'"' {
                        // Triple quotes are only recognized when all three are
                        // present in the same chunk to avoid over-classifying
                        // at chunk boundaries.
                        let has_full_triple =
                            i + 2 < buf.len() && buf[i + 1] == b && buf[i + 2] == b;
                        if !self.transition(base + i as u64, LexicalClass::String, runs) {
                            return;
                        }
                        self.python.mode = PyMode::String;
                        self.python.quote = b;
                        self.python.escape = false;
                        self.python.triple = has_full_triple;
                        self.python.triple_count = 0;
                        if has_full_triple {
                            i += 3;
                        } else {
                            i += 1;
                        }
                        continue;
                    }
                    i += 1;
                }
                PyMode::LineComment => {
                    if buf[i] == b'\n' {
                        if !self.transition(base + i as u64, LexicalClass::Code, runs) {
                            return;
                        }
                        self.python.mode = PyMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                PyMode::String => {
                    let b = buf[i];
                    if self.python.triple {
                        if b == self.python.quote {
                            self.python.triple_count = self.python.triple_count.saturating_add(1);
                            if self.python.triple_count >= 3 {
                                if !self.transition(base + i as u64 + 1, LexicalClass::Code, runs) {
                                    return;
                                }
                                self.python.mode = PyMode::Code;
                                self.python.triple = false;
                                self.python.triple_count = 0;
                            }
                        } else {
                            self.python.triple_count = 0;
                        }
                        i += 1;
                        continue;
                    }
                    if self.python.escape {
                        self.python.escape = false;
                        i += 1;
                        continue;
                    }
                    if b == b'\\' {
                        self.python.escape = true;
                        i += 1;
                        continue;
                    }
                    if b == self.python.quote {
                        if !self.transition(base + i as u64 + 1, LexicalClass::Code, runs) {
                            return;
                        }
                        self.python.mode = PyMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
            }
        }
    }

    fn process_shell_like(&mut self, buf: &[u8], base: u64, runs: &mut LexRuns) {
        let mut i = 0usize;
        while i < buf.len() {
            if runs.is_overflowed() {
                return;
            }
            match self.shell.mode {
                ShellMode::Code => {
                    let b = buf[i];
                    if b == b'#' {
                        if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                            return;
                        }
                        self.shell.mode = ShellMode::LineComment;
                        i += 1;
                        continue;
                    }
                    if b == b'\'' || b == b'"' {
                        if !self.transition(base + i as u64, LexicalClass::String, runs) {
                            return;
                        }
                        self.shell.mode = ShellMode::String;
                        self.shell.quote = b;
                        self.shell.escape = false;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                ShellMode::LineComment => {
                    if buf[i] == b'\n' {
                        if !self.transition(base + i as u64, LexicalClass::Code, runs) {
                            return;
                        }
                        self.shell.mode = ShellMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                ShellMode::String => {
                    let b = buf[i];
                    if self.shell.escape {
                        self.shell.escape = false;
                        i += 1;
                        continue;
                    }
                    if b == b'\\' {
                        self.shell.escape = true;
                        i += 1;
                        continue;
                    }
                    if b == self.shell.quote {
                        if !self.transition(base + i as u64 + 1, LexicalClass::Code, runs) {
                            return;
                        }
                        self.shell.mode = ShellMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
            }
        }
    }

    fn process_config(&mut self, buf: &[u8], base: u64, runs: &mut LexRuns) {
        let mut i = 0usize;
        if self.config.pending_slash {
            self.config.pending_slash = false;
            if let Some(&b0) = buf.first() {
                if b0 == b'/' {
                    if !self.transition(base - 1, LexicalClass::Comment, runs) {
                        return;
                    }
                    self.config.mode = ConfigMode::LineComment;
                    i = 1;
                }
            }
        }
        while i < buf.len() {
            if runs.is_overflowed() {
                return;
            }
            match self.config.mode {
                ConfigMode::Code => {
                    let b = buf[i];
                    if b == b'#' || b == b';' {
                        if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                            return;
                        }
                        self.config.mode = ConfigMode::LineComment;
                        i += 1;
                        continue;
                    }
                    if b == b'/' {
                        if i + 1 >= buf.len() {
                            self.config.pending_slash = true;
                            return;
                        }
                        if buf[i + 1] == b'/' {
                            if !self.transition(base + i as u64, LexicalClass::Comment, runs) {
                                return;
                            }
                            self.config.mode = ConfigMode::LineComment;
                            i += 2;
                            continue;
                        }
                    }
                    if b == b'\'' || b == b'"' {
                        if !self.transition(base + i as u64, LexicalClass::String, runs) {
                            return;
                        }
                        self.config.mode = ConfigMode::String;
                        self.config.quote = b;
                        self.config.escape = false;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                ConfigMode::LineComment => {
                    if buf[i] == b'\n' {
                        if !self.transition(base + i as u64, LexicalClass::Config, runs) {
                            return;
                        }
                        self.config.mode = ConfigMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
                ConfigMode::String => {
                    let b = buf[i];
                    if self.config.escape {
                        self.config.escape = false;
                        i += 1;
                        continue;
                    }
                    if b == b'\\' {
                        self.config.escape = true;
                        i += 1;
                        continue;
                    }
                    if b == self.config.quote {
                        if !self.transition(base + i as u64 + 1, LexicalClass::Config, runs) {
                            return;
                        }
                        self.config.mode = ConfigMode::Code;
                        i += 1;
                        continue;
                    }
                    i += 1;
                }
            }
        }
    }
}

/// Result of lexical context evaluation for a single span.
///
/// `definitive` indicates whether the lexical context was known well enough
/// to apply rule gates. `score` is a coarse signal (0/128/255) used for ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LexicalVerdict {
    /// Resolved lexical class for the span.
    pub class: LexicalClass,
    /// Score used by callers for ranking (0 = deny/unknown, 128 = neutral, 255 = preferred).
    pub score: u8,
    /// `true` when context was known and gates were applied.
    pub definitive: bool,
    /// `true` when the span passes lexical gates (fail-open on unknown).
    pub passes: bool,
}

/// Find the lexical class for an absolute offset.
///
/// The run list must be sorted, non-overlapping, and cover the relevant spans
/// (as produced by [`LexicalTokenizer`]). Returns `Unknown` on overflow or when
/// the offset is outside any run.
#[inline]
pub fn class_at(runs: &LexRuns, offset: u64) -> LexicalClass {
    if runs.is_overflowed() {
        return LexicalClass::Unknown;
    }
    let slices = runs.as_slice();
    let mut lo = 0usize;
    let mut hi = slices.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let run = slices[mid];
        if offset < run.start {
            hi = mid;
        } else if offset >= run.end {
            lo = mid + 1;
        } else {
            return run.class;
        }
    }
    LexicalClass::Unknown
}

/// Evaluate lexical context against a rule-level specification.
///
/// Returns a fail-open verdict when `class` is `Unknown`.
#[inline]
pub fn evaluate_lexical(spec: &LexicalContextSpec, class: LexicalClass) -> LexicalVerdict {
    if class == LexicalClass::Unknown {
        return LexicalVerdict {
            class,
            score: 0,
            definitive: false,
            passes: true,
        };
    }

    let class_set = LexicalClassSet::from(class);
    if spec.deny_any.intersects(class_set) {
        return LexicalVerdict {
            class,
            score: 0,
            definitive: true,
            passes: false,
        };
    }
    if let Some(req) = spec.require_any {
        if !req.intersects(class_set) {
            return LexicalVerdict {
                class,
                score: 0,
                definitive: true,
                passes: false,
            };
        }
    }

    let score = if spec.prefer_any.intersects(class_set) {
        255
    } else {
        128
    };
    LexicalVerdict {
        class,
        score,
        definitive: true,
        passes: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_merge_adjacent_segments() {
        let mut runs = LexRuns::with_capacity(4).unwrap();
        assert!(runs.push_run(0, 4, LexicalClass::Code));
        assert!(runs.push_run(4, 8, LexicalClass::Code));
        assert!(runs.push_run(8, 9, LexicalClass::Comment));
        let slice = runs.as_slice();
        assert_eq!(slice.len(), 2);
        assert_eq!(slice[0].start, 0);
        assert_eq!(slice[0].end, 8);
        assert_eq!(slice[1].class, LexicalClass::Comment);
    }

    #[test]
    fn runs_overflow_fails_open() {
        let mut runs = LexRuns::with_capacity(1).unwrap();
        assert!(runs.push_run(0, 1, LexicalClass::Code));
        assert!(!runs.push_run(1, 2, LexicalClass::Comment));
        assert!(runs.is_overflowed());
        assert_eq!(class_at(&runs, 0), LexicalClass::Unknown);
    }

    #[test]
    fn c_like_tokenizes_comments_and_strings() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::CLike);
        let buf = b"let x = \"secret\"; // comment\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String));
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment));
    }

    #[test]
    fn c_like_block_comment_spans_chunks() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::CLike);
        let buf1 = b"code /* comment";
        let buf2 = b" still */ code";
        tok.process_chunk(buf1, 0, &mut runs);
        tok.process_chunk(buf2, buf1.len() as u64, &mut runs);
        tok.finish((buf1.len() + buf2.len()) as u64, &mut runs);
        let boundary = buf1.len() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::Comment && r.start < boundary && r.end > boundary
        }));
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Code));
    }

    #[test]
    fn c_like_escape_does_not_terminate_string() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::CLike);
        let buf = b"let s = \"a\\\"b\";";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let start = buf.iter().position(|&b| b == b'"').unwrap() as u64;
        let end = buf.iter().rposition(|&b| b == b'"').unwrap() as u64 + 1;
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String && r.start == start && r.end == end));
    }

    #[test]
    fn c_like_line_comment_terminates_at_newline() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::CLike);
        let buf = b"code // comment\nnext\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let newline = buf.iter().position(|&b| b == b'\n').unwrap() as u64;
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment && r.start < newline && r.end == newline));
        assert_eq!(class_at(&runs, newline + 1), LexicalClass::Code);
    }

    #[test]
    fn c_like_multiline_string_spans_chunks() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::CLike);
        let buf1 = b"const char *s = \"line1\n";
        let buf2 = b"line2\";";
        tok.process_chunk(buf1, 0, &mut runs);
        tok.process_chunk(buf2, buf1.len() as u64, &mut runs);
        tok.finish((buf1.len() + buf2.len()) as u64, &mut runs);
        let boundary = buf1.len() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::String && r.start < boundary && r.end > boundary
        }));
    }

    #[test]
    fn python_triple_quotes_are_string() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::PythonLike);
        let buf = b"x = \"\"\"secret\"\"\"\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String));
    }

    #[test]
    fn python_escape_does_not_terminate_string() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::PythonLike);
        let buf = b"x = 'a\\'b'\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let start = buf.iter().position(|&b| b == b'\'').unwrap() as u64;
        let end = buf.iter().rposition(|&b| b == b'\'').unwrap() as u64 + 1;
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String && r.start == start && r.end == end));
    }

    #[test]
    fn python_triple_quote_spans_chunks() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::PythonLike);
        let buf1 = b"x = \"\"\"line1\n";
        let buf2 = b"line2\"\"\"\n";
        tok.process_chunk(buf1, 0, &mut runs);
        tok.process_chunk(buf2, buf1.len() as u64, &mut runs);
        tok.finish((buf1.len() + buf2.len()) as u64, &mut runs);
        let boundary = buf1.len() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::String && r.start < boundary && r.end > boundary
        }));
    }

    #[test]
    fn python_line_comment() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::PythonLike);
        let buf = b"val = 1 # comment\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment));
    }

    #[test]
    fn shell_line_comment() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::ShellLike);
        let buf = b"export KEY=VAL # secret\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment));
    }

    #[test]
    fn shell_hash_inside_quotes_is_string() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::ShellLike);
        let buf = b"echo \"#not\" # comment\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String));
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment));
    }

    #[test]
    fn shell_escape_does_not_terminate_string() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::ShellLike);
        let buf = b"echo \"a\\\"b\" # c\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let start = buf.iter().position(|&b| b == b'"').unwrap() as u64;
        let end = buf.iter().rposition(|&b| b == b'"').unwrap() as u64 + 1;
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String && r.start == start && r.end == end));
    }

    #[test]
    fn shell_string_spans_chunks() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::ShellLike);
        let buf1 = b"echo \"line1";
        let buf2 = b"line2\"";
        tok.process_chunk(buf1, 0, &mut runs);
        tok.process_chunk(buf2, buf1.len() as u64, &mut runs);
        tok.finish((buf1.len() + buf2.len()) as u64, &mut runs);
        let boundary = buf1.len() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::String && r.start < boundary && r.end > boundary
        }));
    }

    #[test]
    fn shell_heredoc_like_sequences_are_code() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::ShellLike);
        let buf = b"cat <<EOF\nsecret\nEOF\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(!runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Comment));
        assert!(!runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String));
    }

    #[test]
    fn config_values_marked_config() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::Config);
        let buf = b"token = abc123\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::Config));
    }

    #[test]
    fn config_escape_does_not_terminate_string() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::Config);
        let buf = b"key = \"a\\\"b\"\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let start = buf.iter().position(|&b| b == b'"').unwrap() as u64;
        let end = buf.iter().rposition(|&b| b == b'"').unwrap() as u64 + 1;
        assert!(runs
            .as_slice()
            .iter()
            .any(|r| r.class == LexicalClass::String && r.start == start && r.end == end));
    }

    #[test]
    fn config_comment_terminates_at_newline() {
        let mut runs = LexRuns::with_capacity(16).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::Config);
        let buf = b"key = 1 # comment\nnext = 2\n";
        tok.process_chunk(buf, 0, &mut runs);
        tok.finish(buf.len() as u64, &mut runs);
        let newline = buf.iter().position(|&b| b == b'\n').unwrap() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::Comment && r.start < newline && r.end == newline
        }));
        assert_eq!(class_at(&runs, newline + 1), LexicalClass::Config);
    }

    #[test]
    fn config_slash_comment_spans_chunks() {
        let mut runs = LexRuns::with_capacity(32).unwrap();
        let mut tok = LexicalTokenizer::new(LexicalFamily::Config);
        let buf1 = b"key = value /";
        let buf2 = b"/ comment\nnext = 1\n";
        tok.process_chunk(buf1, 0, &mut runs);
        tok.process_chunk(buf2, buf1.len() as u64, &mut runs);
        tok.finish((buf1.len() + buf2.len()) as u64, &mut runs);
        let boundary = buf1.len() as u64;
        assert!(runs.as_slice().iter().any(|r| {
            r.class == LexicalClass::Comment && r.start < boundary && r.end > boundary
        }));
    }

    #[test]
    fn class_at_respects_boundaries() {
        let mut runs = LexRuns::with_capacity(4).unwrap();
        assert!(runs.push_run(0, 5, LexicalClass::Code));
        assert!(runs.push_run(5, 10, LexicalClass::Comment));
        assert_eq!(class_at(&runs, 0), LexicalClass::Code);
        assert_eq!(class_at(&runs, 4), LexicalClass::Code);
        assert_eq!(class_at(&runs, 5), LexicalClass::Comment);
        assert_eq!(class_at(&runs, 10), LexicalClass::Unknown);
    }

    #[test]
    fn evaluate_lexical_applies_require_and_deny() {
        let spec = LexicalContextSpec {
            require_any: Some(LexicalClassSet::STRING),
            prefer_any: LexicalClassSet::STRING,
            deny_any: LexicalClassSet::COMMENT,
        };
        let denied = evaluate_lexical(&spec, LexicalClass::Comment);
        assert!(denied.definitive);
        assert!(!denied.passes);

        let allowed = evaluate_lexical(&spec, LexicalClass::String);
        assert!(allowed.definitive);
        assert!(allowed.passes);
        assert_eq!(allowed.score, 255);

        let required_fail = evaluate_lexical(&spec, LexicalClass::Code);
        assert!(required_fail.definitive);
        assert!(!required_fail.passes);
    }
}
