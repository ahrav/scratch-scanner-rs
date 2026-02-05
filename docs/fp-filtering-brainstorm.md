Decision: **don’t put a full AST parser (Tree-sitter) in the hot path.**
If we want to keep the current “tens of GB/s when nothing hits” profile _and_ the “no allocations after warm-up” contract, the only sane architecture is **tiered context**:

- **Tier 0 (already present):** anchors → windows → cheap gates → regex/entropy/validators → findings
- **Tier 1 (cheap, always-on or rule-selective):** _local_ context checks that look at a tiny neighborhood around the match (same line / separators / quotes / key names). No extra pass, no state machine.
- **Tier 2 (optional, file-level, only when needed):** _lexical_ context (string vs comment vs code) via a streaming tokenizer or minimal parser. Still no allocations if we pre-allocate scratch, but it’s an extra pass—so we only run it on candidate files.
- **Tier 3 (optional “big gun”):** Tree-sitter as a _second-pass filter_ for a small subset of files, with strict memory budgets and “fail open” semantics.

That gets you FP reduction without sacrificing the performance envelope for the common case.

---

## Design A: Rule-local “micro-context” gates (no AST, no second pass)

### What it buys

This targets the classic FP generators: **token-only matches** (AWS access key IDs, generic API keys, JWT-ish blobs, etc.) that appear in places that look nothing like “credential assignment”.

Your engine already does some of this (keyword gate, confirm-all, entropy, and a special “assignment shape” check for `generic-api-key`). This design generalizes that _without_ bringing in parsing.

### How it fits your architecture

Add a **post-regex, pre-emit** gate that inspects only a bounded region around the _secret span_:

- same-line assignment structure: `KEY <sep> VALUE`
- separators whitelist: `= : =>`
- “value looks quoted” (optional): `'...'`, `"..."`, `` `...` ``
- optional key-name binding (strong FP killer): require that the LHS key matches a small set (e.g., `aws_access_key_id`, `token`, `secret`, `password`, …) **on the same line**, not anywhere in the 256-byte radius
- negative cues (best as scoring, not hard filter): `example`, `dummy`, `test`, `placeholder`, `lorem`, `REDACTED`

All of this is implementable as branchy-but-small scans with `memchr`/byte loops and **zero allocations**.

### Performance profile

- **Asymptotic:** O(k) per match, where k is a small constant lookbehind/lookahead (say 128–512 bytes)
- **Constant factors:** tiny; it runs only on regex matches (which are already rare compared to bytes scanned)
- **Cache:** stays in L1 (local slices)
- **Branch predictability:** decent; mostly scanning for `\n`, `=`, `:`, quotes

### Correctness contract

- If used as a **hard filter**, it can introduce false negatives (a real secret not on an assignment line).
  So: make it **rule-selective** and/or **mode-selective**:
  - `ContextMode::Score` (default): attach confidence but do not drop
  - `ContextMode::Filter`: drop low-confidence (opt-in)

### Concrete, compilable building block (self-contained)

This is the kind of “micro-context” helper you can call from `window_validate` right after you compute `secret_start/secret_end` (raw variant):

```rust
#[derive(Clone, Copy, Debug)]
pub struct LocalContextSpec {
    /// Look behind from secret_start, bounded.
    pub lookbehind: usize,
    /// Require an assignment separator on the same line before the secret.
    pub require_same_line_assignment: bool,
    /// Require the secret to be wrapped in single/double/backtick quotes.
    pub require_quoted: bool,
}

#[inline]
fn last_newline_before(hay: &[u8], idx: usize, max_back: usize) -> usize {
    let back = idx.min(max_back);
    let start = idx - back;
    // Find last '\n' in hay[start..idx]
    for i in (start..idx).rev() {
        if hay[i] == b'\n' {
            return i + 1;
        }
    }
    start
}

#[inline]
fn first_newline_after(hay: &[u8], idx: usize, max_fwd: usize) -> usize {
    let end = (idx + max_fwd).min(hay.len());
    for i in idx..end {
        if hay[i] == b'\n' {
            return i;
        }
    }
    end
}

#[inline]
fn has_assignment_sep(line: &[u8]) -> bool {
    // conservative: any '=', ':' or '>' (to cover '=>') counts
    line.iter().any(|&b| b == b'=' || b == b':' || b == b'>')
}

#[inline]
fn is_quoted_at(hay: &[u8], secret_start: usize, secret_end: usize) -> bool {
    if secret_start == 0 || secret_end >= hay.len() {
        return false;
    }
    let ql = hay[secret_start - 1];
    let qr = hay[secret_end];
    // Accept ' " `
    (ql == qr) && (ql == b'\'' || ql == b'"' || ql == b'`')
}

/// Conservative local context gate. Returns true when context passes.
#[inline]
pub fn local_context_passes(
    window: &[u8],
    secret_start: usize,
    secret_end: usize,
    spec: LocalContextSpec,
) -> bool {
    if spec.require_same_line_assignment {
        let line_start = last_newline_before(window, secret_start, spec.lookbehind);
        let line_end = first_newline_after(window, secret_start, 256);
        let line = &window[line_start..line_end.min(secret_start)];
        if !has_assignment_sep(line) {
            return false;
        }
    }

    if spec.require_quoted {
        if !is_quoted_at(window, secret_start, secret_end) {
            return false;
        }
    }

    true
}
```

This isn’t “parsing”; it’s “cheap shape checking” and tends to punch way above its weight on FPs.

---

## Design B: Streaming tokenizer / lexical context (strings/comments) with **no allocations**

### What it buys

This is where “context” starts to feel like “parsing” without dragging an AST in:

- classify byte ranges as: `Code`, `LineComment`, `BlockComment`, `String("...")`, `Char('...')`, `Template(`...`)`, etc.
- then rules can say things like:
  - “token must be in a string literal” (for languages where secrets almost always are)
  - “down-rank (or optionally filter) tokens in comments/docstrings”
  - “require it not to be in a URL path literal” (format-specific)

### The key engineering issue: chunking + overlap

Because comments/strings can be arbitrarily long, **fixed overlap is not enough** to determine lexical state at the start of a chunk. So if you want correctness, you either:

1. **Tokenizer runs in the same sequential pass as reading** (maintains state across chunks), or
2. **Second pass over the file** (only for files with candidate findings), so the tokenizer sees the whole prefix.

Given your performance goals: **do a second pass only for candidate files**. That way:

- no extra work for the 99% of files with no findings
- still deterministic and allocation-free (reuse the same fixed buffer)

### Memory strategy (no alloc)

Represent the classification as **run-length encoded segments**, not per-byte flags:

```text
[0..120) Code
[120..180) LineComment
[180..220) Code
[220..900) String
...
```

Store runs into a fixed-capacity `ScratchVec<Run>` (or fixed array + length). If the run cap is exceeded (adversarial alternating delimiters), **fail open**: treat as “unknown context”, don’t filter.

### Performance profile

- **Asymptotic:** O(n) over the bytes you tokenize + O(findings × log runs) (or O(findings × runs) with small run counts)
- **Constant factors:** tokenizer is branchy; still much cheaper than tree-sitter
- **Cache:** sequential scan (good locality)
- **Determinism:** perfect

### Maintenance cost

Medium. You don’t want “a lexer per language.” You want **language families**:

- C-like: `//`, `/* */`, `' "`, escapes
- Python-like: `#`, triple quotes
- Shell-like: `#`, `' "`, backslash escapes
- JSON/TOML/INI/env: string + key/value structure

That will cover the bulk of repositories.

---

## Design C: Tree-sitter (AST) as an **opt-in, bounded second pass**

Tree-sitter is viable, but only in a very specific way that respects your constraints:

### When it’s worth it

- You need **high-fidelity context** in languages where lexical hacks get messy:
  - JavaScript/TypeScript template literals and regex literals
  - heredocs (Ruby, Bash)
  - nested/interpolated strings

- You want node-level semantics: “this token is in an argument to `fetch()`” or “this is a map literal value”

### How to make it compatible with “no alloc after startup”

Hard part: tree-sitter allocates parse trees.

To keep your contract, you need:

- **custom allocator** via `ts_set_allocator` that routes allocations to a **thread-local, preallocated arena**
- a **strict per-file arena budget** (e.g., 4–16 MiB); on OOM, abort parse and **fail open**
- **mmap input** (Unix) or reuse a large preallocated read buffer (portable but re-reads file)
- parser/query objects created at worker startup and warmed

Two huge gotchas:

- `ts_set_allocator` is **global**, so you need a global allocator shim that uses TLS arenas safely across worker threads.
- tree-sitter’s allocation pattern includes `realloc`. A bump allocator can “fake” realloc by allocate+copy, but that increases arena pressure. Budgeting is mandatory.

### Performance profile

- It will be **orders of magnitude slower** than your Tier 1 Vectorscan ceiling.
  That’s fine only if it runs on a small minority of files (candidate-only).

### Recommendation

Treat Tree-sitter as a **feature-gated, “precision mode”** rather than default behavior.

---

## Where to integrate in your codebase (low-disruption)

You have two good insertion points:

### Option 1: In-engine (best for Design A)

Inside `engine/window_validate.rs`, after extracting `secret_start/secret_end` and before `push_finding…`.

Pros:

- avoids emitting garbage findings that you’ll discard later
- still runs only on matches, not bytes

Cons:

- cannot easily use filetype/language unless you thread that through `scan_chunk_into` (API change)

### Option 2: Scheduler/runtime layer (best for Design B/C)

In `scheduler/local.rs` right after `drain_findings_into(&mut pending)` and dedupe, before `emit_findings()`.

Pros:

- has access to file path (extension) and can decide language
- can do a **second-pass read** for candidate files without touching engine internals
- isolates “context complexity” from the core scanning engine

Cons:

- you already paid the regex cost for findings you’ll filter (fine if filtering is mostly for FPs, not perf)

My bias: **start in scheduler/runtime** (least invasive), and only move into engine if it proves worth it.

---

## Correctness + determinism: things you must pin down

To avoid accidental false negatives, define explicit semantics:

- `ContextMode::Off`: current behavior
- `ContextMode::Score`: compute context and attach a confidence (or internal flag), **do not drop**
- `ContextMode::Filter`: drop only when context evaluation is _definitive_; otherwise **fail open** (keep finding)

And define what “definitive” means per analyzer:

- tokenizer exceeded run cap → unknown → keep
- tree-sitter OOM / parse error / unsupported language → unknown → keep

That preserves the “no false negatives” contract unless the user opts into aggressive filtering.

---

## Measurement plan (falsifiable)

### Performance

1. **Microbench context gates alone**
   - cycles/byte for tokenizer on representative corpora (JS, Python, config)
   - cycles/finding for local micro-context gates

2. **End-to-end throughput**
   - reuse existing `cargo bench --bench scanner_throughput`
   - add variants:
     - baseline
     - +Tier A gates (should be near-no-change in Tier 1)
     - +Tier B second pass (measure overhead only on candidate files)

   - success metric example (you can tune):
     - Tier 1: ≤ 2% regression
     - Tier 2/3: ≤ 5–10% regression at the same hit density

3. **Allocation audit**
   - extend `tests/diagnostic/alloc_after_startup.rs` with a scan that enables context mode and asserts `0` allocs after warm-up.

### False positives

You need a labeled dataset; otherwise “FP reduction” turns into vibes.

Minimal viable approach:

- Build a **regression corpus** of:
  - known true positives (synthetic secrets placed in realistic contexts)
  - known false positives (cases you’ve observed in the wild, redacted)

- Track:
  - FP count
  - TP recall (must not drop unless in Filter mode)
  - “noise per MB” (FP/MB)

---

## Practical next steps (lowest risk, highest payoff)

1. **Generalize the existing assignment-shape gate** beyond `generic-api-key`:
   - make it configurable per rule name (without changing public `RuleSpec` yet)
   - add “same-line only” semantics

2. Add a **second-pass tokenizer** for _candidate files only_, with:
   - C-like + Python-like families first
   - run-cap + fail-open behavior

3. Only after (1) and (2) are measured, consider Tree-sitter as a feature-gated precision pass.

This keeps the scanner’s core personality intact: _fast, bounded, deterministic, and allergic to surprise allocations_, while still giving you real leverage on false positives.
