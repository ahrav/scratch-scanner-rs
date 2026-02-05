//! Deterministic virtual path construction for archive entries.
//!
//! # Invariants
//! - Output bytes are printable ASCII; non-printables are percent-escaped.
//! - `..` traversal never escapes above the virtual root.
//! - Output length is bounded by `max_len` with a stable hash suffix on truncation.
//! - Component count is capped to avoid path explosion.
//!
//! # Algorithm
//! - Normalize separators (`\\` → `/`) and split into components.
//! - Drop `.`; clamp `..` while tracking traversal attempts.
//! - Percent-escape unsafe bytes, then apply truncation with a hash suffix.
//!
//! # Design Notes
//! - Output is a **display identifier**, not a filesystem path.
//! - ASCII output avoids terminal/control-byte issues in logs.

/// Default maximum number of path components allowed during canonicalization.
pub const DEFAULT_MAX_COMPONENTS: usize = 256;

/// Suffix inserted on truncation: `~#` + 16 hex digits (64-bit hash).
const TRUNC_SUFFIX_LEN: usize = 2 + 16;

/// Placeholder used when canonicalization produces an empty path.
const EMPTY_PLACEHOLDER: &[u8] = b"<empty>";

/// Placeholder used when component cap is exceeded (caller should usually skip).
const COMPONENT_CAP_PLACEHOLDER: &[u8] = b"<component-cap-exceeded>";

/// Result of entry-path canonicalization.
///
/// `bytes` is a slice into the canonicalizer's internal buffer and is valid
/// until the next call that mutates the canonicalizer.
pub struct CanonicalPath<'a> {
    pub bytes: &'a [u8],
    /// True if input attempted to traverse above root (`..` with empty stack).
    pub had_traversal: bool,
    /// True if output was length-truncated and a hash suffix was appended.
    pub truncated: bool,
    /// True if component cap was exceeded. Output will be a placeholder.
    pub component_cap_exceeded: bool,
    /// 64-bit deterministic hash of the full (untruncated) canonical display bytes.
    pub hash64: u64,
}

/// Result of virtual path construction (`parent::entry`).
pub struct VirtualPath<'a> {
    pub bytes: &'a [u8],
    pub truncated: bool,
    /// 64-bit deterministic hash of the full (untruncated) display bytes.
    pub hash64: u64,
}

/// Canonicalizes archive entry names into stable display bytes.
///
/// # Guarantees
/// - Returned slices are valid until the next call that mutates the canonicalizer.
/// - Output length and component count are bounded by the provided limits.
///
/// # Performance
/// - Intended to be reused (one per worker/reader) to avoid allocations.
#[derive(Default)]
pub struct EntryPathCanonicalizer {
    // Stack of component byte ranges referencing the raw input slice.
    comps: Vec<(usize, usize)>,
    // Output display bytes (ASCII).
    out: Vec<u8>,

    // Debug-only capacity guards.
    #[cfg(debug_assertions)]
    comps_cap: usize,
    #[cfg(debug_assertions)]
    out_cap: usize,
}

impl EntryPathCanonicalizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-size internal buffers for steady-state zero growth.
    pub fn with_capacity(max_components: usize, max_len: usize) -> Self {
        let comps_cap = max_components.min(DEFAULT_MAX_COMPONENTS);
        let out_cap = max_len;
        Self {
            comps: Vec::with_capacity(comps_cap),
            out: Vec::with_capacity(out_cap),
            #[cfg(debug_assertions)]
            comps_cap,
            #[cfg(debug_assertions)]
            out_cap,
        }
    }

    /// Debug-only guard: ensure internal buffers never grow after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            if self.comps_cap != 0 {
                debug_assert_eq!(
                    self.comps.capacity(),
                    self.comps_cap,
                    "canonicalizer comps grew after startup"
                );
            }
            if self.out_cap != 0 {
                debug_assert_eq!(
                    self.out.capacity(),
                    self.out_cap,
                    "canonicalizer output grew after startup"
                );
            }
        }
    }

    /// Canonicalize a raw archive entry path.
    ///
    /// - Separators: `\` and `/` treated as `/`
    /// - Drop empty and `.` components
    /// - `..` pops a component; if empty, clamps and sets `had_traversal=true`
    /// - Component cap exceeded => `component_cap_exceeded=true` and placeholder output
    /// - Non-printable bytes (and `%`) are escaped as `%HH` (uppercase hex)
    /// - If display exceeds `max_len`, truncates and appends `~#<16hex>` (may
    ///   shorten by 1–2 bytes to avoid splitting a `%HH` escape)
    /// - `max_len` and `max_components` are clamped to internal buffer capacity
    ///   to avoid growth; size with `with_capacity` for larger limits
    pub fn canonicalize<'a>(
        &'a mut self,
        raw: &[u8],
        max_components: usize,
        max_len: usize,
    ) -> CanonicalPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        let max_components = max_components
            .min(DEFAULT_MAX_COMPONENTS)
            .min(self.comps.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "canonicalizer output buffer too small for max_len"
        );
        debug_assert!(
            self.comps.capacity() >= max_components,
            "canonicalizer component stack too small for max_components"
        );
        self.comps.clear();

        let mut had_traversal = false;
        let mut component_cap_exceeded = false;

        // Split and resolve '.' / '..' using a bounded stack of ranges into `raw`.
        let mut i = 0usize;
        while i < raw.len() {
            // Skip separators (treat '\\' as '/').
            while i < raw.len() && is_sep(raw[i]) {
                i += 1;
            }
            if i >= raw.len() {
                break;
            }
            let start = i;
            while i < raw.len() && !is_sep(raw[i]) {
                i += 1;
            }
            let end = i;
            if end <= start {
                continue;
            }

            let comp = &raw[start..end];
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                if self.comps.pop().is_none() {
                    had_traversal = true;
                }
                continue;
            }

            if self.comps.len() >= max_components {
                component_cap_exceeded = true;
                break;
            }

            self.comps.push((start, end));
        }

        // Emit escaped display bytes and hash them deterministically.
        self.out.clear();

        // If component cap exceeded, output a deterministic placeholder and hash raw bytes.
        if component_cap_exceeded {
            let h = fnv1a64_raw_with_sep_norm(raw);
            emit_truncated_with_hash_suffix(&mut self.out, COMPONENT_CAP_PLACEHOLDER, h, max_len);
            return CanonicalPath {
                bytes: &self.out,
                had_traversal,
                truncated: self.out.len() < COMPONENT_CAP_PLACEHOLDER.len(),
                component_cap_exceeded: true,
                hash64: h,
            };
        }

        // If empty after canonicalization, emit placeholder.
        if self.comps.is_empty() {
            let h = fnv1a64(EMPTY_PLACEHOLDER);
            emit_truncated_with_hash_suffix(&mut self.out, EMPTY_PLACEHOLDER, h, max_len);
            return CanonicalPath {
                bytes: &self.out,
                had_traversal,
                truncated: self.out.len() < EMPTY_PLACEHOLDER.len(),
                component_cap_exceeded: false,
                hash64: h,
            };
        }

        // Emit full display bytes up to max_len, but compute hash over full (unbounded) display bytes.
        let mut hash = fnv1a64_init();
        let mut full_len = 0usize;

        for (idx, (s, e)) in self.comps.iter().copied().enumerate() {
            if idx != 0 {
                emit_one(&mut self.out, &mut hash, &mut full_len, b'/', max_len);
            }
            for &b in &raw[s..e] {
                emit_escaped_byte(&mut self.out, &mut hash, &mut full_len, b, max_len);
            }
        }

        // If truncation happened (full_len > max_len), rewrite to prefix + suffix.
        let truncated = full_len > max_len;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, max_len);
        } else {
            // Ensure out length matches full_len (it should, since full_len <= max_len).
            debug_assert_eq!(self.out.len(), full_len);
        }

        CanonicalPath {
            bytes: &self.out,
            had_traversal,
            truncated,
            component_cap_exceeded: false,
            hash64: hash,
        }
    }
}

/// Builds `parent::entry` display bytes with truncation + stable hash suffix.
///
/// Reuse this per worker/reader to avoid allocations.
#[derive(Default)]
pub struct VirtualPathBuilder {
    out: Vec<u8>,

    // Debug-only capacity guard.
    #[cfg(debug_assertions)]
    cap: usize,
}

impl VirtualPathBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_len: usize) -> Self {
        Self {
            out: Vec::with_capacity(max_len),
            #[cfg(debug_assertions)]
            cap: max_len,
        }
    }

    /// Debug-only guard: ensure internal buffer never grows after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.out.capacity(),
                self.cap,
                "virtual path builder grew after startup"
            );
        }
    }

    /// Builds `parent_display_bytes + "::" + entry_display_bytes`.
    ///
    /// If result exceeds `max_len`, it truncates and appends `~#<16hex>` where
    /// the hash is computed over the full untruncated bytes.
    pub fn build<'a>(&'a mut self, parent: &[u8], entry: &[u8], max_len: usize) -> VirtualPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "virtual path buffer too small for max_len"
        );
        self.out.clear();

        let mut hash = fnv1a64_init();
        let mut full_len = 0usize;

        for &b in parent {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, max_len);
        }
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', max_len);
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', max_len);
        for &b in entry {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, max_len);
        }

        let truncated = full_len > max_len;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, max_len);
        } else {
            debug_assert_eq!(self.out.len(), full_len);
        }

        VirtualPath {
            bytes: &self.out,
            truncated,
            hash64: hash,
        }
    }

    /// Builds `parent::entry` and appends `suffix` after the entry segment.
    ///
    /// If the full output exceeds `max_len`, it truncates the base
    /// `parent::entry` portion (with `~#<16hex>` hash suffix) and then appends
    /// `suffix`, so the suffix always appears at the end.
    ///
    /// If `suffix` alone exceeds `max_len`, the output is the truncated suffix
    /// and `hash64` is returned as 0.
    pub fn build_with_suffix<'a>(
        &'a mut self,
        parent: &[u8],
        entry: &[u8],
        suffix: &[u8],
        max_len: usize,
    ) -> VirtualPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "virtual path buffer too small for max_len"
        );
        self.out.clear();

        if max_len == 0 {
            return VirtualPath {
                bytes: &self.out,
                truncated: parent
                    .len()
                    .saturating_add(entry.len())
                    .saturating_add(suffix.len())
                    > 0,
                hash64: 0,
            };
        }

        let suffix_len = suffix.len();
        if suffix_len > max_len {
            self.out.extend_from_slice(&suffix[..max_len]);
            return VirtualPath {
                bytes: &self.out,
                truncated: true,
                hash64: 0,
            };
        }

        let base_limit = max_len - suffix_len;
        let mut hash = fnv1a64_init();
        let mut full_len = 0usize;

        for &b in parent {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, base_limit);
        }
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', base_limit);
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', base_limit);
        for &b in entry {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, base_limit);
        }

        let truncated = full_len > base_limit;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, base_limit);
        } else {
            debug_assert_eq!(self.out.len(), full_len);
        }

        if suffix_len > 0 {
            self.out.extend_from_slice(suffix);
        }

        VirtualPath {
            bytes: &self.out,
            truncated,
            hash64: hash,
        }
    }
}

// -------------------------
// Internals
// -------------------------

#[inline(always)]
fn is_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

// Deterministic 64-bit FNV-1a.
#[inline(always)]
fn fnv1a64_init() -> u64 {
    14695981039346656037u64
}

#[inline(always)]
fn fnv1a64_update(mut h: u64, b: u8) -> u64 {
    h ^= b as u64;
    h = h.wrapping_mul(1099511628211u64);
    h
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = fnv1a64_init();
    for &b in bytes {
        h = fnv1a64_update(h, b);
    }
    h
}

// Used only for the component-cap-exceeded placeholder: hash raw bytes with '\\' normalized to '/'.
fn fnv1a64_raw_with_sep_norm(raw: &[u8]) -> u64 {
    let mut h = fnv1a64_init();
    for &b in raw {
        let bb = if b == b'\\' { b'/' } else { b };
        h = fnv1a64_update(h, bb);
    }
    h
}

// Emit one byte into out (stored only up to max_len), but always hash + count full_len.
#[inline(always)]
fn emit_one(out: &mut Vec<u8>, hash: &mut u64, full_len: &mut usize, b: u8, max_len: usize) {
    *hash = fnv1a64_update(*hash, b);
    *full_len = full_len.saturating_add(1);
    if out.len() < max_len {
        out.push(b);
    }
}

// Escape non-printable bytes and '%' as `%HH` (uppercase).
#[inline(always)]
fn emit_escaped_byte(
    out: &mut Vec<u8>,
    hash: &mut u64,
    full_len: &mut usize,
    b: u8,
    max_len: usize,
) {
    if is_printable_ascii(b) && b != b'%' {
        emit_one(out, hash, full_len, b, max_len);
    } else {
        emit_one(out, hash, full_len, b'%', max_len);
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        emit_one(out, hash, full_len, hex_upper(hi), max_len);
        emit_one(out, hash, full_len, hex_upper(lo), max_len);
    }
}

#[inline(always)]
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

#[inline(always)]
fn hex_upper(n: u8) -> u8 {
    debug_assert!(n < 16);
    match n {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

#[inline(always)]
fn hex_lower(n: u8) -> u8 {
    debug_assert!(n < 16);
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

pub(crate) fn apply_hash_suffix_truncation(out: &mut Vec<u8>, hash: u64, max_len: usize) {
    if max_len == 0 {
        out.clear();
        return;
    }

    // Build suffix.
    let mut suffix = [0u8; TRUNC_SUFFIX_LEN];
    suffix[0] = b'~';
    suffix[1] = b'#';
    write_u64_hex_lower(hash, &mut suffix[2..18]);

    if max_len <= TRUNC_SUFFIX_LEN {
        out.clear();
        out.extend_from_slice(&suffix[..max_len]);
        return;
    }

    let prefix_len = max_len - TRUNC_SUFFIX_LEN;
    if out.len() > prefix_len {
        out.truncate(prefix_len);
    }

    // Avoid splitting a percent-escape sequence at the truncation boundary.
    if out.ends_with(b"%") {
        out.truncate(out.len().saturating_sub(1));
    } else if out.len() >= 2 && out[out.len() - 2] == b'%' {
        out.truncate(out.len().saturating_sub(2));
    }

    out.extend_from_slice(&suffix);
    debug_assert!(out.len() <= max_len);
}

fn emit_truncated_with_hash_suffix(out: &mut Vec<u8>, base: &[u8], hash: u64, max_len: usize) {
    out.clear();
    if max_len == 0 {
        return;
    }
    // Emit base into out up to max_len (no escaping assumed here).
    let take = base.len().min(max_len);
    out.extend_from_slice(&base[..take]);

    // If base doesn't fit, suffix truncation is not meaningful - keep prefix only.
    if base.len() <= max_len {
        return;
    }
    // base longer than max - replace with hash suffix truncation.
    apply_hash_suffix_truncation(out, hash, max_len);
}

fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
    debug_assert_eq!(out16.len(), 16);
    for (i, out) in out16.iter_mut().enumerate().take(16) {
        let shift = (15 - i) * 4;
        let nyb = ((x >> shift) & 0xF) as u8;
        *out = hex_lower(nyb);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_separators_and_dots() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        let r = c.canonicalize(b"a\\b/./c", 256, 1024);
        assert_eq!(r.bytes, b"a/b/c");
        assert!(!r.had_traversal);
        assert!(!r.truncated);
        assert!(!r.component_cap_exceeded);
    }

    #[test]
    fn canonicalize_dotdot_clamps_above_root() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        let r = c.canonicalize(b"../../a/b", 256, 1024);
        assert_eq!(r.bytes, b"a/b");
        assert!(r.had_traversal);
    }

    #[test]
    fn canonicalize_dotdot_pops() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        let r = c.canonicalize(b"a/b/../c", 256, 1024);
        assert_eq!(r.bytes, b"a/c");
        assert!(!r.had_traversal);
    }

    #[test]
    fn canonicalize_escapes_non_printable_and_percent() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        // component: "ab%\x01"
        let r = c.canonicalize(b"ab%\x01", 256, 1024);
        assert_eq!(r.bytes, b"ab%25%01");
    }

    #[test]
    fn canonicalize_empty_becomes_placeholder() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        let r = c.canonicalize(b"/./", 256, 1024);
        assert_eq!(r.bytes, b"<empty>");
    }

    #[test]
    fn canonicalize_truncates_with_hash_suffix() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 20);
        let raw = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = c.canonicalize(raw, 256, 20);
        assert_eq!(r.bytes.len(), 20);
        assert_eq!(&r.bytes[2..4], b"~#"); // prefix "aa" then "~#"
        assert!(r.truncated);
    }

    #[test]
    fn component_cap_exceeded_sets_flag_and_placeholder() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 64);
        // 300 components "a/a/a/..."
        let mut raw = Vec::new();
        for i in 0..300 {
            if i != 0 {
                raw.push(b'/');
            }
            raw.push(b'a');
        }
        let r = c.canonicalize(&raw, 16, 64);
        assert!(r.component_cap_exceeded);
        assert!(r.bytes.starts_with(b"<component-cap-exceeded>") || r.bytes.starts_with(b"~#"));
    }

    #[test]
    fn virtual_path_builds_parent_entry() {
        let mut b = VirtualPathBuilder::with_capacity(1024);
        let v = b.build(b"/tmp/a.zip", b"a/b.txt", 1024);
        assert_eq!(v.bytes, b"/tmp/a.zip::a/b.txt");
        assert!(!v.truncated);
    }

    #[test]
    fn virtual_path_truncates() {
        let mut b = VirtualPathBuilder::with_capacity(16);
        let parent = b"/this/is/a/very/very/very/very/very/long/path";
        let entry = b"entry";
        let v = b.build(parent, entry, 16);
        assert_eq!(v.bytes.len(), 16);
        assert!(v.truncated);
    }

    #[test]
    fn virtual_path_appends_suffix_after_truncation() {
        let mut b = VirtualPathBuilder::with_capacity(20);
        let parent = b"/tmp/archive.tar";
        let entry = b"very-long-entry-name";
        let suffix = b"@t0000000000000001";
        let v = b.build_with_suffix(parent, entry, suffix, 20);
        assert!(v.bytes.ends_with(suffix));
        assert!(v.bytes.windows(2).any(|w| w == b"~#"));
    }

    #[test]
    fn canonicalize_clamps_to_output_capacity() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 8);
        let raw = b"this/is/a/very/long/path";
        let r = c.canonicalize(raw, DEFAULT_MAX_COMPONENTS, 128);
        assert!(r.bytes.len() <= 8);
        assert!(r.truncated);
    }
}
