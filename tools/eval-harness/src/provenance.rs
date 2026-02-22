//! Reproducibility metadata for eval runs.
//!
//! Every eval report embeds a [`Provenance`] struct that cryptographically
//! fingerprints the three inputs to an evaluation: the corpus directory, the
//! scanner binary, and the ruleset file. This lets anyone verify whether two
//! reports were produced from identical inputs, or pinpoint exactly which input
//! changed when metrics shift between runs.
//!
//! [`Provenance`] is consumed by [`crate::report::EvalReport`] and serialized
//! into JSON artifacts. It is not currently included in terminal table output.
//!
//! # Design: domain-separated BLAKE3
//!
//! All hashes use BLAKE3 with domain separation: a domain tag followed by a
//! NUL byte is fed to the hasher before any payload bytes. Two domain tags
//! are defined:
//!
//! - [`CORPUS_DOMAIN`] — used by [`hash_corpus`] for the directory-level hash.
//! - [`FILE_DOMAIN`] — used by [`hash_file_streaming`] and [`hash_file`] for
//!   individual files (both the scanner binary and the ruleset).
//!
//! Domain separation prevents cross-context collisions: a corpus that happens
//! to byte-match a binary will still produce different hashes because they are
//! keyed with different domain tags. The scanner binary and ruleset share
//! [`FILE_DOMAIN`] because they occupy separate fields in [`Provenance`] and
//! are never cross-compared; identical content in both fields producing the
//! same hash is correct behavior, not a collision.
//!
//! # Algorithm (corpus hash)
//!
//! 1. Recursively collect file paths under `corpus_dir` into a `Vec<PathBuf>`.
//!    Symlinks and non-regular files are skipped to keep the hash stable
//!    across environments with different link layouts.
//! 2. Sort paths lexicographically by their collected `PathBuf` bytes
//!    (prefix form follows caller input: relative vs absolute). Since all
//!    paths share the same `corpus_dir` prefix, the ordering is equivalent
//!    to sorting by relative path, ensuring deterministic results regardless
//!    of filesystem visit order.
//! 3. Initialize a BLAKE3 hasher with `CORPUS_DOMAIN || 0x00`.
//! 4. For each file in sorted order, feed a self-delimiting record:
//!    `path_len_u64_le || relative_path_bytes || content_len_u64_le ||
//!    file_contents`.
//!    This framing avoids structural ambiguity between adjacent records even
//!    when file contents contain arbitrary bytes.
//! 5. An empty directory produces a hash over just the domain tag and its NUL
//!    separator — still deterministic, but distinct from any non-empty corpus.
//!
//! # Performance
//!
//! - **BLAKE3 over SHA-256**: ~5x faster on Apple Silicon via NEON, already
//!   the standard hash in this codebase.
//! - **`Vec<PathBuf>` + `sort_unstable` over `BTreeSet`**: contiguous memory
//!   layout; sort has better cache behavior than B-tree pointer chasing.
//! - **64 KiB streaming buffer for the scanner binary**: fits L1d on typical
//!   hardware (64–128 KiB/core on Apple Silicon), amortizes syscall overhead.
//!   Corpus hashing and scanner binary hashing both use streaming reads, keeping
//!   memory flat even when the corpus contains large files.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Domain tag for corpus-level hashing.
///
/// Fed to the BLAKE3 hasher before any file data in [`hash_corpus`]. The
/// `eval.provenance.` prefix scopes all domain tags to this module;
/// the `corpus` suffix distinguishes directory hashing from the
/// single-file domain ([`FILE_DOMAIN`]).
const CORPUS_DOMAIN: &[u8] = b"eval.provenance.corpus";

/// Domain tag for single-file hashing (scanner binary and ruleset).
///
/// Shared by both [`hash_file_streaming`] (binary) and [`hash_file`]
/// (ruleset). Using a single domain for both is intentional: these hashes
/// live in separate [`Provenance`] fields and are never cross-compared,
/// so identical files producing the same hash is correct, not a collision.
const FILE_DOMAIN: &[u8] = b"eval.provenance.file";

/// Buffer size for streaming hash reads (64 KiB — fits L1d, amortizes syscalls).
const HASH_BUF_SIZE: usize = 64 * 1024;

/// Reproducibility metadata for an eval run.
///
/// Embeds enough information to answer two questions about any eval report:
///
/// 1. **Identity**: were two reports produced from the exact same inputs?
///    (Compare hash fields.)
/// 2. **Scale**: how large was the evaluation corpus? (Check count and byte
///    fields for sanity when comparing runs of different sizes.)
///
/// All hashes are hex-encoded BLAKE3 (64 hex chars = 32 bytes) with domain
/// separation — the corpus hash uses [`CORPUS_DOMAIN`] while the binary and
/// ruleset hashes use [`FILE_DOMAIN`]. `None` hash fields are omitted from
/// serialized JSON via `skip_serializing_if`, keeping the output clean when
/// optional inputs were not provided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// BLAKE3 hash over all corpus files in sorted-path order.
    ///
    /// Deterministic for a given directory tree: changing file contents, adding
    /// or removing files, or renaming files all produce a different hash.
    pub corpus_hash: String,
    /// BLAKE3 hash of the scanner binary (computed via streaming reads).
    /// `None` when no binary path was provided to [`build_provenance`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_hash: Option<String>,
    /// BLAKE3 hash of the ruleset file (read entirely into memory).
    /// `None` when no ruleset path was provided to [`build_provenance`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset_hash: Option<String>,
    /// Number of regular files found recursively in the corpus directory.
    /// Symlinks and non-file entries are excluded from this count.
    pub corpus_file_count: u64,
    /// Total bytes across all corpus files (sum of individual file sizes).
    pub corpus_total_bytes: u64,
}

/// Hash all files under `corpus_dir` in sorted-path order using BLAKE3.
///
/// Returns `(hex_hash, file_count, total_bytes)`.
///
/// The hash is deterministic for a given directory tree: files are sorted by
/// their collected path bytes (not canonicalized; relative/absolute form
/// follows how `corpus_dir` was provided), then visited in that order. The
/// hasher is initialized with `CORPUS_DOMAIN || 0x00`, then for each file:
/// `path_len_u64_le || relative_path_bytes || content_len_u64_le || file_contents`
/// is appended. Length prefixes make each record self-delimiting.
///
/// # Edge cases
///
/// - **Empty directory**: produces a hash over just the domain tag and its NUL
///   separator, with `file_count = 0` and `total_bytes = 0`.
/// - **Unreadable files**: returns an `io::Error` at the first file that
///   cannot be read. The hash is not partially computed — it is all or nothing.
/// - **Non-UTF-8 paths**: hashed as exact platform path bytes via
///   `as_encoded_bytes()`, avoiding lossy UTF-8 replacement and preserving
///   path identity.
/// - **Dotfiles and zero-byte files**: included like any other regular file.
///   Empty files still contribute their path and a zero content-length field.
pub fn hash_corpus(corpus_dir: &Path) -> io::Result<(String, u64, u64)> {
    let mut files = Vec::with_capacity(1024);
    collect_files_recursive(corpus_dir, &mut files)?;
    files.sort_unstable();

    let mut hasher = blake3::Hasher::new();
    // Domain prefix: prevents a corpus hash from colliding with a single-file hash
    // even if the byte streams happen to match.
    hasher.update(CORPUS_DOMAIN);
    hasher.update(&[0x00]);

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    for path in &files {
        let rel = path.strip_prefix(corpus_dir).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("corpus file {path:?} is not under corpus_dir {corpus_dir:?}: {e}"),
            )
        })?;
        let rel_bytes = path_bytes(rel);
        let mut file = std::fs::File::open(path)?;
        let file_len = file.metadata()?.len();

        update_len_prefixed(&mut hasher, rel_bytes);
        hasher.update(&file_len.to_le_bytes());

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total_bytes += n as u64;
        }

        file_count += 1;
    }

    Ok((
        hasher.finalize().to_hex().to_string(),
        file_count,
        total_bytes,
    ))
}

#[inline]
fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[inline]
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_encoded_bytes()
}

/// Hash a single file using streaming BLAKE3 with a 64 KiB read buffer.
///
/// Preferred over [`hash_file`] for potentially large files (e.g., the scanner
/// binary, which can be hundreds of MB) because it never holds the entire file
/// in memory. The hasher is initialized with `domain || 0x00` before reading
/// any file bytes, providing BLAKE3 domain separation.
///
/// Produces the same hash as [`hash_file`] for the same file and domain —
/// the streaming reads are purely an optimization, not a different encoding.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be opened or read.
pub fn hash_file_streaming(path: &Path, domain: &[u8]) -> io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0x00]);

    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; HASH_BUF_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Hash a single file by reading it entirely into memory.
///
/// Simpler than [`hash_file_streaming`] but allocates the full file contents
/// on the heap. The hasher is initialized with `domain || 0x00`, then the
/// entire file content is fed in a single update. Use this for small files
/// (ruleset config, typically < 1 MB) where the allocation is negligible.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn hash_file(path: &Path, domain: &[u8]) -> io::Result<String> {
    let contents = std::fs::read(path)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0x00]);
    hasher.update(&contents);
    Ok(hasher.finalize().to_hex().to_string())
}

/// Build complete [`Provenance`] from filesystem paths.
///
/// This is the primary entry point for provenance construction. It hashes the
/// corpus directory (required) via [`hash_corpus`] with [`CORPUS_DOMAIN`],
/// and optionally hashes the scanner binary (via [`hash_file_streaming`]) and
/// ruleset file (via [`hash_file`]) when their paths are provided. Both
/// single-file hashes use [`FILE_DOMAIN`].
///
/// # Error propagation
///
/// Errors are fail-fast: if the corpus hash fails, the binary and ruleset are
/// not attempted. If the corpus succeeds but the binary hash fails, the
/// ruleset is not attempted. Each hash operation produces an `io::Error` on
/// failure (missing file, permission denied, etc.).
pub fn build_provenance(
    corpus_dir: &Path,
    binary_path: Option<&Path>,
    ruleset_path: Option<&Path>,
) -> io::Result<Provenance> {
    let (corpus_hash, corpus_file_count, corpus_total_bytes) = hash_corpus(corpus_dir)?;

    let binary_hash = binary_path
        .map(|p| hash_file_streaming(p, FILE_DOMAIN))
        .transpose()?;

    let ruleset_hash = ruleset_path
        .map(|p| hash_file(p, FILE_DOMAIN))
        .transpose()?;

    Ok(Provenance {
        corpus_hash,
        binary_hash,
        ruleset_hash,
        corpus_file_count,
        corpus_total_bytes,
    })
}

/// Recursively collect regular file paths under `dir` into `out`.
///
/// Symlinks and special files (sockets, FIFOs, device nodes) are intentionally
/// skipped. Symlinks are excluded because they can point outside the corpus
/// tree or create cycles, and their resolution depends on the host filesystem
/// layout — including them would break cross-machine reproducibility.
///
/// Traversal is fail-fast: any `read_dir` / `file_type` error aborts
/// immediately and is returned to the caller.
fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files_recursive(&entry.path(), out)?;
        } else if ft.is_file() {
            out.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a temp dir with files, return the TempDir handle.
    fn corpus(files: &[(&str, &[u8])]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (name, contents) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, contents).unwrap();
        }
        dir
    }

    #[test]
    fn add_file_changes_hash() {
        let dir = corpus(&[("a.txt", b"hello")]);
        let (h1, _, _) = hash_corpus(dir.path()).unwrap();

        fs::write(dir.path().join("b.txt"), b"extra").unwrap();
        let (h2, c2, _) = hash_corpus(dir.path()).unwrap();
        assert_ne!(h1, h2, "adding a file must change the hash");
        assert_eq!(c2, 2);
    }

    #[test]
    fn empty_directory() {
        let dir = TempDir::new().unwrap();
        let (h1, count, bytes) = hash_corpus(dir.path()).unwrap();
        let (h2, _, _) = hash_corpus(dir.path()).unwrap();
        assert_eq!(h1, h2, "empty dir must produce deterministic hash");
        assert_eq!(count, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn missing_ruleset_file_returns_error() {
        let result = hash_file(Path::new("/nonexistent/ruleset.yaml"), FILE_DOMAIN);
        assert!(result.is_err());
    }

    #[test]
    fn length_prefix_prevents_boundary_ambiguity() {
        // Different content distributions across files must produce distinct hashes.
        let dir_a = corpus(&[("a", b"XY"), ("b", b"Z")]);
        let dir_b = corpus(&[("a", b"X"), ("b", b"YZ")]);

        let (h_a, _, _) = hash_corpus(dir_a.path()).unwrap();
        let (h_b, _, _) = hash_corpus(dir_b.path()).unwrap();
        assert_ne!(
            h_a, h_b,
            "different record layouts must produce different corpus hashes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_bytes_are_preserved() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let raw = vec![b'f', 0x80, b'g'];
        let rel = std::path::PathBuf::from(OsString::from_vec(raw.clone()));
        assert_eq!(
            path_bytes(&rel),
            raw.as_slice(),
            "path hashing must use exact OS bytes without lossy conversion"
        );
    }

    #[test]
    fn build_provenance_none_binary() {
        let dir = corpus(&[("a.txt", b"data")]);
        let prov = build_provenance(dir.path(), None, None).unwrap();
        assert!(prov.binary_hash.is_none());
        assert!(prov.ruleset_hash.is_none());
        assert_eq!(prov.corpus_file_count, 1);
        assert_eq!(prov.corpus_total_bytes, 4);
    }

    #[test]
    fn build_provenance_with_binary_and_ruleset() {
        let dir = corpus(&[("a.txt", b"corpus data")]);

        // Place binary and ruleset outside the corpus dir so
        // corpus_file_count reflects only the corpus contents.
        let bin_dir = TempDir::new().unwrap();
        let bin_path = bin_dir.path().join("scanner.bin");
        fs::write(&bin_path, b"binary-content-bytes").unwrap();

        let rule_dir = TempDir::new().unwrap();
        let rule_path = rule_dir.path().join("rules.yaml");
        fs::write(&rule_path, b"ruleset-content-bytes").unwrap();

        let prov = build_provenance(dir.path(), Some(&bin_path), Some(&rule_path)).unwrap();
        assert!(prov.binary_hash.is_some(), "binary_hash must be present");
        assert!(prov.ruleset_hash.is_some(), "ruleset_hash must be present");
        // Binary and ruleset have different content, so hashes must differ.
        assert_ne!(
            prov.binary_hash.as_ref().unwrap(),
            prov.ruleset_hash.as_ref().unwrap(),
            "different content must produce different hashes"
        );
        assert_eq!(prov.corpus_file_count, 1);
        assert_eq!(prov.corpus_total_bytes, 11); // b"corpus data".len()
    }

    #[test]
    fn domain_separation_corpus_vs_file() {
        // Hashing the same single file via hash_corpus (CORPUS_DOMAIN) and
        // hash_file (FILE_DOMAIN) must produce different hashes.
        let dir = corpus(&[("only.txt", b"identical content")]);
        let file_path = dir.path().join("only.txt");

        let (corpus_h, _, _) = hash_corpus(dir.path()).unwrap();
        let file_h = hash_file(&file_path, FILE_DOMAIN).unwrap();
        assert_ne!(
            corpus_h, file_h,
            "corpus and file domains must produce different hashes"
        );
    }

    #[test]
    fn modify_content_changes_hash() {
        let dir = corpus(&[("a.txt", b"original")]);
        let (h1, _, _) = hash_corpus(dir.path()).unwrap();

        // Overwrite the file content.
        fs::write(dir.path().join("a.txt"), b"modified").unwrap();
        let (h2, _, _) = hash_corpus(dir.path()).unwrap();
        assert_ne!(h1, h2, "changing file content must change the hash");
    }

    // ── Proptest ─────────────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Repeated calls to hash_corpus on the same directory always
            /// produce identical results, regardless of file count or content.
            #[test]
            fn corpus_hash_deterministic(
                file_count in 0usize..8,
                seed in proptest::collection::vec(0u8..255, 1..32),
            ) {
                let dir = TempDir::new().unwrap();
                for i in 0..file_count {
                    let name = format!("file_{i}.txt");
                    let mut contents = seed.clone();
                    contents.push(i as u8);
                    std::fs::write(dir.path().join(name), &contents).unwrap();
                }
                let (h1, c1, b1) = hash_corpus(dir.path()).unwrap();
                let (h2, c2, b2) = hash_corpus(dir.path()).unwrap();
                prop_assert_eq!(&h1, &h2, "hash must be deterministic");
                prop_assert_eq!(c1, c2);
                prop_assert_eq!(b1, b2);
                prop_assert_eq!(c1, file_count as u64);
            }

            /// Streaming and in-memory file hashing produce identical results
            /// for the same file and domain.
            #[test]
            fn streaming_equals_in_memory(
                contents in proptest::collection::vec(any::<u8>(), 0..4096),
            ) {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("test_file.bin");
                std::fs::write(&path, &contents).unwrap();

                let h_stream = hash_file_streaming(&path, FILE_DOMAIN).unwrap();
                let h_mem = hash_file(&path, FILE_DOMAIN).unwrap();
                prop_assert_eq!(
                    h_stream, h_mem,
                    "streaming and in-memory hashes must match (len={})",
                    contents.len(),
                );
            }
        }
    }
}
