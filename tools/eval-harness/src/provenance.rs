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
//! All hashes use BLAKE3 with domain separation: a domain tag is fed to the
//! hasher before any payload bytes. This prevents cross-context collisions
//! (e.g., a corpus that happens to byte-match a binary will still produce
//! different hashes) and follows the same pattern used elsewhere in the
//! codebase for content-addressable storage.
//!
//! # Algorithm (corpus hash)
//!
//! 1. Recursively collect file paths under `corpus_dir` into a `Vec<PathBuf>`.
//!    Symlinks and non-regular files are skipped to keep the hash stable
//!    across environments with different link layouts.
//! 2. Sort paths lexicographically by their full path bytes. Since all paths
//!    share the same `corpus_dir` prefix, this produces the same order as
//!    sorting by relative path, ensuring deterministic ordering regardless of
//!    filesystem visit order.
//! 3. Feed a single BLAKE3 hasher: for each file, update with
//!    `relative_path_bytes || 0x00 || file_contents`. The NUL byte acts as
//!    an unambiguous delimiter because NUL cannot appear in POSIX paths and
//!    is vanishingly rare in practice on other platforms.
//! 4. An empty directory produces a hash over just the domain tag and its NUL
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
//!   Only the scanner binary is hashed via streaming reads
//!   ([`hash_file_streaming`]); individual corpus files are read entirely into
//!   memory via `std::fs::read` because they are typically small text fixtures
//!   and the simpler code path avoids per-file `File::open` + read-loop
//!   overhead.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Domain separation tags prevent hash collisions across different input types.
///
/// Each tag is a unique byte string prepended to the hasher before payload
/// bytes. The `eval.provenance.v1.` prefix scopes them to this module; the
/// suffix distinguishes corpus-level hashing from single-file hashing.
const CORPUS_DOMAIN: &[u8] = b"eval.provenance.v1.corpus";
const FILE_DOMAIN: &[u8] = b"eval.provenance.v1.file";

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
/// All hashes are hex-encoded BLAKE3 (64 hex chars = 32 bytes). `None` hash
/// fields are omitted from serialized JSON via `skip_serializing_if`, keeping
/// the output clean when optional inputs were not provided.
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
/// The hash is deterministic for a given directory tree: files are visited in
/// lexicographic order of their relative path bytes. Each file contributes
/// `relative_path_bytes || 0x00 || file_contents` to the hasher, so path
/// and content boundaries are unambiguous.
///
/// # Edge cases
///
/// - **Empty directory**: produces a hash over just the domain tag and its NUL
///   separator, with `file_count = 0` and `total_bytes = 0`.
/// - **Unreadable files**: returns an `io::Error` at the first file that
///   cannot be read. The hash is not partially computed — it is all or nothing.
/// - **Non-UTF-8 paths**: handled via `to_string_lossy`; replacement
///   characters are hashed as-is, so two paths differing only in invalid
///   sequences could theoretically collide. This is acceptable because corpus
///   paths are expected to be valid UTF-8 in practice.
pub fn hash_corpus(corpus_dir: &Path) -> io::Result<(String, u64, u64)> {
    let mut files = Vec::with_capacity(1024);
    collect_files_recursive(corpus_dir, &mut files)?;
    files.sort_unstable();

    let mut hasher = blake3::Hasher::new();
    hasher.update(CORPUS_DOMAIN);
    hasher.update(&[0x00]);

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    for path in &files {
        let rel = path
            .strip_prefix(corpus_dir)
            .unwrap_or(path)
            .to_string_lossy();
        let contents = std::fs::read(path)?;

        hasher.update(rel.as_bytes());
        hasher.update(&[0x00]); // NUL delimiter between path and content.
        hasher.update(&contents);

        file_count += 1;
        total_bytes += contents.len() as u64;
    }

    Ok((
        hasher.finalize().to_hex().to_string(),
        file_count,
        total_bytes,
    ))
}

/// Hash a single file using streaming BLAKE3 with a 64 KiB read buffer.
///
/// Preferred over [`hash_file`] for potentially large files (e.g., the scanner
/// binary, which can be hundreds of MB) because it never holds the entire file
/// in memory. The `domain` parameter provides BLAKE3 domain separation.
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
/// on the heap. Use this for small files (ruleset config, typically < 1 MB)
/// where the allocation is negligible.
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
/// corpus directory (required), and optionally hashes the scanner binary and
/// ruleset file when their paths are provided.
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
    fn build_provenance_none_binary() {
        let dir = corpus(&[("a.txt", b"data")]);
        let prov = build_provenance(dir.path(), None, None).unwrap();
        assert!(prov.binary_hash.is_none());
        assert!(prov.ruleset_hash.is_none());
        assert_eq!(prov.corpus_file_count, 1);
        assert_eq!(prov.corpus_total_bytes, 4);
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
