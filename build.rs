//! Build script for scanner-rs.
//!
//! Handles platform-specific dependency requirements:
//!
//! 1. **Boost headers for vectorscan-rs-sys**: vectorscan's cmake needs Boost >= 1.57.
//!    If not found on the system, this script downloads and extracts the headers
//!    to `target/boost` and sets `BOOST_ROOT` for the cmake build.
//!
//! 2. **Compiler detection**: Emits `cargo:warning` messages when the toolchain
//!    lacks SHA3 NEON support (needed by aegis's C backend). On such machines,
//!    build with `--features aegis-pure-rust`.
//!
//! # Environment variables respected
//!
//! - `BOOST_ROOT`: If already set, skip Boost download.
//! - `SCANNER_SKIP_BOOST_DOWNLOAD`: Set to `1` to skip Boost download even if missing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Minimum Boost version required by vectorscan (major * 100000 + minor * 100 + patch).
const BOOST_MIN_VERSION: u32 = 105700; // 1.57.0
const BOOST_DOWNLOAD_VERSION: &str = "1.57.0";
const BOOST_ARCHIVE_NAME: &str = "boost_1_57_0";

fn main() {
    // Re-run only if these change.
    println!("cargo:rerun-if-env-changed=BOOST_ROOT");
    println!("cargo:rerun-if-env-changed=SCANNER_SKIP_BOOST_DOWNLOAD");
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-env-changed=CC");

    handle_boost();
    detect_compiler_capabilities();
}

// ============================================================================
// Boost header management
// ============================================================================

/// Check system Boost version by parsing `boost/version.hpp`.
fn system_boost_version() -> Option<u32> {
    let candidates = [
        PathBuf::from("/usr/include/boost/version.hpp"),
        PathBuf::from("/usr/local/include/boost/version.hpp"),
    ];

    // Also check BOOST_ROOT if set.
    let env_root = std::env::var("BOOST_ROOT").ok().map(|r| {
        PathBuf::from(r)
            .join("include")
            .join("boost")
            .join("version.hpp")
    });

    for path in candidates.iter().chain(env_root.iter()) {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for line in contents.lines() {
                let line = line.trim();
                if line.starts_with("#define BOOST_VERSION ") && !line.contains("BOOST_VERSION_") {
                    let version_str = line.strip_prefix("#define BOOST_VERSION ").unwrap().trim();
                    if let Ok(v) = version_str.parse::<u32>() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

fn handle_boost() {
    // If BOOST_ROOT is already set, trust the user.
    if std::env::var("BOOST_ROOT").is_ok() {
        return;
    }

    // Check system Boost version.
    if let Some(version) = system_boost_version() {
        if version >= BOOST_MIN_VERSION {
            return; // System Boost is sufficient.
        }
        let major = version / 100_000;
        let minor = (version / 100) % 1000;
        let patch = version % 100;
        println!(
            "cargo:warning=System Boost {major}.{minor}.{patch} < required {BOOST_DOWNLOAD_VERSION}; \
             downloading headers..."
        );
    }

    if std::env::var("SCANNER_SKIP_BOOST_DOWNLOAD").as_deref() == Ok("1") {
        println!(
            "cargo:warning=SCANNER_SKIP_BOOST_DOWNLOAD=1; skipping Boost download. \
             vectorscan-rs-sys may fail to build."
        );
        return;
    }

    // Download Boost headers to target/boost.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let boost_dir = PathBuf::from(&out_dir)
        .ancestors()
        .nth(3) // OUT_DIR is target/{profile}/build/{pkg}-{hash}/out
        .expect("cannot find target dir")
        .join("boost");

    let boost_include = boost_dir.join("include");
    let version_hpp = boost_include.join("boost").join("version.hpp");

    if version_hpp.exists() {
        // Already downloaded in a previous build.
        println!("cargo:rustc-env=BOOST_ROOT={}", boost_dir.display());
        set_boost_root_for_deps(&boost_dir);
        return;
    }

    println!("cargo:warning=Downloading Boost {BOOST_DOWNLOAD_VERSION} headers...");

    let archive_path = boost_dir.join(format!("{BOOST_ARCHIVE_NAME}.tar.gz"));
    std::fs::create_dir_all(&boost_dir).expect("failed to create boost dir");

    let url = format!(
        "https://archives.boost.io/release/{BOOST_DOWNLOAD_VERSION}/source/{BOOST_ARCHIVE_NAME}.tar.gz"
    );

    // Download.
    let status = Command::new("curl")
        .args(["-sSL", &url, "-o"])
        .arg(&archive_path)
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            println!(
                "cargo:warning=Failed to download Boost headers from {url}. \
                 Set BOOST_ROOT manually or install Boost >= {BOOST_DOWNLOAD_VERSION}."
            );
            return;
        }
    }

    // Extract just the boost/ headers directory.
    std::fs::create_dir_all(&boost_include).expect("failed to create boost include dir");
    let status = Command::new("tar")
        .args([
            "xzf",
            archive_path.to_str().unwrap(),
            "--strip-components=1",
            "-C",
            boost_include.to_str().unwrap(),
            &format!("{BOOST_ARCHIVE_NAME}/boost"),
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!(
                "cargo:warning=Boost {BOOST_DOWNLOAD_VERSION} headers extracted to {}",
                boost_include.display()
            );
            // Clean up tarball.
            let _ = std::fs::remove_file(&archive_path);
        }
        _ => {
            println!("cargo:warning=Failed to extract Boost headers.");
            return;
        }
    }

    set_boost_root_for_deps(&boost_dir);
}

fn set_boost_root_for_deps(boost_dir: &Path) {
    // Set BOOST_ROOT for cmake (used by vectorscan-rs-sys build script).
    // NOTE: cargo:rustc-env only affects OUR crate's compilation env,
    // not dependency build scripts. We print instructions instead.
    println!(
        "cargo:warning=Set BOOST_ROOT={} in .cargo/config.toml or shell environment \
         for vectorscan-rs-sys.",
        boost_dir.display()
    );
}

// ============================================================================
// Compiler capability detection
// ============================================================================

fn detect_compiler_capabilities() {
    // Check if we're on aarch64 and whether the C compiler supports SHA3 NEON.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64") {
        return;
    }

    // Try to compile a small test file with veor3q_u8.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let test_src = PathBuf::from(&out_dir).join("sha3_check.c");
    let test_obj = PathBuf::from(&out_dir).join("sha3_check.o");

    let test_code = r#"
#include <arm_neon.h>
uint8x16_t test(uint8x16_t a, uint8x16_t b, uint8x16_t c) {
    return veor3q_u8(a, b, c);
}
"#;

    std::fs::write(&test_src, test_code).expect("failed to write SHA3 test file");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let result = Command::new(&cc)
        .args([
            "-c",
            "-march=armv8.2-a+sha3",
            "-o",
            test_obj.to_str().unwrap(),
            test_src.to_str().unwrap(),
        ])
        .output();

    let has_sha3 = matches!(result, Ok(output) if output.status.success());

    if !has_sha3 {
        println!(
            "cargo:warning=C compiler ({cc}) does not support SHA3 NEON intrinsics (veor3q_u8). \
             The aegis crate will fail to build its C backend."
        );
        println!(
            "cargo:warning=Fix: build with `PATH=\"$PWD/tools/cc-shim:$PATH\" cargo build` \
             (requires gcc10: `yum install gcc10`). See .cargo/config.toml for details."
        );
    }

    // Clean up.
    let _ = std::fs::remove_file(&test_src);
    let _ = std::fs::remove_file(&test_obj);
}
