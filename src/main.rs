#![allow(dead_code, unused_imports, unused_variables)]

use scanner_rs::pipeline::scan_path_default;
use scanner_rs::{demo_engine_with_anchor_mode, AnchorMode};
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "scanner-rs".into());
    let mut anchor_mode = AnchorMode::Manual;
    let mut path: Option<PathBuf> = None;

    for arg in args {
        if let Some(flag) = arg.to_str() {
            match flag {
                "--anchors=manual" => {
                    anchor_mode = AnchorMode::Manual;
                    continue;
                }
                "--anchors=derived" | "--derive-anchors" => {
                    anchor_mode = AnchorMode::Derived;
                    continue;
                }
                "--help" | "-h" => {
                    eprintln!(
                        "usage: {} [--anchors=manual|derived] <path>",
                        exe.to_string_lossy()
                    );
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    eprintln!(
                        "usage: {} [--anchors=manual|derived] <path>",
                        exe.to_string_lossy()
                    );
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        if path.is_some() {
            eprintln!(
                "usage: {} [--anchors=manual|derived] <path>",
                exe.to_string_lossy()
            );
            std::process::exit(2);
        }
        path = Some(PathBuf::from(arg));
    }

    let Some(path) = path else {
        eprintln!(
            "usage: {} [--anchors=manual|derived] <path>",
            exe.to_string_lossy()
        );
        std::process::exit(2);
    };

    let engine = Arc::new(demo_engine_with_anchor_mode(anchor_mode));
    let start = Instant::now();
    let stats = scan_path_default(&path, engine)?;
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let throughput_mib = if elapsed_secs > 0.0 {
        (stats.bytes_scanned as f64 / (1024.0 * 1024.0)) / elapsed_secs
    } else {
        0.0
    };

    eprintln!(
        "files={} chunks={} bytes={} findings={} errors={} elapsed_ms={} throughput_mib_s={:.2}",
        stats.files,
        stats.chunks,
        stats.bytes_scanned,
        stats.findings,
        stats.errors,
        elapsed.as_millis(),
        throughput_mib
    );

    Ok(())
}
