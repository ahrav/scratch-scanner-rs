#![allow(dead_code, unused_imports, unused_variables)]

use scanner_rs::pipeline::scan_path_default;
use scanner_rs::{demo_engine_with_anchor_mode, AnchorMode, AsyncIoConfig};
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

enum IoBackend {
    /// Choose the platform async backend (no sync fallback).
    Auto,
    /// Force synchronous IO.
    Sync,
    /// Force Linux io_uring.
    Uring,
    /// Force macOS POSIX AIO.
    Dispatch,
}

impl IoBackend {
    fn default_for_platform() -> Self {
        IoBackend::Auto
    }
}

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "scanner-rs".into());
    let mut anchor_mode = AnchorMode::Manual;
    let mut path: Option<PathBuf> = None;
    let mut io_backend = IoBackend::default_for_platform();

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
                "--io=sync" => {
                    io_backend = IoBackend::Sync;
                    continue;
                }
                "--io=auto" => {
                    io_backend = IoBackend::Auto;
                    continue;
                }
                "--io=uring" => {
                    io_backend = IoBackend::Uring;
                    continue;
                }
                "--io=dispatch" | "--io=aio" => {
                    io_backend = IoBackend::Dispatch;
                    continue;
                }
                "--help" | "-h" => {
                    eprintln!(
                        "usage: {} [--anchors=manual|derived] [--io=auto|sync|uring|aio|dispatch] <path>",
                        exe.to_string_lossy()
                    );
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    eprintln!(
                        "usage: {} [--anchors=manual|derived] [--io=auto|sync|uring|aio|dispatch] <path>",
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
            "usage: {} [--anchors=manual|derived] [--io=auto|sync|uring|aio|dispatch] <path>",
            exe.to_string_lossy()
        );
        std::process::exit(2);
    };

    let engine = Arc::new(demo_engine_with_anchor_mode(anchor_mode));
    let start = Instant::now();
    let stats = match io_backend {
        IoBackend::Sync => scan_path_default(&path, Arc::clone(&engine))?,
        IoBackend::Auto => {
            #[cfg(target_os = "linux")]
            {
                match scanner_rs::UringScanner::new(Arc::clone(&engine), AsyncIoConfig::default()) {
                    Ok(mut scanner) => scanner.scan_path(&path)?,
                    Err(err) => {
                        eprintln!("io_uring unavailable ({}); use --io=sync to override", err);
                        std::process::exit(2);
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                match scanner_rs::DispatchScanner::new(
                    Arc::clone(&engine),
                    AsyncIoConfig::default(),
                ) {
                    Ok(mut scanner) => scanner.scan_path(&path)?,
                    Err(err) => {
                        eprintln!("POSIX AIO unavailable ({}); use --io=sync to override", err);
                        std::process::exit(2);
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                eprintln!("async IO not supported on this platform; use --io=sync to override");
                std::process::exit(2);
            }
        }
        IoBackend::Uring => {
            #[cfg(target_os = "linux")]
            {
                let mut scanner =
                    scanner_rs::UringScanner::new(Arc::clone(&engine), AsyncIoConfig::default())?;
                scanner.scan_path(&path)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                eprintln!("--io=uring is only supported on Linux");
                std::process::exit(2);
            }
        }
        IoBackend::Dispatch => {
            #[cfg(target_os = "macos")]
            {
                let mut scanner = scanner_rs::DispatchScanner::new(
                    Arc::clone(&engine),
                    AsyncIoConfig::default(),
                )?;
                scanner.scan_path(&path)?
            }
            #[cfg(not(target_os = "macos"))]
            {
                eprintln!("--io=aio/--io=dispatch is only supported on macOS");
                std::process::exit(2);
            }
        }
    };
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

    #[cfg(feature = "b64-stats")]
    {
        let b64 = stats.base64;
        let decoded_wasted = b64
            .decoded_bytes_wasted_no_anchor
            .saturating_add(b64.decoded_bytes_wasted_error);
        let decoded_wasted_pct_of_decoded = if b64.decoded_bytes_total > 0 {
            (decoded_wasted as f64) * 100.0 / (b64.decoded_bytes_total as f64)
        } else {
            0.0
        };
        let pre_gate_total_encoded = b64
            .pre_gate_skip_bytes
            .saturating_add(b64.decode_attempt_bytes);
        let pre_gate_skip_pct_of_total_encoded = if pre_gate_total_encoded > 0 {
            (b64.pre_gate_skip_bytes as f64) * 100.0 / (pre_gate_total_encoded as f64)
        } else {
            0.0
        };

        eprintln!(
            "b64 spans={} span_bytes={} decode_attempts={} decode_attempt_bytes={} decode_errors={}",
            b64.spans,
            b64.span_bytes,
            b64.decode_attempts,
            b64.decode_attempt_bytes,
            b64.decode_errors
        );
        eprintln!(
            "b64 decoded_total={} decoded_kept={} decoded_wasted_no_anchor={} decoded_wasted_error={} decoded_wasted_pct_of_decoded={:.2}",
            b64.decoded_bytes_total,
            b64.decoded_bytes_kept,
            b64.decoded_bytes_wasted_no_anchor,
            b64.decoded_bytes_wasted_error,
            decoded_wasted_pct_of_decoded
        );
        eprintln!(
            "b64 pre_gate_checks={} pre_gate_pass={} pre_gate_skip={} pre_gate_skip_bytes={} pre_gate_skip_pct_of_total_encoded={:.2}",
            b64.pre_gate_checks,
            b64.pre_gate_pass,
            b64.pre_gate_skip,
            b64.pre_gate_skip_bytes,
            pre_gate_skip_pct_of_total_encoded
        );
    }

    Ok(())
}
