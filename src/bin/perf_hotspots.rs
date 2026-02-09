#[cfg(not(feature = "bench"))]
fn main() {
    eprintln!("perf_hotspots requires --features bench");
}

#[cfg(feature = "bench")]
fn main() {
    use scanner_rs::{
        bench_contains_any_memmem, bench_find_spans_into, bench_pack_patterns_raw, Gate,
        TransformConfig, TransformId, TransformMode,
    };
    use std::env;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    const BUF_LEN: usize = 4 * 1024 * 1024; // 4 MiB

    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }

        fn fill_bytes(&mut self, buf: &mut [u8]) {
            let mut i = 0;
            while i < buf.len() {
                let mut v = self.next_u64();
                let take = (buf.len() - i).min(8);
                for j in 0..take {
                    buf[i + j] = (v & 0xff) as u8;
                    v >>= 8;
                }
                i += take;
            }
        }

        fn fill_base64(&mut self, buf: &mut [u8]) {
            const ALPH: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for b in buf.iter_mut() {
                let v = (self.next_u64() & 0x3f) as usize;
                *b = ALPH[v];
            }
        }
    }

    fn make_random(len: usize, seed: u64) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut rng = XorShift64::new(seed);
        rng.fill_bytes(&mut buf);
        buf
    }

    fn make_base64(len: usize, seed: u64) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut rng = XorShift64::new(seed);
        rng.fill_base64(&mut buf);
        buf
    }

    fn make_urlish(len: usize) -> Vec<u8> {
        let mut buf = vec![b'a'; len];
        let stride = 64;
        let max = len.saturating_sub(3);
        let mut i = 0usize;
        while i < max {
            buf[i] = b'%';
            buf[i + 1] = b'2';
            buf[i + 2] = b'F';
            i = i.saturating_add(stride);
        }
        buf
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }

    fn url_encode_all_bytes(bytes: &[u8]) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = Vec::with_capacity(bytes.len().saturating_mul(3));
        for &b in bytes {
            out.push(b'%');
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
        out
    }

    fn url_percent_decode(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0usize;
        while i < input.len() {
            if input[i] == b'%' && i + 2 < input.len() {
                if let (Some(hi), Some(lo)) = (hex_nibble(input[i + 1]), hex_nibble(input[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
            }
            out.push(input[i]);
            i += 1;
        }
        out
    }

    fn run_for_iters(duration: Duration, mut f: impl FnMut()) -> u64 {
        let start = Instant::now();
        let mut iters = 0u64;
        while start.elapsed() < duration {
            f();
            iters += 1;
        }
        iters
    }

    fn url_config(max_spans: usize) -> TransformConfig {
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: max_spans,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }
    }

    fn b64_config(max_spans: usize) -> TransformConfig {
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 32,
            max_spans_per_buffer: max_spans,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }
    }

    fn run_for(label: &str, duration: Duration, f: impl FnMut()) {
        let iters = run_for_iters(duration, f);
        eprintln!("{label}: iters={iters}");
    }

    fn run_compare(label: &str, duration: Duration, baseline: impl FnMut(), gated: impl FnMut()) {
        let base_iters = run_for_iters(duration, baseline);
        let gate_iters = run_for_iters(duration, gated);
        let delta = if base_iters == 0 {
            0.0
        } else {
            ((base_iters as f64 - gate_iters as f64) * 100.0) / (base_iters as f64)
        };
        eprintln!(
            "{label}: baseline_iters={base_iters} gate_iters={gate_iters} gate_slowdown_pct={delta:.2}"
        );
    }

    #[cfg(feature = "stats")]
    fn run_stream_stats(label: &str, buf: &[u8]) {
        let engine = scanner_rs::demo_engine();
        let mut scratch = engine.new_scratch();
        let _ = engine.scan_chunk_records(buf, scanner_rs::FileId(0), 0, &mut scratch);
        let stats = engine.vectorscan_stats();
        eprintln!(
            "{label}: stream_force_full={} stream_window_cap_exceeded={}",
            stats.stream_force_full, stats.stream_window_cap_exceeded
        );
    }

    #[cfg(not(feature = "stats"))]
    fn run_stream_stats(label: &str, _buf: &[u8]) {
        eprintln!("{label}: enable --features stats to report stream telemetry");
    }

    let mut args = env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "all".to_string());
    let secs = args
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(3.0);
    let duration = Duration::from_secs_f64(secs);

    let url_cfg_random = url_config(8);
    let url_cfg_full = url_config(4096);
    let b64_cfg_random = b64_config(8);
    let b64_cfg_full = b64_config(4096);

    let random = make_random(BUF_LEN, 0x1234_5678_9abc_def0);
    let urlish = make_urlish(BUF_LEN);
    let base64_noise = make_base64(BUF_LEN, 0x0f0e_0d0c_0b0a_0908);
    let mut spans = Vec::with_capacity(4096);

    let value_suppressors: [&[u8]; 8] = [
        b"ALPHA", b"BRAVO", b"CHARLIE", b"DELTA", b"ECHO", b"FOXTROT", b"GOLF", b"HOTEL",
    ];
    let empty_suppressors: [&[u8]; 0] = [];
    // Compile packed literals once so timed loops measure only gate checks.
    let suppressor_gate = bench_pack_patterns_raw(&value_suppressors);
    let baseline_gate = bench_pack_patterns_raw(&empty_suppressors);

    let secret_nohit_raw = [b'Q'; 32];

    let mut secret_hit_early_raw = [b'X'; 32];
    secret_hit_early_raw[..value_suppressors[0].len()].copy_from_slice(value_suppressors[0]);

    let mut secret_hit_late_raw = [b'Y'; 32];
    let last = value_suppressors[value_suppressors.len() - 1];
    let late_start = secret_hit_late_raw.len() - last.len();
    secret_hit_late_raw[late_start..].copy_from_slice(last);

    // Pre-decode transform-like inputs once to avoid allocating in timed loops.
    let secret_nohit_decoded = url_percent_decode(&url_encode_all_bytes(&secret_nohit_raw));
    let secret_hit_early_decoded = url_percent_decode(&url_encode_all_bytes(&secret_hit_early_raw));
    let secret_hit_late_decoded = url_percent_decode(&url_encode_all_bytes(&secret_hit_late_raw));

    debug_assert_eq!(secret_nohit_decoded.len(), 32);
    debug_assert_eq!(secret_hit_early_decoded.len(), 32);
    debug_assert_eq!(secret_hit_late_decoded.len(), 32);

    match mode.as_str() {
        "url_random" => run_for("url_random", duration, || {
            bench_find_spans_into(&url_cfg_random, black_box(&random), &mut spans);
            black_box(spans.len());
        }),
        "url_urlish" => run_for("url_urlish", duration, || {
            bench_find_spans_into(&url_cfg_full, black_box(&urlish), &mut spans);
            black_box(spans.len());
        }),
        "b64_random" => run_for("b64_random", duration, || {
            bench_find_spans_into(&b64_cfg_random, black_box(&random), &mut spans);
            black_box(spans.len());
        }),
        "b64_noise" => run_for("b64_noise", duration, || {
            bench_find_spans_into(&b64_cfg_full, black_box(&base64_noise), &mut spans);
            black_box(spans.len());
        }),
        "value_suppress_nohit_small" => {
            run_compare(
                "value_suppress_nohit_small_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_nohit_small_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
        }
        "value_suppress_hit_early" => {
            run_compare(
                "value_suppress_hit_early_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_early_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
        }
        "value_suppress_hit_late" => {
            run_compare(
                "value_suppress_hit_late_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_late_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
        }
        "stream_stats" => {
            run_stream_stats("stream_stats", &base64_noise);
        }
        "all" => {
            run_for("url_random", duration, || {
                bench_find_spans_into(&url_cfg_random, black_box(&random), &mut spans);
                black_box(spans.len());
            });
            run_for("url_urlish", duration, || {
                bench_find_spans_into(&url_cfg_full, black_box(&urlish), &mut spans);
                black_box(spans.len());
            });
            run_for("b64_random", duration, || {
                bench_find_spans_into(&b64_cfg_random, black_box(&random), &mut spans);
                black_box(spans.len());
            });
            run_for("b64_noise", duration, || {
                bench_find_spans_into(&b64_cfg_full, black_box(&base64_noise), &mut spans);
                black_box(spans.len());
            });
            run_compare(
                "value_suppress_nohit_small_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_nohit_small_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_nohit_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_early_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_early_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_early_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_late_raw",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_raw),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_raw),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_compare(
                "value_suppress_hit_late_decoded",
                duration,
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_decoded),
                        black_box(&baseline_gate),
                    ));
                },
                || {
                    black_box(bench_contains_any_memmem(
                        black_box(&secret_hit_late_decoded),
                        black_box(&suppressor_gate),
                    ));
                },
            );
            run_stream_stats("stream_stats", &base64_noise);
        }
        _ => {
            eprintln!(
                "usage: perf_hotspots [url_random|url_urlish|b64_random|b64_noise|value_suppress_nohit_small|value_suppress_hit_early|value_suppress_hit_late|stream_stats|all] [seconds]"
            );
        }
    }
}
