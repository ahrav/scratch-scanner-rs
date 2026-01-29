#[cfg(not(feature = "bench"))]
fn main() {
    eprintln!("perf_hotspots requires --features bench");
}

#[cfg(feature = "bench")]
fn main() {
    use scanner_rs::{bench_find_spans_into, Gate, TransformConfig, TransformId, TransformMode};
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

    fn run_for(label: &str, duration: Duration, mut f: impl FnMut()) {
        let start = Instant::now();
        let mut iters = 0u64;
        while start.elapsed() < duration {
            f();
            iters += 1;
        }
        eprintln!("{label}: iters={iters}");
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
        }
        _ => {
            eprintln!(
                "usage: perf_hotspots [url_random|url_urlish|b64_random|b64_noise|all] [seconds]"
            );
        }
    }
}
