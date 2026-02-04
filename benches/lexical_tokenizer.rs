//! Lexical tokenizer throughput microbench.
//!
//! Measures the candidate-only lexical tokenizer performance across supported
//! language families using a deterministic, code-like buffer. The input mixes
//! code, comment, and string segments while keeping run counts low enough to
//! avoid run-cap overflow in steady state.
//!
//! Run with:
//! `cargo bench --bench lexical_tokenizer --features bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_rs::{LexRuns, LexicalFamily, LexicalTokenizer, DEFAULT_LEX_RUN_CAP};

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB
const PAD_SIZE: usize = 4096; // Keeps run counts under the default cap.

fn append_repeat(buf: &mut Vec<u8>, byte: u8, len: usize) {
    buf.extend(std::iter::repeat_n(byte, len));
}

fn build_clike_block() -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAD_SIZE * 3 + 128);
    buf.extend_from_slice(b"int main() { int a = 0; }\n");
    append_repeat(&mut buf, b'a', PAD_SIZE);
    buf.extend_from_slice(b"\n//");
    append_repeat(&mut buf, b'b', PAD_SIZE);
    buf.extend_from_slice(b"\nconst char* s = \"");
    append_repeat(&mut buf, b'c', PAD_SIZE);
    buf.extend_from_slice(b"\";\n");
    buf
}

fn build_python_block() -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAD_SIZE * 3 + 128);
    buf.extend_from_slice(b"def load_token():\n    value = \"");
    append_repeat(&mut buf, b'a', PAD_SIZE);
    buf.extend_from_slice(b"\"\n");
    buf.extend_from_slice(b"#");
    append_repeat(&mut buf, b'b', PAD_SIZE);
    buf.extend_from_slice(b"\nreturn value\n");
    append_repeat(&mut buf, b'c', PAD_SIZE);
    buf
}

fn build_shell_block() -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAD_SIZE * 3 + 128);
    buf.extend_from_slice(b"export TOKEN=\"");
    append_repeat(&mut buf, b'a', PAD_SIZE);
    buf.extend_from_slice(b"\"\n");
    buf.extend_from_slice(b"#");
    append_repeat(&mut buf, b'b', PAD_SIZE);
    buf.extend_from_slice(b"\necho \"$TOKEN\"\n");
    append_repeat(&mut buf, b'c', PAD_SIZE);
    buf
}

fn build_config_block() -> Vec<u8> {
    let mut buf = Vec::with_capacity(PAD_SIZE * 3 + 128);
    buf.extend_from_slice(b"#");
    append_repeat(&mut buf, b'a', PAD_SIZE);
    buf.extend_from_slice(b"\nkey = \"");
    append_repeat(&mut buf, b'b', PAD_SIZE);
    buf.extend_from_slice(b"\"\n;");
    append_repeat(&mut buf, b'c', PAD_SIZE);
    buf.extend_from_slice(b"\npath=/tmp\n");
    buf
}

fn build_buffer(family: LexicalFamily) -> Vec<u8> {
    let block = match family {
        LexicalFamily::CLike => build_clike_block(),
        LexicalFamily::PythonLike => build_python_block(),
        LexicalFamily::ShellLike => build_shell_block(),
        LexicalFamily::Config => build_config_block(),
    };
    let mut data = Vec::with_capacity(BUFFER_SIZE);
    while data.len() < BUFFER_SIZE {
        data.extend_from_slice(&block);
    }
    data.truncate(BUFFER_SIZE);
    data
}

fn tokenize_buffer(tokenizer: &mut LexicalTokenizer, runs: &mut LexRuns, data: &[u8]) {
    let mut offset = 0u64;
    for chunk in data.chunks(CHUNK_SIZE) {
        let chunk = black_box(chunk);
        tokenizer.process_chunk(chunk, offset, runs);
        offset += chunk.len() as u64;
    }
    tokenizer.finish(offset, runs);
    black_box(runs.as_slice());
    black_box(runs.is_overflowed());
}

fn bench_lexical_tokenizer(c: &mut Criterion) {
    let families = [
        (LexicalFamily::CLike, "clike"),
        (LexicalFamily::PythonLike, "python"),
        (LexicalFamily::ShellLike, "shell"),
        (LexicalFamily::Config, "config"),
    ];

    let mut group = c.benchmark_group("lexical_tokenizer");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    for (family, label) in families {
        let data = build_buffer(family);
        group.bench_function(BenchmarkId::new("tokenize", label), |b| {
            let mut tokenizer = LexicalTokenizer::new(family);
            let mut runs = LexRuns::with_capacity(DEFAULT_LEX_RUN_CAP).unwrap();
            b.iter(|| {
                tokenizer.reset();
                runs.clear();
                tokenize_buffer(&mut tokenizer, &mut runs, black_box(&data));
            });
        });
    }

    group.finish();
}

criterion_group!(lexical_benches, bench_lexical_tokenizer);
criterion_main!(lexical_benches);
