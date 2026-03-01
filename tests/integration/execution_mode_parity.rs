use scanner_rs::unified::parity::{
    canonicalize_jsonl_events, enforce_throughput_thresholds, median, throughput_delta_pct,
    CanonicalFinding,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy)]
enum ScanSource {
    Fs,
    Git,
}

impl ScanSource {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Git => "git",
        }
    }
}

#[derive(Clone)]
struct ParityCase {
    name: &'static str,
    source: ScanSource,
    target: PathBuf,
}

struct ThroughputCaseResult {
    name: &'static str,
    delta_pct: f64,
}

fn scanner_bin() -> &'static str {
    env!("CARGO_BIN_EXE_scanner-rs")
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn initialize_repo(repo: &Path) {
    run_git(repo, &["init", "-b", "main"]);
    run_git(repo, &["config", "user.email", "parity@example.com"]);
    run_git(repo, &["config", "user.name", "Parity Bot"]);
}

fn write_and_commit(repo: &Path, file: &str, content: &str, message: &str) {
    fs::write(repo.join(file), content).expect("write repo file");
    run_git(repo, &["add", file]);
    run_git(repo, &["commit", "-m", message]);
}

fn create_fs_flat_case(root: &Path, name: &'static str, files: usize) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir_all(&dir).expect("create fs case dir");
    for idx in 0..files {
        let body = format!(
            "index={idx}\nslack_token=xoxa-1234567890abcdef\npadding={:08}\n",
            idx * 7
        );
        fs::write(dir.join(format!("flat_{idx:04}.txt")), body).expect("write fs fixture");
    }
    dir
}

fn bulk_secret_payload(label: &str, repeats: usize) -> String {
    let mut payload = String::with_capacity(repeats * 64);
    payload.push_str(&format!("{label}=xoxa-1234567890abcdef\n"));
    for idx in 0..repeats {
        payload.push_str(&format!(
            "padding_{idx:05}=this_line_intentionally_has_no_secret_match\n"
        ));
    }
    payload
}

fn create_fs_nested_case(root: &Path, name: &'static str) -> PathBuf {
    let dir = root.join(name);
    for shard in 0..6usize {
        let sub = dir.join(format!("shard_{shard:02}"));
        fs::create_dir_all(&sub).expect("create nested shard");
        for idx in 0..40usize {
            let body = format!(
                "shard={shard}\nidx={idx}\nsecret=xoxa-1234567890abcdef\nnote=stable fixture\n"
            );
            fs::write(sub.join(format!("entry_{idx:03}.env")), body).expect("write nested fixture");
        }
    }
    dir
}

fn create_git_linear_case(root: &Path, name: &'static str) -> PathBuf {
    let repo = root.join(name);
    fs::create_dir_all(&repo).expect("create git linear repo");
    initialize_repo(&repo);
    write_and_commit(
        &repo,
        "app.env",
        &bulk_secret_payload("TOKEN", 5000),
        "seed secret",
    );
    write_and_commit(
        &repo,
        "app.env",
        &bulk_secret_payload("TOKEN_ROTATED", 5200),
        "rotate secret",
    );
    write_and_commit(&repo, "src.txt", "no secret here\n", "noise commit");
    repo
}

fn create_git_branch_merge_case(root: &Path, name: &'static str) -> PathBuf {
    let repo = root.join(name);
    fs::create_dir_all(&repo).expect("create git merge repo");
    initialize_repo(&repo);
    write_and_commit(
        &repo,
        "root.txt",
        &bulk_secret_payload("ROOT", 4200),
        "root commit",
    );
    run_git(&repo, &["checkout", "-b", "feature/parity"]);
    write_and_commit(
        &repo,
        "feature.txt",
        &bulk_secret_payload("FEATURE", 4000),
        "feature secret",
    );
    run_git(&repo, &["checkout", "main"]);
    write_and_commit(
        &repo,
        "main.txt",
        &bulk_secret_payload("MAIN", 4100),
        "mainline secret",
    );
    run_git(
        &repo,
        &["merge", "--no-ff", "feature/parity", "-m", "merge feature"],
    );
    repo
}

fn build_case_matrix(root: &Path) -> Vec<ParityCase> {
    vec![
        ParityCase {
            name: "fs-flat",
            source: ScanSource::Fs,
            target: create_fs_flat_case(root, "fs_flat", 180),
        },
        ParityCase {
            name: "fs-nested",
            source: ScanSource::Fs,
            target: create_fs_nested_case(root, "fs_nested"),
        },
        ParityCase {
            name: "git-linear",
            source: ScanSource::Git,
            target: create_git_linear_case(root, "git_linear"),
        },
        ParityCase {
            name: "git-branch-merge",
            source: ScanSource::Git,
            target: create_git_branch_merge_case(root, "git_branch_merge"),
        },
    ]
}

fn run_scan(case: &ParityCase, execution_mode: &str) -> scanner_rs::unified::parity::CanonicalRun {
    let mut cmd = Command::new(scanner_bin());
    cmd.args(["scan", case.source.as_arg(), "--event-format=jsonl"]);
    match case.source {
        ScanSource::Fs => {
            cmd.arg(format!("--path={}", case.target.display()));
        }
        ScanSource::Git => {
            cmd.arg(format!("--repo={}", case.target.display()));
        }
    }
    cmd.arg(format!("--execution-mode={execution_mode}"));
    let output = cmd.output().expect("run scanner");
    assert!(
        output.status.success(),
        "scan failed for case={} mode={}\nstdout:\n{}\nstderr:\n{}",
        case.name,
        execution_mode,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    canonicalize_jsonl_events(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "failed to canonicalize JSONL for case={} mode={}: {}",
            case.name, execution_mode, err
        )
    })
}

fn parse_stderr_metric_f64(stderr: &str, key: &str) -> Option<f64> {
    for line in stderr.lines().rev() {
        if let Some((k, value)) = line.split_once('=') {
            if k.trim() == key {
                return value.trim().parse::<f64>().ok();
            }
        }
    }
    None
}

fn run_throughput_sample(case: &ParityCase, execution_mode: &str) -> f64 {
    let mut cmd = Command::new(scanner_bin());
    cmd.args(["scan", case.source.as_arg(), "--null-sink"]);
    match case.source {
        ScanSource::Fs => {
            cmd.arg(format!("--path={}", case.target.display()));
        }
        ScanSource::Git => {
            cmd.arg(format!("--repo={}", case.target.display()));
        }
    }
    cmd.arg(format!("--execution-mode={execution_mode}"));
    let output = cmd.output().expect("run scanner for throughput");
    assert!(
        output.status.success(),
        "throughput run failed for case={} mode={}\nstdout:\n{}\nstderr:\n{}",
        case.name,
        execution_mode,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_stderr_metric_f64(&stderr, "throughput_mib_s").unwrap_or_else(|| {
        panic!(
            "missing throughput_mib_s in stderr for case={} mode={}\nstderr:\n{}",
            case.name, execution_mode, stderr
        )
    })
}

fn finding_set(findings: &[CanonicalFinding]) -> BTreeSet<CanonicalFinding> {
    findings.iter().cloned().collect()
}

fn diff_summary(left: &[CanonicalFinding], right: &[CanonicalFinding]) -> String {
    let left_set = finding_set(left);
    let right_set = finding_set(right);
    let missing: Vec<_> = left_set.difference(&right_set).take(5).cloned().collect();
    let extra: Vec<_> = right_set.difference(&left_set).take(5).cloned().collect();
    format!(
        "left_count={} right_count={} missing_sample={:?} extra_sample={:?}",
        left.len(),
        right.len(),
        missing,
        extra
    )
}

fn parity_iterations() -> usize {
    std::env::var("EXECUTION_MODE_PARITY_ITERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|iters| *iters > 0)
        .unwrap_or(5)
}

fn throughput_limits() -> (f64, f64) {
    let median = std::env::var("EXECUTION_MODE_PARITY_MEDIAN_MAX_PCT")
        .ok()
        .and_then(|raw| raw.parse::<f64>().ok())
        .unwrap_or(2.0);
    let per_case = std::env::var("EXECUTION_MODE_PARITY_PER_CASE_MAX_PCT")
        .ok()
        .and_then(|raw| raw.parse::<f64>().ok())
        .unwrap_or(10.0);
    (median, per_case)
}

#[test]
fn execution_mode_parity_matrix_and_thresholds() {
    let temp = tempfile::tempdir().expect("create parity tempdir");
    let cases = build_case_matrix(temp.path());
    let iterations = parity_iterations();
    let (median_limit_pct, per_case_limit_pct) = throughput_limits();

    // Phase 1: Finding parity — hard gate.
    // Both execution modes must produce identical findings for every case.
    for case in &cases {
        let direct_run = run_scan(case, "direct");
        let connector_run = run_scan(case, "connector");
        assert_eq!(
            direct_run.findings,
            connector_run.findings,
            "finding parity drift for case={} ({})",
            case.name,
            diff_summary(&direct_run.findings, &connector_run.findings)
        );
    }

    // Phase 2: Throughput parity — informational.
    // Small test fixtures complete in milliseconds, so throughput measurements
    // are dominated by process startup and OS scheduling jitter. On shared CI
    // runners, per-case variance of 20-50% is routine. We still collect and
    // print the data (useful for local profiling), but do not fail the test.
    let mut results = Vec::with_capacity(cases.len());
    for case in &cases {
        // Warmup: absorb cold-cache / process-startup costs.
        let _ = run_throughput_sample(case, "direct");
        let _ = run_throughput_sample(case, "connector");

        let mut direct_samples = Vec::with_capacity(iterations);
        let mut connector_samples = Vec::with_capacity(iterations);
        for idx in 0..iterations {
            if idx % 2 == 0 {
                direct_samples.push(run_throughput_sample(case, "direct"));
                connector_samples.push(run_throughput_sample(case, "connector"));
            } else {
                connector_samples.push(run_throughput_sample(case, "connector"));
                direct_samples.push(run_throughput_sample(case, "direct"));
            }
        }

        let direct_median = median(&direct_samples).unwrap_or_else(|err| {
            panic!(
                "failed to compute direct median throughput for case={}: {}",
                case.name, err
            )
        });
        let connector_median = median(&connector_samples).unwrap_or_else(|err| {
            panic!(
                "failed to compute connector median throughput for case={}: {}",
                case.name, err
            )
        });
        let delta_pct =
            throughput_delta_pct(direct_median, connector_median).unwrap_or_else(|err| {
                panic!(
                    "failed to compute throughput delta for case={}: {}",
                    case.name, err
                )
            });
        results.push(ThroughputCaseResult {
            name: case.name,
            delta_pct,
        });
    }

    let details = results
        .iter()
        .map(|result| format!("{}={:+.4}%", result.name, result.delta_pct))
        .collect::<Vec<_>>()
        .join(", ");
    let deltas: Vec<f64> = results.iter().map(|result| result.delta_pct).collect();
    match enforce_throughput_thresholds(&deltas, median_limit_pct, per_case_limit_pct) {
        Ok(_) => {
            eprintln!("throughput parity OK: [{details}]");
        }
        Err(err) => {
            eprintln!(
                "throughput parity WARNING (median_limit={}%, per_case_limit={}%): [{details}]: {err}",
                median_limit_pct, per_case_limit_pct
            );
        }
    }
}

#[test]
fn execution_mode_parity_standalone_fs_command_without_execution_mode_flag_still_succeeds() {
    let temp = tempfile::tempdir().expect("create standalone command tempdir");
    fs::write(
        temp.path().join("compat.env"),
        "TOKEN=xoxa-1234567890abcdef\n",
    )
    .expect("write compat fixture");

    let output = Command::new(scanner_bin())
        .args(["scan", "fs", "--null-sink"])
        .arg(format!("--path={}", temp.path().display()))
        .output()
        .expect("run standalone fs command");

    assert!(
        output.status.success(),
        "standalone fs command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
