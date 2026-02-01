//! Per-Rule Cost Analysis
//!
//! This benchmark measures the throughput cost of each individual gitleaks rule
//! to identify the most expensive rules that are dragging down overall performance.
//!
//! Run with: cargo bench --bench per_rule_cost --features bench
//!
//! Output: A ranked list of rules by their throughput impact.

use scanner_rs::{AnchorPolicy, Engine, RuleSpec, Tuning, ValidatorKind};
use std::time::Instant;

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const WARMUP_ITERS: usize = 2;
const MEASURE_ITERS: usize = 5;

/// Generate realistic code-like content that will trigger common anchors.
fn gen_realistic_code(size: usize) -> Vec<u8> {
    let code_snippets = [
        b"const apiKey = process.env.API_KEY;\n".as_slice(),
        b"let token = getAccessToken();\n".as_slice(),
        b"const secret = config.secret;\n".as_slice(),
        b"password: ${PASSWORD}\n".as_slice(),
        b"authorization: Bearer token123\n".as_slice(),
        b"import { api } from './api';\n".as_slice(),
        b"function authenticate(credentials) {\n".as_slice(),
        b"const KEY = 'some-key-value';\n".as_slice(),
        b"export const ACCESS_TOKEN = '';\n".as_slice(),
        b"// This is a comment with key mention\n".as_slice(),
        b"def get_api_response(api_url):\n".as_slice(),
        b"    return requests.get(api_url)\n".as_slice(),
        b"class TokenManager:\n".as_slice(),
        b"    def refresh_token(self):\n".as_slice(),
        b"        pass\n".as_slice(),
        b"DISCORD_TOKEN=your_token_here\n".as_slice(),
        b"SLACK_API_KEY=xoxb-placeholder\n".as_slice(),
        b"aws_secret_access_key = placeholder\n".as_slice(),
        b"github_token: ghp_placeholder\n".as_slice(),
        b"stripe_secret_key: sk_test_placeholder\n".as_slice(),
        b"const client_id = '12345';\n".as_slice(),
        b"private_key: '-----BEGIN RSA PRIVATE KEY-----'\n".as_slice(),
        b"npm_token: npm_xxxxxxxxxxxx\n".as_slice(),
        b"SENDGRID_API_KEY=SG.xxxxxxxxx\n".as_slice(),
        b"twilio_auth_token = 'xxxxxxxxxx'\n".as_slice(),
        b"firebase_api_key: AIzaxxxxxxxxx\n".as_slice(),
        b"heroku_api_key = 'xxxxxxxx-xxxx'\n".as_slice(),
        b"mailchimp_api_key: xxxxxxxxxxxxxxxx-us1\n".as_slice(),
    ];

    let mut data = Vec::with_capacity(size);
    let mut idx = 0;
    while data.len() < size {
        data.extend_from_slice(code_snippets[idx % code_snippets.len()]);
        idx += 1;
    }
    data.truncate(size);
    data
}

/// Result for a single rule measurement.
#[derive(Debug, Clone)]
struct RuleCost {
    name: String,
    anchor_count: usize,
    anchors_preview: String,
    throughput_mib_s: f64,
    time_ms: f64,
}

/// Measure the cost of a single rule.
fn measure_rule(rule: RuleSpec, data: &[u8], tuning: &Tuning) -> RuleCost {
    let name = rule.name.to_string();
    let anchor_count = rule.anchors.len();
    let anchors_preview: String = rule
        .anchors
        .iter()
        .take(3)
        .map(|a| String::from_utf8_lossy(a).to_string())
        .collect::<Vec<_>>()
        .join(", ")
        + if anchor_count > 3 { ", ..." } else { "" };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();

    // Warmup
    for _ in 0..WARMUP_ITERS {
        let _ = engine.scan_chunk(data, &mut scratch);
    }

    // Measure
    let start = Instant::now();
    for _ in 0..MEASURE_ITERS {
        let _ = engine.scan_chunk(data, &mut scratch);
    }
    let elapsed = start.elapsed();

    let total_bytes = data.len() * MEASURE_ITERS;
    let throughput_mib_s = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    let time_ms = elapsed.as_secs_f64() * 1000.0 / MEASURE_ITERS as f64;

    RuleCost {
        name,
        anchor_count,
        anchors_preview,
        throughput_mib_s,
        time_ms,
    }
}

fn main() {
    println!("Per-Rule Cost Analysis");
    println!("======================");
    println!("Buffer size: {} MiB", BUFFER_SIZE / (1024 * 1024));
    println!("Warmup iterations: {}", WARMUP_ITERS);
    println!("Measure iterations: {}", MEASURE_ITERS);
    println!();

    let data = gen_realistic_code(BUFFER_SIZE);
    let tuning = Tuning {
        max_transform_depth: 0, // Disable transforms for pure rule cost
        ..scanner_rs::demo_tuning()
    };

    // Get all rules
    let rules = scanner_rs::gitleaks_rules();
    let total_rules = rules.len();
    println!("Total rules: {}", total_rules);
    println!();

    // Measure baseline (impossible rule that never matches)
    println!("Measuring baseline...");
    let baseline_rule = RuleSpec {
        name: "baseline-impossible",
        anchors: &[b"\xFF\xFE\xFD\xFC"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        entropy: None,
        secret_group: None,
        re: regex::bytes::Regex::new(r"\xFF\xFE\xFD\xFC[a-z]{10}").unwrap(),
    };
    let baseline_engine = Engine::new_with_anchor_policy(
        vec![baseline_rule],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut baseline_scratch = baseline_engine.new_scratch();

    for _ in 0..WARMUP_ITERS {
        let _ = baseline_engine.scan_chunk(&data, &mut baseline_scratch);
    }
    let start = Instant::now();
    for _ in 0..MEASURE_ITERS {
        let _ = baseline_engine.scan_chunk(&data, &mut baseline_scratch);
    }
    let baseline_elapsed = start.elapsed();
    let baseline_throughput =
        (data.len() * MEASURE_ITERS) as f64 / (1024.0 * 1024.0) / baseline_elapsed.as_secs_f64();
    println!(
        "Baseline (impossible rule): {:.1} MiB/s",
        baseline_throughput
    );
    println!();

    // Measure each rule
    println!("Measuring {} rules (this may take a while)...", total_rules);
    println!();

    let mut costs: Vec<RuleCost> = Vec::with_capacity(total_rules);

    for (i, rule) in rules.into_iter().enumerate() {
        if (i + 1) % 20 == 0 || i == 0 {
            eprint!("\rProgress: {}/{}", i + 1, total_rules);
        }
        let cost = measure_rule(rule, &data, &tuning);
        costs.push(cost);
    }
    eprintln!("\rProgress: {}/{}", total_rules, total_rules);
    println!();

    // Sort by throughput (ascending = slowest first)
    costs.sort_by(|a, b| a.throughput_mib_s.partial_cmp(&b.throughput_mib_s).unwrap());

    // Print results
    println!("================================================================================");
    println!("RESULTS: Rules sorted by throughput (slowest first)");
    println!("================================================================================");
    println!();
    println!(
        "{:<4} {:<40} {:>8} {:>12} {:>10}",
        "Rank", "Rule Name", "Anchors", "Throughput", "Time/scan"
    );
    println!(
        "{:<4} {:<40} {:>8} {:>12} {:>10}",
        "----",
        "-".repeat(40).as_str(),
        "-------",
        "-----------",
        "---------"
    );

    for (i, cost) in costs.iter().enumerate() {
        let throughput_str = if cost.throughput_mib_s >= 1000.0 {
            format!("{:.1} GiB/s", cost.throughput_mib_s / 1024.0)
        } else {
            format!("{:.1} MiB/s", cost.throughput_mib_s)
        };

        println!(
            "{:<4} {:<40} {:>8} {:>12} {:>8.2} ms",
            i + 1,
            &cost.name[..cost.name.len().min(40)],
            cost.anchor_count,
            throughput_str,
            cost.time_ms,
        );
    }

    println!();
    println!("================================================================================");
    println!("TOP 10 SLOWEST RULES (potential optimization targets)");
    println!("================================================================================");
    println!();

    for (i, cost) in costs.iter().take(10).enumerate() {
        println!("{}. {} ", i + 1, cost.name);
        println!(
            "   Throughput: {:.1} MiB/s ({:.2} ms per 4 MiB scan)",
            cost.throughput_mib_s, cost.time_ms
        );
        println!(
            "   Anchors ({}): {}",
            cost.anchor_count, cost.anchors_preview
        );
        println!();
    }

    println!("================================================================================");
    println!("TOP 10 FASTEST RULES (good examples)");
    println!("================================================================================");
    println!();

    for (i, cost) in costs.iter().rev().take(10).enumerate() {
        let throughput_str = if cost.throughput_mib_s >= 1000.0 {
            format!("{:.1} GiB/s", cost.throughput_mib_s / 1024.0)
        } else {
            format!("{:.1} MiB/s", cost.throughput_mib_s)
        };
        println!("{}. {} ", i + 1, cost.name);
        println!("   Throughput: {}", throughput_str);
        println!(
            "   Anchors ({}): {}",
            cost.anchor_count, cost.anchors_preview
        );
        println!();
    }

    // Summary statistics
    println!("================================================================================");
    println!("SUMMARY STATISTICS");
    println!("================================================================================");
    println!();

    let slowest = costs.first().unwrap();
    let fastest = costs.last().unwrap();
    let median = &costs[costs.len() / 2];

    let avg_throughput: f64 =
        costs.iter().map(|c| c.throughput_mib_s).sum::<f64>() / costs.len() as f64;

    let under_100_mib = costs.iter().filter(|c| c.throughput_mib_s < 100.0).count();
    let under_500_mib = costs.iter().filter(|c| c.throughput_mib_s < 500.0).count();
    let under_1_gib = costs.iter().filter(|c| c.throughput_mib_s < 1024.0).count();

    println!(
        "Slowest rule: {} ({:.1} MiB/s)",
        slowest.name, slowest.throughput_mib_s
    );
    println!(
        "Fastest rule: {} ({:.1} GiB/s)",
        fastest.name,
        fastest.throughput_mib_s / 1024.0
    );
    println!(
        "Median rule:  {} ({:.1} MiB/s)",
        median.name, median.throughput_mib_s
    );
    println!("Average throughput: {:.1} MiB/s", avg_throughput);
    println!();
    println!(
        "Rules < 100 MiB/s:  {} ({:.1}%)",
        under_100_mib,
        under_100_mib as f64 / total_rules as f64 * 100.0
    );
    println!(
        "Rules < 500 MiB/s:  {} ({:.1}%)",
        under_500_mib,
        under_500_mib as f64 / total_rules as f64 * 100.0
    );
    println!(
        "Rules < 1 GiB/s:    {} ({:.1}%)",
        under_1_gib,
        under_1_gib as f64 / total_rules as f64 * 100.0
    );
}
