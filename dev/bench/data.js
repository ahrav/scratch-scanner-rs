window.BENCHMARK_DATA = {
  "lastUpdate": 1771216601426,
  "repoUrl": "https://github.com/ahrav/scratch-scanner-rs",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "ahrav",
            "username": "ahrav",
            "email": "ahravdutta02@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "be9b5684d229c1661576006106c793482f4e6a4b",
          "message": "Merge pull request #106 from ahrav/feature/rules-entropy-gate-additions\n\nAdd entropy gates to 87 null-entropy detection rules",
          "timestamp": "2026-02-16T04:15:38Z",
          "url": "https://github.com/ahrav/scratch-scanner-rs/commit/be9b5684d229c1661576006106c793482f4e6a4b"
        },
        "date": 1771216600945,
        "tool": "cargo",
        "benches": [
          {
            "name": "write_u64/value/small_42",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_u64/value/medium_1_7B",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_u64/value/large_u64_max",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_oid_hex/sha1_20B",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_oid_hex/sha256_32B",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/scalar_short/4",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/scalar_short/8",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/scalar_short/14",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/clean_ascii/32",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/clean_ascii/128",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/clean_ascii/512",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/32",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/128",
            "value": 118,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/512",
            "value": 420,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/sparse_escapes/512",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_bytes/clean_ascii_128B",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_bytes/with_0xff_128B",
            "value": 301,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "write_f64/81.23",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/fs_finding",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/git_finding",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/no_identity",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/with_identity",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_batch/1000_findings",
            "value": 64892,
            "range": "± 198",
            "unit": "ns/iter"
          },
          {
            "name": "sink_emit/1000_findings_dev_null",
            "value": 80212,
            "range": "± 220",
            "unit": "ns/iter"
          },
          {
            "name": "json_sink_emit/1000_findings_dev_null",
            "value": 82448,
            "range": "± 271",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/2",
            "value": 149923,
            "range": "± 5651",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/4",
            "value": 194241,
            "range": "± 3601",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/8",
            "value": 320301,
            "range": "± 4910",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/custom_write_u64",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/itoa_write",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "f64_vs_ryu/custom_write_f64",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "f64_vs_ryu/ryu_write",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}