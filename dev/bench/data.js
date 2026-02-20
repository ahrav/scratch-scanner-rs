window.BENCHMARK_DATA = {
  "lastUpdate": 1771561505664,
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
      },
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
          "id": "d6c32da9530cb2e461f2366f1cc0fc752f3c10a4",
          "message": "Merge pull request #116 from ahrav/chore/documentation-crusade-part7\n\nFix documentation drift across 108 source files and 4 companion docs (part 7)",
          "timestamp": "2026-02-17T04:00:44Z",
          "url": "https://github.com/ahrav/scratch-scanner-rs/commit/d6c32da9530cb2e461f2366f1cc0fc752f3c10a4"
        },
        "date": 1771302457670,
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
            "value": 13,
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
            "value": 8,
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
            "value": 6,
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
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/128",
            "value": 121,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/512",
            "value": 422,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/sparse_escapes/512",
            "value": 74,
            "range": "± 3",
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
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/git_finding",
            "value": 72,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/no_identity",
            "value": 27,
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
            "value": 65602,
            "range": "± 522",
            "unit": "ns/iter"
          },
          {
            "name": "sink_emit/1000_findings_dev_null",
            "value": 80592,
            "range": "± 1968",
            "unit": "ns/iter"
          },
          {
            "name": "json_sink_emit/1000_findings_dev_null",
            "value": 81355,
            "range": "± 1797",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/2",
            "value": 148937,
            "range": "± 1861",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/4",
            "value": 199882,
            "range": "± 2895",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/8",
            "value": 316527,
            "range": "± 3708",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/custom_write_u64",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/itoa_write",
            "value": 9,
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
      },
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
          "id": "d0b80fb18cdb06de712994b80bee5f086ef96364",
          "message": "Merge pull request #119 from ahrav/feature/extend-min-entropy\n\nExtend min-entropy gate to 56 additional rules (Tiers 1-3)",
          "timestamp": "2026-02-18T04:25:39Z",
          "url": "https://github.com/ahrav/scratch-scanner-rs/commit/d0b80fb18cdb06de712994b80bee5f086ef96364"
        },
        "date": 1771389113570,
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
            "value": 8,
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
            "value": 6,
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
            "value": 44,
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
            "value": 421,
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
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/git_finding",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/no_identity",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/with_identity",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_batch/1000_findings",
            "value": 65430,
            "range": "± 1122",
            "unit": "ns/iter"
          },
          {
            "name": "sink_emit/1000_findings_dev_null",
            "value": 80160,
            "range": "± 5106",
            "unit": "ns/iter"
          },
          {
            "name": "json_sink_emit/1000_findings_dev_null",
            "value": 82358,
            "range": "± 221",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/2",
            "value": 144731,
            "range": "± 1353",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/4",
            "value": 195431,
            "range": "± 2802",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/8",
            "value": 315141,
            "range": "± 3572",
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
            "value": 10,
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
          },
          {
            "name": "offline_validate_aws_access_key/valid_akia",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/valid_a3t",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_charset",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_small",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_large",
            "value": 295,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_prefix",
            "value": 284,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_char",
            "value": 277,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/oversized_payload",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/valid",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/wrong_header",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/invalid_char",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/too_short",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_current",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_legacy",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/user_token",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/config_access",
            "value": 83,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/invalid_segments",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/unknown_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "AhravDutta",
            "username": "ahrav",
            "email": "ahravdutta02@gmail.com"
          },
          "committer": {
            "name": "AhravDutta",
            "username": "ahrav",
            "email": "ahravdutta02@gmail.com"
          },
          "id": "b810a8aebdc84e4d4e587c6cf152e68538af981c",
          "message": "update beads",
          "timestamp": "2026-02-18T17:29:31Z",
          "url": "https://github.com/ahrav/scratch-scanner-rs/commit/b810a8aebdc84e4d4e587c6cf152e68538af981c"
        },
        "date": 1771475457922,
        "tool": "cargo",
        "benches": [
          {
            "name": "write_u64/value/small_42",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_u64/value/medium_1_7B",
            "value": 13,
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
            "value": 8,
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
            "value": 6,
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
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/512",
            "value": 425,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/sparse_escapes/512",
            "value": 76,
            "range": "± 1",
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
            "value": 340,
            "range": "± 6",
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
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/git_finding",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/no_identity",
            "value": 26,
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
            "value": 70880,
            "range": "± 1221",
            "unit": "ns/iter"
          },
          {
            "name": "sink_emit/1000_findings_dev_null",
            "value": 82524,
            "range": "± 783",
            "unit": "ns/iter"
          },
          {
            "name": "json_sink_emit/1000_findings_dev_null",
            "value": 86250,
            "range": "± 344",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/2",
            "value": 156586,
            "range": "± 4078",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/4",
            "value": 201645,
            "range": "± 2816",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/8",
            "value": 327299,
            "range": "± 5779",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/custom_write_u64",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/itoa_write",
            "value": 9,
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
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/valid_akia",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/valid_a3t",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_charset",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_small",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_large",
            "value": 295,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_prefix",
            "value": 284,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_char",
            "value": 277,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/oversized_payload",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/valid",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/wrong_header",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/invalid_char",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/too_short",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_current",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_legacy",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/user_token",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/config_access",
            "value": 82,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/invalid_segments",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/unknown_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "AhravDutta",
            "username": "ahrav",
            "email": "ahravdutta02@gmail.com"
          },
          "committer": {
            "name": "AhravDutta",
            "username": "ahrav",
            "email": "ahravdutta02@gmail.com"
          },
          "id": "7e10819f007e637dc70e437ef5e42bb5ce57fc3c",
          "message": "Promote all eval-harness issues to P0 priority\n\nAll 11 eval-harness issues (1 epic + 10 tasks) updated from P1/P2 to P0\nso they take priority over all other work.\n\nCo-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>",
          "timestamp": "2026-02-20T01:48:52Z",
          "url": "https://github.com/ahrav/scratch-scanner-rs/commit/7e10819f007e637dc70e437ef5e42bb5ce57fc3c"
        },
        "date": 1771561504799,
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
            "value": 13,
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
            "value": 8,
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
            "value": 6,
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
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/128",
            "value": 118,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/with_escapes/512",
            "value": 422,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "write_json_str/sparse_escapes/512",
            "value": 76,
            "range": "± 1",
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
            "value": 341,
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
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_finding/git_finding",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "encode_commit_meta/no_identity",
            "value": 26,
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
            "value": 70021,
            "range": "± 229",
            "unit": "ns/iter"
          },
          {
            "name": "sink_emit/1000_findings_dev_null",
            "value": 81428,
            "range": "± 508",
            "unit": "ns/iter"
          },
          {
            "name": "json_sink_emit/1000_findings_dev_null",
            "value": 84833,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/2",
            "value": 143868,
            "range": "± 941",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/4",
            "value": 182616,
            "range": "± 2347",
            "unit": "ns/iter"
          },
          {
            "name": "sink_contention/threads/8",
            "value": 307343,
            "range": "± 2937",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/custom_write_u64",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "u64_vs_itoa/itoa_write",
            "value": 9,
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
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/valid_akia",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/valid_a3t",
            "value": 33,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_charset",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_aws_access_key/invalid_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_small",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/valid_large",
            "value": 295,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_prefix",
            "value": 285,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/invalid_char",
            "value": 277,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_sentry_org_token/oversized_payload",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/valid",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/wrong_header",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/invalid_char",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_pypi_token/too_short",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_current",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/bot_legacy",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/user_token",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/config_access",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/invalid_segments",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "offline_validate_slack_token/unknown_prefix",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}