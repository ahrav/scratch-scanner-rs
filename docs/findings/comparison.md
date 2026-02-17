# Scanner Comparison Benchmark Results

Generated: 2026-02-15 21:06:39 UTC

## 1. Test Environment

```
=== Benchmark Environment ===
Date: 2026-02-14T22:43:33Z
Hostname: dev-dsk-ahrav-2b-40416d90.us-west-2.amazon.com

--- CPU ---
Architecture:        aarch64
CPU(s):              16
Thread(s) per core:  1
Socket(s):           1
L1d cache:           64K
L1i cache:           64K
L2 cache:            1024K
L3 cache:            32768K
Flags:               fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 sve asimdfhm dit uscat ilrcpc flagm paca pacg dcpodp svei8mm svebf16 i8mm bf16 dgh rng

--- Memory ---
              total        used        free      shared  buff/cache   available
Mem:            61G        5.1G         53G        816K        2.8G         55G
Swap:            0B          0B          0B

--- Kernel ---
Linux dev-dsk-ahrav-2b-40416d90.us-west-2.amazon.com 5.10.247-247.992.amzn2int.aarch64 #1 SMP Mon Jan 26 19:28:10 UTC 2026 aarch64 aarch64 aarch64 GNU/Linux

--- Storage ---
Filesystem      Size  Used Avail Use% Mounted on
/dev/nvme0n1p1  552G  341G  211G  62% /

NAME    MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
nvme0n1 259:0    0  560G  0 disk 

[none] mq-deadline kyber bfq 

--- Compilers ---
rustc 1.90.0 (1159e78c4 2025-09-14)
go version go1.23.3 linux/arm64

--- Scanner versions ---
scanner-rs: e5d217c
kingfisher: 88d3f78
trufflehog: 6961f2bac
gitleaks:   ca20267
```

## 2. Findings Count (per scanner × repo × mode)

Values shown for warm cache runs (cold fallback if warm unavailable).

| Repo        | Mode | scanner-rs | kingfisher | trufflehog | gitleaks |
|-------------|------|-----------:|-----------:|-----------:|---------:|
| node        | git  |     11,168 |     91,289 |        842 |   22,060 |
| node        | fs   |        629 |      4,599 |         59 |      260 |
| vscode      | git  |     98,584 |        303 |          0 |      116 |
| vscode      | fs   |      1,009 |         71 |          2 |       15 |
| linux       | git  |    199,422 |        169 |         38 |      463 |
| linux       | fs   |      2,894 |         91 |         21 |      238 |
| rocksdb     | git  |         71 |        142 |         14 |       29 |
| rocksdb     | fs   |          8 |         27 |          0 |        5 |
| tensorflow  | git  |     14,239 |        225 |          5 |       46 |
| tensorflow  | fs   |      3,719 |         69 |          4 |       11 |
| Babylon.js  | git  |      1,781 |        309 |          1 |        8 |
| Babylon.js  | fs   |        112 |          1 |          0 |        2 |
| gcc         | git  |     17,212 |      2,097 |         35 |      189 |
| gcc         | fs   |        177 |        217 |         10 |       56 |
| jdk         | git  |     11,300 |      3,061 |          9 |      306 |
| jdk         | fs   |      1,754 |      1,170 |          8 |      240 |

## 3. Performance

### 3a. Wall Time

| Repo        | Mode | Cache | scanner-rs | kingfisher | trufflehog | gitleaks  |
|-------------|------|-------|-----------:|-----------:|-----------:|----------:|
| node        | git  | cold  |      15.7s |      1m38s |      8m 3s |    6m48s  |
| node        | git  | warm  |      13.3s |      1m17s |     7m54s  |    6m39s  |
| node        | fs   | cold  |      15.2s |      20.2s |      23.9s |    41.1s  |
| node        | fs   | warm  |       1.5s |       5.0s |      18.6s |    38.5s  |
|             |      |       |            |            |            |           |
| vscode      | git  | cold  |      16.8s |      43.5s |      3m 8s |    2m 4s  |
| vscode      | git  | warm  |      13.7s |      31.1s |     2m59s  |    1m54s  |
| vscode      | fs   | cold  |       3.0s |       6.9s |      15.1s |     9.6s  |
| vscode      | fs   | warm  |       0.9s |       4.6s |      13.3s |    10.4s  |
|             |      |       |            |            |            |           |
| linux       | git  | cold  |     2m51s  |     7m22s  |    28m54s  |   21m20s  |
| linux       | git  | warm  |     2m38s  |     5m57s  |    27m57s  |   20m27s  |
| linux       | fs   | cold  |      28.9s |      35.2s |      1m 2s |    1m14s  |
| linux       | fs   | warm  |       2.2s |       5.2s |      1m 2s |    1m 9s  |
|             |      |       |            |            |            |           |
| rocksdb     | git  | cold  |       3.8s |       8.6s |      36.3s |    22.5s  |
| rocksdb     | git  | warm  |       3.1s |       7.2s |      33.8s |    21.0s  |
| rocksdb     | fs   | cold  |       0.8s |       7.0s |       5.1s |     2.8s  |
| rocksdb     | fs   | warm  |       0.7s |       6.5s |       4.0s |     2.8s  |
|             |      |       |            |            |            |           |
| tensorflow  | git  | cold  |      25.1s |      1m12s |     5m49s  |    3m50s  |
| tensorflow  | git  | warm  |      21.0s |      50.7s |     5m36s  |    3m40s  |
| tensorflow  | fs   | cold  |      10.4s |      15.7s |      21.5s |    26.4s  |
| tensorflow  | fs   | warm  |       1.1s |       5.3s |      18.9s |    27.0s  |
|             |      |       |            |            |            |           |
| Babylon.js  | git  | cold  |      12.7s |      21.2s |     2m14s  |    2m 5s  |
| Babylon.js  | git  | warm  |      10.9s |      14.6s |     2m 7s  |    2m 1s  |
| Babylon.js  | fs   | cold  |       1.7s |       7.0s |      19.1s |    17.0s  |
| Babylon.js  | fs   | warm  |       0.8s |       4.6s |      17.4s |    16.4s  |
|             |      |       |            |            |            |           |
| gcc         | git  | cold  |     2m12s  |     5m52s  |    30m35s  |  145m 6s  |
| gcc         | git  | warm  |     2m25s  |     4m34s  |    30m 4s  |  145m21s  |
| gcc         | fs   | cold  |      53.5s |      59.3s |      1m 2s |  141m59s  |
| gcc         | fs   | warm  |       2.7s |       6.8s |      44.7s |  142m 6s  |
|             |      |       |            |            |            |           |
| jdk         | git  | cold  |      22.6s |      1m13s |     6m15s  |    5m39s  |
| jdk         | git  | warm  |      19.8s |      33.8s |     6m 4s  |    5m19s  |
| jdk         | fs   | cold  |      24.9s |      32.3s |      35.9s |    41.1s  |
| jdk         | fs   | warm  |       1.8s |       7.9s |      19.2s |    32.3s  |

### 3b. Throughput

| Repo        | Mode | Cache | scanner-rs   | kingfisher   | trufflehog   | gitleaks     |
|-------------|------|-------|-------------:|-------------:|-------------:|-------------:|
| node        | git  | cold  |  89.7 MiB/s  |  14.3 MiB/s  |   2.9 MiB/s  |   3.5 MiB/s  |
| node        | git  | warm  | 106.1 MiB/s  |  18.3 MiB/s  |   3.0 MiB/s  |   3.5 MiB/s  |
| node        | fs   | cold  | 136.3 MiB/s  | 102.6 MiB/s  |  86.5 MiB/s  |  50.3 MiB/s  |
| node        | fs   | warm  |   1.4 GiB/s  | 413.9 MiB/s  | 111.0 MiB/s  |  53.7 MiB/s  |
|             |      |       |              |              |              |              |
| vscode      | git  | cold  |  68.3 MiB/s  |  26.4 MiB/s  |   6.1 MiB/s  |   9.3 MiB/s  |
| vscode      | git  | warm  |  84.1 MiB/s  |  37.0 MiB/s  |   6.4 MiB/s  |  10.1 MiB/s  |
| vscode      | fs   | cold  | 440.9 MiB/s  | 189.7 MiB/s  |  86.7 MiB/s  | 136.2 MiB/s  |
| vscode      | fs   | warm  |   1.5 GiB/s  | 283.7 MiB/s  |  97.9 MiB/s  | 125.0 MiB/s  |
|             |      |       |              |              |              |              |
| linux       | git  | cold  |  36.1 MiB/s  |  13.9 MiB/s  |   3.5 MiB/s  |   4.8 MiB/s  |
| linux       | git  | warm  |  39.0 MiB/s  |  17.2 MiB/s  |   3.7 MiB/s  |   5.0 MiB/s  |
| linux       | fs   | cold  | 267.2 MiB/s  | 219.1 MiB/s  | 124.6 MiB/s  | 104.7 MiB/s  |
| linux       | fs   | warm  |   3.3 GiB/s  |   1.4 GiB/s  | 125.1 MiB/s  | 111.7 MiB/s  |
|             |      |       |              |              |              |              |
| rocksdb     | git  | cold  |  61.9 MiB/s  |  27.1 MiB/s  |   6.4 MiB/s  |  10.3 MiB/s  |
| rocksdb     | git  | warm  |  74.1 MiB/s  |  32.2 MiB/s  |   6.9 MiB/s  |  11.1 MiB/s  |
| rocksdb     | fs   | cold  | 340.4 MiB/s  |  39.6 MiB/s  |  54.3 MiB/s  |  97.8 MiB/s  |
| rocksdb     | fs   | warm  | 393.9 MiB/s  |  42.4 MiB/s  |  68.6 MiB/s  |  99.5 MiB/s  |
|             |      |       |              |              |              |              |
| tensorflow  | git  | cold  |  51.2 MiB/s  |  17.8 MiB/s  |   3.7 MiB/s  |   5.6 MiB/s  |
| tensorflow  | git  | warm  |  61.2 MiB/s  |  25.3 MiB/s  |   3.8 MiB/s  |   5.8 MiB/s  |
| tensorflow  | fs   | cold  | 160.7 MiB/s  | 106.8 MiB/s  |  77.8 MiB/s  |  63.4 MiB/s  |
| tensorflow  | fs   | warm  |   1.5 GiB/s  | 318.3 MiB/s  |  88.7 MiB/s  |  62.0 MiB/s  |
|             |      |       |              |              |              |              |
| Babylon.js  | git  | cold  | 107.6 MiB/s  |  64.3 MiB/s  |  10.2 MiB/s  |  10.9 MiB/s  |
| Babylon.js  | git  | warm  | 124.8 MiB/s  |  93.7 MiB/s  |  10.7 MiB/s  |  11.3 MiB/s  |
| Babylon.js  | fs   | cold  |   1.2 GiB/s  | 292.5 MiB/s  | 108.0 MiB/s  | 121.0 MiB/s  |
| Babylon.js  | fs   | warm  |   2.5 GiB/s  | 445.7 MiB/s  | 118.3 MiB/s  | 125.4 MiB/s  |
|             |      |       |              |              |              |              |
| gcc         | git  | cold  |  30.5 MiB/s  |  11.4 MiB/s  |   2.2 MiB/s  |   0.5 MiB/s  |
| gcc         | git  | warm  |  27.7 MiB/s  |  14.7 MiB/s  |   2.2 MiB/s  |   0.5 MiB/s  |
| gcc         | fs   | cold  |  91.2 MiB/s  |  82.4 MiB/s  |  78.8 MiB/s  |   0.6 MiB/s  |
| gcc         | fs   | warm  |   1.8 GiB/s  | 715.7 MiB/s  | 109.1 MiB/s  |   0.6 MiB/s  |
|             |      |       |              |              |              |              |
| jdk         | git  | cold  |  63.3 MiB/s  |  19.7 MiB/s  |   3.8 MiB/s  |   4.2 MiB/s  |
| jdk         | git  | warm  |  72.2 MiB/s  |  42.4 MiB/s  |   3.9 MiB/s  |   4.5 MiB/s  |
| jdk         | fs   | cold  |  87.2 MiB/s  |  67.4 MiB/s  |  60.5 MiB/s  |  52.9 MiB/s  |
| jdk         | fs   | warm  |   1.2 GiB/s  | 273.8 MiB/s  | 113.3 MiB/s  |  67.3 MiB/s  |

## 4. Speedup Summary (warm git mode, scanner-rs as baseline)

Values show how many times slower each competitor is vs scanner-rs.

| Repo        | vs Kingfisher | vs TruffleHog | vs Gitleaks |
|-------------|--------------:|--------------:|------------:|
| node        |          5.8× |         35.6× |       30.0× |
| vscode      |          2.3× |         13.1× |        8.3× |
| linux       |          2.3× |         10.6× |        7.8× |
| rocksdb     |          2.3× |         10.8× |        6.7× |
| tensorflow  |          2.4× |         16.0× |       10.5× |
| Babylon.js  |          1.3× |         11.6× |       11.1× |
| gcc         |          1.9× |         12.4× |       60.0× |
| jdk         |          1.7× |         18.3× |       16.1× |

## 5. Peak Memory Usage

Maximum resident set size across all modes and cache states.

| Repo        | scanner-rs | kingfisher | trufflehog | gitleaks  |
|-------------|-----------:|-----------:|-----------:|----------:|
| node        |    5.5 GiB |    2.3 GiB |    1.7 GiB |   1.6 GiB |
| vscode      |    5.4 GiB |    2.1 GiB |    1.6 GiB |   1.3 GiB |
| linux       |   22.9 GiB |    8.1 GiB |    8.3 GiB |   7.2 GiB |
| rocksdb     |    2.8 GiB |    1.6 GiB |    403 MiB |   403 MiB |
| tensorflow  |    7.2 GiB |    2.4 GiB |    1.8 GiB |   1.4 GiB |
| Babylon.js  |    4.5 GiB |    2.8 GiB |    1.5 GiB |   1.3 GiB |
| gcc         |   15.8 GiB |    5.6 GiB |    4.8 GiB |   4.5 GiB |
| jdk         |    6.2 GiB |    2.3 GiB |    1.8 GiB |   1.6 GiB |

## 6. Rule Coverage Notes

```
# Rules from scanner-rs with no match in at least one scanner
# Total scanner-rs rules: 223
# Matched in TruffleHog: 98
# Matched in Gitleaks: 222
# Kingfisher: superset (277 rules), runs with defaults

1password-secret-key: missing in trufflehog
1password-service-account-token: missing in trufflehog
age-secret-key: missing in trufflehog
atlassian-api-token: missing in trufflehog
authress-service-client-access-key: missing in trufflehog
aws-amazon-bedrock-api-key-long-lived: missing in trufflehog
aws-amazon-bedrock-api-key-short-lived: missing in trufflehog
bittrex-access-key: missing in trufflehog
bittrex-secret-key: missing in trufflehog
cisco-meraki-api-key: missing in trufflehog
clickhouse-cloud-api-secret-key: missing in trufflehog
clojars-api-token: missing in trufflehog
codecov-access-token: missing in trufflehog
cohere-api-token: missing in trufflehog
curl-auth-header: missing in trufflehog
curl-auth-user: missing in trufflehog
defined-networking-api-token: missing in trufflehog
discord-client-id: missing in trufflehog
discord-client-secret: missing in trufflehog
duffel-api-token: missing in trufflehog
dynatrace-api-token: missing in trufflehog
easypost-api-token: missing in trufflehog
easypost-test-api-token: missing in trufflehog
finicity-api-token: missing in trufflehog
finicity-client-secret: missing in trufflehog
freemius-secret-key: missing in trufflehog
generic-api-key: missing in trufflehog
infracost-api-token: missing in trufflehog
jfrog-api-key: missing in trufflehog
jfrog-identity-token: missing in trufflehog
jwt-base64: missing in trufflehog
jwt: missing in trufflehog
kubernetes-secret-yaml: missing in trufflehog
linkedin-client-id: missing in trufflehog
linkedin-client-secret: missing in trufflehog
looker-client-id: missing in trufflehog
looker-client-secret: missing in trufflehog
nuget-config-password: missing in trufflehog
octopus-deploy-api-key: missing in trufflehog
openshift-user-token: missing in trufflehog
perplexity-api-key: missing in trufflehog
pkcs12-file: missing in trufflehog
privateai-api-token: missing in trufflehog
scalingo-api-token: missing in trufflehog
settlemint-application-access-token: missing in trufflehog
settlemint-personal-access-token: missing in trufflehog
settlemint-service-access-token: missing in trufflehog
shippo-api-token: missing in trufflehog
sidekiq-secret: missing in trufflehog
sidekiq-sensitive-url: missing in trufflehog
twitter-access-secret: missing in trufflehog
twitter-access-token: missing in trufflehog
twitter-api-key: missing in trufflehog
twitter-api-secret: missing in trufflehog
twitter-bearer-token: missing in trufflehog
vault-service-token-legacy: missing in gitleaks
yandex-access-token: missing in trufflehog
yandex-api-key: missing in trufflehog
yandex-aws-access-token: missing in trufflehog

```

## 7. Notes

- **Cold cache**: `sync && echo 3 > /proc/sys/vm/drop_caches` + 2s settle
- **Warm cache**: throwaway run first, then measured second run
- **Offline validation only**: no live HTTP checks for any scanner
- **Archive scanning**: enabled for all scanners
- **Decode depth**: 2 for scanner-rs/Gitleaks, default for Kingfisher/TruffleHog
- **Kingfisher**: runs with all 277 default rules (superset of scanner-rs)
- **TruffleHog**: filtered to matched detectors via `--include-detectors`
- **Gitleaks**: custom TOML config with only scanner-rs-matched rules
