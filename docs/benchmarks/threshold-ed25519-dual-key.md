# Threshold Ed25519 Dual-Key Benchmark

Generated: 2026-03-26T05:26:11.976Z

Runtime:
- node: v22.13.0
- platform: darwin
- arch: arm64

Config:
- registration iterations: 25
- Paillier iterations: 5
- Paillier modulus bits: 2048

## Registration

Operational enrollment baseline:
- client verifying-share derive mean/p95: 1.886 ms / 1.418 ms
- relay keygen mean/p95: 4.73 ms / 4.328 ms
- total mean/p95: 6.616 ms / 5.747 ms

Dual-key bootstrap:
- recovery-share preflight mean/p95: 0.165 ms / 0.214 ms
- bootstrap package derive mean/p95: 7.517 ms / 9.704 ms
- total mean/p95: 7.682 ms / 9.918 ms

Delta versus operational enrollment:
- mean delta: 1.066 ms (16.112%)

## Recovery Export

Paillier latency:
- keygen mean/p95: 2029.982 ms / 4386.696 ms
- encrypt mean/p95: 20.558 ms / 20.691 ms
- add-constant mean/p95: 0.013 ms / 0.041 ms
- decrypt mean/p95: 20.325 ms / 20.69 ms

Payload sizes:
- public key raw / b64u: 256 bytes / 342 chars
- request ciphertext raw / b64u: 512 bytes / 683 chars
- response ciphertext raw / b64u: 512 bytes / 683 chars
- request crypto payload raw: 768 bytes
- response crypto payload raw: 512 bytes
- request JSON payload: 1079 bytes
- response JSON payload: 710 bytes
- round trips: 1
## Browser Runtime

Generated: 2026-03-26T05:28:39.462Z

### chromium

Runtime:
- version: 140.0.7339.16
- platform: MacIntel
- user agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/140.0.7339.16 Safari/537.36

Config:
- registration iterations: 10
- Paillier iterations: 3
- Paillier modulus bits: 2048

Registration

Operational enrollment baseline:
- client verifying-share derive mean/p95: 3.61 ms / 21.5 ms
- relay keygen mean/p95: 8.22 ms / 35.5 ms
- total mean/p95: 11.83 ms / 57 ms

Dual-key bootstrap:
- recovery-share preflight mean/p95: 0.24 ms / 0.8 ms
- bootstrap package derive mean/p95: 10.87 ms / 16.3 ms
- total mean/p95: 11.11 ms / 17.1 ms

Delta versus operational enrollment:
- mean delta: -0.72 ms (-6.086%)

Recovery Export

Paillier latency:
- keygen mean/p95: 1176.333 ms / 1541.8 ms
- encrypt mean/p95: 21.367 ms / 22.2 ms
- add-constant mean/p95: 0 ms / 0 ms
- decrypt mean/p95: 21.167 ms / 21.6 ms

Payload sizes:
- public key raw / b64u: 256 bytes / 342 chars
- request ciphertext raw / b64u: 512 bytes / 683 chars
- response ciphertext raw / b64u: 512 bytes / 683 chars
- request crypto payload raw: 768 bytes
- response crypto payload raw: 512 bytes
- request JSON payload: 1079 bytes
- response JSON payload: 710 bytes
- round trips: 1

### webkit

Runtime:
- version: 26.0
- platform: MacIntel
- user agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15

Config:
- registration iterations: 10
- Paillier iterations: 3
- Paillier modulus bits: 2048

Registration

Operational enrollment baseline:
- client verifying-share derive mean/p95: 2.6 ms / 14 ms
- relay keygen mean/p95: 6 ms / 20 ms
- total mean/p95: 8.6 ms / 34 ms

Dual-key bootstrap:
- recovery-share preflight mean/p95: 0.3 ms / 2 ms
- bootstrap package derive mean/p95: 8.9 ms / 13 ms
- total mean/p95: 9.2 ms / 15 ms

Delta versus operational enrollment:
- mean delta: 0.6 ms (6.977%)

Recovery Export

Paillier latency:
- keygen mean/p95: 1330.667 ms / 2024 ms
- encrypt mean/p95: 31.667 ms / 32 ms
- add-constant mean/p95: 0 ms / 0 ms
- decrypt mean/p95: 30.667 ms / 31 ms

Payload sizes:
- public key raw / b64u: 256 bytes / 342 chars
- request ciphertext raw / b64u: 512 bytes / 683 chars
- response ciphertext raw / b64u: 512 bytes / 683 chars
- request crypto payload raw: 768 bytes
- response crypto payload raw: 512 bytes
- request JSON payload: 1079 bytes
- response JSON payload: 710 bytes
- round trips: 1

## Real Device Runtime

Pending physical release-target hardware runs.

The measurements in this file currently cover:

- local node runtime
- local desktop Chromium
- local desktop WebKit

They do not yet include real iOS/Android device measurements.

