# Phase 13A Local Compute and Memory Report

Date: July 13, 2026

Status: canonical local viability evidence. Native process CPU/RSS and Node
WASM synchronous timings are local lower bounds. They do not establish
Cloudflare Worker CPU time, isolate memory, cold-start behavior, or deployed
capacity.

## Measurement policy

Both collectors execute one unreported warm-up followed by twenty sequential
activation and export ceremonies using the 128-KiB stream profile.
Every ceremony uses a fresh OS-random session, fresh ordinary passive base OT,
fresh private output coins, exact stream EOF, terminal transcript completion,
and typed recipient-artifact construction.

Native roles are independent release-mode processes connected by two Unix
sockets. `/usr/bin/time -lp` supplies `user + sys` CPU and maximum resident set
size for each process. CPU values have 10-ms resolution on this host.

The Node WASM collector separately accumulates host-observed synchronous time
inside session construction, Deriver A calls, Deriver B calls, and terminal
output processing. Event-loop yields and transport waits are excluded. It also
records the WebAssembly linear-memory high-water mark and the protocol's exact
live arena, table-buffer, Rust-frame, and JavaScript-wire allocations.

Environment:

- host: Darwin arm64;
- Rust: 1.96.0;
- native build: optimized release;
- Node: 24.18.0;
- WASM: optimized `wasm-pack --target nodejs` build with `wasm-opt`.

## Activation results

| Local measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| native complete ceremony wall | 66.309 ms | 68.026 ms | 70.199 ms |
| native Deriver A CPU | 30 ms | 30 ms | 30 ms |
| native Deriver B CPU | 40 ms | 50 ms | 50 ms |
| native combined CPU | 70 ms | 80 ms | 80 ms |
| Node WASM session construction | 0.279 ms | 0.471 ms | 0.719 ms |
| Node WASM Deriver A garbling/stream calls | 75.058 ms | 84.612 ms | 85.262 ms |
| Node WASM Deriver B evaluation/stream calls | 45.255 ms | 45.440 ms | 47.346 ms |
| Node WASM complete harness wall | 121.967 ms | 132.156 ms | 132.254 ms |

The native p95 maximum resident set sizes were 5,275,648 bytes for Deriver A
and 5,259,264 bytes for Deriver B. Node WASM linear memory reached 4,390,912
bytes. Exact live allocations were:

| Allocation | Bytes |
| --- | ---: |
| Deriver A arena | 115,345 |
| Deriver B arena | 115,345 |
| Deriver A table buffer | 131,072 |
| Deriver B table buffer | 131,072 |
| peak Rust wire frame | 131,164 |
| peak simultaneous JavaScript wire bytes | 262,328 |

These allocation classes overlap and must not be summed into a claimed isolate
peak. Linear memory excludes the JavaScript engine, Worker runtime, request
body intermediates, and platform allocations. Native RSS includes process
runtime and allocator state and is not a Worker-isolate proxy.

## Export results

| Local measurement | p50 | p95 | p99 |
| --- | ---: | ---: | ---: |
| native complete ceremony wall | 22.811 ms | 22.920 ms | 22.956 ms |
| Node WASM Deriver A garbling/stream calls | 1.690 ms | 1.731 ms | 1.753 ms |
| Node WASM Deriver B evaluation/stream calls | 0.905 ms | 0.925 ms | 0.936 ms |
| Node WASM complete harness wall | 2.737 ms | 2.826 ms | 2.836 ms |

Native export CPU rounds below the host timer's 10-ms resolution and is
recorded as zero. No cost conclusion uses that value.

## Reproduction

```sh
cargo build --manifest-path crates/ed25519-yao/Cargo.toml --release \
  --features passive-benchmark --bin benchmark_phase5_role
node crates/ed25519-yao/scripts/collect_phase5_native_compute.mjs

wasm-pack build crates/ed25519-yao/wasm-bench --target nodejs --release \
  --out-dir pkg-phase5
node crates/ed25519-yao/wasm-bench/scripts/collect_phase5_compute.mjs
```

The local activation results fit the provisional 250-ms ceremony, 150-ms
combined compute, and 96-MiB memory budgets. The Phase 13A decision still
requires deployed same-account and independent-account Worker CPU, sampled
isolate memory, latency, placement, and failure evidence.
