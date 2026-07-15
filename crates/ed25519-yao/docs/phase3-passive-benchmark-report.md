# Phase 3 Passive Yao Benchmark Report

Date: July 12, 2026

Status: **local viability evidence only; not a Cloudflare or production result**

## Fixed inputs

- suite: `ed25519_yao_phase3_passive_benchmark_v1`
- activation schedule digest:
  `e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25`
- export schedule digest:
  `bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071`
- activation AND gates / tables: `62,716` / `2,006,912` bytes
- export AND gates / tables: `765` / `24,480` bytes
- samples: 20 warm executions after one unreported warm-up
- correctness: every sample decoded and checked the committed RFC 8032 fixture

The kernel batches the four independent garbler AES calls and the two
independent evaluator AES calls for each AND gate. Fixed schedules are validated
and hashed once per process. Activation input labels are sampled with one 32 KiB
OS/WebCrypto request rather than 2,048 small calls.

## Environment

| Field | Value |
| --- | --- |
| Host architecture | Apple `arm64` |
| macOS | `15.7.1` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Node | `v22.13.0` |
| wasm-pack | `0.13.1` |
| Native build | Cargo `--release` |
| WASM build | wasm-pack `--release --target nodejs`, wasm-opt enabled |

## Results

Times cover only fixed Deriver A garbling and fixed Deriver B evaluation. Input
label provisioning, output verification, transport, OT, framing, and lifecycle
work are outside these timings.

| Target / circuit | Garble p50 | Garble p95 | Evaluate p50 | Evaluate p95 | Combined p50 | Combined p95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Native activation | `18.42 ms` | `20.41 ms` | `25.79 ms` | `27.92 ms` | `44.43 ms` | `46.83 ms` |
| Native export | `0.224 ms` | `0.254 ms` | `0.310 ms` | `0.365 ms` | `0.544 ms` | `0.617 ms` |
| Node WASM activation | `133.74 ms` | `140.13 ms` | `79.71 ms` | `80.99 ms` | `209.35 ms` | `222.04 ms` |
| Node WASM export | `1.654 ms` | `1.811 ms` | `1.049 ms` | `1.156 ms` | `2.556 ms` | `2.758 ms` |

The native activation scalar-AES baseline before batching and schedule caching
was approximately `54.14 ms` p50 garbling plus `30.25 ms` p50 evaluation. The
optimized combined p50 is approximately 47% lower.

## Memory surface

| Circuit | A flat arena | B flat arena | Materialized table payload |
| --- | ---: | ---: | ---: |
| Activation | `97,937 B` | `97,937 B` | `2,006,912 B` |
| Export | `17,425 B` | `17,425 B` | `24,480 B` |

Arena values are exact backing-allocation sizes reported by the compiled target.
They exclude vector metadata, input/output label vectors, allocator overhead,
the embedded schedule, and process/runtime memory. The current Phase 3 local
harness materializes the complete table. Phase 5 must replace that ownership
with bounded streaming before claiming a Worker peak-memory result.

## Basic constant-time qualification

The source kernel uses fixed-size loops, branchless label selection, batched
RustCrypto AES, fixed public schedule indices, and an aggregate constant-time
output-label comparison. Garbler and evaluator ceremony owners are one-shot;
their methods consume the state containing the execution delta and domain.

The constant-time analyzer scanned the optimized `arm64` library assembly:

- 1,027 assembly symbols and 6,381 instructions;
- zero division, remainder, square-root, or other error-level variable-time
  instructions;
- 314 branch warnings manually classified as public schedule/count traversal,
  allocation/error handling, CPU-feature dispatch, or one final aggregate
  invalid-output decision after all labels are processed.

The source and native assembly checks support the benchmark qualification only.
The analyzer cannot ingest the final WASM module, and this report makes no
production constant-time or microarchitectural claim. Phase 6B must inspect the
selected final WASM/native artifact and its actual runtime.

## Interpretation

The symmetric-key computation is viable on the native target. Local Node WASM
already consumes about `209-222 ms` for activation garbling plus evaluation,
leaving little room inside the provisional `250 ms` p95 end-to-end target for
OT, cross-account transfer, cold starts, and framing. This does not decide
Phase 13A: Cloudflare's actual engine, placement, stream overlap, and CPU limits
must be measured. It makes WASM kernel optimization and streaming overlap part
of the immediate critical path.

The original Phase 3 benchmark commands below were used to produce this
historical report. Their whole-buffer facades were deliberately deleted after
the Phase 5 streaming replacement passed differential, native-process, and
WASM-host validation. They are no longer runnable entrypoints.

```text
cargo run --manifest-path crates/ed25519-yao/Cargo.toml --release --features passive-benchmark --bin benchmark_passive_yao
wasm-pack build crates/ed25519-yao/wasm-bench --target nodejs --release
node -e '<load pkg and call benchmark_passive_yao_once twenty times>'
```

Current reproduction commands are maintained in the Phase 5 report.
