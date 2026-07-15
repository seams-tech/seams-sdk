# Phase 9B Same-Account Local Benchmark — workers-rs 0.8.5

Date: July 13, 2026

Status: canonical benchmark-only local-workerd evidence for the selected
`workers-rs` 0.8.5 viability dependency. This is a same-account latency lower
bound. It is neither deployed Cloudflare evidence nor a production security or
capacity claim.

## Configuration

- circuit: activation;
- stream profile: 128 KiB;
- topology: two Workers connected through `DERIVER_B` Service Binding;
- protocol transport: one full-duplex streaming POST;
- samples: one first-request observation followed by 50 sequential warm
  ceremonies;
- host: Darwin arm64;
- Rust: 1.96.0;
- `worker-build` and `workers-rs`: 0.8.5;
- Wrangler: 4.105.0;
- compatibility date: July 2, 2026;
- response/log placement fields: strict nullable `deriver_a_colo` and
  `deriver_b_colo`;
- timing clock: Worker `Date.now()`, with milestones relative to Deriver A's
  protocol start;
- table timing boundary: capacity-one outbound-stream backpressure acceptance.
- body-byte timing boundary: raw stream-chunk emission and receipt, before
  envelope decoding and distinct from physical directional EOF.

Wrangler's unused-request-body drain middleware was disabled. Deriver B's
response body intentionally owns and consumes the still-open request stream
after the fetch handler returns; the development middleware would otherwise
try to acquire a second reader for that correctly locked stream.

## Result

All 51 ceremonies completed successfully. A cannot send `BaseChoices` until
B's response headers and `Offer` arrive, while A reaches physical request EOF
only after `Translation`. Completion therefore proves local workerd advanced
B's response before A closed its request.

| Measurement | First request | Warm 50 p50 | Warm 50 p95 | Warm 50 p99 |
| --- | ---: | ---: | ---: | ---: |
| client wall latency | 215.771 ms | 143.418 ms | 147.640 ms | 149.819 ms |
| A Worker elapsed | 189 ms | 140 ms | 145 ms | 147 ms |
| B response headers received | 12 ms | 3 ms | 3 ms | 3 ms |
| first B-to-A body byte received | 13 ms | 3 ms | 3 ms | 3 ms |
| Offer received | 13 ms | 3 ms | 3 ms | 3 ms |
| first A-to-B body byte emitted | 30 ms | 13 ms | 13 ms | 14 ms |
| Extension received | 51 ms | 29 ms | 30 ms | 31 ms |
| first table frame accepted | 71 ms | 36 ms | 37 ms | 39 ms |
| last table frame accepted | 183 ms | 137 ms | 141 ms | 144 ms |
| table-stream duration | 112 ms | 101 ms | 105 ms | 107 ms |
| Translation accepted | 186 ms | 139 ms | 144 ms | 146 ms |
| final A-to-B body byte emitted | 186 ms | 139 ms | 144 ms | 146 ms |
| request direction closed | 186 ms | 140 ms | 144 ms | 146 ms |
| final B-to-A body byte received | 188 ms | 140 ms | 145 ms | 147 ms |
| Returned received | 188 ms | 140 ms | 145 ms | 147 ms |
| response EOF / protocol complete | 189 ms | 140 ms | 145 ms | 147 ms |

The warm client-wall range was 141.889–149.819 ms. One first request is an
observation rather than a statistically meaningful cold-start distribution.
Local workerd reported `deriver_a_colo = "NRT"` and no B-side `Cf` metadata;
the latter was serialized as `deriver_b_colo = null`. These are local runtime
observations and carry no deployed-placement claim.

The phase measurements describe adapter-visible I/O progress. In deployed
Workers, `Date.now()` advances after I/O boundaries. The table duration spans
acceptance of the first through last table envelopes by the capacity-one
outbound stream. Body-byte milestones mark raw stream chunks before envelope
decoding. Neither boundary claims exact network transit time.

## Bytes, Buffers, And Copies

| Per-ceremony measurement | Deriver A | Deriver B |
| --- | ---: | ---: |
| table payload bytes | 2,104,960 | 2,104,960 |
| protocol body bytes | 2,106,524 | 2,106,524 |
| table frame count | 17 | 17 |
| peak table buffer bytes | 262,236 | 131,164 |
| incoming wire bytes | 37,164 | 2,185,420 |
| maximum incoming platform fragment | 4,096 | 4,096 |
| adapter-owned zeroizing ingress copy bytes | 37,164 | 2,185,420 |
| delivered JavaScript view overwrite bytes | 37,164 | 2,185,420 |
| outgoing wire bytes | 2,185,420 | 37,164 |
| peak outgoing envelope bytes | 131,180 | 24,640 |
| known outgoing `workers-rs` copy bytes | 2,185,420 | 37,164 |
| maximum queued outgoing envelopes | 1 | 1 |

Combined directional wire traffic was 2,222,584 bytes per ceremony. Each
direction makes one adapter-owned ingress copy into zeroizing Rust/WASM memory
and one outgoing `workers-rs` copy into the JavaScript stream, totalling
4,445,168 known copied bytes. The delivered ingress views are overwritten for
another 2,222,584 bytes. These counters exclude workerd, JavaScript engine,
network, and platform-internal copies.

The typed protocol ledger and both roles' adapter counters agree exactly:

| Activation/128-KiB byte class | Bytes |
| --- | ---: |
| Half-Gates table payload | 2,104,960 |
| table frame headers | 1,564 |
| stream manifest | 248 |
| table protocol bytes | 2,106,772 |
| table envelope headers | 288 |
| table transport bytes | 2,107,060 |
| ordinary passive OT payloads | 82,112 |
| direct labels, translation, and returned labels | 33,300 |
| control envelope headers | 112 |
| control transport bytes | 115,524 |
| total envelope headers | 400 |
| total A-to-B transport | 2,185,420 |
| total B-to-A transport | 37,164 |
| total A/B transport | 2,222,584 |

There are 25 binary envelopes: 17 table frames, one binary manifest, and seven
control messages. Ordinary passive OT has exactly four messages in four
sequentially dependent one-way rounds: Offer, Choices, Extension, and Masked.
Each role also produces two 216-byte recipient artifacts;
recipient delivery is outside the A/B transport total. The Worker aborts with
`YAOS_AB_WIRE_ACCOUNTING` if either directional adapter counter differs from
the typed ledger. No table or control payload has a JSON, base64, or whole-body
representation.

Secret ingress attaches to each raw Web Stream before generic `workers-rs`
`Body` conversion. A and B expose the bounded machine-readable claim
`incoming_secret_buffer_disposal =
"rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled"`
together with `production_eligible = false`. Local and deployed collectors
require the exact label and copy/overwrite equalities.

## Dependency Revalidation

The exact 0.8.5 raw request, raw response, Service Binding fetch,
`AbortSignal`, and Web Streams implementations were checked before the
secret-ingress refactor. All four same/cross-account A/B artifacts passed
release Worker builds after the change. The same-account pair then completed
all 51 ceremonies through the raw adapter.

The earlier 0.8.4 run remains in
[`phase9b-same-account-report.md`](phase9b-same-account-report.md) as historical
evidence.

## Open Evidence

- deployed Worker disconnect, cancellation, and wrong-peer behavior; the local
  compile-time fault matrix is complete;
- a statistically meaningful cold-start distribution;
- deployed same-account CPU and Cloudflare reservoir-sampled shared-isolate
  memory percentiles plus `exceededMemory` outcomes;
- separate-account HTTPS early response, latency, placement, connection reuse,
  CPU, memory, and cost.
