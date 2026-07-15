# Phase 9B Same-Account Local Benchmark

Date: July 12, 2026

Status: historical benchmark-only local-workerd evidence recorded with
`workers-rs` 0.8.4. This is a same-account latency lower bound, not the
canonical 0.8.5 baseline, deployed Cloudflare evidence, or a production
security/capacity claim.

## Configuration

- circuit: activation;
- stream profile: 128 KiB;
- topology: two Workers connected through `DERIVER_B` Service Binding;
- protocol transport: one full-duplex streaming POST;
- samples: one first-request observation followed by 50 sequential warm
  ceremonies;
- host: Darwin arm64;
- Rust: 1.96.0;
- `worker-build` and `workers-rs`: 0.8.4 (historical baseline);
- Wrangler: 4.105.0;
- bundled workerd release: June 25, 2026;
- compatibility date: July 2, 2026, the newest date accepted by the bundled
  workerd release.

Wrangler's unused-request-body drain middleware was disabled. Deriver B's
response body intentionally owns and consumes the still-open request stream
after the fetch handler returns; the middleware would otherwise attempt to
acquire a second reader for that correctly locked stream.

## Result

All 51 ceremonies completed successfully. A cannot send `BaseChoices` until
its Service Binding fetch has returned B's response and A has decoded `Offer`.
A does not close its request until after `Translation`. A successful ceremony
therefore proves that this local workerd version exposes and advances B's
response before A's request reaches EOF.

| Measurement | First request | Warm p50 | Warm p95 | Warm p99 | Warm max |
| --- | ---: | ---: | ---: | ---: | ---: |
| client wall time | 218.729 ms | 143.966 ms | 149.131 ms | 149.909 ms | 149.909 ms |
| A Worker elapsed time | 193 ms | 141 ms | 145 ms | 148 ms | 148 ms |

The first request is a single observation after server startup. It is not a
statistically sufficient cold-start distribution.

## Bytes and bounded-memory evidence

| Measurement | Deriver A | Deriver B |
| --- | ---: | ---: |
| incoming directional wire bytes | 37,164 | 2,185,420 |
| outgoing directional wire bytes | 2,185,420 | 37,164 |
| largest incoming platform fragment | 4,096 | 4,096 |
| largest outgoing envelope | 131,180 | 24,640 |
| reported peak table buffer | 262,236 | 131,164 |
| known incoming `workers-rs` copy bytes | 74,328 | 4,370,840 |
| known outgoing `workers-rs` copy bytes | 2,185,420 | 37,164 |
| maximum queued outgoing envelopes | 1 | 1 |

The fixed table payload is 2,104,960 bytes across 17 table frames. Total
directional wire traffic is 2,222,584 bytes, including OT and control messages.
Known `workers-rs` boundary copies total 6,667,752 bytes per ceremony: two copy
passes for each generic incoming `Body` and one for each outgoing `StreamBody`.

The largest observed incoming fragment was 4 KiB, so local workerd did not
coalesce or retain the 2.1 MB activation table as one platform chunk. The
reported table-buffer values and copy counters exclude the complete isolate,
workerd internals, JavaScript engine memory, allocator overhead, and unknown
platform-internal copies. They do not prove the 128 MB deployed-isolate gate.

## Open evidence

- Worker-level disconnect, cancellation, trailing-data, and wrong-service
  injection;
- a statistically meaningful cold-start distribution;
- deployed same-account CPU and isolate memory;
- separate-account HTTPS early response, latency, placement, connection reuse,
  CPU, memory, and cost;
- canonical 0.8.5 remeasurement after the reviewed dependency upgrade.
