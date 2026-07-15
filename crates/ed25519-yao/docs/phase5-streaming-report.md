# Phase 5 Bounded Streaming Report

Date: 2026-07-12

Status: local viability evidence only. The implementation is benchmark-only,
passive/semi-honest, and unavailable to production routes.

## Outcome

Phase 5 replaces the Phase 4 whole-table process frame with incremental
garbling, a fixed binary stream, incremental evaluation, and a dedicated
A-to-B table channel. The 64, 128, and 256 KiB profiles have frozen manifests,
frame encodings, parser tests, and whole-buffer differential runtime tests. The
64, 128, and 256 KiB profiles all run end to end in two child OS processes and
have release-mode latency measurements. The profile choice changes framing and
bounded memory only; one generic protocol runner implements every profile.

## Corrected one-pass order

Phase 5 uses separate control and table channels. Its dependency order is:

1. B sends the fresh base-OT offer on the control channel.
2. A sends base-OT choices and A's direct input labels on the control channel.
3. B sends the OT extension matrix on the control channel.
4. A sends the masked B-input labels on the control channel. OT is complete.
5. A sends the 248-byte manifest and framed table body on the dedicated table
   channel while garbling. B validates and evaluates each frame as it arrives.
6. A closes the table channel, finalizes its local stream transcript, and may
   enqueue B's private-output translation bits on the independent control
   channel. A does not wait for an extra P0 EOF acknowledgement.
7. B requires exact table EOF and finalizes the same stream transcript before
   reading or using the translation bits and before any output release.
8. B decodes only its output share and returns A's opaque selected output
   labels, bound to the post-translation transcript.

Translation must follow the complete table and its exact EOF. A derives B's
translation bits from final output-wire labels, which do not exist until the
last circuit gate has been garbled. Moving translation before the table would
require retaining the whole table or performing a second deterministic
garbling pass. The manifest's pre-stream transcript therefore ends after the
masked labels; translation is bound to the completed stream transcript.

## Frozen framing metrics

Every stream starts with a 248-byte manifest. Each frame adds a 92-byte header
to its payload. `body_bytes` includes frame headers and table payload, while
`total table-channel bytes` also includes the opening manifest.

| Family | Profile | Maximum payload | Frames | Table payload | Header bytes | Body bytes | Total table-channel bytes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Activation | 64 KiB | 65,536 | 33 | 2,104,960 | 3,036 | 2,107,996 | 2,108,244 |
| Activation | 128 KiB | 131,072 | 17 | 2,104,960 | 1,564 | 2,106,524 | 2,106,772 |
| Activation | 256 KiB | 262,144 | 9 | 2,104,960 | 828 | 2,105,788 | 2,106,036 |
| Export | 64 KiB | 65,536 | 1 | 40,800 | 92 | 40,892 | 41,140 |
| Export | 128 KiB | 131,072 | 1 | 40,800 | 92 | 40,892 | 41,140 |
| Export | 256 KiB | 262,144 | 1 | 40,800 | 92 | 40,892 | 41,140 |

Activation contains 65,780 consecutive 32-byte AND-table records. Under every
profile, the final frame contains 244 records or 7,808 bytes. Export contains
1,275 records and fits in one 40,800-byte frame under every profile. Control
messages and recipient packages are outside the table-channel totals.

## Bounded-memory and copy architecture

Deriver A walks the fixed schedule once. It retains the live garbling arena and
one `Zeroizing<Vec<u8>>` right-sized to the smaller of the family table and the
compile-time chunk profile. The runtime passes a borrowed chunk directly to
`TableStreamSink`; the sink computes the header and digests and writes the
borrowed bytes without owning, copying, or accumulating another table buffer.
After the write completes, the runtime zeroizes and reuses the same allocation.

Deriver B's `TableStreamSource` owns one profile-bounded payload allocation and
one 92-byte header. It validates the header before reading the declared
payload, then verifies the complete payload digest before exposing any table
record. It lends the validated frame to the evaluator, which walks borrowed
32-byte record slices without per-record allocation or a transport callback.
The source zeroizes the complete borrowed payload when the consumer returns or
panics, then reuses the allocation for the next frame.

The process profiles record these live payload peaks on both roles:

| Family | Profile | A peak live table payload | B peak live table payload |
| --- | --- | ---: | ---: |
| Activation | 64 KiB | 65,536 | 65,536 |
| Activation | 128 KiB | 131,072 | 131,072 |
| Activation | 256 KiB | 262,144 | 262,144 |
| Export | 64 KiB | 40,800 | 40,800 |
| Export | 128 KiB | 40,800 | 40,800 |
| Export | 256 KiB | 40,800 | 40,800 |

Both roles right-size their allocation to the smaller of the family table and
profile maximum, and the reported memory metric records actual allocated
capacity. Neither role materializes the complete activation table. The table
does not pass through the client or Router, and there is no text or whole-body
encoding path in the Rust stream adapter.

The transport-neutral runtime is a resumable typestate machine. A yielded
chunk owns its continuation and must be resumed or destroyed before another
chunk can be produced. B accepts a borrowed, family/profile-typed validated
frame. A cannot expose translation state until its host confirms body close,
and B cannot expose output labels until its host confirms exact EOF. Native I/O
and WASM hosts mint the same move-only exact-completion witness through their
separate close/EOF transitions.

## True child-process results

The end-to-end harness starts independent Deriver A and Deriver B child
processes with disjoint role inputs. It uses one Unix domain socket for compact
control messages and another for the table stream. Each ceremony receives a
fresh OS-random session identifier and fresh output coins. A closes its only
table writer after the final frame; B cannot receive a terminal receipt until
the source performs the exact one-byte EOF check.

Both activation and export reconstruct the expected fixture output only in the
parent recipient harness after both roles exit. A and B emit only their typed
recipient packages, agree on the terminal transcript, and report identical
framing and live-table metrics.

| Family | Profile | Table payload | Body bytes | Frames | Peak live table payload |
| --- | --- | ---: | ---: | ---: | ---: |
| Activation | 64 KiB | 2,104,960 | 2,107,996 | 33 | 65,536 |
| Activation | 128 KiB | 2,104,960 | 2,106,524 | 17 | 131,072 |
| Activation | 256 KiB | 2,104,960 | 2,105,788 | 9 | 262,144 |
| Export | 64 KiB | 40,800 | 40,892 | 1 | 40,800 |
| Export | 128 KiB | 40,800 | 40,892 | 1 | 40,800 |
| Export | 256 KiB | 40,800 | 40,892 | 1 | 40,800 |

## Release latency and Phase 4 comparison

Environment: Apple arm64 local host, optimized Rust release build, two child OS
processes connected by local Unix domain sockets, 20 iterations per family and
profile.
Process startup, protocol execution, recipient-package construction, and
package serialization are included. These are local-host wall measurements;
they are not Cloudflare latency or Worker CPU claims.

| Family | Profile | Phase 5 p50 | Phase 5 p95 | Phase 4 p50 | Phase 4 p95 | p50 change | p95 change |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Activation | 64 KiB | 65.872 ms | 73.145 ms | 90.498 ms | 91.658 ms | -24.626 ms (-27.21%) | -18.513 ms (-20.20%) |
| Activation | 128 KiB | 66.344 ms | 68.212 ms | 90.498 ms | 91.658 ms | -24.154 ms (-26.69%) | -23.446 ms (-25.58%) |
| Activation | 256 KiB | 68.041 ms | 69.465 ms | 90.498 ms | 91.658 ms | -22.457 ms (-24.81%) | -22.193 ms (-24.21%) |
| Export | 64 KiB | 22.964 ms | 23.297 ms | 32.977 ms | 33.394 ms | -10.013 ms (-30.36%) | -10.097 ms (-30.24%) |
| Export | 128 KiB | 22.972 ms | 24.577 ms | 32.977 ms | 33.394 ms | -10.005 ms (-30.34%) | -8.817 ms (-26.40%) |
| Export | 256 KiB | 22.968 ms | 23.251 ms | 32.977 ms | 33.394 ms | -10.009 ms (-30.35%) | -10.143 ms (-30.37%) |

The Phase 4 baseline is package-inclusive and uses one whole-table process
frame. The Phase 5 benchmark is also package-inclusive and replaces that frame
with incremental runtime and transport. All profiles improve materially on
this local host. The three export profiles are structurally identical because
the 40,800-byte table fits in one frame. Activation has no decisive local
winner: 64 KiB had the lowest p50, while 128 KiB had the lowest p95 in this
sample. Cloudflare measurements are required before attributing any delta to a
deployment topology or selecting a chunk profile.

## Worker-compatible WASM streaming evidence

The `passive-wasm-benchmark` feature excludes native process/I/O adapters and
the old Phase 3 whole-table WASM facade. Its exported session is driven through
manifest out/return, one frame out/return at a time, outbound-body close,
inbound exact EOF, and then a scalar-only report. The Node harness relays frames
through a WHATWG `TransformStream` with a high-water mark of one and yields the
event loop independently for producer and consumer. It never accumulates a
body or joins frame arrays.

The generated WASM ABI copies each returned `Uint8Array` out of linear memory
and each accepted `Uint8Array` back into linear memory. The harness additionally
performs one explicit JavaScript transport-ownership copy per manifest/frame.
The WASM adapter also constructs one Rust-owned canonical wire `Vec` per frame.
`runtime_chunk_to_wire_copy_bytes` counts only table payload bytes copied from
A's reusable runtime chunk into that wire allocation. It excludes each 92-byte
header write, manifest construction, wasm-bindgen ABI copies, and JavaScript
copies. All adapter copies are separate from the transport-neutral runtime,
whose host-boundary copy count remains zero.

| Family/profile | Frames | Rust frame-allocation peak | Runtime chunk-to-wire payload copy | Peak simultaneous JS wire bytes | WASM-to-host frame bytes | Host-to-WASM frame bytes | Explicit JS transport-copy bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Activation, 64 KiB | 33 | 65,628 | 2,104,960 | 131,256 | 2,107,996 | 2,107,996 | 2,107,996 |
| Activation, 128 KiB | 17 | 131,164 | 2,104,960 | 262,328 | 2,106,524 | 2,106,524 | 2,106,524 |
| Activation, 256 KiB | 9 | 262,236 | 2,104,960 | 524,472 | 2,105,788 | 2,105,788 | 2,105,788 |
| Export, all profiles | 1 | 40,892 | 40,800 | 81,784 | 40,892 | 40,892 | 40,892 |

Each run also copies the 248-byte manifest once in each WASM direction and once
in JavaScript. Rust makes exactly one wire-frame allocation per frame; its
cumulative allocation bytes equal `body_bytes`. A writes every table byte once
into its reusable runtime chunk, and B decodes exactly 65,780 activation or
1,275 export records without a per-record allocation.

The following optimized local Node measurements are single-run,
scheduling-sensitive evidence from the WHATWG-stream harness. They are useful
for gross regression detection and chunk-scheduling comparison on one host.
They are not p50/p95 data or Cloudflare Worker latency claims.

| Family/profile | First frame | Final frame | Evaluation complete | Transcript finalized | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Activation, 64 KiB | 7.728 ms | 232.457 ms | 233.069 ms | 234.757 ms | 235.068 ms |
| Activation, 128 KiB | 9.298 ms | 225.764 ms | 226.412 ms | 226.858 ms | 226.962 ms |
| Activation, 256 KiB | 20.110 ms | 226.541 ms | 227.118 ms | 227.525 ms | 227.636 ms |
| Export, 64 KiB | 3.381 ms | 3.381 ms | 5.161 ms | 5.331 ms | 5.380 ms |
| Export, 128 KiB | 3.106 ms | 3.106 ms | 4.814 ms | 4.901 ms | 4.949 ms |
| Export, 256 KiB | 3.105 ms | 3.105 ms | 4.836 ms | 4.920 ms | 4.968 ms |

With an injected one-millisecond delay before every producer and consumer
operation, the same structural assertions pass. Activation totals were
329.966, 276.248, and 254.291 ms for 64, 128, and 256 KiB; export totals were
10.292, 10.296, and 10.449 ms. This demonstrates real suspension and
backpressure across every frame, including exact EOF, without changing the
transcript, output, byte, or allocation counts.

## Validation and terminal-abort coverage

The current Phase 5 checks cover:

- canonical manifest and frame encodings for all three compile-time chunk
  profiles and both circuit families;
- family, chunk, session, gate-domain, circuit, schedule, and pre-stream
  transcript binding;
- exact sequence, AND-table ordinal continuity, previous-frame chaining,
  payload alignment, expected non-final and final sizes, and body totals;
- malformed magic, version, type, reserved bytes, ranges, lengths, and payload
  digests;
- duplicate, reordered, truncated, overlong, and trailing streams;
- one-byte short reads and writes, header and payload truncation, transport
  disconnect, and exact allocation bounds for every fixed profile;
- deterministic `TimedOut` and `WouldBlock` reads and writes that terminally
  poison or abort the body, zeroize owned read buffers, and cannot mint an
  exact-EOF receipt;
- terminal sink poisoning after a size or transport failure, with no retry or
  recovery branch;
- zeroization of borrowed frame buffers after normal, error, and panic exits;
- incremental activation and export output equivalence with the whole-buffer
  runtime under 64, 128, and 256 KiB profiles;
- early table exhaustion, extra records, receipt/counter mismatch, and sink
  transport failures in the incremental runtime;
- activation and export correctness, transcript agreement, package boundaries,
  exact metrics, and exact table EOF across every fixed profile in two actual
  child processes; and
- transport-neutral WASM session states that yield at each outbound or inbound
  frame, require explicit body-close/EOF transitions, and record boundary copy
  bytes separately from the zero-copy Rust runtime counters;
- normal plus delayed producer/consumer WHATWG-stream scheduling, with an
  independently observed stream `done` event before B's EOF transition.

Source guards reject whole-table allocation in the sink and table transport via
JSON, base64, `arrayBuffer`, JavaScript text, `post_service_json`, or Router
relay. The native and WASM feature closures pass strict Clippy independently.

Within the process harness, only `TableStreamSource::finish` combines completed
decoder state with an actual transport EOF check. The move-only exact receipt
is family/profile bound. Output translations and labels remain inaccessible
until the resumable runtime consumes that receipt. The EOF-writer and exact-EOF
reader traits are sealed. Public native B benchmark facades accept only the
library-owned Unix reader, so memory cursors and custom readers cannot claim a
transient zero-length read as exact EOF. The child harness uses the matching
library-owned Unix half-close writer. These local guarantees do not provide
peer authentication.

## Security and production boundary

The v1 digest chain binds ordering and detects stream corruption in the local
benchmark. SHA-256 framing does not authenticate A, B, the manifest, or any
frame. The current OT and composition support only the passive/semi-honest
benchmark claim. The local Unix sockets do not model independent Cloudflare
administrative domains, TLS identity, signed manifests, or session MACs.

Phase 6B must supply the selected production profile's authenticated peer
handshake, signed opening manifest, session authentication, replay and
lifecycle enforcement, timeout policy, authenticated terminal transcript
roots, recipient encryption, and reviewed release gates. No product, Router,
SDK, or Worker route can call this stream in a default build.

## Phase 5 exit and Phase 9 handoff

The local Phase 5 viability slice is complete: every profile has native
two-process correctness and latency evidence, the transport-neutral WASM path
has bounded backpressure and copy accounting, and first-frame, final-frame,
evaluation, and transcript landmarks are recorded above. More granular native
socket, OT, translation, returned-label, and package landmarks belong in the
Phase 9 deployment observer rather than clocks inside the protocol machines.

Phase 9 must benchmark same-account Cloudflare Service Bindings and
independent-account HTTPS, including p50/p95/p99 wall time, per-role CPU,
memory, bytes, failures, detailed landmarks, and cost inputs.

The Cloudflare topology results, rather than the local Unix-socket improvement,
decide the Phase 13A viability gate.
