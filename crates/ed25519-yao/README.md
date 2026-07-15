# Ed25519 Yao

`ed25519-yao` owns validated **draft** protocol and circuit-manifest types for
the fixed Router A/B Ed25519 Yao design. The crate cannot represent a reviewed
or production-active artifact yet.

The only protocol identifier is:

```text
router_ab_ed25519_yao_v1
```

The protocol has two disjoint circuit families and two disjoint output-schema
types:

- `ed25519_yao_activation_v1` uses
  `ed25519_yao_activation_output_schema_v1` for registration, activation,
  recovery, and refresh output derivation. Its schema must contain no
  seed-export wires.
- `ed25519_yao_export_v1` uses `ed25519_yao_export_output_schema_v1` for
  explicitly authorized seed export.

The Rust API exposes `DraftActivationCircuitManifest`,
`DraftExportCircuitManifest`, and `DraftProtocolManifest`. There are no
production manifest aliases and no constructible reviewed-active state. Each
artifact digest role has a distinct validated type, so same-width circuit,
compiler, source-IR, schedule, constants, input-schema, activation-output, and
export-output digests cannot be exchanged accidentally.
`ActivationCircuitArtifactDigests` and `ExportCircuitArtifactDigests` also make
whole-bundle family substitution a type error. The draft aggregate rejects
circuit, schedule, or output-schema digest reuse across families.

## Canonical draft-manifest identity

Each family manifest computes its identity internally as SHA-256 over this
canonical byte sequence, in exact order:

1. Domain/version bytes:
   `seams:router-ab:ed25519-yao:draft-manifest:v1`.
2. One family byte: `0x01` for activation or `0x02` for export.
3. Output-schema identifier length encoded as one big-endian `u64`.
4. Output-schema identifier UTF-8 bytes.
5. Seven raw 32-byte digests: circuit, compiler, source IR, schedule,
   constants, input schema, then the family-specific output schema.
6. Thirteen big-endian `u64` metrics: AND gates, XOR gates, inversion gates,
   total gates, complete circuit depth, AND depth, input wires, output-wire
   references, total logical wires, scheduled gates, peak live wires, encoded
   schedule bytes, then passive Half-Gates table payload bytes. The payload is
   derived as exactly 32 bytes per AND gate.

`DraftActivationManifestDigest32` and `DraftExportManifestDigest32` expose the
results. Their fields and constructors are private, so callers cannot supply or
override a manifest identity.

## Security status

The compile-time `passive-benchmark` feature contains the Phase 3 kernel and the
Phase 4 role-separated viability composition: zeroizing 128-bit labels,
fixed-key AES hashing, free-XOR, Half-Gates, strict pinned schedule parsing,
liveness-slot execution, fresh Chou-Orlandi random base OT, semi-honest IKNP,
joint A/B output coins, private B translation bits, and opaque labels returned
to A. Both fixed families run through the Phase 5 stream in two child OS
processes with disjoint inputs and outputs. Completed roles emit only distinct Client, SigningWorker, or
export-recipient benchmark packages bound to the terminal transcript. Scalar
packages carry checked scalar-to-point commitments, and the recipient harness
verifies `2 * X_client - X_server = A_pub`. The process harness uses exact
binary frames and rejects malformed lengths, family/session mismatches, replay
domains, and trailing bytes.

Phase 5 now has a compile-time-fixed bounded stream grammar with 64, 128, and
256 KiB profiles, explicit AND-table ordinals, exact body/frame counts,
digest chaining, and strict EOF receipts. Its normative layout is recorded in
[`docs/passive-stream-wire-v1.md`](docs/passive-stream-wire-v1.md). The digest
chain detects benchmark corruption; it does not authenticate a peer.

The incremental garbler and evaluator match the whole-buffer runtime under all
three profiles. The bounded streaming path retains at most one
selected-profile table buffer per role, enforces terminal aborts, and requires
actual table-channel EOF before output release. Every fixed profile runs
activation and export in two child OS processes over separate control and
table sockets. Their exact memory, framing, correctness, and local
release-latency results are recorded in
[`docs/phase5-streaming-report.md`](docs/phase5-streaming-report.md).

The separate `passive-wasm-benchmark` feature contains only the shared crypto,
fixed stream grammar, resumable runtime, and Worker-compatible WASM facade. It
excludes native process/I/O adapters and the Phase 3 whole-table WASM surface.
The host must relay the manifest and one frame at a time, confirm A's body
close, then confirm B's exact EOF before any output report exists. The Node
WHATWG-stream harness covers all six family/profile combinations, normal and
delayed producer/consumer scheduling, exact EOF, and separate Rust/WASM plus
JavaScript copy/allocation counters.

The `phase9-role-benchmark` feature exposes six fixed-fixture, fixed-profile
split-role facades for a separate Cloudflare viability harness. A and B consume
one self-framed binary message or directional EOF witness at a time; the public
instruction reports the next expected action, tag, and exact inner length. Its
benchmark-only order, outer envelope, terminal semantics, fixture, and copy
accounting are frozen in
[`docs/passive-role-relay-v1.md`](docs/passive-role-relay-v1.md).

The non-default `local-protocol` feature reuses that exact move-only engine for
Phase 9C local composition. It exposes only the fixed 128 KiB activation/export
roles, accepts real role-local inputs with fresh OS-generated output coins,
preserves role-and-recipient package types, and provides recipient-only package
combination plus public activation receipts. The sole intended dependent is
`router-ab-ed25519-yao`; the feature remains nonproduction and contains no
transport, persistence, Cloudflare, or runtime profile negotiation.

The native feature exposes only bounded, branch-specific Phase 5 facades for
64, 128, and 256 KiB plus the Phase 5 role benchmark binary. Superseded Phase 3
whole-buffer and Phase 4 whole-message facades, binaries, and integration tests
have been deleted; whole-buffer execution remains test-only as a differential
oracle. The WASM feature exposes only the incremental Phase 5 adapter. Neither
feature exposes a generic circuit loader, runtime security-profile negotiation,
or production conversion. Historical Phase 4 measurements and limitations are recorded in
[`docs/phase4-role-separated-report.md`](docs/phase4-role-separated-report.md).

This remains a passive/semi-honest benchmark. Same-account and independent-
account Cloudflare topology measurements remain open. The stream does not
provide transport authentication, replay persistence, recipient encryption,
selected production packages, or an active-security claim. No product, Router,
SDK, or Worker route can call it in a default build. The isolated local adapter
may enable `local-protocol` for Phase 9C only. Production remains blocked on
Phase 13A viability, Phase 6A profile selection, and Phase 6B
implementation/review of the selected suite.

The kernel has source review, native assembly scanning, native measurements,
and local Node WASM measurements. Those checks establish benchmark evidence
only. The final selected native/WASM artifact still requires dedicated
constant-time, secret-lifecycle, composition, and deployment review.

## Boundary policy

There is intentionally no Serde representation. A future wire or artifact
adapter must validate raw lengths and values at its boundary, construct the
field-specific digest types plus `GateMetrics` and `ScheduleMetrics`, derive
`CircuitMetrics` through `CircuitMetrics::new_passive_half_gates`, place
artifact digests into the required family-specific bundle, then pass only those
validated types into draft manifest constructors. Output counts reference wires
already included in the logical wire count.

## Formal verification

The phased scaffold and proof plan is in
[`docs/formal-verification-plan.md`](docs/formal-verification-plan.md). Formal
implementation is viability-first: executable KAT, vector, differential,
parser, and constant-time safeguards track the active benchmark, while deep
profile-security proofs resume only after a Phase 13A `go` selects the surviving
implementation.

## Checks

```bash
cargo fmt --manifest-path crates/ed25519-yao/Cargo.toml -- --check
cargo test --manifest-path crates/ed25519-yao/Cargo.toml --features passive-benchmark
cargo clippy --manifest-path crates/ed25519-yao/Cargo.toml --all-targets --features passive-benchmark -- -D warnings
cargo clippy --manifest-path crates/ed25519-yao/Cargo.toml --features passive-wasm-benchmark --target wasm32-unknown-unknown -- -D warnings
cargo clippy --manifest-path crates/ed25519-yao/wasm-bench/Cargo.toml --target wasm32-unknown-unknown -- -D warnings
wasm-pack build crates/ed25519-yao/wasm-bench --target nodejs --release --out-dir pkg-phase5
node crates/ed25519-yao/wasm-bench/scripts/run_phase5_streaming.mjs
PHASE5_SLOW_PRODUCER_MS=1 PHASE5_SLOW_CONSUMER_MS=1 node crates/ed25519-yao/wasm-bench/scripts/run_phase5_streaming.mjs
```
