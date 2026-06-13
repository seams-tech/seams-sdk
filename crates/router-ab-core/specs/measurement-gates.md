# Measurement Gates

This spec defines the Phase 6 measurement evidence for the Router/A/B
derivation primitive selection and release gates.

## Current Gate Snapshot

Selected production primitive: `mpc_threshold_prf_v1`.

The Rust API `candidate_measurement_gate_report_v1()` exposes the current gate
state.

Completed gates:

- `native_adapter_latency_baseline`
- `adapter_round_trip_shape`
- `wasm32_library_build`
- `candidate_a_cryptographic_path_native_latency`
- `candidate_b_cryptographic_path_native_latency`
- `cryptographic_path_native_latency`

Blocked gates:

- `deployable_wasm_or_worker_bundle_size`
- `cloudflare_worker_runtime_latency`

## Adapter Round-Trip Shape

Both Candidate A and Candidate B currently have the same adapter round-trip
shape for registration, export, and refresh:

- client-visible Router requests: 1
- Router invocations: 1
- Deriver A invocations: 1
- Deriver B invocations: 1
- direct A/B coordination round trips: 0
- deriver output packages: 4

This shape assumes the Router forwards role-specific encrypted envelopes to A
and B, then relays encrypted client and SigningWorker output packages back to
the client and active SigningWorker.

## Native Adapter Latency

Captured command:

```text
cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates
```

Captured environment:

- `rustc 1.86.0`
- host: `aarch64-apple-darwin`
- machine: `arm64`

Current measurements are adapter metadata-path timings. They exclude final
cryptographic PRF evaluation, hash-to-scalar, DLEQ verification, envelope
encryption, HTTP transport, Workers startup, storage, and KMS access.

## Candidate A Native Crypto Latency

Captured command:

```text
cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates
```

Captured environment:

- `rustc 1.86.0`
- host: `aarch64-apple-darwin`
- machine: `arm64`

Current Candidate A measurements:

- `router_ab_mpc_prf_purpose_binding_plan_v1`: 2.5788 us
- `router_ab_mpc_prf_crypto_evaluate_partial_with_dleq_v1`: 101.81 us
- `router_ab_mpc_prf_crypto_verify_partial_dleq_v1`: 123.21 us
- `router_ab_mpc_prf_crypto_combine_verified_partials_v1`: 262.91 us
- `router_ab_mpc_prf_crypto_two_proofs_and_combine_v1`: 466.80 us

These measurements include the real `threshold-prf` Ristretto/SHA-512/DLEQ
path through Router/A/B purpose-bound context bytes. They still exclude
envelope encryption, HTTP transport, Workers startup, storage, and KMS access.

## Candidate B Native Crypto Latency

Captured command:

```text
cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates
```

Captured environment:

- `rustc 1.86.0`
- host: `aarch64-apple-darwin`
- machine: `arm64`

Current Candidate B measurements:

- `router_ab_split_root_crypto_derive_output_share_v1`: 2.4611 us
- `router_ab_split_root_crypto_combine_output_shares_v1`: 6.5834 us

These measurements include the real `HashToScalarSha512V1` output-share
derivation and Curve25519 scalar-share combine path. They still exclude
envelope encryption, HTTP transport, Workers startup, storage, and KMS access.

## Wasm Compatibility

Completed commands:

```text
cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-unknown-unknown
cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-wasip1
```

Both library builds pass. The current artifact is an `rlib`, so it is only a
compatibility signal. It is not a deployable Worker bundle.

## Blocked Gate Requirements

### Deployable Wasm Or Worker Bundle Size

The protocol crate currently emits `rlib` artifacts. The bundle-size gate
requires one of:

- a Worker adapter crate that imports this protocol crate
- a `cdylib` target with exported wasm entrypoints

The size must be measured after optimization using the same build profile
planned for deployment.

### Cloudflare Worker Runtime Latency

Worker runtime latency requires an adapter benchmark deployed to, or executed
under, the intended Workers runtime.

Minimum measurements:

- p50 and p95 registration ceremony adapter latency
- p50 and p95 export ceremony adapter latency
- p50 and p95 refresh ceremony adapter latency
- cold-start or first-request measurement if the adapter bundle changes

## Release Rule

The production primitive is selected as `mpc_threshold_prf_v1`. The blocked
gates remain release gates for Cloudflare deployment. A production Worker
release cannot claim size or runtime readiness until those measurements have
concrete evidence or an explicit product/security decision accepts the missing
evidence as out of scope for the first release.
