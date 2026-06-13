# Candidate Comparison

The implementation compared two candidate families before selecting the
production primitive.

The Phase 0A side-by-side evidence record is
[phase-0a-decision-record.md](phase-0a-decision-record.md).

## Candidate 1: MPC Threshold PRF

Each deriver holds a role-specific PRF share. A/B evaluate partials over the
same canonical context and transcript binding. The protocol combines verified
partials into output material scoped to the requested recipient.

Current answers:

- Proof format: reuse `threshold-prf` fixed-width partial, share commitment,
  and DLEQ proof wires through a Router/A/B adapter.
- Purpose binding: `MpcPrfPurposeBindingPlanV1` defines deriver-neutral
  context bytes for `router-ab/x_client_base/v1` and
  `router-ab/x_relayer_base/v1`.
- Combiner placement: final recipient combines plaintext partials. Router sees
  only public metadata, encrypted packages, commitments, and receipts.
- Role visibility: covered in
  [candidate-mpc-threshold-prf.md](candidate-mpc-threshold-prf.md) and
  [leakage-analysis.md](leakage-analysis.md).
- A/B coordination: no direct A/B coordination messages in the basic partial
  path.
- Reuse decision: reuse `threshold-prf` cryptographic internals through a
  narrow adapter. `threshold-prf` now supports the Router/A/B purpose labels
  and canonical scalar output required by this adapter.

## Candidate 2: Split Root Derivation

A and B hold independent split roots. Each role derives output shares from its
own root, the canonical context, and the transcript binding. Recipient-specific
outputs are released only to the intended recipient.

Current answers:

- Root structure: independent A/B split roots with recipient-side output-share
  combination.
- Output-share path: `HashToScalarSha512V1` derives role-local Curve25519
  scalar shares from root-share material plus the transcript-bound output
  request; recipients add canonical scalar shares.
- Refresh: new epoch creates a new verified output relation. Preserving refresh
  is unavailable in the current split-root adapter.
- Minimum Level C: protects transcript and delivery binding; it does not prove
  output-share correctness or prevent deriver bias by itself.
- Stronger path: public-share-binding or address verification must catch biased
  output relations before activation.
- A/B coordination: no direct A/B coordination messages in the basic
  output-share path.

## Current Comparison

| Dimension | Candidate A: MPC Threshold PRF | Candidate B: Split Root |
| --- | --- | --- |
| Round trips, adapter model | Router to A/B, deriver outputs to recipients; no direct A/B coordination; one Router-facing client request in the Router design | Router to A/B, deriver outputs to recipients; no direct A/B coordination; one Router-facing client request in the Router design |
| Cryptographic dependency | Reuses `threshold-prf` Ristretto/Shamir/DLEQ internals with Router/A/B purpose-label compatibility | Implements SHA-512 hash-to-scalar and Curve25519 scalar addition for measurement; root generation and bias resistance still require review |
| Correctness hardening | DLEQ proof path already exists in `threshold-prf`; adapter proof plan is typed | Needs root-generation and anti-bias mechanism; likely needs public-share-binding or address verification gate |
| Refresh | Threshold refresh can preserve the logical PRF key in the underlying model; Router/A/B adapter still needs purpose binding | Refresh creates a new verified output relation; preserving refresh is unavailable |
| Implementation complexity | Higher integration complexity due to proof and purpose-binding adapter | Lower adapter and latency cost; higher protocol risk around bias and refresh semantics |
| Leakage | Completed adapter leakage table; Router excludes plaintext partials | Completed adapter leakage table; Router excludes roots and output-share wires |
| Proof effort | Reuse existing `threshold-prf` proof concepts plus Router/A/B adapter proofs | Requires new formula, bias, and refresh reasoning |

## Native Adapter Benchmark Snapshot

Environment:

- `rustc 1.86.0`
- host: `aarch64-apple-darwin`
- machine: `arm64`
- command: `cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates`

These measurements include both adapter metadata-path timings and native
cryptographic-path timings. They exclude envelope encryption, HTTP transport,
Workers startup, and storage/KMS access.

| Benchmark | Median |
| --- | ---: |
| `router_ab_context_encode_v1` | 166.90 ns |
| `router_ab_mpc_prf_signer_input_validate_v1` | 30.581 ns |
| `router_ab_mpc_prf_partial_verification_plan_v1` | 2.5027 us |
| `router_ab_mpc_prf_purpose_binding_plan_v1` | 2.5788 us |
| `router_ab_mpc_prf_crypto_evaluate_partial_with_dleq_v1` | 101.81 us |
| `router_ab_mpc_prf_crypto_verify_partial_dleq_v1` | 123.21 us |
| `router_ab_mpc_prf_crypto_combine_verified_partials_v1` | 262.91 us |
| `router_ab_mpc_prf_crypto_two_proofs_and_combine_v1` | 466.80 us |
| `router_ab_mpc_prf_combiner_plan_v1` | 5.5476 us |
| `router_ab_split_root_signer_input_validate_v1` | 30.109 ns |
| `router_ab_split_root_combiner_plan_v1` | 5.4908 us |
| `router_ab_split_root_crypto_derive_output_share_v1` | 2.4611 us |
| `router_ab_split_root_crypto_combine_output_shares_v1` | 6.5834 us |
| `router_ab_split_root_refresh_plan_v1` | 454.64 ns |

Interpretation:

- Adapter metadata overhead is negligible for both candidates compared with
  expected network, encryption, storage, and cryptographic costs.
- Candidate A's native cryptographic proof path is now measured through
  Router/A/B purpose-bound `threshold-prf` contexts.
- Candidate B's native cryptographic path is much faster locally because it is
  a direct hash-to-scalar plus scalar-addition design.
- Candidate A still has the clearer correctness-hardening story because the
  DLEQ proof path already exists.
- Candidate B still has unresolved malicious bias, root-generation, and
  preserving-refresh risks.

## Wasm Compatibility Snapshot

Commands:

- `cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-unknown-unknown`
- `cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-wasip1`

Results:

- `wasm32-unknown-unknown` library build passed.
- `wasm32-wasip1` library build passed.
- The crate currently produces `rlib` artifacts around 4.2 MiB for each target.
- No deployable `.wasm` bundle is produced yet because this crate is an `rlib`
  protocol crate. Real bundle-size comparison requires a Worker adapter or
  `cdylib` target.

## Production Selection

Selected production primitive: `mpc_threshold_prf_v1`.

Candidate A is the production path because Router/A/B purpose binding is wired
into `threshold-prf`, native proof-path latency is sub-ms, and the proof
adapter gives a clearer correctness-hardening, refresh-continuity, and
formal-verification path.

Candidate B remains comparison/prototype material. Its local crypto path is much
faster, but root generation, anti-bias, preserving-refresh semantics, and
address-verification activation still need a separate decision record before it
can be reconsidered for production.

The current typed measurement-gate snapshot is exposed by
`candidate_measurement_gate_report_v1()` and documented in
[measurement-gates.md](measurement-gates.md).

Remaining release gates for the selected Candidate A path:

- wasm32 bundle-size and runtime numbers for deployable artifacts
- Cloudflare Worker runtime numbers if Workers are the first deployment target
- frozen Router/A/B Candidate A vectors
- decision on whether Candidate A DLEQ verification ships in the first
  production path or remains stronger hardening after Minimum Level C

## Production Release Gate

The selected production path must have:

- committed vectors
- leakage-analysis answers
- registration/export/refresh flow diagrams
- benchmark numbers for local and Workers-compatible builds
- proof inventory entries
- source guards for forbidden joined-state construction
