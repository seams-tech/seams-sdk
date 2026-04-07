# Succinct Garbling Spec

Date updated: April 5, 2026

This document is the single active spec for the fixed-function succinct
garbling / HSS work in this crate.

## Objective

Build a fixed-function succinct-garbling / HSS protocol for the hidden
Ed25519 seed-expansion step used by the stateless shared-root model.

The target stays intentionally narrow:

- one fixed hidden conversion:
  - shared `y_client`, `y_relayer`
  - `d = LE32(y_client + y_relayer mod 2^256)`
  - `h = SHA-512(d)`
  - `a = clamp(h[0..31]) mod l`
- one output projection:
  - reconstructed base signing shares
  - public key `A = [a]B`
- one product goal:
  - make the hidden `d -> a` path fast enough for registration, unlock,
    signing-session creation, export, and recovery while materially beating
    cached GC

This crate is not solving generic threshold signing. It is solving one
specific hidden conversion problem inside the Ed25519 shared-root lifecycle.

Deployment constraint:

- the browser/client runtime for this fixed-function path must stay small enough
  to ship as a dedicated wasm artifact
- so any protocol or implementation change should now be judged both by
  correctness and by browser artifact size

## Domain Context

The domain-specific constraints are:

- the canonical secret must be a standard Ed25519 seed `d`
- export must remain compatible with standard NEAR `ed25519:` private-key
  export
- signing uses threshold shares of the Ed25519 signing scalar `a`
- neither the client nor the server may see plaintext `d`
- neither the client nor the server may see plaintext `a`
- the product must keep one Ed25519 lifecycle, not separate export and signing
  key lifecycles

That means the hard part is the hidden nonlinear conversion:

- root-share domain:
  - client holds `y_client`
  - server holds `y_relayer`
- canonical seed:
  - `d = LE32(y_client + y_relayer mod 2^256)`
- signing scalar:
  - `a = clamp(SHA-512(d)[0..31])`
- reconstructed signing shares:
  - derived from the same hidden `a`

## Revised Product Architecture

The current product target is:

- the client derives its hidden inputs from `PRF.output` plus canonical
  account context
- the server derives its hidden inputs from server-held roots plus the same
  canonical context
- HSS performs the hidden joint `d -> SHA-512(d) -> clamp -> a` conversion and
  output-share projection whenever the product needs fresh signing-share
  reconstruction
- no durable wrapped `x_client_base` is stored on the client

So this path is for:

- registration
- login / unlock
- signing-session creation
- export
- recovery

It is not the per-signature hot path after a session is already open.

## Non-Negotiable Invariants

The implementation must preserve all of the following:

- one canonical public key per
  `(orgId, accountId, keyPurpose, keyVersion)`
- one shared-root lifecycle
- one export model based on canonical seed `d`
- one signing model based on threshold shares of `a`
- no alternate local-only Ed25519 lifecycle
- no client-visible plaintext `d`
- no server-visible plaintext `d`
- no client-visible plaintext `a`
- no server-visible plaintext `a`

If a candidate violates any of those, it is out of scope.

## Fixed Ideal Functionality

Private inputs:

- client:
  - `y_client in Z_(2^256)`
  - `tau_client in F_l`
- server:
  - `y_relayer in Z_(2^256)`
  - `tau_relayer in F_l`

Internal computation:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`
- `A = [a]B`

Outputs:

- client learns `x_client_base`
- server learns `x_relayer_base`
- both learn `A`

Invariant:

- `a = 2 * x_client_base - x_relayer_base mod l`

Security goal:

- neither side learns plaintext `d`
- neither side learns plaintext `a`
- each side learns only its own reconstructed base share plus public
  verification data

## Protocol Mental Model

This protocol has two hidden paths that meet at the output-share projector.

Seed path:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

Share path:

- `tau_client + tau_relayer -> tau`

Output-share projection:

- `x_client_base = a + tau`
- `x_relayer_base = a + 2 * tau`

Important distinction:

- `d` is the canonical hidden seed
- `a` is the canonical hidden signing scalar derived from `d`
- `tau` is a hidden rerandomization value
- `x_client_base` and `x_relayer_base` are the reconstructed signing shares

## HSS and OT Split

For the current DDH baseline, the primitive HSS surface is:

- `KeyGen`
- `Share`
- `EvalAdd`
- `EvalMult`
- `Decode`

Role split:

- OT is the private input-delivery mechanism for client-owned bits
- HSS is the hidden-computation mechanism once those inputs are represented as
  hidden shared values

## Protocol Layers

### 1. Input-share layer

Responsibilities:

- accept hidden `y_client` and `y_relayer`
- bind them to canonical context
- define private input delivery and context binding

### 2. Nonlinear expansion layer

Responsibilities:

- evaluate the fixed hidden function
  `shared y_client, y_relayer -> d -> SHA-512(d) -> clamp -> a`
- provide the fixed-function hidden evaluator
- define CPU fallback and accelerator-aware execution shape

### 3. Output-share layer

Responsibilities:

- combine hidden `a` with hidden `tau`
- emit:
  - `x_client_base`
  - `x_relayer_base`
  - `A`

## Runtime Boundary Requirement

The live implementation now enforces a runtime split that matches the role
model:

- browser/client runtime contains evaluator-facing HSS code only
- relay/server runtime contains garbler-facing HSS code only

So the spec boundary is no longer abstract. It is reflected directly in the
build outputs.

Current browser HSS artifact baseline:

- original broad browser HSS wasm: `1,163,476` bytes
- current dedicated browser HSS wasm: `262,409` bytes

That reduction is large enough that future changes should preserve the split
unless a replacement is clearly better on both security and size.

## Chosen Backend

The active backend family is the size-optimized prime-order-group
instantiation.

Reason:

- artifact size is the deciding axis for this track
- it is the smallest published family that still aligns with the real product
  question
- the crate already implements the prime-order stack end to end

Current backend-family estimates still kept in code:

- prime-order size-optimized: `138,256` bytes
- prime-order compute-optimized: `5,320,016` bytes

Those backend-family estimates are still useful for internal comparison, but
the product-facing browser artifact is now dominated by the compiled runtime,
wire, and evaluator machinery around the chosen prime-order path. That is why
the current optimization priority is browser artifact size rather than backend
profile tuning alone.

The earlier Paillier and lattice families were removed from the active
codebase because their public evaluator payloads were prohibitively large for
this track.

## Candidate Shape

Cross-session template artifact:

- canonical `context_binding`
- stable `candidate_digest`
- stable `round_template_digest`
- backend-specific fixed-function artifact summary

Default artifact:

- structured sectioned artifact for the prime-order size-optimized backend
- explicit sections for:
  - header
  - context descriptor
  - `2^256` addition template
  - message-schedule template
  - round constants
  - round-template blocks
  - clamp/reduce template
  - output-projector template
  - grouped public-data window section

Per-run public control:

- `client_input_commitment`
- `server_input_commitment`
- `run_binding`

Private inputs:

- client: `y_client`, `tau_client`
- server: `y_relayer`, `tau_relayer`

Hidden internal state:

- `a`

Outputs:

- client: `x_client_base`
- server: `x_relayer_base`
- public: `A`

## High-Level Flow

Prepare once for a canonical context:

1. build the context-bound artifact
2. compile it into a hidden-eval program
3. prepare the HSS backend state and evaluation key
4. prepare OT offer material for `y_client_bits` and `tau_client_bits`

Per run:

1. client derives `y_client` and `tau_client`
2. client prepares blinded OT requests for its selected branches
3. server derives `y_relayer` and `tau_relayer`
4. server resolves OT requests and contributes hidden server input material
5. evaluator reconstructs client-owned hidden bundles from its local OT state
   plus garbler-returned material
6. evaluator executes the fixed hidden-eval program
7. output-share projection emits hidden `x_client_base` and
   `x_relayer_base`
8. each side opens only its own output share plus public verification data

## Security Boundary

The deployed protocol must preserve this rule:

- the evaluator may evaluate on hidden server input
- the evaluator must not receive enough material to decode server input into
  plaintext

That means:

- no non-export production wire type may carry both halves of a hidden
  server-owned value in reconstructable form
- joined hidden values must stay confined to trusted simulation, explicit
  debug/profiling paths, or internal computation states that never cross the
  evaluator/garbler boundary as a production client surface
- any optimization that reconstructs hidden intermediates in the evaluator is
  not production-safe
- `ExplicitKeyExport` is the explicit exception: it intentionally delivers the
  canonical seed to the authorized client and therefore is outside the
  non-export secrecy invariant for `y_relayer` and `tau_relayer`
- that exception is deliberate because export is the operation where the user
  is explicitly asking to receive private-key-equivalent material in the
  client runtime; a compromised client runtime can therefore abuse export by
  design, while non-export flows must keep the stronger secrecy boundary

The most important recent security lesson was the rejected insecure A2B
shortcut:

- reconstructing arithmetic words and re-emitting `(bit, 0)` Boolean shares is
  correct but not secure for the real boundary
- the production path now uses secure carry-aware A2B again

The kept staged production path now advances through real server-owned
continuation state:

- add-stage materializes only the add-stage transition plus the first stored
  `message_schedule` continuation
- each `message_schedule(n)` response advances only the immediately prior
  schedule continuation
- each `round_core(n)` response advances only the immediately prior
  round-core continuation
- `output_projection` materializes final output only when that stage executes
- the only accepted retained-state exception before `output_projection` is the
  minimal server-owned `projector_inputs` needed to reach that stage without
  recomputing from dropped relayer roots

## Current Implementation Status

Implemented in code:

- candidate model:
  [`src/candidate.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/candidate.rs)
- frozen reference path and fixtures:
  [`src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
  and
  [`fixtures/f_expand_v1.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/fixtures/f_expand_v1.json)
- DDH hidden-eval IR compiler:
  [`src/ddh/hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval.rs)
- DDH primitive baseline:
  [`src/ddh/ddh_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/ddh_hss.rs)
- structured prime-order artifact path:
  [`src/artifact/prime_order_encoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/artifact/prime_order_encoder.rs)
  and
  [`src/artifact/prime_order_decoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/artifact/prime_order_decoder.rs)
- CPU execution baseline:
  [`src/runtime/prime_order_cpu_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/prime_order_cpu_executor.rs)
- kept secure prepared-session and packetized role split:
  [`src/protocol/prepared.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/prepared.rs)
  plus
  [`src/client/api.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs),
  [`src/server/api.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs),
  and
  [`src/wire/mod.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
- compiled hidden evaluator:
  [`src/ddh/hidden_eval_executor.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)

Role-separated flow:

- process driver:
  [`src/bin/prime_order_succinct_hss_driver.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/bin/prime_order_succinct_hss_driver.rs)
- process integration test:
  [`tests/prime_order_driver_process.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/tests/prime_order_driver_process.rs)
- separated e2e example and audit:
  [`examples/prime_order_separated_roles_e2e.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs)

## Current Secure Performance Position

Recent kept secure checkpoint:

- native total hidden eval: about `266.4 ms`
- browser total hidden eval: about `363.6 ms`
- browser `session.evaluate`: about `364.4 ms`
- browser hidden-eval probe total: about `299.5 ms`
- native `round_core`: about `137.7 ms`
- browser `round_core`: about `178.1 ms`
- browser `ot_open_join`: about `67.0 ms`

These results put the secure path roughly back at the old native watermark and
past the old browser watermark.

## Biggest Durable Wins

The durable wins came from deleting real work, not from helper-level
micro-optimization:

- arithmetic carry-through for message-schedule accumulation
- arithmetic carry-through for `temp1`, `temp2`, `new_a`, and `new_e`
- secure raw packed A2B carry helpers below the generic width-1 helper layer
- raw packed `Ch` and `Maj` gate paths
- OT/open/join reductions that deleted real scalar-multiply work without
  widening the evaluator boundary

The main rejected class of work was:

- seam-level helper rewrites that only rearranged the same Boolean-lane cost

## Trust-Boundary Status

What is fixed:

- direct joint-share relayer bundles no longer serialize across the interparty
  packet boundary
- evaluator runtime no longer materializes the full secret-seeded backend
- sealed transport/output packets are role-gated
- process-separated driver flow now exists and matches the frozen fixture path

What remains structurally important:

- production execution must keep role-local state at the real evaluator /
  garbler boundary
- transport-facing types must remain wire-safe and non-joined
- optimizations must not reintroduce evaluator-visible plaintext hidden
  intermediates

## Phased Roadmap

### Phase 0 — Freeze executable specs and fixtures

Status: complete.

- fixed `F_expand`
- fixed deterministic fixtures
- fixed invariant/property tests

### Phase 1 — Evaluation and hardware profiling

Status: partially complete.

- native CPU benchmarking is implemented
- browser wasm benchmarking is implemented
- device/runtime matrix expansion is still open

### Phase 2 — Candidate artifact and protocol shape

Status: complete for the active backend.

- fixed candidate shape
- structured prime-order artifact implemented
- compute-optimized prime-order family remains as a comparison-only model

### Phase 2b / 3 — DDH baseline and output-share integration

Status: complete on the active secure path.

- DDH primitive baseline implemented
- compiled hidden evaluator implemented
- output-share integration implemented
- prepared-session and wire-message path implemented

### Phase 3b / 3c — Delivery hardening and trust-boundary corrections

Status: materially advanced, not “done forever”.

- process-separated role flow exists
- wire-level joint-share leaks were removed
- evaluator runtime ownership is narrower
- secure A2B path restored after rejecting the insecure shortcut

Ongoing rule:

- no optimization may widen the evaluator boundary or reconstruct server-owned
  hidden values in plaintext

### Phase 4 / 5 / 6 — Performance hardening

Status: major secure wins landed.

- round-core arithmetic path heavily reduced
- secure A2B path improved again after restoring boundary safety
- OT/open/join path materially reduced

Future performance work should prioritize:

- secure A2B/crossing cost only if it preserves split secrecy
- OT/open/join reductions only when they delete real curve work without
  changing payload semantics

### Phase 7 — Cleanup

Status: in progress.

- duplicate wrappers and stale benchmark scaffolding have been pruned
- the remaining task is to keep deleting superseded helper paths as the secure
  hot path stabilizes

## Inspection Commands

```bash
cargo test --manifest-path crates/ed25519-hss/Cargo.toml
cargo test --manifest-path crates/ed25519-hss/Cargo.toml tests::prime_order_succinct_hss_matches_reference_fixture_smoke -- --ignored --nocapture
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_candidate_note
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_candidate_artifact_stub -- --fixture derived-alpha
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_prime_order_artifact -- --fixture derived-alpha
cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --example prime_order_separated_roles_e2e
cargo test --manifest-path crates/ed25519-hss/Cargo.toml process_driver_end_to_end_matches_reference_fixture -- --ignored --nocapture
```

## Decision Rule

This crate now keeps one active specs document and one active backend family.

- active spec: this file
- active backend family: prime-order
- comparison-only backend family: prime-order compute-optimized

Paillier and lattice are intentionally gone from the active codebase because
they were not just unimplemented; they were the wrong fit for this track’s
payload budget.
