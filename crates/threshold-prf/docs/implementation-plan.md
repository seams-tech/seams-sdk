# Threshold PRF Implementation Plan

Date created: April 16, 2026

## Scope

Prototype a Rust crate that derives project-scoped server HSS inputs from
random signing-root material using a threshold PRF.

The crate should answer one question before any integration work:

Can the same canonical `y_relayer` be produced from either:

- the direct reference path from reconstructed signing root `k_org`
- Option A one-runtime threshold partial evaluation and combine
- any valid 2-of-3 signing-root share subset

while keeping latency and compute low enough for signing-scale use?

The crate is a prerequisite for replacing current server-root derivation in the
`ed25519-hss` and `ecdsa-hss` flows. It does not replace those HSS crates.

## Design Goal

The target lifecycle is:

```text
signing_root_secret / k_org
  -> threshold-prf
  -> y_relayer
  -> ed25519-hss or ecdsa-hss
  -> final threshold signing shares
```

`threshold-prf` owns only the `k_org -> y_relayer` layer.

For product Phase 1, a single Cloudflare signer decrypts two signing-root
shares, evaluates two threshold-PRF partials in one runtime, and combines them
into `y_relayer`. For product Phase 2, each server evaluates a PRF partial from
its own signing-root share, and a combiner should produce the same `y_relayer`
if benchmark results justify the extra runtime complexity.

## Flow Summary

The crate must support two operational modes with the same output.

### One-Server Variant

Use this for product Phase 1 and self-hosted SDK deployments.

```text
sealed_signing_root_share_i
sealed_signing_root_share_j
  -> signer decrypts two shares
  -> partial_i = [k_org_share_i] P
  -> partial_j = [k_org_share_j] P
  -> signer lagrange-combines partials
  -> y_relayer
  -> ed25519-hss or ecdsa-hss
  -> final server signing share
```

Properties:

- simplest runtime
- no signing-path network hop to a second server
- no durable plaintext `k_org`
- signer observes two plaintext root shares in memory, which is enough material
  to reconstruct `k_org`
- protects mainly against accidental durable storage loss and casual plaintext
  root exposure in storage
- does not protect against malicious signer code or signer runtime compromise

This mode uses the same canonical threshold-PRF partial evaluation and combine
algorithm as the two-server mode. The only difference is runtime placement:
Option A computes both partials in one worker; Option B computes them in
separate workers.

### Two-Server Variant

Use this for product Option B and the future stronger custody mode.

```text
server A:
  sealed_signing_root_share_i
    -> decrypt share_i
    -> partial_i = [k_org_share_i] P

server B:
  sealed_signing_root_share_j
    -> decrypt share_j
    -> partial_j = [k_org_share_j] P

combiner:
  partial_i, partial_j
    -> lagrange-combine partials
    -> y_relayer
    -> ed25519-hss or ecdsa-hss
    -> final server signing share
```

Properties:

- no one server needs to reconstruct `k_org`
- root-share custody can be split across deployment, storage, and wrapping-key
  boundaries
- the combiner learns `y_relayer` for the requested wallet context, not
  `k_org`
- the output must match the one-server partial-combine evaluation byte-for-byte
- DLEQ proofs or TEE attestation should be added before treating partials as
  malicious-server safe
- latency includes at least one server-to-server or coordinator round trip

This mode is a custody hardening step. It should not change wallet addresses,
HSS inputs, or downstream threshold signing behavior.

### Shared Output Invariant

Both variants must satisfy:

```text
direct_prf(k_org, context, purpose)
  == option_a_combine_prf_partials([share_i, share_j], context, purpose)
  == option_b_combine_prf_partials([share_i, share_j], context, purpose)
  == y_relayer
```

The direct PRF path is a reference test path, not the preferred production
signing path. The main production invariant is that Option A and Option B
combine the same root-share partials into the same `y_relayer`. That lets
product Phase 1 ship with one signer while preserving a clean migration path to
two servers later.

## Spec Hardening Decisions

The protocol spec intentionally tightens a few areas before HSS integration:

- Option A and Option B must both use threshold partial evaluation and combine.
- Direct `k_org -> y_relayer` evaluation is reference-only.
- `PrfPartialWireV1` should carry `share_id`, `context_tag`, and compressed
  partial point so Option B transport can reject accidental wrong-context
  partials.
- Zero signing-root scalars are invalid, but zero share scalar values are valid
  Shamir shares if canonically encoded and bound to a valid share ID.
- v1 has no `Custom(bytes)` production purpose. New outputs require fixed
  purpose strings and a specs update.
- Malicious-worker safety requires DLEQ, TEE attestation, or an equivalent
  partial-authenticity layer. Until then, Option B is honest/semi-honest with
  respect to partial correctness.

## Non-Goals

- replacing `ed25519-hss`
- replacing `ecdsa-hss`
- changing threshold signing protocols
- implementing wallet migration
- introducing per-wallet durable server secrets
- preserving HKDF byte compatibility
- generic multi-curve abstraction before the first suite is benchmarked
- implementing a new elliptic-curve library

## Proposed PRF Shape

Use a prime-order group suite. The first prototype should use a single suite,
for example `ristretto255-sha512-v1`, unless benchmark or dependency review
rejects it.

Direct evaluation:

```text
P = HashToGroup("threshold-prf:v1/input", context)
Z = [k_org] P
raw32 = HashToBytes("threshold-prf:v1/output", suite_id, purpose, context, encode(Z))[0..32]
output = PurposeOutputEncoding(purpose, raw32)
```

Threshold evaluation:

```text
P = HashToGroup("threshold-prf:v1/input", context)
partial_i = [k_org_share_i] P
Z = sum(lambda_i * partial_i)
raw32 = HashToBytes("threshold-prf:v1/output", suite_id, purpose, context, encode(Z))[0..32]
output = PurposeOutputEncoding(purpose, raw32)
```

Where:

- `k_org` is a non-zero scalar in the PRF suite field
- `k_org_share_i` is a Shamir share over the same scalar field
- `lambda_i` is the public Lagrange coefficient for the selected share IDs
- `purpose` domain-separates outputs such as `ecdsa-hss/y_relayer`,
  `ed25519-hss/y_relayer`, and `ed25519-hss/tau_relayer`
- `ed25519-hss/tau_relayer` output is reduced to canonical Ed25519 scalar
  bytes because the downstream HSS circuit treats tau as scalar input
- `context` is a canonical byte encoding of the wallet/project derivation
  context

The threshold partial-combine path must produce the same output as direct
reference evaluation for every valid threshold subset.

## Initial API Shape

The first API should be small and hard to misuse.

```rust
pub struct SigningRootScalar([u8; 32]);
pub struct SigningRootShare {
    pub id: NonZeroShareId,
    pub value: SigningRootShareScalar,
}

pub struct PrfContext {
    pub suite_id: SuiteId,
    pub purpose: PrfPurpose,
    pub context_bytes: Vec<u8>,
}

pub fn generate_signing_root(rng: impl CryptoRngCore) -> SigningRootScalar;
pub fn split_signing_root_2_of_3(
    root: &SigningRootScalar,
    rng: impl CryptoRngCore,
) -> [SigningRootShare; 3];
pub fn refresh_signing_root_shares_2_of_3(
    shares: &[SigningRootShare],
    rng: impl CryptoRngCore,
) -> ThresholdPrfResult<[SigningRootShare; 3]>;

pub fn evaluate_direct_reference(
    root: &SigningRootScalar,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32>;
pub fn evaluate_partial(
    share: &SigningRootShare,
    context: &PrfContext,
) -> ThresholdPrfResult<PrfPartial>;
pub fn combine_partials(
    partials: &[PrfPartial],
    context: &PrfContext,
) -> ThresholdPrfResult<PrfOutput32>;

pub struct PrfPartialWireV1 {
    pub share_id: NonZeroShareId,
    pub context_tag: [u8; 32],
    pub compressed_point: [u8; 32],
}
```

The names can change during implementation, but the separation should stay:

- root generation
- root splitting
- share refresh
- direct reference evaluation
- partial evaluation
- partial combination
- partial wire encoding/decoding

## Verification Hooks

The current formal-verification folder has a Verus abstract spec model,
production anti-drift parity against the committed JSON corpus, and a narrow
Lean privacy model for one-server/two-server visibility.

Decision: this scope is accepted as sufficient for first Option A integration.
The remaining production-shaped Verus module mirror is deferred maintainability,
not a correctness blocker. Trusted seams remain Ristretto arithmetic, SHA-512,
hash-to-group, Fiat-Shamir soundness, randomness generation, runtime isolation,
transport authenticity, side-channel resistance, authenticated commitment
registry behavior, and Cloudflare Worker runtime behavior.

The crate-local formal-verification track lives in:

- [formal-verification-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/formal-verification-plan.md)
- [formal-verification-proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/formal-verification-proof-inventory.md)
- [formal-verification/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/formal-verification/README.md)

Useful verification artifacts:

- root share commitments: `[k_org_share_i] G`
- partial evaluation proof: DLEQ between `[k_org_share_i] G` and
  `[k_org_share_i] P`
- context binding inside the proof transcript
- subset binding inside the combine step
- partial wire context-tag binding

DLEQ proof generation and verification are now implemented in the crate. First
Option A integration does not require DLEQ on the hot path because one runtime
computes both partials locally. Two-server Option B should require DLEQ, TEE
attestation, or an equivalent deployment-level authenticity mechanism before
claiming malicious-worker partial correctness.

## Test Requirements

Minimum correctness tests:

- direct reference evaluation is deterministic
- direct reference evaluation changes when `purpose` changes
- direct reference evaluation changes when context changes
- any valid 2-of-3 share pair matches direct reference evaluation
- one-worker partial combine matches two-worker partial combine
- all three valid share pairs produce the same output
- duplicate share IDs fail
- unknown share IDs fail
- one share cannot combine
- share refresh preserves direct-equivalent output
- different signing roots produce different outputs for the same context
- malformed scalar encodings fail
- zero root scalars are rejected
- zero share scalar encodings are accepted as valid Shamir shares

Vector tests:

- commit `fixtures/protocol-v1.json`
- commit JSON vectors for root generation from fixed seed material
- commit JSON vectors for 2-of-3 splitting
- commit JSON vectors for direct reference evaluation
- commit JSON vectors for each valid pairwise combine path
- commit JSON vectors for refreshed shares
- include vectors for `ecdsa-hss/y_relayer`
- include vectors for `ed25519-hss/y_relayer`
- include vectors for `ed25519-hss/tau_relayer`
- include partial wire vectors with `share_id`, `context_tag`, and compressed
  point
- include root-share commitment and DLEQ proof vectors for each partial

Security-focused tests:

- no panic on malformed public inputs
- no accidental acceptance of duplicate share IDs
- no accidental acceptance of insufficient threshold subsets
- no accidental acceptance of wrong-context wire partials
- no logging or `Debug` output that exposes scalar material
- zeroization behavior for root scalars, shares, and partials

## Benchmark Requirements

Full performance benchmarking should begin once the core `threshold-prf` package
is complete enough that benchmark numbers are meaningful:

- the public crate API used for signing-root generation, splitting, refresh,
  partial evaluation, partial combination, DLEQ proof generation, and DLEQ proof
  verification is stable for v1
- committed vectors pin direct, Option A, Option B, refresh, wire, and DLEQ
  behavior
- `cargo test` passes for the crate
- `just threshold-prf-fv` passes, or the remaining formal-verification scope is
  explicitly accepted as deferred
- no Cloudflare, Durable Object, database, or HSS integration dependencies have
  been introduced into the crate

Benchmarks should measure at least:

- direct reference evaluation from `k_org`
- 2-of-3 share splitting
- one partial evaluation
- two-partial combine
- full 2-of-3 threshold evaluation
- share refresh
- optional DLEQ proof generation
- optional DLEQ proof verification

Initial native targets:

- direct reference evaluation: comfortably below 1 ms p95
- full 2-of-3 threshold evaluation: comfortably below 2 ms p95
- share refresh: low enough for admin operations, not signing-hot-path critical

Initial Worker/WASM target, if the crate is compiled to WASM:

- full 2-of-3 threshold evaluation below 5 ms p95

These are prototype targets, not specs. The first benchmark run should record
real numbers and update this plan.

## Benchmarking Workstream

The benchmarking workstream should answer whether threshold-PRF is cheap enough
to sit on the signing hot path before any Cloudflare Worker or server SDK
integration starts.

Native baseline goals:

- measure local CPU cost for every primitive and full Option A derivation
- measure DLEQ proof generation and verification separately from unauthenticated
  partial evaluation
- record the exact command, date, machine, OS, Rust toolchain, crate dependency
  versions, and relevant git revision
- keep results in `docs/benchmarks.md`

Worker/WASM goals:

- compile the crate for the Worker/WASM target if Cloudflare Worker is the first
  deployment target
- measure Option A full derivation inside the same runtime shape expected in the
  signer worker
- measure DLEQ proof generation and verification in Worker/WASM even if DLEQ is
  deferred to Option B
- record wasm binary size and any startup or initialization costs that matter to
  request latency
- compare Worker/WASM numbers against native numbers before integration

Deployment-readiness goals:

- confirm Option A derivation is comfortably below the HSS signing ceremony cost
- estimate Option B crypto cost separately from the future network/coordinator
  round trip
- decide whether DLEQ is acceptable on the hot path or only for the two-server
  milestone
- define a repeatable command or script for rerunning benchmark suites after
  crypto-relevant changes
- make benchmark regression thresholds explicit before integrating into wallet
  derivation

## Crate Layout

Proposed files:

```text
crates/threshold-prf/
  Cargo.toml
  README.md
  docs/
    implementation-plan.md
    protocol.md
    benchmarks.md
    dependency-review.md
    integration-design.md
  benches/
    threshold_prf_baseline.rs
  examples/
    generate_vectors.rs
  fixtures/
    protocol-v1.json
  formal-verification/
    README.md
    docs/
      implementation-plan.md
      proof-inventory.md
    fixtures/
      README.md
    verus/
      README.md
      docs/
        implementation-plan.md
    lean-boundary/
      README.md
      docs/
        implementation-plan.md
    lean-privacy/
      README.md
      docs/
        implementation-plan.md
  src/
    lib.rs
    context.rs
    error.rs
    shamir.rs
    suite.rs
  tests/
    protocol.rs
    vectors.rs
```

Keep the crate focused. Do not add Cloudflare, Durable Object, project-store,
or HSS integration dependencies.

## Integration Gates

Do not integrate this crate into wallet derivation until all gates pass:

- [x] committed protocol spec exists
- [x] committed JSON vector corpus exists
- [x] direct reference and threshold partial-combine paths are vector-equivalent
      against the committed JSON corpus
- [x] share refresh preserves outputs in tests
- [x] initial native benchmark numbers are recorded
- [x] post-core-completion benchmark numbers are recorded
- [x] crate-local formal-verification parity passes
- [x] dependencies are reviewed
- [x] root/share zeroization is implemented
- [x] HSS context encoding is stable
- [x] `ed25519-hss` and `ecdsa-hss` integration contexts are explicitly mapped
- [x] Option A one-worker partial combine and Option B two-worker partial combine
      are byte-identical
- [x] Canonical one-runtime Option A helper exists, is tested, and is benchmarked
- [x] Benchmark review confirms threshold-PRF is fast enough for server SDK
      Option A integration
- [x] `PrfPartialWireV1` includes context-tag transport binding
- [x] DLEQ/TEE is implemented or Option B is explicitly documented as
      honest/semi-honest for partial correctness
- [x] Native benchmark guardrail thresholds are defined
- [x] Latest native benchmark guardrail check passes
- [x] Local Node/V8 WASM proxy benchmarks are recorded
- [x] Cloudflare Worker runtime benchmarks are not required before the first
      server SDK integration target; keep them gated before Worker deployment
- [x] Formal-verification scope is explicitly accepted as sufficient for first
      integration, or the remaining proof obligations are completed

Once those gates pass, integration should replace only the server-input
derivation layer:

```text
old:
  process-level master secret or direct HKDF root derivation -> y_relayer

new:
  sealed signing-root shares -> PRF partials -> threshold-prf combine -> y_relayer
```

HSS behavior should remain unchanged except for the byte value of `y_relayer`
for newly created wallets.

## Phased Todo List

### Phase 0. Crate Skeleton

- [x] Create `crates/threshold-prf/Cargo.toml`.
- [x] Create the initial `src/lib.rs`.
- [x] Add crate-level docs describing the direct reference and threshold
      partial-combine paths.
- [x] Add `README.md` with prototype status and non-goals.
- [x] Add dependency review notes for the first group suite.
- [x] Keep the crate independent from `ed25519-hss`, `ecdsa-hss`, and
      server code.

### Phase 1. Protocol Spec

- [x] Write `docs/protocol.md`.
- [x] Freeze suite id naming for the prototype.
- [x] Define signing-root scalar encoding.
- [x] Define signing-root share encoding.
- [x] Define share ID encoding.
- [x] Define canonical context input requirements.
- [x] Define `purpose` domain strings.
- [x] Define direct reference evaluation.
- [x] Define threshold partial evaluation.
- [x] Define partial combination.
- [x] Define output encoding.
- [x] Define failure behavior for malformed inputs.

### Phase 2. Shamir And Root Lifecycle

- [x] Implement non-zero signing-root generation.
- [x] Implement 2-of-3 Shamir splitting over the PRF scalar field.
- [x] Implement reconstruction only for tests, vectors, and recovery checks.
- [x] Implement share refresh that preserves `k_org`.
- [x] Reject duplicate share IDs.
- [x] Reject insufficient share sets.
- [x] Reject malformed share values.
- [x] Preserve zero share values as valid Shamir shares.
- [x] Add zeroization for root and share types.

### Phase 3. Direct Reference PRF Evaluation

- [x] Implement suite-specific hash-to-group.
- [x] Implement reference direct `k_org -> PrfOutput32`.
- [x] Add domain-separated purposes:
  - [x] `ecdsa-hss/y_relayer`
  - [x] `ed25519-hss/y_relayer`
  - [x] `ed25519-hss/tau_relayer`
- [x] Add deterministic tests for direct reference evaluation.
- [x] Add context-change tests.
- [x] Add purpose-separation tests.

### Phase 4. Threshold PRF Evaluation

- [x] Implement partial evaluation from one signing-root share.
- [x] Implement Lagrange coefficient calculation for selected share IDs.
- [x] Implement partial combination.
- [x] Prove by tests that every valid 2-of-3 pair matches direct reference
      evaluation.
- [x] Prove by tests that one-worker partial combine and two-worker partial
      combine are byte-identical.
- [x] Prove by tests that refreshed shares match direct reference evaluation.
- [x] Add negative tests for wrong subset handling.
- [x] Add negative tests for duplicate partials.
- [x] Add a canonical Option A helper that derives output from exactly two
      decrypted signing-root shares without reconstructing `k_org`.
- [x] Add fixed-width decrypted signing-root share encoding for the server SDK
      boundary.
- [x] Add fixed-width worker partial wire encoding.
- [x] Add partial context mismatch rejection.
- [x] Update worker partial wire encoding to `PrfPartialWireV1 =
share_id || context_tag || compressed_point`.
- [x] Reject wrong-context wire partials during decode.
- [x] Add sole public context-bound `PrfPartialWireV1::decode(context, bytes)`
      API.
- [x] Remove public raw wire parsing so transported partial bytes must use the
      context-bound decode path.
- [x] Remove public compressed-point partial construction so external callers
      cannot bypass `PrfPartialWireV1::decode` for transported partials.
- [x] Keep compressed-point reconstruction as a private module helper, not an
      inherent `PrfPartial` constructor, so the public API shape cannot imply a
      second transported-partial decode path.
- [x] Rename the server-SDK signing-root share wire parser to
      `SigningRootShareWireV1::decode` / `decode_slice` and remove the
      legacy-looking `from_bytes` / `from_slice` aliases.

### Phase 5. Vectors

- [x] Define `fixtures/protocol-v1.json`.
- [x] Add fixed-seed root generation vectors.
- [x] Add share split vectors.
- [x] Add signing-root share wire vectors for server SDK parity tests.
- [x] Add direct reference evaluation vectors.
- [x] Add pairwise threshold evaluation vectors.
- [x] Add share refresh vectors.
- [x] Add malformed-input rejection vector cases where practical.
- [x] Add a vector regeneration tool.
- [x] Move interim Rust vector constants into the committed JSON corpus.
- [x] Add a test that committed JSON vectors match the implementation.
- [x] Add `ed25519-hss/y_relayer` and `ed25519-hss/tau_relayer` vectors before
      Ed25519 HSS integration.
- [x] Add deterministic DLEQ commitment/proof vectors.
- [x] Add anti-drift tests for deterministic DLEQ commitment/proof vectors.

### Phase 6. Benchmarks

- [x] Add Criterion benchmark harness.
- [x] Benchmark direct reference evaluation.
- [x] Benchmark share splitting.
- [x] Benchmark partial evaluation.
- [x] Benchmark partial combination.
- [x] Benchmark full 2-of-3 threshold evaluation.
- [x] Benchmark canonical Option A derivation helper.
- [x] Benchmark share refresh.
- [x] Benchmark DLEQ proof generation.
- [x] Benchmark DLEQ proof verification.
- [x] Optimize DLEQ proof generation to avoid duplicate hash-to-group work.
- [x] Save first native benchmark report.
- [x] Write `docs/benchmarks.md`.
- [x] Re-run native benchmarks after the core v1 crate surface is complete.
- [x] Record post-core-completion native benchmark environment details:
      toolchain, machine, OS, crate revision, and command.
- [x] Add or document a repeatable benchmark command/script for developers.
- [x] Decide whether WASM/Worker benchmarks are needed before integration.
- [x] Run native benchmark guardrail check after DLEQ nonce and partial decode
      hardening.
- [x] Add a local `wasm-pack --target nodejs` benchmark harness before
      Cloudflare Worker integration.
- [x] Benchmark Option A full derivation under the local Node/V8 WASM harness.
- [x] Benchmark the canonical Option A helper under the local Node/V8 WASM
      harness.
- [x] Benchmark DLEQ proof generation and verification under the local Node/V8
      WASM harness.
- [x] Record local Node/V8 WASM benchmark results in `docs/benchmarks.md`.
- [x] Review benchmark results against existing HSS ceremony costs.
- [x] Defer real Cloudflare Worker runtime benchmark results because Worker
      deployment is not the first integration target.
- [x] Decide benchmark regression thresholds for CI or release gating.

Decision: Worker/WASM benchmarks are required before Cloudflare Worker
integration, because native results do not model Worker runtime startup,
WASM/runtime overhead, or isolate scheduling. Native benchmark guardrails are
release/integration regression checks only.

The local Node/V8 WASM benchmark is a useful runtime proxy, not a substitute for
final Cloudflare Worker measurements before Worker deployment.

### Phase 7. Verification Hooks

- [x] Define root share commitment encoding.
- [x] Define DLEQ/attestation transcript fields:
  - [x] suite id
  - [x] purpose
  - [x] context tag
  - [x] share ID
  - [x] suite base point `G`
  - [x] PRF input point `P`
  - [x] root-share commitment `[share_i]G`
  - [x] partial point `[share_i]P`
- [x] Prototype DLEQ proof generation for partials.
- [x] Prototype DLEQ proof verification for partials.
- [x] Bind proofs to suite id, purpose, context, share ID, and partial output.
- [x] Add `combine_verified_partials` as the DLEQ-enforced Option B combiner
      helper.
- [x] Benchmark proof generation and verification.
- [x] Reject and retry zero DLEQ proof nonces.
- [x] Document that DLEQ nonce uniqueness depends on a correct `CryptoRng`.
- [x] Decide whether DLEQ is required before first integration or deferred to
      the two-server milestone.

Decision: DLEQ is not required for first one-worker Option A integration. The
crate keeps DLEQ implemented, vector-pinned, and benchmarked so two-worker
Option B can require it later without changing the threshold-PRF output.

### Phase 7a. Formal Verification Scaffold

- [x] Add `docs/formal-verification-plan.md`.
- [x] Add `docs/formal-verification-proof-inventory.md`.
- [x] Add `formal-verification/README.md`.
- [x] Add `formal-verification/docs/implementation-plan.md`.
- [x] Add `formal-verification/docs/proof-inventory.md`.
- [x] Add `formal-verification/fixtures/README.md`.
- [x] Add `formal-verification/verus/README.md`.
- [x] Add `formal-verification/verus/docs/implementation-plan.md`.
- [x] Add deferred `formal-verification/lean-boundary/` docs.
- [x] Add deferred `formal-verification/lean-privacy/` docs.
- [x] Add the first Verus abstract spec-model crate.
- [x] Add anti-drift vectors after the JSON corpus exists.
- [x] Add production anti-drift parity tests under the Verus FV crate.
- [x] Wire full `just threshold-prf-fv`.
- [x] Add DLEQ vector anti-drift checks under the FV crate.
- [x] Model sole public context-bound partial wire decode.
- [x] Model zero DLEQ nonce rejection.
- [x] Accept the current FV scope as sufficient for first Option A integration.
- [x] Defer production-shaped Verus module mirror views until the Rust/FV
      module split can compile under both Verus and normal Cargo parity tests
      without creating a duplicate legacy model.

Decision: production-shaped Verus module mirror views remain deferred. The
current Verus abstract spec, anti-drift vector parity, and Lean privacy model
cover the first-integration correctness and visibility gates. Add module mirrors
later if they can compile cleanly under both Verus and normal Cargo parity tests
without creating a duplicate legacy model.

Deferred follow-up: add production-shaped Verus module mirror views after the
shared Rust/FV boundary is stable enough to avoid maintaining two independent
models.

### Phase 8. Integration Design Review

- [x] Map `ecdsa-hss` context fields into `threshold-prf` context bytes.
- [x] Map `ed25519-hss` context fields into `threshold-prf` context bytes.
- [x] Define a separate threshold-PRF purpose for `ed25519-hss/tau_relayer`.
- [x] Confirm output endianness expected by each HSS flow.
- [x] Confirm `y_relayer` and `tau_relayer` output handling in each downstream
      crate.
- [x] Encode `ed25519-hss/tau_relayer` as canonical Ed25519 scalar bytes.
- [x] Add an integration design memo before editing HSS or server code.

### Phase 9. Integration Readiness

- [x] Confirm no customer wallets depend on the old derivation output.
- [x] Update `docs/korg-secrets.md` if threshold-PRF becomes canonical.
- [x] Update `docs/cloudflare-signing-worker-self-host.md` if threshold-PRF
      becomes canonical.
- [x] Replace current server derivation only after vectors, benchmarks, and
      accepted formal-verification gates pass.
- [x] Remove the replaced derivation path as part of the integration change.
- [x] Add end-to-end tests proving wallet identity is stable across Option A
      one-worker partial combine and Option B two-worker partial combine.

Decision: no real customer wallets exist yet, so replacing the old derivation
output for future wallets is still a safe breaking change. Do not preserve a
parallel legacy derivation path when integration starts.

### Phase 10. Cloudflare Worker And Server SDK Integration

This phase is explicitly gated. Do not start it until the crate has committed
vectors, native benchmarks, any required Worker/WASM benchmarks, and accepted
formal-verification coverage.

- [x] Decide whether the first integration target is Cloudflare Worker only,
      server SDK only, or both in one change.
- [x] Identify the current server-input derivation entry points that produce
      `y_relayer` for `ecdsa-hss` and `ed25519-hss`.
- [x] Extract a narrow crate-local derivation interface that accepts exactly two
      `SigningRootShareWireV1` values and a canonical `PrfContext`.
- [x] Wire crate-local Option A through threshold partial evaluation and combine
      in one runtime; do not reconstruct `k_org` as the canonical signing path.
- [x] Add the server storage/decrypt adapter boundary that validates decrypted
      `SigningRootShareWireV1` values from sealed signing-root shares.
- [x] Add server SDK adapter boundary unit tests for share selection,
      decrypted-wire copying, malformed share rejection, and plaintext
      zeroization on success and failure.
- [x] Add a server SDK WASM binding that derives HSS relayer inputs from two
      `SigningRootShareWireV1` values using frozen HSS context encodings.
- [x] Add the server SDK provider boundary that lists/decrypts sealed
      signing-root shares, derives HSS relayer inputs, and zeroizes plaintext
      share wires after derivation.
- [x] Add provider-level server SDK tests for resolving signing-root shares and
      deriving ECDSA/Ed25519 HSS outputs from committed vectors.
- [x] Add a storage/decrypt-backed `SigningRootShareResolver` factory over
      injected store and share-decrypt provider interfaces.
- [x] Add concrete in-memory and Postgres signing-root stores that persist only
      sealed share bytes.
- [x] Implement the AES-GCM sealed-share decrypt provider over an injected
      deployment/KMS KEK resolver.
- [ ] Connect the KEK resolver to the production KMS or HSM boundary.
- [x] Wire the store/decrypt provider into server SDK configuration.
- [x] Preserve existing Ed25519 HSS prepare behavior after signing-root
      `y_relayer` / `tau_relayer` inputs are produced.
- [x] Preserve existing ECDSA HSS behavior after signing-root `y_relayer` is
      produced.
- [x] Wire the signing-root provider into the ECDSA HSS prepare bootstrap path
      without preserving a parallel process-level fallback.
- [x] Add a server SDK ECDSA HSS prepare test that uses sealed signing-root
      shares and no secp256k1 master secret.
- [x] Wire first ECDSA bootstrap key-material derivation through the
      signing-root provider when runtime org scope is present.
- [x] Add a server SDK first-bootstrap test that creates ECDSA key material
      from sealed signing-root shares with no secp256k1 master secret.
- [x] Remove the stale secp256k1 master-secret guard from the ECDSA signing
      finalization handler; signing uses persisted integrated-key and
      presignature state, not a global master secret.
- [x] Remove stale Ed25519 HSS finalization-only master-secret checks; the
      provider-derived server inputs are staged during prepare and finalize does
      not rederive them.
- [x] Keep SaaS-only policy, sponsorship, console, and project-management code
      outside the minimal self-hosted server SDK boundary.
- [x] Add Cloudflare Worker tests covering sealed-share read, decrypt-in-memory,
      partial evaluation, combine, and handoff into existing HSS flows.
- [x] Add server SDK tests proving the same context and signing-root shares
      produce the same `y_relayer` as the crate vectors.
- [x] Add an integration test that Option A output remains byte-identical to
      the future Option B partial-combine placement.
- [x] Remove old server-input derivation code in the same refactor; do not keep
      a parallel legacy derivation path.

Decision: first integration target is the server SDK only. Cloudflare
Worker-style tests now cover sealed-share read, in-memory decrypt, threshold-PRF
combine, and HSS handoff. Actual Cloudflare Worker deployment remains gated on
real Worker runtime benchmarks and production KEK/HSM sealed-share wiring. Do
not integrate both targets in one change; keep the first refactor narrow so old
server-input derivation can be removed cleanly.

## Success Criteria

The prototype is successful when:

- direct reference evaluation, Option A one-worker partial combine, and Option B
  two-worker partial combine are byte-identical
- share refresh preserves outputs
- benchmark numbers are comfortably below HSS ceremony costs
- the API can feed current `ed25519-hss` and `ecdsa-hss` inputs without changing
  those protocols
- the crate can be integrated by replacing only the server-input derivation
  layer

## Main Risks

- choosing a suite or encoding that is awkward to verify later
- accidentally treating PRF output as a scalar with inconsistent endianness
- failing to bind context and purpose strongly enough
- leaving HKDF and threshold-PRF as parallel production derivation paths
- integrating before vectors and benchmarks establish the canonical output

## Current Recommendation

Build and benchmark this crate before changing wallet derivation. If the
prototype meets the benchmark and equivalence gates, make threshold-PRF the
canonical `k_org -> y_relayer` derivation before real customer wallets are
created.
