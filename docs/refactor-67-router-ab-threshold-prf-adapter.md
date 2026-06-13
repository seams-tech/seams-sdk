# Router A/B Threshold-PRF Adapter Refactor

Date created: June 12, 2026

Status: active follow-up. The Router/A/B primitive comparison selected
Candidate A for the production path. The adapter target is a `threshold_prf`
policy-aware backend, initially configured as `2-of-3` to preserve current
Router/A/B behavior while removing the fixed-pair backend dependency.

## Goal

Turn the current Router/A/B Candidate A proof-of-compatibility into a narrow
production adapter over `threshold-prf`.

The intended crate boundary is:

- `threshold-prf` owns Ristretto, Shamir, DLEQ, partial evaluation, proof
  verification, verified combine, fixed crypto wire encodings, and crypto
  vectors.
- `router-ab-core` owns Router/A/B context binding, transcript binding,
  signer-set identity, recipient authorization, role-local visibility,
  encrypted delivery boundaries, diagnostics, and release gates.

This refactor should avoid extracting a lower-level shared crypto crate.
`threshold-prf` is already the small crypto primitive module. A lower-level
module would expose curve and share internals to Router/A/B and increase the
API surface that needs review.

## Current State

Completed compatibility work:

- `threshold-prf::PrfPurpose` now includes:
  - `router-ab/x_client_base/v1`
  - `router-ab/x_relayer_base/v1`
- both Router/A/B purposes return canonical Ed25519 scalar bytes
- `threshold-prf` vectors include Router/A/B purpose vectors
- `router-ab-core` has dev-only tests and benchmarks proving the
  Router/A/B purpose plan can drive the real `threshold-prf` DLEQ and combine
  path

Current limitation:

- Worker bundle-size and runtime evidence are still release gates.

## Design Decision

Use a thin adapter module inside `router-ab-core`.

Proposed module:

```text
crates/router-ab-core/src/derivation/candidate_mpc_prf_threshold_backend.rs
```

The module should be the only production code in `router-ab-core` that
imports `threshold_prf`.

The adapter converts:

| Router/A/B input                   | Threshold-PRF backend                                       |
| ---------------------------------- | ----------------------------------------------------------- |
| `MpcPrfPurposeBindingPlanV1`       | `threshold_prf::PrfContext`                                 |
| decrypted signer share bytes       | `threshold_prf::SigningRootShareWire::decode`           |
| signer output request              | `evaluate_partial_with_dleq_proof`                          |
| backend partial/proof bundle       | Router/A/B partial, commitment, and proof wire wrappers     |
| recipient verified partial package | `verify_partial_dleq_proof` and `combine_verified_partials` |
| backend output bytes               | `x_client_base` or `x_relayer_base` recipient material      |

Keep dependency direction one-way:

```text
router-ab-core -> threshold-prf
```

`threshold-prf` must not import Router/A/B types.

## Public API Shape

Add production adapter APIs as part of the selected Candidate A production
path.

Suggested signer-side API:

```rust
pub struct MpcPrfThresholdSignerInputV1 {
    pub signer_input: MpcPrfSignerPartialInputV1,
    pub output_request: MpcPrfOutputRequestV1,
    pub signing_root_share_wire: MpcPrfSigningRootShareWire,
    pub proof_rng: R,
}

pub fn evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
    input: MpcPrfThresholdSignerInputV1,
) -> RouterAbDerivationResult<MpcPrfPartialProofBundleV1>;
```

Suggested combiner-side API:

```rust
pub struct MpcPrfThresholdCombineInputV1 {
    pub transcript: TranscriptBinding,
    pub opened_share_kind: OpenedShareKind,
    pub recipient_role: Role,
    pub recipient_identity: String,
    pub left: MpcPrfPartialProofBundleV1,
    pub right: MpcPrfPartialProofBundleV1,
}

pub fn combine_mpc_prf_verified_partials_with_threshold_backend_v1(
    input: MpcPrfThresholdCombineInputV1,
) -> RouterAbDerivationResult<MpcPrfThresholdCombinedOutputV1>;
```

The exact type names can change during implementation. The important boundary
is that callers provide Router/A/B typed context, a normalized threshold policy,
and encrypted/decrypted share material at the adapter boundary, while the
adapter owns conversion into `threshold-prf` types.

## Policy Boundary

Router/A/B should normalize threshold-prf protocol selection at the request or
persistence boundary, then pass a precise internal policy into the adapter:

```rust
enum RouterAbThresholdPrfProtocol {
    ThresholdPrfRistretto255Sha512 {
        threshold: u16,
        share_count: u16,
    },
}
```

Initial production migration target:

- use `threshold_prf` with policy `2-of-3`
- keep Router/A/B output purpose labels as `router-ab/x_client_base/v1` and
  `router-ab/x_relayer_base/v1` until a separate Router/A/B context-version
  revision is planned
- replace backend wire assumptions at the adapter boundary:
  - signing-root share wire: `34` bytes
  - partial wire: `66` bytes
  - share commitment wire: `34` bytes
  - DLEQ proof wire: unchanged `64` bytes
- require exactly `policy.threshold` signer proof bundles before verified
  combine
- add parity tests against
  `crates/threshold-prf/fixtures/protocol-t-of-n.json`

## Secret Handling

The adapter must preserve these rules:

- decrypted signing-root share bytes enter only signer-local code
- decoded `threshold_prf::SigningRootShare` values stay inside the adapter call
- plaintext partial bytes stay signer-local until wrapped for recipient
  encryption
- Router-visible outputs are public metadata, commitments, proofs, encrypted
  packages, receipts, and diagnostics
- logs and diagnostics never include share bytes, partial bytes, scalar bytes,
  or plaintext package bytes
- source guards continue to reject serialization for plaintext secret wrappers

## Correctness And Binding

The adapter must check:

- `MpcPrfSignerPartialInputV1::validate`
- `MpcPrfOutputRequestV1::validate`
- request belongs to the signer input
- signer identity and root-share epoch match transcript
- Router/A/B purpose plan maps exactly to the expected `threshold-prf` purpose
- backend proof verifies against the supplied commitment and bound context
- two partials use distinct signer roles
- recipient binding matches `x_client_base -> client` or
  `x_relayer_base -> relayer`

The adapter should keep the existing `MpcPrfPurposeBindingPlanV1` as the single
source of truth for `threshold-prf::PrfContext` construction.

## Implementation Phases

### Phase 0: Current Compatibility Baseline

- [x] Add Router/A/B purposes to `threshold-prf`.
- [x] Add canonical scalar output encoding for Router/A/B purposes.
- [x] Add Router/A/B vectors to `threshold-prf`.
- [x] Add Router/A/B dev-only crypto-path tests in `router-ab-core`.
- [x] Capture Candidate A native crypto-path latency.

### Phase 1: Dependency Boundary

- [x] Decide whether Candidate A is selected for production.
- [x] Move `threshold-prf` from dev-dependency to a production dependency.
- [x] Add `candidate_mpc_prf_threshold_backend.rs`.
- [x] Re-export only the Router/A/B adapter functions and output types.
- [x] Keep raw `threshold_prf` types out of Router/A/B public production APIs
      unless there is a concrete reason to expose them.

### Phase 2: Signer Backend

- [x] Add a zeroizing Router/A/B signing-root-share wire wrapper if the
      existing `threshold-prf` wire type is too backend-specific for the public
      Router/A/B API.
- [x] Convert Router/A/B purpose plans into `threshold_prf::PrfContext`.
- [x] Decode the signer-local root-share wire.
- [x] Call `evaluate_partial_with_dleq_proof`.
- [x] Convert backend partial, commitment, and proof into existing Router/A/B
      wire wrappers.
- [x] Add tests for wrong share id, wrong signer role, wrong recipient, wrong
      epoch, and malformed share wire.

### Phase 3: Combiner Backend

- [x] Convert Router/A/B proof bundles into backend proof bundles.
- [x] Verify DLEQ proofs through `threshold-prf`.
- [x] Combine verified partials through `threshold-prf`.
- [x] Return a Router/A/B combined-output type scoped to the requested
      recipient.
- [x] Add tests for proof mismatch, transcript mismatch, duplicate signer
      role, recipient mismatch, and wrong-purpose partials.

### Phase 4: Vectors And Anti-Drift

- [x] Add Router/A/B Candidate A vectors that include backend partial,
      commitment, proof, verified-combine output, and rejection cases.
- [x] Add anti-drift tests comparing committed vectors to backend output.
- [x] Keep `threshold-prf` vectors as crypto primitive vectors.
- [x] Keep Router/A/B vectors as protocol-binding vectors.

### Phase 4A: Threshold-PRF Policy Boundary

- [x] Update this adapter plan to target a `threshold_prf` policy-aware
      backend.
- [x] Add a Router/A/B threshold-prf protocol-selection type that normalizes to
      `ThresholdPolicy`.
- [x] Migrate signer backend imports from the fixed-pair backend to
      `threshold_prf` with initial policy `2-of-3`.
- [x] Replace Router/A/B backend wire-width assumptions with signing-root,
      partial, and commitment widths.
- [x] Update combiner validation to require exactly `policy.threshold` verified
      proof bundles.
- [x] Add Router/A/B parity tests against the committed threshold-prf `2-of-3` fixture before adding broader `t-of-N` policies.

### Phase 5: Benchmarks And Wasm

- [ ] Keep native Candidate A crypto-path benchmarks in
      `benches/derivation_candidates.rs`.
- [x] Add wasm build checks with the production dependency enabled.
- [ ] Measure deployable Worker bundle size after a Worker adapter exists.
- [ ] Measure Cloudflare Worker runtime p50/p95 before release.
- [ ] Update `measurement-gates.md` with every completed gate.

### Phase 6: Release Gates

- [x] Candidate A selected as the production path.
- [x] Candidate B comparison gate closed for v1 production selection.
- [ ] No Router or shared server path can call signer-local backend APIs.
- [ ] Source guards reject plaintext partial/share serialization and logging.
- [ ] Vectors cover registration, export, and refresh.
- [ ] Native and wasm benchmarks are recorded.
- [ ] Address verification gate is wired before root rotation.

## Validation Commands

Run the focused checks after implementation:

```sh
rtk cargo test --manifest-path crates/threshold-prf/Cargo.toml
rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml
rtk cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates --no-run
rtk cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-unknown-unknown
rtk cargo build --manifest-path crates/router-ab-core/Cargo.toml --lib --release --target wasm32-wasip1
```

Run the full benchmark only when updating evidence:

```sh
rtk cargo bench --manifest-path crates/router-ab-core/Cargo.toml --bench derivation_candidates
```

## Open Decisions

- Whether Router/A/B public APIs should wrap decrypted signing-root share wires
  or accept `threshold_prf::SigningRootShareWire` directly.
- Whether proof verification is mandatory for Minimum Level C release or a
  stronger release gate.
- Whether the adapter should be feature-gated until Worker bundle and runtime
  release gates pass.
