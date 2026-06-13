# Threshold PRF Protocol

Date created: April 16, 2026
Last updated: June 13, 2026

## Scope

This crate derives project-scoped server HSS input bytes from signing-root
shares. The active protocol is the configurable `t-of-N` threshold-policy
surface exposed through `threshold_prf`.

It does not replace `ed25519-hss` or `ecdsa-hss`. It only provides the
server-side root input consumed by those protocols.

The primary HSS output is called `y_relayer` in HSS integration plans. The
`ed25519-hss/tau_relayer` purpose is also supported and is encoded as canonical
Ed25519 scalar bytes because the downstream Ed25519 HSS circuit requires scalar
inputs for tau. Router/A/B outputs use fixed `x_client_base` and
`x_relayer_base` purposes, and both are encoded as canonical Ed25519 scalar
bytes.

Router/A/B purpose labels currently end in `/v1` because they name the
Router/A/B transcript version:

```text
router-ab/x_client_base/v1
router-ab/x_relayer_base/v1
```

Those labels are serialized purpose names. They are separate from the
threshold-prf suite version.

## API Surface

Rust callers import protocol behavior through the crate root:

```rust
use threshold_prf::{
    combine_partials,
    combine_verified_partials,
    evaluate_partial,
    split_signing_root,
    ThresholdPolicy,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
```

The canonical API owns the configurable threshold API:

- `ThresholdPolicy`
- `ThresholdShareId`
- `ValidatedThresholdSet<T>`
- `SigningRootShare`
- `SigningRootShareWire`
- `PrfPartial`
- `PrfPartialWire`
- `SigningRootShareCommitment`
- `PrfDleqProof`
- `PrfPartialProofBundle`
- `combine_partials`
- `combine_verified_partials`

The crate root exposes context, purpose, output, suite, error, threshold-policy,
wire, split, partial-evaluation, proof, and combine APIs.

## Production Evaluation Semantics

Production signing must use threshold partial evaluation and combination.

Option A and Option B differ only in runtime placement:

- Option A: one runtime decrypts a threshold subset of signing-root shares,
  computes threshold partials, validates the partial set, and combines them into
  `y_relayer`.
- Option B: multiple runtimes each decrypt signing-root shares and compute
  partials; a combiner validates a threshold partial set and combines the
  partials into `y_relayer`.

The direct `k_org -> y_relayer` path is a reference path only. It exists for
tests, vectors, recovery checks, and implementation audits. It is not the
canonical production signing path.

The canonical API production paths should use `threshold_prf::evaluate_partial`,
`threshold_prf::ValidatedThresholdSet`, and
`threshold_prf::combine_partials`.

## Trust Model

The trust model is split by deployment mode:

- One-server Option A observes a complete threshold subset of plaintext
  signing-root shares in one runtime. This protects against durable plaintext
  root storage, but not against malicious signer code or runtime compromise.
- Multi-runtime Option B without DLEQ proofs or TEE attestation prevents any
  honest single worker from seeing enough local share material to reconstruct
  `k_org` when placement keeps every worker below threshold, but it does not
  prove that a remote worker honestly computed its partial.
- Multi-runtime Option B with DLEQ proofs lets the combiner reject a partial
  that does not match the supplied root-share commitment.
- A combiner learns `y_relayer` for the requested context and purpose. It must
  not receive plaintext signing-root scalars or plaintext signing-root share
  scalars.
- DLEQ proofs authenticate partials only against supplied commitments.
  Malicious-worker safety still requires authenticated commitment registration,
  TEE attestation, or an equivalent deployment-level authenticity mechanism.

## Suite

The active configurable threshold suite is:

```text
threshold-prf/ristretto255-sha512
```

The suite uses:

- Ristretto255 prime-order group
- canonical `curve25519-dalek` scalar encodings
- SHA-512 for hash-to-group input expansion
- SHA-512 for output hashing
- Shamir sharing over the Ristretto scalar field

## Threshold Policy

The canonical API threshold policy is explicit and validated at the boundary:

```text
1 <= threshold <= share_count <= MAX_SHARE_COUNT
valid_share_ids = {1, ..., share_count}
combine_count = threshold
```

Every split, reconstruct, combine, DLEQ verified-combine, and WASM boundary path
normalizes raw inputs into `ThresholdPolicy`, `ThresholdShareId`, and
`ValidatedThresholdSet<T>` before core combine logic runs. Invalid subset size,
duplicate IDs, and IDs outside the selected policy are rejected at this
validation boundary.

## Public Constants

The canonical API domain strings:

```text
input_domain           = "threshold-prf/input"
output_domain          = "threshold-prf/output"
partial_context_domain = "threshold-prf/partial-context"
dleq_domain            = "threshold-prf/dleq"
```

Fixed production purposes:

```text
ecdsa-hss/y_relayer
ed25519-hss/y_relayer
ed25519-hss/tau_relayer
router-ab/x_client_base/v1
router-ab/x_relayer_base/v1
```

No custom purpose is exposed in the production API. Tests, experiments, or
future integrations must add a new fixed purpose through a specs update rather
than feeding arbitrary output into HSS integrations.

## Encoding Rules

All scalar bytes are canonical Ristretto scalar bytes as accepted by
`Scalar::from_canonical_bytes`.

Scalar rules:

- `SigningRootScalar` is 32 canonical scalar bytes and must be non-zero.
- `SigningRootShare.value` is 32 canonical scalar bytes.
- malformed scalar encodings are rejected.
- zero signing-root scalar encodings are rejected.
- zero share scalar encodings are valid Shamir shares.

Share ID rules:

- share IDs are non-zero `u16` values.
- valid share IDs are exactly `1..=share_count`.
- share ID `0` is rejected.
- share IDs greater than the selected policy `share_count` are rejected by
  threshold-set validation.

Point rules:

- `PrfPartial` encodes one Ristretto point as 32 compressed bytes.
- `PrfPartial` also carries a 32-byte context tag.
- `PrfPartialWire` encodes one public u16 share ID, one context tag, and one
  compressed point.
- malformed compressed point encodings are rejected.

Output rules:

- `PrfOutput32` is exactly 32 bytes.
- raw-output purposes return opaque PRF output bytes.
- scalar-output purposes reduce the raw output hash with
  `Scalar::from_bytes_mod_order(raw32).to_bytes()`.

Secret signing-root share wire rules:

- `SigningRootShareWire` is fixed-width secret material:
  `u16be(share_id) || canonical_scalar(share_i)[32]`.
- total length is exactly 34 bytes.
- `share_id` must be non-zero and must be inside the selected policy when a
  threshold set is validated.
- the scalar must be a canonical Ristretto scalar encoding.
- zero share scalar encodings are valid Shamir shares.
- this format is for decrypted signing-root share material at the server SDK
  boundary; it is not a public worker-to-worker transport format.

## Transcript Encoding

All length prefixes are big-endian.

General PRF transcript:

```text
u16be(len(domain)) || domain
u16be(len(suite_id)) || suite_id
u16be(len(purpose)) || purpose
u32be(len(context_bytes)) || context_bytes
u32be(len(payload)) || payload
```

`context_bytes` must already be a canonical, collision-resistant encoding of
the HSS request or Router/A/B transcript. No production integration may use ad
hoc strings such as `project:alpha/wallet:0` as canonical context bytes.

## Partial Wire Format

The worker-to-worker partial wire format is fixed-width:

```text
partial_wire =
  u16be(share_id) || context_tag[32] || compressed_ristretto(partial_point)[32]
```

Rules:

- total length is exactly 66 bytes.
- `share_id` must be non-zero and inside the selected policy when a threshold
  set is validated.
- `context_tag` must equal the partial-context transcript hash for the
  supplied `PrfContext`.
- the compressed point must decode as a Ristretto point.
- the wire format does not include `suite_id`, `purpose`, `context`,
  `threshold`, or `share_count`.
- WASM and request boundaries must supply the expected policy and context and
  normalize partial wires into a `ValidatedThresholdSet<PrfPartial>`.

Security boundary:

- worker-to-worker partial wires are public with respect to share ID, context
  tag, and PRF partial point.
- partial wires are bound to exactly one context tag.
- a combiner must decode transported partials through the fixed-width wire
  decode path before combining them.
- combining partials with a different context is rejected.

## DLEQ Partial Authenticity

The crate implements a DLEQ proof that a transported partial point and a
root-share commitment use the same signing-root share scalar:

```text
commitment_i = [share_i]G
partial_i    = [share_i]P
```

The proof statement is equality of discrete log between `(G, commitment_i)` and
`(P, partial_i)`.

Share commitment wire format:

```text
share_commitment_wire =
  u16be(share_id) || compressed_ristretto(commitment_point)[32]
```

Rules:

- commitment length is exactly 34 bytes.
- `share_id` must be non-zero and inside the selected policy when proof bundles
  are validated.
- the commitment point must decode as a Ristretto point.
- commitments must be authenticated by deployment state; DLEQ proves consistency
  with a supplied commitment, not that the commitment itself is authorized.

DLEQ proof wire format:

```text
dleq_proof_wire =
  canonical_scalar(challenge)[32] || canonical_scalar(response)[32]
```

Rules:

- proof length is exactly 64 bytes.
- challenge and response must both be canonical scalar encodings.
- proof generation rejects zero nonce samples and retries.
- proof verification rejects wrong context, wrong share ID, wrong commitment,
  wrong partial, and tampered proof scalars.

The DLEQ challenge transcript is:

```text
u16be(len("threshold-prf/dleq")) || "threshold-prf/dleq"
u16be(len(suite_id)) || suite_id
u16be(len(purpose)) || purpose
context_tag[32]
u16be(share_id)
compressed_ristretto(G)[32]
compressed_ristretto(P)[32]
compressed_ristretto(commitment_i)[32]
compressed_ristretto(partial_i)[32]
compressed_ristretto(nonce_G)[32]
compressed_ristretto(nonce_P)[32]
```

## Required Invariant

For every valid threshold subset and every fixed context:

```text
direct_prf(k_org, context, purpose)
  == combine_prf_partials(threshold_subset, context, purpose)
  == y_relayer
```

Option A computes a threshold subset of partials and combines them in one
runtime.

Option B computes the partials across multiple workers and combines a validated
threshold set afterward.

Both options must use the same threshold partial evaluation and combine
algorithm, and both options must produce byte-identical output.

## Vectors

The threshold-policy vector corpus pins:

- root generation from fixed seed material
- policy-shaped 2-of-3 and 3-of-5 splitting
- direct reference evaluation
- every valid threshold subset for the committed policies
- Option A and Option B equivalence through `PrfPartialWire`
- fixed-width signing-root share and partial wire encodings
- representative production purposes:
  - `ecdsa-hss/y_relayer`
  - `router-ab/x_relayer_base/v1`

The committed vector corpus must live at:

```text
crates/threshold-prf/fixtures/protocol-t-of-n.json
```

The corpus schema is:

- `schema_id`
- `vectors`

Each `vectors[]` item has:

- `suite_id`
- `purpose`
- `context_hex`
- `policy`, with `threshold` and `share_count`
- `root_seed_hex`
- `split_seed_hex`
- `root_scalar_hex`
- `shares`, each with `id`, `scalar_hex`, and `wire_hex`
- `partials`, each with:
  - `id`
  - `context_tag_hex`
  - `compressed_point_hex`
  - `wire_hex`
- `direct_output_hex`
- `threshold_outputs`, each with `ids` and `output_hex`

The committed corpus must contain at least:

- a 2-of-3 `ecdsa-hss/y_relayer` vector
- a 2-of-3 Router/A/B relayer vector
- a 3-of-5 Router/A/B relayer vector

Fixture randomness is deterministic and part of the spec:

- `root_seed_hex` initializes `rand_chacha 0.3.1` `ChaCha20Rng::from_seed`.
- `root_scalar_hex` is the first non-zero `curve25519-dalek 4.1.3`
  `Scalar::random` output from that RNG.
- `split_seed_hex` initializes a separate `ChaCha20Rng::from_seed`.
- Shamir coefficients are non-zero `Scalar::random` outputs from the split RNG.

## Integration Gates

Do not integrate `threshold-prf` into HSS wallet derivation until:

- this protocol spec is frozen
- the committed JSON vector corpus exists
- vector parity passes for direct reference, Option A, and Option B
- HSS context encodings are frozen
- benchmark numbers are recorded for native and any required Worker/WASM target
- DLEQ or an equivalent authenticity mechanism is selected for any
  multi-runtime deployment that must reject malicious partials
