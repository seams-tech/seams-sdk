# `threshold-prf` `t-of-N` Protocol And API Spec

Last updated: June 13, 2026

## Scope

This document specifies the active configurable `t-of-N` threshold-prf API for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

The crate derives project-scoped server HSS and Router/A/B input bytes from
threshold signing-root shares. HSS crates consume the resulting 32-byte values
after threshold-prf derivation. Storage, KMS, HSM, TEE, database behavior,
policy evaluation, and route authorization are owned by integration layers.

The crate root is the only active threshold-prf public protocol surface.
Downstream Router/A/B may still use `/v1` in purpose labels or serialized
Router/A/B request fields; those names identify Router/A/B protocol versions.

## Suite

```text
threshold-prf/ristretto255-sha512
```

The suite uses:

- Ristretto255
- canonical `curve25519-dalek` scalar encodings
- SHA-512 for hash-to-group input expansion
- SHA-512 for output hashing
- Shamir sharing over the Ristretto scalar field

## Threshold Policy

```text
1 <= threshold <= share_count <= MAX_SHARE_COUNT
valid_share_ids = {1, ..., share_count}
combine_count = threshold
```

The active operational `MAX_SHARE_COUNT` is 255. Share identifiers are encoded
as `u16` values, but public policy validation rejects larger operational
share sets to bound allocation and interpolation cost at request boundaries.

Raw threshold policy input is normalized into `ThresholdPolicy` once at the
boundary. Core split, reconstruct, combine, and verified-combine logic receives
validated policy and subset types. Invalid subset size, duplicate IDs, and IDs
outside the selected policy are rejected before interpolation or verification.

## Rust API

Callers import operations from `threshold_prf`:

```rust
use threshold_prf::{
    combine_verified_partials,
    evaluate_partial,
    split_signing_root,
    ThresholdPolicy,
    ValidatedThresholdSet,
};
use threshold_prf::trusted::combine_partials;
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};
```

The crate root exports:

- `ThresholdPolicy`
- `ThresholdShareId`
- `ValidatedThresholdSet<T>`
- `SigningRootScalar`
- `SigningRootShare`
- `SigningRootShareWire`
- `PrfPartial`
- `PrfPartialWire`
- `SigningRootShareCommitment`
- `PrfDleqProof`
- `PrfPartialProofBundle`
- `generate_signing_root`
- `split_signing_root`
- `evaluate_partial`
- `evaluate_partial_with_dleq_proof`
- `verify_partial_dleq_proof`
- `combine_verified_partials`
- `reference::evaluate_direct_reference`
- `recovery::reconstruct_signing_root`
- `trusted::combine_partials`

Production signing uses partial evaluation and `combine_verified_partials` for
peer-provided proof bundles. Direct `k_org -> output` evaluation is a reference
path for tests, vectors, recovery checks, and audits. `trusted::combine_partials`
is reserved for local authenticated partials, such as one-runtime derivation.

## Purposes

Current fixed production purposes:

- `ecdsa-hss/y_server`
- `ed25519-hss/y_server`
- `ed25519-hss/tau_server`
- `router-ab/x_client_base/v1`
- `router-ab/x_server_base/v1`

The Router/A/B purpose suffixes are Router/A/B transcript-version names. They do
not version the threshold-prf protocol.

No custom purpose is exposed in the production API. New integrations add a fixed
purpose through this spec and committed-vector updates.

## Transcript Encoding

All length prefixes are big-endian.

```text
u16be(len(domain)) || domain
u16be(len(suite_id)) || suite_id
u16be(len(purpose)) || purpose
u32be(len(context_bytes)) || context_bytes
u32be(len(payload)) || payload
```

`context_bytes` must already be a canonical, collision-resistant encoding of
the HSS request or Router/A/B transcript. Production integrations should use
frozen HSS or Router/A/B context encoders rather than ad hoc strings.

## Wire Formats

All integer fields are big-endian.

| Wire | Layout | Width |
| --- | --- | ---: |
| signing-root share | `u16be(share_id) || scalar[32]` | 34 bytes |
| partial | `u16be(share_id) || context_tag[32] || compressed_point[32]` | 66 bytes |
| commitment | `u16be(share_id) || compressed_point[32]` | 34 bytes |
| DLEQ proof | `challenge_scalar[32] || response_scalar[32]` | 64 bytes |
| proof bundle | partial wire + commitment wire + proof wire | 164 bytes |

Wire decoding validates fixed width, canonical scalar encodings where relevant,
compressed point encodings where relevant, and non-zero share IDs. Policy
membership is checked when the decoded item enters a `ValidatedThresholdSet`.

### Signing Root Share Wires

`SigningRootShareWire` is fixed-width secret material:

```text
u16be(share_id) || canonical_scalar(share_i)[32]
```

Rules:

- total length is exactly 34 bytes
- `share_id` must be non-zero
- `share_id` must be inside the selected policy when a threshold set is
  validated
- the scalar must be a canonical Ristretto scalar encoding
- zero share scalar encodings are valid Shamir shares

This format is for decrypted signing-root share material at the server SDK
boundary. Worker-to-worker transport uses partial wires.

### Partial Wires

```text
u16be(share_id) || context_tag[32] || compressed_ristretto(partial_point)[32]
```

Rules:

- total length is exactly 66 bytes
- `share_id` must be non-zero
- `context_tag` must equal the partial-context transcript hash for the supplied
  `PrfContext`
- the compressed point must decode as a Ristretto point
- policy and context are supplied by the boundary, then normalized before core
  combine logic

## Production Evaluation

One-runtime derivation evaluates and combines a threshold subset in the current
server SDK runtime:

```text
load ThresholdPolicy(threshold, share_count)
decrypt threshold signing-root share wires
validate the share set against the policy
partials = evaluate_partial(each share, context)
output = trusted::combine_partials(validated partial set, context)
```

Distributed verified partial combine evaluates partials across workers and
combines a transported threshold set:

```text
workers:
  load ThresholdPolicy(threshold, share_count)
  decrypt assigned signing-root share wires
  partial_i = evaluate_partial(assigned share_i, context)

combiner:
  validate a threshold partial set against the policy
  output = trusted::combine_partials(validated partial set, context)
```

Both modes use the same threshold partial evaluation and combine algorithm. For
every valid threshold subset and fixed context:

```text
direct_prf(k_org, context, purpose)
  == combine_prf_partials(threshold_subset, context, purpose)
```

## Trust Model

The trust model is split by deployment mode:

- One-runtime derivation observes a complete threshold subset of plaintext
  signing-root shares in one runtime. This protects against durable plaintext
  root storage. It does not claim malicious-runtime privacy.
- Distributed verified partial combine can keep every honest worker below
  threshold when share placement is configured that way.
- A combiner learns the requested output for the selected context and purpose.
  It must not receive plaintext signing-root scalars or plaintext
  signing-root share scalars.
- DLEQ proofs authenticate partials against supplied commitments. Deployment
  code must authenticate the commitment registry, TEE attestation, or equivalent
  source before claiming malicious-worker partial correctness.

## Sealed Share Boundary

The server SDK persistence boundary stores encrypted signing-root share bytes.
The threshold-prf crate consumes only decrypted 34-byte signing-root share
wires.

The active resolver shape is policy-aware:

- storage lists sealed share records by signing-root id and version
- a decrypt adapter returns plaintext share-wire bytes
- the resolver parses plaintext with the threshold-prf WASM parser
- the resolver selects exactly `threshold` distinct shares from the configured
  policy
- scratch plaintext buffers are zeroized after parsing

The retained SDK AES-GCM envelope for persisted sealed signing-root records is:

```text
magic[5] || nonce[12] || aes_gcm_ciphertext_and_tag
```

where:

- `magic = 0x74 0x70 0x72 0x73 0x01`
- `nonce` is a fresh 96-bit AES-GCM nonce
- the AEAD tag is the WebCrypto AES-GCM default 128-bit tag
- KEK material is AES-256-GCM only

This envelope is a persistence format. It is isolated from the core
threshold-prf protocol.

AES-GCM AAD is public metadata encoded as:

```text
u16be(len(domain))              || domain
u16be(len(signing_root_id))     || signing_root_id
u16be(len(signing_root_version))|| signing_root_version
u8(share_id)
u16be(len(kek_id))              || kek_id
```

with:

- `domain = "seams/signing-root-share/aes-gcm/v1"`
- `signing_root_id` trimmed and non-empty
- `signing_root_version` trimmed, or empty bytes when absent
- `kek_id` trimmed and non-empty

Opening a sealed share with different signing-root id, signing-root version,
share id, or KEK id must fail before plaintext is accepted.

## DLEQ

The crate implements a DLEQ proof that a transported partial point and a
root-share commitment use the same signing-root share scalar:

```text
commitment_i = [share_i]G
partial_i    = [share_i]P
```

Verified combine requires each proof bundle to bind:

- share ID
- partial point
- share commitment
- context tag
- PRF context

The combiner rejects malformed proofs, wrong context tags, mismatched
commitments, duplicate share IDs, wrong subset size, and share IDs outside the
selected policy.

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

Proof generation rejects zero nonce samples and retries. Nonce uniqueness
depends on a correct `CryptoRng`.

## WASM Boundary

The production WASM exports use explicit `threshold_prf_` names. Boundary
inputs are raw JS numbers and byte arrays. The WASM wrapper normalizes them into
policy and wire types before calling core Rust logic.

Current exported boundary groups:

- ECDSA HSS `y_server`
- Ed25519 HSS server inputs
- verified partial combine

## Fixtures And Verification

The committed threshold-policy vector corpus lives at:

```text
crates/threshold-prf/fixtures/protocol-t-of-n.json
```

Committed fixtures cover:

- `2-of-3`
- `3-of-5`
- Router/A/B `2-of-3` context bytes through the suite label
- direct reference evaluation
- every valid threshold subset for committed policies
- one-runtime and distributed-combine equivalence through `PrfPartialWire`
- fixed-width signing-root share and partial wire encodings

Current validation:

```bash
cargo test --manifest-path crates/threshold-prf/Cargo.toml
just threshold-prf-fv
just threshold-prf-wasm-smoke
```

Integration should also record the native, local WASM, and any required
deployed Worker benchmarks listed in
[benchmarks.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/benchmarks.md).
