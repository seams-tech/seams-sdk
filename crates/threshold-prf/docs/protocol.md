# Threshold PRF Protocol

Date created: April 16, 2026
Last updated: April 17, 2026

## Scope

This crate derives project-scoped server HSS input bytes from a 2-of-3
signing-root sharing.

It does not replace `ed25519-hss` or `ecdsa-hss`. It only provides the
server-side root input consumed by those protocols.

The primary output is called `y_relayer` in HSS integration plans. The
`ed25519-hss/tau_relayer` purpose is also supported and is encoded as canonical
Ed25519 scalar bytes because the downstream Ed25519 HSS circuit requires scalar
inputs for tau.

## Production Evaluation Semantics

Production signing must use threshold partial evaluation and combination.

Option A and Option B differ only in runtime placement:

- Option A: one runtime decrypts two signing-root shares, computes two partials,
  and combines them into `y_relayer`.
- Option B: two runtimes each decrypt one signing-root share, each computes one
  partial, and a combiner combines the partials into `y_relayer`.

The direct `k_org -> y_relayer` path is a reference path only. It exists for
tests, vectors, recovery checks, and implementation audits. It is not the
canonical production signing path.

The canonical one-runtime Option A Rust helper is
`derive_output_from_signing_root_shares(shares, context)`. It must accept
exactly two decrypted signing-root shares, compute two threshold partials, and
combine them. It must not reconstruct `k_org` as the production derivation
mechanism.

## Trust Model

The v1 trust model is split by deployment mode:

- One-server Option A observes two plaintext signing-root shares in one runtime.
  This protects against durable plaintext root storage, but not against
  malicious signer code or runtime compromise.
- Two-server Option B without DLEQ proofs or TEE attestation prevents either
  honest single worker from seeing enough local share material to reconstruct
  `k_org`, but it does not prove that a remote worker honestly computed its
  partial.
- Two-server Option B with DLEQ proofs lets the combiner reject a partial that
  does not match the supplied root-share commitment.
- A combiner learns `y_relayer` for the requested context and purpose. It must
  not receive plaintext signing-root scalars or plaintext signing-root share
  scalars.
- DLEQ proofs authenticate partials only against supplied commitments.
  Malicious-worker safety still requires authenticated commitment registration,
  TEE attestation, or an equivalent deployment-level authenticity mechanism.

## Suite

Version 1 supports exactly one suite:

```text
threshold-prf/ristretto255-sha512/v1
```

The suite uses:

- Ristretto255 prime-order group
- canonical `curve25519-dalek` scalar encodings
- SHA-512 for hash-to-group input expansion
- SHA-512 for output hashing
- Shamir sharing over the Ristretto scalar field

## Public Constants

Domain strings:

```text
input_domain           = "threshold-prf:v1/input"
output_domain          = "threshold-prf:v1/output"
partial_context_domain = "threshold-prf:v1/partial-context"
```

Fixed production purposes:

```text
ecdsa-hss/y_relayer
ed25519-hss/y_relayer
ed25519-hss/tau_relayer
```

No custom purpose is exposed in the v1 production API. Tests, experiments, or
future integrations must add a new fixed purpose through a specs update rather
than feeding arbitrary `Custom(bytes)` output into HSS integrations.

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

- share IDs are one byte conceptually, exposed as integers.
- valid share IDs are exactly `1`, `2`, and `3`.
- share ID `0` is rejected.
- share IDs greater than `3` are rejected.

Point rules:

- `PrfPartial` encodes one Ristretto point as 32 compressed bytes.
- `PrfPartial` also carries a 32-byte context tag.
- `PrfPartialWireV1` encodes one public share ID, one context tag, and one
  compressed point.
- malformed compressed point encodings are rejected.
- the identity point is not separately rejected in v1.

Output rules:

- `PrfOutput32` is exactly 32 bytes.
- most output bytes are opaque PRF output bytes, not scalar encodings.
- `ed25519-hss/tau_relayer` is the exception: its raw output hash is reduced
  with `Scalar::from_bytes_mod_order` and returned as canonical Ed25519 scalar
  bytes.

Secret signing-root share wire rules:

- `SigningRootShareWireV1` is fixed-width secret material:
  `u8(share_id) || canonical_scalar(share_i)[32]`.
- total length is exactly 33 bytes.
- `share_id` must be one of `1`, `2`, or `3`.
- the scalar must be a canonical Ristretto scalar encoding.
- zero share scalar encodings are valid Shamir shares.
- this format is for decrypted signing-root share material at the server SDK
  boundary; it is not a public worker-to-worker transport format.
- server SDK Option A derivation should decode decrypted share bytes through
  `SigningRootShareWireV1::decode` or `SigningRootShareWireV1::decode_slice`,
  then call
  `derive_output_from_signing_root_share_wires`.

## Transcript Encoding

Hash-to-group and output hashing both use the same transcript framing:

```text
transcript(domain, suite_id, purpose, context, payload) =
  u16be(len(domain))   || domain
  u16be(len(suite_id)) || suite_id
  u16be(len(purpose))  || purpose
  u32be(len(context))  || context
  u32be(len(payload))  || payload
```

Rules:

- `suite_id` is the exact suite identifier byte string.
- `purpose` is the exact purpose byte string.
- `context` is caller-provided canonical context bytes.
- this crate does not parse, trim, or normalize `context`.
- the HSS integration layer is responsible for defining canonical context bytes.
- transcript length prefixes are big-endian.
- `domain`, `suite_id`, and `purpose` lengths must fit in `u16`.
- `context` and `payload` lengths must fit in `u32`.

## Hash-To-Group

For context `ctx`:

```text
P = Ristretto255.hash_from_bytes<SHA-512>(
      transcript(input_domain, suite_id, purpose, context, empty_payload)
    )
```

The hash-to-group primitive itself is treated as a trusted suite primitive.

## Output Hashing

For a Ristretto point `Z`:

```text
encoded_Z = compressed_ristretto(Z)
digest64  = SHA-512(transcript(output_domain, suite_id, purpose, context, encoded_Z))
raw32     = digest64[0..32]
output32  = purpose_output_encoding(purpose, raw32)
```

The output hash primitive itself is treated as a trusted suite primitive.

Purpose-specific output encoding:

- `ecdsa-hss/y_relayer`: `raw32`
- `ed25519-hss/y_relayer`: `raw32`
- `ed25519-hss/tau_relayer`: `Scalar::from_bytes_mod_order(raw32).to_bytes()`

## Partial Context Tag

Every partial is bound to the context used when it was produced:

```text
partial_context_tag =
  SHA-512(transcript(partial_context_domain, suite_id, purpose, context, empty_payload))[0..32]
```

Combining partials with a different context is rejected. This prevents a caller
from accidentally mixing a partial generated for one wallet/purpose with a
combine call for another wallet/purpose.

For transported partials, the context tag is part of the wire format. A decoder
must recompute the expected context tag from the caller-provided `PrfContext` and
reject the wire partial if the transmitted tag differs.

## Partial Wire Format

The v1 worker-to-worker partial wire format is fixed-width:

```text
partial_wire_v1 =
  u8(share_id) || context_tag[32] || compressed_ristretto(partial_point)[32]
```

Rules:

- total length is exactly 65 bytes.
- `share_id` must be one of `1`, `2`, or `3`.
- `context_tag` must equal
  `SHA-512(transcript(partial_context_domain, suite_id, purpose, context, empty_payload))[0..32]`.
- the compressed point must decode as a Ristretto point.
- the wire format does not include `suite_id`, `purpose`, or `context`.
- the caller must supply the expected `PrfContext` when decoding.
- decoding binds the partial to the supplied context by comparing the transmitted
  tag to the recomputed `partial_context_tag`.
- the only public decode path for transported partial bytes is context-bound:
  `PrfPartialWireV1::decode(context, bytes) -> PrfPartial`.
- raw container parsing is internal only; external callers cannot construct a
  `PrfPartial` from transported bytes without supplying the expected context.
- compressed-point partial construction is internal only; external callers must
  use the fixed-width wire decode path for transported partials.

Security boundary:

- the wire format prevents accidental malformed input and context-mixing bugs.
- it does not prove that a remote worker honestly computed `[share_i]P`.
- DLEQ proof verification is the separate protocol layer for checking a partial
  against a supplied root-share commitment.
- deployment code must still authenticate the commitment source before claiming
  malicious-worker safety.

## DLEQ Partial Authenticity

The crate implements a v1 DLEQ proof that a transported partial point and a
root-share commitment use the same signing-root share scalar.

Share commitment wire format:

```text
share_commitment_wire_v1 =
  u8(share_id) || compressed_ristretto([share_i]G)[32]
```

Rules:

- total length is exactly 33 bytes.
- `share_id` must be one of `1`, `2`, or `3`.
- the compressed point must decode as a Ristretto point.

DLEQ proof wire format:

```text
dleq_proof_wire_v1 =
  challenge_scalar[32] || response_scalar[32]
```

Rules:

- total length is exactly 64 bytes.
- both scalars must be canonical Ristretto scalar encodings.
- proof generation must reject and retry a zero nonce.
- nonce uniqueness and unpredictability depend on a correct `CryptoRng`.
- reusing a DLEQ nonce across distinct statements can reveal the signing-root
  share scalar.

Proof generation:

```text
G = Ristretto255 basepoint
P = HashToGroup(context)
A = [share_i]G
B = [share_i]P
r <- random non-zero scalar
R_G = [r]G
R_P = [r]P
c = DLEQChallenge(suite_id, purpose, context_tag, share_id, G, P, A, B, R_G, R_P)
z = r + c*share_i
proof = (c, z)
```

Verification recomputes:

```text
R_G' = [z]G - [c]A
R_P' = [z]P - [c]B
c' = DLEQChallenge(suite_id, purpose, context_tag, share_id, G, P, A, B, R_G', R_P')
```

and accepts only if `c == c'`.

The challenge transcript binds:

- `suite_id`
- `purpose`
- `context_tag`
- `share_id`
- suite base point `G`
- PRF input point `P`
- root-share commitment `[share_i]G`
- partial point `[share_i]P`
- proof nonce point `[r]G`
- proof nonce point `[r]P`

The challenge scalar is derived as:

```text
dleq_challenge =
  ScalarFromWide(SHA-512(
    u16be(len("threshold-prf:v1/dleq")) || "threshold-prf:v1/dleq"
    || u16be(len(suite_id)) || suite_id
    || u16be(len(purpose))  || purpose
    || context_tag[32]
    || u8(share_id)
    || compressed_ristretto(G)[32]
    || compressed_ristretto(P)[32]
    || compressed_ristretto(A)[32]
    || compressed_ristretto(B)[32]
    || compressed_ristretto(R_G)[32]
    || compressed_ristretto(R_P)[32]
  ))
```

This proves partial correctness against the supplied commitment. It does not by
itself authenticate the commitment, transport, runtime, or storage layer.
Option B still needs an authenticated commitment registry, TEE attestation, or
an equivalent deployment-level authenticity mechanism before malicious-worker
safety can be claimed.

When DLEQ is the chosen Option B authenticity mechanism, combiner code should
use `combine_verified_partials(bundles, context)`. That API verifies each
partial's DLEQ proof against its supplied root-share commitment before
combining the two partial points.

## Shamir Sharing

Version 1 uses fixed 2-of-3 Shamir sharing over the Ristretto scalar field.

Project-root generation:

```text
k_org <- random non-zero scalar
```

Splitting:

```text
a <- random non-zero scalar
f(x) = k_org + a*x
share_1 = f(1)
share_2 = f(2)
share_3 = f(3)
```

The splitter does not retry zero share values. A zero share is a valid Shamir
share and is still bound to its share ID.

Reconstruction from exactly two distinct shares `(x_i, y_i)` and `(x_j, y_j)`:

```text
lambda_i = x_j / (x_j - x_i)
lambda_j = x_i / (x_i - x_j)
k_org    = lambda_i*y_i + lambda_j*y_j
```

All arithmetic is modulo the Ristretto scalar field order.

Valid reconstruction inputs:

- exactly two shares
- distinct share IDs
- share IDs in `{1, 2, 3}`
- canonical share scalars

Invalid reconstruction inputs:

- one share
- more than two shares
- duplicate share IDs
- malformed scalar encodings
- unsupported share IDs

## Direct Reference Evaluation

The direct reference path is:

```text
P = HashToGroup(context)
Z = [k_org] P
y_relayer = OutputHash(Z, context)
```

This path is for tests, vectors, and recovery checks. It is not the preferred
production signing path.

## Threshold Evaluation

Partial evaluation for share `(x_i, y_i)`:

```text
P = HashToGroup(context)
partial_i = (x_i, partial_context_tag, [y_i] P)
```

Combination for exactly two distinct partials:

```text
Z = lambda_i * partial_i.point + lambda_j * partial_j.point
y_relayer = OutputHash(Z, context)
```

The Lagrange coefficients are computed from the partial share IDs using the
same formulas as Shamir reconstruction.

## Required Invariant

For every valid 2-of-3 share pair and every fixed context:

```text
direct_prf(k_org, context, purpose)
  == combine_prf_partials([partial_i, partial_j], context, purpose)
  == y_relayer
```

Option A computes both partials and combines them in one worker.

Option B computes the partials on separate workers and combines them afterward.

Both options must use the same threshold partial evaluation and combine
algorithm, and both options must produce byte-identical output.

## Refresh

Share refresh reconstructs the current root and resplits it into a new 2-of-3
sharing in the prototype implementation.

Refresh must preserve:

```text
direct_prf(k_org, context, purpose)
```

for all contexts and purposes.

A future distributed refresh may replace the implementation while preserving the
same public API and output invariant.

## Failure Behavior

The crate must return typed errors for:

- invalid scalar encoding
- invalid point encoding
- zero signing-root scalar
- invalid share ID
- invalid threshold subset size
- duplicate share ID
- partial context mismatch
- transcript length overflow

The crate must not panic on malformed public inputs.

Transcript field length overflow is a typed error. Public input decoding,
partial decoding, partial combination, direct reference evaluation, and partial
evaluation must not panic on malformed public inputs.

## Secret Handling

Debug output must redact:

- signing-root scalar
- signing-root share scalar
- PRF partial point
- PRF partial context tag
- PRF output bytes

Root and share scalar containers must zeroize on drop.

## HSS Integration Contexts

The HSS integration layer is responsible for canonical context bytes, but those
bytes directly determine `y_relayer` and therefore downstream signing material.

Before this crate feeds `ed25519-hss` or `ecdsa-hss`, each integration must use
one of the frozen context encodings below:

- `ecdsa-hss/y_relayer`
- `ed25519-hss/y_relayer`
- `ed25519-hss/tau_relayer`

### `ecdsa-hss/y_relayer`

The v1 ECDSA context bytes are the existing `ecdsa-hss` canonical context
encoding:

```text
ecdsa_hss_context_v1 =
  "ecdsa-hss:context:v1"
  || u16be(len("ecdsa-hss-v1")) || "ecdsa-hss-v1"
  || u16be(len("secp256k1"))    || "secp256k1"
  || u16be(len(near_account_id_ascii)) || near_account_id_ascii
  || u16be(len(key_purpose_ascii))     || key_purpose_ascii
  || u16be(len(key_version_ascii))     || key_version_ascii
  || u8(2)
  || u16be(1)
  || u16be(2)
```

The threshold-PRF purpose must be `ecdsa-hss/y_relayer`.

The downstream `ecdsa-hss` consumer currently treats the resulting
`y_relayer[32]` as little-endian integer input interpreted modulo `2^256`, then
uses the HSS protocol's existing scalar handling. Threshold-PRF does not parse
or reduce the output.

### `ed25519-hss/y_relayer` And `ed25519-hss/tau_relayer`

The v1 Ed25519 context bytes are the 32-byte SHA-256 binding digest produced by
`Ed25519HssCanonicalContextV1`:

```text
ed25519_hss_context_digest_v1 =
  SHA-256(
    "succinct-garbling-proto/context-binding/v1"
    || u32be(len(org_id))       || org_id_utf8
    || u32be(len(account_id))   || account_id_utf8
    || u32be(len(key_purpose))  || key_purpose_utf8
    || u32be(len(key_version))  || key_version_utf8
    || u32be(participant_count)
    || participant_id_1_u16be
    || ...
    || participant_id_n_u16be
    || u32be(derivation_version)
  )
```

Normalization rules:

- `org_id`, `account_id`, `key_purpose`, and `key_version` must be non-empty
  UTF-8 strings with no leading or trailing whitespace.
- `participant_ids` must be non-zero `u16` values, sorted, deduplicated, and
  contain at least two participants.
- `derivation_version` is encoded as `u32be`.

The same Ed25519 context bytes are used for both server outputs. The
threshold-PRF purpose distinguishes:

- `ed25519-hss/y_relayer`
- `ed25519-hss/tau_relayer`

The downstream `ed25519-hss` consumer treats `y_relayer` as opaque 32-byte input
to the HSS seed expansion. It treats `tau_relayer` as an Ed25519 scalar input,
so threshold-PRF reduces the `ed25519-hss/tau_relayer` purpose output and
returns canonical scalar bytes.

No production HSS integration may use ad hoc strings such as
`project:alpha/wallet:0` as canonical context bytes.

## Vectors

The v1 vector corpus pins:

- root generation from fixed seed material
- 2-of-3 splitting
- direct reference evaluation
- every valid pairwise threshold combine path
- Option A and Option B equivalence through `PrfPartialWireV1`
- share refresh
- root-share commitment and DLEQ proof vectors for each partial
- malformed-input rejection cases where practical
- all fixed production purposes:
  - `ecdsa-hss/y_relayer`
  - `ed25519-hss/y_relayer`
  - `ed25519-hss/tau_relayer`

The committed vector corpus must live at:

```text
crates/threshold-prf/fixtures/protocol-v1.json
```

The corpus schema is:

- `schema_id`
- `vectors`

Each `vectors[]` item has:

- `suite_id`
- `purpose`
- `context_hex`
- `root_seed_hex`
- `split_seed_hex`
- `root_scalar_hex`
- `shares`, each with `id`, `scalar_hex`, and `wire_hex`
- `partials`, each with:
  - `id`
  - `context_tag_hex`
  - `compressed_point_hex`
  - `wire_hex`
  - `share_commitment_wire_hex`
  - `dleq_proof_seed_hex`
  - `dleq_proof_wire_hex`
- `direct_output_hex`
- `pairwise_outputs`, each with `ids` and `output_hex`
- `refresh_seed_hex`
- `refresh_input_share_ids`
- `refreshed_shares`, each with `id`, `scalar_hex`, and `wire_hex`
- `refreshed_pairwise_outputs`
- `invalid_cases`, each with `name` and `expected_error`

The committed corpus must contain exactly one vector for each v1 production
purpose:

- `ecdsa-hss/y_relayer`
- `ed25519-hss/y_relayer`
- `ed25519-hss/tau_relayer`

Fixture randomness is deterministic and part of the spec:

- `root_seed_hex` initializes `rand_chacha 0.3.1` `ChaCha20Rng::from_seed`.
- `root_scalar_hex` is the first non-zero `curve25519-dalek 4.1.3`
  `Scalar::random` output from that RNG.
- `split_seed_hex` initializes a separate `ChaCha20Rng::from_seed`.
- the Shamir slope is the first non-zero `Scalar::random` output from the split
  RNG.
- `refresh_seed_hex` initializes a separate `ChaCha20Rng::from_seed` for
  refresh splitting after reconstructing from `refresh_input_share_ids`.
- `dleq_proof_seed_hex` initializes a separate `ChaCha20Rng::from_seed` for
  deterministic DLEQ proof nonce generation for that partial vector.

## Formal Verification Targets

The first formal-verification slice should prove, in an abstract model:

- valid 2-of-3 subset rules
- duplicate and insufficient-subset rejection
- Lagrange reconstruction shape
- direct-vs-threshold equivalence
- Option A and Option B placement equivalence
- partial wire decoding preserves share ID, context tag, and compressed point
- context-tag mismatch rejection
- DLEQ commitment/proof boundary shape
- DLEQ wrong-context and wrong-share-ID rejection

The initial proof track does not prove Ristretto, SHA-512, hash-to-group,
randomness generation, runtime isolation, transport behavior, side-channel
resistance, Fiat-Shamir soundness, or DLEQ malicious-worker security from first
principles.

## Integration Gates

Do not integrate `threshold-prf` into HSS wallet derivation until:

- this protocol spec is frozen
- the committed JSON vector corpus exists
- vector parity passes for direct reference, Option A, and Option B
- HSS context encodings are frozen
- benchmark numbers are recorded for native and any required Worker/WASM target
- dependencies are reviewed
- root/share zeroization is implemented
- Option A and Option B output parity is pinned
- DLEQ/TEE is either implemented or explicitly deferred with honest/semi-honest
  Option B deployment language
