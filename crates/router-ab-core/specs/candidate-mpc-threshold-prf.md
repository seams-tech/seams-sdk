# Candidate Spec: MPC Threshold PRF

Candidate id: `mpc_threshold_prf_v1`

This candidate derives output material from A/B threshold PRF partials. It is
the leading candidate when we want straightforward refresh and established
partial-verification machinery.

## State

Signer A holds:

- `prf_share_a`
- Signer A identity key
- current root-share epoch
- candidate suite id

Signer B holds:

- `prf_share_b`
- Signer B identity key
- current root-share epoch
- candidate suite id

Router holds:

- public account scope
- role identities
- replay state
- encrypted envelopes and package commitments

Router does not hold plaintext PRF shares or plaintext output partials.

## Output Inputs

Each output derivation binds:

- transcript digest
- output kind: `x_client_base` or `x_relayer_base`
- recipient role
- recipient identity
- candidate id
- root-share epoch

## Preferred Combine Location

The preferred combine location is the final recipient:

- client combines client-output partials and opens `x_client_base`
- relayer combines relayer-output partials and opens `x_relayer_base`

Router must not combine plaintext partials.

If the relayer is Signer A, Signer A may combine relayer-output partials for
`x_relayer_base`. That does not grant access to `x_client_base`.

## Message Flow

Registration, export, and refresh use the same candidate-local shape:

1. Router creates transcript and role envelopes.
2. Router sends encrypted signer input to A and B.
3. A and B validate transcript, signer identity, and epoch.
4. A derives A-side partials for client and relayer outputs.
5. B derives B-side partials for client and relayer outputs.
6. A encrypts client partials to the client and relayer partials to the
   relayer.
7. B encrypts client partials to the client and relayer partials to the
   relayer.
8. A and B return authenticated receipts and package commitments.
9. Minimum Level C verifies transcript and delivery binding.
10. Recipients decrypt and combine their own partials.

No A/B coordination round trip is required for the basic PRF partial path
unless the selected proof system requires an interactive proof.

## Partial Format

Implemented adapter types:

- `MpcPrfSignerPartialInputV1`
- `MpcPrfOutputRequestV1`
- `MpcPrfPartialBindingV1`
- `MpcPrfPartialWireV1`
- `MpcPrfSignerPartialV1`

Required public binding fields:

- suite id
- transcript digest
- root-share epoch
- output kind: `x_client_base` or `x_relayer_base`
- recipient role
- recipient identity
- signer role
- signer identity

`partial bytes` are secret until delivered to the recipient.
`MpcPrfPartialWireV1` is fixed-width, zeroizing, debug-redacted, and
intentionally non-serializable. Adapters must encrypt partial bytes before
transport.

## Proof Format

The preferred proof format is the existing `threshold-prf` DLEQ proof shape:

- partial wire length: 65 bytes
- share commitment wire length: 33 bytes
- DLEQ proof wire length: 64 bytes

Implemented adapter types:

- `MpcPrfShareCommitmentWireV1`
- `MpcPrfDleqProofWireV1`
- `MpcPrfPartialProofBundleV1`
- `MpcPrfPartialVerificationInputV1`
- `MpcPrfPartialVerificationPlanV1`
- `MpcPrfVerifiedPartialV1`

Implemented planner: `plan_mpc_prf_partial_verification_v1`.

The planner validates:

- context candidate id is `mpc_threshold_prf_v1`
- partial transcript digest matches the transcript
- root-share epoch matches the transcript context
- signer role and identity match the transcript signer set
- recipient role matches the opened share kind
- partial, commitment, and proof wires use fixed v1 lengths

`MpcPrfVerifiedPartialV1` may only be constructed by an adapter after the DLEQ
statement has been verified against the authenticated signer commitment
registry. Native cryptographic benchmarks now exercise the real
`threshold-prf` DLEQ path through Router/A/B purpose-bound context bytes.

If proof cost is too high, Minimum Level C may defer proof verification and rely
on address verification before activation.

## Purpose Binding

Implemented adapter type: `MpcPrfPurposeBindingPlanV1`.

Implemented planner: `plan_mpc_prf_purpose_binding_v1`.

The planner validates the signer input, confirms the output request belongs to
that input, and emits signer-neutral context bytes for the underlying
`threshold-prf` call. Signer A and Signer B must derive identical PRF context
bytes for the same transcript and output request.

The context bytes bind:

- Router/A/B Candidate A context-byte version
- Candidate A suite id
- external `threshold-prf` suite label
- external `threshold-prf` purpose label
- required output encoding
- transcript digest
- opened share kind
- recipient role
- recipient identity

Canonical external purpose labels:

- `router-ab/x_client_base/v1`
- `router-ab/x_relayer_base/v1`

Both outputs require `canonical_ed25519_scalar_32` encoding.

## Relation To `threshold-prf`

Decision: reuse `threshold-prf` cryptographic internals through a narrow
Router/A/B adapter. Do not mirror Ristretto, Shamir, or DLEQ arithmetic in this
crate.

Reasons:

- `threshold-prf` already provides partial evaluation, fixed-width partial
  wires, DLEQ proof generation and verification, verified combining, redacted
  debug output, zeroizing share containers, vectors, dependency review, and
  benchmark scaffolding.
- Reusing it avoids creating a second curve-arithmetic implementation.
- Router/A/B can enforce stricter role, recipient, transcript, and encryption
  boundaries in this crate.

Current adapter boundary:

- `threshold-prf::PrfPurpose` includes `router-ab/x_client_base/v1` and
  `router-ab/x_relayer_base/v1`.
- Both Router/A/B purposes return canonical Ed25519 scalar bytes.
- Router/A/B Candidate A has a typed purpose-binding plan for `x_client_base`
  and `x_relayer_base`.

## Combiner Behavior

Implemented adapter type: `MpcPrfCombinerInputV1`.

Implemented planner: `plan_mpc_prf_combine_v1`.

The planner validates:

- context candidate id is `mpc_threshold_prf_v1`
- two verified partials bind the same transcript digest
- partials bind the requested recipient role and identity
- `x_client_base` outputs target the client
- `x_relayer_base` outputs target the relayer
- signer roles are distinct
- signer identities match the transcript signer set

The planner returns `MpcPrfCombinePlanV1`. Native benchmarks cover the
underlying `threshold-prf` verified-combine path.

## A/B Coordination Messages

Candidate A v1 has no direct A/B coordination messages for registration,
export, or refresh in the basic partial path. Router sends role-specific input
envelopes. Each signer independently derives partials, produces output
packages, and returns receipts.

Future interactive proof systems must introduce a new coordination-message
version and new vectors.

## Recipient Encryption Boundary

Plaintext partial wires are signer-local until encrypted to the designated
recipient. Router-visible payloads must be encrypted packages and public
commitments.

The Rust adapter reinforces this by keeping `MpcPrfPartialWireV1`,
`MpcPrfSignerPartialV1`, `MpcPrfPartialProofBundleV1`, and
`MpcPrfVerifiedPartialV1` out of Serde serialization. Boundary adapters can
extract bytes for encryption, then zeroize the plaintext wrapper on drop.

## Refresh

MPC Threshold PRF refresh should use share refresh that preserves the logical
PRF key while changing A/B shares. The refresh protocol must:

- avoid reconstructing the PRF key
- bind old and new root-share epochs
- authenticate old and new signer identities
- produce verification evidence before activating the new epoch
- preserve existing account-output verification relations

The exact refresh formula is a P0 candidate-specific spec item.

## Leakage Table

| View | Visible plaintext | Forbidden material excluded | Adapter guard |
| --- | --- | --- | --- |
| Router | context, transcript, signer-set metadata, encrypted package headers, commitments, receipts, replay decisions | PRF shares, plaintext partial wires, joined outputs | Router APIs only accept public metadata and package commitments |
| Signer A | A PRF share, A-side partial wires before encryption, A commitment, A proof, signer input metadata | B PRF share, B partial wires, joined `x_client_base`, joined `x_relayer_base`, joined `d`, joined `a` | signer input validates Signer A identity, transcript digest, recipient binding, and epoch |
| Signer B | B PRF share, B-side partial wires before encryption, B commitment, B proof, signer input metadata | A PRF share, A partial wires, joined `x_client_base`, joined `x_relayer_base`, joined `d`, joined `a` | signer input validates Signer B identity, transcript digest, recipient binding, and epoch |
| Client | client-targeted A/B partial wires after decryption, `x_client_base` after combine, Minimum Level C evidence | relayer-targeted partial wires, `x_relayer_base`, relayer HSS material | output request enforces `x_client_base -> client` |
| Relayer | relayer-targeted A/B partial wires after decryption, `x_relayer_base` after combine, Minimum Level C evidence | client-targeted partial wires, `x_client_base`, client hidden computation material | output request enforces `x_relayer_base -> relayer` |
| Sealed-share storage | encrypted A/B PRF shares, key epoch labels, signer identity labels | decrypted PRF shares, partial wires, joined outputs | storage is outside this crate; adapters must decrypt into zeroizing wrappers |
| Diagnostics/logging | stable error codes, redacted diagnostics, public digests | PRF share bytes, partial wire bytes, proof scalar internals, plaintext package bytes | source guards reject logging macros and secret serialization |
| Replayed transcript view | replay cache key, accepted transcript digest, prior public package commitments | fresh partial wires or alternate recipient openings | Minimum Level C replay binding rejects changed transcript digest |

Minimum Level C protects server blindness and delivery binding. A malicious
signer can still produce a bad partial unless DLEQ verification or an equivalent
authenticity mechanism is required before activation. Address verification is
the production gate when proof verification is deferred.

## Constant-Time Requirements

Implementation must avoid:

- branching on PRF share bits
- table lookup by PRF share bits
- division or modulo by secret-derived values
- early-exit comparison of secret partials

Secret partials and shares must zeroize on drop.

Current adapter scope:

- fixed-width checks operate on public wire lengths
- signer role, recipient role, and transcript checks operate on public metadata
- plaintext partial wrappers zeroize and redact debug output
- curve operations, scalar operations, and DLEQ verification stay inside
  `threshold-prf`

## Open Items

- exact refresh formula
- whether proof verification is included in Minimum Level C or deferred
