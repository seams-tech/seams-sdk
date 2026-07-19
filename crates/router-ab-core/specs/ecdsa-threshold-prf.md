# Fixed ECDSA Threshold-PRF Contract

## Scope

Router A/B ECDSA derivation uses one compile-time construction:

- Ristretto255/SHA-512 threshold PRF;
- a fixed 2-of-2 construction;
- Deriver A share id `1`;
- Deriver B share id `2`;
- DLEQ verification for every partial;
- `all(2)` at the Router protocol boundary.

There is no candidate, suite, backend, quorum, correctness-level, or downgrade
selection in a request. Unknown request fields are rejected. The canonical
wire domains identify the fixed construction directly.

## Ownership

Deriver A and Deriver B each own one signing-root share and create only their
own proof bundles. The Router owns public lifecycle metadata, authenticated
role envelopes, replay admission, and ciphertext routing. It never receives a
plaintext signing-root share or plaintext recipient output.

The Client combines only `x_client_base` partials addressed to its identity.
The SigningWorker combines only `x_server_base` partials addressed to its
identity. A/B proof-batch messages are authenticated and bind sender,
recipient, transcript digest, root-share epoch, output kind, and output
recipient.

Each Deriver proof bundle is encrypted directly to its fixed Client or
SigningWorker recipient. The Router forwards the ciphertext and cannot open a
partial or derived scalar share. The recipient verifies and decrypts both
bundles before threshold combination.

## Fixed boundaries

- `EcdsaThresholdPrfRequestV1` is the only internal Router request shape.
- `SignerInputPlaintextV1` is parsed once after role-envelope decryption.
- `MpcPrfSigningRootShareWireV1` accepts only share ids `1` and `2`.
- `MpcPrfPartialWireV1` and `MpcPrfShareCommitmentWireV1` accept only those
  same fixed ids.
- Deriver A requires id `1`; Deriver B requires id `2`.
- `EcdsaThresholdPrfProofBatchPayloadV1` is the only A/B derivation
  proof-batch payload.
- Each proof bundle carries the public share commitment used by its DLEQ proof.
  The recipient verifies that proof-contained commitment before combining the
  bundle with its peer.

The reusable `threshold-prf` crate may support general t-of-n policies. That
generality does not cross the Router A/B ECDSA adapter.

## Canonical domains

- `router-ab-ecdsa-threshold-prf/context/v1`
- `router-ab-ecdsa-threshold-prf/context-digest/v1`
- `router-ab-protocol/ecdsa-threshold-prf-request/v1`
- `router-ab-protocol/ecdsa-threshold-prf-request-context/v1`
- `router-ab-protocol/ecdsa-threshold-prf-proof-batch-payload/v1`
- `threshold-prf/ristretto255-sha512`
- `threshold_prf_ristretto255_sha512`
- `router-ab/x_client_base/v1`
- `router-ab/x_server_base/v1`

## Security boundary

One honest Deriver plus recipient encryption preserves server blindness
against Router-plus-one-Deriver compromise. A+B collusion is outside the
claim. DLEQ verification binds each accepted partial to its authenticated
share commitment and fixed PRF context. Transcript, role, recipient, epoch,
and output-purpose validation prevents cross-session and cross-recipient
substitution.

The recipient verifies each proof against the commitment carried in that proof
bundle, then checks the fixed role, recipient, transcript, root-share epoch,
output kind, and peer relationship before combining the two bundles. A
commitment supplied outside the proof bundle is not part of the protocol.

After activation, presignatures and the server additive share remain owned by
the SigningWorker. Ordinary ECDSA signing uses the Router, Client, and
SigningWorker and performs zero Deriver calls.

Deployment separation, transport authentication, durable replay state, and
credential isolation remain composition requirements owned by the wider Router
A/B plan.

## Validation evidence

- deterministic direct-reference versus 2-of-2 combine tests;
- malformed proof, role/id swap, transcript, epoch, output-purpose, and
  recipient rejection tests;
- proof-contained commitment, role/share-id, transcript, epoch, and
  commitment-substitution tests;
- recipient-ciphertext AAD tests binding the fixed suite and proof payload;
- source guards proving normal signing has no Deriver invocation;
- committed canonical payload vectors;
- source guards rejecting candidate selectors and the deleted generic modules;
- native and Worker adapter tests;
- Verus anti-drift tests for role/output authorization and activation context.
