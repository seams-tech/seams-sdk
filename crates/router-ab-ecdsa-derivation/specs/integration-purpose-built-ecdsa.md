# Purpose-Built Router A/B ECDSA Integration

This specification defines the production integration between role-local ECDSA
derivation and the fixed 2-of-2 presign and online protocols.

## Fixed roles

- Client owns `x_client` and its Client presignature half.
- SigningWorker owns `x_relayer` and its SigningWorker presignature half.
- The public identity is `X = x_client G + x_relayer G`.
- The production protocol has exactly these two roles. Runtime participant,
  threshold, and role selection are outside every cryptographic API.

The Client and SigningWorker consume their additive shares directly. There is
no backend share mapping or generic threshold-signing representation.

## Owners

- `router-ab-ecdsa-derivation` derives role-local additive shares and the
  shared public identity.
- `router-ab-ecdsa-presign` creates matched, one-use presignature halves using
  fixed Client and SigningWorker session types.
- `router-ab-ecdsa-pool` defines monotonic admission, reservation, committed
  use, and tombstone transitions.
- `router-ab-ecdsa-online` computes the Client signature share and finalizes
  the SigningWorker signature.
- Role-specific Wasm crates expose only the operations owned by their runtime.

The pinned NEAR implementation is a dev/test oracle. It is absent from normal
and build dependency graphs for all production owners.

## Lifecycle

1. Router A/B derivation produces `x_client`, `x_relayer`, their public shares,
   the group public key, and the Ethereum address under one stable context.
2. Activation verifies both proof-contained DLEQ commitments and the fixed
   A/B recipient, transcript, epoch, and lifecycle bindings before admitting
   either presignature half.
3. Presigning binds both halves to the fixed protocol, public key, SigningWorker
   epoch, activation epoch, authenticated scope, and pair identifier.
4. Online signing reserves and durably commits one matched pair before any
   signature share or final signature is released.
5. Every success, rejection, cancellation, timeout, crash recovery, or
   ambiguous delivery ends in a material-free tombstone.
6. Explicit export releases the additive SigningWorker export share only after
   authorization. The Client reconstructs `x = x_client + x_relayer mod n` and
   verifies the resulting public key and address.

Normal signing does not call either Deriver after activation.

## Required invariants

- Both additive shares are canonical non-zero secp256k1 scalars.
- The public shares sum to the group public key used for the request.
- The Ethereum address is derived from that same group public key.
- A presignature pair is usable only under its exact authenticated scope and
  pair binding.
- A pair half cannot be cloned, revived, substituted across scopes, or consumed
  twice.
- Final signatures are canonical low-`s`, verify against the request-bound group
  key, and carry the correct recovery identifier.
- Client secrets never cross the Client boundary. SigningWorker secrets never
  cross the SigningWorker boundary except the explicitly authorized additive
  export share.

## Forbidden architecture

Production code must not contain:

- additive-share-to-backend mapping functions or mapped private-share fields;
- generic participant vectors, thresholds, or runtime role selectors;
- a generic threshold ECDSA service or protocol driver;
- normal/build dependencies on the pinned oracle implementation; or
- compatibility readers for the deleted backend state and message formats.

The coordinated Cloudflare release, one-account development topology, and
independent-account production topology are governed by
`docs/router-ab/ed25519-yao/deployment.md`. Those deployment choices do not change this
cryptographic interface.
