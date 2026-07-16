# `signer-core` Formal Verification Proof Inventory

Last updated: 2026-04-16

This inventory tracks the recommended first proof targets for
[crates/signer-core](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core).

The current recommendation is:

- Verus for implementation-facing shared-helper proofs
- executable anti-drift checks against committed vectors
- no standalone Lean track initially

Current implementation status:

- `FV-SIGNER-CORE-001` through `FV-SIGNER-CORE-004` have first Verus models
  and executable anti-drift coverage.
- `FV-SIGNER-CORE-005` has a first Verus public-key helper model and
  executable anti-drift coverage through committed secp256k1 fixtures.
- `FV-SIGNER-CORE-006` has a first Verus derivation model.
- `FV-SIGNER-CORE-007` has first Verus participant-ID and key-package models.
- `FV-SIGNER-CORE-008` has a first Verus NEP-413 digest/nonce model.
- `FV-SIGNER-CORE-008` has executable anti-drift coverage through committed
  NEP-413 digest vectors.
- The current signer-core Verus-first scope passes under both
  `just signer-core-fv` and full repository `just fv`.

## FV-SIGNER-CORE-001

Target:

- `src/secp256k1.rs`
- `reduce_hkdf_output_to_nonzero_secp256k1_scalar`

Property:

- 64-byte HKDF output is reduced deterministically
- reduction output is always a valid non-zero secp256k1 scalar
- output encoding is stable as 32 big-endian bytes

Why it matters:

- this helper sits under relayer-share derivation and canonical secp256k1
  private-key derivation
- higher-level `router-ab-ecdsa-derivation` proofs still treat this seam as trusted

Status:

- Verus scalar-domain model exists.
- Reduction determinism theorem exists.
- Reduction scalar-domain theorem exists.
- Executable anti-drift checks compare derived outputs against the frozen
  modulo-`(n - 1) + 1` reduction formula through public helpers.

Remaining trust:

- SHA-256/HKDF and `k256` reduction internals remain trusted primitive/library
  seams.

## FV-SIGNER-CORE-002

Target:

- `src/secp256k1.rs`
- `derive_threshold_secp256k1_relayer_share`

Property:

- for fixed `(master_secret, relayer_key_id)`, relayer-share derivation is deterministic
- the returned signing share is valid and non-zero
- the returned verifying share is the compressed public key of that signing share
- the output layout is exactly `signing_share32 || verifying_share33`

Why it matters:

- this helper defines the threshold relayer-share shape consumed downstream

Status:

- Verus output-shape model exists.
- Determinism theorem exists.
- Signing-share scalar-domain theorem exists.
- Executable anti-drift checks cover output layout and public-key consistency.

## FV-SIGNER-CORE-003

Target:

- `src/secp256k1.rs`
- `derive_secp256k1_keypair_from_prf_second`

Property:

- for fixed `(prf_second, near_account_id)`, key derivation is deterministic
- the derived private key is valid and non-zero
- the derived compressed public key corresponds to the private key
- the derived Ethereum address corresponds to the same public key
- the output layout is exactly `private_key32 || public_key33 || address20`

Why it matters:

- this is a direct key-derivation seam used by downstream EVM signing paths

Status:

- Verus output-shape model exists.
- Determinism theorem exists.
- Private-key scalar-domain theorem exists.
- Executable anti-drift checks cover output layout, public-key consistency,
  address consistency, and reduction formula parity.

## FV-SIGNER-CORE-004

Target:

- `src/secp256k1.rs`
- `map_additive_share_to_threshold_signatures_share_2p`

Property:

- participant-ID handling is fixed to `{1, 2}`
- unsupported IDs are rejected
- the mapping uses the intended fixed lambdas
- mapped outputs remain valid non-zero scalars
- mapped-share semantics preserve the same local additive-share meaning

Why it matters:

- this is the shared backend-mapping seam beneath `router-ab-ecdsa-derivation`

Status:

- Verus mapping model exists.
- Fixed participant-ID lemmas exist.
- Unsupported-ID rejection lemma exists.
- Lambda inverse correctness lemmas exist.
- Mapped-share scalar-domain theorem exists.
- Mapped-share semantic-preservation theorem exists.
- Executable anti-drift checks cover mapping formula parity and rejected IDs.

## FV-SIGNER-CORE-005

Target:

- `src/secp256k1.rs`
- public-key helper functions

Property:

- SEC1 compressed public keys are validated strictly
- public-key addition result stays in the valid compressed encoding domain
- private-key-to-public-key helper matches the same compressed public-key encoding

Why it matters:

- downstream proofs and callers rely on stable public-key encoding behavior

Status:

- Verus public-key helper model exists.
- Invalid compressed public keys are modeled as rejected.
- Valid compressed public-key validation is modeled as byte-preserving.
- Private-key-to-public-key output is modeled as compressed SEC1.
- Public-key-to-address output is modeled as 20 bytes.
- Public-key addition output is modeled as compressed SEC1.
- Executable anti-drift checks cover helper output shape through committed
  secp256k1 vectors.

Remaining trust:

- SEC1 parsing, point addition, Keccak, and `k256` public-key internals remain
  trusted primitive/library seams.

## FV-SIGNER-CORE-006

Target:

- `src/near_threshold_ed25519.rs`
- threshold client-share derivation

Property:

- client-share derivation from `(wrap_key_seed, near_account_id)` is deterministic
- the derived client signing share is non-zero
- the derived verifying share corresponds to the same signing share

Why it matters:

- this is the shared Ed25519 threshold derivation seam beneath higher-level flows

Status:

- Verus derivation model exists.
- Threshold client-share derivation determinism theorem exists.
- Non-zero signing-share theorem exists.
- Verifying-share-from-signing-share relation theorem exists.
- Fixed signing/verifying-share layout theorem exists.
- Ed25519 derivation anti-drift checks cover committed client-share vectors.

Remaining trust:

- HKDF, SHA-256, Ed25519 scalar reduction, and curve basepoint multiplication
  remain trusted primitive/library seams.

## FV-SIGNER-CORE-007

Target:

- `src/near_threshold_ed25519.rs`
- participant-ID and key-package helpers

Property:

- participant-ID normalization is deterministic
- invalid participant-ID combinations are rejected
- key-package construction preserves the intended signing-share / verifying-share / group-key relationship

Why it matters:

- these helpers are shared boundary code, not just local convenience wrappers

Status:

- Verus participant-ID model exists.
- Normalized participant-ID list invariants exist.
- Default empty participant set selects `(1, 2)`.
- Partial explicit IDs are rejected.
- Duplicate explicit IDs are rejected.
- Explicit distinct IDs with an empty list are accepted.
- Explicit IDs missing from a non-empty list are rejected.
- Explicit IDs present in a non-empty list are accepted.
- Inferred one-ID and more-than-two-ID lists are rejected.
- Inferred two-ID lists select the normalized pair.
- Verus key-package shape model exists.
- Key-package shape preserves identifier, signing share, derived verifying
  share, group public key, and fixed `min_signers = 2`.

Remaining trust:

- FROST identifier parsing, share deserialization, verifying-share
  deserialization, verifying-key deserialization, and `frost-ed25519`
  key-package internals remain trusted library seams.

## FV-SIGNER-CORE-008

Target:

- `src/near_threshold_ed25519.rs`
- `compute_nep413_signing_digest_*`

Property:

- nonce-length validation is exact
- digest construction shape is deterministic
- the same message components always produce the same digest

Why it matters:

- digest shape drift here would silently break signing compatibility

Status:

- Verus NEP-413 digest/nonce model exists.
- Payload prefix is modeled as fixed little-endian bytes for `2147484061`.
- Digest construction is deterministic for equal message, recipient, nonce,
  and state.
- Digest output is modeled as fixed 32 bytes.
- Decoded nonce validation rejects every non-32-byte length.
- Decoded nonce validation accepts exactly 32 bytes.
- Executable anti-drift checks cover committed digest vectors, independent
  Borsh payload reconstruction, prefix bytes, nonce-base64 path parity,
  nonce-bytes path parity, and rejected decoded nonce lengths.

Remaining trust:

- Base64 decoding, Borsh serialization, and SHA-256 internals remain trusted
  primitive/library seams.

## Recommended Order

Implement in this order:

1. `FV-SIGNER-CORE-001`
2. `FV-SIGNER-CORE-002`
3. `FV-SIGNER-CORE-003`
4. `FV-SIGNER-CORE-004`
5. `FV-SIGNER-CORE-005`
6. `FV-SIGNER-CORE-006`
7. `FV-SIGNER-CORE-007`
8. `FV-SIGNER-CORE-008`

If only one initial slice is funded, stop after `FV-SIGNER-CORE-004`.
