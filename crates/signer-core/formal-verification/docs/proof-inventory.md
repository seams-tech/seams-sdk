# `signer-core` Formal Verification Proof Inventory

Last updated: 2026-04-16

This inventory tracks implemented and planned proof targets for:

- [`crates/signer-core`](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core)

## Current Posture

- Verus is the active implementation-proof track.
- Executable anti-drift tests pin the Verus mirror to production helper behavior.
- Lean/Aeneas is not active for `signer-core` yet.

## FV-SIGNER-CORE-001

Target:

- `src/secp256k1.rs`
- HKDF-output-to-nonzero-scalar reduction

Property:

- 64-byte HKDF output is reduced deterministically
- reduction output is modeled as a valid non-zero secp256k1 scalar
- output encoding is modeled as stable 32-byte big-endian scalar bytes

Status:

- Verus scalar-domain model exists
- reduction determinism theorem exists
- reduction scalar-domain theorem exists
- production anti-drift checks compare derived outputs against the frozen
  modulo-`(n - 1) + 1` reduction formula through public helpers

Remaining trust:

- SHA-256/HKDF and `k256` reduction internals are trusted primitive/library seams

## FV-SIGNER-CORE-002

Target:

- `src/secp256k1.rs`
- `derive_threshold_secp256k1_relayer_share`

Property:

- derivation from `(master_secret, relayer_key_id)` is deterministic
- signing share is a valid non-zero scalar
- verifying share is the compressed public key for that signing share
- output layout is `signing_share32 || verifying_share33`

Status:

- Verus output-shape model exists
- determinism theorem exists
- signing-share scalar-domain theorem exists
- executable anti-drift checks cover output layout and public-key consistency

## FV-SIGNER-CORE-003

Target:

- `src/secp256k1.rs`
- `derive_secp256k1_keypair_from_prf_second`

Property:

- derivation from `(prf_second, near_account_id)` is deterministic
- private key is valid and non-zero
- compressed public key corresponds to the private key
- Ethereum address corresponds to the same public key
- output layout is `private_key32 || public_key33 || address20`

Status:

- Verus output-shape model exists
- determinism theorem exists
- private-key scalar-domain theorem exists
- executable anti-drift checks cover output layout, public-key consistency,
  address consistency, and reduction formula parity

## FV-SIGNER-CORE-004

Target:

- `src/secp256k1.rs`
- `map_additive_share_to_threshold_signatures_share_2p`

Property:

- participant IDs are fixed to `{1, 2}`
- unsupported IDs are rejected
- mapping uses the intended lambdas
- mapped outputs remain valid non-zero scalars
- mapped-share semantics preserve local additive-share meaning

Status:

- Verus mapping model exists
- fixed participant-ID lemmas exist
- unsupported-ID rejection lemma exists
- lambda inverse correctness lemmas exist
- mapped-share scalar-domain theorem exists
- mapped-share semantic-preservation theorem exists
- executable anti-drift checks cover mapping formula parity and rejected IDs

## FV-SIGNER-CORE-005

Target:

- `src/secp256k1.rs`
- public-key helper functions

Property:

- compressed SEC1 public keys are validated strictly
- public-key addition result remains compressed SEC1
- private-key-to-public-key helper matches compressed SEC1 encoding

Status:

- Verus public-key helper model exists
- invalid compressed public keys are modeled as rejected
- valid compressed public-key validation is modeled as byte-preserving
- private-key-to-public-key output is modeled as compressed SEC1
- public-key-to-address output is modeled as 20 bytes
- public-key addition output is modeled as compressed SEC1
- executable anti-drift checks cover helper output shape through committed
  secp256k1 vectors

Remaining trust:

- SEC1 parsing, point addition, Keccak, and `k256` public-key internals remain
  trusted primitive/library seams

## FV-SIGNER-CORE-006 To FV-SIGNER-CORE-008

Target:

- `src/near_threshold_ed25519.rs`

Status:

- `FV-SIGNER-CORE-006` has a first Verus derivation model.
- Threshold client-share derivation determinism theorem exists.
- Non-zero signing-share theorem exists.
- Verifying-share-from-signing-share relation theorem exists.
- Fixed signing/verifying-share layout theorem exists.
- Ed25519 derivation anti-drift checks cover committed client-share vectors.
- `FV-SIGNER-CORE-007` has a first Verus participant/key-package model.
- Participant-ID normalization invariants exist.
- 2P participant-ID validation branch theorems exist.
- Key-package shape theorems preserve identifier, signing share, derived
  verifying share, group key, and fixed 2P min-signers.
- `FV-SIGNER-CORE-008` has a first Verus NEP-413 digest/nonce model.
- NEP-413 prefix, deterministic digest shape, fixed digest width, and exact
  decoded nonce-length validation theorems exist.
- NEP-413 anti-drift checks cover committed digest vectors, independent Borsh
  payload reconstruction, prefix bytes, nonce-base64 path parity, nonce-bytes
  path parity, and rejected decoded nonce lengths.

Remaining trust:

- HKDF, SHA-256, Ed25519 scalar reduction, curve basepoint multiplication,
  FROST key-package internals, Borsh serialization, and base64 decoding remain
  trusted primitive/library seams.
