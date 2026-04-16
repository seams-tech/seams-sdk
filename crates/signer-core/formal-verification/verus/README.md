# `signer-core` Verus Track

This is the Verus implementation-proof track for the narrow shared-helper
slice of `signer-core`.

Current scope:

- `src/secp256k1.rs` scalar-domain model
- HKDF-output reduction shape
- relayer-share derivation shape
- canonical keypair derivation shape
- fixed `{1, 2}` additive-share mapping formula
- public-key helper output-shape invariants
- executable anti-drift checks against committed secp256k1 fixtures
- threshold Ed25519 client-share derivation shape
- threshold Ed25519 participant-ID validation shape
- threshold Ed25519 key-package construction shape
- NEP-413 digest construction and nonce-length shape

Run:

```sh
just signer-core-fv
```

The current Verus model intentionally does not prove secp256k1, HKDF,
SHA-256, Keccak, or SEC1 encoding from first principles.
