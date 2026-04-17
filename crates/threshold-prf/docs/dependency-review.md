# Threshold PRF Dependency Review

Date created: April 16, 2026

## Scope

This note records the initial dependency decision for the prototype
`threshold-prf` crate.

## Runtime Dependencies

### `curve25519-dalek = 4.1.3`

Purpose:

- Ristretto255 scalar arithmetic
- Ristretto255 point arithmetic
- Ristretto hash-to-group

Decision:

- Accept for prototype and first integration design.
- Pin exact version in `Cargo.toml` for protocol-vector stability during the
  prototype phase.

Reasoning:

- Widely used Rust implementation for Ristretto255.
- Provides canonical scalar parsing, compressed point parsing, and hash-to-group.
- Avoids implementing curve arithmetic in this crate.
- Supports `zeroize` integration.

Review notes:

- This crate still relies on `curve25519-dalek` for constant-time scalar and
  point operations.
- Protocol vectors must be treated as the compatibility boundary if the
  dependency or suite changes.

### `sha2 = 0.10`

Purpose:

- SHA-512 transcript hashing
- Ristretto hash-to-group digest backend

Decision:

- Accept.

Reasoning:

- Stable RustCrypto hash implementation.
- Already compatible with `curve25519-dalek` hash-to-group APIs.

### `rand_core = 0.6`

Purpose:

- RNG trait boundary for signing-root and share generation.

Decision:

- Accept.

Reasoning:

- Keeps entropy source injectable and testable.
- Does not force a specific runtime RNG into the crate.

### `subtle = 2.6`

Purpose:

- Constant-time byte/scalar equality where equality may involve secret-adjacent
  material.

Decision:

- Accept.

### `zeroize = 1.8`

Purpose:

- Zeroize signing-root and share scalar containers on drop.

Decision:

- Accept.

## Dev Dependencies

### `criterion = 0.5`

Purpose:

- Native performance benchmarking.

Decision:

- Accept for prototype benchmarking.

### `rand_chacha = 0.3`

Purpose:

- Deterministic seeded vectors and tests.

Decision:

- Accept as a dev dependency only.

## Deferred Review Items

- Revisit exact version pins before publishing or integrating into a larger
  workspace.
- Re-review DLEQ proof dependencies before Option B; the current implementation
  uses existing Ristretto, SHA-512, `rand_core`, `subtle`, and `zeroize`
  dependencies.
- Run Cloudflare Worker or WASM benchmarks before making Worker latency claims.
