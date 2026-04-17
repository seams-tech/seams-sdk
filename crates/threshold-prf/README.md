# Threshold PRF

Prototype crate for deriving project-scoped server HSS inputs from random
signing-root shares.

The crate is intentionally narrow:

- generate a random signing root
- split it into 2-of-3 shares
- encode and explicitly decode decrypted signing-root shares at the server SDK
  boundary
- evaluate threshold-PRF partials from shares
- derive a one-runtime Option A output from exactly two shares without
  reconstructing `k_org`
- derive a one-runtime Option A output from exactly two validated
  `SigningRootShareWireV1` values
- serialize partials for worker-to-worker transport
- optionally prove partial correctness with DLEQ against root-share commitments
- combine any valid two partials into the same `y_relayer`
- benchmark the cost before integration

Production signing should use partial evaluation and combine. The one-runtime
Option A helper is `derive_output_from_signing_root_shares`; direct
`k_org -> y_relayer` evaluation exists only as a reference test path.

Current status:

- prototype Rust implementation exists
- formal verification has a first Verus abstract spec model
- HSS integration contexts are frozen for the current `ecdsa-hss` and
  `ed25519-hss` mappings
- committed JSON vectors exist for all fixed v1 production purposes
- DLEQ partial-authenticity proof generation and verification exists
- DLEQ proof generation rejects and retries zero nonces; nonce uniqueness
  depends on a correct `CryptoRng`
- native benchmarks and guardrail checks pass for the current crate surface
- local Node/V8 WASM proxy benchmarks are sub-millisecond for Option A and DLEQ
- Option B still needs an authenticated commitment registry, TEE attestation, or
  equivalent deployment binding before malicious-worker safety can be claimed

See [docs/implementation-plan.md](docs/implementation-plan.md).
The current server SDK sealed-share format is frozen in
[docs/signing-root-share-sealing.md](docs/signing-root-share-sealing.md).

Regenerate the committed vector corpus with:

```bash
cargo run --manifest-path crates/threshold-prf/Cargo.toml --example generate_vectors \
  > crates/threshold-prf/fixtures/protocol-v1.json
```
