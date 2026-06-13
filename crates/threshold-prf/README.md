# Threshold PRF

Prototype crate for deriving project-scoped server HSS inputs from random
signing-root shares.

The crate is intentionally narrow:

- generate a random signing root
- split it into a configurable `t-of-N` signing-root sharing
- encode and explicitly decode decrypted signing-root shares at the server SDK
  boundary
- evaluate threshold-PRF partials from shares
- derive a one-runtime output from threshold shares without
  reconstructing `k_org`
- serialize partials for worker-to-worker transport
- optionally prove partial correctness with DLEQ against root-share commitments
- combine any valid threshold subset into the same `y_relayer`
- benchmark the cost before integration

## Canonical API

New code should import configurable threshold behavior from `threshold_prf`.
The canonical API supports explicit threshold policies, fixed-width wire types, generic
trusted local partial combine, and generic DLEQ verified combine.

```rust
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use threshold_prf::trusted::combine_partials;
use threshold_prf::{
    evaluate_partial, generate_signing_root, split_signing_root, ThresholdPolicy,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfPurpose, SuiteId};

let policy = ThresholdPolicy::from_u16s(3, 5)?;
let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
let root = generate_signing_root(&mut rng);
let shares = split_signing_root(&root, policy, &mut rng)?;
let context = PrfContext::new(
    SuiteId::Ristretto255Sha512,
    PrfPurpose::EcdsaHssYRelayer,
    b"canonical-hss-context".to_vec(),
);

let partials = vec![
    evaluate_partial(&shares[0], &context)?,
    evaluate_partial(&shares[2], &context)?,
    evaluate_partial(&shares[4], &context)?,
];
let set = ValidatedThresholdSet::from_partials(policy, partials)?;
let y_relayer = combine_partials(&set, &context)?;
```

Production signing should use verified combine for peer partials. Local one-runtime
derivation may use `trusted::combine_partials` after authenticating the share set.
`reference::evaluate_direct_reference` exists for tests, vectors, recovery
checks, and audits.

Current status:

- prototype Rust implementation exists
- formal verification has a Verus abstract threshold-policy model
- HSS integration contexts are frozen for the current `ecdsa-hss` and
  `ed25519-hss` mappings
- committed JSON vectors exist for configurable coverage
- DLEQ partial-authenticity proof generation and verification exists
- DLEQ proof generation rejects and retries zero nonces; nonce uniqueness
  depends on a correct `CryptoRng`
- native benchmarks and guardrail checks pass for the current crate surface
- local Node/V8 WASM proxy benchmarks are sub-millisecond for one-runtime and
  DLEQ paths
- distributed verified partial combine still needs an authenticated commitment
  registry, TEE attestation, or equivalent deployment binding before
  malicious-worker safety can be claimed

Canonical docs:

- [t-of-N protocol and API spec](docs/threshold-prf-t-of-n-spec.md)
- [benchmarks](docs/benchmarks.md)
- [dependency review](docs/dependency-review.md)
- [formal verification](formal-verification/README.md)

Regenerate the committed vector corpus with:

```bash
cargo run --manifest-path crates/threshold-prf/Cargo.toml --example generate_vectors \
  > crates/threshold-prf/fixtures/protocol-t-of-n.json
```
