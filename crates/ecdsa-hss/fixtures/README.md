# `ecdsa-hss` Fixture Corpus

This directory holds deterministic fixture corpora for the frozen v1 specs.

Current corpus:

- [protocol-v1.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/protocol-v1.json)

The current corpus is the narrow fixed-function reference set for:

- `encode_context_v1`
- canonical `x` derivation
- compressed public-key derivation
- Ethereum address derivation
- additive-share derivation
- fixed `{1, 2}` backend share mapping

These fixtures are the source of truth for early cross-runtime parity and
future proof/anti-drift work.
