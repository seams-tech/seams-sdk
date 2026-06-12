# `threshold-prf` Formal Verification Fixtures

This directory references committed anti-drift vectors for the
`threshold-prf` formal-verification track.

Canonical first corpus:

- [`../../fixtures/protocol-v1.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/fixtures/protocol-v1.json)

The first corpus includes:

- root generation from fixed seed material
- 2-of-3 share splitting
- direct reference evaluation
- each valid pairwise threshold combine path
- `PrfPartialWireV1` encoding with share ID, context tag, and compressed point
- refreshed-share behavior
- malformed-input rejection cases where practical
- purpose vectors for `ecdsa-hss/y_relayer`
- purpose vectors for `ed25519-hss/y_relayer`
- purpose vectors for `ed25519-hss/tau_relayer`
- purpose vectors for `router-ab/x_client_base/v1`
- purpose vectors for `router-ab/x_relayer_base/v1`

If formal-verification tests need a local copy, it must be byte-identical to the
canonical corpus. Do not add generated benchmark output here. Keep fixtures
deterministic and small enough for review.
