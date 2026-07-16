# `threshold-prf` Formal Verification Fixtures

This directory references committed anti-drift vectors for the
`threshold-prf` formal-verification track.

Canonical current corpora:

- [`../../fixtures/protocol-t-of-n.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/fixtures/protocol-t-of-n.json)
- [`../../fixtures/protocol-wire.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/fixtures/protocol-wire.json)

The threshold-policy corpus includes:

- root generation from fixed seed material
- 2-of-3 and 3-of-5 share splitting
- direct reference evaluation
- each valid threshold subset for the committed policies
- `PrfPartialWire` encoding with share ID, context tag, and compressed point
- purpose vectors for `router-ab-ecdsa-derivation/y-server/v1`
- purpose vectors for `router-ab/x_server_base/v1`

If formal-verification tests need a local copy, it must be byte-identical to the
canonical corpus. Do not add generated benchmark output here. Keep fixtures
deterministic and small enough for review.
