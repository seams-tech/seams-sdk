# `ecdsa-hss` Fixtures

This directory is reserved for the role-local ECDSA HSS fixture corpus.

The active production path derives:

- client role share from client-local root material
- relayer role share from relayer-local root material
- public identity from `X_client + X_relayer`
- explicit export key in the client export runtime

The committed fixture is
[role_local_v2.json](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/fixtures/role_local_v2.json).
