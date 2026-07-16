# `router-ab-ecdsa-derivation` Fixtures

This directory is reserved for the role-local Router A/B ECDSA derivation fixture corpus.

The active production path derives:

- client role share from client-local root material
- relayer role share from relayer-local root material
- public identity from `X_client + X_relayer`
- explicit export key in the client export runtime

The committed fixture is
[role_local_v1.json](./role_local_v1.json).

`tests/role_local_mvp.rs` validates the fixture against the production
derivation code, including scalar-to-public-key validity, public-key sum,
Ethereum address parity, retry counters, and client-side export reconstruction.
