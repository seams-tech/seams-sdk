Seed-backed Ed25519 export vectors live here.

Published v1 contents:
- canonical seed `d`
- derived scalar `a`
- public key `A`
- `x_client`, `x_relayer`
- `y_client`, `y_relayer`
- final `ed25519:` export string
- client/relayer verifying shares
- recombined seed and threshold public key checks

Rust core is the source of truth for these vectors.
