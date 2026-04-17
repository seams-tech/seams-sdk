# Rotate Server Root

This note is intentionally retired.

The active custody and signing-root rotation design lives in:

- [korg_secrets.md](korg_secrets.md)
- [tenant-id-refactor.md](tenant-id-refactor.md)

Relevant retained conclusion:

- Refreshing shares for the same `signing_root_secret` preserves derived wallet
  keys and wallet addresses.
- Replacing `signing_root_secret` creates a new signing-root version and should
  be treated as explicit wallet-key migration, not transparent ops rotation.
- There is no deterministic platform `master_secret -> k_org` derivation in the
  active availability-first MPC custody design.

Do not add new implementation details here. Update the active specs instead.
