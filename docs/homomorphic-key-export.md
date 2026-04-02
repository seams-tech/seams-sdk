# Homomorphic Key Export Plans

Date updated: March 31, 2026

This design has been split so ECDSA and Ed25519 export semantics are tracked separately.

Active plans:

- [ECDSA homomorphic key export](./homomorphic-key-export-ECDSA.md)
- [Ed25519 homomorphic key export, Option A](./homomorphic-key-export-ED25519-OPTION-A.md)

Historical background:

- [Ed25519 Option B historical note](./homomorphic-key-export-ED25519-OPTION-B.md)

Important note:

- the additive-share HE export flow is currently specified only for ECDSA private-scalar export,
- Ed25519 is tracked separately because NEAR export is seed-based while
  threshold Ed25519 signing material is scalar-based,
- Option A is the active Ed25519 default because it preserves one canonical
  key lifecycle across hidden conversion, signing-share reconstruction, and
  controlled export.
- Option B is historical background only. It is not part of the active product
  path or active Ed25519 specs.
