# Homomorphic Key Export Plans

Date updated: March 22, 2026

This design has been split so ECDSA and Ed25519 export semantics are tracked separately.

Canonical plans:

- [ECDSA homomorphic key export](./homomorphic-key-export-ECDSA.md)
- [Ed25519 homomorphic key export support](./homomorphic-key-export-ED25519.md)

Important note:

- the additive-share HE export flow is currently specified only for ECDSA private-scalar export,
- Ed25519 is tracked separately because this repo's current NEAR private-key format is seed-based while threshold Ed25519 signing material is scalar-based.
