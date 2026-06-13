# Public Share Binding

This spec defines the stronger correctness path beyond Minimum Level C.

## Goal

Public-share binding detects malformed deriver output earlier by checking public
relations between deriver output shares, verifying shares, and the account public
key or candidate-specific relation.

This path strengthens correctness. Server blindness still relies on role-state
separation and recipient-scoped delivery.

## Required Inputs

The verifier receives:

- verified Minimum Level C evidence
- candidate-specific public verifying shares
- candidate-specific output commitments
- account public key or verification relation
- transcript digest
- root-share epoch
- deriver identities

## Candidate A: MPC Threshold PRF

Possible checks:

- A-side partial proof verifies against A public commitment
- B-side partial proof verifies against B public commitment
- combined recipient output matches expected public relation after recipient
  opening

Open items:

- proof system
- share commitment format
- whether proof verification is required before delivery

## Candidate B: Split Root Derivation

Possible checks:

- A output share commitment binds to A verifying share
- B output share commitment binds to B verifying share
- combined output relation matches account public key after recipient opening

Open items:

- root commitment format
- output-share proof format
- bias-resistance proof
- whether this path is mandatory for split-root production

## Verification Result

Public-share-binding verification returns a typed stronger evidence value:

```rust
pub struct VerifiedPublicShareBindingEvidenceV1 {
    pub minimum_level_c: VerifiedMinimumLevelCEvidenceV1,
    pub public_binding_digest: PublicDigest32,
}
```

Activation APIs may accept either:

- Minimum Level C plus address verification, or
- public-share-binding evidence plus address verification

The product can later require the stronger value for all refresh activation.
