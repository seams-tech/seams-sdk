# Leakage Analysis

Leakage analysis must be done before selecting the primitive.

## Required Questions

- Does any single server-side role hold enough state to reconstruct joined `d`?
- Does any single server-side role hold enough state to reconstruct joined `a`?
- Does any single server-side role hold enough state to reconstruct joined
  `x_client_base`?
- Does the client hold enough state to reconstruct joined `y_relayer` or
  `tau_relayer`?
- Are opened values limited to `x_client_base` for the client and
  `x_relayer_base` for the SigningWorker?
- Can Router observe both role shares in plaintext?
- Can A or B bias output without detection at Minimum Level C?
- What changes when public verifying shares are bound?

## Release Gate

Production use requires a candidate-specific leakage table covering:

- Router view
- Deriver A view
- Deriver B view
- client view
- relayer view
- storage view
- diagnostics/logging view
- replayed transcript view

## Candidate A: MPC Threshold PRF

Status: adapter leakage table complete for the current gated prototype.

Reference:

- [candidate-mpc-threshold-prf.md](candidate-mpc-threshold-prf.md)

Summary:

- Router sees public metadata, encrypted package headers, commitments, receipts,
  and replay decisions.
- Deriver A sees only A-side PRF share material and A-side plaintext partials
  before recipient encryption.
- Deriver B sees only B-side PRF share material and B-side plaintext partials
  before recipient encryption.
- Client opens only `x_client_base`.
- SigningWorker opens only `x_relayer_base`.
- Plaintext partial wrappers are debug-redacted, zeroizing, and excluded from
  Serde serialization.
- Minimum Level C does not prove partial correctness by itself; production
  activation must require DLEQ verification, equivalent authenticity, or address
  verification before accepting a new output relation.

Remaining Candidate A leakage work before selecting this primitive:

- bind the cryptographic DLEQ adapter to the production authenticated deriver
  commitment registry
- decide whether DLEQ is mandatory at Minimum Level C or a stronger output
  correctness level
- add formal model entries for the partial/recipient visibility invariant

## Candidate B: Split Root Derivation

Status: adapter leakage table complete for the current gated prototype.

Reference:

- [candidate-split-root.md](candidate-split-root.md)

Summary:

- Router sees public metadata, encrypted package headers, commitments, receipts,
  and replay decisions.
- Deriver A sees only `root_a` and A-side plaintext output shares before
  recipient encryption.
- Deriver B sees only `root_b` and B-side plaintext output shares before
  recipient encryption.
- Client opens only `x_client_base`.
- SigningWorker opens only `x_relayer_base`.
- Plaintext root and output-share wrappers are debug-redacted, zeroizing, and
  excluded from Serde serialization.
- Refresh creates a new verified output relation; preserving refresh is outside
  the current split-root adapter.
- Minimum Level C does not prevent deriver bias by itself; production activation
  must require address verification or public-share-binding hardening.

Remaining Candidate B leakage work before selecting this primitive:

- decide whether to promote the provisional SHA-512-to-Scalar and
  scalar-addition suite
- define the root generation and anti-bias ceremony
- decide whether public-share-binding hardening is mandatory
- add formal model entries for split-root output-share visibility
