# Router A/B Core Specifications

`router-ab-core` implements one ECDSA derivation construction. The normative
contract is [ecdsa-threshold-prf.md](ecdsa-threshold-prf.md). Product-wide
Ed25519 Yao architecture, rollout, and security-profile work is tracked in
[`docs/yaos-ab.md`](../../../docs/yaos-ab.md).

The deleted pre-selection documents described candidate negotiation,
split-root comparison code, Minimum Level C, generic evidence/state-machine
scaffolding, and comparison vectors. None of those shapes are part of the
current API or protocol.
