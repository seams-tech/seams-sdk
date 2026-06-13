# `threshold-prf` Verus Track

This is the Verus abstract spec-model track for `threshold-prf`.

The model proves the intended protocol shape. Production anti-drift tests pin
the committed JSON vector corpus to the current Rust helper APIs.

Current covered scope:

- threshold-policy bounds for `1 <= threshold <= share_count`
- share-ID membership against the selected policy
- duplicate and out-of-policy subset rejection for representative shapes
- representative `2-of-3` and `3-of-5` subset acceptance
- fixed-width signing-root share, partial, commitment, proof, and proof-bundle
  wires
- signing-root share-wire decode shape
- proof-bundle ID binding for commitment and partial share IDs
- representative abstract reconstruction claims for `2-of-N` and `3-of-N`
- committed-vector anti-drift parity for production Rust helpers

Current command:

```bash
just threshold-prf-fv
```

Covered by anti-drift tests:

- executable checks against committed vectors
- signing-root share and partial wire width parity
- subset-rejection behavior against production helpers
- DLEQ valid proof-bundle output parity
- DLEQ malformed proof, wrong context, duplicate bundle, and ID-mismatch
  rejection coverage in production Rust tests

Remaining Verus work:

- generic interpolation for arbitrary valid threshold subsets
- production Lagrange-helper linkage
- symbolic DLEQ challenge binding
- symbolic verified-combine rejection obligations

Deferred from this track:

- full hash-to-group correctness
- full hash-to-bytes correctness
- side-channel resistance
- DLEQ proof soundness from first principles
- runtime/transport isolation
