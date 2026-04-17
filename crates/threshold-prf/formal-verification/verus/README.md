# `threshold-prf` Verus Track

This is the Verus abstract spec-model track for `threshold-prf`.

The first model exists and verifies. It proves the intended protocol shape. The
crate also has anti-drift tests that pin the committed JSON vector corpus to
the production Rust helpers.

Current covered scope:

- input-domain and output-width model
- 2-of-3 subset validation
- duplicate/insufficient-share rejection
- Shamir reconstruction equivalence for all valid pairs
- direct reference PRF evaluation shape
- threshold partial-combine shape
- direct-vs-threshold equivalence
- partial wire context-tag validation
- secret signing-root share wire decode and Option A derivation boundary shape
- abstract malformed scalar-encoding rejection
- explicit output-derivation input tuple binding
- abstract DLEQ commitment/proof boundary shape
- DLEQ-enforced verified-combine boundary shape

Current command:

```bash
just threshold-prf-fv
```

Covered by anti-drift tests:

- executable checks against committed vectors
- share-refresh preservation
- server-SDK signing-root share wire derivation parity
- malformed wire/input rejection parity

Deferred from this track:

- full hash-to-group correctness
- full hash-to-bytes correctness
- side-channel resistance
- DLEQ proof soundness from first principles
- runtime/transport isolation
