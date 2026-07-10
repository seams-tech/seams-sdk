# Ed25519 Yao Verus Mirror

This unpublished standalone crate verifies four concrete facts about the
implemented foundation: family-byte separation, manifest digest-slot count,
manifest metric count, and the valid gate-total relation.

The family and count specifications use the same executable constants imported
by `tests/anti_drift.rs`. The executable checked-overflow gate relation carries
a Verus postcondition equating it with the mathematical relation, and the
anti-drift suite compares that function with production acceptance and
rejection cases.

Its executable helpers mirror the generator's wrapping addition and RFC 8032
clamp. [`tests/anti_drift.rs`](tests/anti_drift.rs) compares those helpers and
all frozen identifiers with production independently of Verus.

```sh
cargo yao-fv anti-drift
cargo yao-fv verus-check
```

The verifier command requires release `0.2026.04.03.21dfcd2` and
`vstd = 0.0.0-2026-03-29-0113`. A mismatch is a hard failure.

This crate proves no SHA-256 property, circuit equivalence, garbling property,
privacy statement, or active-security composition.
