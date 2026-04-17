# `threshold-prf` Lean Boundary Track

This track is deferred.

Use it only if `threshold-prf` develops a stable Rust-facing helper boundary
that is important enough to mechanically extract and compare against a
handwritten Lean model.

Do not create generated artifacts here until the extraction boundary,
`PrfPartialWireV1`, and the JSON vector corpus are frozen.

Planned boundary candidates:

- canonical context encoding
- share/partial wire encoding, including transported context-tag validation
- direct reference evaluation wrapper
- partial-combine wrapper

Non-goals:

- proving hash-to-group internals
- proving full runtime behavior
- proving side-channel resistance
- duplicating the Verus algebraic model without a Rust extraction target
