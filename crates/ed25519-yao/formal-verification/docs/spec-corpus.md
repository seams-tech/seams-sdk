# Ed25519 Yao Verification Spec Corpus

Status: **FV1 baseline; Phase 1 functionality freeze remains open**

## Source precedence

1. [`docs/yaos-ab.md`](../../../../docs/yaos-ab.md) owns the approved
   architecture, corruption model, and phased protocol plan.
2. The Phase 1 functionality freeze pack will own exact lifecycle functions,
   context bytes, party views, leakage, and abort behavior.
3. [`tools/ed25519-yao-generator`](../../../../tools/ed25519-yao-generator/README.md)
   owns the clear reference oracle and committed vector corpus.
4. [`crates/ed25519-yao`](../../README.md) owns implemented public identifiers,
   draft manifests, digest roles, and metric validation.
5. This formal tree contains derived mirrors, generated translations, models,
   and explanatory evidence.

The HSS formal tree is historical tooling guidance. Its statements, generated
artifacts, and theorem names have no authority over this protocol.

## Frozen in the FV1 baseline

- protocol and activation/export circuit identifiers;
- activation/export output-schema identifiers;
- canonical draft-manifest domain and family bytes;
- six typed artifact digest roles plus one family-specific output digest;
- twelve scalar manifest metrics;
- exact stable-context encoding, validation, normalization, and binding digest;
- two pure clear-reference helpers: little-endian addition modulo `2^256` and
  RFC 8032 clamping.

## Unfrozen and excluded

- exact lifecycle ideal functionalities;
- stable-context role-local KDF integration and public-key continuity rules;
- complete role views, leakage, randomness, and aborts;
- deterministic circuit IR, compiler, schedule, and generated artifacts;
- garbling, OT, streaming, outputs, tickets, and runtime adapters;
- active-security assumptions and real/ideal security statements.

These exclusions prevent the scaffold from presenting architecture prose as a
mechanized protocol claim. Exact immutable source revisions are recorded after
the Phase 1 freeze checkpoint.
