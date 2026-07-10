# Ed25519 Yao Verification Spec Corpus

Status: **FV1 baseline; Phase 1 functionality freeze remains open**

## Source precedence

1. [`docs/yaos-ab.md`](../../../../docs/yaos-ab.md) owns the approved
   architecture, corruption model, and phased protocol plan.
2. [`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`](../../../../tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md)
   owns the frozen partial lifecycle and value-custody boundary. Its blocker
   sections identify the semantics it does not yet own.
3. [`tools/ed25519-yao-generator/docs/input-provenance-v1.md`](../../../../tools/ed25519-yao-generator/docs/input-provenance-v1.md)
   owns the proof-system-neutral provenance statement, paired-role invariants,
   epoch meanings, and registration anti-bias requirements. Its explicit
   blockers retain commitment, proof, custody, and active composition work.
4. [`tools/ed25519-yao-generator`](../../../../tools/ed25519-yao-generator/README.md)
   owns the clear reference oracle, role-local KDF, and committed arithmetic and
   KDF-continuity corpora.
5. [`crates/ed25519-yao`](../../README.md) owns implemented public identifiers,
   draft manifests, digest roles, and metric validation.
6. This formal tree contains derived mirrors, generated translations, models,
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
- exact visible-ASCII Yao-only application-binding facts (`walletId`,
  `nearEd25519SigningKeyId`, `signingRootId`, and positive immutable
  `keyCreationSignerSlot`), validation, LP32 encoding, and SHA-256 digest;
- exclusion of circular `nearAccountId`, mutable/current signer slots, versions,
  and epochs from that application binding;
- exact role/source/output-separated HKDF-SHA256 contribution derivation;
- a disjoint five-lifecycle boundary, activation continuation, output custody,
  common public leakage, ideal sharing distributions, and uniform abort shape;
- same-logical-root recovery semantics, opposite-delta refresh arithmetic, and
  the monotonic reference cutover boundary;
- proof-system-neutral provenance statement slots, encodings, role pairing,
  root/input-state epoch meanings, and registration anti-bias requirements;
- committed clear-arithmetic and KDF-continuity corpora plus deterministic
  differential generation;
- two pure clear-reference helpers: little-endian addition modulo `2^256` and
  RFC 8032 clamping.

## Unfrozen and excluded

- production recovery custody/proof, joint refresh-delta generation and proof,
  distributed cutover, provenance artifacts, and the registration anti-bias
  mechanism;
- complete role-private views, persistence views, active-protocol randomness,
  frames, and abort equivalence;
- deterministic circuit IR, compiler, schedule, and generated artifacts;
- garbling, OT, streaming, outputs, tickets, and runtime adapters;
- active-security assumptions and real/ideal security statements.

These exclusions prevent the scaffold from presenting architecture prose as a
mechanized protocol claim. Exact immutable source revisions are recorded after
the Phase 1 freeze checkpoint.
