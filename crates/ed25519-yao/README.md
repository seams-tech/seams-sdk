# Ed25519 Yao

`ed25519-yao` owns validated **draft** protocol and circuit-manifest types for
the fixed Router A/B Ed25519 Yao design. The crate cannot represent a reviewed
or production-active artifact yet.

The only protocol identifier is:

```text
router_ab_ed25519_yao_v1
```

The protocol has two disjoint circuit families and two disjoint output-schema
types:

- `ed25519_yao_activation_v1` uses
  `ed25519_yao_activation_output_schema_v1` for registration, activation,
  recovery, and refresh output derivation. Its schema must contain no
  seed-export wires.
- `ed25519_yao_export_v1` uses `ed25519_yao_export_output_schema_v1` for
  explicitly authorized seed export.

The Rust API exposes `DraftActivationCircuitManifest`,
`DraftExportCircuitManifest`, and `DraftProtocolManifest`. There are no
production manifest aliases and no constructible reviewed-active state. Each
artifact digest role has a distinct validated type, so same-width circuit,
compiler, source-IR, schedule, constants, input-schema, activation-output, and
export-output digests cannot be exchanged accidentally.
`ActivationCircuitArtifactDigests` and `ExportCircuitArtifactDigests` also make
whole-bundle family substitution a type error. The draft aggregate rejects
circuit, schedule, or output-schema digest reuse across families.

## Canonical draft-manifest identity

Each family manifest computes its identity internally as SHA-256 over this
canonical byte sequence, in exact order:

1. Domain/version bytes:
   `seams:router-ab:ed25519-yao:draft-manifest:v1`.
2. One family byte: `0x01` for activation or `0x02` for export.
3. Output-schema identifier length encoded as one big-endian `u64`.
4. Output-schema identifier UTF-8 bytes.
5. Seven raw 32-byte digests: circuit, compiler, source IR, schedule,
   constants, input schema, then the family-specific output schema.
6. Thirteen big-endian `u64` metrics: AND gates, XOR gates, inversion gates,
   total gates, complete circuit depth, AND depth, input wires, output-wire
   references, total logical wires, scheduled gates, peak live wires, encoded
   schedule bytes, then passive Half-Gates table payload bytes. The payload is
   derived as exactly 32 bytes per AND gate.

`DraftActivationManifestDigest32` and `DraftExportManifestDigest32` expose the
results. Their fields and constructors are private, so callers cannot supply or
override a manifest identity.

## Security status

This crate does not implement Yao garbling, oblivious transfer, streaming,
output decoding, recipient encryption, or any ceremony state machine. It has no
passive protocol entrypoint and no runtime backend or security-level selector.
No active-security suite has been selected. Production implementation remains
blocked until one reviewed suite has specified garbling correctness,
malicious-secure OT, input consistency, selective-failure resistance, private
randomized outputs, and correctness-with-abort composition.

All values currently handled by this crate are public artifact metadata. Future
code that handles labels, masks, OT state, or secret inputs requires dedicated
constant-time and secret-lifecycle review.

## Boundary policy

There is intentionally no Serde representation. A future wire or artifact
adapter must validate raw lengths and values at its boundary, construct the
field-specific digest types plus `GateMetrics` and `ScheduleMetrics`, derive
`CircuitMetrics` through `CircuitMetrics::new_passive_half_gates`, place
artifact digests into the required family-specific bundle, then pass only those
validated types into draft manifest constructors. Output counts reference wires
already included in the logical wire count.

## Formal verification

The phased scaffold and proof plan is in
[`docs/formal-verification-plan.md`](docs/formal-verification-plan.md). Formal
implementation remains gated on the exact Phase 1 functionality and party
views, the Phase 2 deterministic circuit artifacts, and the Phase 6 active
suite. The plan reuses the HSS Verus/Lean/Aeneas structure while requiring
explicit nonempty Lean builds and real party-specific security games.

## Checks

```bash
cargo fmt --manifest-path crates/ed25519-yao/Cargo.toml -- --check
cargo test --manifest-path crates/ed25519-yao/Cargo.toml
cargo clippy --manifest-path crates/ed25519-yao/Cargo.toml --all-targets -- -D warnings
cargo check --manifest-path crates/ed25519-yao/Cargo.toml --target wasm32-unknown-unknown
```
