# Ed25519 Yao Provisional Benchmark Manifest V1

Status: frozen Phase 2B candidate and benchmark-only. This manifest cannot be
converted into a reviewed production manifest and does not satisfy the Phase 2B
exit by itself.

## 1. Purpose

The Phase 2A `EYAOBA01` index commits six exact IR/schedule files and their
lengths. This companion manifest additionally commits the compiler contract,
bit and wire order, schemas, component metrics, liveness metrics, passive table
counts, and the complete Phase 2A index identity.

The builder accepts no paths, bytes, digests, schemas, metrics, component lists,
or profile selector. It compiles the three fixed components internally. The
strict parser accepts only byte-for-byte regeneration under this compiler
contract.

## 2. Global identities

```text
magic             = ASCII("EYAOBM01")
format_version    = BE16(1)
status            = 0x01  // benchmark-only
bit_order_tag     = 0x01  // byte-major LSB0
component_count   = 3
component_order   = 0x81, 0x91, 0x92
```

The compiler-contract identity is:

```text
seams/router-ab/ed25519-yao/provisional-benchmark/compiler/rust-boolean-ir/v1
```

The explicit bit-order text is:

```text
field-order, then byte-index ascending, then bit-index 0..7 (LSB0)
```

The explicit wire-order text is:

```text
inputs-consecutive;gate-output=input-count+gate-index;outputs-ordered;commutative-operands-ascending
```

## 3. Canonical encoding

Every variable-width field uses `LP32(value) = BE32(len(value)) || value`.

```text
ProvisionalBenchmarkManifestV1 =
    ASCII("EYAOBM01")
 || BE16(1)
 || 0x01
 || 0x01
 || LP32(compiler_contract_utf8)
 || LP32(bit_order_utf8)
 || LP32(wire_order_utf8)
 || LP32(ASCII("ed25519-yao-phase2a-bundle-v1.bin"))
 || BE64(phase2a_bundle_index_bytes)
 || phase2a_bundle_index_digest[32]
 || 0x03
 || Component(sha512_fixed32)
 || Component(activation)
 || Component(export)
```

Each component is:

```text
Component =
    component_tag[1]
 || LP32(ir_filename_utf8)
 || LP32(schedule_filename_utf8)
 || LP32(input_schema_utf8)
 || LP32(output_schema_utf8)
 || ir_digest[32]
 || schedule_digest[32]
 || BE64(input_wire_count)
 || BE64(output_wire_count)
 || BE64(wire_count)
 || BE64(and_gate_count)
 || BE64(xor_gate_count)
 || BE64(inversion_gate_count)
 || BE64(total_gate_count)
 || BE64(circuit_depth)
 || BE64(and_depth)
 || BE64(canonical_ir_bytes)
 || BE64(schedule_input_wire_count)
 || BE64(schedule_output_wire_count)
 || BE64(scheduled_gate_count)
 || BE64(reusable_slot_count)
 || slot_width_bytes[1]
 || gate_record_width_bytes[1]
 || BE64(canonical_schedule_bytes)
 || BE64(passive_half_gates_table_bytes)
```

For every component:

```text
scheduled_gate_count = total_gate_count
passive_half_gates_table_bytes = 32 * and_gate_count
```

The multiplier is two 16-byte ciphertexts per AND gate. It excludes OT,
framing, recipient-output translation, transport authentication, allocator
overhead, and every active-security mechanism.

## 4. Frozen candidate identity

The exact canonical encoding is 1973 bytes. Its digest is:

```text
SHA-256(
  LP32(ASCII("seams/router-ab/ed25519-yao/provisional-benchmark/manifest-digest/v1"))
  || LP32(ProvisionalBenchmarkManifestV1)
)
= c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81
```

It wraps the 387-byte `EYAOBA01` index with digest:

```text
aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1
```

Any compiler-contract, schema, ordering, artifact, schedule, metric, or count
change requires an explicit reviewed candidate-identity update.

## 5. Acceptance and rejection

The canonical builder has no caller-controlled artifact surface. The strict
parser rejects:

- truncated bytes;
- another magic, version, or status;
- unknown, reordered, missing, or additional components;
- any changed compiler/order/schema/filename field;
- any stale, mixed, caller-provided, or mutated artifact digest;
- any changed circuit, schedule, or passive-table count; and
- trailing bytes.

Exact regeneration is the acceptance predicate. This deliberately avoids a
generic parser that could make arbitrary benchmark artifacts appear approved.

## 6. Security scope

This manifest is deterministic benchmark evidence. It does not establish:

- completion of the Phase 1 lifecycle and runtime party-view contract;
- reviewer approval of compiler semantics or bit ordering;
- clean-build reproducibility on independent hosts beyond the two isolated
  local Cargo targets;
- production circuit, compiler, suite, or artifact authority;
- garbling, OT, output translation, streaming, or protocol security;
- constant-time execution or secret-safe runtime behavior; or
- P0, P1, P2, or P3 security.

The independent stdlib-Python verifier decodes every field, recomputes the
manifest digest, cross-checks the wrapped index, and rejects prefix, component,
and index mutations. Phase 2B remains open until the complete Phase 1 corpus is
reconciled, independent-host builds reproduce it, filesystem handling closes,
and a reviewer explicitly approves the candidate.
