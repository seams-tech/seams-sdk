# Ed25519 Yao Circuit IR V1

Status: **frozen generator-owned Phase 2A benchmark
component/schedule/bundle contract; benchmark-only and non-promotable**

This specification fixes the Boolean intermediate representation and three
deterministic benchmark components implemented by
`tools/ed25519-yao-generator`: SHA-512 over exactly one 32-byte input, the
provisional activation core, and the provisional export core. It owns their byte
and bit order, field order, fixed SHA-512 block, Boolean and scalar topology,
canonical IR and liveness-schedule encodings, schema bindings, scheduled
clear-evaluator semantics, purpose-specific digest types, digests, and metrics.

The keywords **MUST**, **MUST NOT**, and **REQUIRED** are normative.

## 1. Scope and authority

Version one covers:

- the private generator IR with XOR, AND, and inversion gates;
- deterministic constant folding, commutative operand ordering, dead-gate
  pruning, and wire renumbering;
- the fixed 32-byte SHA-512 benchmark component;
- 256-bit wrapping addition, RFC 8032 clamp, seven-round clamped reduction
  modulo `l`, canonical-scalar addition, `tau` aggregation, and both activation
  output equations;
- distinct provisional activation and export core components;
- one canonical binary IR encoding;
- a deterministic last-use liveness schedule and canonical schedule encoding;
- a variable-time scheduled clear evaluator over public synthetic inputs;
- six purpose-specific, non-promotable component and schedule digest types;
- deterministic emission and byte-for-byte checking of a six-file provisional
  bundle plus its canonical index;
- separate provisional artifact-file and bundle-index digest types;
- the frozen component/schedule digests, derived metrics, and bundle golden in
  Section 9.

These components and schedules are construction-independent Phase 2A evidence.
They are compiler/schedule-correctness fixtures and provisional gate-count
inputs. They do not provide:

- repository-committed generated binary blobs; the six files and index are
  intentionally regenerated on demand;
- a garbled circuit, OT protocol, stream, or private-output protocol;
- a Phase 2B benchmark manifest or circuit-family digest;
- a Phase 6B production artifact or security-suite digest;
- constant-time, role-private, or P0-P3 protocol-security evidence;
- an artifact accepted by Router, Cloudflare, SigningWorker, SDK, persistence,
  or any production loader.

There is no conversion or promotion API from `FixedSha512CircuitV1`,
`ProvisionalActivationCoreV1`, `ProvisionalExportCoreV1`,
`ProvisionalArtifactBundleV1`, or any component, schedule, artifact-file, or
bundle-index digest type to a production artifact or digest. The generator
crate rejects `wasm32`, and production Rust manifests are guarded from
depending on the generator.

## 2. Components and schemas

### 2.1 Fixed SHA-512/32 component

The fixed component discriminator is:

```text
component = 0x81
```

Its input schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/input/v1:seed[32]:byte-major-lsb0
```

Its SHA-256 digest is:

```text
af185192c2e452faff40a0100b8633310f1d7319ef752963caf7ea3f2d6f68c6
```

Its output schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/output/v1:digest[64]:byte-major-lsb0
```

Its SHA-256 digest is:

```text
e587b9ea7d3ac3572fcdd95082e7907790361eb418443a10ab120b87372bb8cc
```

The finalizer requires exactly 256 input wires and 512 distinct output wires.
The two schema digests are embedded in the canonical header. A schema text,
width, order, or digest change produces a different component.

### 2.2 Provisional activation core

The provisional activation component discriminator is:

```text
component = 0x91
```

Its input schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/provisional-benchmark/activation/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l:field-byte-bit-lsb0
```

Its SHA-256 digest is:

```text
bf3ff9a45d95e8cbe0fffbe0adf574d164da8f2913da8f14fe0170d607594ced
```

Its output schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/provisional-benchmark/activation/output/v1:x_client_base[32]:canonical-l,x_server_base[32]:canonical-l:field-byte-bit-lsb0:no-seed
```

Its SHA-256 digest is:

```text
8cfb712162c1497a54e8cf80ccaf53cb1af98c3316f28be594ebc5bd7aa32cb9
```

The finalizer requires exactly 2048 input wires and 512 distinct output wires.
The output schema contains two canonical scalars and explicitly excludes a seed.

### 2.3 Provisional export core

The provisional export component discriminator is:

```text
component = 0x92
```

Its input schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/provisional-benchmark/export/input/v1:a.y_client[32],a.y_server[32],b.y_client[32],b.y_server[32]:field-byte-bit-lsb0:no-tau
```

Its SHA-256 digest is:

```text
d010a3776f9f311033e601835c08d05ef1c196f45d7b36a29d6804f0b57dc093
```

Its output schema is the exact UTF-8 byte string:

```text
seams/router-ab/ed25519-yao/provisional-benchmark/export/output/v1:seed[32]:field-byte-bit-lsb0:no-scalar
```

Its SHA-256 digest is:

```text
667d428722fa5c98635a8dbd3c016481b517a4bdbe3d7c3821b484cd15fdbecf
```

The finalizer requires exactly 1024 input wires and 256 distinct output wires.
The input schema excludes `tau`; the output schema contains only the joined seed
and excludes scalar outputs.

## 3. Byte and bit order

Field traversal is:

```text
field order, then byte index ascending, then bit index 0..7 (LSB0)
```

Within any 32-byte field, field-relative wire `8*j + k` carries bit `k` of byte
`j`, where `j` is in `0..32` and `k` is in `0..8`.

The fixed SHA component has one input field, `seed`.

The activation input fields and wire intervals are exactly:

| Order | Field | Input wires |
| ----: | ----- | ----------- |
| 1 | `a.y_client` | `0..256` |
| 2 | `a.y_server` | `256..512` |
| 3 | `a.tau_client` | `512..768` |
| 4 | `a.tau_server` | `768..1024` |
| 5 | `b.y_client` | `1024..1280` |
| 6 | `b.y_server` | `1280..1536` |
| 7 | `b.tau_client` | `1536..1792` |
| 8 | `b.tau_server` | `1792..2048` |

Its outputs are `x_client_base` followed by `x_server_base`, each in byte-major
LSB0 order.

The export input fields and wire intervals are exactly:

| Order | Field | Input wires |
| ----: | ----- | ----------- |
| 1 | `a.y_client` | `0..256` |
| 2 | `a.y_server` | `256..512` |
| 3 | `b.y_client` | `512..768` |
| 4 | `b.y_server` | `768..1024` |

Its only output is the 32-byte joined seed in byte-major LSB0 order.

SHA-512 consumes the 32 bytes in their existing byte order. Each eight-byte
chunk is parsed as one big-endian SHA-512 word. Internally, each 64-bit word is
an array whose index zero is the word's least significant bit. The mapping from
input bytes to internal word bits performs this byte reversal explicitly.

The digest output uses standard SHA-512 byte order. Output wires traverse digest
word zero through word seven, the most-significant byte through the
least-significant byte of each word, and bit zero through bit seven within each
byte.

## 4. Fixed SHA-512 message block

The component accepts exactly 32 message bytes, or 256 message bits. Standard
SHA-512 padding therefore produces one 1024-bit block with these initial words:

```text
W0  = BE64(seed[0..8])
W1  = BE64(seed[8..16])
W2  = BE64(seed[16..24])
W3  = BE64(seed[24..32])
W4  = 0x8000000000000000
W5  = 0x0000000000000000
W6  = 0x0000000000000000
W7  = 0x0000000000000000
W8  = 0x0000000000000000
W9  = 0x0000000000000000
W10 = 0x0000000000000000
W11 = 0x0000000000000000
W12 = 0x0000000000000000
W13 = 0x0000000000000000
W14 = 0x0000000000000000
W15 = 0x0000000000000100
```

Words `W16..W79` use the standard SHA-512 schedule:

```text
W[t] = small_sigma_1(W[t-2])
       + W[t-7]
       + small_sigma_0(W[t-15])
       + W[t-16]
       mod 2^64

small_sigma_0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
small_sigma_1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
```

The initial state and all 80 round constants are the standard SHA-512 values
encoded as literal `u64` constants by `src/circuit/sha512.rs`. Every compression
round uses:

```text
big_sigma_0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
big_sigma_1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)

Ch(e,f,g)  = g XOR (e AND (f XOR g))
Maj(a,b,c) = c XOR ((a XOR c) AND (b XOR c))
```

All additions are modulo `2^64`. After round 79, each working word is added to
its corresponding initial-state word, and all eight resulting words are emitted.

## 5. Boolean topology

### 5.1 Wires and gate outputs

`WireId` is an unsigned 32-bit integer. Input wires are numbered consecutively
from zero. After canonical dead-gate pruning, gate record `i` has implicit output
wire:

```text
output_wire(i) = input_wire_count + i
```

Every gate operand MUST refer to an input wire or an earlier gate output. Every
output wire MUST be below `input_wire_count + gate_count`.

Builder constants are transient compile-time values. Constants have no encoded
wire or gate record. Every final output MUST resolve to a wire, and final output
wires MUST be distinct.

### 5.2 Gate set

The encoded gate set is exactly:

| Opcode | Gate | Semantics |
| -----: | ---- | --------- |
| `0x01` | XOR  | `left XOR right` |
| `0x02` | AND  | `left AND right` |
| `0x03` | INV  | `NOT input` |

XOR and AND operands are ordered by ascending wire ID when the gate is created.
An inversion record repeats its input wire in both encoded operand slots.

### 5.3 Canonical simplification

The builder applies these local rules before appending a gate:

```text
constant XOR constant -> constant
x XOR 0               -> x
x XOR 1               -> INV(x)
x XOR x               -> 0

constant AND constant -> constant
x AND 0               -> 0
x AND 1               -> x
x AND x               -> x

INV(constant)          -> constant
```

Finalization traces backwards from the ordered output wires, marks reachable
gates, removes every unreachable gate, preserves the relative order of retained
gates, and deterministically remaps retained gate outputs and final outputs.
There is no common-subexpression elimination or runtime optimization pass.

### 5.4 SHA Boolean formulas

For bit position `i`, a 64-bit addition computes:

```text
sum[i]       = left[i] XOR right[i] XOR carry[i]
carry[i + 1] = carry[i]
               XOR ((left[i] XOR carry[i])
                    AND (right[i] XOR carry[i]))
```

`carry[0]` is zero. The carry network is emitted for positions `0..62`. Position
63 emits its sum and discards the final carry, preventing dead final-carry gates.
Three-word XORs are left-associated. Rotations only permute existing builder
bits; right shifts fill vacated high positions with compile-time zero bits.

### 5.5 256-bit addition and RFC 8032 clamp

Little-endian 256-bit addition uses the same sum and carry equations as Section
5.4 over bit positions `0..255`. A wrapping addition discards carry 256. The
conditional scalar subtraction helper retains carry 256 as its no-borrow bit.

The RFC 8032 clamp rewrites these builder bits without emitting gates:

```text
bit 0   = 0
bit 1   = 0
bit 2   = 0
bit 254 = 1
bit 255 = 0
```

Every other bit remains the corresponding digest-prefix wire.

### 5.6 Scalar reduction and addition

The scalar order is the canonical little-endian value frozen by
`fixed-reference-v1.md`:

```text
l = edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010
```

One conditional subtraction computes `value + (2^256 - l)`. Its final carry is
one exactly when `value >= l`. The result selects the low 256-bit difference
when that carry is one and retains `value` when it is zero:

```text
selected = value XOR (no_borrow AND (difference XOR value))
```

`reduce_clamped_mod_l_bits` applies this conditional subtraction exactly seven
times. RFC 8032 clamping makes the input smaller than `2^255`, while `l` is
greater than `2^252`; seven fixed rounds therefore reduce every permitted
clamped input to its canonical representative.

`add_mod_l_bits(left, right)` requires both inputs to be canonical encodings. It
computes their 256-bit sum and applies one conditional subtraction. Canonical
inputs satisfy `left + right < 2*l < 2^256`, so the wrapping sum loses no carry
and one subtraction is sufficient.

The activation harness validates all four `tau` fields with
`Scalar::from_canonical_bytes` before evaluation. A rejection identifies one of
`DeriverAClient`, `DeriverAServer`, `DeriverBClient`, or `DeriverBServer`. The
Boolean core contains no `tau < l` comparator. Canonical `tau` is an explicit
public-synthetic host precondition encoded by `:canonical-l` in the activation
input schema. Production provenance, input consistency, and malicious-input
handling remain outside this contract.

### 5.7 Provisional activation core

The activation core composes the implemented fragments in this exact order:

```text
y_A  = a.y_client + a.y_server mod 2^256
y_B  = b.y_client + b.y_server mod 2^256
seed = y_A + y_B mod 2^256

digest         = SHA-512(seed)
digest_prefix  = digest[0..32]
clamped        = clamp_rfc8032(digest_prefix)
signing_scalar = clamped mod l, using seven conditional-subtraction rounds

tau_A = a.tau_client + a.tau_server mod l
tau_B = b.tau_client + b.tau_server mod l
tau   = tau_A + tau_B mod l

x_client_base = signing_scalar + tau mod l
x_server_base = x_client_base + tau mod l
```

Only `x_client_base` and `x_server_base` are output wires. The joined seed,
SHA-512 digest, clamped value, signing scalar, and joined `tau` remain internal
clear-evaluator wires and are absent from the activation result type.

### 5.8 Provisional export core

The export core composes only three 256-bit wrapping additions:

```text
y_A  = a.y_client + a.y_server mod 2^256
y_B  = b.y_client + b.y_server mod 2^256
seed = y_A + y_B mod 2^256
```

Only `seed` is output. The export core has no `tau`, SHA-512, clamp, scalar
reduction, or scalar-output wires.

## 6. Canonical IR and liveness-schedule encodings

### 6.1 Canonical Boolean IR encoding

The canonical encoding has one 86-byte header, one 9-byte record per canonical
gate, and one four-byte wire ID per output. It has no padding, alignment bytes,
trailer, checksum field, or embedded metric block.

All integer fields and wire IDs use unsigned big-endian encoding.

| Offset | Bytes | Field |
| -----: | ----: | ----- |
| `0`  | `8`  | ASCII magic `EYAOIR01` |
| `8`  | `1`  | component discriminator: `0x81`, `0x91`, or `0x92` |
| `9`  | `1`  | bit-order discriminator `0x01` for byte-major LSB0 |
| `10` | `32` | SHA-256 of the exact input-schema bytes |
| `42` | `32` | SHA-256 of the exact output-schema bytes |
| `74` | `4`  | input-wire count, `BE32` |
| `78` | `4`  | canonical gate count, `BE32` |
| `82` | `4`  | output-wire count, `BE32` |

Each gate record is:

```text
opcode[1] || left_or_input_wire_BE32[4] || right_or_input_wire_BE32[4]
```

The ordered output-wire list immediately follows the final gate record:

```text
output_wire_0_BE32 || ... || output_wire_(output_count-1)_BE32
```

The exact byte length is:

```text
86 + 9 * gate_count + 4 * output_count
```

The circuit digest is SHA-256 over this complete canonical byte sequence.

### 6.2 Deterministic liveness schedule

The schedule is derived only after canonical IR dead-gate pruning and wire
renumbering. Its last-use, smallest-free, read-before-write, and output-pinning
rules are exact:

1. Scan canonical gates in order. The last gate that reads a wire is its last
   use.
2. Assign every ordered circuit output a terminal use after the final gate.
   This pins every output wire and its slot through completion.
3. Load input wire `i` into slot `i`. An input with no use is immediately
   available for reuse.
4. For each canonical gate, resolve and read both operand slots before any slot
   release or output write. An inversion uses the same slot as both operands.
5. Release each operand slot whose last use is the current gate. Equal operands
   release their shared slot once.
6. Assign the gate output the numerically smallest free slot. Allocate the next
   consecutive slot when the free set is empty, then write the output.
7. Append the pinned output-slot identifiers in canonical circuit-output order.

Reading both operands before releasing either slot permits the current gate's
output to reuse a just-consumed operand slot safely. The resulting
`reusable_slot_count` is the evaluator's fixed slot-arena high-water count for
that canonical schedule.

### 6.3 Canonical liveness-schedule encoding

The canonical schedule encoding has a 58-byte header, one fixed-width record
per canonical gate, and one slot identifier per ordered output. It has no
padding, alignment bytes, trailer, checksum field, or embedded metric block.

All count fields and slot identifiers use unsigned big-endian encoding.

| Offset | Bytes | Field |
| -----: | ----: | ----- |
| `0`  | `8`  | ASCII magic `EYAOSC01` |
| `8`  | `1`  | component discriminator: `0x81`, `0x91`, or `0x92` |
| `9`  | `1`  | minimal slot-identifier width in bytes |
| `10` | `32` | SHA-256 digest of the complete canonical Boolean IR encoding |
| `42` | `4`  | input-wire count, `BE32` |
| `46` | `4`  | scheduled canonical gate count, `BE32` |
| `50` | `4`  | pinned output-slot count, `BE32` |
| `54` | `4`  | reusable-slot count, `BE32` |

Each scheduled gate record is:

```text
opcode[1] || left_slot_BE[slot_width] || right_slot_BE[slot_width]
          || output_slot_BE[slot_width]
```

Opcodes `0x01`, `0x02`, and `0x03` retain the XOR, AND, and INV meanings from
Section 5.2. An INV record repeats its input slot in the left and right fields.
The ordered output-slot list immediately follows the final gate record.

The slot width is the minimum width that represents
`reusable_slot_count - 1`: one byte through `0xff`, two through `0xffff`, three
through `0xff_ffff`, and four otherwise. Each of the three frozen schedules has
two-byte slots and seven-byte gate records.

For slot width `w`, the exact byte length is:

```text
58 + gate_count * (1 + 3*w) + output_count * w
```

The schedule digest is SHA-256 over this complete canonical byte sequence. Its
header binds the schedule to the exact component discriminator and canonical IR
digest.

### 6.4 Generated Phase 2A bundle index

The generator emits these six files in fixed tag order:

| Tag | Fixed filename | Canonical contents |
| --: | -------------- | ------------------ |
| `1` | `sha512-fixed32.ir.bin` | fixed SHA-512/32 Boolean IR |
| `2` | `sha512-fixed32.schedule.bin` | fixed SHA-512/32 liveness schedule |
| `3` | `activation.ir.bin` | provisional activation Boolean IR |
| `4` | `activation.schedule.bin` | provisional activation liveness schedule |
| `5` | `export.ir.bin` | provisional export Boolean IR |
| `6` | `export.schedule.bin` | provisional export liveness schedule |

The seventh emitted filesystem entry is the canonical index
`ed25519-yao-phase2a-bundle-v1.bin`. Its header is exactly:

```text
ASCII("EYAOBA01")[8] || entry_count[1] = 0x06
```

Six entries follow in the table's tag order. Each entry is exactly:

```text
tag[1]
|| filename_length_BE16[2]
|| filename_utf8[filename_length]
|| artifact_length_BE64[8]
|| SHA256(artifact_bytes)[32]
```

The index has no paths, padding, alignment bytes, trailer, embedded artifact
bytes, Phase 2B fields, or production fields. Its digest is SHA-256 over the
complete index and is represented only by
`ProvisionalArtifactBundleDigest32V1`. Individual file digests use
`ProvisionalArtifactFileDigest32V1`.

The six binary files and index are generated evidence and remain uncommitted.
The index is a canonical Phase 2A reproducibility index. It is neither a Phase
2B reviewed benchmark manifest nor a production manifest.

## 7. Clear evaluator

The public compiler entrypoints are exactly:

```text
compile_fixed_sha512_32_v1
compile_provisional_activation_core_v1
compile_provisional_export_core_v1
```

They accept no component tag, schema, gate list, output list, circuit bytes, or
caller-provided artifact.

`evaluate_public_synthetic_seed` accepts exactly `[u8; 32]`, maps those bytes to
256 Boolean inputs, evaluates the canonical liveness schedule, reads the 512
pinned output slots, and returns `[u8; 64]`.

`ProvisionalActivationCoreV1::evaluate_public_synthetic` accepts only
`PublicSyntheticActivationCoreInputsV1`. That aggregate requires the disjoint A
and B role input types, and each role constructor validates its two canonical
`tau` fields once at the host boundary. Evaluation returns only
`PublicSyntheticActivationCoreOutputsV1`, whose accessors expose the two
canonical scalar outputs and no seed.

`ProvisionalExportCoreV1::evaluate_public_synthetic` accepts only
`PublicSyntheticExportCoreInputsV1`. Its disjoint A and B role types carry only
`y_client` and `y_server`. Evaluation returns
`PublicSyntheticExportCoreOutputV1`, whose sole accessor exposes the joined
seed.

All three public evaluators allocate one clear `bool` vector sized to the
schedule's reusable-slot count, load input bits into the initial slots, execute
records in order, and read the pinned output slots. Each record reads its
operands before writing its output slot. The private scheduled evaluator rejects
an input slice whose length differs from the schedule's fixed input count.

`ProvisionalBenchmarkComponentDigest32V1`,
`ProvisionalActivationCoreDigest32V1`, and
`ProvisionalExportCoreDigest32V1` are distinct opaque component-digest types.
`ProvisionalBenchmarkScheduleDigest32V1`,
`ProvisionalActivationScheduleDigest32V1`, and
`ProvisionalExportScheduleDigest32V1` are distinct opaque schedule-digest types.
Each exposes public bytes for benchmark reproduction and has no conversion into
another benchmark family, component/schedule purpose, or production digest
type.

The artifact `emit` and `check` commands compile the trusted generator outputs
locally. `check` compares the exact seven expected files byte for byte. It does
not parse, decode, or evaluate bytes supplied by the emitted directory. The
separate stdlib-Python verifier now strictly decodes those bytes, independently
rederives the liveness schedules, and evaluates both encodings over the five
committed cases. That early evidence has no Phase 2B manifest or exit authority;
review, wider reconciliation, and production artifact acceptance remain open.

Phase 2A emission and verification require a direct, process-owned bundle
directory with no concurrent writers. Both implementations reject a static
symlinked root, static symlinked entries, and files larger than their fixed
length before unbounded allocation. Their path-based I/O does not exclude
hardlinks or replacement races and emission is not atomic. Phase 2B must use
descriptor-relative no-follow I/O and atomic publication, or confine every run
to a newly created private directory, before any shared or externally supplied
artifact directory is accepted.

The evaluator stores clear `bool` slots in a host `Vec`. Its execution may be
variable-time and may allocate because all permitted values are public
synthetic fixtures. Production secrets MUST NOT enter this crate.

## 8. Rejection and non-authority rules

The component finalizer rejects:

- zero input wires, zero gates, or zero outputs;
- a fixed SHA component width other than 256 inputs and 512 outputs;
- a provisional activation width other than 2048 inputs and 512 outputs;
- a provisional export width other than 1024 inputs and 256 outputs;
- a constant final output;
- a duplicate final output wire;
- a count or allocation-size overflow;
- a forward or out-of-range gate/output reference.

Dead gates are removed deterministically before topology validation, IR
encoding, and schedule derivation. The IR and schedule byte surfaces have no
decoder or loader. Unknown, stale, mixed-family, malformed, or caller-provided
bytes therefore have no acceptance path in this API.

A component digest, schedule digest, or metric mismatch invalidates the V1
benchmark evidence. A semantic, schema, topology, liveness, encoding, or golden
change requires an explicit versioned specification and reviewed regeneration.
It cannot be treated as production artifact rollout.

The activation harness additionally rejects each noncanonical `tau` before
creating its complete typed input. The export input surface cannot represent a
`tau` field, and the activation output surface cannot represent a seed.

Bundle checking rejects a nondirectory path, any missing expected file, any
extra directory entry, and any byte mutation in an artifact or the index.
Repeated emission is deterministic and may recreate or overwrite expected
files; emission rejects every extra directory entry. These checks establish
regeneration parity only and grant no artifact-loading authority.

## 9. Frozen benchmark golden

### 9.1 Fixed SHA-512/32 component

The canonical fixed SHA-512/32 component has:

| Property | Frozen V1 value |
| -------- | --------------: |
| Input wires | `256` |
| Output wires | `512` |
| Total wires | `331113` |
| AND gates | `54868` |
| XOR gates | `269622` |
| INV gates | `6367` |
| Total gates | `330857` |
| Full Boolean depth | `10675` |
| AND depth | `3301` |
| Canonical encoded bytes | `2979847` |
| Passive Half-Gates table estimate | `1755776` bytes |
| Scheduled gates | `330857` |
| Reusable schedule slots (high-water) | `4737` |
| Schedule slot width | `2` bytes |
| Scheduled-gate record width | `7` bytes |
| Canonical schedule bytes | `2317081` |

The passive table estimate is:

```text
54868 AND gates * 2 ciphertexts * 16 bytes = 1755776 bytes
```

No garbled table is generated by this component.

The SHA-256 digest of the complete canonical IR encoding is:

```text
11488ae3b47722d42d4fc7e2d03fa2684312887ab93c3c9a0b080021b468f53b
```

The SHA-256 digest of the complete canonical liveness-schedule encoding is:

```text
0d7c79a0ab31b2ae04b91319355bb79aef32c5f3d5f8532a3db632b121f627da
```

Full depth assigns depth zero to inputs and adds one for XOR, AND, or INV.
AND depth assigns depth zero to inputs, adds one only for AND, and takes the
maximum operand depth through XOR and INV. Both metrics are recomputed from the
canonical pruned topology.

### 9.2 Provisional activation core

The canonical provisional activation core has:

| Property | Frozen V1 value |
| -------- | --------------: |
| Component discriminator | `0x91` |
| Input wires | `2048` |
| Output wires | `512` |
| Total wires | `369288` |
| AND gates | `62716` |
| XOR gates | `294021` |
| INV gates | `10503` |
| Total gates | `367240` |
| Full Boolean depth | `17903` |
| AND depth | `5723` |
| Canonical encoded bytes | `3307294` |
| Passive Half-Gates table estimate | `2006912` bytes |
| Scheduled gates | `367240` |
| Reusable schedule slots (high-water) | `5761` |
| Schedule slot width | `2` bytes |
| Scheduled-gate record width | `7` bytes |
| Canonical schedule bytes | `2571762` |

Its passive table estimate is:

```text
62716 AND gates * 2 ciphertexts * 16 bytes = 2006912 bytes
```

This estimate is below the Phase 2 passive-table ceiling of 2.10 MiB. It covers
only Half-Gates table bytes for this provisional Boolean topology.

The SHA-256 digest of the complete canonical activation IR encoding is:

```text
747fa6f1815e3a0c70f0077ffc10508882f321ad6e7bb422f4eef695a853b5a5
```

The SHA-256 digest of the complete canonical activation-schedule encoding is:

```text
e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25
```

At one 16-byte label per reusable slot, the activation schedule implies:

```text
5761 slots * 16 bytes = 92176 bytes
```

This is a provisional single-label-per-slot arithmetic implication. A
production garbler or evaluator may require multiple slot buffers, labels, or
auxiliary state. The value excludes garbled tables, input material, output
translation, protocol framing, and runtime allocation overhead.

### 9.3 Provisional export core

The canonical provisional export core has:

| Property | Frozen V1 value |
| -------- | --------------: |
| Component discriminator | `0x92` |
| Input wires | `1024` |
| Output wires | `256` |
| Total wires | `5608` |
| AND gates | `765` |
| XOR gates | `3819` |
| INV gates | `0` |
| Total gates | `4584` |
| Full Boolean depth | `766` |
| AND depth | `255` |
| Canonical encoded bytes | `42366` |
| Passive Half-Gates table estimate | `24480` bytes |
| Scheduled gates | `4584` |
| Reusable schedule slots (high-water) | `1025` |
| Schedule slot width | `2` bytes |
| Scheduled-gate record width | `7` bytes |
| Canonical schedule bytes | `32658` |

Its passive table estimate is:

```text
765 AND gates * 2 ciphertexts * 16 bytes = 24480 bytes
```

The SHA-256 digest of the complete canonical export IR encoding is:

```text
3cc95694e01966642db7eaed9d68a4116c66bc4d72f14908d0d3b5e25ee79838
```

The SHA-256 digest of the complete canonical export-schedule encoding is:

```text
bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071
```

No garbled table is generated by either provisional core.

### 9.4 Generated Phase 2A artifact bundle

The six generated artifact files are frozen as:

| Tag | Filename | Bytes | SHA-256 |
| --: | -------- | ----: | ------- |
| `1` | `sha512-fixed32.ir.bin` | `2979847` | `11488ae3b47722d42d4fc7e2d03fa2684312887ab93c3c9a0b080021b468f53b` |
| `2` | `sha512-fixed32.schedule.bin` | `2317081` | `0d7c79a0ab31b2ae04b91319355bb79aef32c5f3d5f8532a3db632b121f627da` |
| `3` | `activation.ir.bin` | `3307294` | `747fa6f1815e3a0c70f0077ffc10508882f321ad6e7bb422f4eef695a853b5a5` |
| `4` | `activation.schedule.bin` | `2571762` | `e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25` |
| `5` | `export.ir.bin` | `42366` | `3cc95694e01966642db7eaed9d68a4116c66bc4d72f14908d0d3b5e25ee79838` |
| `6` | `export.schedule.bin` | `32658` | `bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071` |

The canonical `ed25519-yao-phase2a-bundle-v1.bin` index is exactly 387 bytes.
Its SHA-256 digest is:

```text
aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1
```

Generate the intentionally uncommitted files and index with:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-circuit-artifacts -- emit \
  --output-dir target/ed25519-yao-phase2a-bundle-v1
```

Regenerate the canonical bundle in memory and compare that exact directory with:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-circuit-artifacts -- check \
  --input-dir target/ed25519-yao-phase2a-bundle-v1
```

Both successful commands report the canonical bundle-index digest above. The
checker accepts only the six files and one index with exact bytes.

## 10. Executable evidence

Generator tests establish:

- gate truth tables, constant folding, commutative ordering, and deterministic
  dead-gate pruning;
- fixed-schema input/output width rejection;
- exact big-endian `W0..W3`, fixed padding `W4`, zero `W5..W14`, and bit length
  `W15`;
- parity with `sha2::Sha512` for zero, all-ones, incremental, and single-bit
  inputs spanning byte and word boundaries;
- 256-bit wrapping addition parity across carry, wrap, bit-boundary, and
  deterministic cases;
- exact clamp bit replacement and clear-oracle parity;
- seven-round scalar reduction at clamp extremes and around `k*l` for
  `k = 1..7`;
- canonical modular-addition parity and repeated four-input `tau` aggregation;
- rejection of each noncanonical A/B client/server `tau` field;
- activation/export field, schema, result, and purpose-specific digest
  separation;
- activation scalar-output and export seed-output parity for every committed
  five-case arithmetic vector and 128 deterministic differential vectors;
- exact last-use release, smallest-free allocation, read-before-write reuse,
  output pinning, and ordered output-slot recovery on a focused circuit;
- scheduled/unscheduled clear-evaluation parity and scheduled evaluation of all
  public component and family vectors;
- byte-for-byte IR and `EYAOSC01` schedule regeneration with exact component
  discriminators, two-byte slots, and seven-byte scheduled-gate records;
- all six component/schedule digests and every metric in Section 9;
- exact `EYAOBA01` index header, six-entry order, filenames, lengths, file
  digests, 387-byte index encoding, and bundle digest;
- idempotent emission plus rejection of nondirectory, missing, extra, and
  byte-mutated emitted-file inputs.

Run the focused component tests with:

```sh
cargo test --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  circuit::
```

Run the 11 focused bundle tests with:

```sh
cargo test --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  artifact_bundle::tests
```

The counted `cargo yao-fv parity` CI track currently runs 303 generator tests,
including 16 circuit tests, 11 bundle tests, seven semantic-lifecycle vector
tests, 11 output-party-view tests, 14 evaluation-input party-view tests, and
four uniform-abort plus four evaluator-abort state/party-view and four export-
delivery corpus tests, plus two activation-delivery core and four activation-
delivery corpus tests. Six
generator tests cover the construction-independent ideal joint refresh delta;
three separate tests cover the artifact-filesystem policy crate.

This is executable correctness, cost, emitted-file regeneration, and independent
five-case byte-decoding/evaluation evidence for the host-only benchmark
components, liveness schedules, and generated bundle. The counted Phase 2B
mechanical reconciliation gate now passes against the complete Phase 1 corpus.
Independent-host reproduction and review, 128-case artifact evaluation, formal circuit refinement,
compiled constant-time behavior, garbling correctness, and every
protocol-security claim remain open.

## 11. Required next-artifact separation

The following artifacts remain distinct:

1. The V1 fixed SHA-512/32 benchmark component, identified by component `0x81`,
   its schema digests, `ProvisionalBenchmarkComponentDigest32V1`,
   `ProvisionalBenchmarkScheduleDigest32V1`, and its Section 9 component and
   schedule digests.
2. The provisional activation core, identified by component `0x91`, its
   seed-free schemas, `ProvisionalActivationCoreDigest32V1`,
   `ProvisionalActivationScheduleDigest32V1`, and its Section 9 component and
   schedule digests.
3. The provisional export core, identified by component `0x92`, its
   `tau`-free/seed-only schemas, `ProvisionalExportCoreDigest32V1`,
   `ProvisionalExportScheduleDigest32V1`, and its Section 9 component and
   schedule digests.
4. The on-demand Phase 2A generated bundle: six intentionally uncommitted
   binary files, their `ProvisionalArtifactFileDigest32V1` identities, and the
   canonical `EYAOBA01` index identified by
   `ProvisionalArtifactBundleDigest32V1` and the Section 9.4 digest. This index
   has no Phase 2B or production-manifest authority.
5. Phase 2B reviewed passive benchmark manifests and core-family digests,
   frozen only after reconciliation with the complete Phase 1 contract.
6. Phase 6B production artifacts, which bind the Phase 6A-selected P0-P3
   composition, private-output realization, protocol checks, production
   schedules, and production security-suite digest.

No later artifact may reuse any current component, schedule, file, or bundle
digest as its artifact identity or accept it as production-equivalent evidence.
