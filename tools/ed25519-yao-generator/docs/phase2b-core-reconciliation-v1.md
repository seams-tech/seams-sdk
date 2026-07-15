# Ed25519 Yao Phase 2B Core Reconciliation V1

Status: **normative benchmark-only Phase 2B reconciliation specification; no
production, selected-profile, or reviewer-approval authority**

This document freezes the strict five-case certificate that reconciles the
provisional Boolean compiler, scheduled clear evaluator, fixed schemas, and
`EYAOBM01` candidate benchmark manifest with the complete closed Phase 1 corpus
and its party-output semantics.

The certificate is executable evidence. It remains generator-owned, contains
only public synthetic fixture evidence, and cannot be converted into a
production artifact. The keywords **MUST**, **MUST NOT**, and **REQUIRED** are
normative.

## 1. Authority and purpose

The existing specifications retain authority over their values:

- `fixed-reference-v1.md` owns the Phase 1 arithmetic and canonical corpus
  commitments;
- `circuit-ir-v1.md` owns the provisional Boolean IR, clear evaluator,
  liveness schedule, schemas, bit order, wire order, and benchmark-only
  component identities;
- `benchmark-manifest-v1.md` owns the `EYAOBM01` candidate encoding and its
  benchmark-only acceptance rule;
- `evaluation-input-party-views-v1.md` owns the five accepted-input stages,
  exact A/B input custody, evaluation plans, and ideal-function randomness
  exclusion;
- `output-party-views-v1.md` owns the five output stages, A/B share custody,
  authorized Client export seed, and reconstruction relations;
- `semantic-frame-party-views-v1.md` owns the success traces, activation's
  zero-evaluator continuation, and cumulative role views; and
- the branch-specific evaluator specifications own admitted registration,
  recovery, refresh, and export execution authority.

This document owns only:

1. the exact snapshot of all twenty Phase 1 corpus commitments;
2. the exact binding to the existing `EYAOBM01` candidate and its three
   internally generated components;
3. one closed reconciliation case for each request kind;
4. the field-to-wire and wire-to-semantic-output mappings used by the
   independent clear evaluators; and
5. the required Rust and independent stdlib-Python verification procedure.

The certificate MUST NOT select a P0-P3 profile, instantiate output-protection
randomness, define runtime frames, approve circuit semantics on behalf of a
reviewer, or create a production artifact identity.

## 2. Canonical certificate envelope

The committed certificate path is:

```text
vectors/ed25519-yao-phase2b-core-reconciliation-v1.json
```

Its exact envelope identifiers are:

```text
schema = seams:router-ab:ed25519-yao:phase2b-core-reconciliation:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = benchmark_only_phase2b_core_cross_corpus_reconciliation_v1
```

Top-level field order is exactly:

```text
schema
protocol_id
evidence_scope
benchmark_manifest_binding
phase1_corpus_commitments
mapping_contracts
cases
explicit_nonclaims
```

Unknown, missing, duplicated, reordered, or `null` fields are invalid.
Canonical bytes are pretty-printed UTF-8 JSON with two-space indentation and
exactly one trailing LF. A strict Rust parser accepts bytes only when they equal
the internally regenerated canonical certificate byte for byte. It does not
provide general deserialization into the certificate domain type.

The builder accepts no caller-supplied corpus, path, schema, digest, manifest,
component, circuit, schedule, mapping, case, metric, count, profile, or result.
It derives every value from the twenty canonical Phase 1 corpus builders, the
three fixed compiler outputs, and the canonical `EYAOBM01` builder.

## 3. Candidate benchmark-manifest binding

`benchmark_manifest_binding` has exactly this field order:

```text
manifest_magic
manifest_canonical_bytes
manifest_digest_hex
compiler_contract
bit_order
wire_order
bundle_index_file
bundle_index_canonical_bytes
bundle_index_digest_hex
components
```

The fixed values are:

```text
manifest_magic = EYAOBM01
manifest_canonical_bytes = 1973
manifest_digest_hex = c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81
compiler_contract = seams/router-ab/ed25519-yao/provisional-benchmark/compiler/rust-boolean-ir/v1
bit_order = field-order, then byte-index ascending, then bit-index 0..7 (LSB0)
wire_order = inputs-consecutive;gate-output=input-count+gate-index;outputs-ordered;commutative-operands-ascending
bundle_index_file = ed25519-yao-phase2a-bundle-v1.bin
bundle_index_canonical_bytes = 387
bundle_index_digest_hex = aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1
```

`components` contains exactly three entries in `fixed_sha512_32`,
`activation`, `export` order. Each entry has exactly:

```text
component_kind
component_tag
ir_file
schedule_file
input_schema
output_schema
ir_digest_hex
schedule_digest_hex
```

The entries are:

| Component kind | Tag | IR file | Schedule file | IR digest | Schedule digest |
| --- | ---: | --- | --- | --- | --- |
| `fixed_sha512_32` | 129 | `sha512-fixed32.ir.bin` | `sha512-fixed32.schedule.bin` | `11488ae3b47722d42d4fc7e2d03fa2684312887ab93c3c9a0b080021b468f53b` | `0d7c79a0ab31b2ae04b91319355bb79aef32c5f3d5f8532a3db632b121f627da` |
| `activation` | 145 | `activation.ir.bin` | `activation.schedule.bin` | `747fa6f1815e3a0c70f0077ffc10508882f321ad6e7bb422f4eef695a853b5a5` | `e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25` |
| `export` | 146 | `export.ir.bin` | `export.schedule.bin` | `3cc95694e01966642db7eaed9d68a4116c66bc4d72f14908d0d3b5e25ee79838` | `bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071` |

The exact schemas are:

```text
fixed_sha512_32.input =
  seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/input/v1:seed[32]:byte-major-lsb0

fixed_sha512_32.output =
  seams/router-ab/ed25519-yao/benchmark-component/sha512-fixed32/output/v1:digest[64]:byte-major-lsb0

activation.input =
  seams/router-ab/ed25519-yao/provisional-benchmark/activation/input/v1:a.y_client[32],a.y_server[32],a.tau_client[32]:canonical-l,a.tau_server[32]:canonical-l,b.y_client[32],b.y_server[32],b.tau_client[32]:canonical-l,b.tau_server[32]:canonical-l:field-byte-bit-lsb0

activation.output =
  seams/router-ab/ed25519-yao/provisional-benchmark/activation/output/v1:x_client_base[32]:canonical-l,x_server_base[32]:canonical-l:field-byte-bit-lsb0:no-seed

export.input =
  seams/router-ab/ed25519-yao/provisional-benchmark/export/input/v1:a.y_client[32],a.y_server[32],b.y_client[32],b.y_server[32]:field-byte-bit-lsb0:no-tau

export.output =
  seams/router-ab/ed25519-yao/provisional-benchmark/export/output/v1:seed[32]:field-byte-bit-lsb0:no-scalar
```

The independent verifier MUST decode the complete candidate manifest and check
all fields, component metrics, schedule metrics, passive-table relations, and
the wrapped bundle index. The certificate's narrower component projection does
not replace that full manifest validation.

## 4. Exact twenty-corpus Phase 1 snapshot

`phase1_corpus_commitments` is an ordered array of exactly twenty entries. Each
entry has this exact field order:

```text
path
schema
case_count
canonical_bytes
sha256_hex
```

Paths are relative to `tools/ed25519-yao-generator`. `canonical_bytes` includes
the one required trailing LF. The exact array is:

| # | Path | Schema | Cases | Bytes | SHA-256 |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `vectors/ed25519-yao-v1.json` | `seams:router-ab:ed25519-yao:vectors:v1` | 5 | 14826 | `13934b86ed57e6634c2a3d8ff1361923e9caf28c2aad160251d0b2af779a7e36` |
| 2 | `vectors/ed25519-yao-kdf-v1.json` | `seams:router-ab:ed25519-yao:kdf-continuity-vectors:v1` | 1 | 4036 | `9b2c99469aaf09c1f63318315bd7c5e359039548365e62d11424e5875bceb469` |
| 3 | `vectors/ed25519-yao-ceremony-context-v1.json` | `seams:router-ab:ed25519-yao:ceremony-context-vectors:v1` | 5 | 31447 | `82c6c085f4b5d3b8e9b04e288aa3576763676e90f12fda5644de20dd89f2ee26` |
| 4 | `vectors/ed25519-yao-lifecycle-continuity-v1.json` | `seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1` | 6 | 39978 | `c115e81252345985fffd5b6b544d601c5a751b657aca4d1740c27f2f59fc32cd` |
| 5 | `vectors/ed25519-yao-provenance-v1.json` | `seams:router-ab:ed25519-yao:role-input-provenance-vectors:v1` | 4 | 50672 | `8a39d15ddb384fa32111815614a30246e167ec1861d215b89c681e364318d4ba` |
| 6 | `vectors/ed25519-yao-output-sharing-v1.json` | `seams:router-ab:ed25519-yao:output-sharing-vectors:v1` | 6 | 11643 | `c3b340c7f8e181ae38aabb654db7cf6631a11ef634b29e9c46c68c5af6d21965` |
| 7 | `vectors/ed25519-yao-semantic-lifecycle-v1.json` | `seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1` | 5 | 96134 | `758ae82455c6847e04d1b2ad56bc231f6a6a4f44522a9a6d20401a789ef1ca6f` |
| 8 | `vectors/ed25519-yao-output-party-views-v1.json` | `seams:router-ab:ed25519-yao:output-party-views-vectors:v1` | 5 | 36950 | `5aa0c4cbde69125a995c89598dffac41d0924a9cfc05c64af41ccad289c0f9ae` |
| 9 | `vectors/ed25519-yao-evaluation-input-party-views-v1.json` | `seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1` | 5 | 20929 | `da76dfe6e93be9e2dfe4ebfd1c6f7e269a05cd69732c302b8573126f85409f80` |
| 10 | `vectors/ed25519-yao-uniform-abort-envelope-v1.json` | `seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1` | 5 | 1965 | `bf71321d0896c3a6591b0a0f2f57db9a01994209bfcf12dd1ec905e9d6599df0` |
| 11 | `vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json` | `seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1` | 4 | 11508 | `9aa77f2cf1b7f74145789bde79d71b53da3c967081d26e609a95f8829a35ed37` |
| 12 | `vectors/ed25519-yao-export-delivery-v1.json` | `seams:router-ab:ed25519-yao:export-delivery-vectors:v1` | 1 | 5856 | `4fae90165fde33a2642eca0704bbe4ebcf126141a8a7d02d410676a0b3cdbe71` |
| 13 | `vectors/ed25519-yao-activation-delivery-v1.json` | `seams:router-ab:ed25519-yao:activation-delivery-vectors:v1` | 3 | 23164 | `8a27dfff5b56be062241667026c0c7cc69ae3d1a395a08a87728afc031df1ccb` |
| 14 | `vectors/ed25519-yao-activation-recipient-party-views-v1.json` | `seams:router-ab:ed25519-yao:activation-recipient-party-views:v1` | 3 | 17058 | `27500219743d5f103f7d39a2af80ac8ab897a93e0a9c373291666e2f2429d420` |
| 15 | `vectors/ed25519-yao-recovery-credential-transition-v1.json` | `seams:router-ab:ed25519-yao:recovery-credential-transition-vectors:v1` | 1 | 7228 | `5293dde1a79a1ceea5fc48e2fe6ff71126c2cd56faec43374e8f087b23ce78b2` |
| 16 | `vectors/ed25519-yao-export-evaluator-authorization-v1.json` | `seams:router-ab:ed25519-yao:export-evaluator-authorization-vectors:v1` | 1 | 9805 | `b9059e1d931227863375afd20af009b056e7b9daa976206236cb307dfe920702` |
| 17 | `vectors/ed25519-yao-registration-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:registration-evaluator-admission-vectors:v1` | 1 | 13763 | `ceab8a1b60963313716fc6493bf18736f385362e4a04b479bd78005672b6e7d5` |
| 18 | `vectors/ed25519-yao-recovery-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:recovery-evaluator-admission-vectors:v1` | 1 | 13727 | `2555067e3a8bbe0b5242aa370a6db650586ab2da533767dcdc53db8b3afdf19f` |
| 19 | `vectors/ed25519-yao-refresh-evaluator-admission-v1.json` | `seams:router-ab:ed25519-yao:refresh-evaluator-admission-vectors:v1` | 1 | 15627 | `9d5327e9a9623fc101be48f414025d9f6fc108542a72b7126b1ed740b2e0c77a` |
| 20 | `vectors/ed25519-yao-semantic-frame-party-views-v1.json` | `seams:router-ab:ed25519-yao:semantic-frame-party-views:v1` | 8 | 249622 | `3dc6d30e9c48b3ff55513bc254193e7ad1c1756b42b4a999773adfa6b89a45e9` |

The builder MUST reuse the same corpus commitment function used by the generated
`fixed-reference-v1.md` block. A duplicated manually maintained digest table in
Rust is invalid. The independent verifier MUST read each committed file, reject
a symlink or non-regular file under the existing artifact-filesystem policy,
check its canonical bytes with the owning verifier, and recompute every entry.

The reconciliation certificate itself is the twenty-first corpus. It MUST NOT
include its own commitment in `phase1_corpus_commitments`.

## 5. Closed mapping contracts

`mapping_contracts` has exactly these fields in order:

```text
activation_family
activation_continuation
export_family
```

Each producing mapping has exactly:

```text
mapping_id
component_kind
input_fields
output_fields
```

Each input or output field entry has exactly:

```text
semantic_field
source_role
source_field
wire_start
wire_count
byte_order
bit_order
```

`source_role` is `deriver_a`, `deriver_b`, or `circuit_output`.
`byte_order` is always `little_endian`.
`bit_order` is always `byte_index_ascending_lsb0`. Wire ranges are half-open
`[wire_start, wire_start + wire_count)` ranges.

### 5.1 Activation-family mapping

```text
mapping_id = activation_family_inputs_outputs_v1
component_kind = activation
```

The exact input order is:

| Semantic field | Source role | Source field | Wire start | Wire count |
| --- | --- | --- | ---: | ---: |
| `a.y_client` | `deriver_a` | `y_client_hex` | 0 | 256 |
| `a.y_server` | `deriver_a` | `y_server_hex` | 256 | 256 |
| `a.tau_client` | `deriver_a` | `tau_client_hex` | 512 | 256 |
| `a.tau_server` | `deriver_a` | `tau_server_hex` | 768 | 256 |
| `b.y_client` | `deriver_b` | `y_client_hex` | 1024 | 256 |
| `b.y_server` | `deriver_b` | `y_server_hex` | 1280 | 256 |
| `b.tau_client` | `deriver_b` | `tau_client_hex` | 1536 | 256 |
| `b.tau_server` | `deriver_b` | `tau_server_hex` | 1792 | 256 |

The exact output order is:

| Semantic field | Source role | Source field | Wire start | Wire count |
| --- | --- | --- | ---: | ---: |
| `x_client_base` | `circuit_output` | `x_client_base` | 0 | 256 |
| `x_server_base` | `circuit_output` | `x_server_base` | 256 | 256 |

Input `tau` values MUST be canonical little-endian scalars. The clear evaluator
MUST reject each noncanonical A/B client/server `tau` before evaluation.

### 5.2 Activation-continuation mapping

`activation_continuation` has exactly:

```text
mapping_id
evaluation_plan
input_fields
output_fields
```

Its fixed value is:

```text
mapping_id = activation_continuation_zero_evaluation_v1
evaluation_plan:
  kind = zero_evaluation_continuation
  counts:
    yao_evaluations = 0
    deriver_a_invocations = 0
    deriver_b_invocations = 0
    contribution_derivations = 0
    ideal_output_share_samples = 0
input_fields = []
output_fields = []
```

This mapping has no `component_kind`, component tag, circuit id, artifact
digest, schedule digest, schema, wire count, input value, output value, or
output-sharing randomness field.

### 5.3 Export-family mapping

```text
mapping_id = export_family_inputs_outputs_v1
component_kind = export
```

The exact input order is:

| Semantic field | Source role | Source field | Wire start | Wire count |
| --- | --- | --- | ---: | ---: |
| `a.y_client` | `deriver_a` | `y_client_hex` | 0 | 256 |
| `a.y_server` | `deriver_a` | `y_server_hex` | 256 | 256 |
| `b.y_client` | `deriver_b` | `y_client_hex` | 512 | 256 |
| `b.y_server` | `deriver_b` | `y_server_hex` | 768 | 256 |

The exact output order is:

| Semantic field | Source role | Source field | Wire start | Wire count |
| --- | --- | --- | ---: | ---: |
| `seed` | `circuit_output` | `seed` | 0 | 256 |

The export mapping contains no `tau`, scalar, or SigningWorker field.

## 6. Five-case closed certificate

`cases` is an ordered array of exactly five objects. Every object has exactly:

```text
request_kind
vector
```

`request_kind` order is:

```text
registration
activation
recovery
refresh
export
```

`vector` is a closed tagged union selected by its first field `case_kind`.
There is no generic case, optional component, optional output, runtime profile,
or caller-selected evaluation plan.

### 6.1 Producing activation-family case shape

Registration, recovery, and refresh use
`case_kind = activation_evaluation_reconciliation` and exactly this field order:

```text
case_kind
case_id
evaluation_input_party_view_case_id
output_party_view_case_id
semantic_frame_success_case_id
evaluator_admission_case_id
mapping_id
component_kind
canonical_input_digest_hex
ir_evaluated_output_digest_hex
schedule_evaluated_output_digest_hex
party_output_reconstruction_digest_hex
reconciliation_result
```

The fixed selector matrix is:

| Request | Case id | Evaluation-input case | Output-party case | Semantic-frame success case | Evaluator-admission case |
| --- | --- | --- | --- | --- | --- |
| registration | `registration_phase2b_core_reconciliation_v1` | `registration_evaluation_input_party_views_v1` | `registration_output_party_views_package_prepared_v1` | `registration_success_worker_activated_v1` | `registration_admitted_evaluation_output_committed_v1` |
| recovery | `recovery_phase2b_core_reconciliation_v1` | `recovery_evaluation_input_party_views_v1` | `recovery_output_party_views_package_prepared_v1` | `recovery_success_worker_activated_v1` | `recovery_admitted_evaluation_output_committed_v1` |
| refresh | `refresh_phase2b_core_reconciliation_v1` | `refresh_evaluation_input_party_views_v1` | `refresh_output_party_views_package_prepared_v1` | `refresh_success_worker_activated_v1` | `refresh_admitted_evaluation_output_committed_v1` |

For all three rows:

```text
mapping_id = activation_family_inputs_outputs_v1
component_kind = activation
reconciliation_result = exact_input_ir_schedule_and_party_output_match
```

Each evaluator-admission selector MUST resolve exactly to the row above in its
owning one-case admission corpus. Alias, fallback, inferred, or nested-selector
resolution is prohibited.

### 6.2 Activation zero-evaluation case shape

Activation uses `case_kind = activation_continuation_reconciliation` and exactly:

```text
case_kind
case_id
evaluation_input_party_view_case_id
output_party_view_case_id
semantic_frame_success_case_id
activation_origin
mapping_id
evaluation_plan
reconciliation_result
```

Its fixed values are:

```text
case_id = activation_phase2b_zero_evaluation_reconciliation_v1
evaluation_input_party_view_case_id = activation_no_evaluation_input_party_views_v1
output_party_view_case_id = activation_output_party_views_metadata_consumed_v1
semantic_frame_success_case_id = registration_success_worker_activated_v1
activation_origin = registration
mapping_id = activation_continuation_zero_evaluation_v1
evaluation_plan = the exact all-zero plan in Section 5.2
reconciliation_result = exact_zero_evaluation_and_no_new_private_output
```

This branch MUST NOT contain any producing-case-only field, including
`evaluator_admission_case_id`, `component_kind`, an artifact or schedule digest,
a schema, an input/output digest, or an output-reconstruction digest. Its source
input and output corpora MUST show empty Deriver input extensions and no new
private output for all seven roles. The semantic success trace MUST show that
activation control emits no evaluator frame.

Registration origin is the canonical compact certificate representative.
Recovery- and refresh-origin zero-evaluation equivalence remains required by
the already committed output-party and semantic-frame corpora.

### 6.3 Export-family case shape

Export uses `case_kind = export_evaluation_reconciliation` and exactly:

```text
case_kind
case_id
evaluation_input_party_view_case_id
output_party_view_case_id
semantic_frame_success_case_id
evaluator_authorization_case_id
mapping_id
component_kind
canonical_input_digest_hex
ir_evaluated_output_digest_hex
schedule_evaluated_output_digest_hex
party_output_reconstruction_digest_hex
authorized_client_output_digest_hex
reconciliation_result
```

Its fixed selector values are:

```text
case_id = export_phase2b_core_reconciliation_v1
evaluation_input_party_view_case_id = export_evaluation_input_party_views_v1
output_party_view_case_id = export_output_party_views_released_v1
semantic_frame_success_case_id = export_release_exact_redelivery_v1
evaluator_authorization_case_id = export_authorized_evaluation_released_v1
mapping_id = export_family_inputs_outputs_v1
component_kind = export
reconciliation_result = exact_input_ir_schedule_party_output_and_authorized_client_match
```

The authorization selector MUST resolve exactly to the value above in the
one-case authorization corpus. Alias, fallback, inferred, or nested-selector
resolution is prohibited.

## 7. Canonical case digest fields

Every `*_digest_hex` case field is a 64-character lowercase SHA-256 value. The
digest operation is:

```text
Digest(domain, payload) =
  SHA-256(LP32(ASCII(domain)) || LP32(payload))

LP32(value) = BE32(len(value)) || value
```

The domains are:

```text
canonical_input_digest_hex:
  seams/router-ab/ed25519-yao/phase2b-reconciliation/canonical-input/v1

ir_evaluated_output_digest_hex:
  seams/router-ab/ed25519-yao/phase2b-reconciliation/ir-output/v1

schedule_evaluated_output_digest_hex:
  seams/router-ab/ed25519-yao/phase2b-reconciliation/schedule-output/v1

party_output_reconstruction_digest_hex:
  seams/router-ab/ed25519-yao/phase2b-reconciliation/party-output/v1

authorized_client_output_digest_hex:
  seams/router-ab/ed25519-yao/phase2b-reconciliation/authorized-client-output/v1
```

The canonical input payload is the concatenation of the 32-byte source fields
in the mapping's exact order before LSB0 expansion. The clear evaluators expand
each byte into bits `0..7`, then concatenate fields without reordering.

The IR and schedule output payloads are the decoded output bytes in mapping
order. For activation this is:

```text
x_client_base[32] || x_server_base[32]
```

For export it is:

```text
seed[32]
```

The party-output reconstruction payload uses the same byte order after
reconstructing the exact typed A/B shares from the selected output-party-view
case. The export authorized-Client payload is the exact authorized seed in the
Client extension.

The IR and schedule outputs MUST be byte-identical before their separately
domain-separated digests are computed. The party-output payload MUST then equal
that common evaluated payload. For export, the authorized Client payload MUST
also equal it.

## 8. Required Rust construction and checks

The Rust implementation MUST:

1. build the certificate only from internal canonical builders;
2. reuse the fixed-reference corpus-commitment implementation for all twenty
   entries;
3. build the `EYAOBM01` candidate internally and require the complete canonical
   manifest identity;
4. compile all three fixed components internally;
5. obtain A/B evaluation inputs through narrow typed projections of the exact
   accepted-input fixtures, preserving role and source labels;
6. validate each activation-family `tau` at its boundary;
7. evaluate both the canonical IR and the derived liveness schedule;
8. require byte-identical IR and schedule outputs;
9. obtain A/B output shares through narrow typed projections of the exact
   output-party fixtures;
10. reconstruct Client and SigningWorker scalars modulo `l`, or the export seed
    modulo `2^256`, and compare the exact bytes with the evaluated outputs;
11. require the export Client output to equal the evaluated/reconstructed seed;
12. validate every case selector against its exact owning corpus;
13. prove structurally that the activation continuation contains no component,
    input, evaluation, artifact, schedule, output, or ideal coin; and
14. emit only the strict evidence DTO after all relations succeed.

The reconciliation builder may use variable-time operations because all values
are public synthetic fixture evidence. Production crates MUST NOT depend on it.

The implementation MUST NOT parse its own canonical JSON to perform core
reconciliation. JSON is the evidence boundary after typed construction. Broad
`serde_json::Value`, generic property bags, raw optional branch fields, and
caller-supplied circuit inputs are prohibited in the Rust core.

## 9. Independent stdlib-Python verification

The independent verifier MUST accept these explicit inputs:

```text
reconciliation_certificate_path
phase1_vector_directory
generated_artifact_directory
canonical_benchmark_manifest_bytes
```

It MUST independently:

1. strict-load the certificate while rejecting duplicate JSON keys, invalid
   UTF-8, BOMs, CRLF, whitespace drift, field reordering, trailing values, and
   missing or extra final newlines;
2. check the exact envelope, five-case order, closed branch shapes, mapping
   tables, and explicit nonclaims;
3. load and run the owning verifier for every one of the twenty Phase 1 corpora;
4. recompute each corpus path, schema, case count, canonical byte length, and
   SHA-256 commitment;
5. require every referenced case selector to exist in the correct corpus and
   match the certificate request kind;
6. independently decode `EYAOBM01`, recompute its digest, verify its complete
   compiler/order/schema/component/metric surface, and bind its wrapped index;
7. independently decode `EYAOIR01` and `EYAOSC01` for every component, rederive
   the canonical liveness schedule, and compare the records byte for byte;
8. extract the exact A/B input fields from each selected accepted-input case,
   validate scalar domains, apply the frozen field/LSB0 mapping, and recompute
   the canonical input digest;
9. evaluate IR and schedule independently and require their decoded outputs and
   certificate digests to match;
10. reconstruct the exact A/B output-party shares and require the party-output
    digest to match the evaluated bytes;
11. require export's authorized Client seed to match the evaluated and
    reconstructed seed;
12. require activation's all-zero plan, empty Deriver input extensions, empty
    new output extensions, and absent producing-only fields; and
13. reject any mutation, cross-family field, reordered role, component splice,
    corpus splice, case-selector splice, output splice, stale digest, or
    production/profile field.

The Python verifier MUST derive expected relations itself. It cannot accept a
Rust success result, reuse Rust parsing code, invoke the Rust evaluator, or
treat the certificate's `reconciliation_result` label as proof.

## 10. Exact explicit nonclaims

`explicit_nonclaims` is this exact ordered array:

```text
production_artifact_authority_absent
selected_security_profile_absent
garbling_and_ot_unimplemented
randomized_output_protection_unimplemented
simulator_and_security_experiment_unimplemented
runtime_frame_and_transport_encoding_absent
durable_lifecycle_and_replay_semantics_absent
production_constant_time_and_erasure_unclaimed
independent_operator_reproducibility_unclaimed
reviewer_approval_absent
```

The certificate and its passing verifiers do not establish:

- a production compiler, circuit, manifest, digest, schedule, or artifact;
- P0, P1, P2, or P3 satisfaction;
- garbling, oblivious transfer, streaming, private output translation,
  recipient encryption, or output authentication;
- fresh/uniform/unbiased output-share sampling;
- a simulator, real/ideal equivalence, privacy, active security, passive
  security, correctness with abort, noninterference, or composition theorem;
- runtime frames, endpoints, service bindings, transcript authentication,
  replay protection, delivery acknowledgement, durable state, or crash safety;
- production constant-time execution, erasure, entropy, forward security, or
  healing;
- reproducibility by an independent operator or host; or
- human reviewer approval of circuit semantics, schemas, bit order, wire order,
  or the candidate manifest.

The fixed `reconciliation_result` strings are successful deterministic relation
labels. They are not security claims or reviewer signatures.

## 11. Required negative evidence

Focused mutation or static tests MUST reject:

- fewer or more than twenty Phase 1 commitments;
- a changed commitment path, schema, case count, byte length, digest, or order;
- a certificate self-commitment inserted into the Phase 1 list;
- another manifest magic, digest, compiler contract, bit order, wire order,
  component order, schema, IR digest, or schedule digest;
- another case count, request-kind order, case kind, or source selector;
- swapping Deriver A and B or client/server input fields;
- MSB0 expansion, byte reversal, field reordering, overlapping wire ranges, or
  a gap in the exact input/output range;
- a noncanonical `tau` in any activation-family input position;
- an IR/schedule output mismatch;
- an activation Client/SigningWorker share swap or wrong modular domain;
- an export seed-share splice, scalar field, `tau` field, or SigningWorker
  output;
- a component, input, output, digest, schema, artifact, or coin on activation;
- any nonzero activation evaluator-window counter;
- a missing, additional, optional, `null`, unknown, duplicate, or reordered JSON
  field;
- a caller-controlled artifact or general certificate parser; and
- any production, selected-profile, negotiation, simulator-output, advantage,
  reviewer-signature, or promotion field.

## 12. CLI and verification gate

The generator CLI exposes exact canonical emission and checking commands:

```text
ed25519-yao-vectors emit-phase2b-core-reconciliation --output <file>
ed25519-yao-vectors check-phase2b-core-reconciliation --input <file>
```

Emission uses safe atomic publication under the existing artifact-filesystem
policy. Checking regenerates the exact certificate internally and compares bytes.
Neither command accepts a manifest, artifact directory, source vector directory,
mapping, profile, or component argument.

The counted formal task is:

```text
cargo yao-fv phase2b-reconciliation-check
```

It MUST run:

1. the strict committed-certificate check;
2. the focused Rust reconciliation suite;
3. the independent Python cross-corpus and artifact verifier against a fresh
   process-owned generated bundle;
4. the complete candidate-manifest decoder; and
5. exact evidence-count checks.

The task is included in `cargo yao-fv all`. A passing named task closes only the
mechanical cross-corpus reconciliation deliverable. It cannot set a reviewer-
approval field or close the Phase 2 exit by itself.

## 13. Expected executable evidence

Initial attachment requires exactly:

- one strict five-case reconciliation corpus;
- six focused Rust reconciliation tests covering canonical construction and
  case order, all-twenty commitment equality, typed input/wire mapping,
  activation output reconstruction, export output/Client reconstruction, and
  activation-zero plus mutation/nonproduction rejection;
- four focused independent Python tests covering the valid cross-reconciliation,
  Phase 1 commitment/source mutation, field/order/component splicing, and
  output/zero-evaluation mutation;
- the existing complete `EYAOBM01`, `EYAOBA01`, `EYAOIR01`, and `EYAOSC01`
  decoders and evaluators; and
- one named counted `phase2b-reconciliation-check` gate.

With no other evidence changes, attachment raises the pinned aggregate to:

```text
26 normative reference documents
21 committed corpora
407 generator Rust tests
185 independent Python tests
```

The fixed-reference generated commitments, formal toolchain baseline, formal
spec corpus, proof-obligation inventory, compliance baseline, and living plan
must all change in the same implementation tranche. Count drift or a missing
attachment fails the gate.

## 14. Closure boundary

Passing every requirement in this document establishes the following narrow
claim:

> The exact provisional compiler-generated activation and export Boolean cores,
> their clear IR and liveness-schedule evaluators, their benchmark-only schemas
> and ordering, and the current `EYAOBM01` candidate reproduce the exact accepted
> inputs and party-output reconstruction relations selected from the complete
> twenty-corpus Phase 1 contract for all five request kinds, with activation
> performing zero evaluation.

This is the evidence required to mark the first Phase 2B reconciliation TODO
complete. The candidate remains provisional until a human reviewer separately
approves circuit semantics and bit ordering and the plan records that approval.
The Phase 2 exit, Phase 3, Phase 6A selection, Phase 6B production artifacts, and
all runtime integration remain open.
