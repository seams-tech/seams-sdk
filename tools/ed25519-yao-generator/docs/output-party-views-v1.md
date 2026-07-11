# Ed25519 Yao Output Party Views V1

Status: **Phase 1 profile-neutral host-only output-custody specification; no
production protocol authority**

This document freezes the construction-independent output views for the
host-reference Ed25519 Router A/B lifecycle. Each view contains one common
public-leakage value plus one closed, role-specific extension. The model covers
registration, recovery, and refresh after package preparation; activation after
metadata/control consumption; and export after host-reference release.

The core model uses synthetic inputs and nonserializable Rust values. A separate
strict DTO projects selected synthetic values into the evidence corpus defined
in Section 9. It defines no production transport, ciphertext, storage, receipt-
signature, or security-profile format. The keywords **MUST**, **MUST NOT**, and
**REQUIRED** are normative.

## 1. Authority and scope

The existing companion specifications retain authority over their own values:

- `fixed-reference-v1.md` owns the Ed25519 arithmetic, registered public key,
  and identity relations;
- `ceremony-context-v1.md` owns canonical public request, authorization, and
  transcript values;
- `input-provenance-v1.md` owns the role-input provenance outer contract and
  public epoch relations;
- `output-sharing-v1.md` owns activation scalar shares, export seed shares, and
  their reconstruction equations;
- `semantic-artifact-lifecycle-v1.md` owns public package descriptors, package
  sets, receipt bodies, output-committed identities, and metadata-consumed
  projections;
- `ideal-functionalities-v1.md` Sections 5, 6, and 11.5 own the wider leakage,
  custody, and eventual complete-party-view requirements.

This document owns their composition into stage- and role-discriminated host
output views and the exact synthetic evidence attachment for those views. It
does not model a party's private inputs, protocol randomness, sent or received
frames, abort timing, or corruption-game state. Those values belong to the
eventual complete party-view and selected-profile specifications.

No value defined here may enter a production Worker, Router, SigningWorker,
SDK, persistence record, or network message. Production crates MUST NOT depend
on the host generator or these view types.

## 2. Closed stage family

Exactly five output-view stages exist in version one:

| Stage | Request kind | Circuit family | Public terminal state |
| --- | --- | --- | --- |
| `registration_package_prepared` | registration | activation | `output_committed` |
| `recovery_package_prepared` | recovery | activation | `output_committed` |
| `refresh_package_prepared` | refresh | activation | `output_committed` |
| `activation_metadata_consumed` | activation | activation | `metadata_consumed` |
| `export_released` | export | export | `export_released` |

`package_prepared` means that host-reference output sharing, semantic package
construction, receipt construction, and the output-committed projection have
all succeeded. It does not mean that a production ciphertext exists or that a
recipient has decrypted a package.

`activation_metadata_consumed` means that a fresh activation-control DAG has
consumed metadata/control authority for an output-committed registration,
recovery, or refresh origin. The origin kind is required and is exactly one of
those three branches. This stage performs no new private-output computation.

`export_released` means that the host reference has checked registered-key
equality, produced typed A/B seed shares, formed the public export receipt, and
retained the registered host state. It does not establish production
authorization finality.

There is no generic lifecycle stage, optional stage tag, runtime profile field,
or caller-selected circuit. There is also no SigningWorker-activated stage in
this companion. Actual package opening and activated signing state remain
separate blockers.

## 3. Common public leakage

Every role view for one validated stage MUST carry the same
`CommonOutputPublicLeakageV1` value. The value is a closed union over the five
stages above. It contains only public host-reference data already authorized by
the owning companion specifications.

### 3.1 Package-prepared leakage

The registration, recovery, and refresh variants contain exactly:

- the stage, request kind, and derived activation circuit family;
- the canonical public request-context, authorization, and transcript digests;
- the transcript's transport-binding and artifact-suite digests;
- the one-use execution id;
- the branch-matched input-provenance pair digest;
- the opaque host-reference evaluation-evidence digest;
- the activation epoch;
- the ordered four-member public activation package projection defined by
  `semantic-artifact-lifecycle-v1.md`, including role, recipient, output-family,
  recipient-binding, share-point, opaque digest, and declared-length fields;
- the activation package-set digest and receipt-body digest;
- `X_client`, `X_server`, and the registered `A_pub` from the public receipt;
- the exact output-committed persistence identity; and
- the public terminal label `output_committed`.

The package projection may carry the canonical host-reference descriptor and
receipt encodings already frozen by `semantic-artifact-lifecycle-v1.md`. Their
presence adds no production wire authority.

Registration establishes the registered `A_pub`. Recovery and refresh MUST
carry the already registered `A_pub`; their public value cannot fork from
registration or export.

### 3.2 Activation metadata-consumed leakage

The activation variant contains exactly:

- the stage, activation request kind, and activation circuit family;
- the origin kind;
- the unchanged output-committed origin identity, including the origin request,
  authorization, and transcript digests, one-use execution id, package-set
  digest, receipt-body digest, activation epoch, and registered `A_pub`;
- the fresh activation-control request-context, authorization, and transcript
  digests;
- the public terminal label `metadata_consumed`; and
- the five zero-valued host-reference counters:
  `yao_evaluations`, `deriver_a_invocations`, `deriver_b_invocations`,
  `contribution_derivations`, and `output_share_samples`.

This leakage carries no newly sampled share point, package descriptor, package
set, receipt, ciphertext digest, or recipient output. Origin package and receipt
identities remain available only through the unchanged committed identity.

### 3.3 Export-released leakage

The export variant contains exactly:

- the stage, export request kind, and export circuit family;
- the canonical public request-context, authorization, and transcript digests;
- the transcript's transport-binding and artifact-suite digests;
- the one-use execution id;
- the branch-matched input-provenance pair digest;
- the opaque host-reference evaluation-evidence digest;
- the ordered two-member public export package projection defined by
  `semantic-artifact-lifecycle-v1.md`, addressed only to the Client;
- the export package-set digest and released receipt-body digest;
- the already registered `A_pub`;
- the exact output-committed receipt digest, opaque Client-delivery evidence
  digest, and host-reference authorization-consumption evidence digest;
- the public terminal label `export_released`; and
- the closed state effect `registered_state_retained`.

Export public leakage contains no seed, seed share, seed-share point,
SigningWorker package, `X_client`, or `X_server`.

### 3.4 Public-leakage equality

All seven role views derived from one validated stage MUST compare equal in
their common public-leakage field. A role-specific extension cannot change,
shadow, or duplicate any common field. A diagnostics adapter may retain a
strict subset of this public value. It cannot add protocol payloads, opaque
handles, or private outputs.

Runtime ticket ids, response timings, allocator measurements, retry metadata,
and network sizes are absent from this host model. Their possible classification
as public leakage in `ideal-functionalities-v1.md` does not authorize synthetic
fixture values or production logging here.

## 4. Closed role-local extensions

Each role has one stage-indexed extension family. An empty extension is a sealed
zero-field variant, never `None`, an optional property bag, or a generic byte
buffer.

| Role | Registration/recovery/refresh package prepared | Activation metadata consumed | Export released |
| --- | --- | --- | --- |
| Deriver A | `client_scalar_share_A`, `signing_worker_scalar_share_A` | empty; no new private output | `seed_share_A` |
| Deriver B | `client_scalar_share_B`, `signing_worker_scalar_share_B` | empty; no new private output | `seed_share_B` |
| Client | empty pending-output extension | empty; no new private output | authorized RFC 8032 seed `d` |
| SigningWorker | empty pending-output extension; no scalar opens | empty; no new private output | empty; export is ineligible |
| Router | empty private extension; public opaque package metadata is common leakage | empty; no new private output | empty private extension; public opaque package metadata is common leakage |
| Observer | empty | empty | empty |
| Diagnostics/logs | empty | empty | empty |

The package-prepared Client view contains no scalar. The separate activation
recipient-release transition reconstructs `x_client_base` from the exact
retained A/B shares and yields it only through a move-only Client release
capability.

The SigningWorker receives no clear scalar in the modeled package-prepared or
metadata-consumed stages. The host relation checker may hold
`x_server_base` transiently while validating output sharing. That value remains
outside every party view in this companion. A future activated-stage
specification owns the conditions under which SigningWorker may receive it.

Router, Observer, and Diagnostics/logs have no private output extension in this
host model. Public package descriptors, digests, points, declared lengths,
receipts, and persistence identities belong to the common field. Ciphertext
bytes and opaque runtime handles are absent.

## 5. Structural output-family separation

The following role-local types are disjoint:

- Deriver A activation scalar shares;
- Deriver B activation scalar shares;
- Client activation scalar deliverable;
- Deriver A export seed share;
- Deriver B export seed share;
- authorized Client export seed;
- the sealed empty extensions for SigningWorker, Router, Observer, and
  Diagnostics/logs.

A seed-bearing type is constructible only in `export_released`. Registration,
recovery, refresh, and activation types MUST NOT contain a seed field, seed-share
field, seed accessor, optional seed, or generic payload capable of carrying one.
Export types MUST NOT contain a client scalar share, SigningWorker scalar share,
`x_client_base`, `x_server_base`, or SigningWorker recipient extension.

The authorized Client export seed and each Deriver export seed share are
different types. The Client activation scalar deliverable is unrelated to all
three seed types even though every value has a 32-byte host representation.

Host-only clear traces, output-sharing coins, joined `a`, joined `tau`, role
inputs, roots, refresh deltas, and recovery credentials cannot appear in any
extension. These values remain private builder inputs or test-oracle material
outside all party views.

## 6. Consuming static observation

Relation validation may require a private host aggregate containing all
synthetic role outputs. That aggregate is `ValidatedOutputPartyViewSetV1<S>` in
the model. It has private constructors and fields, implements neither `Clone`,
`Copy`, nor Serde, and exposes no aggregate accessor.

Deriver observation is static and consuming. Its required shape is:

```rust
pub fn observe_deriver_a_v1<S: OutputPartyViewStageV1>(
    views: ValidatedOutputPartyViewSetV1<S>,
) -> DeriverAOutputPartyViewV1<S>;

pub fn observe_deriver_b_v1<S: OutputPartyViewStageV1>(
    views: ValidatedOutputPartyViewSetV1<S>,
) -> DeriverBOutputPartyViewV1<S>;
```

Each function consumes the complete validated set and returns the common public
leakage plus exactly one Deriver's extension. The unselected extensions are
dropped. A test that observes another role rebuilds a fresh deterministic host
fixture.

The API MUST NOT provide:

- a runtime `observe_deriver(role)` selector;
- a tagged return union containing either role's private extension;
- a method that returns both Deriver views or both private extensions;
- a peer-extension accessor, iterator, broad object spread, or generic map;
- a conversion between Deriver A and Deriver B views; or
- a reusable observation token.

Equivalent static consuming functions may project the Client, SigningWorker,
Router, Observer, and Diagnostics/log views. No public API exposes the private
validated set itself.

This construction is structural host evidence. The trusted fixture builder can
hold all synthetic outputs while checking relations. Consuming projection does
not prove computational privacy, memory erasure, or security against a runtime
adversary.

## 7. Required relation checks

The private builder MUST validate every relation before constructing
`ValidatedOutputPartyViewSetV1<S>`.

### 7.1 Package-prepared relations

For registration, recovery, and refresh:

```text
client_scalar_share_A + client_scalar_share_B mod l = x_client_base

signing_worker_scalar_share_A
  + signing_worker_scalar_share_B mod l
  = x_server_base

X_client = [x_client_base]B
X_server = [x_server_base]B
2 * X_client - X_server = A_pub
```

The builder MUST additionally require:

- one move-owned output commitment carries the package set and exact typed A/B
  shares produced by the same evaluation;
- the party-view builder consumes the typed pending lifecycle state and accepts
  no independently supplied package set, artifacts, or shares;
- each private scalar share is canonical modulo `l`;
- each descriptor share point equals the base-point multiplication of the exact
  matching role/recipient scalar share;
- the fixed A-Client, B-Client, A-SigningWorker, B-SigningWorker descriptor
  order and tags match the role extensions;
- all four descriptors, the package set, the receipt, and the output-committed
  identity share one ceremony/provenance identity, one-use execution id, and
  activation epoch;
- the Client extension is empty while the builder internally verifies that the
  exact A/B Client shares reconstruct the committed `X_client`;
- registration establishes the receipt's `A_pub`; and
- recovery and refresh preserve the registered `A_pub`, `X_client`, and
  `X_server` required by their frozen host-reference continuity relations.

Zero individual additive scalar shares and identity share-point commitments are
valid. The joined Client and SigningWorker points MUST be nonidentity canonical
prime-subgroup points.

### 7.2 Activation metadata-consumed relations

For each registration, recovery, or refresh origin:

- the origin identity equals the exact output-committed identity selected for
  activation;
- the activation-control request id, replay nonce, request-context digest,
  transcript nonce, and transcript digest are origin-distinct as required by
  `semantic-artifact-lifecycle-v1.md`;
- the metadata-consumed projection retains the origin identity unchanged and
  binds the fresh activation-control digest triple;
- all five reference counters equal zero; and
- every role-local extension is the sealed empty activation variant.

The builder MUST reject a new scalar share, seed share, output-sharing coin,
Deriver invocation result, package set, receipt, or recipient deliverable in
this stage.

Metadata consumption retains the same move-owned activation output commitment,
including its exact A/B shares. The selected-profile worker-opening transition
is the next reviewed point allowed to consume that retained value.

### 7.3 Export-released relations

For export:

```text
seed_share_A + seed_share_B mod 2^256 = d
Ed25519PublicKey(d) = registered_A_pub
```

The builder MUST additionally require:

- both export descriptors are Client seed descriptors in fixed A-then-B order;
- each Deriver extension matches its corresponding typed seed share;
- the authorized Client extension equals the reconstructed `d`;
- the package-set and receipt digests match the common export leakage;
- the receipt's registered public key equals the authorization- and provenance-
  bound registered key; and
- the state effect is exactly `registered_state_retained`.

The builder is crate-private and consumes the released export transition. That
transition retains the exact package set and exact typed A/B seed shares from
one evaluation. Callers cannot substitute another receipt, package set, share
pair, or seed. Export descriptors contain no seed-share point or public
commitment to an individual split; selected-profile output protection owns the
ciphertext and opening binding.

No export relation constructs or observes a SigningWorker output.

### 7.4 Cross-view relations

For every stage:

- independent static projections rebuilt from the same deterministic synthetic
  fixture have equal common public leakage;
- each projection contains only the extension named by the role/stage matrix;
- Router and Observer private extensions are empty;
- Diagnostics/logs contain no value absent from the common leakage;
- each Deriver observation omits the peer share, joined Client scalar, joined
  SigningWorker scalar, and joined export seed; and
- no host-only clear-trace value appears through a public or role-local accessor
  unless that exact value is the role's authorized output.

This field-absence and type-separation check makes no computational
non-reconstruction statement. Simulation, indistinguishability, and discrete-
log assumptions belong to the later selected-profile corruption games.

## 8. Required negative evidence

Implementations of this companion MUST include compile-time or focused runtime
rejections for:

- construction of any view or validated set through a public field literal;
- cloning or directly serializing the validated set or a core private role
  extension; only the explicit synthetic corpus projection in Section 9 may
  serialize copied fixture bytes;
- observing A and B from the same consumed set;
- returning a runtime-selected Deriver extension;
- inserting a B share into an A view or an A share into a B view;
- swapping Client and SigningWorker scalar shares or public descriptor points;
- adding a seed or seed share to a non-export stage;
- adding a scalar share or SigningWorker output to export;
- adding any private output to activation metadata consumption;
- exposing `x_server_base` in the package-prepared or metadata-consumed
  SigningWorker view;
- changing common leakage between role projections of one fixture;
- placing a host clear trace, output coin, contribution, root, credential,
  refresh delta, protocol label, mask, OT state, or decryption key in any view;
- using an untyped byte vector, raw JSON object, optional secret, or generic
  role/output property bag at the core boundary; and
- treating the common public projection as a production log schema.

## 9. Strict portable corpus

The version-one attachment is:

`vectors/ed25519-yao-output-party-views-v1.json`

Its exact envelope values are:

```text
schema         = seams:router-ab:ed25519-yao:output-party-views-vectors:v1
protocol_id    = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_output_party_views_v1
```

The corpus contains synthetic role-private scalar and seed values so that an
independent verifier can check custody and reconstruction. Those values are
published test evidence. Public availability of the fixture file does not
change their role-private classification in the modeled execution. They are not
public runtime leakage and MUST NOT be served, logged, persisted, copied into a
production artifact, or interpreted as a deployable party-view format.

### 9.1 Canonical JSON boundary

Top-level field order is exact:

```text
schema
protocol_id
evidence_scope
cases
```

The `cases` array contains exactly five cases in this order:

| # | Request kind | Stage | Case id | Required semantic-lifecycle case id |
| ---: | --- | --- | --- | --- |
| 1 | registration | `registration_package_prepared` | `registration_output_party_views_package_prepared_v1` | `registration_semantic_artifacts_output_committed_v1` |
| 2 | activation | `activation_metadata_consumed` | `activation_output_party_views_metadata_consumed_v1` | `activation_metadata_control_v1` |
| 3 | recovery | `recovery_package_prepared` | `recovery_output_party_views_package_prepared_v1` | `recovery_semantic_artifacts_output_committed_v1` |
| 4 | refresh | `refresh_package_prepared` | `refresh_output_party_views_package_prepared_v1` | `refresh_semantic_artifacts_output_committed_v1` |
| 5 | export | `export_released` | `export_output_party_views_released_v1` | `export_semantic_artifacts_host_reference_receipt_v1` |

Each case is a closed tagged object with this exact field order:

```text
request_kind
vector
```

Every `vector` has this exact field order:

```text
case_id
stage
common_public
role_extensions
static_deriver_observations
```

The JSON bytes are the UTF-8 result of the canonical Rust builder serialized
with `serde_json::to_vec_pretty`, followed by exactly one LF. The corpus domain
type is opaque and `Serialize`-only. Its parser accepts only the exact canonical
bytes. Unknown, missing, null, duplicated, or reordered fields; alternate union
shapes; BOMs; CRLF; whitespace drift; malformed or uppercase hex; and missing
or extra terminal newlines are invalid.

The normalized corpus representation defines one role-view evidence projection
as:

```text
corpus_view_evidence(role)
  = (vector.common_public, vector.role_extensions[role])
```

`common_public` occurs once per case to avoid duplicating the same public value
seven times. The corpus projection records the closed fields below and
cross-links the fuller host-only descriptor/receipt values to the semantic
attachment. This normalization does not change the host type requirement that
every observed role view owns its common value.

### 9.2 Role-extension container

Every `role_extensions` object has exactly these keys in this order:

```text
deriver_a
deriver_b
client
signing_worker
router
observer
diagnostics_logs
```

Each value is a closed object beginning with `kind`. No extension accepts an
unknown field or an untagged byte bag.

For registration, recovery, and refresh, the exact extension shapes are:

```text
deriver_a:
  kind = deriver_a_activation_scalar_shares
  client_scalar_share_hex
  signing_worker_scalar_share_hex

deriver_b:
  kind = deriver_b_activation_scalar_shares
  client_scalar_share_hex
  signing_worker_scalar_share_hex

client:
  kind = client_no_private_output

signing_worker:
  kind = signing_worker_no_private_output

router:
  kind = router_no_private_output

observer:
  kind = observer_no_private_output

diagnostics_logs:
  kind = diagnostics_logs_no_private_output
```

The field order within each nonempty object is `kind` followed by the fields
shown. Every scalar is exactly 32 lowercase-hex bytes and canonical modulo `l`.
The A/B scalar shares are the exact role-local Client and SigningWorker shares
whose public points appear in the corresponding semantic descriptors. The
Client value is the reconstructed sum of the two Client shares,
`x_client_base`.

For activation, all seven extensions contain exactly one `kind` field:

```text
deriver_a.kind       = deriver_a_no_new_private_output
deriver_b.kind       = deriver_b_no_new_private_output
client.kind          = client_no_new_private_output
signing_worker.kind  = signing_worker_no_new_private_output
router.kind          = router_no_new_private_output
observer.kind        = observer_no_new_private_output
diagnostics_logs.kind = diagnostics_logs_no_new_private_output
```

No activation extension contains a scalar, seed, share, point, package,
receipt, coin, or opaque payload.

For export, the exact extension shapes are:

```text
deriver_a:
  kind = deriver_a_seed_share
  seed_share_hex

deriver_b:
  kind = deriver_b_seed_share
  seed_share_hex

client:
  kind = client_authorized_seed
  seed_hex

signing_worker:
  kind = signing_worker_no_export_output

router:
  kind = router_no_private_output

observer:
  kind = observer_no_private_output

diagnostics_logs:
  kind = diagnostics_logs_no_private_output
```

Every seed or seed share is exactly 32 lowercase-hex bytes in
`Z_(2^256)`. `seed_hex` is representable only in the Client extension of the
export case. `seed_share_hex` is representable only in the matching Deriver
extension of that case.

### 9.3 Package-prepared common-public shape

Registration, recovery, and refresh use this exact `common_public` field order:

```text
semantic_lifecycle_case_id
stage
request_kind
circuit_id
public_request_context_digest_hex
authorization_digest_hex
transcript_digest_hex
transport_binding_digest_hex
artifact_suite_digest_hex
one_use_execution_id_hex
input_provenance_pair_digest_hex
host_reference_evaluation_evidence_digest_hex
package_projection
package_set_digest_hex
receipt_body_digest_hex
activation_epoch
registered_public_key_hex
x_client_hex
x_server_hex
deriver_a_receipt_evidence_digest_hex
deriver_b_receipt_evidence_digest_hex
terminal_state
```

`circuit_id` is exactly `ed25519_yao_activation_v1`, and `terminal_state` is
exactly `output_committed`. All hex fields are exactly 32 lowercase-hex bytes.
`activation_epoch` is a positive JSON integer exactly representable as a `u64`.
Every digest and one-use id is nonzero. `registered_public_key_hex`,
`x_client_hex`, and `x_server_hex` encode canonical nonidentity prime-subgroup
Edwards points.

`package_projection` has exactly these keys in this order:

```text
deriver_a_client
deriver_b_client
deriver_a_signing_worker
deriver_b_signing_worker
```

Each member has this exact field order:

```text
role
recipient
output_family
recipient_key_binding_hex
share_point_hex
recipient_protection_digest_hex
recipient_ciphertext_digest_hex
ciphertext_length
output_binding_digest_hex
package_authentication_digest_hex
```

The exact `(role, recipient, output_family)` string tuples are
`(deriver_a, client, client_scalar)`,
`(deriver_b, client, client_scalar)`,
`(deriver_a, signing_worker, signing_worker_scalar)`, and
`(deriver_b, signing_worker, signing_worker_scalar)` in package order. Every hex
field is exactly 32 lowercase-hex bytes. `ciphertext_length` is a positive JSON
integer exactly representable as a `u64`.

The independent verifier MUST load
`vectors/ed25519-yao-semantic-lifecycle-v1.json` as a required companion and
derive every common value from the mapped semantic case. It MUST:

- rebuild the ceremony digest triple;
- parse the fixed four activation descriptors and receipt body;
- obtain transport, artifact-suite, one-use, provenance, and evaluation-
  evidence bindings from those encodings;
- reconstruct every package-projection member from its exact descriptor;
- require one package-set and receipt digest across the public artifacts and
  output-committed projection;
- parse the activation epoch, `X_client`, `X_server`, `A_pub`, and both receipt-
  evidence digests from the receipt and persistence identity; and
- reject any copied field that differs from the semantic attachment.

The role-private scalar values are absent from the semantic-lifecycle corpus.
The party-view builder obtains them only from the same consuming host-reference
evaluation that produced the descriptors. The verifier independently checks
their canonical encodings, descriptor point equality, A/B reconstruction, and
the registered public-key relation in Section 7.1.

### 9.4 Activation common-public shape

Activation uses this exact `common_public` field order:

```text
semantic_lifecycle_case_id
stage
request_kind
circuit_id
origin_metadata_projections
```

The first four values are exactly:

```text
semantic_lifecycle_case_id = activation_metadata_control_v1
stage                      = activation_metadata_consumed
request_kind               = activation
circuit_id                 = ed25519_yao_activation_v1
```

`origin_metadata_projections` contains exactly three objects in registration,
recovery, refresh order. Each object has this exact field order:

```text
origin_kind
origin_case_id
origin_request_context_digest_hex
origin_authorization_digest_hex
origin_transcript_digest_hex
one_use_execution_id_hex
package_set_digest_hex
receipt_body_digest_hex
activation_epoch
registered_public_key_hex
activation_request_context_digest_hex
activation_authorization_digest_hex
activation_transcript_digest_hex
terminal_state
zero_reevaluation
```

`terminal_state` is exactly `metadata_consumed`. The
`zero_reevaluation` object has this exact field order, and every value is the
JSON integer zero:

```text
yao_evaluations
deriver_a_invocations
deriver_b_invocations
contribution_derivations
output_share_samples
```

Every digest, one-use id, and registered public key is exactly 32 lowercase-hex
bytes. Digests and one-use ids are nonzero; the public key is a canonical
nonidentity prime-subgroup Edwards point. Every activation epoch is a positive
JSON integer exactly representable as a `u64`.

Every projection MUST equal the matching entry in the semantic-lifecycle
activation case, including its origin case id, unchanged committed identity,
fresh activation digest triple, terminal state, and counters. The three
registered public keys MUST equal the package-prepared and export registered
key. No activation role extension may differ from its exact empty shape.

The three entries are three independent canonical activation observations
grouped into one compact corpus case. A runtime activation selects exactly one
origin and never exposes a three-origin aggregate.

### 9.5 Export-released common-public shape

Export uses this exact `common_public` field order:

```text
semantic_lifecycle_case_id
stage
request_kind
circuit_id
public_request_context_digest_hex
authorization_digest_hex
transcript_digest_hex
transport_binding_digest_hex
artifact_suite_digest_hex
one_use_execution_id_hex
input_provenance_pair_digest_hex
host_reference_evaluation_evidence_digest_hex
package_projection
package_set_digest_hex
receipt_body_digest_hex
registered_public_key_hex
output_committed_receipt_digest_hex
client_delivery_evidence_digest_hex
export_authorization_consumption_evidence_digest_hex
terminal_state
state_effect
```

The fixed values are:

```text
semantic_lifecycle_case_id = export_semantic_artifacts_host_reference_receipt_v1
stage                      = export_released
request_kind               = export
circuit_id                 = ed25519_yao_export_v1
terminal_state             = export_released
state_effect               = registered_state_retained
```

Every common-public hex field is exactly 32 lowercase-hex bytes. Digests and
one-use ids are nonzero; `registered_public_key_hex` is a canonical nonidentity
prime-subgroup Edwards point.

`package_projection` has exactly these keys in this order:

```text
deriver_a_client
deriver_b_client
```

Each member has this exact field order:

```text
role
recipient
output_family
recipient_key_binding_hex
recipient_protection_digest_hex
recipient_ciphertext_digest_hex
ciphertext_length
output_binding_digest_hex
package_authentication_digest_hex
```

The exact `(role, recipient, output_family)` string tuples are
`(deriver_a, client, client_seed)` followed by
`(deriver_b, client, client_seed)`. Every hex field is exactly 32 lowercase-hex
bytes, and `ciphertext_length` is a positive JSON integer exactly representable
as a `u64`. Export has no `share_point_hex` field.

The verifier MUST parse the exact two Client seed descriptors and export
receipt from the semantic-lifecycle companion. It derives the ceremony,
transport, artifact-suite, one-use, provenance, evaluation-evidence,
package-projection, package-set, released receipt, registered key, preceding
output-committed receipt, Client-delivery evidence, and authorization-
consumption fields from those bytes and rejects any copied mismatch. It then
checks the private export relation in Section 7.3.

The export common value contains no activation epoch, `X_client`, `X_server`,
share point, SigningWorker descriptor, seed, or seed share.

### 9.6 Static observation evidence

Every `static_deriver_observations` object has exactly these keys in this order:

```text
deriver_a
deriver_b
```

The Deriver A observation has this exact field order:

```text
observation_kind = static_consuming_deriver_a
source_case_id
source_stage
extension
```

The Deriver B observation has the same shape with
`observation_kind = static_consuming_deriver_b`.

`source_case_id` and `source_stage` MUST equal the enclosing vector. Each
`extension` MUST be byte-for-byte equal as a JSON value to the corresponding
entry in `role_extensions`; it contains no peer field or peer extension. The A
and B observations are constructed from separate deterministic rebuilds because
one Rust `ValidatedOutputPartyViewSetV1` is consumed by one static observation.

The JSON proves exact projected shapes and cross-links only. Rust compile-fail
and move-semantics tests prove that one set cannot produce both observations,
that a runtime role selector is absent, and that neither observed view exposes
the peer extension or private aggregate.

### 9.7 Forbidden keys and values

The corpus recursively rejects these exact keys wherever they occur:

```text
clear_reference_trace
host_only_source_reference
host_only_joined_output
host_only_joined_outputs
host_only_reference_randomness
client_root_hex
deriver_a_root_hex
deriver_b_root_hex
contributions
joined_seed_hex
sha512_digest_hex
clamped_scalar_bytes_hex
signing_scalar_hex
tau_a_hex
tau_b_hex
tau_hex
x_server_base_hex
y_a_hex
y_b_hex
joined_y_hex
refresh_delta_y_hex
refresh_delta_tau_hex
credential_hex
recovery_envelope_hex
ciphertext_bytes_hex
recipient_decryption_key_hex
garbling_seed_hex
label_hex
mask_hex
ot_state_hex
```

Keys ending in `_coin_hex`, `_root`, `_root_hex`, `_contribution`,
`_contribution_hex`, `_private_key_hex`, or `_decryption_key_hex` are also
forbidden. `signing_worker_scalar_share_hex` is an allowed role-local share;
the joined SigningWorker scalar remains forbidden as `x_server_base_hex`.

The only permitted synthetic role-private values and paths are:

- package-prepared A/B `client_scalar_share_hex` and
  `signing_worker_scalar_share_hex`;
- export A/B `seed_share_hex`; and
- export Client `seed_hex`.

Within each case, each A/B value may occur once more inside the matching
`static_deriver_observations.<role>.extension`, where the complete extension
must equal its `role_extensions.<role>` source. No other private-value path is
permitted within that case. Identical fixture bytes may recur across the named
registration, recovery, and refresh cases when their canonical host builders
intentionally reuse the same output shares or continuity output. Every such
recurrence remains confined to the permitted per-case paths above.

The verifier MUST derive the known synthetic roots, all eight KDF
contributions, output-sharing coins, refresh deltas, and private host clear-
trace values used by the canonical builders and reject those exact byte strings
anywhere in the corpus, except when the value is one of the permitted role
outputs at an exact path class above. Public points, public keys, and public
digests are not part of this forbidden-value scan. The authorized export
`seed_hex` is the sole permitted path class for joined `d`.
The package-prepared and metadata-consumed views have no permitted path for a
joined activation scalar. `HostOnlyActivationClientReleasedV1` owns that value
only after the separate two-recipient release transition. Joined `a`, `tau`,
`y`, and `x_server_base`; SHA-512
and clamped bytes; roots; contributions; coins; credentials; and refresh deltas
have no permitted path.

Every extension, static observation, and common-public object has an exact key
set and order. Recursive forbidden-name checks supplement those closed shapes;
they do not replace them.

### 9.8 Required corpus checks

Rust and an independent verifier MUST:

- require exact canonical bytes, headers, case ids, order, stage tags, and
  per-branch object shapes;
- cross-link all five cases to the required semantic-lifecycle attachment;
- require one registered `A_pub` across registration, recovery, refresh,
  activation origins, and export;
- validate every package-prepared scalar, share point, reconstruction equation,
  `X_client`, `X_server`, and public-key relation;
- require all seven closed role extensions for every case;
- require exactly three activation origin projections and seven empty activation
  extensions;
- validate export seed reconstruction and RFC 8032 public-key continuity;
- enforce structural export-only seed representation;
- reproduce both static Deriver observation shapes from separate consuming
  fixture rebuilds; and
- reject forbidden keys, known forbidden values, role swaps, recipient swaps,
  peer-extension injection, common-public drift, and stage/family splicing.

Passing these checks establishes deterministic host-reference custody and
cross-language shape evidence over synthetic test material. It does not
establish privacy for a deployed execution.

## 10. Explicit nonclaims and blockers

This companion supplies no evidence for:

- production entropy, unbiased distributed output sharing, or erasure;
- constant-time processing of production secrets;
- garbling, oblivious transfer, streaming, preprocessing, tickets, labels,
  masks, or protocol frames;
- recipient encryption, ciphertext bytes, package delivery, package opening, or
  scalar combination by a deployed Client or SigningWorker;
- output authentication, anti-equivocation, signatures, commitments, proofs, or
  verification of opaque evidence digests;
- globally unique issuance, replay admission, retry/redelivery storage, durable
  transactions, or authenticated state-version authority;
- actual SigningWorker activation, `x_server_base` delivery, activated signing
  state, or an idempotent signed activation receipt;
- production recovery custody, replacement-credential binding, or refresh
  promotion and cutover;
- complete party inputs, protocol randomness, frames, abort timing, adaptive
  behavior, or any real/ideal corruption game;
- passive, one-sided, malicious, or collusion security; or
- a P0, P1, P2, or P3 protocol-security claim.

The host aggregate, relation checker, and static observations operate on
synthetic host material and may use variable-time arithmetic. They cannot open
Phase 1, Phase 2B, profile selection, product integration, or release gates
without the remaining lifecycle, complete-party-view, selected-protocol, and
deployment evidence.
