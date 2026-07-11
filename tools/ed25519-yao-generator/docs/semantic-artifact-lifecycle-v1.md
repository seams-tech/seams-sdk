# Ed25519 Yao Semantic Artifact Lifecycle Evidence V1

Status: **Phase 1 host-only public evidence; no production protocol authority**

This document freezes the public semantic encodings and lifecycle projections in
`vectors/ed25519-yao-semantic-lifecycle-v1.json`. The corpus is deterministic
reference evidence for package descriptors, package sets, receipt bodies,
activation metadata/control, and digest-only persistence relations. It contains
no production cipher, signature, proof, durable record, or worker-activation
format.

## 1. Authority and scope

The arithmetic and stable-key rules remain owned by `fixed-reference-v1.md`.
Canonical request, authorization, and transcript bytes remain owned by
`ceremony-context-v1.md`. Role-input provenance remains owned by
`input-provenance-v1.md`. Output-share equations remain owned by
`output-sharing-v1.md`.

This document owns the composition of those public commitments into:

- four role/recipient-typed activation package descriptors;
- two role-typed client export package descriptors;
- fixed activation and export package sets;
- activation output-committed plus export output-committed and released receipt
  bodies;
- output-committed, rejected-attempt self-loop, and metadata-consumed
  persistence projections;
- three valid activation origins and four freshness-reuse rejection fixtures.

Every opaque host-reference digest is a nonzero semantic slot. Its presence does
not authenticate, encrypt, prove, sign, or consume the referenced artifact.

## 2. Canonical corpus envelope

The schema and evidence-scope strings are exact:

```text
schema         = seams:router-ab:ed25519-yao:semantic-artifact-lifecycle-vectors:v1
protocol_id    = router_ab_ed25519_yao_v1
evidence_scope = host_only_public_semantic_artifact_lifecycle_v1
```

The top-level case order is fixed:

1. `registration`
2. `activation`
3. `recovery`
4. `refresh`
5. `export`

The JSON bytes are the UTF-8 result of the canonical Rust builder followed by
exactly one LF. Object order, tagged-union shape, case order, and every value are
part of the version-one attachment. The strict parser accepts only those exact
bytes.

## 3. Public-data boundary

The corpus may contain:

- canonical public request, authorization, and transcript encodings and digests;
- role, recipient, output-family, request-kind, status, and lifecycle tags;
- one-use execution IDs and public epochs;
- public recipient-key bindings;
- scalar-share public points and the registered Ed25519 public key;
- opaque evidence, recipient-protection, ciphertext, output-binding,
  authentication, and receipt-evidence digests;
- ciphertext lengths;
- descriptor, package-set, and receipt-body encodings and digests;
- public activation abort metadata and digest-only persistence identities.

The corpus MUST NOT contain:

- client or Deriver roots;
- role-local `y` or `tau` contributions;
- joined `d`, `a`, `y`, `tau`, or signing scalars;
- scalar or seed share bytes;
- output-sharing coins;
- ciphertext bytes or recipient decryption keys;
- credential material or recovery envelopes;
- refresh deltas;
- OT, garbling, label, mask, or preprocessing material.

Encoded public points are commitments to host-reference scalar shares. The
scalar bytes remain outside the corpus.

## 4. LP32 rule and digest rule

`LP32(x)` is `BE32(len(x)) || x`. Every semantic encoding below is a sequence
of LP32 fields. Integer fields inside LP32 are fixed-width big-endian values.

Every semantic digest uses:

```text
SHA-256(LP32(digest_domain) || LP32(canonical_encoding))
```

Recipient-key bindings use the same two-field digest form over their typed
domain and the canonical public-request-context digest.

The exact V1 semantic domains are:

| Meaning | UTF-8 domain |
| --- | --- |
| Deriver A → Client scalar descriptor | `seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/client-scalar/v1` |
| Deriver B → Client scalar descriptor | `seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/client-scalar/v1` |
| Deriver A → SigningWorker scalar descriptor | `seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/signing-worker-scalar/v1` |
| Deriver B → SigningWorker scalar descriptor | `seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/signing-worker-scalar/v1` |
| Deriver A → Client seed descriptor | `seams/router-ab/ed25519-yao/semantic-package/export/deriver-a/client-seed/v1` |
| Deriver B → Client seed descriptor | `seams/router-ab/ed25519-yao/semantic-package/export/deriver-b/client-seed/v1` |
| Client recipient-key binding | `seams/router-ab/ed25519-yao/semantic-recipient-key-binding/client/v1` |
| SigningWorker recipient-key binding | `seams/router-ab/ed25519-yao/semantic-recipient-key-binding/signing-worker/v1` |
| Activation package set | `seams/router-ab/ed25519-yao/semantic-package-set/activation/v1` |
| Activation package-set digest | `seams/router-ab/ed25519-yao/semantic-package-set/activation-digest/v1` |
| Export package set | `seams/router-ab/ed25519-yao/semantic-package-set/export/v1` |
| Export package-set digest | `seams/router-ab/ed25519-yao/semantic-package-set/export-digest/v1` |
| Activation output-committed receipt | `seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed/v1` |
| Activation receipt digest | `seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed-digest/v1` |
| Export output-committed receipt | `seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed/v1` |
| Export output-committed receipt digest | `seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed-digest/v1` |
| Export released receipt | `seams/router-ab/ed25519-yao/semantic-receipt/export-released/v1` |
| Export released receipt digest | `seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1` |

Every tag is exactly one byte:

| Tag family | V1 values |
| --- | --- |
| Request kind | registration `0x01`; activation `0x02`; recovery `0x03`; refresh `0x04`; export `0x05` |
| Deriver role | A `0x01`; B `0x02` |
| Recipient | Client `0x01`; SigningWorker `0x02` |
| Output family | Client scalar `0x01`; SigningWorker scalar `0x02`; Client seed `0x03` |
| Receipt kind | output committed `0x01`; export released `0x02` |
| Terminal status | output committed `0x01`; export released `0x02` |

Every activation epoch and ciphertext length is an eight-byte big-endian
positive integer. Every typed digest, recipient binding, one-use execution ID,
and evidence slot in this specification is exactly 32 bytes and nonzero.

## 5. Shared semantic ceremony binding

Every descriptor and receipt carries this ordered public binding:

```text
LP32(public_request_context_digest[32])
LP32(authorization_digest[32])
LP32(transcript_digest[32])
LP32(transport_binding_digest[32])
LP32(artifact_suite_digest[32])
LP32(one_use_execution_id[32])
LP32(input_provenance_pair_digest[32])
LP32(host_reference_evaluation_evidence_digest[32])
```

The first three digests MUST match the exact canonical ceremony case. The
input-provenance digest MUST equal the SHA-256 digest of the exact fixed A/B
provenance-pair encoding for the same branch. Registration, recovery, refresh,
and export use distinct branch types. Activation has no role-input provenance
pair and consumes an already committed activation artifact identity.

## 6. Activation package descriptors

The fixed descriptor order is:

1. Deriver A → Client scalar package;
2. Deriver B → Client scalar package;
3. Deriver A → SigningWorker scalar package;
4. Deriver B → SigningWorker scalar package.

Each descriptor encodes:

```text
LP32(descriptor_domain)
LP32(request_kind_tag)
LP32(deriver_role_tag)
LP32(recipient_tag)
LP32(output_family_tag)
shared_semantic_ceremony_binding
LP32(activation_epoch_be64)
LP32(typed_recipient_key_binding[32])
LP32(role_share_public_point[32])
LP32(host_reference_recipient_protection_digest[32])
LP32(host_reference_recipient_ciphertext_digest[32])
LP32(ciphertext_length_be64)
LP32(host_reference_output_binding_digest[32])
LP32(host_reference_package_authentication_digest[32])
```

The request kind is registration, recovery, or refresh. Role, recipient, and
output-family tags MUST agree with the descriptor domain. The four package
descriptors share one ceremony binding, one activation epoch, and one one-use
execution ID.

The activation package-set encoding is:

```text
LP32(activation_package_set_domain)
LP32(deriver_a_client_descriptor)
LP32(deriver_b_client_descriptor)
LP32(deriver_a_signing_worker_descriptor)
LP32(deriver_b_signing_worker_descriptor)
```

The two Client points add to `X_client`. The two SigningWorker points add to
`X_server`. Every committed case MUST satisfy:

```text
2 * X_client - X_server = A_pub
```

All point operations use canonical compressed Edwards encodings and the
prime-order Ed25519 subgroup rules enforced by the host reference.

## 7. Export package descriptors

The fixed export order is Deriver A → Client followed by Deriver B → Client.
Each descriptor encodes:

```text
LP32(export_descriptor_domain)
LP32(export_request_kind_tag)
LP32(deriver_role_tag)
LP32(client_recipient_tag)
LP32(seed_output_family_tag)
shared_semantic_ceremony_binding
LP32(client_recipient_key_binding[32])
LP32(host_reference_recipient_protection_digest[32])
LP32(host_reference_recipient_ciphertext_digest[32])
LP32(ciphertext_length_be64)
LP32(host_reference_output_binding_digest[32])
LP32(host_reference_package_authentication_digest[32])
```

No seed, seed share, seed-share point, or SigningWorker recipient appears in an
export descriptor or package set.

The export package-set encoding is:

```text
LP32(export_package_set_domain)
LP32(deriver_a_client_descriptor)
LP32(deriver_b_client_descriptor)
```

## 8. Receipt bodies

The activation output-committed receipt body encodes:

```text
LP32(activation_output_committed_receipt_domain)
LP32(output_committed_receipt_tag)
LP32(output_committed_status_tag)
LP32(origin_request_kind_tag)
shared_semantic_ceremony_binding
LP32(activation_epoch_be64)
LP32(activation_package_set_digest[32])
LP32(X_client[32])
LP32(X_server[32])
LP32(A_pub[32])
LP32(host_reference_deriver_a_receipt_evidence_digest[32])
LP32(host_reference_deriver_b_receipt_evidence_digest[32])
```

The export output-committed receipt body encodes:

```text
LP32(export_output_committed_receipt_domain)
LP32(output_committed_receipt_tag)
LP32(output_committed_status_tag)
LP32(export_request_kind_tag)
shared_semantic_ceremony_binding
LP32(export_package_set_digest[32])
LP32(registered_A_pub[32])
LP32(host_reference_deriver_a_receipt_evidence_digest[32])
LP32(host_reference_deriver_b_receipt_evidence_digest[32])
```

Output commitment retains the exact A/B seed shares produced by the same
evaluation and leaves export authorization unconsumed.

The export released receipt body encodes:

```text
LP32(export_released_receipt_domain)
LP32(export_released_receipt_tag)
LP32(export_released_status_tag)
LP32(export_request_kind_tag)
shared_semantic_ceremony_binding
LP32(export_package_set_digest[32])
LP32(registered_A_pub[32])
LP32(export_output_committed_receipt_digest[32])
LP32(host_reference_client_delivery_evidence_digest[32])
LP32(host_reference_export_authorization_consumption_evidence_digest[32])
```

Release consumes the retained authorization and binds the exact preceding
output commitment. The Client-delivery and authorization-consumption digests
are opaque host-reference evidence slots. They do not prove production delivery,
replay consumption, or authorization finality. The export state effect is the
closed value `registered_state_retained`. The complete transition is owned by
`export-delivery-lifecycle-v1.md`.

## 9. Activation metadata/control

Activation accepts committed artifacts from exactly three origins:

- registration;
- recovery;
- refresh.

For each origin, the corpus includes a fresh canonical activation ceremony, the
exact committed artifact identity, and five zero-valued host-reference counters:

```text
yao_evaluations
deriver_a_invocations
deriver_b_invocations
contribution_derivations
output_share_samples
```

These counters witness the local metadata path. They do not instrument a
deployed Worker or prove a network-level zero-call property.

The activation-control request ID, replay nonce, request-context digest,
transcript nonce, and transcript digest MUST each differ from the selected
origin. Production global uniqueness and replay admission remain separate
requirements.

The four rejection fixtures reuse:

1. the origin request ID;
2. the origin replay nonce;
3. the origin transcript nonce;
4. the complete reusable freshness tuple: request ID, replay nonce, request
   expiry, and transcript nonce.

The synthetic authorization-record, transport-binding, and artifact-suite
digests remain the activation fixture values in every rejection case. They are
outside the origin freshness tuple exercised by this corpus.

Every rejected fixture carries the full public fresh-field proposal. The
independent verifier rebuilds its attempted activation request, authorization,
and transcript; the computed request and transcript digests MUST equal the
redacted abort envelope. Every rejection uses the single code `rejected`.

## 10. Persistence projections

`output_committed` stores only this public identity:

```text
origin kind and origin request kind
origin request-context, authorization, and transcript digests
one-use execution ID
package-set digest
receipt-body digest
activation epoch
registered public key
```

`attempt_rejected` contains `before`, `after`, and the public abort. `before`
and `after` MUST be byte-for-byte equal and MUST match the registration
output-committed identity. The four v1 rejection fixtures all exercise the
registration-origin activation path.

`metadata_consumed` contains the unchanged committed artifact identity plus the
fresh activation request-context, authorization, and transcript digests. This
state records consumption of metadata/control authority. It makes no
SigningWorker activation, credential promotion, refresh promotion, or durable
consumption claim.

The host lifecycle retains one move-owned activation output containing the
exact package set and exact A/B shares from the same evaluation through
`output_committed` and `metadata_consumed`. This private ownership relation is
absent from the public corpus and authorizes no runtime serialization.

These projections are nonserializable host model values rendered as JSON
evidence. They are not production storage schemas.

## 11. Required independent checks

An independent verifier MUST:

- reject noncanonical object shapes, order, tags, lengths, hex, and case order;
- parse every LP32 ceremony, descriptor, package-set, and receipt encoding;
- recompute every domain-separated SHA-256 digest;
- cross-link ceremony and provenance attachments by branch and digest;
- enforce descriptor role/recipient/output-family order;
- add public points and verify `2*X_client-X_server=A_pub`;
- require prime-subgroup membership for every compressed activation-share point;
- require one registered public key across registration, recovery, refresh, and
  export;
- enforce export seed non-disclosure;
- require export output commitment before release, authorization consumption
  only at release, and the exact output-committed receipt link;
- cross-link every persistence identity to its package set and receipt;
- require all three metadata-consumed origins and five zero counters;
- rebuild all four rejected activation attempts from their public proposals;
- require exact registration-bound rejected-attempt persistence self-loops and
  the uniform abort;
- recursively reject forbidden secret-bearing field names.

## 12. Explicit blockers and nonclaims

This corpus supplies no evidence for:

- production store parsing, independently enforced active-state rollback
  floors, authority-key distribution, or durable transactions; the companion
  `authenticated-store-resolution-v1.md` and its focused Rust tests now own the
  host-level signed request/state binding;
- globally unique issuance or a durable replay ledger;
- production recovery custody and verification of the proof-system-specific
  same-root artifact; the signed host lifecycle now binds the active credential,
  distinct authorized replacement, active state version, registered identity,
  stable scope, and common A/B same-root artifact into one sealed evidence value;
- authenticated refresh next-state promotion within this companion; the
  separate `refresh-promotion-v1.md` contract owns the host transition;
- selected-profile recipient decryption and authenticated package opening; the
  separate `signing-worker-activation-v1.md` contract owns post-opener share
  combination, activated state, and signed receipt verification;
- production wire, storage, or distributed-transaction bytes; host-only retry
  and redelivery semantics are owned by `export-delivery-lifecycle-v1.md`;
- constant-time execution of a selected cryptographic construction;
- P0, P1, P2, or P3 protocol security.

The registered session bridges and activation metadata consumer remain
crate-private until the corresponding blockers close. This attachment cannot
open Phase 1, Phase 2B, profile selection, or product integration by itself.
