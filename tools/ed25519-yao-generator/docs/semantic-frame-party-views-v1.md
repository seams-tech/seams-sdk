# Ed25519 Yao Semantic Frame and Party Views V1

Status: **Phase 1 construction-independent semantic trace specification; no
runtime-frame or protocol-security authority**

This document freezes the profile-neutral semantic trace layer that composes
the existing input, output, abort, activation-delivery, export-delivery, and
activation-recipient views. It defines directed semantic frame classes,
delivery states, cumulative value learning for seven closed roles, and typed
corruption-game interface shapes. It does not define a network encoding or a
security experiment implementation.

The keywords **MUST**, **MUST NOT**, and **REQUIRED** are normative.

## 1. Authority and scope

The existing companion specifications retain authority over their values:

- `ceremony-context-v1.md` owns public request, authorization, and transcript
  identity;
- `input-provenance-v1.md` owns ordered A/B provenance;
- `evaluation-input-party-views-v1.md` owns accepted role-local inputs and
  ideal-function randomness custody;
- `semantic-artifact-lifecycle-v1.md` owns public packages, receipts, and
  lifecycle projections;
- `output-party-views-v1.md` owns output custody;
- `uniform-abort-envelope-v1.md` and
  `evaluator-abort-state-party-views-v1.md` own public abort and retained-state
  views;
- `activation-delivery-lifecycle-v1.md` and
  `activation-recipient-party-views-v1.md` own activation release, uncertainty,
  redelivery, and SigningWorker activation;
- `export-delivery-lifecycle-v1.md` owns export release and redelivery; and
- the registration, recovery, refresh, and export evaluator companions own
  their admitted evaluation authority.

This document owns only the ordered composition of those artifacts into
semantic classes, states, role views, cumulative `known_values` labels, and
profile-neutral corruption-interface shapes. A label names a value class owned
by another companion. It never contains the value, an encoding, a length, or a
runtime handle.

Production crates MUST NOT treat this document or its committed corpus as a wire,
storage, logging, routing, authentication, replay, or authorization format.

## 2. Exactly eleven directed semantic frame classes

Version one contains exactly these classes in this canonical order:

1. `client_to_router_evaluation_request`
2. `router_local_activation_control`
3. `router_to_deriver_a_input_delivery`
4. `router_to_deriver_b_input_delivery`
5. `deriver_a_to_deriver_b_peer_protocol`
6. `deriver_b_to_deriver_a_peer_protocol`
7. `deriver_a_to_router_output_packages`
8. `deriver_b_to_router_output_packages`
9. `router_to_client_recipient_delivery`
10. `router_to_signing_worker_recipient_delivery`
11. `signing_worker_to_router_activation_receipt`

The names describe only semantic direction and purpose. They define no bytes,
payload schema, streaming chunk, message count, transport endpoint, service
binding, retry packet, authentication tag, or ciphertext.

`router_local_activation_control` is local to the Router. Activation emits no
evaluator frames: an activation continuation MUST NOT emit either Router-to-
Deriver input class, either peer-protocol class, or either Deriver-to-Router
output class. An evaluator abort is a terminal observation and emits no abort
frame class. Exact redelivery reuses the original
`router_to_client_recipient_delivery` and, for activation, the original
`router_to_signing_worker_recipient_delivery` class; version one has no
redelivery class.

## 3. Exactly eleven semantic delivery states

Version one contains exactly these state tags in this canonical enumeration
order:

1. `ceremony_admitted`
2. `evaluation_inputs_accepted`
3. `peer_protocol_in_progress`
4. `output_committed`
5. `evaluator_aborted`
6. `activation_metadata_consumed`
7. `recipient_delivery_uncertain`
8. `activation_recipients_released`
9. `export_released`
10. `signing_worker_activated`
11. `exact_redelivery`

The enumeration order is an identity order, not one universal transition
sequence. The allowed canonical trace sequences are:

```text
registration/recovery/refresh success:
  ceremony_admitted
  -> evaluation_inputs_accepted
  -> peer_protocol_in_progress
  -> output_committed
  -> activation_metadata_consumed
  -> recipient_delivery_uncertain
  -> activation_recipients_released
  -> exact_redelivery
  -> signing_worker_activated

export success:
  ceremony_admitted
  -> evaluation_inputs_accepted
  -> peer_protocol_in_progress
  -> output_committed
  -> recipient_delivery_uncertain
  -> export_released
  -> exact_redelivery

registration/recovery/refresh/export evaluator abort:
  ceremony_admitted
  -> evaluation_inputs_accepted
  -> peer_protocol_in_progress
  -> evaluator_aborted
```

Activation exact redelivery occurs only after atomic recipient release and
before SigningWorker activation. Export exact redelivery occurs only after
export release. A state tag cannot be skipped, repeated, reordered, or used by
an ineligible request family in the strict corpus.

## 4. Seven ordered roles and closed views

Every state has exactly seven views in this canonical order:

1. `deriver_a`
2. `deriver_b`
3. `client`
4. `signing_worker`
5. `router`
6. `observer`
7. `diagnostics`

There is no runtime role selector, generic observation map, optional role,
role-indexed property bag, secret-bearing clone, serialized production role
view, or API that returns multiple private role views. A host builder may
validate one complete synthetic view set. Static consuming projection MUST
return exactly one role view and drop the others.

Each corpus role view has exactly:

```text
role
known_values
observed_frame_classes
```

`known_values` and `observed_frame_classes` are ordered arrays of enum labels.
They contain no values or frame payloads. `known_values` is cumulative along one
trace: for each role, the next state's array MUST be an order-preserving
superset of the prior array. The model makes no forgetting or erasure claim.

## 5. Value-class vocabulary

The public labels are cumulative trace knowledge shared by all seven roles:

- `ceremony_public`
- `evaluation_inputs_accepted_public`
- `peer_progress_public`
- `output_commitment_public`
- `uniform_abort_public`
- `activation_metadata_public`
- `recipient_delivery_uncertainty_public`
- `activation_recipient_release_public`
- `export_release_public`
- `exact_redelivery_identity_public`
- `signing_worker_activation_receipt_public`

The private or role-local labels are:

- `client_role_scoped_inputs`
- `deriver_a_activation_inputs`
- `deriver_b_activation_inputs`
- `deriver_a_export_inputs`
- `deriver_b_export_inputs`
- `deriver_a_peer_local_state`
- `deriver_b_peer_local_state`
- `deriver_a_protocol_randomness`
- `deriver_b_protocol_randomness`
- `deriver_a_activation_output_shares`
- `deriver_b_activation_output_shares`
- `deriver_a_export_seed_share`
- `deriver_b_export_seed_share`
- `client_activation_scalar`
- `signing_worker_activation_authority`
- `client_export_seed`
- `signing_worker_activated_scalar`
- `router_opaque_role_envelope_identities`
- `router_opaque_output_package_identities`
- `router_opaque_recipient_delivery_identities`
- `router_lifecycle_control_knowledge`
- `router_receipt_control_knowledge`

For table compactness, `A_IN` and `B_IN` mean the matching activation-input
label for registration/recovery/refresh or the matching export-input label for
export. `A_OUT` and `B_OUT` mean the matching activation-output-shares label or
export-seed-share label. `P(state)` means every public label learned on the
unique prefix reaching that state. The strict corpus MUST expand these aliases
to the full ordered label arrays.

The following additional aliases are exact ordered private-label lists:

```text
A_ACT = deriver_a_activation_inputs,
        deriver_a_peer_local_state,
        deriver_a_protocol_randomness,
        deriver_a_activation_output_shares
B_ACT = deriver_b_activation_inputs,
        deriver_b_peer_local_state,
        deriver_b_protocol_randomness,
        deriver_b_activation_output_shares
A_EXP = deriver_a_export_inputs,
        deriver_a_peer_local_state,
        deriver_a_protocol_randomness,
        deriver_a_export_seed_share
B_EXP = deriver_b_export_inputs,
        deriver_b_peer_local_state,
        deriver_b_protocol_randomness,
        deriver_b_export_seed_share
R_CONTROL = router_lifecycle_control_knowledge
R_INPUT = R_CONTROL,
          router_opaque_role_envelope_identities
R_OUTPUT = R_INPUT,
           router_opaque_output_package_identities,
           router_receipt_control_knowledge
R_DELIVERY = R_OUTPUT,
             router_opaque_recipient_delivery_identities
```

The public-prefix aliases expand exactly as follows:

```text
P(ceremony_admitted) =
  [ceremony_public]
P(evaluation_inputs_accepted) =
  [ceremony_public, evaluation_inputs_accepted_public]
P(peer_protocol_in_progress) =
  [ceremony_public, evaluation_inputs_accepted_public, peer_progress_public]
P(output_committed) =
  [ceremony_public, evaluation_inputs_accepted_public, peer_progress_public,
   output_commitment_public]
P(evaluator_aborted) =
  [ceremony_public, evaluation_inputs_accepted_public, peer_progress_public,
   uniform_abort_public]
P(activation_metadata_consumed) =
  P(output_committed) + [activation_metadata_public]
P(recipient_delivery_uncertain, activation) =
  P(activation_metadata_consumed) + [recipient_delivery_uncertainty_public]
P(recipient_delivery_uncertain, export) =
  P(output_committed) + [recipient_delivery_uncertainty_public]
P(activation_recipients_released) =
  P(recipient_delivery_uncertain, activation) + [activation_recipient_release_public]
P(export_released) =
  P(recipient_delivery_uncertain, export) + [export_release_public]
P(exact_redelivery, activation) =
  P(activation_recipients_released) + [exact_redelivery_identity_public]
P(exact_redelivery, export) =
  P(export_released) + [exact_redelivery_identity_public]
P(signing_worker_activated) =
  P(exact_redelivery, activation) + [signing_worker_activation_receipt_public]
```

Where the table says `P(recipient_delivery_uncertain)` or `P(exact_redelivery)`, the
request kind selects the corresponding exact expansion above.

## 6. Complete cumulative value-learning table

Each cell lists the role's complete cumulative private additions to `P(state)`.
Observer and Diagnostics learn only the public value prefix in version one;
Diagnostics separately observes semantic class-and-direction labels under
Section 7. Router learns the exact opaque identity and control labels expressed
by `R_CONTROL`, `R_INPUT`, `R_OUTPUT`, and `R_DELIVERY`, with no plaintext or
secret value.

| State | Deriver A | Deriver B | Client | SigningWorker | Router | Observer | Diagnostics |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ceremony_admitted` | `P(ceremony_admitted)` | `P(ceremony_admitted)` | `P(ceremony_admitted) + client_role_scoped_inputs` | `P(ceremony_admitted)` | `P(ceremony_admitted) + R_CONTROL` | `P(ceremony_admitted)` | `P(ceremony_admitted)` |
| `evaluation_inputs_accepted` | `P(evaluation_inputs_accepted) + A_IN` | `P(evaluation_inputs_accepted) + B_IN` | `P(evaluation_inputs_accepted) + client_role_scoped_inputs` | `P(evaluation_inputs_accepted)` | `P(evaluation_inputs_accepted) + R_INPUT` | `P(evaluation_inputs_accepted)` | `P(evaluation_inputs_accepted)` |
| `peer_protocol_in_progress` | `P(peer_protocol_in_progress) + A_IN + deriver_a_peer_local_state + deriver_a_protocol_randomness` | `P(peer_protocol_in_progress) + B_IN + deriver_b_peer_local_state + deriver_b_protocol_randomness` | `P(peer_protocol_in_progress) + client_role_scoped_inputs` | `P(peer_protocol_in_progress)` | `P(peer_protocol_in_progress) + R_INPUT` | `P(peer_protocol_in_progress)` | `P(peer_protocol_in_progress)` |
| `output_committed` | activation: `P(output_committed) + A_ACT`; export: `P(output_committed) + A_EXP` | activation: `P(output_committed) + B_ACT`; export: `P(output_committed) + B_EXP` | `P(output_committed) + client_role_scoped_inputs` | `P(output_committed)` | `P(output_committed) + R_OUTPUT` | `P(output_committed)` | `P(output_committed)` |
| `evaluator_aborted` | `P(evaluator_aborted) + A_IN + deriver_a_peer_local_state + deriver_a_protocol_randomness` | `P(evaluator_aborted) + B_IN + deriver_b_peer_local_state + deriver_b_protocol_randomness` | `P(evaluator_aborted) + client_role_scoped_inputs` | `P(evaluator_aborted)` | `P(evaluator_aborted) + R_INPUT` | `P(evaluator_aborted)` | `P(evaluator_aborted)` |
| `activation_metadata_consumed` | `P(activation_metadata_consumed) + A_ACT` | `P(activation_metadata_consumed) + B_ACT` | `P(activation_metadata_consumed) + client_role_scoped_inputs` | `P(activation_metadata_consumed)` | `P(activation_metadata_consumed) + R_OUTPUT` | `P(activation_metadata_consumed)` | `P(activation_metadata_consumed)` |
| `recipient_delivery_uncertain` | activation: `P(recipient_delivery_uncertain) + A_ACT`; export: `P(recipient_delivery_uncertain) + A_EXP` | activation: `P(recipient_delivery_uncertain) + B_ACT`; export: `P(recipient_delivery_uncertain) + B_EXP` | `P(recipient_delivery_uncertain) + client_role_scoped_inputs` | `P(recipient_delivery_uncertain)` | `P(recipient_delivery_uncertain) + R_DELIVERY` | `P(recipient_delivery_uncertain)` | `P(recipient_delivery_uncertain)` |
| `activation_recipients_released` | `P(activation_recipients_released) + A_ACT` | `P(activation_recipients_released) + B_ACT` | `P(activation_recipients_released) + client_role_scoped_inputs + client_activation_scalar` | `P(activation_recipients_released) + signing_worker_activation_authority` | `P(activation_recipients_released) + R_DELIVERY` | `P(activation_recipients_released)` | `P(activation_recipients_released)` |
| `export_released` | `P(export_released) + A_EXP` | `P(export_released) + B_EXP` | `P(export_released) + client_role_scoped_inputs + client_export_seed` | `P(export_released)` | `P(export_released) + R_DELIVERY` | `P(export_released)` | `P(export_released)` |
| `exact_redelivery` | activation: `P(exact_redelivery) + A_ACT`; export: `P(exact_redelivery) + A_EXP` | activation: `P(exact_redelivery) + B_ACT`; export: `P(exact_redelivery) + B_EXP` | activation: `P(exact_redelivery) + client_role_scoped_inputs + client_activation_scalar`; export: `P(exact_redelivery) + client_role_scoped_inputs + client_export_seed` | activation: `P(exact_redelivery) + signing_worker_activation_authority`; export: `P(exact_redelivery)` | `P(exact_redelivery) + R_DELIVERY` | `P(exact_redelivery)` | `P(exact_redelivery)` |
| `signing_worker_activated` | `P(signing_worker_activated) + A_ACT` | `P(signing_worker_activated) + B_ACT` | `P(signing_worker_activated) + client_role_scoped_inputs + client_activation_scalar` | `P(signing_worker_activated) + signing_worker_activation_authority + signing_worker_activated_scalar` | `P(signing_worker_activated) + R_DELIVERY` | `P(signing_worker_activated)` | `P(signing_worker_activated)` |

For abort, `P(evaluator_aborted)` is exactly `ceremony_public`,
`evaluation_inputs_accepted_public`, `peer_progress_public`, and `uniform_abort_public`.
It excludes `output_commitment_public`. For activation uncertainty,
`P(recipient_delivery_uncertain)` includes activation metadata; for export uncertainty it
does not. `exact_redelivery` adds only
`exact_redelivery_identity_public`; all private labels equal the preceding
release state. It never adds or resamples a private value.

The table records knowledge, not current memory custody. Existing companion
types remain authoritative for move ownership, release capability, terminal
retention, and secret erasure. A cumulative label cannot authorize an accessor.

## 7. Semantic frame observations

A role observes a semantic frame class exactly when it is the class's sender,
recipient, or local owner:

| Class | Observing roles |
| --- | --- |
| `client_to_router_evaluation_request` | Client, Router, Diagnostics |
| `router_local_activation_control` | Router, Diagnostics |
| `router_to_deriver_a_input_delivery` | Router, Deriver A, Diagnostics |
| `router_to_deriver_b_input_delivery` | Router, Deriver B, Diagnostics |
| `deriver_a_to_deriver_b_peer_protocol` | Deriver A, Deriver B, Diagnostics |
| `deriver_b_to_deriver_a_peer_protocol` | Deriver B, Deriver A, Diagnostics |
| `deriver_a_to_router_output_packages` | Deriver A, Router, Diagnostics |
| `deriver_b_to_router_output_packages` | Deriver B, Router, Diagnostics |
| `router_to_client_recipient_delivery` | Router, Client, Diagnostics |
| `router_to_signing_worker_recipient_delivery` | Router, SigningWorker, Diagnostics |
| `signing_worker_to_router_activation_receipt` | SigningWorker, Router, Diagnostics |

Observer observes no semantic frame class. Diagnostics observes the class and
direction label for every emitted semantic frame and no payload, secret value,
runtime byte, endpoint, or authentication material. Both roles may learn the
public state labels from Section 6. This separation prevents lifecycle
observation from implying network or payload access.

`observed_frame_classes` is cumulative and preserves first-observation order.
Redelivery MUST NOT append a second class label; the trace step records the
reused class while the role's cumulative observation set remains unchanged.

## 8. Ten corruption markers

Version one contains exactly these markers in this canonical order:

1. `honest_execution` (`HonestExecution`)
2. `router_only` (`RouterOnly`)
3. `passive_deriver_a` (`PassiveDeriverA`)
4. `passive_deriver_b` (`PassiveDeriverB`)
5. `router_and_passive_deriver_a` (`RouterAndPassiveDeriverA`)
6. `router_and_passive_deriver_b` (`RouterAndPassiveDeriverB`)
7. `active_deriver_a` (`ActiveDeriverA`)
8. `active_deriver_b` (`ActiveDeriverB`)
9. `router_and_active_deriver_a` (`RouterAndActiveDeriverA`)
10. `router_and_active_deriver_b` (`RouterAndActiveDeriverB`)

Each marker fixes only the corrupted-role set and passive/active label needed
by a future game. It does not assert that a construction tolerates the marker.
Router-only is a distinct marker with no implied passive or active theorem.

The closed universe excludes A+B collusion, Client corruption, SigningWorker
corruption, Observer or Diagnostics corruption, platform-wide compromise,
adaptive corruption, mobile corruption, and any composition containing them.

## 9. Four corruption-game interface shapes

Exactly four profile-neutral shape tags exist in this order:

1. `corrupted_view_input`
2. `selected_profile_real_execution`
3. `selected_profile_ideal_simulator`
4. `selected_profile_security_experiment`

```text
CorruptedViewInputV1 {
  corruption_marker,
  ordered_corrupted_roles,
  ordered_known_value_labels,
  ordered_observed_frame_classes,
}

SelectedProfileRealExecutionV1 {
  corruption_marker,
  semantic_trace_case_id,
  source_reference_digest_labels,
}

SelectedProfileIdealSimulatorV1 {
  corruption_marker,
  ideal_functionality_id,
  allowed_known_value_labels,
}

SelectedProfileSecurityExperimentV1 {
  corruption_marker,
  selected_profile_real_execution_shape,
  selected_profile_ideal_simulator_shape,
  corrupted_view_input_shape,
}
```

These are type/interface shapes only. Version one supplies no simulator,
experiment runner, distribution, advantage definition, theorem, default
corruption claim, profile-satisfaction assertion, or real/ideal equivalence.
The future selected-profile specification must instantiate and review them.

## 10. Ordering, identity, retry, and redelivery invariants

Every strict trace MUST satisfy all of the following:

1. states follow exactly one sequence in Section 3;
2. frame classes follow the fixed semantic direction in Section 2;
3. all steps retain one case id, request kind, ceremony identity, and ordered
   source-reference set;
4. input, output, delivery, activation, and abort identities equal the exact
   identities in their owning companion artifacts;
5. Deriver A always precedes Deriver B in input, peer, output, role-view, and
   source-reference ordering;
6. activation control links one exact output-committed registration, recovery,
   or refresh origin and emits no evaluator frame;
7. evaluator abort is terminal, has no output or delivery frame, burns the
   admitted request/execution, and cannot resume;
8. an evaluator retry is a new trace with the fresh identities required by the
   branch evaluator companion;
9. activation uncertainty and export uncertainty perform zero private
   reevaluation and sample no new output or delta value;
10. activation redelivery reuses the exact original Client and SigningWorker
    delivery identities and classes after recipient release and before worker
    activation;
11. export redelivery reuses the exact original Client delivery identity and
    class after export release; and
12. redelivery leaves every `known_values` and `observed_frame_classes` array
    unchanged except for appending `exact_redelivery_identity_public` to
    `known_values`.

## 11. Eight canonical semantic trace cases

The committed strict corpus contains exactly these cases in this order:

1. `registration_success_worker_activated_v1`
2. `recovery_success_worker_activated_v1`
3. `refresh_success_worker_activated_v1`
4. `export_release_exact_redelivery_v1`
5. `registration_evaluator_abort_v1`
6. `recovery_evaluator_abort_v1`
7. `refresh_evaluator_abort_v1`
8. `export_evaluator_abort_v1`

Each activation-family success includes exact redelivery between recipient
release and SigningWorker activation. The export success includes exact
redelivery after export release. Each abort ends at `evaluator_aborted`.

The exact per-step emitted class arrays are:

| Trace/state | `emitted_frame_classes` |
| --- | --- |
| every `ceremony_admitted` | [`client_to_router_evaluation_request`] |
| every `evaluation_inputs_accepted` | [`router_to_deriver_a_input_delivery`, `router_to_deriver_b_input_delivery`] |
| every `peer_protocol_in_progress` | [`deriver_a_to_deriver_b_peer_protocol`, `deriver_b_to_deriver_a_peer_protocol`] |
| every successful `output_committed` | [`deriver_a_to_router_output_packages`, `deriver_b_to_router_output_packages`] |
| every `evaluator_aborted` | [] |
| activation-family `activation_metadata_consumed` | [`router_local_activation_control`] |
| activation-family `recipient_delivery_uncertain` | [`router_to_client_recipient_delivery`, `router_to_signing_worker_recipient_delivery`] |
| activation-family `activation_recipients_released` | [] |
| activation-family `exact_redelivery` | [`router_to_client_recipient_delivery`, `router_to_signing_worker_recipient_delivery`] |
| activation-family `signing_worker_activated` | [`signing_worker_to_router_activation_receipt`] |
| export `recipient_delivery_uncertain` | [`router_to_client_recipient_delivery`] |
| export `export_released` | [] |
| export `exact_redelivery` | [`router_to_client_recipient_delivery`] |

Abort traces emit no output class before their terminal state. Redelivery rows
record reuse of an existing class and identity. They do not add a new class to
any cumulative `observed_frame_classes` set.

## 12. Strict canonical JSON schema

The expected corpus path is:

```text
vectors/ed25519-yao-semantic-frame-party-views-v1.json
```

The top-level object has exactly these keys in this order:

```text
schema
protocol_id
evidence_scope
ordered_roles
frame_classes
delivery_states
corruption_markers
interface_shapes
cases
```

Their exact fixed values are:

```text
schema = "seams:router-ab:ed25519-yao:semantic-frame-party-views:v1"
protocol_id = "router_ab_ed25519_yao_v1"
evidence_scope = "construction_independent_semantic_trace_and_value_learning_v1"
ordered_roles = the seven labels from Section 4
frame_classes = the eleven labels from Section 2
delivery_states = the eleven labels from Section 3
corruption_markers = the ten labels from Section 8
interface_shapes = [
  "corrupted_view_input",
  "selected_profile_real_execution",
  "selected_profile_ideal_simulator",
  "selected_profile_security_experiment"
]
```

Each case object has exactly these keys in this order:

```text
case_id
request_kind
outcome
source_references
trace_steps
retry_redelivery_policy
explicit_nonclaims
```

`request_kind` is one of `registration`, `recovery`, `refresh`, or `export`.
`outcome` is `success` or `evaluator_abort`. `source_references` is an ordered,
nonempty array of external references, each with exactly:

```text
artifact_kind
schema
case_selector
```

The referenced artifact bytes are never embedded. `case_selector` names either
an owning corpus `case_id` or the exact `source_ceremony_case_id` used by a
corpus without its own case identifier. Every case MUST reference the matching
ceremony, provenance, evaluation-input, and evaluator-authority/admission
artifacts. Success cases MUST also reference semantic-lifecycle and output-
party-view artifacts. Activation successes MUST reference activation delivery
and activation recipient views. Export success MUST reference export delivery.
Abort cases MUST reference uniform-abort and evaluator-abort artifacts instead
of success-only output views. Recovery success MUST reference the recovery
credential-transition corpus. Refresh success MUST reference the refresh
lifecycle-continuity case and refresh evaluator-admission corpus.

Each `trace_steps` entry has exactly these keys in this order:

```text
ordinal
delivery_state
emitted_frame_classes
ordered_role_views
identity_labels
```

`ordinal` starts at zero and increments by one. `emitted_frame_classes` is an
ordered array of zero or more labels from Section 2. `ordered_role_views` has
exactly seven entries in Section 4 order. Each entry has exactly:

```text
role
known_values
observed_frame_classes
```

`identity_labels` is an ordered array of public crosslink names only. It
contains no digest or value bytes. The independent verifier loads the exact
required sibling source corpora and verifies artifact-kind, schema, case-
selector existence, and request-family applicability. Each owning corpus
verifier and the generated fixed-reference commitments retain authority for
byte-level equality. Labels alone cannot establish identity equality. Rust typed
construction may enforce stronger in-process identity composition before
building this label-only projection.

The canonical cumulative identity-label arrays are:

```text
ceremony_admitted =
  [ceremony_request_identity, authorization_identity, transcript_identity]
evaluation_inputs_accepted = ceremony_admitted +
  [provenance_pair_identity, evaluator_admission_identity,
   one_use_execution_identity, evaluation_input_view_identity]
peer_protocol_in_progress = evaluation_inputs_accepted +
  [peer_protocol_execution_identity]
output_committed = peer_protocol_in_progress +
  [output_package_set_identity, output_committed_receipt_identity]
evaluator_aborted = peer_protocol_in_progress +
  [burned_execution_identity, uniform_abort_identity]
activation_metadata_consumed = output_committed +
  [activation_control_identity]
recipient_delivery_uncertain (activation) = activation_metadata_consumed +
  [activation_recipient_delivery_identity]
recipient_delivery_uncertain (export) = output_committed +
  [export_client_delivery_identity]
activation_recipients_released = recipient_delivery_uncertain (activation) +
  [activation_recipient_release_identity]
export_released = recipient_delivery_uncertain (export) +
  [export_client_release_identity]
exact_redelivery = the applicable release array +
  [exact_redelivery_identity]
signing_worker_activated = exact_redelivery (activation) +
  [signing_worker_activation_receipt_identity]
```

The verifier MUST require these exact arrays. A different label, missing label,
reordering, or branch-inapplicable identity is invalid.

`retry_redelivery_policy` has exactly:

```text
evaluator_retry
redelivery
fresh_identity_requirements
```

`evaluator_retry` is `not_applicable`, `fresh_trace_required`, or
`terminal_abort_no_resume`. `redelivery` is `not_applicable`,
`exact_activation_recipient_redelivery`, or `exact_export_client_redelivery`.
`fresh_identity_requirements` is an ordered label array and contains no value.

`explicit_nonclaims` is the exact ordered case-relevant subset of Section 13.
Unknown keys, missing keys, duplicate enum labels, reordered fixed arrays,
unknown labels, optional fields, `null`, extension objects, and trailing JSON
values are invalid. Canonical bytes are pretty-printed UTF-8 JSON with two-space
indentation and exactly one trailing LF. A strict parser accepts only bytes
equal to the canonical builder output.

The corpus MUST NOT contain a key whose name includes `bytes`, `hex`, `size`,
`length`, `timing`, `latency`, `authentication`, `signature`, `ciphertext`,
`ticket`, `durable`, `transaction`, `security_profile`, `profile_negotiation`,
`simulator_output`, `advantage`, or `proof`.

## 13. Explicit exclusions and nonclaims

This specification and corpus do not define or establish:

- runtime frame bytes, payloads, envelopes, schemas, counts, sizes, lengths,
  chunking, sequencing, scheduling, timing, latency, or backpressure;
- authenticated transport, service bindings, endpoint identity, encryption,
  signatures, replay persistence, tickets, durable records, transactions,
  crash recovery, or delivery acknowledgement;
- production serialization or logging of any role view;
- secret values, private-input openings, output-share bytes, seed bytes,
  scalar bytes, delta values, roots, credentials, OT state, garbling state, or
  protocol randomness;
- dynamic role selection, A+B collusion, Client/SigningWorker corruption,
  platform-wide compromise, or adaptive/mobile corruption;
- profile negotiation, a default P0-P3 profile, or satisfaction of any profile;
- a simulator implementation, experiment execution, distinguishing advantage,
  noninterference theorem, real/ideal equivalence, privacy theorem, active-
  security theorem, correctness-with-abort theorem, or protocol-composition
  claim; or
- production constant-time behavior, erasure, forward security, healing,
  entropy, anti-bias, selective-abort resistance, or retry-grinding resistance.

## 14. Expected executable and formal evidence

Closure requires all of the following evidence, with exact counts pinned by the
formal-verification baseline when implementation lands:

- Rust closed-enum and constructor tests for exactly eleven frame classes,
  eleven states, seven roles, ten corruption markers, and four interfaces;
- Rust relation tests for all three allowed state sequences, activation's zero
  evaluator frames, frame-direction observation, cumulative monotonic
  `known_values`, exact redelivery, terminal abort, and static consuming role
  projection;
- strict Rust corpus and CLI tests for the eight cases, canonical key/array
  order, external crosslinks, retry/redelivery policy, and forbidden fields;
- independent Python reconstruction of every state sequence, emitted class,
  seven-role cumulative learning view, observation set, crosslink, and policy,
  with mutations for order, identity, monotonicity, role isolation, abort,
  redelivery, corruption markers, interface shapes, and forbidden fields; and
- Lean structural theorems for exact finite universes, allowed transitions,
  seven-role totality, monotonic cumulative knowledge, Deriver isolation,
  activation zero-evaluator-frame behavior, abort terminality, redelivery
  identity, and the absence of a profile-satisfaction conclusion.

These artifacts remain policy-shape and trace-composition evidence. They do not
upgrade the exclusions in Section 13 into security claims.
