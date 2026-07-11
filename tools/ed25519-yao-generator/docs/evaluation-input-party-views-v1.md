# Ed25519 Yao Evaluation-Input Party Views V1

Status: **Phase 1 profile-neutral host-only evaluation-input specification; no
production protocol authority**

This document freezes the construction-independent party views at the accepted
evaluation boundary of the host-reference Ed25519 Router A/B lifecycle. Each
view contains one common public-leakage value plus one closed, role-specific
input extension. Registration, recovery, and refresh use the activation family;
export uses the export family; activation consumes committed metadata and has
no evaluation inputs.

The core model uses synthetic inputs and nonserializable Rust values. A strict
DTO projects selected synthetic private values and ideal-function randomness
into the evidence corpus defined in Section 10. Published fixture bytes remain
test evidence. They define no production transport, storage, circuit wire,
garbling, OT, or logging format. The keywords **MUST**, **MUST NOT**, and
**REQUIRED** are normative.

## 1. Authority and scope

The existing companion specifications retain authority over their values:

- `fixed-reference-v1.md` owns Ed25519 arithmetic, clamping, reduction, and
  registered-public-key relations;
- `ceremony-context-v1.md` owns canonical public request, authorization, and
  transcript values;
- `input-provenance-v1.md` owns the role-input provenance outer statement,
  A/B pair digest, public epochs, and opaque evidence slots;
- `output-sharing-v1.md` owns the mathematical activation-scalar and export-seed
  sharing distributions and reconstruction equations;
- `semantic-artifact-lifecycle-v1.md` owns semantic packages, receipts, and
  persistence projections;
- `output-party-views-v1.md` owns the construction-independent output-custody
  views; and
- `ideal-functionalities-v1.md` owns the wider leakage, custody, lifecycle, and
  eventual complete-party-view requirements.

This document owns the composition of accepted evaluation inputs into five
stage-discriminated, seven-role host views. It also owns the exact synthetic
evidence attachment for those views. It does not select the circuit compiler,
garbling scheme, oblivious-transfer construction, active-security mechanism,
transport frames, or production provenance verifier.

Protocol coins used to share outputs belong to the ideal functionality. They
are outside every party view in this companion. Section 10 records deterministic
fixture coins in a separate verifier-only field so an independent checker can
reproduce the later output relation. That field is never common public leakage
or a role extension.

No value or type defined here may enter a production Worker, Router,
SigningWorker, SDK, persistence record, log, or network message. Production
crates MUST NOT depend on the host generator or these view types.

## 2. Closed stage family

Exactly five input-view stages exist in version one:

| Stage | Request kind | Evaluation plan | Private evaluation inputs |
| --- | --- | --- | --- |
| `registration_evaluation_accepted` | registration | one activation evaluation | four A fields and four B fields |
| `activation_continuation_accepted` | activation | zero-evaluation continuation | none |
| `recovery_evaluation_accepted` | recovery | one activation evaluation | four A fields and four B fields |
| `refresh_evaluation_accepted` | refresh | one activation evaluation | four A fields and four B fields |
| `export_evaluation_accepted` | export | one export evaluation | two A `y` fields and two B `y` fields |

`evaluation_accepted` means that branch typing, public ceremony construction,
host-reference provenance pairing, and the required public pre-state checks
have succeeded. The values are ready for one ideal evaluation. It does not mean
that a production proof was verified, an OT session began, a circuit artifact
was authenticated, or an output was committed.

`activation_continuation_accepted` means that one origin-specific continuation
has passed the metadata/control relation. Activation performs zero Yao
evaluations and supplies zero Deriver inputs. The corpus groups the three
canonical registration, recovery, and refresh origin projections for compact
evidence; a runtime continuation selects exactly one origin.

There is no generic lifecycle stage, optional stage tag, runtime security
profile, caller-selected circuit, or caller-supplied evaluation count.

## 3. Input domains

### 3.1 Activation-family Deriver inputs

Registration, recovery, and refresh supply each Deriver exactly four
role-local values:

```text
Deriver A: y_client_A, y_server_A, tau_client_A, tau_server_A
Deriver B: y_client_B, y_server_B, tau_client_B, tau_server_B
```

Each `y` value is exactly 32 bytes interpreted in little-endian
`Z_(2^256)`. Every 32-byte string is canonical in this domain. Each `tau` value
is exactly 32 bytes in the canonical little-endian encoding of one element of
`Z_l`, where `l` is the Ed25519 subgroup order. Encodings greater than or equal
to `l` are invalid.

The client/server suffix is a KDF source label. It does not designate the party
that sees the contribution. Deriver A receives only the four A values; Deriver
B receives only the four B values. The Client, SigningWorker, Router, Observer,
and Diagnostics/logs receive no private accepted-evaluation input.

The activation-family joined relation is:

```text
y = y_client_A + y_server_A + y_client_B + y_server_B mod 2^256
tau = tau_client_A + tau_server_A + tau_client_B + tau_server_B mod l
d = y
a = clamp_lower_32_bytes(SHA-512(d)) mod l
x_client_base = a + tau mod l
x_server_base = a + 2 * tau mod l
X_client = [x_client_base]B
X_server = [x_server_base]B
2 * X_client - X_server = [a]B = A_pub
```

The independent verifier MUST reproduce the exact fixed-reference equations,
then link the derived output to the coherent semantic and output-party
attachments named by the case. Joined `y`, joined `tau`, `d`, `a`, the SHA-512
digest, clamped bytes, `x_client_base`, and `x_server_base` remain outside every
input party view.

### 3.2 Export-family Deriver inputs

Export supplies exactly:

```text
Deriver A: y_client_A, y_server_A
Deriver B: y_client_B, y_server_B
```

The export circuit reconstructs:

```text
d = y_client_A + y_server_A + y_client_B + y_server_B mod 2^256
Ed25519PublicKey(d) = registered_A_pub
```

Export input types have no `tau` field, scalar slot, optional scalar, or generic
payload. The registered public key remains public state in the owning provenance
and semantic companions; this narrow input view binds it transitively through
the validated provenance pair and does not duplicate it. The joined seed `d` is
absent from every accepted-input party view and becomes an authorized Client
output only through the export output contract.

### 3.3 Activation continuation

Activation supplies no `y`, `tau`, root, contribution, output coin, output
share, or circuit-private input. Every role extension is a sealed empty
activation variant. Its plan has five zero counters as frozen in Section 5.

## 4. Common public leakage

Every role view for one validated stage MUST carry the same common-public
value. Role extensions cannot change, shadow, or duplicate any common field.

### 4.1 Accepted evaluation common value

Registration, recovery, refresh, and export common public leakage contains
exactly:

- the stage and request kind;
- the derived, closed evaluation plan;
- the canonical public request-context, authorization, and transcript digests;
- the ordered A/B input-provenance-pair digest; and
- no private input or output value.

Circuit family, circuit id, final-circuit digest, input-schema digest,
client-envelope-set digest, transport/artifact-suite bindings, one-use execution
id, public pre-state, registered key, and later semantic/output identities remain
available through their owning validated companions. This narrow core view does
not copy them. The strict corpus names those companions in a separate
`host_only_source_references` field outside all party views.

The final-circuit and input-schema digests in the provenance attachment are
synthetic opaque values. Their transitive binding supplies host evidence only.
It cannot authorize a production circuit or input schema.

### 4.2 Activation-continuation common value

Activation common public leakage contains exactly:

- the activation-continuation stage and request kind;
- the closed zero-evaluation plan;
- the canonical public request-context, authorization, and transcript digests;
  and
- no provenance-pair digest or private input.

The strict five-case corpus selects the canonical registration-origin
continuation. Its separate source-reference object links the digest triple to
the registration-origin entry in the semantic-lifecycle and output-party
companions. One runtime input-view set represents one activation request. It
never aggregates multiple origins.

The generic activation case in `ceremony-context-v1.md` uses an independent
canonical example and does not byte-match the selected origin-specific semantic
continuation. The source-reference object therefore omits a ceremony or
provenance case id. Recovery- and refresh-origin zero-input equivalence is
covered by the prior output-party corpus.

### 4.3 Equality and diagnostics

All seven role projections rebuilt from one deterministic fixture MUST compare
equal in their common-public field. Diagnostics/logs may retain a strict subset
of this public value in a future runtime adapter. They cannot acquire an input,
coin, opaque private handle, or peer extension.

Timing, response sizes, allocation data, retry metadata, ticket ids, and network
sizes are absent from this host model. Their possible classification in the
wider ideal functionality does not authorize fixture invention or production
logging here.

## 5. Closed evaluation plans

`evaluation_plan` is an exact tagged object:

```text
evaluation_plan:
  kind
  counts
```

Its `counts` object uses this field order:

```text
yao_evaluations
deriver_a_invocations
deriver_b_invocations
contribution_derivations
ideal_output_share_samples
```

The allowed plans are:

| Request family | `kind` | Counts in the order above |
| --- | --- | --- |
| registration/recovery/refresh | `one_activation_evaluation` | `1, 1, 1, 0, 2` |
| activation | `zero_evaluation_continuation` | `0, 0, 0, 0, 0` |
| export | `one_export_evaluation` | `1, 1, 1, 0, 1` |

These counters describe only the accepted evaluator window. Contribution KDF
derivation has already completed, so `contribution_derivations` is zero for
every stage. Output-share sample counts describe the ideal functionality's
mathematical sampling obligations. They do not reveal a sampled coin and do not
claim that a production entropy source ran.

Constructors derive the plan from the stage. A caller cannot supply or mutate a
plan, count, circuit family, or circuit identifier.

## 6. Closed role-local extensions

Every view has exactly one stage-indexed role extension. Empty extensions are
sealed zero-field variants after their `kind` tag. They are never `None`, an
optional object, a byte bag, or a generic map.

| Role | Registration/recovery/refresh | Activation | Export |
| --- | --- | --- | --- |
| Deriver A | A's four activation-family inputs | empty | A's two `y` inputs |
| Deriver B | B's four activation-family inputs | empty | B's two `y` inputs |
| Client | empty | empty | empty |
| SigningWorker | empty | empty | empty |
| Router | empty | empty | empty |
| Observer | empty | empty | empty |
| Diagnostics/logs | empty | empty | empty |

The role-local activation-family types are disjoint:

```text
DeriverAEvaluationInputsV1 {
  y_client,
  y_server,
  tau_client,
  tau_server,
}

DeriverBEvaluationInputsV1 {
  y_client,
  y_server,
  tau_client,
  tau_server,
}
```

The export types are separate and contain only `y_client` and `y_server`.
There is no conversion between A and B, between activation and export inputs,
or from raw bytes without boundary validation.

Client envelope plaintext, derivation roots, recovery credentials, refresh
deltas, output coins, output shares, protocol randomness, labels, masks, OT
state, and recipient decryption keys cannot occur in a role extension.

## 7. Ideal-function-owned randomness

The ideal functionality samples fresh output-sharing coins only after accepting
the evaluation inputs.

Activation-family distribution:

```text
R_client <-$ Z_l
R_signing_worker <-$ Z_l

client_share_A = R_client
client_share_B = x_client_base - R_client mod l

signing_worker_share_A = R_signing_worker
signing_worker_share_B = x_server_base - R_signing_worker mod l
```

Export distribution:

```text
U <-$ Z_(2^256)
seed_share_A = U
seed_share_B = d - U mod 2^256
```

Activation continuation samples nothing.

The arrows above define the required mathematical distributions. The strict
corpus uses deterministic boundary values to reproduce equations. Deterministic
fixtures establish no entropy, independence, unpredictability, uniformity,
anti-bias, erasure, or distributed-generation claim. The selected P0-P3
construction must realize and review the distribution required by its exact
security claim.

Neither Deriver supplies these coins as an evaluation input. No party input
view contains the coins, even when a later output share happens to equal one of
them. The corpus field `host_only_ideal_function_randomness` is a verifier-only
oracle attachment outside all views.

## 8. Consuming static observation

The private host builders may hold both synthetic role inputs long enough to
construct one branch-specific custody set. The exact sets are
`HostOnlyRegistrationEvaluationInputViewSetV1`,
`HostOnlyActivationContinuationInputViewSetV1`,
`HostOnlyRecoveryEvaluationInputViewSetV1`,
`HostOnlyRefreshEvaluationInputViewSetV1`, and
`HostOnlyExportEvaluationInputViewSetV1`. Each set has private fields and
constructors, implements neither `Clone`, `Copy`, nor Serde, and exposes no
aggregate accessor.

Deriver observation is an inherent, static-named, consuming method on each
branch-specific set. Registration illustrates the activation-family pattern:

```rust
impl HostOnlyRegistrationEvaluationInputViewSetV1 {
    pub fn observe_deriver_a_v1(
        self,
    ) -> HostOnlyDeriverAActivationEvaluationInputViewV1<
        HostOnlyRegistrationEvaluationInputCommonV1,
    >;

    pub fn observe_deriver_b_v1(
        self,
    ) -> HostOnlyDeriverBActivationEvaluationInputViewV1<
        HostOnlyRegistrationEvaluationInputCommonV1,
    >;
}
```

Recovery and refresh expose the same two method names on their own concrete set
types. Export returns the two concrete y-only view types. Activation returns the
two concrete empty view types. No generic runtime stage value chooses a set or
return type.

Each function consumes the complete validated set and returns the common public
value plus exactly one Deriver extension. The unselected extensions are
dropped. Tests observing both roles rebuild a fresh deterministic fixture.

The API MUST NOT provide:

- a runtime `observe_deriver(role)` selector;
- a tagged return union holding either private role input;
- a method returning both Deriver views or private extensions;
- a peer-input accessor, iterator, generic map, or reusable observation token;
- a conversion between A and B views; or
- a public accessor to the validated aggregate.

The host-only randomness evidence is never stored in any branch-specific input
view set and cannot be reached through an observation method. A private corpus
fixture builder may return separate view and randomness evidence to the strict
DTO projector.

This construction supplies structural host evidence. Consuming projection does
not prove memory erasure, computational privacy, simulation, or security against
a runtime adversary.

## 9. Required relation checks

Responsibility is split between the core input-view builders and the strict
corpus composition checks. No single API receives inputs, ideal coins, and
future outputs together.

### 9.1 Core input-view construction

Each producing-branch core builder accepts its exact sealed request, ordered
A/B provenance pair, and an already validated branch-matched prepared host
reference. It MUST:

1. derive request kind, stage, evaluation plan, and counts from the branch;
2. require the provenance request kind to equal the sealed ceremony branch;
3. require exact request-context, authorization, and transcript digest equality
   between the ceremony and provenance pair;
4. compute the ordered A/B provenance-pair digest through its canonical
   encoder;
5. copy only the already validated role inputs from the branch-matched prepared
   reference;
6. preserve exact A/B and client/server ownership; and
7. expose only one role through a consuming branch-specific observation.

Canonical `tau` parsing and branch arithmetic validation occur when the prepared
host reference is constructed. The input-view builder accepts no raw role input,
ideal output-sharing coin, future output share, output-party view, or semantic
package result. Borrowing the exact branch-specific prepared reference keeps the
view inputs call-locally coherent with that preparation and prevents injection
of an unrelated contribution tuple. Export retains and projects only the four
y values required by its family.

The provenance-pair digest slots are synthetic and opaque in this host slice.
Digest equality does not authenticate a root, record, artifact, epoch, or
contribution and does not prove that the prepared inputs came from production
custody.

The activation-continuation builder accepts its sealed activation request and
the typed no-ideal-coins witness. It constructs only empty extensions and the
derived zero plan.

### 9.2 Strict corpus composition

For each activation-family case, the corpus builder and independent verifier
collectively MUST:

1. validate every serialized `y` and canonical `tau` field;
2. reproduce the fixed activation-family arithmetic in Section 3.1;
3. require the common ceremony digest triple to match the named ceremony,
   provenance, and semantic attachments;
4. require the provenance-pair and client-envelope-set digests to match the
   named provenance case;
5. require the one-use execution id, transcript transport/artifact bindings,
   and registered-state branch to match the named semantic case;
6. apply the separate host-only coins and reproduce the output-sharing
   equations owned by `output-sharing-v1.md`;
7. require the reconstructed shares and public outputs to equal the named
   coherent output-party case; and
8. require the plan to be exactly `one_activation_evaluation` with counts
   `1,1,1,0,2`.

The named registration source must have the unregistered public pre-state.
Recovery and refresh source attachments must have registered pre-state and exact
registered-key continuity. Those facts remain companion data; they are absent
from the narrow common-public DTO.

Recovery uses the same effective four-field role inputs after the frozen
same-root rewrap relation. Refresh uses the next role inputs after the frozen
opposite-delta transform. The recovery root equality and refresh delta are
host-oracle material outside all party views.

### 9.3 Activation continuation

The core builder MUST construct seven sealed empty role extensions, derive
`zero_evaluation_continuation`, and require the typed no-ideal-coins witness. It
accepts no `y`, `tau`, provenance evaluation pair, circuit input, output-sharing
coin, Deriver invocation result, or recipient output.

The strict corpus selects the canonical registration-origin continuation. The
corpus builder and independent verifier MUST require its common digest triple to
equal the registration-origin semantic metadata-consumed projection and the
matching output-party origin projection. They also require the unchanged origin
identity and registered key, the fresh activation-control digest triple, seven
empty extensions, and five zero counts. The earlier output-party corpus covers
the equivalent recovery- and refresh-origin zero-input shapes.

### 9.4 Export

The export corpus builder and independent verifier collectively MUST:

1. accept exactly two `y` fields from each Deriver;
2. reconstruct `d` modulo `2^256`;
3. derive the RFC 8032 public key and compare it with the registered pre-state;
4. cross-link the ceremony/provenance/semantic identities and digests exactly;
5. apply the separate host-only export coin under the equation in Section 7;
6. reproduce the A/B seed shares and authorized Client seed in the named
   output-party case; and
7. require `one_export_evaluation` with counts `1,1,1,0,1`.

No export input type or view may contain a `tau`, scalar, output share, joined
seed, or SigningWorker input.

The core export input-view builder is narrower: it validates the sealed
ceremony/provenance binding and copies the four y-only values from an already
validated prepared export reference. It receives no ideal coin or future
output.

### 9.5 Cross-view relations

For every stage:

- independent A and B projections rebuilt from the same deterministic fixture
  have equal common public leakage;
- each Deriver projection contains only its own extension;
- Client, SigningWorker, Router, Observer, and Diagnostics/logs have sealed
  empty extensions;
- the static observation duplicates only its matching role extension;
- the host-only randomness field is absent from all seven views; and
- no joined value or peer input is available through a public or role-local
  accessor.

Field absence and type separation do not establish computational
non-reconstruction. The selected-profile corruption games own that claim.

## 10. Strict portable corpus

The version-one attachment is:

`vectors/ed25519-yao-evaluation-input-party-views-v1.json`

Its exact envelope values are:

```text
schema         = seams:router-ab:ed25519-yao:evaluation-input-party-views-vectors:v1
protocol_id    = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_evaluation_input_party_views_v1
```

The corpus intentionally publishes synthetic role-private `y` and `tau` inputs
and deterministic ideal-function coins. These bytes are verifier inputs. Their
publication does not reclassify them as public leakage in the modeled
execution. They MUST NOT be served, logged, persisted, copied into a production
artifact, or interpreted as a deployable party-view format.

### 10.1 Canonical JSON boundary

Top-level field order is exact:

```text
schema
protocol_id
evidence_scope
cases
```

The `cases` array contains exactly five cases in this order:

| # | Request kind | Stage | Case id |
| ---: | --- | --- | --- |
| 1 | registration | `registration_evaluation_accepted` | `registration_evaluation_input_party_views_v1` |
| 2 | activation | `activation_continuation_accepted` | `activation_no_evaluation_input_party_views_v1` |
| 3 | recovery | `recovery_evaluation_accepted` | `recovery_evaluation_input_party_views_v1` |
| 4 | refresh | `refresh_evaluation_accepted` | `refresh_evaluation_input_party_views_v1` |
| 5 | export | `export_evaluation_accepted` | `export_evaluation_input_party_views_v1` |

Each case is a closed tagged object with this exact field order:

```text
request_kind
vector
```

Every `vector` has this exact field order:

```text
case_id
stage
host_only_source_references
common_public
role_extensions
static_deriver_observations
host_only_ideal_function_randomness
```

The JSON bytes are the UTF-8 result of the canonical Rust builder serialized
with `serde_json::to_vec_pretty`, followed by exactly one LF. The corpus domain
type is opaque and `Serialize`-only. Its parser accepts only the exact canonical
bytes. Unknown, missing, null, duplicated, or reordered fields; alternate union
shapes; BOMs; CRLF; whitespace drift; malformed or uppercase hex; and missing
or extra terminal newlines are invalid.

The normalized corpus representation defines one input-view evidence
projection as:

```text
corpus_view_evidence(role)
  = (vector.common_public, vector.role_extensions[role])
```

`common_public` occurs once per case to avoid copying the same public value
seven times. The core observed role view still owns its common value.
`host_only_source_references` and `host_only_ideal_function_randomness` are
verifier-only host evidence outside this equation and outside every role view.

### 10.2 Host-only source-reference shape

Registration, recovery, refresh, and export use this exact
`host_only_source_references` field order:

```text
ceremony_context_case_id
provenance_case_id
semantic_lifecycle_case_id
output_party_view_case_id
```

The exact attachment identities are:

| Request | Ceremony | Provenance | Semantic lifecycle | Output party view |
| --- | --- | --- | --- | --- |
| registration | `ceremony-registration-v1` | `registration_provenance_outer_v1` | `registration_semantic_artifacts_output_committed_v1` | `registration_output_party_views_package_prepared_v1` |
| recovery | `ceremony-recovery-v1` | `recovery_provenance_outer_v1` | `recovery_semantic_artifacts_output_committed_v1` | `recovery_output_party_views_package_prepared_v1` |
| refresh | `ceremony-refresh-v1` | `refresh_provenance_outer_v1` | `refresh_semantic_artifacts_output_committed_v1` | `refresh_output_party_views_package_prepared_v1` |
| export | `ceremony-export-v1` | `export_provenance_outer_v1` | `export_semantic_artifacts_host_reference_receipt_v1` | `export_output_party_views_released_v1` |

Activation uses this exact source-reference shape and order:

```text
semantic_lifecycle_case_id = activation_metadata_control_v1
output_party_view_case_id  = activation_output_party_views_metadata_consumed_v1
activation_origin          = registration
```

The source-reference object is not common public leakage. It names corpus rows
that an independent verifier must load. It contains no digest or private value
that a runtime role observes. The activation object omits ceremony and
provenance case ids because the generic ceremony fixture does not byte-match
the selected registration-origin continuation and activation performs no
provenance-bound evaluation.

### 10.3 Accepted-evaluation common-public shape

Registration, recovery, refresh, and export use this exact `common_public`
field order:

```text
stage
request_kind
evaluation_plan
public_request_context_digest_hex
authorization_digest_hex
transcript_digest_hex
input_provenance_pair_digest_hex
```

`stage` and `request_kind` equal the enclosing case. The three ceremony digests
and provenance-pair digest are exactly 32 lowercase-hex bytes and nonzero.

`evaluation_plan` has exact field order:

```text
kind
counts
```

`counts` has exact field order:

```text
yao_evaluations
deriver_a_invocations
deriver_b_invocations
contribution_derivations
ideal_output_share_samples
```

Registration, recovery, and refresh use
`kind = one_activation_evaluation` and integer counts `1,1,1,0,2` in that
order. Export uses `kind = one_export_evaluation` and counts `1,1,1,0,1`.

The independent verifier MUST load the named source attachments and derive the
narrow common value:

- ceremony supplies the public request, authorization, and transcript digests;
- provenance supplies the ordered A/B pair digest and repeats that ceremony
  digest triple;
- semantic lifecycle repeats the ceremony and provenance bindings and supplies
  the later one-use and registered-state continuity checks; and
- output party view supplies the coherent later public/output projection used
  to check the private input arithmetic and separate fixture coins.

Any disagreement among those attachments or the copied common value is
invalid. Circuit family/id, synthetic final-circuit and input-schema digests,
client-envelope-set digest, transport/artifact-suite values, one-use execution
id, registered key, and output values remain in the named companions. They
MUST NOT be copied into this narrow `common_public` object.

### 10.4 Activation common-public shape

Activation uses this exact `common_public` field order:

```text
stage
request_kind
evaluation_plan
public_request_context_digest_hex
authorization_digest_hex
transcript_digest_hex
```

The fixed values are:

```text
stage        = activation_continuation_accepted
request_kind = activation
```

`evaluation_plan` is:

```text
kind = zero_evaluation_continuation

counts:
  yao_evaluations             = 0
  deriver_a_invocations       = 0
  deriver_b_invocations       = 0
  contribution_derivations    = 0
  ideal_output_share_samples  = 0
```

The plan and counts use the field orders frozen in Section 10.3.

The three digest fields are exactly 32 lowercase-hex bytes and nonzero. They
MUST equal the activation-control digest triple in the registration-origin
entry of both named companions. `common_public` has no provenance-pair digest,
origin aggregate, package identity, registered key, circuit field, or private
input.

### 10.5 Role-extension container

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

Every extension is a closed object beginning with `kind`.

Registration, recovery, and refresh use:

```text
deriver_a:
  kind = deriver_a_activation_evaluation_inputs
  y_client_hex
  y_server_hex
  tau_client_hex
  tau_server_hex

deriver_b:
  kind = deriver_b_activation_evaluation_inputs
  y_client_hex
  y_server_hex
  tau_client_hex
  tau_server_hex

client:
  kind = client_empty

signing_worker:
  kind = signing_worker_empty

router:
  kind = router_empty

observer:
  kind = observer_empty

diagnostics_logs:
  kind = diagnostics_empty
```

The nonempty object field order is `kind`, `y_client_hex`, `y_server_hex`,
`tau_client_hex`, `tau_server_hex`. Every value is exactly 32 lowercase-hex
bytes. Each `tau` is canonical modulo `l`.

Activation uses seven one-field objects:

```text
deriver_a.kind        = deriver_a_empty
deriver_b.kind        = deriver_b_empty
client.kind           = client_empty
signing_worker.kind   = signing_worker_empty
router.kind           = router_empty
observer.kind         = observer_empty
diagnostics_logs.kind = diagnostics_empty
```

Export uses:

```text
deriver_a:
  kind = deriver_a_export_evaluation_inputs
  y_client_hex
  y_server_hex

deriver_b:
  kind = deriver_b_export_evaluation_inputs
  y_client_hex
  y_server_hex

client:
  kind = client_empty

signing_worker:
  kind = signing_worker_empty

router:
  kind = router_empty

observer:
  kind = observer_empty

diagnostics_logs:
  kind = diagnostics_empty
```

The nonempty export field order is `kind`, `y_client_hex`, `y_server_hex`.
No export object contains a `tau` field.

### 10.6 Static Deriver observation evidence

Every `static_deriver_observations` object has exactly these keys in this order:

```text
deriver_a
deriver_b
```

Each observation has exact field order:

```text
observation_kind
source_case_id
source_stage
extension
```

The exact observation strings are:

```text
deriver_a = static_consuming_deriver_a_evaluation_inputs
deriver_b = static_consuming_deriver_b_evaluation_inputs
```

`source_case_id` and `source_stage` equal the enclosing vector. Each `extension`
is byte-for-byte equal as a JSON value to the matching `role_extensions` entry
and contains no peer field. A and B observations come from separate
deterministic rebuilds because one Rust validated view set is consumed by one
static observation.

The JSON establishes exact projected shapes and cross-links. Rust compile-fail
and move-semantics tests establish that one set cannot yield both observations,
that a runtime role selector is absent, and that an observed view exposes no
peer extension or private aggregate.

### 10.7 Host-only ideal-function randomness

This final vector field is verifier-only host evidence. It is outside
`common_public`, outside `role_extensions`, outside static observations, and
outside the normalized party-view equation.

Registration, recovery, and refresh use this exact shape and order:

```text
kind = activation_family_output_sharing_coins
client_scalar_coin_hex
signing_worker_scalar_coin_hex
```

Both coins are canonical little-endian scalars modulo `l`. The canonical
coherent semantic/output-party fixture uses:

```text
client_scalar_coin_hex =
  0300000000000000000000000000000000000000000000000000000000000000

signing_worker_scalar_coin_hex =
  0500000000000000000000000000000000000000000000000000000000000000
```

Activation uses the sealed one-field shape:

```text
kind = activation_no_ideal_function_randomness
```

Export uses this exact shape and order:

```text
kind = export_seed_output_coin
seed_output_coin_hex
```

The canonical coherent export fixture uses:

```text
seed_output_coin_hex =
  7777777777777777777777777777777777777777777777777777777777777777
```

The independent verifier applies these values to the equations in Section 7
and requires the results to equal the role outputs in the named output-party
case. `output-sharing-v1.md` is the relation and distribution authority. No
existing output-sharing corpus case uses this exact coherent input/coin tuple,
so this corpus MUST NOT include or imply an `output_sharing_case_id` cross-link.

### 10.8 Forbidden keys, paths, and values

The corpus recursively rejects these exact keys anywhere in `common_public`,
`role_extensions`, or `static_deriver_observations`:

```text
client_root_hex
deriver_a_root_hex
deriver_b_root_hex
recovered_client_root_hex
role_root_hex
root_hex
refresh_delta_y_hex
refresh_delta_tau_hex
joined_y_hex
joined_tau_hex
joined_seed_hex
seed_hex
d_hex
sha512_digest_hex
clamped_scalar_bytes_hex
signing_scalar_hex
x_client_base_hex
x_server_base_hex
client_scalar_share_hex
signing_worker_scalar_share_hex
seed_share_hex
client_scalar_coin_hex
signing_worker_scalar_coin_hex
seed_output_coin_hex
host_only_source_references
host_only_ideal_function_randomness
credential_hex
recovery_envelope_hex
client_envelope_plaintext_hex
garbling_seed_hex
label_hex
mask_hex
ot_state_hex
recipient_decryption_key_hex
ciphertext_bytes_hex
```

Keys ending in `_root`, `_root_hex`, `_coin_hex`, `_output_share_hex`,
`_private_key_hex`, or `_decryption_key_hex` are also forbidden in those three
view-bearing containers. The exact coin keys are permitted only under the final
`vector.host_only_ideal_function_randomness` object in the stage-appropriate
shape. The final object cannot contain any party input, joined value, output
share, or protocol-randomness field.

The only permitted synthetic private input paths are:

- activation-family A/B `y_client_hex`, `y_server_hex`, `tau_client_hex`, and
  `tau_server_hex`;
- export A/B `y_client_hex` and `y_server_hex`; and
- the duplicate matching A/B values inside that role's static observation.

The verifier MUST derive the known synthetic roots, joined `y`, joined `tau`,
seed `d`, SHA-512 digest, clamped bytes, signing scalar, joined Client and
SigningWorker scalars, refresh deltas, output shares, and host clear-trace
values used by the canonical builders. It rejects those exact byte strings at
every path unless the bytes are also an exact role input at one of the permitted
paths above. It separately permits only the three fixed coins at their exact
host-only randomness paths.

Public digests, public keys, and public Edwards points are outside the
forbidden-value scan. Exact closed object shapes remain authoritative; recursive
name and value checks supplement them.

### 10.9 Required independent-verifier checks

Rust and an independent implementation MUST:

- require exact canonical bytes, headers, case ids, case order, stage tags,
  field order, and closed branch shapes;
- cross-link the four producing cases to their exact ceremony, provenance,
  semantic-lifecycle, and output-party attachments;
- cross-link the activation case to the registration-origin semantic and
  output-party projections without claiming a false `ceremony-activation-v1`
  byte match;
- derive every plan and count from the stage;
- enforce unregistered versus registered public pre-state disjointness;
- validate all activation-family `tau` encodings;
- reproduce the activation and export input arithmetic;
- require A/B input ownership and the seven closed role extensions;
- require activation to contain zero inputs and zero counts;
- require export to contain `y` inputs only;
- apply the separate host-only coins, reproduce output sharing, and compare the
  result with the coherent output-party attachment;
- reproduce both static observations from separate consuming fixture rebuilds;
  and
- reject forbidden keys, forbidden values, peer injection, common-public drift,
  plan drift, role swaps, source-label swaps, stage/family splicing, and a coin
  moved into any view.

Passing these checks establishes deterministic host-reference input custody,
arithmetic coherence, and cross-language shape evidence over synthetic
material. It establishes no privacy or entropy property for a deployed run.

## 11. Required negative evidence and mutation matrix

Implementations MUST include compile-time or focused runtime rejection evidence
for:

- constructing a core view or validated set through a public field literal;
- cloning or serializing the validated set or a core private input extension;
- observing A and B from one consumed set;
- returning a runtime-selected Deriver extension;
- inserting B input into an A view or A input into a B view;
- swapping `y_client` with `y_server` or `tau_client` with `tau_server`;
- replacing a canonical `tau` with `l`, `l + 1`, or another noncanonical
  encoding;
- adding a `tau`, scalar slot, seed, or generic payload to export;
- deleting either required export `y` field;
- adding any private input or nonzero count to activation;
- changing a plan kind or any one of its five derived counts;
- changing a ceremony/provenance/semantic/output-party case id or copied digest;
- changing the one-use execution id, envelope-set digest, or provenance-pair
  digest;
- changing the registered key on recovery, refresh, export, or any activation
  origin;
- giving registration a registered pre-state or a registered branch an
  unregistered pre-state;
- moving an ideal-function coin under common public, a role extension, or a
  static observation;
- changing a coin without changing the linked output, or changing the output
  while retaining the coin;
- adding a root, refresh delta, joined value, output share, protocol coin,
  label, mask, OT state, ciphertext plaintext, or decryption key to a view;
- duplicating a peer extension inside a static observation;
- changing common public leakage between independently rebuilt role views;
- accepting unknown, missing, null, duplicate, reordered, or optional fields;
  and
- treating the synthetic corpus DTO as a production wire, persistence, or log
  schema.

Canonical-JSON mutation tests MUST cover at least one example of every class
above that is representable in JSON. Rust compile-fail or source-surface tests
must cover the ownership, constructor, Serde, and static-observation guards.

## 12. Formal-verification obligations

The construction-independent formal scaffold MUST model closed `Stage`,
`Party`, `RequestKind`, `EvaluationPlan`, and input-value classes. Its first
proof layer establishes structural policy facts only:

| Obligation | Required statement |
| --- | --- |
| `YAO-EINPUT-001` | the five stages are exhaustive and disjoint |
| `YAO-EINPUT-002` | every stage has exactly seven role projections |
| `YAO-EINPUT-003` | A's projection contains no B input class |
| `YAO-EINPUT-004` | B's projection contains no A input class |
| `YAO-EINPUT-005` | Client, SigningWorker, Router, Observer, and Diagnostics/logs have no private evaluation input |
| `YAO-EINPUT-006` | activation has no private input and the zero plan |
| `YAO-EINPUT-007` | export admits `y` input classes and excludes every `tau` class |
| `YAO-EINPUT-008` | ideal-function output coins occur outside all party views |
| `YAO-EINPUT-009` | each stage determines one plan family and exact counts |
| `YAO-EINPUT-010` | static A/B observation yields one role extension and cannot yield the peer extension |
| `YAO-EINPUT-011` | registration has only the unregistered pre-state; recovery, refresh, and export have only registered pre-state |
| `YAO-EINPUT-012` | activation-family and export input families cannot be confused |

Lean theorems may prove the finite policy model above. Verus contracts may
prove canonical-domain checks, plan derivation, arithmetic identities, and
consuming ownership for the Rust host model. Neither tool may introduce
`axiom`, `sorry`, `admit`, or an uninterpreted theorem that asserts the desired
security conclusion.

Computational noninterference, real/ideal simulation, selective-failure
resistance, active input consistency, coin uniformity, and erasure remain later
selected-profile obligations. A finite structural theorem cannot be cited as
evidence for those properties.

## 13. Explicit nonclaims and blockers

This companion supplies no evidence for:

- authenticated production roots, role-input records, epochs, provenance
  artifacts, proofs, or authorization records;
- authority of the synthetic final-circuit or input-schema digests;
- production entropy, unbiased or distributed coin generation, independence,
  unpredictability, or erasure;
- constant-time processing of production secrets;
- garbling, oblivious transfer, streaming, preprocessing tickets, labels,
  masks, protocol frames, or frame-level leakage;
- evaluator-input consistency, garbler correctness, output authentication,
  anti-equivocation, selective-failure resistance, or uniform detectable abort;
- complete runtime party views, delivery, retry/redelivery, abort timing,
  durable transition, or adaptive corruption behavior;
- recovery root custody and replacement-credential proof;
- refresh joint-delta generation, transition proof, promotion, cutover, or old-
  epoch retirement;
- recipient encryption, package opening, SigningWorker activation, or Client
  export delivery;
- passive, one-sided, malicious, or collusion security; or
- a P0, P1, P2, or P3 protocol-security claim.

The host builder, arithmetic checker, corpus projection, and static observations
operate on public synthetic material and may use variable-time arithmetic.
They cannot open Phase 1, Phase 2B, profile selection, SDK/Worker integration,
or release gates without the remaining selected-protocol, complete-party-view,
provenance, entropy, lifecycle, and deployment evidence.
