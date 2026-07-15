# Ed25519 Yao Refresh Evaluator Admission V1

Status: construction-independent host lifecycle semantics. This document
freezes one ideal refresh admission, one activation-family evaluation, and
exact retention of the admitted current/next-state authority through output
commitment, abort, SigningWorker activation, and refresh promotion. Production
delta proofs, contribution anti-bias, input opening, transport, durable
transactions, constant-time execution, and P0-P3 protocol security remain in
their owning later phases.

## 1. State machine

```text
AuthenticatedRegistered(currentState, activeStateVersion)
  -> AcceptedRefreshAdmission(
       currentState retained,
       proposed A/B next bindings fixed,
       terminalAdmission fixed
     )
       -> EvaluatorAborted(
            currentState retained,
            proposed transition non-promotable,
            terminalAdmission retained for audit,
            request/execution burned
          )
       -> OutputCommitted(
            currentState retained,
            proposed A/B next bindings fixed,
            terminalAdmission retained,
            exact receipt identity fixed
          )
            -> MetadataConsumed[zero private evaluation]
            -> RecipientsReleased
            -> StrictlyVerifiedRefreshWorkerActivation
            -> PreparedRefreshPromotion
            -> StrictStoreAuthorityVerification
            -> Active(nextState) + Retired(old A/B input-state epochs)
```

Admission changes no durable registered state. A pre-admission rejection
returns the unchanged authenticated store resolution. A post-admission
evaluator abort preserves the same registered-state projection and retains the
terminal proposal only as non-reusable audit authority. Promotion requires the
forward path through output commitment, activation delivery, and strictly
verified refresh-origin SigningWorker activation.

## 2. Inputs and two transition-evidence identities

The ideal relation consumes:

- one canonical refresh request, authorization, and transcript;
- one ordered A/B refresh provenance pair;
- one strictly verified request-bound registered-store resolution;
- one nonzero checked-at Unix timestamp;
- one strictly advancing next activation epoch;
- one nonzero one-use execution identity; and
- one nonzero selected-mechanism transition-acceptance evidence digest.

The next A/B role-state bindings and their epochs come from the sealed
provenance pair. Callers cannot supply independent next-role bindings or role
epochs at the admission boundary.

Two opaque transition-evidence identities remain distinct:

1. `continuity_evidence_artifact_digest` is the common opposite-delta
   transition artifact committed by both refresh provenance statements;
2. `selected_mechanism_acceptance_evidence_digest` records that the Phase
   6A-selected mechanism accepted that transition for this exact admission.

Phase 1 binds both identities. Phase 6B instantiates the second slot only after
the selected mechanism validates the first artifact, the actual private-input
openings, the role-local contribution relation, and every security property
required by the selected profile. A digest equality between the two slots is
neither required nor interpreted as proof.

The host-only ideal joint-delta coins remain evaluation inputs. Their role-local
values and combined delta never appear in the public admission encoding.

## 3. Admission checks

Admission succeeds only when:

1. request, authorization, transcript, provenance, and store resolution all
   name the refresh branch;
2. request-context, authorization, and transcript digests match across the
   ceremony DAG, ordered provenance pair, and signed store resolution;
3. the store authority signature, authority key epoch, authority key digest,
   durable identity, provenance-pair digest, active state version, and complete
   registered state have already passed strict store-resolution verification;
4. `checked_at_unix_ms <= request_expiry_unix_ms`;
5. the A and B provenance statements name the same stable scope, registered
   Ed25519 key, circuit binding, input schema, ceremony binding, and continuity
   artifact;
6. each role's before snapshot matches the authenticated current root record,
   root binding, root epoch, input-state record, and input-state epoch;
7. each role's after snapshot preserves its root record, root binding, and root
   epoch while its input-state epoch strictly advances;
8. the authorization's current A/B input-state epochs equal the authenticated
   store epochs;
9. the authorization's next A/B input-state epochs equal the corresponding
   provenance after-snapshot epochs;
10. `next_activation_epoch > current_activation_epoch`;
11. the one-use execution identity is nonzero; and
12. the selected-mechanism transition-acceptance evidence digest is nonzero.

The host admission is move-only. Its exact digest becomes the sole
`evaluation_evidence_digest` accepted by the refresh semantic context. No
refresh session entrypoint accepts an independently supplied raw evaluation-
evidence digest.

## 4. Canonical admission encoding

`LP32(x)` means `BE32(len(x)) || x`. The encoding contains exactly 37 LP32
fields: one domain, 35 body fields, and one accepted terminal tag. The exact
order is:

```text
RefreshEvaluatorAdmissionV1 =
    LP32("seams/router-ab/ed25519-yao/refresh-evaluator-admission/v1")
 || LP32(canonical_durable_identity_scope)
 || LP32(UTF8(request_id))
 || LP32(replay_nonce[32])
 || LP32(BE64(request_expiry_unix_ms))
 || LP32(BE64(checked_at_unix_ms))
 || LP32(request_context_digest[32])
 || LP32(authorization_digest[32])
 || LP32(transcript_digest[32])
 || LP32(ordered_provenance_pair_digest[32])
 || LP32(deriver_a_statement_digest[32])
 || LP32(deriver_b_statement_digest[32])
 || LP32(authenticated_store_resolution_signing_bytes_sha256[32])
 || LP32(BE64(store_authority_key_epoch))
 || LP32(store_authority_key_digest[32])
 || LP32(BE64(active_state_version))
 || LP32(active_credential_binding_digest[32])
 || LP32(registered_ed25519_public_key[32])
 || LP32(canonical_stable_scope)
 || LP32(BE64(current_activation_epoch))
 || LP32(BE64(next_activation_epoch))
 || LP32(BE64(current_deriver_a_input_state_epoch))
 || LP32(next_deriver_a_role_root_record_digest[32])
 || LP32(next_deriver_a_root_binding_artifact_digest[32])
 || LP32(BE64(next_deriver_a_role_root_epoch))
 || LP32(next_deriver_a_input_state_record_digest[32])
 || LP32(BE64(next_deriver_a_input_state_epoch))
 || LP32(BE64(current_deriver_b_input_state_epoch))
 || LP32(next_deriver_b_role_root_record_digest[32])
 || LP32(next_deriver_b_root_binding_artifact_digest[32])
 || LP32(BE64(next_deriver_b_role_root_epoch))
 || LP32(next_deriver_b_input_state_record_digest[32])
 || LP32(BE64(next_deriver_b_input_state_epoch))
 || LP32(provenance_continuity_evidence_artifact_digest[32])
 || LP32(selected_mechanism_acceptance_evidence_digest[32])
 || LP32(one_use_execution_id[32])
 || LP32(0x01) // accepted terminal tag
```

The 35 body fields begin with `canonical_durable_identity_scope` and end with
`one_use_execution_id`. Each proposed role binding is flattened into five
consecutive fields. No nested role-state encoding or role tag is inserted.
Deriver A's current epoch and complete proposed binding precede Deriver B's.

The admission digest is:

```text
SHA-256(
    LP32("seams/router-ab/ed25519-yao/refresh-evaluator-admission-digest/v1")
 || LP32(RefreshEvaluatorAdmissionV1)
)
```

No security-profile identifier, extension bag, retry counter, proof bytes,
delta bytes, role-local delta contributions, private input, ciphertext, joined
seed, private scalar, output share, or seed-output field appears.

## 5. One evaluation and output commitment

The accepted admission constructs one refresh semantic context and permits
exactly one activation-family evaluation. The existing host reference:

- consumes distinct move-owned A/B ideal delta contributions;
- derives the joint seed-domain and scalar-domain deltas internally;
- rejects a zero joint result in either domain;
- preserves all client contribution fields;
- applies the seed and scalar delta to Deriver A's server contributions;
- applies the exact inverse delta to Deriver B's server contributions; and
- checks complete joined-seed, joined-scalar, RFC 8032 derivation, public-point,
  and activation-output continuity.

The output-sharing relation samples ideal scalar coins and returns private
additive Client and SigningWorker shares. Refresh produces no seed output.

Before `RefreshPendingActivationV1` can be constructed, release-mode checks
require the committed artifacts to preserve exactly:

- refresh origin;
- request-context, authorization, and transcript digests;
- next activation epoch;
- one-use execution identity;
- admission digest as evaluation evidence; and
- authenticated registered Ed25519 public key.

The package set and committed receipt retain their existing internal digest,
public-point, recipient, and output-binding relations.

## 6. Ownership and retention

`TerminalRefreshEvaluationV1` owns:

- the canonical admission encoding and digest;
- every construction-independent admission binding;
- the unchanged authenticated current-state resolution; and
- the exact proposed A/B next-state bindings.

The same terminal value is moved through:

```text
RefreshArtifactSessionV1
  -> RefreshPendingActivationV1
  -> MetadataConsumedRefreshActivationV1
  -> ActivatedSigningWorkerOriginStateV1::Refresh
  -> refresh promotion preparation
  -> authenticated refresh promotion
```

Refresh promotion derives the old state and both proposed role bindings only
from this terminal authority. The signed promotion body transitively binds the
admission through the committed-output receipt digest, whose evaluation-
evidence field equals the admission digest. It also binds the strictly verified
worker activation receipt, complete old/next registered-state digests, both A/B
retirement edges, active-state versions, and durable transaction-receipt
digest.

Activation remains a metadata/control continuation. It consumes already
committed refresh-origin packages and performs zero private evaluations,
Deriver invocations, contribution derivations, or output-share samples.

## 7. Abort and retry

An evaluator failure emits the uniform public abort. Internally,
`FailedRefreshArtifactAttemptV1` owns:

- the exact terminal refresh admission;
- the unchanged authenticated current state and proposed transition contained
  by that terminal; and
- the burned request DAG and one-use execution identity.

The public persistence relation is a registered-state self-loop. The proposed
transition has no promotion entrypoint after abort. Recovering the terminal from
the private abort projection supplies audit identity only and cannot construct
another evaluator session.

A retry requires a fresh refresh request and replay nonce, a fresh request-bound
store resolution, a fresh one-use execution identity, a freshly accepted
selected-mechanism transition identity, and fresh ideal delta coins for the new
evaluation.
The previous terminal, request, execution identity, and role-local contributions
cannot be reused. Durable replay floors, contribution-attempt persistence,
crash-safe grinding prevention, atomic state promotion, and retirement writes
remain Phase 7 adapter obligations.

After output commitment, forward progress uses the exact committed package and
receipt identities. Delivery uncertainty and redelivery never trigger another
private evaluation or another delta sample.

## 8. Security scope

This host relation establishes exact ceremony/store/provenance binding,
request-expiry checking, strict activation and role-epoch advancement, sealed
current/next state authority, single-use ownership, one evaluation, release-
enforced output binding, and terminal retention through activation and
promotion.

It does not establish:

- validity of the opaque provenance continuity artifact;
- cryptographic relation between that artifact and the selected-mechanism
  acceptance-evidence digest;
- consistency between synthetic host contributions and production private
  openings;
- entropy or independence of role-local delta contributions;
- commitment correctness, anti-bias, selective-abort resistance, or retry-
  grinding resistance for delta generation;
- forward security, mobile-adversary healing, or secure erasure from refresh;
- durable replay prevention, global one-use uniqueness, database atomicity,
  rollback floors, retirement finality, or crash recovery;
- production opener, encryption, transport, delivery acknowledgement, or
  storage behavior;
- Yao privacy or malicious-party security under P0-P3; or
- production constant-time behavior.

The generator is intentionally variable-time public synthetic infrastructure.
Production constant-time analysis applies later to the selected secret-bearing
kernel.

## 9. Executable evidence

The expected strict one-case corpus is:

```text
vectors/ed25519-yao-refresh-evaluator-admission-v1.json
```

It must contain the exact store-authority verifying key, signature, signed
resolution bytes and digest, current and proposed role-state bindings, both
transition-evidence identities, admission bytes and digest, output-committed
receipt, burned-attempt/retry relation, and source cross-links to the refresh
ceremony, provenance, evaluation-input views, semantic lifecycle, output views,
activation delivery, activation recipient views, evaluator-abort semantics, and
refresh-promotion specification. Secret contributions, delta values, output
shares, selected-profile proof bytes, and transport frames remain absent.

The closure target is:

- eight focused core Rust tests for canonical success, expiry, zero values,
  stale activation epoch, provenance/identity splicing, selected-evidence
  binding, arithmetic-failure burn/retention, and source exclusions;
- one compile-fail doctest proving move-only admission;
- five strict Rust corpus and CLI tests;
- seven independent Python reproduction and mutation tests; and
- twelve Lean structural theorems covering binding, terminal ownership,
  success/abort retention, and promotion gating.

Once those artifacts are attached to generated-spec drift checks and the formal
evidence baseline, they are expected to close `YAO-SPEC-024` and
`YAO-RFR-002`. The Lean model establishes structural state and ownership facts.
It supplies no cryptographic, noninterference, randomness-security,
constant-time, or selected-profile protocol proof.
