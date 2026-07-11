# Ed25519 Yao Evaluator-Abort State And Party Views V1

## 1. Scope

This document freezes the construction-independent host semantics after an
admitted registration, recovery, refresh, or export evaluation fails before
`OutputCommitted`.

It owns:

- branch-typed retention of the pre-evaluation lifecycle state;
- one burned request and one-use execution identity;
- the exact uniform public abort envelope; and
- seven common-only abort views for Deriver A, Deriver B, Client,
  SigningWorker, Router, observer, and diagnostics.

It does not freeze a production persistence record, transport frame, timeout,
ticket encoding, security profile, or distributed transaction.

## 2. State relation

Every admitted evaluation failure burns the request and the one-use execution
identity. The request is not returned for retry.

The state relation is:

```text
registration: Unregistered -> Unregistered
recovery:     CredentialSuspended(s) -> CredentialSuspended(s)
refresh:      Registered(s) -> Registered(s)
export:       Registered(s) -> Registered(s)
```

For recovery, `before()` and `after()` return the same authenticated credential-
suspended state; the old credential cannot return to ordinary signing admission.
Refresh and export retain the same `RegisteredLifecyclePreStateV1`. Refresh has
no promotable next state after failure. Export releases no seed and consumes no
success output.

The four failure-retention types are distinct:

```text
FailedRegistrationArtifactAttemptV1
FailedRecoveryArtifactAttemptV1
FailedRefreshArtifactAttemptV1
FailedExportArtifactAttemptV1
```

Their corresponding `ArtifactEvaluationFailureV1<T>` types cannot be passed to
another branch's persistence constructor.

`BurnedArtifactAttemptV1` retains the request kind, request-context digest,
authorization digest, transcript digest, and one-use execution identifier for
crate-owned host audit handling. These fields are not added to the public abort
or party views.

## 3. Public abort and role views

Every role receives exactly `HostOnlyPublicAbortViewV1`, containing one
`UniformLifecycleAbortV1`:

```text
request_kind
public_transcript_digest
public_failure_code = rejected
terminal = aborted
```

No role view adds a private extension. In particular, no evaluator-abort view
contains a contribution, input, output share, scalar, seed, package plaintext,
peer frame, semantic failure cause, suspected role, or blame label.

The host API exposes separate consuming observation methods for all seven
roles. It has no runtime role-selector argument and cannot project two role
views from one moved set.

The semantic failure cause retained by `ArtifactEvaluationFailureV1<T>` remains
crate-private and is absent from its `Debug` output.

## 4. Canonical host corpus

The committed file is:

```text
vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json
```

Its identifiers are:

```text
schema = seams:router-ab:ed25519-yao:evaluator-abort-state-party-views:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_evaluator_abort_state_party_views_v1
```

The case order is registration, recovery, refresh, export. Activation performs
no evaluator work and remains covered by the uniform-abort and activation
metadata-rejection contracts.

Every case has exact top-level key order:

```text
request_kind
source_ceremony_case_id
persistence
party_views
```

`persistence` has exact key order:

```text
pre_state_class
transition
burned_attempt
public_abort
```

The transition is always `self_loop`. Registration has pre-state class
`unregistered`, recovery uses `credential_suspended`, and refresh/export use
`registered`.

`burned_attempt` has exact key order:

```text
request_kind
request_context_digest_hex
authorization_digest_hex
transcript_digest_hex
one_use_execution_id_hex
```

The first four values cross-link to the named ceremony case. The one-use
execution identifier is nonzero and case-specific. The burned transcript
digest equals the public abort transcript digest.

`party_views` has exact serialized key order:

```text
deriver_a
deriver_b
client
signing_worker
router
observer
diagnostics
```

Every value is byte-for-byte the case's `public_abort` object.

The corpus is pretty JSON with LF line endings and exactly one trailing LF.
Unknown, missing, reordered, duplicate, or optional fields are rejected by
exact canonical-byte comparison.

## 5. Required evidence

Rust and an independent verifier must establish:

- the exact four-case order, schema, scope, and canonical bytes;
- ceremony cross-links for every burned and public transcript digest;
- one nonzero, case-specific burned execution identity;
- the unregistered/credential-suspended/registered pre-state-class table;
- a self-loop transition for every case;
- exact equality of all seven role views with the public abort;
- absence of private output, failure-cause, frame, and blame-bearing fields;
- branch-specific failure-retention and persistence-constructor types; and
- consuming static role observation without a runtime role selector.

## 6. Explicit nonclaims

This contract supplies no evidence for:

- production storage bytes or authenticated durable state;
- actual session or preprocessing-ticket destruction;
- transport framing, delivery, timeout, cancellation, or disconnect behavior;
- equality of success and failure timing;
- independence of failure behavior from protected inputs;
- selective-failure resistance or malicious-Deriver attribution;
- memory erasure, crash recovery, replay admission, or retry coordination; or
- P0, P1, P2, or P3 correctness-with-abort or protocol security.

Those claims remain blocked until Phase 6A selects one coherent profile and
Phase 6B freezes its frame graph, state machine, encodings, and adversary games.
