# Registration Evaluator Admission V1

Status: normative construction-independent host-reference contract.

This document freezes the Phase 1 registration evaluator relation. It defines
one sealed admission capability, one terminal input-selection identity, one
activation-family evaluation, and one move-owned candidate registered identity.
It does not instantiate a production input-selection mechanism or prove that a
durable store contains no registered key.

## 1. Required state chain

```text
canonical registration request
  + ordered A/B registration provenance pair
  + checked admission time
  + first activation epoch
  + one-use execution identity
  + terminal selection-attempt identity
  + opaque selected-mechanism acceptance evidence
    -> accepted registration admission
    -> one registration evaluation
       -> output committed registration candidate
       -> evaluation abort with unregistered public state and terminal selection retained
    -> activation metadata consumption with candidate retained
    -> verified SigningWorker activation with candidate retained for promotion
```

The accepted admission and every later state in this chain are move-owned. They
are neither `Clone` nor `Copy`. Pre-evaluation rejection returns the request and
complete issuance authority. Post-admission evaluation failure burns the request
and execution identity.

## 2. Construction-independent admission boundary

Phase 1 models an already accepted ideal relation. The public constructor
validates call-local coherence and produces a sealed capability. Phase 6B must
replace the caller's opaque selected-mechanism evidence with verification of the
chosen deployment mechanism. Phase 7 must provide durable absence, reservation,
global replay, rollback, crash-recovery, and atomic-promotion semantics.

The field named `unregistered_public_identity_scope` is the immutable public
wallet/key scope copied from the registration request. It is not an absence
proof. Phase 1 may prove that the evaluator's public lifecycle class is
`Unregistered`; it may not prove that no concurrent or previously registered
key exists in production storage.

## 3. Admission checks

Admission succeeds only when:

- the request kind is registration;
- the provenance pair commits the exact request-context, authorization, and
  transcript digests from the sealed ceremony DAG;
- the registration intent in authorization exactly equals the intent in both
  provenance statements;
- `checked_at_unix_ms` is nonzero and no later than request expiry;
- the activation epoch, execution ID, selection-attempt ID, and selected-
  mechanism acceptance evidence are nonzero and purpose typed;
- all canonical encodings fit the V1 LP32 length bound.

The accepted capability is revalidated against the request, provenance pair,
activation epoch, and execution ID when the evaluator session is created.

## 4. Evidence identities

Registration admission commits two distinct evidence identities:

1. `provenance_input_selection_artifact_digest` is the opaque artifact digest
   committed identically by the A and B provenance statements;
2. `selected_mechanism_acceptance_evidence_digest` is the opaque Phase 6B slot
   asserting that the selected mechanism accepted the provenance artifact and
   fixed selection attempt.

Phase 1 binds both values. It assumes the second witnesses acceptance of the
first. It does not verify their cryptographic relation. A production security
claim requires the Phase 6B verifier, its exact wire artifacts, and the selected
P0-P3 profile review.

## 5. Canonical admission encoding

The admission encoding is LP32 in this exact order:

1. `seams/router-ab/ed25519-yao/registration-evaluator-admission/v1`;
2. canonical durable public identity-scope encoding;
3. request ID;
4. replay nonce;
5. request expiry as BE64 Unix milliseconds;
6. checked-at time as BE64 Unix milliseconds;
7. request-context digest;
8. authorization digest;
9. transcript digest;
10. registration-intent digest;
11. ordered provenance-pair digest;
12. Deriver A provenance-statement digest;
13. Deriver B provenance-statement digest;
14. canonical stable-KDF-scope encoding;
15. provenance input-selection artifact digest;
16. ordered Client-envelope-set digest;
17. Deriver A role-root record digest;
18. Deriver A root-binding artifact digest;
19. Deriver A root epoch as BE64;
20. Deriver A input-state record digest;
21. Deriver A input-state epoch as BE64;
22. Deriver B role-root record digest;
23. Deriver B root-binding artifact digest;
24. Deriver B root epoch as BE64;
25. Deriver B input-state record digest;
26. Deriver B input-state epoch as BE64;
27. first activation epoch as BE64;
28. one-use execution ID;
29. selection-attempt ID;
30. selected-mechanism acceptance evidence digest;
31. accepted-selection tag `0x01`.

The admission digest is SHA-256 over LP32:

1. `seams/router-ab/ed25519-yao/registration-evaluator-admission-digest/v1`;
2. exact admission encoding.

This digest occupies every activation package's semantic evaluation-evidence
field and the output-committed receipt's evaluation-evidence field.

## 6. Evaluator rule

The admitted evaluator uses the activation family and performs exactly:

- one Yao evaluation;
- one Deriver A invocation;
- one Deriver B invocation;
- zero additional contribution derivations inside the circuit;
- two ideal scalar-output share samples.

The host evaluator checks that the supplied synthetic stable context equals the
stable scope committed at admission. Raw synthetic roots remain a host-fixture
boundary. Phase 1 does not claim that opaque root records authenticate those raw
roots; the Phase 6B input-opening verifier owns that relation.

The evaluation applies `d -> SHA-512(d) -> clamp -> a` contribution arithmetic,
derives the joined Client and SigningWorker points, and establishes exactly one
nonidentity registered Ed25519 public key satisfying
`2 * X_client - X_server = A_pub`. Registration has no seed output.

## 7. Candidate state

Successful output commitment creates one `RegistrationCandidateStateV1`. Its
canonical encoding is LP32:

1. `seams/router-ab/ed25519-yao/registration-candidate-state/v1`;
2. every construction-independent common admission field in Section 5 through
   the one-use execution ID;
3. selection-attempt ID;
4. selected-mechanism acceptance evidence digest;
5. admission digest;
6. established registered Ed25519 public key;
7. output-committed receipt digest.

The candidate digest is SHA-256 over LP32:

1. `seams/router-ab/ed25519-yao/registration-candidate-state-digest/v1`;
2. exact candidate encoding.

Before candidate construction, release-enforced checks compare the committed
artifact's request kind, request-context digest, authorization digest,
transcript digest, activation epoch, execution ID, and evaluation-evidence
digest with the terminal admission. A mismatch enters the uniform evaluator-
failure path and retains the terminal selection.

The candidate retains the typed public identity scope, registration intent,
stable scope, initial A/B role-state bindings, first activation epoch, execution
identity, and terminal selection. It moves unchanged through pending activation,
activation metadata consumption, and verified SigningWorker activation. Initial
credential authority, initial registered-store version, and durable promotion
are later boundary inputs.

## 8. Abort and retry

An admitted evaluator failure produces the uniform public abort and the public
state-class transition `Unregistered -> Unregistered`. Internally it retains:

- the burned request-context, authorization, transcript, and one-use execution
  identity;
- the exact terminal selection, including all typed common admission fields;
- the admission digest and selected-mechanism evidence identity.

The accepted selection is terminal. Retry requires a fresh request/execution
ceremony and may not resample another candidate under the retained selection.
Phase 1 proves ownership and local state retention. Durable enforcement across
processes and crashes is a Phase 7 obligation.

## 9. Security and constant-time boundary

The host generator uses deterministic fixture material and variable-time host
arithmetic. It is excluded from production dependency closures. This contract
provides no production constant-time evidence.

Its structural claims depend on Rust ownership, canonical LP32 encoding, and
SHA-256 collision resistance. It excludes authenticated store absence, durable
uniqueness, global replay protection, trusted clock sourcing, input-opening
consistency, anti-bias security, signatures, proofs, recipient encryption,
transport authentication, production randomness, and P0-P3 protocol security.

The constant-time analyzer applies later to the selected production evaluator,
opener, and secret-bearing circuit kernel. Running it over this variable-time
fixture generator would not establish a production claim.

## 10. Canonical corpus

`vectors/ed25519-yao-registration-evaluator-admission-v1.json` contains one
canonical successful case named
`registration_admitted_evaluation_output_committed_v1`. It commits exact
admission and candidate bytes/digests, both evidence identities, the checked-at
time, fixed evaluation counts, registered public key, package-set and receipt
identities, terminal retry rule, explicit nonclaims, and source links to the
registration ceremony, provenance, evaluation-input, semantic-lifecycle,
output-party-view, activation-delivery, activation-recipient-party-view, and
evaluator-abort corpora.

The independent verifier reconstructs both domain-separated hashes and all
cross-field identities. Mutation tests reject schema/order drift, request and
scope splices, intent and provenance splices, selection/epoch/execution splices,
output and receipt splices, forbidden construction-specific fields, and retry
resampling.
