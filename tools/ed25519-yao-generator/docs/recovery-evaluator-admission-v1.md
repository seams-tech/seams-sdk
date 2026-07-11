# Ed25519 Yao Recovery Evaluator Admission V1

Status: construction-independent host lifecycle semantics. This document
freezes one ideal recovery admission, one activation evaluation, and exact
retention of the admitted authority through output commitment, abort,
SigningWorker activation, and recovery promotion. It defines no production
same-root proof, input opener, transport, durable transaction, constant-time
claim, or P0-P3 protocol security claim.

## 1. State machine

```text
AuthenticatedRegistered(oldCredential, activeStateVersion)
  -> AcceptedRecoveryAdmission(
       oldCredential suspended,
       replacementCredential fixed,
       terminalAdmission fixed
     )
       -> EvaluatorAborted(
            oldCredential remains suspended,
            terminalAdmission retained,
            request/execution burned
          )
       -> OutputCommitted(
            oldCredential remains suspended,
            terminalAdmission retained,
            exact receipt identity fixed
          )
            -> MetadataConsumed[zero private evaluation]
            -> RecipientsReleased
            -> StrictlyVerifiedRecoveryWorkerActivation
            -> PreparedRecoveryPromotion
            -> StrictStoreAuthorityVerification
            -> Active(replacementCredential) + Tombstone(oldCredential)
```

Admission is the old-credential suspension boundary. Every check in section 3
passes before `AuthenticatedRecoveryCredentialSuspensionV1` is constructed. A
pre-admission rejection returns the unchanged authenticated registered state.
No post-admission transition restores the old credential to active state.

## 2. Inputs and two evidence identities

The ideal relation consumes:

- one canonical recovery request, authorization, and transcript;
- one ordered A/B recovery provenance pair;
- one strictly verified request-bound registered-store resolution;
- one nonzero checked-at Unix timestamp;
- one strictly advancing activation epoch;
- one nonzero one-use execution identity; and
- one nonzero selected-mechanism recovery-acceptance evidence digest.

Two opaque evidence identities remain distinct:

1. `same_root_evidence_artifact_digest` is committed by both recovery
   provenance statements;
2. `selected_mechanism_acceptance_evidence_digest` records that the Phase
   6A-selected mechanism accepted the first artifact for this admission.

Phase 1 binds both values. It does not verify their cryptographic relation.
Phase 6B must instantiate the second slot only after its reviewed mechanism has
validated the first artifact and the actual private-input opening relation.

## 3. Admission checks

Admission succeeds only when:

1. request, authorization, transcript, provenance, and store resolution all
   name the recovery branch;
2. the request-context, authorization, and transcript digests match across the
   ceremony DAG, provenance pair, and signed store resolution;
3. the store authority signature, authority key epoch, authority key digest,
   durable identity, provenance-pair digest, active state version, and complete
   registered state have already passed strict store-resolution verification;
4. `checked_at_unix_ms <= request_expiry_unix_ms`;
5. the A and B provenance statements name the same registered Ed25519 key,
   stable scope, envelope set, and same-root artifact;
6. every A/B root record, root binding, root epoch, input-state record, and
   input-state epoch matches the authenticated registered state;
7. the authorization fixes a replacement credential distinct from the active
   credential;
8. `next_activation_epoch > current_activation_epoch`;
9. the one-use execution identity is nonzero; and
10. the selected-mechanism acceptance-evidence digest is nonzero.

The host admission type is move-only. Its exact digest becomes the sole
`evaluation_evidence_digest` accepted by the recovery semantic context. The old
API that accepted an arbitrary raw recovery evaluation-evidence digest does not
exist.

## 4. Canonical admission encoding

`LP32(x)` means `BE32(len(x)) || x`. The exact encoding is:

```text
RecoveryEvaluatorAdmissionV1 =
    LP32("seams/router-ab/ed25519-yao/recovery-evaluator-admission/v1")
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
 || LP32(replacement_credential_binding_digest[32])
 || LP32(registered_ed25519_public_key[32])
 || LP32(canonical_stable_scope)
 || LP32(provenance_same_root_evidence_artifact_digest[32])
 || LP32(selected_mechanism_acceptance_evidence_digest[32])
 || LP32(BE64(current_activation_epoch))
 || LP32(BE64(next_activation_epoch))
 || LP32(one_use_execution_id[32])
 || LP32(0x01) // accepted terminal tag
```

The admission digest is:

```text
SHA-256(
    LP32("seams/router-ab/ed25519-yao/recovery-evaluator-admission-digest/v1")
 || LP32(RecoveryEvaluatorAdmissionV1)
)
```

No security-profile identifier, extension bag, retry counter, proof bytes,
ciphertext bytes, private root, joined seed, or private scalar appears.

## 5. One evaluation and output commitment

The accepted admission constructs one recovery semantic context and permits
exactly one activation-family evaluation. Before private host arithmetic, the
supplied `StableKeyDerivationContext` must encode the admitted stable scope.
The existing recovery reference then enforces:

- current and recovered logical client roots are equal;
- current A/B client contributions match deterministic derivation under that
  stable context;
- recovered A/B client contributions are rederived from the same root;
- A/B server contributions remain unchanged; and
- every before/after activation arithmetic field is equal.

The output-sharing relation samples two ideal scalar coins and returns private
additive Client and SigningWorker shares. It returns no seed.

Before `RecoveryPendingActivationV1` can be constructed, release-mode checks
require the committed artifacts to preserve exactly:

- recovery origin;
- request-context, authorization, and transcript digests;
- next activation epoch;
- one-use execution identity;
- admission digest as evaluation evidence; and
- authenticated registered Ed25519 public key.

The package set and committed receipt already enforce their internal digest,
public-point, recipient, and output-binding relations.

## 6. Ownership and retention

`TerminalRecoveryEvaluationV1` owns:

- the canonical admission encoding and digest;
- every construction-independent admission binding;
- the authenticated credential suspension; and
- the exact old-to-replacement continuity evidence.

The same terminal value is moved through:

```text
RecoveryArtifactSessionV1
  -> RecoveryPendingActivationV1
  -> MetadataConsumedRecoveryActivationV1
  -> ActivatedSigningWorkerOriginStateV1::Recovery
  -> recovery promotion preparation
  -> authenticated recovery promotion
```

Promotion borrows the suspension through this terminal authority. The signed
promotion body transitively binds the admission through the committed-output
receipt digest, whose evaluation-evidence field equals the admission digest.

## 7. Abort and retry

An evaluator failure produces one uniform public abort. Internally,
`FailedRecoveryArtifactAttemptV1` owns:

- the exact terminal recovery admission;
- the exact authenticated credential suspension; and
- the burned request DAG and one-use execution identity.

The public state is a credential-suspended self-loop. A retry requires fresh
recovery authorization, a fresh request-bound store resolution, and a fresh
one-use execution identity. It cannot reuse the terminal admission. Durable
suspension and replay enforcement remain Phase 7 adapter obligations.

## 8. Security scope

This host relation establishes exact ceremony/store/provenance binding,
request-expiry checking, distinct replacement authority, typed suspension,
single-use ownership, one evaluation, release-enforced output binding, and
terminal-authority retention through the existing activation and promotion
state machines.

It does not establish:

- validity of the opaque same-root artifact;
- cryptographic relation between that artifact and the selected-mechanism
  acceptance-evidence digest;
- consistency between synthetic host inputs and production private openings;
- durable suspension, global replay prevention, global one-use uniqueness,
  database atomicity, rollback floors, or crash recovery;
- root custody, root availability, or compromise classification;
- production opener, encryption, transport, delivery acknowledgement, or
  storage behavior;
- Yao privacy or malicious-party security under P0-P3; or
- production constant-time behavior.

The generator is intentionally variable-time public synthetic infrastructure.
Production constant-time analysis applies later to the selected secret-bearing
kernel.

## 9. Executable evidence

The strict one-case corpus
`vectors/ed25519-yao-recovery-evaluator-admission-v1.json` contains the exact
store-authority verifying key, signature, signed resolution bytes, admission
bytes/digest, committed receipt, and
cross-links to the recovery ceremony, provenance, evaluation-input views,
semantic lifecycle, output views, activation delivery, activation recipient
views, credential transition, and evaluator-abort corpus.

Rust tests cover canonical success, expiry, zero values, stale epoch,
provenance/identity splicing, selected-evidence binding, stable-scope failure,
arithmetic failure, move-only ownership, exact corpus bytes, CLI parity, and
explicit nonclaims. The independent Python verifier reconstructs every LP32
encoding and digest and strictly verifies the store-authority Ed25519 signature.
The Lean companion models structural ownership and retention only.
