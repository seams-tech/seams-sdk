# Ed25519 Yao Recovery Credential Transition V1

Status: construction-independent host lifecycle semantics. This document
freezes credential suspension at admitted recovery and replacement promotion
after a strictly verified recovery-origin SigningWorker activation. It defines
no production database transaction, credential-envelope opener, transport,
replay coordinator, or P0-P3 security claim.

## 1. State machine

```text
Active(oldCredential, oldStateVersion)
  -> AdmittedRecoveryCredentialSuspended(oldCredential, replacementCredential)
       -> EvaluatorAborted[oldCredential remains suspended]
       -> OutputCommitted[oldCredential remains suspended]
            -> MetadataConsumed
            -> RecipientsReleased
            -> StrictlyVerifiedRecoveryWorkerActivation
            -> PreparedRecoveryPromotion
            -> StrictStoreAuthorityVerification
            -> Active(replacementCredential, nextStateVersion)
               + Tombstone(oldCredential, oldStateVersion)
```

Recovery admission is the suspension boundary. An admitted request and one-use
execution identity are burned after evaluator failure, while the suspension is
retained. No post-admission transition restores the old credential to active
state. A retry requires new recovery authorization and starts from the retained
suspended state.

The returned host suspension remains bound to the burned attempt for audit and
has no re-admission API. A durable retry boundary must persist the suspended-old-
credential status, authenticate a new request-bound store resolution, and seal
new authorization/provenance continuity. It must never reuse the burned
attempt's replacement or same-root binding as the next attempt's authority.

## 2. Authenticated suspension

`AuthenticatedRecoveryCredentialSuspensionV1` owns:

- the strictly verified request-bound registered-store resolution;
- its active state version and complete registered state;
- the active credential binding that is now suspended;
- the distinct replacement credential fixed by recovery authorization;
- the registered Ed25519 public key and stable KDF scope; and
- the common A/B same-root evidence artifact fixed by provenance.

The suspension is created only after the recovery request, authorization,
transcript, authenticated store resolution, and recovery provenance pair have
passed the existing exact binding checks. It has no constructor from raw store
metadata. It is a move-only lifecycle authority and is not a durable record.

`TerminalRecoveryEvaluationV1` owns this exact suspension plus the canonical
evaluator-admission identity. `RecoveryArtifactSessionV1`,
`RecoveryPendingActivationV1`, metadata consumption, recipient delivery,
SigningWorker activation, and promotion retain that terminal value. An admitted
evaluator failure returns `FailedRecoveryArtifactAttemptV1`, which owns the
same terminal admission and burned request/execution identity. The recovery
abort is a suspended-state self-loop.

## 3. Promotion preconditions

Only `SigningWorkerActivationSuccessV1` whose origin is recovery can enter
promotion. The activation already proves strict verification of the
SigningWorker-bound deterministic receipt and retains the exact recovery
suspension.

Promotion requires:

1. a nonzero next active-state version strictly greater than the suspended
   active-state version;
2. an activation epoch strictly greater than the suspended activation epoch;
3. a replacement credential distinct from the suspended credential;
4. a nonzero opaque recovery transaction-receipt digest; and
5. the exact non-weak store-authority Ed25519 verifying key retained by the
   authenticated suspended store resolution.

Promotion preparation has no caller-supplied authority parameter. The signed
body inherits the authority epoch and key digest from the resolution that
authenticated the old state. Receipt verification uses that retained key, so a
coherent attacker-key preparation, signature, and verifier-key substitution is
not representable.

Registration- and refresh-origin activations are rejected while retaining the
verified activated secret for exact retry.

## 4. Exact state relation

The promoted state changes exactly:

```text
active_credential_binding = authorized replacement credential
active_activation_epoch   = verified worker activation epoch
active_state_version       = strictly advancing supplied version
```

It preserves byte-for-byte:

- registered Ed25519 public key;
- stable KDF scope;
- Deriver A root record, root binding, root epoch, input-state record, and
  input-state epoch; and
- Deriver B root record, root binding, root epoch, input-state record, and
  input-state epoch.

The old credential becomes `RecoveryCredentialTombstoneV1`, binding the old
credential digest to the retired active-state version. No success type can
represent both old and replacement credentials as active.

The tombstone digest is:

```text
SHA-256(
    LP32("seams/router-ab/ed25519-yao/recovery-credential-tombstone-digest/v1")
 || LP32(old_credential_binding_digest[32])
 || LP32(BE64(retired_active_state_version))
)
```

## 5. Signed promotion receipt

`LP32(x)` is `BE32(len(x)) || x`. The store authority signs exactly:

```text
RecoveryPromotionReceiptBodyV1 =
    LP32("seams/router-ab/ed25519-yao/recovery-promotion/v1")
 || LP32(BE64(store_authority_key_epoch))
 || LP32(store_authority_key_digest[32])
 || LP32(canonical_durable_identity_bytes)
 || LP32(BE64(old_active_state_version))
 || LP32(BE64(next_active_state_version))
 || LP32(verified_worker_activation_receipt_digest[32])
 || LP32(UTF8(signingWorkerId))
 || LP32(BE64(signingWorkerRecipientKeyEpoch))
 || LP32(BE64(next_activation_epoch))
 || LP32(package_set_digest[32])
 || LP32(output_committed_receipt_digest[32])
 || LP32(worker_storage_receipt_digest[32])
 || LP32(old_registered_state_digest[32])
 || LP32(next_registered_state_digest[32])
 || LP32(old_credential_binding_digest[32])
 || LP32(replacement_credential_binding_digest[32])
 || LP32(same_root_evidence_artifact_digest[32])
 || LP32(old_credential_tombstone_digest[32])
 || LP32(recovery_transaction_receipt_digest[32])
```

Each registered-state digest commits the registered key, active credential,
stable scope, activation epoch, and complete A/B root and input-state bindings:

```text
SHA-256(
    LP32("seams/router-ab/ed25519-yao/recovery-promotion-state-digest/v1")
 || LP32(registered_state_fields_in_canonical_order)
)
```

The verified promotion-receipt digest is:

```text
SHA-256(
    LP32("seams/router-ab/ed25519-yao/recovery-promotion-receipt-digest/v1")
 || LP32(RecoveryPromotionReceiptBodyV1)
)
```

No timestamp, retry counter, runtime security-profile selector, or generic
extension bag appears in version one.

## 6. Retry and failure rules

- Stale state version, wrong activation origin, non-advancing activation epoch,
  or invalid transition construction returns the unchanged strictly verified
  worker activation.
- Signature failure under the retained store authority returns the complete
  prepared promotion and rejected signature.
- No recoverable failure exposes or serializes the activated SigningWorker
  scalar.
- Repeating preparation over the same host transition inputs produces identical
  receipt bytes and tombstone identity.

## 7. Security scope and remaining blockers

The host engine establishes typed suspension, monotonic credential authority,
exact registered-state preservation, strict recovery-origin gating, signed
replacement promotion, and old-credential tombstoning.

The supplied recovery transaction-receipt digest is an opaque nonzero host slot.
This contract does not prove that a production database suspended the old
credential, atomically wrote the replacement state and tombstone, enforced a
rollback floor, or survived a crash. The production durable adapter must create
that digest only after its reviewed atomic transaction succeeds and must test
every crash boundary.

The same-root evidence digest remains an authenticated semantic binding. The
terminal admission separately binds the selected-mechanism acceptance-evidence
digest. The selected production custody/proof mechanism must verify the
underlying artifact before issuing that acceptance evidence.
Selected-profile ciphertext opening, transport, delivery acknowledgement,
global replay admission, backup/restore behavior, and P0-P3 protocol security
remain separate Phase 6B-7 obligations.

## 8. Executable evidence

Focused Rust tests require:

- verified recovery promotion preserves the registered key, stable scope, and
  every A/B root/input-state binding;
- only the active credential, activation epoch, and active-state version change;
- the tombstone names the exact suspended credential and retired state version;
- registration or refresh activation cannot enter recovery promotion;
- stale-version rejection retains verified recovery activation;
- invalid signatures and authority substitution fail closed while preserving
  retry state;
- receipt and tombstone bytes are deterministic; and
- an all-zero transaction-receipt digest is rejected.

The strict one-case recovery credential-transition corpus cross-links the
ceremony, provenance, semantic lifecycle, activation delivery, and activation
recipient companions. Its independent verifier recomputes both registered-state
digests, the tombstone, the exact 20-field receipt, its digest, and the strict
Ed25519 signature under a verifier-pinned authority. It also rejects coherent
authority re-signing. Durable-adapter evidence remains separate follow-on work.
