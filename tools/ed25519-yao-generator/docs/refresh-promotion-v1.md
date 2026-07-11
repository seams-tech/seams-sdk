# Ed25519 Yao Authenticated Refresh Promotion V1

Status: construction-independent host transaction semantics. This document
freezes promotion after a strictly verified SigningWorker activation receipt.
The production durable-store adapter and its atomic commit implementation remain
Phase 7 work.

## 1. State machine

```text
VerifiedRefreshActivation
  -> PreparedRefreshPromotion
  -> StrictStoreAuthorityVerification
  -> AuthenticatedRefreshPromotion
```

Registration and recovery activation states cannot enter this transition. Every
pre-signature or signature failure retains the verified activated secret for
exact retry.

## 2. Promoted state

The next registered state preserves the authenticated old state's registered
Ed25519 public key, active credential binding, and stable KDF scope. It replaces
the active activation epoch with the verified worker activation epoch and copies
the proposed next A/B root record, root binding, root epoch, state record, and
input-state epoch from the sealed refresh origin authority.

The next active state version and activation epoch must each be strictly greater
than their authenticated old values. The refresh lifecycle boundary already
requires both proposed input-state epochs to strictly advance and binds them to
the refresh authorization and provenance pair.

Promotion preparation inherits the exact store-authority verifying key and key
epoch retained by the authenticated old-state resolution. It accepts no caller-
supplied authority. Receipt verification uses that retained key, preventing a
coherent attacker-key preparation, signature, and verifier-key substitution.

## 3. Signed transaction receipt

The durable adapter supplies a nonzero transaction-receipt digest only after its
atomic transaction has written the complete next state and retired the old A/B
input-state epochs. The store authority signs:

```text
RefreshPromotionReceiptBodyV1 =
    LP32(ASCII("seams/router-ab/ed25519-yao/refresh-promotion/v1"))
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
 || LP32(BE64(old_deriver_a_input_state_epoch))
 || LP32(BE64(next_deriver_a_input_state_epoch))
 || LP32(BE64(old_deriver_b_input_state_epoch))
 || LP32(BE64(next_deriver_b_input_state_epoch))
 || LP32(durable_transaction_receipt_digest[32])
```

Each registered-state digest commits the registered key, active credential,
stable scope, activation epoch, and complete A/B root and input-state bindings
under:

```text
seams/router-ab/ed25519-yao/refresh-promotion-state-digest/v1
```

The authenticated promotion receipt digest is:

```text
SHA-256(
  LP32(ASCII("seams/router-ab/ed25519-yao/refresh-promotion-receipt-digest/v1"))
  || LP32(RefreshPromotionReceiptBodyV1)
)
```

No timestamp, retry counter, or runtime profile selector appears in version one.

## 4. Security scope and remaining blocker

The host engine establishes that a strict store-authority signature binds one
verified refresh activation receipt, one authenticated old state/version, one
complete next state/version, both A/B retirement edges, and one durable
transaction-receipt digest. It keeps the activated secret live through success
and every recoverable failure.

This contract does not prove that a production database created the supplied
transaction-receipt digest or committed all writes atomically. Phase 7 must
seal construction of that digest inside the reviewed durable adapter, enforce
rollback floors and replay admission, and test crash recovery at every write
boundary. Until then, this is authenticated host transition evidence rather
than deployed atomic-storage evidence.
