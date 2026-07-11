# Ed25519 Yao SigningWorker Activation V1

Status: construction-independent host semantics. This document freezes the
profile-neutral boundary after selected-profile recipient decryption and package
authentication. Phase 6A/6B still selects and implements the ciphertext, AAD,
authentication, output-binding, transport, and production storage mechanisms.

## 1. Purpose and lifecycle position

Activation consumes one metadata/control-accepted package set produced by
registration, recovery, or refresh. It performs zero Yao evaluations, Deriver
calls, contribution derivations, or output-share sampling.

```text
OutputCommitted(origin)
  -> MetadataConsumed(origin)
  -> RecipientsReleased(ClientCapability, SigningWorkerReleaseAuthority)
  -> ProfileAuthenticatedOpenedA + ProfileAuthenticatedOpenedB
  -> ReceiptPendingActivatedWorker
  -> StrictlyVerifiedWorkerReceipt + ActivatedWorker
```

The selected profile owns ciphertext opening. It is the only component allowed
to produce the sealed opened-share types accepted by the activation engine. The
engine rechecks every semantic relation independently and combines only the two
SigningWorker-recipient scalar shares.

## 2. Sealed opened-share contract

Each role-specific opened plaintext contains:

```text
role                         = Deriver A | Deriver B, fixed by the Rust type
recipient_key_binding        = SigningWorkerRecipientKeyBindingDigest32V1
activation_epoch             = nonzero BE64 epoch
package_authentication_digest = selected-profile authenticated package binding
scalar_share                 = canonical LE32 scalar in Z_l
```

There is no public raw-value constructor. The Phase 6B selected-profile opener
must decrypt the role- and recipient-typed ciphertext, authenticate its complete
descriptor/AAD, validate the plaintext shape, and then construct the sealed
value. Host-only tests use a crate-private synthetic constructor and make no
recipient-encryption claim.

## 3. Required activation checks

Before an activated scalar can exist, the engine must enforce all of the
following:

1. the runtime SigningWorker ID and recipient-key epoch equal the origin request;
2. both package descriptors use the SigningWorker recipient tag and scalar-output tag;
3. each descriptor and opened plaintext contains
   `SHA-256(LP32(signing-worker-recipient-domain) || LP32(originRequestDigest))`;
4. descriptor and opened activation epochs equal the committed artifact epoch;
5. both descriptors bind the origin request-context digest;
6. each opened package-authentication digest equals its descriptor binding;
7. each opened scalar equals its exact retained same-evaluation role share by
   constant-time comparison;
8. each canonical scalar share multiplied by the Ed25519 base point equals its
   role-specific public share point;
9. the sum of the A/B scalars multiplied by the base point equals committed
   `X_server`;
10. `2*X_client-X_server` equals the registered canonical prime-subgroup public key;
11. the receipt authority is configured for the same SigningWorker ID and
    recipient-key epoch.

All byte comparisons involving secret-derived share points use constant-time
equality. Canonical decoding rejects attacker-controlled malformed plaintext
before activation. Scalar addition and fixed-base multiplication use the pinned
`curve25519-dalek` implementation. Activated scalar storage zeroizes on drop.

A failed preparation retains the unchanged SigningWorker release authority for
an exact semantic-package retry. Opened plaintexts are destroyed. The selected
profile must reopen them from its committed package representation.
Cryptographic re-evaluation and package replacement remain forbidden. The host
model makes no exact-ciphertext-redelivery claim.

## 4. Activated state

`ActivatedSigningWorkerStateV1` owns the joined secret scalar and these public
bindings:

```text
origin
SigningWorker ID and recipient-key epoch
activation epoch
package-set digest
output-committed receipt digest
X_server
registered Ed25519 public key
SigningWorker output-retention evidence digest
origin-specific lifecycle authority
```

The origin authority is disjoint:

- registration retains its consumed origin request;
- recovery retains its authenticated prior state and credential-continuity evidence;
- refresh retains its authenticated prior state and both proposed next role states.

The joined scalar has no serialization or exposure API. A future normal-signing
engine consumes it only through a narrower activated-state capability.

## 5. Receipt authority

Every receipt authority has:

- one exact SigningWorker ID and recipient-key epoch;
- a nonzero independent receipt-signing-key epoch;
- a canonical non-weak Ed25519 verifying key.

```text
receipt_key_digest =
  SHA-256(
    LP32(ASCII("seams/router-ab/ed25519-yao/signing-worker-receipt-key-digest/v1"))
    || LP32(UTF8(signingWorkerId))
    || LP32(BE64(signingWorkerRecipientKeyEpoch))
    || LP32(receiptVerifyingKey[32])
  )
```

The key digest and key epoch are included in the signed receipt. Verification
under another worker, recipient-key epoch, receipt-key epoch, or verifying key
fails before activation success is released.

Activation success retains the exact authority used for strict verification,
including its worker binding, receipt-key epoch, key digest, and verifying-key
bytes. Later party views derive receipt-authority evidence from this retained
typed value.

## 6. Deterministic idempotent receipt

```text
SigningWorkerActivationReceiptBodyV1 =
    LP32(ASCII("seams/router-ab/ed25519-yao/signing-worker-activation-receipt/v1"))
 || LP32(BE64(receipt_key_epoch))
 || LP32(receipt_key_digest[32])
 || LP32(UTF8(signingWorkerId))
 || LP32(BE64(signingWorkerRecipientKeyEpoch))
 || LP32(origin_tag[1])
 || LP32(activation_request_context_digest[32])
 || LP32(activation_authorization_digest[32])
 || LP32(activation_transcript_digest[32])
 || LP32(origin_tag[1])
 || LP32(origin_request_kind_tag[1])
 || LP32(origin_request_context_digest[32])
 || LP32(origin_authorization_digest[32])
 || LP32(origin_transcript_digest[32])
 || LP32(one_use_execution_id[32])
 || LP32(package_set_digest[32])
 || LP32(BE64(activation_epoch))
 || LP32(registered_public_key[32])
 || LP32(output_committed_receipt_digest[32])
 || LP32(X_server[32])
 || LP32(registered_public_key[32])
 || LP32(worker_output_retention_evidence_digest[32])

receipt_signature = Ed25519-Sign(receipt_signing_key,
                                 SigningWorkerActivationReceiptBodyV1)
```

The registered public key appears once inside the complete origin artifact
binding and once in the activation result suffix. This duplication is an
intentional equality check across origin and activated-state projections.

No timestamp or retry counter appears in version one. Reopening the same
committed semantic package identity against the same opaque output-retention
evidence deterministically reproduces the same body and Ed25519 signature. The
opaque digest does not prove durable storage. A failed signature verification
retains the receipt-pending activated secret for safe signature retry.

The receipt digest is:

```text
SHA-256(
  LP32(ASCII("seams/router-ab/ed25519-yao/signing-worker-activation-receipt-digest/v1"))
  || LP32(SigningWorkerActivationReceiptBodyV1)
)
```

## 7. Security scope and remaining blockers

This contract establishes the host transition from profile-authenticated opened
shares to strictly receipt-verified activated state. It does not establish:

- a selected ciphertext, HPKE/AEAD, AAD, MAC, proof, or package-signature format;
- that a production opener actually authenticated or decrypted the committed
  ciphertexts;
- durable atomic storage, rollback floors, replay admission, redelivery records,
  backup/restore behavior, or Cloudflare transactions;
- production execution of the implemented authenticated refresh promotion or
  retirement-tombstone transaction;
- normal signing, nonce state, FROST share mapping, or erasure after replacement;
- P0-P3 privacy, active-security, selective-failure, or noninterference claims.

The full plan item remains open until Phase 6B supplies the selected-profile
opener and production wire/storage transaction. The profile-neutral activation
engine, share checks, secret state, and strict idempotent receipt are complete
host evidence.
