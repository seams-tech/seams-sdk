# Ed25519 Yao Authenticated Store Resolution V1

Status: construction-independent host semantics. This document freezes the
signed registered-state resolution consumed by recovery, refresh, and export.
Production wire parsing, key distribution, durable transactions, rollback
floors, and Cloudflare storage integration remain later-phase work.

## 1. Purpose

A registered lifecycle session cannot begin from an unauthenticated database
projection. The store authority resolves the current registered state for one
exact ceremony and signs a domain-separated resolution. The verified result is
move-only and remains authenticated through issuance, evaluation failure,
output commitment, and metadata consumption.

Registration has no registered pre-state. Activation remains outside this
contract until SigningWorker package opening and state promotion are specified.

## 2. Authority key

The authority key is Ed25519. Its verifying key must decode canonically and must
not be a weak Edwards point. Every key has a nonzero unsigned 64-bit epoch.

```text
LP32(x) = BE32(byte_length(x)) || x

authority_key_digest =
  SHA-256(
    LP32(ASCII("seams/router-ab/ed25519-yao/store-authority-key-digest/v1"))
    || LP32(authority_verifying_key[32])
  )
```

The signed resolution commits both the key epoch and key digest. Verification
under a different epoch or key fails before lifecycle issuance.

## 3. Immutable durable identity

The exact immutable request identity subset is:

```text
DurableStoreIdentityScopeV1 =
    LP32(ASCII("seams/router-ab/ed25519-yao/store-identity-scope/v1"))
    || LP32(ASCII("walletId"))        || LP32(UTF8(walletId))
    || LP32(ASCII("organizationId"))  || LP32(UTF8(organizationId))
    || LP32(ASCII("projectId"))       || LP32(UTF8(projectId))
    || LP32(ASCII("environmentId"))   || LP32(UTF8(environmentId))
    || LP32(ASCII("signingRootId"))   || LP32(UTF8(signingRootId))
    || LP32(ASCII("chainTarget"))     || LP32(UTF8(chainTarget))
```

The stable KDF scope separately commits the application-binding digest,
participant identifiers, and stable-context binding digest. The application
binding commits `walletId`, the Ed25519 signing-key ID, logical signing-root ID,
and immutable key-creation signer slot.

`accountId`, `sessionId`, signing-root version, request ID, replay nonce,
expiry, transport state, and deployment epochs remain request-scoped or mutable.
They are covered by the full request-context, authorization, and transcript
digests and do not become durable immutable identity.

The previous plan shorthand `tenant/application` maps to the frozen canonical
fields `organizationId`, `projectId`, and `environmentId`. No additional tenant
or application identifier is inferred.

## 4. Registered state

The registered-state payload contains, in order:

1. registered Ed25519 public key;
2. nonzero active credential-binding digest;
3. canonical stable KDF scope;
4. nonzero active activation epoch;
5. Deriver A role-root record digest;
6. Deriver A root-binding artifact digest;
7. Deriver A role-root epoch;
8. Deriver A input-state record digest;
9. Deriver A input-state epoch;
10. the same five role-root/input-state fields for Deriver B.

Every item is LP32-framed. Numeric values use big-endian unsigned 64-bit
encoding. The role-typed fields must exactly match the current-state binding
extracted from the accepted A/B provenance pair.

The active credential binding is store-owned lifecycle state. It is absent from
the stable KDF scope and role-input snapshots because recovery changes the
credential while preserving the logical root, role inputs, and public identity.

## 5. Signed resolution

```text
AuthenticatedStoreResolutionV1 =
    LP32(ASCII("seams/router-ab/ed25519-yao/authenticated-store-resolution/v1"))
    || LP32(BE64(authority_key_epoch))
    || LP32(authority_key_digest[32])
    || LP32(request_kind_tag[1])
    || LP32(public_request_context_digest[32])
    || LP32(authorization_digest[32])
    || LP32(transcript_digest[32])
    || LP32(provenance_pair_digest[32])
    || LP32(BE64(active_state_version))
    || LP32(DurableStoreIdentityScopeV1)
    || LP32(RegisteredLifecyclePreStateV1)

signature = Ed25519-Sign(authority_signing_key,
                         AuthenticatedStoreResolutionV1)
```

The active state version is nonzero. Version monotonicity and rollback floors
belong to the later durable authority and epoch-floor design; this contract
ensures the exact resolved version is authenticated and cannot be changed after
signing.

## 6. Consumption rules

Before producing an authenticated value:

1. the request context must reproduce the validated DAG request digest;
2. request kind must be recovery, refresh, or export;
3. provenance request-context, authorization, and transcript digests must equal
   the validated DAG;
4. the ordered A/B provenance-pair digest must be recomputed;
5. every registered-state field must equal the provenance current-state
   binding, except the store-owned active credential binding, which is covered
   directly by the authority signature;
6. the authority key epoch and digest must match the verification key;
7. strict Ed25519 signature verification must succeed.

Before a sealed value enters a lifecycle session, the request, DAG, provenance
pair, durable identity, and registered-state relation are checked again. A
sealed value cannot cross request kinds or provenance pairs.

Issuance and every failure/continuation state retain the authenticated wrapper.
No transition exposes a raw state that can re-enter evaluation without store
authority.

For recovery, successful session construction derives one sealed
`AuthenticatedRecoveryCredentialContinuityEvidenceV1` from three inputs already
covered by the signed resolution:

1. the active state version and active credential binding in registered state;
2. the distinct replacement credential binding in recovery authorization;
3. the common same-root evidence artifact in the ordered A/B provenance pair.

The evidence also retains the registered public key and stable KDF scope. A
replacement equal to the active credential is rejected before evaluation. The
sealed binding remains attached to recovery pending and metadata-consumed
states. The same-root artifact remains proof-system-specific; production must
verify it at the protected custody boundary before signing the store resolution.

## 7. Security scope

This contract establishes host-level authenticity and binding for public state
metadata under the store authority key. It does not establish:

- correct operation or compromise resistance of the store authority signer;
- rollback resistance below an independently enforced active-state floor;
- production record parsing or atomic database transactions;
- production recovery custody/proof verification or refresh next-state
  promotion;
- Yao privacy, active security, recipient encryption, or output correctness;
- a constant-time claim for future secret-bearing Yao kernels.

All signed inputs here are public identifiers, public keys, epochs, and public
digests. Secret-dependent constant-time review remains attached to labels, OT
state, private contributions, output masks, seed/scalar material, and recipient
protection code.
