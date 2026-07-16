# Wallet Key And Signing Lane Foundation

Date created: June 15, 2026

Last reconciled: July 15, 2026

Status: active foundation plan. Branded IDs, parsers, record types, policy
types, type fixtures, server store interfaces, and a QR v4 parser exist. The
runtime still signs through the current owner capability model, and linked or
delegated behavior remains disabled.

## Dependencies And Authority

This plan consumes:

- [yaos-ab.md](./yaos-ab.md) for Ed25519 key identity, key-creation signer
  slots, Yao Client and SigningWorker lifecycle, recovery, refresh, and export;
- `crates/router-ab-ecdsa-derivation` for the EVM-family secp256k1 key,
  role-local additive shares, threshold sessions, signing, and export;
- [refactor-95-passkey-account-refactor.md](./refactor-95-passkey-account-refactor.md)
  for wrapped client roots and holder shares.

It supplies the domain model consumed by:

- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) for lane
  provisioning, refresh, activation, and revocation;
- [refactor-98-delegated-agent-linked-device-behavior.md](./refactor-98-delegated-agent-linked-device-behavior.md)
  for product behavior.

## Goal

Represent every persistent wallet signing identity and every independently
revocable authority with precise domain objects.

```text
Wallet
  -> WalletKey: one stable cryptographic public identity
       -> SigningLane: one holder/server participant pair and policy
            -> live capability and exact signing sessions
```

A wallet can contain several `WalletKey` records. A physical device or agent can
hold one lane for each key included in its enrollment.

## Architecture Decisions

### Wallet Key

A `WalletKey` is the stable cryptographic identity whose public key or address
must remain unchanged across recovery, share refresh, and additional signing
lanes.

```ts
type WalletKeyRecord = Ed25519WalletKeyRecord | EvmFamilyWalletKeyRecord;

type Ed25519WalletKeyRecord = {
  kind: 'wallet_key_record_v1';
  keyFamily: 'ed25519';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  walletKeyVersion: WalletKeyVersion;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  keyCreationSignerSlot: KeyCreationSignerSlot;
  registeredPublicKeyB64u: string;
  evmFamilySigningKeySlotId?: never;
  thresholdPublicKey33B64u?: never;
  evmAddress?: never;
  lifecycle: WalletKeyLifecycle;
};

type EvmFamilyWalletKeyRecord = {
  kind: 'wallet_key_record_v1';
  keyFamily: 'ecdsa_secp256k1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  walletKeyVersion: WalletKeyVersion;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdPublicKey33B64u: string;
  evmAddress: string;
  nearEd25519SigningKeyId?: never;
  keyCreationSignerSlot?: never;
  registeredPublicKeyB64u?: never;
  lifecycle: WalletKeyLifecycle;
};
```

`WalletPublicIdentity = { address: string }` is too weak for the mixed SDK. The
record must make key family, public-key encoding, and immutable key-slot identity
agree at construction.

### Key Creation, Lanes, And Sessions

These operations have separate meanings:

| Operation | Wallet key | Lane | Share epoch | Credential/session |
| --- | --- | --- | --- | --- |
| Ed25519 `add-signer` | new `WalletKey` and registered `A_pub` | new owner lane | first epoch | new Yao capability |
| Add passkey credential | same | same | same | new envelope |
| Recover credential | same | same | same or explicitly refreshed | replacement envelope/capability |
| Create linked device | same | new linked-device lane | first target epoch | new device capability |
| Create delegated agent | same | new delegated lane | first target epoch | new agent capability |
| Refresh a lane | same | same | next epoch | replacement capability |
| ECDSA session refill | same | same | same | new one-use presign state |
| Wallet rekey | new | new | first epoch | new public identity |

An ECDSA threshold session is an operational binding under the EVM-family
`WalletKey`. Tempo, Arc, Ethereum, and future EVM-family targets share the same
persistent ECDSA wallet key when they use the same key slot. Chain-specific
sessions, nonce lanes, and transaction formats do not create additional wallet
keys.

### Signing Lane

A lane binds one wallet key to one holder principal, one server participant,
one share epoch, and one policy.

```ts
type SigningLaneReference = {
  kind: 'signing_lane_reference_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneKind:
    | 'owner_passkey'
    | 'owner_email_otp'
    | 'linked_device'
    | 'delegated_agent'
    | 'recovery'
    | 'break_glass';
  laneShareEpoch: LaneShareEpoch;
};
```

Every signing request resolves a concrete lane before any root, share,
presignature, Yao capability, or SigningWorker capability is touched.

### Lane Lifecycle

Lifecycle and revocation state form one exhaustive union.

```ts
type SigningLaneLifecycle =
  | {
      state: 'provisioning';
      revocationEpoch: number;
      activationDeadlineMs: number;
      activatedAtMs?: never;
      suspendedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'pending_holder_receipt';
      revocationEpoch: number;
      activationDeadlineMs: number;
      activatedAtMs?: never;
      suspendedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'active';
      revocationEpoch: number;
      activatedAtMs: number;
      suspendedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'suspended';
      revocationEpoch: number;
      activatedAtMs: number;
      suspendedAtMs: number;
      suspendReason: 'user_paused' | 'risk_engine' | 'budget_exhausted';
      revokedAtMs?: never;
    }
  | {
      state: 'expired';
      revocationEpoch: number;
      activatedAtMs: number;
      expiredAtMs: number;
      suspendedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked_before_activation';
      revocationEpoch: number;
      revokedAtMs: number;
      revokeReason:
        | 'user_revoked'
        | 'device_compromise'
        | 'agent_compromise'
        | 'policy_revoked'
        | 'enrollment_rollback';
      activatedAtMs?: never;
      suspendedAtMs?: never;
    }
  | {
      state: 'revoked_after_activation';
      revocationEpoch: number;
      activatedAtMs: number;
      revokedAtMs: number;
      revokeReason:
        | 'user_revoked'
        | 'device_compromise'
        | 'agent_compromise'
        | 'policy_revoked';
      suspendedAtMs?: never;
    };
```

Only `active` lanes can sign. A suspended, expired, revoked, provisioning, or
pending-receipt lane fails before server-share or SigningWorker admission.

## Lane Records

The record union keeps principal and policy branches exact.

```ts
type SigningLaneRecord =
  | OwnerPasskeySigningLaneRecord
  | OwnerEmailOtpSigningLaneRecord
  | LinkedDeviceSigningLaneRecord
  | DelegatedAgentSigningLaneRecord
  | RecoverySigningLaneRecord
  | BreakGlassSigningLaneRecord;
```

Owner lanes carry their exact credential or provider principal and cannot carry
a device principal, delegate principal, or mandate policy.

A linked-device lane carries:

- `LinkedDeviceId`;
- device identity public key;
- passkey RP and credential identity;
- owner-equivalent or scoped permission policy;
- enrollment ID;
- exact holder and server participant bindings;
- lane lifecycle.

A delegated-agent lane carries:

- `AgentPrincipalId`;
- named custody key and runtime;
- mandate policy and digest;
- enrollment ID;
- exact holder and server participant bindings;
- lane lifecycle.

## Wallet-Scoped Enrollment

A linked device or agent commonly needs multiple lanes. Model the product
operation above the key-specific records.

```ts
type EnrollmentTarget =
  | {
      keyFamily: 'ed25519';
      walletKeyId: WalletKeyId;
      targetLaneId: SigningLaneId;
      targetLaneShareEpoch: LaneShareEpoch;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      registeredPublicKeyB64u: string;
      evmFamilySigningKeySlotId?: never;
      thresholdPublicKey33B64u?: never;
      evmAddress?: never;
    }
  | {
      keyFamily: 'ecdsa_secp256k1';
      walletKeyId: WalletKeyId;
      targetLaneId: SigningLaneId;
      targetLaneShareEpoch: LaneShareEpoch;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      thresholdPublicKey33B64u: string;
      evmAddress: string;
      nearEd25519SigningKeyId?: never;
      registeredPublicKeyB64u?: never;
    };

type EnrollmentLifecycle =
  | {
      state: 'preparing';
      startedAtMs: number;
      activatedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'pending_holder_receipts';
      startedAtMs: number;
      keyManifestDigestB64u: string;
      activatedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'committed_completion_required';
      startedAtMs: number;
      keyManifestDigestB64u: string;
      transcriptSetDigestB64u: string;
      activatedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'active';
      startedAtMs: number;
      activatedAtMs: number;
      aggregateReceiptDigestB64u: string;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked_before_activation';
      startedAtMs: number;
      revokedAtMs: number;
      revocationEpoch: number;
      activatedAtMs?: never;
    }
  | {
      state: 'revoked_after_activation';
      startedAtMs: number;
      activatedAtMs: number;
      revokedAtMs: number;
      revocationEpoch: number;
    };

type LinkedDeviceEnrollmentRecord = {
  kind: 'linked_device_enrollment_v1';
  enrollmentId: LinkedDeviceEnrollmentId;
  walletId: WalletId;
  deviceId: LinkedDeviceId;
  linkSessionId: LinkDeviceSessionId;
  permissionPolicyDigestB64u: string;
  keyManifestDigestB64u: string;
  targets: readonly [EnrollmentTarget, ...EnrollmentTarget[]];
  lifecycle: EnrollmentLifecycle;
};
```

`DelegatedAgentEnrollmentRecord` has the same aggregate shape with an agent
principal, custody binding, and mandate digest.

Rules:

- target wallet keys are exact, unique, active, and owned by the wallet;
- every target has one lane record and one protocol job;
- the manifest digest commits the ordered target set and policy;
- the enrollment becomes active only after every target is ready;
- signing admission requires both the child lane and parent enrollment active;
- revoking a physical device revokes its parent enrollment and all child lanes;
- a scoped agent can intentionally target a strict subset of wallet keys;
- partial target activation is never exposed as an active enrollment.

This aggregate closes the mixed-wallet gap in the earlier plan, where one
`SigningLaneRecord` could not represent an entire device.

## Linked-Device Permission Policy

Use a discriminated union.

```ts
type LinkedDevicePermissionPolicy =
  | {
      kind: 'owner_equivalent';
      administrationScope: 'signing_only' | 'device_management' | 'full_owner_admin';
      mandatePolicy?: never;
    }
  | {
      kind: 'scoped';
      administrationScope: 'no_account_admin';
      mandatePolicy: DelegatedMandatePolicy;
    };
```

Owner-equivalent signing still requires local user presence. Administrative
scope is evaluated separately from transaction-signing authority. Scoped lanes
use the delegated mandate admission pipeline.

The first product release supports `owner_equivalent` with `signing_only`.
Device-management and full-owner administration require separate high-risk
authorization and dedicated tests. Scoped permissions follow after the
owner-equivalent lane lifecycle is stable.

## Delegated Mandate Policy

A mandate is an allowlist over typed intents. It never acts as an arbitrary
transaction predicate over raw caller-provided JSON.

Required dimensions:

- exact wallet and target wallet-key set;
- allowed chains and networks;
- allowed intent variants;
- receiver, contract, method, token, and counterparty constraints;
- per-operation and aggregate value limits;
- expiry and optional schedule;
- replay nonce scope;
- idempotency rules;
- allowance or approval ceilings;
- policy version and digest.

Supported intent families should remain discriminated:

```ts
type DelegatedIntent =
  | NativeTransferIntent
  | Erc20TransferIntent
  | ContractCallIntent
  | ExactPurchaseIntent
  | NearFunctionCallIntent;
```

Boundary parsers normalize chain-specific raw requests into these types once.
Policy logic validates the typed intent and the final unsigned transaction.

## Authorization And Budget Layering

Signing admission requires every layer:

```text
authenticated Wallet Session
  + active parent enrollment when applicable
  + active lane and current laneShareEpoch/revocationEpoch
  + exact WalletKey public identity
  + exact Ed25519 participant or ECDSA threshold-session binding
  + lane permission or mandate admission
  + wallet-level grant budget and expiry
  + lane-level budget when configured
  + replay and idempotency admission
```

The existing wallet-level counter remains the outer spending/signing budget for
the mixed wallet. Delegated and scoped lanes can impose a stricter inner budget.
Consumption succeeds only once. A failed policy check performs no share work
and consumes no signing budget.

## QR Link Session

Device 2 creates an unclaimed link session. The QR payload contains no wallet
identifier.

```ts
type QrLinkedDeviceSessionPayloadV4 = {
  version: 'v4';
  purpose: 'linked_device_lane_creation';
  linkSessionId: LinkDeviceSessionId;
  linkPublicKeyB64u: string;
  devicePublicKeyB64u: string;
  requestedPermission: QrLinkedDevicePermissionRequest;
  issuedAtMs: number;
  expiresAtMs: number;
};
```

Device 1 binds the session to its wallet only after authenticated owner approval.
The relay stores public session facts and encrypted packages. It never receives
plaintext roots, holder shares, PRF output, KEKs, recovery material, or an
export-capable secret.

The protocol remains transport-neutral. SSE with POST claim/receipt requests is
the preferred initial browser transport because Device 2 mainly receives
updates. Authenticated polling is acceptable. WebSocket transport can implement
the same state machine without changing cryptographic records.

## Agent Custody Binding

An agent lane targets a named custody key.

```ts
type AgentCustodyBindingRecord = {
  kind: 'agent_custody_binding_v1';
  agentId: AgentPrincipalId;
  custodyKeyId: AgentCustodyKeyId;
  custodyRuntime: 'managed_service' | 'tee' | 'hsm' | 'customer_runtime';
  encryptionPublicKeyB64u: string;
  attestation: AgentCustodyAttestation;
  lifecycle: AgentCustodyLifecycle;
};
```

Activation requires a receipt bound to enrollment ID, wallet key, lane, share
epoch, policy digest, custody key, and protocol transcript. A bare agent ID is
never a custody boundary.

## Storage Surfaces

Shared domain package:

```text
packages/shared-ts/src/signing-lanes/
  ids.ts
  records.ts
  policies.ts
  intents.ts
  enrollments.ts
  rotation.ts
  validation.ts
```

Server interfaces:

```text
packages/sdk-server-ts/src/core/signingLanes/
  WalletKeyStore.ts
  SigningLaneStore.ts
  SigningLaneRotationStore.ts
  SigningLaneLockStore.ts
  LinkedDeviceEnrollmentStore.ts
  DelegatedAgentEnrollmentStore.ts
  LaneAdmissionStore.ts
```

Web SDK:

```text
packages/sdk-web/src/core/signingEngine/session/lanes/
packages/sdk-web/src/SeamsWeb/operations/devices/
packages/sdk-web/src/SeamsWeb/operations/delegation/
```

Persistence adapters parse database rows into domain records immediately.
Route adapters parse request bodies once. Store and route interfaces do not
accept `Partial`, raw strings for branded IDs, or compatibility records.

## Public API Direction

```text
listWalletKeys()
listSigningLanes(walletKeyId?)
listLinkedDevices()
listAgentWallets()
startLinkedDeviceEnrollment()
approveLinkedDeviceEnrollment()
revokeLinkedDevice(deviceId)
createAgentEnrollment()
revokeAgentEnrollment(agentId)
```

Public methods return result unions with typed recoverable failures. They do not
return raw holder/server records or accept caller-constructed lane records.

## Current Implementation Gaps

- `WalletKeyRecord` still has one generic `{ address }` public identity.
- `SigningLaneRecord` and rotation scaffolding exist without registered runtime
  behavior.
- rotation job branches use one broad permission digest for both linked devices
  and agents.
- linked-device receipts are key-specific and have no parent enrollment receipt.
- QR v4 parsing exists and correctly excludes `walletId`.
- `linkDevice.ts` and `scanDevice.ts` fail closed.
- server stores are interfaces only.
- the old public link-device surface remains visible for UI integration while
  runtime behavior is disabled.

These shapes may be replaced directly. No compatibility aliases or duplicate
record versions are required during development.

## Implementation Phases

### Phase 0: Correct The Foundation Types

- [ ] Replace generic wallet public identity with the curve-specific wallet-key
      union.
- [ ] Add immutable Ed25519 key-creation signer-slot identity.
- [ ] Make EVM-family key-slot identity distinct from threshold sessions.
- [ ] Merge lane lifecycle and revocation into one exhaustive union.
- [ ] Add enrollment, manifest, and aggregate receipt IDs.

### Phase 1: Enrollments And Policies

- [ ] Add linked-device and delegated-agent enrollment records.
- [ ] Add branch-specific lane-creation jobs and policy digests.
- [ ] Add owner-equivalent signing-only policy as the first supported branch.
- [ ] Add mandate parsers and exact typed-intent admission.

### Phase 2: Persistence And Admission

- [ ] Implement wallet-key, lane, enrollment, lock, and receipt stores.
- [ ] Add active enrollment and lane checks to signing admission.
- [ ] Bind the mixed Wallet Session grant to exact lane/key/session identities.
- [ ] Keep route shells unregistered until Refactor 98 activates behavior.

### Phase 3: Curve Protocol Handoff

- [ ] Route Ed25519 lane jobs to Yao lane provisioning.
- [ ] Route ECDSA lane jobs to Router A/B ECDSA resharing.
- [ ] Require exact per-key receipts and aggregate activation.
- [ ] Reject partial mixed-wallet activation.

### Phase 4: Product Handoff

- [ ] Enable Refactor 98's owner-equivalent linked-device flow.
- [ ] Add aggregate revocation and activity views.
- [ ] Add delegated-agent and scoped-device branches after owner-equivalent
      behavior passes its gate.

## Validation

Static checks:

- Ed25519 key with EVM identity fields fails;
- EVM-family key with an Ed25519 signer slot fails;
- add-signer result cannot reuse an existing wallet-key ID;
- passkey addition cannot create a new lane;
- linked-device lane without an enrollment ID or device principal fails;
- delegated lane without a custody binding or mandate fails;
- owner lane with delegate/device policy fields fails;
- owner-equivalent policy with a mandate fails;
- scoped policy with administrative authority fails;
- a lifecycle branch with fields from another branch fails;
- raw IDs and partial records cannot reach core admission.

Focused behavior tests:

- mixed wallet inventory contains the registered Ed25519 key and one EVM-family
  wallet key with exact public identities;
- Tempo and Arc/EVM share the EVM-family key while retaining exact sessions;
- Ed25519 add-signer creates a new wallet key;
- passkey addition preserves wallet key, lane, and epoch;
- linked-device enrollment targets every required wallet key exactly once;
- parent enrollment remains inactive while any child lane is pending;
- signing fails for inactive enrollment, stale epoch, stale revocation epoch,
  wrong session, exhausted budget, expired policy, and replay;
- revoking one device leaves owner and unrelated device lanes active.

## Non-Goals

- giving agents or linked devices complete wallet private keys;
- treating an ECDSA session as a persistent wallet key;
- placing wallet IDs or secret material in QR payloads;
- using diagnostics, availability snapshots, or UI booleans as authorization;
- enabling routes before stores, policy admission, and activation fencing exist;
- preserving obsolete AddKey-based linking or blockchain-specific recovery;
- adding compatibility paths for the superseded domain model.

## Decisions Required Before Implementation

- Freeze branded IDs for key-creation signer slots, enrollments, manifests, and
  aggregate receipts.
- Freeze the canonical ordering used by enrollment key-manifest digests.
- Decide whether owner-equivalent device-management and full-owner admin ship as
  separate later policies or remain unavailable in the first product.
- Define how wallet-level and lane-level budgets compose when both exist.
- Define the exact database transaction or durable activation marker that makes
  a multi-key enrollment visible to signing admission.
