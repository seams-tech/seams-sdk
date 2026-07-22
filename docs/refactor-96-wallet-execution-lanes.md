# Wallet Key And Execution Lane Foundation

Date created: June 15, 2026

Rewritten: July 22, 2026

Status: active foundation plan. Curve-specific key identity, local capability
material, and exact Wallet Session admission exist as groundwork. First-class
wallet-key and execution-lane runtime behavior remains disabled. Dormant types
that model an agent identity as a wallet signing lane are obsolete and will be
replaced directly.

## Authority And Dependencies

This plan owns stable wallet-key identity and share-bearing execution lanes.
It does not own agent identity, delegated-spend authorization, device-linking
transport, or user-facing policy.

It consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical capability hydration, active ECDSA manifests, activation
  commits, authorization resources, atomic quota claims, and exact operation
  execution;
- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md)
  for Ed25519 key identity, Client and SigningWorker lifecycle, recovery,
  recipient provisioning, refresh, and export;
- `crates/router-ab-ecdsa-derivation` for secp256k1 role-local additive shares,
  threshold sessions, signing, and export;
- [refactor-95-passkey-account-refactor.md](./refactor-95-passkey-account-refactor.md)
  for wrapped owner and linked-device custody.

It supplies the execution model consumed by:

- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) for lane
  provisioning, refresh, activation, and revocation;
- [refactor-98-device-linking.md](./refactor-98-device-linking.md) for physical
  linked-device enrollment;
- [refactor-99-agent-id-spending.md](./refactor-99-agent-id-spending.md) for an
  optional authorization-bound delegated execution lane after agent identity
  and owner authorization have verified.

## Goal

Represent each persistent wallet public identity and each independently
revocable cryptographic execution path with precise domain objects.

```text
Wallet
  -> WalletKey: one stable public key or address
       -> ExecutionLane: one holder/server participant pair
            -> active capability and exact signing sessions
```

Agent authority is a separate axis:

```text
AgentIdentityKey
  -> owner-signed DelegatedSpendAuthorization
       -> agent-signed SpendRequest
            -> admitted WalletExecution
```

An agent identity key never becomes a `WalletKey`. A delegated authorization
never becomes a lane policy. An execution lane never proves who authored a
request.

## Required Invariants

1. A `WalletKey` is the only persistent cryptographic identity that produces
   wallet or blockchain signatures.
2. An `AgentIdentityKey` is independent from every `WalletKey` and signs only
   agent-authored authorization requests or protocol-specific agent objects.
3. A `SigningLane` is share-bearing execution material for one wallet key. It
   cannot contain a delegated mandate, agent display profile, or raw request.
4. Authorization admission completes before root, share, presignature, Client,
   SigningWorker, or relayer work begins.
5. Every execution resolves one exact wallet key, lane, share epoch,
   revocation epoch, participant binding, and operation identity.
6. Revoking one lane leaves the wallet key and unrelated lanes unchanged.
7. Adding a credential to an existing principal does not create a wallet key
   or lane.
8. Export requires an owner/export authorization branch. Device and delegated
   execution lanes cannot satisfy it.
9. Raw request, persistence, and worker shapes are parsed once at their
   boundaries. Core execution receives precise active records.
10. Obsolete `delegated_agent` lane and lane-owned mandate types are deleted
    when this model lands. No compatibility union enters core logic.

## Wallet Key

A wallet key is stable across credential replacement, share refresh, new
execution lanes, and recovery.

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
  lifecycle: WalletKeyLifecycle;
  evmFamilySigningKeySlotId?: never;
  thresholdPublicKey33B64u?: never;
  evmAddress?: never;
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
  lifecycle: WalletKeyLifecycle;
  nearEd25519SigningKeyId?: never;
  keyCreationSignerSlot?: never;
  registeredPublicKeyB64u?: never;
};
```

`WalletKeyLifecycle` is an exhaustive union of `active`, `retired`, and
`compromised`. Only `active` keys may admit new signing operations.

Tempo, Arc, Ethereum, and future EVM-family targets reuse one EVM-family wallet
key when they share the same key slot. Chain-specific sessions, nonce lanes,
and transaction formats are operational bindings under that key.

## Execution Lane Taxonomy

An execution lane binds one wallet key to one holder participant and one server
participant. The core taxonomy is:

```ts
type SigningLaneKind =
  | 'owner_passkey'
  | 'owner_email_otp'
  | 'linked_device'
  | 'delegated_execution'
  | 'recovery'
  | 'break_glass';

type SigningLaneReference = {
  kind: 'signing_lane_reference_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneKind: SigningLaneKind;
  laneShareEpoch: LaneShareEpoch;
  participantBindingDigestB64u: string;
};
```

`delegated_execution` describes an optional MPC execution topology used after
Refactor 99 authorization. Its holder material may be sealed to an agent
runtime so the agent and Seams policy participant must both cooperate. The
agent's independent identity key remains the request author and authorization
subject.

The canonical record union is:

```ts
type SigningLaneRecord =
  | OwnerPasskeySigningLaneRecord
  | OwnerEmailOtpSigningLaneRecord
  | LinkedDeviceSigningLaneRecord
  | DelegatedExecutionLaneRecord
  | RecoverySigningLaneRecord
  | BreakGlassSigningLaneRecord;
```

Every branch has required holder and server participant bindings. Branches use
`never` fields to reject identities and policies owned by another branch.

### Delegated execution lane

The delegated branch carries execution references only:

```ts
type DelegatedExecutionLaneRecord = SigningLaneReference & {
  laneKind: 'delegated_execution';
  authorizationId: DelegatedSpendAuthorizationId;
  agentIdentityKeyId: AgentIdentityKeyId;
  custodyBindingId: AgentCustodyBindingId;
  authorizationBindingDigestB64u: string;
  holderParticipant: DelegatedExecutionHolderParticipant;
  serverParticipant: DelegatedExecutionServerParticipant;
  lifecycle: SigningLaneLifecycle;
  mandate?: never;
  mandatePolicy?: never;
  agentProfile?: never;
};
```

Refactor 99 owns the referenced authorization, agent key, custody binding, and
policy. This lane can execute only after Refactor 99 returns a committed
admission claim for the exact request and authorization epoch.

Deployments that use a chain-native smart account or credential-provider
payment rail may omit `delegated_execution` entirely. The agent key or released
credential is then the execution mechanism defined by that adapter.

## Lane Lifecycle

Lifecycle and revocation form one exhaustive union:

```ts
type SigningLaneLifecycle =
  | {
      state: 'provisioning';
      revocationEpoch: number;
      startedAtMs: number;
    }
  | {
      state: 'pending_receipt';
      revocationEpoch: number;
      startedAtMs: number;
      deliveryDigestB64u: string;
    }
  | {
      state: 'active';
      revocationEpoch: number;
      activatedAtMs: number;
      activationReceiptDigestB64u: string;
    }
  | {
      state: 'suspended';
      revocationEpoch: number;
      suspendedAtMs: number;
      suspendReason: 'user_paused' | 'risk_engine' | 'authorization_suspended';
    }
  | {
      state: 'expired';
      revocationEpoch: number;
      expiredAtMs: number;
    }
  | {
      state: 'revoked';
      revocationEpoch: number;
      revokedAtMs: number;
      revokeReason:
        | 'user_revoked'
        | 'device_compromise'
        | 'agent_compromise'
        | 'authorization_revoked'
        | 'rotation';
    };
```

Only `active` lanes sign. Admission rejects every other branch before secret
material or server participation.

## Key, Lane, Credential, And Authorization Operations

| Operation | Wallet key | Lane | Authorization identity |
| --- | --- | --- | --- |
| Create owner wallet key | new | new owner lane | owner authentication |
| Add passkey credential | same | same | owner authentication |
| Recover credential | same | same or refreshed | recovery authorization |
| Link physical device | same | new linked-device lane | owner-approved device enrollment |
| Authorize independent agent | same | none required | owner-signed delegated authorization |
| Add delegated MPC execution | same | new delegated-execution lane | existing active delegated authorization |
| Refresh lane shares | same | same lane, next epoch | branch-specific refresh authorization |
| Refill ECDSA presignatures | same | same | existing active execution admission |
| Rekey wallet | new | new | owner rekey authorization |

Creating an agent authorization is never itself a wallet-key or lane-creation
operation.

## Enrollment Boundaries

Physical linked devices commonly require one child lane for every wallet key.
Refactor 98 owns their aggregate enrollment, ordered key manifest, delivery
receipts, and atomic activation.

A Refactor 99 authorization can cover one or more wallet keys without creating
lanes. When a direct threshold-wallet adapter requires delegated execution
lanes, its execution enrollment is subordinate to the already-signed
authorization and must match the authorization's exact key set or a strict
subset explicitly selected for the adapter.

An enrollment cannot mix linked-device and delegated-execution children. Their
principals, receipts, policies, and revocation semantics remain separate.

## Execution Admission Contract

Core signing accepts only a prepared execution admission:

```ts
type PreparedWalletExecution =
  | PreparedOwnerWalletExecution
  | PreparedLinkedDeviceWalletExecution
  | PreparedDelegatedWalletExecution;
```

The delegated branch requires:

- verified agent request signature;
- verified owner authorization signature;
- active authorization and current revocation epoch;
- committed atomic budget claim;
- replay and idempotency claim;
- exact typed intent and final unsigned-transaction digest;
- active wallet key;
- active execution lane when the selected adapter uses one;
- exact holder/server participant and share epochs.

Diagnostics, UI projections, and audit summaries cannot construct this type.

## Storage Ownership

Refactor 96 owns:

- `WalletKeyStore`;
- `SigningLaneStore`;
- lane lifecycle and revocation records;
- active lane lookup by exact wallet key;
- lane-to-capability execution bindings.

Refactor 97 owns protocol jobs, material delivery, activation receipts,
refresh, and cryptographic revocation receipts.

Refactor 98 owns linked-device sessions and aggregate device enrollments.

Refactor 99 owns agent identities, public keys, owner authorizations, custody
bindings, budgets, replay claims, spend requests, and delegated audit records.

No store may persist plaintext roots, holder shares, PRF outputs, KEKs,
presignatures, or live capability handles.

## Current Scaffolds To Replace

The repository currently contains dormant development shapes that encode the
superseded model:

- `SigningLaneKind: 'delegated_agent'`;
- `DelegatedAgentSigningLaneRecord` with lane-owned mandate policy;
- `AgentPrincipalId` described as a principal that holds an MPC share;
- `DelegatedSigningRequest` whose authority is inferred from lane identity;
- `DelegatedBudgetReservationStore` keyed around the old lane-owned policy;
- agent wallet summaries derived from delegated lanes.

Replace these directly with the Refactor 99 identity and authorization model
plus the optional `delegated_execution` lane. Delete obsolete fixtures and
tests that protect the old coupling.

## Implementation Phases

### Phase 0: Correct Wallet And Lane Types

- [ ] Replace generic wallet public identity with the curve-specific union.
- [ ] Add immutable Ed25519 and EVM-family key-slot identities.
- [ ] Replace `delegated_agent` with the execution-only
      `delegated_execution` branch.
- [ ] Remove mandate and agent-profile fields from core lane records.
- [ ] Merge lane lifecycle and revocation into one exhaustive union.
- [ ] Add type fixtures rejecting agent keys as wallet keys and mandates as lane
      policies.

### Phase 1: Persistence And Capability Resolution

- [ ] Implement wallet-key and lane stores.
- [ ] Resolve active lanes through Refactor 90's canonical capability manifest
      and activation journal.
- [ ] Bind each active lane to exact curve participants and share epochs.
- [ ] Keep all dormant route shells fail closed.

### Phase 2: Admission Integration

- [ ] Define `PreparedWalletExecution` branches.
- [ ] Require linked-device enrollment admission for linked-device lanes.
- [ ] Require Refactor 99 committed authorization and budget claims for
      delegated execution.
- [ ] Prove raw requests and diagnostics cannot enter signing.

### Phase 3: Protocol Handoff

- [ ] Route Ed25519 lane jobs to Yao recipient provisioning.
- [ ] Route ECDSA lane jobs to additive target-lane resharing.
- [ ] Verify public-key continuity and exact participant bindings.
- [ ] Activate lane records only from verified protocol receipts.

### Phase 4: Cutover

- [ ] Enable Refactor 98 device-linking behavior.
- [ ] Enable the Refactor 99 threshold-wallet execution adapter.
- [ ] Delete obsolete delegated-agent lane types, stores, APIs, fixtures, and
      tests.

## Validation

Static checks prove:

- agent identity keys cannot construct wallet-key records;
- wallet signing lanes cannot contain delegated mandates;
- delegated execution lanes require authorization, agent-key, and custody
  binding IDs;
- owner and linked-device lanes reject delegated-execution fields;
- inactive lanes cannot construct prepared execution;
- Ed25519 and ECDSA identities and participant bindings cannot be swapped;
- export admissions reject linked-device and delegated branches.

Focused tests prove:

- creating an agent authorization creates no wallet key or lane;
- a valid agent request with no active execution adapter fails closed;
- a delegated execution lane cannot sign without a committed Refactor 99
  admission claim;
- lane revocation blocks execution and leaves owner lanes active;
- authorization revocation blocks delegated execution before share work;
- direct owner and linked-device signing remain independent from agent state;
- wallet public identities remain stable through lane creation and refresh.

## Non-Goals

- treating an agent key as a wallet key;
- transferring funds into an agent-owned wallet as the delegation mechanism;
- storing delegated policy inside a cryptographic lane;
- granting export or account administration through ordinary execution lanes;
- requiring every payment rail to use an MPC delegated-execution lane;
- defining agent UX, AP2 payloads, or device-link transport in this plan.

## Decisions Required Before Implementation

- Freeze the first delegated execution topology: agent-held holder share,
  managed policy co-signers, or both as explicit adapter branches.
- Freeze exact participant-binding records for Ed25519 and ECDSA lanes.
- Freeze which wallet key authorizes mixed-key device enrollments.
- Freeze lane revocation receipt encoding and post-compromise refresh policy.
