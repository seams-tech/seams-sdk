# Share Rotation Plan For Signing Lanes

Date created: June 15, 2026

Status: design plan. This plan defines address-preserving share rotation for
owner and delegated signing lanes. It supersedes using
[rotate-korg-secrets.md](./rotate-korg-secrets.md) as the top-level MPC share
rotation plan. The `k_org` plan remains relevant only for server custody and
signing-root operations.

Full delegated-agent and linked-device product behavior lives in
[refactor-74-delegated-agent-linked-device-behavior.md](./refactor-74-delegated-agent-linked-device-behavior.md).
This plan owns the lane epoch, refresh, revocation, and rollback primitives that
behavior consumes.

## Goal

Define clean share rotation semantics for the delegate wallet architecture.

The critical invariant:

```text
wallet key and public address stay stable during normal lane rotation
```

For a two-party additive lane:

```text
wallet_private_scalar = holder_share + server_share
```

If the holder share stays fixed and the wallet key stays fixed, the effective
server share is fixed. The server can rewrap or reshard custody of its existing
share. Effective share rotation requires a holder-side ceremony.

## Rotation Taxonomy

### 1. Envelope Rewrap

Rewrap changes encryption around the same plaintext share.

```text
same holder share
same server share
same wallet key
same wallet address
new KEK or envelope version
```

Use for:

- passkey replacement
- recovery-code rotation
- agent custody-key rotation
- storage migration
- server KEK rotation

### 2. Server Internal Custody Rotation

Server internal custody rotation changes how the server protects the same
effective server share.

```text
same effective server share
same holder share
same wallet key
same wallet address
new A/B custody shares, KEKs, storage locators, or deployment keys
```

This is the remaining useful scope of `docs/rotate-korg-secrets.md`.

### 3. Lane Share Refresh

Lane share refresh changes the effective holder and server shares for one lane.

```text
old_holder + old_server = wallet key
new_holder + new_server = same wallet key
```

This is the normal cryptographic rotation for owner and delegated lanes. It
requires the holder, recovery path, or an approved custody ceremony.

### 4. Delegated Lane Revocation

Delegated lane revocation disables one agent lane.

```text
revoked agent holder share cannot combine with active server share
owner lanes remain active
wallet address stays stable
```

Revocation should happen immediately at policy and server-share admission. Share
destruction or lane refresh provides cryptographic cleanup evidence.

### 5. Wallet Rekey

Wallet rekey creates a new wallet key and usually a new address.

Use for:

- confirmed compromise of both sides of a lane
- intentional wallet migration
- root or protocol compromise that invalidates address-preserving recovery

Wallet rekey is outside normal rotation.

## Server Share Rotation Boundary

The server cannot unilaterally rotate the effective server share for a lane while
preserving the wallet address.

```text
wallet_key = holder_share + server_share
```

With `wallet_key` and `holder_share` fixed, `server_share` has exactly one
effective value.

The server can still do useful operations without holder input:

- rewrap the same server share
- move the same server share to a new relayer
- split custody of the same server share across A/B operators
- rotate deployment keys and storage credentials
- refresh `k_org` custody shares that derive server-side material

Those operations improve server operations. They do not revoke a holder-side
share or create a new delegated agent lane.

## Lane Share Refresh Protocol

The preferred protocol is an address-preserving resharing ceremony.

Inputs:

- active wallet key identity
- active lane id
- active lane share epoch
- current holder participation or recovery authority
- current server participation
- target holder principal
- target server custody boundary
- transcript binding and policy digest

Outputs:

- new holder share
- new server share
- holder share public commitment
- server share public commitment
- new lane share epoch
- proof or verification that the wallet public key is unchanged
- sealed holder-share envelope
- sealed server-share record

Protocol requirements:

1. Authenticate the rotation request.
2. Pin `walletKeyId`, `laneId`, `laneShareEpoch`, participant identities, and
   protocol version.
3. Freeze signing for the target lane.
4. Run resharing or approved provisioning ceremony.
5. Seal new holder and server shares.
6. Verify wallet public key and address parity.
7. Write new lane records atomically.
8. Activate the new lane epoch and make the old lane epoch unavailable for
   signing in the same commit.
9. Reject stale lane epochs in signing admission.

## First Target Protocol: Additive Delta Reshare

For the current two-party additive model, the first implementation can use a
holder-sampled delta reshare. This covers deterministic-passkey migration,
owner-lane refresh, Email OTP holder-share refresh, delegated agent lane
creation, and QR linked-device lane creation.

Definitions:

```text
q = scalar field order
X = wallet public key
h_old + s_old = x mod q
h_old * G + s_old * G = X
```

Holder-sampled refresh:

```text
holder samples h_new uniformly from [1, q - 1]
holder computes delta = h_old - h_new mod q
holder sends delta and H_new = h_new * G to server
server computes s_new = s_old + delta mod q
server computes S_new = s_new * G
both sides verify H_new + S_new = X
```

Properties:

- the wallet scalar is never reconstructed in one process
- the server never receives `h_old` or `h_new`
- the holder never receives `s_old` or `s_new`
- `delta` is transient resharing material and must not be persisted
- `delta` is sent over an authenticated encrypted channel and bound to the
  transcript hash
- the new holder share is random when `h_new` is sampled uniformly
- public key parity proves address preservation for the new lane epoch

Delegated signer lane creation uses the same primitive:

```text
owner holder opens h_owner inside worker
owner worker samples h_delegate uniformly from [1, q - 1]
owner worker computes delta = h_owner - h_delegate mod q
server computes s_delegate = s_owner + delta mod q
owner worker verifies H_delegate + S_delegate = X
owner worker encrypts h_delegate to the target custody boundary
```

For an agent lane, the target custody boundary is the agent custody key. For a
linked-device lane, the target custody boundary is the link-session public key
or device custody key from the QR payload.

The owner worker must encrypt `h_delegate` directly to the target custody key.
The host page, server, and policy engine must receive only ciphertext, public
commitments, receipts, and transcript hashes.

Transcript binding must include:

- wallet id and wallet key id
- source lane id and source lane share epoch
- target lane id and target lane share epoch
- source holder principal and target holder principal
- server custody record id
- public wallet key
- `H_new` and `S_new`
- mandate policy digest for delegated lanes
- linked-device permission policy digest for linked-device lanes
- QR link-session id and link public key for linked-device lanes
- envelope AAD hash
- operation id and idempotency key
- protocol version

Failure handling:

- if parity verification fails, discard the pending epoch
- if holder-share delivery fails, discard the pending epoch
- if server-share sealing fails, discard the pending epoch
- if activation fails after both shares are sealed, keep the old epoch active
  until an explicit retry or operator-approved cleanup
- after activation, reject the old epoch for signing
- retained rollback material must stay unavailable to signing admission

This protocol is operationally secure under the current trusted-service model.
It does not provide a full malicious-secure resharing proof. A future FROST or
malicious-secure protocol should replace this section for stronger adversarial
settings.

## Rotation Job Lifecycle

Rotation jobs need explicit state so old and new epochs cannot both sign.

```ts
type RotationJobLifecycle =
  | {
      state: 'preparing';
      operationId: RotationOperationId;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'awaiting_server_commitment';
      operationId: RotationOperationId;
      holderCommitmentB64u: string;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'awaiting_holder_delivery';
      operationId: RotationOperationId;
      holderCommitmentB64u: string;
      serverCommitmentB64u: string;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'ready_to_activate';
      operationId: RotationOperationId;
      holderCommitmentB64u: string;
      serverCommitmentB64u: string;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'activated';
      operationId: RotationOperationId;
      activatedAtMs: number;
      failedAtMs?: never;
    }
  | {
      state: 'failed';
      operationId: RotationOperationId;
      failedAtMs: number;
      failureReason: RotationFailureReason;
      activatedAtMs?: never;
    };
```

Only an active lane epoch can sign. Pending epochs are never admitted for
signing. A refresh activates by atomically marking the new epoch active and the
old epoch retired.

## Concurrency And Fencing

Every rotation must acquire a lock scoped to `walletKeyId` and `laneId`.
Delegated lane creation also needs a wallet-key-level sequencing check so two
new agent lanes cannot reuse the same operation id or target lane id.

Admission checks must reject:

- stale `laneShareEpoch`
- stale `revocationEpoch`
- pending rotation job for the same lane
- missing server-share record for the exact lane epoch
- missing holder delivery receipt for delegated lanes
- idempotency key replay with a different transcript hash

Revocation has priority over rotation. If a delegated lane is revoked while a
refresh is pending, the pending job fails and no replacement lane activates
without fresh owner approval.

## Owner Passkey Lane Refresh

Triggers:

- passkey compromise
- migration from deterministic passkey shares
- device replacement
- policy-driven periodic rotation
- recovery after local storage loss

Flow:

1. User authenticates with current passkey, another owner lane, or recovery code.
2. Wallet opens current holder share inside worker boundary.
3. Server resolves matching active server share.
4. Run holder-sampled additive delta reshare.
5. Seal new holder share under passkey KEK.
6. Generate or rotate recovery-code envelopes when required.
7. Verify wallet address parity.
8. Retire old holder and server share epoch.

## Owner Email OTP Lane Refresh

Triggers:

- recovery-code rotation after recovery
- Email OTP client-secret compromise
- device enrollment replacement
- policy-driven periodic rotation

Flow:

1. User completes Email OTP or recovery-code auth.
2. Worker opens current holder share or recovery-wrapped holder-share envelope.
3. Server resolves matching active server share.
4. Run holder-sampled additive delta reshare.
5. Seal new holder share under the Email OTP holder-share envelope.
6. Store 10 active recovery-wrapped holder-share envelopes.
7. Verify wallet address parity.
8. Retire old lane epoch.

## Delegated Agent Lane Creation

Creating a delegated agent lane is a share-creation operation for an existing
wallet key.

Flow:

1. User authenticates through owner lane.
2. User approves delegate principal and mandate policy.
3. Current owner lane or recovery path participates in holder-sampled additive
   delta reshare.
4. System creates agent holder share and matching server share.
5. Agent holder share is encrypted to the agent custody boundary.
6. Server share is sealed for relayer/server custody.
7. New delegated lane becomes active.

The transcript must bind:

- wallet key id
- new lane id
- delegate principal id
- mandate policy digest
- holder custody key
- server custody role
- lane share epoch
- expiry and revocation epoch

## Linked Device Lane Creation

Creating a linked-device lane is the QR link-device replacement for the new
delegated signer architecture.

Flow:

1. Device 2 creates a QR link session with an ephemeral link public key.
2. Device 1 scans the QR code and authenticates through an owner lane.
3. User approves owner-equivalent or scoped device permissions.
4. Owner lane participates in holder-sampled additive delta reshare.
5. System creates linked-device holder share and matching server share.
6. Linked-device holder share is encrypted to the link-session public key.
7. Device 2 receives the encrypted holder share through the relay.
8. Device 2 seals the holder share under its local passkey or custody KEK.
9. Device 2 returns a delivery receipt.
10. New linked-device lane becomes active.

The transcript must bind:

- wallet key id
- source owner lane id and source lane share epoch
- new linked-device lane id
- device principal id
- link session id
- link public key
- permission policy digest
- server custody role
- lane share epoch
- expiry and revocation epoch

Owner-equivalent linked-device lanes should still require local user presence
for signing. Scoped linked-device lanes should use the same mandate admission
checks as agent lanes.

## Delegated Agent Lane Refresh

Triggers:

- agent custody-key rotation
- policy-driven periodic rotation
- suspected agent share exposure
- move from managed service custody to TEE/HSM custody

Flow:

1. Authenticate owner or authorized delegation administrator.
2. Freeze the delegated lane.
3. Run holder-sampled additive delta reshare for that lane.
4. Encrypt new agent holder share to the active custody boundary.
5. Seal new server share.
6. Verify wallet address parity.
7. Activate new lane epoch.
8. Retire old agent share package and server share.

## Delegated Agent Lane Revocation

Revocation should have two layers.

Immediate policy revocation:

1. Mark lane revoked.
2. Increment revocation epoch.
3. Disable matching server share.
4. Reject queued and in-flight signing requests.
5. Emit audit evidence.

Cryptographic cleanup:

1. Destroy or retire server share material.
2. Mark agent share package revoked.
3. Rotate adjacent server custody if compromise scope is uncertain.
4. Issue a replacement lane only after fresh owner approval.

If both old lane shares may have been compromised, treat the lane as fully
compromised and evaluate wallet rekey.

## Data Model

```ts
type LaneShareEpochState =
  | {
      state: 'active';
      laneShareEpoch: LaneShareEpoch;
      activatedAtMs: number;
      retiredAtMs?: never;
    }
  | {
      state: 'retired';
      laneShareEpoch: LaneShareEpoch;
      activatedAtMs: number;
      retiredAtMs: number;
    }
  | {
      state: 'revoked';
      laneShareEpoch: LaneShareEpoch;
      revokedAtMs: number;
      revokedReason: LaneRevocationReason;
      activatedAtMs?: never;
      retiredAtMs?: never;
    };
```

Rotation job:

```ts
type ShareRotationJob =
  | {
      kind: 'holder_envelope_rewrap';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      targetEnvelopeVersion: string;
    }
  | {
      kind: 'signing_lane_creation';
      walletKeyId: WalletKeyId;
      sourceLaneId: SigningLaneId;
      sourceLaneShareEpoch: LaneShareEpoch;
      targetLaneId: SigningLaneId;
      targetLaneKind: 'delegated_agent' | 'linked_device';
      targetLaneShareEpoch: LaneShareEpoch;
      permissionPolicyDigest: string;
      lifecycle: RotationJobLifecycle;
    }
  | {
      kind: 'lane_share_refresh';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      fromLaneShareEpoch: LaneShareEpoch;
      toLaneShareEpoch: LaneShareEpoch;
      rotationReason: LaneShareRotationReason;
      lifecycle: RotationJobLifecycle;
    }
  | {
      kind: 'delegated_lane_revocation';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      revocationEpoch: number;
      revokedReason: LaneRevocationReason;
    }
  | {
      kind: 'server_internal_custody_rotation';
      signingRootId: SigningRootId;
      rootShareEpoch: RootShareEpoch;
      rotationReason: ServerCustodyRotationReason;
    };
```

## Relationship To `rotate-korg-secrets.md`

Keep `docs/rotate-korg-secrets.md` as a server-custody plan only if Router A/B
continues to own signing-root custody.

It should cover:

- `k_org` generation and backup
- A/B root-share rewrap
- A/B root-share refresh
- self-host export or resharing
- server custody incident response

It should not be used as the plan for:

- owner passkey share rotation
- Email OTP holder-share rotation
- delegated agent lane creation
- delegated agent lane revocation
- effective server share rotation for one lane

Those belong to this plan and to the lane architecture in refactor 70.

## Moved Router A/B Phase 7 Scope

The former `Recovery, Rotation, And Migration` Phase 7 from
[router-a-b-SPEC.md](./router-a-b-SPEC.md) is split here.
Wallet/lane rotation belongs to this plan. Router A/B root custody remains in
the Router spec as server-custody work.

Moved lane-rotation responsibilities:

- address/public-key parity before and after lane share refresh
- SigningWorker effective share refresh when a root-share epoch change changes
  the server-side material used by a lane
- rollback fencing for old and new lane epochs
- hosted lane-share retirement evidence after replacement
- self-host migration evidence for exported lane authority

Router A/B responsibilities kept in the Router spec:

- role-local share rewrap
- distributed or approved-provisioning root-share refresh
- Router A/B self-host export/import vectors
- hosted disablement for Router A/B custody
- Router A/B root-epoch rollback behavior and stale-epoch rejection

## Prep Phase: Rotation Types And Fencing

This phase is additive. It should make rotation jobs representable before any
share material moves differently.

### Folder Layout To Prepare

```text
packages/shared-ts/src/signing-lanes/
  rotation.ts
  rotationTranscript.ts
  rotationFencing.ts
  rotation.typecheck.ts

packages/sdk-web/src/core/signingEngine/session/lanes/rotation/
  additiveDeltaReshareTypes.ts
  rotationTranscript.ts
  pendingLaneActivation.ts
  rotationGuards.typecheck.ts

packages/sdk-server-ts/src/core/signingLanes/
  SigningLaneRotationStore.ts
  SigningLaneLockStore.ts
  RotationTranscriptStore.ts
```

### Structs To Introduce First

Add type-only records:

- `SigningLaneCreationJob`
- `LaneShareRefreshJob`
- `HolderEnvelopeRewrapJob`
- `ServerInternalCustodyRotationJob`
- `RotationJobLifecycle`
- `RotationTranscriptBinding`
- `RotationFencingDecision`
- `LaneActivationDecision`
- `AdditiveDeltaReshareCommitment`

These structs should distinguish lane creation from lane refresh. Lane creation
has a source owner lane and a target delegated signer lane. Lane refresh has one
lane moving from an old epoch to a new epoch.

### Non-Breaking Work Available Today

- add rotation job unions and type fixtures
- add transcript binding builders with dummy commitments
- add source guards proving `delta` cannot appear in persisted records
- add lock-store interfaces without concrete persistence
- add activation decision types that make pending epochs unavailable for signing
- add tests that old and new epochs cannot both be active in a typed activation
  result
- add route and store names for future rotation jobs without wiring routes

Prep should leave these behaviors unchanged:

- current server-share custody rotation behavior
- current signing-grant admission and budget accounting
- current link-device flow
- current passkey and Email OTP signing behavior
- current `docs/rotate-korg-secrets.md` content until the server-custody split
  is implemented

### Prep Progress

- [x] Added shared rotation job unions for lane creation, lane refresh, holder
      envelope rewrap, and server internal custody rotation.
- [x] Added rotation lifecycle, additive delta commitment, and lane activation
      decision types.
- [x] Added type fixtures proving lane creation keeps source and target lane
      identity separate.
- [x] Added server store interfaces for rotation jobs, lane locks, and rotation
      transcripts without concrete persistence adapters.

## Implementation Phases

### Phase 0: Terminology And Guards

- [ ] Rename top-level share rotation work to signing-lane rotation.
- [ ] Keep `k_org` rotation under server custody.
- [ ] Add source guards for stale `relayer-share refresh` language in
      user/agent lane code.
- [ ] Document that effective server share rotation requires holder-side
      participation.
- [ ] Complete the additive rotation-types prep phase.

### Phase 1: Lane Epoch Identity

- [ ] Add `laneShareEpoch` to lane records.
- [ ] Add `laneShareEpoch` to `thresholdSessionId` claims, `signingGrantId`
      claims, and budget status checks.
- [ ] Add `laneShareEpoch` to holder and server share envelopes.
- [ ] Reject signing requests that present stale lane epochs.
- [ ] Add lane-scoped rotation locks and wallet-key-level operation sequencing.

### Phase 2: Envelope Rewrap

- [ ] Implement passkey holder-share envelope rewrap.
- [ ] Implement recovery-code envelope rotation.
- [ ] Implement agent custody-key envelope rewrap.
- [ ] Implement server-share KEK rewrap.
- [ ] Verify rewrap does not change wallet address or share commitments.

### Phase 3: Lane Share Refresh

- [ ] Implement holder-sampled additive delta reshare for two-party lanes.
- [ ] Persist rotation job lifecycle states.
- [ ] Add owner passkey lane refresh.
- [ ] Add owner Email OTP lane refresh.
- [ ] Add delegated agent lane refresh.
- [ ] Add QR linked-device lane creation.
- [ ] Add wallet public key parity checks.
- [ ] Make old lane epochs unavailable for signing at activation.
- [ ] Schedule cleanup for inactive rollback material.
- [ ] Add transcript hash and idempotency checks.

### Phase 4: Delegated Revocation

- [ ] Add revocation epoch to delegated lanes.
- [ ] Disable matching server share on revocation.
- [ ] Reject queued and in-flight requests after revocation.
- [ ] Fail pending rotation jobs when the lane is revoked.
- [ ] Add stale agent-share tests.
- [ ] Add replacement delegated-lane flow.

### Phase 5: Server Custody Rotation Split

- [ ] Narrow `rotate-korg-secrets.md` to server-custody work.
- [ ] Move lane rotation references out of that doc.
- [ ] Add cross-reference to this plan.
- [ ] Keep self-host and root-share backup content in the server-custody plan.

### Phase 6: Router A/B Phase 7 Migration

- [ ] Move generic wallet/lane rotation requirements out of
      `docs/router-a-b-SPEC.md`.
- [ ] Keep Router A/B Phase 7 scoped to server-custody rotation, root-share
      refresh, self-host export/import, hosted disablement, and root-epoch
      rollback evidence.
- [ ] Add address/public-key parity gates here for owner lane refresh,
      delegated agent lane refresh, and QR linked-device lane creation.
- [ ] Add SigningWorker effective-share refresh gates when Router A/B
      root-share epoch changes affect active lane server shares.
- [ ] Add rollback-fencing tests proving old and new lane epochs cannot both
      sign after activation.
- [ ] Add retirement evidence for hosted lane shares and exported self-host lane
      authority.

## Validation

Static checks:

- signing request without `laneShareEpoch` fails
- signing-lane creation job without source and target lane identity fails
- lane-share refresh job without both old and new epoch fails
- lane-share refresh job without lifecycle fails
- delegated revocation job without revocation epoch fails
- server internal custody rotation cannot carry holder-share fields
- holder envelope rewrap cannot change share commitment

Unit tests:

- additive delta reshare preserves public key
- additive delta reshare rejects parity mismatch
- additive delta value is absent from persisted records
- signing-lane creation records source owner lane and target lane separately
- server rewrap preserves effective server share
- lane share refresh preserves wallet address
- lane share refresh retires old epoch
- stale lane epoch cannot sign
- pending lane epoch cannot sign
- old and new epochs cannot both sign after activation
- root-share epoch changes cannot bypass lane epoch fencing
- revoked delegated lane cannot sign
- revoked lane fails pending rotation job
- owner lane signs after delegated lane revocation
- recovery-code rotation creates exactly 10 active envelopes

Integration tests:

- migrate deterministic passkey lane, sign, rotate lane, sign again
- create delegated agent lane, sign, revoke, confirm signing fails
- scan QR to create linked-device lane, sign, revoke, confirm signing fails
- rotate server internal custody, confirm active lanes still sign
- rotate Router A/B root custody, refresh affected lane server shares when
  policy requires it, confirm stale lane epochs fail
- simulate relayer compromise and refresh affected lane server shares

## Non-Goals

- server-only effective MPC share rotation for an active two-party lane
- wallet address preservation during wallet rekey
- full malicious-secure resharing proof in the first implementation
- generic omnibus balances for agents
- ambient unlocked-wallet delegation

## Open Questions

- Which address-preserving resharing protocol should be the first production
  target?
- Should first implementation use an approved provisioning ceremony while
  resharing is finalized?
- Which compromise cases require wallet rekey?
- Can server custody rotation remain under Router A/B after passkey lanes move
  to wrapped holder shares?
- Should lane epochs be globally monotonic per wallet key or scoped per lane?
- How long should inactive old-epoch material remain available for
  operator-approved cleanup or recovery?
