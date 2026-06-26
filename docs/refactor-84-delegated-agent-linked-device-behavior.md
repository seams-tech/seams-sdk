# Delegated Agent And Linked-Device Behavior

Date created: June 15, 2026

Status: design plan. This plan owns the full delegated-agent and linked-device
behavior that was split out of
[refactor-82-delegate-wallets.md](./refactor-82-delegate-wallets.md).

## Dependencies

- [refactor-81-passkey-account-refactor.md](./refactor-81-passkey-account-refactor.md)
  supplies wrapped holder-share envelopes.
- [refactor-82-delegate-wallets.md](./refactor-82-delegate-wallets.md) supplies
  `WalletKey`, `SigningLane`, owner-lane normalization, lane policy types, and
  raw-boundary parsers.
- [refactor-83-share-rotation.md](./refactor-83-share-rotation.md) supplies lane
  share epochs, address-preserving refresh, stale-epoch rejection, and
  cryptographic revocation primitives.

## Goal

Add delegated agent wallets and linked-device signer lanes with cryptographic
revocation and audit separation.

The target user stories are:

```text
User approves a bounded mandate.
System creates a delegated agent signing lane.
Agent receives a lane-scoped MPC holder share.
Agent can request signatures only through policy-admitted flows.
Revocation disables that lane without changing the wallet address.
Owner lanes and unrelated agent lanes continue to work.
```

```text
New device shows a QR code with a link-session public key.
Existing owner device scans the QR code.
User approves full or scoped device permissions.
System creates a linked-device signing lane.
New device receives a lane-scoped MPC holder share.
Revocation disables that device without affecting other lanes.
```

## Scope

This plan owns behavior, route registration, product flows, and operational
surfaces. It consumes the lane-domain foundation from refactor-82 instead of
adding optional lane fields to older signing records.

Owned here:

- delegated signer lane creation
- linked-device lane creation
- delegated signing admission
- linked-device signing admission
- immediate delegated and linked-device revocation
- user and operations surfaces for delegation lifecycle

Owned by refactor-83:

- lane share epochs
- lane share refresh
- server-share disablement primitives
- stale-epoch rejection
- rollback fencing

## Phase 0: Behavior Readiness Gate

- [ ] Confirm refactor-81 wrapped holder-share registration and login paths are
      available for owner passkey lanes.
- [ ] Confirm refactor-82 owner lanes are normalized and current signing behavior
      works through explicit lane identity.
- [ ] Confirm refactor-83 lane epoch and revocation primitives are available.
- [ ] Confirm route shells from refactor-82 remain unregistered before this plan.

## Phase 1: Delegated Signer Lane Creation

- [ ] Add user-confirmed delegation UI.
- [ ] Add mandate digest display and approval.
- [ ] Implement address-preserving delegated-lane creation ceremony.
- [ ] Encrypt holder-share package to named agent custody boundary.
- [ ] Store matching server-share record.
- [ ] Emit creation and delivery receipts.
- [ ] Require custody binding and agent receipt before activation.

## Phase 2: Linked-Device Lane Creation

- [ ] Rework QR link-device authorization to create a linked-device lane.
- [ ] Support owner-equivalent and scoped linked-device permission policies.
- [ ] Separate linked-device signing scope from account-administration scope.
- [ ] Relay encrypted linked-device holder-share packages to the new device.
- [ ] Require linked-device holder-share delivery receipt before activation.

## Phase 3: Agent Signing Admission

- [ ] Add delegated signing request parser.
- [ ] Verify delegate principal and lane status.
- [ ] Verify mandate policy, exact intent digest, budget, and expiry.
- [ ] Validate final unsigned transaction against admitted intent.
- [ ] Reject broad approvals and arbitrary calls outside explicit mandate scope.
- [ ] Enforce idempotency before budget reservation.
- [ ] Block signing before any share participation on policy failure.
- [ ] Record denied and admitted agent requests.

## Phase 4: Linked-Device Signing Admission

- [ ] Resolve linked-device lane identity before signing.
- [ ] Require local user presence for owner-equivalent linked-device lanes.
- [ ] Route scoped linked-device lanes through the delegated mandate pipeline.
- [ ] Bind warm sessions to linked-device `laneId` and `laneShareEpoch`.
- [ ] Reject revoked, suspended, expired, or stale linked-device lanes.

## Phase 5: Revocation

- [ ] Add immediate lane revocation.
- [ ] Disable matching server share through refactor-83 primitives.
- [ ] Reject stale revocation epochs.
- [ ] Stop queued operations.
- [ ] Clear warm sessions for revoked linked-device lanes.
- [ ] Add tests proving owner lanes remain active after delegated-lane
      revocation.
- [ ] Require fresh user authorization before issuing a replacement delegated
      lane.

## Phase 6: Product And Operations Surface

- [ ] Add dashboard list for active, suspended, expired, and revoked agent
      wallets.
- [ ] Add dashboard list for linked devices and permission profiles.
- [ ] Add pause, resume, budget top-up, expiry extension, and policy-version
      update flows.
- [ ] Add webhook or notification events for creation, signing, denial,
      suspension, expiry, and revocation.
- [ ] Add out-of-policy owner approval flow for specific purchase requests.
- [ ] Add activity export for delegated signing audit evidence.

## Validation

Static checks:

- delegated lane without `delegatePrincipal` fails
- delegated lane without `mandatePolicy` fails
- owner lane with `delegatePrincipal` fails
- linked-device lane without `devicePrincipal` fails
- owner-equivalent linked-device policy with `mandatePolicy` fails
- scoped linked-device policy without `mandatePolicy` fails
- scoped linked-device policy with account-administration scope fails
- revoked lane with active-only fields fails
- active lane with revoked-only fields fails

Unit tests:

- linked-device lane creation stores a distinct holder share and server share
- owner-equivalent linked-device lane requires local user presence
- scoped linked-device lane uses delegated mandate checks
- linked-device admin actions require the configured administration scope
- revoked linked-device lane cannot sign
- creation rejects unknown agent custody boundary
- creation rejects missing mandate digest
- signing rejects revoked lane
- signing rejects mismatched agent principal
- signing rejects destination outside counterparty scope
- signing rejects amount above per-operation limit
- signing rejects final transaction that exceeds the admitted intent
- reused idempotency key with different digest fails
- suspended lane cannot sign
- expired lane cannot sign
- revocation prevents stale agent share from using active server share
- owner passkey lane still signs after delegated lane revocation

Integration tests:

- scan QR, approve owner-equivalent linked device, sign from new device, revoke,
  confirm signing fails
- scan QR, approve scoped linked device, confirm out-of-scope signing fails
- create agent lane, sign admitted payment, revoke lane, confirm signing fails
- create two agent lanes, revoke one, confirm the other remains active
- pause agent lane, confirm signing fails, resume, confirm signing works
- submit duplicate delegated request, confirm idempotent result
- recover owner access after delegated-agent compromise

## Non-Goals

- giving agents wallet private keys
- treating agent lanes as owner lanes
- letting delegated lanes change recovery factors
- letting delegated lanes export wallet keys
- relying on ambient warm user sessions for agent autonomy
- supporting unbounded agent mandates
- full malicious-secure MPC proof work in the first implementation

## Open Questions

- Which agent custody targets are acceptable for the first release?
- Is a managed service custody target acceptable before TEE or HSM support?
- Which payment protocols should have first-class mandate digest builders?
- Does each merchant identity need an on-chain address allowlist, a verified
  domain binding, or both?
- Should delegated lanes support single-use mandates as a separate lane kind?
- Should revoked agent lanes be physically deleted after evidence export or kept
  as retired records?
- Which owner lane is required for high-risk delegation creation?
- Which allowance forms are acceptable for first release: exact transfer only,
  bounded ERC-20 approval, Permit2, NEAR function-call access keys, or a smaller
  subset?
