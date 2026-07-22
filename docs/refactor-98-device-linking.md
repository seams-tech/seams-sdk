# Linked-Device Enrollment, Signing, And Revocation

Date created: June 15, 2026

Rewritten: July 22, 2026

Status: active product plan. A dormant QR v4 parser and public API, React, and
wallet-iframe UI shells exist. The exported link flow still uses a superseded QR
shape and fails closed. Device linking, lane provisioning, signing admission,
and revocation remain disabled.

## Scope And Dependencies

This plan owns physical and browser device linking. A linked device becomes a
share-bearing participant for existing wallet keys and requires local user
presence for the first release.

It consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical capability hydration, active ECDSA manifests, activation
  commits, exact operation execution, and Wallet Session admission;
- [refactor-95-passkey-account-refactor.md](./refactor-95-passkey-account-refactor.md)
  for wrapped roots, holder-share envelopes, and wallet-scoped recovery;
- [refactor-96-wallet-execution-lanes.md](./refactor-96-wallet-execution-lanes.md)
  for curve-specific wallet keys, linked-device lanes, lifecycle, and
  execution admission;
- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) for Yao
  Ed25519 recipient provisioning, ECDSA additive target-lane resharing,
  aggregate activation, refresh, and revocation.

[refactor-99-agent-id-spending.md](./refactor-99-agent-id-spending.md) owns
agent identity and delegated spending. No agent identity, custody, mandate,
budget, or agent-request type belongs in this plan.

## Goal

Give a new physical device an independently revocable, owner-approved signing
capability for an exact wallet-key set.

```text
Device 2 displays an unclaimed QR session.
Device 1 authenticates and approves the device and permissions.
One child execution lane is provisioned for each approved wallet key.
Device 2 seals each holder capability under its own passkey.
The aggregate device enrollment activates after every receipt verifies.
Device 2 signs through its own lanes with local user presence.
Revocation disables the device without affecting owner or unrelated lanes.
```

## Required Invariants

1. Device 2 creates no wallet and receives no wallet identity before an
   authenticated owner claims its link session.
2. The QR contains public bootstrap material only. It never contains wallet,
   account, share, root, recovery, PRF, KEK, Wallet Session, or export material.
3. Owner approval binds the exact device, wallet, ordered wallet-key manifest,
   permission, target lanes, participants, protocol versions, and expiry.
4. Every target lane remains unavailable until all child protocols and the
   aggregate receipt commit.
5. Device 2 opens holder packages only inside the wallet worker and persists
   sealed custody envelopes plus public projections.
6. The first release requires local user presence for every signature and
   exposes signing-only administration scope.
7. Device revocation rejects new admission before share work, terminates
   pending work, disables every child server capability, and preserves owner
   lanes.
8. Device linking cannot create agent identity, delegated-spend authorization,
   recovery authority, export authority, or an account-admin grant.
9. Raw QR, relay, persistence, callback, and WebAuthn shapes are normalized
   once at their boundaries.
10. Superseded QR shapes, stubs, fixtures, and diagnostics are deleted at
    cutover. No compatibility parser enters core logic.

## Roles And Trust Boundaries

### Device 1

- owns an active owner lane;
- authenticates the linking operation with fresh user verification;
- obtains authorization through the wallet iframe and server-verified Wallet
  Session boundary;
- displays Device 2 identity, key coverage, permissions, expiry, and revocation
  consequences;
- approves one exact enrollment transcript;
- participates in holder-side provisioning required by Refactor 97.

Wallet Session JWTs remain inside the authenticated request boundary. QR
payloads, public results, callbacks, and progress events never carry them.

### Device 2

- generates an ephemeral link-encryption keypair;
- generates a persistent device identity keypair;
- creates an unclaimed, short-lived relay session;
- creates its passkey after owner claim binds the session to a wallet;
- opens holder packages inside the wallet worker;
- stores sealed envelopes and public capability projections;
- returns exact child and aggregate receipts.

### Relay And Router

- store public link-session state, policy digests, ciphertext, and receipts;
- atomically bind one authenticated owner and wallet to an unclaimed session;
- authorize one exact wallet-key manifest;
- coordinate curve-specific child protocols;
- keep partial enrollments unavailable to signing;
- fence cancellation, expiry, activation, and revocation;
- never receive plaintext roots, holder shares, PRF output, KEKs, recovery
  codes, Yao private outputs, or export-capable ECDSA shares.

### Deriver A And Deriver B

- participate only in admitted Ed25519 lifecycle operations defined by Yao;
- produce recipient-isolated Device 2 and SigningWorker packages;
- remain outside ordinary signing.

### SigningWorker Or ECDSA Relayer Participant

- activates only exact target-lane material;
- checks lane, share epoch, revocation epoch, enrollment, Wallet Session, and
  protocol transcript;
- cannot sign without Device 2 holder participation and Router admission.

## Linked-Device Session State

Use one exhaustive state machine:

```ts
type LinkedDeviceSessionState =
  | {
      state: 'displaying_qr';
      linkSessionId: LinkDeviceSessionId;
      expiresAtMs: number;
      walletId?: never;
      enrollmentId?: never;
    }
  | {
      state: 'claimed_by_owner';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      claimExpiresAtMs: number;
    }
  | {
      state: 'awaiting_target_passkey';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      credentialDeadlineMs: number;
    }
  | {
      state: 'provisioning';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      keyManifestDigestB64u: string;
    }
  | {
      state: 'awaiting_aggregate_receipt';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      keyManifestDigestB64u: string;
    }
  | {
      state: 'active';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      activatedAtMs: number;
    }
  | {
      state: 'expired_unclaimed';
      linkSessionId: LinkDeviceSessionId;
      expiredAtMs: number;
      walletId?: never;
      enrollmentId?: never;
    }
  | {
      state: 'expired_claimed';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      expiredAtMs: number;
    }
  | {
      state: 'cancelled_unclaimed';
      linkSessionId: LinkDeviceSessionId;
      cancelledAtMs: number;
      walletId?: never;
      enrollmentId?: never;
    }
  | {
      state: 'cancelled_claimed_precommit';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      cancelledAtMs: number;
    }
  | {
      state: 'committed_completion_required';
      linkSessionId: LinkDeviceSessionId;
      walletId: WalletId;
      enrollmentId: LinkedDeviceEnrollmentId;
      transcriptSetDigestB64u: string;
    };
```

Core operations accept the narrow branch they require. Progress and diagnostic
events project from this state and cannot control it.

## QR Payload

The sole QR boundary is:

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

The parser validates the exact version and purpose, branded session identity,
key encodings, permission branch, issue time, and expiry. It rejects unknown
fields that could smuggle wallet or authorization state.

The current exported `DeviceLinkingQRData`, `linkDevice.ts`, and
`scanDevice.ts` use a superseded payload with `sessionId`, optional
`accountId`, `timestamp`, and an unconstrained version. Replace that surface
directly and delete its Refactor 84 diagnostic and fixtures.

## Device 2: Prepare Link

1. Generate `linkSessionId` from cryptographic randomness.
2. Generate an ephemeral HPKE/link-encryption keypair in the wallet worker.
3. Generate a persistent device identity keypair.
4. Preflight WebAuthn PRF availability without creating wallet-bound custody.
5. Register the public unclaimed session with the relay.
6. Render the parsed v4 QR payload.
7. Subscribe to authenticated session updates.

SSE plus POST is the preferred first transport:

- SSE carries claimed, credential-required, provisioning, delivery, active,
  expired, and terminal events to Device 2;
- POST requests claim, register the target credential, acknowledge delivery,
  cancel, and retry exact committed delivery;
- authenticated polling may implement the same protocol;
- WebSocket transport remains an adapter choice.

## Device 1: Claim And Approve

1. Scan and parse the v4 payload.
2. Resolve the active owner wallet and exact wallet-key inventory.
3. Authenticate with fresh user verification through an active owner lane.
4. Claim the unclaimed session atomically.
5. Display Device 2 identity fingerprint, requested permission, exact key
   coverage, local-presence requirement, expiry, and revocation path.
6. Approve an enrollment transcript binding:
   - link session, device identity, and link public key;
   - wallet and ordered wallet-key manifest;
   - source owner lanes and epochs;
   - target lane IDs and epochs;
   - permission-policy digest;
   - operation ID, idempotency key, protocol versions, and expiry.
7. Send authorization and holder-side contributions through the authenticated
   Router boundary.

A blockchain transaction is unnecessary. The link authorization uses the
current Wallet Session, fresh passkey assertion, and worker-owned holder
participation.

## Device 2: Create Passkey And Receive Material

After the authenticated claim reveals the wallet identity:

1. Create a wallet-bound passkey and derive its KEK in the wallet worker.
2. Register credential identity and device binding with the claimed session.
3. Receive one encrypted package per target wallet key:
   - Ed25519 Yao Client/holder recipient package;
   - ECDSA additive target holder-share package.
4. Verify enrollment, wallet key, public identity, lane, epoch, policy,
   participant, and transcript bindings.
5. Seal each holder capability under the passkey KEK.
6. Persist public projections and sealed envelopes.
7. Return one receipt per key and one aggregate manifest receipt.

The worker rejects missing or duplicate keys, wrong public identity, recipient
swap, transcript mismatch, stale session, unsupported protocol, and any package
containing export authority.

## Aggregate Activation

The Router activates the device only when:

- the delivered manifest equals the approved ordered manifest;
- every child protocol is committed;
- every target server or SigningWorker capability is ready;
- every Device 2 receipt verifies;
- the aggregate receipt covers the complete target set;
- owner authorization and session are current;
- no cancellation, expiry, or revocation fence is active.

Activation marks the parent enrollment and every child lane active through one
durable visibility commit. Device 2 then receives a Wallet Session grant bound
to its exact enrollment and lanes.

## First-Release Permission

The first release supports exactly:

```text
permission kind: owner_equivalent
administration scope: signing_only
local user presence: required
```

Device-management and account-administration scopes remain unavailable. A
future scoped-device design requires its own explicit device principal,
permission union, local-presence policy, and approval flow. It cannot reuse an
agent authorization record.

## Linked-Device Signing

For every signing request:

1. Authenticate Device 2 passkey and device identity.
2. Resolve the active parent device enrollment.
3. Resolve the active child lane for the requested wallet key.
4. Verify share epoch, revocation epoch, participants, and exact curve session.
5. Verify Wallet Session audience, device binding, budget, and expiry.
6. Require local confirmation of the exact normalized intent.
7. Verify the final unsigned transaction still matches that intent.
8. Sign through the normal Client/SigningWorker or ECDSA threshold path.
9. Consume budget and record device, lane, enrollment, and operation identity
   exactly once.

Ed25519 signing performs zero Deriver calls. ECDSA signing consumes one-use
presignature state and retains the same wallet public key and address as owner
lanes.

## Immediate Device Revocation

One aggregate revocation operation:

1. Marks the parent enrollment revoked and increments its revocation epoch.
2. Rejects new admission before share work.
3. Stops queued and pending signing operations.
4. Revokes every child lane and advances each lane revocation epoch.
5. Disables matching SigningWorker and ECDSA relayer capabilities.
6. Clears Device 2 Wallet Sessions, warm handles, and pending delivery state.
7. Emits per-key and aggregate revocation receipts.

Owner lanes and unrelated devices remain active. Confirmed compromise may later
trigger server-share destruction evidence and refresh of remaining lanes.
Immediate server-participant disablement is required for the first release.

## Recovery And Linking

- recovery replaces access to an existing owner lane;
- linking creates new independently revocable device lanes;
- recovery-code and Email OTP recovery remain wallet recovery authorities;
- linked devices gain no recovery authority through ordinary enrollment;
- device revocation leaves owner recovery methods unchanged.

## Public SDK Surface

```text
startDevice2LinkingFlow()
scanAndLinkDevice()
cancelDeviceLinking()
listLinkedDevices()
revokeLinkedDevice()
```

Success returns enrollment ID, device ID, exact active lane references, and the
manifest digest. Recoverable failures use result unions. Cancellation
distinguishes precommit cleanup from committed completion-required recovery.
Direct SDK and iframe routes share one parsed request and service.

No agent method, agent option bag, mandate editor, or delegated budget appears
in this surface.

## Product And Audit Surface

Device management shows:

- device label and platform;
- permission and administration scope;
- covered wallet keys;
- provisioning, active, suspended, expired, or revoked state;
- last activity and creation time;
- revocation action and consequences.

Audit records enrollment, owner approval, protocol commitment, holder delivery,
activation, signing admission, denial, budget consumption, suspension, expiry,
refresh, and revocation.

## Implementation Phases

### Phase 0: Readiness

- [ ] Refactor 95 portable owner custody and recovery pass.
- [ ] Refactor 96 wallet-key and linked-device lane records pass.
- [ ] Refactor 97 target-lane protocols and aggregate activation pass.
- [ ] Aggregate receipt, crash-recovery, and revocation stores exist.
- [ ] Yao production remains gated exactly as documented.

### Phase 1: Session And Claim

- [ ] Replace the superseded QR surface with the v4 state machine.
- [ ] Implement unclaimed sessions, authenticated owner claim, and expiry.
- [ ] Delete legacy QR types, parsers, diagnostics, and fixtures.

### Phase 2: Device Credential And Provisioning

- [ ] Create Device 2 passkey only after claim.
- [ ] Provision exact Ed25519 and ECDSA child lanes.
- [ ] Require child and aggregate receipts.
- [ ] Resume committed delivery safely after transport or process failure.

### Phase 3: Signing And Revocation

- [ ] Mint enrollment-bound Wallet Sessions.
- [ ] Require local user presence for every signature.
- [ ] Route each key family through its normal signing path.
- [ ] Implement immediate aggregate revocation.
- [ ] Prove owner and unrelated device lanes remain available.

### Phase 4: Product Completion

- [ ] Add device management and activity views.
- [ ] Add refresh and compromise cleanup flows.
- [ ] Add operator recovery for committed delivery that cannot complete on the
      original link session.

## Validation

Static fixtures prove:

- unclaimed states cannot contain wallet or enrollment identity;
- active states require exact wallet and enrollment identity;
- device records cannot carry agent identity, mandate, or custody fields;
- device permission cannot grant delegated or recovery authority;
- Ed25519 and ECDSA child results cannot be swapped;
- success requires a nonempty exact lane manifest;
- cancellation after output commitment cannot enter a precommit state.

Focused tests prove:

- malformed, expired, replayed, and already-claimed QR sessions fail;
- owner approval binds exact device, wallet, lanes, participants, and policy;
- Device 2 creates no wallet before claim;
- substituted or partial holder delivery fails before persistence;
- mixed wallets remain inactive until all receipts verify;
- each supported chain signs with local presence;
- revocation disables every child lane and preserves owner signing;
- export and recovery requests from linked-device lanes fail.

Lifecycle tests prove:

- SSE reconnect resumes authenticated state;
- precommit cancellation cleans up;
- postcommit failure enters completion-required recovery;
- refresh, reload, lock, and page hide expose no holder material;
- UI projections cannot activate an enrollment.

## Non-Goals

- agent identity or delegated-agent enrollment;
- owner-signed agent spending mandates;
- transferring funds to a linked-device account;
- placing wallet identity or secret material in QR codes;
- creating a wallet on Device 2 before owner claim;
- blockchain transactions for link authorization;
- sharing an owner lane's existing holder material;
- account administration, recovery, or export in the first release;
- claiming Yao production readiness before its security gates pass.

## Decisions Required Before Implementation

- Freeze link-session, claim, and committed-delivery TTLs.
- Freeze the device identity algorithm and HPKE suite.
- Freeze aggregate receipt encoding and wallet-key ordering.
- Define UX for devices without WebAuthn PRF support.
- Freeze post-compromise cleanup requirements beyond immediate revocation.
