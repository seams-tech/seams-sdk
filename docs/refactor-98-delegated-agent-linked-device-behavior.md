# Linked-Device And Delegated-Agent Behavior

Date created: June 15, 2026

Last reconciled: July 22, 2026

Status: active product plan. A dormant QR v4 parser and public API, React, and
wallet-iframe UI shells exist. The exported link flow still uses a separate
legacy QR shape and fails closed. Device linking, lane provisioning, signing
admission, and revocation remain disabled.

## Dependencies

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  supplies canonical capability hydration, active ECDSA manifests, activation
  commits, exact operation lanes, and Wallet Session admission.
- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md) supplies the Ed25519 Client, Deriver A/B,
  SigningWorker, lifecycle, and production-security architecture.
- [refactor-95-passkey-account-refactor.md](./refactor-95-passkey-account-refactor.md)
  supplies wrapped roots, holder-share envelopes, and wallet-scoped recovery.
- [refactor-96-delegate-wallets.md](./refactor-96-delegate-wallets.md) supplies
  curve-specific wallet keys, lanes, enrollments, policies, and admission
  identity.
- [refactor-97-share-rotation.md](./refactor-97-share-rotation.md) supplies Yao
  Ed25519 lane provisioning, ECDSA additive lane resharing, aggregate
  activation, refresh, and revocation.

## Goal

Give a new physical device or delegated agent an independently revocable,
lane-scoped signing capability for an exact wallet-key set.

Target linked-device story:

```text
Device 2 displays an unclaimed QR session.
Device 1 authenticates and approves the device and permissions.
One child lane is provisioned for each required wallet key.
Device 2 seals every holder capability under its own passkey.
The aggregate enrollment activates after all receipts verify.
Device 2 signs through its own lanes.
Revocation disables the aggregate without affecting owner lanes.
```

Target delegated-agent story:

```text
Owner approves an exact mandate and key set.
Protocol provisions lane holder material to a named custody key.
Agent returns custody and attestation receipts.
Signing requires active enrollment, active lane, exact intent admission,
budget, expiry, replay admission, and matching server participation.
```

## Product Delivery Order

The order is intentional:

1. Preserve the restored Email OTP registration, unlock, recovery, budget, and
   export lifecycle; complete recovery-code mixed-custody semantics and wrapped
   passkey custody in Refactor 95.
2. Complete wallet-key, lane, enrollment, and curve-protocol foundations in
   Refactors 96 and 97.
3. Ship one owner-equivalent, signing-only QR-linked device lane.
4. Add linked-device signing admission and immediate enrollment revocation.
5. Add bounded delegated agents and scoped linked-device permissions.
6. Add advanced administration scopes, cryptographic cleanup evidence, and
   automated remaining-lane refresh after compromise.

The first linked-device release does not wait for the complete mandate product.

## Current SDK Surface Mismatch

The v4 parser in `qrLinkSession.ts` describes the intended unclaimed session:
it carries `linkSessionId`, link and device public keys, requested permission,
and issue/expiry times, and excludes wallet identity.

The currently exported `DeviceLinkingQRData`, `linkDevice.ts`, and
`scanDevice.ts` use a separate legacy-shaped payload with `sessionId`, optional
`accountId`, `timestamp`, and an unconstrained version string. Both operations
terminate with an unsupported error that still names Refactor 84. The React and
wallet-iframe views route into those stubs.

Phase 1 replaces this surface directly with the v4 state machine. It does not
add a compatibility adapter: the legacy QR type, parser, stale diagnostic, and
fixtures are deleted together.

## Roles And Trust Boundaries

### Device 1

- owns an active owner lane;
- authenticates the linking operation with fresh user verification;
- obtains authorization through the wallet iframe and server-verified Wallet
  Session boundary. QR payloads, public results, callbacks, and progress events
  never carry a Wallet Session JWT;
- displays Device 2 identity, key coverage, permissions, expiry, and revocation
  path;
- authorizes the exact enrollment transcript;
- participates in any holder-side provisioning required by Refactor 97.

### Device 2

- generates an ephemeral link-encryption keypair;
- generates a persistent device identity keypair;
- creates an unclaimed, short-lived link session;
- creates its passkey after the session is bound to a wallet and before holder
  material is sealed;
- opens holder packages only inside the wallet worker;
- stores only sealed custody envelopes and public capability projections;
- returns per-key and aggregate delivery receipts.

Device 2 creates a transport and custody bootstrap session. Wallet creation
remains part of the established registration flow.

### Relay And Router

- store public link-session state, policy digests, ciphertext, and receipts;
- authenticate Device 1 before binding a wallet to the link session;
- authorize one exact wallet-key manifest;
- coordinate curve-specific child protocols;
- keep every pending enrollment unavailable to signing;
- never receive plaintext roots, holder shares, PRF output, KEKs, recovery
  codes, Yao private outputs, or export-capable ECDSA shares.

### Deriver A And Deriver B

- participate only in Ed25519 lifecycle operations defined by Yao;
- produce recipient-isolated packages for the target Client and SigningWorker;
- remain outside ordinary signing.

### SigningWorker Or ECDSA Relayer Participant

- activates only exact target-lane material;
- checks lane, share epoch, revocation epoch, enrollment, Wallet Session, and
  protocol transcript;
- cannot sign without the target holder participant and Router admission.

## Linked-Device Session State

Use an exhaustive state machine.

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
      transcriptHashB64u: string;
    };
```

Core operations accept the narrow state they require. UI diagnostics and
progress events project from this state and never control it.

## QR Payload

The existing v4 payload is the starting boundary:

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

The QR omits wallet ID, account ID, public wallet keys, holder material, server
material, PRF output, recovery material, and passkey credential secrets. Device
1 binds the session to a wallet after authenticated claim.

The parser validates version, purpose, branded session ID, key encodings,
permission branch, issue time, and expiry once. Core linking code receives only
the parsed v4 type.

## Device 2: Prepare The Link

1. Generate `linkSessionId` from cryptographic randomness.
2. Generate an ephemeral HPKE/link-encryption keypair inside the wallet worker.
3. Generate a persistent device identity keypair.
4. Preflight WebAuthn PRF availability without creating wallet-bound custody.
5. Register the public link session with the relay.
6. Render the QR payload.
7. Subscribe for authenticated session updates.

SSE plus POST requests is the preferred first transport:

- SSE carries claimed, credential-required, provisioning, delivery, active,
  expired, and terminal events to Device 2;
- POST requests claim, provide target credential identity, acknowledge holder
  delivery, cancel, and retry exact committed delivery;
- authenticated polling can implement the same protocol;
- WebSocket transport remains an adapter choice.

## Device 1: Claim And Approve

1. Scan and parse the QR payload.
2. Resolve the active owner wallet and exact wallet-key inventory.
3. Authenticate with fresh user verification through an active owner lane.
4. Claim the unclaimed link session atomically.
5. Display:
   - Device 2 identity fingerprint;
   - requested permission profile;
   - exact Ed25519 and EVM-family key coverage;
   - local-user-presence requirement;
   - expiry and revocation path.
6. Approve one enrollment transcript binding:
   - link session, device identity, and link public key;
   - wallet and ordered wallet-key manifest;
   - source owner lanes and epochs;
   - target lane IDs and epochs;
   - permission policy digest;
   - operation ID, idempotency key, protocol versions, and expiry.
7. Send the authorization and holder-side protocol contributions through the
   authenticated Router boundary.

A blockchain transaction is unnecessary. The authorization uses the current
Wallet Session, fresh passkey assertion, and worker-owned holder participation.

## Device 2: Create Passkey And Receive Material

After the owner claim reveals the authenticated wallet identity:

1. Create a wallet-bound passkey and derive its KEK inside the secure worker.
2. Register the passkey credential identity and device binding with the claimed
   session.
3. Receive one encrypted holder package per target wallet key:
   - Ed25519 Yao Client/holder recipient package;
   - ECDSA additive target holder-share package.
4. Verify enrollment, wallet key, public identity, target lane, epoch, policy,
   participant, and transcript bindings.
5. Seal each holder capability under the passkey KEK.
6. Persist public capability projections and sealed envelopes.
7. Return a delivery receipt for each key and one aggregate manifest receipt.

The worker rejects a missing key, duplicate key, wrong public identity,
recipient swap, transcript mismatch, stale session, or unsupported protocol.

## Aggregate Activation

The Router activates the linked device only when:

- the target manifest equals the approved manifest;
- every child protocol is committed;
- every target server/SigningWorker capability is ready;
- every Device 2 holder receipt verifies;
- the aggregate receipt covers the exact ordered key set;
- the session, enrollment, and owner authorization are current;
- no revocation or cancellation fence is active.

Activation marks the parent enrollment and all child lanes active through the
durable visibility rule in Refactor 97. Device 2 then receives a Wallet Session
grant bound to its exact enrollment and lanes.

## Owner-Equivalent Linked-Device Signing

The first release supports:

```text
permission kind: owner_equivalent
administration scope: signing_only
local user presence: required
```

For every signing request:

1. Authenticate Device 2's passkey and device identity.
2. Resolve its active parent enrollment.
3. Resolve the active child lane for the requested wallet key.
4. Verify lane share epoch, revocation epoch, participant binding, and exact
   Ed25519 or ECDSA session identity.
5. Verify the wallet-level Wallet Session budget and expiry.
6. Require local user confirmation for the exact intent.
7. Sign through the normal Client/SigningWorker or ECDSA threshold path.
8. Consume budget and record the lane and enrollment audit identity exactly
   once.

Ed25519 signing performs zero Deriver calls. ECDSA signing uses one-use
presignature state and the same EVM-family public identity as the owner lane.

## Immediate Device Revocation

Revoking a linked device is one aggregate operation:

1. Mark the parent enrollment revoked and increment its revocation epoch.
2. Reject new admission before share work.
3. Stop queued and pending signing requests.
4. Revoke every child lane and increment each lane revocation epoch.
5. Disable each matching SigningWorker or ECDSA relayer capability.
6. Clear Device 2 Wallet Sessions, warm handles, and pending delivery state.
7. Emit per-key and aggregate revocation receipts.

Owner lanes and unrelated devices remain active. Later cryptographic cleanup
can attest server-share destruction and refresh remaining lanes when the
compromise model requires it. Immediate server-participant disablement is a
release requirement for the first linked-device lane.

## Delegated-Agent Creation

Agent enrollment reuses the aggregate protocol with these changes:

- the owner selects an exact key subset;
- a typed mandate replaces owner-equivalent permission;
- holder packages target a named custody key and runtime;
- activation requires custody and attestation receipts;
- no local-user-presence claim is inferred unless the agent custody policy
  explicitly provides one;
- every signing request passes typed intent, budget, expiry, replay, allowance,
  and final-transaction admission.

The initial agent surface should support a narrow intent family and one explicit
budget model. Expand intent variants only with matching parsers, policy rules,
and negative tests.

## Scoped Linked Devices

Scoped linked devices use the delegated mandate pipeline with a physical-device
principal and mandatory local user presence. They carry
`administrationScope: 'no_account_admin'`.

Scoped signing ships after owner-equivalent linking, signing, and revocation are
stable. Account administration remains a separate policy family.

## Recovery And Linking

Recovery and linking are distinct product operations:

- passkey or recovery-code recovery replaces access to an existing owner lane;
- linked-device creation adds new independently revocable lanes;
- social Email OTP recovery authorizes opening recovery-wrapped owner material;
- a linked device does not become a recovery authority unless a later explicit
  policy grants that capability;
- revoking a linked device does not remove Email OTP or recovery-code access.

## Public SDK Surface

The current public methods can retain their high-level roles while their result
types become precise:

```text
startDevice2LinkingFlow()
scanAndLinkDevice()
cancelDeviceLinking()
listLinkedDevices()
revokeLinkedDevice()
```

Requirements:

- success results include enrollment ID, device ID, exact active lane
  references, and manifest digest;
- recoverable failures use a result union;
- cancellation distinguishes pre-commit cancellation from committed completion
  required;
- progress events project the domain state and carry no secret material;
- iframe and direct SDK routes share the same parsed request and service.

Agent methods use separate request/result types and never accept the linked
device option bag.

## Product And Operations Surface

Linked-device management shows:

- device label and platform;
- permission and administration scope;
- covered wallet keys;
- active, provisioning, suspended, expired, or revoked state;
- last activity and creation time;
- revocation action and consequences.

Agent management additionally shows mandate version, budget, remaining budget,
expiry, custody runtime, attestation status, denied requests, and policy update
history.

Audit events include enrollment, owner approval, protocol commitment, holder
delivery, activation, signing admission, denial, budget consumption,
suspension, expiry, refresh, and revocation.

## Implementation Phases

### Phase 0: Readiness Gate

- [x] Current Email OTP registration, unlock, recovery, budget refresh, and
      export lifecycle is restored for the mixed wallet.
- [ ] Refactor 95 random-root registration, portable wrapped custody unlock, and
      wallet-scoped recovery-code recovery pass.
- [ ] Refactor 96 curve-specific wallet keys, lanes, and enrollment records pass.
- [ ] Refactor 97 Ed25519 and ECDSA target-lane protocols pass locally.
- [ ] Aggregate activation, receipt, crash recovery, and revocation stores exist.
- [ ] Yao production remains gated exactly as documented.

### Phase 1: Owner-Equivalent Device Enrollment

- [ ] Replace the legacy public QR type and fail-closed display/scan stubs with
      the v4 session state machine; delete the Refactor 84 diagnostic.
- [ ] Implement unclaimed relay sessions, owner claim, and expiry.
- [ ] Implement Device 2 passkey creation after claim.
- [ ] Provision exact Ed25519 and ECDSA child lanes.
- [ ] Require per-key and aggregate holder receipts.

### Phase 2: Linked-Device Signing And Revocation

- [ ] Mint enrollment-bound Wallet Sessions.
- [ ] Require local user presence for each owner-equivalent signature.
- [ ] Route each key family through its normal signing path.
- [ ] Implement immediate aggregate enrollment revocation.
- [ ] Prove owner lanes remain available.

### Phase 3: Delegated Agents

- [ ] Add named agent custody registration and attestation.
- [ ] Add exact key-subset enrollment.
- [ ] Implement one narrow typed mandate and budget model.
- [ ] Add admission, denial, audit, expiry, suspension, and revocation.

### Phase 4: Scoped Linked Devices

- [ ] Reuse typed mandate admission with a device principal.
- [ ] Preserve mandatory local user presence.
- [ ] Keep account administration unavailable.
- [ ] Add out-of-scope and transaction-substitution tests.

### Phase 5: Advanced Administration And Cleanup

- [ ] Add separately authorized device-management scope if product requirements
      justify it.
- [ ] Add custody-destruction evidence and post-compromise remaining-lane
      refresh.
- [ ] Add policy updates, budget top-ups, expiry extension, and notifications.
- [ ] Add operator recovery for committed delivery that cannot complete on the
      original link session.

## Validation

Static checks:

- displaying-QR state cannot contain a wallet ID;
- active state requires wallet and enrollment identity;
- owner-equivalent linked device cannot carry a mandate;
- scoped linked device cannot carry account-administration scope;
- linked-device receipt cannot satisfy an agent custody receipt;
- Ed25519 and ECDSA child results cannot be swapped;
- cancellation after protocol commitment cannot enter pre-commit cancelled
  state;
- success result requires a nonempty exact lane manifest.

Focused flow tests:

- expired, replayed, malformed, and already-claimed QR sessions fail;
- owner approval binds the exact device, wallet, key manifest, lanes, and policy;
- Device 2 creates no wallet before owner claim;
- missing or substituted holder packages fail before persistence;
- mixed wallet remains inactive until both Ed25519 and ECDSA receipts verify;
- owner-equivalent Device 2 signs NEAR, Tempo, and Arc/EVM with local presence;
- ordinary Ed25519 signing invokes no Deriver;
- aggregate device revocation disables every child lane and preserves owner
  signing;
- scoped out-of-policy intent and final transaction substitution fail before
  share work;
- agent custody receipt, mandate, budget, replay, expiry, and revocation are
  enforced.

Browser and lifecycle tests:

- direct SDK and iframe paths share the same behavior;
- SSE disconnect resumes from authenticated session state;
- cancellation before commitment cleans up;
- failure after Yao output commitment enters completion-required recovery;
- refresh, reload, lock, and pagehide never expose holder material;
- UI progress derives from domain state and cannot activate an enrollment.

## Non-Goals

- creating a temporary blockchain wallet on Device 2;
- placing wallet identity or secret material in QR codes;
- using a blockchain AddKey transaction as the linking authority;
- generating a complete wallet private key on the server;
- sharing an owner lane's holder material with a linked device;
- enabling scoped or administrative permissions in the first linked-device
  release;
- letting linked devices or agents use ordinary signing routes for export;
- claiming Yao production readiness before its security and deployment gates.

## Decisions Required Before Implementation

- Freeze link-session TTL, claim TTL, and committed-delivery retention.
- Freeze the device identity key algorithm and HPKE suite used by the selected
  Yao profile and ECDSA delivery protocol.
- Freeze the aggregate receipt encoding and canonical wallet-key ordering.
- Define account UX for a browser without WebAuthn PRF support on Device 2.
- Define the first narrow delegated intent and budget model.
