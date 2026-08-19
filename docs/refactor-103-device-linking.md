# Linked-Device Enrollment, Signing, And Revocation

Date created: June 15, 2026

Rewritten: July 22, 2026

Last reconciled: August 19, 2026 (closeout scope)

Status: closeout. The strict QR v4 contract, exhaustive session
state, durable claim and expiry store, authenticated request-proof transport,
owner approval responses, committed-delivery recovery, aggregate activation
verification, private Gateway completion API, linked authorization domain, and
public SDK/iframe/React cutover are implemented. Both key families use their
linked normal-signing paths, and aggregate revocation is implemented. Refactor
102 provides the curve-specific target-lane lifecycle. The D1 composition owns
lane authorization and curve execution, operator-recovery authentication, and
management-side local-state invalidation. Deployment proof still requires the
configured production topology and credentials.

## Active Closeout Scope

One high-impact task remains: automate the real two-device Passkey and Email
OTP operating flows. Each flow must use two independent browser profiles and
the composed runtime, then prove linking, refresh, unlock, signing, export,
metadata persistence, and revocation without mocked lifecycle state.

This closeout scope supersedes older unchecked checklist entries below. Those
entries remain as implementation history only; they are not active Refactor
103 completion blockers.

The original passkey-only implementation checkpoint is 18/21 complete. Phase 6
adds an exact Passkey or Email OTP target-factor choice and is excluded from
that checkpoint. Phase 7 finishes the current signing-only linked-device path
as a working vertical slice. Phase 8 then replaces the human-device authority
with a canonical owner credential while retaining the independently revocable
execution-lane substrate for Refactor 104. The remaining readiness dependencies
are Refactor 100's live custody verification and Refactor 101's broad
integration gate. Post-v1 refresh, compromise cleanup, and the separately
tracked Wasm-size follow-up in Phase 5 remain deferred.

## Scope And Dependencies

This plan owns physical and browser device linking. A linked device becomes a
share-bearing participant for existing wallet keys and protects its holder
material with one exact target factor.

It consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical capability hydration, active ECDSA manifests, activation
  commits, exact operation execution, and Wallet Session admission;
- [refactor-100-passkey-account-refactor.md](./refactor-100-passkey-account-refactor.md)
  for wrapped roots, holder-share envelopes, and wallet-scoped recovery;
- [refactor-101-wallet-execution-lanes.md](./refactor-101-wallet-execution-lanes.md)
  for curve-specific wallet keys, linked-device lanes, lifecycle, and
  execution admission;
- [refactor-102-rotatable-signing-lanes.md](./refactor-102-rotatable-signing-lanes.md) for Yao
  Ed25519 recipient provisioning, ECDSA additive target-lane resharing,
  aggregate activation, refresh, and revocation.

[refactor-104-agent-id-spending.md](./refactor-104-agent-id-spending.md) owns
agent identity and delegated spending. No agent identity, custody, mandate,
budget, or agent-request type belongs in this plan.

## Delivery Strategy

Implementation proceeds through two deliberate milestones:

1. Complete the existing signing-only device path and prove its execution
   substrate through real NEAR, Tempo, and EVM operations. This milestone keeps
   linked-device holder shares, linked admission, independent revocation, and
   required local presence. It grants no export or recovery authority.
2. Cut human device linking over to canonical owner-factor enrollment. Device 2
   then unlocks, signs, steps up, and exports through the same owner credential,
   Wallet Session, and public operation paths as Device 1. The link bootstrap
   and device-management records remain device-specific.

The first milestone is an implementation proving ground, not the final human
device authority model. Refactor 104 may reuse the curve-specific delegated
execution lanes after the first milestone. It must introduce its own agent
principal, owner-signed authorization, mandate, budget, and request signature;
it cannot reinterpret a human linked-device session as agent authority.

## Final Product Goal

Give a new physical device an owner-approved credential for the existing
wallet. Device 2 becomes a backup owner device and can recover practical access
to the wallet, including key export, when Device 1 is unavailable.

```text
Device 2 prepares an unclaimed target factor and displays a public QR session.
Device 1 authenticates and approves adding that exact device to the wallet.
The existing wallet custody seed is resealed for Device 2's approved factor.
The relay registers Device 2 as a canonical owner credential.
Device 2 unlocks, signs, steps up, and exports through ordinary owner flows.
Revocation disables future hosted use of the credential and clears local state.
Previously exported key material cannot be retracted by revocation.
```

## Signing-Only Execution Milestone

Give a new physical device an independently revocable, owner-approved signing
capability for an exact wallet-key set.

```text
Device 2 displays an unclaimed QR session.
Device 1 authenticates and approves the device and permissions.
One child execution lane is provisioned for each approved wallet key.
Device 2 seals each holder capability under its selected Passkey or Email OTP
factor.
The aggregate device enrollment activates after every receipt verifies.
Device 2 signs through its own lanes with exact factor or linked-session
authorization.
Revocation disables the device without affecting owner or unrelated lanes.
```

## Required Invariants

1. Device 2 creates no wallet and receives no wallet identity before an
   authenticated owner claims its link session.
2. The QR contains public bootstrap material only. It never contains wallet,
   account, share, root, recovery, PRF, KEK, Wallet Session, or export material.
3. Owner approval binds the exact device, wallet, ordered wallet-key manifest,
   permission, target lanes, participants, protocol versions, and expiry. It
   selects exactly one owner authorization source; a reusable owner Wallet
   Session authorization and fresh step-up evidence are never combined.
4. Every target lane remains unavailable until all child protocols and the
   aggregate receipt commit. Each admitted operation carries its own
   `AuthorizedOperationId` and exact `MpcMaterialActivationRef`; neither ID
   aliases the Wallet Session, enrollment, or device identity.
5. Device 2 opens holder packages only inside the wallet worker and persists
   sealed custody envelopes plus public projections.
6. Each holder-material release requires exact target-factor authorization.
   Passkey uses local WebAuthn user verification and PRF output. Email OTP uses
   a verified wallet Email OTP factor and may establish an exact linked Wallet
   Session for later operations until its expiry or quota exhaustion. Every
   branch exposes signing-only administration scope.
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
- obtains exactly one owner authorization source through the wallet iframe and
  server-verified boundary: the existing owner Wallet Session authorization or
  a verified step-up evidence set;
- displays Device 2 identity, key coverage, permissions, expiry, and revocation
  consequences;
- approves one exact enrollment transcript;
- participates in holder-side provisioning required by Refactor 102.

Wallet Session JWTs remain inside the authenticated request boundary. QR
payloads, public results, callbacks, and progress events never carry them.

### Device 2

- generates an ephemeral link-encryption keypair;
- generates a persistent device identity keypair;
- creates an unclaimed, short-lived relay session;
- selects Passkey or Email OTP before displaying the QR;
- completes the selected factor after owner claim binds the session to a
  wallet;
- opens holder packages inside the wallet worker;
- stores sealed envelopes and public capability projections;
- returns exact child and aggregate receipts.

### Gateway, Relay, And Router

- Gateway D1 owns durable link-session claims, enrollment transcripts, policy
  digests, child and aggregate receipts, activation results, and revocation
  facts;
- the relay carries public bootstrap data, ciphertext, and signed receipts;
- Gateway D1 emits one internally authenticated typed command for each
  curve-specific child protocol and aggregate effect;
- Router validates and forwards those commands, coordinates role-local
  execution, and keeps no ceremony, enrollment, activation, or revocation
  ledger;
- private Deriver and SigningWorker stores own role custody, activated
  cryptographic material, delivery state, and one-use execution state;
- no boundary receives plaintext roots, holder shares, PRF output, KEKs,
  recovery codes, Yao private outputs, or export-capable ECDSA shares.

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
      keyManifestDigestB64u: string;
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

type QrLinkedDevicePermissionRequest = {
  kind: 'owner_equivalent_signing';
  administrationScope: 'signing_only';
  localUserPresence: 'required';
};
```

The parser validates the exact version and purpose, branded session identity,
key encodings, permission branch, issue time, and expiry. It rejects unknown
fields that could smuggle wallet or authorization state. The first-release
parser accepts only the `owner_equivalent_signing`/`signing_only` branch with
required local presence. The dormant `device_management`, `full_owner_admin`,
and `scoped_signing` v4 branches, including `mandatePolicyDigest`, are deleted
at cutover rather than retained as compatibility paths.

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
7. Select one exact owner authorization source and send authorization
   and holder-side contributions through the Gateway boundary. Gateway emits
   the internally authenticated Router command; Router remains stateless.

After the Gateway accepts the claim, owner approval, and holder-side
contributions, Device 1 enters `owner_handoff_complete`. The scanner closes,
focus returns to the initiating account-menu control, and a success toast
announces:

```text
QR code scanned
Continue setup on your other device.
```

QR decoding alone cannot enter this state. Parse, claim, authorization, or
contribution failures remain in their exact recoverable error states and never
emit the success toast.

A blockchain transaction is unnecessary. The link authorization uses the
existing owner Wallet Session authorization or one verified step-up evidence
set.
The fresh owner passkey assertion is evidence for the selected source. It never
creates a second source. The resulting `AuthorizedOperationId` is independent
of every target lane's `MpcMaterialActivationRef`.

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

When an embedded browser rejects WebAuthn because the wallet document has a
cross-origin ancestor, Device 2 performs the credential operation in a
short-lived top-level wallet-origin window. That window inherits the same
wallet origin and RP ID, closes after the prompt, and returns only the
credential result to the wallet worker flow. 7. Return one receipt per key and one aggregate manifest receipt.

The worker rejects missing or duplicate keys, wrong public identity, recipient
swap, transcript mismatch, stale session, unsupported protocol, and any package
containing export authority.

## Linked-Device Authorization Extension

Refactor 90 currently implements only `WalletSessionAuthorization` as its
`AuthorizationGrant` variant. This plan owns the linked-device extension and
adds it to the shared authorization union only after its boundary parser,
quota owner, and operation adapter are specified:

```ts
type LinkedDeviceWalletSessionAuthorizationRefV1 = {
  kind: 'linked_device_wallet_session_authorization_v1';
  authorizationId: LinkedDeviceWalletSessionAuthorizationId;
};

type LinkedDeviceWalletSessionAuthorizationV1 = {
  kind: 'linked_device_wallet_session_authorization_v1';
  authorizationGrantRef: LinkedDeviceWalletSessionAuthorizationRefV1;
  walletId: WalletId;
  enrollmentId: LinkedDeviceEnrollmentId;
  deviceId: LinkedDeviceId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  keyManifestDigestB64u: string;
  permission: {
    kind: 'owner_equivalent_signing';
    administrationScope: 'signing_only';
    localUserPresence: 'required';
  };
  revocationEpoch: number;
  issuedAtMs: number;
  expiresAtMs: number;
};

type AuthorizationGrant = WalletSessionAuthorization | LinkedDeviceWalletSessionAuthorizationV1;

type AuthorizationGrantRef =
  | {
      kind: 'wallet_session_authorization';
      authorizationId: WalletSessionAuthorizationId;
    }
  | LinkedDeviceWalletSessionAuthorizationRefV1;

type LinkedDeviceExecutionAdmission = {
  authorizedOperation: Extract<AuthorizedOperation, { lifecycle: 'claimed' }>;
  materialActivation: MpcMaterialActivationRef;
};
```

The Gateway creates one linked-device Wallet Session and quota for the exact
enrollment and key manifest. This plan adds the linked-device branch to the
shared `AuthorizationGrantRef` and `AuthorizationGrant` unions while retaining
the shared `OperationAuthorizationSource`: the reusable branch must resolve its
reference to the linked-device authorization variant, while verified step-up
remains the existing disjoint branch. Every signing admission creates one
`AuthorizedOperationId` and carries the exact material activation reference
separately. Wallet Session renewal may preserve that activation when all
bindings still match. Session expiry or quota exhaustion rejects new admission
and leaves sealed material and its activation intact until an explicit material
lifecycle operation changes them.

## Aggregate Activation

Gateway D1 accepts the activation result only when:

- the delivered manifest equals the approved ordered manifest;
- every child protocol is committed;
- every target server or SigningWorker capability is ready;
- every Device 2 receipt verifies;
- the aggregate receipt covers the complete target set;
- the selected authorization source is current (with Wallet Session validity
  checked only for the reusable branch);
- no cancellation, expiry, or revocation fence is active;
- every target lane has an exact `MpcMaterialActivationRef` bound to its key,
  participant set, lifecycle binding, and SigningWorker.

Gateway D1 records the parent enrollment, child lanes, and activation result in
one durable visibility commit. Private worker stores activate the corresponding
cryptographic material. Router records none of these facts. Device 2 then
receives the linked-device Wallet Session authorization defined above, bound to
its exact enrollment and lanes.

## First-Release Permission

The first release supports exactly:

```text
permission kind: owner_equivalent_signing
administration scope: signing_only
local user presence: required
```

Device-management, full-owner-admin, and scoped-device branches remain
unavailable and are removed from the dormant v4 parser. A future scoped-device
design requires its own explicit device principal, permission union,
local-presence policy, and approval flow. It cannot reuse an agent authorization
record.

## Linked-Device Signing

For every signing request:

1. Authenticate Device 2 passkey and device identity.
2. Resolve the active parent device enrollment.
3. Resolve the active child lane for the requested wallet key.
4. Verify share epoch, revocation epoch, participants, and exact curve session.
5. Verify one operation authorization source. The reusable branch must resolve
   to the exact linked-device authorization, Wallet Session audience, device
   binding, quota, and expiry; the verified-step-up branch carries none of
   those reusable identities.
6. Require local confirmation of the exact normalized intent.
7. Verify the final unsigned transaction still matches that intent.
8. In Gateway D1, atomically create or replay one `AuthorizedOperation`, consume
   applicable quota, and write audit linkage. A completed replay returns its
   recorded result before any share or presignature work.
9. For a newly claimed operation, construct `LinkedDeviceExecutionAdmission`
   with the exact `MpcMaterialActivationRef`, then sign through the normal
   Client/SigningWorker or ECDSA threshold path.
10. Complete the authorized operation and record device, lane, enrollment,
    authorization, and operation identity exactly once. Keep material activation
    separate from every authorization identity.

Wallet Session expiry or quota exhaustion rejects new admission while preserving
sealed material, public capabilities, and the material activation. Explicit
renewal or step-up can authorize a new operation; it never silently replaces
the activation.

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
6. Revokes Device 2 linked-device Wallet Sessions, warm handles, and pending
   delivery state.
7. Emits per-key and aggregate revocation receipts.

Gateway D1 persists the revocation facts and receipts. Router only forwards the
fenced command and response; private workers disable their role-local
participants. Revocation preserves the material activation as an audit
identity even when its server capability is disabled.

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
activation, signing admission, denial, quota consumption, suspension, expiry,
refresh, and revocation.

Wallet Session expiry and quota exhaustion belong to the linked-device
authorization projection. They deny new admission while the enrollment and
material activation remain intact.

## Historical Implementation Phases

### Phase 0: Readiness

- [ ] Refactor 100 portable owner custody and recovery pass.
- [ ] Refactor 101 wallet-key and linked-device lane records pass.
- [x] Refactor 102 target-lane protocols and aggregate activation pass.
- [x] Aggregate receipt, crash-recovery, and revocation stores exist.
- [x] Yao production remains gated exactly as documented.

### Phase 1: Session And Claim

- [x] Replace the superseded QR surface with the v4 state machine.
- [x] Implement unclaimed sessions, authenticated owner claim, and expiry.
- [x] Delete legacy QR types, parsers, diagnostics, and fixtures.

### Phase 2: Device Credential And Provisioning

- [x] Create Device 2 passkey only after claim.
- [x] Provision exact Ed25519 and ECDSA child lanes.
- [x] Require child and aggregate receipts.
- [x] Resume committed delivery safely after transport or process failure.

### Phase 3: Signing And Revocation

- [x] Mint linked-device Wallet Session authorizations and their quotas.
- [x] Bind each admission to one `AuthorizedOperationId` and exact material
      activation reference.
- [x] Require local user presence for every signature.
- [x] Route each key family through its normal signing path.
- [x] Implement immediate aggregate revocation.
- [x] Prove owner and unrelated device lanes remain available. Aggregate
      revocation is scoped to the linked enrollment, and the behavioral test
      preserves an unrelated enrollment while resolving the owner lane.

### Phase 4: Product Completion

- [x] Add device management and activity summary views.
- [ ] Add the Device 1 `owner_handoff_complete` state. Close the scanner,
      restore focus, and show `QR code scanned` with `Continue setup on your
  other device.` only after the Gateway accepts the complete owner handoff.
- [ ] Add post-v1 refresh, reprovisioning, and compromise cleanup flows.
- [x] Add operator recovery for committed delivery that cannot complete on the
      original link session. The route binds a fresh Device 2 continuation key,
      and the D1 composition constructs a separate constant-time operator
      authenticator rather than reusing Router internal-service credentials.

### Phase 5: Wasm Size Attribution And Opaque ECDSA Authority

This follow-up first establishes whether Refactor 103 increased the SDK's
unique shipped and flow-delivered Wasm bytes. A larger shared artifact alone is
insufficient evidence because commit `1691bb036` removed the separate ECDSA
presign and online Wasm artifacts while moving their work into custody-owning
modules. The comparison must account for the removed artifacts and must use the
same build toolchain for both revisions.

#### Matched-Build Evidence

The pre-consolidation revision is `a256452b30682da993d323eefb4a9e5f25f67d1c`,
the parent of candidate `1691bb0369dd22e6492821430459ea33733b301c`.
Both revisions were built twice from clean detached worktrees with their own
checked-in lock files. Repeated builds produced identical SHA-256 digests.

The matched environment used Rust 1.97.1, wasm-pack 0.13.1, wasm-opt 117,
Node 26.4.0, pnpm 11.11.0, and Bun 1.2.18 on `aarch64-apple-darwin`.
Both ECDSA derivation builds enabled `simd128`; every artifact used its
checked-in release profile and wasm-opt configuration.

| Unique affected Wasm    |  Baseline raw | Candidate raw |    Delta raw | Baseline gzip | Candidate gzip |   Delta gzip |
| ----------------------- | ------------: | ------------: | -----------: | ------------: | -------------: | -----------: |
| Ed25519 Yao client      |     1,210,795 |       979,566 |     -231,229 |       433,487 |        383,404 |      -50,083 |
| ECDSA derivation client |       610,161 |       700,917 |      +90,756 |       245,876 |        285,620 |      +39,744 |
| ECDSA presign client    |       172,129 |       removed |     -172,129 |        73,064 |        removed |      -73,064 |
| ECDSA online client     |        68,774 |       removed |      -68,774 |        31,585 |        removed |      -31,585 |
| **Unique affected set** | **2,061,859** | **1,680,483** | **-381,376** |   **784,012** |    **669,024** | **-114,988** |

| Unique affected Wasm    | Baseline Brotli | Candidate Brotli | Delta Brotli |
| ----------------------- | --------------: | ---------------: | -----------: |
| Ed25519 Yao client      |         311,801 |          298,141 |      -13,660 |
| ECDSA derivation client |         198,286 |          231,161 |      +32,875 |
| ECDSA presign client    |          60,378 |          removed |      -60,378 |
| ECDSA online client     |          26,382 |          removed |      -26,382 |
| **Unique affected set** |     **596,847** |      **529,302** |  **-67,545** |

The repeat-build SHA-256 digests are:

```text
baseline ed25519  e9cd4ef26adeeb0ee20c15d2cd7b7dadddd51c1ef2408b3bb182d5cef6066252
baseline derive   e2998204b3d1f29cd0ff52a192f2bf9a021398dd9d94efcb8701b9531e5a0ba9
baseline presign  5268424757bd28d712181b0415fb4df1ac2beedac7b509597eacd8f2185ec2ca
baseline online   eb4e19caf637977dec0b0f5c7faff5b8aea2e12f866b65263c9ec36b7e9ed770
candidate ed25519 417e953b400dce6907e975d2bafbb76be9d04579f397d3a365ade5599e34157f
candidate derive  26379fd9f6b7ceaf3aacaa807f13efd28ca8ab2492f88dc2bd66e17ae147005a
```

Refactor 103's consolidation therefore reduced this matched SDK Wasm set by
18.5% raw, 14.7% gzip, and 11.3% Brotli. It did not add 423 KB to the SDK. The
ECDSA derivation client grew by about 91 KB raw and 40 KB gzip, so
stage-specific ECDSA loading still requires a cold-cache flow trace.

The current post-fix worktree measures 1,679,417 raw, 668,687 gzip, and 529,229
Brotli bytes for the two remaining modules. Those worktree values are
informational until the fixes are committed and rebuilt from a clean revision.

The recorded Ed25519 Yao budget is not a reproducible historical baseline in
this environment: the clean pre-consolidation artifact is 1,210,795 raw and
433,487 gzip against its checked-in 556,435 raw and 223,677 gzip budget. The
budget failure is real, while its attribution to Refactor 103 is false under
the matched build. Phase 5 reconciles this stale gate and measures actual flow
cost before authorizing an architectural split.

#### Phase 5A: Reproducible Baseline And Attribution Gate

- [x] Build the baseline and candidate from separate clean worktrees. Use each
      revision's checked-in lock files and the same recorded toolchain, target,
      release profile, and environment.
- [x] Build each revision twice. Require byte-identical Wasm SHA-256 digests
      between repeats before comparing sizes.
- [x] Record raw, gzip level 9, Brotli quality 11, and SHA-256 for every
      affected Wasm artifact in the matched release builds.
- [x] Compare the unique affected Wasm set by content hash. Count the baseline
      Ed25519 Yao client, ECDSA derivation client, ECDSA presign client, and
      ECDSA online client. Count the candidate modules that replace them.
      Copies emitted under multiple SDK paths count once.
- [ ] Measure cold-cache transferred Wasm bytes for an Ed25519-only owner flow
      and an owner ECDSA signing flow on both revisions. Record the new linked
      Ed25519 and linked ECDSA flow footprints on the candidate, because the
      baseline has no equivalent production path. Record requested asset URLs
      and compressed transfer bytes.
- [x] Publish a table containing baseline, candidate, absolute delta, and
      percentage delta for each artifact, the unique shipped set, and every
      completed measurement.

Use the repository production path for both revisions:

```bash
WASM_SDK_BUILD_MODE=prod pnpm -C packages/wallet run build:wasm
pnpm build:sdk-prod
pnpm -C packages/wallet run size:lite -- --json
```

The conclusion uses precise terms:

- a **shared-artifact regression** exists when a candidate shared Wasm artifact
  is larger than the matching baseline artifact;
- **net SDK bloat** exists when the candidate's unique affected Wasm set is
  larger than the baseline set;
- a **flow regression** exists when a candidate cold-cache flow transfers more
  compressed Wasm than the matching baseline flow.

If only the shared file grows while the unique shipped set shrinks or remains
constant, classify the change as artifact consolidation rather than net SDK
bloat. A recorded-budget failure remains a release signal, but the budget is
updated only after the historical measurement is reproduced or shown to be
unreproducible under the recorded toolchain.

#### Phase 5B: Dedicated Opaque ECDSA Authority

Enter this implementation phase only when the remaining Phase 5A network trace
confirms a material flow regression that cannot be fixed through loading or
build configuration. The matched unique-artifact evidence alone does not
justify this refactor.

- [ ] Introduce one lazily loaded ECDSA authority Wasm module that owns client
      presign and online state for both owner and linked-device ECDSA lanes.
- [ ] Remove ECDSA presign, online, wire, k256, and presign RNG dependencies
      from the Ed25519 Yao client artifact. Keep the ECDSA derivation artifact
      focused on derivation, custody ceremony, and explicit export.
- [ ] Initialize the authority from exact sealed custody input inside its
      owning worker. Raw roots, additive shares, `kShare`, `sigmaShare`, and
      export-capable intermediate shares never enter JavaScript or cross Wasm
      instances.
- [ ] Keep completed presign material inside the authority. JavaScript receives
      only public protocol messages, public `R`, expiry, and an opaque one-use
      handle; final signature-share computation returns through that handle.
- [ ] Route ordinary ECDSA and linked-device ECDSA operations through the same
      authority loader. Ed25519-only registration, signing, Email OTP signing,
      and export paths must not fetch the authority artifact.
- [ ] Delete the superseded embedded presign/online exports, dependency paths,
      worker messages, loaders, build entries, fixtures, and source-guard
      exceptions after cutover.
- [ ] Preserve exact group-key, lane, enrollment, expiry, abort, worker-reset,
      and one-use bindings. Add behavioral tests for each owner form and both
      linked key families.
- [ ] Re-run Phase 5A. The shared Ed25519 artifact and the derivation artifact
      must return to their measured pre-regression sizes or document a smaller
      independently attributable delta. Give the dedicated authority its own
      measured raw, gzip, and Brotli budget.

Phase 5 is complete only when the before/after evidence is reproducible, the
secret boundary remains opaque, unrelated Ed25519 flows avoid the ECDSA
authority download, and the production size check enforces budgets for every
resulting artifact.

### Phase 6: Passkey Or Email OTP Target Factor

This phase extends the target-device authorization boundary. Device 2 chooses
one factor before displaying its QR. Device 1 approves that exact factor kind,
and every holder envelope, activation receipt, Wallet Session, and signing
admission remains bound to the same device and enrollment. Passkey remains the
recommended choice.

The Email OTP branch reuses Refactor 100's verified Email OTP factor and
`email_otp_factor_release_v1`. It introduces no second OTP store, factor secret,
or custody construction.

#### Exact Protocol State

- [ ] Replace the QR v4 target contract with QR v5 containing one compact,
      public target-factor discriminator: `passkey_prf` or `email_otp`. Delete
      the v4 parser, types, fixtures, and state branches at cutover.
- [ ] Replace `awaiting_target_passkey` with `awaiting_target_factor`. Model the
      target choice as a discriminated union whose Passkey and Email OTP fields
      are mutually exclusive and whose switches are exhaustive.
- [ ] Bind the selected factor kind into the QR transcript, owner claim,
      approval digest, aggregate enrollment, and activation receipts.
- [ ] Resolve the exact verified wallet Email OTP factor after the owner claim.
      Reject the Email OTP branch before approval when the wallet has no active
      Email OTP factor. Device 2 cannot enter an arbitrary email address.

#### Factor Completion And Holder Sealing

- [ ] Keep the Passkey branch's current post-approval WebAuthn creation, PRF
      extraction, worker-only factor KEK derivation, and zeroization path.
- [ ] Add an Email OTP branch that sends a code to the server-resolved wallet
      email, consumes one verified OTP grant, and releases the existing factor
      secret HPKE-encrypted directly to the wallet worker.
- [ ] Derive the holder-envelope KEK and prepare both curve holder
      registrations inside the worker. Raw OTP values, factor secrets, PRF
      output, and KEKs never enter persistence or public UI state.
- [ ] Persist one factor-specific public reference with the enrollment. The
      reference contains the factor kind and exact server-owned enrollment
      identity required for later authorization; it contains no secret.

#### Signing And Session Admission

- [ ] Replace the Passkey-only linked local-presence input with an exact
      `LinkedDeviceFactorAuthorizationV1` union. The Passkey branch carries the
      existing WebAuthn assertion and PRF evidence. The Email OTP branch carries
      a consumed OTP grant and the exact Email OTP factor reference.
- [ ] Let a successful Email OTP verification establish a device-, enrollment-,
      factor-, wallet-, and intent-bound linked Wallet Session. Reuse that
      session until expiry or quota exhaustion; request another code when no
      valid session exists.
- [ ] Preserve the ordinary NEAR, Tempo, and EVM signing entry points for both
      branches. Linked-device admission remains the only branch-specific
      boundary, and both curves continue through their linked normal-signing
      implementations.
- [ ] Apply aggregate revocation, suspension, expiry, and local material cleanup
      identically to Passkey and Email OTP enrollments.

#### Device 2 Experience

- [ ] Show `Passkey (recommended)` and `Email code` before QR creation. Explain
      that Passkey uses this device's biometric or screen lock and Email OTP
      sends a code to the wallet's verified email.
- [ ] After Device 1 approval, replace the QR immediately with the selected
      factor screen. Passkey shows the existing focused confirmation action;
      Email OTP sends the code and focuses the code input.
- [ ] Show only the masked, server-resolved email hint. Provide direct expired,
      incorrect-code, resend, unavailable-factor, and owner-denied recovery
      actions without returning to an ambiguous intermediate state.

#### Verification And Cutover

- [ ] Add type fixtures proving that Passkey fields cannot enter Email OTP
      states and Email OTP fields cannot enter Passkey states.
- [ ] Add focused behavior tests for claim binding, factor completion, holder
      sealing, active-session reuse, expiry, quota exhaustion, replay, wrong
      factor identity, and revocation across both curves.
- [ ] Run one two-device Passkey E2E and one two-device Email OTP E2E. Each must
      link the device and sign one NEAR operation and one Tempo or EVM operation
      through the linked routes, with exact network assertions proving the
      owner signing routes were not used.
- [ ] Reconcile the goal, invariants, state diagrams, API tables, validation
      checklist, and product copy after the implementation lands. Delete the
      superseded Passkey-only domain names in the same cutover.

Phase 6 is complete when both factor branches activate the same linked-device
lane model, holder material remains worker-confined, valid Email OTP linked
Wallet Sessions avoid redundant step-up, and the two live browser flows pass.

### Phase 7: Complete The Signing-Only Vertical Slice

This phase makes the existing linked execution model reliable before changing
the human-device authority. It fixes demonstrated operating-path failures and
does not add export, recovery, or account administration to the narrow
signing-only execution grant (retained permanently per Refactor 103C).

#### Persisted Device Session And Unlock

- [ ] Project the exact active linked enrollment after refresh and wallet lock.
      The account chooser must discover the linked credential without routing
      it through owner credential lookup.
- [ ] Restore a linked Wallet Session only after exact target-factor
      authorization. Preserve wallet, device, enrollment, factor, lane,
      revocation epoch, expiry, and quota identity.
- [ ] Add an explicit renewal path before quota exhaustion blocks an otherwise
      active enrollment. Renewal requires the same linked factor and never
      mutates material activation.
- [ ] Remove retry loops that repeatedly submit a terminally rejected or
      exhausted session.

#### Curve Execution

- [ ] Route ordinary NEAR entry points through linked Ed25519 admission whenever
      the active session authority is the signing-only linked branch. Gateway
      admission must reach Router with one recognized admission form.
- [ ] Route ordinary Tempo and EVM entry points through linked ECDSA admission
      with the exact active child lane, holder material, presignature identity,
      operation digests, and material activation.
- [ ] Persist and reopen both curve holder envelopes after refresh. Reject
      partial activation as an enrollment failure instead of projecting an
      active device with missing execution material.
- [ ] Return branch-specific server failures for admission, holder opening,
      presign, online signing, session renewal, and revocation. Do not collapse
      them into `linked execution unavailable` or `response failed`.

#### Management And Temporary Product Boundary

- [ ] Make list and revoke tolerate no partial manifest. Committed incomplete
      enrollments enter a repair-required state and never count as active.
- [ ] Keep key export and recovery controls unavailable for the signing-only
      milestone. Explain that this device can sign but is not yet a backup owner
      credential.
- [ ] Complete the Device 1 handoff state: close the scanner, restore focus, and
      show `Device approved` with `Finish setup on your other device` after the
      Gateway accepts the owner handoff.

#### Phase 7 Gate

- [ ] Run one real two-device Passkey flow: link, refresh Device 2, lock and
      unlock Device 2, sign NEAR, Tempo, and EVM, renew the linked session, list
      the enrollment, and revoke it.
- [ ] Assert the linked routes and exact enrollment identity for all three
      operations. Assert that owner signing and export routes are not used.
- [ ] Run the same operating path with Email OTP after Phase 6 lands.

Phase 7 is complete only when a linked device survives refresh and lock,
performs all supported signing operations, renews its authorization, appears in
management, and is revoked without affecting Device 1.

### Phase 8: Cut Human Linking Over To Owner Credentials

This phase implements the final product model. Device 2 receives a canonical
owner credential and an independently provisioned signing lane for each curve.
The owner credential supplies wallet authority, unlock, step-up, and custody;
the device lanes supply exact per-device signing material and revocation.

#### Landed Phase 8 Prerequisites

- [x] Carry the wallet custody seed through the worker-owned sealed transfer
      protocol, persist and relay its public package, expose authenticated
      transfer routes, and assemble the browser transfer port for both devices.
- [x] Start the canonical add-auth-method ceremony under Device 1 authority and
      bind it into the immutable approval and target preparation.
- [x] Carry the server-verified custody key-manifest digest on canonical owner
      Wallet Sessions, bind it into approval, and admit Device 2 finalize from
      the approved `awaiting_target_passkey` state.
- [x] Persist one exact linked enrollment -> canonical `WalletAuthMethodId`
      binding in the same transaction as successful credential and custody-
      envelope activation.
- [x] Reach the canonical add-auth-method finalizer from an authenticated
      Device 2 route without accepting linked-enrollment facts from the wire
      request.
- [x] Make add-auth-method finalize exactly replayable after ceremony
      consumption and reject substituted requests or admissions.
- [x] Record the issuing `walletAuthMethodId` on canonical Wallet Sessions and
      enforce it during readback and issuance replay.
- [x] Extract the canonical local Passkey projection so ordinary add-Passkey
      and Device 2 enrollment can share one persistence path.
- [x] Add approval/parser round-trip guards and focused admission, provenance,
      binding, finalize-replay, and custody-transfer tests.
- [x] Reuse Device 1's approval-time Passkey assertion to retain the current
      custody envelope and PRF output locally until the recipient arrives;
      seal once and zeroize on completion or failure. This is the temporary
      prompted path replaced by the zero-prompt cutover below.
- [x] Wire Device 2 recipient publication, transfer acceptance, canonical
      finalize, local projection persistence, and idempotent session completion
      into one working browser flow.
- [ ] Prove Device 2 canonical unlock before removing any human linked-session
      or target-lane path.

#### Zero-Prompt Device 1 Handoff

Product requirement: scanning and approving a QR on an already-unlocked Device
1 must not invoke WebAuthn, Touch ID, an Email OTP challenge, or another factor
prompt. The QR scan is the deliberate approval action. Device 2 still performs
its own factor ceremony because it is creating the new owner credential.

The old signing-only flow needed only an active owner Wallet Session. Phase 8
also transfers the wallet custody seed, and the current implementation reopens
Device 1's custody envelope during linking to obtain that seed. The zero-prompt
cutover moves that envelope-open step to ordinary registration or unlock, where
the owner factor is already being presented, and retains only an opaque custody
capability inside the wallet worker for the lifetime of the unlocked session.
Raw seed bytes never enter application JavaScript or persistence.

##### Worker Capability

- [x] Add one worker-owned `UnlockedWalletCustodyTransferCapabilityV1`. Its
      public reference contains the opaque handle ID, wallet ID, issuing
      `WalletAuthMethodId`, owner Wallet Session ID, and expiry. The worker owns
      the opened custody-seed handle; no API returns seed bytes or a serializable
      secret representation.
- [x] Establish the capability during successful owner registration and normal
      owner unlock by reusing the factor secret and verified custody envelope
      already present in that operation. Commit it only after the matching owner
      Wallet Session is active. Creating it must add no authenticator or OTP
      interaction.
- [x] Keep at most one active capability per wallet and owner Wallet Session.
      Replacing it destroys the previous handle. Refuse a wallet, auth-method,
      Wallet Session, or expiry mismatch inside the worker before sealing.
- [x] Destroy the capability on lock, logout, wallet switch, Wallet Session
      retirement or replacement, expiry, worker reset, page teardown, and every
      failed registration or unlock after the handle was created. Never persist
      or restore it. After a worker or page restart, the user explicitly unlocks
      the wallet before linking; the linking flow itself never triggers a prompt.

##### Owner Approval And Ceremony Start

- [x] Preflight the active owner Wallet Session and unlocked custody capability
      before claiming the scanned link session. If either is absent, return an
      exact `wallet_unlock_required` result without starting WebAuthn, OTP, or a
      partially approved enrollment.
- [x] Authorize the linked add-auth-method ceremony with the same active owner
      Wallet Session that authorizes the QR claim and approval. Bind the exact
      link session, wallet, enrollment, device, new factor kind, ceremony, and
      expiry into the immutable approval. Do not accept these facts from an
      unauthenticated request body.
- [x] Remove `collectOwnerAssertionV1` from the Device 1 linking composition.
      Delete the approval-time call to
      `collectAuthenticationCredentialForWalletChallengeB64u`, the retained PRF
      buffer, `LinkedDeviceOwnerCustodyHoldV1`, and the prompted fallback. A
      missing capability is an unlock requirement rather than permission to
      prompt from the QR flow.

##### Seed Transfer

- [x] Replace `sealForLinkedDeviceV1({ existingEnvelope,
  existingFactorSecret, ... })` with a worker operation that accepts the
      opaque unlocked capability and the approved recipient binding. The worker
      seals directly from its custody handle and generates a fresh X25519
      ephemeral key and nonce for every transfer.
- [x] Preserve the existing X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 wire
      format and authenticated binding over wallet, enrollment, device,
      recipient public key, and custody-secret identity. The server continues to
      relay only the recipient public key and sealed package.
- [x] Keep Device 2's open-and-reseal operation single-call and single-use. The
      recipient private key, transferred seed handle, and new factor secret stay
      inside its worker and are destroyed whether resealing succeeds or fails.
- [x] Permit the Device 1 capability to seal multiple separately approved
      enrollments only while its exact owner Wallet Session remains active. Each
      transfer gets independent ephemeral key material and remains bound to one
      approved recipient.

##### Cutover And Proof

- [x] Delete the temporary approval-prompt custody path and its fixtures in the
      same commit that makes the worker capability path operational. Keep no
      compatibility branch or automatic prompted fallback.
- [ ] Add one focused lifecycle test proving registration and unlock establish
      the capability, and lock, session retirement, expiry, and worker reset
      destroy or invalidate it.
- [ ] Add one transfer test proving wrong-wallet, wrong-session, expired,
      unknown, and destroyed handles fail before producing ciphertext. Preserve
      the existing substituted-binding and recipient-key rejection tests.
- [ ] Extend the two-device intended-behavior contract with prompt counters:
      reset the counter after Device 1 unlock, scan and approve the QR, assert
      zero Device 1 factor prompts, assert exactly one Device 2 prompt for its
      new Passkey, then reload Device 2 and prove canonical unlock and signing.
- [x] Prove the unavailable-capability case separately: QR linking returns
      `wallet_unlock_required`, performs no factor prompt, records no owner
      approval, and creates no credential or custody-transfer package.

The zero-prompt cutover is complete when an already-unlocked Device 1 links a
new owner device without another factor interaction, while the custody seed
remains worker-confined, volatile, session-bound, and unavailable after lock or
session invalidation.

Status: the cutover is implemented and the fail-closed preflight, registry
lifecycle, and capability seal boundary are proven by focused unit tests
(`tests/unit/unlockedCustodyTransferCapability.unit.test.ts`,
`tests/unit/walletHostOwnerAuthority.unit.test.ts`,
`tests/unit/deviceLinkingCustodyTransferPort.unit.test.ts`). The three
unchecked items above need a composed stack: the lifecycle and
transfer-misuse tests against the real ceremony worker, and the two-device
contract with its prompt counters
(`tests/e2e/linked-device.operating-path.test.ts`, already extended with
zero-Device-1-prompt and exactly-one-Device-2-passkey assertions).

Independent verification of the five cutover commits (`44e7fbfdf`..`4cc6156d3`):
the focused suites pass on re-run (34 tests), the full device-linking unit
group passes 224 with the six known failures in the retired R102 lane surfaces
proven byte-identical at the pre-cutover baseline `f58250b34`, and both
`sdk-web` and `sdk-server-ts` type-check clean.

First composed run of the two-device contract (`SEAMS_LINKED_DEVICE_E2E=1`,
freshly built dist): Device 1's scan fails closed at the preflight with
`wallet_unlock_required` before any HTTP request, so the contract stalls
waiting for the claim. Two candidate causes, not yet separated: the
registration branch the contract's Device 1 takes may not reach the establish
site that seeds the capability, and the running workerd predated
`289a926d0`, so its ceremony start does not yet accept `wallet_session`
authority — the stack must be restarted before the next attempt can be
attributed to client code. The fail-closed behaviour itself worked exactly as
specified: no prompt, no approval, no credential, no package.

#### Owner Credential Enrollment

- [ ] Replace the human-device permission request with the canonical owner
      credential/factor enrollment request already used by wallet custody.
      Superseded by Refactor 103C: the `owner_equivalent_signing`/`signing_only`
      grant is not deleted. It remains the narrow per-device linked execution
      grant — delivery, renewal, execution, revocation — alongside the
      canonical owner credential. It never classifies the human as a
      signing-only user.
- [ ] After Device 1 approval, authenticate the exact Device 2 Passkey or Email
      OTP factor and reseal the existing wallet custody seed for that factor.
      Raw seed, PRF output, OTP factor secret, and envelope KEK remain inside
      their existing trusted worker boundaries.
- [ ] Register Device 2 in the canonical owner credential index used by login,
      challenge verification, step-up, and recent-account discovery. Keep the
      device enrollment ID as management and audit metadata.
- [ ] Bind the new owner credential to the existing verified wallet-key
      manifest. Adding Device 2 must not derive a new wallet, change public
      keys, rotate signing roots, or create a parallel identity.

#### Ordinary Owner Operations

- [x] Make Device 2 use its canonical owner credential for unlock and owner
      authorization while restoring the exact linked Wallet Session and lane
      bound to that credential.
- [x] Make NEAR, Tempo, and EVM calls use Device 2's independently provisioned
      Ed25519 and ECDSA lanes. A current owner session must match the exact
      credential and threshold-session identity before it can authorize a lane.
- [ ] Enable Ed25519 and ECDSA key export through the existing owner export and
      fresh step-up flows. The account menu derives export availability from
      owner authority rather than device-linking UI state.
- [ ] Preserve the same confirmation policy and signing-session reuse behavior
      on Device 1 and Device 2.

#### Revocation And Cleanup

- [x] Revoke the owner credential, factor envelope, owner binding, reusable
      Wallet Sessions, linked Wallet Sessions, and linked lane aggregate through
      one idempotent fenced flow. Refuse removal of the last active owner.
- [ ] State the irreversible boundary in product copy: revocation prevents
      future hosted use but cannot retract key material exported before
      revocation.
- [x] Keep human owner-device lanes distinct from delegated-agent authority.
      Linking provisions one exact Ed25519 lane and one exact ECDSA lane for the
      new device, persists their holder envelopes locally, and leaves Device 1's
      registration material unchanged.
- [x] Keep canonical owner identity and device signing material separate. Adding
      or revoking a device does not rotate wallet public keys, addresses, the
      custody seed identity, or another device's lane.

#### Phase 8 Gate

- [ ] Run one real two-device Passkey flow and one Email OTP flow. For each:
      enroll Device 2, refresh, lock and unlock, sign NEAR, Tempo, and EVM,
      perform fresh step-up, export Ed25519 and ECDSA keys, and revoke Device 2.
- [ ] Assert that Device 2 uses canonical owner endpoints for authentication,
      custody, and step-up, and the linked-lane endpoints for signing-session
      delivery, renewal, execution, and revocation.
- [ ] Assert identical wallet public keys, addresses, manifest identity, and
      account identity on both devices.
- [ ] Assert that revoked credentials cannot unlock or obtain new sessions and
      that Device 1 remains operational.
- [ ] Reconcile every earlier signing-only invariant, state diagram, API table,
      validation item, and product string in this document. Delete obsolete
      signing-only human-device types in the same change.

Phase 8 is complete when Device 2 is a canonical peer owner credential with its
own signing lanes, both devices can authorize revocation of the other while at
least one owner remains, and neither device borrows the other's session or lane
material.

## Validation

Static fixtures prove:

- unclaimed states cannot contain wallet or enrollment identity;
- active states require exact wallet and enrollment identity;
- device records cannot carry agent identity, mandate, or custody fields;
- device permission cannot grant delegated or recovery authority;
- QR parsing rejects every dormant v4 permission branch and accepts only
  `signing_only` with required local presence;
- Ed25519 and ECDSA child results cannot be swapped;
- success requires a nonempty exact lane manifest;
- cancellation after output commitment cannot enter a precommit state.

Focused tests prove:

- malformed, expired, replayed, and already-claimed QR sessions fail;
- owner approval binds exact device, wallet, lanes, participants, and policy;
- approval selects exactly one owner authorization source;
- each admission has one `AuthorizedOperationId` and one independent
  `MpcMaterialActivationRef`;
- Device 2 creates no wallet before claim;
- substituted or partial holder delivery fails before persistence;
- mixed wallets remain inactive until all receipts verify;
- each supported chain signs with local presence;
- revocation fences every linked Wallet Session before aggregate child-lane
  retirement;
- export and recovery requests from linked-device lanes fail.

The two-device E2E drives the public host flow and asserts that ordinary Tempo
and NEAR operations use linked-device Router A/B endpoints with local-presence
evidence, while the owner ECDSA prepare route remains unused. A fresh local run
is still required after the owner-registration harness control is available.

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
- treating the Phase 7 signing-only milestone as the final human-device
  authority model;
- introducing agent identity, mandates, budgets, or agent requests while
  extracting the delegated execution substrate;
- claiming Yao production readiness before its security gates pass.

## Resolved Decisions And Follow-Up Boundary

- Freeze link-session, claim, and committed-delivery TTLs.
- Freeze the device identity algorithm and HPKE suite.
- Freeze aggregate receipt encoding and wallet-key ordering.
- Phase 6 owns the explicit Passkey or Email OTP target-factor choice. Passkey
  remains recommended; Email OTP is available only for wallets with an active
  verified Email OTP factor.
- Phase 7 completes and validates the signing-only lane as an operating path.
  It does not expand that narrow grant into export or recovery authority.
- Phase 8 makes human Device 2 a canonical owner credential. Per Refactor
  103C, the signing-only linked execution grant is retained alongside that
  ownership as the per-device execution and revocation mechanism — it is not
  removed. Refactor 104 owns any later agent use of delegated execution under
  its own principal and authorization types.
- The v1 compromise boundary is immediate aggregate revocation, server-role
  disablement, and exact local holder/session zeroization. Server-share
  destruction evidence, refresh/reprovisioning, and post-compromise recovery
  are follow-up work.
