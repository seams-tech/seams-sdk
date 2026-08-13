# Linked-Device Enrollment, Signing, And Revocation

Date created: June 15, 2026

Rewritten: July 22, 2026

Last reconciled: August 13, 2026 (R103 implementation checkpoint)

Status: active implementation. The strict QR v4 contract, exhaustive session
state, durable claim and expiry store, authenticated request-proof transport,
owner approval responses, committed-delivery recovery, aggregate activation
verification, private Gateway completion API, linked authorization domain, and
public SDK/iframe/React cutover are implemented. Both key families use their
linked normal-signing paths, and aggregate revocation is implemented. Refactor
102 provides the curve-specific target-lane lifecycle. The D1 composition owns
lane authorization and curve execution, operator-recovery authentication, and
management-side local-state invalidation. Deployment proof still requires the
configured production topology and credentials.

Core implementation checklist: 18/21 complete (85.7%). The remaining readiness
dependencies are Refactor 100's live custody verification and Refactor 101's
broad integration gate. Target metadata enrichment, linked Wallet Session host
projection, and the normal NEAR/Tempo dispatch integrations are implemented.
The env-gated two-device live E2E contains exact linked-route assertions, but
its final local rerun stopped at a disabled owner-registration control before
the linking flow began. Post-v1 refresh, compromise cleanup, and the separately
tracked Wasm-size follow-up in Phase 5 remain deferred.

## Scope And Dependencies

This plan owns physical and browser device linking. A linked device becomes a
share-bearing participant for existing wallet keys and requires local user
presence for the first release.

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
   permission, target lanes, participants, protocol versions, and expiry. It
   selects exactly one owner authorization source; a reusable owner Wallet
   Session authorization and fresh step-up evidence are never combined.
4. Every target lane remains unavailable until all child protocols and the
   aggregate receipt commit. Each admitted operation carries its own
   `AuthorizedOperationId` and exact `MpcMaterialActivationRef`; neither ID
   aliases the Wallet Session, enrollment, or device identity.
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
- creates its passkey after owner claim binds the session to a wallet;
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
7. Return one receipt per key and one aggregate manifest receipt.

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

type AuthorizationGrant =
  | WalletSessionAuthorization
  | LinkedDeviceWalletSessionAuthorizationV1;

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

## Implementation Phases

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

| Unique affected Wasm | Baseline raw | Candidate raw | Delta raw | Baseline gzip | Candidate gzip | Delta gzip |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ed25519 Yao client | 1,210,795 | 979,566 | -231,229 | 433,487 | 383,404 | -50,083 |
| ECDSA derivation client | 610,161 | 700,917 | +90,756 | 245,876 | 285,620 | +39,744 |
| ECDSA presign client | 172,129 | removed | -172,129 | 73,064 | removed | -73,064 |
| ECDSA online client | 68,774 | removed | -68,774 | 31,585 | removed | -31,585 |
| **Unique affected set** | **2,061,859** | **1,680,483** | **-381,376** | **784,012** | **669,024** | **-114,988** |

| Unique affected Wasm | Baseline Brotli | Candidate Brotli | Delta Brotli |
| --- | ---: | ---: | ---: |
| Ed25519 Yao client | 311,801 | 298,141 | -13,660 |
| ECDSA derivation client | 198,286 | 231,161 | +32,875 |
| ECDSA presign client | 60,378 | removed | -60,378 |
| ECDSA online client | 26,382 | removed | -26,382 |
| **Unique affected set** | **596,847** | **529,302** | **-67,545** |

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
WASM_SDK_BUILD_MODE=prod pnpm -C packages/sdk-web run build:wasm
pnpm build:sdk-prod
pnpm -C packages/sdk-web run size:lite -- --json
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
- claiming Yao production readiness before its security gates pass.

## Resolved Decisions And Follow-Up Boundary

- Freeze link-session, claim, and committed-delivery TTLs.
- Freeze the device identity algorithm and HPKE suite.
- Freeze aggregate receipt encoding and wallet-key ordering.
- Define UX for devices without WebAuthn PRF support.
- The v1 compromise boundary is immediate aggregate revocation, server-role
  disablement, and exact local holder/session zeroization. Server-share
  destruction evidence, refresh/reprovisioning, and post-compromise recovery
  are follow-up work.
