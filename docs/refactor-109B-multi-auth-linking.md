# Refactor 109B — Mixed-Method Device Linking

Date created: August 20, 2026

Status: blocked pending rewrite. Depends on Refactor 103E authority activation
and Refactor 109A multi-method wallet authentication.

> **Implementation stop:** Do not implement the body of this document yet.
> It still contains the retired R102 owner/lane model, custody-seed transfer,
> factor-specific target-authority construction, and reuse of R109A's
> same-device persistence flow. R103E and the **Relationship to R103E and
> R109B** section of R109A define the controlling seam. Rewrite R109B against
> those contracts before assigning implementation work.

## Goal

Allow Device 1 to authorize a new linked owner with any active wallet method
while Device 2 independently chooses either supported target factor.

The supported matrix becomes:

| Device 1 owner proof | Device 2 target factor |
| --- | --- |
| Passkey | Passkey |
| Passkey | Email OTP |
| Email OTP | Passkey |
| Email OTP | Email OTP |

The source method authorizes the operation. The target method becomes Device
2's canonical owner authority. They serve different roles and never need to
match.

## Dependency on Refactor 109A

Email OTP linking consumes an active wallet-wide Email OTP base factor. It
does not collect or create the wallet's first email identity. Passkey linking
consumes the factor-complete add-auth-method service from Refactor 109A.

This ordering gives device linking two precise target-factor operations:

- add an enrollment-scoped Passkey owner authorized by any active owner;
- derive an enrollment-scoped Email OTP owner from a selected active base
  Email OTP factor.

If the requested target factor is unavailable, Device 1 denies the claim with
an actionable typed result. The link session closes cleanly and Device 2 can
choose another factor.

## Current blockers

The QR and protocol already carry `passkey_prf | email_otp`, and the Email OTP
target branch already has enrollment-scoped owner identity, challenge, grant,
factor release, holder delivery, and Wallet Session machinery.

Two source-side assumptions prevent mixed-method operation:

- Passkey target enrollment rejects any authenticated source whose active
  method is not Passkey.
- Email OTP target enrollment requires an already active local base Email OTP
  method and currently expects one implicit destination.

The first assumption couples authorization to the target factor. The second
needs explicit base-factor resolution once a wallet may contain several
verified emails.

## Correct model

### Source authority and target factor are independent

The link approval records both identities:

```text
active Device 1 Wallet Session authority
  -> exact existing owner proof
  -> link approval
  -> exact Device 2 target-factor branch
  -> enrollment-scoped Device 2 owner authority
  -> Device 2 owner-scoped lanes and Wallet Session
```

Device 1's authority authenticates approval and opens the existing custody
envelope. Device 2's factor seals the transferred custody seed and determines
the new owner authority. No code infers one from the other.

### Email OTP uses an explicit base factor

When the wallet has one active Email OTP base factor, Device 1 may select it
automatically and display its server-approved masked destination. When several
base factors exist, Device 1 must select one before approval. Device 2 cannot
supply or replace the email address.

The approved base `WalletAuthMethodId` is bound through:

- owner enrollment;
- target preparation;
- OTP challenge and one-use verification grant;
- enrollment-scoped linked owner authority;
- holder delivery and aggregate activation receipt;
- linked Wallet Session authorization.

### Passkey target uses wallet configuration

Passkey target registration gets its relying-party identity from the managed
wallet configuration and server-issued registration options. It does not copy
the source authority's factor. This allows an Email OTP source to authorize a
wallet's first Passkey through the factor-complete Refactor 109A service.

### Re-linking creates a new enrollment

The same physical browser may link again with another factor. Each successful
attempt creates a new link session, device key, enrollment, canonical owner
authority, lane set, and revocation identity.

A live link flow still blocks a concurrent start in the same runtime. Active,
cancelled, expired, and failed flows release that guard immediately. Existing
devices are never rejected solely because the browser was linked before.

## Protocol changes

### Owner approval

Replace source-kind guards with one exhaustive owner authorization union:

```ts
type LinkedDeviceSourceOwnerAuthorization =
  | { kind: 'passkey'; walletSession: ActivePasskeyWalletSession }
  | { kind: 'email_otp'; walletSession: ActiveEmailOtpWalletSession };
```

The approval builder requires:

- exact source authority reference and Wallet Session;
- immutable target-factor discriminator;
- target-factor-specific enrollment request;
- selected Email OTP base auth-method ID when the target is Email OTP;
- no Email OTP base ID when the target is Passkey.

Model these as branch-specific builders. Broad object spreads and optional
identity bags are prohibited.

### Custody transfer

Device 1 opens the custody seed through its active source factor and transfers
it through the existing worker-held HPKE channel. Device 2 reseals it under the
target factor:

- Passkey target uses the newly created credential's PRF result;
- Email OTP target uses the consumed `email_otp_factor_release_v1` envelope.

JavaScript never receives the seed, OTP factor secret, PRF output, or envelope
KEK. The two factor branches converge only after they produce an opaque sealed
custody record and exact public owner authority.

### Owner and execution identities

Every linked Device 2 keeps:

- one canonical owner auth method for human ownership;
- one enrollment-scoped linked execution authorization;
- exact Ed25519 and ECDSA lane products;
- one durable owner binding used by device inventory;
- revocation identity scoped to that enrollment and device.

R103C owner-scope resolution starts from the Device 2 Wallet Session authority
and selects only that owner's lanes. Source Device 1 lanes and sibling linked
owners never become candidates.

## Implementation phases

### Phase 1 — Decouple source authorization from target registration

- Replace `authentication.authMethod === 'passkey'` target gating with exact
  active owner Wallet Session authorization.
- Resolve the source authority through the canonical wallet auth-method store
  and verify its authority digest.
- Move Passkey RP resolution to managed wallet configuration and server-issued
  target registration options.
- Require target-factor-specific enrollment inputs through an exhaustive
  union.
- Delete same-factor source/target assumptions after cutover.

Primary locations:

- `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingOwnerEnrollmentStart.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts.ts`
- `packages/shared-ts/src/device-linking/contracts.ts`
- `packages/shared-ts/src/device-linking/parsers.ts`

Exit criterion: both Passkey and Email OTP source Wallet Sessions can produce
a valid Passkey target preparation without using a source Passkey credential
as the target identity.

### Phase 2 — Select the exact Email OTP base factor

- Read active base Email OTP factors from the canonical server inventory.
- Return a typed `target_factor_unavailable` result when none exists.
- Auto-select one factor only when exactly one is active.
- Present masked choices on Device 1 when several are active.
- Bind the selected base auth-method ID into every downstream Email OTP
  artifact.
- Remove local-user display records as an authority source; use them only for
  local presentation after exact server resolution.

Primary locations:

- `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceEmailOtpTargetFactor.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceEmailOtpGrantStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore.ts`

Exit criterion: a Passkey-authenticated Device 1 approves an Email OTP Device
2 against one exact pre-existing base factor, including wallets with multiple
verified email factors.

### Phase 3 — Make failure, cancellation, and retry branch-complete

- Return typed source denial for unavailable, revoked, or ambiguous target
  factors.
- Propagate denial to Device 2 and close the QR surface.
- Release the runtime in-progress guard on every terminal state.
- Keep committed holder delivery recovery child-by-child and idempotent.
- Retry target credential finalize, owner binding, lane activation, and Wallet
  Session delivery without creating duplicate records.
- Preserve committed state when a response is lost after the commit point.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingLaneProvisioning.ts`
- `packages/wallet-server/src/core/deviceLinking/linkedDeviceSession.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetCredentialProvider.ts`

Exit criterion: every precommit failure leaves no active enrollment, while
every postcommit retry converges on one owner binding, lane enrollment, and
Wallet Session delivery.

### Phase 4 — Device experience

- Keep target-factor choice on Device 2 before QR creation.
- Show target-factor availability and any required base-factor choice on
  Device 1 before approval.
- For Passkey target, create exactly one credential.
- For Email OTP target, send exactly one code unless resend is selected.
- Display direct actions for unavailable factor, owner denial, expiry,
  incorrect code, and retryable committed completion.
- Show the resulting factor and enrollment separately in Linked Devices.

Primary locations:

- `packages/wallet/src/react/components/ShowQRCode.tsx`
- `packages/wallet/src/react/components/QRCodeScanner.tsx`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/session.ts`
- `packages/wallet/src/react/components/AccountMenuButton/LinkedDevicesModal.tsx`

Exit criterion: the UI cannot display a Passkey action for an Email OTP
session, cannot collect an email on Device 2, and cannot leave a completed flow
marked in progress.

### Phase 5 — Mixed-method operating paths

- Update intended behavior for all four source/target combinations.
- Extend the composed two-browser harness with independent storage and
  WebAuthn state.
- Reuse shared factories for every protocol record.
- Remove same-factor fixtures and source guards that encode the retired
  constraint.
- Reconcile Refactor 103 Phase 6 statements with the completed mixed-method
  model.

## Verification gate

Start with a Refactor 109A wallet containing one active Passkey and one active
Email OTP factor. Use two clean browser profiles.

For each of the four source/target combinations:

1. Unlock Device 1 using the named source method.
2. Start linking on Device 2 using the named target factor.
3. Approve on Device 1 and complete the target interaction on Device 2.
4. Verify exactly one canonical owner binding, lane enrollment, Ed25519 lane,
   and ECDSA lane for the new enrollment.
5. Sign one NEAR transaction and one EVM-family transaction on Device 2.
6. Export Ed25519 and ECDSA material with one user-presence interaction per
   export.
7. Lock and unlock Device 2 through its target factor.
8. List devices from Device 1 and verify the new device remains visible after
   link-session expiry.
9. Revoke Device 2 and prove Device 1 plus sibling factors remain operational.

Additional recovery checks:

- repeat linking to the same physical Device 2 with the other target factor;
- lose the finalize response and retry;
- interrupt before owner binding commit;
- interrupt after lane commitment with one missing holder record;
- attempt a second concurrent QR flow in one runtime;
- retry immediately after active, cancelled, expired, and failed flows.

## Non-goals

- Creating the wallet's first Email OTP base factor during device linking;
  Refactor 109A owns factor addition.
- Sharing one owner authority or one lane set across two enrollments.
- Allowing Device 2 to enter or replace the wallet email destination.
- Reintroducing wallet-wide lane selection or auth-kind inference.

## Completion criteria

Refactor 109B is complete when all four pairings pass the real two-browser
gate, repeated linking creates independent manageable enrollments, and every
Device 2 operation resolves through its exact target owner authority. Mocked
protocol coverage alone is insufficient.
