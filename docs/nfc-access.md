# Native NFC Access Credentials Plan

Last updated: 2026-05-20

## Goal

Build a simpler AccessGrid-class NFC access product directly inside the MPC
wallet stack.

The product should let a user:

- provision an NFC access credential to an iPhone, Apple Watch, Android phone,
  or physical NFC card
- bind that credential to an existing MPC wallet account
- recover access through passkey and approved wallet recovery factors
- re-provision replacement access credentials after phone or card loss
- gate credential issuance, extension, suspension, revocation, and recovery
  through the same policy pipeline used for signing and gas sponsorship

The durable product boundary is:

```text
wallet account auth -> access credential policy -> native credential authority
  -> mobile Wallet credential or physical NFC card
  -> NFC reader/controller
```

The actual NFC credential is an access-control credential issued by our native
credential authority. The MPC wallet account is the identity, recovery, policy,
and approval root for that credential lifecycle.

## Platform Reality

Native ownership means we own the hard parts that a provider would otherwise
hide:

- credential profiles and key hierarchy
- mobile Wallet provisioning rails
- reader/controller compatibility
- lifecycle synchronization
- revocation and recovery semantics
- platform approval for iPhone, Apple Watch, and some Google Wallet access rails

The iPhone and Apple Watch path depends on Apple Wallet or Apple NFC/SE platform
support. A normal iOS app cannot emit arbitrary NFC access-card responses. The
MVP should keep the account, policy, recovery, and lifecycle model independent
from the first credential rail so we can ship a smaller rail first and add
Apple/Google Wallet rails when the platform work is ready.

## Product Shape

The smallest useful native product is:

- user signs into the wallet portal with passkey or another allowed wallet auth
  method
- user requests an access credential for a site, room, event, warehouse, hotel
  stay, or visitor window
- policy decides whether the credential can be issued
- optional approval or quorum flow runs for sensitive locations
- native credential authority creates an access credential from a published
  credential profile
- portal returns the correct provisioning surface:
  - mobile Wallet install link or QR code
  - physical NFC card personalization job
  - Android HCE/dev credential for early testing
- credential lifecycle is linked to `walletId`
- recovery can revoke the old credential and issue a replacement

The NFC tap remains an access-control exchange:

```text
phone/watch/card credential <-> NFC reader/controller
```

The MPC wallet account governs the lifecycle:

```text
wallet account auth -> policy -> issue/recover/revoke access credential
```

## Non-Goals

- Running MPC on NFC terminals.
- Reusing an EVM threshold key as the NFC credential key.
- Treating static NFC UIDs, static NDEF payloads, or barcodes as secure access
  credentials.
- Keeping third-party AccessGrid-style provider adapters in the core product
  path.
- Hiding Apple/Google platform approval and reader compatibility behind product
  language.
- Adding migration paths for exploratory credential formats.

## Native Credential Rails

Use an explicit credential rail union:

```ts
type AccessCredentialRail =
  | { kind: 'physical_nfc_card'; cardFamily: 'desfire_ev3' | 'javacard' | 'piv' }
  | { kind: 'android_hce_dev'; appId: AndroidApplicationId }
  | { kind: 'google_wallet_access'; passType: 'smart_tap' | 'access_key' }
  | { kind: 'apple_wallet_access'; passType: 'employee_badge' | 'hotel_key' | 'home_key' };
```

Early implementation should choose one rail:

- `physical_nfc_card` for controlled cryptographic access-card tests
- `android_hce_dev` for fast mobile UX prototyping
- `google_wallet_access` when Smart Tap or access-key enrollment is available
- `apple_wallet_access` after Apple Wallet/NFC platform requirements are met

All rails share the same wallet binding, policy, lifecycle, recovery, and audit
model. Rail-specific code stays behind boundary parsers and credential builders.

## Wallet Account Binding

The MPC wallet account should be the identity and recovery root for access
credentials. Use a stable, non-secret access subject derived from the wallet
subject:

```text
access_subject_id =
  HASH("seams:nfc-access-subject:v1" || environment_id || wallet_id)
```

This subject id is safe to store in credential authority records and can be used
as the stable holder identity across credential re-issuance.

Rail-specific credential secrets are created by the native credential authority,
with the access subject and credential profile bound into the derivation or
manifest:

```text
credential_secret_or_manifest =
  CredentialAuthority(profile_key_version).issue(
    access_subject_id,
    credential_id,
    credential_profile_id,
    rail,
    access_scope,
    validity
  )
```

The MPC wallet key does not need to answer NFC reader challenges. It authorizes
credential lifecycle actions through passkey, recovery, policy, and approval.
The credential authority then issues or revokes the NFC credential for the
wallet-linked subject.

## Architecture

### Components

`Wallet Account`

- existing wallet, passkey bindings, recovery factors, signing roots,
  approvals, and audit identity

`Access Credential Service`

- owns credential lifecycle records
- normalizes route bodies into precise internal operation types
- evaluates access-credential policy
- calls the native credential authority
- persists lifecycle state
- emits audit and webhook events

`Native Credential Authority`

- owns credential profiles and key hierarchy
- derives or generates per-credential secrets for the selected rail
- creates mobile Wallet provisioning artifacts or physical-card personalization
  jobs
- signs credential manifests and lifecycle commands
- stores only server-authorized credential authority material

`Reader Registry`

- tracks reader/controller ids, locations, allowed rails, and public keys
- publishes reader configuration bundles when the rail needs them
- records last sync status for online or managed readers

`Console Policy System`

- adds `ACCESS_CREDENTIAL` as a policy kind
- uses the existing draft, publish, approval, versioning, audit, and runtime
  snapshot pipeline
- publishes resolved credential policy artifacts for runtime enforcement

`Wallet Portal`

- authenticates the user
- starts provisioning and recovery flows
- displays QR codes, install links, or card-personalization status
- shows lifecycle state and recovery actions

### Credential Authority Boundary

The native authority should expose one narrow internal interface:

```ts
type NativeAccessCredentialIssueInput = {
  kind: 'native_access_credential_issue';
  walletId: WalletId;
  environmentId: EnvironmentId;
  credentialProfileId: AccessCredentialProfileId;
  rail: AccessCredentialRail;
  accessScope: AccessCredentialScope;
  holder: AccessCredentialHolder;
  validity: AccessCredentialValidityWindow;
  idempotencyKey: IdempotencyKey;
};

type NativeAccessCredentialIssueResult =
  | {
      ok: true;
      value: IssuedNativeAccessCredential;
    }
  | {
      ok: false;
      code: NativeAccessCredentialErrorCode;
      message: string;
    };
```

Route bodies, mobile platform callbacks, reader sync reports, and card
personalization results are parsed once at the boundary. Core logic receives
normalized domain types only.

## Domain Model

### Credential Profile

A credential profile describes how credentials for one rail are created and
verified:

```ts
type AccessCredentialProfile = {
  id: AccessCredentialProfileId;
  environmentId: EnvironmentId;
  rail: AccessCredentialRail;
  name: string;
  status: 'draft' | 'published' | 'retired';
  keyVersion: AccessCredentialKeyVersion;
  readerCompatibility: AccessReaderCompatibility;
  publicDescriptor: AccessCredentialProfileDescriptor;
  createdAt: IsoDateTime;
  updatedAt: IsoDateTime;
};
```

Secret key material lives outside dashboard-visible profile records. The
credential authority resolves secret material through a server-controlled secret
store or HSM-backed key provider.

### Credential Binding

Each access credential is bound to one wallet:

```ts
type NativeAccessCredentialBinding = {
  id: NativeAccessCredentialId;
  walletId: WalletId;
  environmentId: EnvironmentId;
  credentialProfileId: AccessCredentialProfileId;
  credentialPublicId: AccessCredentialPublicId;
  rail: AccessCredentialRail;
  accessScope: AccessCredentialScope;
  policyId: ConsolePolicyId;
  lifecycle: NativeAccessCredentialLifecycle;
  createdAt: IsoDateTime;
  updatedAt: IsoDateTime;
};
```

`credentialPublicId` is safe to log and display. Rail-specific secrets, card
keys, mobile provisioning tokens, and reader keys must stay outside this record.

`accessScope` is the stable product-level object for buildings, rooms, zones,
event ids, hotel reservations, warehouse locations, or role groups.

### Lifecycle

Use one explicit lifecycle union:

```ts
type NativeAccessCredentialLifecycle =
  | {
      state: 'issued_pending_provisioning';
      provisioning: AccessCredentialProvisioningSurface;
      expiresAt: IsoDateTime;
      activatedAt?: never;
      suspendedAt?: never;
      revokedAt?: never;
    }
  | {
      state: 'active';
      provisioning: AccessCredentialProvisioningSurface;
      expiresAt: IsoDateTime;
      activatedAt: IsoDateTime;
      suspendedAt?: never;
      revokedAt?: never;
    }
  | {
      state: 'suspended';
      provisioning: AccessCredentialProvisioningSurface;
      expiresAt: IsoDateTime;
      activatedAt: IsoDateTime;
      suspendedAt: IsoDateTime;
      revokedAt?: never;
    }
  | {
      state: 'revoked';
      priorState: 'issued_pending_provisioning' | 'active' | 'suspended';
      provisioning?: never;
      expiresAt: IsoDateTime;
      activatedAt?: never;
      suspendedAt?: never;
      revokedAt: IsoDateTime;
    }
  | {
      state: 'expired';
      priorState: 'issued_pending_provisioning' | 'active' | 'suspended';
      provisioning?: never;
      expiresAt: IsoDateTime;
      activatedAt?: never;
      suspendedAt?: never;
      revokedAt?: never;
    };
```

Transitions should be branch-specific commands:

- `issueNativeAccessCredential`
- `markNativeAccessCredentialActive`
- `suspendNativeAccessCredential`
- `resumeNativeAccessCredential`
- `revokeNativeAccessCredential`
- `expireNativeAccessCredential`
- `recoverNativeAccessCredential`

Each command takes the narrowest valid lifecycle state.

### Operations

Use operation-specific intents for policy evaluation and audit:

```ts
type AccessCredentialOperation =
  | {
      kind: 'issue';
      walletId: WalletId;
      credentialProfileId: AccessCredentialProfileId;
      rail: AccessCredentialRail;
      accessScope: AccessCredentialScope;
      validity: AccessCredentialValidityWindow;
    }
  | {
      kind: 'recover';
      walletId: WalletId;
      oldCredentialId: NativeAccessCredentialId;
      replacementProfileId: AccessCredentialProfileId;
      replacementRail: AccessCredentialRail;
      replacementScope: AccessCredentialScope;
      replacementValidity: AccessCredentialValidityWindow;
    }
  | {
      kind: 'extend';
      walletId: WalletId;
      credentialId: NativeAccessCredentialId;
      requestedValidity: AccessCredentialValidityWindow;
    }
  | {
      kind: 'suspend';
      walletId: WalletId;
      credentialId: NativeAccessCredentialId;
      reason: AccessCredentialLifecycleReason;
    }
  | {
      kind: 'resume';
      walletId: WalletId;
      credentialId: NativeAccessCredentialId;
      reason: AccessCredentialLifecycleReason;
    }
  | {
      kind: 'revoke';
      walletId: WalletId;
      credentialId: NativeAccessCredentialId;
      reason: AccessCredentialLifecycleReason;
    };
```

## Provisioning Flow

1. User signs into the wallet portal with passkey, app session, or another
   policy-allowed wallet authentication method.
2. Portal requests an access credential for a concrete rail, profile, scope, and
   validity window.
3. Backend normalizes the request into `AccessCredentialOperation`.
4. Runtime policy evaluates the request.
5. If approval is required, the existing approval workflow records and resolves
   the approval.
6. Native credential authority creates the credential.
7. Backend stores `NativeAccessCredentialBinding` with
   `state: 'issued_pending_provisioning'`.
8. Portal returns the provisioning surface:
   - Wallet install URL or QR code
   - physical card personalization task
   - Android HCE/dev activation payload
9. Credential rail reports activation through callback, polling, card
   personalization completion, or reader sync.
10. Backend updates lifecycle to `active`.
11. Audit records the policy, auth method, rail, profile id, credential id,
    public credential id, and resulting lifecycle state.

## Recovery And Re-Provisioning

Recovery is a first-class lifecycle path:

```text
lost phone or card
  -> prove wallet identity
  -> policy approves recovery
  -> old credential is revoked or suspended
  -> replacement credential is issued
  -> provisioning surface is shown
```

Recovery policy can require:

- passkey assertion
- Email OTP or another recovery factor
- admin approval
- manager quorum for high-security scopes
- recent wallet session age
- no unresolved risk flags on the wallet

The recovery command should atomically bind the old and replacement records:

```ts
type NativeAccessCredentialRecoveryRecord = {
  id: NativeAccessCredentialRecoveryId;
  walletId: WalletId;
  oldCredentialId: NativeAccessCredentialId;
  replacementCredentialId: NativeAccessCredentialId;
  policyId: ConsolePolicyId;
  authorizationDigest: AuthorizationDigest;
  requestedAt: IsoDateTime;
  completedAt: IsoDateTime;
};
```

High-security recovery requires confirmed revocation or reader-denylist
publication before returning the replacement provisioning surface. Lower-risk
scopes can allow async cleanup only when policy explicitly permits it.

## Policy Model

Add a new policy kind:

```ts
type ConsolePolicyKind =
  | 'TRANSACTION'
  | 'GAS_SPONSORSHIP'
  | 'ACCESS_CREDENTIAL';
```

`ACCESS_CREDENTIAL` policies should reuse the shared policy store and approval
system. The rules are specific to credential operations:

```ts
type ConsoleAccessCredentialPolicyRules = {
  enabled: boolean;
  scopeType: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
  environmentId: EnvironmentId;
  allowedCredentialProfileIds: AccessCredentialProfileId[];
  allowedRails: AccessCredentialRail[];
  allowedAccessScopes: AccessCredentialScopeRule[];
  allowedOperations: AccessCredentialOperationKind[];
  maxCredentialDurationSeconds: number;
  maxRecoveryDurationSeconds: number;
  requirePasskeyForIssue: boolean;
  requirePasskeyForRecovery: boolean;
  approval: AccessCredentialApprovalRule;
};
```

The runtime snapshot should publish a resolved artifact:

```ts
type ResolvedAccessCredentialPolicy = {
  policyId: ConsolePolicyId;
  enabled: boolean;
  environmentId: EnvironmentId;
  allowedCredentialProfileIds: AccessCredentialProfileId[];
  allowedRails: AccessCredentialRail[];
  allowedAccessScopes: AccessCredentialScopeRule[];
  allowedOperations: AccessCredentialOperationKind[];
  maxCredentialDurationSeconds: number;
  maxRecoveryDurationSeconds: number;
  requiredAuth: AccessCredentialAuthRequirement;
  approval: AccessCredentialApprovalRule;
};
```

The access credential service consumes resolved runtime policy only. Dashboard
authoring can expose friendly presets:

- visitor pass for X hours
- contractor pass during business hours
- hotel stay access until checkout
- warehouse access for a specific shift
- vault access requiring quorum approval
- emergency revoke all credentials for a wallet

## Relationship To Gas Sponsorship

Gas sponsorship already has the right product pattern:

- author policy in console
- publish policy into runtime snapshots
- runtime service consumes the resolved policy
- execution records `policyId`
- billing/audit rows reference the exact policy and caller

NFC access credentials should follow the same split:

- dashboard authors credential rules
- runtime snapshot publishes resolved credential policy
- access credential service matches a normalized operation against resolved
  policy
- native credential authority executes issue, extension, suspension, revocation,
  and recovery
- lifecycle and audit records persist exact outcomes

This is another policy-backed capability, with credential lifecycle as the
execution domain.

## Reader And Terminal Model

Most NFC access decisions should stay local to the reader/controller:

```text
credential tap -> reader challenge -> credential response -> local decision
```

The native product must still model readers because credential profiles and
revocation depend on reader compatibility:

```ts
type AccessReaderRecord = {
  id: AccessReaderId;
  environmentId: EnvironmentId;
  locationScope: AccessCredentialScope;
  supportedRails: AccessCredentialRail[];
  status: 'registered' | 'active' | 'suspended' | 'retired';
  lastSyncAt?: IsoDateTime;
};
```

For online readers, add a later tap-proof API:

```text
reader submits tap proof -> backend verifies reader and credential policy
  -> backend returns signed short-lived UnlockIntent
```

That online flow is an extension. The core product is credential lifecycle,
recovery, policy, and reader-compatible provisioning.

## Security Requirements

- Require cryptographic wallet authentication for provisioning and recovery.
- Bind every credential to one `walletId`.
- Bind every credential to one environment, rail, and credential profile.
- Keep credential authority secrets in server-controlled secret storage or HSM
  infrastructure.
- Keep per-credential secrets, card keys, mobile provisioning tokens, reader
  private keys, and issuer keys out of logs and dashboard-visible records.
- Use idempotency keys for issue and recovery operations.
- Persist lifecycle transitions and callback payload digests.
- Record `policyId`, actor, auth method, approval id, rail, profile id,
  credential id, public credential id, and requested access scope in audit
  events.
- Make high-security recovery fail closed unless old credential revocation or
  reader denylist publication is confirmed.
- Keep live door decisions with the reader/controller unless an online terminal
  integration is explicitly added.
- Require cryptographic challenge-response rails for secure access.

## Phased Plan

### Phase 0: Freeze The Native Boundary

- [ ] Choose the first credential rail.
- [ ] Decide the first supported use case: corporate badge, warehouse pass,
  visitor pass, hotel key, or event access.
- [ ] Define the first `AccessCredentialScope` shape.
- [ ] Define the first `AccessCredentialProfile` shape for the chosen rail.
- [ ] Define which recovery factors can authorize replacement credentials.
- [ ] Decide high-security scopes that require approval before issue/recovery.

### Phase 1: Credential Authority And Persistence

- [ ] Add native access credential domain types.
- [ ] Add credential profile persistence.
- [ ] Add credential binding persistence.
- [ ] Add recovery record persistence.
- [ ] Add native credential authority interface for issue, activate, suspend,
  resume, revoke, expire, and recover.
- [ ] Add secret-resolution boundary for credential authority material.
- [ ] Add callback or polling ingestion for activation and lifecycle updates.

### Phase 2: First Credential Rail

- [ ] Implement the first rail-specific credential builder.
- [ ] Add profile validation for the selected rail.
- [ ] Add provisioning output for the selected rail.
- [ ] Add reader compatibility metadata for the selected rail.
- [ ] Add targeted tests for credential issuance, lifecycle, and recovery on
  the selected rail.

### Phase 3: Provisioning UX

- [ ] Add wallet portal route for requesting an access credential.
- [ ] Require passkey or policy-allowed wallet auth.
- [ ] Evaluate resolved credential policy before issuance.
- [ ] Create the native credential and persist the binding.
- [ ] Return the rail-specific provisioning surface.
- [ ] Show lifecycle state: pending provisioning, active, suspended, revoked,
  expired.

### Phase 4: Recovery UX

- [ ] Add lost-device and replacement-device recovery flow.
- [ ] Parse recovery request once at the route boundary.
- [ ] Evaluate recovery policy against old credential state and requested
  replacement scope.
- [ ] Revoke or suspend the old credential.
- [ ] Issue the replacement credential.
- [ ] Persist a recovery record linking old and new credentials.
- [ ] Emit recovery-specific audit events.

### Phase 5: Policy Engine Integration

- [ ] Add `ACCESS_CREDENTIAL` policy kind.
- [ ] Add `ConsoleAccessCredentialPolicyRules`.
- [ ] Add parser and validation for access credential rules.
- [ ] Add dashboard authoring for credential policies.
- [ ] Add policy publish approval payloads for credential policies.
- [ ] Add resolved access credential policies to runtime snapshots.
- [ ] Add simulation for issue, recovery, extend, suspend, resume, and revoke.

### Phase 6: High-Security Controls

- [ ] Add approval requirements for sensitive scopes.
- [ ] Support quorum approval for vaults, warehouses, labs, and admin-only areas.
- [ ] Fail closed when revocation or reader-denylist publication cannot be
  confirmed before replacement issuance for sensitive scopes.
- [ ] Add emergency revoke for all credentials linked to a wallet.
- [ ] Add audit export for credential lifecycle events.

### Phase 7: Billing And Reporting

- [ ] Record cost events by credential profile, rail, and lifecycle operation.
- [ ] Attribute issued credentials to org, project, environment, API key, and
  policy.
- [ ] Add dashboard reporting for active credentials, recovery events, suspended
  credentials, revoked credentials, and rail-specific cost.
- [ ] Decide whether credential issuance consumes prepaid balance, subscription
  entitlements, or a separate billing product.

### Phase 8: iPhone And Apple Watch Rail

- [ ] Define the Apple Wallet access use case and required platform path.
- [ ] Complete Apple Wallet/NFC entitlement and program work.
- [ ] Add Apple-specific credential profile validation.
- [ ] Add Apple-specific provisioning artifacts and callbacks.
- [ ] Add reader compatibility tests for the supported Apple credential type.
- [ ] Keep the same wallet binding, recovery, policy, and audit model.

### Phase 9: Optional Online Terminal Integration

- [ ] Define terminal registration for online readers.
- [ ] Bind terminal ids to environments and access scopes.
- [ ] Let online terminals submit tap proofs for backend policy verification.
- [ ] Return signed short-lived unlock intents only after terminal and credential
  policy pass.
- [ ] Keep terminal online authorization separate from credential provisioning.

## Acceptance Criteria

- A wallet user can provision a native access credential from the wallet portal
  after passkey authentication.
- The credential record is linked to `walletId`, environment, rail,
  credential profile, public credential id, policy, and lifecycle state.
- The first rail can create a real provisioning artifact or personalization job.
- Lost-device or lost-card recovery can revoke the old credential and issue a
  replacement credential through policy-approved auth.
- Access credential policy can restrict rail, profile, scope, duration,
  operation, and approval requirements.
- Runtime enforcement consumes resolved policy artifacts from runtime snapshots.
- Every issue, recovery, suspend, resume, revoke, and expire operation emits an
  audit event with `policyId` and credential authority outcome.
- High-security scopes can require passkey plus approval or quorum before issue
  or recovery.
- The iPhone and Apple Watch rail ships only after the platform path supports
  the selected access credential type.
