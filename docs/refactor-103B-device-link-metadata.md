# Refactor 103B — Canonical Device-Link Metadata

Status: active implementation. Phase 1 and the independent account-menu work
are complete. Phase 2 and Phase 4 await the live Refactor 103 Phase 8
owner-credential cutover.

Last reconciled: August 17, 2026.

## Goal

Show a person enough trustworthy information to distinguish linked owner
credentials during device management:

- the stable linked-device identity;
- the credential kind;
- browser, operating-system, provider, transport, and sync metadata when the
  credential is a Passkey;
- the canonical owner credential binding created by Refactor 103 Phase 8;
- lifecycle, activity, and revocation state already owned by device management.

This refactor does not add metadata to the QR payload or enrich the temporary
Phase 7 signing-only target credential. Human Device 2 moves to the canonical
owner-credential system in Refactor 103 Phase 8. Metadata follows that durable
credential.

## Dependency And Timing

Refactor 103 has two deliberate milestones:

1. Phase 7 proves the signing-only linked execution substrate.
2. Phase 8 registers human Device 2 as a canonical owner credential and removes
   the human linked-session signing path.

Refactor 103B lands with or after the Phase 8 owner-credential cutover. It may
fix the existing canonical authenticator-list projection earlier, because that
fix is independent of device linking.

Do not add a parallel metadata model to
`linked_device_target_credentials`. That record belongs to the temporary
signing-only path and is deleted when human devices stop using linked holder
lanes.

## Current State

Canonical Passkey registration already derives
`WebAuthnAuthenticatorDeviceInfo` from:

- the registration request `User-Agent` for browser and operating system;
- verified attestation AAGUID for a recognized Passkey provider;
- the verified backup-eligibility flag for sync capability;
- the credential response transports.

The server persists this value as `webauthn_authenticators.device_info_json`.
The D1 record boundary parses it and produces `Unknown device` for an older row
without captured metadata.

The canonical authenticator service contract already declares a required
`device: WebAuthnAuthenticatorDeviceInfo` field. The current
`authenticatorListEntry` projection drops that field at runtime. Refactor 103B
repairs that mismatch before consuming the listing from device management.

The Phase 7 linked-device management projection instead derives the generic
labels `Platform passkey`, `Security key`, or `Passkey` from the temporary
target registration. Those labels contain no browser or operating-system
identity.

The current account-menu modal also computes `Device N` from the creation order
of the currently loaded page. That number is neither a durable device number
nor a signer slot. Pagination, historical deletion, or a different projection
can change it.

## Product Decisions

1. Keep the QR payload byte-for-byte unchanged. It remains a minimal public
   bootstrap message containing session identity, public keys, and expiry.
2. Treat credential metadata as display and audit context only. Authorization,
   enrollment, signing, step-up, and revocation never branch on a label,
   browser, operating system, provider, transport, or sync flag.
3. Use the server-derived canonical authenticator metadata. Do not accept a
   client-supplied device description in the credential-registration body.
4. Describe what the platform establishes. Examples include `Safari on iOS`,
   `Chrome on macOS`, `Windows Hello`, and `Unknown device`.
5. Never claim an exact hardware model. Browser and WebAuthn data cannot
   reliably distinguish a MacBook from another Mac or every iPhone from every
   iPad configuration.
6. Explain synced Passkeys accurately. A synced credential may be usable from
   several physical devices, so its provider metadata does not prove exclusive
   possession by one machine.
7. Email OTP is an owner factor without WebAuthn device metadata. Display
   `Email OTP` and the stable linked-device ID; do not infer a browser or
   machine.
8. Do not present a creation-order ordinal as a slot. If a canonical signer
   slot is relevant to a credential, label it explicitly as `Signer slot N`.
   It is technical credential metadata, not the device identity.
9. Keep user-assigned device names outside this refactor. They require a
   separate rename lifecycle, validation boundary, and audit policy.

## Domain Model

Refactor 103 Phase 8 must expose one exact binding from the device-management
enrollment to its canonical owner auth method. Refactor 103B consumes that
binding and does not infer it from creation times, labels, email addresses, or
credential-list ordering.

Use a branch-specific management projection:

```ts
type LinkedOwnerCredentialMetadataV1 =
  | {
      readonly kind: 'passkey';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly device: WebAuthnAuthenticatorDeviceInfo;
    }
  | {
      readonly kind: 'email_otp';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly device?: never;
      readonly credentialIdB64u?: never;
    };

type LinkedOwnerDeviceSummaryV1 = {
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletId: WalletId;
  readonly credential: LinkedOwnerCredentialMetadataV1;
  readonly coveredWalletKeys: readonly WalletKeyId[];
  readonly state: 'provisioning' | 'active' | 'suspended' | 'expired' | 'revoked';
  readonly createdAtMs: number;
  readonly lastActivityAtMs: number;
  readonly revocationEpoch: number;
};
```

The final type name should follow the Phase 8 management contract. The
important constraint is the discriminated credential branch. A Passkey summary
always carries parsed device metadata. An Email OTP summary cannot carry
WebAuthn fields.

Remove the loose public `label` and `platform` fields after the Phase 8
projection replaces them. Do not retain both shapes or add a compatibility
union in core code.

## Canonical Binding

Phase 8 owns persistence of the exact relationship:

```text
linked device enrollment
  -> canonical WalletAuthMethodId
  -> passkey credential or Email OTP authority
  -> canonical authenticator metadata when kind = passkey
```

The relationship must be written atomically with successful owner-credential
activation. Device management requires all of the following to agree:

- tenant scope;
- wallet ID;
- linked-device enrollment ID;
- linked-device ID;
- owner auth-method ID;
- Passkey credential ID when the branch is Passkey;
- active or revoked lifecycle state.

A missing, cross-wallet, duplicated, or wrong-kind binding is a projection
error. The management store must not select the nearest authenticator by time
or silently fall back to another wallet method.

Refactor 103B does not prescribe a second binding table. It uses the exact
binding shape selected by Phase 8. If Phase 8 stores the device-link provenance
on the canonical auth-method record, consume it there. If Phase 8 stores an
immutable management binding, consume that record. Do not duplicate lifecycle
state in both places.

## Implementation Plan

### Phase 1: Repair Canonical Authenticator Projection

- [x] Add `device: WebAuthnAuthenticatorDeviceInfo` to the exact return type of
      `authenticatorListEntry`.
- [x] Return `authenticator.deviceInfo` from the canonical authenticator row.
- [x] Keep the existing D1 boundary fallback for authenticator rows created
      before metadata capture.
- [x] Tighten the `AuthService` method result type so it cannot omit the
      contract's required `device` field.
- [x] Add a focused test proving `/webauthn/authenticators` returns signer
      binding fields and the parsed device metadata together.

Phase 1 is complete when the runtime response matches the already-published
service contract.

Landed. The core `WebAuthnAuthenticatorRecord` now carries `deviceInfo`, so the
listing can promise the field rather than reconstruct it; the `Unknown device`
fallback lives at each store boundary
(`parseWebAuthnAuthenticatorDeviceInfoJson`) and covers both a legacy row and a
binding with no authenticator row at all.

### Phase 2: Project Metadata Through The Phase 8 Binding

- [x] Define and atomically persist the exact Phase 8 linked enrollment ->
      canonical `WalletAuthMethodId` binding with successful owner-credential
      activation.
- [x] Require the exact Phase 8 owner-auth-method binding when projecting one
      managed linked device.
- [x] For a Passkey binding, resolve the canonical authenticator by wallet and
      credential ID and return its parsed `deviceInfo`.
- [x] For an Email OTP binding, return the Email OTP branch with no WebAuthn
      fields.
- [x] Reject cross-wallet, duplicate, missing, revoked-mismatch, and
      credential-mismatch joins.
- [x] Batch reads for the list path. Avoid one authenticator or auth-method
      query per card.
- [x] Replace `LinkedDeviceSummaryV1.label` and `.platform` with the exact
      credential metadata union at the request boundary.
- [x] Update the parser and type fixtures. Add `@ts-expect-error` cases for
      Passkey metadata on Email OTP and missing metadata on Passkey.

Phase 2 is complete when management returns one exact branch for every active
or historical linked owner credential without consulting the Phase 7 target
registration.

Landed. Management resolves the immutable Phase 8 binding in one wallet-scoped
batch, joins the exact canonical auth method and authenticator, and fails closed
when any identity or lifecycle fact disagrees.

### Phase 3: Update The Account Menu

- [x] Remove creation-order `Device N` numbering.
- [x] Use the credential label as the primary display name for Passkeys.
- [x] Show the provider when present and the sync state when useful.
- [x] Show `Email OTP` for the Email OTP branch.
- [x] Keep the shortened stable device ID visible on every branch; expose the
      full ID through an explicit copy or disclosure action if needed.
- [x] Preserve lifecycle status, last activity, confirmation, revocation, focus
      handling, and live announcements.
- [x] Let the metadata row wrap at narrow widths and at 200% zoom.
- [x] Use the same credential description in removal confirmation and success
      announcements so repeated generic labels do not identify the wrong card.

Example Passkey card:

```text
Safari on iOS                    Can use this wallet
iCloud Keychain · Synced passkey · ID …a8K2pQ7z
Last used today
[Remove]
```

Example Email OTP card:

```text
Email OTP                        Can use this wallet
ID …a8K2pQ7z
Last used today
[Remove]
```

Phase 3 is complete when each card is distinguishable without implying an
unverified hardware model or fabricated slot.

### Phase 4: Delete The Temporary Metadata Path

Perform this deletion with the Refactor 103 Phase 8 human-device cutover:

- [x] Delete `D1LinkedDeviceTargetCredentialMetadataSourceV1` from the human
      management path.
- [x] Delete `metadataFromRegistration` and its generic attachment-derived
      labels when no delegated consumer remains.
- [x] Delete tests and fixtures that require human management summaries to read
      `linked_device_target_credentials.registration_json`.
- [x] Delete the retired `label` and `platform` summary fields and all parser
      branches that accept them.
- [x] Keep R102 target-credential persistence protocol-only; no delegated
      public metadata consumer exists today.

No dual-read fallback remains after cutover.

Landed. Human management has one canonical metadata path and no dual-read
fallback.

## Security And Privacy Constraints

- Metadata never authorizes an operation or selects a wallet, lane, factor, or
  credential.
- The server derives Passkey metadata only after successful WebAuthn
  registration verification.
- Raw `User-Agent`, attestation objects, PRF outputs, factor secrets, and Email
  OTP addresses do not enter the management response.
- Provider and sync labels are informational and may be absent or incomplete.
- A synced Passkey label must never imply that revoking one linked enrollment
  deletes the credential from a platform provider.
- Device IDs and credential IDs remain identifiers rather than secrets. The UI
  shows a short distinguishing suffix and avoids printing full identifiers by
  default.
- Revocation decisions use canonical IDs from the selected card, never display
  labels or list indexes.

## Validation

### Static checks

- Passkey summaries require `device` and `credentialIdB64u`.
- Email OTP summaries reject every WebAuthn-only field.
- Core management functions reject loose `label` and `platform` records.
- No source path adds metadata fields to `QrLinkedDeviceSessionPayloadV4` or
  its compact serializer.
- No management control flow reads `device.label`, `browser`, `os`, `synced`,
  `provider`, or `transports`.

### Focused tests

- Canonical authenticator listing returns persisted metadata.
- Missing historical metadata becomes `Unknown device` at the D1 boundary.
- A Phase 8 Passkey binding resolves only its exact credential.
- An Email OTP binding produces no device metadata.
- Cross-wallet and substituted credential bindings fail closed.
- Batch listing preserves metadata across active, suspended, expired, and
  revoked enrollments.
- Revocation uses the exact device and enrollment IDs even when two cards have
  the same display label.

### Intended behavior

Add one Phase 8 two-device contract that proves:

1. Device 2 enrolls as a canonical owner Passkey.
2. Management shows its captured credential label and stable device ID.
3. Refresh and unlock preserve the same metadata.
4. Device 2 signs and performs fresh step-up through ordinary owner paths.
5. Device 1 revokes the exact linked credential.
6. The revoked credential cannot unlock or receive a new Wallet Session.
7. Device 1 remains operational.

Add the Email OTP variant only when Refactor 103 Phase 8 supports Email OTP as
a canonical linked owner factor. Assert the factor label and stable device ID;
do not assert browser or operating-system metadata.

## Non-Goals

- Change the QR payload or QR version.
- Add metadata to the Phase 7 signing-only target registration.
- Identify exact Mac, iPhone, iPad, Android, or Windows hardware models.
- Allocate a durable human-facing device ordinal.
- Rename devices.
- Use metadata for fraud scoring, authorization policy, or local-presence
  decisions.
- Add a new authenticator metadata framework or duplicate
  `WebAuthnAuthenticatorDeviceInfo`.
- Preserve the temporary human linked-session management shape after Phase 8.

## Completion Gate

Refactor 103B is complete when:

- the canonical authenticator listing returns the metadata its type promises;
- every Phase 8 linked owner credential has one exact management binding;
- Passkey cards display canonical server-derived metadata;
- Email OTP cards make no device claim;
- revocation targets canonical IDs rather than labels or ordinals;
- the QR payload is unchanged;
- the temporary Phase 7 metadata source and loose summary fields are deleted;
- focused tests and the Phase 8 intended-behavior contract pass.
