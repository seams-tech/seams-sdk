# Passkey Account Refactor To Wrapped Holder Shares

Date created: June 15, 2026

Status: design plan. This plan changes passkey-backed accounts so passkey PRF
material acts as a KEK source for a rotatable holder share. It supports the
signing-lane foundation in
[refactor-71-delegate-wallets.md](./refactor-71-delegate-wallets.md), the
share-rotation model in [refactor-72-share-rotation.md](./refactor-72-share-rotation.md),
and the full delegated-agent and linked-device behavior in
[refactor-74-delegated-agent-linked-device-behavior.md](./refactor-74-delegated-agent-linked-device-behavior.md).

## Goal

Move passkey accounts away from deterministic client MPC share derivation.

Target model:

```text
MPC ceremony creates random holder share.
Passkey PRF derives an unwrap KEK.
KEK seals holder share.
Recovery codes seal backup envelopes for the same holder share.
Signing opens the holder share only inside the wallet worker boundary.
```

The passkey becomes an authentication and unwrapping factor. The passkey-derived
secret no longer defines the MPC signing share.

## Why This Is Required

Deterministic passkey-derived shares made early account sync easier. They create
three problems for delegated agent wallets:

1. Share rotation cannot be modeled cleanly because the holder share is tied to
   the authenticator output.
2. Agent lane creation needs address-preserving resharing, which is cleaner when
   holder shares are durable lane secrets.
3. Recovery and backup should wrap the same lane secret instead of rederiving
   unrelated signing material.

The Email OTP account model already has the useful shape: random client-side
secret material is sealed, recovery codes wrap server-stored recovery escrows,
and plaintext recovery codes remain user-held.

This plan also supersedes the stale recovery/export adaptor slice in
[refactor-34b-stepup-adaptor.md](./refactor-34b-stepup-adaptor.md). Export and
recovery authorization should be reworked around wrapped holder-share envelopes
instead of adding the old `requireExportStepUpAuth` wrapper first.

## Current State

Relevant code patterns:

- `passkeyPrfFirstB64u` flows through ECDSA activation and bootstrap paths.
- Passkey warm sessions cache PRF material with TTL and remaining uses.
- Email OTP enrollment generates a client secret and derives
  `clientRootShare32`.
- Email OTP recovery uses `EMAIL_OTP_RECOVERY_KEY_COUNT = 10` and stores
  recovery-wrapped enrollment escrow records server-side.
- Email OTP recovery-code rotation already exists as an explicit capability.

Current passkey behavior should be treated as a migration source. New core logic
should operate on sealed holder-share envelopes.

## Design Decision

Create a passkey lane holder share during registration or address-preserving
resharing. Seal that holder share under passkey-derived KEKs and recovery-code
KEKs.

```text
holder_share_lane
  -> sealed by passkey KEK
  -> sealed by recovery code KEK 1
  -> sealed by recovery code KEK 2
  -> ...
  -> sealed by recovery code KEK 10
```

Server storage contains recovery-wrapped envelopes and metadata. The server must
never store plaintext recovery codes, passkey PRF outputs, holder shares, holder
share KEKs, or wallet private keys.

## Secret Hierarchy

Normal passkey unlock:

```text
WebAuthn PRF output
SecureConfirm session material
  -> passkey lane KEK
  -> opens sealed holder share
  -> holder share participates in MPC signing
```

Recovery-code unlock:

```text
user enters one recovery code
  -> recovery KEK
  -> opens recovery-wrapped holder-share envelope
  -> creates fresh passkey envelope for an owner lane
  -> consumed recovery code is retired
```

Device link:

```text
existing owner lane authenticates
  -> approves linked-device permission profile
  -> creates a new linked-device signing lane
  -> delivers a distinct holder share to the new device
  -> new device seals its holder share under its own passkey KEK
```

Warm sessions:

```text
fresh passkey unlock
  -> opens holder share inside worker
  -> creates bounded holder-share session handle
  -> handle is bound to walletKeyId, laneId, laneShareEpoch, ttl, and signingGrantId
```

Warm sessions should cache an opened holder-share handle or a worker-confined
unwrap capability. They should never cache raw PRF outputs in app-visible state.

## New Records

### Passkey Holder-Share Envelope

```ts
type PasskeyHolderShareEnvelopeRecord = {
  kind: 'passkey_holder_share_envelope_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  rpId: string;
  credentialIdB64u: string;
  passkeyEnvelopeVersion: string;
  passkeyKekVersion: string;
  nonceB64u: string;
  sealedHolderShareB64u: string;
  aadHashB64u: string;
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};
```

### Recovery-Wrapped Holder-Share Envelope

```ts
type RecoveryWrappedHolderShareEnvelopeRecord = {
  kind: 'recovery_wrapped_holder_share_envelope_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  recoveryKeyId: DerivedRecoveryKeyId;
  recoveryKeyStatus: 'active' | 'consumed' | 'revoked';
  recoveryEnvelopeVersion: string;
  nonceB64u: string;
  wrappedHolderShareB64u: string;
  aadHashB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};
```

The recovery-code count should follow the Email OTP model:

```ts
const PASSKEY_RECOVERY_KEY_COUNT = EMAIL_OTP_RECOVERY_KEY_COUNT; // 10
```

This can reuse shared recovery-code formatting after naming is generalized from
Email OTP to wallet recovery.

### Passkey Device Envelope Index

One owner lane may have multiple passkey envelopes for the same holder share and
lane epoch. This supports synced passkeys, multiple authenticators, and
same-device authenticator replacement without changing the MPC share.

```ts
type PasskeyDeviceEnvelopeIndexRecord = {
  kind: 'passkey_device_envelope_index_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  credentialIdB64u: string;
  rpId: string;
  deviceLabel: string;
  envelopeId: PasskeyEnvelopeId;
  status: 'active' | 'retired' | 'revoked';
  createdAtMs: number;
  updatedAtMs: number;
};
```

Removing one passkey credential should revoke that credential's envelope. It
should trigger lane share refresh only when the removed credential or the opened
holder share may have been exposed.

## Passkey Envelopes Versus Linked Devices

Passkey envelopes and QR-linked devices are different operations.

Passkey envelope addition:

```text
same wallet key
same lane id
same lane share epoch
same holder share
new passkey credential wraps the same holder share
```

Use this for:

- synced passkeys on the same platform account
- adding a hardware security key to the same owner lane
- replacing a local authenticator after the owner lane is already open

QR linked-device creation:

```text
same wallet key
new linked-device lane id
new lane share epoch
new holder share
new server share
new passkey credential wraps the linked-device holder share
```

Use this for:

- scanning a QR code on Device 2 from an existing owner device
- revoking one physical device without touching other lanes
- creating a scoped device with a limited mandate
- creating an owner-equivalent device that still has independent revocation

The QR link-device flow belongs to the delegated signer behavior plan in
[refactor-74-delegated-agent-linked-device-behavior.md](./refactor-74-delegated-agent-linked-device-behavior.md).
This passkey refactor supplies the envelope model each device lane uses after
its holder share is delivered.

## KEK Derivation Spec

Passkey KEK derivation needs an explicit, versioned context.

```ts
type PasskeyKekDerivationContext = {
  kind: 'passkey_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  rpId: string;
  credentialIdB64u: string;
  passkeyKekVersion: string;
  purpose: 'holder_share_envelope';
};
```

Recovery-code KEK derivation should use the same wallet recovery context family
as Email OTP after the helper naming is generalized:

```ts
type RecoveryKekDerivationContext = {
  kind: 'wallet_recovery_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  recoveryKeyId: DerivedRecoveryKeyId;
  recoveryEnvelopeVersion: string;
  purpose: 'holder_share_recovery_envelope';
};
```

Both contexts must be hashed into envelope AAD. PRF outputs, KEKs, and recovery
codes must stay inside wallet-owned UI or worker boundaries.

## AAD Binding

All passkey and recovery envelopes must bind:

- wallet id
- wallet key id
- lane id
- lane share epoch
- holder share public commitment
- envelope kind
- envelope version
- rpId and credential id for passkey envelopes
- recovery key id for recovery envelopes
- signing root id and version when the lane depends on Router A/B material

Opening an envelope under mismatched AAD must fail before plaintext is accepted.

## Registration Flow

New passkey account registration:

1. Create or select `WalletKeyRecord`.
2. Run MPC keygen or lane creation ceremony.
3. Produce owner passkey lane holder share and matching server share.
4. Run WebAuthn with PRF.
5. Derive passkey KEK.
6. Seal holder share into `PasskeyHolderShareEnvelopeRecord`.
7. Generate 10 recovery codes.
8. Derive recovery KEKs and wrap the holder share 10 times.
9. Store active recovery-wrapped holder-share envelopes server-side.
10. Persist lane record, passkey envelope, recovery envelopes, and server share.
11. Return recovery codes only to the owning wallet UI boundary.

## Login And Signing Flow

1. Resolve owner passkey lane.
2. Run WebAuthn PRF or claim an active warm passkey KEK session.
3. Open the sealed holder-share envelope inside the wallet worker.
4. Build exact signing lane identity.
5. Run normal signing admission and budget checks.
6. Participate in MPC signing.
7. Zeroize holder-share plaintext after use or retain only inside a bounded warm
   session.

The app and host page must never receive PRF outputs, KEKs, holder-share bytes,
or recovery codes.

## Recovery Flow

1. User enters one recovery code in the wallet-owned UI boundary.
2. Client derives recovery key id and recovery KEK.
3. Server returns the matching active recovery-wrapped holder-share envelope.
4. Wallet worker opens the holder share.
5. Server marks the recovery code as consumed.
6. User registers a new passkey envelope for an owner lane.
7. System rotates recovery codes after successful recovery.

Recovery should fail closed when the expected number of active recovery-wrapped
records is unavailable.

## Recovery-Code Lifecycle

Recovery-code sets are lane-epoch scoped.

Required states:

```ts
type RecoveryCodeLifecycleState =
  | {
      state: 'active';
      issuedAtMs: number;
      consumedAtMs?: never;
      revokedAtMs?: never;
    }
  | {
      state: 'consumed';
      issuedAtMs: number;
      consumedAtMs: number;
      revokedAtMs?: never;
    }
  | {
      state: 'revoked';
      issuedAtMs: number;
      revokedAtMs: number;
      consumedAtMs?: never;
    };
```

Rotation rules:

- new registration issues exactly 10 active recovery-wrapped envelopes
- successful recovery consumes one code and rotates the full set
- user-requested rotation requires an opened owner holder share
- lane share refresh creates a new recovery-code set for the new lane epoch
- old recovery envelopes are revoked after the new set is acknowledged
- recovery-code plaintext is displayed only once to the owner UI boundary

The server may store recovery key ids, statuses, envelope ciphertext, and audit
metadata. It must reject requests that include recovery-code plaintext, recovery
KEKs, passkey PRF outputs, or opened holder-share bytes.

## Device And Passkey Management

Features to account for:

- list passkey envelopes for an owner lane
- add a passkey envelope from an already opened owner lane
- revoke one passkey envelope
- rotate all passkey envelopes after suspected device compromise
- recover onto a new passkey using one recovery code
- regenerate recovery codes after owner confirmation
- clear warm holder-share sessions on passkey envelope revocation

QR device linking should create a new linked-device lane through the delegation
flow. It should create a new passkey envelope only after the new device receives
its distinct holder share.

Linked-device lanes should not create new recovery-code authority by default.
Recovery codes remain attached to owner recovery flows unless the owner
explicitly adds a recovery policy for that linked device.

## Migration From Deterministic Passkey Shares

Existing passkey accounts require an address-preserving migration ceremony.

```text
old deterministic holder contribution + old server contribution = wallet key
new random holder share + new server share = same wallet key
```

Migration requires fresh user authentication because the old holder contribution
must participate. The server cannot convert an old deterministic passkey share
into a new random holder share by itself while preserving the address.

Migration steps:

1. User signs in with passkey and creates a fresh migration operation.
2. Wallet worker derives or opens the old holder contribution inside the worker.
3. Server resolves the matching old server share.
4. Run address-preserving lane resharing.
5. Create a random new holder share and new server share.
6. Seal the new holder share under passkey KEK.
7. Generate or rotate recovery-code envelopes.
8. Verify public key/address parity.
9. Mark the new lane epoch active.
10. Retire deterministic derivation records at the persistence boundary.

Compatibility code belongs only in the migration reader/parser. Core signing
logic should accept only the new sealed-holder-share lane state.

Migration should also define a product gate:

- eligible deterministic accounts migrate after the next successful passkey
  unlock
- signing may continue only through the migration parser until the new envelope
  is created
- new passkey registrations use sealed holder-share envelopes only
- delegated agent lane creation requires the account to be on wrapped holder
  shares
- linked-device lane creation requires the account to be on wrapped holder
  shares
- deterministic passkey share derivation is deleted after the supported
  migration window

## Type Model

Use branch-specific lifecycle types.

```ts
type PasskeyLaneMaterialState =
  | {
      state: 'sealed_holder_share_available';
      envelope: PasskeyHolderShareEnvelope;
      holderShare?: never;
      migration?: never;
    }
  | {
      state: 'holder_share_open';
      holderShare: OpenHolderShare;
      envelope: PasskeyHolderShareEnvelope;
      migration?: never;
    }
  | {
      state: 'legacy_deterministic_migration_required';
      migration: LegacyDeterministicPasskeyMigrationRecord;
      envelope?: never;
      holderShare?: never;
    };
```

Static checks:

- `holder_share_open` without `holderShare` fails.
- sealed state with `holderShare` fails.
- legacy migration state cannot be passed to signing functions.
- recovery envelope with plaintext recovery code fails.

## Prep Phase: Envelope And Recovery Foundations

This phase is additive and should land before passkey behavior changes.

### Folder Layout To Prepare

```text
packages/shared-ts/src/wallet-recovery/
  recoveryCodes.ts
  recoveryEnvelopes.ts
  recoveryKekContext.ts
  walletRecovery.typecheck.ts

packages/sdk-web/src/core/signingEngine/session/passkey/envelopes/
  passkeyKekContext.ts
  holderShareEnvelope.ts
  recoveryWrappedHolderShare.ts
  passkeyEnvelopeIndex.ts
  holderShareEnvelope.typecheck.ts

packages/sdk-web/src/core/signingEngine/session/holderShares/
  holderShareHandle.ts
  holderShareEnvelopeAad.ts
  forbiddenHolderSharePayloads.typecheck.ts
```

The existing Email OTP recovery helpers can remain in place during prep. New
wallet-recovery modules should expose neutral names that Email OTP and passkey
flows can adopt later.

### Structs To Introduce First

Add type-only records and builders:

- `PasskeyHolderShareEnvelopeRecord`
- `RecoveryWrappedHolderShareEnvelopeRecord`
- `PasskeyDeviceEnvelopeIndexRecord`
- `PasskeyKekDerivationContext`
- `RecoveryKekDerivationContext`
- `RecoveryCodeLifecycleState`
- `OpenHolderShareHandle`
- `SealedHolderShareEnvelopeAad`

Keep these structs out of current signing flows until the migration boundary is
ready.

### Non-Breaking Work Available Today

- create generic wallet-recovery aliases around the current Email OTP recovery
  code format
- add passkey KEK derivation context types without deriving new KEKs yet
- add envelope AAD builders with tests using dummy holder-share commitments
- add type fixtures rejecting PRF outputs, KEKs, recovery-code plaintext, and
  opened holder-share bytes in app-visible payloads
- add `PasskeyDeviceEnvelopeIndexRecord` types for same-lane passkey envelope
  management
- add QR linked-device tests proving linked-device envelopes require a distinct
  `laneId` and `laneShareEpoch`
- add source guards around new envelope modules before wiring them into passkey
  registration or login

Prep should leave these behaviors unchanged:

- deterministic passkey share derivation
- current passkey unlock and signing
- current Email OTP recovery-code issuance and rotation
- current QR link-device behavior
- current warm-session storage

### Prep Progress

- [x] Added wallet-neutral recovery aliases under
      `packages/shared-ts/src/wallet-recovery/`.
- [x] Added recovery envelope and KEK-context types that can be reused by
      passkey holder-share envelopes later.
- [x] Added passkey holder-share envelope, passkey KEK context, recovery-wrapped
      holder-share, and passkey envelope index prep modules.
- [x] Added opaque holder-share handle and envelope AAD helper modules.
- [x] Added type fixtures rejecting recovery-code plaintext, PRF output, and
      holder-share bytes in app-visible prep types.

## Implementation Phases

### Phase 0: Inventory

- [ ] List all passkey PRF paths used as signing material.
- [ ] Identify persistence records containing deterministic passkey share state.
- [ ] Identify warm-session paths that cache PRF outputs.
- [ ] Identify Email OTP recovery-code helpers that can be generalized.
- [ ] Complete the additive envelope and recovery prep phase.

### Phase 1: Domain Types

- [ ] Add branded IDs for wallet key, lane id, lane share epoch, and envelope id.
- [ ] Add `PasskeyHolderShareEnvelopeRecord`.
- [ ] Add `RecoveryWrappedHolderShareEnvelopeRecord`.
- [ ] Add `PasskeyDeviceEnvelopeIndexRecord`.
- [ ] Add recovery-code lifecycle state.
- [ ] Add strict parsers for raw persistence rows.
- [ ] Add type fixtures rejecting mixed legacy/new material states.

### Phase 2: Envelope Crypto

- [ ] Define passkey KEK derivation with explicit domain separation.
- [ ] Define recovery KEK derivation with generalized wallet-recovery contexts.
- [ ] Bind all envelope AAD fields.
- [ ] Add open/seal helpers in worker-only code.
- [ ] Add source guards blocking holder-share bytes from app-visible payloads.
- [ ] Add source guards blocking PRF outputs and KEKs from app-visible payloads.

### Phase 3: New Registration Path

- [ ] Generate random holder share during passkey registration.
- [ ] Seal holder share under passkey KEK.
- [ ] Generate 10 recovery codes.
- [ ] Store recovery-wrapped holder-share envelopes server-side.
- [ ] Persist owner passkey lane record.
- [ ] Verify the resulting wallet address.

### Phase 4: Login And Signing

- [ ] Open sealed holder share after WebAuthn PRF.
- [ ] Pass only opened holder-share handles into signing code.
- [ ] Remove direct PRF-as-client-share inputs from core signing functions.
- [ ] Keep warm sessions as bounded holder-share unwrap sessions.
- [ ] Bind warm sessions to `walletKeyId`, `laneId`, `laneShareEpoch`, and
      the active `signingGrantId` when the warm capability spends a signing
      grant.
- [ ] Clear warm sessions when the envelope or lane epoch is revoked.
- [ ] Record budget spends against `signingGrantId`, `laneId`, and
      `laneShareEpoch`.

### Phase 5: Recovery

- [ ] Add passkey recovery-code status API.
- [ ] Add recovery unwrap path for passkey holder-share envelopes.
- [ ] Mark consumed recovery codes.
- [ ] Rotate recovery-code envelopes after recovery.
- [ ] Add UI flow modeled after Email OTP recovery codes.
- [ ] Add user-initiated recovery-code regeneration.
- [ ] Revisit export/recovery step-up routing after holder-share envelopes exist;
      do not revive the superseded refactor-34b `requireExportStepUpAuth` shape
      without a current holder-share and lane-aware design.

### Phase 5a: Device Management

- [ ] List active passkey envelopes for an owner lane.
- [ ] Add a passkey envelope from an authenticated owner lane.
- [ ] Revoke a single passkey envelope.
- [ ] Rotate all passkey envelopes after compromise.
- [ ] Verify single-envelope revocation does not change wallet address.
- [ ] Route QR link-device creation to delegated linked-device lane creation in
      [refactor-74-delegated-agent-linked-device-behavior.md](./refactor-74-delegated-agent-linked-device-behavior.md).
- [ ] Ensure linked-device passkey envelopes wrap distinct holder shares.

### Phase 6: Migration

- [ ] Add migration parser for deterministic passkey records.
- [ ] Require fresh passkey auth before migration.
- [ ] Run address-preserving lane resharing.
- [ ] Seal new random holder share.
- [ ] Generate recovery-code envelopes.
- [ ] Verify address parity.
- [ ] Remove deterministic passkey share paths after migration support is no
      longer needed.

## Validation

Static checks:

- core signing functions reject legacy deterministic passkey material
- passkey envelope records require `walletKeyId`, `laneId`, and
  `laneShareEpoch`
- recovery envelope records cannot contain plaintext recovery codes
- passkey KEK contexts require credential id and lane epoch
- recovery KEK contexts require recovery key id and lane epoch
- opened holder-share state cannot be serialized to app-visible messages

Unit tests:

- wrong AAD fails to open passkey envelope
- wrong recovery code fails to open recovery envelope
- consumed recovery code cannot be reused
- recovery-code rotation leaves exactly 10 active envelopes
- removing one passkey envelope leaves other passkey envelopes active
- revoked passkey envelope clears matching warm sessions
- QR linked-device enrollment creates a distinct lane id and lane share epoch
- QR linked-device enrollment does not reuse the owner holder share
- migration preserves wallet public key/address
- signing fails after envelope revocation

Integration tests:

- register passkey account with sealed holder share
- login via passkey and sign
- recover on new device with one recovery code
- rotate recovery codes
- add a second passkey envelope and sign from it
- revoke one passkey envelope and sign from another
- scan QR to create a linked-device lane and sign from the linked device
- migrate legacy deterministic account and sign with new holder-share envelope

## Non-Goals

- storing recovery-code plaintext in any server-side record
- passing PRF outputs through app-visible payloads
- retaining deterministic passkey-derived signing shares in core logic
- using recovery codes for routine transaction signing
- letting a recovery code create delegated agent lanes without owner policy
- changing wallet addresses during normal migration

## Open Questions

- Should passkey recovery codes reuse the Email OTP code format and naming?
- Should recovery-code APIs become auth-method neutral before passkey migration?
- Which worker owns passkey holder-share envelope opening?
- Should warm sessions cache opened holder shares or cache KEKs that reopen
  holder shares per operation?
- How long should legacy deterministic migration support remain at persistence
  boundaries?
- Which user action is required before generating passkey recovery codes?
- Should synced passkeys share one display label model with physical security
  keys and platform authenticators?
