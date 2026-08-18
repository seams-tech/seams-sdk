# Refactor 103C — Exact Owner Lane Resolution

## Status

Proposed correction to Refactor 103 Phase 8.

R103C fixes owner-lane selection after a wallet has more than one human owner
credential. It also corrects the linked-device inventory source. Refactor 103B
continues to own device display metadata. R103C supersedes the Refactor 103B
statements that describe human linked execution as a temporary path to delete.

## Problem

The wallet persists signing material for several owner credentials and several
historical activations. Some runtime operations read every lane for a wallet,
then search or rank that candidate collection.

That model is wrong for an authenticated owner operation. The active Wallet
Session already identifies the exact authority that authenticated. A sibling
owner's material and retired material cannot be candidates for that operation.

This ambiguity caused:

- `lane_inventory_mismatch` and `ed25519_lane_missing` during unlock;
- `ambiguous_material` during Ed25519 export;
- stale owner-lane preflight requests during device linking;
- device-management results coupled to expired link-session history.

## Correct model

### Owner identity is a derivation chain

For an active human owner session:

```text
active Wallet Session authority
  -> active wallet auth method
  -> exact Passkey credential or Email OTP authority
  -> exact local authenticator and signer slot when kind = Passkey
  -> that owner's signing lanes
```

Each value is derived from the previous value. Callers do not independently
supply wallet ID, auth-method ID, credential ID, and signer slot and ask a
matcher to reconcile them.

The verified credential remains the source during WebAuthn login. After login,
the unique active Wallet Session authorization projection carries its exact
authority reference. Runtime operations resolve that reference through the
active wallet auth-method store. A Passkey method then resolves one local
authenticator by its exact credential ID to obtain the signer slot.

Missing or duplicate records are integrity failures. Timestamps, labels,
auth-method kind, and signer-slot searches cannot select another owner.

### Lanes are canonical inside one owner scope

The persistence reader may load wallet-wide history. Before an owner operation
selects a lane, it filters that history to the exact owner authority and signer
slot.

Within that owner scope, runtime exposes one current Ed25519 lane and one
current ECDSA lane per configured chain target. Each lane keeps its existing
lifecycle states, including ready, restorable, deferred, expired, and
exhausted. Existing restore and mint behavior remains a transition of that
lane.

Retired and superseded activations remain persistence history. Sibling owner
lanes remain valid for their own credentials. Neither collection participates
in the current owner's operational selection.

### Human ownership and linked execution remain distinct

Device 2 has two related records with different jobs:

- its canonical wallet auth method makes it a human owner;
- its linked-device Wallet Session and lane-holder material provide revocable,
  per-device execution.

The existing `owner_equivalent_signing` / `signing_only` permission describes
the narrow linked execution grant. It does not classify the human as a
signing-only user. Keep that grant, the linked execution bundle, delivery,
renewal, and revocation machinery.

The `verified_owner_unlock` activation correctly reuses the owner's verified
PRF and avoids a second WebAuthn prompt. Keep it. The
`existing_target_passkey` branch remains the explicit renewal path when the
stored linked session has actually expired.

## Verified change inventory

### 1. Resolve one exact owner scope

Primary locations:

- `packages/wallet/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts`
- `packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.ts`
- `packages/wallet/src/core/indexedDB/seamsWalletDB/repositories.ts`
- `packages/wallet/src/core/signingEngine/session/identity/signingLaneAuthBinding.ts`

Changes:

- Use the unique active `WalletAuthAuthorityRef` as the runtime starting point.
- Resolve it through one active wallet auth method. Remove the sealed-session
  and loose authenticator-list alternatives from
  `resolveExactWalletAuthAuthority`.
- For Passkeys, resolve the exact local authenticator by credential ID and take
  its signer slot.
- Make `getWalletPasskeyAuthenticator` follow the same wallet/NEAR-profile
  pivot already used by `listWalletPasskeyAuthenticators`; its current direct
  profile lookup can miss valid wallet authenticators.
- Represent the result as one owner-lane scope: Passkey auth binding plus
  signer slot, or Email OTP auth binding.

Verdict: required. This removes multiple sources of owner identity without
adding a new persisted identity or public API field.

### 2. Scope operational lane reads before selection

Primary locations:

- `packages/wallet/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `packages/wallet/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
- `packages/wallet/src/core/signingEngine/interfaces/operationDeps.ts`
- `packages/wallet/src/core/signingEngine/assembly/ports/shared.ts`
- `packages/wallet/src/core/signingEngine/assembly/ports/near.ts`
- `packages/wallet/src/core/signingEngine/assembly/ports/evmFamily.ts`
- `packages/wallet/src/core/signingEngine/assembly/ports/recovery.ts`
- `packages/wallet/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts`

Changes:

- Require the exact owner scope on human operational reads.
- Filter Ed25519 by exact auth binding and signer slot.
- Filter ECDSA by exact auth binding.
- Canonicalize lifecycle and material activation only after that filter.
- Expose canonical lane fields to operational consumers without wallet-wide
  candidate collections.

Keep the wallet-wide raw reader and candidate collections inside persistence,
normalization, diagnostics, and explicit material-identity rehydration. They
must not drive an authenticated human operation.

Verdict: required. This is the central model correction.

### 3. Remove downstream owner candidate scans

Primary locations:

- `packages/wallet/src/core/signingEngine/session/postconditions/runtimePostconditions.ts`
- `packages/wallet/src/core/signingEngine/session/identity/selectLane.ts`
- `packages/wallet/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
- `packages/wallet/src/core/signingEngine/flows/signNear/signNear.ts`
- `packages/wallet/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`
- `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`

Changes:

- Unlock postconditions consume the owner-scoped canonical lanes directly.
- Ed25519 and ECDSA export consume the owner-scoped canonical lane. A sibling
  owner credential no longer produces `ambiguous_material`.
- NEAR and EVM-family signing and step-up consume the same owner-scoped read.
- Login readiness checks use the same scoped result.
- Delete ranking, auth-kind inference, and aggregate-repair logic whose only
  purpose is choosing among different human owners.

Keep exact material-activation checks. They distinguish the current activation
from historical material for the same owner.

Verdict: required after Phase 2. These are consumers of the incorrect
wallet-wide contract and should become linear.

### 4. Project devices from durable owner bindings

Primary locations:

- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceManagementStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore.ts`

Changes:

- Enumerate linked owner bindings for the wallet.
- Join each binding to its canonical auth method, authenticator metadata, lane
  enrollment, and activity.
- Continue adding founding owner auth methods through the existing owner-device
  projection.
- Stop using claimed link sessions as the set of current devices. Sessions are
  workflow history and may expire or be pruned.
- Keep the existing management response and UI projection unless the durable
  enumeration proves a small cursor adjustment is necessary.

Verdict: required. It fixes a demonstrated inventory defect and reuses the
existing durable binding store.

### 5. Update the tests that own these invariants

Primary locations:

- `tests/unit/exportLaneSelection.unit.test.ts`
- `tests/unit/runtimePostconditions.unit.test.ts`
- `tests/unit/ed25519TransactionLaneSelection.unit.test.ts`
- `tests/unit/evmFamilyAuthNeutralPreparedSigning.unit.test.ts`
- `tests/unit/d1LinkedDeviceManagementComposition.unit.test.ts`
- `tests/typecheck/` with one focused owner-scope fixture
- `tests/e2e/linked-device.operating-path.test.ts`

Classification:

- The operating-path E2E test is the intended-behavior contract. Preserve and
  extend its existing prompt, export, and bidirectional revocation checks.
- The export test that expects two valid owner credentials to produce
  `ambiguous_material` encodes the incorrect wallet-wide model. Replace it.
- Runtime-postcondition tests that scan candidates to repair a stale aggregate
  encode the tactical workaround. Delete or rewrite them around the scoped
  operational result.
- Exact activation, lifecycle, expiry, exhaustion, and explicit material
  rehydration tests remain valid.
- Device-management composition should prove durable bindings remain visible
  after workflow sessions expire.

Verdict: required. It removes protection for the incorrect model while keeping
the lifecycle and exact-material invariants.

### 6. Remove contradictory design text

Primary locations:

- `docs/refactor-103-device-linking.md`
- `docs/refactor-103B-device-link-metadata.md`
- `packages/shared-ts/src/device-linking/ownerAuthBinding.ts`

Changes:

- Preserve the Phase 8 rule that canonical owner identity and per-device
  signing material are separate.
- Remove statements that call the linked execution lane temporary or require
  deleting human use of its narrow grant.
- Keep the established endpoint split: canonical owner endpoints handle
  authentication, custody, administration, and step-up; linked-lane endpoints
  handle per-device delivery, renewal, execution, and revocation.

Verdict: required documentation cleanup. The current text contains both the
correct separation and a contradictory deletion instruction.

## Verified non-changes

The inventory found no valid reason to change these areas:

- WebAuthn verification and `webauthn_credential_bindings` already resolve a
  credential by exact RP ID and credential ID.
- `linked_device_owner_auth_bindings` remains enrollment and device-management
  metadata. Founding Device 1 has no such binding, so it cannot become the
  universal runtime owner lookup.
- `packages/shared-ts/src/device-linking/contracts.ts`, its parsers, server
  authorization validation, execution admission, and D1 permission checks keep
  the linked execution grant unchanged.
- The durable link flow already reports success only after its terminal
  `active` event. Retained finalize and `resumeCommittedDeliveryV1` already
  handle interrupted completion.
- `selectWalletHostEd25519SourceLaneV1` and exact rehydration paths intentionally
  select a supplied material activation. They may inspect internal candidates.
- The linked-device execution grant, holder lanes, active delivery, session
  renewal, local-presence proof, and revocation stay in place.
- `WalletSessionRef` stays wallet-scoped. Owner identity comes from the active
  authorization projection inside the signing engine; UI callers do not send
  credential or signer-slot hints.
- No custody cryptography, MPC/Yao protocol, key derivation, QR payload,
  manifest, digest, or new persistence table changes are required.

## Existing enrollments

Current Phase 8 devices with an active canonical owner auth binding remain
valid. They do not need to be linked again.

An older enrollment without an active canonical owner auth binding cannot act
as a human owner. Return a clear re-link requirement at the request or
persistence boundary. Add no compatibility selector and no migration marker.

## Phased TODO

### Phase 0 — Lock the behavioral contract

- [ ] Update the exact-owner unit fixtures so two active owner credentials can
  coexist for one wallet.
- [ ] Replace the obsolete export expectation that sibling owners cause
  `ambiguous_material` with exact-current-owner selection.
- [ ] Classify candidate-backed postcondition tests that repair a stale
  aggregate as obsolete under the scoped-reader contract.

### Phase 1 — Build the owner scope

- [ ] Simplify `resolveExactWalletAuthAuthority` to the active auth-method
  source.
- [ ] Fix exact wallet authenticator lookup across the canonical wallet and
  NEAR-profile storage pivot.
- [ ] Build the owner scope from the active authority and exact authenticator.
- [ ] Add a type fixture proving a Passkey owner scope requires a signer slot
  and Email OTP cannot carry one.

### Phase 2 — Scope the lane reader

- [ ] Require owner scope on the human signing read port.
- [ ] Filter Ed25519 and ECDSA material before canonicalization.
- [ ] Return an owner-scoped operational result without candidate collections.
- [ ] Preserve lifecycle handling for the selected owner's current activation.
- [ ] Prove retired rows and sibling owner rows do not change the result.

### Phase 3 — Simplify operational consumers

- [ ] Cut unlock postconditions to the scoped canonical lanes.
- [ ] Cut NEAR and EVM-family signing and step-up to the scoped lanes.
- [ ] Cut Ed25519 and ECDSA export to the scoped lanes.
- [ ] Cut login readiness to the scoped lanes.
- [ ] Delete downstream scans and ranking that become unreachable.

### Phase 4 — Correct device inventory

- [ ] Enumerate durable linked owner bindings instead of claimed link sessions.
- [ ] Preserve the founding-owner projection and existing display metadata.
- [ ] Verify Device 1 and Device 2 remain visible after link-session expiry.

### Phase 5 — Prove the operating path

- [ ] Run the focused owner-scope unit and type tests.
- [ ] Make `tests/e2e/linked-device.operating-path.test.ts` pass against the
  composed local stack.
- [ ] Run the real two-device gate below.
- [ ] Delete stale tests and helpers that exist only for wallet-wide human owner
  selection.
- [ ] Reconcile the contradictory Refactor 103, Refactor 103B, and owner-binding
  comments with the retained linked execution model.

## Verification gate

Use two clean browser profiles and a fresh wallet.

1. Device 1 creates the wallet.
2. Device 2 links with one Passkey-creation prompt.
3. Both devices refresh, lock, and unlock with one Touch ID prompt each.
4. Both devices sign and perform step-up authentication for NEAR and EVM-family
   transactions.
5. Both devices export their NEAR and EVM-family keys.
6. Device 2 links a third human owner device.
7. Device 1 revokes Device 2.
8. Repeat with Device 2 revoking Device 1 while another owner remains.
9. Repeat unlock, signing, export, linking, and device listing with sibling
   owner lanes and retired historical rows present.
10. Verify an enrollment without a canonical owner binding receives the re-link
    result.

## Completion rule

R103C is complete when every authenticated human operation starts from the
active owner authority, lane selection occurs inside that exact owner scope,
device inventory comes from durable owner bindings, and the automated plus
real-device gates pass.

If implementation requires a new protocol version, generalized selector,
compatibility mode, registry, manifest, digest, or persistence table, stop and
simplify it.
