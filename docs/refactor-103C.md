# Refactor 103C — Exact Owner Lane Resolution

Last reconciled: August 20, 2026 (delegated authority and activation scope)

## Status

Exact device-scope resolution, durable device inventory, and the focused
coverage are implemented. Refactor 103D now owns the remaining activation gap:
Device 2 must install the exact permission-derived capabilities and secret
packages for the complete Device 1 signer manifest before the link becomes
active.
After R103D lands, the remaining R103C gate is the automated real two-device
Passkey and Email OTP flow against the composed runtime.

R103C closeout now has two ordered tasks: complete R103D, then run the automated
real-device gate. Older unchecked phase entries below are implementation
history rather than an active backlog.

R103C fixes device-lane selection after a wallet has more than one human owner
credential. It also corrects the linked-device inventory source. Refactor 103B
continues to own device display metadata. R103C supersedes the Refactor 103B
statements that describe device-link capabilities as a temporary path to
delete.

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

## Incident gap-closure plan

The linked-device operating-path incident exposed three production invariants
that R103C must enforce in addition to owner-scoped reads. These are code
corrections. Focused tests verify them after the operating path works.

### A. Canonicalize exact sealed records at the persistence boundary

- Derive the persisted primary key from the exact durable material identity.
- When legacy primary keys normalize to that identity, compare their
  authenticated public identity facts, keep one current record, and atomically
  rewrite it under the canonical key.
- Treat a repeated write for the same identity as an idempotent replacement.
  Sealed ciphertext is randomized and is not an equality key.
- Reject records whose public identity facts disagree under one canonical key.
- Return only physically canonical records to signing, restore, and export
  readers. In-memory de-duplication alone is insufficient because another
  exact reader can still observe every legacy row.

Implementation boundary:

- `packages/wallet/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `packages/wallet/src/core/indexedDB/seamsWalletDB/signingSessionSeals.ts`

### B. Reconcile committed signer activation child by child

- Treat the committed approval, requested `DelegatedWalletAuthorityV1`,
  administered signer-family manifest, and ordered activation packages as the
  exact activation plan.
- Index durable activation records by enrollment, device, signer family,
  capability identity, material activation, and revocation epoch.
- Reuse every matching record and install only missing packages while their
  factor-bound recipient state remains available.
- Reject duplicate deliveries, conflicting records, absent-family packages,
  and packages outside the approved authority before acknowledging the
  aggregate receipt.
- A grant containing `sign` installs fresh Device 2 signing material. A grant
  containing `export_keys` additionally installs the factor-bound Ed25519 Yao
  Client export-root package when Ed25519 is present. Management permissions
  add no signing or export secret by themselves.
- Persist activation evidence and Wallet Session delivery idempotently before
  reporting completion.
- A committed flow without every package required by its exact authority
  returns a terminal activation error. It cannot spin or claim activation.

Implementation boundary:

- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingLaneProvisioning.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/linkDevice.ts`

### C. Resolve Device 2 export inside the active device scope

- Resolve the active Wallet Session authorization to one exact device scope.
- Require that scope on the first Ed25519 or ECDSA export-lane read.
- Select the active ordinary signer capability only after device, enrollment,
  factor, activation, signer-family, and revocation filtering. Sibling-device
  capabilities never enter export selection.
- Refactor 103D supersedes export-time account hydration. Device linking must
  install the exact ordinary capability before reporting signing ready. A
  grant containing `export_keys` must also install its factor-bound export root
  before reporting export ready. Recovery, rotation, rejoin, and fallback cannot
  manufacture missing material. Missing material after that boundary is an
  integrity failure.
- Ed25519 owner linking transports the Ed25519 Yao Client export root encrypted
  to Device 2's one-use QR recipient and reseals it under Device 2's verified
  Passkey or Email OTP factor. The wallet custody seed never crosses the link.
  Device 2 later uses the existing ordinary Yao export flow with Deriver A and
  Deriver B.
- Device 2 signing material comes from additive ordinary registration. Fresh
  Device 2 client and server shares reproduce the existing public key while
  Device 1's shares remain unchanged. R102 holder material does not participate.
- The approved family set defaults to and currently requires every canonical
  active signer family on Device 1. Selective family delegation is outside
  R103C/R103D.
- Pass the resolved exact lane identity into execution. Execution does not
  repeat lane selection or WebAuthn credential discovery.

Implementation boundary:

- `packages/wallet/src/core/signingEngine/assembly/ports/recovery.ts`
- `packages/wallet/src/SeamsWeb/assembly/createBrowserRecoveryPublicDeps.ts`
- `packages/wallet/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
- `packages/wallet/src/react/components/AccountMenuButton/index.tsx`

Activation readiness and committed completion are specified by
`docs/refactor-103D.md`. R103C owns exact selection after that boundary and
contains no downstream repair behavior.

### Gap-closure acceptance criteria

1. Multiple legacy Ed25519 rows for one exact material identity become one
   canonical durable row without comparing ciphertext bytes.
2. A committed delivery with a mixture of installed and missing activation
   children installs only the missing children and produces one exact aggregate
   receipt.
3. Device 2 resolves export for each present signer family only when its exact
   active authority contains `export_keys`. Ed25519 export consumes the
   installed export root and receives one target-factor interaction per export.
4. An authority without `export_keys` cannot export or carry an export-root
   package at the activation-plan, parser, or persistence boundary.
5. Conflicting sealed records or activation packages terminate with an exact
   integrity error instead of falling back to another lane.

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

### Human ownership and device linking remain distinct

Device 2 has related records with different jobs:

- its verified wallet auth method authenticates the human operation;
- its linked-device Wallet Session provides revocable per-device authority;
- its ordinary signer capabilities provide independent signing material;
- an authority containing `export_keys` additionally carries the factor-bound
  Yao Client export root used by the ordinary Ed25519 export flow.

The device-link enrollment, delivery, renewal, and revocation machinery
provisions and manages the device's ordinary signer capabilities. Export is a
fresh authorized operation over the exact active capability and uses the
ordinary export flow and types.

Refactor 103D binds every present family and derives the required material from
the canonical permission set before `active`. `export_keys` installs every
export package required by the administered manifest. The target factor already
verified during linking supplies that activation, avoiding a second prompt.
Link enrollment remains provenance and management metadata.

The `verified_owner_unlock` activation remains valid for an ordinary later
unlock. The `existing_target_passkey` branch remains the explicit renewal path
when the stored linked session has actually expired. Neither path repairs an
incomplete export operation.

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
- Exact activation, lifecycle, expiry, exhaustion, and explicit internal
  material-identity rehydration tests remain valid. Export-time account
  hydration expectations are obsolete under Refactor 103D.
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

- Preserve the rule that target-factor identity and per-device signer material
  are separate.
- Replace the single signing-only grant with
  `DelegatedWalletAuthorityV1`: a canonical set of `sign`, `export_keys`,
  `link_devices`, and `revoke_devices` permissions shared with future
  agent-delegated wallets. `signing_only` and `full_owner` remain preset
  builders only.
- Keep target-factor endpoints for authentication and step-up, device-linking
  endpoints for delivery, renewal, and revocation, and ordinary signing/export
  endpoints for ordinary capability operations.

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
  authorization validation, execution admission, and D1 permission checks must
  carry the exact canonical delegated permission set. Unknown, duplicate,
  empty, escalated, and contradictory permission/material combinations are
  rejected at the boundary.
- Refactor 103D strengthens the terminal contract: Device 2 acknowledges the
  existing aggregate receipt only after installing its target credential,
  every permission-derived capability for the complete source signer manifest,
  every package required by `export_keys`, warm session, and Wallet Session.
  The durable flow then reports `active`.
  Interrupted post-commit work remains `committed_awaiting_activation` and
  resumes the same plan.
- `selectWalletHostEd25519SourceLaneV1` and exact rehydration paths intentionally
  select a supplied material activation. They may inspect internal candidates.
- The device-link authorization grant, capability delivery, active delivery,
  session renewal, local-presence proof, and revocation stay in place.
- `WalletSessionRef` stays wallet-scoped. Owner identity comes from the active
  authorization projection inside the signing engine; UI callers do not send
  credential or signer-slot hints.
- The existing one-use QR recipient encryption and factor-sealing primitives
  carry the export root. The Yao export protocol, wallet seed derivation, and
  ordinary signing protocols remain unchanged. The authority and activation
  manifests gain the canonical permission set, derived material requirements,
  and package digests; no new persistence table is required.

## Existing enrollments

Current devices are valid only when their exact target-factor binding and every
permission-derived material requirement for the administered manifest satisfy
the Refactor 103D active postcondition. An `active` label alone is insufficient
evidence.

An older or incomplete enrollment that fails the postcondition cannot act as a
human owner. Return a clear re-link requirement at the request or persistence
boundary. Add no compatibility selector, export hydration, or migration marker.

## Historical Implementation Checklist

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
- [ ] Automate the real two-device Passkey and Email OTP gate below.
- [ ] Delete stale tests and helpers that exist only for wallet-wide human owner
      selection.
- [ ] Reconcile the contradictory Refactor 103, Refactor 103B, and owner-binding
      comments with the retained device-link model.
- [ ] Complete Refactor 103D and prove `active` implies every
      permission-derived package is locally installed and durably committed.

## Automated verification gate

Use two independent clean browser profiles and a fresh wallet. Run the same
operating path once with a Passkey target factor and once with Email OTP.

1. Device 1 creates the wallet.
2. Device 2 links with the `full_owner` permission preset, one Passkey-creation
   prompt, and the complete canonical signer manifest active on Device 1.
3. Both devices refresh, lock, and unlock with one Touch ID prompt each.
4. Both devices sign and perform step-up authentication for each present
   signer family.
5. Both devices holding `export_keys` export each present signer family through
   ordinary export flows.
6. Device 2 links a third human owner device with a permission subset of its
   own authority.
7. Device 1 revokes Device 2.
8. Repeat with Device 2 revoking Device 1 while another owner remains.
9. Repeat unlock, signing, export, linking, and device listing with sibling
   owner lanes and retired historical rows present.
10. Verify an enrollment without an exact target-factor binding receives the
    re-link result.
11. Verify the `signing_only` preset can sign and is rejected by export, linking,
    and revocation admission.
12. Verify representative custom permission combinations and require every
    child grant to be a subset of the authorizer's permissions.

## Completion rule

R103C is complete when every authenticated human operation starts from the
active target-factor authority, lane selection occurs inside that exact device
scope, device inventory comes from durable owner bindings, Refactor 103D
supplies the strict activation postcondition, and the automated plus real-device
gates pass.

If implementation requires a new protocol version, generalized selector,
compatibility mode, registry, manifest, digest, or persistence table, stop and
simplify it.
