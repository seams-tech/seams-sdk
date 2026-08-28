# Refactor 115 — Recover Multi-Auth Wallets

Status: the Passkey/Email-origin by Passkey/Google-target 2x2 recovery contract
landed in `7310b703f`. Commit `d3c242eac` subsequently made successful
preparation continue directly into the selected target flow. On 2026-08-28 the
four matrix cases, an admitted Passkey finalization retry, and Google
post-commit response-loss replay passed locally.
Combined-inventory, linked-authority, step-up, export, dual-target
cancellation/conflict/replay, and post-promotion reload acceptance remain in
the worklist below.

## Goal

Make one wallet-scoped recovery code recover any wallet whose current owner
methods are Passkey, Google SSO with Email OTP, or both. The user chooses the
authentication method created on the recovering device:

- Passkey; or
- Google SSO with Email OTP.

Recovery adds a fresh device authority and method. It preserves every existing
method, custody envelope, authority, linked device, and Wallet Session.
Recovery restores access to the wallet; it does not replace or revoke the
wallet's existing access paths.

R115 supersedes R114's selected-Passkey replacement policy. It retains
R114's code-only wallet lookup, reservation lifecycle, complete key-manifest
verification, recovery-code cryptography, possession proofs, retry model, and
normal-login continuation.

## Landed State and Remaining Failure

The landed path resolves the wallet from the recovery-code locator, selects an
exact active Passkey or Email OTP continuity anchor, and installs a fresh
`wallet_recovery` authority plus the selected Passkey or Google/Email method.
The continuity anchor and every pre-existing method, authority, envelope,
linked device, and Wallet Session remain active. Finalization creates no Wallet
Session; normal target login mints it.

The server commit and replay path read back the committed active recovery
authority and target method. The client strictly validates their relationship,
then persists the exact authority, method, and locked selection before building
the remaining local login continuity. Migrations
`0026_r115_wallet_recovery_authority_provenance.sql` and
`0027_r115_email_otp_recovery_bootstrap.sql` are landed and immutable.

One crash boundary remains unresolved. After the server consumes the recovery
code, `promoted_pending_continuity` lives only in the coordinator's in-memory
map while the rest of local continuity is published. Reload at that point loses
the operation needed to resume installation. The remaining work must add a
redacted, non-discoverable durable receipt or equivalent bounded resume record,
then publish the wallet only after every fail-closed login prerequisite is
durable. It must never persist a recovery code, factor secret, custody seed, or
signer root in plaintext.

## Dependencies and Ownership

- R103E owns wallet authorities, signer activations, exact Wallet Sessions,
  signing, export, reload, and linked-device authority installation.
- R109C owns multiple methods, exact method selection, and method-bound custody
  envelopes.
- R109D owns mixed-factor linked-device authorities and independent revocation.
- R114 owns code-only wallet discovery, recovery-set cryptography, reservation,
  key-manifest reconstruction, Passkey replacement, and replay.
- R115 owns additive multi-auth recovery and explicit target selection.

R115 reuses the existing Passkey registration, Google identity, Email OTP,
factor-release, custody sealing, authority activation, local persistence, and
normal-login paths. It adds no parallel provider or signing implementation.

## Product Decisions

### Recovery admission is wallet-scoped

The recovery code locates and authenticates the wallet recovery set. Existing
method count and family never gate admission. The user does not authenticate an
old method and does not select an old device.

The wallet must have one valid recovery set, one complete key manifest, and at
least one exact active method with an active wallet-custody envelope that can be
used as the ceremony's continuity anchor. Missing or contradictory durable
state receives the generic recovery refusal.

### The user selects the new method

The selected target becomes immutable when the code is reserved:

```ts
type WalletRecoveryTargetV1 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly googleProvider?: never;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly googleProvider: 'google';
      readonly rpId?: never;
    };
```

Core functions accept one branch of this union. Target identity, session,
authority, and lifecycle fields remain required within their branch.

### The server selects an exact continuity anchor

The ceremony binds to one existing active auth method and its active custody
envelope. That anchor pins the wallet, current authority, envelope revision,
custody binding, and signer manifest. It does not authorize recovery and is not
revoked by recovery.

Selection is server-owned and deterministic:

1. consider active methods with an exact active wallet-custody-seed envelope;
2. prefer a method on the canonical `wallet_registration` authority;
3. prefer the same family as the selected recovery target;
4. break any remaining tie by creation time and method ID; and
5. persist the selected method, authority, envelope locator, envelope revision,
   authority digest, and update timestamps in the recovery attempt.

The user never chooses this anchor. Finalization re-reads and verifies it. A
changed or revoked anchor causes a retryable conflict before code consumption.

```ts
type WalletRecoveryContinuityAnchorV1 =
  | {
      readonly kind: 'passkey_anchor';
      readonly method: ActivePasskeyWalletAuthMethodRecordV2;
      readonly envelope: ActivePasskeyCustodyEnvelopeLocatorV1;
    }
  | {
      readonly kind: 'email_otp_anchor';
      readonly method: ActiveEmailOtpWalletAuthMethodRecordV2;
      readonly envelope: ActiveEmailOtpCustodyEnvelopeLocatorV1;
    };
```

### Recovery creates a fresh device authority

Recovery creates a new authority for the recovering device, similar to device
linking. The authority owns exactly one new target method and fresh
authority-bound signer activations. Existing public signer identities remain
unchanged.

Add an explicit authority provenance branch:

```ts
type WalletAuthorityProvenanceV1 =
  | WalletRegistrationAuthorityProvenanceV1
  | DeviceLinkAuthorityProvenanceV1
  | {
      readonly kind: 'wallet_recovery';
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly continuityAuthorityId: WalletAuthorityId;
    };
```

The new authority receives a fresh device ID, authority ID, target method ID,
activation identities, and local installation state. It reuses the wallet's
administered signer identities and custody seed.

### Existing access remains unchanged

A successful recovery performs no revocation:

- old Passkeys remain active;
- old Email OTP methods remain active;
- old custody envelopes remain active;
- linked-device authorities remain active; and
- existing Wallet Sessions remain governed by their normal expiry and budget.

Revocation stays an explicit owner operation after recovery.

### Recovery creates no Wallet Session

Finalization installs the recovered-device authority and target method. The
user then signs in through the normal target path. Only normal login mints the
fresh exact-method Wallet Session.

## User Flow

```text
enter recovery code
  -> choose Passkey or Google SSO / Email OTP
  -> reserve code and prepare a fresh recovery authority
  -> create and prove the selected target factor
  -> reconstruct and verify wallet custody
  -> install the new authority atomically
  -> sign in with the new method
```

### Passkey target

1. The user enters a recovery code and selects **Recover with Passkey**.
2. Prepare resolves the wallet, chooses the continuity anchor, reserves the
   code, allocates the recovery authority, and returns Passkey registration
   options.
3. Successful preparation continues directly into
   `navigator.credentials.create()`. The **Create new passkey** state remains
   available as the retry surface when creation is cancelled or uncertain.
   Phase 5 must prove this async continuation is admitted by every supported
   browser; otherwise this state becomes the required post-prepare action.
4. The client reconstructs the custody seed, verifies the complete key
   manifest, provisions the recovery authority, and seals a method-bound
   Passkey envelope.
5. Finalization installs the new authority, method, activations, authenticator,
   binding, and envelope atomically.
6. The user signs in through the normal Passkey flow.

### Google SSO / Email OTP target

1. The user enters a recovery code and selects **Recover with Google**.
2. Prepare resolves the wallet, chooses the continuity anchor, reserves the
   code, and allocates the recovery authority.
3. Successful preparation immediately opens the Google action. The
   **Continue with Google** state remains available as the retry surface when
   the popup cannot start or is cancelled. The server verifies the resulting
   credential and binds provider subject and normalized email identity to the
   recovery attempt. Phase 5 must prove the configured broker works after the
   async iframe-to-host continuation. A broker that requires transient user
   activation uses **Continue with Google** as the required post-prepare action.
4. The server sends an Email OTP. The user submits it through the existing
   first-party prompt.
5. OTP verification yields the target factor material required to seal the
   method-bound Email custody envelope. Google identity alone cannot finalize.
6. The client reconstructs the custody seed, verifies the complete key
   manifest, provisions the recovery authority, and seals its target envelope.
7. Finalization installs the new authority, method, activations, enrollment
   reference, and envelope atomically.
8. The user signs in through the normal Google SSO and Email OTP flow.

## Recovery Domain Model

Use one durable discriminated union:

```ts
type WalletRecoveryAttemptV2 =
  | WalletRecoveryPasskeyAttemptV2
  | WalletRecoveryGoogleEmailOtpAttemptV2;

type WalletRecoveryAttemptCommonV2 = {
  readonly version: 'wallet_recovery_attempt_v2';
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetDeviceId: DeviceId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly continuityAnchor: WalletRecoveryContinuityAnchorV1;
  readonly recoverySetVersion: WalletRecoverySetVersion;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};
```

The Passkey branch requires RP, origin, WebAuthn challenge, and target
credential facts. The Google/Email branch requires verified provider identity,
OTP state, and exact enrollment/factor-release identity. Each branch rejects
the other branch's fields with `never`.

Raw route bodies, Google responses, OTP responses, D1 rows, worker responses,
and UI choices are parsed once at their boundaries.

## Prepare Boundary

Replace R114's source-Passkey request with:

```ts
type WalletRecoveryPrepareRequestV2 = {
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly target: WalletRecoveryTargetV1;
};
```

Prepare performs these steps:

1. Validate request shape, origin, and target-specific application policy.
2. Decode the code once and derive its locator.
3. Resolve the tenant-scoped wallet and authoritative recovery set.
4. Verify the wallet-bound recovery-key ID and active wrap.
5. Select and validate the exact continuity anchor.
6. Resolve the administered signer manifest from durable wallet state.
7. Allocate fresh recovery operation, device, authority, method, and activation
   identities.
8. Reserve the recovery code.
9. Persist the target-specific attempt and return its narrow response.

Prepare never reads a selected Wallet Session or asks the client to supply the
wallet, source method, source authority, or source envelope.

## Target-Specific Preparation

### Passkey

Reuse R114's WebAuthn registration options and registration verification. The
challenge binds the fresh recovery authority and method instead of a source
credential replacement.

Remove R114's Passkey-only source fields:

- `sourceWalletAuthMethodId`;
- `sourceCredentialIdB64u`;
- `sourceAuthorityDigestB64u`; and
- `sourceAuthMethodUpdatedAtMs`.

The persisted continuity-anchor union replaces them.

### Google SSO / Email OTP

Reuse the existing Google credential verifier, Email OTP delivery service,
challenge digest, provider-subject binding, factor release, and method-bound
envelope builders.

Google and OTP routes require the recovery operation and reservation identity.
They reject wrong-wallet, wrong-target, expired, replayed, and finalized
attempts before factor release. The client cannot select the provider subject
or email hash.

## Custody and Signer Continuity

Both target branches open the wallet-scoped recovery set and reconstruct the
same wallet custody seed. Before finalization the recovery ceremony verifies:

- the continuity anchor still identifies the exact active method and envelope;
- Ed25519 recovery reproduces the registered Ed25519 public identity;
- ECDSA recovery reproduces the registered ECDSA public identity;
- every activation and possession proof names the current key manifest; and
- no lane-holder share enters the recovery set.

Provision fresh recovery-authority activations through the established R103E
activation services. Public keys, accounts, addresses, signing roots, chain
targets, and administered wallet key IDs remain unchanged.

### Signer activation refs are asymmetric by family

The recovery authority's `WalletSignerActivationSetV1` needs one
`MpcMaterialActivationRef` per key family, and the two families already differ:

- **Ed25519 mints a fresh ref per recovery.** The Yao capability admitted for a
  recovery carries `capabilityKind: 'recovery'` and a `scope.lifecycle_id`
  derived from the reservation. The recovery authority takes that fresh ref.
- **ECDSA mints nothing, and must not start.** Recovery verifies that the
  wallet's ECDSA signer rows are unchanged and that no activation is pending,
  then admits a possession proof over material the seed reproduces. The
  recovering device's ECDSA capability is local ready state.

So the recovery authority **reuses the wallet's registered ECDSA material
activation ref**. The seed reproduces the same material; nothing is re-shared
and no root rotates, so a second ref would name a fact that did not happen.

This does not collide with the linked-device 1:1 ref lookup: that lookup scans
linked-device installation rows only, and a recovery authority creates none.
Device linking's material reservation is likewise not reusable here — it is
built on a source-device re-share contribution, and recovery has no source
device.

## Atomic Server Commit

Replace Passkey replacement promotion with an additive target union:

```ts
type WalletRecoveryAuthorityInstallCommitV2 =
  | WalletRecoveryPasskeyAuthorityInstallCommitV2
  | WalletRecoveryGoogleEmailOtpAuthorityInstallCommitV2;
```

Every successful branch atomically:

- consumes the reserved recovery-code wrap;
- retains the consumed code locator as a non-secret tombstone;
- inserts the fresh active recovery authority;
- inserts the fresh target auth method;
- inserts the method-bound target custody envelope;
- inserts the authority's signer activation records and receipts;
- inserts the Passkey authenticator/binding or Email enrollment reference;
- deletes target challenges and the durable recovery attempt; and
- returns the exact committed authority, method, and activation identities.

Extend the landed recovery-finalize committed projection rather than creating a
parallel loose-ID response. The server reads the committed active recovery
authority and target method after promotion/replay; the owning commit/replay
path separately verifies the target envelope, activation set, and Email
enrollment where applicable. The client boundary parser proves the returned
wallet, authority, method, factor, and lifecycle relationships before any local
write.

The transaction does not update or delete existing auth methods, authorities,
envelopes, sessions, authenticators, or linked-device records.

Replay succeeds only when readback proves the same recovery authority, method,
factor, activations, envelope, consumed-code locator, and deleted challenges. A
wallet-wide active method never proves replay success.

## Client and Hosted UI

The hosted recovery entry renders:

- one recovery-code field;
- **Recover with Passkey**; and
- **Recover with Google**.

Both actions are available with empty IndexedDB. Existing local wallet state
does not control recovery visibility or target choice.

The hosted state is a lifecycle union:

```ts
type HostedRecoveryStateV2 =
  | { readonly kind: 'entry'; readonly code: string }
  | { readonly kind: 'preparing'; readonly target: WalletRecoveryTargetV1 }
  | { readonly kind: 'passkey_ready'; readonly operation: PasskeyRecoveryHandle }
  | { readonly kind: 'google_ready'; readonly operation: GoogleRecoveryHandle }
  | { readonly kind: 'email_code_required'; readonly operation: EmailOtpRecoveryHandle }
  | { readonly kind: 'finalizing'; readonly operation: RecoveryFinalizationHandle }
  | { readonly kind: 'sign_in_ready'; readonly continuation: RecoveryLoginContinuation }
  | { readonly kind: 'refused' };
```

Back, Escape, popup cancellation, OTP cancellation, and iframe disposal abort
the operation and zeroize code, seed, factor, and worker material. The hosted UI
receives handles, masked email display data, and generic errors. It never
receives custody material, provider subjects, or server diagnostics.

After finalization, the landed IndexedDB transaction receives the fresh
authority, target method, and exact locked selection. Profile/authenticator,
legacy local method projection, account, and signer continuity currently publish
through subsequent writes. The page remains locked until those writes complete
and normal target login succeeds. Phase 4 still has to make that post-promotion
publication resumable across reload and give every fail-closed local
prerequisite one terminal publish boundary.

## Security Invariants

1. One active recovery code authorizes one additive recovery attempt.
2. Existing auth-method count and family never gate recovery admission.
3. The recovery code is the sole recovery authorization.
4. The selected target family is immutable after reservation.
5. The continuity anchor is server-selected, exact, active, and unchanged at
   finalization.
6. The continuity anchor is never revoked or rewritten by recovery.
7. Recovery creates a fresh device authority and one fresh target method.
8. Google identity is server-verified and bound to the exact attempt.
9. Email OTP verification precedes Email factor release.
10. The client cannot supply the resolved wallet, anchor, authority, method ID,
    email hash, provider subject, or signer manifest.
11. Complete key-manifest verification precedes promotion.
12. The new envelope is method-bound to the prepared target method.
13. Existing methods, envelopes, authorities, linked devices, and Wallet
    Sessions remain unchanged.
14. Code consumption, locator deletion, recovery-authority installation,
    target installation, and challenge deletion are one transaction.
15. Precommit cancellation leaves the code reusable after release or expiry.
16. Recovery finalization creates no Wallet Session.
17. Raw codes, OTPs, Google credentials, factor secrets, custody seed, and
    signer roots never enter logs, errors, hosted outcomes, or durable
    plaintext state.
18. A committed server promotion remains resumable after page reload. Local
    wallet discovery remains hidden until authority, method, locked selection,
    profile/authenticator, account, and signer continuity are durable.
19. Passkey creation and external-auth brokering start with whatever browser
    user activation their real implementation requires. Async preparation and
    iframe-to-host messaging cannot turn a supported target into a popup-blocked
    or activation-denied dead end.

## Implementation Phases

### Phase 0 — Freeze the additive contract

- [x] Update `docs/intended-behaviours.md` to supersede R114's replacement
      policy.
- [x] Freeze the continuity-anchor selection rule.
- [x] Freeze the additive successor to the landed authority/method committed
      projection. Require server readback of authority, method, envelope, and
      activations; reject loose client-supplied identity fragments.
- [x] Add `wallet_recovery` authority provenance and its static type fixtures.
- [x] Define exact Passkey and Google/Email target branches.
- [x] Rewrite or delete tests whose invariant is the retired single-Passkey
      gate or source revocation.

The retirement worklist, resolved against the landed R114 code:

| Surface                                                                               | Action                                                        |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `tests/unit/walletRecoverySourceSelection.unit.test.ts`                               | Rewrite for exact continuity-anchor ranking.                  |
| `assertSourceWalletSessionRevoked()` in `tests/e2e/intended-behaviours/harness.ts`    | Delete, with its call in `passkey.recovery.contract.test.ts`. |
| `tests/unit/walletRecoveryFinalization.unit.test.ts`                                  | Rewrite the source-replacement guards as additive readback.   |
| `docs/intended-behaviours.md` — the Account Recovery sections and their coverage rows | Supersede the replacement policy.                             |

### Phase 1 — Wallet-scoped preparation

- [x] Remove method cardinality and Passkey-family admission from prepare.
- [x] Select and persist an exact Passkey or Email continuity anchor.
- [x] Allocate fresh recovery device, authority, method, and activation IDs.
- [x] Persist `WalletRecoveryAttemptV2` with an immutable target branch.
- [x] Keep generic refusal for malformed and unknown codes, report an exact
      consumed-code locator as already used, and preserve secret zeroization at
      the request boundary.

### Phase 1.5 — The fresh recovery authority

Both target branches install the same authority, and no existing flow builds
one for a device that reconstructs its own material, so this lands once before
either target moves.

- [x] Add the `wallet_recovery` provenance branch to `WalletAuthorityV1` and its
      encoder, parser, and validator.
- [x] Write the forward migration that admits the new provenance kind, and
      update the authority store's inline schema in the same change.
- [x] Build the recovery-authority builder: fresh device and authority IDs, the
      Ed25519 recovery-scoped activation ref, and the wallet's registered ECDSA
      ref, per the asymmetry above.
- [x] Prove the fresh device ID satisfies the one-active-authority-per-device
      uniqueness index.

### Phase 2 — Additive Passkey recovery

- [x] Move R114 WebAuthn data into the Passkey target branch.
- [x] Remove source-Passkey replacement fields and validation.
- [x] Seal and verify the new method-bound Passkey envelope.
- [x] Install the fresh authority, activations, Passkey method, authenticator,
      binding, and envelope atomically.
- [x] Rewrite replay around exact additive readback.

### Phase 3 — Additive Google SSO / Email OTP recovery

- [x] Add recovery-scoped Google verification using the existing verifier.
- [x] Issue and verify an exact recovery-scoped Email OTP challenge.
- [x] Reuse factor release and method-bound Email envelope sealing.
- [x] Install the fresh authority, activations, Email method, enrollment
      reference, and envelope atomically.
- [x] Keep Google/OTP failure separate from recovery-code consumption.

### Phase 4 — Client, worker, and local installation

- [x] Add target actions and target-specific hosted lifecycle states.
- [x] Make the explicit target action begin preparation and continue
      immediately into Passkey creation or Google verification. Keep the
      target-ready states as retry surfaces for cancellation and uncertainty.
- [ ] Validate the automatic continuation with real WebAuthn and the configured
      external-auth broker in every supported browser. The current focused unit
      uses an in-process broker and cannot prove popup or transient-activation
      behavior. If either target requires a fresh activation, make its
      target-ready CTA the required post-prepare action.
- [x] Extend the coordinator with exact target branches.
- [x] Reconstruct and verify custody once, then provision the new authority.
- [x] Extend `persistRecoveredWalletAuthority` and the strict finalize parser;
      do not synthesize authority or method state from prepared client inputs.
- [x] Install the exact IndexedDB authority, method, and locked selection in one
      transaction.
- [x] Continue through normal Passkey or Google/Email login.
- [ ] Persist a redacted, non-discoverable post-promotion resume record before
      the in-memory operation can be lost. Resume the same committed recovery
      operation after reload without consuming another code.
- [ ] Publish the wallet only after every fail-closed login prerequisite is
      durable, and delete the resume record only after normal-login
      continuation can be reconstructed.

### Phase 5 — Operating acceptance

- [x] Run the complete 2x2 contract from fresh browser storage: Passkey-only
      and Email-only origins through both Passkey and Google/Email targets.
- [ ] Run both recovery targets against a combined Passkey + Email inventory.
- [ ] Prove reload remains locked before normal login, including interruption
      immediately after server promotion and at every local publication
      boundary.
- [x] Prove NEAR, Tempo, and Arc/EVM signing after login.
- [ ] Prove step-up and Ed25519/ECDSA export under the recovered method.
- [ ] Prove every pre-existing method and linked device still operates.
- [x] Prove both targets reject a consumed code and report that it has already
      been used.
- [ ] Prove cancellation, conflict, and replay behavior under both targets.
- [x] Prove successful preparation automatically enters the selected target,
      target failures expose a retry state, and irreversible finalization
      ignores Back/Close cancellation.
- [x] Prove a pre-commit Passkey finalization failure retains the admitted
      operation, and a lost successful Google finalization response replays the
      committed result without consuming another code.
- [x] Align `driveHostedPasskeyRecovery` with automatic Passkey continuation.
      The harness now waits for continuation and clicks **Retry finalization**
      only after an injected retryable finalization failure. The four matrix
      cases, the failed-finalization retry, and the Google post-commit replay
      contract pass locally.

### Phase 6 — Cleanup

- [x] Delete R114 source-method replacement fields and commit branches.
- [ ] Delete duplicate target sealing, Google verification, and OTP helpers.
- [x] Delete or rewrite stale replacement and single-method fixtures and source
      guards.
- [ ] Repair `walletRecoverySourceSelection.unit.test.ts` through the current
      active-authority fixture builder. Classification:
      `valid_test_needs_update`; three cases still construct the retired flat
      `provenanceKind` selection even though production and the exported input
      type now require `authority.provenance.kind`. Do not weaken the production
      continuity-anchor comparator.
- [x] Mark R114's replacement policy as superseded by R115.
- [ ] Record exact commits and acceptance evidence in this ledger.

## Acceptance Matrix

**Matrix scaling rule:** recovery coverage is the Cartesian product of the
existing continuity-anchor auth-method family and the newly recovered
auth-method family. With Passkey and Google/Email, the suite must cover 2x2.
Adding a third family requires 3x3; adding a fourth requires 4x4. Every new
family must work as both the existing continuity anchor and the recovery
target. The wallet-inventory variants below are applied on top of that complete
family matrix.

| Existing wallet inventory | Recover with Passkey                              | Recover with Google / Email OTP                 |
| ------------------------- | ------------------------------------------------- | ----------------------------------------------- |
| Passkey only              | Add fresh Passkey authority                       | Add fresh Email authority                       |
| Email only                | Add fresh Passkey authority                       | Add fresh Email authority                       |
| Passkey + Email           | Add fresh Passkey authority                       | Add fresh Email authority                       |

Each target's intended-browser contract proves:

1. fresh storage contains no remembered wallet;
2. code-only lookup resolves the correct wallet;
3. the selected target creates one fresh recovery authority and method;
4. the exact existing method and envelope are pinned as continuity anchor;
5. every public signer identity is preserved;
6. the page stays locked until normal target login;
7. reload restores the recovered method from IndexedDB;
8. NEAR, Tempo, and Arc/EVM transactions sign;
9. step-up and Ed25519/ECDSA export work;
10. all existing methods, sessions, and linked devices still work; and
11. a consumed code cannot authorize recovery and is reported as already used.

Use one focused Passkey contract and one Google/Email contract with inventory
variants as data. Focused D1 tests own atomicity and replay edge cases.

## Failure Classification

- Consumed code: `consumed` with the already-used message.
- Malformed, unknown, revoked, or mismatched code: `refused` with the generic
  message.
- No exact active continuity anchor or contradictory custody state: `refused`
  without inventory details.
- Anchor or manifest changes after prepare: `retryable_conflict`.
- Wrong Google identity, wrong or expired OTP, or target mismatch: fail target
  verification before factor release.
- User cancellation before finalization: release or expire the reservation and
  zeroize client material.
- Transport uncertainty during finalization: retain the redacted operation and
  replay the exact additive commit.
- Corrupt replay readback: `conflict`; never infer success.

## Expected File Areas

- `packages/shared-ts/src/wallet-recovery/`
- wallet-authority provenance types and type fixtures
- `packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody.ts`
- `packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/`
- `packages/wallet-server/src/router/cloudflare/d1/webauthn/`
- `packages/wallet-server/src/router/domains/passkeyCustody/`
- existing Google/Email OTP routes and services
- `packages/wallet/src/SeamsWeb/operations/recovery/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/`
- existing custody workers and IndexedDB repositories
- `tests/unit/` and `tests/e2e/intended-behaviours/`

If a phase creates a second Google verifier, OTP issuer, custody ceremony,
authority store, or signer activation path, stop and reuse the established
boundary.

### Landed R115 code map

- `d1PasskeyCustodyRouteService.ts` selects a target-independent exact
  continuity anchor through `selectWalletRecoveryContinuityAnchor`.
- `walletRecoveryFinalization.ts` and the wallet-custody commit store install a
  fresh recovery authority, target method, envelope, and activations. Their
  replay guards require the continuity anchor to remain unchanged.
- `d1PasskeyCustodyRouteService.ts` and the Google/Email recovery service read
  the committed active authority and target method after promotion/replay. The
  Passkey and Google/Email client parsers strictly validate those projections.
- `persistRecoveredWalletAuthority` installs the fresh exact authority state.
  The coordinator still owns a separate in-memory
  `promoted_pending_continuity` stage, which is the reload gap tracked in Phase
  4.
- Device linking's signer-material reservation is not a reuse candidate. It is
  built on a source-device re-share contribution, and recovery has no source
  device. Registration's founding-authority builder is the closer model.

## Persistence and Deployment

R115 landed two forward D1 migrations. Applied migrations remain byte-for-byte
unchanged:

- `0026_r115_wallet_recovery_authority_provenance.sql` rebuilds
  `wallet_authorities`, adds recovery provenance, recreates its indexes, and
  recreates the exact Wallet Session authorized-operation trigger; and
- `0027_r115_email_otp_recovery_bootstrap.sql` admits the recovery-bound Email
  OTP challenge purpose.

Three details govern the landed authority migration:

- **The constraint has two copies.** `provenance_kind IN ('wallet_registration',
'device_link')` is written both in the applied authority-baseline migration
  and in the authority store's inline `CREATE TABLE IF NOT EXISTS`. A migration
  that updates only the first leaves every freshly provisioned local and test
  database rejecting the new provenance. Change both in one commit.
- **SQLite cannot alter a `CHECK`.** The migration rebuilds `wallet_authorities`
  — create the successor table, copy, drop, rename — and recreates all three of
  its indexes, including the partial unique index on active device.
- **The paired `CHECK` moves with it.** The provenance kind and the
  enrollment/source-authority/link-session null rules are one constraint;
  `wallet_recovery` needs its own arm naming the recovery operation and
  continuity authority.

Three existing constraints already admit the additive shape, and none needs
changing:

- `wallet_auth_methods` carries a foreign key to `wallet_authorities`, so a
  fresh authority plus a fresh method is legal as long as the authority row is
  written first in the same transaction.
- The active-Email uniqueness index is scoped per authority, so a Google/Email
  recovery method does not collide with an existing Email method for the same
  address on another authority.
- The active-authority uniqueness index is per device, which is what makes the
  fresh device ID load-bearing rather than cosmetic.

The V2 durable recovery attempt uses existing versioned JSON/challenge storage.
R114 attempts were short-lived; the old decoder and source-replacement commit
path have been removed. Future migrations, including R103F, allocate after
`0027` and must preserve the recovery provenance columns and recreate any
dependent trigger they intentionally replace.

## Definition of Done

R115 is complete when:

- valid recovery codes prepare independently of existing method count/family;
- the user can recover with Passkey or Google SSO with Email OTP;
- recovery binds to an exact existing method and custody envelope;
- recovery creates a fresh authority and method without revoking anything;
- both targets preserve public wallet and signer identities;
- a post-promotion reload resumes the same redacted operation and keeps the
  wallet hidden until local continuity is complete;
- normal target login restores signing, step-up, export, and reload;
- obsolete R114 replacement logic and tests are deleted; and
- both intended-browser target contracts pass from clean storage.

## Non-Goals

- Selecting or authenticating an old method during recovery.
- Revoking any existing method, device, authority, envelope, or Wallet Session.
- Supporting identity providers other than Google.
- Help-desk, administrator, SMS, password, seed-phrase, or social recovery.
- Rotating public keys, accounts, addresses, signing roots, or chain targets.
- Minting a Wallet Session during recovery finalization.
- Permanent compatibility for R114's short-lived challenge shape.
