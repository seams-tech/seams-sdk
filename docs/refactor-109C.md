# Refactor 109C — Add the Missing Wallet Auth Method

Date created: August 22, 2026

Status: implementation-ready. Depends on Refactor 103E.

R109C is the sole implementation authority for same-device auth-method
addition. Refactor 109D remains the separate device-linking plan.

## Live implementation ledger

Implementation branch `codex/refactor-109c`, based on `dev` at `ff395dfe1`.
R103E's closure edit was already committed on `dev` in `ff395dfe1`, so this
branch adds no separate documentation commit for it.

A checkpoint is marked done only when the named command was run and reported
green. Green lower-tier evidence does not close a product transition; only a
real browser flow does.

### Phase 0 — revocation prerequisite

- [x] Exact method revocation runs through the composed D1 path and protects
      the wallet's final active method. Command:
      `npx playwright test -c playwright.unit.config.ts ./unit/linkedDeviceManagement.unit.test.ts ./unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts ./unit/d1WalletAuthorityStore.unit.test.ts`
      from `tests/`, 11 passed. The green cases are: revokes one authority
      method and protects the final active wallet method; rolls back method
      revocation when an atomic session fence fails; serializes competing
      revocations of the final two wallet methods; add-auth commit rejects a
      source method revoked after ceremony start; rejects a `WalletAuthorityId`
      in the exact-method revocation boundary; rejects a fresh proof from the
      target auth method itself; revokes one exact linked auth method, fences
      sessions, and disables its ordinary refs; replays a durable revocation
      and retries terminal material deactivation.
- [x] Authority-ID and self-proof revocation requests are rejected — the first
      two cases above own exactly that boundary.
- [x] Real-browser owner-UI revocation with the exact method, revoked-session
      rejection at signing, revoked-method unlock rejection, and the surviving
      owner operation are recorded green in `docs/refactor-103E.md`'s
      verification ledger and are not re-run here.

Four tests in `tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts`
fail on `dev` before any R109C change, with `Passkey wallet authority is not
active for this wallet`, `Missing ownerProofBindingDigest`, `Missing
webauthn_authentication.id/rawId`, and `the verified passkey has no active
wallet custody envelope`. All four are inline hand-written setup fixtures that
predate R103E's authority, owner-proof-binding, and custody-envelope
requirements — the lowest-authority tier in `AGENTS.md`. They are recorded here
as the Phase 4 fixture worklist rather than repaired now, because repairing
them before either product transition works is exactly the stale-fixture loop
the plan forbids.

`tests/scripts/check-auth-method-domain-boundaries.mjs` also fails on `dev`
before any R109C change: five source files carry unallowlisted binary auth
fallbacks and one allowlist entry is stale. R109C adds no new occurrence; the
guard's disposition is Phase 4 work.

### Phase 1 — shared contract and thin SDK entry points

- [x] Two-branch internal contract with branded identities, branch builders,
      admission, and negative type fixtures:
      `packages/shared-ts/src/utils/addWalletAuthMethod.ts` and its
      `.typecheck.ts`. Command: `npx tsc --noEmit` in `packages/shared-ts`,
      clean.

The plan named `tests/typecheck/` for the negative fixtures. That directory is
covered by no `tsconfig` in the repo, so nothing compiles it; the fixtures live
beside the contract in `packages/shared-ts/src/utils/`, which
`packages/wallet/tsconfig.json` does include and `pnpm type-check:sdk`
therefore enforces.

## Goal

Give an authenticated user one **Add authentication method** product action:

```text
Passkey present, Email OTP absent
  -> add Email OTP
  -> Passkey and Email OTP both active

Email OTP present, Passkey absent
  -> add Passkey
  -> Email OTP and Passkey both active
```

The operation fills the missing factor family on the selected installed wallet
authority. It creates one `WalletAuthMethodRecordV2` and preserves the existing
authority, device, permissions, signer activations, shares, public keys, export
material, key manifest, revocation epoch, and selected Wallet Session.

## Product contract

The settings inventory derives the available action from exact active methods
on the selected authority:

| Current factor families | Available action | Result |
| --- | --- | --- |
| Passkey only | **Add email code** | Passkey and Email OTP |
| Email OTP only | **Add passkey** | Email OTP and Passkey |
| Passkey and Email OTP | no add action | `already_configured` from the API |

An authority may already contain several Passkeys. That counts as “Passkey
present.” Existing methods remain valid; R109C never creates another method
from a family already present on the authority.

Email OTP remains limited to one active method per authority across Email OTP
providers. Revoked Email OTP history does not consume the active slot.

## Required prerequisite: exact method revocation

Do not expose either addition flow until ordinary auth-method revocation works
through the real composed path.

The prerequisite behavior is:

1. every user request targets one exact `WalletAuthMethodId`;
2. fresh proof comes from a different active local method for the same wallet;
3. revoking a method invalidates that method, its verifier, its sealed local
   records, and sessions issued through it;
4. the sibling method, shared authority, signer activations, and sibling
   sessions remain active;
5. the transaction refuses to revoke the wallet's final active method;
6. no user-facing operation targets `WalletAuthorityId` or revokes several
   methods at once.

After either R109C addition succeeds, the source method must be able to revoke
the new method, and the new method must be able to revoke the source method.
Both directions use fresh proof from the sibling method. The final-method guard
must remain atomic under competing revocation requests.

Refactor 103E owns this revocation contract. R109C verifies it as a prerequisite
and does not add another revocation model.

## Email OTP security boundary

Adding Email OTP reduces the assurance of a Passkey-only installation because
the email inbox becomes an independent way to unlock it. Show this short note
in the Email OTP addition UI:

> **Security note:** Adding email code lowers this wallet's security because
> your inbox becomes another way to unlock it.

The note is informational. It adds no confirmation step or separate Passkey
authorization ceremony. The shared add-auth-method operation shows the note,
then requires a fresh Passkey assertion for the exact intent immediately before
creating the Email OTP challenge. The assertion is bound to the exact wallet,
authority, source method, source session, target method ID, operation purpose,
authority state, and intent digest. A cancelled or failed attempt removes its
intent, challenge, verification receipt, and pending local method.

## Decisions

1. One internal add-auth-method operation has two exhaustive branches:
   `passkey_to_email_otp` and `email_otp_to_passkey`.
2. Keep two thin typed SDK entry points:
   `registration.addPasskey` and `registration.addEmailOtp`. Both call the same
   internal operation and own no persistence, retry, session, or activation
   logic.
3. The product UI presents one **Add authentication method** action and chooses
   the branch from exact active inventory.
4. The active Wallet Session names the exact source method. The server resolves
   its wallet, authority, device, authority digest, and revocation epoch.
5. The source supplies a fresh operation-specific proof. The target factor is
   verified independently; the source proof cannot serve as target
   verification.
6. The target family must be absent before target verification starts. The
   activation transaction repeats the check to close races.
7. Factor addition is a local reseal. The custody worker opens the source
   method's authenticated envelope and seals the same custody seed and existing
   local signer/export access under the target factor. JavaScript receives no
   custody seed or unsealed signer material.
8. The new method reuses the exact `WalletAuthorityId` and `DeviceId`. It
   creates no authority, signer activation, share, public key, export root, or
   key manifest.
9. The source method and Wallet Session remain selected after addition. The
   new method is used only after explicit selection or lock and unlock.
10. Reuse the existing add-auth-method intent, routes, custody worker, stores,
    and Wallet Session model. Add no aggregate, projection, or workflow
    framework.
11. Parse raw request, factor, and persistence input once at its boundary. Core
    code receives branded identities and one verified branch.

## Out of scope

- adding another Passkey when Passkey is already present;
- adding another Email OTP method when Email OTP is already present;
- replacing an existing factor identity;
- adding a factor on another device;
- changing the Refactor 103E revocation contract;
- changing permissions or signer families;
- deriving, rotating, repairing, or re-establishing signer material;
- transferring custody seed or signer material between devices;
- custom factor-management permissions;
- enterprise SSO;
- a generic ceremony, migration, or projection framework.

## Current gap

The codebase already provides generic intent routes,
`WalletAuthMethodRecordV2`, D1 and IndexedDB stores, the Passkey custody-link
path, and `registration.addPasskey`. The missing operating behavior is narrow:

- `registration.addPasskey` rejects an Email OTP source proof;
- `registration.addEmailOtp` does not exist for an established wallet;
- unlock and settings do not deliberately expose both exact methods on one
  authority;
- route and service branches still assume matching source and target families.

R109C keeps `registration.addPasskey`, adds `registration.addEmailOtp`, and
makes both thin adapters over one internal operation.

## Domain model

```text
WalletAuthorityV1
  authorityId
  deviceId
  permissions
  exact signer activations
       ^
       |
       +-- WalletAuthMethodRecordV2: Passkey
       +-- WalletAuthMethodRecordV2: Email OTP
```

`WalletAuthorityV1` owns permissions and signer state. Each auth method owns
one factor identity, lifecycle, sealed custody envelope, sealed access to local
material, and sessions issued through that method. The presence of both active
branches is the combined state; no combined-auth record is persisted.

## Public and core contracts

Keep branch-specific SDK inputs:

```ts
registration.addPasskey(args: {
  readonly walletId: WalletId | string;
  readonly rpId: string;
  readonly options?: AddPasskeyHooksOptions;
}): Promise<AddWalletAuthMethodResultV1>;

registration.addEmailOtp(args: {
  readonly walletId: WalletId | string;
  readonly emailAddress: string;
  readonly options?: AddEmailOtpHooksOptions;
}): Promise<AddWalletAuthMethodResultV1>;
```

The selected Wallet Session supplies the source method and authority. Callers
do not construct a broad authorization object. The server supplies the target
`WalletAuthMethodId`, scope, intent nonce, authority snapshot, challenge, and
expiry.

After verification, core code accepts only:

- verified Passkey source plus verified new Email OTP target;
- verified Email OTP source plus verified new Passkey target.

Use existing verified proof values when they carry the required guarantees.
Use branch-specific builders and exhaustive switches. Type fixtures reject
same-family additions, mixed target fields, unverified input, ID mismatches,
broad spreads, and unsafe casts.

Both SDK entry points return the same result union with `active`,
`already_configured`, `cancelled`, `expired`, `unauthorized`,
`target_verification_failed`, and `integrity_error` branches. Reuse existing
failure reason unions. UI control flow switches on the result discriminant;
messages and diagnostics remain display data.

## One linear operation

1. Load the active Wallet Session, exact source method, and active authority.
   Require current digest and epoch, complete local installation, exact
   `FULL_OWNER_PERMISSIONS`, and an absent target family.
2. For Passkey-to-Email-OTP, show the short security note in the addition UI.
   Obtain the source authorization required by the shared operation. For
   Email-OTP-to-Passkey, obtain one fresh Email OTP owner grant.
3. Reuse the existing intent route. Bind one server-allocated target method ID
   to the wallet, authority, device, source method, source session, target
   family, authority snapshot, nonce, and expiry.
4. Verify the target factor:

   | Source | Target | User actions |
   | --- | --- | --- |
   | Passkey | Email OTP | security note, source assertion, target email code |
   | Email OTP | Passkey | source email code, target credential creation |

5. In the custody worker, reseal the same custody seed and every existing local
   signer/export access record under the verified target factor.
6. Write the pending target method, sealed records, and installation receipt in
   one IndexedDB transaction. Pending material cannot unlock, sign, export,
   step up, or issue a Wallet Session.
7. Revalidate the source, target, authority snapshot, missing-family invariant,
   intent, and receipt. One D1 transaction inserts the active method and factor
   verifier, consumes the target grant, writes the audit event, and completes
   the intent. It changes no authority or signer record.
8. Replace the pending local method with the exact active server record in one
   IndexedDB transaction. Retain sealed material, delete temporary state, and
   keep the source method selected.

Initial admission returns `already_configured` before target verification when
the target family is present. Activation uses a conditional insert that
succeeds only while the target family remains absent. This closes concurrent
addition races while preserving previously stored multi-Passkey inventories.

Retries reuse the same intent and target method ID. An exact retry returns the
same active method. Cancellation and expiry before activation remove temporary
challenges, source proofs, and matching pending local state.

## Persistence, unlock, and revocation

Reuse `wallet_auth_methods` and its canonical V2 parser. Keep active Passkey
credential uniqueness. Keep one active Email OTP method per
`(scope, wallet_authority_id)` across Email OTP providers. Add no table for the
derived two-family state.

IndexedDB addresses sealed records by the exact wallet, authority, auth method,
and activation or root identity required by the store. A method is locally
usable only when its complete exact record set is present.

Unlock begins with explicit method selection:

```text
selected WalletAuthMethodId
  -> exact active auth method
  -> exact active authority
  -> verify selected factor
  -> open that method's sealed local records
  -> issue an ordinary Wallet Session
```

Both methods resolve the same authority and signer activations. Each issues its
own Wallet Session. Step-up verifies the session's exact method. Lock remains
durable across refresh, and unlock never infers a method from factor kind,
email hint, recent use, display label, or record order.

Revocation continues through the exact Refactor 103E method-level operation.
The addition UI must expose removal for each method once the sibling is active.
Removing either method leaves the sibling usable; removing the final wallet
method is refused.

## Implementation phases

### Phase 0 — Prove the revocation prerequisite

- run exact method revocation through the composed server and IndexedDB path;
- prove each method can revoke its sibling with fresh proof;
- prove the final wallet method cannot be revoked;
- prove authority-ID and batch revocation requests are rejected;
- block R109C product exposure until these checks pass.

### Phase 1 — Shared internal contract and thin SDK entry points

- add the two-branch verified internal input;
- retain `registration.addPasskey` and add `registration.addEmailOtp`;
- make both entry points call the same internal operation;
- make authority, source method, source session, and target method IDs required;
- add boundary parsers, branch builders, exhaustive switches, and type fixtures;
- reject a target family already present before target verification.

Primary locations:

- `packages/shared-ts/src/utils/registrationIntent.ts`
- `packages/shared-ts/src/utils/addAuthMethodRegistration.ts`
- `packages/wallet/src/SeamsWeb/publicApi/types.ts`
- `packages/wallet/src/SeamsWeb/publicApi/createPublicApi.ts`
- `tests/typecheck/`

### Phase 2 — Both cross-family paths

- implement Passkey source to Email OTP target with the short security note;
- implement Email OTP source to Passkey target through the same operation;
- route the existing Passkey custody-link code through the shared reseal and
  activation stages;
- keep the source method and session selected after both paths.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/authMethods/`
- existing custody, Passkey, and Email OTP workers
- `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts`
- existing add-auth-method routes and IndexedDB stores

### Phase 3 — Inventory, selection, and removal

- derive the missing-family action from exact active inventory;
- hide the add action once both families are active;
- require explicit method selection for unlock and step-up;
- issue sessions through the selected exact method;
- expose exact sibling-authorized removal for both methods.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`
- `packages/wallet/src/react/components/AccountMenuButton/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/`

### Phase 4 — Delete and verify

- delete the Email-OTP-source rejection and duplicated branch persistence;
- delete fixtures and mocks that assume one factor family;
- update `docs/intended-behaviours.md` and its contract tests;
- run the real operating matrix.

## Required verification

Run both transitions against Ed25519-only, ECDSA-only, and both-family wallets:

| Existing method | Added method |
| --- | --- |
| Passkey | Email OTP |
| Email OTP | Passkey |

For every cell and signer configuration:

1. prove authority, device, permissions, activation refs, digest, epoch, source
   method, and source session remain unchanged;
2. prove one target method has a fresh opaque ID and complete local records;
3. explicitly lock and unlock with each method;
4. sign through every present signer family under each method;
5. export every present family with step-up from the exact selected method;
6. reload while locked and prove neither method auto-unlocks;
7. prove the add action disappears when both families are active;
8. repeat the target request and receive `already_configured` before target
   verification or local writes;
9. revoke the new method using the source method and prove the source still
   operates;
10. add again, revoke the source using the new method, and prove the new method
    still operates;
11. refuse revocation of the remaining final method.

For Passkey-to-Email-OTP, verify that the short security note renders in the
addition UI.

Run interruption and lost-response cases once per target branch. Every retry
must converge on the same target method without increasing method or sealed
record counts. External email delivery and chain RPC may be stubbed at their
network boundaries; intent, proof, reseal, IndexedDB, D1 activation, unlock,
session, signing, export, step-up, and revocation use the real composed path.

## Completion criteria

R109C is complete when:

- Refactor 103E exact method revocation passes before addition is exposed;
- a Passkey-only authority can add Email OTP after seeing the short security
  note;
- an Email-OTP-only authority can add a Passkey;
- `registration.addPasskey` and `registration.addEmailOtp` are thin entry
  points into one exhaustive two-branch internal operation;
- both methods reference the original authority and signer activations;
- factor addition creates no authority or signer material;
- both methods can explicitly unlock, issue sessions, sign, export, step up,
  and revoke their sibling;
- the source method and session remain selected after addition;
- a target family already present returns `already_configured` before target
  verification;
- same-family addition is absent from the R109C operation;
- duplicated persistence and obsolete fixtures are deleted;
- the real two-transition browser matrix passes.
