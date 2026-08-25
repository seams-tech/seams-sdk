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

### Phase 0 — revocation prerequisite — NOT MET

This section previously carried three ticked boxes. That was wrong on the
ledger's own rule, and the boxes are withdrawn.

The cited command exits 1: it runs 15 tests, 11 pass and 4 fail, because the
file list includes `cloudflareD1RouterApiWalletAuthMethods.unit.test.ts` whose
four failures are recorded further down as a pre-existing fixture problem. A
command that reports failure does not mark a checkpoint done, whatever the
reason for the failure, and citing the passing subset as though the command
were green is exactly the move this ledger's own rule forbids.

The evidence is also the wrong shape. The eleven passing cases exercise
revocation between methods on *separate* authorities. R109C's prerequisite is
revocation between Passkey and Email OTP siblings on *one* authority, in both
proof directions — the configuration this refactor creates and the only one
that proves the sibling guard. No such test exists yet, so the prerequisite is
unproven rather than partially proven.

- [ ] Exact method revocation between two siblings on ONE authority, proven in
      both directions, through the composed path. Not yet written.
- [ ] The cited command exits 0.
- [x] Authority-ID and self-proof revocation requests are rejected at the
      boundary — `linkedDeviceManagement.unit.test.ts` covers exactly this and
      passes on its own.

Passing cases in that run, recorded as partial evidence only: revokes one
authority method and protects the final active wallet method; rolls back method
revocation when an atomic session fence fails; serializes competing revocations
of the final two wallet methods; add-auth commit rejects a source method
revoked after ceremony start; rejects a `WalletAuthorityId` in the exact-method
revocation boundary; rejects a fresh proof from the target auth method itself;
revokes one exact linked auth method, fences sessions, and disables its
ordinary refs; replays a durable revocation and retries terminal material
deactivation.

Real-browser owner-UI revocation with the exact method, revoked-session
rejection at signing, revoked-method unlock rejection, and the surviving owner
operation are recorded green in `docs/refactor-103E.md`'s verification ledger.
That evidence is about separate authorities too, so it does not close the
sibling prerequisite either.

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

### Architecture facts established before implementation

These were read directly and change the size of the remaining work. The plan's
"Current gap" section understates how much R103E already built.

- **The custody reseal is already factor-agnostic; no Rust or WASM change is
  needed.** `passkey_custody_open_wallet_seed_v1` in
  `wasm/near_signer/src/passkey_custody_wasm.rs:237` documents itself as "the
  second-factor enrolment path: a wallet with an Email OTP factor gains a
  passkey, or the reverse" — R109C's operation exactly — and
  `reseal_wallet_custody_seed_under_new_factor_v1` in
  `crates/signer-core/src/passkey_custody.rs:685` rejects only a changed wallet
  or binding, with the message "a reseal may change only the factor and the
  envelope id". The KEK and AAD are derived from the replacement factor and
  binding, so an `email_otp` replacement factor is already supported. The
  worker op is named `linkWalletCustodyPasskey`, but its payload takes an
  envelope whose factor is the full union plus an opaque replacement binding
  JSON; only the name is passkey-specific.
- **The D1 service already accepts an Email OTP source for a Passkey target.**
  `resolveAddAuthMethodExistingAuth` in
  `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts:1078`
  resolves the Email OTP authority, verifies its authority ref, and checks the
  enrollment; `resolveActiveAddAuthMethodSource` resolves the V2 method for
  that branch; and `startWalletAddAuthMethod` already handles
  `storedAuth.auth.kind === 'email_otp'` inside its Passkey-target branch. The
  refusal is one layer up: `parseWalletAddAuthMethodStartBody` admits only
  `webauthn_assertion` and `wallet_session`, and the `wallet_session` branch of
  `handleRouterApiWalletAddAuthMethodStart` requires
  `authority.factor?.kind === 'passkey'`. `email_otp_to_passkey` is therefore a
  route-boundary change, not a service rewrite.
- **The Email-OTP-owned Wallet Session already names its exact source method.**
  `EmailOtpWalletAuthAuthority.bindingId` is a `WalletAuthMethodId`
  (`packages/shared-ts/src/utils/walletAuthAuthority.ts:66`), so the route can
  supply the exact source method without inference.
- **One remaining wallet-wide Email selector sits in the addition path.** The
  add-auth-method start resolves its Email authority through
  `resolveActiveEmailOtpAuthorityForVerifiedSubject`, which requires exactly one
  active Email method for the wallet. That is the same shape as the three
  escaped defects R103E repaired. R109C must use the exact-method resolver
  `resolveActiveEmailOtpAuthorityForVerifiedMethod` that R103E already added.

### Inventory defects that block the product contract

Found while mapping Phase 3, and each one is load-bearing for "derive the
available add action from exact active methods".

- **Only the first active method per authority is projected.**
  `packages/wallet-server/src/core/deviceLinking/linkedDeviceManagement.ts:176-178`
  builds both the linked-device and owner summaries from `activeMethods[0]`, so
  an authority holding both families renders as one card and the sibling is
  invisible. `docs/intended-behaviours.md` already says inventory is derived
  from active authorities "and their exact auth methods", plural, so this is a
  defect against the accepted contract rather than a new R109C requirement.
- **`OwnerDeviceSummaryV1` carries no `walletAuthorityId`**
  (`packages/shared-ts/src/device-linking/contracts.ts:629`), so a client cannot
  scope "the methods on this authority" and cannot decide the add action
  correctly for a wallet that also has linked devices.
- **Owner methods cannot be removed.** The card's remove control is gated off
  owner cards in `LinkedDevicesModal.tsx:658`, and the server refuses any
  revoke whose target authority provenance is not `device_link`
  (`linkedDeviceManagement.ts:239`). R109C requires each method to be removable
  once its sibling is active, so both gates have to go. This widens which
  authorities a user-facing revoke may target; it adds no second revocation
  model — the target is still one exact `WalletAuthMethodId` with a fresh
  sibling proof, and the D1 final-method guard is untouched.

An earlier reading of this file recorded the opposite — that owner-method
removal already worked, because `revokeDevice` handles owner cards. It does
handle them; nothing reaches it.

### The unit suite cannot gate R109C

`npx playwright test -c playwright.unit.config.ts --list` from `tests/` reports
**26 collection errors** and collects zero tests. The failures are unresolvable
imports across unrelated files — missing fixture exports such as
`activeLinkedDeviceWalletSessionFixture`,
`selectWalletHostOwnerSourceLaneCandidatesV1`, and
`parseDerivedEmailOtpRecoveryKeyId`. This branch has touched exactly one file
under `tests/`, so the condition is pre-existing on `dev`.

Because one unresolvable import aborts collection for every file, `pnpm
test:unit` reports failure regardless of what R109C does, and a green unit
suite is not an available gate. Targeted single-file runs do work and are what
this ledger cites throughout.

Repairing the other 25 is a test-only project of its own and is deliberately
not attempted here: `AGENTS.md` forbids fixture-repair loops, and none of these
imports is R109C's to own. `tests/unit/emailOtpRegistrationRoute.unit.test.ts`
was repaired only because its two dead route imports were discovered while
verifying R109C's own Email OTP path.

### Demonstrated R103E defect: revocation never revokes the custody envelope

`revokePasskeyFactorAtomically`
(`packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore.ts:428`)
documents itself as the revocation path for a factor's envelopes, carries the
last-active-envelope guard, and **has no callers anywhere in the repo**.
`revokeWalletAuthMethod` in the D1 auth-method service touches no envelope at
all. So revoking an auth method today revokes the method, its verifier, and its
sessions, and leaves the factor-sealed custody envelope active in D1.

R103E's own contract says revocation "invalidates that method, its verifier,
its sealed local records, and sessions issued through that method". The durable
server-side ciphertext that the revoked factor can still unwrap is not among
the things it invalidates, and `lookupEnvelopeForFactor` will still return it.

This is recorded rather than repaired. R109C's revocation requirement names
*local* sealed records, so the gap is not on R109C's critical path, and silently
changing accepted revocation behaviour mid-implementation is the wrong way to
land a security-relevant fix. It needs its own decision and its own change set.
Note also that the function is passkey-typed, so whoever wires it up has to
generalize it the way `linkWalletCustodyFactorAtomically` was generalized.

### The authority digest has two different brands

`AddWalletAuthMethodSourceV1.authorityDigestB64u` is a `DigestB64u`. The active
Wallet Session projection's `authority.authorityDigest` is a
`WalletAuthorityBindingDigest` — a different value and a different brand. The
correct source is `WalletAuthorityV1.authorityDigestB64u`. The branding makes
the substitution a compile error, which is the point, but the two names are
close enough to be worth stating.

### Scope note: the entry-point plumbing is a surface change

Adding `registration.addEmailOtp` touches thirteen files in
`packages/wallet/src` — the public capability, the two facades, the iframe
client router, the message contract, the request router, the runtime context,
the host handler — because every one of them enumerates request kinds
explicitly. That is a planned Phase 1/2 surface change, not one localized
defect, so the "more than five files" stop condition does not apply to it.

### Open P1: the source-proof protocol does not yet meet the spec

This is the largest correctness gap and nothing on this branch has closed it.
R109C requires a fresh source assertion bound to the wallet, authority, source
method, source session, target method ID, operation purpose, authority state,
and intent digest. What exists binds far less:

- `AddAuthMethodIntentV1` carries only wallet, target description, policy
  scope, and nonce, so the digest a proof signs cannot name the authority, the
  source method, the source session, or the target method.
- The target `WalletAuthMethodId` is allocated *after* the source is
  authenticated, so no source proof can be bound to it. Binding it requires
  allocating the target id in the intent rather than in start.
- The route still admits `auth.kind: 'wallet_session'` — a reusable bearer
  credential — in place of a fresh assertion.

The last one is not simply a bug. That branch is R103E's deliberate zero-prompt
handoff for the *linked-device* ceremony start, where Device 1 holds owner
authority and Device 2 holds the PRF, and the two paths share one endpoint. So
R109C cannot just delete it; the endpoint has to distinguish a same-device
addition from a linked-device ceremony start, and today nothing in the request
does.

A related symptom is not a separate defect: that branch resolves an Ed25519
owner session only, which an ECDSA-only wallet never has. Making it curve-
agnostic does not work — the ECDSA binding has no `authority` field at all, so
it cannot name a source method. An attempt to widen it was reverted for that
reason. The real answer is that an R109C addition must present a fresh proof,
which is curve-independent, and then the ECDSA-only cell needs nothing special.

Consequence for the shared contract: production currently consumes only
`admitAddWalletAuthMethod` from `addWalletAuthMethod.ts`. Nothing builds
`VerifiedAddWalletAuthMethodInputV1`, so the branded two-branch input is not
yet load-bearing. It becomes load-bearing exactly when this protocol is fixed —
the builders are what force the proof, the target, and the identities to agree.

### Reversed: the `0013` provider-identity migration is in scope

An earlier revision of this ledger deferred
`0013_r109c_multi_auth_email_cardinality.sql`, arguing it was really R109D's
because R109D's document specifies it. That reading was wrong in both
directions.

`docs/refactor-109D-multi-auth-linking.md` assigns ownership explicitly —
"R109C owns multi-method inventory, same-device factor addition, Email OTP
cardinality, and verification of the R103E revocation prerequisite" — and its
Phase 0 refuses to start until "the R109C schema change becomes
`0013_r109c_multi_auth_email_cardinality.sql`, after the R103E `0012` repair."
R109D specifies the migration because it is blocked on it, not because it owns
it. `docs/refactor-103E.md` agrees: it assigns the canonical Passkey and Email
OTP provider-identity branches to R109C and forbids implementing them in R103E.

The deferral's supporting argument was also unsound. It claimed the addition
race was "closed transactionally" by a conditional insert, so the cardinality
index could wait. There was no conditional insert. There is one now, and it is
tested, but a guard in one code path is not the schema-level cardinality
constraint the migration is for.

What `0013` must do, from R109D's specification: join the canonical wallet
Email enrollment, copy `provider_user_id`, infer `provider` (a `google:`
subject is `google`, otherwise `email`), retain the normalized
`email_hash_hex`, rewrite columns and JSON to the final provider identity
shape, drop `registrationAuthorityId`, and apply the cardinality index. It
aborts if an active or pending Email method cannot resolve its enrollment, and
drops unresolvable revoked history. No nullable compatibility fields.

This ripples into `EmailOtpWalletAuthMethodDraftV1`, the V2 store and its
parsers, and this refactor's own `addWalletAuthMethod.ts` contract, because
`registrationAuthorityId` disappears from the Email branch. It is not started
yet and is the largest single remaining server item.

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
