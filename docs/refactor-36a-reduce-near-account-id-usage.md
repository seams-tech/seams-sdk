# Reduce NEAR Account ID Usage

Date created: 2026-05-06
Last refreshed: 2026-05-16
Status: code phases complete; refactor-36 follow-ups restored manual smoke
coverage

## Purpose

The SDK still uses `nearAccountId` as a general wallet/session/profile
identifier in many places. That makes ECDSA, Tempo, EVM, auth, iframe routing,
and UI flows look NEAR-specific even when the operation is protocol-neutral or
EVM-family-specific.

This refactor limits `nearAccountId` to NEAR account operations. Wallet/session
identity, ECDSA lane identity, audit scope, and UI display labels should have
separate names and types.

## Post-Implementation Retrospective

This plan started as a naming and ownership cleanup, then became a large
correctness refactor. `nearAccountId` had become the SDK's informal universal
identity for NEAR accounts, hosted wallets, wallet sessions, ECDSA subjects,
HSS audit scope, budget lookup, nonce sender state, export selection, and UI
display. Splitting those meanings forced the code to stop relying on implicit
string equivalence.

That tightening exposed hidden bugs that were already present in the design:

- ECDSA HSS stable-key context was coupled to volatile session identity in some
  paths. Fresh unlocks and reconnects could derive verifier material that no
  longer matched the stored integrated key record.
- Passkey wallet unlock and post-exhaustion refresh still had fallback paths
  that accepted partial ECDSA material, stale key refs, or missing exact lanes.
- Tempo and Arc/EVM were treated as target-scoped keys in some places and as one
  shared EVM-family signer in others. That created wrong-address and
  insufficient-funds failures because funding/preflight, nonce sender, and raw
  EIP-1559 broadcast could disagree.
- Email OTP ECDSA bootstrap mixed provider identity, such as `google:*`, with
  wallet-scoped HSS/session identity. That broke wallet unlock and HSS prepare.
- ECDSA export and lane selection could see multiple ready-ish shapes for the
  same logical signer, producing ambiguous export selection.
- Budget and finalization paths sometimes inferred the active session from
  loose records instead of carrying exact lane identity through reauth.

The refactor took several days because the identity split crossed nearly every
signing boundary: SDK facade inputs, iframe messages, persistence, sealed
recovery, wallet unlock, HSS client/server/WASM payloads, EVM-family signing,
nonce handling, budget admission/finalization, key export, Email OTP, and
tests. The repository scan showed roughly 4,916 `nearAccountId` hits across 477
files, which was a useful signal that the change was architectural rather than
local.

The useful outcome is that the system is now stricter. `nearAccountId` is
reserved for NEAR account operations, while ECDSA and EVM-family flows carry
`walletId`, `walletSessionUserId`, `subjectId`, `chainTarget`, and concrete
session identity separately. The follow-up in `docs/refactor-37.md` exists
because this refactor revealed one remaining architectural theme: the same
EVM-family ECDSA signer should be represented by one shared key identity, with
target/session/budget state layered on top.

Lessons for future identity refactors:

- Define the end-to-end smoke matrix up front: registration, wallet unlock,
  direct signing, export, session exhaustion, same-method step-up, passkey, and
  Email OTP.
- Treat stable key identity, concrete session lane identity, wallet budget
  identity, and transaction sender identity as separate types.
- Delete stale fallback paths as soon as exact identity exists.
- Keep compatibility at persistence/request boundaries only.
- Add guards for dangerous field groupings, such as key id plus session id in a
  shared key type, transaction sender identity in shared key records, or
  provider subject in wallet-scoped HSS fields.
- When HSS or signing-root context changes, include server, browser WASM,
  fixtures, and manual wallet-unlock/sign/export flows in the same validation
  slice.

## Goals

1. Make `nearAccountId` mean a NEAR chain account only.
2. Move wallet/session identity to explicit wallet/session types.
3. Move ECDSA identity to `WalletId + ThresholdEcdsaChainTarget`.
4. Make SDK and iframe ECDSA/Tempo/EVM inputs protocol-neutral.
5. Delete account-shaped compatibility paths as each boundary is replaced.
6. Add guards so `nearAccountId` cannot drift back into ECDSA, Tempo, EVM,
   nonce, budget, export, or threshold-session identity.

## Current Problem

`nearAccountId` currently carries multiple meanings:

| Current use | Actual meaning | Target field |
| --- | --- | --- |
| NEAR signer account | NEAR chain account | `nearAccount: NearAccountRef` |
| Wallet session lookup | wallet/session scope | `walletSession: WalletSessionRef` |
| Current app wallet | wallet identity | `walletId: WalletId` |
| ECDSA lane principal | protocol-neutral subject | `subjectId: WalletId` |
| HSS/session audit user | session/audit scope | `walletSessionUserId` |
| UI label | display metadata | `walletDisplayName` or `accountDisplayName` |

The current naming makes exact ECDSA paths easy to regress because a caller can
thread a NEAR account string where an ECDSA subject is required.

## Repository Scan Summary

Scan command:

```sh
rg -l "nearAccountId"
rg -o "nearAccountId" | wc -l
```

Scan date: 2026-05-11

The exact `nearAccountId` token appears in 4,916 places across 477 files. That
includes this plan, docs, tests, and new guard/typecheck files, so the count is
only a sizing signal. The previous 2026-05-06 scan found 4,756 hits across 422
files; the increase mainly reflects the signing-engine module split and the new
refactor-36 guard/typecheck surface.

The scan shows three different classes of usage:

1. NEAR-account usage that should remain, including NEAR signing, access-key
   management, account creation, NEAR recovery, NEAR account projection, and
   Ed25519 HSS derivation.
2. Wallet/session usage that should move to `WalletId`, `WalletSessionRef`, or
   `walletSessionUserId`.
3. ECDSA/Tempo/EVM usage that should move to `WalletId +
   ThresholdEcdsaChainTarget`, with wallet session data passed separately.

Several files are mixed surfaces. For example, wallet iframe message definitions
and host handlers contain both NEAR commands and ECDSA commands. Static guards
there need type-aware checks for specific payload names alongside path-only
searches.

## Target Vocabulary

```ts
export type WalletId = string & { readonly __brand: 'WalletId' };

export type WalletSessionRef = {
  walletId: WalletId;
  walletSessionUserId: string;
};

export type NearAccountRef =
  | { kind: 'named'; accountId: AccountId }
  | { kind: 'implicit'; accountId: AccountId };

export type EcdsaCommandSubject = {
  walletSession: WalletSessionRef;
  walletId: WalletId;
};

export type NearCommandSubject = {
  walletSession: WalletSessionRef;
  nearAccount: NearAccountRef;
};
```

Rules:

1. `NearAccountRef` is the only NEAR chain account identity.
2. `WalletSessionRef` is the only wallet-session/audit context after the SDK
   boundary.
3. `WalletId` is the only ECDSA lane principal.
4. ECDSA commands always require `walletId + chainTarget`.
5. Wallet/session code may map the current hosted wallet profile to a
   `WalletId` once at the app/session boundary.
6. Core ECDSA signing/export/restore/budget/nonce/HSS code must never derive
   `subjectId` from `nearAccountId`.

## Allowed `nearAccountId` Surface

Keep NEAR account identifiers only in code that directly operates on NEAR
accounts:

1. NEAR transaction signing and NEAR transaction display.
2. NEAR access-key lookup, add-key, delete-key, nonce, and blockhash fetch.
3. NEAR registration and account creation.
4. NEAR account recovery and recovery email flows when the recovered object is a
   NEAR account.
5. NEAR account projection/indexing modules under `accountData/near`.
6. NEAR-specific link-device owner-management flows.
7. Server routes and records that explicitly represent hosted NEAR accounts.

Every other use should move to `walletId`, `walletSessionUserId`,
`WalletId`, or an explicit display label.

## Forbidden `nearAccountId` Surface

After this refactor, `nearAccountId` should be absent from:

1. ECDSA session bootstrap, restore, activation, runtime store, durable store,
   export, and key-ref code.
2. Tempo and EVM-family public signing inputs.
3. Tempo and EVM-family iframe messages.
4. ECDSA Email OTP capability inputs and worker messages.
5. ECDSA nonce lane identity, managed nonce snapshots, and nonce metrics.
6. ECDSA budget identity and admission/finalization state.
7. ECDSA HSS prepare/finalize identity. HSS may receive `walletSessionUserId`
   for session/audit scope and `subjectId` for lane identity.
## Public API Target Shape

NEAR commands:

```ts
await seams.near.signTransactions({
  walletSession,
  nearAccount: { kind: 'named', accountId },
  transactions,
  options,
});
```

ECDSA/Tempo/EVM commands:

```ts
await seams.evm.executeTransaction({
  walletSession,
  subjectId,
  chainTarget,
  request,
  options,
});
```

ECDSA export:

```ts
await seams.auth.exportKeypairWithUI({
  kind: 'ecdsa',
  walletSession,
  subjectId,
  chainTarget,
  options,
});
```

NEAR export:

```ts
await seams.auth.exportKeypairWithUI({
  kind: 'near',
  walletSession,
  nearAccount: { kind: 'named', accountId },
  options: { chain: 'near' },
});
```

Email OTP ECDSA unlock:

```ts
await seams.auth.loginWithEmailOtpEcdsaCapability({
  walletSession,
  subjectId,
  chainTarget,
  otpCode,
  challengeId,
});
```

The app/demo layer may construct `walletSession` and `subjectId` from the active
hosted wallet profile. SDK internals receive those values as already-normalized
identity.

## Suggestions From Scan

1. Build on the existing identity module before adding a new one.
   `WalletId`, `NearAccountRef`, `nearAccountRefFromAccountId(...)`, and
   `thresholdEcdsaChainTarget*` already live in
   `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`.
   Add `WalletId`, `WalletSessionRef`, and boundary constructors there or move
   the full set into one new identity module in a single commit.
2. Convert public boundaries first. The largest fan-out starts in the SDK facade,
   wallet iframe protocol, React context, and demo/docs call sites. Once those
   inputs require `walletSession`, `subjectId`, and `nearAccount`, TypeScript
   will expose the internal paths still carrying account-shaped ECDSA identity.
3. Treat ECDSA storage as one vertical slice. Runtime lanes, durable records,
   warm-session envelopes, nonce lanes, budget admission, restore, export, and
   HSS prepare/finalize all need the same lane identity. Splitting those changes
   across phases leaves partial identity models in the hot path.
4. Replace repeated profile lookups from ECDSA code. Calls that use
   `buildNearAccountRefs(nearAccountId)` inside EVM/Tempo paths should receive a
   normalized wallet/profile reference from the boundary, then use that to find
   WebAuthn credentials or account data.
5. Separate Ed25519 HSS from ECDSA HSS in naming. Ed25519 NEAR threshold signing
   can keep `nearAccountId` as the NEAR account scope. ECDSA HSS should name the
   audit/session field `walletSessionUserId` and the lane principal `subjectId`.
6. Update the architecture guard strategy. Keep path-only guards for NEAR-only
   and ECDSA-only directories, and add structural guards for mixed files such as
   wallet iframe messages, `SigningEngine.ts`, `SeamsPasskey/index.ts`,
   `assembly/ports/shared.ts`, `uiConfirm`, and `stepUpConfirmation`.
7. Extend the new refactor-36 guard suite. The repository now has
   `tests/unit/signingEngine.refactor36.guard.unit.test.ts` and
   `tests/unit/signingEngine.refactor36.allowlists.ts`; add `nearAccountId`
   surface guards there. The deleted
   `signingSessionCoordinator.architecture.guard.unit.test.ts` should stay
   deleted.
8. Track remaining account-to-subject derivations explicitly. The rescan found
   direct `toWalletId(nearAccountId)` calls in the SDK facade,
   `SigningEngine.ts`, `session/public.ts`, availability/readiness,
   warm-capability cleanup/status, email-OTP companion sessions, recovery lane
   selection, and assembly shared ports.

## Refactor Area Inventory

| Area | Exact-hit files | Required refactor |
| --- | ---: | --- |
| Tests | 167 | Rewrite fixtures and assertions to use `nearAccount` for NEAR flows, `walletSession + subjectId + chainTarget` for ECDSA flows, and add guards for forbidden payload fields. |
| Server | 35 | Split hosted NEAR account flows from wallet/session identity in ThresholdService, HSS route handlers, sponsorship, recovery, and registration routes. |
| EVM-family signing flows | 30 | Replace `nearAccountId` in `flows/signEvmFamily/**`, including auth planning, ECDSA material state, nonce lifecycle, budget spending, prepared signing, signing flow runtime, and transaction execution. |
| SDK facade: `client/src/core/SeamsPasskey/**` | 23 | Rename public EVM/Tempo/auth inputs, stop deriving `subjectId` from `nearAccountId`, and keep NEAR account refs only under `near/**` and account creation/recovery flows. |
| Signing engine other | 20 | Update `SigningEngine.ts`, threshold modules, EVM chain signer bridge, nonce coordinator, WebAuthn auth, user preferences, and remaining top-level session entrypoints. |
| Examples and demo site | 19 | Update sample apps, docs snippets, demo hooks, login bridges, profile settings, and Tempo/EVM action hooks to model wallet/session identity separately from NEAR account display. |
| UI confirm | 16 | Split confirmation request data into NEAR account display for NEAR operations and wallet/subject display for ECDSA export, Tempo, EVM, and signing-session prompts. |
| React package | 16 | Rename login state, context values, `getWalletSession(...)`, refresh callbacks, account input, account menu, linked devices, QR, and passkey menu data to use wallet/session names where the UI is wallet-scoped. |
| Docs | 14 | Update conceptual docs, nonce docs, OTP privacy docs, deployment docs, refactor docs, and registration-flow docs after the API shape changes. |
| Warm capabilities | 14 | Move ECDSA warm-capability read models, status readers, provision plans, persistence, sealed-refresh parity, login prefill, and cleanup from account identity to `subjectId + chainTarget`. |
| Recovery flows | 13 | Split ECDSA export/recovery lane selection and HSS export from NEAR Ed25519 export/recovery. ECDSA export should receive wallet/session and subject identity directly. |
| Passkey session | 12 | Move ECDSA bootstrap/provision/recovery/warm-capability paths away from account-derived subjects while keeping Ed25519 provision/recovery account-scoped. |
| Email OTP session | 10 | Split ECDSA bootstrap, provisioning, companion sessions, export recovery, and worker requests from Ed25519 account recovery and local metadata. |
| Wallet iframe protocol | 9 | Update shared payload types, client router, iframe wrapper, host handlers, login-status events, preferences events, and route initialization to use wallet/session fields for non-NEAR flows. |
| WASM bindings | 8 | Keep NEAR signer/Ed25519 bindings account-scoped; update HSS client signer and ECDSA bridge payloads that use account strings as wallet/session identity. |
| NEAR signing flows | 8 | Keep `flows/signNear/**` account-scoped; rename only generic wallet/session helpers that leaked in. |
| Workers | 5 | Remove `nearAccountId` from ECDSA Email OTP worker messages, eth signer worker payloads, passkey confirm worker ECDSA paths, and worker type definitions. |
| Operation state | 5 | Ensure lanes, prepared operation, post-sign policy, transaction state, and coordinator inputs require the narrow identity for each lifecycle state. |
| Budget session | 5 | Move ECDSA budget admission, status, finalization, and projections from account identity to selected subject/chain identity. |
| Assembly ports | 5 | Split `assembly/ports/near.ts` from shared/EVM-family port contracts that still route ECDSA status, challenge, and warm-capability calls through account arguments. |
| Step-up confirmation | 4 | Keep NEAR PRF/account prompts account-scoped; split ECDSA export/signing prompts to wallet display plus subject identity. |
| Client core types | 4 | Update SDK sent events, secure-confirm worker types, signer-worker types, and Seams public types to separate account, wallet, subject, and display fields. |
| NEAR account data | 4 | Keep account projection, refs, key material, and NEAR account data types account-scoped; make callers pass normalized `NearAccountRef` or `AccountId` only at this boundary. |
| Shared utilities | 3 | Keep `shared/src/utils/near.ts` and recovery email/domain helpers account-scoped; ensure generic wallet/session helpers live outside NEAR utilities. |
| Session other | 3 | Update session public APIs, coordinator entrypoints, and identity/readiness bridges that still expose account-shaped ECDSA lifecycle inputs. |
| Other flows | 3 | Keep registration account lifecycle scoped to NEAR account creation; update generic registration/export helpers that feed ECDSA bootstrap. |
| Signing engine interfaces | 3 | Split `operationDeps`, `near`, and `nearKeyOps` contracts so ECDSA ports stop inheriting NEAR account naming. |
| Benchmarks | 3 | Update threshold-load and ECDSA HSS fixtures so benchmark inputs match the new API and keep Ed25519/NEAR fixtures account-scoped. |
| Crates | 2 | Keep signer-core NEAR Ed25519 domain comments account-scoped; update iOS vector replay naming only if the vector represents ECDSA wallet identity. |
| Client utils | 2 | Keep intent digest and email recovery utilities account-scoped when they operate on NEAR data; move generic wallet/session formatting elsewhere. |
| Availability | 2 | Remove account-derived subject fallbacks from persisted lane availability and readiness. |
| RPC clients | 2 | Keep NEAR RPC account arguments; rename EVM nonce backend identity from account to subject/wallet session where it is ECDSA lane state. |
| Session persistence | 1 | Audit `session/persistence/records.ts` because it has the densest persisted-record identity surface in the new layout. |

## Refactor Phases

### Phase 1: Add Identity Types And Boundary Helpers

- [x] Extend the existing identity surface. `WalletId`, `NearAccountRef`,
   and `nearAccountRefFromAccountId(...)` already exist in
   `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`.
- [x] Add `WalletId`, `WalletSessionRef`, `NearCommandSubject`, and
   `EcdsaCommandSubject`.
- [x] Add boundary constructors:
   - `walletIdFromSessionValue(...)`
   - `walletSessionRefFromSession(...)`
   - `nearAccountRefFromAccountId(...)`
   - `walletIdFromWalletProfile(...)`
- [x] Move call sites to use these constructors at app/SDK/iframe/server route
   boundaries.
   - [x] Public SeamsPasskey EVM, Tempo, registration, login, and link-device
     bootstrap/owner-management boundaries now use
     `walletIdFromWalletProfile(...)` for hosted-wallet profile
     derivation.
   - [x] Iframe and server route boundaries now use typed wallet/session,
     NEAR-account, or ECDSA lane identities at the ECDSA-relevant command
     boundaries; NEAR-owned routes keep account ids.
- [x] Forbid new `toWalletId(nearAccountId)` calls in core ECDSA code.
   The Refactor 36 guard now freezes the current account-to-subject derivation
   allowlist so later phases can delete entries without letting new ones appear.
   The allowlist is down to signing-engine internals only.
- [x] Move any account-to-subject derivation that remains in the app/demo layer
   behind an explicitly named hosted-wallet profile adapter.
   The demo site and React account-menu export flow no longer call
   `toWalletId(nearAccountId)` directly.

Phase 1 validation on 2026-05-12:

```bash
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C sdk build:rolldown
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
pnpm -C examples/seams-site typecheck
git diff --check
```

### Phase 2: Rename Wallet Session APIs

- [x] Replace `getWalletSession(nearAccountId?)` with
   `getWalletSession(walletId?)`.
- [x] Replace `currentNearAccountId` React state with `currentWalletId`.
   The React account-input hook now receives `currentWalletId`; login-state
   NEAR account display fields remain `nearAccountId` until wallet/session
   projection is split.
- [x] Replace iframe login status fields:
   - `nearAccountId` -> `walletId`
   - add `nearAccount?: NearAccountRef` only when UI needs the NEAR projection.
- [x] Rename wallet iframe routing args from `nearAccountId` to `walletId`.
   The `PM_GET_WALLET_SESSION` payload and router/helper signatures now use
   `walletId`; NEAR-specific command payloads still carry `nearAccountId`.
- [x] Update preferences/current-user storage to use `walletId`.
   Wallet-host preference change events and confirmation-config RPC payloads
   now carry `walletId`; the NEAR-backed profile preference lookup is isolated
   inside `UserPreferencesManager`.

Phase 2 validation on 2026-05-12:

```bash
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C sdk build:rolldown
pnpm -C tests exec playwright test -c playwright.lite.config.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
pnpm -C examples/seams-site typecheck
git diff --check
```

### Phase 3: Split NEAR Public Commands From ECDSA Commands

 - [x] Move NEAR signing inputs to `nearAccount: NearAccountRef`.
   - [x] top-level NEAR signing requests now carry `nearAccount:
     NearAccountRef` for transactions, delegate actions, and NEP-413.
   - [x] NEAR UI-confirm signing payloads and entry validation now require
     `nearAccount` and reject drift against legacy worker-era account-id
     fields.
   - [x] NEAR UI-confirm transaction, delegate-action, and NEP-413 executors
     now resolve signer identity from `nearAccount` at their boundary.
   - [x] shared NEAR signing-material and auth-planning helpers now accept
     `nearAccount` instead of raw account-id strings at their boundary.
   - [x] outer `signNear.ts` transaction-session, ad-hoc session-id, and
     passkey-reconnect helpers now accept `nearAccount` and normalize
     `nearAccountId` once locally.
   - [x] `signNear.ts` transaction wallet-auth helper now accepts
     `nearAccount` and only passes normalized account ids into NEAR-specific
     side effects.
   - [x] `signNear.ts` transaction-operation preparation now accepts
     `nearAccount` and keeps normalized `nearAccountId` local to runtime lane
     selection and record verification.
   - [x] public `SeamsPasskey.near` capability methods and the wallet-iframe
     proxy now require `nearAccount: NearAccountRef` and normalize account ids
     only at the NEAR router boundary.
- [x] Move Tempo/EVM signing inputs to `walletSession + subjectId + chainTarget`.
   - [x] Public `SignTempoArgs` and `ExecuteEvmFamilyTransactionArgs` now use
     `walletSession + subjectId + chainTarget`.
   - [x] `PM_SIGN_TEMPO` iframe payloads now carry `walletSession`.
   - [x] Tempo nonce lifecycle report/reconcile iframe payloads now carry
     `walletSession`.
- [x] Delete `nearAccountId` from:
   - [x] `SignTempoArgs`
   - [x] `ExecuteEvmFamilyTransactionArgs`
   - [x] Tempo signing/report/reconcile iframe payloads
   - [x] EVM-family signing orchestration inputs
      - [x] top-level `signEvmFamily(...)` and `SigningEngine.signTempo(...)`
        now receive `walletSession`.
      - [x] `createEvmFamilySigningFlowRuntime(...)` now receives
        `walletSession`.
      - [x] EVM-family wallet budget spending helpers now receive
        `walletSession`.
      - [x] prepared ECDSA signing helper now receives `walletSession`.
      - [x] auth-planning and Email OTP refresh helpers now receive
        `walletSession`.
      - [x] EVM-family signing flow runtime, UI-confirm signing flow,
        transaction executor, fresh-Email-OTP retry path, account-auth
        lookup, Tempo report/reconcile lifecycle args, and related Tempo
        callers now use `walletId` instead of `nearAccountId` for
        wallet-scoped internal flow inputs.
      - [x] sealed-refresh parity checks for ECDSA bootstrap/transaction
        signing and the EVM-family post-sign wrapper now use `walletId`
        for wallet-scoped bridge inputs.
      - [x] wallet-scoped budget identity preparation and the
        `buildWalletBudgetStatusCheckForSession(...)` helper now use
        `walletId` at their boundary.
      - [x] deeper nonce/material/budget/service helpers now use typed
        wallet/session inputs instead of hosted wallet ids named
        `nearAccountId`.
        - [x] `SigningSessionCoordinator` wallet-scoped status, consume, and
          clear boundaries now use `walletId`.
        - [x] EVM-family warm-session services, ECDSA post-sign policy
          adapters, and threshold-signing readiness helpers now use
          `walletId` for wallet-scoped ECDSA session checks.
        - [x] warm ECDSA status/public helper boundaries now use `walletId`
          for wallet-scoped signing-session reads.
        - [x] EVM-family managed nonce resolution/lifecycle helpers now use
          `walletId` at their internal boundary and translate only at the
          nonce-backend request shape.
        - [x] EVM-family ECDSA selection/auth-planning bridges and the
          Email OTP signing-session bridge now use `walletId` for
          wallet-scoped internal flow inputs.
        - [x] EVM-family ECDSA lane-context assembly now uses `walletId`
          for wallet-scoped lane construction.
        - [x] warm-capability login-prefill, capability-store, and warm-clear
          helper boundaries now use `walletId` for wallet-scoped inputs.
        - [x] warm-capability ECDSA readiness/status wrapper boundaries now
          use `walletId` for wallet-scoped queries.
        - [x] warm-capability ECDSA status-reader, record-resolution, and
          wallet-scoped claim helpers now use `walletId` for wallet-scoped
          ECDSA lane lookups.
      - [x] warm ECDSA bootstrap queue coordination now uses `walletId`
          for wallet-scoped queue ownership.
        - [x] EVM-family reconnect readiness and local ECDSA signer
          commit-queue boundaries now use `walletId` for wallet-scoped helper
          inputs.
        - [x] lower nonce/material helpers and remaining warm-capability/store
          bridges now expose wallet-scoped identity as `walletId` or
          `walletSession`.
       - [x] public ECDSA bootstrap helper surfaces now use
         `walletSession + subjectId + chainTarget` in host-facing SDK APIs
         such as `BootstrapThresholdEcdsaSessionArgs`, including the
         wallet-iframe request path and demo/test callers.
       - [x] public ECDSA presign prefill now uses
         `walletSession + subjectId + chainTarget` across the SeamsPasskey
         API, wallet-iframe payload, and host handler.
- [x] Keep NEAR account refs in NEAR transaction signing, NEP-413, intent
   digest, add-key, and link-device owner operations.
   - [x] deployed link-device owner-management mutations now normalize
     `nearAccount: NearAccountRef` at the NEAR owner boundary before building
     wallet-scoped EVM execution inputs.
   - [x] the `SeamsPasskey/near` facade now normalizes `nearAccountId` once
     per command entrypoint before routing into remote/local NEAR flows.
   - [x] link-device add-key, nonce/blockhash fetch, and auto-login helpers
     now normalize `nearAccount: NearAccountRef` at their NEAR boundary and
     keep raw account ids local to NEAR RPC and signing calls.

Phase 3 partial validation on 2026-05-12:

```bash
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C examples/seams-site typecheck
```

### Phase 4: Split Email OTP Wallet Unlock From ECDSA Capability

Detailed completed Phase 4 subtasks:

- [x] Public Email OTP ECDSA capability args and signing-session
  challenge/refresh APIs now carry `walletSession: WalletSessionRef` instead of
  raw `nearAccountId`.
- [x] Wallet iframe Email OTP request payloads for signing-session challenge,
  refresh, login, and enroll+login now carry `walletSession`.
- [x] Internal Email OTP ECDSA lifecycle login/enrollment paths now take
  `walletSession` and only convert to account-shaped worker fields at the
  worker-request boundary.
- [x] ECDSA signing-session challenge/refresh helpers now keep `walletSession`
  through the session layer and only adapt at the deeper Email OTP worker
  challenge boundary.
- [x] The ECDSA signing-only Email OTP reauth helper now also takes
  `walletSession` directly instead of rebuilding it from `nearAccountId` in the
  EVM-family bridge.
- [x] Email OTP worker challenge/export requests now use an explicit
  `wallet_session_challenge | near_account_challenge` union so ECDSA flows can
  keep `walletSession` while NEAR/export-only flows stay boundary-local.
- [x] Fresh ECDSA Email OTP export now accepts `walletSession` directly and keeps
  the export challenge on a wallet-session branch, leaving only the NEAR/export
  display boundary account-shaped.
- [x] The standalone Email OTP wallet-unlock worker result now also returns
  `clientRootShare32B64u`, and the session module now uses a dedicated typed
  unlock helper.
- [x] Email OTP enroll+login now also runs as two operations:
  `enrollEmailOtpWallet` to mint wallet-scoped enrollment material, then
  `bootstrapEmailOtpEcdsaSessionsFromClientRootShare` to mint the ECDSA
  subject lane. The old combined enroll+bootstrap worker path has been
  deleted.
- [x] Core Email OTP ECDSA login now runs as two operations:
  `loginWithEmailOtpWallet` to recover wallet-scoped material, then
  `bootstrapEmailOtpEcdsaSessionsFromClientRootShare` to mint the ECDSA
  subject lane. The old combined login+bootstrap worker path has been deleted.

Detailed remaining Phase 4 tasks:

- [x] Move HSS prepare to `walletSessionUserId + subjectId + chainTarget`.

- [x] Model wallet unlock as a wallet-session operation:
  ```ts
  loginWithEmailOtp({ walletSession, otpCode, challengeId })
  ```
- [x] Model ECDSA capability bootstrap as an ECDSA subject operation:
  ```ts
  loginWithEmailOtpEcdsaCapability({
    walletSession,
    subjectId,
    chainTarget,
    otpCode,
    challengeId,
  })
  ```
- [x] Delete any Email OTP ECDSA worker payload that accepts `nearAccountId`.
- [x] HSS prepare receives:
  - [x] `walletSessionUserId` for session/audit scope
  - [x] `subjectId` for ECDSA lane identity
  - [x] `chainTarget` for concrete chain identity

### Phase 5: Move ECDSA Stores And Nonce To Subject Identity

Detailed completed Phase 5 subtasks:

- [x] ECDSA runtime session records now normalize `walletId` at the persistence
  boundary and carry `walletId` internally instead of `nearAccountId`.
  Readback remains compatible only at the boundary by accepting persisted
  `walletId | nearAccountId` shapes during normalization.
- [x] Warm-capability envelopes, readers, invariants, transitions, and transition
  callbacks now use `walletId` for wallet-scoped ECDSA state.
- [x] ECDSA downstream consumers that validate or republish runtime records now use
  `record.walletId`, including lane matching, signer canonical-record checks,
  passkey/email-OTP recovery, post-sign policy material, warm-session status
  lookup, and UI-confirm sealed-record metadata.
- [x] Session-public ECDSA admin helpers now use exact wallet/subject language:
  bootstrap upserts take `walletId`, subject-target keyref lookup no longer
  derives `subjectId` from `nearAccountId`, and wallet-scoped clear/list helpers
  are named as wallet operations instead of account operations.
- [x] The remaining warm ECDSA provision/read boundary types now also use
  `walletId`: generic session-record lookup splits ECDSA `walletId` from
  Ed25519 `nearAccountId`, ECDSA warm-reuse helpers take `walletId`, and
  ECDSA capability-ready planning no longer exposes account-shaped identity in
  its internal args.
- [x] The remaining ECDSA-only helper names now match their real keys:
  wallet-target keyref listing no longer says `ForAccountTarget`, and
  Email OTP consume helpers now say `ForSubjectTarget` instead of
  `ForAccount`.
- [x] ECDSA bootstrap persistence now accepts `walletId` at its public/session
  boundary and keeps the NEAR profile/account mapping variable local to the
  IndexedDB persistence layer.
- [x] Managed ECDSA nonce reservation/snapshot identity now uses `walletId`
  through the nonce backend, nonce coordinator adapter, and EVM/Tempo nonce
  lifecycle telemetry.
- [x] Wallet-scoped ECDSA Email OTP challenge/request bridges and the threshold
  ECDSA commit queue now use `walletSession`/`walletId` in shared flow and
  runtime ports, leaving `nearAccountId` only on the explicit NEAR Email OTP
  request branch and other raw NEAR-owned boundaries.
- [x] ECDSA runtime record indexing and wallet-scoped read/clear helpers in
  persistence now use wallet terminology consistently, so the remaining
  account-shaped compatibility surface for ECDSA is isolated to explicit raw
  normalization and NEAR-owned mapping boundaries.
- [x] The canonical ECDSA session-record normalizer now requires `walletId`
  directly instead of accepting `nearAccountId` as an internal fallback, which
  keeps account-shaped compatibility out of the core ECDSA runtime record path.
- [x] Warm-session mixed read-model helpers now use wallet terminology
  consistently (`readWarmSessionCapabilityRecordsForWallet`,
  `discoverLanesForWallet`, `readWalletScopedLaneClaimsForWallet`), leaving
  account-shaped naming only in Ed25519-owned helpers and explicit NEAR-owned
  boundaries.
- [x] The mixed availability/coordinator wallet-scoped surfaces now also use
  wallet terminology (`listSealedRecordsForWallet`,
  `getLaneClaimsForWallet`), which removes the remaining `...ForAccount`
  naming from shared ECDSA lane discovery and wallet-scoped claim readback.
- [x] Wallet-scoped readiness override state also uses `walletId` now, so wallet
  signing-session override keys and clear/readback helpers no longer carry a
  stale `nearAccountId` field through the shared availability layer.
- [x] The shared sealed-recovery/readback boundary no longer uses stale
  `...ForAccount...` result/helper names for mixed wallet-scoped restore work,
  which keeps the shared ECDSA/Ed25519 recovery surface neutral while
  Ed25519-specific account-owned restore helpers remain explicit.
- [x] ECDSA lane candidates now carry `walletId` instead of `accountId`, so the
  ECDSA lane read-model/selection boundary no longer reintroduces
  account-shaped identity before building the selected ECDSA lane.
- [x] Wallet-scoped sealed-session list APIs now use wallet terminology as well,
  so ECDSA sealed-record lookup no longer presents a generic
  `listExactSealedSessionsForAccount` surface in the persistence/runtime path.
- [x] The mixed sealed restore coordinator now also uses wallet terminology for
  wallet-scoped ECDSA restore work (`restoreSealedRecordForWallet`,
  wallet-scoped list/error hooks, passkey ECDSA restore helper naming), while
  Ed25519-specific restore helpers keep their NEAR/account-owned shape.
- [x] The mixed session-public restore API now also uses wallet terminology
  (`restorePersistedSessionsForWallet` and wallet-scoped restore input/result
  types), so the outward wallet-scoped restore surface no longer says
  `...ForAccount`.
- [x] The remaining mixed passkey ECDSA restore helper in UI confirm now also uses
  wallet terminology, and wallet-scoped ECDSA restore diagnostics no longer
  describe the flow as account-scoped.
- [x] The broad subject-wide ECDSA listing no longer exists on production
  signing-engine/session public surfaces. Remaining subject-wide ECDSA listing is
  reduced to test-only helpers, while runtime ECDSA discovery uses
  wallet-target or exact target-scoped readers.
- [x] Email OTP ECDSA commit/publication plumbing now passes `walletId` through the
  session layer, keeping raw `nearAccountId` only at the IndexedDB/account
  mapping boundary that still models hosted NEAR profile state.
- [x] Warm-session ECDSA status/readiness paths now require subject inventory and
  no longer fall back to wallet-keyed ECDSA record scans when resolving
  current lanes or signing-session status.
- [x] Wallet-scoped budget status checks, budget-status readers, and coordinator
  budget adapters now use `walletId` at their boundary, so wallet-budget
  reads no longer expose account-shaped identity through the ECDSA session
  layer.
- [x] Internal wallet-budget projection state also uses `walletId`, removing the
  stale account-shaped identity field from the budget model itself.
- [x] Wallet-signing spend/finalization plans now carry `walletId` instead of
  `nearAccountId`, so ECDSA and wallet-scoped NEAR budget finalization no
  longer rebuild account-shaped identity inside the budget domain model.
- [x] Selected/planning ECDSA lanes now also carry `walletId` instead of
  `accountId`, so the selected-lane capability reader, readiness path, and
  spend-plan normalization no longer reintroduce account-shaped identity after
  lane selection.
- [x] Warm-capability public ECDSA persistence/status helpers now also use wallet
  terminology (`persistThresholdEcdsaBootstrapForWalletTarget`,
  `resolveCanonicalThresholdEcdsaSessionIdForWalletTarget`), so the outward
  ECDSA bootstrap/status surface no longer exposes chain-account or NEAR-owned
  naming.
- [x] Warm-capability cleanup/status helpers also stopped using stale wallet-scoped
  “account” wording in their public/runtime surfaces, which keeps the remaining
  Phase 5 work focused on exact subject-target read models and budget identity
  instead of mixed naming cleanup.
- [x] The warm-capability store now reads ECDSA capability records through explicit
  wallet-plus-chain-family helpers instead of a dead mixed account helper and
  wallet-wide scan/filter path, which narrows the remaining read-model residue
  to exact subject-target claim handling rather than generic inventory shape.
- [x] Lane-based budget identity preparation now derives wallet scope directly from
  the selected lane instead of accepting a duplicate `walletId` input, which
  removes another wallet/account identity bounce from the exact-lane budget
  admission path.
- [x] Warm-capability ECDSA policy/reconnect paths now resolve records by exact
  `thresholdSessionId + walletId + chainTarget` instead of a weaker “current
  record for wallet/target” lookup, which removes another non-exact ECDSA
  read-model escape hatch without overstating the remaining claim aggregation
  cleanup.
- [x] Warm-capability ECDSA status/read paths now also read wallet-scoped claims
  from exact lane sets when the concrete records are already known, so status
  and envelope assembly no longer widen back out to whole-wallet lane
  rediscovery just to compute claims.
- [x] Wallet-budget projection state now requires `walletId` instead of carrying an
  optional wallet field, which narrows the remaining budget work to exact-lane
  projection/finalization semantics rather than partial wallet identity.
- [x] The remaining ECDSA-only bootstrap queue surfaces now also use wallet
  terminology (`queueByWallet`, `thresholdEcdsaBootstrapQueueByWallet`), which
  removes another account-shaped cleanup helper from passkey, Email OTP, and
  engine assembly wiring.
- [x] The exact-record warm-claim reader no longer accepts a redundant wallet-wide
  identity input, so capability envelope/status assembly now exposes the
  narrower record-set contract it actually uses.
- [x] Internal warm ECDSA bootstrap/reuse helpers now use `walletId`, leaving
  `nearAccountId` only on the explicit raw bootstrap request shape passed into
  the lower activation boundary.
- [x] Internal ECDSA provision activation state now also carries `walletId`, and
  the mixed availability/selection helpers no longer bounce wallet-scoped
  ECDSA reads back through local `accountId` naming while assembling exact
  lane inputs.
- [x] Trusted budget-status auth resolution now avoids wallet-wide ECDSA lane scans
  when an exact threshold-target check already provided concrete threshold
  session ids, which narrows another budget/finalization readback path to
  exact-lane identity.
- [x] ECDSA bootstrap session-upsert helpers now also accept `walletId`, removing
  another wallet-scoped `nearAccountId` bounce between passkey/Email OTP
  session orchestration and the ECDSA session store.
- [x] Wallet-scoped ECDSA restore, post-sign policy, and bootstrap-persistence
  helpers now also keep local `walletId` naming through their internal
  orchestration, leaving NEAR/account naming only at explicit hosted-NEAR
  mapping boundaries.
- [x] Wallet-scoped ECDSA account-auth and WebAuthn leaf helpers now also use
  wallet terminology at their own boundary, leaving the hosted-NEAR
  profile/account lookup as the only account-shaped layer underneath.
- [x] Wallet-scoped ECDSA commit-queue helpers now also keep local `walletId`
  naming through their internal orchestration, leaving account-shaped
  terminology only at explicit hosted-NEAR mapping and server request
  boundaries.
- [x] The wallet-scoped Email OTP enrollment bridge now also takes `walletId`
  instead of `nearAccountId`, leaving raw account-shaped identity only in the
  surrounding registration/event boundary that still models NEAR account
  ownership.
- [x] The remaining wallet-scoped ECDSA helper audit is now down to raw
  hosted-NEAR boundaries and mixed Ed25519 paths: the last local enrollment
  bridge residue now uses `walletId`, and the remaining ECDSA `nearAccountId`
  hits are confined to explicit raw bootstrap/activation request assembly.
- [x] The exact warm-capability ECDSA status path now stays exact after
  threshold-session lookup misses, instead of widening back out to
  subject-inventory discovery derived from `walletId`.
- [x] Wallet-scoped ECDSA status listing now reads through the wallet/chain
  persistence helper instead of re-deriving subject inventory from `walletId`
  just to enumerate current records.
- [x] The warm-capability reader/status stack no longer carries the dead
  `listThresholdEcdsaSessionRecordsForSubject` dependency through ECDSA
  status/auth resolution. The remaining subject-based enumeration is now
  isolated to explicit availability/coordinator paths instead of the
  wallet-scoped warm-capability reader itself.
- [x] Remaining ECDSA warm-capability `nearAccountId` hits are now confined to
  explicit raw bootstrap/activation request assembly and hosted-NEAR mapping
  boundaries. The wallet-scoped ECDSA reader/status/provision stack itself no
  longer depends on account-shaped helpers or subject-scan plumbing.
- [x] The remaining open scan-policy residue is now clearly isolated: broad
  subject-wide ECDSA enumeration is no longer part of the warm-capability
  reader/status stack, and only the availability/coordinator paths still use
  subject-wide discovery for mixed wallet-session lane aggregation and Email
  OTP companion selection.
- [x] Wallet-session readiness lane discovery now also enumerates ECDSA records
  through the wallet index instead of the subject index. The remaining
  subject-wide ECDSA discovery is now limited to Email OTP companion selection
  and its Ed25519 warmup/coordinator wiring.
- [x] Email OTP companion selection and Ed25519 warmup/coordinator wiring now
  use wallet-indexed ECDSA record listing as well. The remaining subject-list
  surface is reduced to explicit session-admin/public APIs instead of live
  wallet-session readiness or Email OTP warmup flows.
- [x] The remaining budget/finalization `accountId` branches are now confined to
  the Ed25519 half of shared lane/spend unions. The ECDSA budget reservation,
  finalization, projection, and trace paths use `walletId` plus exact
  lane/session identity.

Detailed remaining Phase 5 tasks:

- [x] Finish the remaining true raw recovery compatibility boundaries.
- [x] Finish the remaining subject-target keyed inventory/read models.
- [x] Finish budget finalization keyed by exact ECDSA lane identity.

- [x] Ensure ECDSA runtime and persisted records use `subjectId + chainTarget`.
- [x] Ensure durable sealed ECDSA records use `subjectId + chainTarget`.
- [x] Ensure warm-capability read models, status readers, provision plans, and
  cleanup use `subjectId + chainTarget`.
- [x] Ensure managed nonce lanes and snapshots use `subjectId + chainTarget`.
- [x] Ensure budget finalization and projection state use exact ECDSA lane
  identity instead of hosted-account semantics.
- [x] Delete account-keyed ECDSA cleanup and inventory helpers.
- [x] Keep account-wide scans only in explicit maintenance/migration tools, with a
  comment explaining the maintenance boundary.

### Phase 6: Server And HSS Cleanup

Detailed completed Phase 6 subtasks:

- [x] The ECDSA HSS bootstrap helpers and their AuthService registration/link-device/
  email-recovery callers now use `walletSessionUserId` internally. Remaining
  `nearAccountId` usage in that slice is isolated to lower signing-root/hosted-NEAR
  boundaries that still model NEAR account derivation inputs.
- [x] Server ECDSA `session_bootstrap` policy validation now parses exact lane
  identity in one place (`subjectId + chainTarget + sessionId +
  walletSigningSessionId + ecdsaThresholdKeyId`) and matches it directly
  against authenticated threshold-ECDSA session claims.
- [x] Persisted ECDSA integrated-key records and their exact-lane server checks
  now use `walletSessionUserId` naming at the typed server boundary, while the
  validation parser still accepts raw persisted `userId` as the compatibility
  readback field.
- [x] Persisted ECDSA signing-session, presign-session, and bootstrap-policy
  server shapes now use `walletSessionUserId` naming at their typed boundary,
  while the validation/request boundary still accepts raw legacy `userId`
  fields during readback.
- [x] The TypeScript ECDSA HSS wrapper context now uses
  `walletSessionUserId` at its typed boundary and passes that field into the
  WASM request payload. Ed25519 HSS remains account-scoped.
- [x] The Rust/WASM ECDSA HSS prepare-session argument now uses
  `walletSessionUserId`. Regenerating `wasm/hss_client_signer/pkg/**` is
  tracked below because later protocol-context changes made the package stale
  again.
- [x] Remaining ECDSA-only handler-local request inputs now use
  `walletSessionUserId` naming where they are fed directly from
  threshold-ECDSA claims, instead of carrying fresh local `userId`
  aliases through presign initialization.
- [x] The sponsored EVM server request/details flow now normalizes
  `walletId` at the request/readback boundary and keeps hosted-NEAR account
  refs only in the explicit spend-cap/account-ref helper.
- [x] The server HSS prepare route now uses a discriminated
  `ThresholdEcdsaHssPrepareRequest` union, so `session_bootstrap` requires
  `ecdsaThresholdKeyId` and `explicit_key_export` requires exact lane identity
  plus authenticated threshold-ECDSA session claims at the typed boundary.
- [x] Remaining ECDSA authorize/sign-init locals now use
  `walletSessionUserId` naming and keep generic `userId` only at the reused
  session-store write/read boundary.
- [x] ECDSA-only signing-root verification, bootstrap derivation, explicit
  export, and wallet-session mint helpers now take `walletSessionUserId`
  directly. The server TypeScript signing-root PRF adapter also uses
  `walletSessionUserId`; the Rust ecdsa-hss context and committed fixture
  keys now use `wallet_session_user_id`, `subject_id`, and `chain_target`.
  This intentionally changed the ECDSA HSS protocol vectors.
- [x] The remaining shared ECDSA session/auth store seam is now wrapped at the
  ThresholdSigningService boundary, so ECDSA callers and handlers consume
  `walletSessionUserId` even though the reused Ed25519 store rows still persist
  `userId` internally for compatibility.

- [x] Split Ed25519 HSS identity from ECDSA HSS identity.
  - [x] Keep Ed25519 HSS `nearAccountId` account-scoped.
  - [x] Move ECDSA HSS to stable EVM-family key identity plus concrete session
    policy:
    - [x] `walletSessionUserId` for audit/session scope at TS server/client
      boundaries.
    - [x] `subjectId` for ECDSA key identity in the HSS stable-key context.
    - [x] `keyScope = "evm-family"` in the HSS stable-key context, so all
      EVM-class signers share the same address for the same wallet, subject,
      RP, signing root, and key version.
    - [x] `chainTarget` in concrete session policy and signing requests.
    - [x] `ecdsaThresholdKeyId` in the HSS protocol context.
    - [x] `signingRootId` in the HSS protocol context.
    - [x] `signingRootVersion` in the HSS protocol context.
    - [x] `walletSigningSessionId` in concrete session policy.
    - [x] `thresholdSessionId` in concrete session policy.
  - [x] Update TS HSS wrapper types in
    `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`.
  - [x] Update Rust/WASM ECDSA HSS args in
    `wasm/hss_client_signer/src/threshold_hss.rs`.
  - [x] Regenerate `wasm/hss_client_signer/pkg/**` after the latest Rust
    ECDSA HSS context/envelope rename.

- [x] Update server ECDSA HSS request validation.
  - [x] Audit:
    - `server/src/core/ThresholdService/ThresholdSigningService.ts`
    - `server/src/core/ThresholdService/signingHandlers.ts`
    - `server/src/core/ThresholdService/validation.ts`
    - HSS prepare/finalize route handlers
  - [x] Validate exact lane identity, not wallet-only identity.
  - [x] Reject requests where token claims disagree with `subjectId`,
    `chainTarget`, session ids, or signing root.

  - [x] Keep hosted NEAR account ids only in hosted-account protocols.
  - [x] Audit `server/src/sponsorship/evm.ts`,
    `server/src/router/relaySponsoredEvmCall.ts`.
  - [x] Rename non-protocol EVM sponsorship identity to wallet/session naming.
  - [x] Add a short boundary comment at every retained `nearAccountIdHash`.

Phase 6 caveat:

- [x] Treat ECDSA HSS context-field changes as a protocol/key-material boundary
  change.
  - [x] Update vectors and fixtures for `subjectId + chainTarget`.
    - [x] Rename the current `ecdsa-hss` fixture context key from
      `near_account_id` to `wallet_session_user_id` without changing encoded
      vector bytes.
    - [x] Regenerate the committed `ecdsa-hss` fixture corpus after adding
      `subjectId` and EVM-family key scope to the HSS stable-key context.
    - [x] Delete the unused `ecdsa-hss/fixtures/protocol-v1.json` fixture that
      still carried the old context shape.
    - [x] Regenerate vectors again after session ids were removed from stable
      ECDSA HSS key derivation.
  - [x] Regenerate WASM package files after the latest Rust ECDSA HSS
    context/envelope rename. Use Homebrew LLVM when local Apple clang lacks the
    `wasm32-unknown-unknown` target:
    `CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build --target web --out-dir pkg`.
  - [x] Clear stale persisted artifacts if required by the final context binding.
    Manual wallet retest should start from cleared local wallet storage because
    the ECDSA HSS context and threshold-PRF `y_relayer` binding changed.

Phase 6 incremental validation on 2026-05-14:

```bash
cargo test --manifest-path crates/ecdsa-hss/Cargo.toml
cargo test --manifest-path crates/threshold-prf/Cargo.toml
cargo check --manifest-path wasm/threshold_prf/Cargo.toml
cargo check --manifest-path wasm/hss_client_signer/Cargo.toml
cargo check --manifest-path wasm/eth_signer/Cargo.toml
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts ./unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
```

WASM regeneration note:

- [x] `wasm/hss_client_signer/pkg/**`, `wasm/eth_signer/pkg/**`, and
  `wasm/threshold_prf/pkg/**` regenerate successfully when `CC` points at
  `/opt/homebrew/opt/llvm/bin/clang`.

### Phase 7: Delete Obsolete Compatibility Shapes

Detailed completed Phase 7 subtasks:

- [x] The ECDSA HSS explicit-export helper now takes
  `walletSessionUserId + subjectId + chainTarget` directly. Raw
  `nearAccountId` remains only in the broader mixed export-flow/UI boundary
  that still reports account-labeled events and return shapes.
- [x] The Email OTP ECDSA export-authorization helper now takes
  `walletSession` directly. Raw `nearAccountId` in that slice is now confined
  to the outer mixed export-flow boundary and NEAR-owned export branches.
- [x] The exact ECDSA export-lane model now carries `walletId` instead of
  `nearAccountId`, and the lane-selection/material lookup path uses that field
  only as wallet scope for exact ECDSA session/sealed-record resolution.
- [x] The Email OTP export-confirmation helper no longer asks ECDSA
  wallet-session callers for both `walletSession` and `nearAccountId`; the
  wallet-session branch now derives its UI/account label from
  `walletSessionUserId` locally.
- [x] The passkey ECDSA export-confirmation request helper now takes
  `walletSessionUserId` directly. The shared passkey export UI helper still
  formats an account label locally, but the ECDSA-specific request boundary no
  longer asks callers for `nearAccountId`.
- [x] The shared export step-up authorization model now splits NEAR and ECDSA
  identity by curve: NEAR export keeps `nearAccountId`, while ECDSA export
  carries `walletSessionUserId` instead of reusing the account-shaped field.
- [x] The ECDSA export viewer helper now also takes `walletSessionUserId`
  internally and normalizes an account label only at the final UI boundary.
- [x] The ECDSA export flow now takes `walletSessionUserId` for its internal
  wallet-session and policy wiring. The remaining `nearAccountId` usage in that
  shell is reduced to explicit viewer/event/account-label edges.
- [x] The public ECDSA bootstrap, presign-prefill, export, and iframe payload
  surfaces now require `walletSession + subjectId + chainTarget` or
  `walletSessionUserId + subjectId + chainTarget`; the final public
  `nearAccountId?: never` tripwire fields have been removed.
- [x] The first remaining ECDSA fixture helper slice is now on the new shape:
  the Tempo signing helper in `tests/helpers/thresholdEcdsaTempoFlow.ts` uses
  `walletSession + subjectId + chainTarget` instead of the old
  account-shaped sign call.
- [x] The sealed-refresh ECDSA helper now uses
  `walletSession + subjectId + chainTarget` for its Tempo signing path;
  bootstrap in that helper was already on the new shape.
- [x] The chain-signer unit fixture now calls `TempoSigner.signTempo` with
  `walletSession + subjectId + chainTarget` instead of the legacy
  account-shaped ECDSA args.
- [x] The chain-signer unit fixture now uses `nearAccount: NearAccountRef` for
  NEAR signer calls instead of raw `nearAccountId`.
- [x] The chain-signer unit lifecycle/report fixtures now use `walletSession`
  for Tempo broadcast-rejection reports and EVM-family transaction execution.
- [x] The high-level Tempo ECDSA browser fixtures now call
  `pm.tempo.signTempo` with `walletSession + subjectId + chainTarget`, and the
  local SDK build was refreshed so `/sdk/esm/*` browser tests exercise the new
  public shape.
- [x] Public SDK browser/e2e fixture call sites now use domain-shaped inputs:
  NEAR signer calls pass `nearAccount`, and Tempo sign/report/reconcile calls
  pass `walletSession` with `subjectId + chainTarget` where signing requires an
  exact ECDSA lane.

- [x] Delete ECDSA/Tempo/EVM overloads that accept `nearAccountId`.
  - [x] `BootstrapThresholdEcdsaSessionArgs`
  - [x] EVM/Tempo bootstrap facade args
  - [x] ECDSA presign prefill args
  - [x] ECDSA export/recovery args
  - [x] ECDSA iframe payloads

- [x] Replace SDK/app boundary derivation with explicit hosted-wallet adapters.
  - [x] No `toWalletId(nearAccountId)` outside approved boundary
    adapters.
  - [x] No ECDSA core helper accepts `nearAccountId` and internally derives
    `subjectId`.

- [x] Rewrite tests and fixtures by domain.
  - [x] NEAR tests use `nearAccount: NearAccountRef`.
  - [x] ECDSA/Tempo/EVM tests use `walletSession + subjectId + chainTarget`.
  - [x] Delete fixtures whose only purpose is old account-shaped ECDSA
    compatibility.
    Public SDK/browser fixtures no longer exercise account-shaped ECDSA
    compatibility calls. Remaining `nearAccountId` fixtures are NEAR-owned,
    export UI/account-label boundaries, or persisted-record compatibility.

- [x] Decide when to remove `nearAccountId?: never` fields.
  - [x] Keep them while old callers are still being flushed out.
  - [x] Remove them only after guards prove there are no old call sites.

Phase 7 caveat:

- [x] Keep `nearAccountId?: never` as a compile-time tripwire until the final
  ratchet.
  - [x] Remove it only when the public API should stop mentioning the legacy
    field name entirely.

### Phase 8: Add Static Guards

- [x] Add path-only guards for ECDSA-only forbidden directories.
  - [x] Fail on new or count-increased `nearAccountId` residue in:
    - `flows/signEvmFamily/**`
    - `nonce/**`
    - `session/budget/**`
    - `threshold/ecdsa/**`
    - `workerManager/workers/**` ECDSA payload branches
    - `wasm/hss_client_signer/**` ECDSA HSS branches

- [x] Add structural guards for mixed files.
  - [x] `SeamsPasskey/interfaces.ts`: ECDSA args must require
    `walletSession`, `subjectId`, `chainTarget`.
  - [x] `WalletIframe/shared/messages.ts`: ECDSA iframe payloads must not
    expose `nearAccountId`.
  - [x] `SigningEngine.ts`: public ECDSA methods must not derive subject from
    account.
  - [x] Recovery flows: ECDSA export uses subject identity; NEAR export keeps
    account identity.

- [x] Add allowlists with expiry notes.
  - [x] Separate allowed NEAR-account usage from temporary ECDSA cleanup
    residue.
  - [x] Store allowlist entries as file + occurrence count.
  - [x] Require a checklist item for deleting each temporary allowlist entry.

- [x] Delete temporary forbidden-path allowlist entries.
  - [x] `client/src/core/SeamsPasskey/evm/index.ts` (1)
  - [x] `client/src/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.ts` (13)
  - [x] `client/src/core/SeamsPasskey/tempo/index.ts` (1)
  - [x] `client/src/core/signingEngine/chains/evm/ethSignerWasm.ts` (6)
  - [x] `client/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts` (9)
  - [x] `client/src/core/signingEngine/session/warmCapabilities/persistence.ts` (4; reclassified as NEAR-owned Ed25519)
  - [x] `client/src/core/signingEngine/session/warmCapabilities/persistence.typecheck.ts` (1; reclassified as NEAR-owned Ed25519)
  - [x] `client/src/core/signingEngine/session/warmCapabilities/statusReader.ts` (10; reclassified as NEAR-owned Ed25519)
  - [x] `client/src/core/signingEngine/session/warmCapabilities/types.ts` (4; reclassified as NEAR-owned Ed25519)
  - [x] `client/src/core/signingEngine/threshold/ecdsa/activation.ts` (7)
  - [x] `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts` (3)
  - [x] `client/src/core/signingEngine/threshold/ecdsa/clientSecretSource.ts` (1)
  - [x] `client/src/core/signingEngine/workerManager/workerTypes.ts` (1)
  - [x] `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts` (2)
  - [x] `client/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts` (4)
  - [x] `server/src/core/ThresholdService/ethSignerWasm.ts` (3 remaining;
    6 removed)

- [x] Add type fixtures.
  - [x] ECDSA command with `nearAccountId` fails.
  - [x] NEAR command without `nearAccount` fails.
  - [x] ECDSA HSS request without `subjectId + chainTarget` fails.
    Server-side HSS prepare type fixtures now reject session bootstrap without
    lane identity in `sessionPolicy` and explicit export without direct
    `subjectId + chainTarget`; the Refactor 36 guard also checks the
    client/server HSS prepare type declarations.
  - [x] Budget finalization from wallet-only identity fails.

Phase 8 caveat:

- [x] Keep regex guards narrow in mixed or generated surfaces.
  - [x] Do not fail on comments, docs, generated WASM bindings, or NEAR-owned
    branches.
  - [x] For Rust/WASM, guard only ECDSA HSS functions; Ed25519 HSS and
    `wasm/near_signer/**` remain account-scoped.

Phase 8 validation on 2026-05-14:

```bash
pnpm -C tests exec playwright test ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts ./unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts --reporter=line
pnpm -C sdk exec tsc -p tsconfig.build.json --noEmit
pnpm -C sdk build:rolldown
cargo check --manifest-path wasm/hss_client_signer/Cargo.toml
cargo check --manifest-path wasm/eth_signer/Cargo.toml
git diff --check
```

Local caveat: `wasm-pack build --target web --out-dir pkg` for
`wasm/hss_client_signer` and `wasm/eth_signer` is currently blocked in this
workspace because the local `clang` cannot create a compatible
`wasm32-unknown-unknown` target for `blst`. Native Rust checks pass, and the
existing generated JS/WASM package exposes the `walletSessionUserId` public
boundary used by the focused tests.

Path-only allowed production paths:

```text
client/src/core/accountData/near/**
client/src/core/SeamsPasskey/near/**
client/src/core/signingEngine/flows/signNear/**
client/src/core/rpcClients/near/**
client/src/core/signingEngine/chains/near/**
client/src/core/signingEngine/assembly/ports/near.ts
client/src/core/signingEngine/workerManager/nearKeyOps/**
client/src/utils/emailRecovery/**
shared/src/utils/near.ts
shared/src/utils/recoveryEmail.ts
shared/src/utils/recoveryDomain.ts
wasm/near_signer/**
server/src/core/hostedAccountIds.ts
server/src/core/*Recovery*
server/src/email-recovery/**
server/src/router/*Recovery*
server/src/router/recoveryExecutionTracking.ts
```

Path-only forbidden production paths:

```text
client/src/core/SeamsPasskey/evm/**
client/src/core/SeamsPasskey/tempo/**
client/src/core/signingEngine/flows/signEvmFamily/**
client/src/core/signingEngine/nonce/**
client/src/core/signingEngine/session/budget/**
client/src/core/signingEngine/session/warmCapabilities/**
client/src/core/signingEngine/chains/evm/**
client/src/core/signingEngine/threshold/ecdsa/**
client/src/core/signingEngine/workerManager/workers/**
client/src/core/signingEngine/workerManager/workerTypes.ts
client/src/core/rpcClients/evm/**
server/src/core/ThresholdService/ethSignerWasm.ts
wasm/hss_client_signer/**
```

Mixed files that need structural guards:

```text
client/src/core/SeamsPasskey/index.ts
client/src/core/SeamsPasskey/interfaces.ts
client/src/core/SeamsPasskey/login.ts
client/src/core/SeamsPasskey/registration.ts
client/src/core/SeamsPasskey/thresholdWarmSessionBootstrap.ts
client/src/core/SeamsPasskey/walletIframeCoordinator.ts
client/src/core/WalletIframe/shared/messages.ts
client/src/core/WalletIframe/client/router.ts
client/src/core/WalletIframe/SeamsPasskeyIframe.ts
client/src/core/WalletIframe/host/wallet-iframe-handlers.ts
client/src/core/signingEngine/SigningEngine.ts
client/src/core/signingEngine/assembly/ports/shared.ts
client/src/core/signingEngine/assembly/ports/evmFamily.ts
client/src/core/signingEngine/assembly/ports/warmSigning.ts
client/src/core/signingEngine/interfaces/operationDeps.ts
client/src/core/signingEngine/session/persistence/records.ts
client/src/core/signingEngine/session/passkey/**
client/src/core/signingEngine/session/emailOtp/**
client/src/core/signingEngine/flows/recovery/**
client/src/core/signingEngine/uiConfirm/**
client/src/core/signingEngine/stepUpConfirmation/**
client/src/react/**
server/src/core/ThresholdService/ThresholdSigningService.ts
server/src/core/ThresholdService/signingHandlers.ts
server/src/core/ThresholdService/validation.ts
server/src/router/relaySponsoredEvmCall.ts
server/src/sponsorship/evm.ts
```

Guard checks:

- [x] ECDSA/Tempo/EVM public inputs do not contain `nearAccountId`.
- [x] ECDSA iframe payloads do not contain `nearAccountId`.
- [x] ECDSA worker payloads do not contain `nearAccountId`.
- [x] ECDSA HSS prepare/finalize requests use `walletSessionUserId` and
  `subjectId`.
- [x] ECDSA nonce and budget identities do not contain `nearAccountId`.
- [x] No production core ECDSA code calls `toWalletId(args.nearAccountId)`.
- [x] Refactor-36 raw identity parsing allowlists stay finite and avoid becoming a
  compatibility sink for account-shaped ECDSA identity.

## Migration Order

- [x] Public SDK and iframe ECDSA command inputs.
- [x] Email OTP ECDSA capability and worker messages.
- [x] Tempo/EVM signing orchestration and nonce/budget types.
- [x] Wallet session APIs and React context naming.
- [x] Server HSS metadata naming.
- [x] Tests, fixtures, docs, and architecture guards.

This order makes TypeScript expose the account-shaped call chain early while
keeping NEAR transaction signing stable.

## Acceptance Criteria

- [x] `nearAccountId` appears only in NEAR-specific code and explicit hosted NEAR
  account metadata.
- [x] ECDSA/Tempo/EVM public SDK inputs require `walletSession`, `subjectId`, and
  `chainTarget`.
- [x] ECDSA/Tempo/EVM iframe and worker payloads require `subjectId` and
  `chainTarget`.
- [x] ECDSA HSS requests distinguish `walletSessionUserId` from `subjectId`.
- [x] ECDSA stores, snapshots, nonce lanes, budget identity, restore, export, and
  signing use `subjectId + chainTarget`.
- [x] No core ECDSA path derives `subjectId` from `nearAccountId`.
- [x] NEAR transaction signing still uses `NearAccountRef`.
- [x] Architecture guards enforce the allowed and forbidden surfaces.

## Verification

Run these after each phase:

```sh
pnpm -C tests exec playwright test ./unit/signingEngine.refactor33.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/evmFamily.requestBoundary.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/seamsPasskey.chainSigners.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/seamsPasskey.emailOtpIframe.unit.test.ts --reporter=line
pnpm -w run type-check:sdk
```

- [x] Final pre-manual verification passed on 2026-05-14.
- [x] `signingEngine.refactor33.guard.unit.test.ts`
- [x] `signingEngine.refactor36.guard.unit.test.ts`
- [x] `evmFamily.requestBoundary.unit.test.ts`
- [x] `seamsPasskey.chainSigners.unit.test.ts`
- [x] `seamsPasskey.emailOtpIframe.unit.test.ts`
- [x] HSS/signing-root vector tests:
  `thresholdPrfWasm.script.unit.test.ts`,
  `thresholdSigningRootParityBaseline.script.unit.test.ts`,
  `signingRootSecretResolver.script.unit.test.ts`,
  `signingRootShareResolver.script.unit.test.ts`,
  `thresholdEcdsa.signingRootResolver.script.unit.test.ts`, and
  `thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts`
- [x] `pnpm -w run type-check:sdk`
- [x] `git diff --check`

Compliance follow-up on 2026-05-14:

- [x] Email OTP ECDSA export authorization uses `wallet_session_export_auth`;
  `near_account_export_auth` is NEAR/Ed25519-only.
- [x] Client-side ECDSA HSS session policies use `walletSessionUserId` instead
  of `userId`, including link-device and Email OTP bootstrap paths.
- [x] Trusted budget-status lookup no longer scans ECDSA runtime lanes by
  derived subject when no exact target threshold session ids are supplied.
- [x] Added refactor-36 guards for the three compliance regressions above.
- [x] Focused compliance verification passed:
  `signingEngine.refactor36.guard.unit.test.ts`,
  `evmFamily.requestBoundary.unit.test.ts`,
  `thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`, and
  `privateKeyExportRecovery.binding.unit.test.ts`.
- [x] Remaining post-fix pre-manual verification passed:
  `signingEngine.refactor33.guard.unit.test.ts`,
  `seamsPasskey.chainSigners.unit.test.ts`,
  `seamsPasskey.emailOtpIframe.unit.test.ts`,
  `pnpm -w run type-check:sdk`, and `git diff --check`.
- [x] Email OTP coordinator fixtures now assert wallet-shaped sealed-session
  lookup args; `emailOtpThresholdSessionCoordinator.unit.test.ts` passes.
- [x] Email OTP coordinator sealed-session fixtures now use a typed current-record
  builder; `pnpm -w run type-check:sdk` passes again after the fixture cleanup.
- [x] Hot maintenance/recovery paths no longer derive ECDSA subject identity from
  wallet id: post-sign Email OTP consumption, exhausted-lane cleanup, warm-session
  clearing, passkey sealed recovery, and canonical threshold-session lookup now
  carry `subjectId` from the selected lane, sealed record, or key ref.

Manual smoke matrix pending browser validation:

- [ ] Passkey registration.
- [ ] Email OTP wallet unlock.
- [ ] NEAR Ed25519 transaction signing.
- [ ] Tempo/EVM ECDSA transaction signing.
- [ ] NEAR Ed25519 key export.
- [ ] ECDSA key export.
- [ ] Session exhaustion and same-method step-up for passkey and Email OTP.
