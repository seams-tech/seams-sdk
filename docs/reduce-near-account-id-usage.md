# Reduce NEAR Account ID Usage

Date created: 2026-05-06
Status: proposed

## Purpose

The SDK still uses `nearAccountId` as a general wallet/session/profile
identifier in many places. That makes ECDSA, Tempo, EVM, auth, iframe routing,
and UI flows look NEAR-specific even when the operation is protocol-neutral or
EVM-family-specific.

This refactor limits `nearAccountId` to NEAR account operations. Wallet/session
identity, ECDSA lane identity, audit scope, and UI display labels should have
separate names and types.

## Goals

1. Make `nearAccountId` mean a NEAR chain account only.
2. Move wallet/session identity to explicit wallet/session types.
3. Move ECDSA identity to `WalletSubjectId + ThresholdEcdsaChainTarget`.
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
| ECDSA lane principal | protocol-neutral subject | `subjectId: WalletSubjectId` |
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
3. ECDSA/Tempo/EVM usage that should move to `WalletSubjectId +
   ThresholdEcdsaChainTarget`, with wallet session data passed separately.

Several files are mixed surfaces. For example, wallet iframe message definitions
and host handlers contain both NEAR commands and ECDSA commands. Static guards
there need type-aware checks for specific payload names alongside path-only
searches.

## Target Vocabulary

```ts
export type WalletId = string & { readonly __brand: 'WalletId' };

export type WalletSubjectId = string & { readonly __brand: 'WalletSubjectId' };

export type WalletSessionRef = {
  walletId: WalletId;
  walletSessionUserId: string;
};

export type NearAccountRef =
  | { kind: 'named'; accountId: AccountId }
  | { kind: 'implicit'; accountId: AccountId };

export type EcdsaCommandSubject = {
  walletSession: WalletSessionRef;
  subjectId: WalletSubjectId;
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
3. `WalletSubjectId` is the only ECDSA lane principal.
4. ECDSA commands always require `subjectId + chainTarget`.
5. Wallet/session code may map the current hosted wallet profile to a
   `WalletSubjectId` once at the app/session boundary.
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
`WalletSubjectId`, or an explicit display label.

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
8. Smart-account deployment identity. NEAR account hashes may remain only as
   explicit hosted-account metadata when the server protocol requires them.

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
   `WalletSubjectId`, `NearAccountRef`, `nearAccountRefFromAccountId(...)`, and
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
   direct `toWalletSubjectId(nearAccountId)` calls in the SDK facade,
   `SigningEngine.ts`, `session/public.ts`, availability/readiness,
   warm-capability cleanup/status, email-OTP companion sessions, recovery lane
   selection, and assembly shared ports.

## Refactor Area Inventory

| Area | Exact-hit files | Required refactor |
| --- | ---: | --- |
| Tests | 167 | Rewrite fixtures and assertions to use `nearAccount` for NEAR flows, `walletSession + subjectId + chainTarget` for ECDSA flows, and add guards for forbidden payload fields. |
| Server | 35 | Split hosted NEAR account flows from wallet/session identity in ThresholdService, HSS route handlers, sponsorship, smart-account deploy, recovery, and registration routes. |
| EVM-family signing flows | 30 | Replace `nearAccountId` in `flows/signEvmFamily/**`, including auth planning, ECDSA material state, nonce lifecycle, budget spending, prepared signing, smart-account deployment, signing flow runtime, and transaction execution. |
| SDK facade: `client/src/core/SeamsPasskey/**` | 23 | Rename public EVM/Tempo/auth inputs, stop deriving `subjectId` from `nearAccountId`, and keep NEAR account refs only under `near/**` and account creation/recovery flows. |
| Signing engine other | 20 | Update `SigningEngine.ts`, threshold modules, EVM chain signer bridge, nonce coordinator, WebAuthn auth, user preferences, and remaining top-level session entrypoints. |
| Examples and demo site | 19 | Update sample apps, docs snippets, demo hooks, login bridges, profile settings, and Tempo/EVM action hooks to model wallet/session identity separately from NEAR account display. |
| UI confirm | 16 | Split confirmation request data into NEAR account display for NEAR operations and wallet/subject display for ECDSA export, Tempo, EVM, and signing-session prompts. |
| React package | 16 | Rename login state, context values, `getWalletSession(...)`, refresh callbacks, account input, account menu, linked devices, QR, and passkey menu data to use wallet/session names where the UI is wallet-scoped. |
| Docs | 14 | Update conceptual docs, smart-account docs, nonce docs, OTP privacy docs, deployment docs, refactor docs, and registration-flow docs after the API shape changes. |
| Warm capabilities | 14 | Move ECDSA warm-capability read models, status readers, provision plans, persistence, sealed-refresh parity, login prefill, and cleanup from account identity to `subjectId + chainTarget`. |
| Recovery flows | 13 | Split ECDSA export/recovery lane selection and HSS export from NEAR Ed25519 export/recovery. ECDSA export should receive wallet/session and subject identity directly. |
| Passkey session | 12 | Move ECDSA bootstrap/provision/recovery/warm-capability paths away from account-derived subjects while keeping Ed25519 provision/recovery account-scoped. |
| Email OTP session | 10 | Split ECDSA bootstrap, provisioning, companion sessions, export recovery, and worker requests from Ed25519 account recovery and local metadata. |
| Wallet iframe protocol | 9 | Update shared payload types, client router, iframe wrapper, host handlers, login-status events, preferences events, and route initialization to use wallet/session fields for non-NEAR flows. |
| WASM bindings | 8 | Keep NEAR signer/Ed25519 bindings account-scoped; update HSS client signer and ECDSA bridge payloads that use account strings as wallet/session identity. |
| NEAR signing flows | 8 | Keep `flows/signNear/**` account-scoped; rename only generic wallet/session helpers that leaked in. |
| Contracts | 7 | Keep or rename `nearAccountIdHash` only where it is part of the smart-account recovery protocol, with boundary comments and matching server manifest names. |
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

1. Extend the existing identity surface. `WalletSubjectId`, `NearAccountRef`,
   and `nearAccountRefFromAccountId(...)` already exist in
   `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`.
2. Add `WalletId`, `WalletSessionRef`, `NearCommandSubject`, and
   `EcdsaCommandSubject`.
3. Add boundary constructors:
   - `walletIdFromSessionValue(...)`
   - `walletSessionRefFromSession(...)`
   - `nearAccountRefFromAccountId(...)`
   - `walletSubjectIdFromWalletProfile(...)`
4. Keep constructors at app/SDK/iframe/server route boundaries.
5. Forbid new `toWalletSubjectId(nearAccountId)` calls in core ECDSA code.
6. Move any account-to-subject derivation that remains in the app/demo layer
   behind an explicitly named hosted-wallet profile adapter.

### Phase 2: Rename Wallet Session APIs

1. Replace `getWalletSession(nearAccountId?)` with
   `getWalletSession(walletId?)`.
2. Replace `currentNearAccountId` React state with `currentWalletId`.
3. Replace iframe login status fields:
   - `nearAccountId` -> `walletId`
   - add `nearAccount?: NearAccountRef` only when UI needs the NEAR projection.
4. Rename wallet iframe routing args from `nearAccountId` to `walletId`.
5. Update preferences/current-user storage to use `walletId`.

### Phase 3: Split NEAR Public Commands From ECDSA Commands

1. Move NEAR signing inputs to `nearAccount: NearAccountRef`.
2. Move Tempo/EVM signing inputs to `walletSession + subjectId + chainTarget`.
3. Delete `nearAccountId` from:
   - `SignTempoArgs`
   - `ExecuteEvmFamilyTransactionArgs`
   - Tempo/EVM iframe payloads
   - EVM-family signing orchestration inputs
4. Keep NEAR account refs in NEAR transaction signing, NEP-413, intent digest,
   add-key, and link-device owner operations.

### Phase 4: Split Email OTP Wallet Unlock From ECDSA Capability

1. Model wallet unlock as a wallet-session operation:
   ```ts
   loginWithEmailOtp({ walletSession, otpCode, challengeId })
   ```
2. Model ECDSA capability bootstrap as an ECDSA subject operation:
   ```ts
   loginWithEmailOtpEcdsaCapability({
     walletSession,
     subjectId,
     chainTarget,
     otpCode,
     challengeId,
   })
   ```
3. Delete any Email OTP ECDSA worker payload that accepts `nearAccountId`.
4. HSS prepare receives:
   - `walletSessionUserId` for session/audit scope
   - `subjectId` for ECDSA lane identity
   - `chainTarget` for concrete chain identity

### Phase 5: Move ECDSA Stores And Nonce To Subject Identity

1. Ensure ECDSA runtime and persisted records use `subjectId + chainTarget`.
2. Ensure durable sealed ECDSA records use `subjectId + chainTarget`.
3. Ensure warm-capability read models, status readers, provision plans, and
   cleanup use `subjectId + chainTarget`.
4. Ensure managed nonce lanes and snapshots use `subjectId + chainTarget`.
5. Ensure budget identity and finalization use the selected `subjectId`.
6. Delete account-keyed ECDSA cleanup and inventory helpers.
7. Keep account-wide scans only in explicit maintenance/migration tools, with a
   comment explaining the maintenance boundary.

### Phase 6: Server And HSS Cleanup

1. Rename server HSS account context to `walletSessionUserId`.
2. Validate ECDSA lane identity with `subjectId + chainTarget +
   ecdsaThresholdKeyId + signingRoot + session ids`.
3. Keep NEAR account IDs only in server flows that create, recover, or operate
   on hosted NEAR accounts.
4. Rename smart-account records that use NEAR account data as metadata:
   - `nearAccountIdHash` remains acceptable only when it is part of the on-chain
     hosted-account derivation protocol.
   - add comments at those protocol boundaries.

### Phase 7: Delete Obsolete Compatibility Shapes

1. Delete overloads that accept `nearAccountId` for ECDSA/Tempo/EVM commands.
2. Delete adapters that convert `nearAccountId` to `subjectId` inside core
   signing code.
3. Rewrite tests and fixtures to use `walletSession`, `subjectId`, and
   `nearAccount` explicitly.
4. Delete legacy test fixtures that preserve account-shaped ECDSA calls.

### Phase 8: Add Static Guards

Add architecture guards that fail when `nearAccountId` appears in forbidden
surfaces.

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
contracts/evm-smart-account/**
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
server/src/router/evmSmartAccountDeploy.ts
server/src/sponsorship/evm.ts
```

Guard checks:

1. ECDSA/Tempo/EVM public inputs do not contain `nearAccountId`.
2. ECDSA iframe payloads do not contain `nearAccountId`.
3. ECDSA worker payloads do not contain `nearAccountId`.
4. ECDSA HSS prepare/finalize requests use `walletSessionUserId` and
   `subjectId`.
5. ECDSA nonce and budget identities do not contain `nearAccountId`.
6. No production core ECDSA code calls `toWalletSubjectId(args.nearAccountId)`.
7. Refactor-36 raw identity parsing allowlists stay finite and avoid becoming a
   compatibility sink for account-shaped ECDSA identity.

## Migration Order

1. Public SDK and iframe ECDSA command inputs.
2. Email OTP ECDSA capability and worker messages.
3. Tempo/EVM signing orchestration and nonce/budget types.
4. Wallet session APIs and React context naming.
5. Server HSS and smart-account metadata naming.
6. Tests, fixtures, docs, and architecture guards.

This order makes TypeScript expose the account-shaped call chain early while
keeping NEAR transaction signing stable.

## Acceptance Criteria

1. `nearAccountId` appears only in NEAR-specific code and explicit hosted NEAR
   account metadata.
2. ECDSA/Tempo/EVM public SDK inputs require `walletSession`, `subjectId`, and
   `chainTarget`.
3. ECDSA/Tempo/EVM iframe and worker payloads require `subjectId` and
   `chainTarget`.
4. ECDSA HSS requests distinguish `walletSessionUserId` from `subjectId`.
5. ECDSA stores, snapshots, nonce lanes, budget identity, restore, export, and
   signing use `subjectId + chainTarget`.
6. No core ECDSA path derives `subjectId` from `nearAccountId`.
7. NEAR transaction signing still uses `NearAccountRef`.
8. Architecture guards enforce the allowed and forbidden surfaces.

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

Manual smoke matrix:

1. Passkey registration.
2. Email OTP wallet unlock.
3. NEAR Ed25519 transaction signing.
4. Tempo/EVM ECDSA transaction signing.
5. NEAR Ed25519 key export.
6. ECDSA key export.
7. Session exhaustion and same-method step-up for passkey and Email OTP.
