# Refactor 104 — Router Folder Organisation

## Status

Planned, not started. Blocked on
[refactor-94C-regression-fixes.md](./refactor-94C-regression-fixes.md) landing:
~15 files under `packages/sdk-server-ts/src/router` are modified on that
branch, and this refactor must start from a clean tree so every phase stays a
reviewable rename-only (or extraction-only) diff.

This refactor changes **no behaviour**. Phases 1–2 are small code extractions
that fix layering inversions; Phases 3–6 are `git mv` plus mechanical import
updates. Anything that would change runtime behaviour is out of scope.

## Problem

`src/router` holds ~130 files whose architecture is real but invisible: 70
files sit flat at the top level, grouped only by filename prefix
(`routerAbEd25519Yao*` alone is 20 modules), and the `cloudflare/` directory
conflates two different layers — the web-standard fetch router and the D1
persistence implementations.

The actual hierarchy, recovered from the import graph:

```
adaptors (express-adaptor, cloudflare-adaptor, ror-adaptor)   ← public entry points
  └─ cloudflare/createCloudflareRouter + cloudflare/routes/*  ← fetch-Request wiring
       └─ top-level handler/service modules                   ← host-agnostic domain logic
            └─ cloudflare/d1* Records/Store/Service/Boundary  ← D1 persistence impls
```

Specific defects:

1. **Prefixes doing folders' jobs.** `routerAbEd25519Yao*` (20 files),
   `emailOtp*` (4), `*RequestValidation` (8), `route*` framework files (8),
   `routerApi*` (6) — all flat.
2. **`cloudflare/http.ts` is not Cloudflare-specific.** It is generic fetch-API
   helpers (`json()`, CORS, `readJson`) with fan-in 22, which is why seven
   host-agnostic core modules import upward into `cloudflare/`, and why
   `express-adaptor.ts` depends on `cloudflare/createCloudflareRouter` (the
   "Cloudflare router" is really a web-standard fetch router).
3. **15 upward edges from core into `cloudflare/`** (inventory below). While
   these exist, no folder layout can honestly express the layering.
4. **Name collision inverts apparent parent/child.** Top-level
   `walletRegistrationRoutes.ts` (2,600 lines) is the handler *service*;
   `cloudflare/routes/walletRegistration.ts` is the wiring that *calls* it.
5. The `d1Xxx{Records,Store,Service,Boundary}` convention inside `cloudflare/`
   is good but buried: 55 flat files, 12 of them `d1EmailOtp*`.

## Target structure

Root-level files are the outermost layer (entry points); depth in the tree
mirrors depth in the call hierarchy.

```
router/
  express-adaptor.ts          # public entry points stay at root — the top of
  cloudflare-adaptor.ts       # the hierarchy, and package.json exports point
  ror-adaptor.ts              # at their dist paths
  ror/                        # unchanged

  framework/                  # host-agnostic route machinery (no domain logic)
  auth/                       # API-credential + wallet-session authentication
  domains/                    # host-agnostic handler/service modules, one
    walletRegistration/       # folder per lifecycle domain
    walletUnlock/
    emailOtp/
    emailRecovery/
    syncAccount/
    ed25519Yao/
      registration/  productRegistration/  recovery/  export/  session/
    ecdsa/
    normalSigning/

  hosts/
    cloudflare/
      router/                 # createCloudflareRouter, registerCloudflareRoute,
        routes/               # cloudflare.types, self-hosted worker, email
      d1/                     # persistence impls, subfolders mirroring domains/
        emailOtp/  registration/  session/  identity/  oidc/  webauthn/
        auth/  wallet/  ed25519Yao/  near/  versionedJson/
      durableObjects/
```

### Layering rule (enforceable after Phase 2)

- `framework/` imports nothing from `auth/`, `domains/`, or `hosts/`.
- `auth/` and `domains/` import `framework/` and `../core`, never `hosts/`.
- `hosts/cloudflare/` imports anything above it.
- Root adaptors import anything.

Once true, this is a candidate for a directory-level lint rule (dependency
direction by path depth) rather than a new source-text guard — per the
[refactor-88B](./refactor-88B-clean-source-guards.md) preference for
structural checks over source greps.

## Inversion inventory

All 15 current core → `cloudflare/` edges, with disposition:

| # | Edge | Disposition |
| - | ---- | ----------- |
| 1–7 | `routerAbEd25519Yao{Registration, Recovery, Export, ExportRequestScopedCloudflare, RecoveryRequestScopedCloudflare, RecoveryWalletSessionAuthorization, RegistrationRequestScopedCloudflare}` → `cloudflare/http` | Fixed by Phase 1 (move `http.ts` to `framework/`) |
| 8–11 | `routerAbEd25519Yao{RegistrationSideEffectBoundary, RegistrationExecutionRecord, ProductRegistrationPartitionedStateStore, ProductRegistrationPersistence}` → `cloudflare/versionedJsonRecordStore` | Phase 2: the port types are host-neutral in shape; extract them to `domains/ed25519Yao/productRegistration/` (or `framework/`), leaving the DO-typed impl in `hosts/` |
| 12 | `routerAbEd25519YaoProductRegistrationPartitionedStateStore` → `cloudflare/d1VersionedJsonRecordStore` (type-only: options/patch types) | Phase 2: move those type declarations to the extracted port module |
| 13 | `authServicePort` → `cloudflare/d1WalletRegistrationSetup` (type-only: `WalletRegistrationSetupInput`, `WalletRegistrationRespondInput`) | Phase 2: move the input types into `auth/` or `domains/walletRegistration/`; the D1 module imports them back |
| 14 | `routerAbEd25519YaoExport` → `cloudflare/d1WalletAuthMethodBoundary` (value: WebAuthn credential codecs) | Phase 2: the codecs are D1-independent parsing helpers; move them to `auth/` or `domains/` and re-export from the boundary |
| 15 | `express-adaptor` → `cloudflare/createCloudflareRouter` | **By design.** The Express adaptor converts Node requests to fetch Requests and delegates to the fetch router. After Phase 4 this edge reads `express-adaptor` → `hosts/cloudflare/router/`, which is the honest description. |

## Phases

Each phase is one commit (or a small stack), independently green. Rename-only
phases must contain no logic edits; extraction phases must contain no renames
beyond the extracted module.

### Phase 0 — Preconditions

- 94C merged; clean worktree on a fresh branch.
- Record the baseline: `pnpm check`, `pnpm test:unit`,
  `pnpm test:source-guards` all green.

### Phase 1 — `http.ts` out of `cloudflare/` (extraction, kills edges 1–7)

Move `cloudflare/http.ts` → `framework/http.ts` (module content unchanged; it
already has no Cloudflare types). Update ~22 importers. This can land before
any other phase and is worth doing even if the rest stalls.

### Phase 2 — Port/type extractions (kills edges 8–14)

Three small extractions, one commit each:

1. Versioned-JSON record-store port types out of
   `cloudflare/versionedJsonRecordStore.ts` / `d1VersionedJsonRecordStore.ts`
   into a host-neutral port module; Cloudflare impls import the port, not the
   reverse.
2. `WalletRegistrationSetupInput` / `WalletRegistrationRespondInput` out of
   `d1WalletRegistrationSetup.ts` into the auth/registration domain.
3. WebAuthn credential codecs out of `d1WalletAuthMethodBoundary.ts`.

After this phase the only upward edge is the by-design adaptor edge (#15).

### Phase 3 — Top-level regrouping (`git mv` only)

Create `framework/`, `auth/`, `domains/` and move the ~70 top-level files per
the move map below. `.typecheck.ts` twins move with their module. No basename
changes.

### Phase 4 — Split `cloudflare/` into `hosts/cloudflare/{router,d1,durableObjects}`

`git mv` only. `d1/` gains domain subfolders mirroring `domains/`.

### Phase 5 — Entry points and public surface

Adaptors stay at `router/` root (no dist-path churn), but verify:

- `package.json` `exports` still resolve
  (`dist/types/sdk-server-ts/src/router/*-adaptor.d.ts`).
- `tests/unit/packageExports.contract.unit.test.ts` — references the three
  adaptor dist paths plus
  `src/router/cloudflare/cloudflare.types.ts`; the latter moves in Phase 4 and
  the contract test updates with it.

### Phase 6 — Guard repair / retirement

`tests/scripts/*.mjs` contains **93** hardcoded `src/router/...` path
references. For each broken guard, apply the
[refactor-88B](./refactor-88B-clean-source-guards.md) decision rule: repoint if
the invariant is live, retire if the guard asserts a source shape this
refactor legitimately changed. Do not contort the new layout to satisfy a
stale guard.

### Phase 7 (optional, separate PR) — Basename de-prefixing

Inside `domains/ed25519Yao/registration/`, names like
`routerAbEd25519YaoRegistrationIntentAuthorization.ts` can shrink to
`intentAuthorization.ts` since the path now carries the context. Deliberately
excluded from Phases 3–4 so move diffs stay `git mv`-clean. Skip entirely if
churn outweighs the readability gain.

## Move map — top level

| Destination | Files |
| ----------- | ----- |
| `framework/` | `routeDefinitions` (+typecheck), `routeExecutionContext`, `routeResponses`, `routeExtensions`, `routeRequestValidation`, `routeAuthPolicy`, `routeMeteringPolicy`, `applyRouteMetering`, `enforceRoutePolicy`, `modules`, `logger`, `commonRouterUtils`, `routerApi`, `routerApiRouteSurface`, `routerApiOptions.typecheck`, `routerCommand.typecheck`, `runtimeSnapshotConsumer`, `http` (from Phase 1) |
| `auth/` | `authServicePort`, `authRequestValidation`, `routerApiKeyAuth`, `routerApiCredentialAuth`, `apiCredentialPorts`, `verifiedWalletSessionAuth` (+typecheck), `walletSessionFailure`, `sessionExchangeRequestValidation` |
| `domains/walletRegistration/` | `walletRegistrationRoutes`, `walletRegistrationSetupPayload` |
| `domains/walletUnlock/` | `walletUnlockRouteHandlers`, `walletUnlockEd25519YaoRequestValidation` |
| `domains/emailOtp/` | `emailOtpRouteHandlers`, `emailOtpSessionRouteHelpers`, `emailOtpExportPolicy`, `emailOtpRequestValidation` |
| `domains/emailRecovery/` | `emailRecoveryRequestValidation`, `recoveryExecutionTracking` |
| `domains/syncAccount/` | `syncAccountRequestValidation` |
| `domains/ed25519Yao/registration/` | `routerAbEd25519YaoRegistration`, `…RegistrationExecutionRecord`, `…RegistrationIntentAuthorization`, `…RegistrationRequestScopedCloudflare`, `…RegistrationSideEffectBoundary` (+typecheck), `…RegistrationTwoPhaseRunner`, `…HttpRegistrationBackend` |
| `domains/ed25519Yao/productRegistration/` | `routerAbEd25519YaoProductRegistration` (+typecheck), `…Partitioning`, `…PartitionedStateStore`, `…Persistence`, `…RequestScopedRunner`, `…RequestScopedRuntime` |
| `domains/ed25519Yao/recovery/` | `routerAbEd25519YaoRecovery`, `…RecoveryActivation.typecheck`, `…RecoveryRequestScopedCloudflare`, `…RecoveryWalletSessionAuthorization` |
| `domains/ed25519Yao/export/` | `routerAbEd25519YaoExport`, `…ExportRequestScopedCloudflare` |
| `domains/ed25519Yao/session/` | `routerAbEd25519YaoWalletSession` (+typecheck) |
| `domains/ed25519Yao/` | `thresholdEd25519RequestValidation` |
| `domains/ecdsa/` | `routerAbEcdsaStrictRegistration`, `routerAbEcdsaDerivationRefreshPort`, `thresholdEcdsaRequestValidation` |
| `domains/normalSigning/` | `routerAbNormalSigningAdmissionCore`, `routerAbNormalSigningAdmissionStore` (+typecheck), `routerAbPrivateSigningWorker` |
| root (unchanged) | `express-adaptor`, `cloudflare-adaptor`, `ror-adaptor`, `ror/` |
| to classify during Phase 3 | `routerApiWebhooks` (framework vs its own domain) |

Files named `…RequestScopedCloudflare` remain in `domains/` — after Phase 1
they no longer import anything Cloudflare-specific; whether to rename them is
a Phase 7 question.

## Move map — `cloudflare/` → `hosts/cloudflare/`

| Destination | Files |
| ----------- | ----- |
| `router/` | `createCloudflareRouter`, `registerCloudflareRoute`, `cloudflare.types`, `createSelfHostedCloudflareSigningWorker`, `email` |
| `router/routes/` | all of `routes/` unchanged |
| `d1/emailOtp/` | the 12 `d1EmailOtp*` + `d1GoogleEmailOtp*` files |
| `d1/registration/` | `d1RegistrationCeremony*` (3), `d1RegistrationIntentService`, `d1RegistrationSharedSigningBudget`, `d1WalletRegistrationCommitStore`, `d1WalletRegistrationService`, `d1WalletRegistrationSetup`, `d1EvmFamilyEcdsaRegistrationBranch` |
| `d1/session/` | `d1SessionRecords`, `d1SessionService`, `d1SessionStore` |
| `d1/identity/` | `d1IdentityRecords`, `d1IdentityService` |
| `d1/oidc/` | `d1OidcBoundary`, `d1OidcVerificationService` |
| `d1/webauthn/` | `d1WebAuthnAuthService`, `d1WebAuthnRecords`, `d1WebAuthnStore` |
| `d1/auth/` | `d1RouterApiAuthBoundary`, `d1RouterApiAuthConfig`, `d1RouterApiAuthService` |
| `d1/wallet/` | `d1WalletAuthMethodBoundary`, `d1WalletAuthMethodService`, `d1WalletAddSignerService` (+typecheck) |
| `d1/ed25519Yao/` | `d1Ed25519YaoCapabilityPersistence`, `d1Ed25519YaoWalletSigner` |
| `d1/near/` | `d1NearPublicKeyStore` |
| `d1/versionedJson/` | `d1VersionedJsonRecordStore`, `versionedJsonRecordStore` (whatever remains after the Phase 2 port extraction) |
| `durableObjects/` | `thresholdStore` |

## Blast radius

- **93** `src/router/...` path references in `tests/scripts/*.mjs` guards
  (Phase 6).
- **11** test files deep-import `@server/router/...` — mechanical import
  updates alongside Phases 3–4.
- `tests/unit/packageExports.contract.unit.test.ts` — 4 path references
  (Phase 5).
- `packages/console-server-ts` imports only `@seams/sdk-server/cloud-host` —
  **unaffected**.
- `package.json` exports unaffected as long as adaptors stay at root.

## Validation

Per phase: `pnpm check` (includes architecture boundary checks) and
`pnpm test:unit`. After Phase 4 and again after Phase 6:
`pnpm test:source-guards`. One full `pnpm test:intended` after the final
phase — behaviour is unchanged, so this is insurance, not the gate.

## Non-goals

- No behaviour, schema, or wire-format changes.
- No changes to the `d1Xxx{Records,Store,Service,Boundary}` naming convention.
- No new source-text guards; the layering rule should become a structural
  lint if enforced at all.
- No `src/router` ↔ `src/core` boundary changes — this refactor only
  reorganises within `src/router`.
