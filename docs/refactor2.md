# Refactor Follow-Up Plan (Readability + Modularity)

Last updated: 2026-02-19

This follow-up roadmap continues from the completed phases in
`docs/refactor.md` and focuses on onboarding clarity and modular boundaries
without over-fragmenting files.

## Next Phased TODOs (Readability + Modularity)

### Phase 8: Align Repo Truth Sources

Goal: remove broken/legacy paths so docs, workspace config, and build config describe the same repo layout.

- [x] Remove missing example package entries from `pnpm-workspace.yaml`.
- [x] Update `sdk/build-paths.ts` frontend example paths to current example apps.

Definition of done:

- New contributors can run documented commands/paths without dead links or missing packages.

### Phase 9: Split Stable vs Experimental SDK Surface

Goal: make the root SDK entrypoint easy to understand and safe by default.

- [x] Keep `client/src/index.ts` focused on stable public APIs.
- [x] Move experimental/internal signing exports to explicit subpaths (for example `@tatchi-xyz/sdk/experimental/*`).
- [x] Update `sdk/package.json` exports map to reflect the split.
- [x] Add a guardrail check to prevent deep internal module exports from the root entrypoint.

Definition of done:

- Root imports communicate a clear "safe public surface"; advanced APIs are opt-in via explicit paths.

### Phase 10: Remove Remaining Wrapper Indirection

Goal: one canonical file path per implementation (no re-export hop chains).

- [x] Remove one-line compatibility wrappers in `client/src/core/signing/api/*` that only re-export nested modules.
- [x] Remove one-line wrappers in `client/src/core/signing/secureConfirm/manager.ts` and `.../manager/index.ts`.
- [x] Remove `lit-components/*` wrapper re-exports where canonical modules already exist under `secureConfirm/ui/*`.
- [x] Delete empty directories under `client/src/core/signing/api/` (`registration`, `signing`, `storage`) unless used immediately.

Definition of done:

- Searching for a symbol lands on the implementation file first, not a wrapper.

### Phase 11: Adopt Flow-Pack Modularity (Not File Explosion)

Goal: make signing flows readable while keeping modules cohesive.

- [x] Group signing logic by flow package (for example `near/transactionsFlow`, `near/delegateFlow`, `near/nep413Flow`, `tempo/tempoSigningFlow`).
- [x] Keep shared primitives in `shared.ts`/`types.ts` per flow package instead of creating micro-files.
- [x] Define module granularity rule in this plan:
  - prefer cohesive files over wrappers,
  - avoid files that only rename/re-export,
  - split only when a file has multiple distinct responsibilities.
- [x] Refactor NEAR signing handlers to follow the new flow-pack layout.

Definition of done:

- A new contributor can follow each signing flow from entrypoint to worker with minimal folder hopping.

### Phase 12: Capability Interfaces + Chain Signers

Goal: make multichain behavior explicit via capability contracts and chain-scoped APIs (`tatchi.<chain>.*`), while keeping modules cohesive.

- [x] Define capability interfaces in `client/src/core/TatchiPasskey/` (for example `capabilities.ts`):
  - required signing capabilities (`sign`, `signAndSend`, chain-specific signing entrypoints),
  - optional capabilities as separate interfaces (`EmailRecoveryCapability`, `DeviceLinkingCapability`, `KeyExportCapability`).
- [x] Implement chain signers that compose those capabilities:
  - `near` signer,
  - `evm` signer,
  - `tempo` signer.
- [x] Expose namespaced chain surfaces on `TatchiPasskey`:
  - `tatchi.near.*`,
  - `tatchi.evm.*`,
  - `tatchi.tempo.*`.
- [x] Cut over from flat root chain methods to namespaced chain surfaces (breaking change allowed in development mode).
- [x] Keep cross-chain orchestration modules shared:
  `walletIframeCoordinator.ts`, `authSessionDomain.ts`, `deviceRecoveryDomain.ts`.
- [x] Split `client/src/core/signing/api/WebAuthnManager.ts` into API surfaces under `signing/api/apiSurfaces/*` (historical naming: `signing/api/modules/*`) and keep class as thin orchestrator.

Progress notes (2026-02-18):

- `WebAuthnManager` is now a thin composition root with domain surfaces:
  `indexedDbRegistration`, `signingActions`, `credentialRecovery`,
  `thresholdSession`, `thresholdKeyLifecycle`.
- Wrapper-style pass-through methods were removed from `WebAuthnManager`
  (breaking change accepted for development mode).
- `TatchiPasskey` wallet-iframe lifecycle/mirroring logic is extracted to
  `walletIframeCoordinator.ts`; `index.ts` delegates to the coordinator.
- `TatchiPasskey` auth/session routing (`login/getSession/logout/recent-logins`)
  is extracted to `authSessionDomain.ts`.
- `TatchiPasskey` device sync/recovery/linking flows are extracted to
  `deviceRecoveryDomain.ts`.
- `TatchiPasskey` transaction-signing flow is split into chain-focused modules:
  `signers/nearSigner.ts`, `signers/tempoSigner.ts`, and `signers/evmSigner.ts`.
- Capability contracts now live in `capabilities.ts`.
- `TatchiPasskey` now exposes chain-scoped surfaces
  (`tatchi.near`, `tatchi.tempo`, `tatchi.evm`) backed by chain signer modules.
- Flat root signing methods were removed from `TatchiPasskey`; internal call
  sites now use namespaced chain surfaces.
- Added chain-signer unit coverage in
  `tests/unit/tatchiPasskey.chainSigners.unit.test.ts` for hook propagation,
  router error handling, and chain-forced threshold bootstrap semantics.

Definition of done:

- Chain-specific signing behavior is discovered under `tatchi.<chain>.*` only.
- Capability support is explicit in types (no pseudo-optional root methods).
- `TatchiPasskey` and `WebAuthnManager` remain composition roots, not monoliths.

### Phase 13: Consolidate Signing Runtime Worker Boundaries

Goal: eliminate conceptual split between worker runtime files and worker transport/orchestration.

- [x] Move `client/src/core/workers/*.worker.ts` under a single signing runtime root (`client/src/core/signing/runtime/workers/*` or equivalent canonical location).
- [x] Keep runtime asset path resolution and build output filenames stable during move.
- [x] Update `sdk/rolldown.config.ts` entries and worker path helpers accordingly.
- [x] Add a check to prevent reintroducing a second worker root.

Progress notes (2026-02-18):

- moved `near-signer.worker.ts`, `eth-signer.worker.ts`, `tempo-signer.worker.ts`,
  `passkey-confirm.worker.ts`, and `workerControlMessages.ts` into
  `client/src/core/signing/runtime/workers/`.
- rewired worker transports and build scripts to the new runtime worker root while
  preserving `/sdk/workers/*.worker.js` runtime URLs and output filenames.
- added architecture guardrail that fails if `client/src/core/workers` reappears.

Definition of done:

- Worker runtime, worker transport, and worker operation contracts live under one discoverable tree.

### Phase 14: Normalize Cross-Package Imports

Goal: improve readability and reduce brittle deep-relative paths.

- [x] Convert deep relative imports to configured aliases (`@shared/*`, `@server/*`, `@/*`) across client core modules.
- [x] Add lint/check rule forbidding deep cross-package relative imports when alias exists.
- [x] Keep local same-folder relative imports for nearby modules (readability first).

Progress notes (2026-02-18):

- converted deep `shared/src` relative imports to `@shared/*` aliases across
  `client/src/*` (including `core/*` plus `utils/*`).
- converted deep client-internal relative imports (3+ parent traversals) to
  `@/*` aliases across `client/src/*`, while keeping nearby local imports
  relative.
- added architecture guardrail in `sdk/scripts/checks/check-signing-architecture.sh`
  that blocks deep `shared/src` relative imports anywhere in `client/src` and
  enforces `@/*` alias usage for deep client-internal imports.
  `check-signing-architecture.sh` as the policy enforcement source for deep
  client-relative imports.
- normalized moved signing-api modules (`api/recovery|registration|signing|threshold`)
  to `@/core/*` imports to satisfy deep-relative alias policy after folder split.

Definition of done:

- Cross-package imports are uniform and easy to scan.


### Phase 15: Enforce with Checks + Incremental Rollout

Goal: prevent regression after cleanup.

- [x] Extend `sdk/scripts/checks/check-signing-architecture.sh` with:
  - no wrapper reintroduction checks,
  - root export boundary checks,
  - capability-interface and chain-namespace guardrails (`tatchi.<chain>.*` surface policy).
- [x] Decompose monolithic checks and keep only durable, high-signal guards in
  `check-signing-architecture.sh`.
- [x] Keep critical architecture checks as focused modules:
  - `check-signing-api-cycles`
  - `check-stable-experimental-export-boundaries`
  - `check-worker-runtime-boundaries`

Progress notes (2026-02-19):

- `check-signing-architecture.sh` now acts as thin orchestration over critical
  checks only.
- migration-specific and brittle stale-path policy checks were removed from
  default blocking gates.
- guard coverage now prioritizes durable boundaries (cycles, export surfaces,
  worker/runtime contracts).

Definition of done:

- Readability/modularity improvements are locked by automation and do not drift back.

### Phase 17: Remove Thin Facades (Ongoing)

Goal: avoid useless wrapper files and keep call paths direct.

- [x] Remove facade files that only proxy to one module without adding policy, lifecycle, caching, or composition logic.
- [x] Inline facade call sites to the real implementation module.
- [x] Keep orchestration facades only when they provide meaningful cross-domain coordination.
- [x] Add a guardrail check for new `*Facade.ts` files that only contain pass-through methods.
- Progress (2026-02-18): removed `client/src/core/signing/api/facade/facadeDependencyFactory.ts` and inlined both call sites.
- Progress (2026-02-18): tightened threshold ECDSA bootstrap persistence semantics
  (chain-id fallback validation + explicit undeployed reset fields) and added
  source-level unit coverage.
- Progress (2026-02-18): removed `client/src/core/signing/api/facade/facadeSettings.ts`,
  inlined its logic in `WebAuthnManager`, and added check-script guardrails
  to prevent stale/new signing facade files from reappearing.
- Progress (2026-02-18): removed `client/src/core/signing/api/facade/facadeConvenience.ts`,
  inlined its behavior into signing surfaces/dependency bundle, and tightened
  guardrails so the `signing/api/facade` directory stays removed.
- Progress (2026-02-18): removed thin wrappers outside `signing/api`:
  `client/src/core/signing/threshold/workflows/deriveThresholdEd25519ClientVerifyingShare.ts`
  and `client/src/core/signing/secureConfirm/ui/lit-components/ExportPrivateKey/iframe-host.ts`;
  inlined imports to canonical modules and added guardrails.
- Progress (2026-02-18): removed additional thin wrappers outside `signing/api`:
  `client/src/core/signing/workers/signerWorkerManager/getDeviceNumber.ts` and
  `client/src/core/signing/webauthn/credentials/serialization.ts`; inlined
  call sites to canonical modules and extended guardrails to block those stale paths.
- Progress (2026-02-18): removed `client/src/core/IndexedDBManager/passkeyClientDB.ts`
  and `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts`; inlined imports
  to `passkeyClientDB/manager|passkeyClientDB.types` and
  `passkeyNearKeysDB/manager|passkeyNearKeysDB.types`, updated test deep-import
  paths, and added denylist guardrails.
- Progress (2026-02-18): removed flat root recovery/device-link pass-through methods from
  `TatchiPasskey` (`syncAccount`, `startEmailRecovery`, `finalizeEmailRecovery`,
  `cancelEmailRecovery`, `startDevice2LinkingFlow`, `stopDevice2LinkingFlow`,
  `linkDeviceWithScannedQRData`) and exposed one capability surface under
  `tatchi.recovery.*` on both `TatchiPasskey` and `TatchiPasskeyIframe`.
- Progress (2026-02-18): migrated wallet host, React UI/hooks, and example app call sites
  to `tatchi.recovery.*`.
- Progress (2026-02-18): removed remaining `(router as any)` recovery/device-link
  shims in `deviceRecoveryDomain.ts`, switched to typed wallet-router methods,
  and added a guardrail that blocks reintroducing those casts.
- Progress (2026-02-18): removed dynamic import indirection in
  `signers/nearSigner.ts` for delegate/relay/NEP-413 paths and switched to
  static imports; tightened `WalletIframeRouter.signDelegateAction` return type
  to `SignDelegateActionResult` and removed signer-side result casts.
- Progress (2026-02-18): started tightening signer/router boundary typing by
  replacing `unknown`-typed delegate signing responses with concrete SDK result
  types and adding guardrails against reintroducing dynamic wrapper-hop imports.
- Progress (2026-02-18): removed remaining NEP-413 signer result cast in
  `signers/nearSigner.ts` and replaced `as any` message/event narrowing in
  `WalletIframe/client/router.ts` with typed object checks; added guardrails to
  keep those casts from reappearing.
- Progress (2026-02-18): removed additional router cast shims in
  `WalletIframe/client/router.ts` by inlining typed `confirmationConfig`
  payloads, removing debug/result normalization casts, and tightening
  delegate/progress guard helpers; extended guardrails to block those cast
  patterns.
- Progress (2026-02-19): removed `TatchiPasskeyIframe` local fallback-parity
  path (`fallbackLocal`, `ensureFallbackLocal`, `getNearClient`, `getContext`),
  tightened wallet-host/mounter types to canonical `TatchiPasskey`, and added
  architecture guardrails to block reintroduction.
- Progress (2026-02-19): migrated recovery-email helpers to capability surface
  (`tatchi.recovery.getRecoveryEmails/setRecoveryEmails`), removed flat root
  methods from `TatchiPasskey`, rewired wallet-host handlers/UI/example call
  sites, and tightened guardrails to block reintroduction.
- Progress (2026-02-19): removed wallet-iframe `getClient` fallback branches in
  `TatchiPasskey` key-management/readiness paths
  (`viewAccessKeyList`, `prefetchBlockheight`, `exportPrivateKeysWithUI`,
  `deleteDeviceKey`) so wallet-origin mode always routes through
  `walletIframe.requireRouter(...)`; added guardrail to block fallback branch
  reintroduction.
- Progress (2026-02-19): moved key export to explicit capability surface
  (`tatchi.keys.exportNearKeypairWithUI/exportPrivateKeysWithUI`), removed flat
  root key-export methods from both `TatchiPasskey` and `TatchiPasskeyIframe`,
  rewired wallet-host/UI call sites, and added guardrails to block flat export
  API reintroduction.
- Progress (2026-02-18): removed remaining wallet-iframe fallback-style logout
  branch in `authSessionDomain.ts` (`walletIframe.getClient()` probe) and
  switched to strict `walletIframe.requireRouter()` routing in iframe mode;
  added guardrail to block reintroduction.
- Progress (2026-02-18): migration grep sweep across `client/tests/examples`
  confirms no legacy flat signing-api import paths for moved modules.
- Progress (2026-02-18): removed `TatchiPasskey` internal-exposure wrappers
  `getWalletIframeClient` and `getNearClient`; added typed wallet-iframe
  lifecycle subscriptions/readiness methods
  (`isWalletIframeReady`, `onWalletIframeReady`,
  `onWalletIframeLoginStatusChanged`, `onWalletIframePreferencesChanged`),
  migrated React lifecycle/readiness consumers and wallet-iframe guardrail
  tests, and added architecture checks to block wrapper reintroduction.
- Progress (2026-02-18): tightened `react/utils/walletIframe.ts` to the new
  `TatchiPasskey` wallet-iframe API only (`initWalletIframe`,
  `isWalletIframeReady`, `onWalletIframeReady`) and removed legacy fallback
  hook branches (`isReady/onReady`) from that utility.
- Progress (2026-02-18): audited orchestration composition modules and kept
  only meaningful cross-domain coordinators (`bootstrap/orchestrationDependencyFactory.ts`,
  `TatchiPasskey/walletIframeCoordinator.ts`); removed the thin
  `apiSurfaces/managerSurfaces.ts` assembly wrapper and inlined surface
  construction in `WebAuthnManager.ts`.

Definition of done:

- No thin pass-through facades remain in signing and passkey core paths.

### Phase 18: Legacy Endpoint/Function/File Purge (Continuous)

Goal: remove legacy code as each refactor slice lands so duplicate paths do not accumulate.

- [x] Maintain a strict denylist in `sdk/scripts/checks/check-signing-architecture.sh` for known stale files/endpoints (for example `nearTransactionsDomain.ts`, legacy wrappers, and removed root signing APIs).
- [x] For every module extraction, remove the old implementation file in the same PR (no temporary dual-path period unless explicitly required).
- [x] Eliminate legacy email-recovery placeholder flow by moving local flow wiring into `deviceRecoveryDomain.ts` and deleting `emailRecovery.ts`.
- [x] Eliminate legacy sync placeholder flow in `syncAccount.ts` by removing `SyncAccountFlow` and retaining one canonical sync implementation.
- [x] Remove compatibility comments/branches that reference removed architectures once migration is complete.

Progress (2026-02-18):

- stale-file denylist now also blocks reintroducing `client/src/core/TatchiPasskey/emailRecovery.ts` after local flow inlining into `deviceRecoveryDomain.ts`.
- added no-dual-path extraction guardrails in `check-signing-architecture.sh`
  that fail if stale signing-api directories (legacy aliases `api/domains`,
  `api/threshold`, `api/modules`, and stale `api/facade`) or stale flat import
  paths reappear.
- removed `SyncAccountFlow` and unused placeholder sync-account types/exports (`PasskeyOptionWithoutCredential`, `PasskeySelection`) from `client/src/core/TatchiPasskey/syncAccount.ts`/`index.ts`.
- removed stale compatibility endpoint `TatchiPasskey.warmCriticalResources` and
  switched wallet-host warm-up paths to `initWalletIframe`.
- removed dead threshold-ECDSA session compatibility API
  (`mintThresholdEcdsaAuthSessionLite`) and added denylist checks to prevent
  reintroduction.
- removed the legacy chain-account compatibility field `legacyNearAccountId`
  from core DB types, write/read paths, smart-account deployment mirroring, and
  affected tests.
- cleaned compatibility-only labels in touched signing/passkey modules so comments
  describe current flow paths only.
- removed stale compatibility phrasing in `TatchiPasskey.exportNearKeypairWithUI`
  docs comment to reflect the canonical flow naming.
- removed remaining compatibility-only wording in touched passkey modules
  (for example stale direct-reference guidance to `TatchiPasskeyIframe`) so
  comments describe current canonical flow paths only.
- guardrails now also forbid reintroducing flat root recovery/device-link methods and
  enforce `readonly recovery: RecoveryCapability` on passkey entrypoints.
- guardrails now fail if `legacyNearAccountId` reappears in `client/src` or `tests`.
- renamed runtime IndexedDB mode label from `legacy` to `app` in
  `IndexedDBManager` and `TatchiPasskey` constructor wiring; added architecture
  checks so `mode: 'legacy'` cannot reappear.
- removed `any` payload/cast shims from
  `TatchiPasskey/deviceRecoveryDomain.ts` and `TatchiPasskey/scanDevice.ts`
  (email-recovery prepare parsing, credential/access-key extraction, relay-claim
  response handling) and added guardrails to block `any` reintroduction there.
- removed remaining `any` payload/cast shims in
  `TatchiPasskey/linkDevice.ts` and `TatchiPasskey/syncAccount.ts`
  (relay/session parsing, nonce/block fetch typing, event payload typing, and
  sync-account challenge/verify parsing); extended guardrails to block `any`
  reintroduction across recovery/link/sync modules.
- removed remaining `any`/cast shims in core passkey action/session paths:
  `TatchiPasskey/registration.ts`, `TatchiPasskey/actions.ts`,
  `TatchiPasskey/login.ts`, `TatchiPasskey/signNEP413.ts`, and
  `TatchiPasskey/relay.ts`; expanded architecture checks to block `as any`/`: any`
  reintroduction across all `client/src/core/TatchiPasskey/*.ts` modules.
- removed `any` boundary/cast shims in non-passkey runtime modules (using
  current signing-api paths):
  `WalletIframe/TatchiPasskeyIframe.ts`, `WalletIframe/host-mode.ts`,
  `WalletIframe/host/context.ts`, `WalletIframe/host/wallet-iframe-handlers.ts`,
  `signing/api/WebAuthnManager.ts`, `signing/api/signing/nearSigning.ts`,
  `signing/api/userPreferences.ts`,
  `signing/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts`,
  `signing/api/recovery/privateKeyExportRecovery.ts`,
  `signing/api/registration/registrationAccountLifecycle.ts`, and
  `signing/api/apiSurfaces/indexedDbRegistrationSurface.ts`.
- removed stale threshold ECDSA keygen session-id prefix `legacy-keygen-*` in
  `near/rpcCalls.ts` and renamed to `threshold-keygen-*`.
- removed remaining `any` boundary/cast shims in `near/rpcCalls.ts`
  (relay login option parsing, login verify parsing, threshold keygen/bootstrap
  error boundaries, recovery-attempt status/hash normalization, and tx broadcast
  error propagation).
- removed deprecated client config alias `relayerAccountId` end-to-end from
  `client/src`:
  `core/types/tatchi.ts` (type surface), `core/config/defaultConfigs.ts`
  (config merge), `react/context/index.tsx` (explicit-domain detection), and
  `react/hooks/useAccountInput.ts` (health discovery key parsing now uses
  `relayerAccount`).
- updated relay health responses (`/healthz`) and test relay harness payloads
  to expose `relayerAccount` instead of `relayerAccountId`, and updated test
  runtime config discovery in `tests/setup/test-utils.ts` accordingly.
- expanded architecture checks to block `as any`/`: any` reintroduction across
  `client/src/core/WalletIframe/*` and `client/src/core/signing/api/*`, and to
  forbid `legacy-keygen-` session-id prefixes in `near/rpcCalls.ts`.
- expanded architecture checks to block `as any`/`: any` reintroduction in
  `near/rpcCalls.ts`.
- expanded architecture checks to block `relayerAccountId` /
  `relayer_account_id` reintroduction in `client/src`.
- canonicalized server/relay naming to `relayerAccount` (removed
  `relayerAccountId` naming from `server/src/core/types.ts`,
  `server/src/core/config.ts`, `server/src/core/AuthService.ts`,
  `server/src/delegateAction/index.ts`, `server/src/email-recovery/*`,
  relay health routes, and relay examples/tests).
- expanded architecture checks to block `relayerAccountId` /
  `relayer_account_id` reintroduction in server/relay source + relayer-focused
  tests/examples.
- removed remaining React context `any` shims in
  `react/context/useTatchiContextValue.ts` and
  `react/context/useTatchiWithSdkFlow.ts` by switching to typed
  `StartDevice2LinkingFlowArgs` request construction and typed sync-event error
  narrowing.

Definition of done:

- There is one canonical implementation path per feature.
- No legacy entrypoints, files, or stale compatibility branches remain in active code paths.

### Phase 19: Prune Architecture Policy Guards + Non-Critical Checks

Goal: remove brittle migration-policy guardrails and keep only durable, high-signal checks.

- [x] Delete migration-specific architecture policy checks and their analyzer + unit-guard pairs.
- [x] Delete non-critical and likely-non-critical check scripts and wrappers.
- [x] Remove all references to deleted checks from:
  - `sdk/scripts/checks/check-signing-architecture.sh`
  - root `package.json` scripts
  - CI workflows (`.github/workflows/*`)
  - test/docs references (`tests/unit/*guard.unit.test.ts`, `docs/refactor2.md`)
- [x] Keep these checks as critical:
  - `check-signing-api-cycles`
  - `check-stable-experimental-export-boundaries`
  - `check-worker-runtime-boundaries`
  - `assert-near-signer-wasm-imports`
- [x] Keep `assert-palette-css.mjs` in CI and release validation.

Progress notes (2026-02-19):

- removed migration-specific check wrappers, analyzer modules, and paired guard unit tests.
- removed non-critical repo/import policy checks from root blocking scripts.
- removed `check-signing-architecture.sh`; `check:signing-architecture` now runs critical checks directly from `package.json`.

Definition of done:

- Migration-specific/stale-path guardrails are removed from default build/test gates.
- Only critical checks remain blocking.
- `assert-palette-css.mjs` remains enforced.

## Immediate Next Steps

1. Keep release-critical validation intact (`assert-palette-css.mjs`, `assert-near-signer-wasm-imports.mjs`, `tsc`, signer parity).
2. Gate each cleanup slice with:
   `pnpm -C sdk exec tsc --noEmit -p tsconfig.build.json`,
   `pnpm -s check:signing-architecture`,
   and targeted Playwright unit tests.
