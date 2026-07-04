# Refactor 89: Clean Source Guards

Date created: June 26, 2026
Renamed: July 3, 2026 — from `refactor-9x-clean-source-guards.md`; all
referencing plans were updated.

Status: planned. This file is both a standing ledger (new temporary guards are
recorded here as they are added) and a cleanup plan.

Sequencing:

- Cleanup executes after [Refactor 88](./refactor-88-intended-behaviour-e2e.md)
  lands: the e2e contract suite is the replacement coverage that justifies
  deleting transitional guards. Do not delete lifecycle-seam guards before
  `test:intended` covers those seams.
- Guard retirement runs incrementally at Refactor 90 slice exits (90 plan
  Decided Point 14): a guard retires in the slice that makes its invariant
  structural (closed unions, branded IDs, generic lanes, boundary parsers).
- The final sweep is Refactor 90 Phase P3, which requires that no guard
  remains whose invariant is structurally enforced.

Related plans:

- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-78-wallet-capability-bindings.md](./refactor-78-wallet-capability-bindings.md)
- [refactor-79-exact-signing-lane.md](./refactor-79-exact-signing-lane.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)
- [refactor-81-trim-rename-v1-v2.md](./refactor-81-trim-rename-v1-v2.md)
- [refactor-53-test-inventory.csv](./refactor-53-test-inventory.csv)

## Goal

Reduce temporary refactor guard debt after the current architecture stabilizes.

Source guards have been useful while broad identity, Router A/B, HSS, and route
boundary refactors were moving quickly. Many of those guards freeze transitional
source text, old symbol bans, route-shape bans, and implementation-specific
call-chain checks. They should be deleted once the same invariant is enforced by
domain types, boundary parsers, focused behavior tests, protocol vectors, or
formal verification.

This plan is the ledger for temporary guards. When a new temporary source guard
is added, add it here with its cleanup trigger.

## Policy

- Every new guard must be classified as `temporary`, `durable`, or `runtime`.
- Temporary guards need a cleanup trigger in this file.
- Durable guards protect security boundaries, platform boundaries, protocol
  vectors, or public API contracts. They stay unless replaced by stronger
  coverage.
- Runtime guards are production validation helpers, such as config validation.
  They are not cleanup debt.
- Prefer deleting temporary source guards after replacement coverage exists.
- Prefer behavior tests, type fixtures, discriminated unions, parser tests, and
  protocol vectors over source-text scans.
- Keep source guards narrow while they exist. Avoid broad string bans that make
  harmless refactors expensive.

## Removal Criteria

A temporary guard can be deleted when all of these are true:

- [ ] The protected behavior is enforced by a type, parser, protocol vector,
      formal check, or behavior test.
- [ ] The guard no longer catches an active migration risk.
- [ ] Any allowlist owned by the guard is empty or replaced by a typed boundary.
- [ ] `rg` confirms the obsolete symbol, route, or pattern is absent from active
      source outside historical docs and this cleanup plan.
- [ ] The replacement validation command is documented in the guard ledger row.

## New Guard Intake Template

Add a row here when adding a temporary guard:

| Field | Value |
| --- | --- |
| Guard | `path/to/guard.test.ts` |
| Owner refactor | `refactor-NN-name.md` |
| Why it exists | One sentence. |
| Cleanup trigger | Exact condition for deletion. |
| Replacement coverage | Test/type/parser/vector expected to replace it. |
| Status | `active`, `ready_to_delete`, or `deleted`. |

## Phase 0: Inventory

- [ ] Inventory all current guard files and classify them as temporary, durable,
      or runtime.
- [ ] Split large guard suites into rows by invariant when one file contains
      both durable and temporary checks.
- [ ] Mark guard-owned allowlist files separately.
- [ ] Add deletion triggers for every temporary guard.

Seed inventory from current source:

- `crates/router-ab-cloudflare/tests/source_guards.rs`
- `crates/router-ab-core/tests/source_guards.rs`
- `crates/ed25519-hss/tests/materialization_graph_guard.rs`
- `tests/unit/*.guard.unit.test.ts`
- `tests/unit/*.behavior.guard.unit.test.ts`
- `tests/unit/*.domain.guard.unit.test.ts`
- `tests/unit/*.guards.test.ts`
- `tests/unit/*.guardrails.unit.test.ts`
- `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts`
- `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json`

## Phase 1: Remove Refactor-Number Guard Suites

These are the easiest cleanup candidates because their names already encode a
past refactor rather than a durable product invariant.

| Guard | Owner refactor | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- | --- |
| `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts` | Refactor 79 | Exact signing-lane identity is stable across NEAR, ECDSA, export, restore, budget, and recovery for one release branch. | Exact-lane builder type fixtures, export/restore/signing behavior tests, HSS digest-boundary vectors. | active |
| `tests/unit/refactor80SwitchCase.guard.unit.test.ts` | Refactor 80 | Route command parsing and lifecycle unions are stable, and all route-body parser tests cover the trust boundaries directly. | Parser unit tests, exhaustive union type fixtures, route handler tests. | active |
| `tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts` | Refactor 74 | Legacy fallback names are absent and exact lookup behavior is covered by direct lane/session tests. | Lane selection duplicate tests, restore/export behavior tests. | active |
| `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` | Refactor 74 | Worker-owned Ed25519 material and HSS boundary shape are enforced by generated command types and HSS tests. | Worker command type fixtures, Ed25519 HSS route/material tests, formal anti-drift checks. | active |
| `tests/unit/refactor76BrandedKeys.guard.unit.test.ts` | Refactor 76 | Branded key constructors are the only public construction path and unsafe casts are covered by type fixtures. | `@ts-expect-error` fixtures and constructor parser tests. | active |
| `tests/unit/refactor71WalletSessionNaming.guard.unit.test.ts` | Refactor 71 | Wallet-session vocabulary is stable and old naming is absent from active source. | Public API type tests and route/session parser tests. | active |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | Refactor 73 | Type-only file naming is enforced by lint/build tooling. | `tests/scripts/check-type-filename-source.mjs`, run by `pnpm -C tests run check:type-filename-source` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor67ReorgFolders.guard.unit.test.ts` | Refactor 67 | Folder layout is stable and package import boundaries are covered by durable architecture guards. | Package boundary tests and build graph checks. | active |
| `tests/unit/refactor58OtpRegistrationSlim.guard.unit.test.ts` | Refactor 58 | OTP registration slim path is represented by behavior tests instead of source shape checks. | OTP registration flow tests. | active |
| `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts` | Refactor 56 | Headless auth public surface is stable and covered by API contract tests. | Public API type tests and headless auth behavior tests. | active |
| `tests/unit/refactor54Simplify.guard.unit.test.ts` | Refactor 54 | The simplified web signing surface is covered by public API tests. | Public API and signing surface contract tests. | active |
| `tests/unit/refactor51bPlatformBoundaries.guard.unit.test.ts` | Refactor 51B | Platform boundary ownership is represented by durable package boundary tests. | Cross-platform boundary guard or build graph tests. | active |
| `tests/unit/refactor51bSeamsWebRename.guard.unit.test.ts` | Refactor 51B | Legacy SeamsWeb names are absent from active source and historical docs are the only remaining mentions. | Public export contract tests. | active |
| `tests/unit/refactor51bWebauthnOriginPolicy.guard.unit.test.ts` | Refactor 51B | WebAuthn origin policy is covered by boundary parser tests. | WebAuthn origin parser/unit tests. | active |
| `tests/unit/refactor8xRegistrationButton.guard.unit.test.ts` | Refactor 8X | Registration button behavior is covered by component tests. | React/component behavior tests. | active |

Checklist run, July 4, 2026:

| Guard | Verdict | Evidence / next action |
| --- | --- | --- |
| `tests/unit/refactor54Simplify.guard.unit.test.ts` | active | Still guards the SeamsWeb public namespace split, signing-surface dependency direction, and root export size. Replacement is incomplete until stable public API/signing-surface contract tests own those checks directly. |
| `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts` | active | Still guards the headless Google Email OTP flow boundary across demo UI, React code, public API, and wallet iframe flow handles. Keep until `googleEmailOtpWalletAuthFlow` and wallet-iframe handle tests cover every guarded branch without source scans. |
| `tests/unit/refactor58OtpRegistrationSlim.guard.unit.test.ts` | active | Still guards the Google Email OTP registration/reroll split and server activation-before-wallet-visibility ordering. Keep until focused Email OTP registration behavior/parser tests replace the source-shape checks. |
| `tests/unit/refactor67ReorgFolders.guard.unit.test.ts` | active | Still guards package-root and deployable-app import boundaries. Keep until durable package-boundary/build-graph checks replace it. |
| `tests/unit/refactor71WalletSessionNaming.guard.unit.test.ts` | active | Still has a large `sessionId` classification allowlist with many `rename_later_agent_b_signing_or_wasm` entries. Keep until Refactor 90 vocabulary work removes or rehomes those names. |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | deleted | Fired in Refactor 88 cleanup: the guard was replaced by `tests/scripts/check-type-filename-source.mjs`, wired through `pnpm -C tests run check:type-filename-source` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts` | active | Still guards exact lookup / no-fallback semantics during the in-flight authority and companion-session cleanup. It is currently being adjusted by 82B work, so no Refactor 89 deletion action is safe yet. |
| `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` | active | Still guards worker-owned Ed25519/HSS material boundaries, deleted raw-material names, and active restore persistence. Keep until generated worker command types, HSS tests, and formal checks replace every source scan. |
| `tests/unit/refactor76BrandedKeys.guard.unit.test.ts` | active | Still guards branded key-version and ECDSA signing-key-slot boundaries. Keep until constructor/parser tests and `@ts-expect-error` type fixtures reject the same invalid constructions. |
| `tests/unit/refactor80SwitchCase.guard.unit.test.ts` | active | Still guards parser-before-service route boundaries, lifecycle union shape, type-only imports, and unsafe casts across route/session code. Keep until parser tests and exhaustive-union fixtures replace each group. |

## Phase 2: Collapse Router A/B Source Guards

Router A/B source guards grew while Router, Deriver A/B, SigningWorker, local
dev, and Cloudflare shapes were changing together. After deployment settles,
prune them to security-critical boundaries.

| Guard | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `crates/router-ab-cloudflare/tests/source_guards.rs` route-shape checks | Refactor 81 route rename has shipped and old `/v1`/`/v2` routes are absent from all active clients. | Route constant tests, local/cloudflare parity tests, release probe scripts. | active |
| `crates/router-ab-cloudflare/tests/source_guards.rs` ECDSA/Ed25519 call-chain checks | Handler boundaries are enforced by typed route commands and behavior tests. | Router public/private handler tests, HSS protocol tests, presignature lifecycle tests. | active |
| `crates/router-ab-core/tests/source_guards.rs` Router boundary checks | Core protocol boundaries are covered by module visibility, type ownership, or protocol vectors. | Core protocol unit tests and vector tests. | active |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` route/topology checks | Refactor 81 unversioned route shape has shipped and active docs/scripts use one namespace. | Route-definition tests, SDK relayer tests, local worker parity tests. | active |
| `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` | Wallet Session claim parsing is enforced by server route parser tests. | Express/Cloudflare route parser tests and JWT claim tests. | active |

Keep a small durable guard or test for each security boundary that cannot be
represented by types alone.

## Phase 3: Collapse Identity Split Guards

These guards protected the wallet/account/key split while the code still had
old account-id-shaped paths. They should shrink once branded bindings and exact
lane identity cover construction.

| Guard | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | `walletCapabilityBindings.sourceGuard.allowlist.json` is empty and builders reject invalid wallet/account/signer combinations. | Builder parser tests and type fixtures. | active |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | Every entry is deleted or converted to a typed boundary. | Same as above. | active |
| `tests/unit/walletScopedLookups.guard.unit.test.ts` | Account-scoped fallback lookups are impossible through function signatures. | Exact lookup function tests and type fixtures. | active |
| `tests/unit/signingEngineEcdsaIdentity.*.guard.unit.test.ts` | ECDSA identity no longer has NEAR-shaped compatibility fields or fallback paths. | ECDSA identity parser tests, activation tests, export tests. | active |
| `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` | Lifecycle state is fully represented by discriminated unions and builders. | Domain type fixtures and lifecycle behavior tests. | active |

## Phase 4: Collapse Architecture Guard Families

Some architecture guards should become durable package-boundary tests. Others
can be deleted after refactor-specific path bans are obsolete.

| Guard family | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `tests/unit/signingEngineArchitecture.*.guard.unit.test.ts` | Signing engine ownership boundaries are stable and represented by package/module boundaries. | Durable package boundary tests. | active |
| `tests/unit/crossPlatformBoundaries.guard.unit.test.ts` | Browser/native/server boundaries are enforced by package exports and build configs. | Durable package boundary tests and build graph checks. | active |
| `tests/unit/indexedDBConsolidation.guard.unit.test.ts` | IndexedDB ownership is stable and schema tests cover persistence behavior. | Browser-backed IndexedDB schema/repository tests. | active |
| `tests/unit/stableExperimentalExportBoundaries.guard.unit.test.ts` | Stable/experimental exports are enforced by package entrypoint tests. | Public export contract tests. | active |

## Phase 5: Delete Or Move Redundant Guards

- [ ] For each `ready_to_delete` row, remove the guard and its allowlist data.
- [ ] Move any remaining durable invariant out of refactor-number files into a
      stable test name.
- [ ] Update `tests/playwright.source.config.ts` if guard file patterns or
      source-guard scope change.
- [ ] Update `tests/package.json` scripts only if the source-guard command
      itself changes.
- [ ] Run the replacement validation commands listed in each row.
- [ ] Run `pnpm -C tests run test:source-guards` once after each cleanup batch.

## Future Guard Ledger

Append new temporary guards here.

| Guard | Owner refactor | Why it exists | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- | --- | --- |
| `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts` | Refactor 79 | Prevents exact-lane authority from drifting back to broad lookup, first-candidate selection, timestamp ranking, flat lane projection authority, or warm-status telemetry authority. | Exact lane identity is stable and behavior/type tests catch the same regressions. | Exact-lane type fixtures, duplicate-record behavior tests, export/restore/signing tests. | active |
| `tests/unit/refactor80SwitchCase.guard.unit.test.ts` | Refactor 80 | Prevents raw route bodies, unsafe lifecycle state, and non-exhaustive control flow from returning after route/parser refactors. | Route parser tests and lifecycle union fixtures cover every guarded branch. | Parser tests, exhaustive-switch type fixtures, route handler tests. | active |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` | Refactors 68, 69, 81 | Prevents Router A/B topology and route-shape regressions while local/cloudflare routing is still settling. | Router A/B deploy path is stable and route constants/parity tests cover the active namespace. | Route-definition tests, SDK relayer tests, local/cloudflare parity tests. | active |
| `crates/router-ab-cloudflare/tests/source_guards.rs` | Router A/B / Refactors 79-81 | Protects Cloudflare Worker security boundaries and route-shape invariants during modularization. | Split into durable security-boundary tests and delete route/refactor-specific text scans. | Cloudflare handler tests, route parity tests, protocol vectors. | active |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | Refactor 78 | Prevents wallet/account identity collapse while binding builders settle. | Builders and type fixtures make the collapse unrepresentable. | Builder tests, `@ts-expect-error` fixtures, parser tests. | active |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | Refactor 78 | Tracks known temporary exceptions to wallet/account source bans. | Allowlist reaches zero entries. | Same as above. | active |
| `tests/unit/refactor83CapabilitySubjects.guard.unit.test.ts` visible iframe passkey registration checks | Refactor 83 | Prevents visible iframe passkey registration from drifting back to optional wallet IDs, `server_allocated` activation payloads, or shortened WebAuthn usernames. | Activation/public/message types, host parser tests, PasskeyAuthMenu behavior tests, and WebAuthn option tests are stable for one release branch. | Activation type fixtures, host activation parser tests, lit WebAuthn option tests. | active |
| `tests/unit/refactor88IntendedE2e.guard.unit.test.ts` | Refactor 88 | Keeps the intended-behaviour contract suite small, public-flow based, and protected from retired mocked setup/runtime surfaces while the harness and cleanup land together. | `test:intended` is wired into remote CI, Phase 3B mutation self-check has passed, and retired setup/runtime files are absent for one release branch. | `pnpm test:intended`, `pnpm test:intended:ci`, mutation self-check evidence, and focused setup/harness unit tests. | active |

## Retired Cleanup Ledger

These rows record deleted tests, fixtures, and setup hooks whose old behavior is
replaced by the Refactor 88 intended-behaviour contracts.

| Surface | Owner refactor | Why it was removed | Replacement coverage | Status |
| --- | --- | --- | --- | --- |
| `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts` | Refactor 88 | Mocked docs/demo registration -> signing through `setupBasicPasskeyTest`, `__testOverrides`, mocked SDK methods, and fake chain responses. | Passkey intended registration contract plus `tests/unit/refactor88IntendedE2e.guard.unit.test.ts`. | deleted |
| `tests/e2e/docs.thresholdSigningActions.smoke.test.ts` | Refactor 88 | Mocked docs/demo signing actions through a fake logged-in SDK surface. | Passkey intended registration/unlock contracts covering NEAR, Tempo, and Arc/EVM signing. | deleted |
| `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts` | Refactor 88 | Kept a production `__testOverrides` path alive to fake SDK hook state. | Demo surfaces no longer expose `__testOverrides`; guarded by `tests/unit/refactor88IntendedE2e.guard.unit.test.ts`. | deleted |
| `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts` | Refactor 88 | Used a large in-memory runtime fixture graph for unlock -> warm signing behavior. | Passkey and Email OTP intended contracts plus focused boundary/domain tests. | deleted |
| `tests/unit/helpers/warmSessionStore.fixtures.ts` | Refactor 88 | Bundled broad warm-session, ECDSA chain-target, signing-session record, status, and touch-confirm fixtures into one runtime-shape fixture. | Focused helpers: `ecdsaChainTarget.fixtures.ts`, `ecdsaBootstrap.fixtures.ts`, `signingSessionRecord.fixtures.ts`, `warmSessionUiConfirm.fixtures.ts`, and `warmSessionTestServices.fixtures.ts`. | deleted |
| `tests/setup/fixtures.ts`, `tests/setup/flows.ts`, `tests/setup/test-utils.ts` | Refactor 88 | Fed broad `window.testUtils` browser mutation helpers into mocked lifecycle tests. | Intended harness drives public SDK/UI flows directly and guards against mocked setup imports. | deleted |
| `tests/setup/webauthn-mocks.ts` | Refactor 88 | Overrode `navigator.credentials.create/get` with a bespoke WebAuthn/PRF mock and kept browser setup on a second authenticator path. | Generic setup and intended contracts both use the PRF-capable CDP virtual authenticator (`hasPrf: true`) plus `tests/unit/refactor88IntendedE2e.guard.unit.test.ts`. | deleted |
| `tests/scripts/provision-router-api-server.mjs`, `tests/scripts/start-servers.mjs`, `tests/scripts/test-router-api-server.mjs` | Refactor 88 | Launched a fake AuthService Router API server through generic Playwright scripts and preserved a flag-controlled fake-relay topology. | Generic Playwright scripts use the Vite-only browser setup; intended contracts own real Router/site lifecycle coverage. Guarded by `tests/unit/refactor88IntendedE2e.guard.unit.test.ts`. | deleted |
| `benchmarks/registration-flow/playwright.config.ts`, `benchmarks/registration-flow/src/report.mjs`, `benchmarks/registration-flow/src/runner.mjs`, `benchmarks/registration-flow/src/scenario-harness.ts`, `benchmarks/registration-flow/src/scenarios.mjs` | Refactor 88 | The runner depended on the deleted `tests/e2e/thresholdEd25519.testUtils` managed-registration mock harness. | Historical reports are retained; any replacement benchmark must use the real intended-behaviour topology. | deleted |
| Browser setup hooks `failureMocks`, `rollbackVerification`, `verifyAccountExists`, `webAuthnUtils`, `loginStatus`, `window.testUtils`, and `createConsoleCapture` | Refactor 88 | Preserved obsolete browser-side mock/control surfaces unrelated to public intended lifecycle behavior. | Refactor 88 guard rejects reintroducing the retired hooks in active setup surfaces. | deleted |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | Refactor 89 / Refactor 73 | Kept a refactor-numbered Playwright source guard alive for a source-layout rule. | Standalone lint-style check `tests/scripts/check-type-filename-source.mjs`, wired into `test:source-guards`. | deleted |

## Validation

Recommended cleanup-batch validation:

```text
pnpm -C tests run test:source-guards
pnpm -C tests exec playwright test tests/unit/<replacement-test>.unit.test.ts --reporter=line
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards
cargo test --manifest-path crates/router-ab-core/Cargo.toml --test source_guards
git diff --check
```

Run broader suites only when deleting a guard changes package boundaries,
public exports, route parsing, HSS material flow, or persisted schema behavior.
