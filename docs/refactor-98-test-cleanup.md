# Refactor 98: Test Cleanup

Date created: July 29, 2026

Status: implementation in progress. Phases 0–1 are complete; Phase 2 is partial;
Phase 4 has initial enforcement. Rebaselined August 6, 2026 against current
`dev`.

Checklist markers: `[x]` complete, `[~]` partial in this pass, `[ ]` still open.

Later refactors already removed the obsolete signing-budget helper, the deleted
D1 convergence test, the old auth-menu monolith, the warm-session-store cluster,
and the public-key source grep. The remaining checklist below is authoritative;
completed or superseded entries are marked explicitly.

## Goal

Remove ~15–20k lines of duplicated test scaffolding with zero coverage loss,
and add the enforcement that stops it regrowing.

The July 2026 audit found the suite is not over-testing: ~184k TS test LOC vs
~428k source LOC and ~4,600 unit tests are normal proportions. The problem is
lines-per-test. The five largest unit files average 121 LOC per test with 2.9%
assertion lines; the two largest relayer files hold 64% of relayer LOC. The
disease is copy-pasted setup — the same fixture blocks, mock servers, and mount
harnesses re-inlined per test and per file instead of imported from
`tests/unit/helpers/` and `tests/helpers/`. The unit suite grew +63% in files
in the three months to July 2026, so untreated this compounds.

Proof the bloat is avoidable: files that follow the existing factory policy
(`emailOtpWalletSessionCoordinator.unit.test.ts`, the `warmSessionStore*`
cluster) are ~2× leaner at the same domain complexity, with zero cross-file
duplicate blocks in the `warmSessionStore*` cluster.

## Non-goals

- No reduction in behavioural coverage. Every deleted line is setup
  duplication, a redundant duplicate test, or dead code — never a unique
  assertion.
- No rewrites of healthy clusters (`warmSessionStore*` beyond two small folds,
  the four small `confirmTxFlow` files, `seamsWeb.chainSigners` scenarios).
- No new source-text guards (per refactor-88B policy: prefer types, lint, and
  behaviour tests).

## Evidence baseline (July 29, 2026)

| Finding                                         | Location                                                                                                                                                                  | Size                                                      |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| express→cloudflare 104-test verbatim copy       | `tests/relayer/console-router.test.ts` (12,662 LOC)                                                                                                                       | ~6,000 LOC                                                |
| 3,142-line inline fixture prelude (137 decls)   | `tests/relayer/console-d1-adapters.test.ts` (8,070 LOC)                                                                                                                   | ~3,100 LOC                                                |
| Top-5 unit files: 121 LOC/test, 2.9% assertions | `addWalletSigner.orchestration`, `seamsAuthMenu.fouc`, `emailOtpWalletSessionCoordinator`, `touchConfirm.workerRouter`, `passkeyClientDB.deviceSelection`                 | ~4,400–5,700 LOC                                          |
| Byte-identical 183-line `beforeEach`            | `confirmTxFlow.successPaths` + `confirmTxFlow.defensivePaths`                                                                                                             | ~400 LOC incl. 17 redundant inline credential-store mocks |
| Same wire record hand-built in 11 files         | `router_ab_ecdsa_derivation_normal_signing_v1` inline vs `helpers/ecdsaSessionRecordVariants.fixtures.ts` (4 importers)                                                   | —                                                         |
| Dead helper files (zero importers)              | July baseline: `tests/helpers/signingBudgetStatus.ts` (retired surface) and `tests/helpers/thresholdEcdsaClientBootstrap.ts`; both are absent on the current rebaseline | 242 LOC                                                   |
| Type-check gap                                  | `tests/tsconfig.unit.json` covers 20/401 unit files; 3 files import type names that no longer exist; lists deleted `d1WalletRegistrationFinalizeConvergence.unit.test.ts` | —                                                         |
| Silent default-run exclusions                   | `playwright.unit.config.ts` `testIgnore` drops 42 files (31 `*.script.unit.test.ts`, 6 `*.guard.unit.test.ts`, …)                                                         | —                                                         |
| Only 85/401 unit files import any shared helper | `tests/unit/`                                                                                                                                                             | —                                                         |

## Sequencing

- Phases are independent except Phase 4 (enforcement), which should land last
  so lint/type-check rules validate against the cleaned-up suite, not the
  current one.
- Runs alongside the existing unit type-check adoption effort (563 errors on
  full adoption, tracked from the test-staleness work); Phase 4 is that
  effort's forcing function.
- Per `AGENTS.md`: keep stale-test deletions, helper extractions, and any
  production fixes in separate commits. One failed repair attempt on a
  lower-authority test ⇒ stop and reclassify before touching anything else.

## Phase 0 — Hygiene deletions (small, zero-risk)

- [x] Confirm `tests/helpers/signingBudgetStatus.ts` is already absent on the
      current rebaseline (the retired production/helper pair was removed by a
      prior refactor; no compatibility copy is reintroduced here).
- [x] Delete `tests/helpers/thresholdEcdsaClientBootstrap.ts` (3 exports,
      zero importers repo-wide).
- [x] Remove the stale `unit/d1WalletRegistrationFinalizeConvergence.unit.test.ts`
      entry from `tests/tsconfig.unit.json` (file deleted in `22e6b3394`).
- [x] Fix the remaining phantom type import (erased at runtime, previously never
      type-checked): `EcdsaRelayerDerivationPublicKey33B64u` →
      `EcdsaDerivationRelayerPublicKey33B64u` in
      `browserPlatformRuntime.signerCrypto.unit.test.ts`. The other audited
      imports were already corrected or removed by later refactors.
- [x] Verify the suspect assertion in
      `cloudflareD1ConsoleServices.unit.test.ts:637`
      (`/relay/router-ab/ed25519/yao/registration/admit` no longer exists in
      src): run the file, classify per AGENTS.md, delete the test if it
      asserts a retired route.
- [x] Rename refactor-numbered test files to behaviour-based names (they test
      current code; only the names are stale): `refactor92.*.unit.test.ts`
      (4 files), `refactor93IntendedFaultIsolation.unit.test.ts`,
      `phase5UseCaseServices.unit.test.ts`. Drop the misleading `.audit.`
      segment (2 of the 4 are not audits). Update active documentation
      references for the renamed files.

Validation: `pnpm -C tests type-check:unit`, focused Playwright runs for the
renamed/edited files, and `git diff --check`. The historical Refactor 88 ledger
command is not present in the current `tests/package.json` and is not treated
as a live gate.

## Phase 1 — Relayer dedup (largest single win)

- [x] `console-router.test.ts`: remove the verbatim Cloudflare copy while
      retaining the 104 shared Fetch-router tests once under the Express
      harness and two explicit Cloudflare adaptor tests for runtime-specific
      routing/storage boundaries. The shared Fetch layer is the R97 portable
      surface, so parameterizing identical Express/Cloudflare bodies would
      preserve the duplicate rather than test a distinct adaptor contract.
      The file now contains 106 tests instead of 208 and is ~7,053 LOC.
- [x] `console-d1-adapters.test.ts`: move the 3,142-line prelude (the 5
      harness classes, `applyConsoleD1Migrations`, the ~30
      `buildRawD1*InsertInput` builders) into
      `tests/relayer/helpers/consoleD1.fixtures.ts`. The test file is now
      ~4,967 LOC and the shared fixture module is ~2,968 LOC.
- [x] Deduplicate per-file reimplementations across `tests/relayer/`:
      `makeConsoleAuthAdapter` (3 copies), `randomNamespace` (2 copies) →
      `tests/relayer/helpers.ts`. The shared adapter and namespace generator
      are now used by the affected router and sponsored-call tests; the
      sponsored-history adapter no longer carries a private adapter class.

Validation: the extracted D1 suite ran with 34 passing and 5 existing
environment/schema failures. The full relayer suite and a before/after title
inventory remain open; the shared-router reduction intentionally removes the
duplicate Cloudflare title set.

## Phase 2 — Top-5 unit files: extract, parametrize, split

Per-file worklist (targets from the audit; split misnamed monoliths while the
fixtures move):

- [~] `addWalletSigner.orchestration.unit.test.ts` (3,483 after current
      fixture repair): the repeated registration/add-signer fetch installation
      is now wrapped locally by `withRegisterWalletFetch` and
      `withAddSignerFetch`, and the IndexedDB/auth fixtures are normalized. The
      wrappers have not yet moved into a shared helper file or split the
      register/add-signer subjects. The file remains a focused follow-up.
      The original work item targeted the two ~400-line hand-rolled fetch route
      servers, shared ECDSA bootstrap fixtures, table-driven rejection cases,
      and a register/add-signer split. Target: −900–1,200 LOC.
- [x] `seamsAuthMenu.fouc.unit.test.ts` (3,230): superseded by the R90/R97
      auth-menu move; the old monolith is absent from the current tree. Keep
      the surviving wallet-iframe and SSR/account-availability coverage in
      their current owners instead of recreating the deleted file.
- [~] `passkeyClientDB.deviceSelection.test.ts` (1,578 after current fixture
      repair): the repeated `activateSignerFixture`/NEAR seed and IndexedDB
      setup are centralized behind one installer in the file, removing the
      duplicated setup while preserving the 16/16 focused result. The planned
      shared-helper extraction, table-driven rejection cases, and subject
      split remain open. The previous monolith was 2,276 LOC.
- [ ] `touchConfirm.workerRouter.integration.test.ts` (2,293): hoist the
      `fakeWorker` literal (15×) and listener/emit wiring (17×) into a
      browser-side `makeWorker` helper (the test at line 1548 already proves
      the pattern works inside `page.evaluate`). Adopt
      `helpers/warmSessionUiConfirm.fixtures.ts` like the 10 other files
      that use it. Split: lines ~874–2100 are sealed-mode persistence, a
      separate subject from worker-router plumbing. Target: −800–1,000 LOC.
- [ ] `emailOtpWalletSessionCoordinator.unit.test.ts` (2,674): lowest
      priority — already factory-based. Add a
      `createCoordinator({ preset: 'sealedRefresh', expiresAtMs })` preset to
      kill the 5 re-inlined ~35-line rehydrate responses; table-drive the
      three transaction-challenge rejections. Target: −500–700 LOC.

Validation: run each touched file individually
(`playwright test -c playwright.unit.config.ts <file>`); compare `--list`
titles before/after each split so no test silently drops. Full
`pnpm test:unit` once per batch, not per file.

## Phase 3 — Cluster consolidation

- [ ] `confirmTxFlow`: extract the byte-identical 183-line `beforeEach`
      (`__buildTestNearProfileAccountContext`,
      `installIndexedDbClientForwarder`, `__attachTestWebAuthnCredentialStore`,
      `__attachTestNonceCoordinator`) from `successPaths` + `defensivePaths`
      into `tests/unit/helpers/`; delete the 17 inline credential-store mocks
      that re-install what the `beforeEach` already installs; then decide
      merge vs keep-split (same module, same flows — split axis is
      success/failure, not concern). Share the `IMPORT_PATHS` literal
      currently redeclared in 8 files.
- [ ] `seamsWeb` / wallet-iframe: move `WALLET_STUB_RESPONSE_SCRIPT` (two
      copies differing by one brace, comment typos copied verbatim) and the
      `WALLET_ORIGIN` / `WALLET_SERVICE_ROUTE` constants (6 redeclarations)
      into `tests/wallet-iframe/harness.ts`. Fold the single test in
      `seamsWeb.duplicateIframes.guardrails.unit.test.ts` into
      `seamsWeb.initWalletIframe.concurrent.unit.test.ts` (same invariant,
      same stub).
- [x] `warmSessionStore`: the one-test `bootstrapResolution.unit.test.ts`
      clone is already absent after the later warm-session cleanup; the
      capability-resolution owner remains. Leave the tripled cookie-Ed25519
      invariant alone (three distinct public surfaces — defensible).
- [ ] `thresholdEcdsa*` vs `ecdsa*`: pick one prefix rule for the 30-file
      subject area and rename to it (12 dot-case vs 4 camelCase within
      `thresholdEcdsa*` alone; `thresholdEcdsa.bootstrapPersistence` vs
      `ecdsaBootstrapWarmPersistence` are same-name-different-module). Then
      resolve the three overlapping pairs, keeping the better-factored side:
      records-ambiguity policy (`thresholdEcdsaEmailOtpConsumption` ×3 tests
      vs `ecdsaRoleLocalRecords` ×2), lane identity
      (`thresholdEcdsaChainTarget` vs `ecdsaLanes.identity`),
      sealed-refresh parity (`registrationBootstrapParity` vs
      `emailOtpBootstrapCommit`). Replace the copy-pasted relayer fetch stub
      in `thresholdEcdsa.authorizationBootstrapVerifier` +
      `ecdsaExplicitExportProvisionIsolation` with
      `createThresholdEcdsaBootstrapFixture`.
- [ ] Fold the two near-trivial files into neighbours:
      `thresholdEcdsa.derivationErrorCodes.unit.test.ts` (58 LOC, hardcoded
      error-code list, no runtime import — consider converting to a
      `tests/typecheck/` fixture) and
      `thresholdEcdsa.publicKeyFieldRegression.unit.test.ts` (41 LOC,
      fs-grep over source — retire per refactor-88B guard policy or move to
      the source-guard chain where it belongs).

Validation: per-file runs plus one full `pnpm test:unit`;
`pnpm check` for the boundary scripts after renames.

## Phase 4 — Enforcement (stops the regrowth)

- [x] Widen `tests/tsconfig.unit.json` incrementally from the stale allowlist:
      the deleted D1 entry is gone, and the six renamed Phase 0 tests plus the
      three import-failure tests are now included in 35 include entries (33
      named unit tests plus helper/type globs).
      Full `unit/**/*.test.ts` adoption remains open because the current suite
      still has the known unresolved-error migration.
- [ ] Extend the existing anti-literal lint (from the test-staleness work) to
      flag the audit's violation patterns: inline
      `router_ab_ecdsa_derivation_normal_signing_v1` wire records (11 files
      today), `} as unknown as <DomainRecord>` casts, and locally-declared
      shadow record types in test files (5 files today).
- [~] Audit `playwright.unit.config.ts` `testIgnore`: the current 28 source/
      script/guard files are matched by `playwright.source.config.ts`, and the
      recursive script matcher now covers nested `*.script.unit.test.ts` files.
      The repository workflows do not currently invoke either source or script
      config, so CI wiring remains open before this item can be marked complete.
- [x] Fix the self-skip-on-import-error pattern (`safari-fallbacks`,
      `nearClient`, `userHandle.parse` — 13 tests): dynamic SDK imports now run
      outside operation-result catches, so module-load failures fail collection
      or the test. No external dependency skip applies to these pure tests.
- [x] Add the shared-helper adoption expectation to `tests/AGENTS.md`
      explicitly: every new unit file that builds complex domain state imports
      a shared factory, and a newly introduced inline fixture over 100 lines is
      a review defect.

Validation: `pnpm -C tests type-check:unit` is green and `git diff --check`
passes. The recursive script matcher and self-skip fixes are covered; CI wiring
for the source/script configs and the anti-literal lint remain open.

## Expected outcome

| Phase     | LOC removed (est.) |
| --------- | ------------------ |
| 0         | ~350               |
| 1         | ~9,000             |
| 2         | ~4,400–5,700       |
| 3         | ~1,000–1,500       |
| 4         | 0 (prevention)     |
| **Total** | **~15,000–16,500** |

Success criteria: test-title inventory (`--list`) unchanged except for
documented merges/renames; `pnpm test:unit`, `pnpm test:relayer`,
`pnpm test:intended`, and `pnpm check` green; helper-import rate in
`tests/unit/` rises from 85/401 toward the majority; no new inline
domain-record literals pass lint. The current pass is not yet at those final
gates: the focused checks are green, while the broad relayer/unit suites still
need their environment-backed reruns and the remaining Phase 2–4 work.

## Current implementation snapshot — August 6, 2026

| Area | Current result |
| ---- | -------------- |
| Relayer shared-router coverage | `console-router.test.ts`: ~7,053 LOC, 106 tests (104 shared Fetch-router cases plus 2 Cloudflare adaptor cases) |
| Shared-router focused run | 94/106 passed; the 12 failures are lower-authority authorization/fixture drift in the Express cases, while both Cloudflare adaptor checks pass |
| D1 fixture prelude | `console-d1-adapters.test.ts`: ~4,967 LOC; `helpers/consoleD1.fixtures.ts`: ~2,968 LOC |
| Registration orchestration fixtures | `addWalletSigner.orchestration.unit.test.ts`: 19 tests; 17 passed in the focused rerun, with 2 lower-authority NEAR provisioning timing/write failures under review |
| Passkey DB fixture reduction | `passkeyClientDB.deviceSelection.test.ts`: 2,276 → 1,578 LOC; focused run 16/16 passed |
| Checked unit surface | `tests/tsconfig.unit.json`: 35 include entries, 33 named unit tests plus helper/type globs |
| This pass measured diff | 11,188 deleted lines and 4,843 added lines across the touched test/doc surface (the added total includes the extracted D1 fixture module) |

The remaining estimates are prospective work, not delivered savings. The five
D1 failures are retained as pre-existing lower-authority migration, billing,
reconciliation, and recovery-preparation cases pending their owning environment
and fixture review.
