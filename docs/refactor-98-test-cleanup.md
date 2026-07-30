# Refactor 105: Test Cleanup

Date created: July 29, 2026

Status: planned. Audit complete (July 29, 2026); no cleanup executed yet.

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

| Finding | Location | Size |
| --- | --- | --- |
| express→cloudflare 104-test verbatim copy | `tests/relayer/console-router.test.ts` (12,662 LOC) | ~6,000 LOC |
| 3,142-line inline fixture prelude (137 decls) | `tests/relayer/console-d1-adapters.test.ts` (8,070 LOC) | ~3,100 LOC |
| Top-5 unit files: 121 LOC/test, 2.9% assertions | `addWalletSigner.orchestration`, `seamsAuthMenu.fouc`, `emailOtpWalletSessionCoordinator`, `touchConfirm.workerRouter`, `passkeyClientDB.deviceSelection` | ~4,400–5,700 LOC |
| Byte-identical 183-line `beforeEach` | `confirmTxFlow.successPaths` + `confirmTxFlow.defensivePaths` | ~400 LOC incl. 17 redundant inline credential-store mocks |
| Same wire record hand-built in 11 files | `router_ab_ecdsa_derivation_normal_signing_v1` inline vs `helpers/ecdsaSessionRecordVariants.fixtures.ts` (4 importers) | — |
| Dead helper files (zero importers) | `tests/helpers/signingBudgetStatus.ts` (retired surface), `tests/helpers/thresholdEcdsaClientBootstrap.ts` | 242 LOC |
| Type-check gap | `tests/tsconfig.unit.json` covers 20/401 unit files; 3 files import type names that no longer exist; lists deleted `d1WalletRegistrationFinalizeConvergence.unit.test.ts` | — |
| Silent default-run exclusions | `playwright.unit.config.ts` `testIgnore` drops 42 files (31 `*.script.unit.test.ts`, 6 `*.guard.unit.test.ts`, …) | — |
| Only 85/401 unit files import any shared helper | `tests/unit/` | — |

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

- [ ] Delete `tests/helpers/signingBudgetStatus.ts` (its production
      counterpart `signingBudgetStatus.ts` was deleted in `9cacbe037`; this
      helper also hand-declares snapshots of the retired types).
- [ ] Delete `tests/helpers/thresholdEcdsaClientBootstrap.ts` (3 exports,
      zero importers repo-wide).
- [ ] Remove the stale `unit/d1WalletRegistrationFinalizeConvergence.unit.test.ts`
      entry from `tests/tsconfig.unit.json` (file deleted in `22e6b3394`).
- [ ] Fix the three phantom type imports (erased at runtime, never
      type-checked): `EcdsaRelayerDerivationPublicKey33B64u` →
      `EcdsaDerivationRelayerPublicKey33B64u` in
      `thresholdSessionClaims.unit.test.ts`,
      `browserPlatformRuntime.signerCrypto.unit.test.ts`,
      `walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts`; and
      `EcdsaDerivationClientCustomRequest` →
      `EcdsaDerivationClientCustomRequestType` in
      `postRegistrationSessionActivation.unit.test.ts`.
- [ ] Verify the suspect assertion in
      `cloudflareD1ConsoleServices.unit.test.ts:637`
      (`/relay/router-ab/ed25519/yao/registration/admit` no longer exists in
      src): run the file, classify per AGENTS.md, delete the test if it
      asserts a retired route.
- [ ] Rename refactor-numbered test files to behaviour-based names (they test
      current code; only the names are stale): `refactor92.*.unit.test.ts`
      (4 files), `refactor93IntendedFaultIsolation.unit.test.ts`,
      `phase5UseCaseServices.unit.test.ts`. Drop the misleading `.audit.`
      segment (2 of the 4 are not audits). Update
      `check-refactor88-test-ledger.mjs` references if any renamed file is in
      its ledger.

Validation: `pnpm -C tests type-check:unit`; run each renamed/edited file
individually via `playwright test -c playwright.unit.config.ts <file>`;
`pnpm -C tests check:refactor88-test-ledger`.

## Phase 1 — Relayer dedup (largest single win)

- [ ] `console-router.test.ts`: replace the `console router (express)` /
      `console router (cloudflare)` twin describe blocks (104 tests each,
      bodies identical modulo transport plumbing and `-cf` id suffixes) with
      one `for (const runtime of ['express', 'cloudflare'])` parameterization
      over the existing `startExpressRouter` / `callCf` helpers in
      `tests/relayer/helpers.ts`. Diff each merged pair during review; any
      pair whose bodies differ beyond transport gets kept as an explicit
      per-runtime test. Expected: ~6,000 LOC removed, test count unchanged
      (208 executed tests, now generated).
- [ ] `console-d1-adapters.test.ts`: move the 3,142-line prelude (the 5
      harness classes, `applyConsoleD1Migrations`, the ~30
      `buildRawD1*InsertInput` builders) into `tests/relayer/helpers/` (new
      files, e.g. `consoleD1.fixtures.ts`) or `tests/helpers/sqliteD1.ts`
      where generic.
- [ ] Deduplicate per-file reimplementations across `tests/relayer/`:
      `makeConsoleAuthAdapter` (3 copies), `randomNamespace` (2 copies) →
      `tests/relayer/helpers.ts`. Target: >20 of 30 files importing
      `./helpers` (today: 6).

Validation: `pnpm -C tests test:relayer` before and after; assert identical
test titles and counts (compare `--list` output).

## Phase 2 — Top-5 unit files: extract, parametrize, split

Per-file worklist (targets from the audit; split misnamed monoliths while the
fixtures move):

- [ ] `addWalletSigner.orchestration.unit.test.ts` (3,311): move
      `installRegisterWalletFetch` / `installAddSignerFetch` (two ~400-line
      hand-rolled fetch route servers sharing structure) to
      `tests/unit/helpers/registrationRouteMockServer.fixtures.ts` with a
      `withRegisterWalletFetch(async (captures) => …)` wrapper (the
      install/try/finally/restore pattern repeats 18×). Replace local
      `mockedEcdsa*` records with `helpers/ecdsaBootstrap.fixtures.ts`
      equivalents. Table-drive the four invalid-bootstrap rejection tests.
      Split: 17 of 20 tests are `registerWallet`, not `addWalletSigner` —
      two files. Target: −900–1,200 LOC.
- [ ] `seamsAuthMenu.fouc.unit.test.ts` (3,230): extract a browser-side mount
      helper (the React `createRoot`/`flushSync` block is repeated 30×, the
      config literal 13×, the stylesheet load-promise 12×) using the same
      `/_test-sdk/` served-module mechanism the file already uses for
      `IMPORT_PATHS`. Share `IMPORT_PATHS` with
      `seamsAuthMenu.accountAvailability` and the wallet-iframe qrButton
      test. Split by subject: FOUC/styles (~2 tests), Google SSO/Email OTP
      flows, passkey + dropdown. Target: −1,300–1,700 LOC.
- [ ] `passkeyClientDB.deviceSelection.test.ts` (2,276): the inline
      `activateSignerFixture` is duplicated verbatim 15× (~600 LOC, 26% of
      the file) and reimplements
      `helpers/accountSignerRecord.fixtures.ts` — import it instead.
      Table-drive the three `activateAccountSigner` rejection tests. Split:
      12 of 18 tests are signer-activation lifecycle, not device selection.
      Target: −900–1,100 LOC.
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
- [ ] `warmSessionStore`: fold `bootstrapResolution.unit.test.ts` (88 LOC,
      1 test, structural clone of `capabilityResolution`'s last test) into
      `capabilityResolution.unit.test.ts`. Leave the tripled cookie-Ed25519
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

- [ ] Widen `tests/tsconfig.unit.json` from the 20-file allowlist toward
      `unit/**/*.test.ts`. Adopt incrementally (the standing estimate is 563
      errors at full adoption): add files as Phases 2–3 touch them, then
      burn down the remainder. `pnpm -C tests type-check:unit` joins
      `pnpm check` when the include is directory-wide.
- [ ] Extend the existing anti-literal lint (from the test-staleness work) to
      flag the audit's violation patterns: inline
      `router_ab_ecdsa_derivation_normal_signing_v1` wire records (11 files
      today), `} as unknown as <DomainRecord>` casts, and locally-declared
      shadow record types in test files (5 files today).
- [ ] Audit `playwright.unit.config.ts` `testIgnore`: each of the 42 excluded
      files must be either (a) covered by another config that CI actually
      runs (`playwright.scripts.config.ts`, `playwright.integration.config.ts`
      — verify CI invokes them), or (b) deleted. No silently-never-run tests.
- [ ] Fix the self-skip-on-import-error pattern (`safari-fallbacks`,
      `nearClient`, `userHandle.parse` — 13 of the 20 skips): distinguish
      "environment dependency unavailable" (skip) from "import threw"
      (fail). Today a broken SDK import shows as a green skip.
- [ ] Add the shared-helper adoption expectation to `tests/AGENTS.md`
      explicitly: new unit test files that build complex domain state must
      import from `helpers/`; reviewers treat a new >100-line inline fixture
      as a defect. (Policy text already exists; make the file-creation case
      explicit.)

Validation: `pnpm -C tests type-check:unit` green at each widening step;
lint chain green; CI config inspected for the excluded-pattern configs.

## Expected outcome

| Phase | LOC removed (est.) |
| --- | --- |
| 0 | ~350 |
| 1 | ~9,000 |
| 2 | ~4,400–5,700 |
| 3 | ~1,000–1,500 |
| 4 | 0 (prevention) |
| **Total** | **~15,000–16,500** |

Success criteria: test-title inventory (`--list`) unchanged except for
documented merges/renames; `pnpm test:unit`, `pnpm test:relayer`,
`pnpm test:intended`, and `pnpm check` green; helper-import rate in
`tests/unit/` rises from 85/401 toward the majority; no new inline
domain-record literals pass lint.
