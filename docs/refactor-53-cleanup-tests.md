# Refactor 53: Legacy Test and Guard Cleanup

Date updated: June 2, 2026

Status: Planned

## Goal

Remove bloated legacy-refactor tests and guards that no longer protect current
behavior. Keep tests that enforce protocol correctness, security invariants,
public API contracts, persistence boundaries, and user-visible signing flows.

This cleanup should make the test suite faster and less brittle without
weakening the gates that catch real regressions.

## Problem

The current test suite has accumulated refactor-era sediment:

- guard tests that assert exact filenames, folder lists, string snippets, and
  obsolete type names
- broad allowlists that require maintenance whenever a valid architecture move
  lands
- browser-backed tests mixed into unit profiles
- duplicate assertions for the same session, budget, lane, and restore
  invariants across several layers
- fixtures that encode historical compatibility behavior after the production
  path has moved on

This makes closeout work noisy. A focused refactor can be complete while old
guards still fail because they were written against a previous architecture.

Current scan notes:

- `tests/unit` has 279 top-level test files.
- `pnpm -C tests run test:unit` runs all of `tests/unit`, so it includes unit,
  guard, browser-backed integration, source-script, and WASM replay suites.
- The largest legacy guard suites are:
  - `signingEngine.refactor33.guard.unit.test.ts`: 114 tests
  - `signingEngine.refactor36.guard.unit.test.ts`: 88 tests
  - `refactor5xCrossPlatform.guard.unit.test.ts`: 60 tests
  - `refactor46d.guard.unit.test.ts`: 36 tests
- The current scripts already recognize some slow profiles, for example
  `test:signer-parity:web-wasm-replay`, but `test:unit` still sweeps those
  files because they live under `tests/unit`.

## Keep

These tests remain part of the core gate:

- protocol and crypto vectors for Ed25519, ECDSA, WASM command surfaces,
  transaction serialization, export, recovery, and signature verification
- parser and persistence boundary tests for malformed, legacy, or incomplete
  external records
- auth, signing-session, budget, and step-up tests that enforce signer-bound
  budget ownership and consumption
- registration, unlock, restore, sign, and export tests that validate current
  passkey and Email OTP flows
- public SDK type checks and public request/response contract fixtures
- small architectural guards that block forbidden compatibility paths,
  direct raw persistence access, unsafe casts, and direct platform API usage in
  core logic

## Delete

Delete tests when they only protect historical implementation details:

- guards that require old top-level folder inventories to remain frozen
- guards that fail solely because a new current owner folder was added
- tests that assert exact source text snippets instead of behavior or public
  contracts
- allowlist count tests where the count is not itself a real invariant
- fixtures whose only purpose is to preserve obsolete compatibility paths
- duplicate tests that prove the same lane/session invariant at multiple
  non-boundary layers
- refactor-specific tests for work that is already complete and now covered by
  current domain tests

Compatibility tests are allowed only at persistence and request boundaries.
Once a compatibility shape is intentionally rejected or deleted in production,
its supporting fixture data should be deleted too.

Deletion requires a short note in the cleanup PR that states one of:

- obsolete behavior: production no longer supports the behavior
- duplicate coverage: name the current test that already protects the invariant
- integration relocation: name the new integration command that owns it
- boundary-only: coverage moved to a parser or request-boundary test

## Rewrite

Rewrite tests that still express a useful invariant but are too brittle.

Examples:

- Replace exact import-list snapshots with forbidden-import assertions.
- Replace folder-list freezes with ownership README checks for currently active
  top-level domains.
- Replace source-snippet checks with type fixtures or boundary parser tests.
- Replace broad string scans with AST-aware checks where practical, or with
  small targeted regexes over named files.
- Replace allowlist occurrence counts with explicit tests for the intended
  remaining owner path.
- Move slow browser/WASM replay tests out of `test:unit` into an integration
  profile.

## Target Test Profiles

### Fast Closeout Gate

Run on every refactor closeout:

```sh
pnpm -s type-check:sdk
pnpm -s type-check:relay-server
pnpm -C sdk run build:prepare
pnpm -C tests run test:signers:gates
pnpm -C tests exec playwright test ./unit/registrationIntentAllocation.unit.test.ts ./unit/sessionTokens.unit.test.ts --reporter=line
```

This gate should stay under a few minutes and catch type drift, public SDK
breakage, signer-domain guard failures, registration intent regressions, and
session-token contract regressions.

### Core Signing Gate

Run before merge for auth/session/sign/export work:

```sh
pnpm -C tests exec playwright test \
  ./unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts \
  ./unit/thresholdEd25519.thresholdSessionState.unit.test.ts \
  ./unit/privateKeyExportRecovery.binding.unit.test.ts \
  ./unit/evmFamilyEcdsaIdentity.unit.test.ts \
  ./unit/warmSessionStore.errorNormalization.unit.test.ts \
  --reporter=line
```

Add or remove files based on current ownership, but keep the gate focused on
current domain contracts.

### Integration Gate

Move browser-heavy and WASM-heavy flows here:

- `seamsPasskey.chainSigners.unit.test.ts`
- `signingVectors.webWasmReplay.unit.test.ts`
- `thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `touchConfirm.workerRouter.unit.test.ts`
- any test that launches full SDK/browser runtime, real WASM replay, or
  end-to-end transaction lifecycle simulation

These should run before release and in CI integration jobs, not as the default
unit closeout signal.

### Source-Guard Gate

Run explicitly when changing folder ownership, exports, generated source,
signing-root script wiring, or platform boundaries:

```sh
pnpm -C tests run test:source-guards
```

This command does not exist yet. It should own source-scanning and script
surface tests that remain useful after the cleanup. It should not be part of the
default unit profile.

Use filename patterns that match the current suite. A glob such as
`./unit/**/*.{guard,script}.test.ts` does not match files named
`*.guard.unit.test.ts`, `*.script.unit.test.ts`, or
`*.source.script.unit.test.ts`.

## Phase 0: Inventory

Create `docs/refactor-53-test-inventory.csv` with one row per guard or large
fixture-heavy suite. This inventory is the deletion ledger and must stay updated
as files move, split, or disappear.

Fields:

- file path
- owner domain
- profile: fast closeout, core signing, integration, or delete
- protected invariant
- reason it still matters
- rewrite/delete decision
- replacement coverage if deleted
- owning command after cleanup
- deletion reason when deleted: obsolete behavior, duplicate coverage,
  integration relocation, or boundary-only
- fixture/helper cleanup completed

Initial candidates:

- `tests/unit/signingEngine.refactor33.guard.unit.test.ts`
- `tests/unit/signingEngine.refactor36.guard.unit.test.ts`
- `tests/unit/refactor46d.guard.unit.test.ts`
- `tests/unit/refactor47.walletScopedLookups.guard.unit.test.ts`
- `tests/unit/refactor5xCrossPlatform.guard.unit.test.ts`
- `tests/unit/indexedDBConsolidation.guard.unit.test.ts`
- `tests/unit/seamsPasskey.chainSigners.unit.test.ts`
- `tests/unit/signingVectors.webWasmReplay.unit.test.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/unit/touchConfirm.workerRouter.unit.test.ts`
- `tests/unit/thresholdSigningRootParityBaseline.script.unit.test.ts`
- `tests/unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts`
- `tests/unit/emailRecoveryVerifiedRequest.source.script.unit.test.ts`
- `tests/unit/profileContinuity.source.script.unit.test.ts`
- `tests/unit/recoveryDomain.source.script.unit.test.ts`
- `tests/unit/signingRoot*.script.unit.test.ts`
- `tests/unit/thresholdEd25519.*.script.unit.test.ts`
- `tests/unit/thresholdPrf*.script.unit.test.ts`
- `tests/unit/wasmLoader.runtimePaths.script.unit.test.ts`

## Initial Disposition Candidates

These are starting recommendations from the first scan. Confirm each during
Phase 0 before deleting files.

| File or group | Current issue | Recommended action |
| --- | --- | --- |
| `signingEngine.refactor33.guard.unit.test.ts` | Very large source-shape guard suite. Freezes old folder contracts, index barrels, exact imports, deleted names, and source snippets. | Split. Keep a small current architecture guard; delete folder/index freezes and exact snippet checks; move remaining source checks to `test:source-guards`. |
| `signingEngine.refactor36.guard.unit.test.ts` and `signingEngine.refactor36.allowlists.ts` | Large finite occurrence-count allowlists for naming cleanup. Fails on legitimate current code movement. | Delete occurrence-count tests. Keep only targeted forbidden ECDSA account-identity derivation checks that express current behavior. |
| `refactor5xCrossPlatform.guard.unit.test.ts` | Mixes useful platform-boundary checks with stale migration allowlists. | Rewrite around current platform boundaries. Keep direct platform API bans in core; delete migration allowlists whose deletion trigger has passed. |
| `refactor46d.guard.unit.test.ts` | Contains some valuable Email OTP/ECDSA branch isolation checks, plus brittle source snippets. | Keep branch-isolation behavior checks. Replace snippet checks with targeted parser/type tests or delete when duplicated. |
| `refactor47.walletScopedLookups.guard.unit.test.ts` | Small guard for an older wallet-scoped lookup cleanup. | Delete if covered by current wallet-session ECDSA identity and request-boundary tests. Otherwise rewrite as one current invariant test. |
| `indexedDBConsolidation.guard.unit.test.ts` | Historical consolidation guard with many source assertions. | Audit for current persistence-boundary value. Delete or move only durable forbidden-store checks to source guards. |
| `emailOtpOperationSplit.guard.unit.test.ts` | Guards current Email OTP registration/login operation split. | Keep, but rename out of legacy guard language if it remains current. |
| `nonceCoordinator.durableArchitecture.guard.unit.test.ts` | Guards current nonce durability architecture. | Keep in core signing or source-guard profile depending on runtime cost. |
| `keyExport.behavior.guard.unit.test.ts` | Likely current user-visible export invariant. | Keep if it tests behavior. Rename if “guard” only means behavior regression. |
| `thresholdEcdsa.behavior.guard.unit.test.ts` | Mix of current behavior and crate-source scanning. | Split behavior tests from source checks. Move source checks to `test:source-guards`. |
| `seamsPasskey.chainSigners.unit.test.ts` | Large SDK/high-level chain signer flow suite; not a unit suite. | Move to integration signing profile. Keep only pure serialization/error mapping tests in unit files. |
| `signingVectors.webWasmReplay.unit.test.ts` | WASM replay and worker wrapper integration. Existing script already treats this as signer parity. | Rename/move to integration or signer parity path; exclude from `test:unit`. |
| `thresholdEcdsa.tempoHighLevel.unit.test.ts` | Full browser-backed threshold ECDSA Tempo flow. | Move to `test:integration:signing` or `test:threshold-core`; exclude from `test:unit`. |
| `touchConfirm.workerRouter.unit.test.ts` | Worker/router integration with persistence and runtime restore behavior. | Move to integration signing profile unless specific pure parser cases are split out. |
| `*.source.script.unit.test.ts` | Source scanners masquerading as unit tests. | Move to `test:source-guards`; delete any that only checks obsolete doc-era wiring. |
| `signingRoot*.script.unit.test.ts` | Script/source wiring around signing root and secrets. Some are security-sensitive. | Keep security-sensitive checks, but run under `test:source-guards` or a signing-root script profile. |
| `thresholdSigningRootParityBaseline.script.unit.test.ts` | Baseline pin can fail due intentional deterministic derivation changes. | Keep only if release/native parity requires it; otherwise convert to vector test with explicit regeneration workflow. |
| Legacy sealed-session tests in `sealedSessionStore.unit.test.ts` | Boundary tests for rejected or cleaned old IndexedDB shapes. | Keep only parser/migration boundary cases. Delete tests for unsupported retired DB compatibility after data reset. |
| `availableSigningLanes.*Duplicates.unit.test.ts` legacy sealed-record cases | Some cases assert ignoring legacy chain-only records. | Keep only if the boundary parser still accepts that input. Delete once production no longer reads the old shape. |
| `confirmTxFlow.*` legacy `profileId: legacy-near:*` fixtures | Repeated historical profile shape in UI confirm fixtures. | Replace with canonical profile fixture builder or delete if unrelated to the tested path. |

Acceptance:

- every legacy refactor guard has an owner decision
- every delete decision names replacement coverage or says the behavior is
  obsolete
- no compatibility-only fixture remains outside a boundary test
- security-sensitive guard deletions map to current behavior tests, type
  fixtures, parser boundary tests, source-guard commands, or native/vector
  parity suites

## Phase 0.5: Establish Replacement Gates First

Add the replacement commands before deleting or relocating coverage.

Work:

- add a working `test:source-guards` command
- add a working `test:integration:signing` command
- update `test:unit` so it cannot accidentally sweep source guards,
  source-script tests, WASM replay suites, full SDK iframe flows, worker-router
  flows, relayer-backed flows, or high-level transaction lifecycle simulations
- run the old broad command and the new split commands once, then record each
  moved suite's owning command in `docs/refactor-53-test-inventory.csv`
- keep existing focused commands such as `test:threshold-core`,
  `test:threshold-ed25519:active-path`, and
  `test:signer-parity:web-wasm-replay`, but make sure their files are not also
  swept by `test:unit`

Source-guard command shape:

```sh
playwright test -c playwright.scripts.config.ts \
  './unit/**/*.guard.unit.test.ts' \
  './unit/**/*.script.unit.test.ts' \
  './unit/**/*.source.script.unit.test.ts' \
  --reporter=line
```

Acceptance:

- `pnpm -C tests run test:unit -- --list` contains no `*.guard.unit.test.ts`,
  `*.script.unit.test.ts`, `*.source.script.unit.test.ts`, WASM replay, full SDK
  iframe, worker router, relayer-backed flow, or high-level transaction
  lifecycle simulation files
- every moved file remains runnable through exactly one documented command
- deletion work can cite an existing replacement command or explicit obsolete
  behavior before removing a file

## Phase 1: Delete Obsolete Guards

Remove guards that freeze previous refactor architecture instead of current
behavior.

Work:

- delete exact folder-count and index-barrel freezes that conflict with current
  Refactor 51 ownership
- delete obsolete deleted-symbol guards once the symbol is already absent from
  production and covered by current type names
- delete tests that fail only because a new current owner module exists
- delete supporting allowlists that exist only for those guards

Acceptance:

- no guard needs updates for valid new owner folders
- no guard encodes old architecture as the desired architecture
- deleted guard coverage is either obsolete or replaced by a current invariant

Phase 1 should start with the largest source of churn:

1. Delete or split `signingEngine.refactor33.guard.unit.test.ts`.
2. Delete occurrence-count allowlists from
   `signingEngine.refactor36.guard.unit.test.ts`.
3. Rewrite `refactor5xCrossPlatform.guard.unit.test.ts` around current
   platform boundaries.
4. Remove historical refactor names from remaining guard file names once the
   tests express current invariants.

## Phase 2: Rewrite Useful Guards

Replace brittle source-shape tests with durable invariants.

Work:

- keep guards that forbid direct platform APIs in core logic, but make the
  allowed boundary explicit and stable
- keep guards that forbid raw ECDSA HSS share fields in production surfaces,
  but scope them to current active roots
- keep guards that reject unsafe casts, broad lifecycle optionals, and invalid
  domain-state construction
- replace `toContain` source snippets with type fixtures or parser assertions
  where the invariant is type-level

Acceptance:

- useful guards fail on real boundary violations
- useful guards do not fail on harmless refactors, renames, or folder moves
- guard files are short enough to understand without reading old refactor docs

## Phase 3: Split Slow Integration Coverage

Move slow browser/WASM replay and high-level transaction lifecycle tests out of
the default unit profile.

Integration relocation rule: any test that uses full SDK iframe runtime, real
WASM replay, worker-router runtime, relayer server, browser storage restore, or
end-to-end transaction lifecycle simulation must leave `test:unit`.

Work:

- create or reuse an integration Playwright config/profile
- move browser-backed high-level tests into that profile
- rename files from `.unit.test.ts` when they are integration tests
- update package scripts so `test:unit` runs an explicit unit file list or
  ignores `*.integration.test.ts`, `*.source.test.ts`, and WASM replay suites
- add an explicit `test:integration:signing` script for the moved suites
- keep existing focused scripts such as `test:signer-parity:web-wasm-replay`
  and `test:threshold-core`, but stop also running their files via `test:unit`

Acceptance:

- unit tests do not hang on full SDK/browser/WASM runtime paths
- integration tests remain runnable and documented
- closeout can use fast gates without pretending integration drift means the
  refactor is unfinished

## Phase 4: Prune Fixtures

Delete fixtures that encode old state shapes or compatibility branches.

Work:

- remove legacy request/record fixtures outside boundary parser tests
- collapse duplicate warm-session and ECDSA lane fixture builders
- require canonical domain builders for current lane, budget, auth, and
  persistence state
- delete snapshot-like fixtures that only make broad object literals compile

Acceptance:

- fixture changes for a domain type update are localized to one builder
- invalid states are rejected by type fixtures or parsers
- test helpers use current domain vocabulary only

## Phase 5: Document the Gate

Update developer docs and package scripts to make the intended test gates clear.

Work:

- document the fast closeout gate
- document the core signing gate
- document the integration signing gate
- document the source-guard gate
- list when each gate is required
- remove references to obsolete refactor guard commands

Recommended scripts:

```json
{
  "test:unit": "pnpm -C ../sdk run build:prepare && playwright test -c playwright.unit.config.ts --reporter=line",
  "test:source-guards": "playwright test -c playwright.scripts.config.ts './unit/**/*.guard.unit.test.ts' './unit/**/*.script.unit.test.ts' './unit/**/*.source.script.unit.test.ts' --reporter=line",
  "test:integration:signing": "pnpm -C ../sdk run build:prepare && USE_RELAY_SERVER=1 playwright test -c playwright.integration.config.ts ./integration/signing --reporter=line"
}
```

Exact paths can differ, but the split must be explicit. Directory placement and
file suffixes should make accidental inclusion in `test:unit` difficult.

Acceptance:

- future closeouts do not default to the entire historical suite
- CI and local commands have names that match their purpose
- contributors can tell whether a failing test is unit, guard, integration, or
  obsolete refactor coverage

## Done Criteria

This cleanup is complete when:

- legacy refactor guard files are deleted or rewritten around current
  invariants
- `test:unit` contains unit tests, not browser/WASM integration flows
- `test:unit -- --list` excludes source guards, script guards, WASM replay,
  full SDK iframe, worker-router, relayer-backed, and high-level transaction
  lifecycle files
- boundary compatibility coverage exists only at request and persistence
  parsers
- fast closeout gates pass without touching historical allowlists
- integration signing tests remain available under an explicit command
- deleted tests have no orphaned fixtures, helpers, or docs references
- final orphan scans find no references to deleted guard filenames, deleted
  helper exports, retired allowlist files, obsolete `legacy-near` fixtures
  outside boundary tests, or refactor-number guard names that were rewritten
