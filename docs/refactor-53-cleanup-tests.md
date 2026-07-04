# Refactor 53: Legacy Test and Guard Cleanup

Date updated: June 2, 2026

Status: complete

Implementation summary:

- `test:unit` now uses `tests/playwright.unit.config.ts` and excludes source
  guards, source-script tests, WASM replay, full SDK iframe, worker-router, and
  high-level transaction lifecycle suites.
- `test:source-guards` runs `tests/playwright.source.config.ts`.
- `test:integration:signing` runs `tests/playwright.integration.config.ts`.
- The relocated browser/WASM-heavy suites now use `.integration.test.ts`
  filenames so they cannot be mistaken for unit coverage.
- `docs/refactor-53-test-inventory.csv` records the owner, profile, decision,
  and replacement command for the legacy guard and large fixture-heavy suites.

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
- `pnpm -C tests run test:unit` now uses `tests/playwright.unit.config.ts`
  and excludes guard, source-script, browser-backed integration, and WASM replay
  suites.
- The largest legacy guard suites are:
  - `signingEngineArchitecture.guard.unit.test.ts`
  - `signingEngineEcdsaIdentity.guard.unit.test.ts`
  - `crossPlatformBoundaries.guard.unit.test.ts`
  - `emailOtpEcdsaBranchIsolation.guard.unit.test.ts`
- The current scripts recognize slow profiles, for example
  `test:signer-parity:web-wasm-replay`, and `test:unit` no longer sweeps those
  files by default.

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

- `seamsPasskey.chainSigners.integration.test.ts`
- `signingVectors.webWasmReplay.integration.test.ts`
- `thresholdEcdsa.tempoHighLevel.integration.test.ts`
- `touchConfirm.workerRouter.integration.test.ts`
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

This command owns source-scanning and script surface tests that remain useful
after the cleanup. It is outside the default unit profile.

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

- `tests/unit/signingEngineArchitecture.guard.unit.test.ts`
- `tests/unit/signingEngineEcdsaIdentity.guard.unit.test.ts`
- `tests/unit/emailOtpEcdsaBranchIsolation.guard.unit.test.ts`
- `tests/unit/walletScopedLookups.guard.unit.test.ts`
- `tests/unit/crossPlatformBoundaries.guard.unit.test.ts`
- `tests/unit/indexedDBConsolidation.guard.unit.test.ts`
- `tests/unit/seamsPasskey.chainSigners.integration.test.ts`
- `tests/unit/signingVectors.webWasmReplay.integration.test.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.integration.test.ts`
- `tests/unit/touchConfirm.workerRouter.integration.test.ts`
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
| `signingEngineArchitecture.guard.unit.test.ts` | Current source-guard suite after deleting folder/index/deleted-path freezes. Still contains source-snippet checks that need later type or parser fixtures. | Keep under `test:source-guards` while Phase 2 rewrites continue. |
| `signingEngineEcdsaIdentity.guard.unit.test.ts` | Current ECDSA identity guard after deleting occurrence-count allowlists. | Keep targeted forbidden ECDSA account-identity derivation checks that express current behavior. |
| `crossPlatformBoundaries.guard.unit.test.ts` | Current platform-boundary guard with stable boundary ownership entries. | Keep direct platform API bans in core and keep raw HSS checks scoped to active roots. |
| `emailOtpEcdsaBranchIsolation.guard.unit.test.ts` | Contains valuable Email OTP/ECDSA branch isolation checks, plus brittle source snippets. | Keep branch-isolation behavior checks. Replace snippet checks with targeted parser/type tests or delete when duplicated. |
| `walletScopedLookups.guard.unit.test.ts` | Small guard for wallet-scoped lookup cleanup. | Keep as one current invariant test unless duplicated by wallet-session ECDSA identity and request-boundary tests. |
| `indexedDBConsolidation.guard.unit.test.ts` | Historical consolidation guard with many source assertions. | Audit for current persistence-boundary value. Delete or move only durable forbidden-store checks to source guards. |
| `emailOtpOperationSplit.guard.unit.test.ts` | Guards current Email OTP registration/login operation split. | Keep, but rename out of legacy guard language if it remains current. |
| `nonceCoordinator.durableArchitecture.guard.unit.test.ts` | Guards current nonce durability architecture. | Keep in core signing or source-guard profile depending on runtime cost. |
| `keyExport.behavior.guard.unit.test.ts` | Likely current user-visible export invariant. | Keep if it tests behavior. Rename if “guard” only means behavior regression. |
| `thresholdEcdsa.behavior.guard.unit.test.ts` | Mix of current behavior and crate-source scanning. | Split behavior tests from source checks. Move source checks to `test:source-guards`. |
| `seamsPasskey.chainSigners.integration.test.ts` | Large SDK/high-level chain signer flow suite; not a unit suite. | Owned by the integration signing profile. Keep only pure serialization/error mapping tests in unit files. |
| `signingVectors.webWasmReplay.integration.test.ts` | WASM replay and worker wrapper integration. Existing script already treats this as signer parity. | Owned by signer parity and integration profiles; excluded from `test:unit`. |
| `thresholdEcdsa.tempoHighLevel.integration.test.ts` | Full browser-backed threshold ECDSA Tempo flow. | Owned by `test:integration:signing` and `test:threshold-core`; excluded from `test:unit`. |
| `touchConfirm.workerRouter.integration.test.ts` | Worker/router integration with persistence and runtime restore behavior. | Owned by the integration signing profile. |
| `*.source.script.unit.test.ts` | Source scanners masquerading as unit tests. | Move to `test:source-guards`; delete any that only checks obsolete doc-era wiring. |
| `signingRoot*.script.unit.test.ts` | Script/source wiring around signing root and secrets. Some are security-sensitive. | Keep security-sensitive checks, but run under `test:source-guards` or a signing-root script profile. |
| `thresholdSigningRootParityBaseline.script.unit.test.ts` | Deterministic signing-root vector. | Keep as a current vector under `test:source-guards`; regenerate the expected output only when the derivation contract intentionally changes. |
| Legacy sealed-session tests in `sealedSessionStore.unit.test.ts` | Boundary tests for rejected or cleaned old IndexedDB shapes. | Keep only parser/migration boundary cases. Delete tests for unsupported retired DB compatibility after data reset. |
| `availableSigningLanes.*Duplicates.unit.test.ts` legacy sealed-record cases | Some cases assert ignoring legacy chain-only records. | Keep only if the boundary parser still accepts that input. Delete once production no longer reads the old shape. |
| `confirmTxFlow.*` profile fixtures | Repeated UI confirm profile fixtures now use a local canonical profile-context builder with `near-profile:*` profile IDs. | Keep while broader fixture-builder consolidation remains open. |

Acceptance:

- [x] every legacy refactor guard has an owner decision
- [x] every delete decision names replacement coverage or says the behavior is
  obsolete
- [x] no compatibility-only fixture remains outside a boundary test
- [x] security-sensitive guard deletions map to current behavior tests, type
  fixtures, parser boundary tests, source-guard commands, or native/vector
  parity suites

## Phase 0.5: Establish Replacement Gates First

Add the replacement commands before deleting or relocating coverage.

Status: complete.

Work:

- [x] add a working `test:source-guards` command
- [x] add a working `test:integration:signing` command
- [x] update `test:unit` so it cannot accidentally sweep source guards,
  source-script tests, WASM replay suites, full SDK iframe flows, worker-router
  flows, relayer-backed flows, or high-level transaction lifecycle simulations
- [x] run the old broad command and the new split commands once, then record each
  moved suite's owning command in `docs/refactor-53-test-inventory.csv`
- [x] keep existing focused commands such as `test:threshold-core`,
  `test:threshold-ed25519:active-path`, and
  `test:signer-parity:web-wasm-replay`, but make sure their files are not also
  swept by `test:unit`

Source-guard command shape:

```sh
pnpm -C ../sdk run build:prepare && playwright test -c playwright.source.config.ts --reporter=line
```

Acceptance:

- [x] `pnpm -C tests run test:unit -- --list` contains no `*.guard.unit.test.ts`,
  `*.script.unit.test.ts`, `*.source.script.unit.test.ts`, WASM replay, full SDK
  iframe, worker router, relayer-backed flow, or high-level transaction
  lifecycle simulation files
- [x] every moved file remains runnable through exactly one documented command
- [x] deletion work can cite an existing replacement command or explicit obsolete
  behavior before removing a file

## Phase 1: Delete Obsolete Guards

Remove guards that freeze previous refactor architecture instead of current
behavior.

Status: complete.

Work:

- [x] delete exact folder-count and index-barrel freezes that conflict with current
  Refactor 51 ownership
- [x] delete obsolete deleted-symbol guards once the symbol is already absent from
  production and covered by current type names
- [x] delete tests that fail only because a new current owner module exists
- [x] delete supporting allowlists that exist only for those guards

Acceptance:

- [x] no guard needs updates for valid new owner folders
- [x] no guard encodes old architecture as the desired architecture
- [x] deleted guard coverage is either obsolete or replaced by a current invariant

Phase 1 should start with the largest source of churn:

1. [x] Delete or split `signingEngineArchitecture.guard.unit.test.ts`.
2. [x] Delete occurrence-count allowlists from
   `signingEngineEcdsaIdentity.guard.unit.test.ts`.
3. [x] Rewrite `crossPlatformBoundaries.guard.unit.test.ts` around current
   platform boundaries.
4. [x] Remove historical refactor names from remaining guard file names once the
   tests express current invariants.

## Phase 2: Rewrite Useful Guards

Replace brittle source-shape tests with durable invariants.

Status: source-guard ownership is split from `test:unit`; the domain-id parser
source snippets in `emailOtpEcdsaBranchIsolation.guard.unit.test.ts` have
runtime parser-boundary coverage in `domainIds.boundary.unit.test.ts`;
public wallet-id boundary helper source snippets are covered by
`domainIds.boundary.unit.test.ts`;
the ECDSA public-identity versus ready-to-sign material-state snippet guard has
type-fixture coverage in `ecdsaMaterialState.typecheck.ts`; the Email OTP
registration-attempt proof-resolution snippet guard has behavior coverage in
`authService.hostedAccountPrivacy.unit.test.ts`; remaining guard rewrites are
tracked in `docs/refactor-53-test-inventory.csv`; the ECDSA lane budget-status
snippet guard is covered by `budget.typecheck.ts`; the Email OTP ECDSA
configured-target unlock snippet guard has behavior coverage in
`emailOtpEcdsaPublication.unit.test.ts`; the passkey ECDSA warm-persistence
shape snippet guard is covered by `persistencePorts.typecheck.ts`; the Email OTP
ECDSA bootstrap passkey warm-persistence source guard is covered by
`ecdsaBootstrapWarmPersistence.unit.test.ts`; the Email OTP UI-confirm passkey
credential lookup source-ordering guard is covered by
`uiConfirmPasskeyCredentialLookup.unit.test.ts`; the EVM-family signing prep
auth-selection source guard is covered by
`evmFamilyPreparedSigningAuthSelection.unit.test.ts`; the Email OTP ECDSA
sealed-refresh persistence input source guard is covered by
`emailOtpEcdsaPublication.unit.test.ts`. The reduced source-guard gate passed
with `pnpm -C tests run test:source-guards` after these replacements.
Email OTP coordinator challenge split method-name snippets are covered by
`emailOtpThresholdSessionCoordinator.unit.test.ts`; cross-platform boundary
guards now assert forbidden leaks without positive current-export inventory
pins; architecture guards no longer freeze root README wording or historical
README-template content. The registration event source-text guard has been
deleted and replaced with `registrationFlowEvents.unit.test.ts`, which exercises
the registration lifecycle event builder directly for passkey and Email OTP flow
identity. The threshold commit queue shared-primitive source guard has been
deleted because dedicated ECDSA and Ed25519 commit queue unit suites already
cover queue behavior, cancellation, and key derivation. The ECDSA role-local
authorization source guard now keeps only legacy derivation bans; the active
key-handle authorization path is covered by `thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`.
Type-level invalid-state coverage remains in dedicated `.typecheck.ts` fixtures
for budget, ECDSA lane identity, ECDSA material state, recovery authorization,
warm capability persistence, worker requests, persistence records, and operation
state. The current source-guard profile passed with
`pnpm -C tests run test:source-guards`. IndexedDB consolidation behavior tests
now live in `indexedDBConsolidation.unit.test.ts`; the guard file keeps only
source-boundary assertions, reducing the persistence guard from a large mixed
suite to a small boundary scanner. The remaining oversized signing-engine
architecture and ECDSA identity guards are split into focused files with shared
helpers, so individual guard files are small enough to review by topic.

Work:

- [x] keep guards that forbid direct platform APIs in core logic, but make the
  allowed boundary explicit and stable
- [x] keep guards that forbid raw ECDSA HSS share fields in production surfaces,
  but scope them to current active roots
- [x] replace public wallet-id boundary helper source snippets with domain-id
  boundary assertions
- [x] add type-fixture coverage for ECDSA material-state invalid branch
  construction
- [x] replace Email OTP registration-attempt proof-resolution source snippets
  with AuthService boundary assertions
- [x] rely on budget type fixtures for concrete ECDSA lane budget-status checks
- [x] replace Email OTP configured ECDSA target source snippets with publication
  target behavior tests
- [x] rely on warm-session persistence type fixtures for passkey ECDSA
  persistence-source and PRF seal material shape checks
- [x] replace the Email OTP ECDSA bootstrap passkey warm-persistence source
  guard with runtime branch-decision assertions
- [x] replace the Email OTP UI-confirm passkey credential lookup source guard
  with direct auth-plan branch assertions
- [x] replace the EVM-family signing prep auth-selection source guard with
  direct policy and intent assertions
- [x] replace the Email OTP ECDSA sealed-refresh persistence input source guard
  with direct persistence-input builder assertions
- [x] remove exact positive source-shape snippets from
  `emailOtpEcdsaBranchIsolation.guard.unit.test.ts`
- [x] replace Email OTP coordinator challenge split method-name snippets with
  coordinator route-plan behavior assertions
- [x] trim EVM-family fresh Email OTP planner-order source checks to forbidden
  legacy pre-sign assertion paths
- [x] trim Email OTP coordinator facade source-shape checks to thin-boundary
  forbidden dependency checks
- [x] trim EVM-family prepared-signing dependency shape source snippets to
  forbidden legacy dependency checks
- [x] remove EVM-family missing-material readiness source snippets covered by
  `ecdsaSelection.typecheck.ts` and `ecdsaSelection.restorable.unit.test.ts`
- [x] trim Email OTP ECDSA helper source-shape checks to forbidden legacy
  key-ref/context paths
- [x] trim ECDSA exact-lane selection source-order checks to forbidden legacy
  key-ref/generic fallback paths
- [x] trim EVM-family sealed-restore ordering source checks to forbidden
  legacy read-side restore and broad auth iteration paths
- [x] remove remaining Email OTP operation-split positive source pins where
  behavior/type tests already cover the current helper, lane, and material
  selection paths
- [x] trim wallet-scoped lookup guard assertions to forbidden NEAR projection
  and legacy authenticator API paths
- [x] delete architecture guard facade-delegation source pins that asserted exact
  SigningEngine field names, assembly constructor wiring, and public helper
  method strings
- [x] trim architecture command-runner guards to forbidden legacy runners,
  misplaced orchestration imports, and UI/display boundary violations
- [x] trim architecture availability, confirmation, EVM post-sign, admission,
  assembly, and WebAuthn boundary guards to forbidden legacy or misplaced-owner
  paths
- [x] trim architecture lower-half type/location source pins for ECDSA target,
  selected-lane, execution-boundary, threshold-session-kind, Ed25519 HSS, and
  session-identity ownership checks
- [x] remove IndexedDB consolidation doc-inventory guard and trim signing-session
  persistence source checks to legacy constant bans
- [x] remove duplicate raw IndexedDB row assertions from the broad repository
  persistence test while keeping repository behavior and targeted signer-mirror
  storage coverage
- [x] trim duplicate auth-method rejection, key-material, and nonce-lease checks
  from the broad IndexedDB repository test; keep those invariants in narrower
  owner tests
- [x] trim signer activation, signer outbox, and authenticator prompt checks from
  the broad IndexedDB repository test; keep them in signer/prompt owner suites
- [x] trim auth-method setup and assertions from the broad IndexedDB repository
  smoke test; keep auth-method edge coverage in dedicated auth-method tests
- [x] trim ECDSA identity wallet-unlock guard to forbidden raw metadata parsing
  in the unlock path instead of exact parser export, branch, and endpoint pins
- [x] trim ECDSA identity export/facade guards to forbidden account-derived
  identity regressions instead of exact positive auth branch and public method
  presence pins
- [x] trim ECDSA identity budget-status route guard to forbidden route-local
  parsing tokens instead of exact parser function-name presence
- [x] trim ECDSA identity WASM surface guard to legacy/root-share/client-relayer
  export bans instead of exact positive current export inventory pins
- [x] trim ECDSA iframe payload guard to required/forbidden field shape checks
  instead of exact alias and inheritance source snippets
- [x] trim cross-platform boundary guards to forbidden platform, root-share,
  raw-material, handwritten-schema, and boolean-result leaks instead of exact
  positive current export and worker action pins
- [x] remove architecture guard checks that froze root README wording and the
  historical folder README template
- [x] replace the registration event source-text guard with direct lifecycle
  event builder assertions
- [x] delete the threshold commit queue shared-primitive source guard covered by
  ECDSA and Ed25519 commit queue behavior suites
- [x] trim ECDSA role-local authorization source pins to legacy derivation bans
  covered by threshold ECDSA authorization behavior tests
- [x] split IndexedDB consolidation repository/browser behavior tests out of
  the source guard file
- [x] keep guards that reject unsafe casts, broad lifecycle optionals, and other
  invalid domain-state construction
- [x] replace `toContain` source snippets with type fixtures or parser assertions
  where the invariant is type-level

Acceptance:

- [x] useful guards fail on real boundary violations
- [x] useful guards do not fail on harmless refactors, renames, or folder moves
- [x] guard files are short enough to understand without reading old refactor docs

Final split replacements:

- `signingEngineArchitecture.ownership.guard.unit.test.ts`
- `signingEngineArchitecture.flows.guard.unit.test.ts`
- `signingEngineArchitecture.state.guard.unit.test.ts`
- `signingEngineArchitecture.threshold.guard.unit.test.ts`
- `signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts`
- `signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts`
- `signingEngineEcdsaIdentity.exportAndFixtures.guard.unit.test.ts`

## Phase 3: Split Slow Integration Coverage

Move slow browser/WASM replay and high-level transaction lifecycle tests out of
the default unit profile.

Status: complete.

Integration relocation rule: any test that uses full SDK iframe runtime, real
WASM replay, worker-router runtime, relayer server, browser storage restore, or
end-to-end transaction lifecycle simulation must leave `test:unit`.

Work:

- [x] create or reuse an integration Playwright config/profile
- [x] move browser-backed high-level tests into that profile
- [x] rename files from `.unit.test.ts` when they are integration tests
- [x] update package scripts so `test:unit` runs an explicit unit file list or
  ignores `*.integration.test.ts`, `*.source.test.ts`, and WASM replay suites
- [x] add an explicit `test:integration:signing` script for the moved suites
- [x] keep existing focused scripts such as `test:signer-parity:web-wasm-replay`
  and `test:threshold-core`, but stop also running their files via `test:unit`

Acceptance:

- [x] unit tests do not hang on full SDK/browser/WASM runtime paths
- [x] integration tests remain runnable and documented
- [x] closeout can use fast gates without pretending integration drift means the
  refactor is unfinished

## Phase 4: Prune Fixtures

Delete fixtures that encode old state shapes or compatibility branches.

Status: complete; compatibility-only fixture cleanup is complete, repeated
confirm-flow profile-context fixtures are collapsed to local builders, and
warm-session test services no longer spread broad fixture input bags into core
ECDSA status readers, and unused warm-session helper scaffolding has been
deleted. Restore coordinator companion sealed-record fixtures now use
branch-specific builders. Available-lane sealed-record fixtures use the
canonical current sealed-session builder for valid current records, and a
legacy chain-only available-lane fixture was deleted. ECDSA duplicate
available-lane fixtures now build current sealed records through the canonical
builder and carry signing-root identity through restore metadata. Broader
warm-session/ECDSA lane builder consolidation remains; `ensureEcdsaCapabilityReady`
and `assertEcdsaOperationAllowed` test helper inputs now name their supported
fixture knobs explicitly instead of accepting arbitrary key bags. The unlock
ECDSA warmup planner local-session fixture now includes a current role-local
ready record instead of casting a partial record into the session-record type.
EVM-family step-up provision-plan tests now use the canonical session-record
builder directly instead of spread-overriding the already-current login source.
ECDSA restorable-selection tests now route the single-use Email OTP variant
through the Email OTP record builder instead of assembling that record inline.
ECDSA export-material fixtures now expose narrow variant inputs instead of
`Partial<ThresholdEcdsaSessionRecord>` override bags.
EVM-family ECDSA identity fixtures now remove redundant current-default
overrides and use narrow session/key-ref fixture inputs; malformed legacy raw
records remain isolated in persistence-boundary assertions.
The remaining session-record cast scan hits are malformed legacy durable
records inside the EVM-family ECDSA persistence-boundary tests.
Available-lane ECDSA sealed/runtime/read fixtures now live in one shared helper
instead of duplicated ECDSA and Ed25519 duplicate-normalization suite builders.
ECDSA export route-auth tests now resolve fresh Email OTP route-auth material
through the production resolver instead of hand-building auth lanes and export
material.

Work:

- [x] remove legacy request/record fixtures outside boundary parser tests
- [x] collapse duplicate warm-session and ECDSA lane fixture builders
- [x] require canonical domain builders for current lane, budget, auth, and
  persistence state
- [x] remove broad fixture-input spreads from warm-session ECDSA status-reader
  adapters
- [x] delete unused warm-session ECDSA store/list helper scaffolding
- [x] collapse duplicate restore coordinator companion sealed-record object
  literals into branch-specific fixture builders
- [x] replace available-lane valid sealed-record object casts with canonical
  current sealed-session builders
- [x] delete legacy chain-only ECDSA sealed-record fixture coverage from the
  non-boundary available-lanes suite
- [x] replace ECDSA duplicate available-lane sealed-record casts with canonical
  current sealed-session builders
- [x] update ECDSA duplicate available-lane fixtures to carry current
  signing-root identity through restore metadata instead of top-level fixture
  fields
- [x] replace broad warm-session ECDSA helper index signatures with explicit
  test fixture fields
- [x] remove redundant warm-session ECDSA provision-plan fixture cast
- [x] replace unlock ECDSA warmup planner session-record cast with a current
  role-local ready-record fixture
- [x] remove redundant EVM-family step-up provision-plan session-record spread
  overrides
- [x] move ECDSA restorable-selection single-use Email OTP record construction
  into the canonical Email OTP record builder
- [x] replace ECDSA export-material `Partial<ThresholdEcdsaSessionRecord>`
  fixture overrides with narrow variant inputs
- [x] replace EVM-family ECDSA identity broad session/key-ref fixture override
  bags with narrow variant inputs
- [x] route ECDSA export route-auth fixture setup through the production
  fresh-material resolver instead of manual auth-lane/material object literals
- [x] delete remaining snapshot-like fixtures that only make broad object
  literals compile

Acceptance:

- [x] fixture changes for a domain type update are localized to one builder
- [x] invalid states are rejected by type fixtures or parsers
- [x] test helpers use current domain vocabulary only

## Phase 5: Document the Gate

Update developer docs and package scripts to make the intended test gates clear.

Status: complete.

Work:

- [x] document the fast closeout gate
- [x] document the core signing gate
- [x] document the integration signing gate
- [x] document the source-guard gate
- [x] list when each gate is required
- [x] remove references to obsolete refactor guard commands

Recommended scripts:

```json
{
  "test:unit": "pnpm -C ../packages/sdk-server-ts run build && pnpm -C .. build:sdk-full && playwright test -c playwright.unit.config.ts --reporter=line",
  "test:source-guards": "pnpm -C .. build:sdk-full && playwright test -c playwright.source.config.ts --reporter=line",
  "test:integration:signing": "pnpm -C .. build:sdk-full && playwright test -c playwright.integration.config.ts --reporter=line"
}
```

Exact paths can differ, but the split must be explicit. Directory placement and
file suffixes should make accidental inclusion in `test:unit` difficult.

Acceptance:

- [x] future closeouts do not default to the entire historical suite
- [x] CI and local commands have names that match their purpose
- [x] contributors can tell whether a failing test is unit, guard, integration, or
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
  helper exports, retired allowlist files, obsolete profile fixtures outside
  boundary tests, or refactor-number guard names that were rewritten
