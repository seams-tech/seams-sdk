# Refactor 88: Intended Behaviour E2E Contract

Date created: 2026-07-02
Updated: July 4, 2026 — merged the companion implementation plan
(`proper-e2e-tests.md`, now deleted) into this document. The two files
described one initiative and had already drifted: the companion still linked
this plan by its pre-rename number (refactor-93). A same-day review folded
in: the assertion model (structured events + signature verification over
error-string matching), the flake policy, the Chromium-only browser matrix,
the recovery-spec deferral, the Refactor 86 topology note, the mutation
self-check, and pre-CI gate enforcement. The live passkey contracts now also
enforce the `budget_unknown` matcher against wallet-origin console output.
Updated: July 4, 2026 — Phase 5 reframed as the exhaustive test ledger
(`keep`/`replace`/`delete`/`blocked_on_coverage`) with the pruning ownership
map, the zero-importer helper rule, and deletion accounting. Phase 8 added:
the gated legacy-suite deletion sweep from the July 4 suite survey.
Updated: July 5, 2026 — the five-spec intended contract is green locally and
under the managed CI launcher. `pnpm -C tests run test:intended:ci` refreshed a
service-account Google OIDC token, started the intended stack, and passed all
five lifecycle specs in 4.5m. Focused passkey registration, Email OTP
registration, and recovery reruns also pass against a clean managed stack. The
remaining Refactor 88 work is deletion accounting and owner-plan-gated cleanup,
not an open lifecycle-contract failure. Supporting gates are green:
`check:refactor88-test-ledger:complete` reports
`scope=406 ledger_existing=406 ledger_deleted=67 missing=0`, and
`test:source-guards` passes all standalone checks plus 190/190 Playwright
source-profile tests.
Updated: July 5, 2026 — post-Refactor 90 F3 validation fixed the Email OTP
Ed25519 export path by restoring the required HSS server advance call before
finalize. `pnpm -C tests run test:intended:ci` now passes all five intended
contracts in 4.1m.

Status: in progress.

Source of truth: [Intended Behaviours](./intended-behaviours.md)

Sequencing:

- Run this refactor early. This suite is the safety net for the in-flight
  82B/83/90 migration work; refactors touching auth, registration, warm
  sessions, signing lanes, budget, key export, D1/DO state, or wallet iframe
  routing gate on `test:intended` once it exists.
- Guard cleanup ([refactor-89-clean-source-guards.md](./refactor-89-clean-source-guards.md))
  follows this suite, not the other way around: the e2e contract is the
  replacement coverage that justifies deleting transitional guards. Guard
  retirement then executes incrementally at Refactor 90 slice exits, with the
  final sweep at 90 Phase P3.
- Phases 5-7 below (mocked-fixture audit and deletion, setup cleanup) record
  their deletions and retired guards in the Refactor 89 ledger.

## Problem

The test suite is large, but the regressions keep landing in lifecycle seams:

- registration -> transaction signing
- wallet unlock -> transaction signing
- session exhaustion -> step-up auth -> first transaction
- key export authorization

Many current tests validate units, guards, or mocked demo surfaces. These
paths cross the wallet iframe, IndexedDB, D1 Router API, Durable Objects,
workers, signing-engine lane selection, budget, and export flows — and tests
that mock SDK internals do not prove them as one system.

The missing gate is a small e2e contract suite that exercises the behaviours
users actually depend on.

## Rule

Do not add more broad unit coverage for these behaviours. Add one small e2e
contract suite and keep it mandatory for refactors touching auth, registration,
warm sessions, signing lanes, budget, key export, D1/DO state, or wallet iframe
routing.

Mandatory local enforcement means `pnpm test:intended` is a named pre-merge
command in the validation sections of the refactors it gates (82B, 83, and the
90 slices). CI mode is available through `pnpm test:intended:ci`; until it is
wired into the remote CI pipeline, the gate remains an explicit checklist item
with a runnable command.

## Non-Goals

- Do not add broad unit coverage for these lifecycle behaviours.
- Do not add another large mocked demo harness.
- Do not mock signing-engine lane selection, budget coordinator, wallet iframe
  protocol, IndexedDB persistence, Router API responses, worker material
  persistence, or D1/DO state.
- Do not test visual polish here. Use manual testing and focused UI tests for
  layout.

## Assertion Model

Primary oracles, in order of authority:

1. **Behavioral outcomes**: prompt counts, operation success without retry,
   remaining spend decrementing, exhaustion triggering step-up, export
   requiring fresh authorization.
2. **Cryptographic signature verification**: the harness verifies every
   returned signature against the registered wallet's public keys — Ed25519
   verify for NEAR; ECDSA public-key recovery plus chain-target address check
   for Tempo and Arc/EVM. This is the observable for cross-chain and
   cross-wallet material mixups (the 0D/0F bug class); "no error thrown" is
   never sufficient evidence that the right key signed.
3. **Structured lifecycle events**: assertions consume typed SDK
   lifecycle/timing events, not console text.

Error-string matchers are secondary tripwires only, owned as a versioned
matcher table inside the harness:

- A matcher is never the only detection for a contract row.
- Any refactor that renames or deletes a listed error string must update the
  matcher table in the same change. 82B's typed-failure replacements, 0F's
  diagnostics renames, and 90 B3's budget-subsystem deletion all hit this
  table.
- Contract specs are phrased in user-visible vocabulary so the lifecycle specs
  survive internal renames: "budget" in the specs means *remaining spend*,
  which becomes grant-use consumption after 90 B3 with no spec change.

## Real Components Under Test

The e2e suite must run real SDK/runtime code:

- `pnpm router` local Router A/B workers and D1 backend
- `pnpm site` local app and wallet origins
- real wallet iframe router
- real IndexedDB wallet database
- real D1 local SQLite state
- real Durable Object session and budget stores
- real Ed25519 and ECDSA workers
- real registration, unlock, signing, step-up, and export SDK flows

Stub only network edges outside our system:

- Google identity token response
- Email OTP delivery/readback
- NEAR RPC/faucet responses
- Tempo RPC responses
- Arc/EVM RPC responses

Do not mock SDK internals, signing-engine lane selection, budget coordinator,
wallet iframe messages, worker material persistence, or Router API responses.

## Minimal Contract Matrix

Keep this suite small. The E2E contract is five lifecycle specs total. Each spec
must exercise real Ed25519 and ECDSA behaviour, but step-up and export assertions
belong inside these lifecycle specs rather than separate test files.

| Flow | Required checks |
| --- | --- |
| Passkey registration lifecycle | registration succeeds; NEAR, Tempo, and Arc/EVM sign without another prompt while budget remains; budget decreases correctly; Ed25519 and ECDSA export require fresh export authorization and succeed |
| Passkey unlock lifecycle | unlock warms NEAR and configured ECDSA targets; NEAR, Tempo, and Arc/EVM sign without another prompt while budget remains; after budget exhaustion, step-up uses passkey and the first post-step-up NEAR and ECDSA transaction succeeds |
| Email OTP registration lifecycle | registration sends one OTP; wallet-name reroll does not send another OTP; NEAR, Tempo, and Arc/EVM sign without another OTP while budget remains; Ed25519 and ECDSA export require fresh export OTP and succeed |
| Email OTP unlock lifecycle | unlock sends one wallet-unlock OTP; unlock warms NEAR and configured ECDSA targets; NEAR, Tempo, and Arc/EVM sign without another OTP while budget remains; after budget exhaustion, step-up uses Email OTP and the first post-step-up NEAR and ECDSA transaction succeeds |
| Email recovery lifecycle | email recovery prepares and finalizes through public recovery APIs; recovered NEAR, Tempo, and Arc/EVM signing succeeds through the real browser/runtime surfaces |

Cross-row assertions:

- Passkey flows never call Email OTP verification.
- Email OTP flows never call WebAuthn/passkey PRF or passkey sealed restore.
- Registration and default unlock produce equivalent lane inventory for the same
  wallet, auth method, and configured chains.
- ECDSA checks are chain-target exact for Tempo and Arc/EVM.
- An indeterminate spend state must fail the test; it is not an acceptable
  intermediate state in a successful signing path. Today that surfaces as
  `budget_unknown` (a matcher-table entry); after 90 B3 the same contract row
  is enforced against grant-state reads.
- The first transaction after step-up must succeed. A failure followed by a
  successful retry is a test failure.

Fifth spec: the recovery lifecycle starts with email recovery into signing.
Recovery-code restore and device-escrow restore remain named follow-up coverage
inside the same lifecycle family. July 4, 2026 update: local D1 Router startup
now mounts `/email-recovery/prepare` and `/email-recovery/ecdsa/respond` with a
structural `RouterApiOptions.emailRecovery` prepare-only service, and the local
worker smoke test rejects malformed prepare requests with HTTP 400 instead of a
route-level 404. July 5, 2026 update: the intended harness now drives and
passes the email-recovery-to-signing lifecycle under intended CI; the remaining
recovery cleanup task is to retire or reclassify the older
`blocked_on_coverage(recovery)` ledger rows.

## Detailed Contract Specs

### Passkey Registration

Test:

1. Register wallet with passkey.
2. Assert exactly one passkey creation prompt.
3. Assert lane inventory exists for:
   - NEAR Ed25519
   - Tempo ECDSA
   - Arc/EVM ECDSA
4. Sign NEAR, Tempo, and Arc/EVM transactions without another prompt.
5. Exhaust signing budget.
6. Trigger step-up auth.
7. Assert the first post-step-up NEAR transaction succeeds.
8. Assert the first post-step-up ECDSA transaction succeeds.
9. Export Ed25519 key with fresh export authorization.
10. Export ECDSA key with fresh export authorization.

Must fail if:

- Email OTP is called.
- `budget_unknown` appears.
- first post-step-up transaction fails and retry succeeds.
- ECDSA target identity is missing or shared incorrectly across Tempo and
  Arc, observed through signature verification: each chain target's signature
  must verify against that target's registered public key.

### Passkey Unlock

Test:

1. Start from a registered passkey wallet fixture created through the real
   registration flow.
2. Clear in-memory runtime state while preserving durable/local persistence.
3. Unlock wallet with passkey.
4. Assert NEAR, Tempo, and Arc/EVM signing works without another prompt while
   budget remains.
5. Repeat the same step-up and key-export assertions from passkey registration.

Must fail if:

- unlock reports success before all default lanes are usable.
- unlock loses sealed/session records needed for later refresh.
- ECDSA signing requires NEAR account identity.

### Email OTP Registration

Test:

1. Start Google SSO-backed Email OTP registration.
2. Assert one registration OTP/proof is issued.
3. Reroll wallet name.
4. Assert reroll does not issue another OTP.
5. Finalize registration with the rerolled wallet ID.
6. Assert Email OTP auth method is bound to the final wallet ID.
7. Assert lane inventory exists for:
   - NEAR Ed25519
   - Tempo ECDSA
   - Arc/EVM ECDSA
8. Sign NEAR, Tempo, and Arc/EVM transactions without another OTP.
9. Exhaust signing budget.
10. Trigger Email OTP step-up auth.
11. Assert the first post-step-up NEAR transaction succeeds.
12. Assert the first post-step-up ECDSA transaction succeeds.
13. Export Ed25519 key with fresh export OTP.
14. Export ECDSA key with fresh export OTP.

Must fail if:

- passkey/WebAuthn/PRF is called.
- registration proof IDs leak into long-lived session/key/lane state.
- wallet-name reroll causes `bootstrap_token_request_mismatch`.
- ECDSA authority is confused with budget state.

### Email OTP Unlock

Test:

1. Start from an Email OTP wallet created through the real registration flow.
2. Clear in-memory runtime state while preserving durable/local persistence.
3. Unlock wallet with one wallet-unlock OTP.
4. Assert NEAR, Tempo, and Arc/EVM signing works without another OTP while
   budget remains.
5. Repeat the same step-up and key-export assertions from Email OTP
   registration.

Must fail if:

- a registration OTP unlocks the wallet.
- step-up/export OTP unlocks the wallet.
- passkey/WebAuthn/PRF is called.
- unlock reports success before default lanes are usable.

## Global Assertions

Every test should fail on:

- `budget_unknown`
- `exact selected lane` errors
- `WalletRuntimePostcondition` errors
- passkey path used in Email OTP flow
- Email OTP path used in Passkey flow
- first step-up transaction failure followed by successful retry
- duplicate canonical ECDSA lanes / ambiguous material groups
- missing chain target in ECDSA budget, readiness, or persistence
- key export succeeding without fresh export authorization

## Test Command And Layout

Add a dedicated directory and config:

```text
tests/playwright.intended.config.ts
tests/e2e/intended-behaviours/
  harness.ts
  passkey.registration.contract.test.ts
  passkey.unlock.contract.test.ts
  email-otp.registration.contract.test.ts
  email-otp.unlock.contract.test.ts
  recovery.email.contract.test.ts
```

Add named commands at the repo root:

```json
"test:intended": "pnpm -C tests test:intended",
"test:intended:ci": "pnpm -C tests test:intended:ci",
"ensure:intended-google-token": "pnpm -C tests ensure:intended-google-token",
"setup:intended-google-oidc": "pnpm -C tests setup:intended-google-oidc",
"refresh:intended-google-token": "pnpm -C tests refresh:intended-google-token"
```

Add in `tests/package.json`:

```json
"test:intended": "pnpm run ensure:intended-google-token && playwright test -c playwright.intended.config.ts --reporter=line",
"test:intended:ci": "pnpm run ensure:intended-google-token && playwright test -c playwright.intended.ci.config.ts --reporter=line",
"ensure:intended-google-token": "node scripts/ensure-intended-google-token.mjs",
"setup:intended-google-oidc": "node scripts/setup-intended-google-oidc.mjs",
"refresh:intended-google-token": "node scripts/refresh-intended-google-token.mjs"
```

Local developer mode:

```sh
pnpm setup:intended-google-oidc
pnpm router
pnpm site
pnpm test:intended
```

The tests should be optimized for local refactor use:

- assume `pnpm router` and `pnpm site` can already be running during local
  debugging
- auto-load ignored `.env.intended.local` in local intended config, CI-managed
  service startup, and mutation preflight
- run `ensure:intended-google-token` before Playwright so the Email OTP
  contracts have a fresh enough `SEAMS_INTENDED_GOOGLE_ID_TOKEN`; the harness
  uses public Google Email OTP SDK flows and reads OTPs through the Router dev
  outbox with a public app-session JWT
- mint that token through service-account impersonation with
  `pnpm setup:intended-google-oidc` or `pnpm refresh:intended-google-token`;
  the token is one-hour generated state, not a committed fixture
- persist the OAuth client secret only in ignored local env when local runtime
  setup needs it; pass `--client-secret=<secret>` to the setup script for a new
  local env file
- provide one CI mode that starts the required local services
- fail fast on the first contract violation
- emit a compact lifecycle trace on failure

## Harness Design

Use a single harness that:

- opens the local site at the real app origin
- configures local Router API, wallet origin, environment ID, and publishable key
- resets browser storage for each test
- creates a unique wallet ID per test
- uses Playwright's virtual WebAuthn authenticator for passkey flows
- provides deterministic Google identity and Email OTP test responses
- intercepts only external chain RPC/faucet calls
- records structured lifecycle events from SDK events and network requests,
  with app console capture kept as diagnostics
- verifies every returned signature against the registered wallet's public
  keys (Assertion Model, oracle 2)
- owns the versioned error-string matcher table and fails on matched
  console/network errors as a secondary tripwire

The harness must expose high-level actions only:

```ts
registerPasskeyWallet()
registerEmailOtpWallet()
unlockPasskeyWallet()
unlockEmailOtpWallet()
signNearTransaction()
signTempoTransaction()
signArcEvmTransaction()
exhaustSigningBudget()
exportEd25519Key()
exportEcdsaKey()
```

Each action should drive the public SDK/UI flow. It must not call private
signing-engine helpers.

Browser matrix: this suite is Chromium-only. Passkey flows depend on the CDP
virtual WebAuthn authenticator, which WebKit and Firefox do not provide.
Cross-browser WebAuthn delegation coverage is owned by Refactor 86's Phase 1B
smokes; do not stall this suite trying to make it tri-browser.

## Service Startup

Phase 1 should assume services are already running, because that is the fastest
way to make the suite useful during refactors:

```sh
pnpm setup:intended-google-oidc
pnpm router
pnpm site
pnpm test:intended
```

CI-managed startup:

- build fresh SDK artifacts into `packages/sdk-web/dist`
- reset local D1 and Router A/B local state
- run local D1 migrations through the existing `pnpm router` startup path
- seed local org/project/env/API key through the local D1 dev worker defaults
- start router
- start site
- run `test:intended`
- stop services

## Data Reset

Each test must use isolated state:

- unique generated readable wallet ID
- unique Email OTP provider subject
- unique passkey credential
- fresh browser context
- cleared IndexedDB/localStorage/sessionStorage
- Email OTP challenges read from the Router dev outbox by challenge ID and
  wallet ID

D1 can be reset once per suite in CI mode. Local developer mode may reuse D1
state as long as wallet IDs are unique.

Topology note: when Refactor 86 Phase 3 flips local serving to the static
wallet origin (app origin returns 404 for `/sdk/*`, `/wallet-service`, and
`/export-viewer`), this suite runs against that topology unchanged — and from
then on it is the standing enforcement that no wallet asset is ever served
from the app origin.

## Failure Output

On failure, print one compact trace:

```text
flow=email_otp.unlock
walletId=...
stage=tempo.sign.after_step_up
authPrompts=email_otp:1 passkey:0
lanes=ed25519:ready tempo:ready arc:ready
budget=grant:... remaining:...
lastNetwork=/router-ab/wallet-budget/status 403 wallet_budget_forbidden
lastError=[SigningSessionBudget] signing grant budget is budget_unknown
```

This replaces manual console archaeology.

## Flake Policy

A mandatory gate that flakes gets bypassed. Rules:

- Zero automatic retries on contract assertions. The step-up rule generalizes
  suite-wide: an operation that fails and then passes on retry is a contract
  failure, not a flake to absorb.
- Serial execution until the suite has a stable history; parallelism is an
  optimization to earn later.
- Generous per-stage timeouts that emit the compact failure trace on expiry;
  no bare Playwright timeout errors.
- Wall-clock budget: the full lifecycle suite targets under ~10 minutes
  locally. If it grows past that, cut setup cost — do not cut specs.
- Quarantine rule: a flaky contract test is a P0 bug in the product or the
  harness. Never `.skip`, never retry-annotate, never "known flaky".
- Source guard: `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` rejects
  local skip/focus/retry annotations under
  `tests/e2e/intended-behaviours/**`.

## Implementation Phases

### Phase 1: Local Harness

- [x] Add `playwright.intended.config.ts`.
- [x] Add `tests/e2e/intended-behaviours/harness.ts`.
- [x] Add `test:intended` scripts.
- [x] Add the hidden site route `/__intended-e2e` under the real
      `SeamsWebProvider`, with a public-SDK passkey-registration action and
      machine-readable lifecycle snapshot. The route is enabled by default in
      dev, disabled by default in production builds, and explicitly enabled by
      the intended CI service launcher through `VITE_ENABLE_INTENDED_E2E=1`.
- [x] Add the first public-SDK NEAR signing action for registered passkey
      wallets and capture signed transaction bytes in the harness snapshot.
- [x] Prove the harness can connect to already-running `pnpm router` and
      `pnpm site`.
- [x] Replace remaining placeholder harness actions with public SDK/UI flows.

### Phase 2: Passkey Contracts

- [x] Add passkey registration contract.
  - [x] Wire passkey registration through the real site provider and wallet
        iframe.
  - [x] Wire post-registration NEAR signing through public SDK
        `signTransactionWithActions`.
  - [x] Add cryptographic Ed25519 verification of the returned signed
        transaction against the registered wallet public key.
  - [x] Wire Tempo and Arc/EVM signing with ECDSA public-key recovery checks.
  - [x] Wire Ed25519 and ECDSA key export through exact-lane public SDK
        `exportKeypairWithUI`.
  - [x] Wire budget exhaustion and step-up checks.
- [x] Add passkey unlock contract.
  - [x] Clear page/runtime memory while preserving browser storage before
        unlock.
  - [x] Wire passkey unlock through public SDK `auth.unlock`.
  - [x] Verify post-unlock NEAR, Tempo, and Arc/EVM signing from warmed lanes.
  - [x] Assert post-registration/post-unlock signing uses structured
        warm-session events instead of passkey or Email OTP prompts.
  - [x] Wire Ed25519 and ECDSA key export actions.
  - [x] Wire post-exhaustion step-up checks.
- [x] Cover Ed25519 signing, ECDSA signing, step-up, and key export.

### Phase 3: Email OTP Contracts

- [x] Add Email OTP registration contract with wallet reroll.
  - [x] Start registration through public
        `auth.beginGoogleEmailOtpWalletAuth`.
  - [x] Assert wallet-name reroll preserves the single registration challenge
        and binds the final wallet ID.
  - [x] Verify post-registration NEAR, Tempo, and Arc/EVM signing from warmed
        lanes.
  - [x] Wire Ed25519 and ECDSA key export actions.
- [x] Add Email OTP unlock contract.
  - [x] Start unlock through public `auth.beginGoogleEmailOtpWalletAuth`.
  - [x] Read the wallet-unlock OTP through the Router dev outbox using a public
        app-session JWT.
  - [x] Submit the OTP through the real wallet iframe UI.
  - [x] Verify post-unlock NEAR, Tempo, and Arc/EVM signing from warmed lanes.
  - [x] Wire post-exhaustion Email OTP step-up checks.
- [x] Cover Ed25519 signing, ECDSA signing, step-up, and key export.

Full execution of the Email OTP contracts now runs locally with the ignored
`.env.intended.local` Google OIDC/service-account token setup and the Router dev
outbox. The token remains one-hour generated state; `test:intended` and
`test:intended:ci` run `ensure:intended-google-token` before Playwright, accept
a still-valid token, and refresh through the configured service account when
needed. `pnpm refresh:intended-google-token` remains available for manual
debugging.

### Live Validation Findings

The harness connects to already-running local `pnpm site` and `pnpm router`
services and reaches the real public passkey registration/unlock paths. Live
passkey runs fixed these boundary issues:

- browser-context storage reset is self-contained inside `page.evaluate`
- Chromium's virtual WebAuthn authenticator is PRF-capable via `hasPrf: true`
- the harness now treats `signing.authentication.complete` with
  `authMethod: "passkey"` as passkey auth, so a storage reconnect cannot be
  misclassified as warm-session signing
- the intended page keeps active wallet/NEAR identity in page state and clears
  per-action lifecycle events when a new action starts; this preserves the
  warmed runtime between registration/unlock and the immediately following
  signing action while keeping each action's event oracle isolated
- the harness closes the key-export viewer after a successful export so the
  next contract action is not blocked by the modal
- the harness now fails fast when a public action click does not move the
  intended page into a running or completed action state, and includes the page
  snapshot plus recent compact trace in the failure
- the `budget_unknown` matcher caught a real ECDSA post-step-up planning gap:
  the fresh passkey ECDSA session had trusted auth for budget admission, while
  the pre-confirm readiness object dropped it. The refresh path now threads
  trusted budget-status auth through readiness before admission.

Current live validation:

- Re-run on July 4, 2026 after the local console seed was fixed to use
  `SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID` / `VITE_SEAMS_PROJECT_ENVIRONMENT_ID`
  and after the post-exhaustion oracle was narrowed to lifecycle-wide step-up
  rather than per-material-family step-up:
  `pnpm -C tests seed:intended-local-console`, Vite on port 3600 with the
  intended env mapping, then `pnpm -C tests test:intended` passed 4/4 in 3.1m
  against the existing local router.
- Re-run on July 4, 2026 after adding the Google ID-token preflight:
  `pnpm test:intended:ci` refreshed/accepted `.env.intended.local`, built the
  SDK, started CI-managed router/site services, seeded D1, and passed all four
  intended contracts in 3.8m.
- `passkey.registration.contract.test.ts` passes end to end, including NEAR,
  Tempo, Arc/EVM, exhaustion, step-up, Ed25519 export, and ECDSA export.
- `passkey.unlock.contract.test.ts` passes end to end across the same signing,
  exhaustion, step-up, and export checks.
- Targeted validation after the `budget_unknown` matcher work:
  `pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/passkey.registration.contract.test.ts e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line`
  passes 2/2. Re-run on July 4, 2026 after restoring the temporary ECDSA oracle
  mutation: 2/2 passed in 1.3m.
- Re-run on July 4, 2026 after starting the Vite site on port 3600 behind the
  existing local Caddy/router stack: the same passkey registration + unlock
  intended command passed 2/2 in 1.3m.
- Earlier cross-chain mutation proof uncovered a target-identity prerequisite:
  the harness could only observe wrong-material reuse once Tempo and Arc/EVM
  registration/provisioning exposed target-specific owner/public-key facts.
  That prerequisite is now satisfied by the target-specific ECDSA registration
  work. On July 5, 2026, a scratch mutation that reported the Tempo key as the
  Arc/EVM registered key made both passkey intended contracts fail with
  `Arc/EVM recovered signer mismatch`; the scratch mutation was restored.
- `pnpm -C tests run check:intended-behaviour-contract-boundaries` passes after
  the active-source retired-setup import guard,
  Refactor 89 retired-cleanup ledger guard,
  sibling-plan pre-merge gate guard, setup-surface cleanup guard,
  suite-wall-clock-budget guard, and action-start fail-fast guard were added.
- Re-run on July 4, 2026 after retiring the stale registration-flow benchmark
  runner and updating historical benchmark docs: 26/26 passed in 1.6s.
- Re-run after pruning stale generic setup lifecycle docs and guarding
  `tests/README.md` against retired lifecycle-test references: 27/27 passed in
  1.7s.
- Re-run after adding guards that keep the four contract files as high-level
  harness scripts and block private SDK/runtime imports from the intended page
  and harness: 29/29 passed in 1.7s.
- Re-run after guarding the intended page and harness result unions plus
  parser/helper switches against action-result discriminant drift: 30/30 passed
  in 1.7s.
- Re-run after gating `/__intended-e2e` to dev and explicit CI opt-in:
  31/31 passed in 1.8s.
- Re-run after reframing `tests/README.md` so generic browser setup is no
  longer documented as lifecycle authority: 31/31 passed in 1.7s.
- Re-run after guarding package scripts against retired registration-flow
  benchmark command reintroduction: 32/32 passed in 1.8s.
- Re-run after guarding local intended Playwright config away from generic
  webServer/fake-router startup: 32/32 passed in 1.8s.
- Re-run after guarding intended harness request routing so only external
  identity/chain RPC hosts are stubbed: 33/33 passed in 1.8s.
- Re-run after marking the retained registration-flow benchmark report as an
  archived historical artifact and guarding its archive banner: 34/34 passed in
  1.7s.
- Re-run after moving the intended page off internal wallet-id imports and demo
  ECDSA chain-target helpers: 34/34 passed in 1.8s. The same change keeps
  `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit --pretty false`
  passing.
- Re-run after classifying the retained wallet-iframe, public signing surface,
  and Email OTP iframe-handle boundary tests and guarding those audit rows:
  35/35 passed in 1.3s.
- Re-run after expanding the retained-boundary guard so every
  `tests/wallet-iframe/*.test.ts` file must have a `keep` row in this audit:
  35/35 passed in 1.3s.
- Re-run after adding retained-boundary source evidence-token checks for every
  `keep` row: 35/35 passed in 1.7s.
- Re-run after deleting the unused `createConsoleCapture` setup logging helper
  and guarding it through the Refactor 89 ledger: 35/35 passed in 1.9s.
- Re-run after guarding that the intended harness owns its Playwright fixture,
  WebAuthn setup, service readiness checks, failure capture, external-host
  stubs, and wallet iframe auto-confirm path outside `tests/setup/**`: 36/36
  passed in 1.6s.
- Re-run after fixing the Phase 3B exit criterion so unchecked mutation proof
  rows cannot coexist with a completed-regression claim: 36/36 passed in 1.8s.
- `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit` passes.
- Re-run on July 4, 2026 with `--pretty false`: passed.
- `node --check tests/scripts/start-intended-services.mjs` passes.
- `node tests/scripts/start-intended-services.mjs --check` resolves the default
  local intended service config.
- CI startup now starts `pnpm router -- --fresh`, waits for router `healthz`
  and `readyz`, then starts only the app Vite server with
  `pnpm -C apps/seams-site run vite`. The Router launcher owns the single local
  Caddy process for app, wallet, docs, and Router origins; CI startup does not
  run the broader `pnpm site` command because that would create a second Caddy
  owner. The launcher verifies representative SDK `dist` artifacts after
  `build:sdk-full`, clears the site Vite optimizer cache, and asks the site
  Vite server to serve the SDK modules used by the intended page before
  publishing readiness. After the HTTPS site and intended page pass their
  internal checks, the startup script exposes a local HTTP Playwright webServer
  readiness sentinel at `http://127.0.0.1:37888/readyz`. This keeps Playwright's
  readiness probe off the self-signed app-origin certificate while still
  preventing tests from racing ahead of Router/site readiness. The CI config
  uses Playwright graceful shutdown so the startup script can terminate nested
  Router, Caddy, Vite, and workerd children instead of leaving the intended
  ports occupied after a run.
- The hidden `/__intended-e2e` route is now guarded by
  `FRONTEND_CONFIG.enableIntendedE2E`: local dev keeps the public-SDK harness
  available, CI opts in explicitly, and production builds do not expose the
  operational intended-behaviour page by default.
- `pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts --list`
  lists the four intended contracts from the CI config without starting
  services.
- Re-run on July 4, 2026 after SDK-dist readiness hardening:
  `pnpm test:intended:ci` passed all four intended contracts in 4.3 minutes.
- The old `benchmark:registration-flow*` scripts and runner files are removed.
  The benchmark depended on the deleted
  `tests/e2e/thresholdEd25519.testUtils` managed-registration mock harness;
  `benchmarks/registration-flow/README.md` now records the retirement and
  points at the retained historical report.
- `pnpm check:intended-mutation-self-check` validates the Phase 3B manifest
  and proof metadata, including exact expected failure-oracle strings for each
  seeded regression row.
- Re-run on July 4, 2026 after benchmark-runner retirement: manifest ok, 4 of
  4 seeded regressions represented.
- Re-run after tightening manifest validation around version, Google-token
  command requirements, known-product-blocker scoping, and proof-command
  contract scope: manifest ok, 4 of 4 seeded regressions represented.
- Re-run after adding machine-readable Phase 3B proof statuses to the mutation
  manifest: `first_post_step_up_transaction_failure` is `detected`, the two
  Email OTP rows are `blocked_email_otp_token`, and
  `cross_chain_ecdsa_material_reuse` is `blocked_product_identity`.
- Validation after adding proof statuses: `pnpm check:intended-mutation-self-check`
  reports manifest ok, `unit/intendedBehaviourContracts.guard.unit.test.ts` passes
  36/36 in 1.8s, and the TypeScript/whitespace checks pass.
- Preflight rows now print each row's `phase3bProof.status` as `status=...`,
  so blocked output identifies Email OTP token setup separately from the
  cross-chain ECDSA product-identity blocker.
- Validation after adding preflight status output: `pnpm check:intended-mutation-self-check`
  reports manifest ok, `unit/intendedBehaviourContracts.guard.unit.test.ts` passes
  36/36 in 1.8s, and the TypeScript/whitespace checks pass.
- Re-run after adding machine-checked `unblockRequirement` fields to blocked
  Phase 3B proof rows: `pnpm check:intended-mutation-self-check` reports
  manifest ok, `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 37/37
  in 1.8s, and the TypeScript check passes.
- Re-run after adding proof-status counts to the manifest check:
  `pnpm check:intended-mutation-self-check` reports
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`;
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 37/37 in 1.8s, and
  the TypeScript check passes.
- Added `pnpm check:intended-mutation-self-check:complete` as the explicit
  Phase 3B completion gate. It requires every selected mutation row to be
  `detected` and prints each blocked row's `unblockRequirement` when the proof
  ledger is still incomplete.
- Validation after adding the completion gate: `pnpm check:intended-mutation-self-check`
  passes, `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 37/37 in
  1.8s, and the TypeScript check passes. `pnpm check:intended-mutation-self-check:complete`
  exits nonzero as expected while the ledger remains
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`, printing
  all three blocked rows with their unblock requirements.
- Targeted completion-gate validation: `pnpm check:intended-mutation-self-check:complete -- --mutation first_post_step_up_transaction_failure`
  passes because that row is `detected`; the same command targeting
  `cross_chain_ecdsa_material_reuse` exits nonzero and prints the
  product-identity unblock requirement.
- Re-run after adding machine-readable detected-proof evidence:
  `first_post_step_up_transaction_failure` now records `observedAt`,
  `observedFailureCommand`, and `restoredValidationCommand`; blocked rows are
  rejected if they carry detected-proof evidence. `pnpm check:intended-mutation-self-check`
  reports manifest ok and the guard suite remains green.
- Targeted completion output now prints the detected row evidence:
  `observedAt`, `oracle`, `failure`, and `restored` command lines for
  `first_post_step_up_transaction_failure`.
- Targeted preflight after adding `unblockRequirement`:
  `pnpm preflight:intended-mutation-self-check -- --mutation cross_chain_ecdsa_material_reuse`
  exits nonzero as expected with the local site/fresh-startup/product-identity
  blockers and prints the manifest `unblock:` requirement.
- Re-run after adding the fake AuthService quarantine guard:
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 37/37 in 1.8s,
  and the TypeScript check passes.
- Re-run on July 4, 2026 after tightening the completion-gate evidence:
  `pnpm check:intended-mutation-self-check` passes with
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`;
  `pnpm check:intended-mutation-self-check:complete -- --mutation first_post_step_up_transaction_failure`
  passes and prints the detected proof evidence;
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 37/37 in 1.7s;
  `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit --pretty false`
  and `git diff --check` pass. Full
  `pnpm check:intended-mutation-self-check:complete` exits nonzero as expected
  until the two Email OTP token-blocked rows and the cross-chain product
  identity row are detected.
- `pnpm -C tests exec playwright test -c playwright.intended.config.ts --list`
  lists exactly the four intended contracts from the local intended config.
- Current Phase 3B preflight output:
  `SEAMS_INTENDED_MUTATION_FRESH_STARTUP=1 pnpm preflight:intended-mutation-self-check -- --mutation first_post_step_up_transaction_failure`
  reports site root, intended page, Router `healthz`, and Router `readyz` as
  ready when the local Vite site is running on port 3600 behind Caddy. The
  `first_post_step_up_transaction_failure` row is ready in that state. The
  `cross_chain_ecdsa_material_reuse` row still carries an explicit
  `knownProductBlocker` naming the shared `evm-family` key scope, so preflight
  remains blocked until target-specific ECDSA owner/public-key facts are
  distinct enough for the seeded wrong-material regression to be observable.
  Blocked proof rows also print `unblock: ...` from the manifest so the next
  required action is visible in preflight output. Full preflight runs
  `ensure:intended-google-token` before readiness checks, so Email OTP rows use
  the local service-account token setup instead of manual inline token
  assignment.
  `pnpm preflight:intended-mutation-self-check:ci` blocks because the fixed
  local intended ports are already occupied by the current Caddy/router stack.
- Re-run without a running local site and without the fresh-startup marker now
  reports `site root: blocked (502)`, `intended page: blocked (502)`, and
  missing `SEAMS_INTENDED_MUTATION_FRESH_STARTUP=1`, while Router `healthz` and
  `readyz` remain ready. Targeted Email OTP preflight reports service/fresh-start
  blockers after the token-ensure step; targeted cross-chain preflight reports
  the target-specific ECDSA owner/public-key blocker. This keeps mutation
  preflight failures actionable when Caddy is up but the Vite site is not
  serving.
- Email OTP mutation preflight now rejects
  `SEAMS_INTENDED_GOOGLE_ID_TOKEN=<local-google-id-token>` and other malformed
  non-JWT values before a proof run. This is a shape check only; Router Google
  OIDC signature and claim verification remain the runtime authority.
- Validation after tightening Email OTP token preflight: `node --check
  tests/scripts/check-intended-mutation-self-check.mjs` passes;
  `pnpm check:intended-mutation-self-check` passes; targeted preflight reports
  `SEAMS_INTENDED_GOOGLE_ID_TOKEN=placeholder`, `malformed`, or `jwt-shaped`
  for placeholder, non-JWT, and compact-JWT-shaped inputs respectively; the
  Refactor 88 guard suite passes 37/37; TypeScript and whitespace checks pass.
- Re-run after guarding active source against retired browser mutation hooks
  and tying the remaining generic e2e bootstrap allowlist to the retained
  boundary audit: `pnpm check:intended-mutation-self-check` reports
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`;
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 39/39 in 1.9s;
  `node --check tests/scripts/check-intended-mutation-self-check.mjs`,
  `pnpm -C tests exec tsc -p tsconfig.playwright.json --noEmit --pretty false`,
  and `git diff --check` pass.
- Re-run after adding retained-boundary audit rows for all
  `tests/lit-components/*.test.ts` component browser tests and guarding that
  every current Lit component test stays classified: `unit/intendedBehaviourContracts.guard.unit.test.ts`
  passes 40/40 in 1.9s; TypeScript and whitespace checks pass.
- Re-run after adding retained-boundary audit rows for the remaining
  `SeamsWeb` browser setup unit tests and guarding that future
  `seamsWeb.*` files using `setupBasicPasskeyTest` stay explicitly
  classified: `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 41/41 in
  1.9s; TypeScript and whitespace checks pass.
- Re-run after adding retained-boundary audit rows for every
  `tests/unit/confirmTxFlow*.test.ts` browser unit and guarding that the
  confirm-flow family stays fully classified: `unit/intendedBehaviourContracts.guard.unit.test.ts`
  passes 42/42 in 1.9s; TypeScript and whitespace checks pass.
- Re-run after classifying every remaining `setupBasicPasskeyTest` consumer as
  retained boundary coverage and adding the aggregate generic-bootstrap audit:
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 43/43 in 1.8s;
  `pnpm check:intended-mutation-self-check` reports
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`;
  TypeScript and whitespace checks pass.
- Re-run after tightening the cross-chain mutation blocker to name the shared
  `evm-family` key scope in machine-checked metadata:
  `node --check tests/scripts/check-intended-mutation-self-check.mjs` passes;
  `pnpm check:intended-mutation-self-check` reports
  `blocked_email_otp_token=2 blocked_product_identity=1 detected=1`;
  the Refactor 88 guard suite, TypeScript, and whitespace checks pass.
- Re-run after moving `test:integration:signing` onto the Vite-only browser
  setup and guarding it away from the fake relay server path:
  `unit/intendedBehaviourContracts.guard.unit.test.ts` passes 44/44; TypeScript and
  whitespace checks pass.
- Re-run after excluding intended contracts from the generic Playwright config:
  the Refactor 88 guard suite passes 45/45; generic
  `./e2e/intended-behaviours --list --reporter=line` reports `No tests found`
  and `Total: 0 tests`; TypeScript and whitespace checks pass.
- Re-run after moving `test:e2e` onto the Vite-only browser setup and aligning
  `wallet-service-headers.test.ts` with the local wallet-origin default:
  the Refactor 88 guard suite passes 46/46; a no-relay e2e smoke subset
  covering cancel overlay, pricing CTA wiring, and wallet-service headers
  passes; TypeScript and whitespace checks pass.
- Re-run after moving `test:lite` onto the Vite-only browser setup: no-relay lite
  discovery lists `Total: 2622 tests in 385 files`, the Refactor 88 guard
  suite guards the script against fake-relay regression, and the targeted
  no-relay lite smoke covering wallet iframe handshake, concurrent overlay
  aggregation, and wallet-service headers passes.
- Re-run after moving `test:inline` onto the Vite-only browser setup: no-relay generic
  discovery lists `Total: 2625 tests in 386 files`, the sticky wallet-iframe
  suite passes, and the Refactor 88 guard suite now guards the inline script
  against fake-relay regression.
- Re-run after refreshing stale ECDSA identity/public-fact fixtures and fixing
  wallet-iframe export overlay capture/close handling: `pnpm build:sdk-full`
  passes; the Email OTP ECDSA publication + threshold-ECDSA authorization unit
  pair passes 8/8; the wallet-origin export-flow integration file passes 3/3;
  broad Playwright discovery has no import-time
  `wallet auth authority` or `evmFamilySigningKeySlotId` errors and lists
  `Total: 2623 tests in 386 files`; the Refactor 88 guard suite passes 47/47;
  `pnpm check:intended-mutation-self-check`, TypeScript, and whitespace checks
  pass.
- Re-run after moving the full generic `test` script onto the Vite-only browser
  setup, deleting the fake AuthService server launcher scripts, and removing
  the generic Playwright fake-relay branch: generic Playwright discovery lists
  `Total: 2627 tests in 386 files`; the Refactor 88 guard suite passes 51/51;
  the wallet-service headers plus sticky/export wallet-iframe smoke subset
  passes 6/6; `pnpm check:intended-mutation-self-check`, TypeScript, and
  whitespace checks pass.
- Re-run after adding deletion guards for the fake AuthService server launcher
  files and the neutral `test:unit:scripts` source-script suite name: the
  Refactor 88 guard suite passes 53/53; TypeScript and whitespace checks pass.
- Re-run after recording the fake AuthService server launcher deletion in the
  Refactor 89 retired-cleanup ledger and guarding that ledger row: the Refactor
  88 guard suite passes 53/53; TypeScript and whitespace checks pass.
- Re-run after updating Refactor 53's current recommended package-script
  examples away from the deleted fake-relay flag and guarding that cleanup doc:
  the Refactor 88 guard suite passes 54/54; TypeScript, whitespace checks, and
  the focused fake-relay search over current test docs/scripts/config pass.
- Re-run after removing duplicate `useRelayer` / `relayServerUrl` fields from
  the generic setup config and switching the retained cancel-overlay shim to
  `relayer.url`: the Refactor 88 guard suite passes 54/54; TypeScript passes;
  `W3A_TEST_FRONTEND_URL=http://localhost:5187 pnpm -C tests exec playwright test -c playwright.config.ts e2e/cancel_overlay_specs.test.ts --reporter=line`
  passes 1/1.
- Re-run after refreshing generic setup comments/docs from the obsolete
  five-step sequence and removing the stale mocked-Router skip guidance: the
  Refactor 88 guard suite passes 54/54; TypeScript and whitespace checks pass.
- Re-run after trimming `handleInfrastructureErrors` to the retained faucet
  429 skip only and guarding against broad Router/funding/port-collision skip
  branches: the Refactor 88 guard suite passes 54/54; TypeScript passes;
  `W3A_TEST_FRONTEND_URL=http://localhost:5188 pnpm -C tests exec playwright test -c playwright.config.ts e2e/cancel_overlay_specs.test.ts --reporter=line`
  passes 1/1.
- If `SEAMS_INTENDED_GOOGLE_ID_TOKEN` is absent, the two Email OTP contracts
  still fail fast with `Email OTP registration requires googleIdToken query
  param`; that is the intended configuration gate. With the refreshed
  service-account token present, the four-contract local suite passes 4/4.
- The earlier Ed25519 HSS respond/finalize retained-state blocker is no longer
  live for the passkey contracts; the passkey export path now completes without
  client-carried server output material.
- Re-run after service-account Google OIDC setup and the two Email OTP mutation
  proofs: `pnpm check:intended-mutation-self-check` reports
  `blocked_email_otp_token=0 blocked_product_identity=1 detected=3`.
  Targeted completion for
  `email_otp_reroll_bootstrap_token_request_mismatch` and
  `export_provider_user_mismatch_after_app_session_refresh` passes and prints
  both detected proof rows. Full completion remains blocked only by
  `cross_chain_ecdsa_material_reuse` pending target-specific Tempo and Arc/EVM
  ECDSA owner/public-key facts. The Refactor 88 guard suite passes 55/55,
  Playwright TypeScript checking passes, and focused whitespace checking
  passes.
- Re-run after retiring inline Google ID-token placeholders from the mutation
  manifest: Email OTP proof rows now run
  `pnpm -C tests run ensure:intended-google-token` before the targeted intended
  Playwright command; `pnpm -C tests preflight:intended-mutation-self-check --
  --mutation email_otp_reroll_bootstrap_token_request_mismatch` reports the row
  ready when local services are ready. The mutation manifest check, Refactor 88
  guard suite, and ledger completeness gate pass.
- Re-run after backing the remaining cross-chain mutation blocker with live
  product evidence: the Refactor 88 guard now checks that
  `cross_chain_ecdsa_material_reuse` stays `blocked_product_identity` only
  while `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts` still asserts shared
  Tempo and Arc/EVM EVM-family owner/fingerprint identity. When that product
  assertion changes, the guard forces this row to become a detected mutation
  proof instead of letting the blocker go stale.
- Stabilization checkpoint, July 4, 2026: after backing out the premature
  recovery fifth-spec probe, the stable four-contract suite remains green.
  `pnpm test:intended:ci` refreshed/accepted `.env.intended.local`, started
  managed router/site services, and passed the four intended contracts in
  4.3m. `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  ./unit/intendedBehaviourContracts.guard.unit.test.ts --reporter=line` passed
  55/55, `pnpm -C tests check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, and
  `pnpm -C tests check:intended-mutation-self-check` reported
  `blocked_email_otp_token=0 blocked_product_identity=1 detected=3`.
  `git diff --check` also passed. The attempted recovery spec failed at
  `/email-recovery/prepare` with HTTP 404 because the local D1 Router API did
  not yet configure the `RouterApiOptions.emailRecovery` route family; that
  historical blocker was resolved by mounting the local prepare-only recovery
  route family.
- Current validation, July 5, 2026: the cross-chain scratch mutation made both
  passkey intended contracts fail with `Arc/EVM recovered signer mismatch`.
  Restored source then passed the same CI-managed passkey contract pair. The
  mutation manifest records all four Phase 3B rows as `detected`, so
  `pnpm check:intended-mutation-self-check:complete` is now the live completion
  gate instead of a known-blocker report.
- Re-run after the current cleanup batch: `pnpm -C tests run
  check:intended-mutation-self-check:complete` passed with 4/4 seeded
  regressions detected and proof-status counts
  `blocked_email_otp_token=0 blocked_product_identity=0 detected=4`.
- Re-run after moving retained-boundary audit ownership into the ledger
  verifier: `node --check
  tests/scripts/check-intended-behaviour-contract-boundaries.mjs`, `node
  --check tests/scripts/check-refactor88-test-ledger.mjs`, `pnpm -C tests run
  check:refactor88-test-ledger:complete`, and `pnpm -C tests run
  check:intended-behaviour-contract-boundaries` passed. `pnpm -C tests run
  test:source-guards` also passed with the ledger verifier wired into the
  aggregate source profile and 190/190 Playwright source-profile tests green.
- Re-run after reconciling Refactor 89 durable guard classifications with this
  Phase 5 ledger: `pnpm -C tests check:refactor88-test-ledger:complete`
  reported `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`; the
  Refactor 88 guard suite passed 55/55; the durable guard subset
  (`authSecretTerminology`, `nonceCoordinator.durableArchitecture`,
  `stableExperimentalExportBoundaries`, `thresholdEcdsa.behavior`, and
  `thresholdEd25519PresignNonceLifecycle`) passed 24/24; and `git diff --check`
  passed.
- Re-run after mounting local D1 Email Recovery prepare/respond routes through
  a structural prepare-only `RouterApiOptions.emailRecovery` service:
  `pnpm -C packages/sdk-server-ts run build` passed;
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1ConsoleServices.unit.test.ts --reporter=line`
  passed 15/15; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=442 ledger_existing=442 ledger_deleted=19 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  572/572 source-profile tests; and `git diff --check` passed.
- Re-run after deleting the Playwright auth terminology guard and moving its
  invariant to `tests/scripts/check-auth-secret-terminology.mjs`:
  `node --check tests/scripts/check-auth-secret-terminology.mjs` passed;
  `pnpm -C tests run check:auth-secret-terminology` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=441 ledger_existing=441 ledger_deleted=20 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  571/571 source-profile tests.
- Re-run after deleting the Playwright legacy facade-name and WebAuthn
  origin-policy guards and moving their invariants to standalone source checks:
  `node --check` plus focused `pnpm -C tests run check:legacy-seams-web-facade-names`
  and `pnpm -C tests run check:webauthn-origin-policy` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=439 ledger_existing=439 ledger_deleted=22 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  568/568 source-profile tests.
- Re-run after deleting the Playwright Ed25519 presign nonce lifecycle guard,
  moving its burn-order and CSPRNG handle assertions to
  `tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`, and
  resolving the exposed Ed25519 material-readiness ownership drift by moving
  wallet-session material readiness/state helpers into
  `session/warmCapabilities`: `node --check
  tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs` passed;
  `pnpm -C tests run check:threshold-ed25519-presign-nonce-lifecycle` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=438 ledger_existing=438 ledger_deleted=23 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  566/566 source-profile tests; and `git diff --check` passed.
- Re-run after deleting the Playwright ECDSA HSS behavior guard and moving its
  source assertions into
  `tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`:
  `node --check tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`
  passed; `pnpm -C tests run check:threshold-ecdsa-hss-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=437 ledger_existing=437 ledger_deleted=24 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  561/561 source-profile tests; and `git diff --check` passed.
- Re-run after deleting the Playwright Router A/B wallet-session claim boundary
  guard and moving its source assertions into
  `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`:
  `node --check
  tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`
  passed; `pnpm -C tests run
  check:router-ab-server-wallet-session-claim-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=436 ledger_existing=436 ledger_deleted=25 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  557/557 source-profile tests.
- Re-run after deleting the Playwright headless Google Email OTP flow-boundary
  guard and moving its source assertions into
  `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`:
  `node --check
  tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs` passed;
  `pnpm -C tests run check:headless-google-email-otp-flow-boundaries` passed;
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  unit/googleEmailOtpWalletIframeHandles.unit.test.ts --reporter=line` passed
  37/37; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=435 ledger_existing=435 ledger_deleted=26 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  551/551 source-profile tests.
- Re-run after deleting the Playwright Email OTP registration boundary guard
  and moving its source assertions into
  `tests/scripts/check-email-otp-registration-boundaries.mjs`: `node --check
  tests/scripts/check-email-otp-registration-boundaries.mjs` passed; `pnpm -C
  tests run check:email-otp-registration-boundaries` passed; `pnpm -C tests
  exec playwright test -c playwright.unit.config.ts
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  unit/googleEmailOtpWalletIframeHandles.unit.test.ts
  unit/emailOtpRegistrationRoute.unit.test.ts --reporter=line` passed 42/42;
  the intended contract source guard was refreshed to the current
  `EmailOtpRegistrationCoreSummary` and `EmailOtpUnlockCoreSummary` page
  result type names; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=434 ledger_existing=434 ledger_deleted=27 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  543/543 source-profile tests.
- Re-run after deleting the Playwright account signer lifecycle guard and
  moving its source assertions into
  `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`: `node --check
  tests/scripts/check-account-signer-lifecycle-boundaries.mjs` passed; `pnpm
  -C tests run check:account-signer-lifecycle-boundaries` passed; and `pnpm
  -C tests run check:refactor88-test-ledger:complete` reported
  `scope=433 ledger_existing=433 ledger_deleted=28 missing=0`; `pnpm -C
  tests run test:source-guards` passed after `build:sdk-full` with 541/541
  source-profile tests.
- Re-run after the latest Refactor 89 source-guard cleanup through
  `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts`: `pnpm -C
  tests run check:exact-lookup-no-fallback-boundaries` passed; `pnpm -C tests
  run check:refactor88-test-ledger:complete` reported
  `scope=430 ledger_existing=430 ledger_deleted=31 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 508/508 source-profile tests.
- Re-run after the Refactor 89 key-material source-guard cleanup:
  `pnpm -C tests run check:key-material-branding-boundaries` passed; `pnpm -C
  tests run check:refactor88-test-ledger:complete` reported
  `scope=429 ledger_existing=429 ledger_deleted=32 missing=0`; `git diff
  --check` passed; the Email OTP registration source check and intended
  action-result discriminant guard were refreshed to current source anchors;
  and `pnpm -C tests run test:source-guards` passed after `build:sdk-full`
  with 499/499 source-profile tests.
- Re-run after the Refactor 89 route/lifecycle source-guard cleanup:
  `pnpm -C tests run check:route-lifecycle-domain-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=428 ledger_existing=428 ledger_deleted=33 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 484/484 source-profile tests.
- Re-run after the Refactor 89 threshold Ed25519 NEAR signing queue
  source-guard cleanup: `pnpm -C tests run
  check:threshold-ed25519-near-signing-queue` passed; `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=427 ledger_existing=427 ledger_deleted=34 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 468/468 source-profile tests.
- Re-run after the Refactor 89 wallet capability binding source-guard cleanup:
  `pnpm -C tests run check:wallet-capability-bindings-source-guard` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=426 ledger_existing=426 ledger_deleted=35 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 468/468 source-profile tests. A later pass pruned stale
  wallet capability allowlist entries and added stale-entry rejection to the
  standalone check; a later pass moved permanent parser/builder/diagnostics
  boundaries into built-in checker exemptions, and the focused command passes
  with six migration-owned JSON allowlist entries remaining. A follow-up pass
  deleted the retired JSON allowlist after wallet-scoped ECDSA and Email OTP
  flow events moved from `accountId` payloads to `walletId`; `pnpm -C tests run
  check:wallet-capability-bindings-source-guard` and `pnpm -C
  packages/sdk-web type-check` passed, and `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=413 ledger_existing=413 ledger_deleted=53 missing=0`. `pnpm -C tests
  run test:source-guards` also passed with all standalone checks and 190/190
  source-profile tests.
  Follow-up validation stabilized the aggregate gate by running
  `build:sdk-full` before standalone source scripts, retrying fresh WASM output
  existence checks in `build-wasm.sh`, and removing the public signer-worker
  type entry's runtime import of generated NEAR signer JS. `pnpm -C
  packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false` passed;
  `pnpm -C packages/sdk-web run build:sdk-full` passed; `pnpm -C tests run
  test:source-guards` passed with 408/408 source-profile tests; `pnpm -C tests
  run check:refactor88-test-ledger:complete` reported
  `scope=420 ledger_existing=420 ledger_deleted=44 missing=0`; and `git diff
  --check` passed.
- Re-run after the Refactor 89 signing-engine architecture source-guard
  cleanup: `pnpm -C tests run
  check:signing-engine-architecture-boundaries` passed; `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=421 ledger_existing=421 ledger_deleted=40 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 431/431 source-profile tests.
- Stabilization re-run after retargeting stale Email OTP enrollment references
  to the current `prewarmedRegistrationMaterial` / worker-enrollment boundary:
  `node --check tests/scripts/check-cross-platform-boundaries.mjs` passed;
  `node tests/scripts/check-cross-platform-boundaries.mjs` passed; `node
  --check tests/scripts/check-email-otp-recovery-code-leakage.mjs` passed;
  `node tests/scripts/check-email-otp-recovery-code-leakage.mjs` passed;
  `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/ed25519HssMaterialBoundaries.guard.unit.test.ts --reporter=line` passed
  26/26; `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/seamsWeb.emailOtp.unit.test.ts --reporter=line` passed 8/8; and
  `pnpm -C tests run test:source-guards` passed end-to-end after
  `build:sdk-full` with 408/408 source-profile tests. The Refactor 88 ledger
  completeness check reported `scope=421 ledger_existing=421 ledger_deleted=44 missing=0`
  after adding the retained D1 registration ECDSA wallet-key row.
- Current validation, July 5, 2026: `pnpm -C tests run test:intended:ci`
  refreshed the service-account Google token and passed all five intended
  lifecycle contracts in 4.5m. Focused clean-stack checks passed for passkey
  registration (34.3s), Email OTP registration (39.7s), and recovery email
  (30.6s). `pnpm -C tests run check:refactor88-test-ledger:complete` reports
  `scope=407 ledger_existing=407 ledger_deleted=66 missing=0`, and
  `pnpm -C tests run test:source-guards` passes all standalone scripts plus
  190/190 Playwright source-profile tests.

### Phase 3B: Prove The Gate Can Fail

One-time mutation self-check after Phases 2-3 land. On a scratch branch,
re-introduce one known regression per class and confirm the suite fails with
the expected compact trace:

- wallet-name reroll triggering `bootstrap_token_request_mismatch`;
- first post-step-up transaction failure (stale spend authority);
- export provider-user matching failure after app-session refresh;
- cross-chain ECDSA material reuse (signature verifying against the wrong
  chain target's key).

A seeded regression the suite cannot detect is a harness bug to fix before
the gate is declared mandatory. Record the results in this plan.

Run these mutation checks with a fresh SDK build and restarted site/router
services, or through `pnpm test:intended:ci`. Long-running local site processes
can serve a cached/prebundled SDK from `packages/sdk-web/dist`; source or `dist`
edits against that stale process can make a seeded mutation appear to pass.
The current local stack is already occupying `https://localhost`,
`https://localhost:8443`, and `https://localhost:9444`, so CI-managed mutation
startup cannot run concurrently with it. Email OTP mutation rows use the same
`ensure:intended-google-token` preflight as `test:intended`, accepting a
fresh-enough token or refreshing through the configured service account before
the readiness checks run.

Preflight commands:

```sh
pnpm check:intended-mutation-self-check
pnpm check:intended-mutation-self-check:complete
pnpm preflight:intended-mutation-self-check
pnpm preflight:intended-mutation-self-check:ci
pnpm preflight:intended-mutation-self-check -- --mutation cross_chain_ecdsa_material_reuse
pnpm preflight:intended-mutation-self-check -- --mutation first_post_step_up_transaction_failure
```

The check command validates the manifest and proof metadata. The completion
check is expected to fail until all rows are `detected`; use it for the final
Phase 3B completion audit. The preflight commands run
`ensure:intended-google-token` before they inspect the environment. They do not
seed regressions; they report whether the current local or CI-managed
environment can run the Phase 3B mutation proof rows.
Local preflight requires `SEAMS_INTENDED_MUTATION_FRESH_STARTUP=1` after a
fresh SDK build and restarted site/router services, because a long-running site
can serve stale SDK artifacts.
Use `--mutation <id>` or `--mutation=<id>` to preflight a single proof row.
That lets passkey-only rows run independently while Email OTP rows reuse the
local Google-token setup.

Tracking:

- [x] Add a structured mutation manifest at
  `tests/e2e/intended-behaviours/mutation-self-check.manifest.json` with the
  four required seeded regressions, target contracts, expected failure oracles,
  and harness evidence tokens.
- [x] Add `tests/scripts/check-intended-mutation-self-check.mjs` and package
  scripts for manifest validation plus local/CI environment preflight.
- [x] Add targeted `--mutation` filtering to the mutation self-check command so
  passkey-only proof rows can be preflighted while Email OTP rows wait for
  `SEAMS_INTENDED_GOOGLE_ID_TOKEN`.
- [x] Guard the manifest in
  `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` so rows cannot be
  dropped or drift away from the live harness, each seeded regression keeps
  runnable proof commands, and expected failure oracles remain exact enough to
  match observed compact traces.
- [x] Guard the mutation instructions so Phase 3B proof must run against a
  fresh SDK build plus restarted site/router services or CI-managed intended
  startup.
- [x] Harden the mutation self-check script so the manifest version is fixed,
  Email OTP proof rows must run `ensure:intended-google-token` before their
  targeted contract command, proof commands cannot inline Google ID tokens,
  non-Email rows cannot require that token setup, `knownProductBlocker` is
  scoped to the cross-chain ECDSA row, and proof commands cannot mention
  contracts outside their manifest row.
- [x] Add machine-readable Phase 3B proof status to each mutation manifest row,
  with validator policy for detected rows, Email OTP token blocks, and the
  cross-chain ECDSA product-identity block.
- [x] Include each mutation row's proof status in preflight output and guard
  the script so status visibility stays wired to `phase3bProof.status`.
- [x] Add machine-checked `unblockRequirement` text to every blocked proof row,
  require detected rows to omit it, and print the requirement in preflight
  output.
- [x] Print proof-status counts from `pnpm check:intended-mutation-self-check`
  so blocked and detected Phase 3B rows remain visible in the normal metadata
  gate.
- [x] Add `pnpm check:intended-mutation-self-check:complete`, which fails until
  every selected Phase 3B mutation proof row is `detected`.
- [x] Add machine-readable proof evidence for detected rows (`observedAt`,
  `observedFailureCommand`, and `restoredValidationCommand`) and reject those
  fields on blocked rows.
- [x] Print detected proof evidence from
  `pnpm check:intended-mutation-self-check:complete` when all selected rows are
  detected.
- [x] Smoke-check the ECDSA oracle by temporarily corrupting the Arc/EVM
  expected signer address in the harness: `passkey.registration.contract.test.ts`
  failed with `Arc/EVM recovered signer mismatch`; restoring the harness made
  the same contract pass 1/1. Re-run on July 4, 2026 against both passkey
  contracts: the seeded mismatch failed both
  `passkey.registration.contract.test.ts` and
  `passkey.unlock.contract.test.ts` with `Arc/EVM recovered signer mismatch`;
  restoring the harness made the same 2-contract command pass 2/2 in 1.3m.
- [x] Run `email_otp_reroll_bootstrap_token_request_mismatch` on a scratch
  branch with the Email OTP intended contract. A local scratch mutation that
  bound the Email OTP registration bootstrap token to the wrong wallet made
  `email-otp.registration.contract.test.ts` fail with
  `bootstrap_token_request_mismatch`; restoring the seed made the same contract
  pass 1/1 in 44.6s.
- [x] Run `first_post_step_up_transaction_failure` against the intended signing
  contracts. A local scratch mutation that forced `signNearTransaction` to fail
  only at `after_step_up:near.sign` made both passkey intended contracts fail
  with the expected `post-step-up transaction failed` oracle; restoring the
  seed made the same 2-contract command pass 2/2 in 1.3m.
- [x] Run `export_provider_user_mismatch_after_app_session_refresh` on a
  scratch branch against the intended export paths. A local scratch mutation
  that let the Email OTP ECDSA export viewer complete without requesting the
  fresh export OTP made `email-otp.registration.contract.test.ts` fail with
  `ECDSA export did not fill a fresh Email OTP export authorization`; rebuilding
  from restored source made the same contract pass 1/1 in 45.2s.
- [x] Run `cross_chain_ecdsa_material_reuse` on a scratch branch against Tempo
  and Arc/EVM signing. On July 5, 2026, a local scratch mutation made the
  intended page report the Tempo target key as the Arc/EVM registered key while
  leaving actual Arc/EVM signing intact. Both
  `passkey.registration.contract.test.ts` and
  `passkey.unlock.contract.test.ts` failed with
  `Arc/EVM recovered signer mismatch` under
  `pnpm -C tests exec playwright test -c playwright.intended.ci.config.ts e2e/intended-behaviours/passkey.registration.contract.test.ts e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line`.
  Restoring the scratch mutation made the same CI-managed passkey contract pair
  pass again.

### Phase 4: CI Startup

- [x] Add CI-managed router/site startup after local mode is stable.
  - `pnpm test:intended` remains the local mode and assumes services are
    already running.
  - `pnpm test:intended:ci` uses `tests/playwright.intended.ci.config.ts` and
    `tests/scripts/start-intended-services.mjs` to build fresh SDK artifacts,
    reset local persisted state, start `pnpm router -- --fresh`, wait for
    Router `healthz` and `readyz`, start the app Vite server without starting a
    second Caddy process, verify the site can serve the intended SDK module
    graph from freshly built `dist`, wait for the site and intended page,
    publish the local HTTP readiness sentinel, then run the same four intended
    contracts. Playwright sends graceful `SIGTERM` on teardown so the launcher
    can sweep nested local service children before exit.
- [x] Keep local mode unchanged.

### Phase 5: Test Ledger And Mocked Runtime Fixture Audit

This phase owns the exhaustive test ledger, not a sampled audit. Every file
under `tests/unit`, `tests/e2e`, `tests/relayer`, `tests/lit-components`,
`tests/wallet-iframe`, and `tests/unit/helpers` gets one ledger row (455 files
at the current sweep: 381 unit/helper files, 13 e2e files, 42 relayer files,
6 Lit component files, and 14 wallet-iframe files).
The audit table below is that ledger in progress — a file absent from the
table is *unaudited*, not implicitly kept. This ledger supersedes
`docs/refactor-53-test-inventory.csv`, which covered only the June
guard-file split.

Pruning ownership map — this ledger is the master index; each owner prunes
its category and records the result here:

- This plan: mocked lifecycle tests, runtime fixture graphs, and setup
  scripts (Phases 5-7).
- [Refactor 89](./refactor-89-clean-source-guards.md): source guards and
  guard allowlists.
- Refactor 90 Phases F1/B1: wallet-first vocabulary tests, via the
  redundant-test ledger.
- 82B, 83, 84a, and 86: their own stale tests, deleted in their owning plans.

Helper files get rows too: a helper with zero surviving importers is deleted
in the same change as its last test.

Audit priorities:

- e2e tests using `__testOverrides`, fake SDK surfaces, or fake auth menus
- unit tests using large warm-session/runtime fixture graphs
- tests that assert mocked lane inventory rather than executing real
  registration, unlock, signing, step-up, or export
- tests whose fixtures must be rewritten every time runtime state shapes change

Known first targets:

- `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts`
- `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`
- `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts`
- runtime fixture helpers under `tests/unit/helpers/*warmSession*`

Classify each test as one of:

- keep: validates parser, cryptographic vector, boundary validation, or a compact
  pure domain transition
- replace: behaviour is covered by `test:intended`
- delete: mocked fixture only preserves obsolete or internal runtime shape
- blocked_on_coverage(coverage): mocked and due for deletion, but its
  behaviour is not yet covered by real-infrastructure tests. The row names
  the covering coverage — an 82B Phase 8 item, a Refactor 86 smoke, or another
  named owner-plan gate — and the batch moves to `replace` when that coverage
  lands. The former recovery batch has moved to replacement cleanup after the
  fifth intended spec landed.

Initial audit:

| Target | Classification | Reason |
| --- | --- | --- |
| `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts` | deleted | Used `setupBasicPasskeyTest`, `__testOverrides`, mocked SDK methods, mocked chain responses, and demo component mounting to approximate registration -> signing. The passkey intended contracts now cover that lifecycle with real Router API, wallet iframe, IndexedDB, D1/DO, and workers. Guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. |
| `tests/e2e/docs.thresholdSigningActions.smoke.test.ts` | deleted | Mounted docs/demo components against a mocked logged-in SDK surface. The passkey intended contracts now cover NEAR, Tempo, and Arc/EVM signing as lifecycle authority. Guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. |
| `tests/unit/intendedBehaviourContracts.guard.unit.test.ts` | deleted | Deleted 2,347-line Refactor 88 intended-behaviour Playwright source guard after moving lifecycle contract shape, retired mocked-surface, OIDC/startup, and runtime oracle checks into `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`; retained audit evidence is now owned by `tests/scripts/check-refactor88-test-ledger.mjs`, and Phase 3B mutation proof is now owned by `tests/scripts/check-intended-mutation-self-check.mjs`. Wired through `pnpm -C tests run check:intended-behaviour-contract-boundaries`, `pnpm -C tests run check:refactor88-test-ledger:complete`, `pnpm -C tests run check:intended-mutation-self-check:complete`, and `pnpm -C tests run test:source-guards`. |
| `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts` | deleted | Mounted the demo login menu with fake SDK hooks through production `__testOverrides` props. The test kept a broad fake-SDK injection path alive while checking wiring that is now either public UI behaviour or intended lifecycle coverage. The demo components no longer expose `__testOverrides`; guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. |
| `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts` | deleted | Built a large in-memory lane/session fixture graph for unlock -> warm signing behaviour. The lifecycle coverage now lives in the passkey and Email OTP intended contracts; retained boundary coverage exists in focused tests for pending Ed25519 login reads, `passkey_assertion` session exchange normalization, implicit NEAR identity handling, and warm-session policy. Guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. |
| `tests/unit/helpers/warmSessionStore.fixtures.ts` | deleted | Former broad fixture module fed large runtime-shape helpers into mocked warm-session tests and was a recurring refactor tax. Cleanup passes split generic ECDSA chain-target/bootstrap helpers, signing-session record store/reset/seed helpers, touch-confirm/status fixtures, and the remaining warm-session service builder into focused helpers. Guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. |
| `tests/unit/helpers/accountAuth.fixtures.ts` | keep | Account-auth fixture helper with one surviving importer. Retain while `tests/unit/accountAuth.fixtures.unit.test.ts` owns the boundary fixture contract; delete if that importer disappears. |
| `tests/unit/helpers/availableSigningLanes.fixtures.ts` | keep | Available-signing-lane fixture helper used by duplicate-lane unit tests. It supports focused lane inventory coverage rather than a broad mocked lifecycle graph. |
| `tests/unit/helpers/cloudflareD1RouterApiAuthService.fixtures.ts` | keep | Shared D1 Router API service fixtures split out of the service-factory monolith for route-family tests. The helper has live importers in the retained D1 route-family suites. |
| `tests/unit/helpers/d1StagingScriptFixtures.ts` | keep | D1 staging script fixture helper shared by retained staging-script tests. It supports script/runbook coverage outside wallet lifecycle contracts. |
| `tests/unit/helpers/ecdsaBootstrap.fixtures.ts` | keep | Focused ECDSA bootstrap fixture helper extracted from the deleted warm-session mega-fixture. It is shared by retained ECDSA bootstrap, reconnect, and request-boundary tests. |
| `tests/unit/helpers/ecdsaChainTarget.fixtures.ts` | keep | Focused ECDSA chain-target helper used by retained ECDSA and warm-session boundary tests. |
| `tests/unit/helpers/signingEngineArchitectureGuard.ts` | deleted | Deleted 118-line helper after the final Refactor 89-owned signing-engine architecture Playwright importer moved to `tests/scripts/check-signing-engine-architecture-boundaries.mjs`. |
| `tests/unit/helpers/signingEngineEcdsaIdentityGuard.ts` | deleted | Deleted 255-line helper after the final Refactor 89-owned ECDSA identity Playwright importer moved to `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`. |
| `tests/unit/helpers/signingSessionRecord.fixtures.ts` | keep | Focused signing-session record fixture helper extracted from the deleted warm-session mega-fixture. It is shared by retained session-store/read-model/request-boundary tests. |
| `tests/unit/helpers/warmSessionTestServices.fixtures.ts` | keep | Focused warm-session service builder used by retained warm-session store tests. It avoids recreating the deleted broad runtime fixture graph. |
| `tests/unit/helpers/warmSessionUiConfirm.fixtures.ts` | keep | Focused UI-confirm/status helper used by retained warm-session store and reconnect tests. |
| `tests/unit/demoThresholdHooks.actions.unit.test.ts` | deleted | Deleted 1,301-line demo hook/component suite. It mounted demo UI and faked signing backends to check Tempo/Arc demo action wiring; the intended contracts own public signing behavior, and demo-only request construction is not a durable SDK contract. |
| `tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts` | keep | Compact iframe transport/config propagation coverage for `PM_SET_CONFIG`. It checks SDK configuration reaches the wallet service iframe without replaying registration, unlock, signing, or step-up as a mocked lifecycle. |
| `tests/unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts` | keep | Wallet-service protocol fixture validates event forwarding shape and signer-selection payloads across iframe boundaries. Keep until intended contracts assert the same public event stream through the static wallet-origin topology. |
| `tests/unit/seamsWeb.emailOtpIframe.unit.test.ts` | keep | Email OTP iframe protocol fixture checks app-origin secrecy and message-shape boundaries. It is boundary coverage for wallet-service transport, not replacement lifecycle coverage. |
| `tests/e2e/cancel_overlay_specs.test.ts` | keep | Browser-level overlay cancel coverage across iframe routes. The test validates host overlay collapse and cancel semantics that the four intended lifecycle specs do not assert directly. |
| `tests/e2e/dashboard.billing.console.apiWiring.test.ts` | keep | Dashboard billing API-wiring browser coverage. It validates console billing page integration with the mocked API boundary, outside registration, unlock, signing, step-up, or export lifecycle authority. |
| `tests/e2e/dashboard.consoleConfigPages.apiWiring.test.ts` | keep | Dashboard configuration API-wiring browser coverage. It owns console config page integration behaviour, outside the wallet lifecycle contract matrix. |
| `tests/e2e/dashboard.webhooks.apiWiring.test.ts` | keep | Dashboard webhook API-wiring browser coverage. It validates console webhook page integration behaviour, outside signing lifecycle coverage. |
| `tests/e2e/intended-behaviours/email-otp.registration.contract.test.ts` | keep | Intended contract spec. It proves Email OTP registration, first NEAR/Tempo/Arc signing, spend exhaustion, step-up, post-step-up signing, and key export through real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/email-otp.registration.benchmark.test.ts` | keep | Intended benchmark spec. It measures Email OTP registration through the same public intended harness and real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/email-otp.unlock.contract.test.ts` | keep | Intended contract spec. It proves Email OTP unlock, NEAR/Tempo/Arc signing, spend exhaustion, step-up, post-step-up signing, and key export through real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/email-otp.unlock.benchmark.test.ts` | keep | Intended benchmark spec. It measures Email OTP registration plus unlock through the same public intended harness and real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/harness.ts` | keep | Intended contract harness. It owns real-infrastructure browser setup, event capture, signature verification, and prompt-count assertions for the five public lifecycle specs. |
| `tests/e2e/intended-behaviours/mutation-self-check.manifest.json` | keep | Mutation proof manifest for the intended suite. It records known regression classes that must make the contract gate fail when reintroduced on scratch branches. |
| `tests/e2e/intended-behaviours/passkey.registration.contract.test.ts` | keep | Intended contract spec. It proves passkey registration, first NEAR/Tempo/Arc signing, spend exhaustion, step-up, post-step-up signing, and key export through real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/passkey.registration.benchmark.test.ts` | keep | Intended benchmark spec. It measures passkey registration through the same public intended harness and real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts` | keep | Intended contract spec. It proves passkey unlock, NEAR/Tempo/Arc signing, spend exhaustion, step-up, post-step-up signing, and key export through real browser/runtime surfaces. |
| `tests/e2e/intended-behaviours/recovery.email.contract.test.ts` | keep | Intended contract spec. It proves email recovery restores NEAR, Tempo, and Arc/EVM signing through public browser/runtime surfaces. This spec now owns the recovery lifecycle coverage that unblocks the older recovery cleanup rows. |
| `tests/e2e/pricing.checkout.apiWiring.test.ts` | keep | Pricing checkout API-wiring browser coverage. It validates console checkout integration behaviour, outside wallet lifecycle authority. |
| `tests/e2e/theme.colorThemer.validation.test.ts` | keep | Theme validation browser coverage. It verifies dashboard color theme validation and persistence UI behaviour, outside registration/signing lifecycle coverage. |
| `tests/e2e/wallet-service-headers.test.ts` | keep | Wallet-service header smoke coverage. It validates wallet-origin response headers and remains useful alongside the static-origin and iframe lifecycle checks. |
| `tests/lit-components/coep.strict.all-elements.test.ts` | keep | Strict COEP browser coverage for public Lit bundles. It verifies SDK component chunks and the export-viewer iframe host upgrade under `crossOriginIsolated` without COEP/CORP console or page errors. |
| `tests/lit-components/confirm-ui.handle.test.ts` | keep | Confirm UI handle and transaction-tree rendering coverage. It verifies `mountConfirmUI`, model-only renders, lazy ABI enrichment, and handle close/update DOM behaviour; lifecycle signing authority stays with intended contracts. |
| `tests/lit-components/confirm-ui.host-and-inline.test.ts` | keep | Modal/drawer confirmer interaction coverage. It validates confirm, cancel, loading-state, backdrop, inline, and transaction-input rendering behaviour for the UI surface. |
| `tests/lit-components/drawer.events.test.ts` | keep | Drawer component event contract coverage. It verifies open/close lifecycle events emitted by the Lit drawer wrapper. |
| `tests/lit-components/harness.ts` | keep | Lit component browser harness. It supports the retained focused component tests without preserving mocked wallet lifecycle fixtures. |
| `tests/lit-components/passkey-registration-btn.test.ts` | keep | Passkey registration button component coverage. It verifies activation events, hover/focus/pressed/busy/disabled state, iframe viewport fill, keyboard activation, and WebAuthn RP ID / username display invariants. |
| `tests/unit/confirmTxFlow.common.helpers.test.ts` | keep | Confirmation channel helper coverage. It verifies postMessage sanitization and transaction-summary parsing as compact helper behavior. |
| `tests/unit/confirmTxFlow.confirmSession.onMounted.unit.test.ts` | keep | Confirm-session handle lifecycle coverage. It verifies `onMounted` exposes the confirm handle early enough for `updateUI` before the user decision resolves. |
| `tests/unit/confirmTxFlow.defensivePaths.test.ts` | keep | Confirmation defensive-path coverage. It verifies cancel behavior, nonce release rules, PRF error surfacing, and viewer/modal behavior for focused failure branches. |
| `tests/unit/confirmTxFlow.determineConfirmationConfig.test.ts` | keep | Confirmation-config normalization coverage. It checks request overrides, silent PRF flows, export UI display mode, and warm-session confirmation policy. |
| `tests/unit/confirmTxFlow.nearAdapter.concurrency.test.ts` | keep | NEAR confirmation adapter concurrency coverage. It verifies concurrent nonce reservations return isolated transaction contexts. |
| `tests/unit/confirmTxFlow.successPaths.test.ts` | keep | Confirmation success-path coverage. It verifies local-only PRF decrypt, registration credential collection, signing nonce reservation, delegate-action warm-session handling, and NEP-413 confirmation behavior. |
| `tests/unit/accountKeyMaterial.generic.unit.test.ts` | keep | Generic account key-material repository coverage. It verifies mapped account references, non-NEAR row persistence, and conflict rejection for explicit key targets. |
| `tests/unit/awaitSecureConfirmationV2.test.ts` | keep | Worker confirmation bridge coverage. It verifies timeout/abort handling, request-id/channel-token isolation, nonce lease preservation, and Email OTP payload forwarding. |
| `tests/unit/chainFamily.naming.unit.test.ts` | keep | Chain-family normalization coverage. It verifies canonical chain-family predicates and active-network config semantics. |
| `tests/unit/confirmationReadinessRegistry.unit.test.ts` | keep | Confirmation readiness registry coverage. It verifies one-shot consumption, explicit clearing, TTL cleanup, and concurrent request isolation. |
| `tests/unit/credentialsHelpers.redaction.test.ts` | keep | Credential-extension redaction coverage. It verifies WebAuthn extension outputs are stripped before crossing display/logging boundaries. |
| `tests/unit/d1EvmFamilyEcdsaRegistrationBranch.unit.test.ts` | keep | D1 EVM-family registration branch coverage. It verifies one signing grant can provision all EVM-family chain targets in a single registration. |
| `tests/unit/d1WalletRegistrationEcdsaKeyHandleSet.unit.test.ts` | keep | D1 wallet-registration ECDSA key-handle coverage. It permits repeated EVM-family handles across chain targets and rejects genuinely different handles. |
| `tests/unit/demoPasskeyEcdsaSignerOptions.unit.test.ts` | deleted | Deleted 35-line demo-only passkey ECDSA option test. The helper only feeds demo defaults, while intended contracts and retained registration/bootstrap tests own real Tempo and EVM ECDSA provisioning behavior. |
| `tests/unit/emailOtpDeviceEnrollmentEscrowStore.unit.test.ts` | keep | Email OTP device-enrollment escrow storage coverage. It verifies IndexedDB record shape, malformed-record fail-closed behavior, scope deletion, and disabled-DB protection without replaying lifecycle flows. |
| `tests/unit/emailOtpRecoveryCodeBackups.unit.test.ts` | keep | Email OTP recovery-code backup repository coverage. It verifies retained-code metadata updates, raw-code rejection, seal isolation, and plaintext deletion. |
| `tests/unit/evmClient.waitForReceipt.unit.test.ts` | keep | EVM receipt-waiting helper coverage. It verifies dropped/replaced/underpriced detection and confirmation-depth handling through stubbed RPC responses. |
| `tests/unit/evmNonceBackend.unit.test.ts` | keep | EVM nonce backend boundary coverage. It verifies pending nonce reads, duplicate-chain routing, and fail-closed managed nonce snapshots. |
| `tests/unit/evmNonceLifecycleMetrics.unit.test.ts` | keep | EVM nonce lifecycle metric coverage. It verifies lane-tagged broadcast and blocked-lane events. |
| `tests/unit/handleSecureConfirmRequest.test.ts` | keep | Secure-confirm worker request validation coverage. It verifies unsupported, missing, and secret-bearing signing requests return structured errors. |
| `tests/unit/indexedDBConsolidation.unit.test.ts` | keep | IndexedDB schema/repository consolidation coverage. It verifies canonical store names, schema manifest parity, signer/key-material invariants, duplicate auth-method rules, and atomic finalize behavior. |
| `tests/unit/localSignerReconciliation.unit.test.ts` | keep | Local signer reconciliation coverage. It verifies missing threshold material, orphaned material, and stale pending signer diagnostics. |
| `tests/unit/nearClient.sendTransaction.retryInvalidNonce.unit.test.ts` | keep | NEAR transaction retry coverage. It verifies transient HTTP retry behavior and InvalidNonce surfacing in the helper client. |
| `tests/unit/nearThresholdKeyMaterial.persistence.unit.test.ts` | keep | NEAR threshold key-material persistence coverage. It verifies canonical single-key writes and participant synthesis for incomplete persisted payloads. |
| `tests/unit/overlayController.test.ts` | keep | Overlay controller DOM-state coverage. It verifies fullscreen visibility, anchored positioning, sticky locks, and inert iframe release. |
| `tests/unit/seamsAuthMenu.accountAvailability.unit.test.ts` | keep | Seams auth menu account-availability coverage. It verifies local saved credentials do not imply chain registration and badge state stays neutral until server existence is known. |
| `tests/unit/seamsAuthMenu.fouc.unit.test.ts` | keep | Seams auth menu UI/state coverage. It verifies style bootstrap, auth-method labels, Email OTP handoff prompts, resend UI, recovery options, and dropdown rendering. |
| `tests/unit/passkeyClientDB.deviceSelection.test.ts` | keep | Wallet device-selection repository coverage. It verifies last-login scoping, signer-slot selection, duplicate registration rejection, idempotent retries, and Email OTP Ed25519 repair behavior. |
| `tests/unit/passkeyClientDB.repositories.unit.test.ts` | keep | Wallet repository coverage. It verifies nonce leases, signer activation/querying, split NEAR identity persistence, ECDSA signer invariants, and scoped last-profile state. |
| `tests/unit/passkeyConfirm.exportFlow.unit.test.ts` | keep | Passkey export worker failure coverage. It verifies cancellation, abort mapping, seed/public-key mismatch fail-closed behavior, and retired artifact rejection. Successful Ed25519 and ECDSA export belongs to the intended contracts. |
| `tests/unit/pluginRorOrigins.unit.test.ts` | keep | Plugin related-origin coverage. It verifies wallet-origin inclusion, invalid-origin rejection, and Vite well-known route output for wallet-origin static hosting. |
| `tests/unit/profileAccountProjection.generic.unit.test.ts` | keep | Generic profile/account projection coverage. It verifies mapped candidate resolution, canonical signer-slot selection, and last-selected profile state lookup. |
| `tests/unit/progressBus.overlayIntentResolver.test.ts` | keep | Progress bus overlay-intent coverage. It verifies interaction metadata maps to show/hide/none and records v2 flow/phase/status stats. |
| `tests/unit/recoveryCodesModal.behavior.unit.test.ts` | keep | Recovery-code modal boundary coverage. It verifies local backup display, iframe presenter delegation, secret isolation, public capability exclusion, account-menu copy, rotation entrypoints, and post-recovery prompts. |
| `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts` | keep | Router A/B Ed25519 wallet-session state coverage. It verifies warm-session read models, wallet/NEAR identity separation, restore/unseal authorization, and malformed persisted material rejection. |
| `tests/unit/safari-fallbacks.test.ts` | keep | Safari WebAuthn fallback coverage. It verifies native-to-bridge cancellation/timeout behavior and challenge cloning. |
| `tests/unit/sealedRefresh.parity.unit.test.ts` | keep | Sealed-refresh startup parity coverage. It verifies relayer capability parity, transient failure behavior, field-level mismatch diagnostics, and app-origin wallet iframe mode. |
| `tests/unit/sealedSessionStore.unit.test.ts` | keep | Sealed session store coverage. It verifies plaintext/JWT secrecy, ECDSA target fail-closed behavior, auth-method/curve filtering, worker-material metadata requirements, and malformed record rejection. |
| `tests/unit/sharedErrors.webauthnRpId.unit.test.ts` | keep | Shared WebAuthn RP ID error coverage. It verifies origin/RP ID configuration failures classify as configuration errors rather than user cancellations. |
| `tests/unit/signingGrantAdmission.unit.test.ts` | keep | Signing-grant admission coverage. It verifies Router A/B admission payload parsing, queue identity construction, and concurrent fresh-admission retry coalescing. |
| `tests/unit/signerMutationSagas.pendingBehavior.unit.test.ts` | keep | Signer mutation saga coverage. It verifies pending add/revoke behavior, key-material validation, local activation timing, and local key-material deletion. |
| `tests/unit/tempo.feeTokenHelper.unit.test.ts` | keep | Tempo fee-token helper coverage. It verifies calldata construction for fee-manager token changes. |
| `tests/unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts` | keep | Threshold ECDSA warm-session auth-material coverage. It verifies JWT resolution requires explicit canonical ECDSA ownership. |
| `tests/unit/thresholdEd25519.hssWasmSurface.unit.test.ts` | keep | Threshold Ed25519 HSS WASM-surface coverage. It verifies durable advanced finalize rejects mismatched artifacts and corrupt state bytes. |
| `tests/unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts` | keep | Threshold Ed25519 wallet-session rehydrate coverage. It verifies canonical Ed25519 session records stay out of `sessionStorage` in wallet-host mode. |
| `tests/unit/useAccountInput.clearPrefill.unit.test.ts` | keep | Account input UI-state coverage. It verifies account refresh does not repopulate a field after explicit user clear. |
| `tests/unit/userPreferences.indexeddb-disabled.test.ts` | keep | User-preference disabled-IndexedDB coverage. It verifies wallet-iframe app-origin mode avoids SDK persistence and handles `setCurrentWallet` without unhandled rejection. |
| `tests/unit/userPreferences.walletIdentity.unit.test.ts` | keep | User-preference wallet-identity coverage. It verifies current-wallet preferences load from wallet-bound metadata for the last NEAR profile. |
| `tests/unit/walletFlowEvent.signing.unit.test.ts` | keep | Wallet flow event mapping coverage. It verifies phase-to-step/message mapping and terminal overlay metadata for signing, account sync, and key export flows. |
| `tests/unit/walletSessionProfileIdentity.unit.test.ts` | keep | Wallet-session profile identity restore coverage. It verifies wallet-id based profile restore and signing-session identity projection without replaying a mocked lifecycle flow. |
| `tests/unit/walletIframe.assetsBaseUrlNormalization.unit.test.ts` | keep | Wallet iframe asset-base normalization coverage. It verifies empty SDK base paths normalize to `/sdk/`. |
| `tests/unit/walletIframeAuthHandlers.unit.test.ts` | keep | Wallet iframe auth-handler coverage. It verifies wallet-session reads resolve from host current-wallet state and pass through unscoped reads when the host wallet is cold. |
| `tests/wallet-iframe/csp.strict.violation-free.test.ts` | keep | Wallet-service CSP regression coverage. It verifies the default wallet-service test route no longer emits the retired strict CSP header, outside the lifecycle contract matrix. |
| `tests/wallet-iframe/export.flow.integration.test.ts` | keep | Wallet-origin export overlay isolation coverage. It uses a stub wallet service to prove stale generic close events and concurrent export/signing request IDs do not cross-talk. The intended contracts prove public export authorization and success; this file owns iframe overlay protocol behaviour. |
| `tests/wallet-iframe/handshake.test.ts` | keep | Wallet iframe CONNECT/READY handshake coverage. It verifies the iframe source, WebAuthn allow attribute, sandbox absence, hidden pointer-inert default state, and READY timeout handling. |
| `tests/wallet-iframe/harness.ts` | keep | Shared wallet-iframe browser harness with surviving importers across retained iframe protocol tests. Delete only if those protocol tests disappear. |
| `tests/wallet-iframe/router.behavior.test.ts` | keep | Wallet iframe router timeout, progress-frame, unlock-status, strict option payload, and session-loss error normalization coverage. The intended contracts exercise real signing/unlock success; this test owns transport failure semantics and protocol payload boundaries. |
| `tests/wallet-iframe/router.behavior.concurrent.test.ts` | keep | Concurrent wallet-iframe request aggregation coverage. It proves overlay visibility remains correct while overlapping requests send independent progress and result frames. |
| `tests/wallet-iframe/router.behavior.sticky.test.ts` | keep | Sticky overlay lifecycle coverage. It verifies sticky export/activation overlays stay visible until explicit cancel and that sticky demand does not pin later Tempo signing overlay visibility. |
| `tests/wallet-iframe/router.cancellationProgress.test.ts` | keep | Wallet iframe cancellation progress coverage. It checks terminal v2 cancelled events are forwarded for core request flows, which the intended contracts do not exercise because they assert successful lifecycle paths. |
| `tests/wallet-iframe/router.computeOverlayIntent.test.ts` | keep | Pure router overlay-intent coverage for activation-required preflight fullscreen behaviour. This is protocol decision coverage, not lifecycle success coverage. |
| `tests/wallet-iframe/router.registrationActivation.test.ts` | keep | Registration activation iframe protocol coverage. It rejects forged, malformed, and early activation button-state messages and verifies anchored hit-target release when iframe registration starts. |
| `tests/wallet-iframe/router.signingProgressForwarding.test.ts` | keep | Signing progress forwarding coverage. It verifies v2 EVM threshold signing progress is forwarded to app `onEvent`; intended contracts consume structured events but do not isolate this iframe forwarding boundary. |
| `tests/wallet-iframe/static-wallet-assets.browser.test.ts` | keep | Static wallet-origin asset browser coverage. It serves `dist/public`, loads the generated wallet-service page, constructs wallet worker modules, and fetches/compiles worker WASM companions outside the lifecycle contract matrix. |
| `tests/wallet-iframe/preferences.sync.test.ts` | keep | Wallet-host preference synchronization coverage. It verifies confirmation config and theme updates propagate between app origin and wallet iframe, outside the lifecycle contract matrix. |
| `tests/wallet-iframe/seamsAuthMenu.qrButton.overlay.test.ts` | keep | QR-button overlay regression coverage. It ensures disabled Device2 linking does not surface the wallet iframe overlay, a UI boundary outside intended lifecycle success. |
| `tests/unit/seamsWeb.namespacedSigningSurface.unit.test.ts` | keep | Public API shape guard. It verifies signing methods live under `near`, `tempo`, and `evm` namespaces and do not leak back onto the flat `SeamsWeb` root object. |
| `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts` | keep | Wallet iframe handle-boundary coverage for Google Email OTP. It serializes login and registration flow handles, rejects wrong-wallet and wrong-mode handle use, burns successful handles, and strips recovery material from iframe results. The intended contracts prove Email OTP lifecycle success; this test owns iframe protocol safety. |
| `tests/unit/seamsWeb.chainSigners.integration.test.ts` | keep | Public signer capability module coverage. It checks `afterCall`/`onError` semantics, local versus iframe signer routing, wallet-session ECDSA key-fact projection, Tempo broadcast/finalization reporting, nonce reconciliation, and abort/timeout canonicalization. The intended contracts verify user lifecycle success; this file owns module-level signing API semantics. |
| `tests/unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts` | keep | Wallet iframe duplicate-mount guardrail. It verifies repeated `SeamsWeb` instance construction does not accumulate multiple wallet overlay iframes, a host DOM invariant outside lifecycle success coverage. |
| `tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts` | keep | Email OTP recovery-code backup persistence and download-helper coverage. It verifies recovery-code backup storage, secret stripping, and download file generation without replaying Email OTP registration/unlock lifecycle. |
| `tests/unit/seamsWeb.initWalletIframe.concurrent.unit.test.ts` | keep | Concurrent `initWalletIframe` mount guardrail. It proves overlapping initialization calls converge to one wallet iframe and one router connection, outside the intended contract matrix. |
| `tests/unit/secureConfirm.warmSigning.test.ts` | keep | Focused UI-confirm worker handler coverage for warm signing. It verifies TouchID is skipped and transaction context is returned for a warm-session auth plan, without pretending to validate end-to-end signing authority. |
| `tests/unit/seamsWeb.setTheme.unit.test.ts` | keep | Public theme setter coverage. It verifies synchronous `setTheme` updates and `appearance.theme` initialization for `SeamsWeb`; this is public surface state, not signing lifecycle authority. |
| `tests/unit/touchConfirm.workerRouter.integration.test.ts` | keep | Worker-router request/response multiplexing and persistence snapshot coverage. This is compact transport/state-read coverage and remains valuable alongside the intended contracts. |
| `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts` | keep | Registration warm-session boundary coverage for identity binding and hydration ordering. The intended specs cover public lifecycle success; this test still catches narrow persistence/binding failures before a full browser flow. |
| `tests/relayer/bootstrap-grants.test.ts` | deleted | Deleted 661-line fake AuthService bootstrap-grant route suite after Refactor 82 Phase 11/12 D1 route-family coverage landed. |
| `tests/relayer/cloudflare-cron.test.ts` | keep | Cloudflare cron boundary coverage. It validates scheduled worker behaviour and does not replay registration, unlock, signing, step-up, or export through mocked lifecycle fixtures. |
| `tests/relayer/cloudflare-router.test.ts` | deleted | Deleted 4,339-line fake AuthService Cloudflare router suite after Refactor 82 Phase 11/12 D1 route-family coverage landed; surviving budget/grant-use assertions are owned by Refactor 90 vocabulary work. |
| `tests/relayer/console-account-router.test.ts` | keep | Console account router boundary coverage. It validates route authorization and account-management behaviour outside wallet lifecycle authority. |
| `tests/relayer/console-account.service.test.ts` | keep | Console account service coverage. It checks compact service-domain behaviour without using mocked wallet lifecycle fixtures. |
| `tests/relayer/console-api-key-kinds.test.ts` | deleted | Deleted 414-line mixed console/router fake AuthService API-key-kind suite after retained console API-key coverage stayed in focused console tests and Router API coverage moved to the D1 route-family harness. |
| `tests/relayer/console-app-session-auth.test.ts` | keep | Console app-session auth coverage. It validates console session authorization and cookie/token handling outside the signing lifecycle matrix. |
| `tests/relayer/console-billing-prepaid-reservations.test.ts` | keep | Console prepaid-reservation coverage. It verifies billing reservation rules as service/domain behaviour, not mocked wallet runtime state. |
| `tests/relayer/console-billing.service.test.ts` | keep | Console billing service coverage. It validates billing ledger and debit behaviour through focused service tests. |
| `tests/relayer/console-d1-adapters.test.ts` | blocked_on_coverage(90 A4/B5 console scopes and RBAC) | Large D1 adapter suite overlaps the future console route-family collapse. Keep until 90 reworks scopes/RBAC, then fold surviving cases into one table-driven suite per console area. |
| `tests/relayer/console-gas-sponsorship.seeding.test.ts` | keep | Console gas-sponsorship seeding coverage. It validates seed data behaviour for sponsorship config outside wallet lifecycle flows. |
| `tests/relayer/console-observability.ingestion.test.ts` | keep | Console observability ingestion coverage. It checks telemetry ingestion boundaries without mocked runtime lifecycle fixtures. |
| `tests/relayer/console-org-project-env.default-organization.test.ts` | keep | Default organization coverage for console org/project/environment service behaviour. |
| `tests/relayer/console-org-project-env.service.test.ts` | keep | Console org/project/environment service coverage. It verifies project and environment domain rules outside lifecycle E2E authority. |
| `tests/relayer/console-policy-rules.test.ts` | keep | Console policy-rule coverage. It validates policy service and route behaviour that the intended wallet lifecycle specs do not own. |
| `tests/relayer/console-router.test.ts` | blocked_on_coverage(90 A4/B5 console scopes and RBAC) | Large console router suite is scheduled for collapse with the console scopes/RBAC rework. Surviving assertions move to table-driven route-family suites in the same change. |
| `tests/relayer/console-sponsored-calls.history.test.ts` | keep | Console sponsored-call history coverage. It validates history filtering/pagination behaviour outside wallet lifecycle authority. |
| `tests/relayer/console-sponsorship-spend-caps.test.ts` | keep | Console sponsorship spend-cap coverage. It verifies sponsorship limit behaviour as console service/route coverage. |
| `tests/relayer/console-webhooks.pagination.test.ts` | keep | Console webhook pagination coverage. It validates webhook list pagination and remains outside registration/signing lifecycle coverage. |
| `tests/relayer/corsOrigins.test.ts` | keep | CORS origin helper coverage. It validates boundary normalization and origin decisions directly. |
| `tests/relayer/email-otp.authservice.test.ts` | deleted | Deleted 2,026-line Email OTP AuthService suite after Refactor 82 Phase 11/12 route-family coverage and the Refactor 88 Email OTP intended contracts superseded the facade-era lifecycle coverage. |
| `tests/relayer/email-otp.route-helpers.test.ts` | keep | Email OTP route-helper coverage. It validates compact parser/response helper behaviour without carrying a mocked lifecycle fixture graph. |
| `tests/relayer/email-otp.shamir3pass.test.ts` | keep | Email OTP Shamir 3-pass AuthService coverage. It checks cryptographic/session policy boundaries directly and is not replaced by the intended success flows. |
| `tests/relayer/email-recovery.prepare.test.ts` | deleted | Deleted 337-line fake AuthService recovery-prepare route suite after the recovery intended spec covered recovery into signing and D1 route-family coverage owned route ingress. |
| `tests/relayer/express-router.test.ts` | deleted | Deleted 4,370-line fake AuthService Express Router API suite after Refactor 90 F3 moved the Express host onto the canonical fetch-backed Router API adapter and deleted the duplicated `router/express/routes/**` implementation files. |
| `tests/relayer/health-wellknown.test.ts` | deleted | Deleted 233-line fake AuthService health/well-known route suite after route readiness coverage moved to the D1 route-family harness and source guards retained active signing-session seal defaults. |
| `tests/relayer/helpers.ts` | keep | Removed the 540-line `makeFakeAuthService` branch with the Refactor 90 F3 Express route deletion. The remaining helper module keeps shared HTTP, Cloudflare, session, and recovery fixture helpers used by retained relayer tests. |
| `tests/relayer/login.challengeReplay.test.ts` | deleted | Deleted 92-line fake AuthService login challenge replay suite after intended unlock contracts and D1 route-family coverage superseded the mocked route fixture. |
| `tests/relayer/nearErrors.test.ts` | keep | NEAR error normalization coverage. It validates helper mapping for route responses and is not lifecycle fixture coverage. |
| `tests/relayer/oidc-exchange.authservice.test.ts` | keep | OIDC exchange AuthService coverage. It verifies token issuer/audience/nonce/session boundaries directly and supports the Google intended-test setup. |
| `tests/relayer/payment-state-machine.test.ts` | keep | Payment state-machine coverage. It validates compact domain transitions outside wallet lifecycle flows. |
| `tests/relayer/router-ab-keyset-routes.test.ts` | deleted | Deleted 142-line fake AuthService Router A/B keyset route suite after D1 route-family coverage owned keyset route ingress. |
| `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts` | deleted | Deleted 1,572-line fake AuthService Router A/B normal-signing boundary suite after intended signing contracts and focused Router A/B boundary/source guards owned the surviving assertions. |
| `tests/relayer/router-api-keys.test.ts` | deleted | Deleted 883-line fake AuthService Router API-key route suite after D1 route-family coverage owned publishable/secret key route boundaries. |
| `tests/relayer/runtime-snapshot-consumer.test.ts` | keep | Runtime snapshot consumer coverage. It validates snapshot ingestion/selection behaviour outside mocked lifecycle execution. |
| `tests/relayer/sessionService.test.ts` | keep | Session service coverage. It checks focused session storage/version behaviour directly. |
| `tests/relayer/signing-session-seal-router.test.ts` | deleted | Deleted 1,066-line fake AuthService signing-session seal route suite after D1 route-family coverage owned route-boundary checks and focused signing-session seal unit/source guards retained seal defaults and idempotency coverage. |
| `tests/relayer/signingBudgetStatus.fixtures.ts` | blocked_on_coverage(90 B3 grant-use migration) | Shared budget-status fixture only supports budget-era router tests. Delete with the budget-to-grant-use migration after any surviving concurrency cases are renamed around grant-use semantics. |
| `tests/relayer/sponsored-evm-call.test.ts` | keep | Sponsored EVM call route/service coverage. It validates billing debit, sponsorship, and D1 behaviour through focused route tests. |
| `tests/relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts` | keep | Threshold ECDSA role-local passkey bootstrap coverage. It verifies digest/key derivation and route boundary behaviour outside end-to-end signing lifecycle success. |
| `tests/relayer/threshold-ecdsa.durable-stores.test.ts` | keep | Threshold ECDSA durable-store coverage. It validates durable object storage, replay guards, and pool/session store behaviour directly. |
| `tests/relayer/threshold-ed25519.scheme-dispatch.test.ts` | deleted | Deleted 268-line fake AuthService Threshold Ed25519 scheme-dispatch route suite after D1 route-family coverage owned route ingress and focused Threshold Ed25519 source guards retained active-path boundaries. |
| `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` | deleted | Deleted 118-line account signer lifecycle Playwright source guard after moving signer lifecycle write-field and shared signer-domain constant checks into `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, wired through `pnpm -C tests run check:account-signer-lifecycle-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/authSecretTerminology.guard.unit.test.ts` | deleted | Durable auth-neutral docs terminology check moved out of Playwright into `tests/scripts/check-auth-secret-terminology.mjs`, wired through `test:source-guards`. |
| `tests/unit/crossPlatformBoundaries.guard.unit.test.ts` | deleted | Deleted 455-line cross-platform Playwright source guard after its platform API, secret-material, runtime-port, role-local persistence, signer-command schema, and export-material boundary checks moved into `tests/scripts/check-cross-platform-boundaries.mjs`, wired through `pnpm -C tests run check:cross-platform-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/d1LocalDevLauncher.script.unit.test.ts` | keep | D1 local dev launcher script coverage. It verifies the local D1 Wrangler command omits missing env-file args and loads SDK plus console `.dev.vars` files in override order, outside wallet lifecycle behavior. |
| `tests/unit/d1StagingEvidenceVerify.script.unit.test.ts` | keep | D1 staging evidence verification script coverage. It validates deployment/runbook tooling outside wallet lifecycle contracts. |
| `tests/unit/d1StagingFixtureImport.script.unit.test.ts` | keep | D1 staging fixture-import script coverage. It validates staging data import tooling outside mocked runtime lifecycle fixtures. |
| `tests/unit/d1StagingKekCheck.script.unit.test.ts` | keep | D1 staging KEK check script coverage. It protects deployment secret-readiness tooling outside lifecycle success specs. |
| `tests/unit/d1StagingMigrate.script.unit.test.ts` | keep | D1 staging migration script coverage. It validates migration runner behavior for staging D1 state. |
| `tests/unit/d1StagingR2RestoreDrill.script.unit.test.ts` | keep | D1 staging R2 restore drill script coverage. It validates backup/restore runbook tooling. |
| `tests/unit/d1StagingReadiness.script.unit.test.ts` | keep | D1 staging readiness script coverage. It checks staging preflight tooling outside SDK lifecycle behavior. |
| `tests/unit/d1StagingReconciliation.script.unit.test.ts` | keep | D1 staging reconciliation script coverage. It validates reconciliation tooling for deployment state. |
| `tests/unit/d1RegistrationCeremonyRecords.ecdsaWalletKeys.unit.test.ts` | keep | D1 registration ceremony record coverage. It verifies target-specific Tempo and Arc/EVM ECDSA wallet-key facts are preserved and duplicate target material is rejected before persistence. |
| `tests/unit/d1StagingResourceInventory.script.unit.test.ts` | keep | D1 staging resource-inventory script coverage. It validates deployment inventory generation. |
| `tests/unit/d1StagingRunbook.script.unit.test.ts` | keep | D1 staging runbook script coverage. It validates generated operator steps rather than wallet lifecycle behavior. |
| `tests/unit/d1StagingSession.unit.test.ts` | keep | D1 staging session helper coverage. It verifies staging session parsing/state for deployment tooling. |
| `tests/unit/d1StagingSignerCustody.script.unit.test.ts` | keep | D1 staging signer-custody script coverage. It protects custody/runbook checks outside the intended browser flows. |
| `tests/unit/d1StagingSmoke.script.unit.test.ts` | keep | D1 staging smoke script coverage. It validates smoke-test orchestration for staging resources. |
| `tests/unit/d1StagingTimeTravelBookmark.script.unit.test.ts` | keep | D1 staging time-travel bookmark script coverage. It validates staging recovery bookmark tooling. |
| `tests/unit/emailOtpEcdsaBranchIsolation.guard.unit.test.ts` | deleted | Deleted 98-line Email OTP ECDSA branch-isolation Playwright source guard after moving central domain-brand ownership, passkey PRF persistence, wallet-subject vocabulary, and temporary diagnostic cleanup checks into `tests/scripts/check-email-otp-ecdsa-branch-isolation.mjs`, wired through `pnpm -C tests run check:email-otp-ecdsa-branch-isolation` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` | deleted | Deleted 790-line Email OTP operation split Playwright source guard after moving transaction/export challenge separation, coordinator facade, exact-lane reauth, committed-lane export/sign/step-up, seal-transport, and diagnostics source checks into `tests/scripts/check-email-otp-operation-split.mjs`, wired through `pnpm -C tests run check:email-otp-operation-split` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/emailOtpRecoveryCodeLeakage.guard.unit.test.ts` | deleted | Deleted 186-line recovery-code leakage Playwright source guard after moving generated-key containment, plaintext-backup confinement, iframe exposure, logging/telemetry, storage, brand-cast, and backup-repository checks into `tests/scripts/check-email-otp-recovery-code-leakage.mjs`, wired through `pnpm -C tests run check:email-otp-recovery-code-leakage` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/emailOtpSigningSession.deviceEscrow.behavior.guard.unit.test.ts` | deleted | Deleted 205-line device-escrow Playwright source guard after the fifth recovery intended spec covered email recovery into signing and the surviving device-local `enc_s(S)`, recovery-wrapped escrow, zeroization, and lock-path checks moved into `tests/scripts/check-email-otp-device-escrow-boundaries.mjs`, wired through `pnpm -C tests run check:email-otp-device-escrow-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/indexedDBConsolidation.guard.unit.test.ts` | deleted | Deleted 64-line IndexedDB consolidation Playwright source guard after browser-backed `tests/unit/indexedDBConsolidation.unit.test.ts` owned schema/repository behavior and the remaining raw IndexedDB/clientDB escape checks moved into `tests/scripts/check-indexeddb-consolidation-boundaries.mjs`, wired through `pnpm -C tests run check:indexeddb-consolidation-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/keyExport.behavior.guard.unit.test.ts` | deleted | Deleted 66-line key-export Playwright source guard after intended contracts owned public exact-lane export success and the remaining AccountMenuButton/export-modal source-boundary checks moved into `tests/scripts/check-key-export-boundaries.mjs`, wired through `pnpm -C tests run check:key-export-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/nonceCoordinator.durableArchitecture.guard.unit.test.ts` | keep | Durable nonce coordinator architecture guard retained by Refactor 89. It protects nonce-lane storage/import boundaries unless package-boundary and nonce-lane repository tests replace the same invariant. |
| `tests/unit/seamsAuthMenuPublicEntry.guard.unit.test.ts` | deleted | Deleted 37-line SeamsAuthMenu public-entrypoint source guard after pre-delete `rg` found no product/test use of `seamsAuthMenuCompat` outside the guard and `tests/unit/packageExports.contract.unit.test.ts` took ownership of the SSR-safe `./react/seams-auth-menu` public subpath plus compat-key rejection. `SeamsAuthMenu` shell CSS now stays behind the explicit `@seams/sdk/react/styles` entrypoint so the public subpath imports in Node SSR. Replacement coverage: package export contract plus `tests/unit/seamsAuthMenu.ssr.unit.test.ts`. |
| `tests/unit/passkeyRegistrationRollback.guard.unit.test.ts` | deleted | Deleted 61-line passkey-registration rollback Playwright source guard after preserving its rollback-state, signer-set registration, and deleted continuation-auth checks in `tests/scripts/check-passkey-registration-rollback-boundaries.mjs`, wired through `pnpm -C tests run check:passkey-registration-rollback-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/packageExports.contract.unit.test.ts` | keep | Package export contract coverage. It verifies public package surfaces and is durable API coverage, not a mocked lifecycle fixture. |
| `tests/unit/sdkPackageInstallSmoke.unit.test.ts` | keep | Package install smoke coverage. It verifies package consumability and remains outside the wallet lifecycle contract matrix. |
| `tests/unit/platformRuntimeBoundaries.guard.unit.test.ts` | deleted | Deleted 348-line platform-runtime Playwright source guard after its runtime, browser adapter, native facade, WalletIframe import, and chain-signer routing boundary checks moved into `tests/scripts/check-platform-runtime-boundaries.mjs`, wired through `pnpm -C tests run check:platform-runtime-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/rpIdContract.unit.test.ts` | keep | RP ID contract coverage. It validates WebAuthn origin/RP ID behavior directly. |
| `tests/unit/runtimeEntryBundles.unit.test.ts` | keep | Runtime entry bundle coverage. It verifies package/runtime entrypoint shape rather than mocked lifecycle behavior. |
| `tests/unit/legacySeamsWebFacadeNames.guard.unit.test.ts` | deleted | Legacy SeamsWeb facade-name check moved out of Playwright into `tests/scripts/check-legacy-seams-web-facade-names.mjs`, wired through `test:source-guards`. |
| `tests/unit/webauthnOriginPolicy.guard.unit.test.ts` | deleted | WebAuthn expected-origin check moved out of Playwright into `tests/scripts/check-webauthn-origin-policy.mjs`, wired through `test:source-guards`. |
| `tests/unit/seamsWebPublicSurfaceBoundaries.guard.unit.test.ts` | deleted | Deleted 553-line SeamsWeb public-surface Playwright source guard after moving namespace split, signing-surface dependency, root export, import-direction, iframe primitive, auth-method folder, and native-facade checks into `tests/scripts/check-seams-web-public-surface-boundaries.mjs`, wired through `pnpm -C tests run check:seams-web-public-surface-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` | deleted | Deleted 104-line headless Google Email OTP Playwright source guard after `googleEmailOtpWalletAuthFlow`, wallet-iframe handle, and SeamsAuthMenu headless tests covered runtime paths and the remaining demo/public API/source-boundary checks moved into `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`, wired through `pnpm -C tests run check:headless-google-email-otp-flow-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts` | deleted | Deleted 167-line Email OTP registration Playwright source guard after Email OTP registration flow, reroll, iframe-handle, route, and parser tests covered runtime paths and the remaining registration/reroll, backup-material, D1 activation-ordering, and parser source-boundary checks moved into `tests/scripts/check-email-otp-registration-boundaries.mjs`, wired through `pnpm -C tests run check:email-otp-registration-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/workspacePackageBoundaries.guard.unit.test.ts` | deleted | Deleted 108-line workspace package-boundary Playwright source guard after moving package-root, type-path, deployable-app import, and native import checks into `tests/scripts/check-workspace-package-boundaries.mjs`, wired through `pnpm -C tests run check:workspace-package-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/walletSessionVocabularyBoundaries.guard.unit.test.ts` | deleted | Deleted 366-line wallet-session vocabulary Playwright source guard after moving old signing-grant name bans, Router A/B Wallet Session JWT claim checks, docs terminology checks, signing auth-token naming checks, and `sessionId` classification allowlists into `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs`, wired through `pnpm -C tests run check:wallet-session-vocabulary-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | deleted | Deleted 269-line Refactor-numbered Playwright source guard after moving the type-filename/source-layout rule into `tests/scripts/check-type-filename-source.mjs`, wired through `pnpm -C tests run check:type-filename-source` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts` | deleted | Deleted 415-line exact lookup / no-fallback Playwright source guard after moving legacy fallback bans, display-only policy fallback checks, exact reconnect planning, duplicate-record/fail-closed lookup assertions, boundary parser fallback checks, typed restore outcomes, and PRF-cache exclusion checks into `tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs`, wired through `pnpm -C tests run check:exact-lookup-no-fallback-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` | deleted | Deleted 1,448-line Ed25519 HSS material-boundary Playwright source guard after moving prepared issuer command, worker-owned handle, raw material marker, restore persistence, recovery-code authorization, and active session-state source checks into `tests/scripts/check-ed25519-hss-material-boundaries.mjs`, wired through `pnpm -C tests run check:ed25519-hss-material-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/keyMaterialBrandingBoundaries.guard.unit.test.ts` | deleted | Deleted 620-line key-material branding Playwright source guard after moving grant-lifecycle, branded key-version parser, ECDSA lifecycle identity, second-tier material brand, WebAuthn RP ID vs NEAR signing-key ID, signing-session seal key, and EVM-family signing key slot checks into `tests/scripts/check-key-material-branding-boundaries.mjs`, wired through `pnpm -C tests run check:key-material-branding-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` | deleted | Deleted 990-line exact signing-lane authority Playwright source guard after moving exact identity, fallback selector, export transport, HSS context, Ed25519 mutation, ECDSA server-record, signer-slot, lane-key, grant-clearing, availability, unsafe-cast, and selected-wallet profile checks into `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`, wired through `pnpm -C tests run check:exact-signing-lane-authority-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/routeLifecycleDomainBoundaries.guard.unit.test.ts` | deleted | Deleted 588-line route/lifecycle Playwright source guard after moving unsafe-cast bans, normalized confirmation config, type-only imports, nonce lifecycle state, public result branch checks, request parser boundaries, absent link-device routes, auth provider mutation parsing, ECDSA key-identity inventory, legacy Ed25519 HSS branch bans, and threshold/session exchange route parser checks into `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`, wired through `pnpm -C tests run check:route-lifecycle-domain-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts` | deleted | Deleted 2,786-line D1 runtime Playwright source guard after moving the D1/DO runtime graph, staging/docs, structural Router API services, registration ceremony split, and HSS/authority boundary checks into `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`, wired through `pnpm -C tests run check:cloudflare-d1-runtime-boundaries` and `pnpm -C tests run test:source-guards`. Refactor 82/90 still own the product/runtime cleanup gates named on the retained relayer and budget rows. |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` | deleted | Deleted 485-line registration/capability subject Playwright source guard after moving role-local ECDSA handle ownership, wallet unlock subject, visible iframe passkey registration, prepared registration route, registration precompute, active-state/persistence-subject, Email OTP commit, and unlock activation-plan checks into `tests/scripts/check-registration-capability-subjects.mjs`, wired through `pnpm -C tests run check:registration-capability-subjects` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/passkeyRegistrationButtonBoundaries.guard.unit.test.ts` | deleted | Deleted 47-line passkey registration-button Playwright source guard after retained Lit component tests owned button behavior and its static import-independence check moved into `tests/scripts/check-passkey-registration-button-boundaries.mjs`, wired through `pnpm -C tests run check:passkey-registration-button-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` | deleted | Deleted 1,181-line Router A/B normal-signing SDK Playwright source guard after moving local topology, Wallet Session request-builder, active material/readiness, route-core, legacy-route, and budget/reconciliation source checks into `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`, wired through `pnpm -C tests run check:router-ab-normal-signing-sdk-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` | deleted | Deleted 139-line Router A/B wallet-session claim boundary Playwright source guard after moving legacy claim-kind bans, exact claim-builder checks, canonical ECDSA-HSS scope comparison checks, and internal-auth helper checks into `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signer-worker.guards.test.ts` | keep | Durable signer-worker protocol coverage. Refactor 89 classified the surviving invariants as worker secret-field rejection checks; the file stays under explicit browser/unit validation, not the source-guard profile. |
| `tests/unit/signerDomain.guard.unit.test.ts` | deleted | Deleted 46-line signer-domain source guard after folding its wallet/signer shared-constant checks into account signer lifecycle coverage. Those checks now live in `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, including the `packages/sdk-web/src/core/types/seams.ts` coverage that was unique to the deleted guard. |
| `tests/unit/signingEngineArchitecture.flows.guard.unit.test.ts` | deleted | Deleted 380-line signing-engine flow architecture Playwright source guard after moving the source-boundary checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-architecture-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineArchitecture.ownership.guard.unit.test.ts` | deleted | Deleted 297-line signing-engine ownership architecture Playwright source guard after moving the README, session-domain, coordinator, and sibling-import checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-architecture-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineArchitecture.state.guard.unit.test.ts` | deleted | Deleted 244-line signing-engine state architecture Playwright source guard after moving the selected-lane, lifecycle-state, execution-boundary, and duplicate-shape checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-architecture-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineArchitecture.threshold.guard.unit.test.ts` | deleted | Deleted 109-line signing-engine threshold architecture Playwright source guard after moving the threshold/session-boundary and warm-session cache checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-architecture-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.exportAndFixtures.guard.unit.test.ts` | deleted | Deleted 214-line ECDSA export/fixture identity Playwright source guard after moving the source-boundary checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-ecdsa-identity-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts` | deleted | Deleted 385-line ECDSA lifecycle identity Playwright source guard after moving lifecycle, parser, logging, activation, cast, and spread checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-ecdsa-identity-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts` | deleted | Deleted 449-line ECDSA public-surface identity Playwright source guard after moving public API, iframe payload, key-ref, role-local bootstrap, and WASM export checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `pnpm -C tests run check:signing-engine-ecdsa-identity-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/signingRootKekProvider.script.unit.test.ts` | keep | Signing-root KEK provider script coverage. It validates deployment secret tooling outside browser lifecycle contracts. |
| `tests/unit/signingRootRecords.script.unit.test.ts` | keep | Signing-root records script coverage. It validates signing-root persistence/runbook tooling. |
| `tests/unit/signingRootScope.script.unit.test.ts` | keep | Signing-root scope script coverage. It verifies signing-root scope parsing and deployment script behavior. |
| `tests/unit/signingRootSecretConfig.script.unit.test.ts` | keep | Signing-root secret config script coverage. It validates deployment secret configuration tooling. |
| `tests/unit/signingRootSecretSealing.script.unit.test.ts` | keep | Signing-root secret sealing script coverage. It verifies operator sealing tooling outside lifecycle specs. |
| `tests/unit/signingRootSecretShare.persistedRecords.unit.test.ts` | keep | Signing-root secret-share persisted-record coverage. It validates stored secret-share record behavior directly. |
| `tests/unit/signingRootSecretStore.script.unit.test.ts` | keep | Signing-root secret store script coverage. It validates secret storage tooling and boundary parsing. |
| `tests/unit/signingRootSecretWires.script.unit.test.ts` | keep | Signing-root secret wire script coverage. It validates generated wire payloads for signing-root secrets. |
| `tests/unit/signingRootShareResolver.script.unit.test.ts` | keep | Signing-root share resolver script coverage. It validates deployment-time share resolution. |
| `tests/unit/stableExperimentalExportBoundaries.guard.unit.test.ts` | deleted | Deleted 15-line stable/experimental package export boundary guard after moving the root-internal-export, experimental-directory, and experimental-subpath assertions into `tests/unit/packageExports.contract.unit.test.ts`. Replacement coverage: `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/packageExports.contract.unit.test.ts --reporter=line`. |
| `tests/unit/thresholdEcdsa.behavior.guard.unit.test.ts` | deleted | Deleted 151-line ECDSA HSS Playwright source guard after moving old-v1 deletion, role-local authorization, refill wiring, and no-export-material checks into `tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts` | deleted | Deleted 462-line threshold Ed25519 NEAR signing queue Playwright source guard after moving queue-wrapper, Email OTP Ed25519 warm-up wait, no ECDSA restore side-effect, material-aware step-up, wallet-session spend recording, passkey unlock restore, worker-material readiness, no raw client-base reads, shared budget consumption, export no-spend, and Router A/B normal-signing checks into `tests/scripts/check-threshold-ed25519-near-signing-queue.mjs`, wired through `pnpm -C tests run check:threshold-ed25519-near-signing-queue` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/thresholdEd25519PresignNonceLifecycle.guard.unit.test.ts` | deleted | Deleted 60-line Ed25519 presign nonce lifecycle Playwright source guard after moving the burn-order and CSPRNG handle assertions into `tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`, wired through `test:source-guards`. |
| `tests/unit/walletScopedLookups.guard.unit.test.ts` | deleted | Deleted 250-line wallet-scoped lookup Playwright source guard after moving the D1 wallet-id parser behavior assertion into `tests/unit/domainIds.boundary.unit.test.ts` and the remaining wallet-scoped lookup / NEAR projection source checks into `tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`, wired through `pnpm -C tests run check:wallet-scoped-lookup-boundaries` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/activateSigningSessionUseCase.unit.test.ts` | keep | Focused signing-session activation use-case coverage. It validates a compact domain transition outside browser lifecycle success paths. |
| `tests/unit/addWalletSigner.orchestration.unit.test.ts` | keep | Add-wallet-signer orchestration coverage. It verifies signer mutation sequencing and validation without replaying full registration/signing flows. |
| `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` | keep | AuthService hosted-account privacy coverage. It validates server-side privacy boundaries directly. |
| `tests/unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts` | keep | Available-signing-lanes ECDSA duplicate handling coverage. It verifies exact lane ambiguity behavior that backs the intended ECDSA contracts. |
| `tests/unit/availableSigningLanes.ed25519Duplicates.unit.test.ts` | keep | Available-signing-lanes Ed25519 duplicate handling coverage. It verifies exact lane ambiguity behavior for NEAR signing. |
| `tests/unit/browserPlatformRuntime.signerCrypto.unit.test.ts` | keep | Browser platform signer-crypto coverage. It validates runtime crypto dependency wiring outside mocked lifecycle tests. |
| `tests/unit/canonicalLaneInventory.unit.test.ts` | keep | Canonical lane inventory coverage. It verifies lane normalization and duplicate handling that the intended contracts rely on. |
| `tests/unit/cloudflareD1ConsoleServices.unit.test.ts` | keep | Cloudflare D1 console service coverage. It validates D1-backed console service behavior outside wallet lifecycle E2E coverage. |
| `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts` | deleted | Deleted 6,695-line D1 Router API service-factory monolith after splitting the retained assertions into route-family suites and the shared D1 fixture helper. The split retained registration-policy, OIDC, Email OTP/recovery, service-surface metadata, registration ceremony, wallet-auth-method, and add-signer coverage. |
| `tests/unit/cloudflareD1RouterApiEmailOtp.unit.test.ts` | keep | D1 Router API Email OTP and recovery route-family coverage split out of the service-factory monolith. It verifies server seals, Google Email OTP registration attempts, wallet registration, recovery-key rotation, recovery session tracking, OTP challenge delivery, provider failures, rate limits, and unlock-proof one-time use. |
| `tests/unit/cloudflareD1RouterApiOidc.unit.test.ts` | keep | D1 Router API OIDC route-family coverage split out of the service-factory monolith. It verifies Google OIDC login token validation, generic OIDC exchange validation, identity linking, and tampered-signature rejection. |
| `tests/unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts` | keep | D1 Router API registration ceremony route-family coverage split out of the service-factory monolith. It verifies Durable Object-backed registration intents, challenge/origin mismatch rejection, wallet mismatch rejection, Ed25519-only ceremonies, combined Ed25519/ECDSA ceremonies, ECDSA target preparation, response, and finalize behavior. |
| `tests/unit/cloudflareD1RouterApiRegistrationPolicy.unit.test.ts` | keep | D1 registration session-policy route-family coverage split out of the service-factory monolith. It verifies passkey authority binding and rejects root RP ID leakage in Ed25519 registration policy construction. |
| `tests/unit/cloudflareD1RouterApiServiceSurface.unit.test.ts` | keep | D1 Router API service-surface route-family coverage split out of the service-factory monolith. It verifies tenant-scoped signer metadata reads, wallet auth-method revocation through D1, and threshold-signing wiring from Durable Object config. |
| `tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts` | keep | D1 Router API wallet-auth-method route-family coverage split out of the service-factory monolith. It verifies adding Email OTP wallet auth methods through D1 and Durable Objects plus ECDSA add-signer ceremony start, respond, and finalize behavior. |
| `tests/unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts` | keep | Cloudflare self-hosted signing-worker script coverage. It validates deployment script behavior outside browser lifecycle contracts. |
| `tests/unit/configs.appearance.test.ts` | keep | Appearance config normalization coverage. It validates public config parsing and defaults. |
| `tests/unit/configs.emailOtpAuthPolicy.test.ts` | keep | Email OTP auth-policy config coverage. It validates config boundary rules for Email OTP. |
| `tests/unit/configs.iframeWalletDisable.test.ts` | keep | Iframe wallet disable config coverage. It validates public configuration behavior outside lifecycle success paths. |
| `tests/unit/configs.registrationTransport.test.ts` | keep | Registration transport config coverage. It validates configuration boundary behavior for registration transport. |
| `tests/unit/confirmationConfig.normalization.unit.test.ts` | keep | Confirmation config normalization coverage. It validates compact parser/default behavior. |
| `tests/unit/consoleApiKeys.secretFormat.unit.test.ts` | keep | Console API-key secret format coverage. It validates credential formatting and classification outside wallet lifecycle coverage. |
| `tests/unit/dashboard.inlineModal.viewportBackdrop.unit.test.ts` | keep | Dashboard inline-modal viewport/backdrop coverage. It is focused UI behavior outside the SDK lifecycle contract matrix. |
| `tests/unit/dashboard.organizationIdentity.unit.test.ts` | keep | Dashboard organization identity coverage. It validates console identity UI/state behavior outside wallet lifecycle contracts. |
| `tests/unit/dashboard.sessionDraftStore.test.ts` | keep | Dashboard session draft store coverage. It validates local dashboard state persistence. |
| `tests/unit/dashboard.useSessionDraft.lifecycle.unit.test.ts` | keep | Dashboard session draft hook lifecycle coverage. It owns focused UI state behavior outside SDK lifecycle contracts. |
| `tests/unit/deriveSecp256k1KeypairFromPrfSecond.unit.test.ts` | keep | Secp256k1 derivation coverage. It validates deterministic crypto helper behavior directly. |
| `tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts` | keep | Device recovery domain coverage for Email Recovery. It validates recovery domain rules directly; the deferred recovery intended spec will cover browser lifecycle success. |
| `tests/unit/domainIds.boundary.unit.test.ts` | keep | Domain ID boundary coverage. It validates branded/domain ID parsing at trust boundaries. |
| `tests/unit/ecdsaBootstrapWarmPersistence.unit.test.ts` | keep | ECDSA bootstrap warm-persistence coverage. It validates focused persistence behavior that supports warm-session correctness. |
| `tests/unit/ecdsaExportMaterial.unit.test.ts` | keep | ECDSA export material coverage. It validates export-material parsing and construction outside the browser export flow. |
| `tests/unit/ecdsaExportViewerPayload.unit.test.ts` | keep | ECDSA export-viewer payload coverage. It verifies payload shaping for the export viewer boundary. |
| `tests/unit/ecdsaLanes.identity.unit.test.ts` | keep | ECDSA lane identity coverage. It validates exact chain-target identity behavior directly. |
| `tests/unit/ecdsaMaterialState.unit.test.ts` | keep | ECDSA material-state coverage. It validates domain-state transitions for ECDSA material. |
| `tests/unit/ecdsaRoleLocalRecords.unit.test.ts` | keep | ECDSA role-local record coverage. It validates persistence record parsing and normalization. |
| `tests/unit/ecdsaSelection.restorable.unit.test.ts` | keep | Restorable ECDSA selection coverage. It verifies lane selection for restore/export surfaces. |
| `tests/unit/ed25519MaterialAuthPlan.unit.test.ts` | keep | Ed25519 material auth-plan coverage. It validates auth-plan selection for NEAR material. |
| `tests/unit/ed25519TransactionLaneSelection.unit.test.ts` | keep | Ed25519 transaction lane-selection coverage. It validates exact NEAR lane selection directly. |
| `tests/unit/emailEncryption.test.ts` | keep | Email encryption helper coverage. It validates crypto/interoperability primitives used by Email OTP and recovery. |
| `tests/unit/emailEncryptionOutlayerInteroperability.test.ts` | keep | Email encryption outlayer interoperability coverage. It validates protocol compatibility for encrypted email payloads. |
| `tests/unit/emailOtp.records.unit.test.ts` | keep | Email OTP record coverage. It validates persistence record shape and parsing. |
| `tests/unit/emailOtpAppSessionJwtCache.unit.test.ts` | keep | Email OTP app-session JWT cache coverage. It validates cache behavior at the auth/session boundary. |
| `tests/unit/emailOtpAuthLane.unit.test.ts` | keep | Email OTP auth-lane coverage. It validates lane selection and auth binding behavior directly. |
| `tests/unit/emailOtpClientSecretSource.unit.test.ts` | keep | Email OTP client-secret source coverage. It validates boundary rules for local/test secret sourcing. |
| `tests/unit/emailOtpDerivation.unit.test.ts` | keep | Email OTP derivation coverage. It validates deterministic key/identity derivation helpers. |
| `tests/unit/emailOtpEcdsaPublication.unit.test.ts` | keep | Email OTP ECDSA publication coverage. It validates ECDSA publication state and persistence boundaries. |
| `tests/unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts` | keep | Email OTP ECDSA signing-session auth coverage. It validates auth material binding for ECDSA signing sessions. |
| `tests/unit/emailOtpEmailHash.unit.test.ts` | keep | Email OTP email-hash coverage. It validates canonical email hashing used by Email OTP identity. |
| `tests/unit/emailOtpGrantAuthorityBinding.unit.test.ts` | keep | Email OTP grant-authority binding coverage. It validates grant authority construction and binding outside browser flows. |
| `tests/unit/emailOtpRecoveryKey.shared.unit.test.ts` | keep | Email OTP recovery-key shared coverage. It validates shared recovery-key helpers directly. |
| `tests/unit/emailOtpRecoveryWrappedEnrollmentEscrowStore.unit.test.ts` | keep | Email OTP wrapped enrollment escrow store coverage. It validates recovery escrow persistence and parsing. |
| `tests/unit/emailOtpRegistrationRoute.unit.test.ts` | keep | Email OTP registration route coverage. It validates route input/output behavior directly. |
| `tests/unit/emailOtpSigningSessionUnsealRoute.unit.test.ts` | keep | Email OTP signing-session unseal route coverage. It validates route boundary behavior that intended contracts consume. |
| `tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts` | keep | Email OTP wallet-session coordinator coverage. It validates focused session coordination behavior. |
| `tests/unit/emailRecoveryService.test.ts` | keep | Email recovery service coverage. It validates service-domain behavior; recovery browser lifecycle coverage is deferred to the fifth spec. |
| `tests/unit/emailRecoveryVerifiedRequest.source.script.ts` | deleted | Deleted 70-line source-evidence fixture with its last importer. Recovery request parsing and recovery lifecycle behavior stay covered by retained parser/domain tests plus the recovery intended contract. |
| `tests/unit/emailRecoveryVerifiedRequest.source.script.unit.test.ts` | deleted | Deleted 104-line source-evidence wrapper. It spawned a TSX fixture to prove source-level recovery request shape; retained recovery parser/domain tests and the recovery intended contract own current behavior. |
| `tests/unit/emailSubjectParsing.test.ts` | keep | Email subject parsing coverage. It validates parser behavior directly. |
| `tests/unit/emails/gmail_reset_full.eml` | keep | Email fixture used by retained email parsing tests. Delete only when its parser-test importer disappears. |
| `tests/unit/emails/gmail_reset_full2.eml` | keep | Email fixture used by retained email parsing tests. Delete only when its parser-test importer disappears. |
| `tests/unit/evmFamily.requestBoundary.unit.test.ts` | keep | EVM-family request-boundary coverage. It validates request parsing and chain-target identity directly. |
| `tests/unit/evmFamilyAccountAuth.unit.test.ts` | keep | EVM-family account-auth coverage. It validates account/auth binding behavior for EVM-family signing. |
| `tests/unit/evmFamilyBudgetSpending.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era EVM-family spending coverage. Rewrite around grant-use consumption when 90 B3 deletes the budget subsystem. |
| `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts` | keep | EVM-family ECDSA identity coverage. It validates chain-target identity and account binding directly. |
| `tests/unit/evmFamilyFreshAuthRetryPolicy.unit.test.ts` | keep | EVM-family fresh-auth retry policy coverage. It validates retry/step-up rules without relying on broad mocked lifecycle fixtures. |
| `tests/unit/evmFamilyNonceSenderIdentity.unit.test.ts` | keep | EVM-family nonce/sender identity coverage. It validates sender identity and nonce behavior directly. |
| `tests/unit/evmFamilyOperationIds.unit.test.ts` | keep | EVM-family operation ID coverage. It validates stable operation identity construction. |
| `tests/unit/evmFamilyPreparedSigningAuthSelection.unit.test.ts` | keep | EVM-family prepared-signing auth-selection coverage. It validates auth-plan selection directly. |
| `tests/unit/evmFamilyStepUpProvisionPlan.unit.test.ts` | keep | EVM-family step-up provision-plan coverage. It validates provision planning for step-up flows. |
| `tests/unit/evmSigning.thresholdReconnectEvents.unit.test.ts` | keep | EVM signing reconnect-event coverage. It validates focused reconnect event behavior outside full browser lifecycle success. |
| `tests/unit/exportKeysUseCase.unit.test.ts` | keep | Export-keys use-case coverage. It validates export authorization and domain behavior directly. |
| `tests/unit/exportLaneSelection.unit.test.ts` | keep | Export lane-selection coverage. It validates exact lane selection for key export. |
| `tests/unit/exportViewerHost.cleanup.unit.test.ts` | keep | Export viewer host cleanup coverage. It validates iframe/viewer cleanup behavior outside lifecycle success specs. |
| `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts` | keep | Google Email OTP wallet-auth flow coverage. It validates handle/session boundaries for the Google auth factor. |
| `tests/unit/googleIdentity.prompt.unit.test.ts` | keep | Google identity prompt coverage. It validates prompt/client behavior for Google identity. |
| `tests/unit/headers.unit.test.ts` | keep | Header helper coverage. It validates HTTP header normalization directly. |
| `tests/unit/hostedAccountIds.unit.test.ts` | keep | Hosted account ID coverage. It validates ID construction and parsing boundaries. |
| `tests/unit/keccak256.unit.test.ts` | keep | Keccak256 helper coverage. It validates crypto primitive behavior directly. |
| `tests/unit/linkDevice.flowEvents.unit.test.ts` | keep | Link-device flow-event coverage. It validates event mapping outside lifecycle success specs. |
| `tests/unit/modularity.lazySigners.unit.test.ts` | keep | Lazy signer modularity coverage. It validates module loading boundaries rather than mocked lifecycle state. |
| `tests/unit/multichain.tempoTxHash.unit.test.ts` | keep | Tempo transaction-hash coverage. It validates multichain helper behavior. |
| `tests/unit/multichain.webauthnP256Engine.unit.test.ts` | keep | WebAuthn P-256 engine coverage. It validates multichain crypto engine behavior directly. |
| `tests/unit/nearClient.test.ts` | keep | NEAR client helper coverage. It validates RPC helper behavior outside wallet lifecycle contracts. |
| `tests/unit/nearEd25519ExportFlow.unit.test.ts` | keep | NEAR Ed25519 export-flow coverage. It validates export-flow domain behavior directly. |
| `tests/unit/nearSigning.sessionSelection.unit.test.ts` | keep | NEAR signing session-selection coverage. It validates session selection for NEAR signing. |
| `tests/unit/nearSigningFlow.singleTransaction.unit.test.ts` | keep | NEAR single-transaction signing-flow coverage. It validates focused signing-flow behavior; intended specs own browser lifecycle success. |
| `tests/unit/nonceCoordinator.nearContext.test.ts` | keep | Nonce coordinator NEAR context coverage. It validates nonce context parsing and behavior. |
| `tests/unit/nonceCoordinator.unit.test.ts` | keep | Nonce coordinator coverage. It validates nonce reservation and release behavior directly. |
| `tests/unit/seamsAuthMenu.ssr.unit.test.ts` | keep | Seams auth menu SSR coverage. It validates server-render safety for the UI surface. |
| `tests/unit/passkeyEd25519Recovery.unit.test.ts` | keep | Passkey Ed25519 recovery coverage. It validates recovery domain behavior; recovery lifecycle success remains deferred to the fifth spec. |
| `tests/unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts` | keep | Persisted available-signing-lanes coverage for Email OTP Ed25519. It validates lane persistence and repair behavior. |
| `tests/unit/phase5UseCaseServices.unit.test.ts` | keep | Phase 5 use-case service coverage. It validates service wiring/domain behavior directly. |
| `tests/unit/platformAdapter.conformance.unit.test.ts` | keep | Platform adapter conformance coverage. It validates platform boundary behavior and remains durable. |
| `tests/unit/privateKeyExportRecovery.binding.unit.test.ts` | keep | Private-key export recovery binding coverage. It validates export/recovery binding behavior directly. |
| `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts` | keep | Private-key export recovery hardening coverage. It validates security hardening for export recovery. |
| `tests/unit/profileContinuity.source.script.ts` | deleted | Deleted 153-line source-evidence fixture with its last importer. Retained profile projection, wallet-session identity, and account/signer persistence tests own the durable behavior. |
| `tests/unit/profileContinuity.source.script.unit.test.ts` | deleted | Deleted 119-line source-evidence wrapper. It validated a synthetic profile-continuity script rather than a live boundary, so it was retired with its fixture. |
| `tests/unit/provisionEcdsaUseCase.unit.test.ts` | keep | Provision-ECDSA use-case coverage. It validates compact ECDSA provisioning domain behavior. |
| `tests/unit/rawThresholdEcdsaBootstrapRemoval.unit.test.ts` | keep | Raw threshold ECDSA bootstrap removal coverage. It guards the removal of raw bootstrap material from persisted/runtime surfaces. |
| `tests/unit/recoverEmailRequestParse.test.ts` | keep | Recover-email request parser coverage. It validates recovery request boundary parsing. |
| `tests/unit/recoveryDomain.source.script.ts` | deleted | Deleted 90-line source-evidence fixture with its last importer. Retained recovery domain, recovery request parser, and recovery intended coverage own the live behavior. |
| `tests/unit/recoveryDomain.source.script.unit.test.ts` | deleted | Deleted 77-line source-evidence wrapper. It spawned a synthetic script to prove recovery-domain shape, which is lower-value than the retained parser/domain and browser recovery coverage. |
| `tests/unit/recoveryExecutionStore.unit.test.ts` | keep | Recovery execution store coverage. It validates recovery execution persistence directly. |
| `tests/unit/recoveryExecutionTracking.unit.test.ts` | keep | Recovery execution tracking coverage. It validates recovery tracking domain behavior. |
| `tests/unit/recoverySessionStore.unit.test.ts` | keep | Recovery session store coverage. It validates recovery session persistence directly. |
| `tests/unit/recoveryStepUpAuthorization.unit.test.ts` | keep | Recovery step-up authorization coverage. It validates recovery authorization decisions outside the deferred recovery E2E spec. |
| `tests/unit/registrationCeremonyStore.unit.test.ts` | keep | Registration ceremony store coverage. It validates registration persistence and ceremony-state behavior directly. |
| `tests/unit/registrationFlowEvents.unit.test.ts` | keep | Registration flow-event coverage. It validates event mapping and lifecycle telemetry for registration. |
| `tests/unit/registrationIntentDigest.unit.test.ts` | keep | Registration intent digest coverage. It validates digest construction for registration requests. |
| `tests/unit/registrationSignerSetNormalization.unit.test.ts` | keep | Registration signer-set normalization coverage. It validates signer selection normalization at the request boundary. |
| `tests/unit/registrationWalletPersistence.unit.test.ts` | keep | Registration wallet persistence coverage. It validates wallet record writes and recovery of registration state. |
| `tests/unit/relayWalletRegistration.boundary.unit.test.ts` | keep | Relay wallet-registration boundary coverage. It validates request/response parsing for registration transport. |
| `tests/unit/relayWalletRegistration.intentModes.unit.test.ts` | keep | Relay wallet-registration intent-mode coverage. It validates registration intent mode selection and payload shape. |
| `tests/unit/requireEvmFamilyStepUpAuth.unit.test.ts` | keep | EVM-family step-up auth requirement coverage. It validates auth requirement decisions directly. |
| `tests/unit/requireNearStepUpAuth.unit.test.ts` | keep | NEAR step-up auth requirement coverage. It validates auth requirement decisions directly. |
| `tests/unit/router.consoleRouteSurface.unit.test.ts` | keep | Console route-surface coverage. It validates registered console routes and route metadata. |
| `tests/unit/router.routeDefinitions.unit.test.ts` | keep | Router route-definition coverage. It validates route constants and active route inventory. |
| `tests/unit/router.routerApiRouteSurface.unit.test.ts` | keep | Router API route-surface coverage. It validates registered Router API routes and route metadata. |
| `tests/unit/router.sponsoredEvmCallCloudflare.unit.test.ts` | keep | Sponsored EVM Cloudflare route coverage. It validates Cloudflare-specific sponsored-call route wiring. |
| `tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era ECDSA HSS route-core coverage. Rewrite or delete with the grant-use migration when the budget subsystem disappears. |
| `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts` | keep | Router A/B ECDSA HSS normal-signing coverage. It validates route-core behavior and protocol boundaries below the intended browser contracts. |
| `tests/unit/routerAbEcdsaHssPresignBridge.unit.test.ts` | keep | Router A/B ECDSA HSS presign bridge coverage. It validates presign bridge behavior directly. |
| `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era Ed25519 route-core coverage. Rewrite or delete with the grant-use migration. |
| `tests/unit/routerAbNormalSigningAdmissionStore.unit.test.ts` | keep | Router A/B normal-signing admission store coverage. It validates admission persistence and transition behavior. |
| `tests/unit/routerAbNormalSigningPolicy.unit.test.ts` | keep | Router A/B normal-signing policy coverage. It validates policy decisions below public signing flows. |
| `tests/unit/routerAbNormalSigningValidation.unit.test.ts` | keep | Router A/B normal-signing validation coverage. It validates parser and route request boundaries. |
| `tests/unit/routerAbNormalSigningVectors.unit.test.ts` | keep | Router A/B normal-signing vector coverage. It validates protocol vector compatibility. |
| `tests/unit/routerAbPublicKeyset.unit.test.ts` | keep | Router A/B public-keyset coverage. It validates public keyset parsing and serialization. |
| `tests/unit/routerAbPublicKeysetEnvBoundary.unit.test.ts` | keep | Router A/B public-keyset environment-boundary coverage. It validates environment scoping for keysets. |
| `tests/unit/routerAbWireVectors.unit.test.ts` | keep | Router A/B wire-vector coverage. It validates protocol wire compatibility. |
| `tests/unit/rpcCalls.sessionExchange.unit.test.ts` | keep | Session-exchange RPC call coverage. It validates client request shape and response parsing. |
| `tests/unit/runtimePostconditions.unit.test.ts` | keep | Runtime postcondition coverage. It validates focused postcondition checks for signing/session state. |
| `tests/unit/sealedRecovery.methodAdapters.unit.test.ts` | keep | Sealed recovery method-adapter coverage. It validates adapter behavior for recovery methods. |
| `tests/unit/sealedRecoveryRecord.strict.unit.test.ts` | keep | Strict sealed recovery record coverage. It validates record parsing and rejection behavior. |
| `tests/unit/seamsWeb.emailOtp.unit.test.ts` | keep | Public `SeamsWeb` Email OTP surface coverage. It validates public API wiring and state behavior around Email OTP. |
| `tests/unit/seamsWeb.unlockCancellationEvents.unit.test.ts` | keep | Public unlock cancellation event coverage. It validates event semantics for cancelled unlock flows. |
| `tests/unit/secureRandomId.shared.unit.test.ts` | keep | Shared secure-random ID coverage. It validates ID generation helpers directly. |
| `tests/unit/sessionTokens.unit.test.ts` | keep | Session token coverage. It validates token construction, parsing, and claim boundaries. |
| `tests/unit/sharedValidation.unit.test.ts` | keep | Shared validation coverage. It validates shared parser/helper behavior. |
| `tests/unit/signatureUses.unit.test.ts` | keep | Signature-use coverage. It validates signature-use classification and request binding. |
| `tests/unit/signerParity.rustPlatforms.unit.test.ts` | keep | Rust platform signer parity coverage. It validates cross-platform signing vector compatibility. |
| `tests/unit/signingBudgetPolicy.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget policy coverage. Replace with grant-use policy coverage when 90 B3 removes the budget subsystem. |
| `tests/unit/signingBudgetStatus.parser.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-status parser coverage. Delete or rewrite around grant-use status parsing when 90 B3 lands. |
| `tests/unit/signingCapabilityStrictRecords.unit.test.ts` | keep | Strict signing capability record coverage. It validates record parsing and rejection behavior. |
| `tests/unit/signingFlow.readySigner.unit.test.ts` | keep | Ready-signer signing-flow coverage. It validates focused readiness behavior below the intended contracts. |
| `tests/unit/signingOperationIdPayloadBinding.unit.test.ts` | keep | Signing operation ID payload-binding coverage. It validates stable operation identity and payload binding. |
| `tests/unit/signingPostSignPolicy.unit.test.ts` | keep | Signing post-sign policy coverage. It validates policy effects after signing completes. |
| `tests/unit/signingRuntime.construction.unit.test.ts` | keep | Signing runtime construction coverage. It validates runtime assembly behavior with narrow inputs. |
| `tests/unit/signingSession.state.unit.test.ts` | keep | Signing-session state coverage. It validates compact state transitions. |
| `tests/unit/signingSessionBudgetFinalizer.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era signing-session finalizer coverage. Replace with grant-use consumption/finalization coverage. |
| `tests/unit/signingSessionCoordinator.ecdsaStepUp.unit.test.ts` | keep | Signing-session coordinator ECDSA step-up coverage. It validates step-up coordination directly. |
| `tests/unit/signingSessionExpiryPersistence.unit.test.ts` | keep | Focused expiry-persistence regression coverage. It verifies an expired passkey Ed25519 seal retains its exact reauth anchor while policy expiry is updated. |
| `tests/unit/signingSessionFreshness.unit.test.ts` | keep | Signing-session freshness coverage. It validates freshness rules and expiry behavior. |
| `tests/unit/signingSessionReadiness.clearGrant.unit.test.ts` | keep | Signing-session readiness clear-grant coverage. It validates readiness cleanup behavior. |
| `tests/unit/signingSessionRestoreCoordinator.unit.test.ts` | keep | Signing-session restore coordinator coverage. It validates restore coordination below the deferred recovery E2E spec. |
| `tests/unit/signingSessionSeal.idempotencyRecords.unit.test.ts` | keep | Signing-session seal idempotency-record coverage. It validates record handling and replay protection. |
| `tests/unit/signingSessionSeal.sessionPolicy.unit.test.ts` | keep | Signing-session seal session-policy coverage. It validates policy binding for sealed sessions. |
| `tests/unit/signingSessionSeal.shared.unit.test.ts` | keep | Shared signing-session seal coverage. It validates token/record helpers used across client and server. |
| `tests/unit/signingSessionTypes.unit.test.ts` | keep | Signing-session type coverage. It validates discriminated state shape and type-level behavior. |
| `tests/unit/signingVectors.webWasmReplay.integration.test.ts` | keep | Web/WASM signing-vector replay coverage. It validates cryptographic parity across browser/WASM signing paths. |
| `tests/unit/sponsorship.evmRelayConfig.unit.test.ts` | keep | Sponsorship EVM relay config coverage. It validates sponsorship configuration parsing. |
| `tests/unit/sponsorship.realPricing.unit.test.ts` | keep | Sponsorship real-pricing coverage. It validates pricing integration behavior. |
| `tests/unit/sponsorship.staticPricing.unit.test.ts` | keep | Sponsorship static-pricing coverage. It validates deterministic pricing helper behavior. |
| `tests/unit/sponsorshipPricing.d1.unit.test.ts` | keep | Sponsorship pricing D1 coverage. It validates D1-backed pricing persistence and reads. |
| `tests/unit/stepUpAdaptor.methodSelection.unit.test.ts` | keep | Step-up adaptor method-selection coverage. It validates method selection for fresh authorization. |
| `tests/unit/stepUpAuthorization.builders.unit.test.ts` | keep | Step-up authorization builder coverage. It validates construction of valid authorization states. |
| `tests/unit/tempo.broadcastNonceLifecycle.unit.test.ts` | keep | Tempo broadcast nonce lifecycle coverage. It validates nonce lifecycle behavior around Tempo broadcasts. |
| `tests/unit/theme.react.unit.test.ts` | keep | React theme coverage. It validates theme provider/hook behavior outside lifecycle contracts. |
| `tests/unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts` | keep | Threshold ECDSA authorization bootstrap verifier coverage. It validates bootstrap proof verification directly. |
| `tests/unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts` | keep | Threshold ECDSA bootstrap persistence coverage. It validates persisted bootstrap records. |
| `tests/unit/thresholdEcdsa.commitQueue.unit.test.ts` | keep | Threshold ECDSA commit queue coverage. It validates queue behavior directly. |
| `tests/unit/thresholdEcdsa.doPoolFill.unit.test.ts` | keep | Threshold ECDSA durable-object pool-fill coverage. It validates DO-backed pool-fill behavior. |
| `tests/unit/thresholdEcdsa.emailOtpBootstrapCommit.unit.test.ts` | keep | Threshold ECDSA Email OTP bootstrap commit coverage. It validates commit behavior for Email OTP bootstrap sessions. |
| `tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts` | keep | Threshold ECDSA HSS bootstrap policy coverage. It validates policy decisions directly. |
| `tests/unit/thresholdEcdsa.hssErrorCodes.unit.test.ts` | keep | Threshold ECDSA HSS error-code coverage. It validates canonical error mapping. |
| `tests/unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts` | keep | Threshold ECDSA HSS role-local client parser coverage. It validates parser behavior for role-local payloads. |
| `tests/unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts` | keep | Threshold ECDSA HSS role-local export policy coverage. It validates export policy decisions. |
| `tests/unit/thresholdEcdsa.hssWasmSurface.unit.test.ts` | keep | Threshold ECDSA HSS WASM surface coverage. It validates WASM API shape and error behavior. |
| `tests/unit/thresholdEcdsa.persistedRecords.unit.test.ts` | keep | Threshold ECDSA persisted-record coverage. It validates record parsing and persistence behavior. |
| `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts` | keep | Threshold ECDSA distributed presign coverage. It validates distributed presign protocol behavior. |
| `tests/unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts` | keep | Threshold ECDSA presign pool policy coverage. It validates pool policy decisions. |
| `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts` | keep | Threshold ECDSA presign pool refill coverage. It validates refill behavior. |
| `tests/unit/thresholdEcdsa.publicKeyFieldRegression.unit.test.ts` | keep | Threshold ECDSA public-key field regression coverage. It validates public-key field compatibility and parsing. |
| `tests/unit/thresholdEcdsa.registrationBootstrapParity.unit.test.ts` | keep | Threshold ECDSA registration/bootstrap parity coverage. It validates parity between registration and bootstrap material. |
| `tests/unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts` | keep | Threshold ECDSA signing-root resolver script coverage. It validates signing-root resolution tooling. |
| `tests/unit/thresholdEcdsa.walletBudgetRefresh.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era threshold ECDSA wallet refresh coverage. Replace with grant-use refresh semantics when 90 B3 lands. |
| `tests/unit/thresholdEcdsaChainTarget.unit.test.ts` | keep | Threshold ECDSA chain-target coverage. It validates exact chain-target parsing and identity. |
| `tests/unit/thresholdEcdsaEmailOtpConsumption.unit.test.ts` | keep | Threshold ECDSA Email OTP consumption coverage. It validates Email OTP consumption behavior for ECDSA. |
| `tests/unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts` | keep | Threshold ECDSA key-identity inventory parser coverage. It validates inventory parsing and identity extraction. |
| `tests/unit/thresholdEd25519.commitQueue.unit.test.ts` | keep | Threshold Ed25519 commit-queue wrapper coverage. Shared FIFO, concurrency, and clear behavior is owned by the ECDSA wrapper suite over the same `commitQueueShared` implementation; this suite retains Ed25519-specific key formatting and rejection. |
| `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts` | keep | Threshold Ed25519 HSS material-handle coverage. It validates material handle parsing and ownership. |
| `tests/unit/thresholdEd25519.nearSignerWasm.unit.test.ts` | keep | Threshold Ed25519 NEAR signer WASM coverage. It validates WASM signer behavior and parity. |
| `tests/unit/thresholdEd25519.persistedRecords.unit.test.ts` | keep | Threshold Ed25519 persisted-record coverage. It validates record parsing and persistence behavior. |
| `tests/unit/thresholdEd25519.presignPool.unit.test.ts` | keep | Threshold Ed25519 presign pool coverage. It validates presign pool behavior directly. |
| `tests/unit/thresholdEd25519.presignStore.unit.test.ts` | keep | Threshold Ed25519 presign store coverage. It validates presign persistence behavior. |
| `tests/unit/thresholdEd25519.routeValidation.unit.test.ts` | keep | Threshold Ed25519 route validation coverage. It validates route parser behavior directly. |
| `tests/unit/thresholdEd25519.separatedRoles.script.unit.test.ts` | keep | Threshold Ed25519 separated-roles script coverage. It validates script/tooling behavior for separated roles. |
| `tests/unit/thresholdEd25519.serverDispatchSend.unit.test.ts` | keep | Threshold Ed25519 server dispatch-send coverage. It validates server dispatch behavior directly. |
| `tests/unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts` | keep | Threshold Ed25519 session policy digest coverage. It validates digest construction. |
| `tests/unit/thresholdEd25519.signingRootResolver.script.unit.test.ts` | keep | Threshold Ed25519 signing-root resolver script coverage. It validates signing-root resolution tooling. |
| `tests/unit/thresholdEd25519SessionRecordSupersession.unit.test.ts` | keep | Threshold Ed25519 session-record supersession coverage. It validates focused persistence behavior for replacing same-authority Email OTP records. |
| `tests/unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts` | keep | Threshold PRF Cloudflare worker signing-root script coverage. It validates worker signing-root tooling. |
| `tests/unit/thresholdPrfWasm.script.unit.test.ts` | keep | Threshold PRF WASM script coverage. It validates WASM tooling behavior. |
| `tests/unit/thresholdService.secureRandomId.unit.test.ts` | keep | Threshold service secure-random ID coverage. It validates ID generation helper behavior. |
| `tests/unit/thresholdSessionClaims.unit.test.ts` | keep | Threshold session claim coverage. It validates claim construction and parsing. |
| `tests/unit/thresholdSigningSessionReadiness.unit.test.ts` | keep | Threshold signing-session readiness coverage. It validates readiness state and transitions. |
| `tests/unit/thresholdStatusCodes.unit.test.ts` | keep | Threshold status-code coverage. It validates canonical status/error mapping. |
| `tests/unit/thresholdWarmSessionPolicyDraft.unit.test.ts` | keep | Threshold warm-session policy draft coverage. It validates policy draft behavior. |
| `tests/unit/touchConfirm.displayModel.unit.test.ts` | keep | Touch-confirm display model coverage. It validates UI model construction for confirmation prompts. |
| `tests/unit/touchConfirm.orchestrationBridge.unit.test.ts` | keep | Touch-confirm orchestration bridge coverage. It validates bridge behavior between confirm UI and signing logic. |
| `tests/unit/touchConfirm.signingAuthPlanValidation.unit.test.ts` | keep | Touch-confirm signing auth-plan validation coverage. It validates auth-plan validation for confirmation prompts. |
| `tests/unit/uiConfirmPasskeyCredentialLookup.unit.test.ts` | keep | UI-confirm passkey credential lookup coverage. It validates credential lookup behavior for confirmation. |
| `tests/unit/unlockEcdsaWarmupPlanner.unit.test.ts` | keep | Unlock ECDSA warmup planner coverage. It validates warmup planning below the unlock intended contracts. |
| `tests/unit/useCaseLifecycle.unit.test.ts` | keep | Use-case lifecycle coverage. It validates compact use-case state transitions. |
| `tests/unit/userHandle.parse.test.ts` | keep | User-handle parser coverage. It validates WebAuthn/user-handle parsing directly. |
| `tests/unit/vite-wallet-corp.unit.test.ts` | keep | Vite wallet CORP coverage. It validates dev-server header behavior for wallet assets. |
| `tests/unit/walletAuthAuthority.shared.unit.test.ts` | keep | Shared wallet-auth authority coverage. It validates authority construction and parsing. |
| `tests/unit/walletAuthMethodStore.unit.test.ts` | keep | Wallet auth-method store coverage. It validates persistence behavior for auth methods. |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | deleted | Deleted 64-line wallet capability binding source-guard allowlist after the six remaining wallet-scoped `accountId: walletId` event/trace projections moved to explicit `walletId` payloads. `tests/scripts/check-wallet-capability-bindings-source-guard.mjs` now rejects a recreated JSON allowlist and still checks built-in parser/builder/diagnostics boundary exemptions for staleness. |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | deleted | Deleted 272-line wallet capability binding Playwright source guard after moving identity fallback bans, stale unit session fixture checks, optional core identity field checks, and allowlist-retirement enforcement into `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`, wired through `pnpm -C tests run check:wallet-capability-bindings-source-guard` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/walletIframeHost.configGuards.test.ts` | keep | Wallet iframe host config guard coverage. It validates iframe host config invariants directly. |
| `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts` | keep | Wallet iframe host Email OTP recovery-code coverage. It validates recovery-code iframe handling. |
| `tests/unit/walletIframeHost.exportUi.unit.test.ts` | keep | Wallet iframe host export UI coverage. It validates export UI host behavior. |
| `tests/unit/walletIframeHost.registrationActivation.unit.test.ts` | keep | Wallet iframe host registration activation coverage. It validates activation message handling. |
| `tests/unit/walletIframeHost.signTempoCancel.unit.test.ts` | keep | Wallet iframe host Tempo cancel coverage. It validates cancel behavior for Tempo signing. |
| `tests/unit/walletIframeUnlockOptions.unit.test.ts` | keep | Wallet iframe unlock options coverage. It validates unlock option payloads and defaults. |
| `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts` | keep | Wallet registration ECDSA Router A/B bootstrap coverage. It validates bootstrap payloads and persistence. |
| `tests/unit/walletRegistrationPrepareTransport.unit.test.ts` | keep | Wallet registration prepare transport coverage. It validates registration prepare request transport. |
| `tests/unit/walletSessionBudgetReservation.store.unit.test.ts` | blocked_on_coverage(90 B3 grant-use migration) | Budget-era wallet-session reservation store coverage. Replace with grant-use reservation/consumption storage when 90 B3 lands. |
| `tests/unit/walletSessionReadiness.gate.unit.test.ts` | keep | Wallet-session readiness gate coverage. It validates readiness gate behavior directly. |
| `tests/unit/warmEd25519SigningSessionAuthorization.unit.test.ts` | keep | Warm Ed25519 signing-session authorization coverage. It validates warm-session authorization behavior. |
| `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts` | keep | Warm-session ECDSA provisioning coverage. It validates focused provisioning behavior using the split helpers. |
| `tests/unit/warmSessionEd25519Persistence.unit.test.ts` | keep | Warm-session Ed25519 persistence coverage. It validates focused persistence behavior. |
| `tests/unit/warmSessionReadModel.unit.test.ts` | keep | Warm-session read-model coverage. It validates read-model projection behavior. |
| `tests/unit/warmSessionRuntime.unit.test.ts` | deleted | Deleted 227-line direct-helper suite after its PRF claim, diagnostic status read, seal transport, and required-failure branches were confirmed through the retained warm-session store PRF-claim, lifecycle, and error-normalization suites. |
| `tests/unit/warmSessionStore.bootstrapResolution.unit.test.ts` | keep | Warm-session store bootstrap-resolution coverage. It validates bootstrap lookup and resolution behavior. |
| `tests/unit/warmSessionStore.capabilityResolution.unit.test.ts` | keep | Warm-session store capability-resolution coverage. It validates capability lookup behavior. |
| `tests/unit/warmSessionStore.concurrency.unit.test.ts` | keep | Warm-session store concurrency coverage. It validates concurrent store behavior. |
| `tests/unit/warmSessionStore.errorNormalization.unit.test.ts` | keep | Warm-session store error-normalization coverage. It validates canonical error mapping. |
| `tests/unit/warmSessionStore.invariants.unit.test.ts` | keep | Warm-session store invariant coverage. It validates focused state invariants after the broad fixture split. |
| `tests/unit/warmSessionStore.lifecycle.unit.test.ts` | keep | Warm-session store lifecycle coverage. It validates compact lifecycle transitions. |
| `tests/unit/warmSessionStore.prfClaim.unit.test.ts` | keep | Warm-session store PRF-claim coverage. It validates PRF claim handling. |
| `tests/unit/warmSessionStore.reconnect.unit.test.ts` | keep | Warm-session store reconnect coverage. It validates reconnect behavior directly. |
| `tests/unit/warmSessionStore.transitions.unit.test.ts` | keep | Warm-session store transition coverage. It validates focused store state transitions. |
| `tests/unit/warmSessionTransitions.unit.test.ts` | keep | Warm-session transition coverage. It validates transition helpers directly. |
| `tests/unit/wasmLoader.runtimePaths.script.unit.test.ts` | keep | WASM loader runtime-path script coverage. It validates runtime path resolution tooling. |
| `tests/unit/webServer.consoleConfig.unit.test.ts` | keep | Web server console-config coverage. It validates server-side config serving behavior. |
| `tests/unit/webServer.stripeBillingProvider.unit.test.ts` | keep | Web server Stripe billing-provider coverage. It validates billing-provider config behavior. |
| `tests/unit/webauthnPromptCredentialSelection.unit.test.ts` | keep | WebAuthn prompt credential-selection coverage. It validates credential selection behavior. |
| `tests/unit/webauthnPromptCoordinator.unit.test.ts` | keep | Focused WebAuthn prompt-coordinator state coverage. It verifies reservation ownership, single consumption, expiry, abort, competing-operation exclusion, and failure cleanup through the coordinator's public state machine. |
| `tests/unit/workerTransport.multichainTimeout.unit.test.ts` | keep | Worker transport multichain timeout coverage. It validates timeout behavior across chain-family worker requests. |

Ledger checkpoint, July 5, 2026:

- [x] `pnpm -C tests run check:refactor88-test-ledger:complete` reports
  `scope=407 ledger_existing=407 ledger_deleted=66 missing=0`.
- [x] Re-run after the first D1 service-factory split reports
  `scope=403 ledger_existing=403 ledger_deleted=65 missing=0`; focused D1
  validation passes 37/37 for
  `tests/unit/cloudflareD1RouterApiRegistrationPolicy.unit.test.ts` plus the
  remaining `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts`.
- [x] Re-run after the OIDC route-family split reports
  `scope=404 ledger_existing=404 ledger_deleted=65 missing=0`; focused D1
  validation passes 35/35 for
  `tests/unit/cloudflareD1RouterApiOidc.unit.test.ts` plus the remaining
  `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts`.
- [x] Re-run after the Email OTP/recovery route-family split reports
  `scope=405 ledger_existing=405 ledger_deleted=65 missing=0`; focused D1
  validation passes 37/37 across the remaining monolith plus the extracted
  registration-policy, OIDC, and Email OTP route-family suites.
- [x] Re-run after the final D1 service-factory split reports
  `scope=407 ledger_existing=407 ledger_deleted=66 missing=0`; focused D1
  validation passes 37/37 across
  `tests/unit/cloudflareD1RouterApiServiceSurface.unit.test.ts`,
  `tests/unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts`,
  `tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts`,
  `tests/unit/cloudflareD1RouterApiRegistrationPolicy.unit.test.ts`,
  `tests/unit/cloudflareD1RouterApiOidc.unit.test.ts`, and
  `tests/unit/cloudflareD1RouterApiEmailOtp.unit.test.ts`.
- [x] Re-run after the Refactor 90 F3 Express route deletion reports
  `scope=406 ledger_existing=406 ledger_deleted=67 missing=0`; current
  Phase 8 test-surface diff records 25 added lines, 5,046 deleted lines,
  net -5,021 after deleting `tests/relayer/express-router.test.ts` and the
  fake AuthService branch in `tests/relayer/helpers.ts`.
- [x] Current `tests/unit/helpers/*.ts` files all have surviving importers; no
  zero-importer helper deletion was available in this inventory pass.

### Phase 6: Delete Mocked Runtime Fixture Tests

- [x] Delete mocked docs lifecycle e2e tests covered by the passkey intended
  contracts:
  - `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts`
  - `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`
- [x] Start shrinking the warm-session fixture API by making internal-only
  helper types/functions private before splitting the broad fixture module.
- [x] Split generic ECDSA chain-target helpers into
  `tests/unit/helpers/ecdsaChainTarget.fixtures.ts` so tests that only need
  chain identity no longer import the broad warm-session runtime fixture module.
- [x] Split generic ECDSA bootstrap construction into
  `tests/unit/helpers/ecdsaBootstrap.fixtures.ts`; warm-session tests now import
  bootstrap records from the focused helper instead of keeping the builder
  exported from `warmSessionStore.fixtures.ts`.
- [x] Split generic signing-session record store/reset/seed helpers into
  `tests/unit/helpers/signingSessionRecord.fixtures.ts`, before the remaining
  warm-session helpers were split into focused files.
- [x] Split generic warm-session status and touch-confirm fixtures into
  `tests/unit/helpers/warmSessionUiConfirm.fixtures.ts`, leaving only the
  warm-session service builder in the former broad module.
- [x] Rename the remaining warm-session service builder into
  `tests/unit/helpers/warmSessionTestServices.fixtures.ts` and delete the broad
  `tests/unit/helpers/warmSessionStore.fixtures.ts` entrypoint.
- [x] Replace empty-string Ed25519 material fixture toggles with explicit
  material-state fixture branches, then update warm-session/read-model tests to
  use current `material_ready`, `restore_available`, and
  `auth_ready_material_pending` shapes directly.
- [x] Refresh stale readiness fixtures to current Router A/B Ed25519 state and
  Email OTP wallet-authority auth context so cleanup tests exercise present
  persistence shapes.
- [x] Delete `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts`, the broad
  mocked unlock -> warm signing lifecycle fixture now covered by `test:intended`
  and focused boundary/domain unit tests.
- [x] Delete `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts` and
  remove the demo `__testOverrides` prop path it depended on.
- [x] Delete the redundant direct warm-session runtime suite and duplicated
  export-success, dashboard-theme, lane-readiness, SeamsAuthMenu source-shape,
  and Ed25519 shared commit-queue cases, then retired stale dashboard status
  panels and copy assertions exposed by the focused run. This pass removed
  1,342 test lines and added 25 lines, net -1,317, while retaining failure,
  cancellation, isolation, parser, and wrapper-specific behavior coverage.
- [x] Classify remaining inspected mocked/demo-browser tests that should stay
  because they cover focused UI, iframe transport, event-forwarding,
  worker-router, public signing API shape, or persistence-boundary behaviour
  rather than lifecycle correctness.
- [x] Guard the retained-boundary audit rows so each `keep` classification
  points at an existing focused test file, stays recorded in this plan, and
  covers every current `tests/wallet-iframe/*.test.ts` file, with source
  evidence tokens for each retained boundary reason. This is now enforced by
  `tests/scripts/check-refactor88-test-ledger.mjs`.
- [x] Classify every remaining `setupBasicPasskeyTest` consumer as retained
  boundary coverage and guard future generic browser bootstrap use behind an
  explicit audit row.
- [x] Delete unused `tests/setup/flows.ts` and `tests/setup/fixtures.ts`, the
  old wrapper layer that drove registration/unlock/signing through
  `window.testUtils`.
- Delete mocked e2e/unit tests covered by `test:intended`.
- Delete fixture helpers that only feed those tests.
- Record every deletion in the Phase 5 ledger with file and line counts; the
  running totals are the pruning evidence, per the 90 plan's Decided Point 14
  bloat-discipline convention.
- Delete stale snapshots, source guards, and allowlists that preserve old runtime
  shapes. Record retired guards in
  [refactor-89-clean-source-guards.md](./refactor-89-clean-source-guards.md).
- Stop updating mocked runtime fixtures during refactors. If a runtime-shape
  change breaks one of these tests, use that as a signal to delete the test once
  `test:intended` covers the behaviour.
- Keep focused unit tests for parsers, domain unions, cryptographic vectors, and
  boundary validation.
- Keep small UI tests only when they check UI behaviour directly, such as
  overlay visibility or button state. They should not pretend to validate
  signing lifecycle correctness.

### Phase 7: Core Setup Script Cleanup

Clean up the setup scripts by extracting the few helpers real e2e tests need
and deleting the rest as their mocked tests disappear.

Keep only these setup primitives for intended-behaviour tests:

- Playwright browser/session setup.
- CDP WebAuthn virtual authenticator setup.
- Router/site readiness checks.
- D1 reset/seed helpers that operate on the real local D1 state.
- Console/network capture for failure output.
- Wallet iframe confirm helpers that click real UI.

Remove from the intended e2e harness:

- fetch overrides for Router API, sponsorship, faucet, auth, or wallet session
  routes
- fake AuthService or in-memory router server setup
- same-origin worker rewrites that hide cross-origin wallet issues
- broad `window.testUtils` mutation for core registration, unlock, signing,
  step-up, or export flows
- setup helpers whose only purpose is feeding mocked runtime fixtures

Concrete cleanup targets:

- [x] Keep intended lifecycle setup split from `tests/setup/bootstrap.ts`: the
  intended suite now enters through `tests/e2e/intended-behaviours/harness.ts`
  and each contract file imports only `./harness`.
- [x] Implement the useful intended browser primitives directly in the intended
  harness: Playwright fixture ownership, CDP WebAuthn, service readiness,
  storage reset, compact failure trace, external identity/chain RPC stubs, and
  wallet iframe auto-confirm.
- [x] Stop using `tests/setup/test-utils.ts` from intended e2e tests.
- [x] Add guards that fail if `tests/e2e/intended-behaviours/**` imports mocked
  setup helpers, legacy setup shims, fake AuthService startup, or known mock
  installers.
- [x] Exclude `tests/e2e/intended-behaviours/**` from the generic Playwright
  config so only `test:intended` and `test:intended:ci` own lifecycle contracts.
- [x] Delete the fake AuthService server launcher scripts now that no package
  script starts them.
- [x] Delete `tests/relayer/helpers.ts` fake AuthService helpers after
  Refactor 90 F3 removed the Express route suite.

Deleted fake AuthService surface:

- `tests/relayer/express-router.test.ts` is deleted.
- `tests/relayer/helpers.ts` no longer exports `makeFakeAuthService`.
- The two route-surface unit tests now use local throwing
  `RouterApiServiceBag` fixtures, so route wiring no longer imports the fake
  AuthService helper.
- `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` now rejects
  `makeFakeAuthService` references outside its own checker token table.

Completed setup cleanup:

- [x] Remove unused `setupRouterApiServerTest` /
  `setupTestnetFaucetTest` exports and the dead
  `window.testUtils.registrationFlowUtils` Router API/faucet mock installers.
- [x] Remove unused browser `window.testUtils` mock hooks:
  `failureMocks`, `rollbackVerification`, `verifyAccountExists`,
  `webAuthnUtils`, and `loginStatus`; guard the setup files so those retired
  hooks stay deleted.
- [x] Remove the unused passkey fixture/flow wrapper files that depended on
  broad `window.testUtils` evaluation.
- [x] Remove the now-unused `TestUtils` setup interface and dead
  `printGroupHeader` / `createConsoleCapture` logging exports.
- [x] Delete `tests/setup/test-utils.ts` and replace the final direct consumers
  with `window.configs` / `__W3A_TEST_RP_ID__`; the remaining setup path no
  longer installs `window.testUtils`.
- [x] Remove stale README references to deleted `tests/setup/fixtures.ts`,
  `tests/setup/flows.ts`, and the old `window.testUtils` wrapper layer.
- [x] Update `tests/README.md` so the quick reference points at
  `e2e/intended-behaviours/*.contract.test.ts` rather than deleted
  threshold-lifecycle e2e files, and guard the README against those retired
  references.
- [x] Reframe `tests/README.md` so registration, unlock, signing, step-up, and
  export lifecycle authority belongs to the intended-behaviour contracts; the
  generic `setupBasicPasskeyTest` path is documented as UI/iframe/component
  bootstrap only and guarded against becoming a lifecycle oracle again.
- [x] Remove the stale `benchmarks/registration-flow` import of deleted
  `tests/setup/flows.ts` by localizing the small wallet-iframe auto-confirm
  primitive the benchmark still needs.
- [x] Retire the registration-flow benchmark runner rather than resurrect its
  pre-existing dependency on deleted `tests/e2e/thresholdEd25519.testUtils`.
  Historical reports stay under `docs/benchmarks/registration-flow.md`; a
  replacement benchmark should use the real intended-behaviour topology.
- [x] Guard root and tests package scripts against reintroducing the retired
  `benchmark:registration-flow*` commands or deleted registration-flow runner
  entrypoints.
- [x] Mark the retained `docs/benchmarks/registration-flow.md` report as an
  archived historical artifact and guard the archive banner so embedded
  commands remain provenance-only.
- [x] Guard active source under `apps`, `packages`, and `tests` against
  importing the retired setup wrapper files.
- [x] Guard active source under `apps`, `packages`, and `tests` against
  reintroducing retired browser mutation hooks: `__testOverrides` and
  `window.testUtils`.
- [x] Guard `tests/e2e/**` so the generic `setupBasicPasskeyTest` bootstrap is
  only allowed in the retained cancel-overlay coverage, keeping lifecycle e2e
  authority inside `tests/e2e/intended-behaviours/**`.
- [x] Remove unused same-origin setup control flags from
  `setupBasicPasskeyTest`; the remaining generic setup mirror is internal to
  legacy UI/browser tests and is not imported by intended contracts.
- [x] Guard `tests/e2e/intended-behaviours/**` against legacy mocked setup
  imports, fake Router API installers, fake AuthService startup, and
  same-origin SDK/worker rewrite shims.
- [x] Guard intended harness request routing so only external identity/chain
  RPC hosts are stubbed; app, Router, wallet-origin, and intended-page traffic
  must continue to real local services.
- [x] Guard intended contracts against local skip/focus/retry annotations and
  public lifecycle action-sequence drift.
- [x] Guard intended contract files so they remain high-level harness scripts
  and cannot import Playwright/page/request APIs directly.
- [x] Remove duplicate generic setup relayer toggles (`useRelayer` and
  `relayServerUrl`) so retained browser tests use the single `relayer.url`
  config path.
- [x] Refresh generic setup comments/docs so they describe the current
  wallet-route/WebAuthn/import-map/bootstrap sequence and no longer recommend
  mocked Router fallback.
- [x] Trim generic infrastructure skipping to the retained testnet faucet 429
  case, and guard against broad Router/funding/port-collision skips returning.
- [x] Guard the intended page and harness against private SDK, signing-engine,
  threshold-service, legacy threshold-Ed25519, and Router route imports.
- [x] Move the intended page's wallet-id normalization onto the public
  `@seams/sdk/advanced` surface and replace demo ECDSA chain-target helpers
  with local typed intended-contract targets; guard the page and harness
  against internal package and demo-helper imports.
- [x] Guard the intended page and harness action-result unions so the nine
  public success discriminants stay aligned with the harness parser and page
  result helper switches.
- [x] Enforce the intended suite wall-clock budget in
  `tests/playwright.intended.config.ts` with `globalTimeout: 600_000`.
- [x] Guard local intended Playwright config against generic webServer startup
  and fake Router API server paths.
- [x] Move `test:integration:signing` onto the Vite-only browser setup and
  guard it against reintroducing the fake relay server path.
- [x] Move `test:e2e` onto the Vite-only browser setup, align the wallet-service
  header smoke with the local wallet-origin default, and guard the script
  against reintroducing the fake relay server path.
- [x] Move `test:lite` onto the Vite-only browser setup and guard the script
  against reintroducing the fake relay server path.
- [x] Move `test:inline` onto the Vite-only browser setup and guard the script
  against reintroducing the fake relay server path.
- [x] Move the full generic `test` script onto the Vite-only browser setup,
  delete the fake AuthService server launcher scripts, and remove the legacy
  fake-relay control branch from the generic Playwright config.
- [x] Guard the deleted fake AuthService server launcher files and the neutral
  `test:unit:scripts` name against reintroduction.
- [x] Guard the generic Playwright config against discovering intended
  contracts through broad `e2e/**/*.test.ts` matching.
- [x] Refresh stale ECDSA top-level fixtures so broad Playwright discovery no
  longer trips on missing wallet auth authority or
  `evmFamilySigningKeySlotId` fields.
- [x] Fix wallet-origin export overlay close coverage so explicit key-export
  progress hide events release sticky overlay ownership and the harness
  captures the wallet-service iframe instead of unrelated passkey iframes.
- [x] Guard fake AuthService helper usage so it stays quarantined to relayer
  and explicit Router boundary tests while Refactor 82B owns final deletion.
- [x] Guard the sibling 82B/83/90 plans so auth/session/signing/export and
  grant-spend migration work keeps naming `pnpm test:intended` as the
  pre-merge lifecycle gate until CI owns startup.
- [x] Record the retired mocked runtime files, deleted fake AuthService server
  launchers, and browser setup hooks in
  [refactor-89-clean-source-guards.md](./refactor-89-clean-source-guards.md)
  and guard the ledger against drifting from the actual deletion list.
- [x] Update current cleanup docs so recommended package scripts use the
  Vite-only integration signing command, and guard those docs against the
  deleted fake-relay flag.

The desired shape is one boring setup path:

```text
test:intended
  -> require pnpm router + pnpm site, or start them in CI
  -> reset D1/IndexedDB/browser context
  -> run real browser flows
  -> capture logs/artifacts on failure
```

### Phase 8: Legacy Suite Deletion Sweep

Executes the large deletions identified in the July 4 suite survey. Scale at
time of writing: ~223k test lines total (unit 146.5k across 377 files,
relayer 48.3k across 42 files); guards alone are 45 files / ~18.5k lines
(12.6% of unit code). Roughly 35-45k lines are deletable without losing a
behaviour — most of it behind gates other plans already define. Every
deletion lands as a Phase 5 ledger row with file/line counts and its named
replacement coverage. Gated tasks fire in the same change as their gate,
never ahead of it.

Ungated — start now:

- [x] Run the Refactor 89 removal checklist over the refactor-numbered guard
      suites whose invariants are now structural or behaviour-covered:
      54, 56, 58, 67, 71, 73 (replace with a lint rule, not a test), 74 (both
      files), 76, and 80. Record each verdict in the
      [Refactor 89](./refactor-89-clean-source-guards.md) ledger; delete rows
      that reach `ready_to_delete`. Guards delete through the 89 checklist,
      never directly from this phase.
      Completed July 4, 2026: the Refactor 89 ledger records a dated verdict
      for each named guard. Refactor 73 fired:
      `tests/unit/refactor73TypeFilename.guard.unit.test.ts` was deleted after
      moving its rule into `tests/scripts/check-type-filename-source.mjs`.
      The remaining named guards stay `active` with concrete replacement gaps:
      public API/signing-surface contract coverage, Email OTP flow/parser
      coverage, package-boundary build checks, Refactor 90 vocabulary cleanup,
      HSS/worker command type fixtures, branded parser/type fixtures, and
      route parser/exhaustive-union fixtures.
- [x] Delete `tests/setup/webauthn-mocks.ts` (598 lines) after converting its
      remaining consumers to the CDP virtual authenticator; shrink
      `tests/setup/bootstrap.ts` and `tests/setup/cross-origin-headers.ts` to
      the primitives the retained browser tests actually import.
      Deletion recorded July 4, 2026: generic setup now uses the same
      PRF-capable CDP virtual authenticator primitive as the intended harness
      (`hasPrf: true` in `tests/setup/bootstrap.ts`) and no active source
      imports `setupWebAuthnMocks`.

Gated — each task names its gate and fires in the same change:

- [x] Split
      `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts` (started at
      6,695 lines) into per-route-family suites. Deleted the monolith after
      retaining current coverage in `tests/unit/cloudflareD1RouterApiRegistrationPolicy.unit.test.ts`,
      `tests/unit/cloudflareD1RouterApiOidc.unit.test.ts`,
      `tests/unit/cloudflareD1RouterApiEmailOtp.unit.test.ts`,
      `tests/unit/cloudflareD1RouterApiServiceSurface.unit.test.ts`,
      `tests/unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts`,
      `tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts`, and
      `tests/unit/helpers/cloudflareD1RouterApiAuthService.fixtures.ts`.
- [x] Gate: Refactor 90 F3 deletes the Express route implementations
      (Decided Point 11). Deleted `tests/relayer/express-router.test.ts`
      (4,370 lines) and the remaining `tests/relayer/helpers.ts`
      `makeFakeAuthService` branch (540 lines) in the same change.
- [x] Gate: Refactor 82 Phase 11/12 lands the D1-canonical route-family
      harness (`routes-d1` — that harness is an 82 deliverable, not a test
      chore here). Deleted the 12 unblocked fake/AuthService relayer suites
      totaling 12,033 lines, including `tests/relayer/email-otp.authservice.test.ts`
      (2,026 lines), and converted the two quarantined unit route-surface tests
      off the fake helper. `tests/relayer/helpers.ts` remains only for the
      Refactor 90 F3 Express deletion gate.
- [ ] Gate: Refactor 90 A4/B5 rework console scopes and RBAC. Collapse
      `tests/relayer/console-router.test.ts` (12,831 lines) and
      `tests/relayer/console-d1-adapters.test.ts` (8,391 lines) into one
      table-driven route-family suite per console area. Do not port both
      layers.
- [ ] Gate: Refactor 90 B3 subsumes the budget subsystem into grant-use
      consumption (Decided Point 13). Delete the budget
      reservation/projection/coordinator suites with the subsystem, keeping
      only the operation-fingerprint concurrency coverage that survives.
- [x] Gate: the fifth (recovery) intended spec lands. The recovery lifecycle is
      now covered by `tests/e2e/intended-behaviours/recovery.email.contract.test.ts`.
      July 5, 2026 validation: focused recovery passes in 30.6s against a
      clean managed stack, and `pnpm -C tests run test:intended:ci` passes all
      five intended contracts in 4.5m. The former
      `blocked_on_coverage(recovery)` ledger rows are now reclassified to
      replacement cleanup work.

Phase exit:

- [x] Every ungated deletion above is done and recorded with file/line
      counts.
- [x] Every gated deletion has its gate named on its ledger rows, and fired
      deletions landed in the same change as their gate. Refactor 90 A4/B5
      and B3 rows remain explicitly blocked until those product migrations
      land.
- [x] Current net test-suite line change is recorded in the ledger checkpoint;
      each fired deletion row names the coverage that replaced it. Refactor 90
      A4/B5 and B3 will add their own line-accounting checkpoints when they
      fire.

## Exit Criteria

- `pnpm test:intended` fails for the regressions we have been finding manually.
- A refactor that breaks any listed intended behaviour fails `test:intended`.
- Refactors touching auth/session/signing/export must run `pnpm test:intended`.
- Manual testing is used for UX polish, not for discovering lifecycle contract
  regressions.
- The suite stays small: new specs require a new auth factor, a new signer
  family, or an existing uncovered user-visible lifecycle. Recovery is now the
  fifth lifecycle spec, starting with email recovery into signing; recovery-code
  restore and device-escrow restore remain follow-up coverage inside that
  lifecycle family.
- `pnpm check:intended-mutation-self-check:complete` must pass before this
  refactor can be declared complete; every Phase 3B seeded regression row now
  records detected proof evidence.
- Mocked runtime fixture tests no longer block runtime refactors.
- The Phase 5 ledger covers every file under the six test directories — no
  unaudited files remain — and deletions are recorded with file/line counts.
  `blocked_on_coverage` rows name live coverage plans, not "later".
- The Phase 8 deletion sweep has fired every unblocked gate. Remaining gated
  deletions name their blocker and must fire in the same change as that blocker.
- Intended e2e tests have one setup entrypoint and cannot import mocked setup
  helpers.
- Current supporting validation, July 5, 2026:
  `pnpm -C packages/sdk-web type-check`,
  `pnpm -C apps/seams-site run typecheck`,
  `pnpm -C tests run test:intended:ci`,
  `pnpm -C tests run check:intended-mutation-self-check:complete`,
  `pnpm -C tests run check:intended-behaviour-contract-boundaries`,
  `pnpm -C tests run check:refactor88-test-ledger:complete`, and
  `pnpm -C tests run test:source-guards` all pass. The latest mutation
  completion run reports 4/4 detected proof rows. The latest ledger completion
  run reports `scope=406 ledger_existing=406 ledger_deleted=67 missing=0`, and
  the latest intended run reports 5/5 contracts green in 4.1m. The latest
  source-guard profile reports all standalone checks plus 190/190 Playwright
  source-profile tests green.
