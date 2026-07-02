# Proper E2E Tests

Date created: 2026-07-02

Status: planning.

Source of truth:

- [Intended Behaviours](./intended-behaviours.md)
- [Refactor 93: Intended Behaviour E2E Contract](./refactor-93-intended-behaviour-e2e.md)

## Problem

The current suite has many unit and guard tests, but the failures we keep
finding manually happen across full lifecycle boundaries:

- registration -> transaction signing
- wallet unlock -> transaction signing
- session exhaustion -> step-up auth -> first transaction
- key export authorization

These paths cross the wallet iframe, IndexedDB, D1 Router API, Durable Objects,
workers, signing-engine lane selection, budget, and export flows. Tests that
mock SDK internals do not prove these behaviours.

## Goal

Create one small e2e contract suite that runs real local infrastructure and
proves the behaviours in `docs/intended-behaviours.md`.

This suite should be the default gate before merging refactors that touch auth,
registration, unlock, signing lanes, worker material, budget, key export,
Router API, D1/DO state, or wallet iframe routing.

## Non-Goals

- Do not add broad unit coverage for these lifecycle behaviours.
- Do not add another large mocked demo harness.
- Do not mock signing-engine lane selection, budget coordinator, wallet iframe
  protocol, IndexedDB persistence, Router API responses, worker material
  persistence, or D1/DO state.
- Do not test visual polish here. Use manual testing and focused UI tests for
  layout.

## Real Components Under Test

The e2e suite must run:

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

## Test Command

Add:

```json
"test:intended": "pnpm -C tests test:intended"
```

Add in `tests/package.json`:

```json
"test:intended": "playwright test -c playwright.intended.config.ts --reporter=line"
```

Local developer mode:

```sh
pnpm router
pnpm site
pnpm test:intended
```

CI mode can start services in Playwright `webServer` once the local developer
mode is stable.

## Files To Add

```text
tests/playwright.intended.config.ts
tests/e2e/intended-behaviours/
  harness.ts
  passkey.registration.contract.test.ts
  passkey.unlock.contract.test.ts
  email-otp.registration.contract.test.ts
  email-otp.unlock.contract.test.ts
```

Keep the suite intentionally small. Four contract files are enough because each
file should exercise Ed25519, ECDSA, step-up, and key export for one lifecycle
entry point.

## Harness Design

Use a single harness that:

- opens the local site at the real app origin
- configures local Router API, wallet origin, environment ID, and publishable key
- resets browser storage for each test
- creates a unique wallet ID per test
- uses Playwright's virtual WebAuthn authenticator for passkey flows
- provides deterministic Google identity and Email OTP test responses
- intercepts only external chain RPC/faucet calls
- records lifecycle events from app console, SDK events, and network requests
- fails on any console/network error matching known lifecycle failure strings

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

## Contract Matrix

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
- ECDSA target identity is missing or shared incorrectly across Tempo and Arc.

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
- duplicate exact lane records
- missing chain target in ECDSA budget, readiness, or persistence
- key export succeeding without fresh export authorization

## Service Startup

Phase 1 should assume services are already running, because that is the fastest
way to make the suite useful during refactors:

```sh
pnpm router
pnpm site
pnpm test:intended
```

Phase 2 can add CI-managed startup:

- reset local D1 state
- run local D1 migrations
- seed local org/project/env/API key
- start router
- start site
- run `test:intended`
- stop services

## Data Reset

Each test must use isolated state:

- unique wallet ID prefix
- unique Email OTP provider subject
- unique passkey credential
- fresh browser context
- cleared IndexedDB/localStorage/sessionStorage

D1 can be reset once per suite in CI mode. Local developer mode may reuse D1
state as long as wallet IDs are unique.

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

## Implementation Phases

### Phase 1: Local Harness

- Add `playwright.intended.config.ts`.
- Add `tests/e2e/intended-behaviours/harness.ts`.
- Add `test:intended` scripts.
- Prove the harness can connect to already-running `pnpm router` and
  `pnpm site`.

### Phase 2: Passkey Contracts

- Add passkey registration contract.
- Add passkey unlock contract.
- Cover Ed25519 signing, ECDSA signing, step-up, and key export.

### Phase 3: Email OTP Contracts

- Add Email OTP registration contract with wallet reroll.
- Add Email OTP unlock contract.
- Cover Ed25519 signing, ECDSA signing, step-up, and key export.

### Phase 4: CI Startup

- Add CI-managed router/site startup after local mode is stable.
- Keep local mode unchanged.

### Phase 5: Mocked Runtime Fixture Audit

Audit tests that mock runtime internals for behaviours now covered by
`test:intended`.

Start with:

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

### Phase 6: Delete Mocked Runtime Fixture Tests

- Delete mocked e2e/unit tests covered by `test:intended`.
- Delete fixture helpers that only feed those tests.
- Delete stale snapshots, source guards, and allowlists that preserve old runtime
  shapes.
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

- Split `tests/setup/bootstrap.ts` into a small intended harness entrypoint and
  legacy-only helpers. Intended tests should import only the small entrypoint.
- Move useful browser primitives from `tests/setup/index.ts`,
  `tests/setup/flows.ts`, `tests/setup/logging.ts`, and
  `tests/setup/cross-origin-headers.ts` into the intended harness without
  carrying over mocks.
- Stop using `tests/setup/test-utils.ts` from intended e2e tests.
- Delete `tests/scripts/test-router-api-server.mjs` once no current test needs
  the fake AuthService server.
- Delete `tests/relayer/helpers.ts` fake AuthService helpers once Phase 11/12
  D1 adapter cleanup is complete.
- Add a small guard that fails if `tests/e2e/intended-behaviours/**` imports
  mocked setup helpers or calls known mock installers.

The desired shape is one boring setup path:

```text
test:intended
  -> require pnpm router + pnpm site, or start them in CI
  -> reset D1/IndexedDB/browser context
  -> run real browser flows
  -> capture logs/artifacts on failure
```

## Exit Criteria

- `pnpm test:intended` fails for the regressions we have been finding manually.
- Refactors touching auth/session/signing/export must run `pnpm test:intended`.
- Manual testing becomes a UX check, not the first place we discover lifecycle
  regressions.
- Mocked runtime fixture tests no longer block runtime refactors.
- Intended e2e tests have one setup entrypoint and cannot import mocked setup
  helpers.
