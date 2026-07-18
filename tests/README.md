# Passkey SDK Test Suite

Playwright tests for the Passkey SDK, covering WebAuthn + PRF flows, wallet iframe behavior, Lit confirm UI, orchestrator logic, and UserConfirm/nonce subsystems.

## Table of Contents

- [Suites & Scope](#suites--scope)
- [Coverage Overview](#coverage-overview)
- [Build & Assets](#build--assets)
- [Setup Architecture](#setup-architecture)
- [Fixtures & Helpers](#fixtures--helpers)
- [Running](#running)
- [Environment](#environment)
- [Suite Quick Reference](#suite-quick-reference)
- [Fixes & Learnings](#fixes--learnings)
- [Troubleshooting](#troubleshooting)
- [Gaps & Next Steps](#gaps--next-steps)

## Suites & Scope

- Intended Behaviour Contracts: registration, unlock, signing, step-up, and
  export lifecycle checks against the real site, wallet origin, Router API,
  D1, Durable Objects, IndexedDB, and workers
- E2E/API Smokes: dashboard, pricing, wallet-service headers, theme validation,
  and cancel-overlay behavior
- Unit: orchestrator helpers, progress heuristics, nonce, confirm handler
- Wallet Iframe: handshake, overlay routing, sticky/anchored behavior
- Lit Components: modal/drawer host + iframe confirm UI

Playwright config includes wallet‑iframe and lit‑components suites in
`testMatch`. The generic config excludes
`tests/e2e/intended-behaviours/**`; run those contracts through
`test:intended` or `test:intended:ci`.

## Coverage Overview

- UserConfirm + Nonce: strong unit/integration coverage
- Wallet Iframe: CONNECT→READY handshake, intent mapping, timeout hide, anchored pre‑show, sticky lifecycle; progress heuristics partially covered
- Confirm Orchestrator: success and defensive paths; batching and local‑only cancel remain
- Lit Confirm UI: host/iframe modal + drawer behavior covered; theme guardrails pending

Status highlights from recent additions:

- OnEventsProgressBus default heuristics for show/hide/none mapping and cancelled → hide
- Overlay controller CSS/ARIA semantics; sticky prevents hide
- Router behavior for pre‑show, timeout hide, anchored bounds, sticky lifecycle
- awaitUserConfirmationV2 error handling via signer worker global
- confirmTxFlow success/defensive paths and helpers sanitization/parsing

## Build & Assets

- `test:intended:ci` builds fresh SDK artifacts before starting local services.
- `test:intended` assumes the already-running local site/router are serving the
  SDK artifacts you intend to test; rebuild and restart those services after SDK
  source changes.
- Intended commands and mutation preflight run the Google ID-token preflight
  before Playwright/readiness checks.
- Dev plugin serves SDK at `/sdk/*` directly from `dist/`
- Assets of interest:
  - `dist/esm/**` ES modules (SDK + embedded bundles)
  - `dist/cjs/**` CommonJS modules
  - `dist/workers/**` Worker bundles and WASM binaries

## Setup Architecture

The generic Playwright bootstrap is a precise sequence for UI/browser tests that
still run through the local app-origin SDK mirror. It is split for clarity:

- `tests/setup/bootstrap.ts`: `executeSequentialSetup()`
  1. Wallet SDK CORS/CORP and wallet-service route setup
  2. WebAuthn Virtual Authenticator (Chromium CDP)
  3. Import map injection (NEAR + lit deps)
  4. Environment stabilization
  5. Dynamic import from `/sdk/esm/...` and instance wiring
  6. Global fallbacks (e.g., base64UrlEncode)

- `tests/setup/index.ts`:
  - `setupBasicPasskeyTest(page, overrides)` runs the generic SDK/browser
    bootstrap for UI, iframe, and component tests
  - `handleInfrastructureErrors()` centralizes CI‑skip for faucet 429

The intended-behaviour contracts use
`tests/e2e/intended-behaviours/harness.ts` instead of this generic bootstrap.
They run public SDK/UI flows against the real local site, wallet origin, Router
API, D1, Durable Objects, IndexedDB, and workers. Registration, unlock,
signing, step-up, and export lifecycle authority belongs there.
The generic Playwright config excludes those contracts so lifecycle checks stay
on the intended runner.

- `tests/setup/logging.ts`: quiet‑by‑default console capture (`VERBOSE_TEST_LOGS`)

## Fixtures & Helpers

- `tests/setup/index.ts` exports public setup helpers:
  - `setupBasicPasskeyTest(page, overrides)` for generic SDK/browser bootstrap
    only; do not use it as a lifecycle oracle
  - `handleInfrastructureErrors(result)` for testnet/faucet skip handling
  - SDK ESM path helpers from `tests/setup/sdkEsmPaths.ts`

- `tests/e2e/intended-behaviours/harness.ts` owns the intended-behaviour
  contract harness:
  - Chromium virtual WebAuthn and PRF setup
  - lifecycle trace capture and versioned failure matchers
  - public registration, unlock, signing, and export actions
  - cryptographic signature verification for returned NEAR and ECDSA signatures

## Running

- Root scripts:
  - `pnpm test` → `pnpm -C tests test` (full suite)
  - `pnpm test:lite` → `pnpm -C tests test:lite` (lite suite; excludes the heavier wallet-iframe sticky-behavior coverage)
  - `pnpm test:inline` → line reporter
  - `pnpm test:intended` → intended-behaviour lifecycle contract suite against already-running local services
  - `pnpm test:intended:ci` → intended-behaviour lifecycle contract suite with CI-managed local service startup
  - `pnpm ensure:intended-google-token` → accept or refresh the Email OTP Google ID token before intended contracts run
  - `pnpm setup:intended-google-oidc` → create/bind the local Google OIDC service account and mint an Email OTP test ID token
  - `pnpm refresh:intended-google-token` → refresh the one-hour Email OTP Google ID token through service-account impersonation
  - `pnpm check:intended-mutation-self-check` → validate Refactor 88 mutation self-check metadata
  - `pnpm check:intended-mutation-self-check:complete` → fail until all Refactor 88 mutation proof rows are `detected`
  - `pnpm preflight:intended-mutation-self-check` / `pnpm preflight:intended-mutation-self-check:ci` → report local or CI-managed readiness for Phase 3B mutation proof
  - `pnpm test:unit`, `pnpm test:source-guards`, `pnpm test:integration:signing`
  - `pnpm test:wallet-iframe`, `pnpm test:lit-components`
  - `pnpm show-report` to open Playwright HTML report

Test profiles:

- `test:unit` runs unit behavior tests from `tests/unit` and excludes source
  guards, source-script tests, WASM replay, worker-router, full SDK iframe, and
  high-level transaction lifecycle suites.
- `test:source-guards` runs architecture guards and source/script checks.
- `test:integration:signing` runs browser/WASM-heavy signing lifecycle suites
  that are intentionally outside the unit closeout gate. It uses the same
  Vite-only browser setup as the generic suites.
- `test`, `test:lite`, and `test:inline` use the Vite-only browser setup.
  The fake relay server launcher has been removed.
- Generic e2e scripts exclude `e2e/intended-behaviours/*.contract.test.ts`;
  lifecycle contracts run through `test:intended` or `test:intended:ci`.
  `test:e2e` uses the same generic config and excludes intended contracts.

- Direct Playwright subset examples:

```bash
pnpm -C tests exec playwright test **/e2e/**/*.test.ts
pnpm -C tests exec playwright test -c playwright.unit.config.ts
```

Intended-behaviour contracts:

```bash
pnpm setup:intended-google-oidc
pnpm router
pnpm site
pnpm test:intended
pnpm test:intended:ci
```

Local `test:intended` is fastest for refactor work and assumes the services are
already running. CI mode resets local Router/D1 state, builds
`packages/sdk-web/dist`, starts router/site, then runs the same four contracts.
Intended commands and mutation preflight run `ensure:intended-google-token`
before Playwright/readiness checks: a still-valid token is accepted, and an
expired/missing token is refreshed through
`SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT` when service-account impersonation is
configured. The intended config, mutation preflight, and CI-managed service
startup load `.env.intended.local` automatically. Restart already-running local
router/site services after changing Google OIDC env values so the runtime sees
`GOOGLE_OIDC_CLIENT_ID`.

Chromium only; `workers=1` to avoid relay/faucet rate limits.

Signer runtime gate (Phase 0-5):

```bash
pnpm -C tests run test:signers:gates
```

Threshold ECDSA lane-key queue matrix (Refactor 22):

```bash
(pnpm build:sdk-full) \
  && pnpm -C tests exec playwright test ./unit/thresholdEcdsa.commitQueue.unit.test.ts --reporter=line \
  && pnpm -C tests exec playwright test ./unit/reportTempoBroadcastFailure.unit.test.ts ./unit/evmSigning.noncePrefetch.unit.test.ts --reporter=line
```

## Environment

- `SEAMS_INTENDED_GOOGLE_ID_TOKEN=<token>` enables the Email OTP intended
  contracts against the local Router Google OIDC/dev-outbox path; mutation
  preflight rejects missing, placeholder, or malformed non-JWT values before
  the Router performs signature and claim verification
- `SEAMS_INTENDED_GOOGLE_PROJECT_ID`, `SEAMS_INTENDED_GOOGLE_CLIENT_ID`,
  `GOOGLE_OIDC_CLIENT_ID`, optional Google OAuth client secret vars, and
  `SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT` are kept in ignored
  `.env.intended.local`. Run `pnpm setup:intended-google-oidc` once, or pass
  `--client-secret=<secret>` when creating a new local env file, then run
  `pnpm refresh:intended-google-token` manually when needed. `pnpm test:intended`
  `pnpm test:intended`, `pnpm test:intended:ci`, and mutation preflight run
  `pnpm ensure:intended-google-token` first and refresh the one-hour ID token
  automatically when the service account is set.
- `VERBOSE_TEST_LOGS=1` print captured console logs live

Manual build without tests:

```bash
pnpm build:sdk
```

## Suite Quick Reference

- E2E
  - `e2e/intended-behaviours/*.contract.test.ts` intended registration,
    unlock, signing, step-up, and export lifecycle contracts
  - `e2e/dashboard.*.apiWiring.test.ts` and
    `e2e/pricing.checkout.apiWiring.test.ts` dashboard/API wiring smoke tests
  - `e2e/cancel_overlay_specs.test.ts` cancel + overlay specs (cancel hides UI)

- Unit
  - `unit/nonceCoordinator.nearContext.test.ts` coordinator-owned NEAR nonce context and batch lifecycle
  - `unit/confirmTxFlow.successPaths.test.ts` register/sign/local‑only success
  - `unit/confirmTxFlow.defensivePaths.test.ts` cancel releases nonces, PRF errors
  - `unit/confirmTxFlow.determineConfirmationConfig.test.ts` override precedence
  - `unit/confirmTxFlow.common.helpers.test.ts` sanitization + summary parsing
  - `unit/awaitUserConfirmationV2.test.ts` error/abort/timeout/mismatch via worker global
  - `unit/overlayController.test.ts` hidden and viewport-modal rendering
  - `unit/handleSecureConfirmRequest.test.ts` request handler behavior

- Wallet Iframe
  - `wallet-iframe/handshake.test.ts` CONNECT→READY handshake
  - `wallet-iframe/router.behavior.test.ts` typed request-surface lifecycle
  - `unit/walletIframeSurfaceDomain.unit.test.ts` reducer arbitration and render coverage
  - `wallet-iframe/seamsAuthMenu.qrButton.overlay.test.ts` QR start regression (no wallet iframe reveal on click)

- Lit Components
  - `lit-components/confirm-ui.host-and-inline.test.ts` modal continuity and modal/drawer confirm/cancel
  - `lit-components/confirm-ui.handle.test.ts` handle.update/close DOM asserts
  - `lit-components/drawer.events.test.ts` drawer event contract

## Fixes & Learnings

- Use UserConfirm worker bundle for `awaitUserConfirmationV2`; read export from global, not `/sdk/esm` direct
- Target the iframe with `allow` containing `publickey-credentials` in tests
- Router hide asserts should check `aria-hidden` and 0×0 with opacity 0
- Registration challenge path may reuse bootstrap challenge in tests
- Multi‑iframe overlay selection: the example app (examples/vite) mounts its own wallet iframe via `PasskeyProvider`, so tests often see two wallet iframes. Naive selection picked the hidden 0×0 iframe and caused false “overlay not visible” failures. Fix:
  - Tag test‑owned iframes by constructing routers with `testOptions: { ownerTag: 'tests' }`.
  - Centralize selection in `captureOverlay()` (harness.ts): prefer `iframe[data-w3a-owner="tests"]`, else choose the interactive candidate (pointer‑enabled, opacity>0, not `aria-hidden`), else fall back to the newest candidate. Inline confirmer host also counts as visible.
  - Router now exposes `getIframeEl()` and `getOverlayState()` to aid diagnostics (test‑only usage).
- Test‑only options: router/transport accept a `testOptions` bag (`routerId`, `ownerTag`, `autoMount`) to aid Playwright without affecting app API.
- Handshake/WebAuthn bridge: replying to the requesting window with `'*'` target after origin validation removes transient `'null'` origin warnings on Safari‑like early navigation without weakening safety.

## Troubleshooting

### Wallet iframe READY timeout under COEP

Chromium enforces COEP. If the initial `CONNECT` is posted with `targetOrigin='*'`, the transferable `MessagePort` is discarded and `READY` never arrives.

To keep iframe tests stable:

- Post initial `CONNECT` to the exact wallet origin (for example `https://wallet.example.localhost`).

## Gaps & Next Steps

- Strengthen lifecycle assertions around sticky flows (handoff and final hide)
- Complete the Refactor 88 mutation self-check rows until
  `pnpm check:intended-mutation-self-check:complete` passes against fresh
  CI-managed intended startup or restarted local services
- Local‑only cancel flow should release nonce and emit structured error
- Theme regression guardrails for confirm UI (light vs dark tokens)
- Consider gating `data-w3a-router-id` to debug/test builds only (cosmetic)
- Optional: convenience `waitForOverlayShown/Hidden` helpers in harness (wrap `captureOverlay` + `waitFor`)
- Keep the wallet stub aligned with production host: adopt ports, reply to `PM_CANCEL` with `ERROR{ code: 'cancelled' }`, emit v2 `WalletFlowEvent` payloads with explicit `interaction.overlay` so overlay assertions have signal

If you update the handshake logic, re-run:

```bash
pnpm exec playwright test tests/wallet-iframe/playwright/handshake.test.ts --project=chromium
pnpm exec playwright test tests/e2e/cancel_overlay_specs.test.ts --project=chromium
```

These cover both the transport handshake and the overlay cancel contract that depends on the simulated progress events.
