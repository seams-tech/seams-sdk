# Refactor 86 Journal

## July 8, 2026

- Removed `seamsWasmMime()` and stopped composing it into the remaining Vite helper. The shared SDK static serving path now owns `.wasm` content type through `setContentType`, and hosted `dist/public` manifests verify `application/wasm`.
- Changed the remaining Vite app/wallet helper composition so dev headers are opt-in (`setDevHeaders === true`). The default wallet-service helper no longer emits COOP, COEP, CORP, CSP, or Permissions-Policy headers.
- Reduced `_headers` emission from `seamsBuildHeaders()` to explicit CORS and explicit strict-isolation output. It no longer emits default COOP, Permissions-Policy, wallet CSP, or wallet-route CORP.
- Added `tests/scripts/check-static-wallet-asset-boundaries.mjs` and wired it into `tests` source guards. The guard rejects `seamsWasmMime()`, default dev header composition, default wallet-service security headers, and default build-time CSP/COOP/Permissions behavior.
- Extended `assert-static-wallet-assets.mjs` so generated `headers.manifest.json` cannot require headers it declares forbidden, document CSP stays limited to `frame-ancestors`, and `/sdk/workers/` authority strings are confined to wallet-worker files or chunks reachable from wallet-host entrypoints.
- Added `tests/wallet-iframe/static-wallet-assets.browser.test.ts`, which serves `packages/sdk-web/dist/public`, loads the generated `/wallet-service` page, constructs every wallet worker as a module worker, and fetches/compiles every worker WASM companion from the static wallet origin.
- Replaced stale header tests that asserted plugin-era defaults with hosted-wallet assertions: app-origin `/wallet-service` no longer receives SDK plugin headers, default wallet-service serving emits no legacy isolation/CSP headers, and strict isolation appears only when requested.

Validation:

- `pnpm -C tests run check:static-wallet-asset-boundaries`
- `pnpm -C packages/sdk-web run check:static-wallet-assets`
- `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
- `pnpm -C packages/sdk-web run build:sdk`
- `pnpm -C tests exec playwright test --reporter=line wallet-iframe/static-wallet-assets.browser.test.ts wallet-iframe/csp.strict.violation-free.test.ts`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/vite-wallet-corp.unit.test.ts unit/pluginRorOrigins.unit.test.ts`
- `pnpm -C tests exec playwright test --reporter=line e2e/wallet-service-headers.test.ts`

## July 7, 2026

- Added build-owned hosted wallet asset emission for `packages/sdk-web/dist/public`, including `/sdk/*`, `/sdk/workers/*`, `/wallet-service`, `/export-viewer`, `wallet-assets.manifest.json`, and `headers.manifest.json`.
- Added static wallet asset verification that checks required routes, content-type/header metadata, worker/WASM companions, HTML references, JS literal imports, `new URL(..., import.meta.url)` references, CSS URLs, and sourcemap references.
- Added a plain static local-origin smoke that verifies app-origin wallet routes return 404 while wallet-origin static routes return 200 with expected content types.
- Removed stale build-path constants that pointed at `apps/seams-site/src/public/sdk`.
- Changed repo-local Caddy so `https://localhost:8443` serves `packages/sdk-web/dist/public` directly and app-origin `/sdk/*`, `/wallet-service`, and `/export-viewer` return 404.
- Removed `@seams/sdk/plugins/vite` from the site Vite config and related app-side env/type/path plumbing.
- Added wasm-pack fallback filenames for ETH and Tempo worker WASM (`eth_signer_bg.wasm`, `tempo_signer_bg.wasm`) to the worker/static asset output, because generated worker JS contains literal relative fallback URLs even though runtime initialization uses the normalized names.
- Wired hosted wallet static asset emission and validation into both `build:sdk` and `build:prod`.
- Added the current-config fail-closed boundary for configured iframe wallets: `iframeWallet.walletOrigin` must be present, while the wallet-host boundary uses an internal `allowDirectWalletMode: 'wallet_host'` option.
- Moved browser test SDK imports off app-origin `/sdk/esm/*` and onto a Playwright-only `/_test-sdk/esm/*` route backed by built SDK/server ESM files. The route also shims CSS side-effect imports as JS modules when loaded from browser ESM.
- Updated passkey menu fixtures that encoded obsolete empty-wallet-origin config and stale accessible names.
- Rewrote app-facing SDK/plugin/self-hosting docs to describe hosted wallet-origin assets directly and added a source guard against reintroducing app-owned plugin hosting examples.
- Moved `wallet-shims.js` and `wallet-service.css` into canonical source files under `src/static/wallet-assets`, then made Rolldown, the static asset build, and the remaining Vite helper consume those files. The static asset checker now fails if `dist/public/sdk` drifts from the source files.
- Ran the hosted-origin browser lifecycle smoke through the intended passkey unlock contract. It registered a wallet, cleared runtime state, unlocked, signed NEAR/Tempo/Arc transactions, exercised post-budget step-up, and exported Ed25519/ECDSA keys against the local app, wallet, and Router origins.
- Removed public package export subpaths for SDK plugin helpers and removed the virtual shim/CSS middleware from the remaining Vite helper. The hosted-wallet guard now rejects public plugin exports, duplicate shim/CSS source strings, and virtual shim/CSS serving.
- Disabled app-origin local worker warmup in iframe mode through an explicit local-worker warmup policy. `prewarm({ workers: true })` and `initWalletIframe()` no longer construct app-origin signer or passkey-confirm workers when hosted wallet iframe mode is configured.
- Added a fail-closed wallet iframe protocol-version handshake. The host advertises `WALLET_PROTOCOL_VERSION` in `READY`, and the client rejects mismatches with `WalletIframeProtocolVersionMismatchError`.
- Recorded `packages/sdk-web/scripts/checks/assert-hosted-wallet-docs.mjs` in the Refactor 89 source-guard ledger.

Validation:

- `pnpm --dir packages/sdk-web build:sdk`
- `pnpm --dir packages/sdk-web build:prod`
- `pnpm --dir packages/sdk-web check:static-wallet-assets`
- `pnpm --dir packages/sdk-web smoke:static-wallet-origin`
- `pnpm --dir packages/sdk-web build:check:fresh`
- `pnpm --dir apps/seams-site typecheck`
- `pnpm --dir apps/seams-site exec vite build`
- `SEAMS_WALLET_PUBLIC_ROOT=/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/dist/public caddy validate --config apps/seams-site/Caddyfile --adapter caddyfile`
- `pnpm --dir packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
- `pnpm --dir packages/sdk-web check:hosted-wallet-docs`
- `pnpm --dir packages/sdk-web build:check:fresh`
- `pnpm --dir tests exec playwright test tests/unit/configs.iframeWalletDisable.test.ts tests/unit/walletIframeHost.configGuards.test.ts tests/unit/seamsWeb.setTheme.unit.test.ts tests/unit/seamsWeb.namespacedSigningSurface.unit.test.ts tests/unit/theme.react.unit.test.ts --reporter=line`
- `pnpm --dir tests exec playwright test tests/unit/seamsAuthMenu.fouc.unit.test.ts --reporter=line`
- `pnpm --dir tests exec playwright test tests/wallet-iframe/handshake.test.ts --reporter=line`
- `pnpm --dir tests exec playwright test tests/unit/seamsWeb.initWalletIframe.concurrent.unit.test.ts --reporter=line`
- `pnpm --dir tests exec playwright test -c playwright.unit.config.ts tests/unit/packageExports.contract.unit.test.ts --reporter=line`
- `SEAMS_INTENDED_SKIP_BUILD=1 pnpm --dir tests exec playwright test -c playwright.intended.ci.config.ts tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line`
- `git diff --check`

Remaining parked or external gates:

- Refactor 90 Phase 0E owns replacing the current `iframeWallet` examples with `createSeamsConfig(...)` / `walletRuntime: hostedWalletIframe(...)` and moving the current named missing-origin error into the 0E config-error taxonomy.
- A full browser matrix for WebAuthn iframe `allow` behavior still needs Safari and Firefox coverage before documenting any app-origin `Permissions-Policy` requirement.
- Hosted `wallet.seams.sh` deployment still needs the Router/API-owned per-tenant embedding-authorization model; local static hosting uses the manifest's localhost `frame-ancestors` default.
