# Refactor 86: Static Wallet Assets And Vite Plugin Removal

Date created: July 1, 2026

Status: planning.

Parent plan: [Refactor 87 Modular Auth And Capability](./refactor-87-modular-auth-capabilities-plan.md)

## Goal

Make the wallet iframe runtime and WASM workers deployable from a Seams-hosted
wallet origin, so host applications do not need any Seams SDK Vite plugin or
SDK asset routing in their app `vite.config.ts`.

The SDK should publish a self-contained wallet asset tree for Seams-operated
wallet hosts such as `https://wallet.seams.sh`. App developers should configure
the hosted wallet iframe through the SDK runtime config from
[Refactor 87](./refactor-87-modular-auth-capabilities-plan.md), and never mount
`/sdk/*`, `/wallet-service`, or wallet workers inside their own app.

Developer contract:

- import the SDK from normal React/application code;
- configure environment ID, publishable key, and `walletRuntime:
  hostedWalletIframe(...)`;
- do not edit Vite config for Seams;
- do not run an extra wallet/static server;
- do not route or expose SDK wallet assets from the app.

## Runtime Invariants

These invariants must hold before removing the plugin from app usage:

- App-origin code must never instantiate signing workers, wallet WASM, export
  workers, or `/sdk/workers/*` URLs in iframe mode. The hosted wallet origin
  owns worker and WASM execution.
- App-origin warmup may preconnect or prefetch hosted wallet URLs. Warmup
  failures must be non-blocking and must not affect registration, unlock,
  export, or signing.
- The app origin must be allowed to return 404 for every `/sdk/*`,
  `/wallet-service`, and `/export-viewer` request while wallet flows still work.
- The wallet iframe must support passkey registration and login with the
  configured app RP ID and allowed origins. The SDK-created iframe `allow`
  attribute is the default WebAuthn delegation mechanism. An app-level
  `Permissions-Policy` header is required only if real-browser smokes prove a
  supported browser needs it.
- Export/private-key viewing must have one supported runtime path: hosted
  `/export-viewer` or a wallet-origin-owned inline document. Delete the unused
  path.
- Hosted wallet assets must be same-origin relative inside the wallet iframe.
  Worker JS and WASM must load by relative URLs from the hosted asset tree.
- Browser wallet capabilities must run through hosted iframe mode. Direct
  browser worker mode is outside the normal integration contract and must not be
  selected silently when `walletOrigin` is missing.
- App-origin package imports such as `@seams/sdk/react/styles` must continue to
  resolve through package exports. Removing the Vite plugin must not require app
  aliases or direct `dist/*` imports.

## Current State

The SDK build already emits the important runtime pieces:

- `packages/sdk-web/dist/esm/sdk/*.js`
- `packages/sdk-web/dist/esm/sdk/*.css`
- `packages/sdk-web/dist/workers/*.worker.js`
- `packages/sdk-web/dist/workers/*.wasm`

The Vite plugin currently also:

- serves `/sdk/*` from `@seams/sdk/dist`;
- serves `/wallet-service` HTML;
- serves virtual `wallet-shims.js` and `wallet-service.css`;
- forces `.wasm` MIME type;
- adds COOP, optional COEP/CORP, Permissions-Policy, and wallet
  Content-Security-Policy;
- serves `/.well-known/webauthn` in dev;
- emits `_headers`, `/wallet-service/index.html`, and `/export-viewer/index.html`.

That makes the plugin both a static file server and a security/header
integration. This is too much for app-level Vite config.

## Initial Plan Critique

The first idea was: publish static assets and make the plugin dev-only. That is
directionally correct, but incomplete.

Critique:

- Static files alone do not solve wallet runtime delivery. Wallet workers still
  need correct WASM MIME. Cross-origin WebAuthn delegation belongs to the app
  embedding boundary, preferably through the SDK-created iframe `allow`
  attribute.
- Worker scripts must be same-origin with the document creating them. The app
  cannot reliably create cross-origin module workers from the wallet origin.
  In iframe mode, worker construction must stay inside the wallet origin.
- The plugin and Rolldown config duplicate wallet shim/CSS generation. Moving to
  static assets without deduplicating that source would preserve bloat.
- Build output must be stable enough for Seams-operated wallet CDN/static
  hosting. A directory shape such as `dist/public/sdk` needs explicit copy rules
  and smoke checks.
- Existing build path constants still reference `apps/seams-site/src/public/sdk`.
  Those paths can mask app-origin `/sdk/*` mistakes and should be deleted or
  quarantined before negative-control smoke tests.
- Internal SDK development still needs a boring way to serve wallet origin
  assets. Removing the plugin before adding a Seams-owned static mount path
  would make `pnpm site` and manual testing worse.
- The current Caddy local wallet origin proxies the app Vite server. Hosted-only
  local dev needs the wallet origin to serve `dist/public` as static files so
  app Vite cannot accidentally satisfy wallet asset requests.
- Header generation belongs at deployment boundaries. It should be a helper or
  generated artifact, not hidden inside a broad `seamsWallet()` wrapper.
- COOP, COEP, and CORP are legacy strict-isolation headers for this flow. They
  should not be part of default wallet asset hosting after MPC signing moved
  into same-origin wallet workers.
- Content-Security-Policy is useful hardening, but it should not be part of the
  required/default wallet asset contract.
- `/.well-known/webauthn` is an RP/auth configuration endpoint, not a wallet
  asset concern. It should not remain coupled to static wallet asset hosting.

Addressed plan:

- Add a package-owned static wallet asset tree for deployment to the hosted
  wallet origin.
- Keep workers same-origin by serving the wallet iframe and `/sdk/workers/*`
  from the hosted wallet origin.
- Deduplicate generated wallet shim/CSS into one build-owned source.
- Dogfood static hosting through Caddy or another plain static mount before
  adding any new SDK dev helper.
- Remove the default Vite plugin requirement after the static route contract is
  proven.
- Move production behavior to files and platform-owned minimal headers.
- Keep dev convenience only where it does not make app Vite config own wallet
  internals.
- Keep COOP/COEP/CORP only in an optional strict-isolation profile, outside the
  default asset contract.
- Keep wallet HTML Content-Security-Policy only in an optional hardening
  profile, outside the default asset contract.

## Tangential Risk Remediation Matrix

All known plugin-removal risks are fixable. Treat this table as the checklist
for avoiding a plugin-free build that passes static checks while wallet runtime
flows fail.

| Risk | Remediation | Phase |
| --- | --- | --- |
| App-origin warmup constructs workers or loads WASM before iframe routing. | Move worker/WASM warmup behind wallet-host execution. Keep app-origin warmup to `preconnect`, `prefetch`, and iframe boot hints only. | Phase 1, Phase 7 |
| Missing `walletOrigin` silently selects direct browser worker mode. | Make hosted iframe mode the browser wallet capability contract. Throw a clear config/use-boundary error when browser wallet capability code runs without `walletOrigin`. Keep any direct mode as explicit internal/test-only code. | Phase 1, Phase 5, Phase 7 |
| Local Caddy proxies wallet origin to app Vite, masking app-origin `/sdk/*` use. | Serve `packages/sdk-web/dist/public` directly from `https://localhost:8443` during repo-local smoke. The app Vite server should never satisfy wallet asset requests. | Phase 3 |
| Build constants copy or reference `apps/seams-site/src/public/sdk`. | Delete those constants/scripts when unused. If a test still needs them temporarily, quarantine them under test-only naming and block production/app examples from using them. | Phase 2, Phase 7 |
| Export viewer has both hosted-page and `srcdoc` paths. | Pick one runtime path and delete the other. The shorter fix is to keep the current `srcdoc` only if it is wallet-origin-owned and passes app-origin `/sdk/* = 404`; otherwise move export to hosted `/export-viewer`. | Phase 1, Phase 3 |
| Lit component CSS falls back to app-origin `/sdk/*`. | Ensure wallet-hosted flows set an absolute SDK base before Lit/export components load. Add a smoke where app-origin `/sdk/*` returns 404 and confirmation/export styling still loads. | Phase 1, Phase 7 |
| Header tests still assert plugin-era CSP/COOP/COEP/CORP behavior. | Replace them with hosted wallet `headers.manifest.json` tests and browser smokes. Keep strict-isolation tests only under an explicit optional profile. | Phase 7 |
| `@seams/sdk/plugins/vite` and `@seams/sdk/plugins/next` keep teaching app-owned runtime hosting. | Remove app-facing examples. Keep only package-internal/static-build helpers that emit hosted wallet artifacts, or delete plugin exports after consumers stop importing them. | Phase 5, Phase 6, Phase 7 |
| App package imports depended on Vite plugin aliases or direct dist paths. | Add package export smoke for `@seams/sdk/react`, `@seams/sdk/react/provider`, `@seams/sdk/react/styles`, and `@seams/sdk/advanced` with a minimal app Vite config. | Phase 2, Phase 3 |
| `/.well-known/webauthn` disappears with the plugin. | Keep it owned by Router/API/auth dev helper. It is RP/auth configuration, not wallet static asset hosting. | Phase 1, Phase 6 |

Remaining decisions:

- [ ] Browser WebAuthn policy: run Chrome, Safari, and Firefox smokes with
      iframe `allow` and no app-origin `Permissions-Policy`. If a supported
      browser fails, document the smallest required app platform header:
      `Permissions-Policy: publickey-credentials-get=(self "https://wallet.seams.sh"), publickey-credentials-create=(self "https://wallet.seams.sh")`.
- [x] Export viewer shape decision: start with the current wallet-origin
      `srcdoc` path. Keep it only if it passes app-origin `/sdk/* = 404`;
      otherwise move export to hosted `/export-viewer` and delete `srcdoc`.
- [x] Direct mode policy decision: hosted iframe mode is required for browser
      wallet capabilities. Missing `walletOrigin` must fail clearly at
      config/use boundary. Any remaining direct browser worker mode is
      internal/test-only.

## Implementation Preconditions

- [ ] Commit or stage this plan before implementation; the file is currently a
      planning artifact and must not be lost.
- [ ] Make the first implementation slice the harsh local smoke:
      - app origin has no Seams SDK Vite plugin;
      - app origin returns 404 for `/sdk/*`, `/wallet-service`, and
        `/export-viewer`;
      - wallet origin serves `packages/sdk-web/dist/public` directly;
      - registration, unlock, NEAR signing, ECDSA signing, and export pass
        through the hosted wallet origin.
- [ ] Enforce direct-mode policy before removing plugin routes:
      - browser wallet capability setup requires hosted iframe mode;
      - missing `walletOrigin` throws a clear error;
      - tests that intentionally use direct mode must opt into an
        internal/test-only path.
- [ ] Keep the export viewer as wallet-origin `srcdoc` for the first pass and
      prove it works under app-origin `/sdk/* = 404`. If it fails, switch to
      hosted `/export-viewer` in the same phase and delete the `srcdoc` path.
- [ ] Run WebAuthn iframe `allow` smokes before documenting any app-origin
      `Permissions-Policy` requirement.

## Target Shape

Seams wallet host deployment artifact:

```txt
@seams/sdk/dist/public/
  sdk/
    wallet-shims.js
    wallet-service.css
    wallet-iframe-host-runtime.js
    wallet-iframe-host-full.js
    wallet-iframe-host-near.js
    wallet-iframe-host-ecdsa.js
    export-private-key-viewer.js
    iframe-export-bootstrap.js
    *.css
    workers/
      near-signer.worker.js
      hss-client.worker.js
      passkey-confirm.worker.js
      email-otp.worker.js
      eth-signer.worker.js
      tempo-signer.worker.js
      *.wasm
    chunks-and-css-loaded-by-sdk-entries
  wallet-service/
    index.html
  export-viewer/
    index.html
  wallet-assets.manifest.json
  headers.manifest.json
```

Seams hosted wallet-origin responsibility:

```txt
GET https://wallet.seams.sh/sdk/*          -> dist/public/sdk/*
GET https://wallet.seams.sh/wallet-service -> dist/public/wallet-service/index.html
GET https://wallet.seams.sh/export-viewer  -> dist/public/export-viewer/index.html
```

App developer responsibility:

```ts
createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  walletRuntime: hostedWalletIframe({
    origin: 'https://wallet.seams.sh',
  }),
  authMethods: [
    passkeyAuth(),
  ],
  capabilities: [
    nearEd25519MpcSigning(),
    evmFamilyEcdsaMpcSigning(),
  ],
});
```

App developers do not serve `/sdk/*`, `/wallet-service`, `/export-viewer`, or
wallet worker/WASM files. Local app development uses the same hosted wallet
origin.

`hostedWalletIframe(...)` is SDK runtime configuration, independent of Vite,
Next, and framework build hooks. Refactor 86 owns the hosted asset contract;
Refactor 87 owns the typed SDK runtime surface and capability dependency
validation.

Minimal app `vite.config.ts`:

```ts
plugins: [react()]
```

Internal repo-local dev should first serve `dist/public` with Caddy or a plain
static mount owned by the Seams dev environment. Do not add an SDK
`seamsStaticWalletDev()` helper unless plain static hosting leaves repeated
setup in multiple Seams-owned local-dev consumers.

`/.well-known/webauthn` ownership: Router/API or an explicit auth dev helper.
Static wallet asset hosting does not serve RP/auth configuration.

## Phased Todo List

### Phase 1: Asset Contract And Manifest

Goal: define the exact static asset contract before changing build output.

Tasks:

- [ ] Inventory every runtime URL under `/sdk/*`, `/sdk/workers/*`,
      `/wallet-service`, and `/export-viewer`.
- [ ] Record which files are loaded by wallet iframe HTML, confirm/export UI,
      workers, WASM bindgen loaders, and preconnect/prewarm code.
- [ ] Inventory every caller of `warmCriticalResources`, worker construction,
      WASM URL resolution, export viewer creation, and wallet iframe creation.
      Mark whether it runs on app origin or wallet origin.
- [ ] Inventory direct browser wallet mode call paths. Decide whether to delete
      direct mode for browser wallet capabilities or make it an explicit
      internal/test-only mode that cannot be selected by missing `walletOrigin`.
- [ ] Inventory package-level imports that app code uses without the plugin:
      `@seams/sdk/react`, `@seams/sdk/react/provider`,
      `@seams/sdk/react/styles`, and `@seams/sdk/advanced`.
- [ ] Document required response headers per route group:
      `/wallet-service`, `/export-viewer`, `/sdk/*.js`, `/sdk/*.css`,
      `/sdk/workers/*.worker.js`, and `/sdk/workers/*.wasm`.
- [ ] Confirm the default required headers are only:
      - correct `Content-Type`, especially `application/wasm`;
      - cache policy.
- [ ] Verify the SDK-created wallet iframe sets the required WebAuthn
      delegation attributes for hosted wallet-origin use.
- [ ] Treat iframe `allow` as the primary WebAuthn delegation mechanism:
      - `publickey-credentials-get`;
      - `publickey-credentials-create`;
      - clipboard permissions needed by copy/export UI.
- [ ] Move or gate any app-origin warmup that constructs workers or loads WASM.
      App-origin warmup may only create non-blocking network hints.
- [ ] Remove SDK/plugin-owned `Permissions-Policy` header injection from normal
      app integration. The SDK owns iframe `allow`; app platforms own any HTTP
      header that a browser truly requires.
- [ ] Test passkey registration and login in Chrome, Safari, and Firefox with
      the app origin serving normal app headers only and the iframe carrying
      the SDK `allow` attribute.
- [ ] If a supported browser fails without HTTP `Permissions-Policy`, document
      the smallest required app platform header and keep it outside SDK Vite
      plugin behavior and wallet static asset hosting.
- [ ] Decide the export/private-key viewer shape and delete the unused path:
      hosted `/export-viewer` or wallet-origin-owned inline viewer.
- [ ] Confirm Lit component CSS base resolution never falls back to app-origin
      `/sdk/*` during iframe-hosted confirmation/export flows.
- [ ] Remove `Content-Security-Policy` from the default
      `headers.manifest.json`.
- [ ] Mark wallet HTML Content-Security-Policy as optional production hardening,
      outside the default header profile.
- [ ] Remove `Cross-Origin-Embedder-Policy`,
      `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy` from the
      default `headers.manifest.json`.
- [ ] If strict cross-origin isolation is still useful for tests, model it as a
      separate optional header profile, not the default.
- [ ] Define `wallet-assets.manifest.json` with `route`, `sourceFile`,
      `contentType`, `cachePolicy`, `requiredHeaders`, and `owner`.
- [ ] Define `headers.manifest.json` with the platform-independent header
      contract.
- [ ] Assign `/.well-known/webauthn` to Router/API or a dedicated auth dev
      helper.

Acceptance:

- [ ] `wallet-assets.manifest.json` lists every required static route.
- [ ] `headers.manifest.json` lists every required route header.
- [ ] The manifest names which runtime code depends on each route.

### Phase 2: Build-Owned Static Asset Tree

Goal: make `@seams/sdk` publish the wallet runtime as static files for the
hosted wallet origin deploy.

Tasks:

- [ ] Add a build step that creates `dist/public/sdk`.
- [ ] Copy `dist/esm/sdk/*` into `dist/public/sdk/*`.
- [ ] Copy `dist/workers/*` into `dist/public/sdk/workers/*`.
- [ ] Delete or quarantine build constants and scripts that copy SDK workers into
      `apps/seams-site/src/public/sdk`. App public assets must not provide a
      hidden fallback for wallet workers.
- [ ] Emit `dist/public/wallet-service/index.html` using the existing wallet
      HTML builder.
- [ ] Emit `dist/public/export-viewer/index.html` using the existing export
      viewer HTML builder.
- [ ] Emit `dist/public/wallet-assets.manifest.json`.
- [ ] Emit `dist/public/headers.manifest.json`.
- [ ] Add a build check that fails when any worker JS lacks its paired WASM file.
- [ ] Add a build check that resolves every import referenced by wallet HTML,
      SDK entry chunks, worker scripts, and CSS from `dist/public`.
- [ ] Ensure WASM workers locate their `.wasm` files by stable relative URLs
      from the worker/static asset location.
- [ ] Add a build/browser check that loads the generated wallet-service page,
      instantiates every wallet worker, and verifies each worker can load its
      paired WASM from `dist/public`.
- [ ] Add a build check that rejects generated wallet runtime JS with
      app-origin `/sdk/workers/` authority assumptions outside wallet-hosted
      entrypoints.
- [ ] Add a package export smoke that imports:
      - `@seams/sdk/react`;
      - `@seams/sdk/react/provider`;
      - `@seams/sdk/react/styles`;
      - `@seams/sdk/advanced`.

Acceptance:

- [ ] `pnpm -C packages/sdk-web build:sdk` creates a complete
      `dist/public` tree.
- [ ] The hosted wallet deploy can publish `dist/public` directly.
- [ ] The static tree is a packaging copy of existing build output, with no new
      runtime URL scheme introduced in this phase.
- [ ] A browser can load worker JS and the worker can load its WASM without a
      Vite plugin.

### Phase 3: Static Smoke And Repo Dogfood

Goal: prove hosted-origin static serving before shrinking SDK plugins.

Tasks:

- [ ] Add `packages/sdk-web/scripts/checks/assert-static-wallet-assets.mjs`.
- [ ] Make the smoke check read `wallet-assets.manifest.json` and verify file
      existence, content type expectations, and required header metadata.
- [ ] Serve wallet assets for `pnpm site` through a Seams-owned Caddy/static
      wallet origin from `packages/sdk-web/dist/public`.
- [ ] Change repo-local Caddy so `https://localhost:8443` serves
      `packages/sdk-web/dist/public` directly instead of reverse-proxying the
      app Vite server.
- [ ] Remove `seamsWallet(...)` from `apps/seams-site/vite.config.ts`.
- [ ] Keep app-origin Vite config limited to React, aliases, and app-owned
      settings.
- [ ] Verify the demo app SDK initialization uses the hosted wallet origin and
      does not depend on local app-hosted `/sdk/*`.
- [ ] Force app-origin `/sdk/*`, `/wallet-service`, and `/export-viewer` to
      return 404 during smoke tests.
- [ ] Ensure `pnpm site` still serves:
      - `https://localhost/`;
      - `https://localhost:8443/wallet-service`;
      - `https://localhost:8443/sdk/workers/near-signer.worker.js`;
      - `https://localhost:8443/sdk/workers/wasm_signer_worker_bg.wasm`.
- [ ] Verify the export/private-key viewer path selected in Phase 1 works from
      the hosted wallet origin.
- [ ] Verify failed app-origin preconnect/prefetch hints do not block wallet
      initialization.
- [ ] Verify app-origin package imports and CSS still load with a minimal Vite
      config and no SDK-specific aliases beyond normal workspace/package
      resolution.

Acceptance:

- [ ] `apps/seams-site/vite.config.ts` no longer imports
      `@seams/sdk/plugins/vite` for wallet hosting.
- [ ] The app can register, unlock, and sign by importing SDK code in React only.
- [ ] Static smoke test passes against `dist/public`.
- [ ] Manual registration, unlock, NEAR signing, and EVM signing load wallet
      iframe workers from the Seams-owned wallet origin.

### Phase 4: Deduplicate Shim And Surface CSS Generation

Goal: remove duplicated wallet shim/CSS sources.

Tasks:

- [ ] Move `wallet-shims.js` source to one build-owned helper.
- [ ] Move `wallet-service.css` source to one build-owned helper.
- [ ] Make Rolldown/static build and Vite dev serving read the same generated
      files.
- [ ] Delete duplicate `WALLET_SHIM_SOURCE` and `WALLET_SURFACE_CSS`
      definitions from `packages/sdk-web/src/plugins/vite.ts` if the files can
      be read from `dist/public/sdk`.
- [ ] Prefer normal source files for `wallet-shims.js` and `wallet-service.css`
      if that is shorter than generated string content.

Acceptance:

- [ ] There is one source of truth for wallet shim JS.
- [ ] There is one source of truth for wallet service CSS.

### Phase 5: Remove Runtime Vite Plugin Requirement

Goal: make wallet runtime delivery plugin-free.

Tasks:

- [ ] Avoid adding `seamsStaticWalletDev(...)` unless Caddy/plain static hosting
      leaves repeated setup in more than one Seams-owned local-dev consumer.
- [ ] Remove app/runtime dependence on `seamsWallet()`, `seamsServeSdk()`,
      `seamsWalletService()`, and `seamsWasmMime()`.
- [ ] Remove public app-facing `@seams/sdk/plugins/vite` usage from examples and
      app docs. Keep only package-internal/static-build helpers that are still
      needed to emit the hosted wallet artifact.
- [ ] Review `@seams/sdk/plugins/next`; remove or rewrite any guidance that
      makes app frameworks responsible for wallet asset hosting or default CSP
      headers.
- [ ] Make browser wallet capability setup require hosted iframe mode. Missing
      `walletOrigin` should fail at config/use boundary with a clear error
      instead of selecting direct app-origin workers.
- [ ] Route browser wallet capability setup through the Refactor 87
      `walletRuntime: hostedWalletIframe(...)` SDK runtime config. Keep any legacy
      `iframeWallet` config normalization at the public config boundary only,
      then delete it when the runtime config replaces examples and tests.
- [ ] If any helpers remain, keep them as examples or optional dev utilities
      for Seams-owned wallet-origin development only.
- [ ] Remove build-time `_headers` emission from app Vite plugin usage.
- [ ] Remove `seamsWasmMime()` if static file serving sets MIME correctly
      through the shared static mount.
- [ ] Remove default `Cross-Origin-Embedder-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [ ] Remove default `Cross-Origin-Opener-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [ ] Remove default `Cross-Origin-Resource-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [ ] Remove default `Content-Security-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [ ] Keep any remaining COOP/COEP/CORP code behind an explicit strict-isolation
      option, or delete it if no current test/runtime path needs it.
- [ ] Keep any remaining wallet HTML CSP generation behind an explicit hardening
      option, or delete it if no current deployment path needs it.
- [ ] Remove debug routes from default app usage.
- [ ] Delete virtual `/sdk/wallet-shims.js` and `/sdk/wallet-service.css`
      serving once files come from `dist/public/sdk`.

Acceptance:

- [ ] Host app Vite config uses no `@seams/sdk/plugins/vite` import.
- [ ] Local wallet-origin dev can still mount the static wallet assets with one
      Seams-owned plain static mount.
- [ ] Wallet runtime delivery succeeds with no Seams SDK Vite plugin.

### Phase 6: Documentation And Deployment Guidance

Goal: make integrator setup boring.

Tasks:

- [ ] Update `packages/sdk-web/src/plugins/README.md` to state app developers use
      the hosted wallet origin and do not configure SDK Vite plugins.
- [ ] Update React/getting-started docs so the normal setup is only:
      install package, import SDK/components, configure environment ID,
      publishable key, `walletRuntime: hostedWalletIframe(...)`, auth methods,
      and requested capabilities.
- [ ] Update `docs/saas/self-hosted-migration.md` to remove app-owned wallet
      asset hosting from the normal integration path.
- [ ] Document the Seams wallet-origin deployment contract for
      `https://wallet.seams.sh`.
- [ ] Document hosted wallet iframe embedding requirements, including any iframe
      `allow` attributes.
- [ ] Document app-origin WebAuthn `Permissions-Policy` only if browser smokes
      prove it is required. Present it as app platform configuration, not SDK
      Vite plugin setup.
- [ ] Document COOP/COEP/CORP as legacy/optional strict-isolation headers, not
      default wallet asset requirements.
- [ ] Document wallet HTML Content-Security-Policy as optional production
      hardening, not a default wallet asset requirement.
- [ ] Generate platform-specific docs snippets from `headers.manifest.json`.
- [ ] Document internal Seams local-dev recipes:
      - app origin on local Vite;
      - wallet origin on Seams-owned Caddy/static server;
      - Router/API on local Router.
- [ ] Document `/.well-known/webauthn` as Router/API/auth-server
      configuration.
- [ ] Document that app developers should not serve or reverse-proxy
      `@seams/sdk/dist/public`.
- [ ] Document that app developers should not run a wallet static server in
      local development.
- [ ] Update stale runtime-path comments and docs that still describe COOP,
      COEP, CORP, CSP, app-origin `/sdk/*`, or app-origin worker hosting as
      required.
- [ ] Decide whether custom CNAME wallet origins are Seams-managed hosted
      wallet origins. If supported, document them as Seams-operated hosting,
      not app-owned asset serving.
- [ ] If optional helper examples remain, present them as Seams-internal
      development utilities.

Acceptance:

- [ ] A new integrator can use the SDK without hosting wallet assets and without
      editing Vite config.
- [ ] A new React integrator can use the SDK by importing package code and
      setting SDK configuration only.
- [ ] Local app development does not require an extra wallet/static server.
- [ ] Hosted wallet-origin headers and app embedding requirements are explicit
      and testable.

### Phase 7: Guards And Cleanup

Goal: keep the plugin from growing back into a framework runtime.

Tasks:

- [ ] Add a source guard that rejects app examples requiring `seamsWallet()` for
      ordinary app pages.
- [ ] Add a source guard that rejects app examples importing
      `@seams/sdk/plugins/vite` for wallet runtime hosting.
- [ ] Add a source guard that rejects app framework examples importing
      `@seams/sdk/plugins/next` for wallet runtime hosting.
- [ ] Add a source guard that rejects app examples serving `/sdk/*`,
      `/wallet-service`, or `/export-viewer` from app-owned infrastructure.
- [ ] Add a source guard that rejects app examples instructing developers to run
      a local wallet static server.
- [ ] Add a source guard that rejects duplicate wallet shim/CSS source strings.
- [ ] Add a static asset smoke test that loads wallet HTML, a worker JS file,
      and a WASM file from `dist/public`.
- [ ] Replace stale wallet-service header tests that assert default CSP,
      COOP/COEP/CORP, or app plugin behavior with hosted-wallet header manifest
      tests.
- [ ] Add browser WebAuthn delegation smokes:
      - app origin has no SDK-generated `Permissions-Policy`;
      - wallet iframe has SDK-generated `allow`;
      - passkey registration succeeds in Chrome, Safari, and Firefox where
        supported;
      - passkey login succeeds in Chrome, Safari, and Firefox where supported.
- [ ] Add a negative-control browser smoke that removes iframe `allow` and
      expects cross-origin WebAuthn to fail.
- [ ] Add a browser smoke that denies app-origin `/sdk/*`, `/wallet-service`,
      and `/export-viewer`, then completes registration, unlock, NEAR signing,
      ECDSA signing, and export through the hosted wallet origin.
- [ ] Add a targeted test proving iframe-mode app-origin warmup does not
      construct workers or load WASM.
- [ ] Add a config test proving browser wallet capabilities cannot silently fall
      back to direct app-origin worker mode when `walletOrigin` is omitted.
- [ ] Delete stale docs that recommend broad `seamsWallet()` app integration.
- [ ] Delete `seamsWasmMime()` if no remaining route needs it.
- [ ] Delete virtual shim/CSS middleware from `packages/sdk-web/src/plugins/vite.ts`
      after static files serve those assets.
- [ ] Delete default debug routes from app examples.
- [ ] Add a source guard that rejects default COOP/COEP/CORP emission in app or
      wallet static hosting helpers.
- [ ] Add a source guard that rejects default Content-Security-Policy emission in
      app or wallet static hosting helpers.

Acceptance:

- [ ] Source guards pass.
- [ ] Static asset smoke test passes.
- [ ] Plugin docs no longer describe any Seams Vite plugin as required runtime
      infrastructure.
- [ ] Public app examples contain no SDK Vite plugin setup and no wallet static
      server setup.
- [ ] Default generated docs/header manifests contain no
      `Cross-Origin-Embedder-Policy`, `Cross-Origin-Opener-Policy`, or
      `Cross-Origin-Resource-Policy`.
- [ ] Default generated docs/header manifests contain no
      `Content-Security-Policy`.

## Open Questions

- Should static entry file names stay stable while imported chunks remain
  generated filenames?
- Should direct no-iframe mode eventually use bundler-owned
  `new Worker(new URL(..., import.meta.url))` instead of `/sdk/workers/*`?
- Can `wallet-service.css` and `wallet-shims.js` become normal source files
  without increasing build glue?
- Can all Vite plugin exports be deleted after the repo dogfoods hosted-origin
  static serving, or should a tiny Seams-internal helper remain?

## Validation Plan

```sh
pnpm -C packages/sdk-web build:sdk
node packages/sdk-web/scripts/checks/assert-static-wallet-assets.mjs
pnpm site
```

Manual checks:

- open `https://localhost`;
- open `https://localhost:8443/wallet-service`;
- confirm `https://localhost/sdk/wallet-iframe-host-runtime.js` returns 404
  during hosted-origin smoke;
- confirm `https://localhost/wallet-service` returns 404 during hosted-origin
  smoke;
- confirm `https://localhost/export-viewer` returns 404 during hosted-origin
  smoke;
- fetch `https://localhost:8443/sdk/workers/near-signer.worker.js`;
- fetch `https://localhost:8443/sdk/workers/wasm_signer_worker_bg.wasm` and
  confirm `Content-Type: application/wasm`;
- confirm `https://localhost:8443` serves static wallet assets from
  `packages/sdk-web/dist/public`, not the app Vite server;
- import `@seams/sdk/react/styles` from the app with no SDK Vite plugin;
- verify app responses do not include SDK-generated `Permissions-Policy`;
- verify wallet iframe contains `allow` entries for
  `publickey-credentials-get` and `publickey-credentials-create`;
- register a wallet;
- unlock the wallet after reload;
- sign one NEAR transaction and one EVM transaction.
- export one key through the selected export viewer path.
