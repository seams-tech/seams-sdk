# Refactor 86: Static Wallet Assets And Vite Plugin Removal

Date created: July 1, 2026
Updated: July 3, 2026 — review added the version-skew contract, embedding
authorization, `/.well-known/webauthn` ownership correction, storage
partitioning, and sequencing gates.
Updated: July 4, 2026 — decoupled from Refactor 90 for the stabilization
milestone: Phase 5 split into 5a (plugin removal on the current
`iframeWallet` config) and 5b (0E config adoption, parked); Phase 6 split the
same way; embedding control two-staged with a named server owner.
Updated: July 7, 2026 — implemented the stabilization slice: build-owned
static wallet assets, repo dogfood through a wallet-origin static mount,
plugin-free app serving, direct-mode fail-closed behavior, protocol-version
handshake, package export cleanup, and source/static guards. The 0E config
surface, full browser matrix, and hosted per-tenant embedding authorization
remain parked/open as noted below.
Updated: July 8, 2026 — removed the remaining Vite helper default header/MIME
paths, added generated static asset authority/header guards, and added a
browser static-wallet worker/WASM smoke against `dist/public`.

Status: stabilization implementation complete for the checked Phase 1-5a and
Phase 7 items. Phase 5b and 6b park on Refactor 90; Safari/Firefox WebAuthn
policy and hosted `sign.seams.sh` per-tenant embedding authorization remain
external gates.

Sequencing gates:

- Phases 1, 1B, and 2 are independent and can start now, in parallel with the
  stabilization tracks. This plan owns build/plugin/Caddy files no other
  in-flight plan touches.
- Phase 3 (the local dogfood flip to static wallet-origin serving) runs after
  Refactor 88's `test:intended` is fully mandatory and green, so the topology
  flip lands under the lifecycle gate and app-origin `/sdk/*` leaks fail
  contracts immediately.
- Refactor 83 Phase 1 registration baselines are captured before Phase 3
  flips local serving, or the serving topology is recorded beside the
  numbers; a topology change mid-measurement contaminates the comparison.
- Phase 5a and Phase 6a use the current `iframeWallet` config surface and are
  stabilization-scoped. Phase 5b and Phase 6b are parked on Refactor 90
  Phase 0E (`createSeamsConfig` / `walletRuntime: hostedWalletIframe(...)`
  and its typed config-error taxonomy).
- Browser passkey smokes reuse the Refactor 84a wallet-binding scenarios
  rather than a parallel suite.

Dated progress entries and validation evidence go to a companion journal file
(`refactor-86-journal.md`, created on first entry), not this plan.

Parent plan: [Refactor 90 Modular Auth And Capability](./refactor-90-modular-auth-capabilities-plan.md)

## Goal

Make the wallet iframe runtime and WASM workers deployable from a Seams-hosted
wallet origin, so host applications do not need any Seams SDK Vite plugin or
SDK asset routing in their app `vite.config.ts`.

The SDK should publish a self-contained wallet asset tree for Seams-operated
wallet hosts such as `https://sign.seams.sh`. App developers configure the
hosted wallet iframe through SDK config — the existing `iframeWallet` surface
during stabilization (Phase 5a), the Refactor 90 Phase 0E
`walletRuntime: hostedWalletIframe(...)` surface once 0E lands (Phase 5b) —
and never mount `/sdk/*`, `/wallet-service`, or wallet workers inside their
own app. Plugin removal is about asset serving, not config API shape: the
current config already carries `walletOrigin`, `servicePath`, `sdkBasePath`,
`walletHostVariant`, and `rpId`, which is everything Phase 5a needs.

Developer contract:

- import the SDK from normal React/application code;
- configure environment ID, publishable key, and the hosted wallet iframe
  (current `iframeWallet` config now; `walletRuntime: hostedWalletIframe(...)`
  after 0E);
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
- The app origin must be allowed to return 404 for every `/sdk/*` and
  `/wallet-service` request while wallet flows still work.
- The wallet iframe must support passkey registration and login with the
  configured app RP ID and allowed origins. The SDK-created iframe `allow`
  attribute is the default WebAuthn delegation mechanism. An app-level
  `Permissions-Policy` header is required only if real-browser smokes prove a
  supported browser needs it.
- Export/private-key viewing has one supported runtime path: a
  wallet-origin-owned inline document. The hosted `/export-viewer` page is
  deleted.
- Hosted wallet assets must be same-origin relative inside the wallet iframe.
  Worker JS and WASM must load by relative URLs from the hosted asset tree.
- Browser wallet capabilities must run through hosted iframe mode. Direct
  browser worker mode is outside the normal integration contract and must not be
  selected silently when `walletOrigin` is missing.
- App-origin package imports such as `@seams/sdk/react/styles` must continue to
  resolve through package exports. Removing the Vite plugin must not require app
  aliases or direct `dist/*` imports.
- The app-side SDK version and the hosted wallet runtime version must be
  pinned to each other (versioned asset paths) or handshake-checked at iframe
  boot. A mismatch fails closed with a typed error; the postMessage protocol
  must never silently drift under an older app SDK.
- The `/wallet-service` document must not be embeddable by arbitrary origins.
  Default embedding control on the wallet document is part of the asset
  contract; postMessage origin checks protect the channel, not the rendered
  confirm UI.

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
- emits `_headers` and `/wallet-service/index.html`.

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
- `/.well-known/webauthn` is not a wallet asset concern — and it is not a
  Router/API concern either. It is the WebAuthn Related Origin Requests file,
  which the browser fetches from the RP ID origin (normally the app's domain)
  when the wallet origin calls WebAuthn with the app's `rpId`. In production
  it is app-platform configuration, the same bucket as any required
  `Permissions-Policy` header; Router/API or an auth dev helper serves it only
  in local development where `rpId=localhost`.

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

## Risk Remediation Matrix

All known plugin-removal risks are fixable. Treat this table as the checklist
for avoiding a plugin-free build that passes static checks while wallet runtime
flows fail.

| Risk | Remediation | Phase |
| --- | --- | --- |
| App-origin warmup constructs workers or loads WASM before iframe routing. | Move worker/WASM warmup behind wallet-host execution. Keep app-origin warmup to `preconnect`, `prefetch`, and iframe boot hints only. | Phase 1, Phase 7 |
| Missing `walletOrigin` silently selects direct browser worker mode. | Make hosted iframe mode the browser wallet capability contract. Throw a clear config/use-boundary error when browser wallet capability code runs without `walletOrigin`. Keep any direct mode as explicit internal/test-only code. | Phase 1, Phase 5, Phase 7 |
| Local Caddy proxies wallet origin to app Vite, masking app-origin `/sdk/*` use. | Serve `packages/sdk-web/dist/public` directly from `https://localhost:8443` during repo-local smoke. The app Vite server should never satisfy wallet asset requests. | Phase 3 |
| Build constants copy or reference `apps/seams-site/src/public/sdk`. | Delete those constants/scripts when unused. If a test still needs them temporarily, quarantine them under test-only naming and block production/app examples from using them. | Phase 2, Phase 7 |
| Export viewer has both hosted-page and `srcdoc` paths. | Keep the current wallet-origin `srcdoc` runtime and delete the hosted `/export-viewer` route. Prove export works while app-origin `/sdk/*` returns 404. | Phase 1, Phase 3 |
| Lit component CSS falls back to app-origin `/sdk/*`. | Ensure wallet-hosted flows set an absolute SDK base before Lit/export components load. Add a smoke where app-origin `/sdk/*` returns 404 and confirmation/export styling still loads. | Phase 1, Phase 7 |
| Header tests still assert plugin-era CSP/COOP/COEP/CORP behavior. | Replace them with hosted wallet `headers.manifest.json` tests and browser smokes. Keep strict-isolation tests only under an explicit optional profile. | Phase 7 |
| `@seams/sdk/plugins/vite` and `@seams/sdk/plugins/next` keep teaching app-owned runtime hosting. | Remove app-facing examples. Keep only package-internal/static-build helpers that emit hosted wallet artifacts, or delete plugin exports after consumers stop importing them. | Phase 5, Phase 6, Phase 7 |
| App package imports depended on Vite plugin aliases or direct dist paths. | Add package export smoke for `@seams/sdk/react`, `@seams/sdk/react/provider`, `@seams/sdk/react/styles`, and `@seams/sdk/advanced` with a minimal app Vite config. | Phase 2, Phase 3 |
| `/.well-known/webauthn` disappears with the plugin. | It is the WebAuthn Related Origin Requests file, served at the RP ID origin — app-platform configuration in production (the app's domain, not Router/API). Router/auth dev helper serves it only in local dev where `rpId=localhost`. | Phase 1, Phase 6 |
| App SDK version and hosted wallet runtime version drift apart, breaking the postMessage protocol under older app SDKs. | Version the asset tree (`/v{sdkVersion}/sdk/*` pinned through `sdkBasePath`) and/or add an iframe boot protocol-version handshake that fails closed with a typed error. Decide with the cache/naming strategy. | Phase 1, Phase 2, Phase 7 |
| Arbitrary origins embed `/wallet-service` and clickjack or context-spoof the confirm UI. | Default embedding control on the wallet-service document (`frame-ancestors` or equivalent), driven by the per-tenant embedding-authorization model. postMessage origin checks protect the channel, not the rendered UI. | Phase 1, Phase 7 |
| Browser storage partitioning silently changes local-material expectations: wallet-origin IndexedDB is partitioned by top-level site, so material cached under one app does not exist under another. | Document the partitioned-storage model per browser, confirm restore/re-registration UX from a second app is acceptable, and record the implications against Refactor 85's local-material assumptions. | Phase 1 |

Remaining decisions:

- [ ] Browser WebAuthn policy: run Chrome, Safari, and Firefox smokes with
      iframe `allow` and no app-origin `Permissions-Policy`. If a supported
      browser fails, document the smallest required app platform header:
      `Permissions-Policy: publickey-credentials-get=(self "https://sign.seams.sh"), publickey-credentials-create=(self "https://sign.seams.sh")`.
- [x] Export viewer shape decision: use the current wallet-origin `srcdoc`
      path. It passes app-origin `/sdk/* = 404`, so the hosted `/export-viewer`
      page is deleted.
- [x] Direct mode policy decision: hosted iframe mode is required for browser
      wallet capabilities. Missing `walletOrigin` must fail clearly at
      config/use boundary. Any remaining direct browser worker mode is
      internal/test-only.
- [x] Version-skew contract: use the iframe boot protocol-version handshake.
      The wallet host advertises `WALLET_PROTOCOL_VERSION` in `READY`, and the
      app client fails closed with `WalletIframeProtocolVersionMismatchError`
      when the hosted wallet runtime is incompatible. Cache/path versioning can
      still be added later as a deployment optimization.
- [ ] Embedding authorization model, two-staged:
      - Stage 1 (stabilization): a static `frame-ancestors` default for local
        dev/dogfood (the localhost app origin), shipped with the Phase 1
        header contract.
      - Stage 2 (hosted deploy): per-tenant allowed parent origins resolved
        from `environmentId`/publishable key server config, driving both
        postMessage origin checks and the wallet-service embedding-control
        response. The server-side resolution is Router/API-owned work — named
        here so it does not fall between plans — and it gates the actual
        `sign.seams.sh` deployment, not local dogfood.
      Resolve the model shape during Phase 1.

## Implementation Preconditions

- [ ] Commit or stage this plan before implementation; the file is currently a
      planning artifact and must not be lost.
- [x] Make the first implementation slice the harsh local smoke:
      - app origin has no Seams SDK Vite plugin;
      - app origin returns 404 for `/sdk/*` and `/wallet-service`;
      - wallet origin serves `packages/sdk-web/dist/public` directly;
      - registration, unlock, NEAR signing, ECDSA signing, and export pass
        through the hosted wallet origin.
- [x] Enforce direct-mode policy before removing plugin routes:
      - browser wallet capability setup requires hosted iframe mode;
      - missing `walletOrigin` throws a clear error;
      - tests that intentionally use direct mode must opt into an
        internal/test-only path.
- [x] Keep the export viewer as wallet-origin `srcdoc` and prove it works under
      app-origin `/sdk/* = 404`. Delete the hosted `/export-viewer` path.
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
  wallet-assets.manifest.json
  headers.manifest.json
```

The worker file list above is illustrative: the manifest's worker entries are
generated from build output, not hand-enumerated, so later worker-fleet
changes (Refactor 90 B4 merges `eth-signer`/`tempo-signer` into one
EVM-family worker) update the artifact without editing this plan.

Seams hosted wallet-origin responsibility:

```txt
GET https://sign.seams.sh/sdk/*          -> dist/public/sdk/*
GET https://sign.seams.sh/wallet-service -> dist/public/wallet-service/index.html
```

App developer responsibility (0E target shape; during stabilization the same
values ride the existing `iframeWallet` config):

```ts
createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  walletRuntime: hostedWalletIframe({
    origin: 'https://sign.seams.sh',
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

App developers do not serve `/sdk/*`, `/wallet-service`, or wallet worker/WASM
files. Local app development uses the same hosted wallet
origin.

`hostedWalletIframe(...)` is SDK runtime configuration, independent of Vite,
Next, and framework build hooks. Refactor 86 owns the hosted asset contract;
Refactor 90 owns the typed SDK runtime surface and capability dependency
validation.

Minimal app `vite.config.ts`:

```ts
plugins: [react()]
```

Internal repo-local dev should first serve `dist/public` with Caddy or a plain
static mount owned by the Seams dev environment. Do not add an SDK
`seamsStaticWalletDev()` helper unless plain static hosting leaves repeated
setup in multiple Seams-owned local-dev consumers.

`/.well-known/webauthn` ownership: this is the WebAuthn Related Origin
Requests file and is served at the RP ID origin — normally the app's domain —
so in production it is app-platform configuration, documented beside the
conditional `Permissions-Policy` requirement. Router/API or an explicit auth
dev helper serves it only in local development where `rpId=localhost`. Static
wallet asset hosting does not serve RP/auth configuration.

## Phased Todo List

### Phase 1: Asset Contract And Manifest

Goal: define the exact static asset contract before changing build output.

Tasks:

- [x] Inventory every runtime URL under `/sdk/*`, `/sdk/workers/*`, and
      `/wallet-service`, plus the deleted hosted `/export-viewer` route.
- [x] Record which files are loaded by wallet iframe HTML, confirm/export UI,
      workers, WASM bindgen loaders, and preconnect/prewarm code.
- [x] Inventory every caller of `warmCriticalResources`, worker construction,
      WASM URL resolution, export viewer creation, and wallet iframe creation.
      Mark whether it runs on app origin or wallet origin.
- [x] Inventory direct browser wallet mode call paths. Decide whether to delete
      direct mode for browser wallet capabilities or make it an explicit
      internal/test-only mode that cannot be selected by missing `walletOrigin`.
- [x] Inventory package-level imports that app code uses without the plugin:
      `@seams/sdk/react`, `@seams/sdk/react/provider`,
      `@seams/sdk/react/styles`, and `@seams/sdk/advanced`.
- [x] Decide the version-skew contract (see Remaining decisions): versioned
      asset paths pinned through `sdkBasePath`, an iframe boot
      protocol-version handshake that fails closed with a typed error, or
      both. No wallet-origin deploy may silently change the postMessage
      protocol under an older app SDK.
- [ ] Define the embedding-authorization model in two stages (see Remaining
      decisions): a static `frame-ancestors` local-dev default now, and the
      Router/API-owned per-tenant allowed-origin resolution that gates the
      hosted `sign.seams.sh` deployment.
- [ ] Document the browser storage-partitioning model: wallet-origin
      IndexedDB and sealed material are partitioned by top-level site in
      current Chrome/Firefox/Safari, so local material cached under one app
      does not exist under another. Confirm restore/re-registration UX is
      acceptable for a user opening the same wallet from a second app, and
      record the implications against Refactor 85's local-material
      assumptions.
- [x] Document required response headers per route group:
      `/wallet-service`, `/sdk/*.js`, `/sdk/*.css`,
      `/sdk/workers/*.worker.js`, and `/sdk/workers/*.wasm`.
- [x] Distinguish route classes in the header contract. For `/sdk/*` asset
      routes the default required headers are only:
      - correct `Content-Type`, especially `application/wasm`;
      - cache policy.
      The `/wallet-service` document class additionally requires default
      embedding control (`frame-ancestors` or equivalent) driven by the
      embedding-authorization model. That is a security default, not optional
      hardening.
- [x] Verify the SDK-created wallet iframe sets the required WebAuthn
      delegation attributes for hosted wallet-origin use.
- [x] Treat iframe `allow` as the primary WebAuthn delegation mechanism:
      - `publickey-credentials-get`;
      - `publickey-credentials-create`;
      - clipboard permissions needed by copy/export UI.
- [x] Move or gate any app-origin warmup that constructs workers or loads WASM.
      App-origin warmup may only create non-blocking network hints.
- [x] Remove SDK/plugin-owned `Permissions-Policy` header injection from normal
      app integration. The SDK owns iframe `allow`; app platforms own any HTTP
      header that a browser truly requires.
- [ ] Test passkey registration and login in Chrome, Safari, and Firefox with
      the app origin serving normal app headers only and the iframe carrying
      the SDK `allow` attribute.
- [ ] If a supported browser fails without HTTP `Permissions-Policy`, document
      the smallest required app platform header and keep it outside SDK Vite
      plugin behavior and wallet static asset hosting.
- [x] Decide the export/private-key viewer shape and delete the unused path:
      wallet-origin-owned inline viewer.
- [x] Confirm Lit component CSS base resolution never falls back to app-origin
      `/sdk/*` during iframe-hosted confirmation/export flows.
- [x] Remove full `Content-Security-Policy` from the default
      `headers.manifest.json` for `/sdk/*` asset routes. Keep default
      embedding control (`frame-ancestors` or equivalent) on the
      wallet-service document class.
- [x] Mark broader wallet HTML Content-Security-Policy (beyond embedding
      control) as optional production hardening, outside the default header
      profile.
- [x] Remove `Cross-Origin-Embedder-Policy`,
      `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy` from the
      default `headers.manifest.json`.
- [x] If strict cross-origin isolation is still useful for tests, model it as a
      separate optional header profile, not the default.
- [x] Define `wallet-assets.manifest.json` with `route`, `sourceFile`,
      `contentType`, `cachePolicy`, `requiredHeaders`, and `owner`.
- [x] Define `headers.manifest.json` with the platform-independent header
      contract.
- [x] Assign `/.well-known/webauthn`: app-platform configuration at the RP ID
      origin in production (it is the WebAuthn Related Origin Requests file);
      Router/API or an auth dev helper only for local dev where
      `rpId=localhost`. Document it beside the conditional
      `Permissions-Policy` requirement.
- [ ] Run the browser WebAuthn smoke campaign as a parallel sub-track
      (Phase 1B) so the manifest and contract tasks are not blocked on
      multi-browser scheduling.

Acceptance:

- [x] `wallet-assets.manifest.json` lists every required static route.
- [x] `headers.manifest.json` lists every required route header.
- [x] The manifest names which runtime code depends on each route.

### Phase 2: Build-Owned Static Asset Tree

Goal: make `@seams/sdk` publish the wallet runtime as static files for the
hosted wallet origin deploy.

Tasks:

- [x] Add a build step that creates `dist/public/sdk`.
- [x] Apply the Phase 1 version-skew contract to the tree layout: if versioned
      paths were chosen, emit the version segment and record it in
      `wallet-assets.manifest.json`; if handshake-only, emit the protocol
      version into the wallet HTML and SDK entry metadata.
- [x] Copy `dist/esm/sdk/*` into `dist/public/sdk/*`.
- [x] Copy `dist/workers/*` into `dist/public/sdk/workers/*`.
- [x] Delete or quarantine build constants and scripts that copy SDK workers into
      `apps/seams-site/src/public/sdk`. App public assets must not provide a
      hidden fallback for wallet workers.
- [x] Emit `dist/public/wallet-service/index.html` using the existing wallet
      HTML builder.
- [x] Keep private-key export on the wallet-origin `srcdoc` path and do not emit
      `dist/public/export-viewer/index.html`.
- [x] Emit `dist/public/wallet-assets.manifest.json`.
- [x] Emit `dist/public/headers.manifest.json`.
- [x] Add a build check that fails when any worker JS lacks its paired WASM file.
- [x] Add a build check that resolves every import referenced by wallet HTML,
      SDK entry chunks, worker scripts, and CSS from `dist/public`.
- [x] Ensure WASM workers locate their `.wasm` files by stable relative URLs
      from the worker/static asset location.
- [x] Add a build/browser check that loads the generated wallet-service page,
      instantiates every wallet worker, and verifies each worker can load its
      paired WASM from `dist/public`.
- [x] Add a build check that rejects generated wallet runtime JS with
      app-origin `/sdk/workers/` authority assumptions outside wallet-hosted
      entrypoints.
- [x] Add a package export smoke that imports:
      - `@seams/sdk/react`;
      - `@seams/sdk/react/provider`;
      - `@seams/sdk/react/styles`;
      - `@seams/sdk/advanced`.

Acceptance:

- [x] `pnpm -C packages/sdk-web build:sdk` creates a complete
      `dist/public` tree.
- [x] The hosted wallet deploy can publish `dist/public` directly.
- [x] The static tree is a packaging copy of existing build output, with no new
      runtime URL scheme introduced in this phase.
- [x] A browser can load worker JS and the worker can load its WASM without a
      Vite plugin.

### Phase 3: Static Smoke And Repo Dogfood

Goal: prove hosted-origin static serving before shrinking SDK plugins.

Tasks:

- [x] Add `packages/sdk-web/scripts/checks/assert-static-wallet-assets.mjs`.
- [x] Make the smoke check read `wallet-assets.manifest.json` and verify file
      existence, content type expectations, and required header metadata.
- [x] Serve wallet assets for `pnpm site` through a Seams-owned Caddy/static
      wallet origin from `packages/sdk-web/dist/public`.
- [x] Change repo-local Caddy so `https://localhost:8443` serves
      `packages/sdk-web/dist/public` directly instead of reverse-proxying the
      app Vite server.
- [x] Remove `seamsWallet(...)` from `apps/seams-site/vite.config.ts`.
- [x] Keep app-origin Vite config limited to React, aliases, and app-owned
      settings.
- [x] Verify the demo app SDK initialization uses the hosted wallet origin and
      does not depend on local app-hosted `/sdk/*`.
- [x] Force app-origin `/sdk/*` and `/wallet-service` to return 404 during
      smoke tests.
- [x] Ensure `pnpm site` still serves:
      - `https://localhost/`;
      - `https://localhost:8443/wallet-service`;
      - `https://localhost:8443/sdk/workers/near-signer.worker.js`;
      - `https://localhost:8443/sdk/workers/wasm_signer_worker_bg.wasm`.
- [x] Verify the export/private-key viewer path selected in Phase 1 works from
      the hosted wallet origin.
- [x] Verify failed app-origin preconnect/prefetch hints do not block wallet
      initialization.
- [x] Verify app-origin package imports and CSS still load with a minimal Vite
      config and no SDK-specific aliases beyond normal workspace/package
      resolution.

Acceptance:

- [x] `apps/seams-site/vite.config.ts` no longer imports
      `@seams/sdk/plugins/vite` for wallet hosting.
- [x] The app can register, unlock, and sign by importing SDK code in React only.
- [x] Static smoke test passes against `dist/public`.
- [x] Manual registration, unlock, NEAR signing, and EVM signing load wallet
      iframe workers from the Seams-owned wallet origin.

### Phase 4: Deduplicate Shim And Surface CSS Generation

Goal: remove duplicated wallet shim/CSS sources.

Tasks:

- [x] Move `wallet-shims.js` source to one build-owned helper.
- [x] Move `wallet-service.css` source to one build-owned helper.
- [x] Make Rolldown/static build and Vite dev serving read the same generated
      files.
- [x] Delete duplicate `WALLET_SHIM_SOURCE` and `WALLET_SURFACE_CSS`
      definitions from `packages/sdk-web/src/plugins/vite.ts` if the files can
      be read from `dist/public/sdk`.
- [x] Prefer normal source files for `wallet-shims.js` and `wallet-service.css`
      if that is shorter than generated string content.

Acceptance:

- [x] There is one source of truth for wallet shim JS.
- [x] There is one source of truth for wallet service CSS.

### Phase 5a: Remove Runtime Vite Plugin Requirement (Current Config)

Goal: make wallet runtime delivery plugin-free against the existing
`iframeWallet` config surface. Stabilization-scoped; no 0E dependency —
plugin removal is asset serving, and the current config already carries every
field this phase needs.

Error-shape note: the fail-closed missing-`walletOrigin` error added here is
one named error on the current config boundary, annotated in code as the
error the 0E config-error taxonomy absorbs in Phase 5b. One forwarding-noted
error is not a parallel taxonomy.

Tasks:

- [x] Avoid adding `seamsStaticWalletDev(...)` unless Caddy/plain static hosting
      leaves repeated setup in more than one Seams-owned local-dev consumer.
- [x] Remove app/runtime dependence on `seamsWallet()`, `seamsServeSdk()`,
      `seamsWalletService()`, and `seamsWasmMime()`.
- [x] Remove public app-facing `@seams/sdk/plugins/vite` usage from examples and
      app docs. Keep only package-internal/static-build helpers that are still
      needed to emit the hosted wallet artifact.
- [x] Review `@seams/sdk/plugins/next`; remove or rewrite any guidance that
      makes app frameworks responsible for wallet asset hosting or default CSP
      headers.
- [x] Make browser wallet capability setup require hosted iframe mode. Missing
      `walletOrigin` fails at the current config/use boundary with the single
      named error (see the error-shape note) instead of selecting direct
      app-origin workers.
- [x] If any helpers remain, keep them as examples or optional dev utilities
      for Seams-owned wallet-origin development only.
- [x] Remove build-time `_headers` emission from app Vite plugin usage.
- [x] Remove `seamsWasmMime()` if static file serving sets MIME correctly
      through the shared static mount.
- [x] Remove default `Cross-Origin-Embedder-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [x] Remove default `Cross-Origin-Opener-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [x] Remove default `Cross-Origin-Resource-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [x] Remove default `Content-Security-Policy` emission from
      `packages/sdk-web/src/plugins/vite.ts`.
- [x] Keep any remaining COOP/COEP/CORP code behind an explicit strict-isolation
      option, or delete it if no current test/runtime path needs it.
- [x] Keep any remaining wallet HTML CSP generation behind an explicit hardening
      option, or delete it if no current deployment path needs it.
- [x] Remove debug routes from default app usage.
- [x] Delete virtual `/sdk/wallet-shims.js` and `/sdk/wallet-service.css`
      serving once files come from `dist/public/sdk`.

Acceptance:

- [x] Host app Vite config uses no `@seams/sdk/plugins/vite` import.
- [x] Local wallet-origin dev can still mount the static wallet assets with one
      Seams-owned plain static mount.
- [x] Wallet runtime delivery succeeds with no Seams SDK Vite plugin, on the
      current `iframeWallet` config.
- [x] The missing-`walletOrigin` error is one named error with the 0E
      forwarding annotation.

### Phase 5b: Adopt The 0E Runtime Config (Parked On Refactor 90 Phase 0E)

Tasks:

- [ ] Route browser wallet capability setup through the Refactor 90
      `walletRuntime: hostedWalletIframe(...)` SDK runtime config. Keep legacy
      `iframeWallet` config normalization at the public config boundary only,
      then delete it when the runtime config replaces examples and tests.
- [ ] Replace the Phase 5a missing-`walletOrigin` error with the 0E
      config-error taxonomy.
- [ ] Update app examples to `createSeamsConfig(...)`.

Acceptance:

- [ ] `iframeWallet` acceptance is deleted; config errors come from the 0E
      taxonomy.

### Phase 6a: Deployment And Internal Documentation

Goal: make integrator setup boring. Stabilization-scoped: internal recipes,
deployment contract, and header docs. The public getting-started rewrite is
Phase 6b, deliberately deferred so public docs are not written against the
`iframeWallet` surface and then re-taught on `createSeamsConfig` after 0E.

Tasks:

- [x] Update `packages/sdk-web/src/plugins/README.md` to state app developers use
      the hosted wallet origin and do not configure SDK Vite plugins.
- [x] Update `docs/saas/self-hosted-migration.md` to remove app-owned wallet
      asset hosting from the normal integration path.
- [x] Document the Seams wallet-origin deployment contract for
      `https://sign.seams.sh`.
- [x] Document hosted wallet iframe embedding requirements, including any iframe
      `allow` attributes.
- [ ] Document app-origin WebAuthn `Permissions-Policy` only if browser smokes
      prove it is required. Present it as app platform configuration, not SDK
      Vite plugin setup.
- [x] Document COOP/COEP/CORP as legacy/optional strict-isolation headers, not
      default wallet asset requirements.
- [x] Document wallet HTML Content-Security-Policy as optional production
      hardening, not a default wallet asset requirement.
- [ ] Generate platform-specific docs snippets from `headers.manifest.json`.
- [x] Document internal Seams local-dev recipes:
      - app origin on local Vite;
      - wallet origin on Seams-owned Caddy/static server;
      - Router/API on local Router.
- [x] Document `/.well-known/webauthn` as app-platform configuration served at
      the RP ID origin (WebAuthn Related Origin Requests), listed beside the
      conditional `Permissions-Policy` requirement; Router/auth dev helper
      ownership is local-dev-only (`rpId=localhost`).
- [x] Document that app developers should not serve or reverse-proxy
      `@seams/sdk/dist/public`.
- [x] Document that app developers should not run a wallet static server in
      local development.
- [x] Update stale runtime-path comments and docs that still describe COOP,
      COEP, CORP, CSP, app-origin `/sdk/*`, or app-origin worker hosting as
      required.
- [ ] Decide whether custom CNAME wallet origins are Seams-managed hosted
      wallet origins. If supported, document them as Seams-operated hosting,
      not app-owned asset serving.
- [x] If optional helper examples remain, present them as Seams-internal
      development utilities.

Acceptance:

- [x] An integrator can use the SDK without hosting wallet assets and without
      editing Vite config.
- [ ] Local app development does not require an extra wallet/static server.
- [x] Hosted wallet-origin headers and app embedding requirements are explicit
      and testable.

### Phase 6b: Public Getting-Started Rewrite (Parked On Refactor 90 Phase 0E)

Tasks:

- [ ] Update React/getting-started docs so the normal setup is only:
      install package, import SDK/components, configure environment ID,
      publishable key, `walletRuntime: hostedWalletIframe(...)`, auth methods,
      and requested capabilities.

Acceptance:

- [ ] A new React integrator can use the SDK by importing package code and
      setting the 0E SDK configuration only.

### Phase 7: Guards And Cleanup

Goal: keep the plugin from growing back into a framework runtime.

Tasks:

- [x] Add a source guard that rejects app examples requiring `seamsWallet()` for
      ordinary app pages.
- [x] Add a source guard that rejects app examples importing
      `@seams/sdk/plugins/vite` for wallet runtime hosting.
- [x] Add a source guard that rejects app framework examples importing
      `@seams/sdk/plugins/next` for wallet runtime hosting.
- [x] Add a source guard that rejects app examples serving `/sdk/*` or
      `/wallet-service` from app-owned infrastructure.
- [x] Add a source guard that rejects app examples instructing developers to run
      a local wallet static server.
- [x] Add a source guard that rejects duplicate wallet shim/CSS source strings.
- [x] Add a static asset smoke test that loads wallet HTML, a worker JS file,
      and a WASM file from `dist/public`.
- [x] Replace stale wallet-service header tests that assert default CSP,
      COOP/COEP/CORP, or app plugin behavior with hosted-wallet header manifest
      tests.
- [ ] Add browser WebAuthn delegation smokes:
      - app origin has no SDK-generated `Permissions-Policy`;
      - wallet iframe has SDK-generated `allow`;
      - passkey registration succeeds in Chrome, Safari, and Firefox where
        supported;
      - passkey login succeeds in Chrome, Safari, and Firefox where supported.
- [ ] Reuse the Refactor 84a wallet-binding passkey scenarios for the hosted
      origin smokes instead of writing a parallel suite.
- [x] Add a version-skew smoke per the Phase 1 contract: an older app SDK
      entry against newer wallet-origin assets must fail closed with the typed
      mismatch error (or be impossible by versioned pathing) — never silently
      talk a drifted postMessage protocol.
- [ ] Add a negative-control smoke that embeds `/wallet-service` from a
      non-allowed origin and expects the embedding control to block it.
- [ ] Add a negative-control browser smoke that removes iframe `allow` and
      expects cross-origin WebAuthn to fail.
- [x] Add a browser smoke that denies app-origin `/sdk/*` and
      `/wallet-service`, then completes registration, unlock, NEAR signing,
      ECDSA signing, and export through the hosted wallet origin.
- [x] Add a targeted test proving iframe-mode app-origin warmup does not
      construct workers or load WASM.
- [x] Add a config test proving browser wallet capabilities cannot silently fall
      back to direct app-origin worker mode when `walletOrigin` is omitted.
- [x] Delete stale docs that recommend broad `seamsWallet()` app integration.
- [x] Delete `seamsWasmMime()` if no remaining route needs it.
- [x] Delete virtual shim/CSS middleware from `packages/sdk-web/src/plugins/vite.ts`
      after static files serve those assets.
- [x] Delete default debug routes from app examples.
- [x] Add a source guard that rejects default COOP/COEP/CORP emission in app or
      wallet static hosting helpers.
- [x] Add a source guard that rejects default Content-Security-Policy emission in
      app or wallet static hosting helpers.
- [x] Record every guard added by this phase in the
      [Refactor 89](./refactor-89-clean-source-guards.md) ledger with intake
      rows (owner refactor, cleanup trigger, replacement coverage).

Acceptance:

- [x] Source guards pass.
- [x] Static asset smoke test passes.
- [x] Plugin docs no longer describe any Seams Vite plugin as required runtime
      infrastructure.
- [x] Public app examples contain no SDK Vite plugin setup and no wallet static
      server setup.
- [x] Default generated docs/header manifests contain no
      `Cross-Origin-Embedder-Policy`, `Cross-Origin-Opener-Policy`, or
      `Cross-Origin-Resource-Policy`.
- [x] Default generated docs/header manifests contain no
      `Content-Security-Policy`.

## Open Questions

- Should static entry file names stay stable while imported chunks remain
  generated filenames? Decide together with the version-skew/cache contract
  (Remaining decisions): versioned immutable paths permit stable entry names
  with long-lived caching; unversioned stable names force short cache
  lifetimes or ETags.
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
