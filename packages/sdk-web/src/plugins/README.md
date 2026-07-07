# Seams SDK Plugin Helpers

App integrations should not use these helpers for wallet runtime delivery.

The normal browser integration is:

1. Import SDK and React package code normally.
2. Configure the hosted wallet iframe with `iframeWallet.walletOrigin`.
3. Let the Seams-operated wallet origin serve `/wallet-service`, `/export-viewer`, `/sdk/*`, and `/sdk/workers/*`.
4. Keep the app Vite or Next config focused on app concerns.

For Vite apps, that means a normal app config such as:

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
});
```

For SDK config during the stabilization milestone:

```ts
const config = {
  relayer: { url: 'https://router.example.com' },
  iframeWallet: {
    walletOrigin: 'https://wallet.seams.sh',
    walletServicePath: '/wallet-service',
    sdkBasePath: '/sdk',
  },
};
```

After Refactor 90 Phase 0E lands, this moves to the typed
`walletRuntime: hostedWalletIframe(...)` surface. The asset-hosting contract
does not change.

## Hosted Wallet Asset Contract

The SDK package build emits the wallet-origin artifact at
`packages/sdk-web/dist/public`:

- `sdk/*`
- `sdk/workers/*`
- `wallet-service/index.html`
- `export-viewer/index.html`
- `wallet-assets.manifest.json`
- `headers.manifest.json`

Seams wallet hosting publishes that tree from the wallet origin:

```txt
GET https://wallet.seams.sh/sdk/*          -> dist/public/sdk/*
GET https://wallet.seams.sh/wallet-service -> dist/public/wallet-service/index.html
GET https://wallet.seams.sh/export-viewer  -> dist/public/export-viewer/index.html
```

App origins should return 404 for `/sdk/*`, `/wallet-service`, and
`/export-viewer`. Wallet workers and WASM execute from the wallet origin.

## Headers And Embedding

The SDK-created iframe carries the WebAuthn and clipboard delegation through its
`allow` attribute. App-platform `Permissions-Policy` is only required if a
supported browser proves it is needed in hosted-origin smokes.

Default hosted wallet asset headers are described by
`dist/public/headers.manifest.json`:

- asset routes require correct `Content-Type` and cache policy;
- wallet document routes require embedding control for allowed parent origins;
- COOP, COEP, CORP, and broad wallet CSP are optional hardening or legacy
  strict-isolation settings, not default app integration requirements.

`/.well-known/webauthn` belongs to the RP ID origin. In production that is app
platform configuration. Local development may use a Router/auth dev helper when
`rpId=localhost`.

## Remaining Helpers

Files in this directory still exist for package-internal build output, legacy
tests, and migration work while Refactor 86 removes app runtime dependence on
plugin serving.

Do not add app examples that use:

- `@seams/sdk/plugins/vite` for normal wallet runtime hosting;
- `@seams/sdk/plugins/next` for normal wallet runtime hosting;
- `seamsWallet()`, `seamsServeSdk()`, `seamsWalletService()`, or
  other SDK static-serving helpers on an app origin;
- app-owned `/sdk/*`, `/wallet-service`, or `/export-viewer` routes.

When a helper remains necessary, keep its usage scoped to Seams-owned wallet
origin development or hosted wallet artifact generation.
