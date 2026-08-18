# SDK Deployment

The SDK has two deployment outputs:

- npm package `@seams/wallet`
- runtime bundles from `packages/wallet/dist` served by Pages at `/sdk/*`

The runtime bundles are commit-built artifacts. Keep the Pages deployment on the
same commit when changing wallet iframe, workers, WASM, or SDK asset loading.

## Build

Production build:

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
```

Main outputs:

- `packages/wallet/dist/esm/sdk/*`
- `packages/wallet/dist/workers/*`
- `packages/wallet/dist/esm/wasm/*`
- `packages/wallet/dist/esm/server/*`

## Pages Runtime Assets

The Pages deployment workflow builds its output in the same job that deploys
it:

```bash
pnpm build:sdk-prod
pnpm -C apps/seams-site exec vite build
```

Then it copies runtime assets into the Pages output:

```bash
packages/wallet/dist/esm/sdk/       -> apps/seams-site/dist/sdk/
packages/wallet/dist/workers/       -> apps/seams-site/dist/sdk/workers/
```

Use `VITE_SDK_BASE_PATH=/sdk` unless you intentionally serve the SDK under a
different path. The wallet service route and app config must agree with that
base path.

Pages deployment is owned by the matching environment-bound frontend workflow.
The backend workflow has no Pages mutation job or Pages credentials. The
frontend build is target-specific because Vite embeds environment
configuration. Both Pages projects deploy from the same job workspace so they
cannot drift to different SDK builds.

## npm Package

npm publish is still manual. Use it after CI passes and after confirming the
SDK runtime deploy path for the same commit.

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
cd packages/wallet
npm publish --access public
```

The package version is in `sdk/package.json`. Commit the version bump before
tagging a release.

## Verification

After Pages deploy:

```bash
curl -fsSI "$VITE_WALLET_ORIGIN/sdk/wallet-iframe-host-runtime.js"
curl -fsSI "$VITE_WALLET_ORIGIN/sdk/workers/near-signer.worker.js"
```

Both checks should return successful responses for environments using wallet
iframe workers.

## Rollback

Pages rollback:

1. In Cloudflare Pages, promote the previous successful deployment for the app
   and wallet projects.
2. Confirm both projects point at SDK assets from the same commit.

npm rollback:

```bash
npm deprecate @seams/wallet@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
an npm warning is not enough.
