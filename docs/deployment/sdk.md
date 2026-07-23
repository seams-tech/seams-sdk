# SDK Deployment

The SDK has two deployment outputs:

- npm package `@seams/sdk`
- runtime bundles from `packages/sdk-web/dist` served by Pages at `/sdk/*`

The runtime bundles are commit-built artifacts. Keep the Pages deployment on the
same commit when changing wallet iframe, workers, WASM, or SDK asset loading.

## Build

Production build:

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
```

Main outputs:

- `packages/sdk-web/dist/esm/sdk/*`
- `packages/sdk-web/dist/workers/*`
- `packages/sdk-web/dist/esm/wasm/*`
- `packages/sdk-web/dist/esm/server/*`

## Pages Runtime Assets

The internal Pages deployment workflow consumes the accepted Pages artifact:

```bash
pnpm build:sdk-prod
pnpm -C apps/seams-site exec vite build
```

Then it copies runtime assets into the Pages output:

```bash
packages/sdk-web/dist/esm/sdk/       -> apps/seams-site/dist/sdk/
packages/sdk-web/dist/workers/       -> apps/seams-site/dist/sdk/workers/
```

Use `VITE_SDK_BASE_PATH=/sdk` unless you intentionally serve the SDK under a
different path. The wallet service route and app config must agree with that
base path.

Pages deploy automatically at the end of the successful branch release chain.
Pages deployment is selected by the environment-bound Cloudflare stack
workflow. There is no direct Pages deployment button.

The implemented
[build-once deployment phase](README.md#follow-up-phase-build-once-deploy-many)
keeps production SDK and Vite compilation outside the Pages upload jobs. The
artifact remains target-specific because Vite embeds environment configuration.
One artifact must contain both app and wallet outputs so the two Pages projects
cannot drift to different SDK builds. A Pages-only retry downloads that
artifact, verifies its manifest, and uploads it without invoking Cargo,
`wasm-pack`, `pnpm build:sdk-prod`, or Vite.

## npm Package

npm publish is still manual. Use it after CI passes and after confirming the
SDK runtime deploy path for the same commit.

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
cd packages/sdk-web
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
npm deprecate @seams/sdk@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
an npm warning is not enough.
