# SDK Deployment

The SDK has two deployment outputs:

- npm package `@tatchi-xyz/sdk`
- runtime bundles from `sdk/dist` served by Pages at `/sdk/*` and optionally
  published to Cloudflare R2

The runtime bundles are commit-built artifacts. Keep the Pages deploy and R2
publish on the same commit when changing wallet iframe, workers, WASM, or SDK
asset loading.

## Build

Production build:

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
```

Main outputs:

- `sdk/dist/esm/sdk/*`
- `sdk/dist/workers/*`
- `sdk/dist/esm/wasm/*`
- `sdk/dist/esm/server/*`

## Pages Runtime Assets

`deploy-pages.yml` runs:

```bash
pnpm build:sdk-prod
pnpm -C examples/tatchi-site build
```

Then it copies runtime assets into the Pages output:

```bash
sdk/dist/esm/sdk/       -> examples/tatchi-site/dist/sdk/
sdk/dist/workers/       -> examples/tatchi-site/dist/sdk/workers/
```

Use `VITE_SDK_BASE_PATH=/sdk` unless you intentionally serve the SDK under a
different path. The wallet service route and app config must agree with that
base path.

Manual Pages deploy:

```bash
gh workflow run deploy-pages.yml --ref dev -f target=all -f deploy_environment=staging
gh workflow run deploy-pages.yml --ref main -f target=all -f deploy_environment=production
```

Deploy only one Pages project:

```bash
gh workflow run deploy-pages.yml --ref dev -f target=app -f deploy_environment=staging
gh workflow run deploy-pages.yml --ref dev -f target=wallet -f deploy_environment=staging
```

## R2 Runtime Publish

`publish-sdk-r2.yml` publishes signed `sdk/dist` bundles to R2.

Default prefixes:

| Ref                              | Prefix                      |
| -------------------------------- | --------------------------- |
| `dev`                            | `releases-dev/<commit-sha>` |
| `main`                           | `releases/<commit-sha>`     |
| `v*` tag on the published commit | `releases/<tag>`            |

The workflow creates:

- `manifest.sha256`
- `manifest.json`
- `manifest.sig`

It installs cosign through `sigstore/cosign-installer` and signs
`manifest.json` with GitHub OIDC keyless signing. The workflow needs
`id-token: write`.

Manual R2 publish:

```bash
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
gh workflow run publish-sdk-r2.yml --ref main -f prefix=auto
```

Use a custom prefix only for a deliberate one-off:

```bash
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=scratch/my-test
```

Do not point production apps at scratch prefixes.

## npm Package

npm publish is still manual. Use it after CI passes and after confirming the
SDK runtime deploy path for the same commit.

```bash
pnpm install --frozen-lockfile
pnpm build:sdk-prod
cd sdk
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

After R2 publish:

```bash
aws s3 ls "s3://$R2_BUCKET/releases-dev/$COMMIT_SHA/" --endpoint-url "$R2_ENDPOINT"
aws s3 ls "s3://$R2_BUCKET/releases/$COMMIT_SHA/" --endpoint-url "$R2_ENDPOINT"
```

Check whichever prefix matches the environment.

## Rollback

Pages rollback:

1. In Cloudflare Pages, promote the previous successful deployment for the app
   and wallet projects.
2. Confirm both projects point at SDK assets from the same commit.

R2 rollback:

1. Point consumers back to a known-good immutable SHA prefix.
2. Avoid deleting bad prefixes until clients are no longer requesting them.

npm rollback:

```bash
npm deprecate @tatchi-xyz/sdk@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
an npm warning is not enough.
