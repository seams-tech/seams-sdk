# Release Runbook

Use this for versioned SDK releases. For infra setup, see
[infra.md](infra.md). For runtime asset publishing, see [sdk.md](sdk.md).

## Preflight

Run the release candidate through CI before tagging:

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm build:sdk-prod
pnpm test:lite
pnpm test:signers:gates
pnpm -C sdk test:relayer
```

For changes touching threshold signing or Postgres-backed relay behavior, also
run:

```bash
pnpm test:threshold-core
pnpm test:threshold-ed25519:active-path
pnpm -C examples/relay-server run postgres:setup:split
```

## Version And Tag

```bash
# Edit sdk/package.json version first.
git add sdk/package.json
git commit -m "release: vX.Y.Z"
git tag vX.Y.Z -m "release: vX.Y.Z"
```

Push the release commit and tag:

```bash
git push origin main
git push origin vX.Y.Z
```

## Publish SDK Runtime Bundles

`publish-sdk-r2.yml` publishes automatically after successful `ci` runs for
deploy refs. To publish manually:

```bash
gh workflow run publish-sdk-r2.yml --ref main -f prefix=auto
```

Expected R2 outputs:

- `releases/<commit-sha>`
- `releases/<tag>` when `vX.Y.Z` points at the published commit
- `manifest.sha256`, `manifest.json`, and `manifest.sig` in each published
  prefix

## Publish npm

npm publish remains manual:

```bash
npm login --scope=@seams-sdk --registry=https://registry.npmjs.org
pnpm install --frozen-lockfile
pnpm build:sdk-prod
cd sdk
npm publish --access public
```

Verify:

```bash
npm view @seams/sdk version
```

## Deploy Hosted Surfaces

Production Pages:

```bash
gh workflow run deploy-pages.yml --ref main -f target=all -f deploy_environment=production
```

Production relay:

```bash
gh workflow run deploy-relay.yml --ref main -f target=production
```

For staging validation, use `--ref dev` and `staging`.

## Release Verification

Check:

- `ci` passed on the release commit.
- R2 prefix exists for the release SHA.
- npm shows the intended version.
- App Pages and wallet Pages are on the same commit.
- `/sdk/wallet-iframe-host-runtime.js` and `/sdk/workers/near-signer.worker.js`
  load from the wallet origin.
- Relay health and registration/signing flows work against the deployed relay.

## Rollback

SDK runtime:

1. Repoint consumers to a known-good immutable R2 SHA prefix, or promote the
   previous Cloudflare Pages deployment.
2. Keep the bad prefix available until clients stop requesting it.

npm:

```bash
npm deprecate @seams/sdk@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
deprecation is insufficient.

Relay and Pages:

1. Promote the previous successful Cloudflare deployment.
2. Re-run smoke checks.
3. Run forward fixes through `ci` before redeploying.
