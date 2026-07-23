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
pnpm -C packages/sdk-web test:relayer
```

For changes touching threshold signing or D1/DO-backed relay behavior, also run:

```bash
pnpm test:threshold-core
pnpm test:threshold-ed25519:active-path
pnpm -C packages/console-server-ts run d1:local:prepare
pnpm -C packages/console-server-ts run d1:local:restore:drill
```

## Version And Tag

```bash
# Edit packages/sdk-web/package.json version first.
git add packages/sdk-web/package.json
git commit -m "release: vX.Y.Z"
git tag vX.Y.Z -m "release: vX.Y.Z"
```

Push the release commit, merge it into protected `main` through a pull request,
then push the tag:

```bash
git push origin HEAD
git push origin vX.Y.Z
```

## Publish npm

npm publish remains manual:

```bash
npm login --scope=@seams-sdk --registry=https://registry.npmjs.org
pnpm install --frozen-lockfile
pnpm build:sdk-prod
cd packages/sdk-web
npm publish --access public
```

Verify:

```bash
npm view @seams/sdk version
```

## Deploy Hosted Surfaces

Pushing the release commit to `main` runs the fast push mode of
`Validate / repository`; successful validation starts
`Deploy / production / cloudflare-stack`. That workflow
contains the Router A/B, Gateway, and Pages jobs, so Pages is deployed as part
of the same environment-bound Cloudflare stack release.

## Release Verification

Check:

- `Validate / repository` passed on the release commit.
- npm shows the intended version.
- App Pages and wallet Pages are on the same commit.
- `/sdk/wallet-iframe-host-runtime.js` and `/sdk/workers/near-signer.worker.js`
  load from the wallet origin.
- Registration/signing smoke paths work against the deployed Router A/B workers.

## Rollback

SDK runtime:

1. Run `Deploy / production / cloudflare-stack` with the previous accepted
   `source_sha`, `artifact_run_id`, and `release_set_id`.
2. Keep app and wallet Pages assets on the same known-good release set.
3. Treat secrets, D1 migrations, Durable Object state, and other environment
   state as separate recovery work.

npm:

```bash
npm deprecate @seams/sdk@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
deprecation is insufficient.

Relay and Pages:

1. Use the accepted-release stack rollback above as the canonical path.
2. Use the Cloudflare dashboard only as an emergency provider-specific
   fallback.
3. Re-run smoke checks and route forward fixes through `Validate / repository`
   before redeploying.
