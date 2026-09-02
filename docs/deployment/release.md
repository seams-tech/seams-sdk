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
pnpm -C packages/wallet test:relayer
```

For changes touching threshold signing or D1/DO-backed relay behavior, also run:

```bash
pnpm test:threshold-core
pnpm -C packages/console-server-ts run d1:local:prepare
pnpm -C packages/console-server-ts run d1:local:restore:drill
```

## Version And Tag

```bash
# Edit packages/wallet/package.json version first.
git add packages/wallet/package.json
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
cd packages/wallet
npm publish --access public
```

Verify:

```bash
npm view @seams/wallet version
```

## Deploy Hosted Surfaces

After the release commit is merged to protected `main`, manually dispatch the
two production backend lane workflows and the shared frontend workflow from
that same `main` revision:

```bash
gh workflow run deploy-production-testnet-backend.yml --ref main
gh workflow run deploy-production-mainnet-backend.yml --ref main
gh workflow run deploy-production-frontend.yml --ref main
```

Each workflow identifies one backend lane or the shared production site and
uses the workflow commit as the source of truth. The production lane workflows
currently produce plans and stop at provisioning guards until fresh testnet
and mainnet resources and identities are available. The frontend production
workflow remains gated while either backend lane is pending.

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

1. Revert the bad change or land a corrective commit on `main`.
2. Dispatch both production backend lane workflows and the production frontend
   workflow from that new `main` tip.
3. Treat secrets, D1 migrations, Durable Object state, and other environment
   state as separate recovery work.

npm:

```bash
npm deprecate @seams/wallet@X.Y.Z "Use X.Y.Z+1"
```

Use `npm unpublish` only inside npm's allowed unpublish window and only when
deprecation is insufficient.

Relay and Pages: use the matching production-testnet or production-mainnet
workflow, plus the production frontend workflow, from the corrective `main`
commit, then re-run its smoke checks. Pending lane provisioning remains a hard
gate. Use the Cloudflare dashboard only as an emergency provider-specific
fallback.
