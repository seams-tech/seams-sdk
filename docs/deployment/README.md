# Deployment

This directory is the deployment runbook for the SDK runtime, Cloudflare Pages
sites, relay Worker, and backing infra.

## Deployment Model

GitHub deployments use two environments:

- `staging`: automatic from `dev`; manual target for pre-production deploys.
- `production`: automatic from `main`; manual target for production deploys.

The workflow target is the deployment environment, not the chain. NEAR network,
RPC URLs, relayer accounts, wallet origins, and Pages aliases come from
environment variables and `examples/relay-cloudflare-worker/wrangler.toml`.

## Workflows

| Workflow                               | Trigger                                                     | Purpose                                                                                                                                              |
| -------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`             | `push`, `pull_request`, `merge_group`                       | Builds, lints, type-checks, runs formal verification, Postgres smoke tests, and threshold signing suites.                                            |
| `.github/workflows/publish-sdk-r2.yml` | Successful `ci` workflow on deploy refs, or manual dispatch | Builds `sdk/dist`, writes `manifest.sha256` and `manifest.json`, signs the manifest with cosign, and publishes SDK runtime bundles to Cloudflare R2. |
| `.github/workflows/deploy-pages.yml`   | Push to `dev`/`main`, or manual dispatch                    | Builds the SDK and `examples/seams-site`, copies SDK runtime assets under `/sdk`, and deploys the app and wallet Pages projects.                    |
| `.github/workflows/deploy-relay.yml`   | Push to `dev`/`main`, or manual dispatch                    | Builds the SDK for Worker bundling, deploys the Cloudflare relay Worker, and configures Cloudflare Email Routing for the recovery recipient.         |

Removed testnet-only workflows are replaced by the staging target in the
workflows above. Move any required GitHub Environment secrets and vars from an
old `testnet` environment into `staging`.

## First Deploy Checklist

1. Create GitHub Environments `staging` and `production`.
2. Add Cloudflare, R2, Pages, relay, and Vite environment values from
   [infra.md](infra.md).
3. Provision Postgres signer and console databases, users, grants, and
   migrations from [infra.md](infra.md#postgres).
4. Provision Cloudflare Worker secrets for the relay.
5. Run `ci` on the target commit.
6. Publish SDK runtime assets with `publish-sdk-r2` or let it run after `ci`.
7. Deploy Pages with `deploy-pages`.
8. Deploy the relay Worker with `deploy-relay`.

## Normal Promotion

Staging:

```bash
git push origin dev
```

Production:

```bash
git push origin main
```

Manual deploys:

```bash
gh workflow run deploy-pages.yml --ref dev -f target=all -f deploy_environment=staging
gh workflow run deploy-relay.yml --ref dev -f target=staging
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
```

For production manual runs, use `--ref main` and `production`.

## Deploy Order

For a fresh environment, deploy in this order:

1. Infra and secrets.
2. Postgres migrations.
3. SDK R2 publish.
4. Pages deploy.
5. Relay deploy.

For routine app changes, `ci` plus the Pages and relay workflows are enough.
For SDK runtime changes, confirm the R2 publish and the Pages `/sdk` copy both
come from the same commit SHA.

## Follow-On Docs

- [infra.md](infra.md): GitHub Environment values, Cloudflare setup, Postgres,
  Worker secrets, and migration commands.
- [sdk.md](sdk.md): SDK runtime bundle publishing, Pages `/sdk` assets, R2
  prefixes, npm release steps, and rollback.
- [release.md](release.md): versioned release process.
