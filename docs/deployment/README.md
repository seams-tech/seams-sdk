# Deployment

This directory is the deployment runbook for the SDK runtime, Cloudflare Pages
sites, Router A/B Workers, and backing infra.

## Deployment Model

GitHub deployments use two environments:

- `staging`: automatic from `dev`; manual target for pre-production deploys.
- `production`: automatic from `main`; manual target for production deploys.

Router A/B Worker deployment currently exposes `staging` only. Its previous
production target used same-account Service Bindings and has been deleted.
Pages, R2, and other non-Router surfaces continue to use both environments.

The workflow target is the deployment environment, not the chain. NEAR network,
RPC URLs, wallet origins, and Pages aliases come from GitHub Environment
variables and checked-in Cloudflare config.

## Workflows

| Workflow                                 | Trigger                                                     | Purpose                                                                                                                                              |
| ---------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`               | `push`, `pull_request`, `merge_group`                       | Builds, lints, type-checks, runs formal verification, D1/DO smoke tests, and threshold signing suites.                                               |
| `.github/workflows/router-ab.yml`        | Router A/B path changes, or manual dispatch                 | Runs Router A/B core/dev/Cloudflare tests, strict Worker checks, local four-worker smoke, and Wrangler startup dry-run evidence.                     |
| `.github/workflows/publish-sdk-r2.yml`   | Successful `ci` workflow on deploy refs, or manual dispatch | Builds `packages/sdk-web/dist`, writes `manifest.sha256` and `manifest.json`, signs the manifest with cosign, and publishes SDK runtime bundles to Cloudflare R2. |
| `.github/workflows/deploy-pages.yml`     | Push to `dev`/`main`, or manual dispatch                    | Builds the SDK and `apps/seams-site`, copies SDK runtime assets under `/sdk`, and deploys the app and wallet Pages projects.                     |
| `.github/workflows/deploy-router-ab.yml` | Manual dispatch                                             | Validates Router A/B, uploads Worker versions for startup evidence, or deploys Router/Deriver A/Deriver B/SigningWorker to Cloudflare.               |

Removed testnet-only workflows are replaced by the staging target in the
workflows above. Move any required GitHub Environment secrets and vars from an
old `testnet` environment into `staging`.

## First Deploy Checklist

1. Create the general `staging` and `production` GitHub Environments plus the
   split Router A/B `staging-*` role environments.
2. Add Cloudflare, R2, Pages, Router A/B, and Vite environment values from
   [infra.md](infra.md).
3. Generate staging Router A/B deployment identity keys with
   `pnpm router:deploy:keygen -- --env staging --apply`.
4. Store `DERIVER_A_ROOT_SHARE_WIRE_SECRET` and
   `DERIVER_B_ROOT_SHARE_WIRE_SECRET` from
   `pnpm router:deploy:root-share-keygen` in the matching GitHub Environment.
5. Provision D1 signer and console databases, Durable Object namespaces, R2
   backups, and migrations from [infra.md](infra.md#cloudflare-data).
6. Run `ci` on the target commit.
7. Run `router-ab` on the target commit when Router A/B files changed.
8. Publish SDK runtime assets with `publish-sdk-r2` or let it run after `ci`.
9. Deploy Pages with `deploy-pages`.
10. Upload Router A/B Worker versions for startup evidence with
    `deploy-router-ab`, then deploy after `router:deploy:check` passes on the
    target commit.

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
pnpm router:deploy:keygen -- --env staging --apply
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
```

Run `operation=deploy` only after `pnpm router:deploy:check` passes on the
target commit. Router A/B role config lives in
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).

Production Router A/B commands remain absent until Phase 6A selects the strict
profile and Phase 10 adds independently administered deployment manifests.

## Deploy Order

For a fresh environment, deploy in this order:

1. Infra and secrets.
2. D1 migrations and Durable Object class migrations.
3. SDK R2 publish.
4. Pages deploy.
5. Router A/B version upload for startup evidence.
6. Router A/B deploy after `router:deploy:check` passes.

For routine app changes, `ci` plus the Pages workflow are enough.
For SDK runtime changes, confirm the R2 publish and the Pages `/sdk` copy both
come from the same commit SHA.

## Follow-On Docs

- [infra.md](infra.md): GitHub Environment values, Cloudflare setup, D1/DO/R2
  data services, Worker secrets, and migration commands.
- [sdk.md](sdk.md): SDK runtime bundle publishing, Pages `/sdk` assets, R2
  prefixes, npm release steps, and rollback.
- [release.md](release.md): versioned release process.
