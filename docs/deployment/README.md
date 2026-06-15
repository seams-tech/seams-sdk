# Deployment

This directory is the deployment runbook for the SDK runtime, Cloudflare Pages
sites, relay Worker, Router A/B Workers, and backing infra.

## Deployment Model

GitHub deployments use two environments:

- `staging`: automatic from `dev`; manual target for pre-production deploys.
- `production`: automatic from `main`; manual target for production deploys.

The workflow target is the deployment environment, not the chain. NEAR network,
RPC URLs, relayer accounts, wallet origins, and Pages aliases come from
environment variables and `examples/relay-cloudflare-worker/wrangler.toml`.

## Workflows

| Workflow                                 | Trigger                                                     | Purpose                                                                                                                                              |
| ---------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`               | `push`, `pull_request`, `merge_group`                       | Builds, lints, type-checks, runs formal verification, Postgres smoke tests, and threshold signing suites.                                            |
| `.github/workflows/router-ab.yml`        | Router A/B path changes, or manual dispatch                 | Runs Router A/B core/dev/Cloudflare tests, strict Worker checks, local four-worker smoke, and Wrangler startup dry-run evidence.                     |
| `.github/workflows/publish-sdk-r2.yml`   | Successful `ci` workflow on deploy refs, or manual dispatch | Builds `sdk/dist`, writes `manifest.sha256` and `manifest.json`, signs the manifest with cosign, and publishes SDK runtime bundles to Cloudflare R2. |
| `.github/workflows/deploy-pages.yml`     | Push to `dev`/`main`, or manual dispatch                    | Builds the SDK and `examples/seams-site`, copies SDK runtime assets under `/sdk`, and deploys the app and wallet Pages projects.                     |
| `.github/workflows/deploy-relay.yml`     | Push to `dev`/`main`, or manual dispatch                    | Builds the SDK for Worker bundling, deploys the Cloudflare relay Worker, and configures Cloudflare Email Routing for the recovery recipient.         |
| `.github/workflows/deploy-router-ab.yml` | Manual dispatch                                             | Validates Router A/B, uploads Worker versions for startup evidence, or deploys Router/Deriver A/Deriver B/SigningWorker to Cloudflare.               |

Removed testnet-only workflows are replaced by the staging target in the
workflows above. Move any required GitHub Environment secrets and vars from an
old `testnet` environment into `staging`.

## First Deploy Checklist

1. Create GitHub Environments `staging` and `production`.
2. Add Cloudflare, R2, Pages, relay, Router A/B, and Vite environment values from
   [infra.md](infra.md).
3. Generate Router A/B deployment identity keys with
   `pnpm router:deploy:keygen -- --env staging --apply`. Repeat for production.
4. Store `SIGNER_A_ROOT_SHARE_WIRE_SECRET` and
   `SIGNER_B_ROOT_SHARE_WIRE_SECRET` from the derivation/provisioning ceremony
   in the matching GitHub Environment.
5. Provision Postgres signer and console databases, users, grants, and
   migrations from [infra.md](infra.md#postgres).
6. Provision Cloudflare Worker secrets for the relay.
7. Run `ci` on the target commit.
8. Run `router-ab` on the target commit when Router A/B files changed.
9. Publish SDK runtime assets with `publish-sdk-r2` or let it run after `ci`.
10. Deploy Pages with `deploy-pages`.
11. Deploy the relay Worker with `deploy-relay`.
12. Upload Router A/B Worker versions for startup evidence with
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
gh workflow run deploy-relay.yml --ref dev -f target=staging
pnpm router:deploy:keygen -- --env staging --apply
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
```

Run `operation=deploy` only after `pnpm router:deploy:check` passes on the
target commit. Router A/B role config lives in
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).

For production manual runs, use `--ref main` and `production`.

## Deploy Order

For a fresh environment, deploy in this order:

1. Infra and secrets.
2. Postgres migrations.
3. SDK R2 publish.
4. Pages deploy.
5. Relay deploy.
6. Router A/B version upload for startup evidence.
7. Router A/B deploy after `router:deploy:check` passes.

For routine app changes, `ci` plus the Pages and relay workflows are enough.
For SDK runtime changes, confirm the R2 publish and the Pages `/sdk` copy both
come from the same commit SHA.

## Follow-On Docs

- [infra.md](infra.md): GitHub Environment values, Cloudflare setup, Postgres,
  Worker secrets, and migration commands.
- [threshold-postgres-reset.md](threshold-postgres-reset.md): local/dev reset
  for refactor-36 threshold/session/signing Postgres tables.
- [sdk.md](sdk.md): SDK runtime bundle publishing, Pages `/sdk` assets, R2
  prefixes, npm release steps, and rollback.
- [release.md](release.md): versioned release process.
