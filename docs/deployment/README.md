# Deployment

This directory is the deployment runbook for the SDK runtime, Cloudflare Pages
sites, Router A/B Workers, and backing infra.

## Deployment Model

GitHub deployments use two isolated environments:

- `staging`: automatic from `dev`; manual target for pre-production deploys.
- `production`: automatic from `main`; manual target for production deploys.

Production has its own Router A/B Workers, Gateway, D1 databases,
Durable Object namespaces, secrets, and Pages configuration. It does not reuse
staging persistence or Worker resources.

The workflow target is the deployment environment, not the chain. NEAR network,
RPC URLs, wallet origins, and Pages aliases come from GitHub Environment
variables and checked-in Cloudflare config.

## Workflows

| Workflow                                  | Trigger                                                     | Purpose                                                                                                                                                           |
| ----------------------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`                | `push`, `pull_request`, `merge_group`                       | Builds, lints, type-checks, runs formal verification, D1/DO smoke tests, and threshold signing suites.                                                            |
| `.github/workflows/router-ab.yml`         | Router A/B path changes, or manual dispatch                 | Runs Router A/B core/dev/Cloudflare tests, strict Worker checks, local four-worker smoke, and Wrangler startup dry-run evidence.                                  |
| `.github/workflows/publish-sdk-r2.yml`    | Successful `ci` workflow on deploy refs, or manual dispatch | Builds `packages/sdk-web/dist`, writes `manifest.sha256` and `manifest.json`, signs the manifest with cosign, and publishes SDK runtime bundles to Cloudflare R2. |
| `.github/workflows/deploy-staging.yml`    | Successful `ci` push on `dev`                               | Clearly labelled staging entrypoint. Deploys only staging resources.                                                                                              |
| `.github/workflows/deploy-production.yml` | Successful `ci` push on `main`                              | Clearly labelled production entrypoint. Deploys only production resources.                                                                                        |
| `.github/workflows/deploy-router-ab.yml`  | Called by a labelled release, or manual dispatch            | Shared ordered implementation: Router A/B Workers, Gateway/D1, then Pages. Manual dispatch can still target an individual Router A/B role.                        |
| `.github/workflows/deploy-gateway.yml`    | Called by the release chain, or manual dispatch             | Generates an environment-specific Wrangler config, applies that environment's two D1 migrations, deploys Gateway and its Durable Objects, then checks readiness.  |
| `.github/workflows/deploy-pages.yml`      | Called by the release chain, or manual dispatch             | Builds the exact release SHA and deploys `seams.sh` plus `wallet.seams.sh` with environment-specific frontend values.                                             |

Removed testnet-only workflows are replaced by the staging target in the
workflows above. Move any required GitHub Environment secrets and vars from an
old `testnet` environment into `staging`.

## First Deploy Checklist

1. Create one protected deployment-values file per target from
   `crates/router-ab-cloudflare/env/deployment-values.example.env`.
2. Add the scoped Cloudflare API token. Add funded relayer, OAuth, EVM sponsor,
   or R2 credentials only for features that target will use.
3. Run `pnpm router:deploy:env-keygen -- --env staging --values-file
"$HOME/.seams/staging-deployment.env" --apply`, then repeat with an
   independent production values file. Store each command's stdout backup
   securely. See [tooling.md](tooling.md#github-environment-bootstrap).
4. Use `pnpm router:deploy:env-apply -- --env staging --apply` for later
   operator-owned configuration changes. This preserves generated identities.
5. Push `dev` for staging or `main` for production. Successful CI applies D1
   migrations, bootstraps the generated tenant and publishable key, provisions
   the signing-root secret, and deploys the target Workers and Pages projects.
6. Configure R2 credentials when SDK bundle publication is required. The R2
   workflow exits successfully without publishing when they are absent.
7. Verify D1 backups and restore procedures from
   [infra.md](infra.md#cloudflare-data).

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
pnpm router:deploy:env-keygen -- --env staging
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
```

Run `operation=deploy` only after `pnpm router:deploy:check` passes on the
target commit. Router A/B role config lives in
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).

## Deploy Order

The automatic branch release runs in this order:

1. Successful `ci` for the current branch tip.
2. SigningWorker, Deriver A, Deriver B, and Router.
3. Gateway D1 migrations, Durable Object migrations, Worker secrets, deploy,
   and readiness check.
4. `seams.sh` and `wallet.seams.sh` from the same SHA.

An older CI run is rejected after a newer commit becomes the branch tip.

## Follow-On Docs

- [infra.md](infra.md): GitHub Environment values, Cloudflare setup, D1/DO/R2
  data services, Worker secrets, and migration commands.
- [tooling.md](tooling.md): deployment script commands, GitHub Environment
  bootstrap/apply mode, release validation, and staging operations.
- [sdk.md](sdk.md): SDK runtime bundle publishing, Pages `/sdk` assets, R2
  prefixes, npm release steps, and rollback.
- [release.md](release.md): versioned release process.
