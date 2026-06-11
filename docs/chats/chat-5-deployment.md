# Chat 5: Deployment Workflow And Docs Rewrite

Date: June 9, 2026

Status: deployment handoff. Workflow and docs updates were prepared in this
chat, but no final git commit or live GitHub deploy was completed here.

## Goal

Review what was needed to deploy the SDK and its hosted surfaces, update the
GitHub Actions setup, account for required infra such as Postgres, and rewrite
the deployment docs accordingly.

Later in the same chat, the user also asked to rename a plan file by prepending
`refactor-5x-`.

## Deployment Direction Chosen

The deployment surface was simplified to two GitHub deployment environments:

- `staging`: automatic target for `dev`
- `production`: automatic target for `main`

The deployment axis is the environment, not a separate testnet-only workflow
family. Network ids, RPC URLs, relayer accounts, wallet origins, Pages project
names, and related values are expected to come from GitHub Environment vars,
GitHub Environment secrets, and `wrangler.toml`.

## Workflow Changes Prepared

The deployment pass in this chat prepared these workflow changes:

- update GitHub Actions versions in `.github/workflows/ci.yml`
- update GitHub Actions versions in `.github/workflows/deploy-relay.yml`
- update GitHub Actions versions in `.github/workflows/publish-sdk-r2.yml`
- add `.github/workflows/deploy-pages.yml`
- remove duplicate testnet-only workflows:
  - `.github/workflows/deploy-vite-testnet.yml`
  - `.github/workflows/deploy-wallet-iframe-testnet.yml`
  - `.github/workflows/deploy-relay-testnet.yml`
  - `.github/workflows/publish-sdk-r2-testnet.yml`

Key workflow decisions:

- `deploy-pages.yml` builds the SDK once, builds `examples/tatchi-site`, copies
  `sdk/dist` assets into `/sdk/*`, and deploys the app Pages project, the
  wallet Pages project, or both.
- `deploy-relay.yml` keeps relay deploys in one workflow and switches between
  `staging` and `production`.
- `publish-sdk-r2.yml` remains the SDK runtime-bundle publisher for Cloudflare
  R2.
- `ci.yml` remains the main validation workflow, including Postgres smoke and
  threshold-signing coverage.

Tooling upgrades prepared in that pass:

- `actions/checkout`: `v6`
- `actions/setup-node`: `v6`
- `pnpm/action-setup`: `v5`
- workflow Node version: `24`
- workflow pnpm version: `10.28.2`
- `sigstore/cosign-installer`: `v4.1.1`
- `actions/upload-artifact`: `v7`

## Docs Added Or Rewritten

This chat reshaped deployment docs around runbooks instead of a single narrow
release note:

- `docs/deployment/README.md`
- `docs/deployment/infra.md`
- `docs/deployment/sdk.md`
- `docs/deployment/release.md`

The intended content split was:

- `README.md`: point readers at the deployment runbook
- `docs/deployment/README.md`: deployment model, workflow inventory, first
  deploy checklist, promotion flow
- `docs/deployment/infra.md`: GitHub Environment secrets/vars, Cloudflare
  Pages, relay Worker secrets, R2 bucket setup, Postgres split-domain setup,
  Redis/Upstash notes
- `docs/deployment/sdk.md`: SDK build, Pages `/sdk/*` runtime asset flow, R2
  publish behavior, npm publish, verification, rollback
- `docs/deployment/release.md`: release runbook and deployment order

The root `README.md` was also updated to point at `docs/deployment/README.md`
and to use “specs” wording.

## Infra Model Captured

The deployment docs written in this chat assume:

- one Cloudflare R2 bucket for `sdk/dist` runtime bundles
- two Cloudflare Pages projects:
  - app/site
  - wallet origin
- one Cloudflare relay Worker with `staging` and `production` Wrangler envs
- split Postgres domains:
  - signer/runtime state
  - console/control-plane state

The Postgres guidance documented in this chat was:

- use `POSTGRES_URL` and `POSTGRES_MIGRATION_URL` for signer/runtime
- use `CONSOLE_POSTGRES_URL` and `CONSOLE_POSTGRES_MIGRATION_URL` for console
- keep runtime roles DML-only and migrator roles DDL-capable
- use the example relay scripts for local split bootstrap, migration, and
  verification:
  - `postgres:setup:split`
  - `postgres:bootstrap:split`
  - `postgres:migrate:all`
  - `postgres:verify:split`

## Validation Run During The Deployment Pass

The deployment/doc workflow pass in this chat ran these checks:

- Prettier check/write on the touched workflows and docs
- YAML parsing for:
  - `.github/workflows/ci.yml`
  - `.github/workflows/deploy-relay.yml`
  - `.github/workflows/deploy-pages.yml`
  - `.github/workflows/publish-sdk-r2.yml`
- `node-actionlint` with ignores for its stale knowledge of:
  - `merge_group`
  - GitHub `vars`

At the time of that pass, `pnpm -C examples/tatchi-site typecheck` did not pass
because of unrelated signing-engine errors around
`client/src/core/signingEngine/orchestration/near/transactionsFlow.ts`. Those
errors were not part of the deployment scope and were left alone.

## What Was Intentionally Not Done

This chat did not finish:

1. a clean git commit for the deployment changes
2. a real GitHub-hosted deploy to `staging` or `production`
3. GitHub Environment population for all required vars and secrets

The deployment workflows were prepared, but live deploy execution still depends
on GitHub Environment setup and a clean commit strategy around the surrounding
dirty worktree.

## Worktree Context During This Chat

The repo was already dirty with a large amount of unrelated signing-engine and
documentation refactor work. The deployment pass was explicitly scoped to:

- `.github/workflows/*`
- `README.md`
- `docs/deployment/*`

The later `git commit changes` request was interrupted before any commit was
made. No deployment-only commit was created in this chat.

## Later Rename Request In This Chat

Later in the same thread, the user asked to prepend `refactor-5x-` to a plan
filename.

The resulting plan file is:

- `docs/threshold-ed25519/refactor-5x-signing-latency-optimization-plan.md`

At the time of the rename check, no repo references to the old filename were
found, so no follow-on text updates were needed for that rename.

## Next Steps

1. Separate the deployment/workflow/docs changes from unrelated worktree churn
   before committing.
2. Populate GitHub Environments `staging` and `production` with the vars and
   secrets documented in `docs/deployment/infra.md`.
3. Run a staging dry run in this order:
   - `publish-sdk-r2`
   - `deploy-pages`
   - `deploy-relay`
4. Verify:
   - Pages app and wallet deploy from the same commit
   - `/sdk/wallet-iframe-host-runtime.js` loads from the wallet origin
   - relay registration/signing flows work against the deployed relay
5. Commit the plan-file rename when the surrounding worktree strategy is clear.

## Resume Prompt

Resume by isolating the deployment workflow/docs diff from unrelated refactor
work, then commit and dry-run the `staging` deployment path documented in
`docs/deployment/README.md` and `docs/deployment/infra.md`.
