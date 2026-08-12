# Deployment

This is the operational runbook for the SDK runtime, Cloudflare Pages sites,
Router A/B Workers, Gateway, and their backing data services. The deployment
surface has five hand-written workflows and two top-level deployment scripts.

The production testnet/mainnet topology and lane-aware pipeline are specified in
[deployment-plan-5.md](deployment-plan-5.md).

The operational pages below describe the deployment pipeline currently present
in the repository, including the production network selector and provisioning
gates for the two production lanes. Deployment Plan 5 records the remaining
resource provisioning and cutover work.

## Document map

- [README.md](README.md): current workflow topology, branch rules, deployment
  order, failure handling, and rollback.
- [infra.md](infra.md): GitHub Environments, Cloudflare resources, storage,
  backup, and recovery setup.
- [tooling.md](tooling.md): environment generation and deployment command
  reference.
- [release.md](release.md): SDK release and hosted-surface release runbook.
- [sdk.md](sdk.md): SDK package and runtime-asset deployment.
- [email-otp-providers.md](email-otp-providers.md): select Resend or Amazon SES for Email OTP
  delivery and configure provider secrets.
- [aws-ses.md](aws-ses.md): Amazon SES sender identity, sandbox testing, permissions, and monthly
  cost guardrails.
- [deployment-plan-5.md](deployment-plan-5.md): three-backend-lane, two-site
  topology, migration sequence, and provisioning status.
- [refactor-82-staging-log.md](refactor-82-staging-log.md): generated staging
  D1/DO evidence template still used by `d1:staging:runbook`.
- [router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml):
  example GitHub Environment contract for Router A/B custody roles.

## System and branch rules

Each deployment targets one complete lane. Backend and frontend lanes are
independent and use the currently deployed version of the other lane during
smoke checks.

| Workflow                                                  | Manual ref  | Automatic trigger | Scope                                   |
| --------------------------------------------------------- | ----------- | ----------------- | --------------------------------------- |
| `.github/workflows/deploy-staging-backend.yml`            | `dev` only  | None              | Staging testnet backend lane            |
| `.github/workflows/deploy-production-testnet-backend.yml` | `main` only | None              | Production testnet backend lane         |
| `.github/workflows/deploy-production-mainnet-backend.yml` | `main` only | None              | Production mainnet backend lane         |
| `.github/workflows/deploy-staging-frontend.yml`           | `dev` only  | None              | Staging site, docs, and wallet Pages    |
| `.github/workflows/deploy-production-frontend.yml`        | `main` only | None              | Production site, docs, and wallet Pages |

The repository validation workflows remain separate. The deployment workflows
use no `workflow_run` trigger and accept no arbitrary revision input. Every job
checks out `${{ github.sha }}` from its workflow event. Staging therefore runs
the `dev` commit that started the run; production runs the `main` commit that
started the run. Direct pushes to protected `main` remain disabled. Production
is manual and uses the existing `production` environment, whose branch policy
and the workflow branch guard both restrict deployments to `main`.

## Dev → staging → PR → main → production

`dev` is the staging integration branch. `main` is the protected production
branch. A production deployment promotes a reviewed `dev` change into `main`,
then rebuilds the merged `main` revision from source.

### Staging branch parity invariant

Every staging deployment starts from the complete `dev` integration branch.
Before dispatching either staging workflow:

1. Commit every change intended for staging and leave the `dev` worktree clean.
2. Integrate the latest `origin/dev` into local `dev` according to repository
   policy.
3. Push the complete local branch with `git push origin dev:dev`.
4. Fetch `origin/dev` again and require the local and upstream `dev` SHAs to
   match exactly.

Abort the deployment when the worktree is dirty, the push is rejected, or the
SHAs differ. Deployment-only branches, isolated worktrees, partial
cherry-picks, and selected-commit pushes are outside the staging release path.
The workflow event SHA must equal both verified `dev` SHAs.

```bash
git switch dev
git status --short # must print nothing
git fetch origin dev
# Integrate origin/dev here when it differs from local dev.
git push origin dev:dev
git fetch origin dev
staging_local_sha="$(git rev-parse dev)"
staging_upstream_sha="$(git rev-parse origin/dev)"
test "$staging_local_sha" = "$staging_upstream_sha"
```

### Production branch parity invariant

Every production deployment starts from the complete protected `main` branch.
Promote the full staging-tested `dev` integration through the repository's
protected pull-request flow. After the promotion merges:

1. Leave the local worktree clean.
2. Fetch `origin/main` and fast-forward local `main` to the merged upstream
   branch.
3. Require the local and upstream `main` SHAs to match exactly.
4. Dispatch every production workflow from that verified `main` SHA.

Abort the deployment when the promotion is incomplete, the worktree is dirty,
the fast-forward fails, or the SHAs differ. Partial promotions, isolated
release branches, partial cherry-picks, selected-commit pushes, and mixed-SHA
production deployments are outside the release path. Every production
workflow event SHA must equal both verified `main` SHAs.

```bash
git switch main
git status --short # must print nothing
git fetch origin main
git merge --ff-only origin/main
production_local_sha="$(git rev-parse main)"
production_upstream_sha="$(git rev-parse origin/main)"
test "$production_local_sha" = "$production_upstream_sha"
```

1. Push the candidate commit to `dev`. The staging workflows accept `dev` only.
   The `dev` branch is currently the integration branch, so feature work may
   arrive through a PR or an integration push according to the repository's
   development policy.
2. Deploy both staging surfaces from that `dev` tip and exercise the staging
   site, wallet iframe, and API. The workflow event SHA is the exact revision
   built and deployed.
3. Open a pull request from `dev` to protected `main`. Resolve conversations
   and complete the repository's review/check requirements before merging.
   Direct pushes to `main` are disabled.
4. Merge the PR. If the merge strategy creates a new commit (for example, a
   squash merge), production uses that new `main` SHA and rebuilds it from
   source; it does not reuse the staging artifact.
5. Manually dispatch the production testnet backend, production mainnet
   backend, and shared production frontend workflows from the resulting
   `main` tip.

The command sequence is:

```bash
# Run the staging branch parity check above first.
gh workflow run deploy-staging-backend.yml --ref dev
gh workflow run deploy-staging-frontend.yml --ref dev

# Open and merge the promotion PR through GitHub's protected-main flow.
gh pr create --base main --head dev --title "Promote dev to main"

# After the PR is merged, run the production branch parity check above, then
# dispatch the independent backend lane workflows and shared frontend workflow.
gh workflow run deploy-production-testnet-backend.yml --ref main
gh workflow run deploy-production-mainnet-backend.yml --ref main
gh workflow run deploy-production-frontend.yml --ref main
```

The PR merge and the production dispatch are separate operations. No production
workflow runs automatically when the PR merges. The production environment
branch policy and the workflow guards both reject a production run from any
branch other than `main`.

The production backend workflows are present as independent lane entrypoints.
Their plans are available immediately, while `production-testnet` and
`production-mainnet` deployment operations remain gated until their fresh
resources and identities are provisioned. Staging is the currently provisioned
backend lane.

There are no `source_sha`, artifact-run, release-set, or coordination-receipt
inputs. A deployment always covers the whole lane; changed-file component
selection is not part of the system.

## Files and commands

The workflow YAML owns branch restrictions, GitHub environment binding, and
visible job order. The scripts own target parsing and
component operations:

```text
scripts/deploy-backend.mjs
  pnpm deploy:backend <plan|build|preflight|migrate|deploy|smoke> --lane <staging-testnet|production-testnet|production-mainnet>

scripts/deploy-frontend.mjs
  pnpm deploy:frontend <plan|build|deploy|smoke> --site <staging|production>

deployment/targets.json
  release sites, backend lanes, capabilities, resources, provisioning state,
  non-secret Gateway configuration, and secret ownership
```

`plan` is the local review command. It needs no credentials, validates the
lane or site identity, and prints the complete ordered sequence without
changing a remote resource. Pending production lanes still produce plans with
their required provisioning values. `build`, `preflight`, `migrate`, `deploy`,
and `smoke` reject pending lanes before credential use or remote mutation.

Backend `preflight`, `migrate`, and `deploy` are CI operations. Preflight is
component-scoped and runs once per custody environment; every leg completes
before migration or deployment. Migrations and deployment mutate remote
resources, and secret-bearing operations remain inside their owning GitHub
environment. Frontend deploy and both lane smoke operations run in CI. No
local command deploys a whole backend lane, and no process receives both
Deriver A and Deriver B secrets.

Lane capabilities derive the Gateway secret requirement at runtime:

- An enabled capability requires and uploads its declared secrets.
- A disabled capability ignores those secrets and never uploads them.
- Required secret names live only in `deployment/targets.json`. Preflight
  receives the bound environment through `toJSON(secrets)` and checks names
  without printing values.
- Optional Gateway secrets are uploaded when configured and are not required
  by preflight.

This keeps configuration validation ahead of every remote mutation.

## Environments and custody

The deployment topology contains three backend lanes, each with five
separately bound component environments:

| Lane                 | Custody environment prefix | Resources                                      |
| -------------------- | -------------------------- | ---------------------------------------------- |
| `staging-testnet`    | `staging-*`                | Provisioned staging testnet resources          |
| `production-testnet` | `production-testnet-*`     | Pending fresh testnet resources and identities |
| `production-mainnet` | `production-*`             | Pending fresh mainnet resources and identities |

The top-level `staging` and `production` GitHub Environments remain the two
frontend release environments. They own Pages credentials and public build
configuration; they do not own backend custody material.

Deriver A and Deriver B secrets never share a job. The preflight matrix binds
one custody environment per leg and checks its inventory against
`deployment/targets.json`. The existing `staging` and `production`
environments own the frontend build variables and Pages credentials. See
[infra.md](infra.md) for the complete environment and secret tables.

## Deployment order

### Backend

Each hand-written backend workflow makes this dependency order visible:

1. Build all backend components once in a clean workspace. The first build
   step rejects any branch other than `dev` for staging or `main` for
   production and rejects pending lane provisioning.
2. Complete every component-scoped preflight against the five custody
   environments for that lane.
3. Apply D1 migrations in order: console first, signer second. Migration
   fingerprints guard the operation.
4. Validate and deploy SigningWorker, Deriver A, and Deriver B concurrently.
5. Validate and deploy MPC Router after all three workers complete.
6. Validate Gateway configuration and deploy Gateway.
7. Run backend smoke checks as the final Gateway job step.

Gateway is last because it depends on the preceding backend services. Worker
releases cannot rely on coordinated ordering: each worker may eventually be
deployed from a separate repository or account. Router waits for all three
worker deployment jobs before publishing. A failed run leaves successful
parallel jobs applied; rerunning failed jobs uses the same workflow SHA and
successful same-run build artifact.

The Gateway uses partitioned D1 and the MPC Router for Ed25519 Yao immediately.
Deployments have no tenant-runtime fallback, family selector, or admission-drain
window. Remove retired `ROUTER_AB_YAO_GATEWAY_*` cutoff/drain values from GitHub
Environments instead of carrying them into a release.

Backend deployment never creates an organization, project, project environment,
or API key. An administrator completes onboarding, creates the project and
browser-safe publishable key, then stores `VITE_SEAMS_PROJECT_ENVIRONMENT_ID`
and `VITE_SEAMS_PUBLISHABLE_KEY` in the target's GitHub environment. Redeploy
the frontend after either value changes.

### Frontend

The frontend workflow has one environment-bound job. It validates its site,
builds the site once, deploys the app and wallet Pages projects from that same
workspace, and runs HTTP readiness, SDK asset, and compatibility smoke checks.
Staging can execute this path with its provisioned lane. Production plan output
works while either backend lane is pending; production build/deploy/smoke is
gated until both lanes are provisioned. The frontend workflow does not wait for
the backend workflows, and the backend workflows do not wait for it.

## Same-run artifacts

The backend build job produces one fixed-name artifact for the current run.
The five deploy jobs download it and assert that their expected entry files
exist before mutation. A failed-job rerun reuses the successful build; a full
workflow rerun overwrites the fixed name within its own run. Frontend needs no
artifact transfer because build, both Pages deployments, and smoke execute in
one job.

Artifacts never move between runs. There is no release manifest, cross-run
promotion, or custom historical-run selection. The workflow event's commit is
the source of truth.

## API evolution and migrations

Frontend and backend changes use expand-contract deployment:

1. Deploy backward-compatible backend additions.
2. Deploy the frontend that uses those additions.
3. Remove obsolete backend behavior in a later deployment after the old
   frontend is no longer live.

Every backend deployment must serve the frontend already deployed, and every
frontend deployment must work with the backend already deployed. Breaking API
changes are split across deployments; lane coordination receipts are not used.

D1 migrations are forward-only. Reverting a commit does not undo an applied
schema change. Undoing one requires a new forward migration. Land a
non-additive schema change in an earlier deployment, then deploy code that
depends on it.

## Smoke, failure, and rollback

Smoke is the final gate for each lane. Backend checks readiness, deployed
revision, Gateway bindings, ceremony key availability, and configured Router
health. Frontend checks both Pages origins, representative SDK runtime assets,
and compatibility with the currently deployed backend.

For Workers and Pages, revert the bad change or land a corrective commit on the
target branch, then deploy that new branch tip. Rollback rebuilds the lane from
the new commit; historical SHA and cross-run artifact inputs are unavailable.
Secrets, D1 schema, Durable Object state, and other environment state require
their own recovery procedure.

For an interrupted run, rerun the failed jobs at the same `${{ github.sha }}`.
Migrations are fingerprint-checked and idempotent, and Worker deployment is
last-write-wins. Do not treat a code rollback as a database rollback.

## Infrastructure and setup

Before the first run, provision the lane-specific GitHub environments and
Cloudflare resources, populate [infra.md](infra.md), and validate each lane or
site with the local `plan` command. Staging testnet is provisioned. Production
testnet and mainnet remain pending until fresh resources and identities are
generated. Keep all three lanes' D1 databases, Durable Object namespaces,
Worker resources, Pages projects, and secrets separate. The target file is the
checked-in source for capabilities, resources, provisioning state, and
ownership; GitHub job YAML remains the explicit source for secret bindings.

For Router A/B configuration, use
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).
For D1, R2, Worker, and Pages details, use [infra.md](infra.md). Deployment
script-specific commands remain in [tooling.md](tooling.md).
