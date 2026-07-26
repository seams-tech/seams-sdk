# Deployment

This is the operational runbook for the SDK runtime, Cloudflare Pages sites,
Router A/B Workers, Gateway, and their backing data services. The deployment
surface has four hand-written workflows and two top-level deployment scripts.

## System and branch rules

Each deployment targets one complete lane. Backend and frontend lanes are
independent and use the currently deployed version of the other lane during
smoke checks.

| Workflow                                           | Manual ref  | Automatic trigger | Scope                           |
| -------------------------------------------------- | ----------- | ----------------- | ------------------------------- |
| `.github/workflows/deploy-staging-backend.yml`     | `dev` only  | None              | Full staging backend lane       |
| `.github/workflows/deploy-production-backend.yml`  | `main` only | None              | Full production backend lane    |
| `.github/workflows/deploy-staging-frontend.yml`    | `dev` only  | None              | Staging app and wallet Pages    |
| `.github/workflows/deploy-production-frontend.yml` | `main` only | None              | Production app and wallet Pages |

The repository validation workflows remain separate. The deployment workflows
use no `workflow_run` trigger and accept no arbitrary revision input. Every job
checks out `${{ github.sha }}` from its workflow event. Staging therefore runs
the `dev` commit that started the run; production runs the `main` commit that
started the run. Direct pushes to protected `main` remain disabled. Production
is manual and uses the existing `production` environment, whose branch policy
and the workflow branch guard both restrict deployments to `main`.

Normal promotion is:

```bash
# Staging remains an explicit deployment
gh workflow run deploy-staging-backend.yml --ref dev
gh workflow run deploy-staging-frontend.yml --ref dev

# Production: merge an accepted change into protected main, then dispatch
gh workflow run deploy-production-backend.yml --ref main
gh workflow run deploy-production-frontend.yml --ref main
```

There are no `source_sha`, artifact-run, release-set, or coordination-receipt
inputs. A deployment always covers the whole lane; changed-file component
selection is not part of the system.

## Files and commands

The workflow YAML owns branch restrictions, GitHub environment binding, and
visible job order. The scripts own target parsing and
component operations:

```text
scripts/deploy-backend.mjs
  pnpm deploy:backend <plan|build|preflight|migrate|deploy|smoke> --target <staging|production>

scripts/deploy-frontend.mjs
  pnpm deploy:frontend <plan|build|deploy|smoke> --target <staging|production>

deployment/targets.json
  target capabilities, resources, non-secret Gateway configuration, and secret ownership
```

`plan` is the local review command. It needs no credentials, validates the
target, and prints the complete ordered mutation sequence without changing a
remote resource. `build` is also runnable locally and performs no remote
mutation.

Backend `preflight`, `migrate`, and `deploy` are CI operations. Preflight is
component-scoped and runs once per custody environment; every leg completes
before migration or deployment. Migrations and deployment mutate remote
resources, and secret-bearing operations remain inside their owning GitHub
environment. Frontend deploy and both lane smoke operations run in CI. No
local command deploys a whole backend lane, and no process receives both
Deriver A and Deriver B secrets.

Target capabilities derive the Gateway secret requirement at runtime:

- An enabled capability requires and uploads its declared secrets.
- A disabled capability ignores those secrets and never uploads them.
- Required secret names live only in `deployment/targets.json`. Preflight
  receives the bound environment through `toJSON(secrets)` and checks names
  without printing values.
- Optional Gateway secrets are uploaded when configured and are not required
  by preflight.

This keeps configuration validation ahead of every remote mutation.

## Environments and custody

The backend lane contains five separately bound component environments:

| Environment               | Custody                                                              |
| ------------------------- | -------------------------------------------------------------------- |
| `<target>-signing-worker` | SigningWorker server-output private key                              |
| `<target>-deriver-a`      | Deriver A root-share, envelope, and peer-signing secrets             |
| `<target>-deriver-b`      | Deriver B root-share, envelope, and peer-signing secrets             |
| `<target>-mpc-router`     | Router A/B internal service-auth secret                              |
| `<target>-gateway`        | Gateway secrets, signing-root KEK, and signing-session seal set      |
| `<target>`                | Cloudflare Pages credentials and public frontend build configuration |

Deriver A and Deriver B secrets never share a job. The preflight matrix binds
one custody environment per leg and checks its inventory against
`deployment/targets.json`. The existing `staging` and `production`
environments own the frontend build variables and Pages credentials. See
[infra.md](infra.md) for the complete environment and secret tables.

## Deployment order

### Backend

The hand-written backend workflow makes this dependency order visible:

1. Build all backend components once in a clean workspace. The first build
   step rejects any branch other than `dev` for staging or `main` for
   production.
2. Complete every component-scoped preflight against the five existing custody
   environments.
3. Apply D1 migrations in order: console first, signer second. Migration
   fingerprints guard the operation.
4. Validate and deploy SigningWorker, Deriver A, and Deriver B concurrently.
5. Validate and deploy MPC Router after all three workers complete.
6. Validate Gateway configuration, bootstrap the tenant, upsert the
   signing-root KEK, and deploy Gateway.
7. Run backend smoke checks as the final Gateway job step.

Gateway is last because it depends on the preceding backend services. Worker
releases cannot rely on coordinated ordering: each worker may eventually be
deployed from a separate repository or account. Router waits for all three
worker deployment jobs before publishing. A failed run leaves successful
parallel jobs applied; rerunning failed jobs uses the same workflow SHA and
successful same-run build artifact.

### Frontend

The frontend workflow has one environment-bound job. It validates its target,
builds the site once, deploys the app and wallet Pages projects from that same
workspace, and runs HTTP readiness, SDK asset, and compatibility smoke checks.
It does not wait for the backend workflow, and the backend workflow does not
wait for it.

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

Before the first run, provision the target-specific GitHub environments and
Cloudflare resources, populate [infra.md](infra.md), and validate the target
with the local `plan` command. Keep staging and production D1 databases,
Durable Object namespaces, Worker resources, Pages projects, and secrets
separate. The target file is the checked-in source for capabilities, resources,
and ownership; GitHub job YAML remains the explicit source for secret bindings.

For Router A/B configuration, use
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).
For D1, R2, Worker, and Pages details, use [infra.md](infra.md). Deployment
script-specific commands remain in [tooling.md](tooling.md).
