# Deployment Refactor 4: Linear Deployment From Scratch

Date created: July 25, 2026

Status: implementation complete; staging and production proof pending

Supersedes: `refactor-deployment-1.md`, `refactor-deployment-2.md`,
`refactor-deployment-3.md`. Those three refactors are abandoned in place, not
continued. This document replaces the system they built.

## Objective

Replace the generated-workflow deployment framework with two deployment scripts
exposing a small set of explicit, component-scoped operations, plus four
hand-written GitHub Actions entrypoints that own only revision pinning,
environment binding, and the visible order in which those operations
run.

The scripts are readable and partly runnable locally — `plan` needs no
credentials at all — but no local mode deploys a whole backend lane, because no
single process may hold two custody domains. See Security Invariants.

The success criterion is comprehension, not feature count: a new engineer must
be able to understand normal deployment by reading one operational page, two
top-level scripts, one target file, and four YAML files in under fifteen
minutes. Those files must answer "what will this run mutate, in what order, and
what does it require." Retained low-level helpers are implementation details
that an operator does not need to read.

Every control that survives this refactor must prevent a specific, nameable
kind of damage. Controls that exist to protect the machinery of previous
refactors are removed with the machinery.

## Why Refactors 1-3 Failed

The prior refactors added provenance, content-addressed release sets, selective
component deployment, and workflow policy checking. Each layer was individually
defensible. Together they produced a system whose failure modes are only
discoverable in CI, on the far side of a remote mutation.

Measured state of the surface being replaced:

- 7,472 lines across four deployment workflow files. The two stack workflows
  are 2,691 lines each.
- 491 lines across two validation workflows that remain outside this refactor.
- 1,048 of those 2,691 lines are a duplicate of the automatic job graph,
  expanded a second time as `manual_*` jobs.
- ~6,300 lines of deployment tooling under `scripts/`, of which 832 lines
  generate the YAML and 528 lines check the YAML the generator produced.
- 30 of the last 71 commits touching deployment paths are fixes to deployment
  itself. Nine of those are the same class of defect: an artifact, manifest, or
  bundle path that disagreed between the producer and the consumer.

Three concrete defects justify replacement rather than further repair.

### The workflow/script split silently mixes two revisions

`workflow_run` executes the workflow definition from the default branch, while
every job checks out `SOURCE_SHA`. For staging that means main's YAML drives
dev's scripts. The two are versioned independently and nothing detects the
mismatch.

This is the actual cause of the staging Stripe failure, and it is not a missing
secret:

```
STRIPE_API_SK references in .github/workflows/deploy-staging-cloudflare-stack.yml
  on main: 0
  on dev:  4
```

`44ab7fc60 fix(billing): wire Stripe Checkout through gateway deploys` exists on
`dev` and `codex/refactor-deployment-3`, not on `main`. The failing run used
main's YAML, which never binds `STRIPE_API_SK` into the job environment, driving
dev's `write-gateway-secrets-file.mjs`, which lists it in
`REQUIRED_SECRET_NAMES`. The secret may well be present in the
`staging-gateway` environment; the YAML that ran had no line to pass it through.

Critically, the preflight gate that would have caught this **already exists on
`dev`**, at `deploy-staging-cloudflare-stack.yml:2495`, correctly ordered before
the migration step at line 2538. It did not fire because it was not the code
that ran. Adding more validation would not have prevented this failure. Pinning
the executing revision would have.

### Duplication propagates single defects into four places

`scripts/deployment-workflow-templates/deploy-cloudflare-gateway.yml:199`
references `steps.gateway_readiness.outputs.gateway_origin`. The only step id in
that job is `gateway_origin`. GitHub resolves unknown step ids to the empty
string without error, so the deployment summary has been reporting a blank
gateway origin. The template expands into the automatic and manual graphs of
both the staging and production workflows: one defect, four live sites.

### Requirements are hard-coded rather than derived

`packages/console-server-ts/scripts/write-gateway-secrets-file.mjs:5-12` marks
`STRIPE_API_SK` as required and `RELAYER_PRIVATE_KEY` as optional. Neither
classification is connected to which capabilities the target actually has
enabled. The requirement is discovered at the moment the file is written, which
is after migrations, tenant bootstrap, and the KEK upsert have already mutated
the target.

## Decision Summary

1. Two Node scripts expose the deployment operations. GitHub Actions owns only
   environment binding and the visible job dependency order.
2. Every job uses the immutable `${{ github.sha }}` from one workflow event.
   Staging accepts only `dev`; production accepts only `main`. See Pinning.
3. Every deployment deploys its entire lane. There is no component selection.
4. There is one deployment graph per lane. The automatic and manual paths are
   the same jobs, differing only in trigger.
5. All configuration validation completes before the first remote mutation.
6. Secret requirements and upload sets are derived at runtime from the target's
   enabled capabilities, declared in one checked-in target file. Each preflight
   leg receives only its bound environment's secret inventory through
   `${{ toJSON(secrets) }}` and checks required names without printing values.
7. Per-component GitHub environments are retained. They are a custody boundary,
   not organizational overhead. See Security Invariants.
8. Artifacts pass between jobs within a single run only. Cross-run artifact
   promotion, release-set identity, and manifest verification are removed.
9. Production deploys the `main` commit identified by its workflow event,
   through manual dispatch and the existing `production` environment branch
   policy. Rollback uses a revert or corrective commit.
10. Workflow YAML is written by hand and reviewed as source. The generator, the
    templates, and the policy checker that validated the generator's output are
    all deleted.
11. Frontend and backend evolve through expand-contract changes. Each lane
    remains compatible with the version of the other lane that is already live.

## Pinning

Revision mixing is the defect this refactor exists to eliminate. GitHub already
provides the required pin: `${{ github.sha }}` identifies the immutable commit
whose workflow is running.

- Every checkout uses `ref: ${{ github.sha }}`.
- No job resolves a branch name independently.
- Neither workflow accepts a `source_sha` input.
- Staging requires `github.ref == 'refs/heads/dev'`.
- Production requires `github.ref == 'refs/heads/main'`.
- Rollback is a revert or corrective commit that becomes the new branch tip.

Cost accepted: rollback rebuilds the lane rather than redeploying a stored
artifact. That is the direct consequence of deleting cross-run promotion, and it
is the intended trade. It also means lane wall clock and rollback time are the
same number — see Open Questions.

## Target Surface

Four workflows, hand-written, no generation. The backend files are new. The
frontend files replace the generated workflows at their existing paths:

```
.github/workflows/deploy-staging-backend.yml
.github/workflows/deploy-production-backend.yml
.github/workflows/deploy-staging-frontend.yml
.github/workflows/deploy-production-frontend.yml
```

Two top-level interfaces, readable top to bottom:

```
scripts/deploy-backend.mjs
  → pnpm deploy:backend <plan|build|preflight|migrate|deploy|smoke> --target <staging|production>
scripts/deploy-frontend.mjs
  → pnpm deploy:frontend <plan|build|deploy|smoke> --target <staging|production>
```

One configuration file, checked in and parsed at runtime:

```
deployment/targets.json       → per-target capabilities, resources, and secret ownership
```

### Trigger rules

- The new workflows use no `workflow_run` trigger.
- Staging supports manual dispatch from `dev`. Its `push` trigger is enabled
  after the replacement workflows pass staging and production.
- Production supports manual dispatch from `main` only.
- The workflows expose no arbitrary revision input.

### On the "50 lines per YAML" target

A 50-line ceiling per workflow is not achievable while preserving per-component
custody separation, and custody wins. `environment:` is a job-level YAML
construct — a Node script cannot bind a GitHub environment from the inside. Each
component that owns distinct secrets requires its own job.

The honest target is approximately 300-360 lines per backend workflow with a
strictly uniform shape:

- one build job whose first step enforces the target branch;
- one compact preflight job, matrixed over the five custody environments;
- one migration job bound to the Gateway environment;
- five deploy jobs with the same checkout, setup, artifact download, validation,
  and deployment lifecycle;
- backend smoke runs as the final step of the Gateway deploy job.

Each deploy job exposes its role-specific environment bindings and invokes the
same component-scoped deployment command. The migration job is the only
distinct mutation job. The comprehension criterion survives because there is
one script to read and the YAML is a visible dependency graph and dispatch
table.

## What Is Deleted or Replaced

Delete the old framework and replace the generated frontend workflow contents:

- `scripts/generate-deployment-workflows.mjs` (832 lines)
- `scripts/check-deployment-workflows.mjs` (528 lines)
- `scripts/deployment-workflow-templates/` (2,469 lines across five templates)
- `scripts/deployment-release.mjs` — release-set identity and manifests
- `scripts/deployment-artifact.mjs` — artifact identity and digest plumbing
- `scripts/deployment-components.mjs` — changed-file component selection
- `scripts/deployment-coordination-receipt.mjs` — cross-lane receipts
- `scripts/deployment-api-compatibility.mjs` — contract values duplicated into
  GitHub variables
- `crates/router-ab-cloudflare/scripts/assert-release-ready.mjs` — source guard
  for the deleted workflow framework
- `.github/workflows/deploy-staging-cloudflare-stack.yml`
- `.github/workflows/deploy-production-cloudflare-stack.yml`
- The generated contents of `.github/workflows/deploy-staging-frontend.yml`
  and `.github/workflows/deploy-production-frontend.yml`, replaced in place by
  the hand-written workflows
- The `manual_*` job graphs, absorbed into the single graph
- Source-text workflow policy tests that exist only for generated deployment
  YAML

The repository validation workflows remain:

- `.github/workflows/validate-repository.yml`
- `.github/workflows/validate-cloudflare-router-ab.yml`

Retained and called directly by the new scripts:

- `packages/console-server-ts/scripts/apply-remote-d1-migrations.mjs`
- `packages/console-server-ts/scripts/render-d1-gateway-config.mjs`
- `packages/console-server-ts/scripts/bootstrap-gateway-deployment.mjs`
- `packages/console-server-ts/scripts/upsert-signing-root-kek.mjs`
- `packages/console-server-ts/scripts/write-gateway-secrets-file.mjs`, with
  `REQUIRED_SECRET_NAMES` replaced by capability-derived requirements
- `packages/console-server-ts/scripts/read-gateway-deployment-plan.mjs`
- `scripts/migration-fingerprint.mjs`

### Same-run artifact passing is retained; cross-run promotion is not

The build must not run five times. One build job uploads with a fixed artifact
name and `overwrite: true`; each deploy job downloads that name from the current
run. A failed-job rerun can reuse the successful build artifact, while a
full-workflow rerun can replace it without a name collision. This needs no
release manifest, custom content-digest gate, or cross-run `run-id` input. Each
consumer asserts that its fixed entry file exists before deployment. The
verification surface in `deployment-artifact.mjs` and
`deployment-release.mjs` existed to support cross-run promotion. Removing
promotion removes that surface.

## Security Invariants

These are preserved. Any implementation that violates one is wrong regardless of
how much simpler it is.

**Deriver A and Deriver B secrets never occupy the same job.** The current
environments exist for this reason and must survive:

| Environment | Holds |
| --- | --- |
| `<target>-signing-worker` | `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY` |
| `<target>-deriver-a` | `DERIVER_A_ROOT_SHARE_WIRE_SECRET`, `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_A_PEER_SIGNING_KEY` |
| `<target>-deriver-b` | `DERIVER_B_ROOT_SHARE_WIRE_SECRET`, `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_B_PEER_SIGNING_KEY` |
| `<target>-mpc-router` | `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET` |
| `<target>-gateway` | Gateway secrets, `SIGNING_ROOT_KEK_VALUE`, signing-session seal set |
| `<target>` | Cloudflare Pages credentials and build variables |

The existing `production` environment is restricted to `main` by its branch
policy and is used by the production frontend lane. The production workflows
remain manually dispatched. Backend custody environments preserve role-specific
secret access.

`docs/refactor-93.md` requires independent Deriver A and Deriver B secret
custody with separate secret bindings. Collapsing these into one
`<target>-backend` environment would make the deploy job a co-custodian able to
reconstruct both halves of the ceremony input. That is simpler and less secure —
the precise failure mode this refactor exists to eliminate, pointed the wrong
way.

The preflight therefore fans out as a five-row matrix, one leg per custody
environment. Each leg binds one existing component environment and passes
`${{ toJSON(secrets) }}` plus `${{ toJSON(vars) }}` to the preflight command.
The command derives required names from `deployment/targets.json`, inspects
secret keys without printing secret values, and validates required variables.
No secret name is enumerated in workflow YAML. Deploy jobs still bind only
their component environment.

Also retained:

- Production requires a manual workflow dispatch from `main`.
- Production accepts only workflow events from `main`.
- One deployment per environment, enforced by concurrency group.
- Secret values are never echoed; `write-gateway-secrets-file.mjs` keeps mode
  `0o600`.
- Pinned package manager, `--frozen-lockfile`, pinned `RUST_TOOLCHAIN`.
- Post-deployment readiness and deployed-SHA checks.
- Backend API changes remain compatible with the currently deployed frontend.

### Inherited hardening rules

Refactor 3 established twenty-six numbered security invariants. Eight are void
with the receipt and release-set machinery, two are amended below, and the rest
still bind. They are restated here because they are hardening rules rather than
tasks, so they appear in no checklist and would otherwise be lost when that
document is retired.

- Each of the four deployment workflows is the **sole** mutation authority for
  its target and surface. Nothing else may deploy a Worker, a Pages project, or
  a browser SDK runtime asset.
- SDK runtime assets ship inside the environment-bound Pages artifact. There is
  no standalone SDK publisher, and none may be reintroduced.
- The environment is a constant in each workflow. It is never a free-form
  manual input.
- No workflow uses `workflow_call`. This is a custody rule, not a style
  preference: a reusable workflow is a path by which one job's declared
  environment secrets reach another job's execution context.
- No `pull_request_target` workflow receives deployment credentials, and a
  pull-request validation run can never authorize a deployment.
- Workflow permissions grant `contents: read` only. Deployment jobs receive no
  write permissions. The `actions: read` grant that existed for cross-run
  artifact consumers is no longer needed and must not be re-added.
- Concurrency is locked by lane and authority boundary —
  `staging-backend`, `staging-frontend`, `production-backend`,
  `production-frontend` — and an in-progress mutation is **never** cancelled.
- GitHub production environments permit only `main` as a deployment branch.
  This is account state, verified in Phase 0.
- Workflow changes require CODEOWNERS review and protected-branch approval.

Amended from Refactor 3:

- Invariant 8 (separate backend and frontend production approval gates) is
  superseded: the backend and frontend remain separate production workflows,
  each manually dispatched from `main`, and neither invents an approval
  environment.
- Invariant 23 (deployment summary contents) drops release-set ID, coordination
  receipt, and selected/skipped service fields. A summary records target, source
  SHA, deployed components, bundle digest, and smoke result.

### Naming

Refactor 3's naming grammar still governs, including the two validation
workflows this refactor does not touch:
`<Action> / <Environment or scope> / <Surface>`, with branch names never
substituting for environment names.

This refactor amends the surface vocabulary once: `cloudflare-stack` becomes
`backend`, matching the lane concept the rest of this document uses. The
resulting six workflow names are `Validate / repository`,
`Validate / cloudflare-mpc-router-ab`, and `Deploy / <environment> / <backend |
frontend>`.

## Backend Command Contract

One script exposes six explicit operations:

```
scripts/deploy-backend.mjs plan      --target <t>
scripts/deploy-backend.mjs build     --target <t>
scripts/deploy-backend.mjs preflight --target <t> --component <c>
scripts/deploy-backend.mjs migrate   --target <t>
scripts/deploy-backend.mjs deploy    --target <t> --component <c>
scripts/deploy-backend.mjs smoke     --target <t>
```

`plan` parses the target file, validates non-secret configuration, and prints
the exact job order without mutation. It is the local review command. `build`
is also locally runnable. Secret preflight and deployment are component-scoped
CI operations because no laptop or job may receive both Deriver A and Deriver B
secrets.

The workflow expresses one fixed order:

1. Build all backend components once in a clean workspace; the first step
   rejects any branch other than the target branch.
2. Parse `deployment/targets.json` and complete every component-scoped
   preflight.
3. Apply D1 migrations (console, then signer), fingerprint-checked.
4. Validate and deploy Signing Worker.
5. Validate and deploy Deriver A.
6. Validate and deploy Deriver B.
7. Validate and deploy MPC Router.
8. Validate Gateway configuration, bootstrap the tenant, upsert the
   signing-root KEK, deploy Gateway, and run live backend smoke tests.

Every preflight leg completes before the migration/deployment chain begins.
The build precedes preflight because it owns the branch guard. This ordering is
explicit in the hand-written workflow dependency graph.

Because the script has no whole-lane verb, this order appears in the workflow's
`needs:` chain and in the output of `plan`. Keep both short and review the order
directly. No source-text policy check is added.

## Frontend Command Contract

The frontend script has the same small operation vocabulary:

```
scripts/deploy-frontend.mjs plan   --target <t>
scripts/deploy-frontend.mjs build  --target <t>
scripts/deploy-frontend.mjs deploy --target <t>
scripts/deploy-frontend.mjs smoke  --target <t>
```

Each target has one frontend job bound to the existing `staging` or
`production` environment. The job validates the branch, builds the site,
deploys the app and wallet Pages projects from the same output, and runs
frontend smoke tests. No frontend artifact upload/download is needed because
all four operations run in that one custody domain.

The lanes are independent. Neither waits on the other, and there are no
coordination receipts between them.

### API evolution without coordination receipts

Independence requires expand-contract deployment:

1. Deploy backward-compatible backend additions.
2. Deploy the frontend that uses them.
3. Remove obsolete backend behavior in a later deployment after the old
   frontend is no longer live.

A frontend deployment must work with the backend already in production. A
backend deployment must continue serving the frontend already in production.
Breaking changes are split across deployments. No coordination receipt is
needed.

## Capability-Derived Secret Requirements

`deployment/targets.json` declares, per target, which capabilities are enabled,
which component owns them, and what each requires:

```jsonc
{
  "staging": {
    "capabilities": {
      "billing":          { "enabled": true,  "owner": "gateway", "secrets": ["STRIPE_API_SK"] },
      "sponsoredExecution": { "enabled": true, "owner": "gateway", "secrets": [] },
      "signingSessionSeal": { "enabled": true, "owner": "gateway", "secrets": ["SIGNING_SESSION_SEAL_KEY_VERSION", "SIGNING_SESSION_SHAMIR_P_B64U", "SIGNING_SESSION_SEAL_E_S_B64U", "SIGNING_SESSION_SEAL_D_S_B64U"] }
    }
  }
}
```

Rules:

- Capability enabled: its required secret list is enforced by preflight and
  uploaded.
- Capability disabled: its secrets are ignored and never uploaded.
- `RELAYER_PRIVATE_KEY` and `SPONSORED_EVM_EXECUTORS_JSON` remain independent
  optional Gateway secrets. They are uploaded when configured and are absent
  from required-secret preflight.
- Every secret has one component owner, and only that component's environment
  may test or consume it.
- Required secret names exist only in the target file. Preflight receives the
  bound environment inventory and does not duplicate those names in YAML.
- Partial capability sets are a preflight failure, replacing the ad-hoc
  four-secret seal check currently inlined in the YAML.

`write-gateway-secrets-file.mjs` derives its required set from this target file
instead of the hard-coded list at lines 5-12. This closes the Stripe class of
failure at the source: both hosted environments require and reference
`STRIPE_API_SK`. The same enabled value configures the Gateway's runtime
capability, so deployment requirements and application behavior cannot
disagree.

## Phases

The old stack workflows and their release framework are removed by the
implementation. The new workflows remain manual-only until staging and
production proof is recorded; the staging push trigger is the final cutover
step after that proof.

### Phase 0: Freeze the old framework

- Keep the new workflows manual-only while the cutover is being proved.
- Keep production closed while staging proof is in progress.
- Reconcile the current partial staging run and return staging to one known
  backend revision.

Exit criterion: validation pushes cannot trigger a deployment, and the new
manual entrypoints are the only deployment paths.

### Phase 1: Configuration target file

Add `deployment/targets.json` and one runtime boundary parser. Add focused
fixtures for malformed targets, unknown components, duplicate secret ownership,
and partial capability sets. No compile-time type fixture or generated config
is introduced.

### Phase 2: The two commands

Implement `scripts/deploy-backend.mjs` and `scripts/deploy-frontend.mjs`,
calling the retained helper scripts. Repoint
`write-gateway-secrets-file.mjs` at the target file.

Exit criterion: both `plan` operations pass locally without secrets and report
their complete ordered mutations. Backend component preflight tests pass with
fake environment values and perform no remote mutation.

### Phase 3: Introduce the new workflows

Add the two backend workflow files with manual dispatch only. Replace the two
frontend workflow files in place with their hand-written versions, also manual
only. Each backend workflow has one branch-guarded build, one compact
five-environment preflight matrix, one migrate job that runs before any Worker
deployment, and five ordered custody deploy jobs — eight in total, as required
by Acceptance Criterion 12. Migrations are never folded into the Gateway job:
Gateway deploys last, so that ordering would apply schema changes after four
Workers were already live. Gateway smoke is the final deployment step. Each
frontend workflow has one environment-bound build/deploy/smoke job. Remove the
two old backend stack workflows and their release framework. Both backend
surfaces use the same concurrency groups, so only one can touch a target at a
time.

**The new workflow files must land on `main` before Phase 4 can run.** GitHub
exposes `workflow_dispatch` only for workflows that exist on the default branch;
a workflow present solely on `dev` has no Run button and cannot be dispatched at
all. Merge the definitions to `main` first, then sync the identical content to
`dev`. Staging runs are then dispatched against branch `dev`, which is what
makes `github.ref == 'refs/heads/dev'` and `github.sha` resolve to the dev tip
as Pinning requires.

Merging deployment workflows to `main` while production triggers are manual-only
is safe, but confirm no production run auto-queues on the merge before
proceeding. This constraint is inherited from Refactor 3 Phase 9, where it was
learned operationally; it is not optional sequencing.

### Phase 4: Prove staging

Run `Deploy / staging / backend` and `Deploy / staging / frontend` through the
new workflows. Both must reach green including smoke tests. Record actual wall
clock per job. Interrupt one staging backend run after at least one worker
deploys, rerun the failed jobs at the same `${{ github.sha }}`, and verify
artifact reuse, recovery, and final smoke.

#### Phase 4 Results

Staging backend, run [30151749558][run-a], 33.6 minutes end to end:

| Job | Duration |
| --- | --- |
| Build / staging / backend | 10.3m |
| Preflight × 5 (parallel) | 0.2–0.3m each |
| Migrate / staging / gateway | 0.7m |
| Deploy / signing-worker | 5.3m |
| Deploy / deriver-a | 4.8m |
| Deploy / deriver-b | 5.5m |
| Deploy / router | 5.5m |
| Deploy / gateway (incl. smoke) | 0.7m |

Staging frontend, run [30155898075][run-f]: 4.8 minutes, one job.

**Fail-before-mutate: proven.** All five preflight legs complete before
`migrate`, visible in the job graph of every run. An earlier run failed with a
missing staging Stripe binding and mutated nothing.

**Interrupted-run recovery: proven.** A cancelled mid-lane run re-ran at the
same `${{ github.sha }}` and reused both the completed jobs and the build
artifact, reaching a green final smoke.

**Smoke raced Cloudflare propagation — found and fixed.** Run [30157416291][run-c]
deployed every component successfully and then failed at the Gateway smoke step
with 500s on `/readyz`, `/healthz`, and both Router A/B health paths, while the
static JWKS path returned 200. No redeploy followed, and the same endpoints
served 200 shortly afterwards: the deployment was healthy and the check was
early. Both lanes used a single-shot `fetch` with a 5-second timeout and no
retry.

This is a false negative that is cheap in staging and expensive in production,
where the lane has already applied forward-only migrations and deployed every
component by the time smoke runs, and where the apparent remedy — rollback — is
a revert commit plus a full rebuild of a healthy deployment.
`scripts/deployment-smoke.mjs` now owns readiness for both lanes: each check
retries to a 180-second budget at 5-second intervals and reports its attempt
count, so a
slow-but-healthy deployment is distinguishable from a broken one. The previously
duplicated per-script `runHttpCheck` implementations are gone.

[run-a]: https://github.com/seams-tech/seams-sdk/actions/runs/30151749558
[run-f]: https://github.com/seams-tech/seams-sdk/actions/runs/30155898075
[run-c]: https://github.com/seams-tech/seams-sdk/actions/runs/30157416291

### Phase 5: Prove production

Run both production lanes manually from `main` using the existing production
environment and its branch policy.

**Blocker: the approval gate currently sits after four production mutations.**
The only `required_reviewers` rule in the repository is on
`production-mpc-router`. Mapping the production backend jobs to their bound
environments and protection rules:

| # | Job | Environment | Protection |
| --- | --- | --- | --- |
| 1 | `migrate` | production-gateway | branch_policy |
| 2 | `deploy_signing_worker` | production-signing-worker | branch_policy |
| 3 | `deploy_deriver_a` | production-deriver-a | branch_policy |
| 4 | `deploy_deriver_b` | production-deriver-b | branch_policy |
| 5 | `deploy_router` | production-mpc-router | **required_reviewers** |
| 6 | `deploy_gateway` | production-gateway | branch_policy |

A production run therefore applies forward-only D1 migrations and deploys three
Workers before prompting anyone. Declining at step 5 does not undo any of it.
Branch policy answers "which ref may deploy," never "did a person agree."

Decision Summary item 9 attributes production control to "the existing
`production` environment branch policy," but no backend job binds `production` —
only the two frontend workflows do. The main-only restriction does hold for the
backend lane, via branch policies on the custody environments themselves.

Resolve before the first production run, by either:

- **(a)** creating a secret-free `production-approval` environment with required
  reviewers and adding a first job that every other job declares in `needs:` —
  one prompt, before any mutation; or
- **(b)** moving `required_reviewers` onto `production-gateway`, which `migrate`
  binds as the first mutating job — no new environment, but it prompts twice,
  since `deploy_gateway` binds the same environment.

(a) matches the design intent of one gate before all mutation. Under either
option, reconsider whether `required_reviewers` should remain on
`production-mpc-router`, which would otherwise add a second prompt mid-lane.

### Phase 6: Delete the old framework

The old backend workflows and support tooling listed in What Is Deleted or
Replaced were deleted during implementation, before remote staging and
production proof. The frontend contents were replaced in Phase 3. This leaves
fix-forward as the recovery path until the new lanes are proven; the deleted
framework remains recoverable from git history. Enable the new staging push
triggers only after Phases 4 and 5 are green. Production remains manual.

### Phase 7: One-page documentation

Rewrite `docs/deployment/README.md` as the single operational page: exact
deployment order, what each lane mutates, the expand-contract rule, rollback
including the forward-only migration constraint, and which operations are
runnable locally versus CI-only and why. Retire the sections of `infra.md` that
describe the deleted framework; `tooling.md` does not reference it and needs no
change.

## Carried Over From Refactor 3

Refactor 3 is superseded, but roughly half of its 69 open checklist items are not
about the framework being deleted. They concern GitHub account state, real
infrastructure, and evidence obligations that are true regardless of which
deployment system exists. Those items move here; the rest are void.

**Void with the framework** (do not re-do): everything asserting coordination
receipts, release-set identity and retention, cross-run artifact freshness and
staleness rejection, component-selection skip behaviour, no-op receipt timing,
`workflow_run` chaining between lanes, machine-checked API compatibility ranges,
and workflow policy/source-guard tests.

**GitHub account state** — absorbed by Phase 0, verified before Phase 5:

- Update branch protection to require the renamed validation jobs. The
  validation workflows are outside this refactor, so this item is otherwise
  orphaned.
- Update CODEOWNERS and environment protections before enabling production.
- Confirm staging jobs cannot read production secrets or variables, and that
  production jobs cannot read staging secrets or variables.
- Confirm a pull-request validation run cannot authorize either deployment lane.
- Configure target GitHub environment variables and protections for every
  custody environment in the Security Invariants table.

**Cutover technique** — absorbed by Phase 3 and Phase 6:

- Start a temporary `main` merge freeze for the cutover; end it only after both
  production lanes and their smoke checks succeed.
- Merge workflow definitions to `main` first, then sync to `dev`. See Phase 3.
- Confirm the Actions sidebar ends with exactly six workflows — four deployment,
  two validation — plus GitHub-managed features.

**Smoke targets** — these hostnames exist nowhere else and are required by
Phases 4 and 5:

| Lane | Staging | Production |
| --- | --- | --- |
| Frontend app | `seams-site-staging.pages.dev` | `seams.sh` |
| Frontend wallet | `seams-wallet-staging.pages.dev` | `sign.seams.sh` |
| Backend | staging readiness checks | production readiness checks |

**Historical Actions cleanup** — independent of both plans, and the one item
with an irreversible step:

Refactor 3 Phase 7 remains entirely open: `phase2b-change-control.yml` and the
former `router-ab.yml` still have historical runs and retained artifacts to
inventory, and their run URLs, commit SHAs, conclusions, and required evidence
must be exported to the durable evidence location **before** any run is deleted.
Evidence required by security, compliance, or protocol review must be retained
there regardless.

This work is unrelated to the deployment framework and must not be closed out as
part of superseding Refactor 3. Deleting historical runs is irreversible and the
export obligation does not survive on its own; it is recorded here so that
marking Refactor 3 dead does not silently discard it. It is not a blocker for
any phase of this refactor and can proceed on its own schedule.

## Rollback

**Workers and Pages:** revert the commit or land a corrective commit, then
deploy the new current branch tip. Deployment has no arbitrary historical-SHA
input, so workflow YAML and scripts cannot drift.

**D1 migrations do not roll back.** Reverting a commit that added a migration
does not undo the applied schema change. Undoing a migration requires writing a
new forward migration and deploying it. Any deployment that couples a
non-additive schema change to a code change must land the schema change in a
separate, earlier deployment. This constraint is a property of the system, not
of this refactor, and the one-page doc must state it in these terms.

**Mid-run failure:** the lane is ordered so that the most dependency-heavy
component (Gateway) deploys last. A failure at step N leaves steps 1..N-1
applied. Re-running failed jobs uses the same `${{ github.sha }}` and reuses the
successful build artifact. Migrations are fingerprint-guarded and idempotent,
and worker deploys are last-write-wins. Phase 4 proves interrupted-run recovery
before production.

## Acceptance Criteria

1. The four explicit deployment workflow files total under 1,000 lines (850 at
   implementation), down from 7,472 across four generated files. Repository
   validation workflows are outside this count and remain.
2. No workflow YAML is generated. No script exists whose purpose is to inspect
   or validate workflow source text.
3. `pnpm deploy:backend plan --target staging` runs locally without secrets,
   parses the complete target, and prints every ordered mutation.
4. Preflight failure for a missing secret occurs before any migration, tenant
   bootstrap, KEK upsert, or worker deploy. A component-scoped test proves the
   JSON inventory path, and one staging workflow run proves fail-before-mutate.
5. Deriver A and Deriver B secrets are never bound to the same job.
6. Workflows accept no arbitrary source SHA. Every job checks out the immutable
   `${{ github.sha }}` supplied by the workflow event; no `actions/checkout`
   step names a branch.
7. A deployment with zero components to deploy is impossible; the lane is always
   whole.
8. `docs/deployment/README.md` describes the entire system on one page.
9. A new engineer reads the operational page, target file, two top-level
   scripts, and four YAML files and can state what a production deploy mutates
   and in what order, in under fifteen minutes.
10. The frontend and backend expand-contract rule is documented and each lane's
    smoke test runs against the other lane's currently deployed version.
11. A deliberately interrupted staging deployment can be rerun at the same
    `${{ github.sha }}` without an artifact collision and reaches a green final
    smoke.
12. Each backend workflow contains exactly eight top-level jobs: build,
    preflight, migrate, and five custody deploy jobs. Each frontend workflow
    contains exactly one job.

## Open Questions

**Full-lane cost is now measured, and a gateway-only fast path is the wrong
lever.** The measurements in Phase 4 Results put a full staging backend lane at
33.6 minutes, above the 20-minute threshold this question originally set. But
the breakdown shows where the time actually goes, and it is not the Gateway:

- Build: 10.3 minutes, paid by every lane including any fast path.
- Four Rust Worker deploys, strictly sequential: 5.3 + 4.8 + 5.5 + 5.5 = 21.1
  minutes, or 63% of the lane.
- Gateway deploy: 0.7 minutes.
- Preflight (five parallel legs) and migrate: under 1 minute combined.

A gateway-only entrypoint would still pay the 10.3-minute build to save a
0.7-minute deploy, landing near 12 minutes. The larger lever is that
`signing-worker`, `deriver-a`, and `deriver-b` are chained sequentially by
`needs:` although they are independent custody domains with no ordering
requirement between them. Running those three concurrently and keeping `router`
after them would cut roughly 10 minutes, taking the lane to about 23 minutes
without adding an entrypoint, a conditional, or a second preflight.

That change is not made here because it needs a protocol answer this document
cannot supply: deploying Deriver A and Deriver B concurrently changes the shape
of the A/B version-skew window during a release. Sequential deployment does not
remove that window — it lengthens it — so concurrency is plausibly the safer
option, but `docs/refactor-93.md` owns the ceremony's skew tolerance and should
rule before the `needs:` edges change.

Recommendation: leave the lane sequential for now, and treat A/B/signing-worker
concurrency as the first optimisation to evaluate, ahead of any fast path.

**Cloudflare resource checks.** Preflight validates target syntax, capability
requirements, and required secret presence. It does not inventory Cloudflare
resources. The component deployment commands report missing D1, KV, Secrets
Store, Worker, or Pages resources through the Cloudflare operations they
already perform.

**`GATEWAY_DEPLOYMENT_CONFIG_JSON`.** This remains an environment-scoped GitHub
variable because it contains deployment-specific D1, tenant/bootstrap, and
optional identity-provider configuration. The build job does not bind the
gateway environment or read this value. It generates a minimal Wrangler config
from the same compatibility constants used by the deploy-time renderer.
Migration and gateway deployment render and validate the real environment
configuration inside the gateway custody job. `deployment/targets.json` remains
authoritative for public origins, capabilities, and resource names.

**Production environment protection.** The existing `production` environment
has a branch-policy rule and the workflow guard independently requires `main`.
It owns the frontend build configuration and Pages credentials. Component
custody environments own backend secrets. Phase 0 must continue to verify the
environment rules before the first new production run.
