# Deployment Refactor 3: Unambiguous GitHub Actions

Date created: July 23, 2026
Last updated: July 25, 2026

Status: the consolidated backend and frontend deployment workflows are
implemented and merged into local `dev`. GitHub environment configuration,
branch protection, historical Actions cleanup, and staging/production cutover
remain operational Phase 9 work.

## Objective

Make the GitHub Actions deployment surface small, predictable, and safe to
operate.

An operator must be able to identify the following from every workflow name
without opening its YAML:

1. whether the workflow validates or deploys;
2. whether it can mutate staging, production, or neither;
3. which Cloudflare service or stack it affects;
4. whether a person may run it directly.

The final Actions sidebar must expose one validation workflow per scope and two
deployment entrypoints per environment:

- a backend entrypoint for Gateway and MPC Router A/B;
- a frontend entrypoint for Cloudflare Pages, the signer iframe, and browser SDK
  runtime assets.

Service-specific deployment work remains visible as named jobs inside the
matching environment and authority boundary. There are no reusable
implementation workflows.

## Frontend Split Rationale

Pages is an independently deployable release surface. Keeping it inside the
backend stack workflow creates coupling that does not protect a real runtime
dependency:

- one environment-wide concurrency lock serializes unrelated frontend and
  backend releases;
- an unrelated backend commit can advance the protected branch while a Pages
  artifact is building, causing the branch-tip freshness gate to reject the
  completed frontend artifact;
- the next backend-only release does not select Pages, so the accepted frontend
  artifact requires manual recovery;
- frontend-only changes wait behind Router or Gateway builds and approvals.

The separate frontend workflows retain the safety properties that matter.
Application Pages, signer Pages, and SDK runtime assets deploy from one
target-specific artifact. Mixed backend and frontend releases require a
successful backend deployment receipt for the same source SHA before Pages
mutation begins. Frontend-only releases use a no-op coordination receipt that
binds the accepted frontend SHA to the already active backend receipt.

The receipt dependency adds one no-op coordination workflow hop to a
frontend-only release. Automatic execution uses `Validate / repository` ->
`Deploy / <environment> / cloudflare-stack` ->
`Deploy / <environment> / frontend`, consuming two of GitHub Actions' three
allowed downstream `workflow_run` levels. The frontend workflow is terminal;
no deployment or publication workflow may chain from it. The split targets
independent mutation concurrency, credential isolation, and reliable artifact
promotion. Phase 8 measures the added queue and setup latency explicitly.

## Pre-refactor Problem

The current workflow names mix several different concepts:

- environments: `deploy-staging`, `deploy-production`;
- services: `deploy-gateway`, `deploy-pages`, `deploy-router-ab`;
- lifecycle phases: `build-release`;
- validation: `ci`, `validate-router-ab`;
- publication: the removed `publish-sdk-r2` SDK R2 publisher;
- historical names retained by GitHub: `router-ab` and
  `Ed25519 Yao Phase 2B evidence staging`.

Before cutover, `deploy-router-ab` orchestrated Router
A/B, Gateway, Pages, activation, and final smoke checks. Its authority is the
whole Cloudflare stack, although its name describes one service.

GitHub also keeps historical workflow names in the Actions sidebar after their
files are deleted. `router-ab` and `Ed25519 Yao Phase 2B evidence staging` are
historical entries. Their workflow files are absent from the current `dev` and
`main` branches.

This creates operational and security risk:

- an operator cannot tell which workflow has deployment authority;
- separate service workflows look like supported entrypoints;
- environment selection is sometimes encoded in the branch or an input instead
  of the visible workflow name;
- a generic manual dispatch can bypass the intended environment entrypoint;
- stale workflows look active;
- the current execution graph is difficult to audit from the Actions UI.

## Naming Contract

### Visible workflow names

Operator-facing workflow names use this grammar:

```text
<Action> / <Environment or scope> / <Deployment surface or platform service>
```

Allowed actions:

- `Validate`
- `Deploy`

Allowed deployment environments:

- `staging`
- `production`

Allowed deployment surfaces and platform services:

- `repository`
- `cloudflare-stack`
- `frontend`
- `cloudflare-mpc-router-ab`
- `cloudflare-api-gateway`
- `cloudflare-pages`

Examples:

```text
Validate / repository
Deploy / staging / cloudflare-stack
Deploy / production / cloudflare-stack
Deploy / staging / frontend
Deploy / production / frontend
```

Branch names never substitute for environment names in workflow or job labels.
The branch mapping remains:

| Branch | Environment  |
| ------ | ------------ |
| `dev`  | `staging`    |
| `main` | `production` |

### Workflow filenames

Filenames use lowercase action, environment, platform, and service segments:

```text
validate-repository.yml
validate-cloudflare-mpc-router-ab.yml
deploy-staging-cloudflare-stack.yml
deploy-production-cloudflare-stack.yml
deploy-staging-frontend.yml
deploy-production-frontend.yml
```

### Run and job names

Every deployment run uses `run-name` to show its environment, service, source
SHA, and mode:

```text
deploy / staging / cloudflare-stack / <source-sha> / automatic
deploy / production / cloudflare-stack / <source-sha> / manual-promotion
deploy / staging / frontend / <source-sha> / automatic
deploy / production / frontend / <source-sha> / manual-promotion
```

Service jobs use the same environment and service vocabulary:

```text
Build / <environment> / cloudflare-mpc-router-ab
Build / <environment> / cloudflare-api-gateway
Build / <environment> / cloudflare-pages
Deploy / <environment> / cloudflare-mpc-router-ab / <role>
Deploy / <environment> / cloudflare-api-gateway
Deploy / <environment> / cloudflare-pages / <surface>
Verify / <environment> / cloudflare-stack
Verify / <environment> / frontend
```

Component selection may skip jobs. A skipped service remains visible with its
canonical job name and a release-summary explanation.

## Target Workflow Surface

The final `.github/workflows` directory contains exactly six workflows. No
workflow uses `workflow_call`.

| File                                     | Actions sidebar name                     | Trigger                                                                                             | Mutation authority                                      |
| ---------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `validate-repository.yml`                | `Validate / repository`                  | Push fast gate; pull request, merge group, or manual full validation                                | None                                                    |
| `validate-cloudflare-mpc-router-ab.yml`  | `Validate / cloudflare-mpc-router-ab`    | Relevant MPC Router A/B pull requests, or manual dispatch                                           | None                                                    |
| `deploy-staging-cloudflare-stack.yml`    | `Deploy / staging / cloudflare-stack`    | Successful validation of a `dev` push, or manual accepted backend release                           | Staging Gateway and MPC Router A/B only                 |
| `deploy-production-cloudflare-stack.yml` | `Deploy / production / cloudflare-stack` | Successful validation of a `main` push, or manual accepted backend release                          | Production Gateway and MPC Router A/B only              |
| `deploy-staging-frontend.yml`            | `Deploy / staging / frontend`            | Successful matching staging stack receipt, or manual accepted frontend release and stack receipt    | Staging app Pages, signer Pages, and SDK assets only    |
| `deploy-production-frontend.yml`         | `Deploy / production / frontend`         | Successful matching production stack receipt, or manual accepted frontend release and stack receipt | Production app Pages, signer Pages, and SDK assets only |

The environment-bound stack workflows own backend artifact creation, Gateway
migration and deployment, Router A/B deployment, backend smoke checks, and a
content-addressed coordination receipt. When backend components deploy, the
receipt records the new active backend identity. When the accepted change set
contains no backend components, the no-op receipt references the existing
active backend receipt and proves that the intervening accepted change set is
frontend-only.

The environment-bound frontend workflows own Pages artifact creation,
artifact verification, app and signer deployment, browser SDK runtime assets,
and frontend smoke checks. The frontend workflows are the only workflows that
receive Pages mutation credentials.

Shared command sequences may move into local scripts or composite actions under
`.github/actions`. Those actions do not create additional workflow files or
deployment authorities.

The generator inputs under `scripts/deployment-workflow-templates/` are job
fragments without workflow triggers. They are not reusable workflows and do not
create additional deployment authorities.

## Pre-refactor-to-Target Mapping

| Current visible name                    | Current meaning                                                     | Target                                                                 |
| --------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `ci`                                    | Repository validation plus release change-set artifact              | `Validate / repository`                                                |
| `build-release`                         | Builds accepted artifacts, creates a release set, then deploys      | Build and deploy jobs inside the matching backend or frontend workflow |
| `deploy-staging`                        | Manual accepted-release staging entrypoint                          | `Deploy / staging / cloudflare-stack`                                  |
| `deploy-production`                     | Manual accepted-release production entrypoint                       | `Deploy / production / cloudflare-stack`                               |
| `deploy-router-ab`                      | Whole-stack orchestrator with an additional direct manual trigger   | MPC Router A/B jobs inside the matching environment stack workflow     |
| `deploy-gateway`                        | Standalone Gateway deployment implementation                        | `Deploy / <environment> / cloudflare-api-gateway` jobs                 |
| `deploy-pages`                          | Standalone Pages deployment implementation                          | `Deploy / <environment> / frontend` with `cloudflare-pages` jobs       |
| `validate-router-ab`                    | Router A/B pull-request and manual validation                       | `Validate / cloudflare-mpc-router-ab`                                  |
| `publish-sdk-r2`                        | Standalone SDK R2 publication                                       | Removed; SDK runtime assets deploy with Pages                          |
| `router-ab`                             | Historical name for the workflow later renamed `validate-router-ab` | Remove historical Actions runs after evidence retention                |
| `Ed25519 Yao Phase 2B evidence staging` | Historical deleted `phase2b-change-control.yml` workflow            | Remove historical Actions runs after evidence retention                |

No compatibility workflow aliases remain after cutover. Old YAML files are
deleted in the same change that introduces their replacements.

## Target Trigger and Execution Flow

Automatic staging:

```text
push dev
    -> Validate / repository
    -> Deploy / staging / cloudflare-stack
       -> Build / staging / cloudflare-mpc-router-ab
       -> Build / staging / cloudflare-api-gateway
       -> Deploy / staging / cloudflare-mpc-router-ab / <role>
       -> Deploy / staging / cloudflare-api-gateway
       -> Verify / staging / cloudflare-stack
       -> Emit staging backend coordination receipt
    -> Deploy / staging / frontend
       -> Verify the matching staging backend coordination receipt
       -> Build / staging / cloudflare-pages
       -> Deploy / staging / cloudflare-pages / <surface>
       -> Verify / staging / frontend
```

Automatic production:

```text
push main
    -> Validate / repository
    -> Deploy / production / cloudflare-stack
       -> Build / production / cloudflare-mpc-router-ab
       -> Build / production / cloudflare-api-gateway
       -> Deploy / production / cloudflare-mpc-router-ab / <role>
       -> Deploy / production / cloudflare-api-gateway
       -> Verify / production / cloudflare-stack
       -> Emit production backend coordination receipt
    -> Deploy / production / frontend
       -> Verify the matching production backend coordination receipt
       -> Build / production / cloudflare-pages
       -> Deploy / production / cloudflare-pages / <surface>
       -> Verify / production / frontend
```

The backend stack workflow runs for every accepted protected-branch push. A
frontend-only change produces a successful no-op coordination receipt quickly.
That receipt binds the accepted source and validation run to the currently
active backend deployment. The frontend workflow starts from the completed
backend stack run and deploys only when the accepted change set selects `site`
or `signer-iframe`.

Manual accepted backend promotion:

```text
Deploy / <environment> / cloudflare-stack
    -> validate exact source SHA, validation run, artifact run, release-set ID,
       source branch, and target environment
    -> deploy only Gateway and Router components named by the accepted release
       set
    -> emit a backend coordination receipt
```

Manual accepted frontend promotion:

```text
Deploy / <environment> / frontend
    -> validate exact source SHA, validation run, frontend artifact run,
       frontend release-set ID, backend coordination receipt run, source
       branch, and target environment
    -> verify the receipt has the same accepted source SHA, validation run, and
       target, then resolve its active backend identity
    -> deploy app Pages, signer Pages, and SDK runtime assets from one accepted
       frontend artifact
```

The four environment-bound deployment workflows are the only workflows with
mutation authority.

## Cross-Lane Compatibility and Retention

Independent backend and frontend promotion makes version skew an expected
deployment state. Every release therefore carries an explicit Gateway API
compatibility contract:

- the frontend release manifest records one required
  `gatewayApiContractVersion`;
- the backend coordination receipt records the active
  `supportedFrontendApiContractRange`;
- frontend preflight rejects deployment or rollback when its required version
  is outside the deployed backend range;
- mixed releases verify the same contract before Pages mutation.

Gateway API changes follow expand/contract compatibility. A backend expansion
lands before a frontend begins using the new contract. The backend retains the
old contract throughout the 30-day frontend rollback window. Contract removal
requires evidence that no retained deployable frontend release depends on the
old version. D1 migrations continue to follow the expand/contract and
non-reversing rollback rules in Deployment Refactor 1.

Backend coordination receipts, backend release sets, and frontend release sets
are immutable and retained for the same 30-day rollback window. A coordination
receipt records its target, accepted source SHA, validation run, selected
backend components, active backend source SHA, active backend receipt run,
backend release-set ID, component digests, compatibility range, and smoke
result. A backend deployment sets its own receipt as active. A no-op run carries
forward the previously active backend receipt after verifying that its accepted
change range selects no backend components. If GitHub artifact retention cannot
satisfy the full window, the receipt and its digest must be copied to the
approved deployment evidence store before the originating run expires.

## Security Invariants

1. `Deploy / staging / cloudflare-stack` is the sole staging Gateway and MPC
   Router A/B mutation authority.
2. `Deploy / production / cloudflare-stack` is the sole production Gateway and
   MPC Router A/B mutation authority.
3. `Deploy / staging / frontend` is the sole staging Pages and browser SDK
   runtime mutation authority.
4. `Deploy / production / frontend` is the sole production Pages and browser
   SDK runtime mutation authority.
5. SDK runtime assets are part of the environment-bound Pages artifact. There
   is no standalone SDK publisher.
6. App Pages and signer Pages always deploy from the same target-specific
   frontend release set and source SHA.
7. Frontend mutation requires a successful backend coordination receipt for the
   same target, accepted source SHA, and validation run. A frontend-only receipt
   resolves and verifies the currently active backend deployment identity.
8. Production backend mutation requires the protected backend approval gate.
   Production frontend mutation requires its protected frontend approval gate.
9. Staging mutation requires the matching protected staging environment.
10. The environment is a constant in each deployment workflow. It is never a
    free-form manual input.
11. Staging workflows accept `dev` SHAs only. Production workflows accept
    `main` SHAs only.
12. Automatic deployment accepts successful push-triggered validation runs and
    receipts derived from those runs only. Pull-request, merge-group, and
    manually dispatched validation runs cannot authorize deployment.
13. Every deployment verifies the exact source SHA, validation run ID, artifact
    run ID, release-set ID, target environment, component digests, and
    protected-branch policy before mutation.
14. Freshness is component-aware in both lanes. An accepted backend SHA remains
    deployable after frontend-only commits, and an accepted frontend SHA
    remains deployable after backend-only commits. A newer accepted change that
    selects a component owned by the same lane makes the older lane release
    stale.
15. Frontend manifests and backend coordination receipts carry
    machine-verifiable Gateway API compatibility versions. Deployment and
    rollback fail when the required frontend version is outside the active
    backend range.
16. Backend coordination receipts and both release-set kinds are immutable and
    retained for the same 30-day rollback window.
17. The repository contains exactly six workflow files: two validation
    workflows, two environment-bound backend workflows, and two
    environment-bound frontend workflows.
18. No workflow uses `workflow_call`. Deployment jobs receive only their
    declared environment secrets.
19. Workflow permissions grant only `contents: read` and, for cross-run
    artifact consumers, `actions: read`; deployment jobs do not receive write
    permissions.
20. Deployment concurrency is locked by environment and authority boundary:
    `staging-backend`, `staging-frontend`, `production-backend`, and
    `production-frontend`. An in-progress mutation is never canceled.
21. The frontend workflow starts only from a completed matching backend run.
    Pages mutation waits for the verified successful backend coordination
    receipt.
22. The frontend workflow is the terminal `workflow_run` deployment level. No
    deployment or publication workflow chains from it.
23. Every final summary records environment, source SHA, validation run,
    artifact run, release-set ID, dependency receipt, selected services,
    deployed services, skipped services, and smoke result.
24. Workflow changes require CODEOWNERS review and protected-branch approval.
25. No `pull_request_target` workflow receives deployment credentials.
26. Production jobs execute only from accepted `main` ancestry. GitHub
    production environments allow only the `main` deployment branch.

## Phase 1: Add Static Workflow Policy Checks

- [x] Add a parsed-YAML workflow policy test.
- [x] Require an explicit allowlist of approved workflow files.
- [x] Require every workflow `name` to match the naming contract.
- [x] Require every operator-facing deployment workflow to include a static
      `staging` or `production` environment in its name.
- [x] Reject any `workflow_call` workflow and any local reusable-workflow call.
- [x] Reject deployment jobs without an explicit GitHub environment.
- [x] Reject environment values outside `staging` and `production`.
- [x] Reject `secrets: inherit`.
- [x] Reject generic names such as `deploy-pages`, `deploy-gateway`,
      `deploy-router-ab`, `router-ab`, and `build-release`.
- [x] Assert the approved workflow surface and service-job authority layout.
- [x] Assert that no standalone SDK R2 publisher exists.
- [x] Add an equivalent parsed workflow validation command to
      repository checks.

## Phase 2: Consolidate Validation

- [x] Rename `ci.yml` to `validate-repository.yml`.
- [x] Set its display name to `Validate / repository`.
- [x] Keep the still-valid Router A/B pull-request validation jobs in the
      explicitly named `Validate / cloudflare-mpc-router-ab` workflow.
- [x] Give the Router A/B validation workflow an unambiguous service name.
- [x] Preserve the push-only release change-set artifact.
- [x] Preserve the authority distinction between push validation and
      pull-request validation.
- [x] Delete the old `validate-router-ab.yml`; the replacement is
      `validate-cloudflare-mpc-router-ab.yml`.
- [ ] Update branch protection rules to require the renamed validation jobs.
- [x] Update every `workflow_run.workflows` reference to the new display name.

## Phase 3: Inline the Cloudflare Stack Jobs

This phase records the completed consolidation that established immutable
release sets and exact-SHA deployment. Phase 8 moves Pages ownership into the
frontend workflows while retaining those artifact guarantees.

- [x] Move release building, exact-SHA artifact creation, and release-set
      verification into each environment-bound stack workflow.
- [x] Keep Router A/B deployment jobs inside the matching stack workflow, with
      independent role environments and approval boundaries.
- [x] Keep Gateway migration and deployment jobs inside the matching stack
      workflow.
- [x] Move Pages build and deployment jobs into the matching frontend workflow.
- [x] Preserve component selection and conditional job execution.
- [x] Preserve Gateway-before-Pages ordering when both components are selected.
- [x] Preserve Router A/B activation ordering and final smoke checks.
- [x] Give every build, deploy, migration, activation, and verification job an
      environment-qualified service name.
- [ ] Move reusable step sequences into scripts or `.github/actions` when that
      reduces duplication without creating reusable deployment authority.
- [x] Delete all service-specific and reusable deployment workflow files.
- [x] Confirm no file under `.github/workflows` declares `workflow_call`.

## Phase 4: Add Environment-Bound Deployment Entrypoints

- [x] Replace `deploy-staging.yml` with
      `deploy-staging-cloudflare-stack.yml`.
- [x] Set its display name to `Deploy / staging / cloudflare-stack`.
- [x] Trigger its automatic path only after successful `dev` push validation.
- [x] Keep its manual path limited to accepted staging release identifiers.
- [x] Hard-code `environment=staging` and `source_branch=dev`.
- [x] Replace `deploy-production.yml` with
      `deploy-production-cloudflare-stack.yml`.
- [x] Set its display name to `Deploy / production / cloudflare-stack`.
- [x] Trigger its automatic path only after successful `main` push validation.
- [x] Keep its manual path limited to accepted production release identifiers.
- [x] Hard-code `environment=production` and `source_branch=main`.
- [x] Add environment-qualified `run-name` values for automatic and manual
      modes.
- [x] Keep each service job's secret access limited to its declared target
      environment and service boundary.
- [x] Remove every environment selector input from operator-facing workflows.

## Phase 5: Remove Standalone SDK R2 Publication

- [x] Delete `publish-sdk-r2.yml`.
- [x] Remove SDK R2 publication secrets, environment discovery, artifact kinds,
      and operator commands.
- [x] Keep SDK runtime assets in the Pages release artifact and verify them as
      part of the environment-bound Pages deployment.

## Phase 6: Harden Deployment Authority

- [x] Replace broad inherited secrets with environment-scoped service secret
      declarations.
- [x] Enforce that Gateway jobs cannot read Pages-only or Router-only secrets
      through the parsed workflow policy.
- [x] Enforce that Pages jobs cannot read backend deployment credentials beyond
      the scoped Cloudflare token they require.
- [ ] Confirm staging jobs cannot read production secrets or variables.
- [ ] Confirm production jobs cannot read staging secrets or variables.
- [x] Require one production environment approval before the first mutating
      job, using the existing `production-mpc-router` preflight.
- [x] Apply one non-canceling concurrency lock per environment in the
      consolidated stack layout.
- [x] Add a preflight summary before mutation.
- [x] Add a final deployment receipt after smoke checks.
- [x] Add CODEOWNERS coverage for `.github/workflows/**`,
      `.github/actions/**`, deployment scripts, and deployment documentation.
- [x] Add the workflow policy check to repository validation; branch protection
      must require the resulting validation check after merge.

## Phase 7: Remove Historical Actions Sidebar Entries

- [ ] Confirm `phase2b-change-control.yml` and the former `router-ab.yml` are
      absent from both `dev` and `main`.
- [ ] Inventory their historical workflow runs and retained artifacts.
- [ ] Export run URLs, commit SHAs, conclusions, and required evidence before
      deleting history.
- [ ] Keep evidence required by security, compliance, or protocol review in the
      repository evidence tree or another approved archive.
- [ ] Delete obsolete historical runs for
      `Ed25519 Yao Phase 2B evidence staging`.
- [ ] Delete obsolete historical runs for `router-ab`.
- [ ] Verify the obsolete names disappear from the Actions sidebar.
- [ ] Record the cleanup date and retained evidence location.

Deleting historical workflow runs is a one-time GitHub repository operation.
It is separate from deleting workflow YAML and must follow the project's audit
retention policy.

## Phase 8: Split Frontend Deployment Authority

- [x] Add `deploy-staging-frontend.yml` with display name
      `Deploy / staging / frontend`.
- [x] Add `deploy-production-frontend.yml` with display name
      `Deploy / production / frontend`.
- [x] Move Pages artifact creation, app deployment, signer deployment, SDK
      runtime asset verification, and frontend smoke checks out of both
      `cloudflare-stack` workflows.
- [x] Remove Pages credentials and Pages GitHub environments from every backend
      stack job.
- [x] Keep app Pages and signer Pages in one target-specific frontend release
      set.
- [x] Record `gatewayApiContractVersion` in every frontend release manifest.
- [x] Make each backend stack workflow emit a coordination receipt containing
      target, accepted source SHA, validation run ID, selected backend
      components, active backend source SHA, active backend receipt run,
      backend release-set ID, deployed component digests,
      `supportedFrontendApiContractRange`, and smoke result.
- [x] Retain immutable backend coordination receipts for 30 days, matching
      backend and frontend release-set retention. Copy receipts and digests to
      the approved evidence store when GitHub retention is insufficient.
- [x] Emit a successful no-op coordination receipt when an accepted release
      contains no Gateway or Router components. Verify and carry forward the
      active backend receipt instead of claiming that backend code deployed at
      the accepted frontend SHA.
- [x] Run no-op receipt creation without backend mutation credentials or a
      backend production approval. Frontend-only production releases require
      the frontend approval gate only.
- [x] Trigger the automatic frontend workflow from the completed matching
      backend stack run.
- [x] Reject automatic frontend mutation unless the backend run succeeded and
      its coordination receipt matches the frontend target, accepted source
      SHA, and validation run.
- [x] Skip the frontend workflow cleanly when the accepted change set contains
      neither `site` nor `signer-iframe`.
- [x] Give manual frontend promotion four required identifiers:
      `source_sha`, `artifact_run_id`, `release_set_id`, and
      `backend_receipt_run_id`. The validation run is derived from the
      accepted backend coordination receipt.
- [x] Verify manual frontend promotion against the protected branch, original
      push validation, immutable frontend artifact, frontend release set, and
      matching backend coordination receipt.
- [x] Add component-aware backend freshness. Reject an older backend release
      only when a newer accepted change between its SHA and the branch tip
      selects Gateway or Router components.
- [x] Add component-aware frontend freshness. Reject an older frontend release
      only when a newer accepted change between its SHA and the branch tip
      selects `site` or `signer-iframe`.
- [x] Use the same boundary parser and component selector for initial selection
      and intervening-change freshness checks.
- [x] Enforce the Gateway API compatibility contract during automatic
      deployment, manual promotion, and frontend rollback.
- [x] Use independent non-canceling concurrency groups for backend and frontend
      in each environment.
- [ ] Add a protected `production-frontend` approval gate with Pages-only
      credentials. Keep backend credentials inaccessible.
- [x] Preserve Gateway-before-Pages ordering for mixed releases through the
      required backend coordination receipt.
- [x] Update the workflow generator so the staging and production frontend
      workflows are generated from the same audited template.
- [x] Give each frontend workflow one trigger-agnostic job graph. Normalize
      `workflow_run` and `workflow_dispatch` inputs in one preflight job instead
      of duplicating `auto_*` and `manual_*` jobs.
- [x] Download and verify only the frontend release set, selected Pages
      artifacts, and required backend coordination receipt. Do not download
      unrelated Router or Gateway artifacts.
- [x] Keep the frontend workflow terminal. Reject any deployment or publication
      workflow that listens for its completion.
- [x] Make changes to either frontend workflow, the workflow generator, shared
      deployment actions, or shared release tooling select both deployment
      lanes so the cutover itself exercises the complete staging chain.
- [ ] Measure frontend-only queue time, no-op receipt execution time, and total
      validation-to-Pages time. The no-op coordination receipt path performs no
      package installation or build and must complete within 60 seconds of
      runner execution at p95 over ten staging runs.
- [x] Update the parsed workflow policy to require exactly the six target files
      and reject Pages mutation jobs outside the two frontend workflows.
- [x] Update source guards to reject backend mutation jobs in frontend
      workflows and frontend mutation jobs in backend workflows.
- [x] Update deployment documentation, operator commands, rollback instructions,
      and release receipt contracts in the same change set.
- [x] Keep read-only backend smoke checks bound to each target's existing
      frontend environment; remove the separate `*-observability` environments
      from workflow generation, manifests, examples, and documentation.
- [ ] Configure the target GitHub environment variables, protections, and
      approved evidence-store retention for the new frontend lane.

## Phase 9: Cutover and Verification

- [ ] Update workflow policy tests, source guards, branch protections,
      environment protections, and CODEOWNERS before enabling production.
- [ ] Confirm the production backend and frontend environments require approval
      before their first mutating job.
- [ ] Start a temporary `main` merge freeze for the cutover. Keep it until the
      staging verification and matching production promotion complete.
- [ ] Merge the reviewed workflow definitions to the default branch, `main`,
      first. Do not approve the automatically queued production deployment.
- [ ] Confirm `deploy-staging-frontend.yml` and
      `deploy-production-frontend.yml` are visible on the default branch and
      that the production run is waiting before mutation.
- [ ] Sync the same cutover content to `dev`. This ordering is required because
      `workflow_run` and `workflow_dispatch` trigger only when the workflow file
      exists on the default branch.
- [ ] Verify a frontend-only staging change follows:
      `Validate / repository` ->
      `Deploy / staging / cloudflare-stack` no-op receipt ->
      `Deploy / staging / frontend`.
- [ ] Verify a backend-only staging change runs the backend stack and produces
      a skipped frontend run with no Pages credentials.
- [ ] Verify a mixed staging change deploys Gateway before either Pages
      mutation.
- [ ] Advance `dev` with a frontend-only commit while a backend artifact builds;
      verify the accepted backend artifact remains deployable.
- [ ] Advance `dev` with a newer backend commit while an older backend artifact
      builds; verify the older backend artifact is rejected as stale.
- [ ] Advance `dev` with an unrelated backend-only commit while a frontend
      artifact builds; verify the accepted frontend artifact remains
      deployable.
- [ ] Advance `dev` with a newer frontend commit while an older frontend
      artifact builds; verify the older artifact is rejected as stale.
- [ ] Verify a pull-request validation run cannot authorize either deployment
      lane.
- [ ] Verify staging workflows cannot access production environments.
- [ ] Verify supported frontend/backend skew deploys and an incompatible
      frontend promotion or rollback fails before Pages mutation.
- [ ] Verify backend coordination receipts and both release-set kinds report
      30-day retention and matching immutable identities.
- [ ] Verify the frontend workflow does not trigger another deployment or
      publication workflow.
- [ ] Record queue time, no-op receipt execution time, and total
      validation-to-Pages time for ten frontend-only staging releases.
- [ ] Run staging frontend smoke against `staging.seams.sh` and
      `sign.staging.seams.sh`.
- [ ] Run staging backend readiness checks.
- [ ] After staging succeeds, approve the pending production backend run and
      verify its matching coordination receipt and active backend identity.
- [ ] Approve the production frontend run only after its preflight verifies the
      production backend coordination receipt and API compatibility range.
- [ ] Verify the production backend and frontend approval gates remain
      independent.
- [ ] Verify a production frontend-only release does not wait for unrelated
      Gateway or Router builds or backend approval after the no-op coordination
      receipt exists.
- [ ] Run production frontend smoke against `seams.sh` and `sign.seams.sh`.
- [ ] Run production backend readiness checks.
- [ ] Verify the Actions sidebar contains exactly the six target workflows plus
      GitHub-managed features.
- [ ] End the temporary `main` merge freeze after both production receipts and
      smoke checks succeed.

## Rollback

Backend rollback uses the matching environment-specific `cloudflare-stack`
entrypoint with a previously accepted backend release set and validation
identity retained for 30 days.

Frontend rollback uses the matching environment-specific `frontend` entrypoint
with a previously accepted frontend release set and its required backend
coordination receipt. Preflight verifies that the retained frontend
`gatewayApiContractVersion` remains inside the live backend's
`supportedFrontendApiContractRange`. It deploys app Pages, signer Pages, and
SDK runtime assets together.

Application rollback restores code and static assets only. Secrets, D1
migrations, Durable Object state, and other environment state require their
documented recovery procedures.

Workflow-cutover rollback uses a reviewed Git revert of the cutover commit. A
rollback must preserve:

- static staging and production authority;
- protected-branch source validation;
- exact artifact and release-set verification;
- matching backend coordination receipts before frontend mutation;
- Gateway API expand/contract compatibility;
- aligned 30-day receipt and release-set retention;
- authority-specific concurrency locks;
- explicit secret boundaries.

## Acceptance Criteria

This refactor is complete when:

- [ ] The Actions sidebar contains exactly the six target workflows plus
      GitHub-managed features.
- [ ] Every operator-facing mutation workflow names its environment and
      deployment surface.
- [ ] There are exactly four deployment buttons: staging backend, staging
      frontend, production backend, and production frontend.
- [ ] `Deploy / staging / frontend` and `Deploy / production / frontend` are
      the only Pages deployment buttons.
- [ ] No individual Gateway or Router A/B deployment button exists.
- [ ] Service-specific build and deployment jobs clearly name both environment
      and service.
- [ ] `router-ab` and `Ed25519 Yao Phase 2B evidence staging` no longer appear
      as historical workflow entries.
- [ ] Only successful protected-branch push validation can start an automatic
      deployment.
- [ ] Manual deployment requires an accepted exact-SHA release set.
- [ ] Manual frontend deployment additionally requires a matching accepted
      backend coordination receipt.
- [ ] No workflow uses `workflow_call`, and no reusable deployment workflow file
      remains under `.github/workflows`.
- [ ] No workflow uses `secrets: inherit`.
- [ ] Backend and frontend have independent environment approvals, credentials,
      and concurrency locks in staging and production. R2 remains only for
      backup/export storage and never serves as an SDK publisher.
- [ ] A backend-only branch advance cannot invalidate an accepted frontend
      artifact.
- [ ] A newer accepted frontend change invalidates every older undeployed
      frontend artifact.
- [ ] A frontend-only branch advance cannot invalidate an accepted backend
      artifact.
- [ ] A newer accepted backend change invalidates every older undeployed
      backend artifact.
- [ ] Mixed releases require a successful same-SHA backend deployment receipt
      before Pages mutation.
- [ ] Frontend deployment and rollback reject Gateway API versions outside the
      live backend compatibility range.
- [ ] Backend coordination receipts and both release-set kinds share an
      immutable 30-day retention window.
- [ ] Each frontend workflow has one trigger-agnostic job graph and verifies
      only selected frontend artifacts plus its backend coordination receipt.
- [ ] The frontend workflows are terminal and consume no further
      `workflow_run` chain level.
- [ ] The frontend-only no-op coordination receipt path completes within 60
      seconds of runner execution at p95 over ten staging runs.
- [ ] Parsed workflow policy tests reject ambiguous names and unauthorized
      triggers.
- [ ] Deployment documentation contains one authoritative execution flow and
      one environment/service matrix.
