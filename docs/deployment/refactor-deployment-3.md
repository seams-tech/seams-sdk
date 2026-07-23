# Deployment Refactor 3: Unambiguous GitHub Actions

Date created: July 23, 2026

Status: implemented in the repository; GitHub history cleanup remains an
administrator action.

## Objective

Make the GitHub Actions deployment surface small, predictable, and safe to
operate.

An operator must be able to identify the following from every workflow name
without opening its YAML:

1. whether the workflow validates or deploys;
2. whether it can mutate staging, production, or neither;
3. which Cloudflare service or stack it affects;
4. whether a person may run it directly.

The final Actions sidebar must expose one validation workflow per scope and one
deployment entrypoint per environment. Service-specific deployment work remains
visible as named jobs inside the two deployment runs. There are no separate
implementation workflows.

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
<Action> / <Environment or scope> / <Platform service>
```

Allowed actions:

- `Validate`
- `Deploy`

Allowed deployment environments:

- `staging`
- `production`

Allowed platform services:

- `repository`
- `cloudflare-stack`
- `cloudflare-router-ab`
- `cloudflare-gateway`
- `cloudflare-pages`

Examples:

```text
Validate / repository
Deploy / staging / cloudflare-stack
Deploy / production / cloudflare-stack
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
validate-cloudflare-router-ab.yml
deploy-staging-cloudflare-stack.yml
deploy-production-cloudflare-stack.yml
```

### Run and job names

Every deployment run uses `run-name` to show its environment, service, source
SHA, and mode:

```text
deploy / staging / cloudflare-stack / <source-sha> / automatic
deploy / production / cloudflare-stack / <source-sha> / manual-promotion
```

Service jobs use the same environment and service vocabulary:

```text
Build / <environment> / cloudflare-router-ab
Build / <environment> / cloudflare-gateway
Build / <environment> / cloudflare-pages
Deploy / <environment> / cloudflare-router-ab / <role>
Deploy / <environment> / cloudflare-gateway
Deploy / <environment> / cloudflare-pages / <surface>
Verify / <environment> / cloudflare-stack
```

Component selection may skip jobs. A skipped service remains visible with its
canonical job name and a release-summary explanation.

## Target Workflow Surface

The final `.github/workflows` directory contains exactly four workflows. No
workflow uses `workflow_call`; all service-level build and deployment work is a
job inside one of the two environment-bound stack workflows:

| File                                     | Actions sidebar name                     | Trigger                                                                  | Mutation authority                                       |
| ---------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------- |
| `validate-repository.yml`                | `Validate / repository`                  | Push fast gate; pull request, merge group, or manual full validation     | None                                                     |
| `validate-cloudflare-router-ab.yml`      | `Validate / cloudflare-router-ab`        | Relevant Router A/B pull requests, or manual dispatch                    | None                                                     |
| `deploy-staging-cloudflare-stack.yml`    | `Deploy / staging / cloudflare-stack`    | Successful validation of a `dev` push, or manual accepted-release input  | Staging Cloudflare environment only                      |
| `deploy-production-cloudflare-stack.yml` | `Deploy / production / cloudflare-stack` | Successful validation of a `main` push, or manual accepted-release input | Production Cloudflare environment only                   |

The release builder, artifact verification, Router A/B deployment, Gateway
migration and deployment, Pages deployment, and final smoke jobs live directly
in the matching staging or production stack workflow. Shared command sequences
may move into local scripts or composite actions under `.github/actions`; those
do not create additional workflow files or operator-facing deployment
entrypoints.

## Pre-refactor-to-Target Mapping

| Current visible name                    | Current meaning                                                     | Target                                                                    |
| --------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `ci`                                    | Repository validation plus release change-set artifact              | `Validate / repository`                                                   |
| `build-release`                         | Builds accepted artifacts, creates a release set, then deploys      | Build and deploy jobs inside the matching environment stack workflow       |
| `deploy-staging`                        | Manual accepted-release staging entrypoint                          | `Deploy / staging / cloudflare-stack`                                     |
| `deploy-production`                     | Manual accepted-release production entrypoint                       | `Deploy / production / cloudflare-stack`                                  |
| `deploy-router-ab`                      | Whole-stack orchestrator with an additional direct manual trigger   | Router A/B jobs inside the matching environment stack workflow             |
| `deploy-gateway`                        | Standalone Gateway deployment implementation                        | `Deploy / <environment> / cloudflare-gateway` jobs                         |
| `deploy-pages`                          | Standalone Pages deployment implementation                          | `Deploy / <environment> / cloudflare-pages` jobs                            |
| `validate-router-ab`                    | Router A/B pull-request and manual validation                       | `Validate / cloudflare-router-ab`                                          |
| `publish-sdk-r2`                        | Standalone SDK R2 publication                                       | Removed; SDK runtime assets deploy with Pages                             |
| `router-ab`                             | Historical name for the workflow later renamed `validate-router-ab` | Remove historical Actions runs after evidence retention                   |
| `Ed25519 Yao Phase 2B evidence staging` | Historical deleted `phase2b-change-control.yml` workflow            | Remove historical Actions runs after evidence retention                   |

No compatibility workflow aliases remain after cutover. Old YAML files are
deleted in the same change that introduces their replacements.

## Target Trigger and Execution Flow

Automatic staging:

```text
push dev
    -> Validate / repository
    -> Deploy / staging / cloudflare-stack
       -> Build / staging / cloudflare-router-ab
       -> Build / staging / cloudflare-gateway
       -> Build / staging / cloudflare-pages
       -> Deploy / staging / cloudflare-router-ab / <role>
       -> Deploy / staging / cloudflare-gateway
       -> Deploy / staging / cloudflare-pages / <surface>
       -> Verify / staging / cloudflare-stack
```

Automatic production:

```text
push main
    -> Validate / repository
    -> Deploy / production / cloudflare-stack
       -> Build / production / cloudflare-router-ab
       -> Build / production / cloudflare-gateway
       -> Build / production / cloudflare-pages
       -> Deploy / production / cloudflare-router-ab / <role>
       -> Deploy / production / cloudflare-gateway
       -> Deploy / production / cloudflare-pages / <surface>
       -> Verify / production / cloudflare-stack
```

Manual accepted-release promotion:

```text
Deploy / <environment> / cloudflare-stack
    -> validate exact source SHA, validation run, artifact run, release-set ID,
       source branch, and target environment
    -> build and deploy only the components named by the accepted release set
```

No service workflow can be dispatched directly. The two stack workflows are the
only workflows with deployment authority.

## Security Invariants

1. Only `Deploy / staging / cloudflare-stack` can mutate staging application
   resources.
2. Only `Deploy / production / cloudflare-stack` can mutate production
   application resources.
3. SDK runtime assets are deployed as part of the environment-bound Pages
   artifact; there is no standalone SDK publisher.
4. Production mutation requires the protected GitHub `production` environment
   and its approval policy.
5. Staging mutation requires the protected GitHub `staging` environment.
6. The environment is a constant in each operator-facing workflow. It is never
   a free-form manual input.
7. The staging entrypoint accepts `dev` SHAs only. The production entrypoint
   accepts `main` SHAs only.
8. Automatic deployment accepts successful push-triggered validation runs only.
   Pull-request, merge-group, and manually dispatched validation runs cannot
   authorize deployment.
9. Every deployment verifies the exact source SHA, validation run ID, artifact
   run ID, release-set ID, target environment, component digests, and current
   protected-branch policy before mutation.
10. The repository contains exactly four workflow files: the two validation
    workflows and the two environment-bound stack workflows.
11. No workflow uses `workflow_call`; service jobs run inside the matching stack
    workflow and receive only their declared environment secrets.
12. Workflow permissions grant only `contents: read` and, for cross-run
    artifact consumers, `actions: read`; deployment jobs do not receive write
    permissions.
13. Deployment concurrency is locked by environment and never cancels an
    in-progress mutation.
14. A production deployment cannot overlap another production deployment. A
    staging deployment cannot overlap another staging deployment.
15. The final summary records environment, source SHA, validation run, artifact
    run, release-set ID, selected services, deployed services, skipped services,
    and final smoke result.
16. Workflow changes require CODEOWNERS review and protected-branch approval.
17. No `pull_request_target` workflow receives deployment credentials.
18. Production jobs execute only from `refs/heads/main`. GitHub production
    environments allow only the `main` deployment branch, and the
    `production-mpc-router` preflight is the single required approval gate.

## Phase 1: Add Static Workflow Policy Checks

- [x] Add a parsed-YAML workflow policy test.
- [x] Require exactly the four approved workflow files.
- [x] Require every workflow `name` to match the naming contract.
- [x] Require every operator-facing deployment workflow to include a static
      `staging` or `production` environment in its name.
- [x] Reject any `workflow_call` workflow and any local reusable-workflow call.
- [x] Reject deployment jobs without an explicit GitHub environment.
- [x] Reject environment values outside `staging` and `production`.
- [x] Reject `secrets: inherit`.
- [x] Reject generic names such as `deploy-pages`, `deploy-gateway`,
      `deploy-router-ab`, `router-ab`, and `build-release`.
- [x] Assert the exact four-workflow surface and the inline service-job layout.
- [x] Assert that no standalone SDK R2 publisher exists.
- [x] Add an equivalent parsed workflow validation command to
      repository checks.

## Phase 2: Consolidate Validation

- [x] Rename `ci.yml` to `validate-repository.yml`.
- [x] Set its display name to `Validate / repository`.
- [x] Keep the still-valid Router A/B pull-request validation jobs in the
      explicitly named `Validate / cloudflare-router-ab` workflow.
- [x] Give the Router A/B validation workflow an unambiguous service name.
- [x] Preserve the push-only release change-set artifact.
- [x] Preserve the authority distinction between push validation and
      pull-request validation.
- [x] Delete the old `validate-router-ab.yml`; the replacement is
      `validate-cloudflare-router-ab.yml`.
- [ ] Update branch protection rules to require the renamed validation jobs.
- [x] Update every `workflow_run.workflows` reference to the new display name.

## Phase 3: Inline the Cloudflare Stack Jobs

- [x] Move release building, exact-SHA artifact creation, and release-set
      verification into each environment-bound stack workflow.
- [x] Keep Router A/B deployment jobs inside the matching stack workflow, with
      independent role environments and approval boundaries.
- [x] Keep Gateway migration and deployment jobs inside the matching stack
      workflow.
- [x] Keep Pages build and deployment jobs inside the matching stack workflow.
- [x] Preserve component selection and conditional job execution.
- [x] Preserve Gateway-before-Pages ordering when both components are selected.
- [x] Preserve Router A/B activation ordering and final smoke checks.
- [x] Give every build, deploy, migration, activation, and verification job an
      environment-qualified service name.
- [ ] Move reusable step sequences into scripts or `.github/actions` when that
      reduces duplication without creating another workflow file.
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
- [ ] Confirm the Gateway jobs cannot read Pages-only or Router-only secrets.
- [ ] Confirm Pages jobs cannot read backend deployment credentials beyond the
      scoped Cloudflare token they require.
- [ ] Confirm staging jobs cannot read production secrets or variables.
- [ ] Confirm production jobs cannot read staging secrets or variables.
- [x] Require one production environment approval before the first mutating
      job, using the existing `production-mpc-router` preflight.
- [x] Apply one non-canceling concurrency lock per environment.
- [x] Add a preflight summary before mutation.
- [x] Add a final deployment receipt after smoke checks.
- [ ] Add CODEOWNERS coverage for `.github/workflows/**`,
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

## Phase 8: Cutover and Verification

- [ ] Land the complete workflow rename as one reviewed change set.
- [ ] Delete obsolete workflow files in that same change set.
- [ ] Update deployment documentation and operator commands in the same commit.
- [ ] Update source guards, workflow parsing tests, branch protections, and
      CODEOWNERS before enabling production.
- [ ] Push the cutover to `dev`.
- [ ] Verify the exact staging chain:
      `Validate / repository` ->
      `Deploy / staging / cloudflare-stack`, with the Router A/B, Gateway,
      Pages, and final smoke jobs inside that run.
- [ ] Verify staging jobs clearly show
      `cloudflare-router-ab`, `cloudflare-gateway`, and `cloudflare-pages`.
- [ ] Verify direct service deployment buttons do not exist.
- [ ] Verify a pull-request validation run cannot authorize deployment.
- [ ] Verify a staging run cannot access production environment values.
- [ ] Run staging final smoke against `staging.seams.sh` and its backend
      readiness endpoints.
- [ ] Merge the exact cutover commit to `main`.
- [ ] Change the repository default branch to `main` immediately after the
      cutover commit exists there. Production fails closed until this is done.
- [ ] Verify the production chain and required production approval.
- [ ] Run production final smoke against `seams.sh` and its backend readiness
      endpoints.
- [ ] Verify the Actions sidebar contains exactly the four target workflows
      plus GitHub-managed features.

## Rollback

Application rollback uses the same environment-specific deployment entrypoint
with a previously accepted release set retained for 30 days. It redeploys code
and Pages assets without restoring prior secrets, D1 migrations, Durable Object
state, or other environment state. It does not restore old workflow names or
direct service dispatch paths.

Workflow-cutover rollback uses a reviewed Git revert of the cutover commit. A
rollback must preserve:

- static staging and production authority;
- protected-branch source validation;
- exact artifact and release-set verification;
- environment concurrency locks;
- explicit secret boundaries.

## Acceptance Criteria

This refactor is complete when:

- [ ] The Actions sidebar contains exactly the four target workflows plus
      GitHub-managed features.
- [ ] Every operator-facing mutation workflow names its environment and
      platform service.
- [ ] There are exactly two application deployment buttons: staging and
      production.
- [ ] No individual Gateway, Router A/B, or Pages deployment button exists.
- [ ] Service-specific build and deployment jobs clearly name both environment
      and service.
- [ ] `router-ab` and `Ed25519 Yao Phase 2B evidence staging` no longer appear
      as historical workflow entries.
- [ ] Only successful protected-branch push validation can start an automatic
      deployment.
- [ ] Manual deployment requires an accepted exact-SHA release set.
- [ ] No workflow uses `workflow_call`, and no reusable deployment workflow file
      remains under `.github/workflows`.
- [ ] No workflow uses `secrets: inherit`.
- [ ] Staging and production have independent environment approvals, secrets,
      variables, and concurrency locks. R2 remains only for backup/export
      storage, not SDK publication.
- [ ] Parsed workflow policy tests reject ambiguous names and unauthorized
      triggers.
- [ ] Deployment documentation contains one authoritative execution flow and
      one environment/service matrix.
