# Deployment Refactor 1: Fast, Reusable Releases

Status: in progress

## Objective

Keep routine staging and production deployments below 10 minutes at p90.
Deployment must reuse exact-SHA artifacts, run independent uploads concurrently,
and perform only the checks required to prevent a partial or incorrectly
targeted release.

Full CI, comprehensive tests, formal evidence, and compilation do not belong in
the deployment critical path. They run before an artifact is accepted or in
separate manual and scheduled workflows.

## Fast Path

The routine path is:

```text
select exact SHA and affected components
    -> fetch accepted artifacts
    -> verify manifest and digests
    -> deploy independent components concurrently
    -> activate dependent components
    -> run one bounded smoke check
```

Deployment performs these checks:

- Source SHA and artifact digest verification.
- Target environment and release-set identity verification.
- Required Cloudflare binding and configuration presence.
- One readiness check per deployed component.
- Migration status when the release contains D1 migrations.
- One final smoke check for the selected release.

Deployment does not:

- Recompile Cargo, WASM, SDK, or Vite artifacts.
- Run full CI or repeat tests already accepted for the exact SHA.
- Run source-text workflow guards.
- Validate unrelated components.
- Use long retry loops.
- Serialize independent Worker or Pages uploads.

## Current State

The repository now has:

- Path-filtered deployment triggers.
- PR/manual Router A/B validation split into parallel jobs.
- Manual-only SDK publication to R2.
- Exact source SHAs passed into deployment workflows.
- Per-component artifacts and digest verification within a deployment run.
- Initial pnpm, Cargo, Rust target, and generated artifact caching.
- Router A/B role uploads run concurrently before MPCRouter activation.
- Mutating deployment workflows use non-canceling concurrency.
- A CI-gated `build-release.yml` workflow that builds the accepted SHA once.
- A content-addressed release-set manifest with cross-run artifact verification.
- A single target lock and bounded final smoke in the deployment orchestrator.
- Selector-driven artifact jobs and deployment jobs for Router A/B, Gateway, and Pages.
- CI records the complete pushed `before..after` file range, so multi-commit pushes
  select every affected component instead of only the tip commit.

The reusable release path is now wired for Router A/B, Gateway, and Pages. The
remaining work is runtime identity, migration skip reporting, provider version
receipts, and measured rollback:

- `build-release.yml` owns the Router A/B, Gateway, and Pages builds.
- Mutating component workflows consume artifacts from an explicit artifact run.
- `deploy-production.yml` and `deploy-staging.yml` are explicit accepted-release
  promotion entrypoints.
- Gateway D1 migration steps run on every Gateway deployment, although the
  migration applier is idempotent.
- Gateway and Pages are reusable workflows without direct mutation entrypoints;
  the Router A/B orchestrator owns the target lock.
- Readiness checks are component-local, followed by one selected-release smoke
  that verifies the manifest identity and representative deployed routes.

The first milestone is complete. Component selection is recorded in the
release-set build identity and controls artifact and deployment job selection.
Router changes expand to the full Router topology so MPCRouter activation never
depends on skipped roles.

## Scope

This plan changes GitHub Actions orchestration, artifact metadata, component
selection, deployment ordering, and release reporting.

It does not change signing protocols, runtime APIs, deployment identities,
secrets, D1 schemas, or application behavior.

Eliminating duplicate semantic SDK builds inside `ci.yml` is a separate CI
optimization. This plan only requires one accepted release build and prohibits
deployment workflows from compiling again.

## Phase 1: Establish the Release Artifact Set

- [x] Add one trusted release-build workflow that builds all selected
      deployment artifacts once.
- [x] Upload the artifacts to a cross-run store. Start with GitHub Actions
      artifacts and explicit `run-id` downloads; use R2 only if retention
      requirements exceed the GitHub artifact window.
- [x] Make every deployment require an accepted artifact run ID and exact
      source SHA.
- [x] Define one canonical release-set manifest and derive `releaseSetId` from
      its canonical digest.
- [x] Record the schema version, source SHA, target, accepted validation run,
      artifact-producing run, creation timestamp, build/toolchain identity,
      migration set, component artifact digests, and component release IDs.
- [x] Reference MPCRouter, Deriver A, Deriver B, SigningWorker, Gateway, site,
      and signer iframe artifacts from the manifest.
- [ ] Keep compiled Worker and SDK artifacts environment-neutral where their
      bytes are identical.
- [ ] Keep Vite and other environment-embedded artifacts target-specific.
- [x] Build production-target artifacts during the trusted release build so
      production promotion performs no compilation.
- [ ] Accept artifacts only from a trusted workflow for a protected branch.
- [x] Verify the manifest and all selected artifact digests before the first
      Cloudflare mutation.
- [x] Retain accepted artifacts for at least 30 days and record their run ID in
      the deployment summary.
- [x] Remove the disabled legacy Router build block from the mutating workflow.

Acceptance:

- A retry receives the original artifact run ID, downloads the accepted release
  set, and starts no compilation.
- Production consumes the production-target artifacts already built for the
  accepted source SHA.
- Artifact or target mismatch fails before any deployment mutation.

## Phase 2: Select Only Affected Components

- [x] Add one explicit component-input map covering source directories, shared
      crates and packages, lockfiles, toolchains, build scripts, generated
      bindings, migrations, and deployment configuration.
- [x] Implement one shared selector used by the release builder and deployment
      orchestrator. Record its reviewed component map in the release manifest
      and workflow summary.
- [x] Select from the complete accepted push range; manual release dispatches
      require an explicit ancestor baseline.
- [x] Treat unknown shared inputs as affecting every dependent component.
- [x] Deploy Pages alone when only site or signer iframe inputs changed.
- [x] Deploy Gateway alone when only Gateway inputs changed.
- [x] Deploy only affected Router A/B roles when the release topology permits
      an independent role update.
- [x] Include a migration fingerprint and migration file list in the selected
      Gateway release.
- [x] Keep the selector as a small reviewed script or data table. Do not build a
      generalized dependency-analysis system.

Acceptance:

- Pages-only releases do not deploy Router A/B or Gateway.
- Gateway-only releases do not deploy Router A/B or Pages.
- Shared protocol or toolchain changes select the complete affected release set.

## Phase 3: Shorten the Deployment Graph

- [x] Deploy SigningWorker, Deriver A, and Deriver B concurrently.
- [ ] Require each deployed role to report the expected release-set ID at
      runtime; deployment metadata is currently passed into Wrangler variables.
- [ ] Deploy or activate MPCRouter only after every selected role reports the
      expected release-set ID and readiness.
- [x] Start Router roles and Gateway concurrently after release verification;
      Pages waits for Gateway when both are selected and never waits for
      MPCRouter.
- [x] Activate MPCRouter after its selected roles are ready while unrelated
      Gateway and Pages readiness checks continue.
- [ ] Compare the selected migration fingerprint with the currently deployed
      release and run D1 migration steps only when new migrations exist.
- [ ] Require D1 migrations to follow expand/contract compatibility. Binary
      rollback does not attempt to reverse an applied migration.
- [x] Run one final smoke check covering Gateway readiness, ceremony JWKS,
      selected service bindings, Router A/B health, Pages routes,
      representative SDK assets, and release-set identity consistency.
- [ ] Preserve the previous Cloudflare Worker versions until the smoke check
      succeeds.

Target graph:

```text
release-set verification
    |
    +-- SigningWorker --+
    +-- Deriver A ------+--> MPCRouter activation --+
    +-- Deriver B ------+                         |
    |                                             +--> final smoke
    +-- Gateway deployment -----------------------+
    +-- Pages deployment -------------------------+
```

Acceptance:

- Independent uploads execute concurrently.
- A mixed Router A/B release is never activated.
- A failed component can be retried without rebuilding successful components.
- The complete staging or production path stays below 10 minutes at p90.

## Phase 4: Keep Validation Out of Deployment

- [x] Run Router A/B validation for relevant pull requests and manual dispatch.
- [x] Split Router A/B validation into focused parallel jobs.
- [x] Use filtered installs and initial pnpm/Cargo caches.
- [ ] Require protected `dev` and `main` branches so deployed SHAs have passed
      the required semantic checks before entering a deployment workflow.
- [ ] Remove checks duplicated by authoritative Rust vectors, type fixtures, or
      another required check.
- [ ] Delete stale fixtures and source guards that encode retired behavior.
- [x] Replace literal workflow-text checks in `assert-release-ready.mjs` with
      parsed YAML checks for exact SHA, target, artifact verification, and
      dependency ordering.
- [ ] Keep startup and local four-worker tests only when they own a distinct
      deployment invariant.

Acceptance:

- Deployment trusts the accepted exact-SHA result and does not rerun semantic
  tests.
- Every retained validation job owns a current, documented invariant.
- Workflow refactors do not require restoring obsolete literal strings.

## Phase 5: Make Cancellation and Rollback Accurate

- [x] Use `cancel-in-progress: true` only for validation and artifact-building
      work that has not mutated Cloudflare state.
- [x] Use `cancel-in-progress: false` for workflows that deploy Workers, update
      secrets, or apply migrations.
- [x] Before the first mutation, stop a queued deployment when a newer accepted
      release supersedes it.
- [x] Route automatic and manual mutations through one deployment orchestrator.
- [x] Serialize every mutation for the same target with one shared
      `deployment-${target}` lock. Component workflows must not own independent
      target mutation locks.
- [ ] Record the previous and new Worker version IDs, Pages deployment ID, and
      release-set ID before activation.
- [ ] Roll back by reactivating a retained Worker version or redeploying a
      previously accepted manifest.
- [ ] Document that an applied D1 migration remains in place during binary
      rollback.

Acceptance:

- Cancellation cannot leave secrets, migrations, and Worker roles split across
  releases.
- Rollback requires no compilation while retained artifacts or Worker versions
  remain available.

## Phase 6: Measure the Critical Path

- [ ] Summarize artifact lookup, verification, migration, upload, activation,
      readiness, and final smoke durations.
- [ ] Track a rolling p50 and p90 from the most recent successful runs.
- [ ] Use 10 successful cold and warm runs for the initial budget assessment.
- [ ] Keep the routine deployment p90 target at 10 minutes.
- [ ] Use a 15-minute hard timeout initially, then reduce it after cold-cache
      runs consistently fit the target.
- [ ] Remove the current 25–35 minute deployment timeouts once the accepted
      release path is operational.
- [ ] Exclude manual deep-validation and scheduled evidence workflows from the
      routine deployment budget.

Performance targets:

| Workflow             | p90 target |
| -------------------- | ---------- |
| `deploy-gateway`     | Under 5m   |
| `deploy-pages`       | Under 5m   |
| `validate-router-ab` | Under 8m   |
| `deploy-router-ab`   | Under 8m   |
| `deploy-staging`     | Under 10m  |
| `deploy-production`  | Under 10m  |

## Verification

- [x] Validate changed workflow YAML with the repository parser or `actionlint`.
- [x] Confirm selection with one Pages-only, Gateway-only, and Router A/B-only
      change.
- [ ] Run one cold-cache staging deployment.
- [ ] Run one warm-cache staging deployment.
- [ ] Retry one failed component without rebuilding.
- [ ] Confirm the summary reports source SHA, target, selected components,
      artifact digests, Worker versions, and duration.
- [ ] Promote the accepted production-target artifact set.
- [ ] Confirm one production smoke check succeeds.

No additional comprehensive test suite is required for deployment verification.

## Rollout

Land the remaining work in four independently revertible commits:

1. Release-set manifest, accepted artifact run ID, and cross-run download.
2. Component selection and parallel deployment graph.
3. Safe mutation concurrency, activation, and rollback.
4. Workflow summaries, budget measurement, and runbook updates.

Measure deployment duration after each commit. Stop adding checks when the
required release identity, readiness, and migration invariants are covered.

## Completion Criteria

- [ ] Staging and production routine deployments stay below 10 minutes at p90.
- [x] Mutating deployment workflows contain no artifact compilation steps.
- [x] Production promotion performs no compilation.
- [x] Documentation-only and test-only changes launch no deployment.
- [x] Component-only changes deploy only affected components.
- [x] Independent components deploy concurrently.
- [x] A release mismatch fails before activation.
- [x] The final summary identifies the deployed release without raw-log review.
- [x] A retained release can be retried without rebuilding.
- [ ] A retained release can be rolled back without rebuilding.
