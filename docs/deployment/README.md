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

| Workflow                                   | Trigger                                                    | Purpose                                                                                                                                                                                                              |
| ------------------------------------------ | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`                 | `push`, `pull_request`, `merge_group`                      | Builds, lints, type-checks, records the exact pushed `before..after` change set, and runs Router A/B deployment validation on protected-branch pushes.                                                               |
| `.github/workflows/build-release.yml`      | Successful `ci` run on `dev` or `main`, or manual dispatch | Builds the accepted source SHA once, verifies the release-set manifest, retains cross-run artifacts for 30 days, and invokes the deployment orchestrator.                                                            |
| `.github/workflows/validate-router-ab.yml` | Relevant Router A/B pull requests, or manual dispatch      | Runs parallel Router A/B core/Cloudflare tests, strict Worker checks, and Wrangler startup dry-run evidence. It does not run on ordinary branch pushes because deployment performs its own exact-SHA release checks. |
| `.github/workflows/publish-sdk-r2.yml`     | Manual dispatch                                            | Optionally builds `packages/sdk-web/dist`, writes signed manifests, and publishes immutable SDK runtime bundles to Cloudflare R2.                                                                                    |
| `.github/workflows/deploy-staging.yml`     | Manual dispatch with an accepted release set               | Thin staging promotion entrypoint. It accepts only an exact SHA, artifact run ID, and release-set ID.                                                                                                                |
| `.github/workflows/deploy-production.yml`  | Manual dispatch with an accepted release set               | Thin production promotion entrypoint. It accepts only an exact SHA, artifact run ID, and release-set ID.                                                                                                             |
| `.github/workflows/deploy-router-ab.yml`   | Called by an accepted release build or promotion           | Shared target-locked orchestrator: preflight, concurrent role/Gateway deployment, compatibility-ordered Pages deployment, activation, and final smoke.                                                               |
| `.github/workflows/deploy-gateway.yml`     | Called only by the release orchestrator                    | Downloads and verifies the accepted Gateway artifact, applies checked D1 migrations, deploys Gateway and its Durable Objects, then checks readiness.                                                                 |
| `.github/workflows/deploy-pages.yml`       | Called only by the release orchestrator                    | Downloads and verifies the accepted Pages artifact and deploys `seams.sh` plus `sign.seams.sh` without compiling.                                                                                                    |

Removed testnet-only workflows are replaced by the staging target in the
workflows above. Move any required GitHub Environment secrets and vars from an
old `testnet` environment into `staging`.

## First Deploy Checklist

1. Create one protected deployment-values file per target from
   `crates/router-ab-cloudflare/env/deployment-values.example.env`.
2. Add the scoped Cloudflare API token. Add funded relayer, OAuth, EVM sponsor,
   or R2 credentials only for features that target will use.
3. Run `pnpm deploy:env-rotate -- staging`, then repeat for `production` with
   its independent protected values file. The wrapper prepares one generation,
   stores separate wallet-core and product manifests, and uploads them in that
   order. See [tooling.md](tooling.md#github-environment-bootstrap).
4. Use `pnpm wallet-core:deploy:env-update -- --env staging --apply` or
   `pnpm product:deploy:env-update -- --env staging --apply` for later
   operator-owned configuration changes. These preserve generated identities
   and keep ownership boundaries explicit. Add `--variables-only`,
   `--secrets-only`, or `--only NAME_A,NAME_B` to scope the upload further.
5. Push `dev` for staging or `main` for production. Successful CI starts
   `build-release`, which creates the immutable release set before deployment.
6. Configure R2 credentials when the optional SDK release mirror is required,
   then dispatch `publish-sdk-r2.yml` manually. Pages deployments already serve
   the required runtime assets from `/sdk/*`.
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

Manual accepted-release promotion:

```bash
gh workflow run deploy-staging.yml --ref dev \
  -f source_sha=<40-char-sha> \
  -f artifact_run_id=<accepted-artifact-run-id> \
  -f release_set_id=<release-set-id>
gh workflow run publish-sdk-r2.yml --ref dev -f prefix=auto
```

Router A/B role config lives in
[router-ab-cloudflare-env.example.yml](router-ab-cloudflare-env.example.yml).

## Deploy Order

The accepted branch release runs in this order:

1. Successful `ci` for the current protected-branch tip.
2. The selector chooses the affected components and only their artifact jobs run.
3. The release-set manifest and selected artifact digests verify before mutation.
4. Selected Router roles and Gateway deploy concurrently; Pages waits for Gateway when both are selected so the frontend cannot lead its backend.
5. MPCRouter activates only after a Router topology release has all three role deployments succeed.
6. One selected-release smoke check completes the deployment.

An older CI run is rejected after a newer commit becomes the branch tip.

## Follow-Up Phase: Build Once, Deploy Many

Status: implemented for Gateway, Router A/B, Pages, and optional manual R2
publication. Cross-run release-set provenance is now the required deployment
path.

Previously, cold deployment runners compiled cryptographic WASM and the complete
Pages SDK before each upload. A failed upload could repeat an otherwise
successful build. This phase separates release artifact production from
Cloudflare mutation so retries remain short and deterministic.

### Artifact production

- [x] Add artifact-production jobs for an exact commit SHA and target.
- [x] Produce a Gateway artifact containing its prebundled Worker and four
      required WASM packages. Deployment uploads the bundle without rebuilding.
- [x] Produce one target-specific Pages artifact containing the production SDK,
      app output, wallet output, workers, WASM, and static wallet-service
      assets. The app and wallet deployments must consume the same artifact.
- [x] Produce the four Router A/B role bundles from the same release build
      while preserving independent role deployment and approval boundaries.
- [x] Include source SHA, target, build profile, toolchain versions, artifact
      digests, public deployment identity, and creation time in an immutable
      GitHub Actions artifact with a reported Actions digest.
- [x] Reject deployment when an artifact SHA, target, profile, digest, or
      public deployment identity differs from the selected release.

### Tooling and cache

- [x] Move the pinned `wasm-pack` and `wasm-bindgen` bootstrap into one
      repository-owned script or composite action used by Gateway, Pages, R2,
      and SDK publication.
- [x] Pin downloadable tool versions and verify published checksums before
      execution.
- [x] Cache Cargo registries, Git dependencies, compiled targets, wasm-pack
      state, and generated WASM using keys derived from the Rust toolchain,
      Cargo lockfiles, build scripts, target, and build profile.
- [x] Keep Gateway's package selection explicit so it cannot regress to the
      complete 12-package browser SDK build.
- [x] Record artifact build durations in the workflow summary.
- [ ] Add cold and warm duration budgets after two representative staging runs.

### Deployment and retry

- [x] Make Worker and Pages deployment jobs download immutable artifacts and
      perform no Rust, WASM, SDK, or Vite compilation.
- [x] Keep comprehensive tests in `ci.yml` and protocol evidence workflows.
      Deployment jobs run static manifest checks and lightweight readiness
      checks only.
- [x] Allow Gateway, each Router A/B role, app Pages, and wallet Pages to be
      retried independently without rebuilding successful artifacts or
      redeploying successful components.
- [x] Preserve deployment ordering where a release changes bindings or public
      identities: SigningWorker and Derivers, MPCRouter, Gateway, then Pages.
- [ ] Keep cross-run rollback artifact-based. An operator selects a previously
      accepted manifest rather than rebuilding an old commit.

### Verification and reporting

- [x] Verify Gateway readiness, ceremony JWKS availability, and required
      Gateway-to-MPC service bindings after backend deployment.
- [x] Verify app and wallet HTTP readiness plus representative SDK worker and
      WASM assets after Pages deployment.
- [x] Emit GitHub Actions summaries containing the source SHA, target, artifact
      digests, exact Pages deployment URLs, readiness results, elapsed build
      time, and retained artifact names.
- [x] Fail with a component-specific error and retain the accepted artifacts
      when a Cloudflare upload or readiness probe fails.

### Acceptance criteria

- A failed Cloudflare upload can be retried without invoking Cargo,
  `wasm-pack`, the SDK build, or Vite.
- Gateway compilation remains limited to the four server-consumed WASM
  packages.
- App and wallet Pages are always deployed from one target-specific artifact
  and one source SHA.
- Every deployed component is traceable to a content-addressed manifest.
- Deployment jobs contain no comprehensive test suites or protocol evidence
  generation.
- A role-specific retry cannot access another role's private environment or
  artifact.
- The workflow summary is sufficient to identify the deployed release and its
  retained cross-run artifacts without reading raw job logs.

Use GitHub's **Re-run failed jobs** action after an upload or readiness failure.
Successful artifact-production jobs are retained, so the retry enters only the
failed protected deployment job and does not invoke Cargo, `wasm-pack`, the SDK
build, or Vite. Release artifacts are retained for 30 days. Cross-run artifact
selection remains follow-up work; use Cloudflare's prior deployment promotion
for Pages rollback and the documented component rollback procedures elsewhere.

## Follow-On Docs

- [infra.md](infra.md): GitHub Environment values, Cloudflare setup, D1/DO/R2
  data services, Worker secrets, and migration commands.
- [tooling.md](tooling.md): deployment script commands, GitHub Environment
  bootstrap/apply mode, release validation, and staging operations.
- [sdk.md](sdk.md): SDK runtime bundle publishing, Pages `/sdk` assets, R2
  prefixes, npm release steps, and rollback.
- [release.md](release.md): versioned release process.
