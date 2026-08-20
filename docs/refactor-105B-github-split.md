# Refactor 105B: The seams-wallet GitHub Split

Date created: August 18, 2026

Status: planned. Executes Refactor 105 Phase 8 with one deliberate change of
shape: a single new public repository is carved out, and the existing
repository remains the private application home. Nothing here is pushed,
published, or deleted without an explicit go decision per phase.

## Decision

Create one new repository, `seams-tech/seams-wallet`, owning the Wallet
implementation end to end. The existing `seams-tech/seams-sdk` repository is
not replaced or renamed; it keeps everything else and becomes the private
application repository that R105 calls "seams-cloud" — no second extraction.

This supersedes `repository-split.json`'s two-new-repos model. The manifest
and `scripts/extract-repositories.mjs` remain the extraction tooling; Phase 0
reconciles them to this shape.

### Moves to `seams-wallet`

- `packages/wallet` (`@seams/wallet`) — browser client SDK
- `packages/wallet-server` (`@seams/wallet-server`) — server SDK, signer
  runtime, signer D1 migrations
- `packages/shared-ts` — wallet-only shared contracts (verified: zero console
  importers)
- `crates/` — all Rust protocol and Worker crates, EXCEPT the private
  deployment surfaces already excluded by the manifest
  (`crates/router-ab-dev/scripts`, `crates/router-ab-cloudflare/env/*.env`,
  the GitHub env-value generators)
- `wasm/` — wasm signer modules
- `tools/` — ed25519-yao generator/verifier
- `examples/self-host-cloudflare-worker`
- `benchmarks/`, `voiceId/` — wallet-adjacent; confirm at Phase 0
- the wallet-owned test families from `tests/` (see Test Split below)
- `justfile`, `.cargo`, rustfmt/clippy config, wallet-relevant root scripts

### Stays in `seams-sdk` (existing repository)

- `apps/seams-site`, `apps/seams-console`, `apps/web-server`, `apps/docs`
  (decision: docs stay private for now; the old manifest sent `apps/docs`
  public — this plan overrides that)
- `packages/console-shared-ts`, `packages/console-server-ts`,
  `packages/wallet-console-shared-ts`, `packages/wallet-console-server-ts`
- `deployment/`, `.github/workflows/*`, deploy scripts, Caddy topology,
  `crates/router-ab-dev/scripts` (local composed runtime)
- console-owned tests and the composed-stack test harness

### Consumption model after the split

The private repository consumes `@seams/wallet` and `@seams/wallet-server` as
exact-pinned published packages. No workspace link, git dependency, path
alias, submodule, or sibling checkout. Registry: npm public (the SDK is being
open-sourced); until the repo flips public, GitHub Packages or a tarball pin
is acceptable as an interim.

Precedent already in tree: signer migrations and wasm assets are resolved via
`node_modules/@seams/wallet-server/...` in the wrangler configs and deploy
scripts, and the R105 packed-artifact proof
(`tests/scripts/check-packed-console-boundaries.mjs`) already validates the
private side against packed tarballs.

### History policy

The new repository starts from a fresh initial commit (no history). The
monorepo history contains private deployment values, operational runbooks,
and pre-rename internals; scrubbing with git-filter-repo would still require
a full secret/history audit for lower value. The monorepo remains the private
historical record. Record the extraction source SHA in the initial commit
message.

## Test Split

The old manifest ignored `tests/` entirely; this is the largest unresolved
surface (~487 unit files, 14 wallet-iframe, 29 relayer, 9 e2e, plus
`tests/e2e/intended-behaviours`). Ownership follows the R105 Phase 0
inventory (`docs/refactor-105-ownership-inventory.md`):

- Move to `seams-wallet`: `tests/wallet-iframe/`, `tests/lit-components/`,
  `tests/e2e/intended-behaviours/`, `tests/relayer/` wallet files, the wallet
  unit families (`routerAb*`, `d1Wallet*`, `linkedDevice*`, `seamsWeb*`,
  `emailOtp*`, `passkey*`, `ecdsa*`, `ed25519*`, `walletCustody*`,
  `configs.*`, ...), the wallet source-guard scripts, and the Playwright
  configs they need. The intended-behaviour harness moves with a public local
  runtime target (the composed private stack is not a public dependency).
- Stay: console/dashboard tests, `consoleSchemaOwnership`,
  `walletConsoleServiceBinding`, staging-script tests, the console boundary
  guards, packed-boundary proof, and shared D1 fixtures they use.
- Mixed files identified in the inventory (`pricing.checkout.apiWiring`,
  `packageExports.contract`, `d1LocalDev*`/`d1Staging*` script tests) are
  split or duplicated at Phase 2, not shared.

## Phases

### Phase 0: Reconcile the manifest and confirm placements

- [ ] Update `repository-split.json`: rename the public repo to
      `seams-wallet`; delete the `seams-cloud` entry (the existing repo is the
      private home); add the test-split paths; move `apps/docs` to stays.
- [ ] Confirm `benchmarks/`, `voiceId/`, `apps/docs` placement with the owner.
- [ ] Decide registry (npm public vs interim GitHub Packages) and initial
      public visibility timing.
- [ ] Land the in-flight R105 service-binding work first; do not extract a
      moving tree.

### Phase 1: Preflight scans (gate for any push)

- [ ] Secret scan over the extraction file set (gitleaks or equivalent), plus
      a manual pass over `*.example.env`, wrangler configs, and fixtures.
- [ ] License audit: LICENSE files for both repos, crate/package license
      fields, third-party notices.
- [ ] Source-map and built-artifact audit: no `dist/`, `.wrangler/`, or
      `.env` content in the tracked extraction set.
- [ ] Verify the boundary guards are green so no console source can ride
      along (`check-signer-console-module-boundaries` already scans dist).

### Phase 2: Materialize and validate locally

- [ ] Run `scripts/extract-repositories.mjs` against the reconciled manifest.
- [ ] In the extracted tree: `pnpm install`, `build:wasm`, wallet +
      wallet-server type-checks, vector tests (`cargo test`), the moved unit
      families, and the local reference runtime lifecycle (start, restart
      preserving state, explicit reset).
- [ ] Author the public repo's own CI (build, type-check, vectors, unit
      subset) and README; no deploy workflows.
- [ ] Fix the extraction gaps this surfaces (the R105 dry run needed wasm
      artifacts copied in; the public CI must build them itself).

### Phase 3: Create and push `seams-tech/seams-wallet`

- [ ] Create the repo private; push the validated tree as the initial commit
      (source SHA recorded).
- [ ] Re-run CI in the real repo.
- [ ] Flip public only after Phase 1 scans are re-verified on the pushed tree
      and the owner signs off.

### Phase 4: Publish and re-point the private repository

- [ ] Publish `@seams/wallet` and `@seams/wallet-server` (first release under
      the new names; version from `repository-split.json.publicSdkVersion`).
- [ ] In `seams-sdk`: replace `workspace:*` with exact pins; `pnpm install`;
      remove moved paths in the same change set.
- [ ] Rewire local dev: `pnpm router` / `gateway:server` stop building the
      SDK from source; wallet iframe assets and signer migrations resolve
      from the installed package. `build:sdk*` scripts are deleted, not
      stubbed.
- [ ] Rewire deploy: `deploy-backend.mjs` consumes the installed
      `@seams/wallet-server` dist instead of building wasm + SDK in CI.
- [ ] Delete the moved test families and the extraction tooling from the
      private repo; keep `repository-split.json` as the record.

### Phase 5: Verify both sides independently

- [ ] Private: full local stack (`pnpm router`, console app, site), the
      intended-behaviour contracts against installed packages, one staging
      deploy.
- [ ] Public: clean clone on a second machine or CI runner — install, build,
      test, run the local wallet lifecycle with no access to the private
      repo.
- [ ] Reconcile `docs/refactor-105-split-console.md` Phase 8 checkboxes and
      this plan.

## Risks and controls

- Dev-loop regression is the real cost: today the SDK rebuilds in-tree
  (`build:sdk`), post-split it is a versioned dependency. Wallet changes then
  require publish-and-bump (or a local tarball pin for spikes). Accept this
  deliberately — it is the point of the boundary — and keep the tarball-pin
  path documented for local iteration.
- Accidental publication: nothing goes public before Phase 1 scans pass on
  the pushed tree; the repo is created private.
- Split drift: extraction from a moving tree. Freeze: land in-flight R105
  work, then extract from a tagged SHA.
- The composed intended-behaviour harness must not silently lose coverage in
  the private repo: the two-device and lifecycle contracts that exercise the
  composed stack keep private copies until the public runtime covers them.
