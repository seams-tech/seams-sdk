# Refactor 105B: GitHub And Release Split

Date created: August 18, 2026

Last reconciled: August 24, 2026

Status: planned. This plan executes Refactor 105 Phase 8 after the in-monorepo
Console boundary is complete.

## Decision

Use exactly two repositories:

| Repository | Visibility | Ownership |
| --- | --- | --- |
| `seams-tech/seams-monorepo` | private | The current `seams-tech/seams-sdk` repository, renamed in place. It owns Console, future private products, deployment topology, environment configuration, secrets, provider configuration, and staging/production operations. |
| `seams-tech/seams-wallet` | public | One fresh-history repository containing the Wallet client and server SDKs, their Rust/Wasm implementation, public docs, public examples, and a generic self-hostable runtime. |

The current repository keeps its history and is renamed. Do not create a
second private repository. The public repository starts with one initial commit
created from a fixed source revision; private history is not copied.

Rust remains in `seams-wallet` beside the TypeScript packages that use it.
Refactor 105B creates no additional Rust repositories and publishes no crates
to crates.io. Carried crate manifests use `publish = false` unless a later,
separately approved plan changes that decision.

Private deployment remains in `seams-monorepo`, with Console and Wallet-system
secrets and environment variables managed by separate pipelines and disjoint
write credentials.

## Repository Ownership

### Public `seams-wallet`

Move the complete public Wallet implementation:

- `packages/wallet`, published as `@seams/wallet`;
- `packages/wallet-server`, published as `@seams/wallet-server`;
- Wallet-only shared packages required by those packages;
- the required `crates/`, `wasm/`, generators, and checked-in bindings;
- Wallet-owned tests that run without Console or private infrastructure;
- Wallet API, protocol, self-hosting, and development documentation under
  `docs/`;
- `examples/seams-auth-menu`, containing the minimal `SeamsAuthMenu` consumer;
- `examples/self-host-cloudflare-worker` and the generic local/self-host
  runtime;
- package build configuration and newly authored credential-free CI and npm
  publishing workflows.

The public repository contains no Seams production/staging topology, account
IDs, customer data, provider registrations, environment values, deployment
secrets, private runbooks, or Console source.

### Private `seams-monorepo`

Keep:

- `apps/seams-site`, `apps/seams-console`, `apps/web-server`, and `apps/docs`;
- Console core, Wallet Console, Admin, and future private product packages;
- every current `.github/workflows/*` file;
- deployment scripts, Cloudflare/Wrangler configuration, domains, routes,
  environment declarations, account identifiers, provider configuration,
  secrets, and production/staging runbooks;
- the separate Console and Wallet-system target files, environment/secret
  generators, update/rotation commands, and deployment entrypoints;
- Console, deployment, staging, and composed-stack tests;
- internal architecture and refactor plans.

Wallet documentation that belongs to the public SDK receives one canonical
copy in `seams-wallet/docs`. The hosted docs application remains private and
links to the public Wallet documentation where appropriate.

## Consumption And Deployment Contract

The private monorepo imports exact published versions of `@seams/wallet` and
`@seams/wallet-server`. It uses no workspace link, path or Git dependency,
submodule, sibling checkout, or fallback to public source.

`@seams/wallet` ships the browser SDK and `SeamsAuthMenu` exports needed by the
private frontend. `@seams/wallet-server` ships the generic executable Worker
modules, Wasm assets, signer migrations, types, and an artifact manifest needed
by the private backend.

The packages contain generic runtime artifacts only. Private workflows add the
real Cloudflare bindings, routes, database IDs, service names, provider
configuration, environment values, and secrets when they deploy. Private
deployment does not run Cargo or `wasm-pack` and does not check out
`seams-wallet` source.

All existing GitHub Actions remain in `seams-monorepo`. The public repository
gets new workflows limited to public validation and npm publishing. Those
workflows require no Seams deployment credential or private environment.

The two npm packages may be released together, but their package manifests are
the version authorities. The private lockfile records the exact compatible
pair. Do not add a second release-version manifest.

### Private Secret And Environment Pipelines

The repository split also makes private deployment ownership explicit. Replace
the current paired `wallet-core`/`product` generation with two independent
private pipelines:

```text
deployment/console/targets.json
  console:deploy:env-prepare
  console:deploy:env-apply
  console:deploy:env-update
  console:deploy

deployment/wallet-system/targets.json
  wallet-system:deploy:env-prepare
  wallet-system:deploy:env-apply
  wallet-system:deploy:env-update
  wallet-system:deploy
```

The Console pipeline owns Console Pages/Worker/D1, Console session and OAuth
secrets, Console email/webhook/billing configuration, Console routes, and
Console origins. The Wallet-system pipeline owns Wallet Gateway/Runtime,
hosted Wallet Pages, signer and Router A/B infrastructure, protocol keys, root
shares, ceremony/signing-session material, relayer credentials, Wallet network
configuration, and Wallet origins.

The two generators have different manifest schemas and output files. Each can
write only its own protected GitHub environments and owned variable/secret
names. Preparing or rotating Console configuration never generates Wallet
cryptographic material. Preparing or rotating Wallet infrastructure never
reads or writes a Console secret.

Use distinct environment names. Console uses `staging-console` and
`production-console`. Wallet-system environments remain lane/role-specific,
for example `<lane>-gateway`, `<lane>-mpc-router`, `<lane>-deriver-a`,
`<lane>-deriver-b`, and `<lane>-signing-worker`. No GitHub environment belongs
to both pipelines. Site/docs environments keep their existing private owner and
are outside the Wallet-system secret set.

Deploy workflows follow the same boundary. Remove the combined backend
sequence that deploys Wallet Runtime, Console, and Gateway under one secret
inventory. Do not pass a repository environment's complete secret map into a
cross-authority deployment process. Each workflow receives the narrow list of
values owned by its GitHub environment and a Cloudflare token scoped to its
resources.

The only cross-pipeline handoff is read-only, non-secret deployment identity:
network names, public origins, service binding names, and deployed Wallet
artifact/runtime versions. Neither pipeline can invoke, rotate, or overwrite
the other pipeline.

## Test Ownership

Move a test when it can run against the generic Wallet runtime with generated
fixtures and no Console, provider account, private service, or deployment
secret. Keep a test private when it exercises Console, private bindings,
staging/production topology, deployment behavior, or composed product flows.

Split mixed files by behavior. Avoid a cross-repository test package or any
test helper that recreates a source dependency between the repositories.

The required checks are intentionally small:

- public: install, build both packages and required Wasm, run the Wallet-owned
  tests, and start the generic runtime once;
- private: install the exact npm versions, build Console/backend artifacts, and
  run one composed Wallet flow before deployment.

Existing Rust/Wasm checks move with their owning source. This plan does not add
an exhaustive new test matrix or formal-verification gate solely for the split.

## Extraction Contract

Update `repository-split.json` and `scripts/extract-repositories.mjs` for one
public output named `seams-wallet`. The existing repository is the retained
private source and is not an extraction output.

Extract from one recorded commit into an empty directory. The manifest must
explicitly include public paths and reject unassigned or private deployment
paths. After extraction, inspect the final tree for secrets and private
configuration before its first push. This is a one-time source movement tool;
delete it from the private repository after the split unless it still has a
concrete owner.

## Phases

### Phase 0: Freeze Ownership

- [ ] Complete the Refactor 105 in-monorepo boundary and classify unfinished
      Refactor 99B paths as private.
- [ ] Reconcile the ownership inventory against the current tree.
- [ ] Classify every deployment variable, secret, target, generator output,
      GitHub environment, and Cloudflare token as Console or Wallet-system.
- [ ] Confirm the public docs, examples, tests, Rust/Wasm inputs, and package
      artifacts required for an independent Wallet build.
- [ ] Choose the extraction commit, initial npm versions, public license, and
      required third-party notices.

Exit: every moved path has a destination and the extraction source is no longer
changing.

### Phase 1: Rename And Extract

- [ ] Rename `seams-tech/seams-sdk` to `seams-tech/seams-monorepo` in place and
      update its remote, package metadata, links, and badges.
- [ ] Create `seams-tech/seams-wallet` as an empty private repository.
- [ ] Reconcile the split manifest to the two-repository decision and extract
      the public tree from the fixed source commit.
- [ ] Check the extracted tree for private configuration, secrets, and missing
      public dependencies.

Exit: the private repository is intact and the candidate public tree contains
only the intended Wallet source.

### Phase 2: Make `seams-wallet` Independent

- [ ] Give the public repository its own workspace manifest, lockfile, package
      metadata, README, license, security policy, docs, and examples.
- [ ] Set every carried Rust crate to `publish = false`.
- [ ] Make `@seams/wallet-server` package the Worker, Wasm, migrations, types,
      and generic runtime artifacts consumed by private deployment.
- [ ] Add credential-free CI and npm trusted-publishing workflows.
- [ ] Install, build, run the Wallet-owned tests, start the generic runtime,
      and build `examples/seams-auth-menu` from a clean public checkout.

Exit: `seams-wallet` builds and runs without the private repository or private
credentials.

### Phase 3: Publish The Public Repository And Packages

- [ ] Push one fresh initial commit with the extraction source SHA recorded.
- [ ] Make the repository public after the final tree review.
- [ ] Publish `@seams/wallet` and `@seams/wallet-server` to public npm using
      trusted publishing and provenance.
- [ ] Confirm a clean install resolves the intended package versions and all
      documented runtime artifacts.

Exit: the public source and both npm packages are independently consumable.

### Phase 4: Rewire The Private Monorepo

- [ ] Replace Wallet workspace ranges and source aliases with exact npm
      versions, then regenerate the private lockfile.
- [ ] Rewire frontend builds to import `@seams/wallet`.
- [ ] Rewire backend, migration, local-runtime, and deployment scripts to use
      artifacts from `@seams/wallet-server`.
- [ ] Split `deployment/targets.json`, environment generation, update/rotation
      commands, GitHub environments, and deploy entrypoints into the Console
      and Wallet-system owners described above.
- [ ] Remove the paired generation manifest, shared generation ID, generic
      `product` component, combined rotation command, and cross-authority
      `DEPLOYMENT_SECRETS_JSON` input.
- [ ] Remove Cargo, `wasm-pack`, and public-source build steps from private
      deployment workflows.
- [ ] Run the private build and one composed Wallet flow before deleting moved
      source.

Exit: private development and deployment use only installed public artifacts.

### Phase 5: Delete Moved Source And Deploy

- [ ] Delete public Wallet source, public tests/docs/examples, and obsolete
      public build/extraction paths from `seams-monorepo`.
- [ ] Remove stale workspace entries, aliases, forwarding packages, and source
      fallbacks. Keep private Console, Admin, deployment, and composed tests.
- [ ] Deploy the staging Wallet system and staging Console through their
      separate private workflows using the exact npm pins. Deploy production
      only after both staging paths succeed.

Exit: the private repository owns product composition and deployment; the
public repository owns the Wallet implementation; neither depends on the
other's source tree.

## Failure Handling

Do not delete moved source until the public packages are published and the
private build works against their exact versions. Before deletion, a failed
phase leaves the private tree unchanged. After deletion, revert the private
rewiring/deletion commit and restore the previous exact package pins if needed.
Published npm versions remain immutable; publish a corrected version instead of
overwriting or unpublishing one.

## Definition Of Done

- `seams-tech/seams-monorepo` is the renamed private historical repository;
- `seams-tech/seams-wallet` is the only new repository and has fresh history;
- Console, future private products, all existing workflows, environment and
  secret configuration, provider configuration, and staging/production
  deployment remain private;
- the public repository owns both Wallet npm packages and all Rust/Wasm needed
  to build them;
- Rust crates remain co-located and unpublished;
- the public repository includes Wallet docs, a minimal `SeamsAuthMenu`
  example, and a working generic self-host runtime;
- the private monorepo exact-pins the public packages and deploys their prebuilt
  artifacts without public source access or Rust tooling;
- Console and Wallet-system secrets, variables, targets, rotations, GitHub
  environments, Cloudflare tokens, and deployment workflows are disjoint;
- neither private pipeline can generate, apply, rotate, or deploy the other
  authority's configuration;
- no compatibility package or duplicate repository remains.

## Related Plans

[Refactor 105](./refactor-105-split-console.md) owns the Console/Wallet source
boundary. [Refactor 105C](./refactor-105C.md) starts after this split and owns
the private unified Console deployment. [Refactor 99B](./refactor-99B-MPC-control-plane.md)
owns the private Admin control plane.
