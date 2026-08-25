# Refactor 105: Product-Neutral Console Boundary

Date created: August 11, 2026

Last reconciled: August 24, 2026 (repository closeout decision)

Status: planned closeout. Phases 0–6 define the required in-monorepo Console
boundary. Confirm their remaining work against the current tree before Phase 7.
Phase 8 is executed by Refactor 105B. The current private repository will be
renamed in place and will not be extracted into a second private repository.

## Decision

Make the Seams Console an independently buildable customer control plane with a
product-neutral core. Move wallet-specific Console behavior behind an explicit
Wallet Console integration. Keep the Wallet SDK and signer runtime independent
of every Console package.

The public Wallet packages use the final names `@seams/wallet` and
`@seams/wallet-server`. Refactor 105 treats that already-applied rename as an
atomic breaking change and adds no aliases or compatibility packages.

After the boundary and rename pass, keep the current product and deployment
monorepo private and rename it to `seams-tech/seams-monorepo`. Create one new
public repository, `seams-tech/seams-wallet`, containing the Wallet
implementation and enough reference infrastructure to build, test, and run it
locally. This is one new-repository extraction plus an in-place private-repo
rename, not two new repositories.

The public repository owns `@seams/wallet`, `@seams/wallet-server`, their Rust
and Wasm implementation, public tests and SDK documentation, public examples
(including a minimal `SeamsAuthMenu` example), and a generic local runtime.
Its Rust crates remain implementation crates with `publish = false` by
default. Refactor 105 does not publish crates to crates.io or create a separate
Rust repository. The public repository has credential-free validation and npm
release workflows. The private repository exact-pins npm releases and deploys
the prebuilt generic Wallet artifacts shipped by those packages.

Inside the private monorepo, Console deployment and Wallet-system deployment
are separate pipelines. They use different target files, generators, protected
GitHub environments, secret/variable inventories, scoped Cloudflare tokens,
rotation commands, backups, and deploy workflows. Neither pipeline can write or
rotate the other authority's configuration.

The target dependency graph is:

```text
Console core ----------------------+
  organizations                    |
  projects and environments        |
  membership and RBAC              |
  customer-console sessions        +--> Wallet Console application and Worker
  audit, email, webhook transport  |      explicit static composition
  billing account and ledger       |
                                    |
@seams/wallet and                   |
@seams/wallet-server ---------------+
  wallet lifecycle
  wallet sessions and signing
  signer storage and custody
  supported Wallet host APIs
  local reference runtime

MPC admin control plane (Refactor 99B)
  separate application, Worker, auth plane, and storage
```

The Console core and Wallet SDK do not depend on each other. The composed Wallet
Console depends on both. A future Satyr Ecommerce Agents module can compose the
same Console core with its own services without inheriting wallet signing,
custody, recovery, or chain dependencies.

## Implementation Prerequisite: Wallet-Boundary Stabilization

Refactor 105's source-boundary work was conditioned on these Wallet refactors;
the current tree treats their stabilized outputs as upstream inputs:

- [Refactor 100](./refactor-100-passkey-account-refactor.md) owns passkey account
  custody, account identity, threshold sessions, and browser Wallet state;
- [Refactor 101](./refactor-101-wallet-execution-lanes.md) owns wallet-key
  identity and execution-lane domain types;
- [Refactor 102](./refactor-102-rotatable-signing-lanes.md) owns signing-lane
  storage, rotation protocols, recipient packages, and session bindings;
- [Refactor 103E](./refactor-103E.md) owns public Wallet APIs, React and iframe
  flows, Gateway routes, D1 state, linked-device enrollment, exact authority
  activation, and the canonical metadata projection. Durable product behavior
  lives in [Intended Behaviours](./intended-behaviours.md#linked-devices);
- [Refactor 107](./refactor-107-remove-app-session.md) owns the deletion of Wallet AppSessions,
  server-internal `VerifiedOwnerProof`, and opaque D1-backed Wallet Sessions.

These plans change the files, routes, stores, migrations, and exported types that
Refactor 105 must classify. Parallel package movement or package renaming would
create avoidable merge conflicts and a stale ownership inventory.

[Refactor 130A](./refactor-111-legacy-email-recovery-cleanup.md) has landed. Its
deletion of the legacy inbound-email recovery system, routes, stores, browser
state, and Wasm bindings is part of the Refactor 105 starting tree. Do not
inventory or recreate those deleted paths.

The current source tree is the post-Refactor-100/101/102/103/103B/107 and
Refactor-130A starting tree. Their lifecycle, session, lane, linked-device,
schema, and deletion decisions are upstream inputs, not a second R105 backlog.
The checked-in ownership inventory is the historical starting snapshot. Phase 0
of R105B regenerates it against the closeout tree before freezing the source
reference. Confirm that no branch is still changing a shared Wallet domain,
route, signer store, public package, or browser Wallet state that R105 will move
or rename. Any such change moves the source-reference freeze; unrelated
follow-ups stay in their own plans.

Documentation decisions may land earlier. Repository materialization, package
release, and deployment cutover wait for the Phase 7 and Phase 8 gates.

The public Wallet package rename is one atomic late change. The current source
paths use the final names; Phase 7 proves the rename across artifacts. Do not
introduce forwarding packages, aliases, or dual import paths while preparing the
release.

For the remaining release and extraction work, use narrow static checks and
focused tests while editing, then run each gate's full build once after its
source changes are complete. Do not start, stop, rebuild beneath, or leave
behind the developer's manual-testing services unless the developer explicitly
asks for runtime verification.

Refactors 113 and 114 are proposed Wallet follow-ups. Refactor 130B is deferred.
They do not block Refactor 105 unless they enter implementation before this gate
passes; if that happens, finish their changes to shared Wallet paths before the
ownership inventory and package movement begin.

Refactor 99B is a private-repository prerequisite for the final Console route
and authorization classification, not a public Wallet dependency. Before the
Phase 8 source reference is frozen, its `/admin/*` routes, admin session
authority, platform-support paths, bindings, and tests must be either moved to
the private admin plane or explicitly retained as private composition code.
Refactor 105 does not wait for a second repository or public package for admin
work. An unfinished R99B implementation stays entirely in the private
monorepo, and any R99B path in the public extraction allowlist is a gate
failure.

## Why This Refactor Exists

The repository already has a useful first boundary:

- `@seams/wallet` contains the browser wallet runtime and has no Console dependency.
- `@seams/wallet-server` contains the signer runtime and exposes a curated
  `cloud-host` composition surface.
- `@seams-internal/console-server` and `@seams-internal/console-shared` are
  separate workspace packages.
- `seams-console` and `seams-signer` are separate D1 databases.

The remaining coupling prevents the Console from standing on its own:

- `@seams-internal/console-server` directly depends on `@seams/wallet-server`.
- Console modules import wallet-owned D1, logger, random-ID, HTTP, session, and
  Router API types from `@seams/wallet-server/cloud-host`.
- the Console router is one large optional service bag containing customer
  administration, wallets, sponsorship, policies, key export, billing, and
  platform observability;
- `apps/seams-site` combines marketing, wallet demos, SDK examples, dashboard
  login, and the customer Console in one Vite application;
- the whole site runs inside `SeamsWebProvider`, including dashboard routes;
- customer Console sign-in still uses the combined Gateway's generic
  `/session/exchange` route, even though it issues the distinct
  `console_session_v1` credential;
- the Console database contains both product-neutral records and wallet-specific
  projections such as `wallet_index`, `key_exports`, sponsored calls, runtime
  snapshots, and monthly active wallet billing;
- local and staging composition wires the Console database and signer database
  from the Console package.

These are compile-time, deployment, authentication, and data-ownership issues.
Moving folders alone will not establish the intended boundary.

## Relationship To Existing Plans

### `refactor-87-signer-console-split.md`

[Refactor 87](./refactor-87-signer-console-split.md) is the completed foundation
for this work. It moved Console implementation out of `@seams/wallet-server`, made
the signer package free of Console imports, split signer and Console migrations,
and introduced supported composition exports.

Refactor 105 starts from that result. It does not reopen signer cryptography,
wallet ceremonies, or signer storage.

### `refactor-99-console.md`

[Refactor 99 Console](./refactor-99-console.md) is directly relevant. Its
organization, billing, email, and package-boundary decisions remain useful
where they describe implemented behavior. Its repository names and extraction
shape are superseded by this closeout plan.

The filename calls this Refactor 99 while its current heading says “Refactor
103.” Resolve that documentation-number mismatch separately; this plan refers to
the file by its repository name.

Refactor 105 narrows and updates its repository-boundary work:

- the Console core becomes product-neutral instead of treating every hosted
  wallet feature as part of the core Console;
- the customer dashboard moves out of the mixed `apps/seams-site` application;
- the already distinct customer Console session moves out of Wallet-owned
  adapters, routes, secrets, and deployment composition;
- generic Console modules stop importing the Wallet server package;
- Wallet Console modules become the only Console-side consumers of supported
  wallet server exports;
- the public packages are renamed to `@seams/wallet` and
  `@seams/wallet-server` in a dedicated pre-extraction phase;
- the current repository will be renamed `seams-tech/seams-monorepo` and remains
  the private product/deployment home;
- one public `seams-tech/seams-wallet` repository is materialized from a frozen
  source reference after the artifact gates pass.

Refactor 99's placement of the whole `apps/seams-site` application in the private
repository is confirmed. Refactor 105 additionally extracts the customer
dashboard into `apps/seams-console` inside that same private repository. The
marketing site and hosted Wallet demos remain private. The public Wallet
repository keeps SDK documentation, tests, local reference examples, and a
local reference runtime.

Refactor 99's old extraction section used `seams-cloud` and
`seams-wallet-sdk`, described two new repositories, and deferred the public
package rename. Those names and that shape are historical. Refactor 105
supersedes them with the in-place `seams-tech/seams-monorepo` rename and the one
new `seams-tech/seams-wallet` repository. The extraction change remains source
movement and release wiring only; no domain, protocol, schema, or public API
redesign belongs in that change.

### `refactor-99B-MPC-control-plane.md`

[Refactor 99B](./refactor-99B-MPC-control-plane.md) is relevant as an adjacent
security boundary. It owns the separation of MPC fleet observability,
platform-support operations, and MPC configuration into `apps/seams-admin` and
`packages/platform-admin-server-ts`.

Refactor 105 does not absorb that work. During ownership classification:

- tenant-facing audit, usage, and product errors remain in the customer Console;
- fleet telemetry, Ops Cockpit, platform-wide customer search, platform billing
  operations, and MPC configuration move to the Refactor 99B admin plane;
- `platformSupport` leaves customer Console claims under Refactor 99B;
- Console, Wallet Gateway, and Admin remain separate Worker deployments.

Refactor 99B's route and authorization movement must be classified before the
Phase 8 source reference is frozen and before this plan deletes mixed
observability or platform-support paths. The work itself remains private and
does not add a public Wallet dependency.

### `refactor-107.md`

[Refactor 107](./refactor-107-remove-app-session.md) is the current Wallet authorization baseline.
It deletes application authentication from the Wallet SDK, replaces
client-visible Wallet Session JWTs with opaque D1-backed bearer tokens, and
keeps `console_session_v1` as a separate authority plane.

Refactor 105 preserves those decisions. It does not add an application session
back to the Wallet SDK or share a bearer credential between Wallet and Console.
Its remaining authentication work is ownership and deployment separation:

- move the Console session interface and implementation out of Wallet server
  exports;
- move Google and GitHub Console exchange endpoints from the combined Gateway
  to the Console Worker;
- give the Console its own route namespace, issuer, audience, cookie, secrets,
  and deployment;
- keep opaque Wallet Session resolution entirely inside the Wallet Gateway.

### Wallet Recovery Follow-Ups

[Refactor 130A](./refactor-111-legacy-email-recovery-cleanup.md) is implemented and
defines the starting tree: legacy inbound-email recovery no longer exists.
[Refactor 113](./refactor-113-recovery-code-reveal-step-up.md) and
[Refactor 114](./refactor-114-recover-account-with-code.md) are proposed Wallet lifecycle work. Refactor
130B is deferred and has no checked-in implementation plan. They remain
Wallet-owned and do not change the Console boundary in this plan.

## Goals

1. Build and test the Console core without `@seams/wallet`,
   `@seams/wallet-server`,
   signer Wasm, signer migrations, or signer database bindings.
2. Build and test the Wallet packages and local reference signer without any
   Console package, Console route, or Console migration.
3. Compose the hosted Wallet Console explicitly from Console core and wallet
   product modules.
4. Give the customer Console its own application, authentication plane, Worker,
   database binding, deployment, and route namespace.
5. Assign every route, service, table, migration, UI page, event category, and
   billing meter to Console core, Wallet Console, MPC Admin, or composition.
6. Preserve current customer-visible behavior during the boundary changes.
7. Make a future Satyr Ecommerce Agents integration possible without adding a
   Satyr abstraction, SDK, route, or product behavior during this refactor.
8. Rename the public packages without forwarding packages, deprecated aliases,
   or parallel legacy import paths.
9. Produce `seams-tech/seams-wallet` with public SDK docs, tests, examples, a
   minimal `SeamsAuthMenu` example, and a generic local runtime that runs the
   real Wallet lifecycle while leaving staging and production deployment
   ownership private.
10. Extract from one recorded source commit and make the private deployment
    consume only exact-pinned npm packages and their prebuilt generic artifacts.

## Non-goals

- implementing NFC credentials, robot provisioning, or Satyr Ecommerce Agents;
- designing a generic plugin marketplace or dynamic module loader;
- changing wallet signing, registration, recovery, key custody, or cryptography;
- changing customer organization, RBAC, prepaid billing, or email behavior;
- changing Git history before the boundary, rename, and packed-build gates pass;
- publishing internal Console packages;
- publishing Rust crates to crates.io or splitting the Rust implementation into
  another repository;
- combining the customer Console and MPC admin plane;
- moving production or staging GitHub Actions, environment values, topology,
  secrets, provider configuration, or operational runbooks into the public
  repository;
- generalizing a wallet-specific feature before a second product demonstrates a
  shared domain model.

## Ownership Rules

Use domain ownership rather than technical similarity.

### Console core

The Console core owns customer control-plane capabilities that remain meaningful
without wallets:

- customer identity and Console sessions;
- organizations, projects, environments, memberships, invitations, and RBAC;
- account settings and organization switching;
- API credential records, rotation, revocation, and IP/origin restrictions;
- audit event storage, evidence, and exports;
- email outbox, delivery, templates, and provider adapters;
- webhook endpoint and delivery transport;
- billing accounts, ledger, credit purchases, refunds, invoices, and receipts;
- tenant isolation metadata;
- the dashboard shell, project/environment selector, administration navigation,
  and shared customer-console components;
- Console HTTP routing, authorization, D1 contracts, logging, and boundary
  normalization.

Product-specific scope names, event categories, meters, policy payloads, and UI
pages are supplied by the composed product.

### Wallet Console

The Wallet Console integration owns hosted wallet administration:

- wallet inventory and wallet lifecycle projections;
- wallet and signing API-key scopes;
- wallet policies and their compiled runtime snapshots;
- gas sponsorship, spend caps, pricing, reservations, and sponsored-call history;
- wallet approvals and key-export workflows;
- wallet usage meters, including monthly active wallets;
- wallet webhook event categories and wallet-specific audit event details;
- wallet onboarding steps;
- wallet dashboard routes, navigation, API clients, and product copy;
- wallet Router API route extensions and supported signer-host composition.

Keep the current policy and approval implementations wallet-owned. Extract a
shared mechanism only after another product needs the same lifecycle and the
common invariant is concrete.

### MPC admin

Refactor 99B owns:

- Ops Cockpit and platform observability;
- fleet telemetry, incidents, and alerts;
- MPC configuration and rollout state;
- platform-support authorization and platform-wide customer operations;
- operator audit history;
- the `admin.seams.sh` application and `/admin/*` Worker.

### Composition roots

Composition code may import Console core, Wallet Console, and Wallet SDK
packages. It owns:

- the deployed Wallet Console Worker entrypoint;
- explicit construction of core and wallet services;
- service bindings between customer Console and wallet runtime;
- environment parsing and provider selection;
- migration orchestration for the composed deployment;
- private composed-development and staging harnesses.

Domain packages must never import a composition root.

The public Wallet repository owns a separate Wallet-only local composition root.
That runtime may compose Wallet packages, signer storage, MPC development
services, and development adapters. It cannot import the Console server merely
to obtain a Worker entrypoint, D1 migration command, route, or utility.

## Target Source Layout

Use clear domain names for the final repository and package boundaries:

```text
seams-monorepo/                       # private, renamed in place
  apps/
    seams-site/
    seams-console/
    seams-admin/
    docs/                             # hosted docs application and private docs
  packages/
    console-shared-ts/
    console-server-ts/
    wallet-console-shared-ts/
    wallet-console-server-ts/
    platform-admin-server-ts/
  deployment/
    console/targets.json
    wallet-system/targets.json
  scripts/deployment/
    console/
    wallet-system/
  .github/workflows/                 # every staging/production workflow
    deploy-console-*.yml
    deploy-wallet-system-*.yml

seams-wallet/                         # public, fresh history
  packages/
    wallet/                           # @seams/wallet
    wallet-server/                    # @seams/wallet-server
    shared-ts/
  crates/
  wasm/
  tools/
  docs/                               # Wallet API/protocol/runtime docs
  examples/
    seams-auth-menu/
    self-host-cloudflare-worker/
```

Inside `apps/seams-console`, keep direct and readable ownership:

```text
src/
  core/                               # shell, session, org/team/account UI
  products/
    wallet/                           # wallet routes and pages
  app/                                # static composition of core + wallet routes
```

Do not create a general plugin framework. The application imports one typed
Wallet Console route definition and appends it to the core route list. A future
Satyr Ecommerce Agents module can add another explicit route definition when it
has a working private operating path.

## Final Repository Ownership

The repository destinations are fixed: rename the current private repository to
`seams-tech/seams-monorepo`, and create only one new repository,
`seams-tech/seams-wallet`.

### Private `seams-tech/seams-monorepo`

Owns:

- `apps/seams-site`, including marketing and hosted Wallet demos;
- `apps/seams-console`;
- `apps/seams-admin` from Refactor 99B;
- product and deployment documentation, including private Console/Admin
  architecture, staging and production runbooks, and operator procedures;
- `apps/web-server` and hosted Gateway/Worker composition;
- `console-shared-ts` and `console-server-ts`;
- `wallet-console-shared-ts` and `wallet-console-server-ts`;
- `platform-admin-server-ts`;
- Console, billing, sponsorship, webhook, audit, email, and admin migrations;
- all production and staging GitHub Actions, Cloudflare entrypoints, routes,
  bindings, domains, environment variables, secrets, provider configuration,
  topology, observability, backup, restore, and operational runbooks;
- separate Console and Wallet-system target files, generators, protected GitHub
  environments, secret/variable inventories, rotation commands, Cloudflare
  tokens, and deployment workflows;
- production migration orchestration for both private schemas and the installed
  Wallet server package's signer schema.

The private repository exact-pins published `@seams/wallet` and
`@seams/wallet-server` releases. It consumes their prebuilt generic runtime and
Wasm/Worker artifacts from the installed packages. It never builds the public
Rust/Wasm implementation from a source checkout during deployment and uses no
workspace link, Git dependency, source-path alias, submodule, or sibling
checkout to consume Wallet code.

### Public `seams-tech/seams-wallet`

Owns:

- `@seams/wallet`;
- `@seams/wallet-server`;
- Wallet-owned shared code and required Rust/Wasm crates;
- the Cargo manifests, lockfiles, protocol tooling, and build configuration
  needed to build those artifacts; every implementation crate is
  `publish = false` by default;
- registration, authentication, signing, recovery, Wallet Session, key, lane,
  and linked-device behavior;
- signer storage schemas and migrations;
- Cloudflare-compatible Wallet Worker factories and typed bindings;
- a local reference Worker and local D1/Durable Object setup sufficient to run
  the real Wallet lifecycle;
- protocol vectors, intended-behaviour contracts, Wallet package tests, SDK
  documentation under `docs/`, `examples/seams-auth-menu`, and
  `examples/self-host-cloudflare-worker`;
- credential-free validation workflows and npm release workflows using the
  registry's trusted publishing mechanism rather than a checked-in token.

The public repository does not own Console, Admin, billing, production or
staging configuration, provider credentials, deployment topology, or private
operational docs. It does not publish Rust crates to crates.io. The npm package
artifacts are its release boundary.

The public repository owns the signer schema because it is part of the Wallet
runtime contract. The private repository owns applying those versioned
migrations to real deployments.

The local reference runtime exercises the same public handlers, storage schema,
and Wasm assets used by the private deployment. It uses explicit development
adapters and contains no Console, billing, sponsorship, private environment,
production secret, account-specific binding, or operational configuration.
Normal restarts preserve its local signer and Wallet state. Reset is a separate,
explicit command.

Documentation follows the same boundary. Wallet API, protocol, local-runtime,
and public example documents are extracted from the current hosted docs tree
into `seams-wallet/docs`. The `apps/docs` application remains private with
Console, Admin, product, deployment, staging, production, provider, topology,
and operational documents. Moved Wallet documents have one canonical public
copy; the private docs application links to that copy instead of retaining a
second editable version. A public document may link to a generic interface and
must disclose no private hostname, environment variable, secret, binding,
provider account, or deployment procedure.

## Dependency Rules

1. `@seams/wallet` and `@seams/wallet-server` import no Console package or
   Console source.
2. `console-shared-ts` contains no wallet, chain, signing, sponsorship, or MPC
   vocabulary.
3. `console-server-ts` has no dependency on `@seams/wallet`,
   `@seams/wallet-server`, Wallet Console, signer Wasm, or signer migrations.
4. `wallet-console-shared-ts` owns wallet scope, event, policy, and UI/server
   vocabulary shared by the Wallet Console application and backend.
5. `wallet-console-server-ts` may depend on `console-server-ts`, both shared
   Console packages, and supported public exports from
   `@seams/wallet-server`.
6. `apps/seams-console` is the static frontend composition. Core UI files cannot
   import `@seams/wallet` or Wallet product files.
7. `platform-admin-server-ts` and `apps/seams-admin` import neither customer
   Console product modules nor customer session authorization.
8. The Wallet Gateway serves wallet runtime APIs. The Console Worker serves
   `/console/*`. The Admin Worker serves `/admin/*`.
9. The Console Worker receives no signer D1, threshold Durable Object, signer
   Wasm, key-encryption-key, or MPC participant binding.
10. The Wallet Gateway receives no Console D1 binding. Hosted API-key,
    policy/sponsorship, and usage integration crosses a narrow internal service
    binding owned by the private Wallet Console deployment.
11. Cross-package integration uses exported, typed contracts. Source-path aliases,
    wildcard internals, and workspace-only imports are forbidden at the final
    boundary gate.
12. The private deployment consumes only exact-pinned npm packages and their
    prebuilt generic artifacts. It does not compile public Rust/Wasm sources or
    resolve a public-repository path at build or deploy time.
13. Rust crates in the public repository are build inputs, not registry
    products. `publish = false` is the default and no crates.io release gate is
    part of Refactor 105.
14. Console and Wallet-system deployment generation are separate write
    authorities. No command emits, applies, or rotates both secret/variable
    inventories.
15. Console deployment credentials can write only Console Pages, Worker, D1,
    provider, and session configuration. Wallet-system credentials can write
    only Wallet Gateway/Runtime, hosted Wallet, signer, Router A/B, relayer, and
    Wallet-network configuration.
16. Cross-pipeline configuration is a read-only, non-secret handoff containing
    public origins, network names, service binding names, and deployed artifact
    versions. A complete GitHub secret inventory never crosses this boundary.

## Authentication Boundary

Customer Console authentication is a Console capability. The current
`console_session_v1` credential is already semantically distinct from Wallet
authorization. Refactor 105 moves its remaining interface, provider exchange,
cookie, secret, route, and Worker ownership out of Wallet infrastructure.

Target flow:

```text
Browser
  -> /console/auth/google or /console/auth/github
  -> Console Worker validates the provider response
  -> Console Worker issues a Console session
  -> /console/* authorizes organization and project access
```

Requirements:

- use a Console-specific issuer, audience, cookie name, signing key, and expiry;
- internalize the existing Console session parser, issuer, and adapter contract
  in `console-server-ts` without changing its authority semantics;
- move Google/GitHub Console exchange routes away from the combined Gateway;
- replace the dashboard's generic `/session/exchange` dependency with exact
  `/console/auth/*` endpoints owned by the Console Worker;
- keep identity claims minimal: account user ID plus Console authorization lookup
  identifiers;
- load current role, permissions, and project access at the Console boundary;
- make organization switching a Console session operation;
- remove `platformSupport` when Refactor 99B moves the last operator route;
- invalidate the former shared Console cookie during cutover, then delete the
  request-boundary compatibility parser.

A Console session identifies a customer Console account and selects its live
organization authorization. An opaque Wallet Session authorizes bounded
operations for one wallet after owner proof. Neither credential can authorize
the other surface, and no identity correlation between them is required.

## Server Composition

Replace the broad `ConsoleRouterOptions` optional service bag with exact
composition functions:

```ts
createConsoleCoreRouter({
  auth,
  organizations,
  memberships,
  accounts,
  apiCredentials,
  audit,
  billing,
  email,
  webhooks,
});

createWalletConsoleRouter({
  core,
  walletInventory,
  walletPolicies,
  sponsorship,
  walletApprovals,
  keyExports,
  walletUsage,
});
```

The exact input types must require every service needed by that composition.
Use separate local-development builders for explicit in-memory or capture
providers. Production builders cannot represent a partially configured router.

The core router owns common request parsing, Console authentication, tenant
authorization, and response formatting. Wallet routes are declared and
authorized in `wallet-console-server-ts` and mounted once by the Wallet Console
composition root.

## Removing The `cloud-host` Dependency From Console Core

The `@seams/wallet-server/cloud-host` entrypoint remains a supported Wallet
Console integration surface. Generic Console modules stop consuming it for
incidental utilities.

Move each dependency according to its ownership:

| Current import                                         | Target                                            |
| ------------------------------------------------------ | ------------------------------------------------- |
| `SessionAdapter` and session claims                    | Console-owned session contract and implementation |
| D1 structural types and SQL result parsing             | Console-owned D1 boundary module                  |
| logger types and normalization                         | Console-owned minimal logger contract             |
| HTTP request/response helpers                          | Console router transport module                   |
| random IDs and base64url                               | small Console-owned Web Crypto utilities          |
| string and request normalization                       | parse once in Console request/storage boundaries  |
| wallet IDs, signing routes, wallet stores, signer Wasm | Wallet Console package or Wallet Gateway          |
| wallet host composition primitives                     | Wallet Console composition root only              |

Do not create a third public utility package. Small platform adapters belong to
the product that owns their persistence and request boundary.

## Data And Migration Boundary

The existing `seams-console` and `seams-signer` database split remains.

The August 17 clean-slate cutover replaced the prior migration ledgers with one
canonical baseline per database. The current result contains 49 Console tables
and 52 Wallet runtime tables. The security-critical split is sound:
`seams-console` contains no wallet custody seeds, signer shares, WebAuthn
credentials, opaque Wallet Sessions, or
signing-protocol state. The remaining work is product ownership inside
`seams-console` and removal of the hosted Gateway's direct `CONSOLE_DB` binding.

Classify the Console database further:

```text
Console core tables
  organizations, projects, environments
  memberships, invitations, permissions
  account profiles
  api credential records
  audit and evidence
  webhook transport
  billing ledger, purchases, refunds, invoices
  billing_monthly_active_resources
  email outbox and deliveries

Wallet Console tables and projections
  wallet_index
  key_exports
  wallet policy and runtime snapshots
  sponsorship caps, reservations, pricing, and call records
  wallet-specific approval payloads

Signer database
  wallet custody, signers, authenticators, sessions
  recovery and registration state
  key material and signer protocol state
```

Rules:

- the Console Worker cannot bind or query `seams-signer`;
- the Wallet Gateway cannot bind or query `seams-console` after the hosted
  control-plane service binding is live;
- wallet reads in the Console use a non-secret projection or a narrow internal
  wallet administration API;
- wallet mutations cross a typed `WalletControlPort` implemented by an internal
  service binding; the Console never receives signer custody storage;
- Console core billing consumes typed usage events and has no wallet meter logic;
- wallet event producers own idempotency keys and wallet usage dimensions;
- the canonical `0001` files describe the only supported fresh database state;
- Refactor 105 may replace the composed Console baseline with explicit fresh
  Console-core and composed Wallet Console entrypoints in one atomic cutover;
- do not add legacy upgrade paths for the databases deleted by the clean-slate
  reset;
- add a checked-in per-table ownership inventory for the existing Console
  schema, including tables whose columns or constraints mix core and Wallet
  vocabulary;
- every new migration has exactly one owner: Console core, Wallet Console, or
  MPC Admin;
- create fresh-schema migration tests for Console core alone and for the composed
  Wallet Console before repository extraction;
- recreate local and deployed migration ledgers when the R105 schema ownership
  cutover lands.
- resolve signer migrations and generic runtime artifacts from the exact-pinned
  installed `@seams/wallet-server` package in the private monorepo; deployment
  jobs must not reach a public source checkout or run the public Rust build.

Keep Console core and Wallet Console tables in one private `seams-console` D1 by
default. This preserves atomic billing, reservation, and control-plane updates.
Do not add another production database during this refactor. The package,
migration-owner, fresh-schema, and Worker-binding boundaries supply the required
separation; a later physical split requires an observed isolation or scaling
need and an explicit cross-database consistency design.

## Frontend Boundary

Extract `/dashboard/*` from `apps/seams-site` into `apps/seams-console`.

The Console application owns:

- customer Console login;
- the organization/project/environment context;
- dashboard layout, theme, navigation, tables, modals, and error handling;
- account, team, API credential, audit, billing, invoice, and webhook transport
  pages;
- the statically composed Wallet Console route group.

The Console shell uses its own design tokens and theme state. It does not run
inside `SeamsWebProvider`. Wallet pages may import wallet-specific clients where
the route genuinely requires them. Server-side Console APIs remain the default
for administration operations.

Move platform routes according to Refactor 99B before completing the extraction:

- `/dashboard/ops-cockpit` -> `apps/seams-admin`;
- platform observability -> `apps/seams-admin`;
- `/platform/billing` and platform customer operations -> `apps/seams-admin`;
- customer-visible product errors, usage, and audit remain in
  `apps/seams-console`.

## Boundary Closeout And Final Split

Phases 0–6 are the in-monorepo prerequisite for the release and repository
split. Their former detailed checklists are historical context. Before Phase 7,
confirm the following against the current tree:

- Console core is product-neutral and imports no Wallet implementation;
- Wallet Console is the sole customer-control-plane composition that consumes
  supported Wallet server exports;
- Console, Wallet Gateway, and Admin route and credential namespaces are
  distinct, with every unfinished R99B path classified private;
- every Console and signer table, migration, binding, scheduled job, and test
  has one current owner in the reconciled ownership inventory;
- `apps/seams-console` is independently buildable and the main-site dashboard
  extraction has one explicit remaining cutover owner;
- Console core and Wallet Console build and their focused boundary checks pass;
- packed packages resolve without workspace, Git, source-path, or sibling
  checkout fallbacks.

A failed item reopens the corresponding boundary work. Phase 7 and Refactor
105B remain blocked until the closeout is complete. Refactor 99B's
implementation remains private, and R105C separately requires its complete
Admin authority exit.

### Phase 7: Packed-Artifact Gate For The Wallet Packages

The package rename is one breaking change and is already represented by the
canonical source paths. This phase confirms the package boundary without
reopening Wallet behavior or introducing compatibility names:

- [ ] Confirm the final `@seams/wallet` and `@seams/wallet-server` names and
      remove old names, aliases, and forwarding packages.
- [ ] Build and pack both packages, including the required Worker, Rust/Wasm,
      migration, type, and browser artifacts. Keep all crates `publish = false`.
- [ ] Inspect the package contents for private Console, Admin, deployment,
      provider, secret, or source-path material.
- [ ] Start the generic runtime and build the minimal `SeamsAuthMenu` example
      from the packed packages with private packages absent.
- [ ] Build the private composition against those packages with workspace,
      path, Git, and sibling-checkout fallbacks disabled.
- [ ] Confirm private migration and deployment scripts use the prebuilt
      artifacts from `node_modules/@seams/wallet-server` and do not run Cargo or
      `wasm-pack`.

Exit:

- the two renamed npm packages pass clean packed builds and contain no private
  source or configuration;
- the public generic runtime and `SeamsAuthMenu` example work without private
  code or credentials;
- the private composition consumes only exact package versions and prebuilt
  generic artifacts;
- no Rust crate is published to crates.io, and no compatibility package exists;
- the packages contain the runtime artifacts required by private deployment.

### Phase 8: Execute Refactor 105B

Phase 8 starts only after the Phase 7 exit and Refactor 99B's admin paths are
classified. [Refactor 105B](./refactor-105B-github-split.md) is the authoritative
execution plan for extraction, npm release, private rewiring, deletion, and
deployment. The required outcome is:

- [ ] Extract from one recorded source commit using the reconciled ownership
      manifest. Do not hand-copy a moving working tree.
- [ ] Materialize only the new public `seams-tech/seams-wallet` candidate. The
      existing private repository is renamed in place to
      `seams-tech/seams-monorepo`; do not create a second private repository or
      retain a `seams-cloud`/`seams-wallet-sdk` target.
- [ ] Put `@seams/wallet`, `@seams/wallet-server`, Rust/Wasm implementation,
      signer migrations, Wallet-owned tests and type fixtures, SDK/protocol
      docs, public examples, the minimal `SeamsAuthMenu` example, generic local
      runtime, public CI, and npm release workflows in `seams-wallet`.
- [ ] Keep Console/Admin/product/deployment docs, Console and Wallet Console
      tests, staging and production GitHub Actions, environment values,
      Cloudflare topology, secrets, provider configuration, operational
      runbooks, and composed-stack harnesses in `seams-monorepo`.
- [ ] Replace the paired `wallet-core`/`product` environment generation with
      explicit private `console` and `wallet-system` target files, generators,
      protected GitHub environments, update/rotation commands, backup outputs,
      scoped Cloudflare tokens, and deploy workflows.
- [ ] Remove the combined backend deployment sequence and shared
      `DEPLOYMENT_SECRETS_JSON` authority. Each pipeline accepts only its owned
      secret and variable names and cannot write the other pipeline's targets.
- [ ] Create the public repository with its own workspace manifest, lockfile,
      license, README, credential-free validation workflows, and npm release
      workflow. Rust crates remain repository implementation crates with
      `publish = false` and no crates.io workflow.
- [ ] Publish the first `@seams/wallet` and `@seams/wallet-server` npm releases
      from `seams-tech/seams-wallet`, then replace private workspace ranges with
      exact versions and regenerate the private lockfile.
- [ ] Run the private production/staging build and deploy workflows using only
      exact npm versions and prebuilt generic artifacts. Confirm that the
      private repository has no filesystem, Git, or source-build dependency on
      `seams-wallet`.
- [ ] Delete moved source and stale fallbacks only after both repositories work
      independently. Keep the split free of domain, protocol, schema, or route
      behavior changes.

Exit:

- `seams-tech/seams-monorepo` is the private product/deployment monorepo and
  owns all production/staging actions, configuration, topology, and secrets;
- `seams-tech/seams-wallet` is the only new repository and builds/tests/runs the
  real Wallet lifecycle, docs, examples, and generic local runtime independently;
- private deployments use exact-pinned npm packages and prebuilt generic
  artifacts without public source access;
- public validation is credential-free, npm releases use trusted publishing,
  and no Rust crate is published to crates.io;
- Console and Wallet-system configuration can be generated, rotated, and
  deployed independently without overwriting one another.

## Minimal Validation

Run only the checks needed for the moved boundary:

- type-check and build the public Wallet packages from the public candidate;
- start the generic Wallet runtime and build the `SeamsAuthMenu` example once;
- type-check and build Console against the packed, exact-version packages;
- run one focused composed Wallet flow from the private monorepo;
- confirm Console, Wallet Gateway, and Admin reject one another's credentials
  and route namespaces;
- inspect the public tree and npm packages for private configuration or secrets.

Reuse existing Wallet lifecycle, Rust/Wasm, and Console tests where they already
cover changed behavior. Do not add an exhaustive split-specific matrix, proof
format, or duplicate lifecycle suite.

## Risks And Controls

### Accidental framework construction

Use static composition and one concrete Wallet Console module. Add no registry,
discovery protocol, dynamic loader, manifest, or generalized product SDK.

### Generalizing wallet concepts too early

Keep policies, approvals, scopes, event categories, runtime snapshots, and usage
meters wallet-owned until another implemented product reveals the common model.

### Authentication cutover regressions

Deploy the Console session endpoint first, switch the dashboard, invalidate the
old cookie, and delete the Gateway exchange path. Keep any old-cookie parser at
the request boundary for one bounded pre-R105C cutover only, then delete it as a
Refactor 105 closeout condition. R105C starts with no compatibility parser.

### Migration ownership drift

Require one owner for each baseline section and each later migration. Confirm
the core-only and composed schemas can be created before repository movement.

### Cross-plane D1 binding leakage

Treat deployed bindings as part of the security boundary. Tests must inspect the
actual Worker configuration and fail when the Console receives signer D1,
threshold Durable Object, signer Wasm, KEK, or MPC service bindings, or when the
Wallet Gateway receives Console D1. The permitted cross-plane surfaces are the
exact typed service-binding operations named by this plan.

### Premature physical database separation

Keep Console core and Wallet Console in the existing private Console D1 during
this refactor. Package ownership, explicit migration entrypoints, fresh-schema
tests, and Worker bindings establish the extraction boundary. Introduce another
production database only after an observed isolation or scaling requirement and
an explicit consistency design.

### False independence caused by workspace resolution

Package builds inside the monorepo are insufficient. Packed-artifact deletion
builds with workspace links and source aliases disabled are the exit gate.

### Extraction from a moving tree

Extract from one recorded commit through the ownership manifest. Do not
hand-copy a working tree whose public/private ownership is still changing.

### Private configuration leaking through public artifacts

Scan the public tree, npm tarballs, declarations, source maps, Wasm/Worker
artifacts, workflows, and initial commit before publication. Keep all staging
and production actions, environment values, topology, secrets, provider config,
and operational docs in the private monorepo. Public validation and npm release
jobs use no private credentials; the private deploy consumes only exact-pinned
packages and their prebuilt generic artifacts.

### Cross-pipeline secret overwrite

The current paired generation and combined backend deployment give one process
visibility into both Console and Wallet-system configuration. Replace them with
disjoint manifests, commands, GitHub environments, and scoped deployment
credentials. Each apply operation rejects unknown names and cannot address the
other authority's environment.

## Definition Of Done

- Refactors 100-102, 103E, and 107 satisfied the Wallet-boundary stabilization
  gate before Refactor 105 moved or renamed their Wallet-owned paths.
- `@seams/wallet` and `@seams/wallet-server` contain no Console source or
  dependency.
- the public Wallet packages have one canonical name and no aliases or
  compatibility paths;
- `@seams-internal/console-shared` and
  `@seams-internal/console-server` build without Wallet SDK packages present.
- `@seams-internal/console-server` has no `@seams/wallet-server` dependency.
- wallet-specific customer administration lives in
  `@seams-internal/wallet-console-server` and `apps/seams-console/src/products/wallet`.
- the customer Console has its own application, authentication plane, Worker,
  cookie, issuer, audience, and database binding.
- the Console Worker cannot access signer custody or MPC infrastructure.
- the Wallet Gateway cannot access Console D1; its control-plane integration uses
  only the exact private Wallet Console service-binding operations.
- Gateway, Console, and Admin serve mutually exclusive route namespaces.
- every effective Console table, migration, mixed constraint, and scheduled job
  has an explicit Console-core, Wallet Console, MPC Admin, or composition owner.
- a fresh Console-core schema contains only core-owned tables, while a fresh
  composed schema contains exactly Console core plus Wallet Console tables.
- the canonical Console-core and composed Wallet Console baselines create their
  declared schemas from an empty database.
- `apps/seams-site` contains no customer dashboard or Console dependency.
- Console core, Wallet SDK, and Wallet Console composition pass clean packed
  builds without workspace links.
- `seams-tech/seams-monorepo` owns the frontend site, customer Console, admin
  application, hosted services, all production/staging GitHub Actions,
  environment values, topology, secrets, provider configuration, and real
  Cloudflare deployments;
- `seams-tech/seams-wallet` is the only new repository and owns the Wallet
  packages, Rust/Wasm implementation, signer migrations, Wallet tests/docs/
  examples, minimal `SeamsAuthMenu` example, and generic local runtime;
- the public repository builds, tests, and runs the real Wallet lifecycle with
  no private repository access, preserves local state on normal restart, and
  exposes reset as an explicit operation;
- public validation is credential-free, npm releases use trusted publishing,
  and all Rust crates remain `publish = false` with no crates.io release;
- the private repository consumes exact-pinned npm package versions and
  prebuilt generic artifacts without public-repository source access;
- private Console and Wallet-system secret/variable generation, rotation, and
  deployment use separate pipelines with disjoint write credentials;
- the public tree contains no private configuration, credentials, deployment
  workflow, or operational material;
- the cutover changes repository and release wiring only, without another
  domain-boundary redesign.
