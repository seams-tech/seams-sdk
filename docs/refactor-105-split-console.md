# Refactor 105: Product-Neutral Console Boundary

Date created: August 11, 2026

Last reconciled: August 17, 2026 (D1 ownership and deployment-binding audit)

Status: Planned; implementation is gated on the Wallet-boundary stabilization
criteria below.

Implementation gate: begin after Refactors 100-103, 103B, and 107 are complete
and stabilized. Refactor 130A is part of the implementation baseline.

## Decision

Make the Seams Console an independently buildable customer control plane with a
product-neutral core. Move wallet-specific Console behavior behind an explicit
Wallet Console integration. Keep the Wallet SDK and signer runtime independent
of every Console package.

Rename the public Wallet packages during this refactor:

```text
@seams/sdk        -> @seams/wallet
@seams/sdk-server -> @seams/wallet-server
```

After the boundary and rename pass, split the monorepo into two repositories:

- a private Seams application repository containing the frontend site, customer
  Console, admin application, hosted services, and real Cloudflare deployments;
- a public `seams-wallet` repository containing the Wallet implementation and
  enough reference infrastructure to build, test, and run it locally.

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
Console depends on both. A future Seams Access product can compose the same
Console core with Access-specific services without inheriting wallet signing,
custody, recovery, or chain dependencies.

## Implementation Prerequisite: Wallet-Boundary Stabilization

Refactor 105 code movement starts only after these active Wallet refactors are
merged into the target branch and stabilized:

- [Refactor 100](./refactor-100-passkey-account-refactor.md) owns passkey account
  custody, account identity, threshold sessions, and browser Wallet state;
- [Refactor 101](./refactor-101-wallet-execution-lanes.md) owns wallet-key
  identity and execution-lane domain types;
- [Refactor 102](./refactor-102-rotatable-signing-lanes.md) owns signing-lane
  storage, rotation protocols, recipient packages, and session bindings;
- [Refactor 103](./refactor-103-device-linking.md) owns public Wallet APIs,
  React and iframe flows, Gateway routes, D1 state, linked-device enrollment,
  and the Phase 8 canonical owner-credential cutover;
- [Refactor 103B](./refactor-103B-device-link-metadata.md) owns the dependent
  canonical linked-device metadata projection and deletion of the temporary
  human-device metadata path;
- [Refactor 107](./refactor-107.md) owns the deletion of Wallet AppSessions,
  server-internal `VerifiedOwnerProof`, and opaque D1-backed Wallet Sessions.

These plans change the files, routes, stores, migrations, and exported types that
Refactor 105 must classify. Parallel package movement or package renaming would
create avoidable merge conflicts and a stale ownership inventory.

[Refactor 130A](./refactor-130A-email-recovery-cleanup.md) has landed. Its
deletion of the legacy inbound-email recovery system, routes, stores, browser
state, and Wasm bindings is part of the Refactor 105 starting tree. Do not
inventory or recreate those deleted paths.

The prerequisite is satisfied when:

1. Refactors 100-103 and 107 are merged into the branch that will receive
   Refactor 105.
2. Refactor 103 Phase 8 and the dependent Refactor 103B canonical metadata
   projection have replaced the temporary human linked-session authority and
   metadata paths.
3. Refactor 107 has passed its final `pnpm check` gate and its plan is reconciled
   with the landed opaque-session implementation.
4. Their intended-behaviour contracts, type fixtures, vectors, migrations, and
   targeted package builds pass.
5. Temporary lifecycle paths and obsolete fixtures from their implementation
   have been deleted.
6. No active branch is still restructuring the shared Wallet domain, Wallet
   routes, signer persistence, public SDK surface, or browser Wallet state that
   Refactor 105 will move or rename.

Documentation decisions may land earlier. Detailed inventories, file movement,
package creation, and import renaming wait for this gate.

### Prepared Kickoff Runway

The pre-gate architecture review is complete. Refactor 107 is reconciled and its
final repository gate passed. Refactor 130A and the clean-slate D1 consolidation
are part of the starting tree. The Console and signer databases each have one
canonical `0001` baseline; the current baselines contain 49 Console tables and
52 signer tables.

Refactor 105 remains a no-go while Refactor 103 is changing linked-owner Wallet
Sessions, custody handles, canonical owner lifecycle, revocation, or browser
Wallet state. Refactor 103B also remains open until its metadata projection is
proven through that canonical lifecycle.

Refactors 100-102 still contain open validation or follow-up items in their
plans. Reconcile those items at the gate: complete anything that can still
change an R105-owned path, and explicitly defer unrelated follow-ups. Do not
carry an ambiguous "active" prerequisite into the ownership freeze.

The gate classification is:

- Refactor 100's clean lifecycle rerun and zero-Deriver ordinary Ed25519
  signing evidence are blockers because they exercise public Wallet runtime and
  browser state. The development OTP reset is operational clean-state work.
  Compromise-triggered lane refresh remains a deferred lane-protocol follow-up.
- Refactor 101's intended-behavior, source-guard, and wallet-iframe gate is a
  blocker because it owns normal-signing resolution and browser lane hydration.
- Refactor 102's Rust/TypeScript Ed25519 owner-source vector reconciliation is a
  blocker because it can change shared encoders and lane bindings. Wallet-key
  root refresh remains deferred, and public device bootstrap belongs to
  Refactor 103.

Immediately after those gates close:

1. freeze the stabilized route, service, table, migration, job, binding, UI, and
   test ownership inventory;
2. add the narrow Console-core Wallet-import boundary check with a temporary,
   explicit allowlist;
3. create `wallet-console-shared-ts` and move Wallet-specific scopes, policies,
   events, meters, sponsorship contracts, and webhook categories out of
   `console-shared-ts`;
4. add Console-owned D1, logger, HTTP, random-ID, encoding, normalization, and
   Console-session boundary modules;
5. replace the broad optional Console router service bag with exact core and
   Wallet Console compositions;
6. create `wallet-console-server-ts`, move the clearly Wallet-owned services,
   and remove the Wallet server dependency from Console core;
7. run the packed-artifact boundary proof before relocating authentication,
   deployments, dashboard code, schemas, or public package names.

The public Wallet package rename remains one atomic late phase. Do not introduce
forwarding packages, aliases, or dual import paths while preparing it.

During implementation, use narrow static checks and focused tests while editing.
Run each phase's full build once after its source changes are complete. Do not
start, stop, rebuild beneath, or leave behind the developer's manual-testing
services unless the developer explicitly asks for runtime verification.

Refactors 113 and 114 are proposed Wallet follow-ups. Refactor 130B is deferred.
They do not block Refactor 105 unless they enter implementation before this gate
passes; if that happens, finish their changes to shared Wallet paths before the
ownership inventory and package movement begin.

## Why This Refactor Exists

The repository already has a useful first boundary:

- `@seams/sdk` contains the browser wallet runtime and has no Console dependency.
- `@seams/sdk-server` contains the signer runtime and exposes a curated
  `cloud-host` composition surface.
- `@seams-internal/console-server` and `@seams-internal/console-shared` are
  separate workspace packages.
- `seams-console` and `seams-signer` are separate D1 databases.

The remaining coupling prevents the Console from standing on its own:

- `@seams-internal/console-server` directly depends on `@seams/sdk-server`.
- Console modules import wallet-owned D1, logger, random-ID, HTTP, session, and
  Router API types from `@seams/sdk-server/cloud-host`.
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
for this work. It moved Console implementation out of `@seams/sdk-server`, made
the signer package free of Console imports, split signer and Console migrations,
and introduced supported composition exports.

Refactor 105 starts from that result. It does not reopen signer cryptography,
wallet ceremonies, or signer storage.

### `refactor-99-console.md`

[Refactor 99 Console](./refactor-99-console.md) is directly relevant. Its
organization, billing, email, package-boundary, and eventual repository-split
decisions remain authoritative where they describe implemented behavior.

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
- the physical repository split in Refactor 99 Phase 6 remains paused until the
  deletion builds and deployment boundaries in this plan pass.

Refactor 99's placement of the whole `apps/seams-site` application in the private
repository is confirmed. Refactor 105 additionally extracts the customer
dashboard into `apps/seams-console` inside that same private repository. The
marketing site and hosted Wallet demos remain private. The public Wallet
repository keeps SDK documentation, tests, local reference examples, and a
local reference runtime.

Refactor 99 currently says not to rename public SDK packages during extraction.
This plan preserves the underlying safety rule by completing the rename in a
separate atomic phase before Git-history extraction. The extraction change
remains source movement and release wiring only.

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

Refactor 99B should complete its route and authorization movement before this
plan deletes the mixed observability and platform-support paths.

### `refactor-107.md`

[Refactor 107](./refactor-107.md) is the current Wallet authorization baseline.
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

[Refactor 130A](./refactor-130A-email-recovery-cleanup.md) is implemented and
defines the starting tree: legacy inbound-email recovery no longer exists.
[Refactor 113](./refactor-113-recovery-code-reveal-step-up.md) and
[Refactor 114](./refactor-114.md) are proposed Wallet lifecycle work, while
[Refactor 130B](./refactor-130B-email-recovery-v2.md) is deferred. They remain
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
7. Make a future Access Console integration possible without adding an Access
   abstraction, SDK, or product behavior during this refactor.
8. Rename the public packages without forwarding packages, deprecated aliases,
   or parallel legacy import paths.
9. Produce a public Wallet repository that runs its real Wallet lifecycle
   locally while leaving staging and production deployment ownership private.

## Non-goals

- implementing NFC credentials, robot provisioning, or Seams Access;
- designing a generic plugin marketplace or dynamic module loader;
- changing wallet signing, registration, recovery, key custody, or cryptography;
- changing customer organization, RBAC, prepaid billing, or email behavior;
- changing Git history before the boundary, rename, and packed-build gates pass;
- publishing internal Console packages;
- combining the customer Console and MPC admin plane;
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

Use clear domain names for the final package boundary. The Wallet directories
are renamed in the same atomic phase as their package manifests:

```text
apps/
  seams-site/                         # marketing, docs links, wallet demos
  seams-console/                      # customer Console composition
  seams-admin/                        # Refactor 99B MPC operator UI

packages/
  console-shared-ts/                  # product-neutral browser/server contracts
  console-server-ts/                  # product-neutral customer control plane
  wallet-console-shared-ts/           # wallet scopes and browser/server contracts
  wallet-console-server-ts/           # hosted wallet administration integration
  wallet/                             # @seams/wallet; renamed from sdk-web
  wallet-server/                      # @seams/wallet-server; renamed from sdk-server-ts
  platform-admin-server-ts/           # Refactor 99B operator control plane
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
Access product can add another explicit route definition when it exists.

## Final Repository Ownership

The repository destination is fixed.

### Private Seams application repository

Owns:

- `apps/seams-site`, including marketing and hosted Wallet demos;
- `apps/seams-console`;
- `apps/seams-admin` from Refactor 99B;
- `apps/web-server` and hosted Gateway/Worker composition;
- `console-shared-ts` and `console-server-ts`;
- `wallet-console-shared-ts` and `wallet-console-server-ts`;
- `platform-admin-server-ts`;
- Console, billing, sponsorship, webhook, audit, email, and admin migrations;
- production and staging Cloudflare entrypoints, routes, bindings, domains,
  secrets, observability, backup, restore, and operational runbooks;
- production migration orchestration for both private schemas and the installed
  Wallet server package's signer schema.

The private repository exact-pins published `@seams/wallet` and
`@seams/wallet-server` releases. It uses no workspace link, Git dependency,
source-path alias, submodule, or sibling checkout to consume Wallet code.

### Public `seams-wallet` repository

Owns:

- `@seams/wallet`;
- `@seams/wallet-server`;
- Wallet-owned shared code and required Rust/Wasm crates;
- registration, authentication, signing, recovery, Wallet Session, key, lane,
  and linked-device behavior;
- signer storage schemas and migrations;
- Cloudflare-compatible Wallet Worker factories and typed bindings;
- a local reference Worker and local D1/Durable Object setup sufficient to run
  the real Wallet lifecycle;
- protocol vectors, intended-behaviour contracts, package tests, SDK
  documentation, examples, and release workflows.

The public repository owns the signer schema because it is part of the Wallet
runtime contract. The private repository owns applying those versioned
migrations to real deployments.

The local reference runtime exercises the same public handlers, storage schema,
and Wasm assets used by the private deployment. It uses explicit development
adapters and contains no Console, billing, sponsorship, private environment,
production secret, account-specific binding, or operational configuration.
Normal restarts preserve its local signer and Wallet state. Reset is a separate,
explicit command.

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

The current `@seams/sdk-server/cloud-host` entrypoint becomes
`@seams/wallet-server/cloud-host` during the package rename. It remains a
supported Wallet Console integration surface. Generic Console modules stop
consuming it for incidental utilities.

Move each dependency according to its ownership:

| Current import | Target |
| --- | --- |
| `SessionAdapter` and session claims | Console-owned session contract and implementation |
| D1 structural types and SQL result parsing | Console-owned D1 boundary module |
| logger types and normalization | Console-owned minimal logger contract |
| HTTP request/response helpers | Console router transport module |
| random IDs and base64url | small Console-owned Web Crypto utilities |
| string and request normalization | parse once in Console request/storage boundaries |
| wallet IDs, signing routes, wallet stores, signer Wasm | Wallet Console package or Wallet Gateway |
| wallet host composition primitives | Wallet Console composition root only |

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
  email outbox and deliveries

Wallet Console tables and projections
  wallet_index
  key_exports
  wallet policy and runtime snapshots
  sponsorship caps, reservations, pricing, and call records
  wallet-specific approval payloads
  billing_monthly_active_wallets

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

## Implementation Phases

### Phase 0: Reconcile And Classify The Stabilized Wallet Boundary

- [ ] Verify the Refactors 100-103 and 107 implementation prerequisite,
      including the Refactor 103 Phase 8 and Refactor 103B cutovers.
- [ ] Re-read the resulting Wallet lifecycle types, public exports, routes,
      stores, migrations, and composition entrypoints.
- [ ] Treat Refactor 130A's deleted legacy email-recovery paths as absent from
      the baseline; record any later Refactor 113 or 114 implementation that
      landed before this phase.
- [ ] Inventory every Console route, service, table, migration, scheduled job,
      environment binding, UI route, event category, and test.
- [ ] Assign each item to `console-core`, `wallet-console`, `mpc-admin`, or
      `composition`.
- [ ] Record all 49 effective `seams-console` tables in a checked-in ownership
      matrix. Mark `api_keys`, audit/evidence, prepaid reservations, billing
      usage enums, observability, and webhook categories as mixed until their
      product vocabulary is assigned.
- [ ] Record all 52 effective `seams-signer` tables as Wallet runtime ownership
      and verify that the canonical baseline contains no retired App Session,
      authorization-session, or legacy email-recovery tables.
- [ ] Record the current route surfaces for Gateway, Console, and Admin.
- [ ] Record imports from `console-server-ts` to
      `@seams/sdk-server/cloud-host` by domain and symbol.
- [ ] Record the Console Worker's current signer database, Durable Object, Wasm,
      and key-related bindings.
- [ ] Classify the root local commands, `router-ab-dev` runtime, combined local
      Worker, migration scripts, state-preserving startup, and explicit reset
      path between the public Wallet runtime and private composed development.
- [ ] Add one narrow package-boundary check that prevents new Wallet imports in
      declared Console-core folders while the initial allowlist is burned down.

Exit:

- every current item has one owner;
- the inventory describes the stabilized post-Refactor-107 and post-Refactor-130A
  tree;
- disputed modules stay Wallet-owned until a concrete shared invariant exists;
- no prerequisite implementation branch still restructures an owned path.

### Phase 1: Establish Product-Neutral Console Contracts

- [ ] Move Wallet and chain vocabulary out of `console-shared-ts`.
- [ ] Create `wallet-console-shared-ts` for Wallet scope, event, policy, and
      request/response contracts used by both Wallet Console surfaces.
- [ ] Add Console-owned D1, logger, HTTP, random-ID, encoding, and normalization
      boundary modules where generic Console services currently use
      `cloud-host`.
- [ ] Define the Console-owned session parser and issuer port without changing
      the deployed session implementation yet.
- [ ] Split product scope catalogs from generic API credential lifecycle.
- [ ] Split product event catalogs from generic webhook delivery.
- [ ] Split Wallet meters from the billing ledger and account model.
- [ ] Remove Wallet-only `CHECK` catalogs from Console-core storage contracts.
      Keep normalized product identifiers in generic transport rows and validate
      Wallet scope, event, approval, policy, meter, and webhook-category values
      once in Wallet Console request/storage boundaries.
- [ ] Classify tenant-facing observability as Console core or Wallet Console and
      move fleet/platform observability to MPC Admin under Refactor 99B.
- [ ] Require exact core service sets through branch-specific builders instead
      of extending the broad router optional bag.

Exit:

- `console-shared-ts` contains no Wallet, chain, signing, sponsorship, or MPC
  vocabulary;
- generic Console modules import no incidental D1, HTTP, logging, random-ID, or
  session utility from the Wallet server package;
- current hosted behavior remains unchanged through explicit composition.

### Phase 2: Create The Wallet Console Integration

- [ ] Create `packages/wallet-console-server-ts`.
- [ ] Move Wallet inventory, policies, sponsorship, sponsored calls, spend caps,
      runtime snapshots, key exports, Wallet approvals, and Wallet usage modules.
- [ ] Move ownership of `wallet_index`, `key_exports`, `policies`,
      `policy_versions`, `policy_assignments`, `approvals`, `runtime_snapshots`,
      `runtime_snapshot_outbox`, sponsorship pricing/cap/call tables, and
      `billing_monthly_active_wallets` to the Wallet Console package.
- [ ] Decide the mixed billing reservation tables by their current behavior:
      keep a product-neutral reservation mechanism in Console core only if it
      has a non-Wallet caller; otherwise move it with Wallet sponsorship.
- [ ] Move Wallet route definitions, request parsers, policy rules, webhook event
      vocabulary, and billing meters with their domains.
- [ ] Keep supported `@seams/sdk-server/cloud-host` imports inside this package or
      the final composition root until Phase 7 renames the public package.
- [ ] Define a narrow `WalletControlPort` for commands that cross from the
      Console Worker to the Wallet runtime.
- [ ] Define the opposite hosted runtime seam as exact internal service-binding
      operations for API-key validation, policy and sponsorship resolution, and
      idempotent usage-event ingestion. Do not expose the Console database or a
      generic SQL/query endpoint to the Wallet Gateway.
- [ ] Read Wallet lists and status from the Console-owned projection.
- [ ] Route custody-sensitive mutations through the internal Wallet service
      binding.
- [ ] Add `createWalletConsoleRouter` with required Wallet services.
- [ ] Delete moved exports and compatibility aliases from `console-server-ts`.
- [ ] Remove `@seams/sdk-server` from `console-server-ts/package.json` after its
      last core import is gone.

Exit:

- all Wallet Console behavior has one package owner;
- Console core cannot construct Wallet routes;
- Wallet Console can be omitted without optional-service runtime failures;
- `console-server-ts` has no Wallet server dependency.

### Phase 3: Prove The Compile-Time Boundary

- [ ] Pack Console core packages and install them into a temporary workspace with
      no Wallet packages or source aliases.
- [ ] Build the Wallet packages and local reference signer with every Console
      package absent.
- [ ] Start, restart, migrate, and explicitly reset the Wallet-only local
      reference runtime with every Console package absent.
- [ ] Pack and build the Wallet Console composition against released-style
      package artifacts with workspace links disabled.
- [ ] Inspect package tarballs and generated declarations for forbidden imports.
- [ ] Run current intended Wallet behavior contracts.
- [ ] Delete the temporary boundary allowlist after all consumers move.

Exit:

- Console core, Wallet SDK, and composed Wallet Console pass independent clean
  installs and builds;
- deleting either side produces no unresolved source import on the other;
- only the composed Wallet Console depends on both sides.

This is the first major checkpoint. Authentication, frontend, deployment, and
schema cutovers start only after it passes.

### Phase 4: Relocate Console Authentication And Deployment

- [ ] Move the existing Console session interface and implementation into
      Console-owned modules and remove their `SessionAdapter` import from the
      Wallet server package.
- [ ] Move Google and GitHub customer Console authentication from the combined
      Gateway's `/session/exchange` path to exact `/console/auth/*` routes.
- [ ] Change dashboard sign-in, session refresh, organization switching, and
      sign-out to use only the Console Worker.
- [ ] Deploy the Console-only Worker entrypoint with Console-specific session
      secrets and bindings.
- [ ] Deploy the private Wallet Console service-binding operations for API-key
      validation, policy and sponsorship resolution, and idempotent usage-event
      ingestion.
- [ ] Switch the Wallet Gateway to those exact operations and remove its direct
      Console D1 queries.
- [ ] Move Console-owned scheduled email and control-plane jobs out of the
      Gateway's scheduled handler.
- [ ] Remove `CONSOLE_DB` from the Gateway environment type, Wrangler bindings,
      readiness checks, migration orchestration, and deployment documentation.
- [ ] Build the hosted Wallet Gateway with only the exact Wallet Console
      service-binding client and no Console database contract in its runtime
      inputs.
- [ ] Stop serving `/console/*` from the Wallet Gateway.
- [ ] Delete the combined Gateway's Console exchange and Console-session
      construction after the cutover.
- [ ] Coordinate removal of `platformSupport` with Refactor 99B.

Exit:

- a Console session cannot authorize a Wallet runtime route;
- a Wallet session cannot authorize a Console route;
- the Gateway cannot resolve `/console/*`;
- the Console Worker has no signer database or MPC binding;
- the Wallet Gateway has no Console database binding and exposes no generic
  Console query operation;
- the Gateway schedules no Console-owned job.

### Phase 5: Extract The Customer Console Application

- [ ] Create `apps/seams-console` and move dashboard login, shell, core routes,
      styles, and customer Console API clients into it.
- [ ] Keep marketing, hosted Wallet demos, and intended Wallet examples in the
      private `apps/seams-site` application.
- [ ] Remove the customer Console from the site router.
- [ ] Replace dashboard uses of Wallet theme hooks and `SeamsWebProvider` with
      Console-owned theme state and tokens.
- [ ] Create `core/`, `products/wallet/`, and `app/` ownership folders.
- [ ] Move Ops Cockpit, platform observability, and platform customer operations
      according to Refactor 99B.
- [ ] Preserve URLs through deployment routing rather than a second React
      compatibility router.

Exit:

- `apps/seams-site` and `apps/seams-console` build as separate private
  applications;
- the Console core UI builds without a Wallet package import;
- the composed Console still serves the existing customer dashboard URLs.

### Phase 6: Separate Schema And Operational Ownership

- [ ] Complete the checked-in per-table and per-migration ownership inventory,
      including the mixed columns and `CHECK` catalogs in `api_keys`, audit and
      evidence, prepaid reservations, billing usage, observability, and webhook
      tables.
- [ ] Move new Wallet Console migrations and scheduled jobs under the Wallet
      Console package.
- [ ] Treat `0001_console_d1_initial.sql` as the current composed source
      baseline. Replace it atomically when the explicit fresh Console-core and
      composed Wallet Console entrypoints are ready.
- [ ] Add an explicit fresh Console-core schema entrypoint containing only the
      core-owned tables and product-neutral forms of retained mixed tables.
- [ ] Add an explicit composed Wallet Console schema entrypoint containing
      Console core plus Wallet Console tables and Wallet-owned catalogs.
- [ ] Remove Wallet-only constraints from retained Console-core tables and
      validate Wallet values at the Wallet Console request or storage boundary.
- [ ] Validate fresh Console-core and fresh composed creation. Keep these as
      direct migration entrypoints without adding a schema generator, migration
      framework, or legacy upgrade path.
- [ ] Make migration orchestration an explicit responsibility of the private
      deployed composition root.
- [ ] Remove signer migration and signer smoke orchestration from Console-core
      scripts.
- [ ] Resolve signer migrations from the installed Wallet server package in
      staging and production.
- [ ] Verify backup, restore, and readiness checks against their owned stores.

Exit:

- a new Console-core database contains no Wallet tables;
- a composed Wallet Console database contains core plus Wallet product tables;
- both fresh schemas match the checked-in ownership inventory exactly;
- the canonical baselines create only their declared fresh schemas;
- signer migrations remain owned and packaged by the Wallet server package;
- the private deployment applies signer migrations without Wallet source access;
- no migration path silently creates tables owned by another product.

### Phase 7: Rename The Public Wallet Packages And Re-run Boundary Proofs

Perform the rename as one atomic breaking change after the domain boundary is
stable:

- [ ] Rename package `@seams/sdk` to `@seams/wallet`.
- [ ] Rename package `@seams/sdk-server` to `@seams/wallet-server`.
- [ ] Rename `packages/sdk-web` to `packages/wallet` and
      `packages/sdk-server-ts` to `packages/wallet-server`.
- [ ] Update every manifest, import, export map, declaration rewrite, build
      script, test, example, migration resolver, generated artifact, and document.
- [ ] Preserve existing runtime class, protocol, route, and storage names unless
      a separate refactor explicitly owns their redesign.
- [ ] Delete the old package names in the same change. Add no forwarding package,
      alias export, deprecated symbol, or dual import path.
- [ ] Publish or locally pack the first release candidates under the new names.
- [ ] Build the private applications against exact release-candidate versions
      with workspace links and source aliases disabled.
- [ ] Build and run the public local reference Wallet runtime from packed
      packages and packaged signer migrations.
- [ ] Verify a normal Wallet-only runtime restart preserves signer and Wallet
      state, while the explicit reset command deletes only its resolved local
      persistence root.
- [ ] Re-run intended behavior, type fixtures, vectors, fresh migrations, package
      deletion builds, and tarball inspection.
- [ ] Verify Gateway, Console, and Admin route namespace rejection in staging.

Exit:

- the repository contains no `@seams/sdk` or `@seams/sdk-server` package or
  import;
- `@seams/wallet` and `@seams/wallet-server` pass clean packed builds;
- the private hosted composition consumes only exact packed versions;
- the public local runtime exercises registration, unlock, signing, recovery,
  opaque Wallet Sessions, state-preserving restart, explicit reset, and signer
  migrations without private code.

### Phase 8: Split The Repositories

After Phases 0-7 pass, resume Refactor 99 Phase 6 with the ownership fixed in
this plan:

- [ ] Update extraction allowlists for the new package paths, Console
      application, Wallet Console packages, and public local reference runtime.
- [ ] Extract the private Seams application repository with `apps/seams-site`,
      `apps/seams-console`, hosted services, private packages, production
      Cloudflare configuration, and operational assets.
- [ ] Extract the public `seams-wallet` repository with `@seams/wallet`,
      `@seams/wallet-server`, Wallet Rust/Wasm, signer migrations, tests, SDK
      documentation, examples, and local reference infrastructure.
- [ ] Publish the first independent Wallet releases under the new names.
- [ ] Exact-pin those releases in the private repository.
- [ ] Build and deploy the private hosted services to Cloudflare staging without
      filesystem or Git access to the public repository.
- [ ] Clone, install, build, test, and run the public Wallet locally without
      access to the private repository.
- [ ] Perform the history, secret, source-map, license, CI, and staging checks
      from Refactor 99.
- [ ] Cut over repositories without domain behavior, public API, protocol, or
      schema changes in the movement pull request.

## Minimal Validation

Run the narrowest test for each moved boundary. The final phase requires:

```bash
pnpm -C packages/console-shared-ts type-check
pnpm -C packages/console-server-ts type-check
pnpm -C packages/wallet-console-shared-ts type-check
pnpm -C packages/wallet-console-server-ts type-check
pnpm -C packages/wallet type-check
pnpm -C packages/wallet-server type-check
pnpm -C apps/seams-site typecheck
pnpm -C apps/seams-console typecheck

pnpm -C packages/console-server-ts build
pnpm -C packages/wallet-console-server-ts build
pnpm -C packages/wallet build
pnpm -C packages/wallet-server build
pnpm -C apps/seams-site build
pnpm -C apps/seams-console build
```

Add targeted behavioral tests for:

- Console-account sessions, opaque Wallet Sessions, and admin credentials cannot
  authorize one another's routes or operations;
- Gateway rejection of `/console/*` and `/admin/*`;
- Console rejection of wallet runtime and `/admin/*` routes;
- customer organization, membership, project access, API credential, billing,
  email, webhook, and audit behavior after extraction;
- API-key validation, policy and sponsorship resolution, and idempotent usage
  ingestion across the exact Wallet Console service-binding operations;
- deployed binding inspection proving that the Console Worker receives only its
  Console D1 and the Wallet Gateway receives only its signer D1 plus the narrow
  Wallet Console service binding;
- Wallet Console route parity before and after module movement;
- wallet projection reads without signer database access;
- custody-sensitive commands using only the internal wallet control port;
- Console-core fresh schema containing exactly the core-owned tables and composed
  Wallet Console fresh schema containing exactly core plus Wallet-owned tables;
- fresh creation from the canonical Console-core and composed Wallet Console
  baselines;
- effective Wallet signer schema ownership, including absence of the retired App
  Session, authorization-session, and legacy email-recovery tables;
- package deletion builds and packed-artifact installs;
- Wallet-only local startup, state-preserving restart, migration, and explicit
  reset without `console-server-ts`.

The authoritative wallet lifecycle contracts remain `pnpm test:intended`.
Console route and dashboard tests remain responsible for customer control-plane
behavior.

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
the request boundary for one bounded cutover only.

### Migration ownership drift

Require one owner for each baseline section and each later migration. Prove both
fresh schema variants before repository movement.

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

## Definition Of Done

- Refactors 100-103, 103B, and 107 satisfied the Wallet-boundary stabilization
  gate before Refactor 105 moved or renamed their Wallet-owned paths.
- `@seams/wallet` and `@seams/wallet-server` contain no Console source or
  dependency.
- `@seams/sdk` and `@seams/sdk-server` no longer exist as packages, imports,
  aliases, or compatibility paths.
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
- the private Seams application repository owns the frontend site, customer
  Console, admin application, hosted services, and real Cloudflare deployments;
- the public `seams-wallet` repository builds, tests, and runs its real Wallet
  lifecycle locally with no private repository access, preserves local state on
  normal restart, and exposes reset as an explicit operation;
- the private repository consumes exact published Wallet package versions and
  deploys them without public-repository source access;
- Refactor 99's extraction completed as source movement and release wiring,
  without another domain-boundary redesign.
