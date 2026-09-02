# Refactor 105C: Unified Seams Console

Date created: August 21, 2026

Last reconciled: August 29, 2026 (landed Console operating suite)

Status: planned. This is private `seams-monorepo` work and begins after
Refactors 105B and 99B complete.

## Decision

Deploy one customer Console for Seams Wallet:

```text
production   https://console.seams.sh
staging      https://staging.console.seams.sh
```

The private `seams-monorepo` owns the Console application, Console Worker,
customer data, Wallet Console composition, deployment topology, provider
configuration, environment values, secrets, and all staging/production
workflows. It consumes exact published versions of `@seams/wallet` and
`@seams/wallet-server` and deploys their prebuilt generic artifacts.

The public `seams-wallet` repository owns no Console route, Console session,
customer database, private service binding, or deployment configuration.
Refactor 105C moves no additional source into the public repository.

R105C composes Wallet only. Satyr Ecommerce Agents and any other future product
remain private, but they receive no placeholder route, entitlement, or generic
plugin framework in this refactor. Add a product when it has a concrete
operating path.

Production testnet and mainnet are Wallet networks inside the production
Console. They do not receive separate customer login domains. Staging has its
own Console origin, session authority, database, provider registrations, and
Wallet testnet service.

Keep the hosted Wallet signing runtime at `sign.seams.sh` and its existing
environment-specific origins. The Console receives no signer storage, custody
secret, signer Wasm, key-encryption key, Wallet Session bearer, or threshold
participant credential.

Keep internal MPC administration at `admin.seams.sh` under Refactor 99B. The
customer Console contains no platform-operator route or credential.

## Prerequisites

1. [Refactor 105B](./refactor-105B-github-split.md) is complete:
   `seams-wallet` is public, both npm packages are published, and
   `seams-monorepo` builds and deploys from exact package versions without a
   public source checkout.
2. [Refactor 99B](./refactor-99B-MPC-control-plane.md) is complete:
   `admin.seams.sh`, operator authentication, MPC configuration, telemetry,
   and operator audit have independent private ownership.
3. [Refactor 105](./refactor-105-split-console.md) has removed the Wallet
   Gateway's Console authority and established the product-neutral Console core
   plus explicit Wallet Console composition.

Repository extraction, Admin separation, and this domain cutover remain
separate changes. R105C does not begin while any prerequisite still has mixed
ownership.

## Environment Model

Keep these axes distinct:

```text
DeploymentStage       = staging | production
ConsoleEnvironmentKey = dev | staging | prod
WalletNetwork         = testnet | mainnet
```

- `DeploymentStage` selects a hosted infrastructure trust plane.
- `ConsoleEnvironmentKey` identifies the customer's Console environment.
- `WalletNetwork` selects a Wallet network within that environment.

The supported mapping is:

| Console environment | Deployment | Wallet networks |
| --- | --- | --- |
| `dev` | local | local testnet |
| `staging` | staging | staging testnet |
| `prod` | production | production testnet and mainnet |

`ConsoleEnvironment` remains the product-neutral customer record with required
organization, project, and environment identity. Console D1 owns a durable
`WalletEnvironmentBinding` that connects that exact environment and network to
a server-owned Wallet service target.

Private deployment configuration owns the hosted service targets: deployment
stage, Wallet network, runtime environment ID, exact service bindings, and the
deployed Wallet runtime version. The private service binding is the capability;
no Wallet-system secret is copied into Console configuration. Customer
organization, project, and environment IDs do not belong in deployment
configuration.

The browser may request an authenticated Console environment ID and Wallet
network. The server verifies the customer scope and resolves the configured
target. The browser never supplies a service URL, Cloudflare binding name,
credential, deployment target, or origin override.

## Product And Authorization Ownership

Console core owns:

- customer identity and Console sessions;
- organizations, projects, Console environments, membership, and IAM;
- the durable `wallet` product entitlement;
- billing accounts, audit transport, webhooks, email, and the application
  shell.

Wallet Console owns:

- Wallet routes, resources, permissions, policies, and API clients;
- Wallet environment bindings and Wallet control-plane projections;
- Wallet-specific events, usage dimensions, and customer copy.

Every Wallet operation requires live membership, an active `wallet`
entitlement, the exact organization/project/environment, the selected Wallet
network, the Wallet permission for the action, and the target resource. Missing
or conflicting scope fails closed. Navigation reflects this server decision;
it does not grant authority.

The initial entitlement migration grants `wallet` only to projects whose
existing Wallet ownership is unambiguous. Resolve ambiguous projects before
cutover. Future products extend the entitlement union and schema through their
own plans.

## Canonical Topology

```text
seams.sh
  company site and hosted examples

docs.seams.sh
  hosted documentation application

console.seams.sh
  production Console application and Worker
  production testnet and mainnet Wallet administration

staging.console.seams.sh
  staging Console application and Worker
  staging testnet Wallet administration

sign.seams.sh and environment variants
  hosted Wallet iframe, browser storage, and signer runtime

api.seams.sh and environment variants
  Wallet Gateway runtime APIs

admin.seams.sh
  internal MPC and platform operations
```

The Console application owns `/dashboard/*`. The same-origin Console Worker
owns `/console/*`, `/healthz`, and `/readyz`. Wallet Gateway, hosted Wallet,
Console, and Admin keep separate route and credential authorities.

## Source And Route Ownership

Keep direct static composition in private source:

```text
apps/seams-console/
  src/core/
  src/products/wallet/
  src/app/

packages/console-shared-ts/
packages/console-server-ts/
packages/wallet-console-shared-ts/
packages/wallet-console-server-ts/
deployment/
```

Console core imports no Wallet implementation, SDK, signer type, or runtime
credential. The Wallet module may import supported Console-core contracts and
its own Wallet contracts. `app/` composes the core and Wallet routes directly.
Add no registry, dynamic loader, product manifest, or generalized product SDK.

Use these route owners:

```text
/dashboard/overview
/dashboard/wallet/*
/dashboard/team/*
/dashboard/billing/*
/dashboard/audit/*
/dashboard/settings/*

/console/auth/*
/console/session
/console/organizations/*
/console/projects/*
/console/environments/*
/console/wallet/*
```

Keep existing product-neutral routes under `/console/*`; do not introduce a
`/console/core/*` rename. Move Wallet pages and APIs under their explicit
Wallet namespaces, then delete the old route literals.

## Deployment Contract

Console deployment uses a dedicated private target source:

```text
deployment/console/targets.json
deployment/wallet-system/targets.json
```

`deployment/console/targets.json` is the single human-edited source for Console
topology. Each hosted stage declares:

- the site, docs, and Console origins;
- the Console Pages project, Worker name, routes, and readiness routes;
- one Console D1 binding, name, and exact database ID;
- the Console issuer, audience, `__Host-seams-console` cookie, and session
  secret reference;
- Google and GitHub client-ID/secret references and exact callback paths;
- the allowed Wallet service-binding handoff for each network in that stage.

Production declares exact testnet and mainnet targets. Staging declares only
its staging testnet target. Local development uses a separate local builder and
cannot construct a hosted target.

Secret values remain in the private secret store. Generated deployment output
must not infer a Console hostname from a Wallet Gateway hostname. Delete
`consoleOriginFor(gatewayOrigin)` and any equivalent substitution once the
explicit site Console origin is in use.

`deployment/wallet-system/targets.json` is owned by the independent Wallet
system pipeline. It contains Wallet Gateway/Runtime, hosted Wallet Pages,
signer D1, Router A/B workers and role D1s, Wallet origins and networks,
relayer configuration, protocol keys, root shares, ceremony material, and
signing-session configuration. The Console generator cannot read or write its
secret values.

The Console pipeline consumes one parsed, read-only handoff per Wallet network:
network name, public origin where required, exact service binding name, runtime
environment identity, and deployed artifact/runtime version. The handoff
contains no secret. The Console-to-Wallet control port uses the private service
binding itself as the deployment capability; Wallet cryptographic or runtime
secrets are never copied into a Console environment.

Retire the current paired generation model:

- replace the generic `product:deploy:env-*` commands with
  `console:deploy:env-*` commands that emit and apply only Console values;
- keep `wallet-system:deploy:env-*` commands for Wallet infrastructure only;
- use separate manifest schemas, backup files, generation IDs, protected
  GitHub environments, Cloudflare tokens, rotation commands, and deployment
  workflows;
- remove any combined prepare/rotate command and any apply process that can
  receive both secret inventories;
- preserve site/docs-only deployment values under their private site/docs
  owner; they do not enter the Wallet-system pipeline.

Console uses the protected GitHub environments `staging-console` and
`production-console`. Wallet-system environments remain lane/role-specific,
such as `<lane>-gateway`, `<lane>-mpc-router`, `<lane>-deriver-a`,
`<lane>-deriver-b`, and `<lane>-signing-worker`. No environment is shared by
both pipelines.

Console rotation cannot generate Router A/B identities, root shares, ceremony
keys, signing-session material, relayer keys, or Wallet service credentials.
Wallet-system rotation cannot write Console D1 IDs, session/OAuth/email/webhook/
billing secrets, Console routes, or Console Pages/Worker configuration.

Console sessions use `Secure`, `HttpOnly`, host-only `__Host-` cookies with
`Path=/` and no `Domain`. Production and staging use distinct issuers, secrets,
provider registrations, and hosts. R105C requires fresh login on the canonical
host and introduces no old-cookie parser or cross-origin session exchange.

## Data Migration And Cutover

Production currently has testnet and mainnet lane-owned Console authorities.
Both are sources for one canonical production Console D1. Staging moves to its
own canonical staging Console D1 first.

For each stage:

1. Create the canonical Console deployment and database while old customer
   routes remain active.
2. Snapshot the source Console data. If a source is empty, record that result
   and skip its copy.
3. Map organization, project, environment, identity, and resource IDs into the
   canonical graph. Resolve collisions explicitly; do not choose a lane by
   precedence.
4. Add Wallet entitlements and durable environment/network bindings.
5. Deploy the canonical Console read-only and confirm login configuration,
   route ownership, and Wallet target resolution.
6. Enter a short maintenance window, stop source writes and old callback/link
   issuance, apply the final data delta, and switch provider callbacks, links,
   routes, and DNS.
7. Enable canonical writes, require fresh login, and run the stage's operating
   flow.
8. Remove old routes, sessions, providers, D1 bindings, and obsolete topology
   after the agreed rollback window.

Do staging before production. Production cutover covers both source lanes in
one maintenance window so only one authority accepts customer writes. Do not
add dual-write logic or a compatibility application on an old host.

Before the canonical database accepts writes, rollback restores the previous
routes and source authorities. After canonical writes begin, keep the canonical
database, freeze writes if necessary, and redeploy the previous application
version against it. Do not route new canonical records back into a lane-owned
database.

## Implementation Phases

### Phase 0: Confirm Prerequisites And Current Owners

- [ ] Confirm the R105B exact-package boundary and R99B Admin boundary.
- [ ] Identify the current Console routes, databases, session/provider
      authorities, generated links, and deployment targets that must move.
- [ ] Classify the current paired generator inputs and outputs, GitHub
      environments, Cloudflare tokens, and every secret/variable name as
      Console, Wallet-system, or site/docs.
- [ ] Confirm ownership of both production lane data sets and staging data.
- [ ] Record the landed Refactor 117 `pnpm test:console` suite as the private
      operating baseline; update that suite rather than creating another
      Console browser harness.

Exit: every current authority has one canonical destination.

### Phase 1: Implement The Private Authority Model

- [ ] Add the stage/environment/network types and boundary parsers.
- [ ] Add the Wallet entitlement and environment-binding schema changes.
- [ ] Compose only the Wallet product and remove inactive product placeholders.
- [ ] Add the site-level Console deployment configuration and explicit Wallet
      service targets.
- [ ] Add the Console-only target file, generator, GitHub environments,
      update/rotation commands, backup output, scoped Cloudflare token, and
      deploy workflow. Confirm the Wallet-system equivalents have disjoint
      inputs and write targets.
- [ ] Replace paired generation metadata with independent Console and
      Wallet-system generations and a non-secret Wallet service handoff.
- [ ] Replace derived Console origins with the configured Console origin.

Exit: invalid stage/environment/network combinations are rejected and the
private deployment has one explicit Console authority per stage.

### Phase 2: Move Staging

- [ ] Provision the staging Pages project, Worker, D1, session authority,
      provider registrations, and staging testnet service target.
- [ ] Generate and apply staging Console values through the Console pipeline
      only; consume the staged Wallet-system handoff without invoking or
      rotating the Wallet-system pipeline.
- [ ] Migrate staging data, switch the canonical origin, and require fresh
      login.
- [ ] Complete one staging flow covering organization/project/environment
      selection and a Wallet administration operation.
- [ ] Update `pnpm test:console` for the canonical same-origin Console routes
      and run its existing five operating paths against the private composed
      manager.

Exit: staging uses only `staging.console.seams.sh` and its exact testnet target.

### Phase 3: Move Production

- [ ] Provision the production Console and exact testnet/mainnet service
      targets.
- [ ] Generate and apply production Console values through the Console pipeline
      only; preserve the deployed Wallet-system generations for both networks.
- [ ] Merge the production lane-owned Console data into the canonical
      production D1 and create the Wallet entitlements/bindings.
- [ ] Cut over provider callbacks, generated links, routes, DNS, and sessions in
      the order described above.
- [ ] Confirm testnet and mainnet administration through the same production
      Console session.

Exit: `console.seams.sh` is the only production Console authority.

### Phase 4: Remove The Old Topology

- [ ] Remove the Console bundle and `/dashboard/*` routing from `seams.sh`.
- [ ] Remove old lane Console routes, D1/session/provider bindings, derived
      origins, environment fallbacks, and obsolete workflow inputs.
- [ ] Delete the paired `wallet-core`/`product` generator path, combined
      rotation/verification commands, and the Console component in the combined
      backend deployment sequence.
- [ ] Delete inactive product placeholders and compatibility code.

Exit: production and staging each have one Console authority and all R105C
source, data, configuration, and deployment remain private.

## Focused Verification

Keep verification proportional to the cutover:

- type-check and build the Console and its four Console packages;
- use the existing Refactor 117 `pnpm test:console` suite as the Console
  browser authority, updating its Caddy/origin assumptions as R105C removes the
  main-site mount;
- complete the staging operating flow before production;
- confirm production testnet and mainnet resolve through one authenticated
  Console session;
- confirm old Console hosts/cookies and cross-plane credentials are rejected;
- confirm a Console environment update has no Wallet-system write target and a
  Wallet-system update has no Console write target;
- run one hosted Wallet registration and signing flow to ensure the
  `sign.seams.sh` boundary is unchanged.

Do not add an exhaustive new matrix, duplicate lifecycle suite, proof format,
or source-text guard for this refactor.

## Risks And Controls

### Shared Console blast radius

Keep the Console first-party, use a strict CSP, authorize Wallet operations on
the server, and route custody-sensitive work through `sign.seams.sh`. A future
product needing a distinct trust boundary receives a separate origin and plan.

### Environment confusion

Resolve Wallet routing only from server-owned environment bindings. Browser
state can request a network but cannot choose infrastructure or credentials.

### Migration conflicts

Treat testnet and mainnet Console data as two sources with one destination.
Stop the cutover on ambiguous identities, grants, or resource ownership and
resolve them explicitly.

### Cross-plane authority leakage

The Console receives only Console D1, Console providers, and the narrow Wallet
control bindings. Wallet Gateway receives no Console D1. Their generators,
GitHub environments, Cloudflare tokens, secret inventories, and deployment
workflows are disjoint. Admin and signer credentials remain unusable on Console
routes.

### Premature product framework

Ship one static Wallet composition. Add Satyr Ecommerce Agents through a later
private product plan once its routes, resources, entitlements, and operating
path exist.

## Non-Goals

- implementing Satyr Ecommerce Agents or another product;
- creating disabled product placeholders or a product registry;
- moving Console, deployment, or customer data into `seams-wallet`;
- changing Wallet signing, custody, recovery, export, or device-link behavior;
- renaming `sign.seams.sh` or changing its iframe/RP-ID contract;
- combining customer Console and MPC Admin;
- adding parent-domain cookies, old-cookie parsing, cross-origin session copy,
  or dual-write migration;
- splitting Console core and Wallet Console into separate production databases
  without an observed need;
- publishing Rust crates or changing the package ownership defined by R105B.

## Definition Of Done

- private `seams-monorepo` owns Console, Wallet Console composition, future
  private product work, deployment topology, and customer data;
- public `seams-wallet` supplies only generic Wallet artifacts through exact
  npm package versions;
- production and staging use only `console.seams.sh` and
  `staging.console.seams.sh`, respectively;
- production has one Console D1 and session authority across Wallet testnet and
  mainnet; staging has an independent Console D1 and session authority;
- Wallet entitlement and environment/network binding are server-owned and
  checked for each Wallet operation;
- Console core contains no Wallet implementation or runtime credential;
- the Console application and Console API are same-origin;
- `seams.sh` contains no customer Console bundle or dashboard route;
- Console, Wallet Gateway, hosted Wallet, and Admin keep separate credentials,
  bindings, data, and routes;
- Console and Wallet-system secrets and environment variables are generated,
  updated, rotated, and deployed through independent pipelines with disjoint
  write credentials;
- Console consumes only a non-secret Wallet service handoff and cannot
  overwrite Wallet-system configuration;
- the existing five-test `pnpm test:console` operating suite targets the
  canonical Console topology and runs from the private composed manager;
- old lane Console authorities, derived origins, inactive product placeholders,
  and compatibility paths are deleted.
