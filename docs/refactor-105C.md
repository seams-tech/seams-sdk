# Refactor 105C — Unified Seams Console

Date created: August 21, 2026

Last reconciled: August 21, 2026 (unified Wallet, Ecommerce Agents, and CafeOS
Console decision)

Status: planned. Implementation begins after Refactor 105B completes the
repository split. Keep this domain cutover separate from the source-movement
pull request.

## Decision

Deploy one customer control plane for all Seams products:

```text
production   https://console.seams.sh
staging      https://staging.console.seams.sh
```

The Console statically composes three product areas:

```text
Wallet
Ecommerce Agents
CafeOS
```

Console core owns customer identity, organizations, projects, environments,
membership, IAM, billing, audit transport, webhooks, and the application shell.
Each product owns its routes, resources, permissions, API clients, policies,
events, usage meters, and product copy.

Production testnet and mainnet are environments inside the production Console.
They receive no separate top-level Console applications or customer login
domains. Staging has its own Console origin, session authority, database, OAuth
registration, and product services.

Keep the hosted Wallet signing runtime at `https://sign.seams.sh` and its
existing environment-specific origins. The Console receives no signer storage,
signer Wasm, threshold participant, key-encryption-key, wallet custody secret,
or wallet-origin browser storage access.

Keep internal MPC administration at `admin.seams.sh` under Refactor 99B. The
customer Console contains no platform-operator credential or route.

## Product Model

The Console uses one shared-resource hierarchy:

```text
Organization
  -> Project
     -> Environment
        -> Wallet resources
        -> Ecommerce Agent resources
        -> CafeOS resources
```

The hierarchy supplies customer ownership and deployment context. Product
resources remain product-specific:

| Product          | Example resources                                                 |
| ---------------- | ----------------------------------------------------------------- |
| Wallet           | wallets, policies, sponsorship, approvals, signing activity       |
| Ecommerce Agents | agents, commerce connections, mandates, runs, outcomes            |
| CafeOS           | locations, stations, robots, recipes, inventory, operating events |

Cross-product relationships use explicit identifiers and typed server
contracts. For example:

```text
CafeOS station
  -> invokes an Ecommerce Agent mandate
  -> requests one Wallet-authorized payment
  -> records product-specific outcomes in each owning service
```

Every cross-product operation verifies the current organization, project,
environment, product entitlement, initiating principal, exact requested action,
and target resource at its boundary. A resource reference from one product
grants no authority in another.

## Why This Refactor Exists

Refactor 105 established a product-neutral Console core and an explicit Wallet
Console integration. Refactor 105B owns the physical split between the public
Wallet repository and the private Seams application repository.

The hosted frontend still carries transitional assumptions:

- `apps/seams-console` builds separately, then `scripts/deploy-frontend.mjs`
  copies it into the main site under `dashboard-static`;
- customer routes continue to appear under the main `seams.sh` site;
- deployment code derives Console API origins by replacing the `api` label in a
  Wallet Gateway hostname with `console`;
- production testnet and mainnet point at separate lane-owned Console databases
  and session authorities;
- the application has a product switcher, while only Wallet is implemented.

R105C completes the customer-facing control-plane boundary. It gives the
Console its own origin and production authority, moves Console ownership above
individual Wallet network lanes, and defines how implemented products join the
shared shell without creating a plugin framework.

## Relationship To Existing Refactors

### Refactor 86

[Refactor 86](./refactor-86-static-wallet-assets.md) owns the static hosted
Wallet runtime at `sign.seams.sh`, including wallet iframe assets, workers,
WebAuthn delegation, embedding authorization, and version checks. R105C does not
rename that origin or move Wallet runtime assets into the Console.

### Refactor 105

[Refactor 105](./refactor-105-split-console.md) owns the product-neutral Console
core, independent customer authentication, Console Worker, explicit Wallet
Console composition, Console database boundary, and removal of Console routes
from the Wallet Gateway.

R105C preserves those owners and promotes the composed customer Console from a
Wallet-only hosted application to the Seams multi-product control plane. The
Console core stays product-neutral. Wallet, Ecommerce Agents, and CafeOS remain
explicit product modules.

R105's temporary requirement to preserve dashboard URLs through deployment
routing ends at this explicit domain cutover. No React compatibility router is
introduced.

### Refactor 105B

[Refactor 105B](./refactor-105B-github-split.md) owns repository extraction,
publication of the public Wallet packages, and exact-pin consumption by the
private application repository. Its movement pull request contains no R105C
domain or product behavior. R105C starts after that split completes.

### Refactor 99B

Refactor 99B owns platform observability, MPC configuration, fleet incidents,
platform support, operator audit, `admin.seams.sh`, and the Admin Worker. CafeOS
robot-fleet customer resources remain customer product data; signer-fleet and
platform operations remain Admin data. The shared word `fleet` grants no import,
route, session, or database relationship.

## Canonical Topology

```text
seams.sh
  company site and hosted product examples

docs.seams.sh
  documentation

console.seams.sh
  production Console application and Worker
  Wallet, Ecommerce Agents, and CafeOS customer control plane
  production testnet and mainnet environments

staging.console.seams.sh
  staging Console application and Worker
  staging product environments

sign.seams.sh
test.sign.seams.sh
staging.sign.seams.sh
  hosted Wallet iframe, WebAuthn, signer workers, and Wallet browser storage

api.seams.sh
test.api.seams.sh
staging.api.seams.sh
  Wallet Gateway runtime APIs

admin.seams.sh
  internal MPC and platform operations
```

The Console application owns its static routes. The Console Worker owns
`/console/*`, `/healthz`, and `/readyz` on the same origin. Product runtime
services remain independent deployments connected through exact private service
bindings or authenticated product APIs.

## Source And Route Ownership

Keep direct static composition in `apps/seams-console`:

```text
src/
  core/
  products/
    wallet/
    ecommerce-agents/
    cafeos/
  app/
```

The exact folders may follow existing landed names where they already express
these owners. Do not move files solely to reproduce this illustration.

Composition rules:

1. Console core imports no product module, product API client, Wallet SDK,
   signer type, agent type, or CafeOS type.
2. Each product module may import supported Console-core browser contracts and
   its own product contracts.
3. Product modules do not import one another. Cross-product UI reads a composed
   view model supplied by the application boundary or an exact backend result.
4. `app/` imports Console core and each implemented product module and builds
   one exhaustive route and navigation definition.
5. A product appears in navigation only when its implementation and current
   customer entitlement exist. Add no disabled or coming-soon product branch.
6. Add no plugin registry, dynamic loader, product manifest, runtime discovery,
   or generalized product SDK.

Use stable product namespaces:

```text
/dashboard/overview
/dashboard/wallet/*
/dashboard/agents/*
/dashboard/cafeos/*
/dashboard/team/*
/dashboard/billing/*
/dashboard/audit/*
/dashboard/settings/*

/console/core/*
/console/wallet/*
/console/agents/*
/console/cafeos/*
```

Authentication and session lifecycle remain exact Console-core routes under
`/console/auth/*` and `/console/session`. Move current Wallet pages beneath
`/dashboard/wallet/*` during the domain cutover and delete their old route
literals. Ecommerce Agents and CafeOS routes land only with their first working
product path.

## Required Invariants

1. Production has one Console origin, Console session authority, Console core
   database, organization graph, billing graph, and customer identity plane
   across all products and networks.
2. Staging has an independent Console origin, session secret, issuer, database,
   provider registration, and product services.
3. Production testnet and mainnet are environment selections inside the
   production control plane. Selecting an environment cannot change the
   authenticated organization or grant a product entitlement.
4. Console session cookies are `Secure`, `HttpOnly`, host-only `__Host-`
   cookies with `Path=/` and no `Domain` attribute.
5. Product admission separately verifies live membership, entitlement, role,
   project, environment, and resource scope.
6. A Console session grants no Wallet signing, Wallet Session, agent execution,
   CafeOS machine-control, or platform-admin authority by itself.
7. The Console Worker receives the Console database and declared Console
   providers. It receives no product runtime database or runtime credential.
8. Each product service owns its runtime state and exposes only exact
   control-plane operations to the Console.
9. The Wallet Gateway receives no Console database and uses only the R105 exact
   internal Wallet Console service-binding operations.
10. `sign.seams.sh` remains the only hosted Wallet browser runtime origin. The
    Console cannot read its IndexedDB, workers, or Wallet Session bearer.
11. Product modules cannot manufacture another product's resource identity,
    entitlement, authorization, or execution result.
12. Console, Wallet, product-runtime, and Admin credentials are mutually
    unusable across their route namespaces.
13. The main site serves no customer Console bundle or `/dashboard/*` route
    after cutover.
14. Old Console hosts and main-site dashboard routes receive no compatibility
    application.

## Deployment And Session Contract

Move Console deployment ownership from Wallet lanes to the site-level
environment in `deployment/targets.json`:

```json
{
  "site": {
    "origin": "https://seams.sh",
    "docsOrigin": "https://docs.seams.sh",
    "console": {
      "origin": "https://console.seams.sh",
      "pagesProjectEnv": "CF_PAGES_PROJECT_CONSOLE",
      "workerName": "seams-console"
    }
  }
}
```

The staging site carries `https://staging.console.seams.sh`, its own Pages
project, Worker, session authority, and Console database. Wallet lanes keep
their Wallet Gateway, Wallet origin, signer resources, and exact internal Wallet
Console service binding.

The parser validates one required Console deployment per site environment,
origin-only HTTPS URLs, distinct trust-plane origins, required Pages and Worker
names, one Console database per site environment, and the absence of lane-owned
Console session or database configuration after cutover.

Delete `consoleOriginFor(gatewayOrigin)` and its hostname-substitution tests.
`deployment/targets.json` remains the single human-edited topology source.

The two Console session authorities are exact:

```text
production
  origin       = https://console.seams.sh
  issuer       = exact production Console issuer
  audience     = seams-console
  cookie       = __Host-seams-console

staging
  origin       = https://staging.console.seams.sh
  issuer       = exact staging Console issuer
  audience     = seams-console
  cookie       = __Host-seams-console
```

Google origin registration and GitHub redirect registration name the exact
Console origin. Production OAuth state cannot complete on staging. Product
access comes from live server-side entitlements; navigation visibility is a
projection of that authority.

## Data Ownership

Production Console core and implemented product control-plane tables may share
one Console D1 initially, following R105's composed-schema decision. Every table,
migration, job, and retention rule keeps one declared owner: Console core,
Wallet Console, Ecommerce Agents Console, CafeOS Console, or composition.

Product runtime databases remain outside Console D1. These include signer
custody state, agent execution and replay state, and CafeOS telemetry or machine
control. The Console stores customer configuration, durable control-plane
records, and projections required for administration.

Do not split product control-plane databases until an observed scaling,
regional, compliance, or failure-isolation requirement justifies the
consistency cost.

## Implementation Phases

### Phase 0: Complete R105B And Freeze The Current Surface

- [ ] Complete Refactor 105B and exact-pin the public Wallet packages in the
      private application repository.
- [ ] Inventory current main-site dashboard routes, Console Worker routes,
      lane-owned Console databases, OAuth registrations, email links, Stripe
      return URLs, webhook links, readiness probes, CORS allowlists, cookies,
      Pages projects, custom domains, and deployment secrets.
- [ ] Record current staging Console login, organization selection, Wallet
      inventory, policy, sponsorship, billing, webhook, and audit behavior.
- [ ] Confirm certificate coverage for `console.seams.sh` and
      `staging.console.seams.sh`.

Exit:

- every current Console route, store, session, and deployment input has one
  owner and one planned destination;
- both canonical Console origins can terminate TLS;
- R105B has no remaining source-movement work.

### Phase 1: Move Console Deployment Above Wallet Lanes

- [ ] Add the required site-level Console deployment object and exact boundary
      parser to `deployment/targets.json` handling.
- [ ] Assign one production Console D1 and one staging Console D1.
- [ ] Reconcile production-testnet control-plane records into the production
      Console schema before deleting the lane-owned testnet Console database.
      If production holds no durable customer data, prove the empty state and
      create the canonical database directly.
- [ ] Remove Console D1, session, provider, and public-origin ownership from
      Wallet lane configuration.
- [ ] Replace every `consoleOriginFor(gatewayOrigin)` consumer with the parsed
      site Console origin.
- [ ] Delete `consoleOriginFor` and tests that encode hostname-label
      substitution.
- [ ] Render Console Worker routes, `CONSOLE_BASE_URL`, issuer, audience, cookie,
      provider registration, readiness probes, and email links from the exact
      site Console object.

Exit:

- Console identity and persistence belong to production or staging, never a
  Wallet network lane;
- deployment plans print one Console origin per site environment;
- no production or deployment code derives a Console origin.

### Phase 2: Deploy The Console Independently

- [ ] Build `apps/seams-console` once for production and once for staging.
- [ ] Deploy each build to its exact Console Pages project.
- [ ] Bind application routes to the matching Console origin.
- [ ] Route `/console/*`, `/healthz`, and `/readyz` on the same hostname to the
      matching Console Worker.
- [ ] Remove the `dashboard-static` copy from the main site build.
- [ ] Remove Console routes and Console smoke paths from the main site Pages
      project.
- [ ] Keep docs and Wallet static deployment behavior unchanged.

Exit:

- the Console application and credentialed Console API are same-origin;
- `seams.sh` deploys with no Console bundle;
- production and staging each have one customer Console authority.

### Phase 3: Establish Explicit Product Composition

- [ ] Keep Console core free of product imports.
- [ ] Keep the landed Wallet module under `products/wallet` and move its UI
      routes beneath `/dashboard/wallet/*`.
- [ ] Replace the broad product-switcher configuration with one exhaustive
      composition of implemented and entitled products.
- [ ] Remove inactive ecommerce-agent and generic API placeholder entries.
- [ ] Add Ecommerce Agents and CafeOS branches only with their first working
      route, server authorization, product grant, and behavioral smoke.
- [ ] Give each product an exact navigation group and route namespace.
- [ ] Keep shared team, billing, audit, and settings navigation owned by Console
      core.

Exit:

- Wallet is the only product branch until another product has an operating
  path;
- every visible product has a working route and server-enforced entitlement;
- no product imports another product's implementation.

### Phase 4: Unify Production Environment Selection

- [ ] Replace mutable lane API selection with typed production environment
      records loaded through the production Console authority.
- [ ] Require every product request to name the exact selected project and
      environment from authenticated Console state.
- [ ] Resolve Wallet mainnet or testnet service bindings from the selected
      environment at the Console server boundary.
- [ ] Prevent browser-provided Gateway, Wallet, agent-service, or CafeOS-service
      origins from influencing server routing.
- [ ] Preserve the selected environment across refresh without encoding
      authority in local storage.

Exit:

- one production session administers authorized testnet and mainnet resources;
- environment changes update resource scope and service routing through
  server-validated configuration;
- browser state cannot select an undeclared product service.

### Phase 5: Cut Over Authentication And Links

- [ ] Register `console.seams.sh` and `staging.console.seams.sh` with Google and
      register their exact GitHub redirect URLs.
- [ ] Issue the canonical host-only `__Host-seams-console` cookie.
- [ ] Update invitation, billing, invoice, approval, audit-export, and webhook
      links to the exact Console origin.
- [ ] Remove credentialed Console CORS for the old main-site origin. Retain an
      exact allowlist only for an observed external caller requirement.
- [ ] Verify sign-out and organization switching affect the active Console
      session across every product area.
- [ ] Require a fresh login on the new host. Add no old-cookie parser,
      parent-domain cookie, or cross-origin session copy.

Exit:

- authentication begins and completes on one production or staging Console
  origin;
- product navigation never changes the Console session authority;
- generated emails and provider configuration contain no old Console URL.

### Phase 6: Delete The Old Hosted Topology

- [ ] Remove `/dashboard/*`, `/dashboard-static`, and `/platform/*` Console
      routing from `seams.sh` deployment configuration.
- [ ] Remove old lane Console Worker routes, session configuration, database
      bindings, and DNS after the unified production Console passes smoke.
- [ ] Delete obsolete frontend environment variables, network-origin switching,
      workflow inputs, route fixtures, smoke expectations, and documentation.
- [ ] Delete superseded Wallet route literals after the product namespace is
      live.
- [ ] Add no redirect application or dual-host compatibility mode.

Exit:

- production and staging each have one canonical Console hostname;
- old site paths and lane Console hosts cannot create or use a Console session;
- deployment configuration contains no legacy Console topology.

## Verification

Run the narrowest check for each changed boundary. Complete one staging
operating flow before production cutover.

### Static And Build Checks

```bash
pnpm -C apps/seams-console typecheck
pnpm -C apps/seams-console build
pnpm -C packages/console-shared-ts type-check
pnpm -C packages/console-server-ts type-check
pnpm -C packages/wallet-console-shared-ts type-check
pnpm -C packages/wallet-console-server-ts type-check
pnpm -C tests run test:source-guards
```

Add focused checks proving:

- production and staging each declare one exact Console origin, Worker, Pages
  project, session authority, and Console database;
- Wallet lanes contain no Console D1 or Console session configuration;
- no `api`-to-`console` hostname derivation remains;
- the main site artifact contains no Console bundle;
- Console core declarations contain no product imports;
- each visible product route has one product owner and entitlement check;
- generated deployment output binds Console routes only to the declared Console
  origin;
- Console cookies carry the exact host-only security attributes.

### Browser And Route Checks

- Open each Console origin and complete its provider login.
- Verify `/dashboard/*` loads and `/console/session` is same-origin.
- Verify organization, project, environment, team, billing, audit, webhook, and
  settings behavior once on staging.
- Verify the Wallet area can select authorized staging resources and complete
  inventory, policy, sponsorship, approval, and audit flows.
- Verify production environment selection resolves testnet and mainnet through
  the same Console session without accepting browser-supplied service origins.
- Verify a staging Console cookie is absent from production requests.
- Verify product entitlements hide and deny unavailable product routes.
- Verify Console credentials fail on Wallet Gateway and Admin routes.
- Verify Wallet Session and Admin credentials fail on Console routes.
- Verify the Console Worker rejects Wallet runtime paths and the Wallet Gateway
  rejects `/console/*`.
- Verify the main site and deleted lane Console hosts serve no customer Console.
- Run one hosted Wallet registration and signing flow to prove the unchanged
  `sign.seams.sh` boundary.

The authoritative Wallet lifecycle suite remains `pnpm test:intended`. Run it
after the staging Console operating path succeeds.

## Risks And Controls

### Shared-Origin Product Blast Radius

All customer product modules share one browser origin and Console session. Keep
Console code first-party, enforce a strict CSP, admit product operations at the
server, avoid third-party runtime scripts, and route custody-sensitive Wallet
work through `sign.seams.sh`. A product requiring untrusted frontend code or a
distinct compliance boundary receives a separate explicit plan and origin.

### Product Entitlement Confusion

Authentication alone cannot expose a product. Load live product entitlements at
the Console boundary and require the exact product grant on every product route.
Navigation visibility remains a projection of server authority.

### Cross-Product Authority Leakage

Shared organization and environment identity grant no product authority.
Cross-product actions carry explicit source and target resources and verify both
product grants before either service performs work.

### Production Environment Confusion

One production Console manages several Wallet networks and future product
environments. Resolve service routing from server-owned environment records.
Browser display state supplies a requested environment identifier only.

### Recreating A Generic Console Framework

R105 already provides a product-neutral core and one explicit Wallet
composition. Add Ecommerce Agents and CafeOS as two more explicit branches when
their operating paths exist. R105C adds no registry, manifest, dynamic loader,
or plugin protocol.

### Mixing Domain Cutover With Repository Movement

R105B remains a source and release boundary change. R105C begins after its clean
independent builds pass, keeping failures attributable to one cutover.

## Non-Goals

- implementing Ecommerce Agents or CafeOS product behavior in this refactor;
- creating disabled product placeholders before an operating path exists;
- creating `wallet.seams.sh` or a wallet-owner `/profile` application;
- changing Wallet signing, custody, recovery, export, or linked-device behavior;
- renaming `sign.seams.sh` or changing its RP ID and iframe contract;
- combining customer Console and MPC Admin;
- adding parent-domain session cookies;
- exposing signer or robot-control credentials to the Console;
- splitting each product control plane into its own production database without
  an observed requirement;
- changing public Wallet package names or repository ownership established by
  R105B.

## Definition Of Done

- the production Console is deployed only at `console.seams.sh`;
- the staging Console is deployed only at `staging.console.seams.sh`;
- production and staging each own one Console session authority, Console core
  database, organization graph, and statically composed application;
- production testnet and mainnet are server-validated environments inside the
  production Console;
- Console core contains no product implementation or dependency;
- Wallet, Ecommerce Agents, and CafeOS have explicit product ownership and
  route namespaces, with only implemented and entitled products visible;
- the Console application and Console Worker API are same-origin;
- the main site contains no Console bundle or dashboard route;
- the Wallet Gateway, product services, Console Worker, hosted Wallet origin,
  and Admin Worker keep mutually exclusive credentials, bindings, and routes;
- `sign.seams.sh` continues to pass the hosted Wallet lifecycle without Console
  storage or session access;
- old lane Console hosts, main-site dashboard routes, derived-origin helpers,
  environment fallbacks, inactive product placeholders, and compatibility code
  are deleted;
- future product work adds an explicit statically composed module without
  changing Console core or inheriting another product's domain state.
