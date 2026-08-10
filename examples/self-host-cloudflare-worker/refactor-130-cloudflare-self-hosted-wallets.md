# Refactor 130: Cloudflare Self-Hosted Wallets

Date created: August 5, 2026
Cloudflare API feasibility checked: August 9, 2026

Status: active demo implementation plan. This plan replaces the earlier
production self-hosting proposal with a bounded example that demonstrates the
public Seams SDK on customer-owned Cloudflare infrastructure.

## Purpose

Build a convincing, reproducible demo of the SDK's strict Router A/B signing
architecture in a customer-owned Cloudflare account.

The demo should let an evaluator authorize Cloudflare, wait for an automatic
deployment, create a wallet, and observe:

- one Cloudflare OAuth consent;
- five separately deployed runtime artifacts;
- role-specific secrets and private D1 stores;
- private same-account Service Bindings;
- a fixed single-tenant Gateway boundary;
- a public `workers.dev` Gateway endpoint, with optional custom-domain routing;
- new Ed25519 and ECDSA wallet registration and signing;
- normal signing without Deriver participation;
- health, readiness, configuration, and key-agreement diagnostics.

This is an SDK showcase. It is not the supported production self-hosting
product, a managed-tenant migration destination, or a general infrastructure
platform.

After this strict-topology demo works from a clean account, a separate
follow-up may demonstrate a single-Worker custody profile. That follow-up is
defined below so its protocol and security tradeoffs do not alter the first
milestone.

## Decisions

1. All demo-specific specification, compilation, provisioning, state, and
   diagnostics code lives under
   [`examples/self-host-cloudflare-worker`](.).
2. The demo consumes public SDK exports and prebuilt Router A/B artifacts. It
   does not import `@seams-internal/*`, reach into `packages/*/src`, or reuse
   managed deployment scripts through relative paths.
3. The managed Gateway, GitHub deployment pipeline, `deployment/targets.json`,
   and local Router A/B initializer remain unchanged.
4. Gateway, MPCRouter, Deriver A, Deriver B, and SigningWorker are separate
   Workers. The existing reviewed strict topology remains intact.
5. Same-account private calls use Service Bindings. Only the Gateway is
   internet-accessible.
6. The demo uses one fixed tenant scope configured at deployment time. A
   request cannot choose organization, project, environment, database, or
   deployment identity.
7. The primary experience is a narrow browser onboarding application. It uses
   Cloudflare OAuth to authorize one account, deploys automatically, and then
   enables wallet creation. It does not introduce a Seams administrator
   account, membership model, or general management API.
8. The first complete demo exercises both Ed25519 and ECDSA with locally
   verified signatures. Live-chain broadcasting, sponsorship, billing,
   production funding, and managed relayers are separate concerns.
9. The Cloudflare OAuth access token remains on the onboarding server and is
   discarded or revoked when deployment finishes. Generated role secrets are
   installed directly into their owning Workers and never enter browser state,
   rendered configuration, or a deployment receipt.
10. Backup support is a separate optional demonstration. The initial demo does
    not claim production disaster recovery or safe restoration after deleting
    active wallet authority.
11. No compatibility path is kept for the current one-Worker example. The
    generated strict-topology demo replaces it directly.
12. The onboarding application uses one verified public Cloudflare OAuth
    client. Customers authorize only the account and scopes required by the
    deployment and may revoke that authorization from Cloudflare.

## Isolation Boundary

The demo should prove that an SDK consumer can assemble the supported pieces
without becoming part of the main application.

### Allowed dependencies

Demo runtime and tooling may depend on:

- `@seams/sdk-server`;
- `@seams/sdk-server/router/cloudflare`;
- other documented public `@seams/sdk-server` exports;
- Cloudflare OAuth and Cloudflare's public REST APIs;
- Wrangler for local development and CI dry runs;
- content-addressed Router A/B Worker artifacts produced by the release build.

During monorepo development, `workspace:*` may resolve those public packages.
The clean-install validation must use packed or published packages and must not
depend on repository path aliases.

### Forbidden dependencies

The demo must not:

- import `@seams-internal/*`;
- import files from `packages/*/src`, `crates/*/src`, or `apps/*/src`;
- mutate or interpret `deployment/targets.json`;
- call managed GitHub environment scripts;
- import hosted console, billing, support, organization-switching, or platform
  membership modules;
- add demo flags or demo lifecycle branches to core SDK functions;
- add a repository-wide `DeploymentTenantMode` solely for this example.

If the demo discovers a missing public SDK capability, implementation pauses at
that boundary. The capability is proposed as a small public SDK change with its
own behavioral or type-level contract. The demo does not bypass the public
surface by importing internal code.

### Expected directory ownership

```text
examples/self-host-cloudflare-worker/
  README.md
  package.json
  refactor-130-cloudflare-self-hosted-wallets.md
  onboarding/
    oauth.ts
    session.ts
    deployment.ts
    wallet.ts
    ui/
  src/
    gateway.ts
  tooling/
    spec.ts
    plan.ts
    apply.ts
    doctor.ts
    state.ts
    cloudflare.ts
  cli/
    apply.ts
    doctor.ts
  templates/
    gateway.wrangler.jsonc
    router.wrangler.jsonc
    deriver-a.wrangler.jsonc
    deriver-b.wrangler.jsonc
    signing-worker.wrangler.jsonc
```

CLI dry-run output and non-secret local state go in a gitignored directory
inside the example. The browser flow uses the short-lived server-side job
described below. Tests remain in the top-level `tests/` workspace, as required
by the repository layout.

## Streamlined Onboarding Experience

The primary experience has two user actions.

### 1. Deploy with Cloudflare

The onboarding page presents one explicit action:

```text
Deploy with Cloudflare
```

The label communicates that authorization will create resources. After the
user continues:

1. Redirect to Cloudflare's OAuth authorization endpoint.
2. Let Cloudflare authenticate the user, select the authorized account, and
   display the requested scopes.
3. Exchange the returned authorization code on the onboarding server.
4. Generate the deployment name, fixed tenant identity, resource names, and
   role secrets without asking the user to enter them.
5. Compile and render one secret-free mutation summary.
6. Reuse the account's existing `workers.dev` subdomain or create one when the
   account has none.
7. Create D1 databases, deploy all five artifacts, attach bindings, install
   role secrets, apply schemas, and enable only the Gateway's public endpoint.
8. Run readiness and protocol diagnostics automatically.
9. Revoke or discard the Cloudflare token and transition to
   `ready_for_wallet_creation`.

There is no specification form or second apply button. The initial action says
`Deploy with Cloudflare`, and Cloudflare's consent screen is the authorization
for the bounded mutations shown there.

The progress surface speaks in product operations:

```text
Authorizing Cloudflare
Creating secure wallet backend
Configuring storage
Installing signing material
Verifying deployment
```

Worker role names and resource identifiers remain available under deployment
details. They are not setup decisions.

The default public endpoint is the Gateway's stable `workers.dev` hostname.
The operator may select an active zone and attach a Custom Domain before wallet
creation. Cloudflare then creates the required DNS record and certificate.

The wallet origin and WebAuthn RP ID are finalized before the first durable
wallet is created. Adding a cosmetic Gateway hostname later does not silently
change an existing wallet's RP ID. Moving an existing wallet to a different RP
ID requires an explicit passkey re-enrollment design outside this demo.

### 2. Create wallet

The second screen is unavailable until deployment diagnostics pass:

```text
Your wallet backend is ready

Create wallet
```

Selecting `Create wallet`:

1. loads the public SDK against the generated Gateway configuration;
2. performs one passkey registration;
3. completes Ed25519 and ECDSA wallet provisioning through strict Router A/B;
4. displays wallet public identities and addresses;
5. signs and locally verifies one test message for each algorithm.

RPC selection, chain funding, relayer credentials, sponsorship, backup, and
production policy do not block this first success.

### Advanced CLI

A package-local CLI exercises the same parser, compiler, provisioner, and
doctor for CI and debugging. It is not the onboarding path and does not define
a second deployment protocol. This plan does not create a repository-wide
`seams` CLI or a long-lived CLI compatibility contract.

## Supported Topology

```text
Customer wallet origin
  -> Gateway Worker
       -> fixed demo tenant scope
       -> Gateway wallet/auth/session D1
       -> MPCRouter Service Binding
            -> Deriver A Worker -> Deriver A private D1
            -> Deriver B Worker -> Deriver B private D1
            -> SigningWorker    -> SigningWorker private D1
```

The exact role-to-role binding graph, protocol routes, key formats, and storage
schemas come from the current strict Router A/B artifacts. The demo compiler
supplies names, bindings, public configuration, and role-owned secret plans. It
does not reimplement the signing protocol.

The Cloudflare account administrator is inside the demo trust assumption.
Separating roles within one account demonstrates secret ownership and runtime
boundaries; it does not protect against a malicious account administrator who
can replace deployed Worker code.

## Demo Specification

The browser does not ask the user to author a deployment specification. Its raw
input is the authenticated Cloudflare authorization plus an optional custom
Gateway hostname:

```ts
type SelfHostedCloudflareOnboardingInputV1 = {
  readonly kind: 'self_hosted_cloudflare_onboarding_v1';
  readonly gatewayRoute:
    | {
        readonly kind: 'workers_dev';
      }
    | {
        readonly kind: 'custom_domain';
        readonly zoneId: string;
        readonly hostname: string;
      };
};
```

The authorized Cloudflare account comes from the OAuth grant. The deployment
name, resource prefix, tenant fields, Gateway origin, allowed onboarding origin,
and test-vector configuration are generated. Selecting a custom domain uses a
zone returned by Cloudflare; the UI does not accept an unverified account or
zone identifier.

The onboarding boundary validates and normalizes the OAuth result and route
choice once, then constructs the internal `SelfHostedCloudflareDemoSpecV1`.
Tooling after that boundary accepts only the normalized specification. The
OAuth token, private keys, root shares, KEKs, and session secrets are never
members of either input or specification.

## Fixed Tenant Adapter

The demo defines one local `DemoTenantScope` that maps the specification's
tenant fields into the current public Gateway and storage configuration:

```ts
type DemoTenantScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
};
```

The Gateway constructs this scope once from normalized deployment
configuration. Public requests carry wallet, credential, session, and operation
identities only.

This adapter stays inside the example. The demo does not introduce a new global
tenant lifecycle union, rename the current SDK tenant fields, or migrate all
core persistence records. A broader required `TenantContext` remains a separate
production architecture decision.

## Demo Compiler

The example owns a small pure compiler:

```text
normalized demo spec + reviewed artifact manifest
  -> exact five-role demo plan
       -> Worker upload metadata and modules
       -> role-owned secret installation plan
       -> D1 migration plan
       -> Service Binding graph
       -> public Gateway route plan
       -> health and canary plan
```

The compiler performs no I/O. It does not call Cloudflare, read OAuth state,
spawn Wrangler, read the filesystem, or inspect managed deployment
configuration.

Its output is a discriminated union of the five role plans. Each branch contains
only the bindings, public values, database identity, artifact digest, and secret
names owned by that role. Secret values never enter the compiled plan.

The compiler is intentionally demo-specific. Shared compiler extraction happens
only if a later production self-hosting project demonstrates a real second
consumer and the extraction removes more code than it adds.

## Secret Handling

The onboarding server uses Cloudflare's Authorization Code flow with a client
secret. The OAuth client is public, has a verified publisher domain, and asks
Cloudflare to scope authorization to the customer-selected account. The
authorization code and access token never enter browser JavaScript.

The OAuth `state` value is single-use and bound to the encrypted onboarding
session. The server exchanges the code, preflights the granted account and
scopes, performs the bounded deployment, and calls Cloudflare's revocation
endpoint when the job reaches a terminal state. A later update requires a new
authorization. No refresh token or Cloudflare credential is retained in the
deployment receipt.

The provisioner generates independent role material using a dedicated secret
generation helper. Root shares, KEKs, envelope keys, peer keys, session keys,
and internal-service credentials are never derived from one retained master
seed.

Secrets are installed directly into the owning Worker through Cloudflare's bulk
script-secrets API. Private values are never included in browser responses,
logs, Worker upload metadata, the rendered plan, or the non-secret receipt.

JavaScript cannot guarantee zeroization of immutable strings or garbage-
collected copies. The implementation minimizes secret lifetime and copies. A
small Rust or native helper may use mutable byte buffers for generation and
sealing when that materially improves handling. Documentation must describe
cleanup accurately and must not claim guaranteed process-memory zeroization.

## Cloudflare Configuration

The primary onboarding path calls Cloudflare's REST APIs directly. Wrangler
JSONC templates remain useful for local development and dry-run bundle checks;
they are not runtime input to the browser flow.

Worker upload metadata uses:

- a current compatibility date and `nodejs_compat` where required;
- generated Worker binding types from `wrangler types`;
- declarative SQLite Durable Object exports if the Gateway requires a Durable
  Object namespace;
- role-specific D1 bindings and migrations;
- Service Bindings for private Worker calls;
- disabled `workers.dev` endpoints for private roles;
- an enabled `workers.dev` endpoint for the Gateway;
- structured logs and explicit observability configuration;
- no secret values in plain-text bindings.

The provisioner treats Cloudflare APIs as an external control-plane boundary.
Runtime Workers use bindings for Cloudflare resources and do not call the
Cloudflare REST API.

### Cloudflare API feasibility

The streamlined flow is supported by Cloudflare's documented public APIs as of
August 9, 2026:

| Onboarding operation | Cloudflare surface | Required permission |
| --- | --- | --- |
| Authenticate, choose an account, and consent | [OAuth Authorization Code flow](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/) | OAuth client scopes selected at consent |
| Exchange and revoke authorization | [OAuth authorization, token, and revoke endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/) | OAuth protocol |
| Discover zones for optional custom routing | `GET /zones` via [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/) | `Zone Zone Read` |
| Create role databases | `POST /accounts/{account_id}/d1/database` via [Create D1 Database](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/create) | `D1 Write` |
| Apply and verify D1 schemas | `POST /accounts/{account_id}/d1/database/{database_id}/query` via [D1 Database API](https://developers.cloudflare.com/api/resources/d1/subresources/database/) | `D1 Write` |
| Upload each Worker and its non-secret bindings | `PUT /accounts/{account_id}/workers/scripts/{script_name}` via [Workers Scripts API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/) | `Workers Scripts Write` |
| Describe D1, Durable Object, and Service Bindings | Worker multipart [`metadata.bindings`](https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/) | `Workers Scripts Write` |
| Install role-owned secrets | `PATCH /accounts/{account_id}/workers/scripts/{script_name}/secrets-bulk` via [Bulk Secrets API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/bulk_update) | `Workers Scripts Write` |
| Read or create the account's `workers.dev` name | `GET` or `PUT /accounts/{account_id}/workers/subdomain` via [Workers Subdomains API](https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/) | `Workers Scripts Write` |
| Publish the default Gateway endpoint | `POST /accounts/{account_id}/workers/scripts/{script_name}/subdomain` via [Workers Scripts API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/) | `Workers Scripts Write` |
| Attach an optional custom hostname | `PUT /accounts/{account_id}/workers/domains` via [Attach Domain](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/) | `Workers Scripts Write` |

The public OAuth client requests `Workers Scripts Write`, `D1 Write`, and
`Zone Zone Read`. Cloudflare represents OAuth scopes with IDs, so client setup
resolves and pins the current IDs returned by `GET /oauth/scopes` rather than
embedding guessed identifiers. `Zone Zone Read` is used only to populate the
optional custom-domain selector; the base `workers.dev` deployment needs the
two account-level write permissions.

Cloudflare supports public OAuth clients for third-party applications, account
selection during consent, server-side Authorization Code exchange, and PKCE
for public clients. This onboarding uses the server-side branch so the OAuth
client secret and access token stay off the browser. A public client requires a
verified publisher domain and permanent promotion to public visibility.

Custom Domain attachment requires an active zone in the authorized account and
a hostname without a conflicting CNAME. Failure to attach the optional domain
does not roll back a ready base deployment. Wallet creation remains blocked
until the operator retries the Custom Domain or explicitly selects the verified
`workers.dev` route, which then becomes the pinned wallet origin.

This is an API-documentation feasibility verification. Phase 0 must still run
one live OAuth-to-wallet smoke test with the registered public client. The plan
does not claim live verification until that receipt exists.

Cloudflare account administrators can disable access by public OAuth
applications. That policy fails authorization before mutation and produces a
clear administrator-policy error. The primary flow does not fall back to a
manually copied API token.

## Deployment State and Receipt

The onboarding server stores a short-lived deployment job with:

- normalized deployment and tenant identities;
- plan and artifact digests;
- exact Worker, D1, route, and binding identifiers;
- the last completed apply phase;
- schema and doctor receipts;
- whether any demo wallet has been created.

The job never stores role-secret values in durable state. Its OAuth token is
encrypted separately, scoped to the single deployment session, and removed at
the terminal transition. Apply phases are idempotent for one deployment name
and plan digest. A changed plan produces a new review rather than mutating an
active demo implicitly.

At completion, the user downloads a non-secret receipt containing resource
identifiers, artifact digests, public origins, wallet SDK configuration, and
doctor results. The receipt is sufficient for discovery and diagnostics. It
does not authorize Cloudflare operations.

Pre-wallet rollback removes only resources listed in the deployment job. Once
the demo has created a wallet, automated destructive cleanup is disabled and
the receipt identifies the exact resources requiring manual review.

## Provisioning Operations

The onboarding deployment job performs the compiler, apply, and doctor stages
behind one visible deployment action. Internally it:

1. Parses and normalizes the authorized account and route selection.
2. Resolves and verifies all five artifact digests.
3. Preflights OAuth scopes, resource names, origins, RP ID, quotas, and optional
   zone ownership.
4. Compiles the exact five-role plan and records its digest.
5. Reuses the account's current Workers subdomain or creates a generated one
   when the account has none. It never renames an existing account subdomain.
6. Creates the Gateway and role-private D1 databases.
7. Deploys the pinned MPCRouter, Deriver A, Deriver B, SigningWorker, and
   Gateway artifacts with their bindings.
8. Generates and installs independent role secrets.
9. Applies current schemas to the exact owning databases.
10. Enables the Gateway `workers.dev` endpoint or attaches the selected Custom
   Domain while leaving private roles unexposed.
11. Runs doctor and marks the job `ready_for_wallet_creation`.
12. Revokes or discards Cloudflare authorization and emits the non-secret
    receipt.

No active production state is imported or destroyed.

### Doctor

Doctor verifies:

- all five Worker versions and artifact digests;
- public Gateway health and readiness;
- private role reachability through Service Bindings;
- D1 binding and schema identity;
- public/private key agreement without exposing private material;
- expected wallet origin, RP ID, CORS, cookie, and iframe configuration;
- normal-signing configuration and zero-Deriver-call diagnostics;
- absence of unresolved apply phases.

Doctor returns a structured exhaustive result and concise human output. It does
not infer readiness from a diagnostics object used for control flow; each check
produces an explicit pass or failure branch.

## Optional Snapshot Demonstration

Portable recovery is not required for the first demo milestone.

A later optional milestone may demonstrate:

1. exporting each D1 database to a portable SQL snapshot;
2. encrypting snapshots and required role material to a customer-provided
   recipient;
3. creating new empty resources;
4. importing the snapshots;
5. reinstalling the sealed role material;
6. verifying the same demo wallet public keys and addresses.

Cloudflare Time Travel bookmarks and Durable Object PITR bookmarks are useful
operational tools within their retention windows. They are not treated as
portable backups and cannot by themselves satisfy recovery after namespace or
database deletion.

The demo must not advertise production backup, deletion, or disaster recovery
until this complete export-and-restore exercise passes.

## Implementation Plan

### Phase 0: prove the external boundaries

- [ ] Confirm the public SDK exports required by the demo Gateway.
- [ ] Prove that wallet creation and local Ed25519/ECDSA signature verification
      complete without asking the evaluator for an RPC URL, funded account, or
      relayer credential.
- [ ] Confirm the existing four strict Router A/B artifacts accept generated
      names, D1 bindings, Service Bindings, and role-owned secrets without
      managed deployment inputs.
- [ ] Register a verified public Cloudflare OAuth client using the server-side
      Authorization Code flow.
- [ ] Resolve and pin the OAuth scope IDs for `Workers Scripts Write`,
      `D1 Write`, and `Zone Zone Read`.
- [ ] Verify the no-mutation failure shown when an account administrator has
      disabled public OAuth application access.
- [ ] Execute one live API smoke sequence: OAuth consent, account-level Workers
      subdomain discovery or creation, D1 creation, Worker upload, D1 and
      Service Bindings, bulk secret installation, Gateway `workers.dev`
      enablement, optional Custom Domain attachment, doctor, and OAuth
      revocation.
- [ ] Freeze the exact Cloudflare permissions and paid-plan assumptions
      required by the demo.
- [ ] Dry-run all five artifacts from the example without importing internal
      source modules.

This phase may reveal a missing public SDK capability. Any SDK change is kept
small, independently reviewed, and separate from the demo implementation.

### Phase 1: replace the partial example

- [ ] Delete the current one-Worker configuration and wiring.
- [ ] Add the OAuth callback, encrypted deployment session, and exhaustive
      onboarding-state union.
- [ ] Add the onboarding-input parser and generated normalized specification.
- [ ] Add the pure five-role demo compiler.
- [ ] Add Worker upload templates, local JSONC templates, and generated binding
      types.
- [ ] Add the fixed demo tenant adapter at the Gateway boundary.
- [ ] Render one complete secret-free deployment summary after OAuth consent.

### Phase 2: automate the operating path

- [ ] Add the Cloudflare provisioner and non-secret apply journal.
- [ ] Generate every role secret independently.
- [ ] Install secrets directly into their exact owners.
- [ ] Create D1 databases, deploy the five Workers, and create Service Bindings.
- [ ] Apply schemas and enable the Gateway `workers.dev` endpoint.
- [ ] Add optional zone selection and Custom Domain attachment before wallet
      creation.
- [ ] Run doctor automatically and reach `ready_for_wallet_creation` from a
      clean account.
- [ ] Revoke or discard Cloudflare authorization at the terminal transition.

### Phase 3: demonstrate the SDK

- [ ] Present `Create wallet` only after deployment readiness passes.
- [ ] Register one Ed25519 wallet and locally verify a normal signature.
- [ ] Register one ECDSA wallet and locally verify a normal signature.
- [ ] Show that normal signing does not invoke either Deriver.
- [ ] Demonstrate owner authentication and one recovery flow already supported
      by the public SDK.
- [ ] Capture a secret-free walkthrough receipt with artifact, keyset, health,
      wallet public key, address, and transaction or signature evidence.

### Phase 4: package and publish the demo

- [ ] Make the example work with packed or published public SDK packages.
- [ ] Publish the exact Cloudflare OAuth scopes, quotas, costs, and optional
      custom-domain prerequisites.
- [ ] Document teardown behavior and the lack of production recovery guarantees.
- [ ] Run the two-action walkthrough against a clean dedicated Cloudflare
      account without entering a token, resource name, tenant ID, RPC URL, or
      relayer credential.
- [ ] Replace the existing README with the verified onboarding walkthrough and
      advanced CLI notes.

### Phase 5: optional portable snapshot exercise

- [ ] Define an encrypted demo snapshot format.
- [ ] Export all authoritative D1 data and required role material.
- [ ] Restore into new resource identifiers.
- [ ] Verify identical demo wallet public keys and addresses.
- [ ] Clearly label the result experimental until operational review is
      complete.

## Follow-Up: Single-Worker Custody Profile

This work starts only after the strict Router A/B definition of done has been
met. The strict demo must first prove that the current public SDK, reviewed
artifacts, deployment compiler, and Cloudflare operating path work together
without protocol changes. The optional snapshot exercise does not gate this
follow-up.

The follow-up tests a different proposition: a customer willing to trust one
customer-operated Worker can run a much smaller Seams deployment while keeping
the same high-level wallet API.

### Security position

The single-Worker profile is organizational custody. It does not provide the
split-custody, independent-role, or single-Deriver-compromise properties of
Router A/B.

One deployed Worker contains the Gateway boundary, direct derivation service,
persistence adapters, and normal-signing service. Compromise of its code,
bindings, or administrative account has a larger blast radius than compromise
of one strict Router A/B role.

Collapsing the trust boundary removes protocol work that no longer protects
against the relevant adversary:

- Ed25519 derivation uses direct reviewed derivation instead of A/B streaming
  Yao;
- ECDSA derivation uses direct reviewed derivation instead of the A/B
  threshold-PRF exchange;
- the client sends one authenticated derivation request instead of separate
  Deriver A and Deriver B envelopes;
- the server has no A/B peer transport, oblivious transfer, role-to-role HPKE,
  Service Bindings, or cross-role ceremony coordination.

HTTPS, request authentication, authorization, replay protection, transcript
binding, lifecycle binding, recipient encryption for client-owned secret
outputs, and encryption at rest remain required. Raw secret derivation remains
inside reviewed Rust or WASM cryptographic code. TypeScript and JavaScript
orchestrate the protocol and do not implement secret-dependent arithmetic.

### Profile architecture

The SDK supports two explicit custody profiles rather than a collection of
feature flags:

```ts
type CustodyProfile =
  | {
      readonly kind: 'router_ab_v1';
    }
  | {
      readonly kind: 'single_worker_v1';
    };
```

The intended SDK shape is:

```text
one public wallet API
  -> router_ab_v1 protocol driver
       -> Gateway + MPCRouter + Deriver A + Deriver B + SigningWorker
  -> single_worker_v1 protocol driver
       -> one customer-operated Worker
```

The public registration, recovery, export, and signing methods remain the
same. Each protocol driver owns its exact request types, lifecycle transitions,
and response parsing. Shared domain behavior may be reused where it already
fits; Router A/B functions do not gain optional fields or simple-mode branches.

The profile is selected from authenticated, deployment-pinned configuration
and recorded when a wallet is created. Every later lifecycle operation requires
that exact profile. Requests cannot choose a profile, and neither client nor
server falls back from `router_ab_v1` to `single_worker_v1` after an error.

Wallet portability between profiles is excluded. A migration would require a
separately reviewed protocol and must not be inferred from compatible public
keys, storage records, or derivation outputs.

### Isolation boundary

The follow-up lives in a sibling example:

```text
examples/self-host-cloudflare-single-worker/
```

It does not replace or add conditionals to
`examples/self-host-cloudflare-worker`. The strict example remains the proof of
the reviewed Router A/B architecture.

The single-Worker example initially consumes public SDK surfaces. If the spike
finds a missing client or server capability, that capability is proposed as a
narrow profile-specific public entrypoint with its own protocol tests. Demo
code must not import package source files or add repository-wide demo flags.

Server code remains internally separated into Gateway, derivation, storage,
and signing modules even though those modules share one deployed Worker and use
direct calls. This preserves readable ownership without pretending the modules
are separate security principals.

### Follow-up phase 0: specify and prove the direct protocol

- [ ] Inventory every Router A/B step used by registration, recovery, export,
      refresh, activation, and normal signing.
- [ ] Specify the direct Ed25519 and ECDSA derivation transcripts, recipient
      outputs, replay rules, and lifecycle bindings.
- [ ] Confirm which existing Rust/WASM primitives can be reused without
      exposing raw secret arithmetic to TypeScript.
- [ ] Define authenticated server metadata and client configuration that pin
      exactly one custody profile.
- [ ] Prove with vectors that direct derivation produces the intended wallet
      keys and signer material.
- [ ] Review the reduced security claim before implementation proceeds.

### Follow-up phase 1: build the segregated server

- [ ] Add the sibling example with one Worker entrypoint and one demo-local
      deployment specification.
- [ ] Compose public Gateway, derivation, persistence, and signing surfaces as
      internal modules with direct calls.
- [ ] Use the smallest D1 and secret layout required by the demonstrated
      lifecycle.
- [ ] Add a package-local provisioner and doctor command without changing the
      strict demo compiler.
- [ ] Demonstrate a clean deployment without A/B Service Bindings, Yao,
      threshold-PRF exchange, or role envelopes.

### Follow-up phase 2: add the client protocol driver

- [ ] Keep the existing high-level wallet API unchanged.
- [ ] Add an exhaustive custody-profile boundary and separate branch-specific
      request builders and response parsers.
- [ ] Send one direct lifecycle request in `single_worker_v1` while preserving
      the existing Router A/B ceremony in `router_ab_v1`.
- [ ] Persist the profile with wallet lifecycle state and reject mismatched
      server metadata, stored state, or operation requests.
- [ ] Add type fixtures that reject wallets and requests assembled from
      mismatched custody-profile branches.
- [ ] Confirm normal signing uses the narrow single-Worker path and does not
      retain unused derivation ceremony state.
- [ ] Compare browser bundle size and lifecycle round trips against the strict
      profile.

### Follow-up phase 3: demonstrate and compare

- [ ] Register, sign, recover, and export one Ed25519 wallet.
- [ ] Register, sign, recover, and export one ECDSA wallet.
- [ ] Run both profiles through the same public SDK walkthrough.
- [ ] Publish a concise topology, latency, deployment-step, and security-claim
      comparison.
- [ ] Verify the single-Worker example works from packed or published SDK
      packages with no monorepo source imports.

### Follow-up acceptance criteria

The single-Worker follow-up is complete when:

1. One customer-operated Cloudflare Worker supports the demonstrated wallet
   lifecycle for both Ed25519 and ECDSA.
2. Applications use the same public wallet operations for both custody
   profiles.
3. Profile choice is authenticated, pinned, persisted, and exhaustive, with no
   request-selected downgrade or automatic fallback.
4. The direct protocol contains no A/B envelopes, Yao transport, threshold-PRF
   exchange, or role-to-role Service Bindings.
5. Direct secret derivation remains in reviewed Rust/WASM code.
6. The sibling example consumes public packages and introduces no simple-mode
   branches into Router A/B implementation code.
7. Documentation labels the deployment as organizational custody and states
   its larger compromise boundary plainly.

## Validation

Tests live in the top-level `tests/` workspace and focus on behavior:

- one valid OAuth account and route choice compile into exact role-owned plans;
- invalid OAuth state, insufficient scopes, unauthorized accounts, and invalid
  route choices fail before Cloudflare mutation;
- a dry run bundles all five artifacts using only public package exports;
- secret values and OAuth tokens never appear in browser responses, rendered
  configuration, the receipt, or human output;
- a clean dedicated account reaches `ready_for_wallet_creation` through
  Cloudflare OAuth without manual token or environment-variable copying;
- a denied or interrupted OAuth flow performs no mutation;
- a resumed deployment continues from the exact recorded plan digest;
- the base flow exposes only the Gateway on `workers.dev`;
- optional Custom Domain attachment accepts only a zone in the authorized
  account and completes before durable wallet creation;
- Ed25519 and ECDSA wallets register and sign through the strict topology;
- normal signing produces zero Deriver calls;
- the fixed tenant scope is used regardless of caller-supplied tenant-like
  headers or fields;
- hosted console, billing, support, and membership routes are unavailable;
- pre-wallet apply retries are idempotent;
- cleanup targets only the exact pre-wallet resources in the deployment job.

The suite does not add source-text guards. Public-boundary isolation is proven
by building the packed example outside the monorepo and by exercising the
resulting deployment.

## Definition Of Done

The first demo is complete when:

1. An evaluator starts with a Cloudflare account and the onboarding page.
2. The evaluator selects `Deploy with Cloudflare`, authorizes one account, and
   enters no API token or infrastructure specification.
3. The onboarding service deploys and verifies the exact five-role topology,
   then removes its Cloudflare access token.
4. The Gateway receives a working `workers.dev` endpoint; attaching a Custom
   Domain is optional and automated.
5. The onboarding page enables `Create wallet` only after doctor reaches
   `ready_for_wallet_creation`.
6. One passkey ceremony creates Ed25519 and ECDSA wallet capability, and both
   algorithms produce locally verified signatures.
7. Normal signing demonstrates zero Deriver calls.
8. The deployed Gateway serves exactly one generated fixed tenant scope.
9. The downloadable receipt contains no OAuth token or role secret.
10. The example consumes only public SDK packages, reviewed release artifacts,
    and documented Cloudflare APIs.
11. Managed deployment code and core domain types contain no demo lifecycle,
    demo configuration, OAuth, or compatibility branches.
12. A clean-account OAuth-to-wallet walkthrough succeeds and records the API,
    artifact, deployment, doctor, and signature evidence.

## Non-Goals

- supported production self-hosting;
- migrating a managed Seams tenant;
- Refactor 115 import staging or activation;
- production backup, destruction, or disaster recovery;
- a repository-wide `seams` CLI;
- a general administrator console or self-host membership system;
- billing, support access, organization switching, sponsorship, or managed
  relayers;
- Kubernetes, AWS, GCP, generic OCI, or multi-account role isolation;
- refactoring the managed deployment pipeline before the demo works;
- introducing global deployment-mode or tenant-context types for the demo;
- preserving compatibility with the retired one-Worker example.

## Future Production Work

If the demo creates real demand for supported self-hosting, a separate plan can
promote the proven pieces into a production product. That plan must independently
address:

- a stable CLI and update policy;
- production administrator authentication and authorization;
- portable encrypted backup and destructive restore drills;
- artifact rollback after wallets are active;
- customer monitoring and alert delivery;
- production chain funding and sponsorship;
- tenant portability and Refactor 115 activation;
- provider support and operational ownership.

The demo supplies evidence for that decision. It does not pre-commit the core
SDK or managed platform to the production architecture.
