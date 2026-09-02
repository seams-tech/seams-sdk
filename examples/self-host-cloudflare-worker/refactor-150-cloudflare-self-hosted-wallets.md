# Refactor 150: Cloudflare Self-Hosted Wallets

Date created: August 5, 2026
Cloudflare API feasibility checked: August 9, 2026
Workers routing and RP-domain boundary rechecked: August 27, 2026

Status: active product-validation plan. The first milestone remains a bounded
public-SDK deployment example. The complete plan now proves a progressive
custody path from an embedded managed wallet to an independently operable
wallet on customer-owned Cloudflare infrastructure.

## Purpose

Build a convincing, reproducible proof that an MPC wallet can begin with the
UX of an embedded managed wallet and later move to customer-operated
infrastructure without changing its public keys or addresses.

The product thesis is:

- embedded registration, recovery, and signing should remain the easy starting
  experience;
- wallet owners and operators should have a practical exit from Seams-operated
  infrastructure;
- a changed WebAuthn RP ID is handled by creating a new destination credential
  through explicit device linking, rather than by copying or rebinding the old
  passkey;
- one browser on one physical device is sufficient for that migration;
- after verified destination activation, the self-hosted wallet must operate
  with the old wallet origin, Seams runtime, and Seams control plane
  unavailable;
- the original managed signer remains a usable backup until the owner
  explicitly revokes it.

The proof should let an evaluator authorize Cloudflare, wait for an automatic
deployment, create a new wallet or migrate an existing wallet, and observe:

- one Cloudflare OAuth consent;
- five separately deployed runtime artifacts;
- role-specific secrets and private D1 stores;
- private same-account Service Bindings;
- a fixed single-tenant Gateway boundary;
- a public `workers.dev` Gateway endpoint, with optional custom-domain routing;
- new Ed25519 and ECDSA wallet registration and signing;
- one-device migration from an old RP ID to a customer-controlled destination
  RP ID;
- unchanged wallet public keys and addresses across migration;
- normal signing without Deriver participation;
- health, readiness, configuration, and key-agreement diagnostics.

The first milestone is still an SDK showcase. The complete proof extends the
existing device-link protocol across a deployment boundary, provisions fresh
destination-owned client and server material, and verifies the destination
with the source unavailable. Refactor 150 owns that narrow protocol extension,
the Cloudflare destination, and the same-device cross-RP linking experience.
It does not depend on an app-level migration or general deployment-portability
design.

`100% self-hosted operation` means destination unlock, signing, and key export
have no runtime, RP-domain, or control-plane dependency on Seams. Keeping the
old signer as an independently usable backup does not create a destination
dependency. It does retain the source signer's attack surface. The UI and
receipt distinguish independent self-hosted operation from exclusive
customer-only operation. The latter requires an explicit source revocation and
decommissioning decision. The customer and its chosen infrastructure providers
remain inside the trust model. A Cloudflare account administrator can replace
deployed Worker code, so this phrase does not claim independence from
Cloudflare or protection from a malicious customer administrator.

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
10. Destination-local recovery and backup do not gate clean-account deployment
    or cross-deployment linking. The existing signer remains an optional backup
    while those destination operations mature.
11. No compatibility path is kept for the current one-Worker example. The
    generated strict-topology demo replaces it directly.
12. The onboarding application uses one verified public Cloudflare OAuth
    client. Customers authorize only the account and scopes required by the
    deployment and may revoke that authorization from Cloudflare.
13. For a `workers.dev` deployment, the default RP ID is the customer account's
    registrable domain, `<account-subdomain>.workers.dev`. `workers.dev` itself
    is a public suffix and is never accepted as an RP ID. Worker names may
    change within the account while the account subdomain remains pinned.
14. A wallet created under a Seams-owned RP ID migrates by linking a new wallet
    authority whose passkey is created under the destination RP ID. Related
    Origin Requests are not part of the migration path because they preserve a
    liveness dependency on the old RP domain.
15. The migration UX runs on one physical device. The source and destination
    wallet origins remain isolated browser principals and exchange only a
    versioned, one-use device-link session reference through an untrusted
    coordinator.
16. Destination activation requires a fresh source-owner proof, a verified
    destination credential, exact destination origin and deployment binding,
    identical wallet public identities, and successful destination reload,
    unlock, signing, and export for both signing families.
17. Cross-deployment linking has ordinary device-link semantics: the source and
    destination authorities may remain active concurrently. Successful linking
    never fences, revokes, deletes, or retires the source. Revocation is a
    separate explicit owner operation.
18. The strict Router A/B topology is the self-hosting target. A single-Worker
    custody profile is outside this plan because it would test a different
    custody proposition.
19. The device-link change is a narrow additive branch in precise protocol
    unions. The same-deployment and cross-deployment branches have required,
    mutually exclusive fields and exhaustive handling. The implementation does
    not introduce a generalized portability framework.

## Isolation Boundary

The demo should prove that an SDK consumer can assemble the supported pieces
without becoming part of the main application.

### Allowed dependencies

Demo runtime and tooling may depend on:

- `@seams/wallet-server`;
- `@seams/wallet-server/router/cloudflare`;
- other documented public `@seams/wallet-server` exports;
- public device-linking contracts from the SDK, including the reviewed
  cross-deployment target branch;
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
  refactor-150-cloudflare-self-hosted-wallets.md
  onboarding/
    oauth.ts
    session.ts
    deployment.ts
    wallet.ts
    ui/
  linking/
    coordinator.ts
    transcript.ts
    source.ts
    destination.ts
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

## Streamlined Onboarding And Migration Experience

A new-wallet evaluator has two primary actions: deploy, then create. Migration
adds the two explicit WebAuthn confirmations required to establish a new RP
credential and authorize it from the existing wallet.

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

The default public endpoint is the Gateway's `workers.dev` hostname. Given:

```text
wallet origin: https://wallet.<account-subdomain>.workers.dev
RP ID:         <account-subdomain>.workers.dev
```

the passkey remains valid if the customer later replaces the `wallet` Worker
with another Worker in the same Cloudflare account. The account subdomain is a
durable wallet boundary and cannot be renamed after the first wallet is
created. The operator may instead select an active zone and attach a Custom
Domain before wallet creation. Cloudflare then creates the required DNS record
and certificate.

Cloudflare [documents Worker hostnames](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
as `<worker>.<account-subdomain>.workers.dev`, and Cloudflare lists `workers.dev`
in the [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat).
The [WebAuthn RP-ID rules](https://www.w3.org/TR/webauthn-3/#relying-party-identifier)
therefore permit the account subdomain as the common RP boundary and reject
`workers.dev` itself.

The wallet origin and WebAuthn RP ID are finalized before a new durable wallet
is created. Adding a Gateway hostname later does not silently change an
existing wallet's RP ID. A changed RP ID enters the migration experience below.

### 2. Create or migrate a wallet

The wallet screen is unavailable until deployment diagnostics pass:

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

An evaluator with an existing managed wallet instead selects:

```text
Move an existing wallet
```

The first migration proof uses one browser and one physical device. A
cross-deployment link coordinator embeds the old and new wallet origins as
separate origin-owned frames. The destination frame initiates a one-use
device-link session and creates its passkey under the destination RP ID. The
coordinator relays only the opaque
session reference to the source frame. The source frame displays the exact
destination origin, RP ID, deployment identity, wallet identities, and
permissions, then obtains fresh owner approval with the existing factor.

Each frame calls WebAuthn for its own origin and RP ID. The top-level page must
delegate `publickey-credentials-create` and `publickey-credentials-get` through
[Permissions Policy](https://www.w3.org/TR/webauthn-3/#sctn-iframe-guidance).
The server verifies the exact iframe origin, expected top origin when the client
supplies it, cross-origin state, challenge, and linking transcript. A parent
click is not treated as user activation inside either frame.

The parent frame is an untrusted transport. It cannot receive custody seeds,
holder or server shares, PRF output, credential private material, reusable
Wallet Sessions, Cloudflare credentials, or role secrets. Both wallet origins
load the canonical transcript from authenticated server state and compare its
digest before acting.

Phase 0 must prove that supported Chrome, Safari, and Firefox versions allow
the required embedded WebAuthn operations and expose the source wallet's
required local state under storage partitioning. If that exact path fails on a
supported browser, implementation selects a sequential top-level redirect for
that product release before migration code lands. The plan does not accumulate
two partially supported migration protocols.

Cross-deployment linking completes through these ten steps:

1. The destination creates and verifies its new credential under the exact
   destination RP ID.
2. The destination publishes its signed deployment descriptor, target client
   recipient keys, and destination server-material recipient keys.
3. The source displays the exact destination origin, RP ID, deployment digest,
   wallet identities, requested permissions, and expiry; the owner approves
   that transcript with a fresh source-wallet proof.
4. The source client creates destination-bound Ed25519 and ECDSA linked-device
   contributions using the existing source-preserving flows.
5. The source SigningWorker transforms the ECDSA server counterpart and seals
   the fresh destination server share directly to the destination
   SigningWorker. The Ed25519 contribution is likewise sealed only to the
   target-owned recipients named by the verified descriptor.
6. The destination stores the client and server packages as one inactive,
   transcript-bound installation.
7. The destination verifies that every wallet ID, wallet-key ID, public key,
   and address matches the source wallet.
8. The destination commits the fresh linked authority through the existing
   idempotent activation ordering. The Gateway publishes it as active only
   after every required role receipt passes.
9. The destination reloads, unlocks, signs, and exports Ed25519 and ECDSA keys,
   then records a self-contained activation receipt.
10. The source authority and its server participants remain intact as a usable
    backup. Only a later explicit owner revocation disables that wallet.

The independence test temporarily blocks the old origin and all managed
services, then repeats destination reload, unlock, signing, and export. It next
restores source availability and confirms the old wallet still works. These two
checks prove both destination independence and source preservation; no
automatic source retirement is part of migration.

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

### Progressive custody path

```text
embedded managed wallet
  -> customer deploys destination Router A/B
       -> destination creates a new RP-scoped passkey
            -> old wallet approves one linked authority
                 -> device linking emits destination-bound client and server material
                      -> destination activates and verifies the linked authority
                           -> both wallets remain usable until explicit revocation
```

Migration is device linking with a destination participant that belongs to a
different deployment. Each authority owns fresh client material and a matching
server counterpart for the same wallet public key. The source authority, its
shares, sessions, and signing lanes remain unchanged.

This bounded active-active state is intentional and matches ordinary device
linking. The destination never calls the source after activation. The source is
used during enrollment and remains independently available afterward as an
optional backup. An explicit owner revocation later removes the source
authority through the source-owned device-management path.

The retained source is an active authorized signer, even when the product
presents it as standby. This improves rollback safety and preserves the old
deployment's compromise surface. The approval UI and final receipt state that
tradeoff plainly and offer the separate source-revocation action.

### Cross-deployment linking boundary

The existing device-linking operating path creates another authority inside
one deployment. Migration extends that proven authority-install model across a
deployment boundary without adding a request-selected Router URL to the
ordinary linking API or creating a second migration lifecycle.

The destination link job supplies its signed deployment manifest, recipient
keys, exact tenant mapping, target origin, and target RP ID. The source resolves
that job from the one-use `LinkDeviceSessionId`, verifies the source owner's
`link_devices` authority and wallet-key manifest, and emits only contributions
encrypted to destination recipients. The destination verifies those
contributions against its pinned link job and public wallet identities before
committing a pending authority. Browser input cannot choose a Router, database,
tenant, deployment, recipient key, or signer identity.

For ECDSA, let the existing authority use client share `C1` and source server
share `S1`. The source client samples a fresh destination client share `C2` and
computes `delta = C1 - C2`. The source SigningWorker derives
`S2 = S1 + delta`, which preserves the aggregate secret and public key because
`C2 + S2 = C1 + S1`. It seals `S2` directly to the destination SigningWorker
and keeps `S1` unchanged. The client seals `C2` to the destination browser. A
raw source server share never crosses the deployment boundary.

The existing same-deployment ECDSA flow can use one SigningWorker recipient for
both the transformation input and resulting server material. The
cross-deployment branch must distinguish:

- the source SigningWorker recipient that can open `delta` and perform the
  transformation; and
- the destination SigningWorker recipient that can open the fresh `S2`
  material.

Ed25519 continues to use the existing source-preserving linked-device
activation. Its client and SigningWorker contributions are sealed to the exact
destination-owned recipients from the verified target admission keyset. The
wallet custody seed is never transferred. The linked authority remains capable
of ordinary Ed25519 and ECDSA export through the existing export flows.

The protocol change stays narrow. The existing ECDSA target preparation
replaces its single SigningWorker recipient field with one required
server-recipient union. Source contribution already carries that target, so the
new branch flows through without a parallel payload family:

```ts
type LinkedDeviceEcdsaServerRecipientTargetV2 =
  | {
      readonly kind: 'same_deployment_v2';
      readonly signingWorkerRecipientPublicKeyB64u: string;
      readonly destination?: never;
      readonly sourceTransformationRecipientPublicKeyB64u?: never;
      readonly destinationServerMaterialRecipientPublicKeyB64u?: never;
    }
  | {
      readonly kind: 'cross_deployment_v2';
      readonly destination: VerifiedLinkedDeviceDestinationV1;
      readonly sourceTransformationRecipientPublicKeyB64u: string;
      readonly destinationServerMaterialRecipientPublicKeyB64u: string;
      readonly signingWorkerRecipientPublicKeyB64u?: never;
    };

type LinkedDeviceEcdsaTargetRecipientPreparationV2 = {
  readonly activation: MpcMaterialActivationRef;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly clientRecipientPublicKeyB64u: string;
  readonly serverRecipients: LinkedDeviceEcdsaServerRecipientTargetV2;
};
```

`VerifiedLinkedDeviceDestinationV1` contains the signed deployment digest,
origin, RP ID, tenant binding, target credential, client recipient keys, and
destination role-key identities. The device-link session target also gains a
small same-deployment/cross-deployment union that commits this descriptor for
both signing families. Ed25519 keeps its current target admission and recipient
fields; the cross-deployment branch requires them to match the verified
destination descriptor.

A boundary parser verifies and normalizes the descriptor once. Core
contribution functions accept only the narrowed branch. Every switch is
exhaustive, and type fixtures reject missing cross-deployment recipients,
mixed-branch fields, broad object spreads, and unsafe construction. The affected
V1 wire shapes are replaced by required V2 discriminants at request boundaries;
no optional compatibility branch is retained.

The current same-deployment ECDSA validators require the source and target
activation records to name the same SigningWorker, and they preserve the same
SigningWorker key epoch in normal-signing state. The V2 validation relation is
branch-specific:

- `same_deployment_v2` retains every existing equality;
- `cross_deployment_v2` preserves wallet-key identity fields and requires every
  deployment-local target field to match the verified destination descriptor;
- source fields continue to match the configured source deployment;
- destination SigningWorker identity, key epoch, recipient key, activation
  reference, reservation, and storage identity come from the destination.

Phase 0 must classify every normal-signing and activation field as wallet-key
identity or deployment-local state before the V2 shape is finalized. The cross
branch changes only the latter. Its canonical binding domain is versioned and
commits the branch discriminator, destination digest, and both server recipient
keys. Rust vectors and TypeScript fixtures own that boundary. The source Worker
seals `S2` using the key already committed in the binding; it does not accept a
second unbound destination key in its completion request.

The destination begins with no wallet row. Existing same-deployment commit
code may assume that the wallet projection and key manifests already exist.
Phase 0 must verify that assumption. If present, the destination install request
gains one cross-deployment branch carrying the minimal public wallet bootstrap:
wallet ID, wallet-key IDs, public keys, manifest digest, signing-root metadata,
and destination activation references. A boundary parser verifies those public
facts against both source contributions and constructs the established
destination records. SQL rows, raw server material, source sessions, nonces,
presignatures, and source deployment epochs never appear in this request.

Every client recipient key, both ECDSA server recipient keys, the deployment
digest, source authority, wallet-key manifest, permissions, expiry, and one-use
session ID are committed into the canonical linking transcript. Recipient keys
are pairwise distinct within each family and prove possession under their
expected client or Worker roles. Ordinary same-deployment linking remains a
first-class branch of the same protocol.

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

The boundary converts that route choice into one exact RP configuration:

```ts
type SelfHostedWalletRpConfigurationV1 =
  | {
      readonly kind: 'cloudflare_account_rp_v1';
      readonly accountSubdomain: WorkersDevAccountSubdomain;
      readonly walletOrigin: WalletOrigin;
      readonly rpId: WebAuthnRpId;
    }
  | {
      readonly kind: 'custom_domain_rp_v1';
      readonly zoneId: string;
      readonly walletOrigin: WalletOrigin;
      readonly rpId: WebAuthnRpId;
    };
```

The `cloudflare_account_rp_v1` parser requires `rpId` to equal the exact
`<account-subdomain>.workers.dev` registrable domain obtained from Cloudflare.
It rejects `workers.dev`, another account's subdomain, and a Worker-specific
host where the account-level RP was selected. The custom-domain branch requires
an authorized zone and an RP ID that contains the wallet origin under normal
WebAuthn domain rules.

The authorized Cloudflare account comes from the OAuth grant. The deployment
name, resource prefix, tenant fields, Gateway origin, RP configuration, allowed
onboarding origin, and test-vector configuration are generated. Selecting a
custom domain uses a zone returned by Cloudflare; the UI does not accept an
unverified account or zone identifier.

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

The compiler remains example-specific through the clean deployment milestone.
Production promotion happens only after another concrete consumer demonstrates
the same compiler boundary and shared extraction removes more code than it
adds.

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

| Onboarding operation                              | Cloudflare surface                                                                                                                                                                                                      | Required permission                     |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Authenticate, choose an account, and consent      | [OAuth Authorization Code flow](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)                                                                                                           | OAuth client scopes selected at consent |
| Exchange and revoke authorization                 | [OAuth authorization, token, and revoke endpoints](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/)                                                                                     | OAuth protocol                          |
| Discover zones for optional custom routing        | `GET /zones` via [List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)                                                                                                                      | `Zone Zone Read`                        |
| Create role databases                             | `POST /accounts/{account_id}/d1/database` via [Create D1 Database](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/create)                                                             | `D1 Write`                              |
| Apply and verify D1 schemas                       | `POST /accounts/{account_id}/d1/database/{database_id}/query` via [D1 Database API](https://developers.cloudflare.com/api/resources/d1/subresources/database/)                                                          | `D1 Write`                              |
| Upload each Worker and its non-secret bindings    | `PUT /accounts/{account_id}/workers/scripts/{script_name}` via [Workers Scripts API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/)                                                     | `Workers Scripts Write`                 |
| Describe D1, Durable Object, and Service Bindings | Worker multipart [`metadata.bindings`](https://developers.cloudflare.com/workers/configuration/multipart-upload-metadata/)                                                                                              | `Workers Scripts Write`                 |
| Install role-owned secrets                        | `PATCH /accounts/{account_id}/workers/scripts/{script_name}/secrets-bulk` via [Bulk Secrets API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/bulk_update) | `Workers Scripts Write`                 |
| Read or create the account's `workers.dev` name   | `GET` or `PUT /accounts/{account_id}/workers/subdomain` via [Workers Subdomains API](https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/)                                                  | `Workers Scripts Write`                 |
| Publish the default Gateway endpoint              | `POST /accounts/{account_id}/workers/scripts/{script_name}/subdomain` via [Workers Scripts API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/)                                          | `Workers Scripts Write`                 |
| Attach an optional custom hostname                | `PUT /accounts/{account_id}/workers/domains` via [Attach Domain](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/)                                                          | `Workers Scripts Write`                 |

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
- the pinned wallet origin, RP ID, and Workers account subdomain or verified
  custom-domain identity;
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

Cross-deployment linking uses the existing device-link session lifecycle. It
does not add `SelfHostedWalletMigrationStateV1`, a cutover state, or a source
retirement transition. The only protocol-state extension is the
`cross_deployment_v2` target branch carried by target preparation, source
contribution, and the resulting installation receipt.

Each existing link transition consumes the exact preceding state and canonical
transcript digest. The destination completes the session only after its
authority and role-local material are active and the destination verification
receipt passes. Source state is absent from that receipt because successful
linking does not mutate the source authority or source signer material.

Browser messages carry only a one-use `LinkDeviceSessionId`; they cannot
propose a lifecycle state, destination deployment, tenant, RP ID, recipient
key, or authority record. A failed or abandoned link leaves the source
unchanged and the destination installation inactive. Destination cleanup is
scoped to that pending link session and is idempotent.

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

The clean-wallet path imports no production state. The cross-deployment path
accepts only a verified linked-device destination descriptor and encrypted
curve-specific contribution packages at the destination boundary. It never
copies a managed D1 database, wallet custody seed, raw source server share,
deployment KEK, session issuer, CI credential, complete private key, or
cross-tenant record. Source mutation is outside destination installation.

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

Cross-deployment link doctor additionally verifies:

- the target passkey RP ID and exact destination origin;
- source and destination wallet ID, key ID, public-key, and address equality;
- the destination deployment digest, role identities, recipient-key proofs,
  and role-owned storage identity;
- distinct source-transformation and destination-server-material recipients;
- the active destination authority and its exact auth method;
- destination reload, unlock, Ed25519 and ECDSA signing, and both export paths;
- absence of destination calls to the old RP domain or managed runtime after
  activation;
- source authority preservation after the source test environment is restored.

Doctor returns a structured exhaustive result and concise human output. It does
not infer readiness from a diagnostics object used for control flow; each check
produces an explicit pass or failure branch.

## Cross-Deployment Link Independence

The self-hosting proof is complete when the destination can perform its normal
wallet operations without reaching the source deployment. Keeping the source
available as a backup is compatible with that property because destination
operation does not depend on source availability.

The complete proof must demonstrate:

1. bootstrap of empty destination resources and fresh role secrets;
2. creation of a destination credential under the exact destination RP ID;
3. signed publication and proof of the destination's client and server
   recipient keys;
4. fresh source-owner approval of the exact link transcript;
5. creation of destination-bound Ed25519 contributions and the ECDSA `C2` and
   `S2` shares without copying `S1` or the wallet custody seed;
6. activation of one fresh destination authority with unchanged wallet IDs,
   wallet-key IDs, public keys, and addresses;
7. destination reload, unlock, Ed25519 and ECDSA export, and both signing flows;
8. continued destination operation while the old origin and managed services
   are blocked;
9. continued source operation after the source test environment is restored;
10. source revocation only through a separate, explicit owner action.

Destination independence also requires the linked authority to act as Device 1
for a later ordinary device link while the managed source is blocked. Phase 0
must verify that the installed Ed25519 Yao Client root, ECDSA client share,
permissions, and export-capable state already support that flow. A failure here
limits the claim to independent signing and export until the device-growth gap
is fixed.

Cloudflare Time Travel bookmarks and Durable Object PITR bookmarks remain
useful destination-local operational aids within their retention windows.
Destination backup and disaster recovery need a separate design and do not
block this cross-deployment link proof.

Both backends can sign for the same public wallet after linking. Applications
that submit chain transactions from both at once must coordinate chain-specific
nonces, sequence numbers, and replacement policy. The source is presented as a
standby backup in this experience; simultaneous transaction orchestration is
outside the linking protocol.

Source revocation remains a source-scoped operation because the deployments
have independent authority stores. The destination UI may relay an exact,
owner-signed revocation request to the source, and the source must return a
verifiable receipt. Once accepted, source decommissioning disables the source
authority and retires that wallet's client-specific server participants.
Source unavailability makes that signer unreachable; it does not prove
cryptographic erasure. The first proof adds no replicated revocation registry
or destination-controlled source deletion.

The revocation receipt proves that the source deployment accepted and enforced
the authority transition. It cannot prove physical erasure of every historical
secret copy. Documentation must avoid presenting it as cryptographic
invalidation of a copied signer while the wallet public key remains unchanged.

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
- [ ] Prove in hosted Chrome, Safari, and Firefox that two exact cross-origin
      wallet frames can perform the required `get` and `create` ceremonies with
      explicit frame-owned clicks and Permissions Policy delegation.
- [ ] Record `origin`, `crossOrigin`, and `topOrigin` behavior for both frames
      and prove exact server-side verification.
- [ ] Verify whether the embedded source origin can read the wallet-local state
      required for linking under each browser's storage partitioning. If it
      cannot, select the sequential top-level redirect path before Phase 1 and
      remove the two-frame path from the implementation plan.
- [ ] Prove that `<account-subdomain>.workers.dev` is accepted as the RP ID from
      two Worker origins in one account and that `workers.dev` and another
      account's subdomain are rejected.
- [ ] Inventory the exact public device-link target-preparation, source-
      contribution, destination-installation, export, and receipt contracts.
      Identify the smallest payload union that can own the cross-deployment
      target branch.
- [ ] Classify every ECDSA activation and normal-signing field as preserved
      wallet-key identity or destination-owned deployment state. Locate every
      same-Worker and same-key-epoch assertion that needs branch-specific V2
      validation.
- [ ] Determine the minimal public wallet projection required when the
      destination has no existing wallet row; prove the existing install path
      can consume it after one boundary parser.
- [ ] Prove the ECDSA two-recipient path: `delta` opens only in the source
      SigningWorker, `S2` opens only in the destination SigningWorker, the
      destination public key is unchanged, and `S1` remains usable at source.
- [ ] Prove the existing Ed25519 source-preserving activation against
      destination-owned client and SigningWorker recipients.
- [ ] Prove both linked-authority export flows without transferring the wallet
      custody seed.
- [ ] With the managed source blocked, prove the destination linked authority
      can act as Device 1 for another ordinary link. Record any missing
      permission or retained Ed25519 Yao Client root requirement before
      implementation.
- [ ] Inventory the exact source-scoped owner-revocation operation and receipt.
      Keep cross-deployment revocation out of the link completion transaction.
      If last-owner protection blocks it, specify a separate owner-confirmed
      source-wallet decommission action instead of weakening ordinary device
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

### Phase 4: prove one-device cross-RP linking

- [ ] Add the versioned cross-deployment link transcript and server-held
      one-use rendezvous using the existing device-link lifecycle.
- [ ] Add the selected same-device coordinator from Phase 0. The browser relay
      carries only a `LinkDeviceSessionId` and validates exact message sources
      and origins.
- [ ] Create and verify the destination passkey under the pinned customer RP
      ID before it receives wallet authority.
- [ ] Display the destination origin, RP ID, deployment digest, wallet public
      identities, permissions, expiry, and the fact that the source wallet will
      remain active inside the source-owned approval surface.
- [ ] Obtain fresh source-owner proof and bind it to the exact target
      credential and canonical link transcript.
- [ ] Add one required cross-deployment variant to the narrowest existing
      target-preparation and source-contribution payload union. Use exhaustive
      switches and branch-specific builders; reject partial or mixed variants
      at the request boundary.
- [ ] Split the ECDSA source-transformation recipient from the destination-
      server-material recipient in that branch. Preserve the existing
      same-deployment behavior.
- [ ] Version the ECDSA binding and enforce branch-specific activation,
      SigningWorker, key-epoch, and recipient validation in Rust and
      TypeScript.
- [ ] Route the existing Ed25519 source-preserving contributions to the
      destination-owned client and SigningWorker recipients.
- [ ] Add the minimal cross-deployment destination-install branch for a verified
      public wallet projection when no destination wallet row exists.
- [ ] Install a fresh linked authority and role-local signer material without
      transferring the wallet custody seed or raw source server shares through
      the coordinator.
- [ ] Reuse the existing inactive-reservation and activation receipts across
      destination roles. Publish the Gateway authority only after all required
      commits pass; make retry and pending-reservation cleanup idempotent.
- [ ] Verify identical wallet IDs, wallet-key IDs, public keys, and addresses,
      then reload, unlock, sign, and export both signing families from the
      destination.
- [ ] Disable the old origin and managed routes in the test environment and
      repeat destination reload, unlock, signing, and export without Related
      Origin Requests or source calls.
- [ ] Restore the old origin and managed routes and prove the original wallet
      can still reload, unlock, and sign.

### Phase 5: prove source preservation and explicit revocation

- [ ] Verify that successful destination activation changes no source authority,
      server share, signing lane, or source credential state.
- [ ] Verify that destination failure or abandonment leaves the source usable
      and all destination material inactive or scoped for cleanup.
- [ ] Keep the source visible as an optional backup after link completion.
- [ ] With the source blocked, link and revoke a third test authority from the
      destination to prove that future device management is self-hosted.
- [ ] Exercise the source-scoped explicit owner-revocation path as a separate
      opt-in test and prove the source stops working only after the source
      accepts that action and returns its receipt.
- [ ] Document the concurrency warning for applications that submit transactions
      from both active signers and require chain-specific nonce coordination.
- [ ] Record destination-local backup and disaster recovery as future work
      without adding a portability package to this protocol.

### Phase 6: package and publish the proof

- [ ] Make the example work with packed or published public SDK packages.
- [ ] Publish the exact Cloudflare OAuth scopes, quotas, costs, and optional
      custom-domain prerequisites.
- [ ] Document the RP-ID boundary, same-account Worker portability, changed-RP
      linking ceremony, retained source backup, explicit revocation, recovery
      limits, and administrator trust model.
- [ ] Run the two-action walkthrough against a clean dedicated Cloudflare
      account without entering a token, resource name, tenant ID, RPC URL, or
      relayer credential.
- [ ] Run the one-device managed-to-self-hosted walkthrough and record its
      destination-independent link receipt.
- [ ] Replace the existing README with the verified onboarding walkthrough and
      migration, recovery, and advanced CLI notes.

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
- a `workers.dev` route derives the exact account-level RP ID and rejects the
  public suffix, another account's subdomain, and an unpinned account-subdomain
  change;
- optional Custom Domain attachment accepts only a zone in the authorized
  account and completes before durable wallet creation;
- Ed25519 and ECDSA wallets register and sign through the strict topology;
- normal signing produces zero Deriver calls;
- the fixed tenant scope is used regardless of caller-supplied tenant-like
  headers or fields;
- hosted console, billing, support, and membership routes are unavailable;
- pre-wallet apply retries are idempotent;
- cleanup targets only the exact pre-wallet resources in the deployment job;
- a source passkey and destination passkey with different RP IDs can authorize
  the same wallet through one-device linking;
- iframe messages with the wrong source window, origin, version, link session
  ID, or transcript digest fail before lifecycle mutation;
- WebAuthn verification requires the exact source or destination origin and
  expected embedded top origin;
- migration preserves every wallet ID, wallet-key ID, public key, and address;
- the same-deployment payload branch rejects cross-deployment fields, while the
  cross-deployment branch requires the signed destination descriptor, source
  transformation recipient, and destination server-material recipient;
- type fixtures reject missing recipients, mixed variants, unsafe casts, broad
  spreads, and non-exhaustive switches for the deployment-target union;
- ECDSA client, source-transformation, and destination-server-material
  recipient keys are pairwise distinct and prove possession under their
  expected client, source Worker, and destination Worker roles;
- ECDSA linking preserves the aggregate public key, leaves `S1` unchanged, and
  makes `S2` decryptable only by the destination SigningWorker;
- same-deployment ECDSA validation retains its Worker and key-epoch equalities,
  while cross-deployment validation admits only destination-local values from
  the signed descriptor;
- Ed25519 contributions are decryptable only by the target-owned client and
  SigningWorker recipients in the verified admission keyset;
- an empty destination can construct only the verified public wallet projection
  and fresh destination-owned authority records required by the link;
- a failed destination install leaves the source active and creates no active
  destination authority;
- a failure injected before or after each destination role commit leaves the
  Gateway authority unpublished, supports idempotent retry, and exposes no
  half-active signing path;
- replaying source approval, destination credential evidence, installation,
  activation, or acknowledgement creates no duplicate authority or signing
  lane;
- destination reload, unlock, both exports, and both signing flows succeed
  after the old domain and managed endpoints are disabled;
- restoring the old domain and managed endpoints shows that the source wallet
  remains usable after successful destination activation;
- source authority removal occurs only after a separate explicit owner
  revocation request;
- destination runtime tracing records no call to the source deployment after
  activation;
- while the source is blocked, the destination can act as Device 1 to add and
  revoke a third test authority;
- a destination-local revocation record alone has no effect on the source; the
  source stops only after accepting an explicit owner-signed source request;
- no cross-deployment link request fetches or depends on the old RP ID's
  `/.well-known/webauthn` resource.

The suite does not add source-text guards. Public-boundary isolation is proven
by building the packed example outside the monorepo and by exercising the
resulting deployment.

## Definition Of Done

The deployment milestone is complete when:

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

The progressive self-hosting thesis is complete when:

1. An existing managed Ed25519 and ECDSA wallet enters a one-device migration
   from its old wallet origin.
2. The destination creates a new passkey under the pinned customer RP ID; the
   existing credential remains scoped to the old RP ID.
3. The source owner explicitly approves the exact destination deployment,
   origin, RP ID, credential, permissions, wallet identities, and expiry.
4. One narrow cross-deployment device-link variant carries exact destination
   recipient and deployment bindings through type-safe, exhaustive payloads.
5. The source emits fresh destination-bound Ed25519 contributions and derives
   ECDSA `C2` and `S2` without exporting the wallet custody seed, `S1`, shared
   managed deployment secrets, or raw databases.
6. Device linking installs one fresh destination authority while preserving
   every wallet ID, wallet-key ID, public key, and address.
7. Destination reload, unlock, Ed25519 export, ECDSA export, Ed25519 signing,
   and ECDSA signing all pass.
8. Failed or abandoned migration leaves the source wallet operational and the
   destination authority inactive.
9. Successful migration leaves the source authority and server participants
   intact as a usable backup.
10. With the old RP domain, managed Gateway, and Seams control plane blocked,
    the destination still reloads, unlocks, exports, and signs. Restoring those
    services proves the source wallet still operates.
11. Only a separate explicit owner-revocation action disables the source
    wallet; migration completion itself never performs that action.
12. The final receipt lets the customer independently verify deployment,
    artifact, destination-recipient, wallet-identity, linked-authority, and
    independence-test facts.
13. Documentation states the remaining Cloudflare and customer-administrator
    trust assumptions and the limits of destination disaster recovery.
14. With the managed source blocked, the destination can act as Device 1 for a
    later link and can manage that new authority through its local deployment.

## Non-Goals

- silent or background RP-ID migration without fresh user presence;
- copying, exporting, or rewriting a passkey private key;
- using `workers.dev` as an RP ID or sharing credentials across unrelated
  Cloudflare account subdomains;
- relying on Related Origin Requests after destination activation;
- automatic source fencing, revocation, deletion, or server-participant
  retirement during migration;
- app-level migration or a general deployment-portability package;
- copying a raw source server share, wallet custody seed, complete private key,
  or managed database into the destination;
- coordinating simultaneous chain transaction nonces across both active
  backends;
- destination disaster recovery or destructive restore in the first migration
  proof;
- a single-Worker custody profile;
- a production self-hosting support commitment before every progressive
  self-hosting definition-of-done item passes;
- a repository-wide `seams` CLI;
- a general administrator console or self-host membership system;
- billing, support access, organization switching, sponsorship, or managed
  relayers;
- Kubernetes, AWS, GCP, generic OCI, or multi-account role isolation;
- refactoring the managed deployment pipeline before the demo works;
- introducing global deployment-mode or tenant-context types for the demo;
- preserving compatibility with the retired one-Worker example.

## Future Production Work

After the proof passes, productionization promotes the demonstrated boundaries
without creating a second device-link protocol. A supported release must
address:

- a stable CLI and update policy;
- production administrator authentication and authorization;
- artifact rollback after wallets are active;
- customer monitoring and alert delivery;
- production chain funding and sponsorship;
- operational approval, audit, and support for cross-deployment linked-device
  activation and explicit source revocation;
- browser support policy for the selected one-device migration surface;
- destination-local backup, recovery-package rotation, and restore drills;
- provider support and operational ownership.

The clean deployment milestone supplies early SDK evidence. The
source-unavailable destination test and source-preservation test supply the
evidence needed for the stronger product promise: embedded-wallet UX with a
practical path to customer-controlled operation and an optional managed backup.
