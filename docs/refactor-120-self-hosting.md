# Single-Tenant Self-Hosting

Date created: August 5, 2026

Status: active implementation plan. This refactor creates the production
single-tenant destination required by
[Refactor 115](./refactor-115-deployment-portability.md). Tenant export,
wallet-key handoff capsules, import, and managed cutover remain owned by
Refactor 115.

## Decision Summary

1. The first supported self-host profile is a customer-owned Cloudflare
   account running the strict Router A/B topology.
2. Single tenant means one fixed deployment tenant. It may contain many human
   users, wallets, wallet keys, devices, agents, and Agent Wallets.
3. The Router, Deriver A, Deriver B, and SigningWorker remain separate roles
   with separate secrets and private stores. Self-hosting does not collapse
   the signing architecture into one process or secret bag.
4. The operator provides one small deployment specification and a short-lived
   Cloudflare credential. A bootstrap command generates and installs the
   internal environment variables, secrets, bindings, databases, keysets, and
   deployment manifest.
5. The destination generates fresh operational secrets. Hosted Seams role
   roots, KEKs, service credentials, session keys, relayer keys, databases,
   and CI credentials never move into the customer deployment.
6. Runtime records retain a required `TenantContext`. The self-hosted request
   boundary supplies one fixed configured context rather than resolving a
   caller-selected tenant.
7. The first release excludes the hosted control plane: organization
   switching, billing, support access, hosted membership, multi-project
   routing, and platform-wide administration.
8. Self-host initialization and tenant migration are separate ceremonies. A
   customer can deploy and operate a new empty self-hosted tenant before the
   Refactor 115 import path is complete.
9. The bootstrapper emits an encrypted deployment recovery package containing
   customer-owned operational recovery material. This is separate from the
   tenant portability package used to move wallets.
10. Tests prove the supported operating path. This refactor does not add
    source guards for historical routes, fields, deployment shapes, or names.

## Goal

Make this the complete operator experience for a new customer-owned
single-tenant deployment:

```text
seams self-host init --spec seams.self-host.json
seams self-host apply
seams self-host doctor
```

After those commands, the customer has an empty production deployment that
can register new wallets, authenticate owners, sign, recover, export, operate
agents, and receive a Refactor 115 tenant import.

The operator must not hand-author the internal Router A/B environment matrix
or manually copy secrets between roles.

## Relationship To Refactor 115

Refactor 120 owns the destination substrate:

- single-tenant deployment specification;
- Cloudflare resource provisioning;
- role configuration compilation;
- independent secret generation and installation;
- fixed tenant-context resolution;
- customer domains and wallet origin;
- deployment manifest, health checks, backup, and restore;
- the empty destination import recipient and staging boundary.

Refactor 115 owns movement of an existing tenant:

- managed tenant eligibility and export authorization;
- `TenantPortabilityPackageV1`;
- Ed25519 and ECDSA server-participant handoff capsules;
- wallet, credential, recovery, and agent projections;
- destination import and public-key continuity verification;
- source fencing, activation, revocation, and receipts.

The dependency order is:

```text
Refactor 120: create and verify an empty destination
  -> Refactor 115: export one managed tenant
       -> import into the fixed destination tenant
            -> verify identical wallet public keys and addresses
                 -> activate destination and revoke source
```

## Current State

### Hosted deployment pipeline

The production deployment path is designed for Seams-operated staging and
production environments:

- [`deployment/targets.json`](../deployment/targets.json) describes the two
  managed targets and their component ownership;
- [`generate-github-env-values.mjs`](../crates/router-ab-cloudflare/scripts/generate-github-env-values.mjs)
  prepares GitHub environment values and managed deployment secrets;
- [`gateway-deployment-config.mjs`](../packages/console-server-ts/scripts/gateway-deployment-config.mjs)
  parses the managed Gateway configuration;
- the deployment workflows assume Seams-owned GitHub environments,
  Cloudflare resources, service names, domains, and operational authority;
- the Gateway and console include hosted concerns such as billing, managed
  membership, support, platform policy, and multi-tenant routing.

These components contain useful production role builders and validation.
Their operator surface is the managed platform surface.

### Local Router A/B initializer

The local Router A/B tooling already demonstrates useful mechanics:

- generate a complete role graph from one command;
- create role-specific local configurations;
- wire Router, Deriver A, Deriver B, and SigningWorker;
- apply local schemas and run health checks;
- reject wrong-role material.

It is a development tool. It may derive fixture material from one seed, write
plaintext local environment files, use local transports, and assume a trusted
developer workstation. The production bootstrapper may reuse its precise
builders and validation shapes. It must generate independent randomness and
install private values directly into the destination secret manager.

### Existing self-host example

[`examples/self-host-cloudflare-worker`](../examples/self-host-cloudflare-worker)
is a useful SDK example for a minimal signing Worker. It is not a complete
self-host deployment. It currently lacks the full strict role topology,
resource provisioner, fixed tenant domain, production secret installation,
customer domain setup, operational verification, backup, and import staging.

Refactor 120 replaces this partial example with a generated example backed by
the same deployment compiler used by the supported CLI.

## Supported Topology

The first production profile is:

```text
self_hosted_cloudflare_single_tenant_v1
```

It contains:

```text
Customer wallet origin / Gateway
  -> MPCRouter
       -> Deriver A Worker -> private Deriver A D1
       -> Deriver B Worker -> private Deriver B D1
       -> SigningWorker    -> private SigningWorker D1

Gateway
  -> fixed TenantContext
  -> wallet/auth/policy/audit D1
  -> customer relayer configuration
  -> customer logs and alert destinations
```

Service Bindings are preferred for same-account private role calls. Public
HTTP exposure is limited to the reviewed Gateway and public protocol routes.
Deriver and SigningWorker administrative and storage surfaces remain private.

The Cloudflare account administrator remains inside the first profile's trust
assumption. Moving roles into separate Cloudflare accounts or other providers
requires a separately reviewed profile.

## Single-Tenant Domain Model

The deployment mode is an exhaustive union:

```ts
type DeploymentTenantMode =
  | {
      kind: 'managed_multi_tenant_v1';
      deploymentId: DeploymentId;
      tenantResolution: 'signed_request_and_server_membership';
    }
  | {
      kind: 'self_hosted_single_tenant_v1';
      deploymentId: DeploymentId;
      tenantId: TenantId;
      projectId: ProjectId;
      environmentId: EnvironmentId;
      tenantResolution: 'fixed_deployment_tenant';
    };
```

The self-hosted adapter creates this required context at the request boundary:

```ts
type TenantContext = {
  deploymentId: DeploymentId;
  tenantId: TenantId;
  projectId: ProjectId;
  environmentId: EnvironmentId;
};
```

Core wallet, signing, authorization, budget, recovery, and audit functions
continue to require `TenantContext`. A self-hosted route cannot select another
tenant through a request field, header, token claim, or database locator.

Storage schemas keep tenant identity. This makes backup records self-
describing and preserves a symmetric path from self-hosted back to managed
Seams without creating a second set of single-tenant record types.

## Operator-Facing Specification

The customer maintains one non-secret specification:

```ts
type SelfHostedDeploymentSpecV1 = {
  kind: 'self_hosted_deployment_spec_v1';
  deploymentId: DeploymentId;
  tenant: {
    tenantId: TenantId;
    projectId: ProjectId;
    environmentId: EnvironmentId;
  };
  provider: {
    kind: 'cloudflare_v1';
    accountId: CloudflareAccountId;
    resourcePrefix: CloudflareResourcePrefix;
  };
  origins: {
    walletOrigin: WalletOrigin;
    rpId: WebAuthnRpId;
    allowedAppOrigins: readonly [AppOrigin, ...AppOrigin[]];
  };
  chains: SelfHostedChainConfiguration;
  administration: SelfHostedAdministrationConfiguration;
  observability: SelfHostedObservabilityConfiguration;
  backupRecipient: PortabilityPackageRecipient;
};
```

Chain configuration uses explicit branches:

```ts
type SelfHostedNearConfiguration =
  | { kind: 'disabled' }
  | {
      kind: 'customer_relayer_v1';
      networkId: NearNetworkId;
      rpcUrl: HttpsUrl;
      relayerAccountId: NearAccountId;
      relayerCredentialSource: 'bootstrap_secret_input';
    };

type SelfHostedEvmConfiguration =
  | { kind: 'disabled' }
  | {
      kind: 'customer_rpc_v1';
      chains: readonly [SelfHostedEvmChainV1, ...SelfHostedEvmChainV1[]];
      sponsorship: 'disabled' | 'customer_policy_v1';
    };

type SelfHostedChainConfiguration = {
  near: SelfHostedNearConfiguration;
  evm: SelfHostedEvmConfiguration;
};
```

Cloudflare credentials, relayer private keys, KMS credentials, and backup
private keys are supplied through interactive input, process-local secret
input, or a customer secret-manager reference. They never enter the spec,
manifest, logs, generated config files, or command history.

## Generated Deployment State

### Public deployment manifest

Bootstrap emits a signed, content-addressed `SelfHostedDeploymentManifestV1`:

```ts
type SelfHostedDeploymentManifestV1 = {
  kind: 'self_hosted_deployment_manifest_v1';
  deploymentId: DeploymentId;
  tenantContext: TenantContext;
  profile: 'self_hosted_cloudflare_single_tenant_v1';
  artifactDigests: SelfHostedArtifactDigestsV1;
  resources: SelfHostedResourceManifestV1;
  publicKeyset: RouterAbPublicKeysetV2;
  origins: SelfHostedOriginManifestV1;
  schemaVersions: SelfHostedSchemaVersionsV1;
  createdAtMs: number;
  manifestDigestB64u: string;
  signatureB64u: string;
};
```

The manifest contains resource identifiers, public keys, key epochs, artifact
digests, origins, schema versions, and health endpoints. It contains no secret
values or private storage credentials.

### Private role state

Bootstrap generates independent private state for each owner:

| Owner | Private state installed directly into that owner |
| --- | --- |
| Gateway | session issuer keys, ceremony keys, internal-service credential, customer route secrets |
| MPCRouter | internal-service credential reference and private routing state |
| Deriver A | A root share, role-private D1 KEK, envelope private key, peer-signing key |
| Deriver B | B root share, role-private D1 KEK, envelope private key, peer-signing key |
| SigningWorker | role-private D1 KEK, server-output private key, nonce and presignature protection keys |

The bootstrapper never derives production roles from a retained master seed.
Temporary plaintext is scoped to the generating process, installed once, and
zeroized after the recovery package is confirmed.

### Local bootstrap state

The CLI keeps one non-secret local state file containing:

- deployment and tenant identities;
- Cloudflare resource identifiers;
- artifact and manifest digests;
- completed bootstrap phase;
- health and backup verification timestamps.

It stores secret references, never secret values. Losing this file does not
destroy the deployment; `seams self-host discover` reconstructs it from the
signed manifest and customer-owned Cloudflare resources.

## Deployment Compiler

Refactor the existing pipeline into two layers:

```text
shared role configuration compiler
  <- managed deployment adapter
  <- self-hosted Cloudflare adapter
```

The shared compiler accepts precise current-domain inputs and returns exact
role branches:

- Gateway public config and private secret installation plan;
- MPCRouter bindings and policy;
- Deriver A public config and A-only secret plan;
- Deriver B public config and B-only secret plan;
- SigningWorker public config and SigningWorker-only secret plan;
- D1 migration plan;
- deployment manifest inputs;
- health and canary plan.

The compiler does not call Cloudflare, GitHub, Wrangler, or the filesystem. It
does not understand staging, production, billing, or managed organization
membership.

Provider adapters consume the compiled plan. The existing managed path keeps
its GitHub environment and Seams control-plane integration. The self-hosted
adapter creates customer resources and installs the same exact role outputs
without passing through hosted deployment configuration.

## Bootstrap Lifecycle

Bootstrap state is a discriminated union:

```ts
type SelfHostedBootstrapState =
  | { state: 'planned'; planDigestB64u: string }
  | { state: 'resources_created'; resourceManifestDigestB64u: string }
  | { state: 'secrets_installed'; secretReceiptDigestB64u: string }
  | { state: 'artifacts_deployed'; artifactReceiptDigestB64u: string }
  | { state: 'schemas_applied'; schemaReceiptDigestB64u: string }
  | { state: 'verified'; doctorReceiptDigestB64u: string }
  | { state: 'active_empty'; deploymentManifestDigestB64u: string };
```

Each transition is idempotent for one `deploymentId` and plan digest. A retry
continues from the last verified phase. A different plan cannot mutate an
existing deployment without an explicit reviewed update operation.

### `self-host init`

1. Parse and normalize `SelfHostedDeploymentSpecV1`.
2. Verify Cloudflare account authority, domains, RP ID, app origins, resource
   names, chain endpoints, backup recipient, and required quotas.
3. Resolve reviewed artifact digests for every role.
4. Compile the complete public and private role plan.
5. Show the customer a secret-free resource and trust summary.
6. Create an encrypted local bootstrap journal.

`init` performs no remote mutation unless the operator explicitly chooses an
interactive `--apply` branch.

### `self-host apply`

1. Create role-owned D1 databases and required Durable Object namespaces.
2. Generate independent role keys, roots, KEKs, issuer keys, and internal
   credentials in memory.
3. Install each private value directly into its owning Worker or selected
   customer secret manager.
4. Deploy pinned Router, Deriver A, Deriver B, SigningWorker, and Gateway
   artifacts.
5. Create fixed Service Bindings and customer domain routes.
6. Apply current schemas to the exact owning databases.
7. Publish the signed public keyset and deployment manifest.
8. Run `doctor` against the empty deployment.
9. Produce and verify `SelfHostedDeploymentRecoveryPackageV1`.
10. Mark the deployment `active_empty` and zeroize temporary plaintext.

### Failure cleanup

Before `active_empty`, the journal records every resource created by the
current plan. An explicit `seams self-host cleanup-failed` command removes only
those exact resources after showing their identifiers and confirming that no
wallet has been activated.

The normal deployment destroy path is a separate high-assurance operation. It
requires a current recovery package and proof that no active wallet authority
would become unavailable.

## Fixed Tenant Runtime

### Request boundary

The self-host Gateway constructs its `TenantContext` from signed deployment
configuration. Public requests contain wallet, credential, session, operation,
and agent identities only. They do not carry organization, project,
environment, database, schema, or deployment selectors.

### Storage

The first profile uses dedicated customer-owned databases:

- Gateway wallet, authentication, policy, budget, and audit state;
- Deriver A private role state;
- Deriver B private role state;
- SigningWorker private signing, nonce, and presignature state.

All records bind the fixed `TenantContext`, deployment ID, role, storage ID,
and relevant key epoch in their persistence boundary. Dedicated databases
simplify operations while preserving the same domain isolation used by the
managed implementation.

### Administration

The hosted console is not copied into the first self-host profile. Bootstrap
creates one destination administrator through a customer-owned authentication
configuration. Deployment operations initially use the local CLI and
customer Cloudflare authority.

Wallet ownership remains separate from deployment administration. An
administrator cannot sign for users or unwrap owner custody merely because it
controls the self-host deployment.

A dedicated self-host administration UI may later consume the same management
API. It must not import hosted billing, support access, organization switching,
or platform membership semantics.

## Customer Domains And Credentials

The preferred configuration preserves a customer-owned wallet origin before
and after migration:

```text
wallet.customer.example
```

Bootstrap verifies:

- the wallet origin is HTTPS;
- the RP ID is valid for the customer domain;
- every app origin is explicit;
- CORS, iframe, CSP, cookie, and related-origin configuration agree;
- DNS and Cloudflare custom-domain ownership are available;
- the wallet origin points at the destination only during activation.

Keeping the origin and RP ID stable allows existing passkeys and origin-bound
browser storage to remain usable. A changed RP ID requires owner recovery and
credential enrollment; passkey private keys are never exported.

## Relayers, Gas, And Chain Configuration

The customer supplies or explicitly disables chain infrastructure.

For NEAR, the customer owns the relayer account, funding, RPC choice, and
private credential. Bootstrap installs the credential into the exact owning
runtime and records only the public account and network in the manifest.

For EVM-family chains, the customer owns RPC endpoints and any sponsorship
funding or policy. Sponsorship defaults to disabled. Enabling it requires an
explicit customer policy and funded execution identity.

Managed Seams relayer keys, gas budgets, pricing, billing, and sponsorship
accounts never enter the self-hosted deployment.

## Observability And Operations

The first production profile requires:

- structured role-local logs with no secret values;
- health and readiness checks for every public and private role;
- customer-owned alert destinations;
- D1 backup and restore procedures;
- deployment manifest and artifact-digest monitoring;
- key, certificate, domain, and backup freshness reporting;
- zero-Deriver-call evidence during normal signing;
- an operator-visible audit trail for bootstrap, updates, backup, restore,
  import staging, and activation.

Hosted Seams telemetry endpoints are not a required dependency. Customers may
choose an observability exporter through an explicit adapter.

## Deployment Recovery

`SelfHostedDeploymentRecoveryPackageV1` protects destination operational
recovery:

- role-local private secrets in separately sealed entries;
- resource identities and schema versions;
- deployment manifest and artifact digests;
- encrypted storage snapshot references;
- recovery sequence and predecessor digest;
- restore and rotation instructions.

The package is encrypted to the customer backup recipient from the deployment
spec. The CLI must successfully decrypt and inventory the package before
bootstrap completes.

This package restores the customer's own deployment. It is distinct from
`TenantPortabilityPackageV1`, which transfers tenant wallet state from another
deployment.

Restore may create new resource IDs and runtime epochs. It must restore the
same wallet identities and destination role material required by existing
wallet execution lanes, then rotate replaceable operational credentials after
verification.

## Migration Readiness Boundary

An `active_empty` destination publishes:

- deployment manifest digest;
- fixed destination `TenantContext`;
- portability import recipient public key and key ID;
- supported package and capsule versions;
- supported wallet curves and execution lanes;
- origin and RP ID manifest;
- import staging health;
- destination activation authority policy.

Refactor 115 binds the source migration request to these values before package
construction.

Import writes only to a dedicated staging namespace. Bootstrap and ordinary
wallet routes cannot activate imported state. Activation requires the
Refactor 115 continuity receipt, source freeze receipt, destination authority,
and exact wallet-key manifest.

## CLI Surface

The first supported commands are:

```text
seams self-host init --spec <file>
seams self-host plan
seams self-host apply
seams self-host doctor
seams self-host status
seams self-host discover
seams self-host backup
seams self-host restore <deployment-recovery-package>
seams self-host cleanup-failed
```

Refactor 115 adds:

```text
seams self-host import <tenant-portability-package>
seams self-host verify-import
seams self-host activate-import
```

Commands return exhaustive result unions suitable for interactive and CI use.
Human output includes resource identities, public digests, health, and the next
required action. Secret values are never printed.

## Implementation Plan

### Phase 0: freeze the supported empty-deployment contract

- [ ] Freeze `SelfHostedDeploymentSpecV1` and its boundary parser.
- [ ] Freeze `DeploymentTenantMode` and fixed `TenantContext` construction.
- [ ] Freeze the Cloudflare resource manifest and naming rules.
- [ ] Freeze the signed deployment manifest and artifact digest format.
- [ ] Decide the first administrator authentication branch.
- [ ] Document the exact supported Near and EVM chain branches.

### Phase 1: extract the shared role compiler

- [ ] Extract pure role configuration builders from the hosted deployment
      generator and local initializer.
- [ ] Require separate Router, A, B, SigningWorker, and Gateway input branches.
- [ ] Return exact public config and private secret-installation plans.
- [ ] Keep managed GitHub, staging, production, billing, and membership inputs
      in the managed adapter.
- [ ] Make the existing managed deployment consume the shared compiler once.
- [ ] Verify one compiled role graph with the existing Router A/B health and
      signing checks.

### Phase 2: add the self-host Cloudflare provisioner

- [ ] Add `seams self-host init`, `plan`, and `apply`.
- [ ] Create dedicated role databases, namespaces, Workers, bindings, and
      domain routes.
- [ ] Generate every production secret independently.
- [ ] Install private values directly into exact role owners.
- [ ] Deploy pinned, content-addressed artifacts.
- [ ] Apply current schemas and publish the public keyset.
- [ ] Emit the signed deployment manifest and non-secret local state.

### Phase 3: add the fixed tenant Gateway

- [ ] Add the `self_hosted_single_tenant_v1` runtime branch.
- [ ] Construct one required `TenantContext` from deployment config.
- [ ] Wire current wallet, auth, policy, recovery, signing, audit, and agent
      services to the dedicated stores.
- [ ] Exclude hosted billing, support, organization switching, and platform
      membership from the artifact.
- [ ] Provision one destination administrator without granting wallet custody.
- [ ] Support new wallet registration and normal operation in an empty
      self-hosted tenant.

### Phase 4: production operations

- [ ] Add `doctor`, `status`, `discover`, and failed-bootstrap cleanup.
- [ ] Add customer domains, RP ID, CORS, iframe, cookie, and related-origin
      verification.
- [ ] Add customer relayer, RPC, sponsorship, and funding checks.
- [ ] Add customer-owned logs, alerts, D1 backup, and restore monitoring.
- [ ] Add update planning with pinned artifact and schema transitions.
- [ ] Prove retries are idempotent for one deployment and plan digest.

### Phase 5: deployment backup and restore

- [ ] Freeze `SelfHostedDeploymentRecoveryPackageV1`.
- [ ] Seal role entries independently to the customer backup recipient.
- [ ] Require a successful decrypt-and-inventory check after bootstrap.
- [ ] Restore a deleted empty deployment from the package.
- [ ] Restore a deployment containing test wallets while preserving their
      public keys and addresses.
- [ ] Rotate replaceable runtime credentials after restore.

### Phase 6: Refactor 115 import readiness

- [ ] Generate the portability import recipient and publish its digest.
- [ ] Add a tenant-scoped staging namespace and import status API.
- [ ] Bind import staging to the fixed destination tenant and manifest.
- [ ] Expose supported capsule and package versions.
- [ ] Add continuity verification hooks without implementing source export in
      this refactor.
- [ ] Hand the verified empty destination contract to Refactor 115.

### Phase 7: replace the partial example and release

- [ ] Generate the self-host Cloudflare example from the production compiler.
- [ ] Publish one operator guide covering domain, Cloudflare, chain, backup,
      and restore prerequisites.
- [ ] Publish a cost and quota checklist.
- [ ] Run a clean-account installation without repository-internal access.
- [ ] Run a full new-wallet registration, signing, recovery, export, backup,
      destruction, and restore drill.
- [ ] Mark the Cloudflare single-tenant profile supported.

## First Thin Slice

The smallest useful delivery is an empty self-hosted tenant that supports new
wallets. It does not wait for managed migration.

1. Parse one `SelfHostedDeploymentSpecV1`.
2. Compile and deploy the five runtime artifacts.
3. Create dedicated databases and fixed tenant context.
4. Generate and install independent role secrets.
5. Configure one customer wallet origin and administrator.
6. Run Router A/B health, registration, signing, and recovery once.
7. Produce and verify the deployment recovery package.

Only after this path works should implementation add portability import
staging and managed cutover.

## Validation

Positive operating-path tests prove:

- one valid spec compiles into exact role-owned configurations;
- one clean customer Cloudflare account reaches `active_empty` without manual
  environment-variable or secret editing;
- new Ed25519 and ECDSA wallets register and sign through the strict topology;
- normal signing does not invoke either Deriver;
- fixed tenant context reaches every durable record and audit event;
- customer origins and RP ID work from the real wallet iframe;
- a deployment recovery package restores the same wallet public keys and
  addresses after resource deletion;
- `doctor` verifies role reachability, key agreement, stores, origins,
  schemas, backups, and manifest digests;
- Refactor 115 can discover the import recipient and stage into the fixed
  tenant without activating wallet authority.

Failure-path tests cover realistic boundary and operational failures:

- invalid specs fail before remote mutation;
- insufficient Cloudflare authority and quota fail during preflight;
- secret installation into the wrong role fails the compiled plan;
- partial provisioning resumes idempotently or cleans up exact created
  resources;
- wrong RP ID, origin, key agreement, schema, artifact digest, or backup
  recipient blocks activation;
- failed restore never exposes an active partial deployment.

The suite does not scan for historical routes, request fields, symbols,
environment variables, or deployment shapes. Removed designs remain absent
because their implementations and documentation are deleted.

## Definition Of Done

Refactor 120 is complete when:

1. A customer starts with one Cloudflare account, one domain, chain choices,
   and a backup recipient.
2. The customer writes one non-secret deployment specification.
3. One supported CLI provisions and verifies the complete strict Router A/B
   topology without manual internal config or secret copying.
4. The deployment serves one fixed tenant and can register, authenticate,
   sign, recover, export, and operate agents for newly created wallets.
5. Hosted billing, organization switching, support, shared platform secrets,
   and multi-tenant routing are absent from the self-host artifact.
6. Every private role has independent secrets and private storage.
7. The customer can discover, diagnose, back up, destroy, and restore the
   deployment from documented commands.
8. The deployment publishes the destination manifest and import recipient
   required by Refactor 115.
9. A clean-account release drill passes using only public artifacts and
   customer-owned credentials.

## Non-Goals

- migrating an existing managed tenant; Refactor 115 owns that workflow;
- copying managed Seams environment variables, role roots, KEKs, databases,
  relayer keys, or operational credentials;
- collapsing Router A/B roles for convenience;
- removing tenant identity from domain or persistence records;
- shipping the hosted billing and organization control plane;
- supporting Kubernetes, generic OCI, AWS, GCP, or multiple Cloudflare
  accounts in the first profile;
- exporting passkey private keys;
- making an administrator equivalent to a wallet owner;
- maintaining compatibility with earlier self-host examples or deployment
  shapes;
- adding guards that search for removed historical designs.

## Decisions Required Before Implementation

- Choose the first self-host administrator authentication branch.
- Decide whether Gateway and MPCRouter remain separate Workers in the first
  customer profile or are separately deployed artifacts connected through a
  fixed Service Binding.
- Choose the Cloudflare credential scopes required by `plan`, `apply`, domain
  setup, secret installation, backup, and discovery.
- Decide whether the first release supports both Near and EVM-family chains or
  requires one enabled chain profile at a time.
- Choose the customer backup recipient required for organizations and whether
  high-entropy passphrase recovery is available in the first release.
- Define the supported artifact update and rollback policy after wallets are
  active.
