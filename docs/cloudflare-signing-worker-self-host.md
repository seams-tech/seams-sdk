# Cloudflare Signing Worker Self-Host Plan

Date updated: 2026-04-16

## Objective

Make the Cloudflare signing worker usable as a customer self-hosted SDK runtime
for availability-first MPC custody.

The first refactor should be behavior-preserving. It is primarily a
modularization and packaging effort that establishes a clean boundary between:

- the minimal server SDK code required to sign transactions after self-host
  migration
- our proprietary backend and console code for managing the SaaS
  wallet-as-a-service platform

The self-hosted worker must let a customer run the server-side threshold
signing share for their own project using their own imported `k_org`, while
preserving:

- the same wallet origin and `rpId`
- the same passkey-derived client share
- the same deterministic server share derivation for the active migration mode
- the same threshold public keys and addresses
- no per-wallet durable server secret database

This is a forward-looking refactor plan. Breaking package and API changes are
allowed where they create cleaner boundaries. The initial signing behavior
should remain unchanged until the boundary is isolated and covered by parity
tests.

## Decision

The self-hosted worker should first be extracted as a minimal signing runtime
without changing current signing behavior.

After the boundary is clean, the worker should run from an imported
project-root bundle.

The bundle contains the customer's project-level `k_org` and versioned
derivation metadata. The worker stores that root in its own Cloudflare Durable
Object and derives `k_srv_wallet` locally during signing.

The customer does not need our hosted KMS path for normal signing after cutover.

## Self-Host Semantics

Self-host migration means:

- the customer can independently operate signing for the same wallets
- the customer receives the exact project root material needed to derive the
  same server shares
- our hosted signer is disabled for that project
- our active cached copies are deleted from hosted infrastructure
- we provide audit evidence for export, disablement, and deletion actions

Self-host migration does not mean cryptographic vendor exclusion when `k_org` is
deterministically derived from a platform `master_secret`.

If we retain the relevant `master_secret` and derivation context, we can
technically rederive `k_org`. That is the explicit availability tradeoff of
deterministic derivation.

The correct product language is:

- same-wallet self-hosting is supported
- hosted signing custody is operationally retired
- the customer must trust that we will not rederive their `k_org` after
  migration
- cryptographic vendor exclusion would require a random per-project root,
  customer-generated root, or destruction of the relevant master derivation path

## Current State

The current Cloudflare relay worker is close as a runtime shell, but it is not
yet a clean self-hosted `k_org` SDK.

What is already useful:

- the worker can run in Cloudflare Workers
- the SDK exports a Durable Object threshold store
- the router already mounts threshold ECDSA routes
- threshold sessions, auth sessions, presign sessions, and key records can use
  Cloudflare Durable Objects
- the client-side passkey and PRF flows are already separate from server-side
  infrastructure

Main gaps:

- ECDSA uses `THRESHOLD_SECP256K1_MASTER_SECRET_B64U`, not `k_org`
- the server share derivation is `master_secret + relayerKeyId`
- `relayerKeyId` does not include `project_id`, `k_org_version`, or
  `wallet_key_version`
- ECDSA key records do not record project-root version or derivation version
- the Cloudflare worker example only passes the Ed25519 threshold master secret
- the shared Durable Object is still named as if it were Ed25519-only
- signing logic still has checks that require the secp256k1 master secret even
  when imported key material should be enough

## Behavior Preservation

The self-host worker refactor should not change signing behavior by default.

The first milestone is boundary extraction:

- same public threshold routes
- same request and response shapes
- same session semantics
- same presign protocol behavior
- same signature outputs for the same inputs
- same persisted record semantics
- same client SDK behavior

The initial self-host package may still use the current derivation behavior
internally. The point of the first cut is to prove that the minimal threshold
signing runtime can be built and deployed without importing proprietary SaaS
platform modules.

The `k_org` project-root model is the target root abstraction, but it should be
introduced behind explicit tests and migration steps. It should not be bundled
into the same change as route/package extraction unless the compatibility
harness proves same-wallet behavior.

Behavior-preserving acceptance criteria:

- existing hosted tests pass unchanged
- existing threshold ECDSA signing vectors remain stable
- existing Cloudflare relay behavior remains stable when using the hosted
  factory
- the self-host factory can sign with the same effective root material as the
  hosted path
- no premium SaaS module is required by the self-host bundle

## Target Architecture

The self-hosted SDK should expose a Cloudflare-first signing worker package.

Conceptually:

```ts
import {
  createSelfHostedCloudflareSigningWorker,
  ThresholdStoreDurableObject,
} from '@tatchi-xyz/sdk/self-host/cloudflare';

export { ThresholdStoreDurableObject };

export default createSelfHostedCloudflareSigningWorker();
```

The worker owns:

- threshold ECDSA HSS bootstrap routes
- threshold authorization routes
- threshold presign routes
- threshold sign routes
- project-root import/export/status routes
- health and readiness routes

The worker depends on:

- Cloudflare Durable Objects for Phase 0 root and threshold state
- caller-provided session/JWT verification hooks
- configured wallet origin and `rpId`
- imported `k_org` bundle

The worker must not require:

- our hosted KMS
- our hosted database
- our hosted relay account
- our hosted console
- per-wallet server secret storage

## Open-Source Boundary

Only the minimal threshold signing logic needed for self-hosted signing should
be open sourced as the server SDK.

The open-source self-host package should include:

- Cloudflare Worker entrypoint factory for self-hosted signing
- neutral threshold Durable Object store
- project-root import, status, verify, and delete routes
- project-root storage interfaces and Cloudflare implementation
- threshold ECDSA HSS bootstrap routes needed to establish sessions
- threshold ECDSA authorization, presign, and sign routes
- canonical `k_org -> k_srv_wallet` derivation bindings
- minimal session/JWT verification adapter interfaces
- migration bundle validation and wallet-address verification helpers
- tests and vectors required to verify same-wallet self-host migration

The open-source self-host package should not include hosted premium product
features.

Keep proprietary:

- policy engines and policy administration
- gas sponsorship and sponsored-call execution
- billing, metering, prepaid reservations, and invoice finalization
- console organization/project/environment management
- team RBAC and console approvals
- audit export products beyond minimal migration evidence
- webhook retry infrastructure
- runtime snapshot distribution and hosted config propagation
- observability ingestion and hosted incident pipelines
- managed bootstrap grant brokers and commercial API-key enforcement
- customer onboarding automation and premium dashboard surfaces
- hosted KMS provisioning services
- hosted root export approval workflows, except for the minimal export artifact
  schema needed by the self-host SDK

The boundary is:

```text
open-source server SDK:
  enough code to import k_org, derive server shares, verify sessions, and sign

proprietary hosted platform:
  everything around commercial operations, policy, sponsorship, billing,
  console management, and hosted automation
```

The self-host SDK must stay intentionally small. If a feature is not required
to sign transactions after migration, it should not be part of the self-hosted
server SDK.

The initial boundary extraction should move code, split imports, and create
package entrypoints. It should not change cryptographic derivation, request
payloads, routing behavior, or persisted state formats unless covered by the
explicit `k_org` migration phase.

## Secret Model

The self-hosted worker stores one project root per migrated project.

```text
k_org -> k_srv_wallet -> server MPC share
passkey PRF -> client MPC share
```

The self-hosted worker derives:

```text
k_srv_wallet = HKDF(
  ikm = k_org,
  salt = "wallet-server-secret:v1",
  info = encode(
    env,
    project_id,
    user_id,
    rp_id,
    scheme_id,
    key_purpose,
    wallet_key_version,
    k_org_version,
    derivation_version
  )
)
```

The derivation must be implemented in `signer-core` and exposed through the
server WASM/runtime bindings. It should not be duplicated as ad hoc
TypeScript.

## Migration Bundle

The same-wallet self-host migration bundle should include:

- `bundle_version`
- `project_id`
- `environment_id`
- `wallet_origin`
- `rp_id`
- `k_org_b64u`
- `k_org_version`
- `derivation_version`
- `scheme_id`
- `key_purpose`
- `participant_ids`
- KMS provider metadata used to create or wrap the root
- export timestamp
- export actor and approval metadata
- integrity checksum over the bundle

The bundle should not include per-wallet server shares.

Optional wallet inventory can be included or exported separately:

- `wallet_id`
- `user_id`
- `rp_id`
- `wallet_key_version`
- `k_org_version`
- threshold public key
- address
- active or retired status

The wallet inventory is metadata. It is useful for validation and import
auditing, but signing should remain derivable from `k_org` and wallet context.

## Self-Hosted Project Root Store

Add a neutral project-root store abstraction.

```ts
interface ProjectRootStore {
  getProjectRoot(projectId: string): Promise<ProjectRootRecord | null>;
  putProjectRoot(record: ProjectRootRecord): Promise<void>;
  deleteProjectRoot(projectId: string): Promise<void>;
}
```

`ProjectRootRecord` should include:

- `version`
- `projectId`
- `environmentId`
- `walletOrigin`
- `rpId`
- `kOrgB64u`
- `kOrgVersion`
- `derivationVersion`
- `createdAtMs`
- `updatedAtMs`
- `source`

Allowed `source` values:

- `hosted-export`
- `customer-import`
- `customer-generated`
- `dev`

Phase 0 self-host mode stores plaintext `kOrgB64u` in the customer's Durable
Object. Later modes can add customer-owned wrapping without changing wallet
identity.

## Required Refactors

### 1. Rename threshold store surfaces

Current naming is Ed25519-specific even though the store now holds ECDSA state
too.

Rename public SDK surfaces to neutral names:

- `ThresholdEd25519StoreDurableObject` -> `ThresholdStoreDurableObject`
- `ThresholdEd25519KeyStoreConfigInput` -> `ThresholdStoreConfigInput`
- `THRESHOLD_ED25519_DO_NAMESPACE` -> `THRESHOLD_DO_NAMESPACE`

Do this as a breaking cleanup. Do not keep duplicate old names in the primary
code path.

### 2. Add `ProjectRootProvider`

Add a server-side provider that resolves `k_org` for a project.

```ts
interface ProjectRootProvider {
  resolveKOrg(input: {
    projectId: string;
    kOrgVersion: string;
  }): Promise<
    | { ok: true; kOrg32: Uint8Array; derivationVersion: string }
    | { ok: false; code: string; message: string }
  >;
}
```

Implementations:

- Cloudflare Durable Object project-root store
- Node/Postgres project-root store
- dev in-memory store
- hosted KMS provisioning adapter for project creation and recovery

The threshold service should depend on this provider, not directly on
`THRESHOLD_SECP256K1_MASTER_SECRET_B64U`.

### 3. Move `k_srv_wallet` derivation into `signer-core`

Replace the ECDSA server-share derivation input shape.

Current shape:

```text
derive_threshold_secp256k1_relayer_share(master_secret, relayer_key_id)
```

Target shape:

```text
derive_threshold_secp256k1_server_share(k_org, wallet_context)
```

The canonical context must include:

- `project_id`
- `user_id`
- `rp_id`
- `scheme_id`
- `key_purpose`
- `wallet_key_version`
- `k_org_version`
- `derivation_version`

The function should return:

- server signing share
- server verifying share
- derivation metadata or context hash

### 4. Version ECDSA key records

Replace the current ECDSA key record with a record that explicitly names its
root source.

Minimum fields:

- `version`
- `projectId`
- `ecdsaThresholdKeyId`
- `userId`
- `rpId`
- `schemeId`
- `keyPurpose`
- `walletKeyVersion`
- `kOrgVersion`
- `derivationVersion`
- `clientVerifyingShareB64u`
- `thresholdEcdsaPublicKeyB64u`
- `ethereumAddress`
- `participantIds`
- `serverShareSource`
- `createdAtMs`
- `updatedAtMs`

`serverShareSource` should distinguish:

- `derived_from_k_org`
- `imported_integrated_record`
- `dev`

If we keep `relayerRootShare32B64u` or `relayerBackendInputB64u`, they must be
treated as cached derived material, not the canonical root of custody.

### 5. Update ECDSA bootstrap

ECDSA bootstrap should:

1. resolve project context from the session, request, or environment
2. load `k_org` through `ProjectRootProvider`
3. derive `k_srv_wallet` from canonical wallet context
4. combine with the client passkey-derived share
5. persist versioned wallet metadata

It should not require `THRESHOLD_SECP256K1_MASTER_SECRET_B64U`.

### 6. Update ECDSA signing

Signing should be able to use either:

- derived server material from `k_org`
- validated cached derived material from the key record

Any current sign-time checks that require the secp256k1 master secret should be
removed when the active key record is already bound to a self-hosted project
root.

Presign and signing session records must carry:

- `projectId`
- `kOrgVersion`
- `walletKeyVersion`
- `derivationVersion`
- `ecdsaThresholdKeyId`

### 7. Add self-host import routes

The worker should expose admin-gated import/status routes.

Recommended routes:

- `GET /self-host/healthz`
- `POST /self-host/project-root/import`
- `GET /self-host/project-root/status`
- `POST /self-host/project-root/verify-wallet`
- `POST /self-host/project-root/delete`

These routes must be disabled unless a self-host admin authentication adapter is
configured.

Import must validate:

- bundle schema
- checksum
- `project_id`
- `wallet_origin`
- `rp_id`
- `k_org` length
- supported `derivation_version`
- supported `scheme_id`

Verification should derive at least one known wallet public identity from the
bundle and compare it to the exported wallet inventory.

### 8. Add hosted export tooling

Hosted export tooling should produce a customer migration bundle.

The export flow should:

1. require customer admin authentication
2. require explicit approval
3. freeze or pin project-root version during export
4. export `k_org` and metadata
5. export wallet inventory
6. write an audit event
7. provide a checksum and import instructions

The hosted project should not be disabled until the customer confirms the
self-hosted worker validates the bundle.

### 9. Add hosted retirement tooling

After customer cutover:

1. disable hosted signing for the project
2. delete active plaintext `k_org` from hosted Durable Objects
3. delete or disable hosted wrapped recovery artifacts
4. delete cached derived server material where applicable
5. retain only non-secret audit and billing metadata
6. issue deletion and disablement attestation

The attestation should explicitly state that deterministic master derivation may
still technically allow rederivation if the platform master derivation key is
retained.

## Customer Deployment Shape

Customer self-hosting should require a small worker entrypoint.

```ts
import {
  createSelfHostedCloudflareSigningWorker,
  ThresholdStoreDurableObject,
} from '@tatchi-xyz/sdk/self-host/cloudflare';

export { ThresholdStoreDurableObject };

export default createSelfHostedCloudflareSigningWorker({
  projectId: 'proj_...',
  walletOrigin: 'https://wallet.customer.com',
  rpId: 'customer.com',
});
```

Required Cloudflare bindings:

- `THRESHOLD_STORE`

Required customer secrets or admin configuration:

- admin import token or admin auth adapter secret
- session/JWT signing secret or external session verification config

Project root material should normally be imported into the Durable Object using
the admin import route, not hard-coded into `wrangler.toml`.

Development mode can allow `K_ORG_B64U` as a secret for local testing, but that
should not be the recommended production import path.

## Cutover Flow

Recommended same-wallet self-host cutover:

1. Customer already uses a customer-owned wallet origin and stable `rpId`.
2. Hosted system pins the active `k_org_version`.
3. Hosted system exports the migration bundle.
4. Customer deploys the self-hosted Cloudflare signing worker.
5. Customer imports the project-root bundle.
6. Customer verifies one or more known wallet addresses against the bundle.
7. Customer points traffic to the self-hosted worker.
8. Customer runs signing validation.
9. Hosted system disables signing for the project.
10. Hosted system deletes active hosted root records.
11. Hosted system issues audit and deletion evidence.

In-flight sessions and presignatures are disposable. They should not be
migrated.

## Safety Requirements

The self-hosted worker must fail closed when:

- no project root is imported
- `project_id` is missing or mismatched
- `rp_id` does not match the imported bundle
- `wallet_origin` does not match configured self-host origin
- `k_org_version` is unsupported
- `derivation_version` is unsupported
- a wallet record references an unknown root version
- a threshold session references a different project root than the active key

The worker must log non-secret context for:

- project-root import
- project-root verification
- signing authorization
- root deletion
- failed derivation-context validation

Logs must never include:

- `k_org`
- `k_srv_wallet`
- client PRF material
- server signing share
- presignature secret shares

## Testing Plan

Add tests for:

- canonical `k_srv_wallet` derivation vectors
- same `k_org` plus same context produces same threshold address
- different `k_org_version` changes threshold identity
- imported self-host bundle reproduces hosted wallet address
- self-host worker signs with imported `k_org`
- missing project root fails before signing
- mismatched `rpId` fails before signing
- mismatched `project_id` fails before signing
- hosted export followed by self-host import and sign
- hosted retirement prevents hosted signing after cutover

Add an end-to-end migration harness:

1. create wallet in hosted mode
2. export project-root bundle
3. import bundle into self-host worker
4. verify same EVM address
5. sign with self-host worker
6. disable hosted project
7. assert hosted signing fails

## Phased Todo List

### Phase 0. Current-state inventory

- [ ] Document the current ECDSA bootstrap and signing call graph from
  Cloudflare route to threshold service to WASM.
- [ ] Identify every read of `THRESHOLD_SECP256K1_MASTER_SECRET_B64U`.
- [ ] Identify every persisted ECDSA record field that contains derived server
  material.
- [ ] Confirm which Cloudflare Durable Object keys are used for ECDSA key
  records, auth sessions, presign sessions, signing sessions, and
  presignatures.
- [ ] Write an explicit compatibility baseline test that captures the current
  hosted derivation output before changing derivation code.

### Phase 1. Behavior-preserving boundary extraction

- [ ] Split self-host signing routes from hosted SaaS routes without changing
  route behavior.
- [ ] Create a self-host worker factory that reuses the current threshold
  signing behavior.
- [ ] Move only the minimal threshold signing dependencies into the server SDK
  boundary.
- [ ] Add dependency-boundary checks that fail if the self-host SDK imports
  console, billing, sponsorship, policy, webhook, runtime snapshot, or hosted
  KMS modules.
- [ ] Add parity tests comparing hosted factory and self-host factory behavior
  for the same threshold signing inputs.
- [ ] Keep current persisted state formats unchanged in this phase.

### Phase 2. Root and derivation specs

- [ ] Define `ProjectRootRecord`.
- [ ] Define `ProjectRootProvider`.
- [ ] Define `ProjectRootStore`.
- [ ] Define the self-host migration bundle schema.
- [ ] Define canonical `k_srv_wallet` derivation context.
- [ ] Add signer-core test vectors for `k_org -> k_srv_wallet`.
- [ ] Add a context hash to make derivation mismatches easy to diagnose without
  logging secrets.

### Phase 3. Cloudflare project-root storage

- [ ] Extend the threshold Durable Object protocol with project-root operations.
- [ ] Store plaintext `k_org` in the customer's Durable Object for Phase 0.
- [ ] Store root metadata next to `k_org`.
- [ ] Add import, status, verify, and delete operations.
- [ ] Add an in-memory root cache inside the worker or Durable Object client
  path.
- [ ] Add fail-closed behavior when a project root is missing.

### Phase 4. ECDSA `k_org` derivation refactor

- [ ] Replace ECDSA bootstrap derivation from global master secret with
  `ProjectRootProvider.resolveKOrg`.
- [ ] Replace `relayerKeyId`-only derivation context with canonical wallet
  context.
- [ ] Add `projectId`, `kOrgVersion`, `walletKeyVersion`, and
  `derivationVersion` to ECDSA key records.
- [ ] Carry project-root metadata through ECDSA auth sessions.
- [ ] Carry project-root metadata through presign sessions.
- [ ] Carry project-root metadata through signing sessions.
- [ ] Remove secp256k1 master-secret checks from paths that can resolve or
  validate the active project root.

### Phase 5. Self-hosted Cloudflare SDK package

- [ ] Add `createSelfHostedCloudflareSigningWorker`.
- [ ] Add a neutral `ThresholdStoreDurableObject` export.
- [ ] Add a minimal self-host worker example.
- [ ] Add a Wrangler template for the customer deployment.
- [ ] Add self-host admin authentication hooks for project-root import routes.
- [ ] Add setup docs that avoid requiring `k_org` in `wrangler.toml`.

### Phase 6. Hosted export and cutover

- [ ] Add hosted project-root export tooling.
- [ ] Add wallet inventory export tooling.
- [ ] Add bundle checksum generation.
- [ ] Add self-host import verification against known wallet addresses.
- [ ] Add hosted project signing disablement.
- [ ] Add hosted root deletion flow.
- [ ] Add audit evidence for export, disablement, deletion, and the deterministic
  rederivation trust tradeoff.

### Phase 7. Hardening and cleanup

- [ ] Rename Ed25519-specific threshold store public surfaces to neutral names.
- [ ] Remove duplicate old public store names from primary docs and examples.
- [ ] Remove global ECDSA master-secret assumptions from self-hosted flows.
- [ ] Add recovery drills for exported/imported project roots.
- [ ] Add alerts for signing attempts against a retired hosted project.
- [ ] Add a wrapped-only project-root storage option after Phase 0 is stable.

## Cloudflare Worker Refactor Outline

### Step 1. Split the current worker into hosted and self-host factories

The current Cloudflare example wires all relay behavior directly in
`examples/relay-cloudflare-worker/src/worker.ts`.

Refactor toward two SDK-level factories:

```ts
createHostedCloudflareRelayWorker(...)
createSelfHostedCloudflareSigningWorker(...)
```

The self-host factory should mount only the routes required for customer-owned
signing, project-root import/status, health, readiness, and session validation.
It should not require hosted console, billing, cron, webhook, sponsorship, or
hosted KMS configuration.

This step should preserve behavior. The self-host factory can initially call
the same threshold service and use the same store semantics as the hosted path.
The change is where the code lives and what it imports, not how signatures are
computed.

The hosted factory may keep proprietary integrations. The self-host factory
must be buildable from the open-source server SDK without importing premium
modules.

Concretely, the self-host factory should not import:

- console services
- billing services
- sponsorship services
- policy services
- webhook services
- hosted observability services
- hosted bootstrap brokers
- hosted KMS provisioning internals

If the shared router currently imports those modules eagerly, split route
registration so the self-host package can tree-shake or omit them entirely.

Recommended extraction sequence:

1. Create a threshold-only route registry.
2. Move `/threshold-ecdsa/*`, minimal health, and self-host admin route mounting
   into that registry.
3. Keep hosted routes in the existing hosted relay router.
4. Point the hosted router at the threshold-only registry where needed.
5. Point the self-host worker factory only at the threshold-only registry.
6. Add a dependency-boundary test for the self-host entrypoint.

At the end of this step, hosted behavior should be unchanged and the self-host
entrypoint should expose the same signing semantics with fewer dependencies.

### Step 2. Make threshold storage neutral

The current Durable Object is exported as
`ThresholdEd25519StoreDurableObject`, but it stores more than Ed25519 state.

Rename the public worker export to:

```ts
ThresholdStoreDurableObject
```

The Durable Object protocol should remain generic key/value plus the ECDSA
presign atomic operations, then gain project-root operations.

### Step 3. Add project-root operations to the Durable Object

Extend the Durable Object request protocol with operations like:

```text
projectRootGet
projectRootPut
projectRootDelete
projectRootStatus
```

These operations should validate and store `ProjectRootRecord` objects. They
must never return secret root material through unauthenticated routes.

The public worker routes call these operations only after admin authentication.
The threshold signing path uses them internally to resolve `k_org`.

### Step 4. Add `ProjectRootProvider` to the threshold service

Thread a `ProjectRootProvider` into `createThresholdSigningService` and
`ThresholdSigningService`.

Hosted mode can provide a provider backed by hosted project-root storage and
KMS provisioning. Self-host mode provides a provider backed by the customer's
Durable Object.

After this step, ECDSA code should resolve:

```text
project_id + k_org_version -> k_org
```

instead of reading a process-level secp256k1 master secret.

`ProjectRootProvider` belongs in the open-source boundary because self-hosted
signing cannot work without it. Hosted KMS implementations of that provider do
not need to be open sourced.

This is the first step that may change root-resolution behavior. It should land
after the boundary extraction and parity tests are in place.

### Step 5. Move server-share derivation to `signer-core`

Add a new signer-core function that accepts `k_org` and canonical wallet
context.

The TypeScript wrapper in `server/src/core/ThresholdService/ethSignerWasm.ts`
should expose the new function. Existing ECDSA bootstrap code should call the
new wrapper.

The old `master_secret + relayerKeyId` derivation path should be removed from
the self-host flow once the `k_org` path is complete.

### Step 6. Rework ECDSA bootstrap around project roots

ECDSA bootstrap should resolve:

```text
project_id
k_org_version
wallet_key_version
derivation_version
rp_id
user_id
```

Then it should derive the server share from `k_org` and persist a versioned
wallet key record.

The persisted record should be sufficient to validate future signing sessions,
but the canonical server share source remains `k_org + wallet_context`.

### Step 7. Rework ECDSA authorize, presign, and signing sessions

Every session object that can lead to signing must carry the project-root
binding:

```text
project_id
k_org_version
wallet_key_version
derivation_version
ecdsa_threshold_key_id
```

Each route should reject mismatches before touching secret material.

This prevents a self-hosted worker from accidentally using one imported
project root to sign for a wallet derived under another root.

### Step 8. Add self-host admin routes

Add Cloudflare routes for:

```text
POST /self-host/project-root/import
GET /self-host/project-root/status
POST /self-host/project-root/verify-wallet
POST /self-host/project-root/delete
```

These routes should be available only in the self-host worker factory and only
when an admin auth adapter is configured.

### Step 9. Package the customer-facing SDK entrypoint

Add an SDK export such as:

```ts
@tatchi-xyz/sdk/self-host/cloudflare
```

The export should include:

```ts
createSelfHostedCloudflareSigningWorker
ThresholdStoreDurableObject
```

The customer entrypoint should be small enough to copy into a Cloudflare Worker
project without understanding the hosted relay internals.

The package should have no dependency on proprietary hosted feature modules.
The dependency graph should be checked in CI so accidental imports from console,
policy, billing, sponsorship, or hosted KMS modules fail the build.

### Step 10. Add migration and verification harnesses

Add tests that run the same wallet through:

```text
hosted bootstrap
hosted export
self-host import
self-host address verification
self-host signing
hosted disablement
hosted signing rejection
```

This harness is the acceptance test for same-wallet self-host migration.

## Implementation Phases

### Phase 1. Extract server SDK boundary and define root specs

1. Extract the minimal threshold signing server SDK boundary without changing
   behavior.
2. Add dependency-boundary checks for the self-host package.
3. Add hosted-vs-self-host parity tests for current signing behavior.
4. Write the canonical `k_org` and `k_srv_wallet` derivation specs.
5. Add test vectors in `signer-core`.
6. Add project-root and wallet-key metadata types.
7. Remove direct ECDSA assumptions that `master_secret` is the server share
   root.

### Phase 2. Add project-root storage

1. Add `ProjectRootStore`.
2. Add Cloudflare Durable Object implementation.
3. Add Node/Postgres implementation for non-Cloudflare self-hosting.
4. Add import/status/delete operations.

### Phase 3. Refactor ECDSA to use `k_org`

1. Update bootstrap to resolve `k_org`.
2. Update signing and presign to carry project-root metadata.
3. Update ECDSA integrated key records.
4. Remove unnecessary secp256k1 master-secret requirements from sign-time paths.

### Phase 4. Package the self-hosted worker SDK

1. Add `@tatchi-xyz/sdk/self-host/cloudflare` exports.
2. Add `createSelfHostedCloudflareSigningWorker`.
3. Add neutral `ThresholdStoreDurableObject` export.
4. Add a minimal worker example.
5. Add Wrangler config template.
6. Add dependency-boundary checks that prevent premium hosted modules from
   entering the self-host SDK bundle.
7. Add a minimal public API review: every exported symbol must be required for
   self-hosted signing, root import, or migration verification.

### Phase 5. Add hosted migration tooling

1. Add hosted project-root export.
2. Add wallet inventory export.
3. Add self-host import verification.
4. Add hosted signing disablement.
5. Add deletion and audit attestation.

### Phase 6. Remove stale surfaces

1. Remove Ed25519-only names from shared threshold store APIs.
2. Remove global ECDSA master-secret assumptions from public self-host docs.
3. Remove duplicate compatibility paths after the `k_org` model is complete.

## Non-Goals

- per-wallet durable server secret storage
- migrating in-flight presign sessions
- guaranteeing cryptographic vendor exclusion while deterministic
  `master_secret -> k_org` derivation remains available
- requiring the customer to re-register passkeys
- changing wallet addresses during same-root self-host migration
- using the hosted KMS path on the self-hosted signing hot path
- open sourcing hosted premium features such as policies, gas sponsorship,
  billing, console management, webhooks, runtime snapshots, or hosted KMS
  provisioning
- making the self-host SDK a full replacement for the hosted relay platform

## Open Questions

- Is `k_org` scoped per project, org, environment, or custody domain?
- Should the self-hosted worker support multiple active project roots in one
  deployment?
- Which admin auth adapter should gate root import in the default Cloudflare
  template?
- Should the migration bundle include wallet inventory by default or require a
  separate export?
- Do we want customer-owned wrapping for imported `k_org` in Phase 0, or only
  plaintext Durable Object storage?
- Which hosted deletion evidence is sufficient if deterministic rederivation is
  still technically possible?

## Summary

The current Cloudflare worker is a reusable relay runtime, but not yet a clean
self-hosted signing SDK.

To make it self-hostable, the root dependency must move from a global
`THRESHOLD_SECP256K1_MASTER_SECRET_B64U` to an imported project `k_org` resolved
through a `ProjectRootProvider`.

The self-hosted worker should:

- import a customer project-root bundle
- store plaintext `k_org` in the customer's Durable Object in Phase 0
- derive `k_srv_wallet` locally using canonical versioned context
- preserve wallet identity without passkey re-registration
- let hosted infrastructure disable and delete active signing state after
  cutover
- expose only the minimal server-side signing surface required for migrated
  customers

This gives customers operational self-hosting while preserving the deterministic
root tradeoff: we can still technically rederive `k_org` from the platform
master derivation key unless that capability is destroyed or replaced.

The open-source boundary is intentionally narrow: threshold signing runtime,
project-root import, and migration verification. Premium hosted features remain
proprietary and should not be dependencies of the self-hosted server SDK.
