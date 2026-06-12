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
signing share for their own project using their own imported signing-root
shares, while preserving:

- the same wallet origin and `rpId`
- the same factor-derived client share
- the same versioned server-side derivation for the active migration mode
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
signing-root share bundle.

The bundle contains the customer's signing-root shares and versioned derivation
metadata. The worker stores sealed root shares in its own Cloudflare Durable
Object, decrypts two shares in memory for signing, computes two threshold-PRF
partials, and combines them into `y_relayer` locally.

The customer does not need our hosted root-share storage or wrapping path for
normal signing after cutover.

## Self-Host Semantics

Self-host migration means:

- the customer can independently operate signing for the same wallets
- the customer receives the signing-root shares needed to reconstruct the same
  root and derive the same server-side inputs
- our hosted signer is disabled for that project
- our active cached copies are deleted from hosted infrastructure
- we provide audit evidence for export, disablement, and deletion actions

Self-host migration means a custody transfer of the same random
`signing_root_secret` / `k_org`. Because the target model does not use a
deterministic platform `master_secret`, hosted infrastructure should not be able
to rederive the root after hosted shares are deleted.

The correct product language is:

- same-wallet self-hosting is supported
- hosted signing custody is operationally retired
- the customer imports the root shares required for the same wallets
- hosted root-share deletion has real cryptographic meaning if no hosted backup
  or wrapping path remains
- if the customer chooses a fresh signing root, that is wallet-key migration,
  not same-wallet self-host migration

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

- production Cloudflare wiring must choose a customer-owned
  `SigningRootSecretResolver` or an explicit hosted resolver adapter
  composition
- self-host Worker deployments still need production-grade customer KEK/KMS/HSM
  configuration and failure runbooks
- `relayerKeyId` is still an identifier, not a complete self-describing
  derivation envelope; callers must load the persisted key record to validate
  `projectId`, `signingRootVersion`, `walletKeyVersion`, and
  `derivationVersion`
- production Worker benchmarks and deployment-level KEK/KMS failure behavior
  still need to be captured before Worker deployment
- hosted project signing disablement, hosted root deletion, and export audit
  evidence remain migration-tooling work

Already completed by the signing-root refactor:

- ECDSA key records carry signing-root version and derivation metadata.
- The public Cloudflare Durable Object export has a neutral threshold-store
  name.
- The server SDK path derives ECDSA and Ed25519 HSS server inputs from
  signing-root shares through `SigningRootShareResolver`.

## Current ECDSA Call Graph

Cloudflare and Express expose the same threshold ECDSA route shape. The
Cloudflare route entrypoint is `handleThresholdEcdsa` in
`server/src/router/cloudflare/routes/thresholdEcdsa.ts`.

Registration and bootstrap:

```text
POST /threshold-ecdsa/hss/prepare
  -> handleThresholdEcdsa
  -> scheme.hss.prepare
  -> ThresholdSigningService.ecdsaHss.prepare
  -> deriveEcdsaHssYRelayerFromSigningRootSecretResolver
  -> threshold-prf WASM Option A partial evaluation and combine
  -> prepareThresholdEcdsaHssServerSession

POST /threshold-ecdsa/hss/respond
  -> scheme.hss.respond

POST /threshold-ecdsa/hss/finalize
  -> scheme.hss.finalize
  -> upsertIntegratedEcdsaKeyRecord
  -> optional threshold ECDSA session JWT/cookie issuance
```

First-bootstrap from registration material:

```text
ThresholdSigningService.bootstrapEcdsaFromRegistrationMaterial
  -> deriveEcdsaKeyMaterialForFirstBootstrapFromClientRootShare
  -> deriveEcdsaHssYRelayerFromSigningRootSecretResolver
  -> roleLocalThresholdEcdsaHssRelayerBootstrap
  -> upsertIntegratedEcdsaKeyRecord
```

Authorization and signing:

```text
POST /threshold-ecdsa/authorize
  -> validateThresholdEcdsaAuthorizeInputs
  -> validateRuntimeSnapshotExpectation
  -> scheme.authorize
  -> threshold session record / JWT or cookie

POST /threshold-ecdsa/presign/init
  -> validateThresholdEcdsaSessionInputs
  -> scheme.presign.init
  -> EcdsaSigningHandlers.ecdsaPresignInit
  -> resolve persisted integrated key material
  -> create ThresholdEcdsaPresignSession
  -> persist presign session

POST /threshold-ecdsa/presign/step
  -> scheme.presign.step
  -> advance presign session by CAS
  -> persist completed presignature relayer share

POST /threshold-ecdsa/sign/init
  -> scheme.protocol.signInit
  -> reserve or consume presignature
  -> persist signing session

POST /threshold-ecdsa/sign/finalize
  -> scheme.protocol.signFinalize
  -> take signing session
  -> finalize threshold ECDSA signature
```

The current signing-root dependency is concentrated in HSS prepare and
first-bootstrap. Presign and sign use persisted integrated-key and presignature
state; they do not rederive from a process-level secp256k1 master secret.

## Current ECDSA Durable State

Persisted ECDSA records that contain server-derived material:

- `ThresholdEcdsaIntegratedKeyRecord` contains `relayerRootShare32B64u`,
  `relayerBackendInputB64u`, and optionally `relayerVerifyingShareB64u`.
- `ThresholdEcdsaPresignatureRelayerShareRecord` contains `kShareB64u` and
  `sigmaShareB64u` for the relayer presignature share.
- `ThresholdEcdsaSigningSessionRecord` contains ephemeral signing-session
  material such as `entropyB64u`, `bigRB64u`, the digest, and identifiers that
  bind the session to the persisted integrated key.
- `ThresholdEcdsaPresignSessionRecord` contains session metadata and ownership
  state, not long-lived server root material.
- ECDSA auth/session records contain `relayerKeyId`, `userId`, `rpId`,
  participant IDs, and optional `runtimeSnapshotScope`.

Current Cloudflare Durable Object ECDSA key spaces:

- Object name defaults to `threshold-ecdsa-store`.
- Integrated key records use `THRESHOLD_ECDSA_KEYSTORE_PREFIX`, or
  `THRESHOLD_PREFIX + "key"`, or default `w3a:threshold-ecdsa:key:`.
- Auth sessions use `THRESHOLD_ECDSA_AUTH_PREFIX`, or
  `THRESHOLD_PREFIX + "auth"`, or default `w3a:threshold-ecdsa:auth:`.
- Threshold sessions use `THRESHOLD_ECDSA_SESSION_PREFIX`, or
  `THRESHOLD_PREFIX + "sess"`, or default `w3a:threshold-ecdsa:sess:`.
- Signing sessions use `THRESHOLD_ECDSA_SIGNING_PREFIX`, or
  `THRESHOLD_PREFIX + "signing"`, or default
  `w3a:threshold-ecdsa:signing:`.
- Presign sessions and presignature pools use `THRESHOLD_ECDSA_PRESIGN_PREFIX`,
  or `THRESHOLD_PREFIX + "presign"`, or default
  `w3a:threshold-ecdsa:presign:`.
- Available presignatures are stored under
  `presignPrefix + "avail:" + relayerKeyId`.
- Reserved presignatures are stored under
  `presignPrefix + "res:" + relayerKeyId + ":" + presignatureId`.

Current signing-root share storage:

- `CloudflareDurableObjectSigningRootSecretStore` defaults to object name
  `threshold-signing-root-secrets`.
- The signing-root share key prefix defaults to
  `threshold-prf:signing-root-secret:`.
- Share indexes use `idx:${signingRootId}\0${signingRootVersionKey}` under that prefix.
- Sealed share records use
  `rec:${signingRootId}\0${signingRootVersionKey}\0${shareId}` under that prefix.

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

The `k_org` signing-root model is the target root abstraction, but it should be
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
} from '@seams/sdk/self-host/cloudflare';

export { ThresholdStoreDurableObject };

export default createSelfHostedCloudflareSigningWorker();
```

The worker owns:

- threshold ECDSA HSS bootstrap routes
- threshold authorization routes
- threshold presign routes
- threshold sign routes
- signing-root import/export/status routes
- health and readiness routes

The worker depends on:

- Cloudflare Durable Objects for Phase 0 root and threshold state
- caller-provided session/JWT verification hooks
- configured wallet origin and `rpId`
- imported signing-root share bundle

The worker must not require:

- our hosted root-share wrapping or storage services
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
- signing-root import, status, verify, and delete routes
- signing-root storage interfaces and Cloudflare implementation
- threshold ECDSA HSS bootstrap routes needed to establish sessions
- threshold ECDSA authorization, presign, and sign routes
- canonical `k_org -> y_relayer` derivation bindings
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
- hosted root-share provisioning and wrapping services
- hosted root export approval workflows, except for the minimal export artifact
  schema needed by the self-host SDK

The boundary is:

```text
open-source server SDK:
  enough code to import root shares, decrypt two shares in memory, derive
  y_relayer through threshold-prf partial evaluation and combine, verify
  sessions, and sign

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

The self-hosted worker stores one signing root per migrated project environment.

```text
sealed_signing_root_secret_shares
  -> threshold-prf partials
  -> y_relayer
  -> server signing share
factor-derived secret -> client MPC share
```

The self-hosted worker derives server inputs through the same threshold-prf
Option A semantics used by the hosted Phase 1 model:

```text
share_i, share_j = decrypt_two_signing_root_secret_shares(signing_root_id, signing_root_version)
context = canonical_hss_context(...)
partial_i = threshold_prf_partial(share_i, context)
partial_j = threshold_prf_partial(share_j, context)
y_relayer = threshold_prf_combine([partial_i, partial_j], context)
```

`y_relayer` is the server-side per-wallet root input used by the existing HSS
and threshold signing flows. The derivation must use the committed
`crates/threshold-prf` protocol, vectors, and context encodings. It should not
be duplicated as ad hoc TypeScript.

The direct `k_org -> y_relayer` path is reference-only for vectors, recovery
checks, and audits. Production signing should use partial evaluation and combine
even when one worker computes both partials.

## Migration Bundle

The same-wallet self-host migration bundle should include:

- `bundle_version`
- `project_id`
- `env_id`
- `signing_root_id`
- `wallet_origin`
- `rp_id`
- `signing_root_version`
- `root_share_epoch`
- `sealed_signing_root_secret_shares` or plaintext root shares for an explicit import
  ceremony
- share threshold metadata, for example `threshold = 2`, `share_count = 3`
- `derivation_version`
- `scheme_id`
- `key_purpose`
- `participant_ids`
- share wrapping metadata, if the bundle contains sealed shares
- export timestamp
- export actor and approval metadata
- integrity checksum over the bundle

The bundle should not include per-wallet server shares.

Optional wallet inventory can be included or exported separately:

- `wallet_id`
- `user_id`
- `rp_id`
- `wallet_key_version`
- `signing_root_version`
- threshold public key
- address
- active or retired status

The wallet inventory is metadata. It is useful for validation and import
auditing, but signing should remain derivable from `k_org` and wallet context
after reconstructing the signing root from imported shares.

## Self-Hosted Signing Root Store

Add a neutral signing-root store abstraction.

```ts
interface SigningRootStore {
  getSigningRoot(signingRootId: string): Promise<SigningRootRecord | null>;
  putSigningRoot(record: SigningRootRecord): Promise<void>;
  deleteSigningRoot(signingRootId: string): Promise<void>;
}
```

`SigningRootRecord` should include:

- `version`
- `projectId`
- `envId`
- `signingRootId`
- `walletOrigin`
- `rpId`
- `signingRootVersion`
- `rootShareEpoch`
- `shareThreshold`
- `shareCount`
- `sealedSigningRootSecretShares`
- `derivationVersion`
- `contextHashB64u` or recomputable context-hash inputs
- `createdAtMs`
- `updatedAtMs`
- `source`

Allowed `source` values:

- `hosted-export`
- `customer-import`
- `customer-generated`
- `dev`

Phase 0 self-host mode stores sealed signing-root shares in the customer's
Durable Object. The worker decrypts two shares in memory during signing and uses
threshold-prf partial evaluation and combine as the canonical path. Development
mode may allow plaintext test root material, but production import should use
root shares.

## Required Refactors

### 1. Rename threshold store surfaces

Some threshold-store naming is still Ed25519-specific even though the store now
holds ECDSA and signing-root state too.

The Durable Object worker export has been renamed to:

- `ThresholdStoreDurableObject`

Remaining public SDK surfaces should move to neutral names:

- `ThresholdStoreConfigInput` -> `ThresholdStoreConfigInput`
- `THRESHOLD_DO_NAMESPACE` -> `THRESHOLD_DO_NAMESPACE`

Do this as a breaking cleanup. Do not keep duplicate old names in the primary
code path.

### 2. Add Signing-Root Share Adapters

Add server-side adapters that resolve sealed signing-root shares for a project.
The derivation layer decrypts two shares in memory and uses threshold-prf
partial evaluation and combine.

```ts
type SigningRootSecretResolverAdapters = {
  storageAdapter: SigningRootSecretShareSource;
  decryptAdapter: SigningRootSecretDecryptAdapter;
};

interface SigningRootSecretShareSource {
  listSealedSigningRootSecretShares(input: {
    signingRootId: string;
    signingRootVersion?: string;
  }): Promise<readonly SealedSigningRootSecretShare[]>;
}

interface SigningRootSecretDecryptAdapter {
  decryptSigningRootSecretShare(record: SealedSigningRootSecretShare): Promise<Uint8Array>;
}
```

Storage adapters:

- Cloudflare Durable Object signing-root store
- Node/Postgres signing-root store
- dev in-memory store for tests/local fixtures
- AWS Secrets Manager or GCP Secret Manager adapter if sealed share records live
  there

Decrypt adapters:

- local AES-GCM KEK resolver for local/dev or self-hosted deployments
- AWS Secrets Manager or GCP Secret Manager KEK resolver
- AWS KMS or GCP KMS decrypt adapter
- TEE-backed unwrap/decrypt adapter

The threshold service should depend on the composed provider, not on a
process-level server-root secret.

### 2A.0. Signing-Root Scope Invariants

The self-host and hosted code paths must keep organization policy scope separate
from signing-root custody scope.

- `orgId` is an organization, policy, and billing identifier. It must not be a
  signing-root cryptographic domain separator.
- `signingRootId` is the signing-root lookup and cryptographic custody
  identifier.
- Registration bootstrap grants and threshold sessions must carry enough runtime
  scope to derive or persist `signingRootId` before any route derives
  `y_relayer`.
- `SigningRootShareResolver` calls must receive `signingRootId` from
  authenticated runtime scope, a bootstrap token, persisted key metadata, or a
  fixed self-host resolver scope.
- The implementation must not pass `context.orgId` as signing-root resolver
  `signingRootId`.
- The repository check `check-signing-root-refactor-boundaries` is the minimum
  static guard for this class of regression.

### 2A. Add `SigningRootShareResolver`

The core signing service should depend on one resolver abstraction that returns
the two signing-root shares needed by threshold-prf. Storage, decrypt, hosted
multi-tenancy, and self-host import details should stay outside the signing
service.

```ts
interface SigningRootShareResolver {
  resolveSigningRootSharePair(input: {
    signingRootId: string;
    signingRootVersion?: string;
    preferredShareIds?: readonly [1 | 2 | 3, 1 | 2 | 3];
  }): Promise<readonly [Uint8Array, Uint8Array]>;
}
```

Hosted multi-customer configuration:

- The hosted resolver accepts dynamic `signingRootId` and `signingRootVersion`
  from the session/runtime scope.
- The hosted resolver composes a durable storage adapter with a decrypt adapter.
- Durable storage adapters may be Cloudflare Durable Objects, Postgres, AWS
  Secrets Manager, GCP Secret Manager, or custom customer/provider storage.
- Decrypt adapters may be local AES-GCM KEK resolution, AWS KMS, GCP KMS,
  Secret Manager backed KEK resolution, TEE-backed unwrap, or custom decrypt.
- The hosted resolver returns exactly two plaintext signing-root share wires and
  zeroization remains the caller's responsibility after threshold-prf copies what
  it needs.

Customer self-hosted configuration, direct-import model:

- The customer imports a bundle containing their signing-root shares.
- The self-host resolver validates `signingRootId`, `signingRootVersion`, share
  ids, and canonical share-wire shape.
- The self-host resolver returns any two imported share wires.
- No `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` or equivalent KEK is required for this
  minimal model because the customer is choosing to run from locally supplied
  shares.

Customer self-hosted configuration, sealed-local model:

- The customer imports the same signing-root share bundle once.
- The self-host worker reseals shares into the customer's chosen local storage.
- The self-host resolver composes the customer's storage adapter with the
  customer's decrypt adapter.
- The decrypt adapter can use a local env KEK, customer KMS, HSM, Secret
  Manager, or TEE-backed unwrap.

Todo:

- [x] Define `SigningRootShareResolver` in the server SDK boundary.
- [x] Refactor threshold-ECDSA HSS prepare to depend on
      `SigningRootShareResolver.resolveSigningRootSharePair`.
- [x] Refactor threshold-Ed25519 HSS prepare to depend on
      `SigningRootShareResolver.resolveSigningRootSharePair`.
- [x] Keep hosted adapter composition outside the core signing service.
- [x] Implement `createHostedSigningRootShareResolver({ storageAdapter,
decryptAdapter })`.
- [x] Implement `createSelfHostedSigningRootShareResolver({ signingRootId,
signingRootVersion, shares })` for direct imported shares.
- [x] Implement `createSealedSelfHostedSigningRootShareResolver({
storageAdapter, decryptAdapter })` for customer-local sealed storage.
- [x] Add tests proving hosted, direct self-host, and sealed self-host resolvers
      derive the same `y_relayer` for the same root shares and context.
- [x] Add tests proving direct self-host mode does not require a KEK env var.
- [x] Add tests proving hosted mode rejects missing project scope and missing
      sealed-share records.
- [x] Update self-host import routes to support both direct-import and
      sealed-local resolver configuration.

### 2B. Rename Tenant-Root Secret API Surface

Use signing-root secret names for public server SDK APIs. Avoid `master_secret`
because that name is reserved for the removed platform-wide deterministic root
model.

Todo:

- [x] Expose `SigningRootSecretShare`, `SigningRootSecretShareWireV1`, and
      `SigningRootSecretShareId` as the public share types.
- [x] Expose `SealedSigningRootSecretShare` as the sealed stored-share record.
- [x] Expose `SigningRootSecretShareSource`,
      `SigningRootSecretDecryptAdapter`, and `SigningRootSecretResolverAdapters`
      for hosted sealed-share composition.
- [x] Expose `SigningRootSecretResolver` for adapter-backed sealed-share
      resolution.
- [x] Expose `SigningRootSecretStore` for durable storage adapters.
- [x] Expose `SigningRootSecretShareKekResolver` for local AES-GCM sealed-share
      mode.
- [x] Rename built-in stores to
      `CloudflareDurableObjectSigningRootSecretStore`,
      `PostgresSigningRootSecretStore`, and `InMemorySigningRootSecretStore`.
- [x] Expose the local AES-GCM decrypt adapter as
      `createSigningRootSecretAesGcmDecryptAdapter`.
- [x] Rename config fields to `signingRootSecretResolverAdapters`,
      `signingRootSecretStore`, `signingRootSecretDecryptAdapter`, and
      `signingRootSecretShareKekResolver`.
- [x] Use `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` for the local AES-GCM decrypt
      adapter.
- [x] Update docs, tests, Cloudflare worker examples, and self-host examples in
      the same breaking cleanup.
- [x] Do not keep deprecated aliases or legacy flags after the rename lands.

### 3. Move `y_relayer` derivation to `threshold-prf`

Replace the ECDSA server-share derivation input shape.

Previous shape:

```text
derive_server_share(process_root_secret, relayer_key_id)
```

Target shape:

```text
derive_threshold_prf_y_relayer(signing_root_secret_share_i, signing_root_secret_share_j, wallet_context)
```

The canonical context must include:

- `signing_root_id`
- `user_id`
- `rp_id`
- `scheme_id`
- `key_purpose`
- `wallet_key_version`
- `signing_root_version`
- `derivation_version`

The function should return:

- `y_relayer`
- derivation metadata or context hash

Server verifying shares remain an HSS/downstream concern after `y_relayer` is
produced.

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
- `signingRootVersion`
- `derivationVersion`
- `clientVerifyingShareB64u`
- `thresholdEcdsaPublicKeyB64u`
- `ethereumAddress`
- `participantIds`
- `serverShareSource`
- `createdAtMs`
- `updatedAtMs`

`serverShareSource` should distinguish:

- `derived_from_signing_root`
- `imported_integrated_record`
- `dev`

If we keep `relayerRootShare32B64u` or `relayerBackendInputB64u`, they must be
treated as cached derived material, not the canonical root of custody.

### 5. Update ECDSA bootstrap

ECDSA bootstrap should:

1. resolve project context from the session, request, or environment
2. resolve two usable signing-root shares through `SigningRootSecretResolver`
3. derive `y_relayer` from threshold-prf partial evaluation and canonical
   wallet context
4. combine with the client factor-derived share
5. persist versioned wallet metadata

It should require a signing-root share provider, not a global server-root
secret.

### 6. Update ECDSA signing

Signing should be able to use either:

- derived server material from threshold-prf over signing-root shares
- validated cached derived material from the key record

Any current sign-time checks that require the secp256k1 master secret should be
removed when the active key record is already bound to a self-hosted project
root.

Presign and signing session records must carry:

- `signingRootId`
- `signingRootVersion`
- `walletKeyVersion`
- `derivationVersion`
- `ecdsaThresholdKeyId`

### 7. Add self-host import routes

The worker should expose admin-gated import/status routes.

Recommended routes:

- `GET /self-host/healthz`
- `POST /self-host/signing-root/import`
- `GET /self-host/signing-root/status`
- `POST /self-host/signing-root/verify-wallet`
- `POST /self-host/signing-root/delete`

These routes must be disabled unless a self-host admin authentication adapter is
configured.

Import must validate:

- bundle schema
- checksum
- `signingRootId`
- `wallet_origin`
- `rp_id`
- root share count and threshold
- root share lengths and identifiers
- supported `derivation_version`
- supported `scheme_id`

Verification should derive at least one known wallet public identity from the
imported signing-root shares and compare it to an exported wallet inventory
entry. For ECDSA, the route receives a user/device-supplied
`clientPublicKey33B64u`, adds it to the relayer public share derived from the
imported signing root, and compares the resulting threshold wallet address.

### 8. Add hosted export tooling

Hosted export tooling should produce a customer migration bundle.

The export flow should:

1. require customer admin authentication
2. require explicit approval
3. freeze or pin signing-root version during export
4. export signing-root shares and metadata
5. export wallet inventory
6. write an audit event
7. provide a checksum and import instructions

The hosted project should not be disabled until the customer confirms the
self-hosted worker validates the bundle.

### 9. Add hosted retirement tooling

After customer cutover:

1. disable hosted signing for the project
2. delete active hosted signing-root shares
3. delete or disable hosted sealed-share recovery artifacts
4. delete cached derived server material where applicable
5. retain only non-secret audit and billing metadata
6. issue deletion and disablement attestation

The attestation should explicitly state which hosted root-share copies and
wrapping paths were deleted or disabled.

## Customer Deployment Shape

Customer self-hosting should require a small worker entrypoint.

```ts
import {
  createSelfHostedCloudflareSigningWorker,
  ThresholdStoreDurableObject,
} from '@seams/sdk/self-host/cloudflare';

export { ThresholdStoreDurableObject };

export default createSelfHostedCloudflareSigningWorker({
  signingRootId: 'proj_...:prod',
  walletOrigin: 'https://wallet.customer.com',
  rpId: 'customer.com',
});
```

Required Cloudflare bindings:

- `THRESHOLD_STORE`

Required customer secrets or admin configuration:

- admin import token or admin auth adapter secret
- session/JWT signing secret or external session verification config

Project root shares should normally be imported into the Durable Object using
the admin import route, not hard-coded into `wrangler.toml`.

Development mode can allow `SIGNING_ROOT_SECRET_B64U` or plaintext root shares
as local test secrets, but that should not be the recommended production import
path.

## Cutover Flow

Recommended same-wallet self-host cutover:

1. Customer already uses a customer-owned wallet origin and stable `rpId`.
2. Hosted system pins the active `signing_root_version`.
3. Hosted system exports the migration bundle.
4. Customer deploys the self-hosted Cloudflare signing worker.
5. Customer imports the signing-root share bundle.
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

- no signing root is imported
- `signingRootId` is missing or mismatched
- `rp_id` does not match the imported bundle
- `wallet_origin` does not match configured self-host origin
- `signingRootVersion` is unsupported
- `derivation_version` is unsupported
- a wallet record references an unknown root version
- a threshold session references a different signing root than the active key

The worker must log non-secret context for:

- signing-root import
- signing-root verification
- signing authorization
- root deletion
- failed derivation-context validation

Logs must never include:

- `k_org`
- `y_relayer`
- client PRF material
- server signing share
- presignature secret shares

## Testing Plan

Add tests for:

- canonical `y_relayer` derivation vectors
- same `k_org` plus same context produces same threshold address
- different `signingRootVersion` changes threshold identity
- imported self-host bundle reproduces hosted wallet address
- self-host worker signs with imported signing-root shares
- missing signing root fails before signing
- mismatched `rpId` fails before signing
- mismatched `signingRootId` fails before signing
- hosted export followed by self-host import and sign
- hosted retirement prevents hosted signing after cutover

Add an end-to-end migration harness:

1. create wallet in hosted mode
2. export signing-root bundle
3. import bundle into self-host worker
4. verify same EVM address
5. sign with self-host worker
6. disable hosted project
7. assert hosted signing fails

## Phased Todo List

### Phase 0. Current-state inventory

- [x] Document the current ECDSA bootstrap and signing call graph from
      Cloudflare route to threshold service to WASM.
- [x] Confirm the server SDK no longer reads a process-level server-root env
      secret for ECDSA or Ed25519 HSS input derivation.
- [x] Identify every persisted ECDSA record field that contains derived server
      material.
- [x] Confirm which Cloudflare Durable Object keys are used for ECDSA key
      records, auth sessions, presign sessions, signing sessions, and
      presignatures.
- [x] Write an explicit compatibility baseline test that captures the current
      hosted derivation output before changing derivation code.

### Phase 1. Behavior-preserving boundary extraction

- [x] Split self-host signing routes from hosted SaaS routes without changing
      route behavior.
- [x] Create a self-host worker factory that reuses the current threshold
      signing behavior.
- [x] Move only the minimal threshold signing dependencies into the self-host
      router boundary.
- [x] Add dependency-boundary checks that fail if the self-host SDK imports
      console, billing, sponsorship, policy, webhook, runtime snapshot, or hosted
      root-share provisioning modules.
- [x] Add parity tests comparing hosted factory and self-host factory behavior
      for the same threshold signing inputs.
- [x] Keep current persisted state formats unchanged in this phase.

### Phase 2. Root and derivation specs

- [x] Define `SigningRootRecord`.
- [x] Define `SigningRootSecretResolver`.
- [x] Define `SigningRootSecretStore`.
- [x] Define `SigningRootSecretShareRecord`.
- [x] Define `SealedSigningRootSecretShare`.
- [x] Define the self-host migration bundle schema.
- [x] Define canonical `y_relayer` derivation context in the threshold-prf
      specs.
- [x] Add threshold-prf test vectors for `k_org_share_i + k_org_share_j ->
y_relayer`.
- [x] Add a context hash to make derivation mismatches easy to diagnose without
      logging secrets.

### Phase 3. Cloudflare signing-root storage

- [x] Extend the threshold Durable Object protocol with signing-root operations.
- [x] Store sealed signing-root shares in the customer's Durable Object for
      Phase 0.
- [x] Store root and share metadata next to the sealed shares.
- [x] Add authenticated self-host import, status, and delete routes.
- [x] Add self-host wallet-address verification route.
- [x] Add an optional in-memory sealed-share cache inside the Durable Object
      client path.
- [x] Add fail-closed behavior when a signing root is missing.

### Phase 4. ECDSA `k_org` derivation refactor

- [x] Replace ECDSA bootstrap derivation from global master secret with
      `SigningRootSecretResolver.resolveSigningRootSecretShares` plus threshold-prf Option
      A partial evaluation and combine.
- [x] Replace `relayerKeyId`-only derivation context with canonical wallet
      context.
- [x] Add `projectId`, `signingRootVersion`, `walletKeyVersion`, and
      `derivationVersion` to ECDSA key records.
- [x] Carry signing-root metadata through ECDSA auth sessions.
- [x] Carry signing-root metadata through presign sessions.
- [x] Carry signing-root metadata through signing sessions.
- [x] Remove secp256k1 master-secret checks from paths that can resolve or
      validate the active signing root.

### Phase 5. Self-hosted Cloudflare SDK package

- [x] Add `createSelfHostedCloudflareSigningWorker`.
- [x] Add a neutral `ThresholdStoreDurableObject` export.
- [x] Add a minimal self-host worker example.
- [x] Add a Wrangler template for the customer deployment.
- [x] Add self-host admin authentication hooks for signing-root import routes.
- [x] Add setup docs that avoid requiring `k_org` in `wrangler.toml`.

### Phase 6. Hosted export and cutover

- [x] Add hosted signing-root export artifact tooling.
- [x] Add wallet inventory export tooling.
- [x] Add bundle checksum generation.
- [x] Add self-host import verification against known wallet addresses.
- [x] Add hosted project signing disablement to the migration plan.
      Disablement must set a hosted signing state such as `retired` or
      `self_hosted_migrated` at the signing-root/project boundary, reject every
      hosted threshold prepare/sign route for that signing root, and leave
      read-only status/export-audit routes available for support.
- [x] Add hosted root deletion flow to the migration plan.
      Deletion is a separate, explicit, post-cutover action. It requires export
      checksum verification, self-host import verification, wallet-address
      parity verification, signing disablement, and a delay/approval window
      before deleting or cryptographically shredding hosted sealed shares.
- [x] Add audit evidence requirements for export, disablement, hosted share
      deletion, and wrapping-path disablement.
      The migration bundle must include event ids, actor ids, timestamps,
      signing-root id/version, exported share ids, wallet inventory checksum,
      import verification result, disablement reason, deletion/shred evidence,
      and proof that hosted unwrap/decrypt adapters for the retired root are no
      longer callable.

### Phase 7. Hardening and cleanup

- [x] Rename the Durable Object public export to a neutral threshold-store name.
- [x] Rename remaining Ed25519-specific threshold config surfaces to neutral
      names.
- [x] Remove the old Durable Object public store name from primary docs and
      examples.
- [x] Remove global ECDSA master-secret assumptions from self-hosted flows.
- [x] Add recovery drills for exported/imported signing roots.
      Drills must restore a migration bundle into a clean self-host deployment,
      derive known Ed25519 and ECDSA wallet public keys, sign a test NEAR
      transaction and EVM/Tempo transaction, verify hosted signing remains
      disabled, and prove the customer can recover without any platform
      `master_secret` or hosted share store.
- [x] Add alerts for signing attempts against a retired hosted project.
      Hosted workers must emit an audit/security event whenever a retired
      signing root receives prepare, presign, sign, refresh, export, or unwrap
      traffic. Alerts should include signing-root id/version, route, actor,
      source IP, session/app key id when available, and whether the request was
      rejected before share access.
- [x] Add independent storage and share-wrapping boundary requirements for the
      post-Phase-0 hardening lane.
      At least two root shares should live in independently administered
      storage/control planes, and share wrapping/decrypt authority should be
      split from the application database. Acceptable boundaries include
      Postgres plus object/secret storage, KMS/HSM/TEE-backed unwrap adapters,
      independent IAM roles, separate audit logs, and break-glass recovery
      procedures.

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
signing, signing-root import/status, health, readiness, and session validation.
It should not require hosted console, billing, cron, webhook, sponsorship, or
hosted root-share provisioning configuration.

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
- hosted root-share provisioning internals

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

The Durable Object is exported as:

```ts
ThresholdStoreDurableObject;
```

The Durable Object protocol should remain generic key/value plus the ECDSA
presign atomic operations, then gain signing-root operations.

### Step 3. Add signing-root operations to the Durable Object

Extend the Durable Object request protocol with operations like:

```text
signingRootGet
signingRootPut
signingRootDelete
signingRootStatus
```

These operations should validate and store `SigningRootRecord` objects. They
must never return secret root material through unauthenticated routes.

The public worker routes call these operations only after admin authentication.
The threshold signing path uses them internally to resolve sealed root shares
and derive server inputs.

### Step 4. Add `SigningRootSecretResolver` to the threshold service

Thread a `SigningRootSecretResolver` into `createThresholdSigningService` and
`ThresholdSigningService`.

Hosted mode can provide a provider backed by hosted signing-root storage and
share reconstruction. Self-host mode provides a provider backed by the
customer's Durable Object.

After this step, ECDSA code should resolve:

```text
signing_root_id + signing_root_version -> two usable sealed root shares -> y_relayer
```

instead of reading a process-level secp256k1 master secret.

`SigningRootSecretResolver` belongs in the open-source boundary because
self-hosted signing cannot work without resolving imported shares. Hosted share
storage and wrapping implementations of that provider do not need to be open
sourced.

This is the first step that may change root-resolution behavior. It should land
after the boundary extraction and parity tests are in place.

### Step 5. Move server-share derivation to `threshold-prf`

Add a server SDK binding that accepts two signing-root shares and canonical
wallet context and returns `y_relayer` using the `threshold-prf` crate.

The TypeScript wrapper in `server/src/core/ThresholdService` should expose the
new derivation boundary. Existing ECDSA bootstrap code should call the new
boundary before entering the existing HSS flow.

The old process-level secret plus relayer-key-id derivation path should be
removed from the self-host flow once the threshold-prf path is complete.

### Step 6. Rework ECDSA bootstrap around signing roots

ECDSA bootstrap should resolve:

```text
signing_root_id
signing_root_version
wallet_key_version
derivation_version
rp_id
user_id
```

Then it should derive `y_relayer` from `k_org` and persist a versioned
wallet key record.

The persisted record should be sufficient to validate future signing sessions,
but the canonical server-side input source remains `k_org + wallet_context`.

### Step 7. Rework ECDSA authorize, presign, and signing sessions

Every session object that can lead to signing must carry the signing-root
binding:

```text
signing_root_id
signing_root_version
wallet_key_version
derivation_version
ecdsa_threshold_key_id
```

Each route should reject mismatches before touching secret material.

This prevents a self-hosted worker from accidentally using one imported
signing root to sign for a wallet derived under another root.

### Step 8. Add self-host admin routes

Add Cloudflare routes for:

```text
POST /self-host/signing-root/import
GET /self-host/signing-root/status
POST /self-host/signing-root/verify-wallet
POST /self-host/signing-root/delete
```

These routes should be available only in the self-host worker factory and only
when an admin auth adapter is configured.

### Step 9. Package the customer-facing SDK entrypoint

Add an SDK export such as:

```ts
@seams/sdk/self-host/cloudflare
```

The export should include:

```ts
createSelfHostedCloudflareSigningWorker;
ThresholdStoreDurableObject;
```

The customer entrypoint should be small enough to copy into a Cloudflare Worker
project without understanding the hosted relay internals.

The package should have no dependency on proprietary hosted feature modules.
The dependency graph should be checked in CI so accidental imports from console,
policy, billing, sponsorship, or hosted root-share provisioning modules fail
the build.

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
4. Reuse the canonical threshold-prf `k_org_share_i + k_org_share_j ->
y_relayer` derivation specs.
5. Reuse the threshold-prf test vectors.
6. Add signing-root and wallet-key metadata types.
7. Remove direct ECDSA assumptions that a process-level secret is the server
   share root.

### Phase 2. Add signing-root storage

1. Add `SigningRootStore`.
2. Add Cloudflare Durable Object implementation.
3. Add Node/Postgres implementation for non-Cloudflare self-hosting.
4. Add import/status/delete operations.

### Phase 3. Refactor ECDSA to use `k_org`

1. Update bootstrap to resolve `k_org`.
2. Update signing and presign to carry signing-root metadata.
3. Update ECDSA integrated key records.
4. Remove unnecessary secp256k1 master-secret requirements from sign-time paths.

### Phase 4. Package the self-hosted worker SDK

1. Add `@seams/sdk/self-host/cloudflare` exports.
2. Add `createSelfHostedCloudflareSigningWorker`.
3. Add neutral `ThresholdStoreDurableObject` export.
4. Add a minimal worker example.
5. Add Wrangler config template.
6. Add dependency-boundary checks that prevent premium hosted modules from
   entering the self-host SDK bundle.
7. Add a minimal public API review: every exported symbol must be required for
   self-hosted signing, root import, or migration verification.

### Phase 5. Add hosted migration tooling

1. Add hosted signing-root export.
2. Add wallet inventory export.
3. Add self-host import verification.
4. Add hosted signing disablement.
5. Add deletion and audit attestation.

### Phase 6. Remove old surfaces

1. Remove Ed25519-only names from shared threshold store APIs.
2. Remove global ECDSA master-secret assumptions from public self-host docs.
3. Remove duplicate compatibility paths after the `k_org` model is complete.

## Non-Goals

- per-wallet durable server secret storage
- migrating in-flight presign sessions
- guaranteeing protection against malicious signer runtime code in the Phase 0
  single-worker reconstruction model
- requiring the customer to re-register passkeys
- changing wallet addresses during same-root self-host migration
- using hosted root-share storage or wrapping paths on the self-hosted signing
  hot path
- open sourcing hosted premium features such as policies, gas sponsorship,
  billing, console management, webhooks, runtime snapshots, or hosted
  root-share provisioning
- making the self-host SDK a full replacement for the hosted relay platform

## Open Questions

- Confirm whether `signing_root_secret` is scoped per project, environment, or
  custody domain.
- Should the self-hosted worker support multiple active signing roots in one
  deployment?
- Which admin auth adapter should gate root import in the default Cloudflare
  template?
- Should the migration bundle include wallet inventory by default or require a
  separate export?
- Should self-host import seal root shares immediately with customer-owned
  wrapping keys?
- Which hosted deletion evidence is sufficient for hosted share deletion and
  wrapping-path disablement?

## Summary

The current Cloudflare worker is a reusable relay runtime, but not yet a clean
self-hosted signing SDK.

To make it self-hostable, the root dependency must be imported signing-root
shares resolved through a `SigningRootSecretResolver`.

The self-hosted worker should:

- import a customer signing-root bundle
- store sealed signing-root shares in the customer's Durable Object in Phase 0
- decrypt two signing-root shares in memory during signing
- derive `y_relayer` locally using threshold-prf partial evaluation and combine
- preserve wallet identity without passkey re-registration
- let hosted infrastructure disable and delete active signing state after
  cutover
- expose only the minimal server-side signing surface required for migrated
  customers

This gives customers operational self-hosting without a deterministic platform
`master_secret` that can rederive `k_org` after hosted shares and wrapping paths
are deleted.

The open-source boundary is intentionally narrow: threshold signing runtime,
signing-root import, and migration verification. Premium hosted features remain
proprietary and should not be dependencies of the self-hosted server SDK.
