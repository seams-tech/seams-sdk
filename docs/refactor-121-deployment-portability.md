# Deployment Portability

Date created: August 5, 2026

Status: active design plan. Refactors 100 through 104 establish portable client
custody, stable wallet-key identity, replaceable execution lanes, lane
resharing, device continuity, and delegated agent spending. A tenant-scoped
backup format, production self-host bootstrapper, Router A/B import ceremony,
tenant cutover fence, and source-independent restore path remain unimplemented.

## Decision Summary

1. The first supported self-host target is a customer-owned Cloudflare account
   running the same strict Router A/B role topology as the managed service.
2. Operators configure one small single-tenant deployment specification. A
   bootstrapper generates and installs every role-local secret, public key,
   binding, database, and signed deployment manifest.
3. Managed deployment environment variables, root shares, KEKs, API tokens,
   relayer keys, databases, and CI credentials never cross the tenant export
   boundary.
4. Migration uses one encrypted `TenantPortabilityPackageV1` containing only
   the selected tenant's wallet inventory, credential metadata, encrypted
   recovery material, portable policy projections, and audit checkpoint.
5. Each wallet key carries a curve-specific portability capsule sufficient to
   hand one incomplete server participant from the managed deployment to the
   dedicated destination while preserving the owner's complementary holder
   material, public key, and address. The exact Ed25519 and ECDSA capsule
   protocols must be frozen before implementation.
6. The destination generates new deployment secrets and re-encrypts imported
   records under new role identities, KEKs, and epochs. Import never copies raw
   source rows or source ciphertext into live destination stores.
7. `WalletId`, `WalletKeyId`, public keys, addresses, and customer-owned wallet
   origin remain stable. Source organization, project, environment, and storage
   identifiers map once at the import boundary.
8. Agent identities and desired Agent Wallet settings may move with the wallet.
   Active delegated-spend authorizations, budget reservations, replay claims,
   sessions, and presignatures do not. The owner reauthorizes Agent Wallets on
   the destination after activation.
9. The preferred cutover provisions and validates destination lanes before the
   source is disabled. A previously downloaded current package provides the
   source-unavailable escape path.
10. The existing `SigningRootMigrationBundleV1` and the shared-secret migration
    guidance in `docs/saas/self-hosted-migration.md` are superseded for wallet
    portability. They are deleted when Refactor 115 lands. No compatibility
    importer enters the new migration path.

## Dependencies And Authority

This plan consumes:

- [Refactor 100](./refactor-100-passkey-account-refactor.md) for portable
  encrypted owner custody, recovery envelope sets, credential replacement, and
  exact mixed-wallet identity continuity;
- [Refactor 101](./refactor-101-wallet-execution-lanes.md) for stable
  `WalletKey` identity and independently replaceable holder/server execution
  lanes;
- [Refactor 102](./refactor-102-rotatable-signing-lanes.md) for curve-specific lane
  provisioning, share refresh, activation, revocation, and public-key
  continuity;
- [Refactor 103](./refactor-103-device-linking.md) for linked-device continuity
  and aggregate lane activation;
- [Refactor 104](./refactor-104-agent-id-spending.md) for agent identities,
  delegated authorizations, server-canonical budgets, replay state, and Agent
  Wallet projections;
- [Refactor 90](./refactor-90-modular-auth-capabilities-plan.md) for exact
  authorization resources, operation identity, atomic claims, fencing, audit,
  and prepared execution;
- [the canonical Router A/B deployment](./router-ab/deployment.md) for strict
  role boundaries, production artifacts, private stores, and fail-closed role
  configuration;
- the Ed25519 Yao and ECDSA Router A/B protocol documents for recovery, export,
  recipient provisioning, activation, signing, and identity verification.

This plan owns:

- the tenant portability package and encryption boundary;
- managed multi-tenant export into a single-tenant package;
- single-tenant destination bootstrap and configuration compilation;
- deployment-local secret generation and recovery packaging;
- source and destination migration lifecycle, fencing, activation, rollback,
  and receipts;
- source-to-destination identity mapping;
- agent authorization behavior during deployment migration;
- product and SDK surfaces for backup, restore, and deployment cutover.

It does not redefine either signing protocol, lower the Router A/B role
separation requirements, or make development-only transports eligible for
production.

## Goal

Allow a customer to leave the managed multi-tenant Seams deployment and run
the same wallets in a dedicated, single-tenant deployment without changing any
wallet public key or address.

```text
managed Seams deployment
  -> tenant-scoped encrypted portability package
       -> customer-owned deployment bootstrap
            -> fresh destination Router A/B secrets and stores
                 -> imported wallet keys and fresh execution lanes
                      -> verified identical public keys and addresses
```

`single tenant` means one customer or application tenant. The deployment may
serve many human users, Human Wallets, wallet keys, devices, and Agent Wallets.
The deployment customer operates the destination server participants. An
end-user wallet owner retains the complementary holder material. Tenant
administration alone never grants complete wallet-key export authority.

The customer experience should be:

```text
seams self-host init
seams self-host import customer.seams-backup
seams self-host verify
seams self-host activate
```

The operator supplies deployment identity, customer-owned origins, Cloudflare
authority, chain settings, and a backup recipient. They do not hand-author the
Router, Deriver A, Deriver B, and SigningWorker environment matrices.

## Product Portability Contract

### Wallet identity portability

The following identities remain byte-for-byte stable:

- `WalletId`;
- every active `WalletKeyId`;
- Ed25519 public keys and registered account bindings;
- secp256k1 threshold public keys and EVM addresses;
- wallet-key versions that identify the imported keys;
- the customer-owned wallet origin and RP ID when the customer keeps the same
  domain boundary.

Credential IDs, lane IDs, holder/server participants, share epochs, sessions,
and deployment epochs may change. Refactors 100 through 103 already treat these
as replaceable access and execution state.

### Deployment portability

Deployment portability means the customer can:

- move from managed Seams into a customer-owned Cloudflare account;
- operate the four strict Router A/B roles without manually managing their
  internal configuration graph;
- restore from a customer-held package when the managed source is unavailable;
- move back to managed Seams or into another supported deployment through the
  same package and import protocol;
- verify public-key and address continuity independently before activation.

The first release supports the customer-owned Cloudflare profile. A future OCI
or Kubernetes profile must reuse the same transport-neutral protocol and
package boundary. It requires separately reviewed transport, storage, secret
manager, availability, and role-isolation adapters.

### Agent portability

Agent portability is part of wallet deployment migration. It is not a separate
wallet-key portability mechanism.

The package may retain:

- agent IDs and public identity keys;
- display metadata;
- declared custody bindings that remain valid in the destination environment;
- requested scope, budget, counterparty, expiry, and policy projections for
  owner review;
- completed audit evidence.

The package never activates those projections. The destination owner signs a
fresh delegated-spend authorization after wallet activation. This prevents a
mutable source budget, replay reservation, revocation epoch, or ambiguous
operation from silently acquiring authority in a new deployment.

## Current Architecture And Gaps

### Router A/B complexity

The production topology intentionally has four roles:

```text
Router
Deriver A
Deriver B
SigningWorker
```

Deriver A, Deriver B, and SigningWorker each have private storage and private
cryptographic material. Public encryption and verifying keys are distributed
to their peers. The Router carries public policy and routing material and must
remain unable to read private role state.

The current Cloudflare deployment exposes this internal graph as a large set
of Worker bindings, database identifiers, key epochs, public keys, private
keys, KEKs, internal authentication values, JWT material, URLs, and CI
credentials. Those values are appropriate as generated role inputs. They are
an unsuitable operator-facing configuration surface.

The local development initializer already proves that a single command can
generate four role-specific configurations and reject wrong-role inputs. It is
development-only, writes local env files, and derives fixture material from one
seed. The production bootstrapper should reuse its branch-specific config
builders and validation shape while generating independent production secrets
and installing them directly into the destination secret manager.

### Multi-tenant source

The managed deployment serves many customers using shared deployment roles,
root material, storage infrastructure, relayer infrastructure, CI authority,
and operational secrets. Records carry wallet, account, project, environment,
and authorization scope through the protocols and persistence boundaries.

A tenant migration cannot export any shared deployment value. Copying a
managed Deriver root share, D1 KEK, internal service secret, session issuer key,
or relayer key would expose or influence other tenants. Copying a managed D1
database would also bypass boundary parsing and tenant-isolation guarantees.

The export ceremony must resolve one exact tenant and construct portable
per-wallet material through role-local code. Every source repository read is
tenant-scoped. Cross-tenant records cause the export to fail.

### Existing migration bundle

`SigningRootMigrationBundleV1` exports a project/environment signing-root
record containing sealed 2-of-3 root shares and optional wallet inventory. It
predates the current Refactor 100 through 104 wallet-key and execution-lane
model. Its sealed shares retain storage and KEK locator concepts from the
source deployment and do not define a complete mixed-wallet, agent, cutover,
or single-tenant import contract.

Refactor 115 replaces that format. Development fixtures using the old bundle
are deleted with its parser and type fixtures. Existing development data is
recreated under `TenantPortabilityPackageV1`.

### Customer-owned domain

The existing customer-owned domain plan remains the preferred browser path:

```text
hosted phase:     wallet.customer.example -> managed Seams
self-host phase:  wallet.customer.example -> customer deployment
```

Keeping the wallet origin and RP ID stable preserves passkeys and origin-bound
browser storage. A customer migrating from a Seams-owned RP ID cannot copy a
passkey private key. The user must authenticate through an existing recovery
factor, import the same wallet key, and enroll a credential under the new RP
ID. The wallet address still remains stable.

## Required Invariants

1. Migration preserves every imported wallet public key and address exactly.
2. The export is bound to one exact tenant, wallet-key manifest, source
   deployment, source epoch, package sequence, and creation time.
3. A package contains no managed platform root share, role KEK, Worker secret,
   API token, CI credential, relayer private key, session signing key, internal
   service credential, raw database export, or other tenant's data.
4. The package contains no plaintext private key, root, holder share, recovery
   secret, PRF output, KEK, or agent private key at rest.
5. Package decryption requires a customer-controlled recovery recipient. A
   source operator cannot decrypt the completed customer-KMS branch.
6. Every protected item binds package ID, tenant, wallet, wallet key, curve,
   purpose, source epoch, schema version, and content digest in AEAD associated
   data.
7. Import parses and validates every item once. Core import and activation
   logic never accepts raw archive entries, source DB rows, partial records, or
   compatibility shapes.
8. The destination creates fresh deployment-local roots, role keys, KEKs,
   issuer keys, internal credentials, storage identities, and epochs.
9. Imported records are re-encrypted under the destination role and deployment
   bindings before entering live stores.
10. Migration never joins the complete wallet private key in JavaScript, the
    Router, persistence code, the export coordinator, the destination
    bootstrapper, logs, or tenant-admin tooling.
11. A tenant package gives the destination only the incomplete server-side
    authority previously held by managed Seams. It does not contain the
    complementary owner holder material in a form the tenant administrator can
    open.
12. An explicit per-wallet owner export remains a separate Refactor 100/101
    operation. Only that branch may reconstruct complete key material inside a
    reviewed owner-controlled boundary.
13. The Ed25519 and ECDSA keys within one mixed wallet activate atomically. A
    tenant package may contain many independently staged wallets.
14. Destination signing remains disabled until each imported wallet proves
    public identity continuity and its server-participant handoff is activated.
15. Source mutation is fenced per tenant during the final cutover. Other
    managed tenants remain available.
16. New source operations fail after the cutover fence. Queued operations that
    have not crossed an irreversible boundary are cancelled.
17. `outcome_unknown` transactions are reconciled before final package and
    budget checkpoint creation.
18. Sessions, warm handles, presignatures, nonces, quotes, temporary grants,
    replay leases, and uncommitted budget reservations are disposable and are
    never imported.
19. The source disables and erases the migrated tenant's server participants
    after destination activation under the selected honest-erasure threat
    model. The migration receipt enumerates every revoked source participant.
20. Package import is idempotent for one package digest. A different package
    cannot overwrite an active destination deployment.
21. Failed staging has no signing authority. Rollback is available until
    destination activation and unavailable after source revocation.
22. The package is treated as sensitive server-custody and tenant data.
    Download, replacement, and restore require fresh high-assurance tenant
    administration. Per-wallet owner recovery material retains its independent
    owner authorization and encryption boundary.
23. No legacy migration branch, old bundle parser, dual persistence model, or
    caller-selected deployment profile enters runtime core logic.

## Deployment And Tenant Domain Model

Deployment configuration is an exhaustive union:

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

Raw requests in either deployment normalize immediately into one required
`TenantContext`. Core wallet, policy, signing, and audit functions receive that
context and retain the same cross-tenant rejection behavior. The self-hosted
branch resolves exactly one configured tenant rather than deleting tenant
identity from domain records.

This avoids a second single-tenant implementation. It also keeps future
single-tenant-to-managed import symmetric.

## Tenant Portability Package

### Package shape

The downloadable artifact is one encrypted, authenticated archive:

```ts
type TenantPortabilityPackageV1 = {
  kind: 'tenant_portability_package_v1';
  packageId: PortabilityPackageId;
  sourceDeploymentId: DeploymentId;
  sourceTenantId: TenantId;
  packageSequence: PortabilityPackageSequence;
  snapshot: PortabilitySnapshot;
  recipient: PortabilityPackageRecipient;
  encryptedPayloadB64u: string;
  ciphertextDigestB64u: string;
  sourceAttestation: PortabilitySourceAttestation;
  createdAtMs: number;
};

type PortabilityPackageRecipient =
  | {
      kind: 'customer_kms_hpke_v1';
      recipientKeyId: CustomerRecoveryKeyId;
      algorithm: 'x25519_hkdf_sha256_chacha20poly1305';
      recipientPublicKeyB64u: string;
    }
  | {
      kind: 'customer_recovery_passphrase_v1';
      kdf: 'argon2id';
      saltB64u: string;
      memoryKiB: number;
      iterations: number;
      parallelism: number;
    };
```

The customer-KMS branch is preferred for organizations and automated backups.
The passphrase branch is an explicit high-entropy recovery flow for customers
without a KMS. UI strength checks are advisory; the fixed minimum Argon2id
parameters are enforced by the package builder and parser.

The source encrypts KMS packages directly to the customer's public key. For a
passphrase package, the trusted browser or local CLI generates an ephemeral
package keypair and the package data key. Source roles encrypt their fragments
to the ephemeral public key. The browser or CLI assembles the payload and wraps
the data key under the Argon2id-derived key. The passphrase, ephemeral private
key, and plaintext package data key never reach the managed backend.

Only the outer version, package identity, encryption parameters, ciphertext
digest, and source attestation remain visible. Tenant names, users, wallet
addresses, credential metadata, and policies live inside the ciphertext.

### Encrypted payload

The decrypted payload contains required branches:

```ts
type TenantPortabilityPayloadV1 = {
  kind: 'tenant_portability_payload_v1';
  tenant: PortableTenantIdentityV1;
  walletOrigin: WalletOrigin;
  authorityScope: PortableWalletAuthorityScopeV1;
  walletManifest: readonly [PortableWalletV1, ...PortableWalletV1[]];
  credentialManifest: readonly PortableCredentialV1[];
  recoveryManifest: readonly PortableRecoveryFactorV1[];
  agentManifest: readonly PortableAgentIdentityV1[];
  proposedAgentWallets: readonly ProposedAgentWalletV1[];
  auditCheckpoint: PortabilityAuditCheckpointV1;
  sourceRevocationManifest: SourceRevocationManifestV1;
  payloadDigestB64u: string;
};

type PortableWalletAuthorityScopeV1 = {
  kind: 'passkey_rp_v1';
  rpId: WebAuthnRpId;
};
```

Each `PortableWalletV1` requires a nonempty wallet-key manifest. Each wallet key
contains exactly one curve-specific `WalletKeyPortabilityCapsule`:

```ts
type WalletKeyPortabilityCapsule =
  | Ed25519WalletKeyPortabilityCapsuleV1
  | EvmWalletKeyPortabilityCapsuleV1;
```

The capsule is a server-participant handoff. It contains the managed server
participant's tenant-scoped, incomplete wallet material encrypted for the
customer package and bound to the owner holder commitment. The destination
re-encrypts it under its SigningWorker identity and storage KEK. It may refresh
the holder/server shares later with owner participation through Refactor 102.

The package also carries the owner's existing passkey- or recovery-encrypted
holder envelopes as opaque ciphertext. Tenant administration cannot unwrap
them. With a stable RP ID, the owner's existing authenticator opens the holder
side after cutover. With a changed RP ID, the owner uses the explicit recovery
flow and enrolls a new destination credential.

The Ed25519 and ECDSA protocol documents must define their server-handoff
capsules, owner-holder commitments, recipient keys, transcript digests,
activation receipts, and zeroization requirements. A generic
`privateKeyB64u` field is forbidden.

### Credential material

The package may include:

- credential IDs and public keys;
- RP ID and wallet-origin bindings;
- backup eligibility and observed backup state;
- passkey-encrypted custody envelopes from Refactor 100;
- recovery-factor metadata and encrypted recovery envelopes;
- credential, lane, and revocation epochs needed to reject stale state.

The package cannot include a passkey private key because WebAuthn authenticators
do not export one. A stable RP ID lets the destination use the existing
credential. A changed RP ID requires recovery plus new credential enrollment.

### Explicit exclusions

The package excludes:

- source Router, Deriver, SigningWorker, Gateway, console, and CI env files;
- source deployment root shares and derivation roots;
- D1 KEKs, HPKE private keys, peer-signing keys, JWT private keys, HMAC secrets,
  API tokens, and Cloudflare account credentials;
- raw D1, Durable Object, Redis, Postgres, R2, SQLite, or log exports;
- relayer private keys and funded relayer accounts;
- active sessions, quotes, presignatures, replay entries, locks, leases, and
  caches;
- pending or ambiguous agent budget reservations;
- agent private identity keys held by external agent runtimes;
- source membership, SSO, API-key, and organization-admin credentials that are
  meaningful only in the managed control plane.

### Snapshot and freshness

One package represents one immutable snapshot. Its checkpoint records:

- highest included wallet, credential, recovery, lane, authorization, and audit
  sequence;
- source deployment and tenant epochs;
- completed-operation high-water marks;
- no unresolved execution inventory;
- package predecessor digest when this replaces an older backup.

Creating a new wallet, adding a credential, rotating recovery, changing a
wallet key, or completing source-only administrative state makes an older
package stale for those changes. Managed Seams should support periodic package
creation encrypted directly to a customer KMS. Manual download remains
available for the passphrase branch.

The destination reports the snapshot time and missing post-snapshot activity
before a source-independent restore. It never presents a stale backup as a
current cutover. Restored server participants remain unable to sign without
the corresponding wallet owners' holder material.

## Simplified Self-Hosted Router A/B

### First supported profile

The first profile is:

```text
router_ab_customer_cloudflare_single_tenant_v1
```

It deploys:

- Gateway and customer wallet origin routes;
- MPCRouter;
- Deriver A Worker and private D1;
- Deriver B Worker and private D1;
- SigningWorker, private D1, and required nonce/presignature state;
- fixed Service Bindings;
- customer-owned logs, backups, and alert destinations.

This reuses the reviewed same-account P0 topology. The customer Cloudflare
account administrator is inside the P0 trust assumption, matching the current
managed same-account profile. Deriver A, Deriver B, and SigningWorker still use
distinct Worker identities, secrets, databases, KEKs, logs, and deployment
labels.

### Operator-facing specification

The customer writes or confirms one specification:

```ts
type SelfHostedDeploymentSpecV1 = {
  kind: 'self_hosted_deployment_spec_v1';
  deploymentId: DeploymentId;
  tenantId: TenantId;
  projectId: ProjectId;
  environmentId: EnvironmentId;
  walletOrigin: WalletOrigin;
  rpId: WebAuthnRpId;
  allowedAppOrigins: readonly [AppOrigin, ...AppOrigin[]];
  cloudflareAccountId: CloudflareAccountId;
  networkConfiguration: SelfHostedNetworkConfiguration;
  relayerConfiguration: SelfHostedRelayerConfiguration;
  backupRecipient: PortabilityPackageRecipient;
};
```

Cloudflare authentication is supplied to the bootstrap process through an
interactive or short-lived deployment credential. It is never serialized into
the specification, deployment manifest, or backup package.

### Generated deployment state

The bootstrapper creates, installs, and validates:

| Owner         | Generated private state                                        | Generated public state                                                         |
| ------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Router        | internal service credential reference                          | issuer/audience, A/B and SigningWorker public keys, bindings, protocol digests |
| Deriver A     | independent root share, D1 KEK, envelope key, peer-signing key | envelope public key, peer verifying key, key epochs                            |
| Deriver B     | independent root share, D1 KEK, envelope key, peer-signing key | envelope public key, peer verifying key, key epochs                            |
| SigningWorker | D1 KEK, server-output key, nonce/presignature secrets          | server-output public key, worker identity, key epochs                          |
| Gateway       | session and ceremony issuer keys, customer route secrets       | JWKS, wallet origin, RP ID, allowed app origins                                |

The bootstrapper generates independent randomness per role. It never derives
all production secrets from a retained master seed. Public state is written to
a signed content-addressed `DeploymentManifestV1`. Private state is installed
directly into the owning Worker secret binding or customer-selected secret
manager.

The operator sees semantic resources and health results. Internal environment
variable names remain an implementation detail of the Cloudflare adapter.

### Bootstrap flow

```text
seams self-host init
  -> validate customer domain, RP ID, app origins, account authority
  -> generate independent role secrets in memory
  -> create three private databases and required state namespaces
  -> deploy reviewed content-addressed role artifacts
  -> install only each role's allowed secrets
  -> derive and publish the signed public deployment manifest
  -> run wrong-role and opposite-store negative checks
  -> emit an encrypted deployment recovery package
  -> zeroize bootstrap plaintext and temporary credentials
```

`seams self-host doctor` verifies:

- every role artifact and protocol digest;
- distinct A/B deploy identities, stores, KEKs, envelope keys, and peer keys;
- SigningWorker separation from both Derivers;
- public/private key agreement and key epochs;
- service binding reachability and public route exposure;
- private store schemas and encrypted round trips;
- customer origin, RP ID, related-origin, CORS, and iframe policy;
- backup recipient and restore drill status;
- zero Deriver calls during normal signing.

### Deployment recovery package

After bootstrap, the customer receives a separate encrypted
`SelfHostedDeploymentRecoveryPackageV1`. It backs up destination-local role
secrets, resource identities, and restore metadata for disaster recovery of
that single-tenant deployment.

This package is never exported by managed multi-tenant Seams. It exists only
after the customer owns a dedicated deployment. It uses the same customer
recovery recipient and keeps role entries separately sealed. Storage snapshots
remain separate encrypted objects referenced by digest.

The distinction is deliberate:

- `TenantPortabilityPackageV1` moves customer wallet state across deployments;
- `SelfHostedDeploymentRecoveryPackageV1` restores one customer-owned
  deployment and its freshly generated operational secrets.

## Multi-Tenant To Single-Tenant Normalization

### Identity mapping

The import preserves wallet-domain identities and records an explicit mapping
for control-plane identities:

```ts
type TenantImportIdentityMappingV1 = {
  kind: 'tenant_import_identity_mapping_v1';
  sourceDeploymentId: DeploymentId;
  sourceTenantId: TenantId;
  sourceProjectId: ProjectId;
  sourceEnvironmentId: EnvironmentId;
  destinationDeploymentId: DeploymentId;
  destinationTenantId: TenantId;
  destinationProjectId: ProjectId;
  destinationEnvironmentId: EnvironmentId;
  preservedWalletIds: readonly [WalletId, ...WalletId[]];
  mappingDigestB64u: string;
};
```

The destination may preserve customer-selected project and environment IDs if
they are valid and collision-free. Deployment IDs, storage IDs, role IDs,
participant IDs, lane IDs, sessions, and epochs are destination-owned.

### Data conversion

The source exports domain records through branch-specific builders. The
destination parser converts them into precise import records, verifies their
proofs, and writes new destination-native rows. There is no database copy,
schema replay, or shared persistence compatibility layer.

Every destination record receives:

- the fixed destination `TenantContext`;
- destination deployment, role, storage, and encryption bindings;
- fresh holder/server lane IDs and share epochs where required;
- an import receipt linking the source package digest and destination record
  digest;
- the preserved wallet and wallet-key identities.

### Derivation and signing roots

Managed A/B derivation roots may cover many tenants. They remain in the source
deployment. The destination generates fresh A/B roots for new wallet
registrations after migration.

Existing wallet keys enter through their curve-specific server-handoff
capsules and destination activation ceremony. They do not require the
destination to inherit the managed platform's derivation root. Refactors 101
and 102 must represent imported wallet keys and destination server-participant
epochs directly. A later owner-approved share refresh may replace both sides'
material while retaining the wallet key.

Wallets whose current key material cannot produce a tenant-scoped portability
capsule are ineligible for address-preserving migration until they complete an
owner-authorized recovery or refresh into the Refactor 100 through 102 model.
The product reports this before export.

### Authentication and membership

The managed organization's SSO connections, API tokens, support access,
platform administrators, billing roles, and managed console memberships stay
at the source.

The self-hosted administrator bootstraps a new destination admin identity. The
package may carry proposed wallet-owner and display mappings for review. Each
destination membership is created through destination authentication and
explicit acceptance.

Existing wallet passkeys remain usable when the wallet origin and RP ID stay
stable. They prove wallet access; they do not automatically grant destination
deployment administration.

### Agent Wallets

Before final export, the source:

1. stops new agent requests for the migrating tenant;
2. reconciles committed and unknown operations;
3. commits completed budget use;
4. releases only definitive pre-execution failures;
5. revokes active delegated authorizations at the source cutover epoch;
6. exports agent public identities, desired policies, remaining-budget
   projections, and audit evidence as inert records.

After destination wallet activation, the human reviews each proposed Agent
Wallet and signs a new destination authorization. The UI may preserve names and
show the previously remaining allocation, while clearly labeling it pending
until authorization completes.

## Migration Lifecycle

### State model

```ts
type DeploymentMigrationState =
  | {
      state: 'requested';
      migrationId: DeploymentMigrationId;
      sourceTenantId: TenantId;
      requestedManifestDigestB64u: string;
    }
  | {
      state: 'destination_prepared';
      migrationId: DeploymentMigrationId;
      destinationDeploymentId: DeploymentId;
      destinationManifestDigestB64u: string;
      importRecipientDigestB64u: string;
    }
  | {
      state: 'package_ready';
      migrationId: DeploymentMigrationId;
      packageId: PortabilityPackageId;
      packageDigestB64u: string;
      sourceSnapshotEpoch: number;
    }
  | {
      state: 'staged';
      migrationId: DeploymentMigrationId;
      stagedWalletManifestDigestB64u: string;
      continuityReceiptDigestB64u: string;
    }
  | {
      state: 'source_frozen';
      migrationId: DeploymentMigrationId;
      freezeEpoch: number;
      finalCheckpointDigestB64u: string;
    }
  | {
      state: 'destination_active';
      migrationId: DeploymentMigrationId;
      activationReceiptDigestB64u: string;
      activatedAtMs: number;
    }
  | {
      state: 'source_revoked';
      migrationId: DeploymentMigrationId;
      sourceRevocationReceiptDigestB64u: string;
      completedAtMs: number;
    }
  | {
      state: 'aborted_before_activation';
      migrationId: DeploymentMigrationId;
      reason: DeploymentMigrationAbortReason;
      abortedAtMs: number;
    };
```

There is no rollback branch after `destination_active`. Failures after
destination activation enter an operational reconciliation procedure and
cannot reactivate source signing automatically.

### Phase A: eligibility and tenant approval

1. Resolve the exact managed tenant, wallet inventory, key families, origins,
   RP ID, active credentials, recovery factors, devices, and Agent Wallets.
2. Verify every active wallet key has a supported server-handoff capsule path
   and an owner-holder commitment that can be checked at the destination.
3. Verify no unresolved transaction, export, recovery, rotation, or migration
   operation exists.
4. Display the destination identity, origin, RP ID, wallet-key manifest,
   addresses, agent behavior, source revocation, and backup consequences.
5. Obtain fresh high-assurance export authorization covering the canonical
   migration request digest.

### Phase B: destination preparation

1. Bootstrap the dedicated single-tenant deployment.
2. Publish its signed deployment manifest and import recipient keys.
3. Run `self-host doctor` with no wallet state installed.
4. Bind the migration request to the destination manifest digest and recipient
   digest.

### Phase C: package construction

1. Begin one tenant-scoped export snapshot.
2. Ask each source role for only its tenant-scoped portable fragments.
3. Verify every fragment's tenant, wallet, wallet-key, role, curve, epoch,
   recipient, and transcript binding.
4. Construct public identities and manifests from canonical source records.
5. Encrypt the payload to the customer KMS recipient, or return encrypted role
   fragments for final passphrase wrapping inside the trusted browser or local
   CLI.
6. Sign the outer package digest with the source portability attestation key.
7. Deliver the package to the customer and require a successful decrypt-and-
   inventory verification before cutover can proceed.

The export coordinator handles ciphertext and public manifests. It cannot open
role-private fragments or receive raw role roots.

### Phase D: destination staging

1. Decrypt inside the local restore coordinator or customer KMS boundary.
2. Parse the package once and verify source attestation, package sequence,
   predecessor, snapshot, manifest, and payload digests.
3. Map source tenant scope into the fixed destination scope.
4. Import each incomplete server participant into a fresh destination
   participant identity and epoch while retaining the owner holder binding.
5. Re-encrypt every durable record under destination role KEKs and AAD.
6. Verify Ed25519 public keys, ECDSA threshold public keys, EVM addresses,
   material owners, key slots, participants, and imported lifecycle.
7. Verify the server share, owner holder commitment, and public identity
   relation through the curve-specific handoff proof.
8. Keep all imported server participants staged and incapable of serving
   public signing. Record a first-owner-use canary requirement for each wallet.

### Phase E: final source freeze

1. Increment the tenant migration fence epoch.
2. Reject new signing, recovery, export, agent, credential, device, and policy
   mutations for the migrating tenant.
3. Allow already irreversible chain operations to settle.
4. Reconcile unknown outcomes and produce a zero-unknown-operation inventory.
5. Create the final audit and agent-budget checkpoint.
6. Confirm the staged destination still matches the exact final wallet-key
   manifest.

If mutable portable state changed after the package snapshot, generate a new
package. The destination discards the earlier staging records.

### Phase F: activation and routing cutover

1. Obtain final tenant migration authority approval over the destination
   manifest, continuity receipt, source freeze receipt, and exact wallet-key
   manifest.
2. Activate each destination wallet's complete mixed-key server manifest
   atomically. The tenant cutover may activate many wallets in one fenced
   checkpoint without joining their custody.
3. Mint destination-native sessions only after that wallet's aggregate
   activation commits.
4. Change customer-controlled DNS or edge routing while keeping the wallet
   hostname stable.
5. Run an administrative imported-state canary immediately. Run each wallet's
   transaction-free signing canary on its owner's first authenticated use.
6. Publish the destination activation receipt.

### Phase G: source revocation and cleanup

1. Revoke all migrated tenant execution lanes and server participants.
2. Disable source signing, recovery, export, agent, device, and session
   admission permanently for the migrated wallet-key manifest.
3. Erase tenant-scoped active signing material according to each role's
   deletion and backup-retention procedure.
4. Tombstone source records with the destination activation and migration
   receipt digests.
5. Retain the minimum audit and legal records required by policy, encrypted and
   incapable of signing.
6. Give the customer a source revocation receipt enumerating every affected
   wallet key, lane, participant, and epoch.

### Source-unavailable restore

A current customer-held package must be sufficient to restore the incomplete
managed server participants without the managed control plane. The customer:

1. bootstraps a destination deployment;
2. imports the latest package through the explicit recovery branch;
3. proves control of the tenant package recovery recipient;
4. provisions fresh destination roles and imports the incomplete server
   participants;
5. verifies every public key, address, and owner-holder commitment;
6. activates server handoff through high-assurance tenant approval;
7. requires the normal wallet-owner holder proof before each wallet's first
   signature;
8. records that source revocation could not be acknowledged.

This path preserves wallet identity and restores the server half of
availability. The unavailable source and the new destination each possess, or
may possess, only an incomplete server participant. Neither can sign without
the wallet owner's holder material. No protocol can prove that an unavailable
source erased its old participant. The security claim remains bounded by the
original threshold topology and the source operator threat model. Chain-native
smart accounts may offer stronger signer replacement while keeping the account
address stable; those adapters require separate designs.

## Backup Package Security

The portability package contains the tenant's incomplete server custody and
sensitive account metadata. A party able to decrypt a current package may run
a competing server participant and attempt to interact with wallet owners. It
still lacks each owner's complementary holder material. The package is not a
complete-key export.

Required controls:

- fresh tenant-administrator verification and explicit migration consent;
- optional organization multi-approval policy;
- customer KMS or HSM recipient for managed automatic backups;
- high-entropy passphrase plus fixed Argon2id minimums for manual packages;
- encrypted-at-rest browser download with no analytics, logging, caching, or
  support upload path;
- one visible package fingerprint and wallet-address inventory;
- package replacement and stale-package warnings;
- wallet-owner notification of backup creation, restore, and destination
  activation;
- restore notifications and immutable audit evidence;
- no secret values in filenames, manifests, errors, logs, traces, or receipts;
- restore drills before the package is considered the customer's recovery
  source.

The source attestation proves package origin and contents digest. It does not
replace customer-controlled package encryption, wallet-owner holder custody,
or destination cryptographic verification.

## Public Product And CLI Surface

Managed dashboard:

```text
Create encrypted portability backup
Download backup
Configure customer KMS backup recipient
Verify backup fingerprint and wallet inventory
Prepare self-host migration
Freeze and activate migration
Download source revocation receipt
```

Self-host CLI:

```text
seams self-host init
seams self-host doctor
seams self-host import <package>
seams self-host verify
seams self-host activate
seams self-host backup
seams self-host restore <deployment-recovery-package>
seams self-host status
```

The CLI prints resource identities, public digests, health, and next required
action. It never prints generated secrets. Automation receives the same precise
result union as the interactive CLI.

SDK management APIs:

```text
createTenantPortabilityPackage()
getTenantPortabilityPackageStatus()
verifyTenantPortabilityPackage()
createDeploymentMigration()
getDeploymentMigration()
freezeDeploymentMigrationSource()
activateDeploymentMigrationDestination()
getDeploymentMigrationReceipts()
```

Package creation and migration activation use separate authorization branches.
An ordinary wallet signing, recovery, device, or agent session cannot call
them.

## Failure And Rollback

| Failure point                              | Required outcome                                                                          |
| ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| Destination bootstrap fails                | Source remains active; delete incomplete destination resources                            |
| Package construction fails                 | Source remains active; retain no partial downloadable package                             |
| Package decrypt or validation fails        | Destination remains empty or staged; source remains active                                |
| One wallet key fails continuity            | No key in that mixed wallet activates; discard that wallet's staging                      |
| Source changes after snapshot              | Invalidate staging and create a new package                                               |
| Source freeze fails                        | Destination remains staged; release the tenant fence only after proving no cutover effect |
| Destination activation fails before commit | Destination remains staged; source may unfreeze through an audited abort                  |
| Destination activates and DNS fails        | Keep destination authoritative; repair routing without reactivating source signing        |
| Source revocation acknowledgement fails    | Destination remains authoritative; enter source-revocation incident procedure             |
| Unknown chain operation exists             | Keep source frozen and destination staged until reconciliation completes                  |

Migration state transitions and side effects are idempotent. Retrying one phase
uses the same operation and package digests.

## Implementation Phases

### Phase 0: freeze portability boundaries

- [ ] Freeze `TenantPortabilityPackageV1`, recipient branches, canonical CBOR
      encoding, signature domain, digest, and maximum package size.
- [ ] Freeze exact tenant identity and wallet-key manifests.
- [ ] Specify Ed25519 server-participant handoff and owner-holder commitment
      capsules.
- [ ] Specify ECDSA server-participant handoff and owner-holder commitment
      capsules.
- [ ] Decide which Refactor 100 owner-encrypted envelopes plus incomplete
      server-participant backups satisfy source-unavailable restore and which
      require new material.
- [ ] Freeze source-unavailable threat claims and erase assumptions.
- [ ] Delete `SigningRootMigrationBundleV1` from the target architecture and
      list its code, tests, fixtures, and docs for cutover removal.

### Phase 1: single-tenant deployment compiler

- [ ] Add `SelfHostedDeploymentSpecV1` boundary parser.
- [ ] Generate independent role secrets and public keys in an offline bootstrap
      process.
- [ ] Compile one spec into exact Router, A, B, SigningWorker, and Gateway
      config branches.
- [ ] Create customer-owned Cloudflare resources and install role-local secrets
      without plaintext env files.
- [ ] Emit and verify a signed content-addressed deployment manifest.
- [ ] Promote local init's wrong-role validation patterns into the production
      bootstrapper.
- [ ] Add `self-host doctor` and one complete empty-deployment smoke test.

### Phase 2: tenant export and backup

- [ ] Add a server-canonical tenant export inventory.
- [ ] Add tenant-scoped role fragment builders and cross-tenant denial tests.
- [ ] Add customer-KMS and passphrase encryption branches.
- [ ] Add package sequence, predecessor, freshness, and audit checkpoints.
- [ ] Add dashboard creation, download, fingerprint, replacement, and restore-
      drill status.
- [ ] Prove package and logs contain no deployment-local or cross-tenant secret.

### Phase 3: destination import

- [ ] Add the local restore coordinator and strict package boundary parser.
- [ ] Add source-to-destination tenant identity mapping.
- [ ] Import each curve-specific capsule into fresh destination lanes and
      stores.
- [ ] Verify aggregate public-key and address continuity.
- [ ] Add staged handoff-proof verification and first-owner-use signing
      canaries.
- [ ] Re-encrypt every imported record under destination role KEKs and AAD.

### Phase 4: managed cutover

- [ ] Add tenant-scoped source fencing without pausing other tenants.
- [ ] Add final package refresh after mutation detection.
- [ ] Add aggregate destination activation and source revocation receipts.
- [ ] Integrate stable-domain DNS cutover checks.
- [ ] Add failure injection at every lifecycle transition.
- [ ] Add source-unavailable restore and stale-backup warnings.

### Phase 5: agents, audit, and operations

- [ ] Reconcile agent budgets and unknown operations before freeze.
- [ ] Export inert agent identity and proposed Agent Wallet projections.
- [ ] Require fresh destination delegated-spend authorization.
- [ ] Export customer-visible migration audit evidence.
- [ ] Add notifications, source tombstones, retention, deletion, and incident
      procedures.

### Phase 6: destination disaster recovery

- [ ] Add `SelfHostedDeploymentRecoveryPackageV1`.
- [ ] Back up role-local secrets and storage snapshots under customer custody.
- [ ] Restore a destroyed single-tenant deployment with identical wallet
      identities and fresh runtime epochs.
- [ ] Automate quarterly restore drills and backup-freshness reporting.

### Phase 7: provider-neutral deployment

- [ ] Define one production OCI transport and storage profile after the
      customer-owned Cloudflare profile passes migration drills.
- [ ] Preserve the same role config compiler and tenant package format.
- [ ] Review service-to-service authentication, private storage, secret
      manager, backup, scheduling, and availability independently.
- [ ] Keep local development adapters outside production artifacts.

## Validation

Static fixtures prove:

- managed and self-hosted deployment config branches cannot be combined;
- single-tenant requests always carry the fixed destination tenant context;
- portability packages require a nonempty wallet-key manifest;
- Ed25519 and ECDSA capsules cannot cross key families;
- raw private-key fields and complete-key export material cannot construct a
  tenant portability capsule;
- active authorization, session, presignature, replay, lease, or deployment
  secret fields cannot enter package records;
- an old signing-root migration bundle cannot enter the new importer;
- imported records require destination role, deployment, tenant, key, lane,
  participant, and epoch bindings.

Cryptographic tests prove:

- package tampering, truncation, reordering, wrong recipient, wrong package ID,
  wrong tenant, wrong wallet, wrong curve, wrong epoch, and wrong predecessor
  fail;
- customer-KMS and passphrase packages decrypt only through their exact branch;
- wrong or weak Argon2id parameters fail parsing;
- cooperative and source-unavailable imports preserve keys without opening
  complete private keys in any deployment or tenant-admin component;
- imported server material remains cryptographically incomplete without the
  wallet owner's holder material;
- destination Ed25519 public keys, ECDSA public keys, and EVM addresses equal
  the package manifest exactly;
- destination handoff proofs bind every server participant to the preserved
  public key and owner-holder commitment;
- destination role records fail under source or opposite-role KEKs and AAD.

Tenant-isolation tests prove:

- exporting tenant A cannot read, count, infer, or package tenant B records;
- shared root shares, KEKs, relayer keys, API tokens, and databases never appear
  in tenant packages;
- migration fencing blocks tenant A and leaves tenant B registration, signing,
  recovery, and agents available;
- a package cannot import over an unrelated or already active tenant;
- one fixed destination tenant cannot be selected through caller input.

Lifecycle tests prove:

- partial mixed-wallet staging never activates;
- mutation after snapshot invalidates staging;
- unknown execution outcomes block cutover;
- destination activation cannot precede source freeze and tenant migration
  authority approval;
- source unfreeze is available only before destination activation;
- source sessions and lanes fail after revocation;
- destination sessions fail before that wallet's aggregate activation and
  succeed after it;
- retrying every phase is idempotent;
- Agent Wallet projections remain inactive until freshly authorized;
- stale offline backup restore reports the exact snapshot checkpoint.

Operational tests prove:

- a new customer-owned Cloudflare deployment requires no manual role env or
  secret editing;
- one spec creates distinct Workers, stores, keys, bindings, and audit labels;
- `self-host doctor` detects shared A/B credentials, stores, or keys;
- generated artifacts contain no secrets;
- backup and restore succeed after complete destination resource deletion;
- normal Ed25519 and ECDSA signing makes zero Deriver calls;
- a complete managed-to-self-hosted cutover preserves all wallet addresses;
- the customer-owned wallet origin and RP ID continue to unlock existing
  credentials when kept stable.

## Non-Goals

- migrating managed platform operational secrets into customer infrastructure;
- copying source databases or retaining source persistence readers;
- making all current Router A/B environment variables customer-facing config;
- collapsing Deriver A, Deriver B, and SigningWorker private state into one
  runtime secret bag;
- promising cryptographic proof that an unavailable external source erased old
  material;
- exporting passkey private keys;
- preserving source sessions, presignatures, replay caches, or in-flight
  reservations;
- silently activating migrated Agent Wallet authorizations;
- supporting every cloud, orchestrator, database, KMS, and HSM in the first
  release;
- changing wallet public identities merely to simplify deployment;
- maintaining the old signing-root migration format or dual import paths.

## Decisions Required Before Implementation

- Freeze the server-participant handoff and owner-holder commitment capsule for
  Ed25519 wallet keys.
- Freeze the server-participant handoff and owner-holder commitment capsule for
  ECDSA wallet keys.
- Decide whether the passphrase package is available to organizations by
  default or requires an explicit policy override in favor of customer KMS.
- Define maximum acceptable backup age and which wallet changes require an
  immediate replacement package.
- Define the organization approval policy for package creation and destination
  activation.
- Select the first customer-owned Cloudflare bootstrap credential flow and its
  minimum API scopes.
- Decide whether Gateway shares the deployment bootstrap command while
  retaining a separate release artifact and secret set.
- Freeze destination relayer ownership, funding, and cutover behavior for each
  supported network.
- Define source tombstone retention and deletion evidence for regulated
  customers.
- Define the first OCI production target before making a provider-neutral
  self-hosting claim beyond customer-owned Cloudflare.
