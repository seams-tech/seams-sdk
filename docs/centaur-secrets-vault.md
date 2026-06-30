# Centaur Secrets Vault Architecture Plan

Status: architecture plan

Related plan:

- [Cloudflare-Native Centaur Fork Plan](./centaur-cloud-fork.md)

## Objective

Design the first-party secrets vault for the Cloudflare-native Centaur fork.
The vault should let merchant operators store credentials, delegate controlled
use to agents, and route privileged calls through trusted Worker-side egress
handlers without giving agents reusable plaintext secrets by default.

The vault is a runtime control surface, not a general consumer password manager.
It should support dashboard management, Slack approvals, typed tools, model
gateway calls, merchant API egress, raw database leases, audit, and optional
1Password integration.

## Resolved Design Decisions

These decisions define the first architecture pass:

1. Build a first-party multi-tenant vault for merchant secrets.
2. Use Cloudflare Secrets Store and Worker secrets only for platform secrets,
   bootstrap material, and platform adapter credentials. Tenant connector
   tokens belong in the vault custody model.
3. Make cloud Worker injection the default runtime mode.
4. Do not claim server-blindness for the default cloud-injection path.
5. Keep server-blind merchant sidecar injection as a future enterprise mode.
6. Keep own-vault storage as the primary secret backend.
7. Treat 1Password as an adapter: live Connect reads or sync into own vault.
8. Delegate members receive `VaultFieldSelector` values, placeholder
   credentials, and short-lived use grants.
9. Delegate members do not receive reusable plaintext secrets.
10. Use Seams authorization and short-lived `CapabilityGrant` records as the
    default gate for vault runtime operations.
11. Treat `mpc_signer_proof` as optional high-assurance grant evidence for
    tenants that enable MPC capabilities.
12. Treat threshold unwrap as a later extension for sidecar or customer-managed
    key modes.
13. Store tenant-scoped metadata, permissions, grants, and access indexes in D1.
14. Store encrypted secret payloads and wrapped key blobs in R2 unless the
    payload is small enough to justify D1 storage.
15. Model vault access as a capability instance gated by the same
    auth/evidence/grant infrastructure used for MPC signing and key export.
16. Let registration provision capability instances independently:
    `near_ed25519_mpc_signing`, `evm_ecdsa_mpc_signing`, and `vault_access`.
17. Support vault-only customers that use Seams auth, sessions, step-up, grants,
    and audit without provisioning wallet signers.
18. Model humans, agents, and services as first-class principals that can all
    become team members.
19. Use membership access mode to distinguish direct vault access from
    proxy-only delegated use.
20. Default agent memberships to `delegate_member`, while allowing explicit
    promotion to direct membership when a team chooses that trust level.

Product claim:

```text
Delegate members can use secrets without receiving secrets.
Agents default to delegate-member access.
```

Do not claim:

```text
Seams cloud is blind to secrets during cloud injection.
```

## Product Invariants

1. Delegate members receive secret references, placeholder credentials, signed
   use grants, or scoped proxy tokens.
2. Delegate members do not receive reusable plaintext secrets.
3. Secret readback is a separate privileged action from secret use.
4. Every item, field, permission, grant, access intent, audit event, and egress
   decision carries a required tenant identity.
5. Untrusted inputs are normalized once at the request or persistence boundary.
6. Core logic accepts precise domain types instead of raw route bodies, D1 rows,
   Slack payloads, or adapter-specific shapes.
7. Stored secret values are encrypted before persistence.
8. Runtime plaintext exists only inside an approved cloud injection boundary,
   human reveal boundary, or future merchant sidecar boundary.
9. The default cloud injection path is trusted-cloud execution, not server-blind
   execution.
10. Strict server-blind tenants require a merchant-side proxy or sidecar
   injection boundary.
11. Revocation of a secret that has ever been revealed requires rotation.
12. Team permissions resolve through membership access mode before becoming
    effective vault access.
13. `delegate_member` access permits brokered use through Egress Gateway, DB
    Gateway, or Model Gateway and rejects reveal, export, raw readback, manage,
    and delegate actions.
14. Agents use the same principal, membership, role, grant, and audit schema as
    humans and services.

## Scope

In scope:

- Dashboard-managed secret creation, update, rotation, archiving, tagging, and
  grant management.
- Slack approval flows for sensitive access.
- Worker-side Secret Broker APIs for typed tools, model gateway calls, egress
  transforms, and raw database leases.
- Short-lived vault `CapabilityGrant` issuance using Seams sessions, grant
  evidence, policies, and optional MPC signer proof.
- Own-vault encrypted payload storage.
- 1Password adapter modes for live reads and sync/import.
- Vault-only registration that provisions auth and vault access without
  Ed25519 or ECDSA wallet signer setup.
- Team-based RBAC for humans, agents, and service principals, with direct and
  delegate member access modes.
- Audit records for every mutation, grant decision, reveal, injection, and
  failed access attempt.

Out of scope for the first design:

- Browser extension autofill.
- Desktop or mobile vault clients.
- Consumer password-manager import UX.
- Offline editable vaults.
- Shared family or personal-password workflows.
- Broad plaintext export APIs.

## Trust Boundaries

| Boundary | Sees plaintext? | Responsibility |
| --- | --- | --- |
| Dashboard browser during create/update/reveal | Yes, for the acting human | Secret entry, optional reveal, local encryption before upload where configured |
| D1 metadata store | No | Tenant-scoped metadata, permissions, grants, indexes, lifecycle state |
| R2 encrypted blob store | No | Encrypted secret payloads, large audit payloads, adapter sync blobs |
| Secret Broker Worker | Yes, only for approved cloud-injection mode | Policy, unwrap, injection grant minting, audit |
| Egress Gateway Worker | Yes, only for approved cloud-injection mode | Request rewrite, upstream call, redacted audit |
| Merchant sidecar | Yes, only for strict server-blind tenants | Local unwrap and injection |
| Agent container | No by default | Tool calls with secret references and placeholders |
| 1Password adapter | Depends on adapter mode | Live fetch or sync source |

Runtime modes should be explicit. `cloud_worker_injection` is the required
default. `merchant_sidecar_injection` is an enterprise extension path.

```ts
type VaultRuntimePlaintextBoundary =
  | {
      kind: "cloud_worker_injection";
      tenantId: TenantId;
      workerBoundaryId: WorkerBoundaryId;
      sidecarId?: never;
    }
  | {
      kind: "merchant_sidecar_injection";
      tenantId: TenantId;
      sidecarId: SidecarId;
      workerBoundaryId?: never;
    };
```

## Target Architecture

```text
Dashboard / Slack / Tool Gateway / Egress Gateway
   |
Vault API Worker
   |
Tenant Resolver + Auth + Boundary Parsers
   |
Secret Broker
   |----------------------------|
   |                            |
D1 metadata                R2 encrypted payloads
   |
Capability Grant Durable Object
   |
Policy Engine + Approval Workflow
   |
Seams Authorization
   |
short-lived CapabilityGrant
   |
Egress Gateway / DB Gateway / Model Gateway / merchant sidecar
```

Component responsibilities:

| Component | Cloudflare service | Responsibility |
| --- | --- | --- |
| Vault API Worker | Workers | Dashboard and internal API routes |
| Secret Broker | Workers | Grant resolution, policy checks, unwrap orchestration, 1Password adapters |
| Capability Grant DO | Durable Objects | One-time grant state, replay locks, grant counters, per-item and per-field hot locks |
| Approval Workflow | Workflows | Human approval, expiration, retry, escalation |
| Async jobs | Queues | Rotation jobs, sync jobs, audit fanout |
| Metadata | D1 | Tenant-scoped vault metadata, permissions, grants, version indexes |
| Encrypted payloads | R2 or D1 BLOBs | Secret ciphertext and adapter sync blobs |
| Platform bootstrap secrets | Cloudflare Secrets Store / Worker secrets | Platform-only bootstrap material |
| Egress Gateway | Workers | Secret injection, upstream fetch, redacted audit |

Cloudflare Secrets Store should hold platform operational secrets only. Merchant
secrets belong in the first-party vault, because tenant grants, policy, audit,
and export controls are product data.

Cloudflare Secrets Store is account-level infrastructure for reusable
Cloudflare-bound secrets. It is useful for deploying platform secrets to Workers
and AI Gateway, but it does not model merchant tenants, agent grants, one-time
egress grants, MPC authorization, rotation state, or product audit. Those are
first-party vault responsibilities.

## Domain Model

Use a 1Password-style item model with typed fields and immutable versions.
The user-facing object is a `VaultItem`; the exact authorization target is a
field inside a specific item version.

```ts
type VaultItemLifecycle =
  | { kind: "draft"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId }
  | { kind: "active"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId; activeVersionId: VaultItemVersionId }
  | { kind: "rotating"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId; fromVersionId: VaultItemVersionId; rotationId: RotationId }
  | { kind: "archived"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId; archivedBy: PrincipalId; archivedAt: IsoTimestamp };

type VaultItemCategory =
  | "api_credential"
  | "login"
  | "database"
  | "oauth_client"
  | "ssh_key"
  | "tls_certificate"
  | "webhook_secret"
  | "model_provider_key"
  | "service_account_json"
  | "server"
  | "generic_secret";

type VaultBackend =
  | { kind: "own_vault"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId }
  | { kind: "onepassword_connect"; tenantId: TenantId; vaultId: VaultId; sourceVaultId: OnePasswordVaultId; sourceItemId: OnePasswordItemId }
  | { kind: "onepassword_sync"; tenantId: TenantId; vaultId: VaultId; sourceVaultId: OnePasswordVaultId; syncedItemId: VaultItemId; sourceItemId: OnePasswordItemId };

type VaultFieldKind =
  | "secret"
  | "text"
  | "url"
  | "hostname"
  | "username"
  | "password"
  | "port"
  | "json"
  | "otp_seed"
  | "private_key"
  | "certificate"
  | "file";

type VaultFieldSensitivity =
  | "public_display"
  | "tenant_sensitive_metadata"
  | "secret_value";

type VaultItem = {
  tenantId: TenantId;
  vaultId: VaultId;
  itemId: VaultItemId;
  backend: VaultBackend;
  category: VaultItemCategory;
  lifecycle: VaultItemLifecycle;
  displayName: string;
  labels: VaultLabel[];
  createdBy: PrincipalId;
  createdAt: IsoTimestamp;
  updatedAt: IsoTimestamp;
};

type VaultItemVersion = {
  tenantId: TenantId;
  vaultId: VaultId;
  itemId: VaultItemId;
  versionId: VaultItemVersionId;
  schemaVersion: 1;
  createdBy: PrincipalId;
  createdAt: IsoTimestamp;
  activatedAt: IsoTimestamp | null;
  retiredAt: IsoTimestamp | null;
};

type VaultField = {
  tenantId: TenantId;
  vaultId: VaultId;
  itemId: VaultItemId;
  versionId: VaultItemVersionId;
  fieldId: VaultFieldId;
  sectionId: VaultSectionId;
  label: string;
  kind: VaultFieldKind;
  semanticPurpose: VaultFieldSemanticPurpose;
  sensitivity: VaultFieldSensitivity;
  valueRef: VaultFieldValueRef;
};
```

Field-level access is the default. Dashboard UI can display item-level
groupings, while policy and permissions remain precise enough for egress
injection, database leases, reveal, and rotation.

```ts
type VaultFieldSelector =
  | {
      kind: "active_field";
      tenantId: TenantId;
      vaultId: VaultId;
      itemId: VaultItemId;
      fieldId: VaultFieldId;
    }
  | {
      kind: "versioned_field";
      tenantId: TenantId;
      vaultId: VaultId;
      itemId: VaultItemId;
      versionId: VaultItemVersionId;
      fieldId: VaultFieldId;
    };

type ResolvedVaultFieldRef = {
  kind: "resolved_vault_field_ref";
  tenantId: TenantId;
  vaultId: VaultId;
  itemId: VaultItemId;
  versionId: VaultItemVersionId;
  fieldId: VaultFieldId;
  envelopeId: VaultFieldEnvelopeId;
};

type VaultAccessLane = {
  kind: "vault_access_lane";
  tenantId: TenantId;
  capabilityId: CapabilityId;
  operationKind:
    | "vault.proxy_use"
    | "vault.mint_scoped_credential"
    | "vault.reveal"
    | "vault.rotate"
    | "vault.permission_change"
    | "vault.break_glass_reveal";
  vaultId: VaultId;
  itemId: VaultItemId;
  fieldId: VaultFieldId | null;
  projectId: ProjectId | null;
  environmentId: EnvironmentId | null;
};
```

Selectors can point at the active field for dashboard and tool ergonomics.
Runtime execution resolves the selector once to `ResolvedVaultFieldRef` before
policy evaluation, digest construction, and secret unwrap. Rotation creates a new
version and changes the active pointer; existing runtime grants stay bound to the
resolved version they authorized.

Access intents are capability-local. They are parsed by the vault module, then
converted into a generic `CapabilityOperationEnvelope` for Seams authorization:

```ts
type VaultAccessIntent =
  | {
      kind: "use_via_egress";
      lane: VaultAccessLane;
      fieldRef: ResolvedVaultFieldRef;
      principal: Principal;
      executionId: ExecutionId;
      destination: EgressDestination;
      injection: EgressInjectionRule;
      proxyBindingId: VaultProxyBindingId;
      revealReason?: never;
    }
  | {
      kind: "mint_scoped_credential";
      lane: VaultAccessLane;
      fieldRef: ResolvedVaultFieldRef;
      principal: Principal;
      executionId: ExecutionId;
      credentialAudience: CredentialAudience;
      destination?: never;
      injection?: never;
      revealReason?: never;
    }
  | {
      kind: "reveal_to_human";
      lane: VaultAccessLane;
      fieldRef: ResolvedVaultFieldRef;
      principal: Principal;
      sessionId: SeamsSessionId;
      approvalId: ApprovalId;
      revealReason: RevealReason;
      executionId?: never;
      destination?: never;
      injection?: never;
    }
  | {
      kind: "rotate_item";
      lane: VaultAccessLane;
      principal: Principal;
      rotationId: RotationId;
      requestedActiveVersionId: VaultItemVersionId;
      fieldRef?: never;
      executionId?: never;
      destination?: never;
      injection?: never;
      revealReason?: never;
    };
```

Durable vault permissions are separate from short-lived capability grants:

```ts
type VaultPermissionAction =
  | "vault.item.metadata.read"
  | "vault.field.use_via_egress"
  | "vault.field.mint_scoped_credential"
  | "vault.field.reveal_to_human"
  | "vault.item.rotate"
  | "vault.item.delegate"
  | "vault.item.manage"
  | "vault.break_glass.reveal";

type VaultPermissionScope =
  | { kind: "vault"; tenantId: TenantId; vaultId: VaultId }
  | { kind: "item"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId }
  | { kind: "field"; tenantId: TenantId; vaultId: VaultId; itemId: VaultItemId; fieldId: VaultFieldId }
  | { kind: "label"; tenantId: TenantId; label: VaultLabel }
  | { kind: "environment"; tenantId: TenantId; environmentId: EnvironmentId }
  | { kind: "project"; tenantId: TenantId; projectId: ProjectId };

type VaultPermissionSubject =
  | { kind: "principal"; tenantId: TenantId; principalId: PrincipalId }
  | { kind: "team"; tenantId: TenantId; teamId: TeamId }
  | { kind: "role"; tenantId: TenantId; roleId: RoleId };

type VaultPermissionGrant = {
  kind: "vault_permission_grant";
  tenantId: TenantId;
  permissionId: VaultPermissionId;
  subject: VaultPermissionSubject;
  scope: VaultPermissionScope;
  actions: VaultPermissionAction[];
  constraints: VaultPermissionConstraints;
  status: "active" | "suspended" | "revoked";
  createdBy: PrincipalId;
  createdAt: IsoTimestamp;
};
```

`VaultPermissionGrant` answers whether a principal can request an operation.
`CapabilityGrant` answers whether this exact operation instance has satisfied
session, evidence, approval, digest, TTL, replay, and policy requirements.

## Team RBAC And Member Access Modes

Humans, agents, and services should use one principal and team membership model.
Agents are first-class members when a tenant chooses to add them to a team.
The default agent membership mode is `delegate_member`, which allows proxy-only
secret use without reveal or raw readback.

```ts
type Principal =
  | {
      kind: "human";
      tenantId: TenantId;
      principalId: PrincipalId;
      displayName: string;
    }
  | {
      kind: "agent";
      tenantId: TenantId;
      principalId: PrincipalId;
      agentId: AgentId;
      displayName: string;
    }
  | {
      kind: "service";
      tenantId: TenantId;
      principalId: PrincipalId;
      serviceId: ServiceId;
      displayName: string;
    };

type MemberAccessMode =
  | {
      kind: "direct_member";
      canRevealSecrets: boolean;
      canManageGrants: boolean;
      canDelegateAccess: boolean;
      proxyOnly?: never;
    }
  | {
      kind: "delegate_member";
      proxyOnly: true;
      canRevealSecrets?: never;
      canManageGrants?: never;
      canDelegateAccess?: never;
    }
  | {
      kind: "metadata_only";
      canRevealSecrets?: never;
      canManageGrants?: never;
      canDelegateAccess?: never;
      proxyOnly?: never;
    }
  | {
      kind: "approval_only";
      canRevealSecrets?: never;
      canManageGrants?: never;
      canDelegateAccess?: never;
      proxyOnly?: never;
    };

type TeamMembership = {
  tenantId: TenantId;
  teamId: TeamId;
  principalId: PrincipalId;
  roleId: RoleId;
  accessMode: MemberAccessMode;
  createdBy: PrincipalId;
  createdAt: IsoTimestamp;
};
```

Effective access is the intersection of durable permissions, capability policy,
and membership mode:

```text
principal direct permissions
  + team permissions
  + role permissions
  + item or field permissions
  ∩ membership access mode
  ∩ capability grant policy
  ∩ runtime boundary
```

Examples:

| Member | Team | Access mode | Result |
| --- | --- | --- | --- |
| Alice | Support Ops | `direct_member` | Can reveal or manage secrets only when permissions and policy allow it |
| refunds-agent | Support Ops | `delegate_member` | Can use approved fields through Egress Gateway only |
| ops-agent | Platform Admins | `direct_member` | Treated like a promoted team member under explicit tenant policy |
| billing-service | Finance | `delegate_member` | Can mint scoped credentials or use proxy-only egress |
| reviewer | Security | `approval_only` | Can approve access without receiving or using the secret |

Admin UI should expose this distinction as:

```text
Share with team
Delegate to member
Promote member to direct access
```

Use one permission system for agents, humans, and services. Membership mode
constrains how a principal can request a runtime grant.

## Capability Authorization Model

Registration should provision capabilities independently. Wallet customers can
receive signing and vault capabilities. Vault-only customers receive
`vault_access` without Ed25519 or ECDSA signer provisioning.

The shared authorization layer must stay generic. It owns sessions, grant
evidence, capability bindings, policy resolution, TTL, remaining uses, replay
checks, grant consumption, and audit envelopes. The vault module owns vault
items, fields, lanes, intents, display text, egress policy, unwrap, reveal, and
rotation.

```ts
type ResourceScope =
  | { kind: "tenant"; tenantId: TenantId }
  | { kind: "project"; tenantId: TenantId; projectId: ProjectId }
  | {
      kind: "environment";
      tenantId: TenantId;
      projectId: ProjectId;
      environmentId: EnvironmentId;
    };

type CapabilityInstance = {
  kind: "capability_instance";
  tenantId: TenantId;
  capabilityId: CapabilityId;
  capabilityKind:
    | "vault_access"
    | "near_ed25519_mpc_signing"
    | "evm_ecdsa_mpc_signing";
  resourceScope: ResourceScope;
  defaultPolicyId: PolicyId;
  configDigest: DigestB64u;
  lifecycle: "active" | "suspended" | "deleted";
};

type CapabilityBindingKind =
  | "owner"
  | "admin"
  | "direct_member"
  | "delegate_member";

type CapabilityBinding = {
  kind: "capability_binding";
  tenantId: TenantId;
  bindingId: CapabilityBindingId;
  capabilityId: CapabilityId;
  principalId: PrincipalId;
  bindingKind: CapabilityBindingKind;
  lifecycle: "active" | "suspended" | "deleted";
};

type CapabilityOperationEnvelope = {
  kind: "capability_operation_envelope";
  tenantId: TenantId;
  principalId: PrincipalId;
  capabilityKind: CapabilityKind;
  capabilityId: CapabilityId;
  operationKind: CapabilityOperationKind;
  laneDigest: DigestB64u;
  intentDigest: DigestB64u;
  displayDigest: DigestB64u;
};
```

Capability modules register operation descriptors. The descriptor normalizes a
parsed vault intent into:

- `laneDigest`, which binds the stable authorization lane such as
  `vault.proxy_use` or `vault.reveal`;
- `intentDigest`, which binds the exact field, version, destination, injection
  rule, reason, expiry, nonce, and execution context;
- `displayDigest`, which binds the human prompt and audit display.

Requests never carry `CapabilityGrantPolicy`. Seams authorization resolves
policy server-side from tenant, capability, resource scope, principal binding,
operation kind, evidence, and environment. The resolved policy ID is recorded on
the `CapabilityGrant`.

Shared authorization flow:

```text
principal + SeamsSession or service-account evidence
  -> capability-local lane, intent, and display digests
  -> server-side policy resolution
  -> required grant evidence challenges or approvals
  -> short-lived CapabilityGrant
  -> vault executor consumes the grant
  -> audit and replay lock
```

Default vault policy should be usable without MPC:

| Vault operation | Default grant evidence |
| --- | --- |
| Proxy use by delegate member | `seams_session` or `service_account_api_key` plus policy-bound capability binding |
| Mint scoped credential | `seams_session` or `service_account_api_key` plus stricter destination/audience policy |
| Human reveal | `passkey_assertion` or configured SSO assurance, direct-member binding, and tenant reveal policy |
| Permission change | `passkey_assertion` and direct admin binding |
| Break-glass reveal | `approval_decision` plus `passkey_assertion` |
| High-assurance export or regulated reveal | Tenant policy may require `mpc_signer_proof` |

## Encryption And Key Hierarchy

Use envelope encryption for own-vault payloads:

```text
secret plaintext
  -> random VaultFieldDataKey
  -> ciphertext + AAD
  -> wrapped VaultFieldDataKey records
```

Suggested key levels:

| Key | Owner | Purpose |
| --- | --- | --- |
| Platform bootstrap key | Cloudflare account | Open platform wrapping material and service credentials |
| Tenant vault root | Tenant or platform tier | Wrap project or environment keys |
| Project/environment wrapping key | Tenant scope | Wrap secret data keys |
| Field data key | Per item version field | Encrypt one secret-bearing field value |
| Session use grant key | Per approved use | Bind one egress or reveal operation |

Associated data must bind ciphertext to its tenant, item, version, and field
identity:

```ts
type VaultFieldEnvelopeAAD = {
  tenantId: TenantId;
  vaultId: VaultId;
  itemId: VaultItemId;
  versionId: VaultItemVersionId;
  fieldId: VaultFieldId;
  backendKind: "own_vault";
  fieldKind: VaultFieldKind;
  semanticPurpose: VaultFieldSemanticPurpose;
  createdAt: IsoTimestamp;
  schemaVersion: 1;
};
```

Do not reuse wallet key-material storage types for vault items. Reuse the
envelope pattern and AAD discipline, then create vault-specific parsers,
builders, and static fixtures.

MVP encryption stance:

- Dashboard writes send secret plaintext to the Vault API over TLS.
- The Vault API encrypts before persistence.
- R2 and D1 never store plaintext secret values.
- Browser-side encryption is optional in the first release because default cloud
  injection already requires a trusted cloud plaintext boundary.
- Browser-side encryption becomes important for sidecar or customer-managed key
  modes.

Strict server-blind tenants should store ciphertext in Seams cloud and keep the
unwrap key material in a merchant sidecar or customer-controlled key provider.
Cloudflare Workers then issue signed policy grants and audit decisions while
the sidecar performs plaintext injection.

## MPC Signer Role

The first vault release should treat the Seams MPC signer as optional
high-assurance grant evidence. It should not be the primary data decryption
primitive, and it should not be required for vault-only tenants.

When tenant policy requires `mpc_signer_proof`, the signer should authorize the
same capability operation envelope used for non-MPC grant evidence:

```text
MpcVaultGrantEvidenceChallenge =
  H(
    tenantId,
    principalId,
    sessionId,
    signerCapabilityId,
    targetCapabilityId,
    operationKind,
    laneDigest,
    intentDigest,
    displayDigest,
    evidencePolicyId,
    policyVersion,
    deviceId,
    expiresAt,
    nonce
  )
```

The Secret Broker and Egress Gateway require a fresh `CapabilityGrant` before
unwrapping and injecting a secret. Tenant policy can require that the grant
include `mpc_signer_proof`, passkey assertion, Slack OTP, SSO assurance,
service-account evidence, approval evidence, or a configured combination.

MPC authorization does not make cloud injection server-blind because the Worker
still handles plaintext after authorization.

Future modes can use MPC or threshold cryptography for unwrap participation:

- browser reveal where final plaintext is reconstructed in the dashboard;
- merchant sidecar injection where final plaintext is reconstructed locally;
- customer-managed key mode where Seams signs policy grants and the customer
  key provider performs unwrap.

## Secret Write Flow

```text
Admin opens dashboard
  -> enters secret value
  -> browser validates metadata
  -> Vault API receives plaintext over TLS in default cloud-injection mode
  -> Vault API creates item, version, and typed fields
  -> Vault API encrypts secret-bearing fields before persistence
  -> Vault API stores item and field metadata in D1
  -> Vault API stores ciphertext in R2 or D1
  -> Secret Broker creates initial permissions
  -> audit records vault.item.created
```

Required validation:

- Tenant context.
- Acting principal.
- Field value kind.
- Item and field scope.
- Lifecycle branch.
- Item category.
- Field kind and sensitivity.
- Label set.
- Permission action set.
- Encrypted envelope AAD.

The API should never echo secret values after creation. Creation and rotation
responses return metadata, version ID, fingerprint, and audit ID.

Client-side encryption can be added as a branch-specific write path later:

```ts
type SecretWriteMode =
  | { kind: "cloud_encrypt"; tenantId: TenantId }
  | { kind: "browser_encrypt_for_sidecar"; tenantId: TenantId; sidecarPublicKeyId: SidecarPublicKeyId }
  | { kind: "browser_encrypt_for_customer_kms"; tenantId: TenantId; kmsKeyId: CustomerKmsKeyId };
```

## Secret Use Flow

```text
Agent calls typed tool with `VaultFieldSelector`
  -> Tool Gateway resolves item, active version, and field
  -> Tool Gateway builds VaultAccessIntent
  -> Secret Broker resolves durable vault permissions
  -> Policy Engine evaluates destination, action, budget, tenant, principal, and session
  -> Approval Workflow runs when policy requires it
  -> Seams Authorization verifies required grant evidence
  -> Capability Grant DO stores one-time CapabilityGrant replay lock
  -> Egress Gateway injects secret into the approved request
  -> audit records allow or deny
```

The one-time `CapabilityGrant` should bind:

- `tenantId`
- `capabilityId`
- `operationKind`
- `itemId`
- `versionId`
- `fieldId`
- `envelopeId`
- `principalId`
- grant evidence set digest
- `executionId`
- destination host
- method and path policy
- injection location
- expiration
- nonce
- policy version
- `laneDigest`
- `intentDigest`
- `displayDigest`

Grant replay must fail closed.

## Reveal And Break-Glass Flow

Reveal is an admin operation with a different lifecycle from use:

```text
Admin requests reveal
  -> Policy Engine checks reveal permission
  -> Seams Authorization resolves reveal grant policy
  -> step-up or SSO assurance required
  -> approval required when tenant policy says so
  -> optional MPC signer proof required when tenant policy says so
  -> dashboard displays value once
  -> audit records vault.field.revealed
```

Reveal should be disabled for `delegate_member` principals. Agents default to
`delegate_member`, so agent reveal requires explicit promotion to direct
membership plus a permission, runtime grant, and tenant policy that allow
reveal. Tenant policy can
disable reveal entirely. Export is a separate action and should remain out of
the MVP unless an enterprise requirement forces it.

## Egress Integration

The Egress Gateway should support these injection modes:

| Mode | Example | Notes |
| --- | --- | --- |
| Header injection | `Authorization: Bearer ...` | Default for API tokens |
| Query injection | `?api_key=...` | Allow only for trusted hosts |
| Basic auth | `Authorization: Basic ...` | Build inside gateway |
| Placeholder replacement | `sk_seams_placeholder_*` | For harnesses that require API-key-shaped values |
| OAuth exchange | refresh token to access token | Prefer short-lived access tokens |
| AWS SigV4 / GCP token | signed upstream request | Keep signer code in trusted gateway |

Egress policy must match host, method, path, and injection location before the
Secret Broker unwraps or fetches the secret.

The gateway must also defend against egress bypass:

- no direct credential access for `delegate_member` principals;
- no default open internet egress from containers;
- deny redirects to unapproved hosts;
- deny credential injection after host or scheme changes;
- canonicalize host, scheme, method, path, and port before matching;
- redact injected headers and query parameters before audit persistence;
- bind each outbound request to a tenant, evidence set, execution, and
  capability grant ID.

## 1Password Adapter Plan

Support two adapter modes:

```ts
type OnePasswordMode =
  | {
      kind: "connect_live";
      tenantId: TenantId;
      connectServerCredentialRef: VaultFieldSelector;
      sourceVaultId: OnePasswordVaultId;
    }
  | {
      kind: "sync_to_own_vault";
      tenantId: TenantId;
      sourceVaultId: OnePasswordVaultId;
      syncedAt: IsoTimestamp;
      targetLabel: VaultLabel;
    };
```

`connect_live` keeps 1Password as the source of truth and resolves at runtime.
`sync_to_own_vault` imports selected items into the first-party vault for lower
latency and stronger grant/audit semantics.

Adapter rules:

- Adapter credentials are tenant-scoped secrets.
- Runtime reads go through the same `VaultAccessIntent` path.
- Synced secrets receive first-party item and field IDs.
- Sync jobs record source item fingerprints and last sync timestamps.
- 1Password item IDs should not leak to agents.

## Persistence Plan

Add or refine these D1 tables:

```text
principals(
  tenant_id,
  principal_id,
  principal_kind,
  foreign_id,
  display_name,
  status,
  created_at,
  updated_at
)

teams(
  tenant_id,
  team_id,
  display_name,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

roles(
  tenant_id,
  role_id,
  display_name,
  status,
  created_at,
  updated_at
)

team_memberships(
  tenant_id,
  team_id,
  principal_id,
  role_id,
  access_mode_kind,
  access_mode_json,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

capability_instances(
  tenant_id,
  capability_id,
  capability_kind,
  resource_scope_kind,
  resource_scope_id,
  lifecycle_kind,
  config_digest,
  default_policy_id,
  created_by_principal_id,
  created_at,
  updated_at
)

capability_bindings(
  tenant_id,
  binding_id,
  capability_id,
  principal_id,
  binding_kind,
  lifecycle_kind,
  created_by_principal_id,
  created_at,
  updated_at
)

grant_evidence_refs(
  tenant_id,
  evidence_ref_id,
  principal_id,
  evidence_ref_kind,
  evidence_digest,
  lane_digest,
  intent_digest,
  display_digest,
  source_ref_json,
  asserted_at,
  expires_at
)

capability_grants(
  tenant_id,
  grant_id,
  capability_id,
  principal_id,
  operation_kind,
  lane_digest,
  intent_digest,
  display_digest,
  policy_id,
  policy_version_id,
  evidence_set_digest,
  remaining_uses,
  status,
  created_at,
  expires_at,
  consumed_at
)

vaults(
  tenant_id,
  vault_id,
  display_name,
  resource_scope_kind,
  resource_scope_id,
  default_capability_id,
  lifecycle_kind,
  created_by_principal_id,
  created_at,
  updated_at
)

vault_items(
  tenant_id,
  vault_id,
  item_id,
  backend_kind,
  category,
  display_name,
  labels_json,
  lifecycle_kind,
  active_version_id,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

vault_item_versions(
  tenant_id,
  vault_id,
  item_id,
  version_id,
  schema_version,
  encrypted_blob_ref,
  ciphertext_fingerprint,
  aad_json,
  created_by_principal_id,
  created_at,
  activated_at,
  retired_at
)

vault_item_fields(
  tenant_id,
  vault_id,
  item_id,
  version_id,
  field_id,
  section_id,
  label,
  field_kind,
  semantic_purpose,
  sensitivity,
  value_ref,
  index_value_hash,
  created_at
)

vault_item_attachments(
  tenant_id,
  vault_id,
  item_id,
  version_id,
  attachment_id,
  content_type,
  encrypted_blob_ref,
  size_bytes,
  fingerprint,
  created_at
)

vault_wrapped_keys(
  tenant_id,
  vault_id,
  item_id,
  version_id,
  field_id,
  wrapping_scope_kind,
  wrapping_scope_id,
  wrapped_data_key_ref,
  wrapping_key_version,
  status,
  created_at
)

vault_permission_grants(
  tenant_id,
  permission_id,
  subject_kind,
  subject_id,
  scope_kind,
  scope_id,
  actions_json,
  constraints_json,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

vault_proxy_bindings(
  tenant_id,
  proxy_binding_id,
  vault_id,
  item_id,
  field_id,
  destination_policy_json,
  injection_rule_json,
  response_redaction_json,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

vault_access_events(
  tenant_id,
  request_id,
  capability_grant_id,
  vault_id,
  item_id,
  version_id,
  field_id,
  envelope_id,
  principal_id,
  evidence_set_digest,
  execution_id,
  intent_kind,
  destination_json,
  decision,
  policy_version_id,
  approval_id,
  lane_digest,
  intent_digest,
  display_digest,
  audit_id,
  created_at,
  expires_at
)

vault_rotation_jobs(
  tenant_id,
  rotation_id,
  item_id,
  from_version_id,
  to_version_id,
  lifecycle_kind,
  requested_by_principal_id,
  workflow_id,
  created_at,
  completed_at
)
```

Encrypted payload R2 keys:

```text
tenants/{tenant_id}/vaults/{vault_id}/items/{item_id}/versions/{version_id}/fields/{field_id}.json
tenants/{tenant_id}/vaults/{vault_id}/items/{item_id}/versions/{version_id}/attachments/{attachment_id}.json
tenants/{tenant_id}/vaults/{vault_id}/wrapped-keys/{item_id}/{version_id}/{field_id}/{scope_id}.json
tenants/{tenant_id}/vault/sync/onepassword/{sync_id}.json
```

D1 has no row-level security. Every repository method must require a parsed
`TenantContext`, and cross-tenant denial tests should cover all vault tables and
R2 key builders.

## Audit And Observability

Audit event types:

- `vault.item.created`
- `vault.item.updated_metadata`
- `vault.item.version_created`
- `vault.item.activated_version`
- `vault.item.archived`
- `vault.item.grant_created`
- `vault.item.grant_revoked`
- `vault.field.access_allowed`
- `vault.field.access_denied`
- `vault.field.injected`
- `vault.field.revealed`
- `vault.item.rotation_started`
- `vault.item.rotation_completed`
- `capability_grant.authorized`
- `capability_grant.denied`
- `capability_grant.consumed`
- `vault.adapter.onepassword.sync_started`
- `vault.adapter.onepassword.sync_completed`
- `vault.adapter.onepassword.sync_failed`

Audit records should include tenant, principal, capability ID, item ID, version
ID, field ID, capability grant ID, operation kind, intent kind, destination,
policy version, approval ID, run ID, lane digest, intent digest, display digest,
decision, and grant consumption outcome. They must omit plaintext secret values,
raw authorization headers, OAuth tokens, raw database passwords, and full
request bodies unless a redaction policy has classified every field.

Operational signals:

- Secret access deny rate by tenant.
- Egress injection failures by destination.
- Grant replay failures.
- Rotation job failures.
- 1Password sync staleness.
- Secrets with no active permission.
- Runtime grants that have never been used.
- Secrets revealed in the last 30 days.

## Remaining Architectural Issues

These topics need explicit design decisions before implementation:

| Area | Issue | Decision needed |
| --- | --- | --- |
| Worker boundary split | Should Secret Broker and Egress Gateway be one Worker or separate service-bound Workers? | Separate gives least privilege; single Worker is simpler for MVP. |
| Key custody | Where do tenant root wrapping keys live? | Cloudflare Secrets Store, Worker secret, platform KMS, customer KMS, or sidecar. |
| Tenant isolation tiers | How far does pooled storage go? | Decide pooled, dedicated data, and dedicated deployment migration paths. |
| Metadata privacy | Which fields are plaintext for dashboard search? | Classify labels, hostnames, usernames, URLs, descriptions, and tags. |
| Grant policy model | How expressive are vault permissions and capability grant policies? | Start with typed constraints, then add policy DSL only when needed. |
| Approval thresholds | Which actions need human approval or two-person approval? | Decide defaults for use, reveal, delegate, rotate, export, and raw DB access. |
| Rotation | Which providers get first-class rotation? | Prioritize providers used by commerce harness demos and agent model calls. |
| Egress bypass | How are containers prevented from direct network use? | Decide outbound routing, deny-by-default networking, and redirect handling. |
| Audit retention | How long are access events and redacted request facts retained? | Set retention by tenant tier and compliance needs. |
| Incident response | What happens during suspected compromise? | Tenant disable, revoke permissions and active grants, rotate affected secrets, freeze egress. |
| 1Password behavior | Live read or sync by default? | Live keeps 1Password source of truth; sync gives stronger runtime control. |
| Reveal UX | How is break-glass presented and recorded? | Step-up, reason, approval, one-time display, post-reveal rotation reminder. |
| Sidecar future | How much sidecar design must exist in v1 types? | Keep explicit runtime branch, defer implementation. |
| Raw DB secrets | Are database passwords normal secrets or lease-only credentials? | Prefer lease-bound connection credentials for raw DB sessions. |
| Model-provider calls | Should LLM API keys go through AI Gateway, Egress Gateway, or both? | Decide routing and cost/audit ownership. |
| Local development | How do engineers test without real merchant secrets? | Fixture vault, fake providers, `.dev.vars`, local R2/D1, no production secret access. |
| Disaster recovery | What backups are required for encrypted payloads and wrapped keys? | Define recovery drills and key-loss behavior before production. |

Recommended defaults:

- Worker boundary split: define Secret Broker, Egress Gateway, Vault API, and
  Grant DO as separate logical boundaries from the first implementation. The
  pooled MVP can co-deploy them when needed, while dedicated enterprise tiers
  should split them into service-bound Workers.
- Key custody: use envelope encryption with per-field data keys, tenant/project
  wrapping keys, and a platform-managed root in the default tier. Add customer
  KMS and merchant sidecar root custody as explicit enterprise branches.
- Tenant isolation: start with pooled D1/R2 and strict tenant-bound repository
  parsers. Offer dedicated data stores for larger tenants and dedicated
  Cloudflare deployments for regulated tenants.
- Metadata privacy: plaintext metadata is allowed only after classification.
  Names, labels, usernames, hostnames, URLs, and descriptions are
  `tenant_sensitive_metadata` by default.
- Reveal and break-glass: delegate members cannot reveal. Direct-member reveal
  requires grant evidence and tenant reveal policy. Break-glass requires
  approval evidence, a reason, one-time display, noisy audit, and a rotation
  reminder.
- Automation: service accounts can request proxy-use and rotation grants through
  `service_account_api_key` evidence. Reveal and export stay interactive unless
  a later enterprise policy explicitly enables a stronger workload proof.
- 1Password: own vault is the runtime source of truth by default. Live Connect
  reads are allowed for tenants that intentionally keep 1Password as source of
  truth.

## Design Critique And Resolutions

This design should be judged against the long-term objective: a multi-tenant
enterprise vault for human, agent, and service principals that can share and use
secrets through controlled runtime boundaries, while sharing the same auth and
grant machinery as MPC signing.

| Critique | Resolution |
| --- | --- |
| A shared auth core that imports vault, NEAR, EVM, or future capability unions will become another monolith. | `seams-authorization` only knows sessions, grant evidence, capability IDs, operation kinds, policies, digests, grants, and audit. Capability modules own rich lane, intent, and display structs. |
| Principal-owned capabilities are too narrow for shared vaults, project wallets, team resources, and service-owned resources. | Capabilities are resource-scoped through `CapabilityInstance.resourceScope`; principals gain access through `CapabilityBinding`. |
| “Grant” can mean durable sharing permission or one-time runtime authorization. | Durable sharing uses `VaultPermissionGrant`; runtime authorization uses `CapabilityGrant`. |
| Making MPC mandatory bloats vault-only customers and breaks non-browser integrations. | Vault policies use generic `GrantEvidenceRef` records. `mpc_signer_proof` is optional evidence for high-assurance tenants. |
| Active-field references can drift during rotation. | Tools can hold `VaultFieldSelector`; runtime resolves once to `ResolvedVaultFieldRef` and binds the exact version and envelope in the grant. |
| Proxy use can become an exfiltration channel if the destination is loosely specified. | `VaultProxyBinding` binds host, scheme, method, path, port, injection location, redirects, and response redaction before unwrap. |
| Service accounts and scheduled jobs need non-interactive authorization. | Service-account API keys create `service_account_api_key` grant evidence and can request only policy-approved `CapabilityGrant` records. |
| Shared team vaults do not map to the wallet signer model. | A vault is a resource. Teams, humans, agents, and services receive permissions and capability bindings against that resource. |
| Agent identity should be first-class without forcing plaintext access. | Agents are normal principals with `delegate_member` default binding. Teams can explicitly promote an agent to `direct_member`. |
| 1Password adapter credentials can create a bootstrap cycle. | Store connector credentials as sealed tenant adapter credentials under the own-vault key hierarchy or platform bootstrap path, then expose them only through adapter-specific broker code. |
| Metadata search leaks sensitive names, usernames, hostnames, or tags. | Classify metadata as `public_display`, `tenant_sensitive_metadata`, or `secret_value`; encrypted metadata search is an enterprise extension. |
| Break-glass reveal is operationally necessary and risky. | Model it as a distinct operation with approval evidence, passkey or SSO assurance, one-time display, noisy audit, and post-reveal rotation reminder. |

## Repository Inventory

The vault implementation should build on the modular auth refactor instead of
landing as a parallel subsystem.

| Area | Current inventory | Required refactor |
| --- | --- | --- |
| Auth monolith | `packages/sdk-server-ts/src/core/AuthService.ts` mixes wallet registration, WebAuthn, Email OTP, sessions, recovery, threshold signing, stores, and signer WASM. | Extract session/factor provider ports used by Seams authorization; keep MPC runtime behind capability modules. |
| Route policy | `packages/sdk-server-ts/src/router/routeAuthPolicy.ts` has `console`, `api_credentials`, `user_session`, `threshold_session`, and `public`. | Add management/API/session/capability-grant route planes from refactor-83; runtime vault routes require `capability_grant`. |
| Route definitions | `packages/sdk-server-ts/src/router/routeDefinitions.ts` validates API scopes and route auth planes centrally. | Teach definitions about `management_api_key`, `seams_session`, and `capability_grant`; keep unknown capability operations fail-closed. |
| Cloudflare router | `packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts` eagerly wires wallet, session, threshold, OTP, and seal routes. | Register vault routes through route modules with lazy runtime handler factories; keep vault-only Workers free of MPC imports. |
| Route modules | `packages/sdk-server-ts/src/router/modules.ts` and `routeExtensions.ts` already support route extensions. | Evolve this into capability route registration; preserve Express parity only where the runtime actually supports the route. |
| Express routes | `packages/sdk-server-ts/src/router/express/*` mirrors relay routes. | Decide whether vault runtime routes are Cloudflare-only for v1; management routes can keep Express parity. |
| API credential scopes | `packages/shared-ts/src/console/apiKeyScopes.ts` is wallet-bootstrap oriented. | Split management scopes from grant-request scopes such as `grants.request.vault_proxy_use` and `grants.request.vault_rotate`. |
| Console RBAC | `packages/sdk-server-ts/src/console/teamRbac/*` uses org-scoped team roles and wallet-operation categories. | Add principal kinds, member access modes, vault/admin categories, and direct/delegate membership constraints. |
| Console policies | `packages/sdk-server-ts/src/console/policies/*` supports transaction and gas sponsorship policies. | Add capability grant policies, vault proxy policies, reveal policies, and permission-change policies. |
| Approvals | `packages/sdk-server-ts/src/console/approvals/*` supports policy publish and key export. | Add vault reveal, break-glass reveal, permission change, rotation, and export approval operation types. |
| Audit | `packages/sdk-server-ts/src/console/audit/*` and `consoleAuditMetadata.ts` handle existing console events. | Add capability, vault, proxy injection, reveal, deny, replay, rotation, adapter, and redaction event categories. |
| Key exports | `packages/sdk-server-ts/src/console/keyExports/*` has signing/export-specific approval and service flows. | Move key export onto the same `CapabilityGrant` evidence and approval path used by vault reveal/export. |
| Wallet index | `packages/sdk-server-ts/src/console/wallets/*` assumes wallet-centric resource surfaces. | Keep wallets as optional capability inventory; vault-only tenants should not require wallet rows. |
| D1 migrations | `packages/sdk-server-ts/migrations/d1-console/0001` through `0018` cover console, RBAC, policies, API keys, audit, approvals, wallet index, key exports, webhooks, and observability. | Add new migrations for principals, capability instances/bindings, grant evidence, capability grants, vaults, vault items, fields, envelopes, permissions, proxy bindings, access events, and rotations. |
| Dashboard shell | `apps/seams-site/src/pages/dashboard/dashboardConfig.tsx`, sidebar, routes, and route API clients cover current console pages. | Add vault pages; update team members, policy engine, approvals, API keys, audit, onboarding, and ops cockpit to surface vault capabilities. |
| Dashboard API clients | `apps/seams-site/src/pages/dashboard/routes/*/*Api.ts` mirror server console APIs. | Add `routes/secrets-vault/consoleVaultApi.ts` and adapt existing clients for capability policies, grant-request scopes, and vault approval metadata. |
| Browser step-up | `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts` is signing-centered. | Rename to capability-grant confirmation types with generic evidence challenges, then map signing and vault UI onto it. |
| React auth UI | `packages/sdk-web/src/react/components/PasskeyAuthMenu/*` exposes wallet/account policies. | Keep the components, adapt copy and adapters so passkey/OTP evidence can satisfy vault grants without wallet registration. |
| Lit confirmation UI | `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/*` renders transaction/export confirmations. | Add capability display renderers for vault reveal, proxy use, permission change, and break-glass. |
| Web worker split | `packages/sdk-web/src/core/walletRuntimePaths/*`, `SeamsWeb/walletIframe/*`, and signing workers currently load wallet/MPC runtime paths. | Add auth-only and vault-only entrypoints; assert that vault-only imports do not pull signer WASM, HSS, or MPC workers. |
| SeamsWeb public API | `packages/sdk-web/src/SeamsWeb/publicApi/*` and `operations/registration/*` are wallet-registration heavy. | Add capability provisioning APIs and vault grant request helpers; make wallet signers optional capabilities. |
| Server assembly | `apps/web-server/src/consoleConfig.ts` and server bootstrap seed console data. | Seed vault capability policies, direct/delegate team memberships, service-account grant-request scopes, and fake vault fixtures. |
| Examples | `examples/self-host-cloudflare-worker` and `examples/relay-cloudflare-worker` are signing/relay focused. | Add a vault-only Cloudflare Worker example with no MPC bundle, plus a full-platform example with optional MPC evidence. |
| Tests | `tests/relayer/*`, `tests/e2e/dashboard*.test.ts`, and `tests/unit/*guard*.test.ts` cover current console, router, and signing assumptions. | Phase 0 must list obsolete wallet-only expectations, delete redundant fixtures, and add type/runtime tests for vault-only tenants, grant replay, tenant isolation, and no-MPC imports. |
| Rust Cloudflare router | `crates/router-ab-cloudflare/*` owns existing project-policy and normal-signing Cloudflare concepts. | Inventory only for v1 unless Centaur chooses to reuse Rust router primitives for egress policy or Durable Object evaluation. |
| Missing adjacent spec | `docs/seams-commerce-harness.md` is referenced by product discussion but is absent in the repo. | Restore the file, update the reference, or move commerce harness requirements into `docs/centaur-cloud-fork.md` before implementation starts. |

## Local Development

Local fixtures should include:

- Two tenants.
- Separate projects and environments.
- Human admin, normal operator, service principal, and agent principals.
- Direct, delegate, metadata-only, and approval-only team memberships.
- Agent default `delegate_member` membership and one explicit direct-member
  promotion fixture.
- Own-vault API key secret.
- Own-vault database password secret.
- 1Password synced secret fixture.
- Active and revoked permissions and grants.
- Allowed and denied egress fixtures.
- Reveal-disabled tenant policy.

Tests should run against local D1/R2 bindings through Wrangler or Miniflare when
the change touches persistence, Durable Objects, Workflows, Queues, or egress
policy. Pure type and parser changes can use unit tests.

## Implementation Phases

| Phase | Focus | Deliverable |
| --- | --- | --- |
| 0 | Inventory and test triage | List wallet-only assumptions, redundant tests, stale fixtures, route surfaces, dashboard pages, SDK entrypoints, worker imports, migrations, and public exports. Delete tests that only preserve obsolete wallet-first behavior. |
| 1 | Generic authorization foundation | Land or depend on refactor-83 primitives: `SeamsSession`, `GrantEvidenceRef`, `CapabilityInstance`, `CapabilityBinding`, `CapabilityOperationEnvelope`, `CapabilityGrant`, policy resolution, replay locks, and route planes. |
| 2 | Vault domain package | Add vault IDs, item/version/field/envelope types, selectors, resolved refs, permission grants, proxy bindings, runtime boundary types, and type fixtures. |
| 3 | Persistence foundation | Add D1 migrations, D1 repositories, R2 key builders, envelope AAD builders, boundary parsers, cross-tenant denial tests, and seed fixtures. |
| 4 | Management API and dashboard CRUD | Add vault metadata/value write APIs, dashboard list/detail/create/edit/archive flows, redacted responses, audit records, and no-echo secret write behavior. |
| 5 | Permissions and policies | Add vault permission grants, member access mode enforcement, capability grant policies, service-account grant-request scopes, approval policy wiring, and dashboard grant UI. |
| 6 | Proxy use runtime | Implement vault access lanes, egress proxy bindings, grant evidence challenge flow, one-time `CapabilityGrant` issuance, Secret Broker unwrap, and Egress Gateway injection. |
| 7 | Reveal and break-glass | Implement direct-member reveal, approval evidence, passkey/SSO step-up, optional `mpc_signer_proof`, one-time display, noisy audit, and rotation reminder. |
| 8 | Rotation and scoped credentials | Implement manual rotation, version activation, retired versions, scoped credential minting, rotation workflows, and service-account rotation grants. |
| 9 | 1Password adapter | Implement live Connect read, sync/import, adapter credential custody, source fingerprinting, stale sync detection, and adapter audit. |
| 10 | Bundle and deployment hardening | Prove vault-only Workers and SDK imports do not load MPC code; decide Express parity; add dedicated-data and dedicated-deployment wiring. |
| 11 | Security hardening | Add replay, destination mismatch, redirect, redaction, tenant isolation, abuse limit, incident response, disaster recovery, and backup drills. |
| 12 | Enterprise modes | Add merchant sidecar injection, customer-managed key hooks, opaque metadata tier, and strict server-blind tenant mode. |

## Validation Plan

Type-level checks:

- Invalid item lifecycle states.
- Invalid access intent branch combinations.
- Invalid capability instance and binding branch combinations.
- Vault-only registration cannot require wallet signer fields.
- Wallet signing capability lanes cannot be used as vault access lanes.
- Warm signing authority cannot be spread into vault reveal authority.
- `VaultPermissionGrant` cannot be used where a `CapabilityGrant` is required.
- `CapabilityGrant` cannot be constructed without lane, intent, and display
  digests.
- `delegate_member` access cannot construct reveal, export, manage, or delegate
  operations.
- Agent direct membership must be explicit and cannot be inferred from agent
  principal kind.
- Missing tenant identity on items, fields, permissions, grants, and access
  requests.
- Delegate-member reveal attempts rejected at type and runtime boundaries.
- Broad object spreads cannot construct core lifecycle branches.
- Vault-only public entrypoints cannot import MPC signer workers or WASM.

Unit tests:

- Item and field metadata parsers.
- Envelope AAD normalization.
- Permission action normalization.
- Capability operation envelope construction.
- Egress destination matching.
- Injection rule matching.
- Access intent digest construction.
- Capability grant digest construction for signing, export, and vault access.
- Capability registration plan normalization.
- Service-account grant evidence normalization.
- Audit redaction.

Integration tests:

- D1 migrations and seed fixtures.
- R2 encrypted payload writes and reads by tenant.
- Cross-tenant metadata denial.
- Cross-tenant R2 key denial.
- Capability grant replay denial through Capability Grant DO.
- Egress injection to fake OpenAI, Anthropic, Shopify, Stripe, and GitHub
  endpoints.
- Reveal-disabled policy denial.
- Rotation from version N to N+1.
- 1Password sync fixture import.
- Vault-only Worker bundle excludes MPC signer modules.
- Service-account API key can request proxy-use and rotation grants only when
  binding and policy allow it.

Security tests:

- Secret value never appears in access denial logs.
- Authorization headers are redacted in audit payloads.
- Delegate members cannot call reveal endpoints.
- Expired use grants fail closed.
- Revoked grants fail closed.
- Secret use with destination mismatch fails closed.
- Secret use with policy version mismatch fails closed.
- Secret use after active-version rotation stays bound to the originally
  resolved version.
- Redirect to an unapproved host fails before secret injection.
- Service-account grant evidence cannot authorize reveal or export by default.
- Delegate-member raw readback and reveal requests fail closed.
- Promoted direct-member agent reveal requires explicit direct membership, grant,
  step-up, and tenant policy.

## Open Questions

- Which tenant tier should be the first strict server-blind mode?
- Where should tenant root wrapping keys live in the default cloud-injection
  tier?
- Which MPC signer policy threshold should apply to secret use, reveal,
  delegate, and rotate actions?
- Should `reveal_to_human` require two-person approval for all tenants?
- Which upstream APIs need first-class token exchange rather than raw secret
  injection?
- Should 1Password live reads be allowed in the default pooled tier?
- What rotation providers are needed first: OpenAI, Anthropic, Shopify, Stripe,
  GitHub, Slack, Postgres, or custom HTTP?
- How much secret metadata can remain plaintext for dashboard search?
- What retention window applies to vault access audit events?

## References

- [Cloudflare-Native Centaur Fork Plan](./centaur-cloud-fork.md)
- Cloudflare Workers: https://developers.cloudflare.com/workers/
- Cloudflare Durable Objects: https://developers.cloudflare.com/durable-objects/
- Cloudflare D1: https://developers.cloudflare.com/d1/
- Cloudflare R2: https://developers.cloudflare.com/r2/
- Cloudflare Queues: https://developers.cloudflare.com/queues/
- Cloudflare Workflows: https://developers.cloudflare.com/workflows/
- Cloudflare Secrets Store: https://developers.cloudflare.com/secrets-store/
- Centaur upstream: https://github.com/paradigmxyz/centaur
