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
   bootstrap material, and adapter credentials.
3. Make cloud Worker injection the default runtime mode.
4. Do not claim server-blindness for the default cloud-injection path.
5. Keep server-blind merchant sidecar injection as a future enterprise mode.
6. Keep own-vault storage as the primary secret backend.
7. Treat 1Password as an adapter: live Connect reads or sync into own vault.
8. Delegate members receive `VaultFieldRef` values, placeholder credentials, and
   short-lived use grants.
9. Delegate members do not receive reusable plaintext secrets.
10. Use the Seams MPC signer as the default authorization gate for
    `VaultAccessIntent`.
11. Treat threshold unwrap as a later extension for sidecar or customer-managed
    key modes.
12. Store tenant-scoped metadata, grants, and access indexes in D1.
13. Store encrypted secret payloads and wrapped key blobs in R2 unless the
    payload is small enough to justify D1 storage.
14. Model vault access as a protected capability gated by the same
    sensitive-operation auth infrastructure used for MPC signing and key
    export.
15. Let registration provision protected capabilities independently:
    `near_ed25519_signing`, `evm_ecdsa_signing`, and `vault_access`.
16. Support vault-only customers that use Seams auth, sessions, step-up, grants,
    and audit without provisioning wallet signers.
17. Model humans, agents, and services as first-class principals that can all
    become team members.
18. Use membership access mode to distinguish direct vault access from
    proxy-only delegated use.
19. Default agent memberships to `delegate_member`, while allowing explicit
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
4. Every item, field, grant, access intent, audit event, and egress decision
   carries a required tenant identity.
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
12. Team grants resolve through membership access mode before becoming effective
    vault access.
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
- Short-lived `VaultAccessIntent` approval with Seams MPC signer gating.
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
| D1 metadata store | No | Tenant-scoped metadata, grants, indexes, lifecycle state |
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
Vault Grant Durable Object
   |
Policy Engine + Approval Workflow
   |
Seams MPC signer gate
   |
short-lived use grant
   |
Egress Gateway / DB Gateway / Model Gateway / merchant sidecar
```

Component responsibilities:

| Component | Cloudflare service | Responsibility |
| --- | --- | --- |
| Vault API Worker | Workers | Dashboard and internal API routes |
| Secret Broker | Workers | Grant resolution, policy checks, unwrap orchestration, 1Password adapters |
| Vault Grant DO | Durable Objects | One-time grant state, replay locks, grant counters, per-item and per-field hot locks |
| Approval Workflow | Workflows | Human approval, expiration, retry, escalation |
| Async jobs | Queues | Rotation jobs, sync jobs, audit fanout |
| Metadata | D1 | Tenant-scoped vault metadata, grants, version indexes |
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
  | { kind: "draft"; tenantId: TenantId; itemId: VaultItemId }
  | { kind: "active"; tenantId: TenantId; itemId: VaultItemId; activeVersionId: VaultItemVersionId }
  | { kind: "rotating"; tenantId: TenantId; itemId: VaultItemId; fromVersionId: VaultItemVersionId; rotationId: RotationId }
  | { kind: "archived"; tenantId: TenantId; itemId: VaultItemId; archivedBy: PrincipalId; archivedAt: IsoTimestamp };

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
  | { kind: "own_vault"; tenantId: TenantId; itemId: VaultItemId }
  | { kind: "onepassword_connect"; tenantId: TenantId; vaultId: OnePasswordVaultId; sourceItemId: OnePasswordItemId }
  | { kind: "onepassword_sync"; tenantId: TenantId; syncedItemId: VaultItemId; sourceItemId: OnePasswordItemId };

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
groupings, while policy and grants remain precise enough for egress injection,
database leases, reveal, and rotation.

```ts
type VaultFieldRef = {
  tenantId: TenantId;
  itemId: VaultItemId;
  fieldId: VaultFieldId;
};

type VaultAccessLane = {
  tenantId: TenantId;
  itemId: VaultItemId;
  versionId: VaultItemVersionId;
  fieldId: VaultFieldId;
  grantId: VaultGrantId;
};
```

Access intents must distinguish use from reveal:

```ts
type VaultAccessIntent =
  | {
      kind: "use_via_egress";
      lane: VaultAccessLane;
      principal: Principal;
      sessionId: SessionId;
      executionId: ExecutionId;
      destination: EgressDestination;
      injection: EgressInjectionRule;
      revealReason?: never;
    }
  | {
      kind: "mint_scoped_credential";
      lane: VaultAccessLane;
      principal: Principal;
      sessionId: SessionId;
      executionId: ExecutionId;
      credentialAudience: CredentialAudience;
      destination?: never;
      injection?: never;
      revealReason?: never;
    }
  | {
      kind: "reveal_to_human";
      lane: VaultAccessLane;
      principal: Principal;
      approvalId: ApprovalId;
      revealReason: RevealReason;
      sessionId?: never;
      executionId?: never;
      destination?: never;
      injection?: never;
    }
  | {
      kind: "rotate_item";
      tenantId: TenantId;
      itemId: VaultItemId;
      principal: Principal;
      rotationId: RotationId;
      lane?: never;
      sessionId?: never;
      executionId?: never;
      destination?: never;
      injection?: never;
      revealReason?: never;
    };
```

Grants should be resource-specific:

```ts
type VaultGrantAction =
  | "vault.item.metadata.read"
  | "vault.field.use_via_egress"
  | "vault.field.mint_scoped_credential"
  | "vault.field.reveal_to_human"
  | "vault.item.rotate"
  | "vault.item.delegate"
  | "vault.item.manage";

type VaultGrantScope =
  | { kind: "item"; tenantId: TenantId; itemId: VaultItemId }
  | { kind: "field"; tenantId: TenantId; itemId: VaultItemId; fieldId: VaultFieldId }
  | { kind: "label"; tenantId: TenantId; label: VaultLabel }
  | { kind: "environment"; tenantId: TenantId; environmentId: EnvironmentId }
  | { kind: "project"; tenantId: TenantId; projectId: ProjectId };

type VaultGrantSubject =
  | { kind: "principal"; tenantId: TenantId; principalId: PrincipalId }
  | { kind: "team"; tenantId: TenantId; teamId: TeamId }
  | { kind: "role"; tenantId: TenantId; roleId: RoleId };

type VaultGrant = {
  tenantId: TenantId;
  grantId: VaultGrantId;
  grantee: VaultGrantSubject;
  scope: VaultGrantScope;
  actions: VaultGrantAction[];
  constraints: VaultGrantConstraints;
  status: "active" | "suspended" | "revoked";
  createdBy: PrincipalId;
  createdAt: IsoTimestamp;
};
```

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

Effective access is the intersection of grants and membership mode:

```text
principal direct grants
  + team grants
  + role grants
  + item or field grants
  ∩ membership access mode
  ∩ sensitive-operation policy
  ∩ runtime boundary
```

Examples:

| Member | Team | Access mode | Result |
| --- | --- | --- | --- |
| Alice | Support Ops | `direct_member` | Can reveal or manage secrets only when grants and policy allow it |
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
constrains how a principal can exercise a grant.

## Protected Capability Model

Registration should provision protected capabilities independently. Wallet
customers can receive signing and vault capabilities. Vault-only customers can
receive `vault_access` without Ed25519 or ECDSA signer provisioning.

```ts
type ProtectedCapability =
  | {
      kind: "near_ed25519_signing";
      tenantId: TenantId;
      walletId: WalletId;
      signerId: NearEd25519SignerId;
    }
  | {
      kind: "evm_ecdsa_signing";
      tenantId: TenantId;
      walletId: WalletId;
      keyId: EcdsaWalletKeyId;
      chainTarget: ThresholdEcdsaChainTarget;
    }
  | {
      kind: "vault_access";
      tenantId: TenantId;
      vaultPrincipalId: VaultPrincipalId;
      defaultPolicyId: VaultPolicyId;
    };
```

The shared sensitive-operation layer owns auth freshness, step-up, canonical
digests, TTL, remaining uses, grant consumption, and audit envelopes. Each
capability family owns its exact lane and executor.

```ts
type SensitiveOperationIntent =
  | {
      kind: "mpc_sign";
      lane: MpcSigningLane;
      transactionIntent: TransactionIntent;
      policy: SensitiveOperationPolicy;
    }
  | {
      kind: "key_export";
      lane: KeyExportLane;
      exportIntent: KeyExportIntent;
      policy: SensitiveOperationPolicy;
    }
  | {
      kind: "vault_access";
      lane: VaultAccessLane;
      vaultIntent: VaultAccessIntent;
      policy: SensitiveOperationPolicy;
    };
```

Shared authorization flow:

```text
principal + auth session + exact lane + intent + policy + expiry + nonce
  -> canonical digest
  -> step-up or approval when policy requires it
  -> signer-approved authorization
  -> short-lived operation grant
  -> domain executor
  -> audit and grant consumption
```

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

The first vault release should use the Seams MPC signer as an authorization
gate, not as the primary data decryption primitive.

The signer should authorize a canonical access digest:

```text
VaultAccessIntentDigest =
  H(
    tenantId,
    itemId,
    versionId,
    fieldId,
    grantId,
    principalId,
    agentId,
    sessionId,
    executionId,
    destinationHost,
    destinationPathPolicy,
    methodPolicy,
    injectionRule,
    sensitiveOperationPolicy,
    policyVersion,
    expiresAt,
    nonce
  )
```

The Secret Broker and Egress Gateway should require a fresh signer-approved
intent before unwrapping and injecting a secret. The MPC authorization does not
make cloud injection server-blind because the Worker still handles plaintext
after authorization.

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
  -> Secret Broker creates initial grants
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
- Grant action set.
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
Agent calls typed tool with `VaultFieldRef`
  -> Tool Gateway resolves item, active version, and field
  -> Tool Gateway builds VaultAccessIntent
  -> Secret Broker resolves effective grants
  -> Policy Engine evaluates destination, action, budget, tenant, principal, and session
  -> Approval Workflow runs when policy requires it
  -> Seams MPC signer gates the approved intent
  -> Vault Grant DO stores one-time use grant
  -> Egress Gateway injects secret into the approved request
  -> audit records allow or deny
```

The one-time grant should bind:

- `tenantId`
- `itemId`
- `versionId`
- `fieldId`
- `grantId`
- `principalId`
- `agentId`
- `sessionId`
- `executionId`
- destination host
- method and path policy
- injection location
- expiration
- nonce
- policy version
- MPC signer authorization digest

Grant replay must fail closed.

## Reveal And Break-Glass Flow

Reveal is an admin operation with a different lifecycle from use:

```text
Admin requests reveal
  -> Policy Engine checks reveal permission
  -> step-up auth required
  -> approval required for configured tenants
  -> Seams MPC signer gates reveal intent
  -> dashboard displays value once
  -> audit records vault.field.revealed
```

Reveal should be disabled for `delegate_member` principals. Agents default to
`delegate_member`, so agent reveal requires explicit promotion to direct
membership plus a grant and tenant policy that allow reveal. Tenant policy can
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
- bind each outbound request to a tenant, session, execution, and grant ID.

## 1Password Adapter Plan

Support two adapter modes:

```ts
type OnePasswordMode =
  | {
      kind: "connect_live";
      tenantId: TenantId;
      connectServerCredentialRef: VaultFieldRef;
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

protected_capabilities(
  tenant_id,
  capability_id,
  principal_id,
  capability_kind,
  lifecycle_kind,
  default_policy_id,
  created_by_principal_id,
  created_at,
  updated_at
)

sensitive_operation_authorizations(
  tenant_id,
  operation_id,
  capability_id,
  operation_kind,
  lane_json,
  intent_digest,
  policy_id,
  policy_version_id,
  auth_session_id,
  approval_id,
  remaining_uses,
  status,
  created_at,
  expires_at,
  consumed_at
)

vault_items(
  tenant_id,
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

vault_grants(
  tenant_id,
  grant_id,
  grantee_kind,
  grantee_id,
  scope_kind,
  scope_id,
  actions_json,
  constraints_json,
  status,
  created_by_principal_id,
  created_at,
  updated_at
)

vault_access_requests(
  tenant_id,
  request_id,
  item_id,
  version_id,
  field_id,
  grant_id,
  principal_id,
  session_id,
  execution_id,
  intent_kind,
  destination_json,
  decision,
  policy_version_id,
  approval_id,
  mpc_authorization_digest,
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
tenants/{tenant_id}/vault/items/{item_id}/versions/{version_id}/fields/{field_id}.json
tenants/{tenant_id}/vault/items/{item_id}/versions/{version_id}/attachments/{attachment_id}.json
tenants/{tenant_id}/vault/wrapped-keys/{item_id}/{version_id}/{field_id}/{scope_id}.json
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
- `sensitive_operation.authorized`
- `sensitive_operation.denied`
- `sensitive_operation.consumed`
- `vault.adapter.onepassword.sync_started`
- `vault.adapter.onepassword.sync_completed`
- `vault.adapter.onepassword.sync_failed`

Audit records should include tenant, principal, capability ID, item ID, version
ID, field ID, grant ID, sensitive operation kind, intent kind, destination,
policy version, approval ID, run ID, digest, decision, and grant consumption
outcome. They must omit plaintext secret values, raw authorization headers,
OAuth tokens, raw database passwords, and full request bodies unless a redaction
policy has classified every field.

Operational signals:

- Secret access deny rate by tenant.
- Egress injection failures by destination.
- Grant replay failures.
- Rotation job failures.
- 1Password sync staleness.
- Secrets with no active grant.
- Grants that have never been used.
- Secrets revealed in the last 30 days.

## Remaining Architectural Issues

These topics need explicit design decisions before implementation:

| Area | Issue | Decision needed |
| --- | --- | --- |
| Worker boundary split | Should Secret Broker and Egress Gateway be one Worker or separate service-bound Workers? | Separate gives least privilege; single Worker is simpler for MVP. |
| Key custody | Where do tenant root wrapping keys live? | Cloudflare Secrets Store, Worker secret, platform KMS, customer KMS, or sidecar. |
| Tenant isolation tiers | How far does pooled storage go? | Decide pooled, dedicated data, and dedicated deployment migration paths. |
| Metadata privacy | Which fields are plaintext for dashboard search? | Classify labels, hostnames, usernames, URLs, descriptions, and tags. |
| Grant policy model | How expressive are vault grants? | Start with typed constraints, then add policy DSL only when needed. |
| Approval thresholds | Which actions need human approval or two-person approval? | Decide defaults for use, reveal, delegate, rotate, export, and raw DB access. |
| Rotation | Which providers get first-class rotation? | Prioritize providers used by commerce harness demos and agent model calls. |
| Egress bypass | How are containers prevented from direct network use? | Decide outbound routing, deny-by-default networking, and redirect handling. |
| Audit retention | How long are access events and redacted request facts retained? | Set retention by tenant tier and compliance needs. |
| Incident response | What happens during suspected compromise? | Tenant disable, revoke all grants, rotate affected secrets, freeze egress. |
| 1Password behavior | Live read or sync by default? | Live keeps 1Password source of truth; sync gives stronger runtime control. |
| Reveal UX | How is break-glass presented and recorded? | Step-up, reason, approval, one-time display, post-reveal rotation reminder. |
| Sidecar future | How much sidecar design must exist in v1 types? | Keep explicit runtime branch, defer implementation. |
| Raw DB secrets | Are database passwords normal secrets or lease-only credentials? | Prefer lease-bound connection credentials for raw DB sessions. |
| Model-provider calls | Should LLM API keys go through AI Gateway, Egress Gateway, or both? | Decide routing and cost/audit ownership. |
| Local development | How do engineers test without real merchant secrets? | Fixture vault, fake providers, `.dev.vars`, local R2/D1, no production secret access. |
| Disaster recovery | What backups are required for encrypted payloads and wrapped keys? | Define recovery drills and key-loss behavior before production. |

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
- Active and revoked grants.
- Allowed and denied egress fixtures.
- Reveal-disabled tenant policy.

Tests should run against local D1/R2 bindings through Wrangler or Miniflare when
the change touches persistence, Durable Objects, Workflows, Queues, or egress
policy. Pure type and parser changes can use unit tests.

## Implementation Phases

| Phase | Focus | Deliverable |
| --- | --- | --- |
| 0 | Domain and threat model | Finalize tenant, protected capability, item, field, grant, intent, runtime-boundary, and audit types |
| 1 | Persistence foundation | D1 migrations, R2 key builders, boundary parsers, repository tests |
| 2 | Own-vault create/update | Dashboard API for metadata and encrypted value writes |
| 3 | Grant model | Resource grants, sensitive-operation policy constraints, static type fixtures, dashboard grant UI |
| 4 | Secret use path | `VaultAccessIntent`, policy evaluation, MPC signer gate, one-time use grants |
| 5 | Egress integration | Header/query/placeholder injection through Worker-side Egress Gateway |
| 6 | Reveal path | Human-only reveal with step-up, approval, audit, and tenant disable control |
| 7 | Rotation | Manual rotation, version activation, retired versions, rotation workflow hooks |
| 8 | 1Password adapter | Live Connect read path, sync/import path, adapter audit |
| 9 | Hardening | Cross-tenant denial, grant replay denial, redaction checks, abuse limits |
| 10 | Enterprise modes | Merchant sidecar injection, dedicated vault namespace, customer-managed key hooks |

## Validation Plan

Type-level checks:

- Invalid item lifecycle states.
- Invalid access intent branch combinations.
- Invalid protected capability branch combinations.
- Vault-only registration cannot require wallet signer fields.
- Wallet signing capability lanes cannot be used as vault access lanes.
- Warm signing authority cannot be spread into vault reveal authority.
- `delegate_member` access cannot construct reveal, export, manage, or delegate
  operations.
- Agent direct membership must be explicit and cannot be inferred from agent
  principal kind.
- Missing tenant identity on items, fields, grants, and access requests.
- Delegate-member reveal attempts rejected at type and runtime boundaries.
- Broad object spreads cannot construct core lifecycle branches.

Unit tests:

- Item and field metadata parsers.
- Envelope AAD normalization.
- Grant action normalization.
- Egress destination matching.
- Injection rule matching.
- Access intent digest construction.
- Sensitive operation digest construction for signing, export, and vault access.
- Protected capability registration plan normalization.
- Audit redaction.

Integration tests:

- D1 migrations and seed fixtures.
- R2 encrypted payload writes and reads by tenant.
- Cross-tenant metadata denial.
- Cross-tenant R2 key denial.
- Grant replay denial through Vault Grant DO.
- Egress injection to fake OpenAI, Anthropic, Shopify, Stripe, and GitHub
  endpoints.
- Reveal-disabled policy denial.
- Rotation from version N to N+1.
- 1Password sync fixture import.

Security tests:

- Secret value never appears in access denial logs.
- Authorization headers are redacted in audit payloads.
- Delegate members cannot call reveal endpoints.
- Expired use grants fail closed.
- Revoked grants fail closed.
- Secret use with destination mismatch fails closed.
- Secret use with policy version mismatch fails closed.
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
