# Modular Auth And Capability Refactor SPEC

Date created: June 28, 2026

Status: planning.

Companion doc: [Implementation plan](./refactor-83-modular-auth-capabilities-plan.md).

## Goal

Split the current signing-session architecture into a small shared auth/session
core plus optional protected capability modules.

The shared layer should gate sensitive operations for multiple capabilities:

- vault access;
- NEAR Ed25519 MPC signing;
- EVM-family ECDSA MPC signing.

Vault-only customers should provision an auth account and vault access without
loading MPC signer material, signer WASM, HSS export logic, wallet UI, or
threshold-session setup.

Auth methods should be modular. Passkeys, Email OTP, Slack OTP, recovery codes,
Better Auth, and future SSO providers can all feed normalized auth evidence into
Seams. Capabilities sit downstream from auth and bind operation-level policies
to normalized auth factor kinds.

Build Seams authorization as first-party security infrastructure. `seams-auth`
is the first-party auth provider. Better Auth can also be used through a
session-provider adapter. The system of record for step-up, sensitive-operation
grants, capability policies, and audit envelopes lives inside Seams.

`seams-auth` must store authentication data in the customer's configured
database by default. This preserves data residency, compliance control, pricing
predictability, and deployer ownership of auth records.

`seams-auth` must support multi-tenant organizations, multiple active sessions
per user across devices, and enterprise SSO through OIDC and SAML providers
such as Okta, Google Workspace, Microsoft Entra ID, OneLogin, and JumpCloud.

`seams-auth` must also support identity-provider mode for applications that want
Seams to be the login authority. In this mode, Seams authenticates the principal
and issues identity assertions to configured relying-party applications.

## Core Decision

Split auth into two layers:

1. Auth providers prove identity, session state, and auth factors.
2. Seams authorization evaluates capability policy and mints exact
   sensitive-operation grants.

`seams-auth` is the built-in auth provider. Better Auth is a supported upstream
provider through `betterAuthSessionProvider(auth)`.

Rename the parent concept from `signing-session` to `SeamsSession`.

`SeamsSession` owns identity, auth factors, session state, step-up
authorization, operation grants, budgets, and audit envelopes. MPC signing is a
capability that uses this shared layer. Vault access is another capability that
uses the same shared layer.

```text
Auth account
  -> auth provider
  -> normalized auth factors
  -> SeamsSession
  -> StepUpAuthorization
  -> SensitiveOperationGrant

Protected capabilities
  -> vault_access
  -> near_ed25519_mpc_signing
  -> evm_ecdsa_mpc_signing
```

Auth providers define mechanisms. Capabilities define resources. Operation
policies bind mechanisms to resources.

## Current Incompatibilities And Refactor Moves

The existing SDK is wallet-first. The target architecture is auth-first, with
wallet, MPC signing, vault access, and IdP behavior attached as optional modules.
Handle the incompatibilities by extracting narrow ports and deleting the shared
wallet assumptions as each call site moves.

### `AuthService` Monolith

`packages/sdk-server-ts/src/core/AuthService.ts` currently combines auth,
wallet registration, WebAuthn, Email OTP, identity links, recovery,
threshold-signing service access, stores, and signer runtime concerns. The
router also imports this shape through `CloudflareRouterApiAuthService`, which is a
large `Pick<AuthService, ...>`.

`packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService.ts` is the
second monolith to split. It is already closer to the target shape because it
delegates to smaller D1 services, but its public facade still presents one
auth/wallet/session/signing surface to Cloudflare route assembly. Treat it as
the first concrete adapter to break into the new route service ports.

Refactor move:

- introduce narrow route service ports instead of importing `AuthService` into
  router assembly;
- split the D1 router facade into matching D1-backed port adapters;
- keep `AuthService` and the D1 facade as internal assembly objects during
  extraction only;
- move each domain behind a first-party package boundary;
- remove each `AuthService` and D1 facade method from router-facing types once
  the owning port exists.

Target service ports:

```ts
type SeamsRouteServices = {
  authProvider: SeamsAuthProviderPort;
  authorization: SeamsAuthorizationPort;
  webAuthnFactor?: WebAuthnFactorPort;
  emailOtpFactor?: EmailOtpFactorPort;
  slackOtpFactor?: SlackOtpFactorPort;
  walletLoginFactor?: WalletLoginFactorPort;
  idp?: SeamsIdpPort;
  vault?: VaultCapabilityPort;
  nearEd25519Mpc?: NearEd25519MpcPort;
  evmEcdsaMpc?: EvmEcdsaMpcPort;
};
```

Ownership split:

| Current concern | Target owner |
| --- | --- |
| Auth account and sessions | `packages/seams-auth/` and `packages/seams-authorization/` |
| WebAuthn, Email OTP, Slack OTP, wallet login factors | `packages/seams-auth/` plugins |
| Identity links, SSO claims, IdP relying parties | `packages/seams-auth/` and `packages/seams-auth-idp/` |
| Wallet registration and signer provisioning | capability provisioning modules |
| Threshold signing, HSS, signer WASM | MPC capability modules |
| Vault grants and proxy use | `packages/capability-vault/` |
| Cloudflare D1 auth/session/signing facade | D1 adapters behind the same route service ports |

### Signer-First Auth Vocabulary

`packages/shared-ts/src/utils/signerDomain.ts` currently aliases
`AuthMethod` to signer auth methods. This makes shared auth vocabulary inherit
wallet constraints.

Refactor move:

- create a shared `authFactorDomain` with `AuthFactorKind`;
- move passkey, Email OTP, Slack OTP, wallet login, recovery code, and SSO
  evidence names into auth vocabulary;
- keep `SignerAuthMethod` and `WalletAuthMethod` inside signer and wallet
  capability vocabulary;
- delete `export type AuthMethod = SignerAuthMethod`;
- update callers to request the narrowest domain type.

Target split:

```ts
type AuthFactorKind =
  | "passkey"
  | "email_otp"
  | "slack_otp"
  | "wallet_login"
  | "recovery_code";

type MpcCapabilityAuthFactorKind = Extract<
  AuthFactorKind,
  "passkey" | "email_otp" | "wallet_login"
>;
```

### Signing-Centered Step-Up UI

`packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts` currently
uses `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`,
`thresholdSessionId`, and `signingGrantId`. That makes the browser step-up
system hard to reuse for vault access and IdP high-risk scope issuance.

Refactor move:

- rename shared client step-up concepts to `SensitiveOperationAuthPlan` and
  `SensitiveOperationChallenge`;
- keep `thresholdSessionId` only inside MPC capability lanes and MPC UI
  adapters;
- replace `signingGrantId` in shared UI payloads with
  `sensitiveOperationGrantId`;
- move wallet-specific display data behind a capability display adapter;
- let vault, IdP, and MPC modules provide operation-specific prompt metadata.

Target UI shape:

```ts
type SensitiveOperationAuthPlan =
  | {
      kind: "active_session";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      capabilityId: CapabilityId;
      operationKind: SensitiveOperationKind;
      grantId: SensitiveOperationGrantId;
      expiresAtMs: number;
      remainingUses: PositiveInt;
    }
  | {
      kind: "step_up";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
      operationDigest: DigestB64u;
    };
```

MPC capability modules can adapt this to signing-specific UI state when a
transaction or key export is the requested operation.

### Eager Cloudflare Router Assembly

`packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts` mounts
wallet, threshold, session, OTP, seal, and recovery routes in one static handler
list. Capability lazy-loading requires route registration to come from enabled
modules.

Existing module decision:

`packages/sdk-server-ts/src/router/modules.ts` already defines `RouterApiModule`
and route-extension resolution. Evolve that mechanism instead of creating a
parallel plugin registry. The current module shape is extension-only; the target
module shape should own route definitions, runtime handlers, required service
ports, capability metadata, and import-guard expectations.

Refactor move:

- extend `RouterApiModule` from route-extension wrapper into the canonical route
  module contract;
- replace the static handler array with `RouterApiModule` instances;
- let app assembly choose enabled modules from tenant capability config;
- mount IdP routes only when IdP mode is enabled;
- mount vault routes only when `vault_access` is enabled;
- mount MPC routes only when the relevant MPC capability is enabled;
- add import guards proving vault and IdP route modules do not import threshold,
  HSS, signer WASM, or chain modules.

Target module shape:

```ts
type RouterApiModule =
  | {
      kind: "router_api_module";
      moduleId: RouterApiModuleId;
      capabilityKind: ProtectedCapabilityKind | "seams_auth" | "seams_session" | "management";
      routeDefinitions: readonly RouterApiRouteDefinition[];
      cloudflareHandlers: readonly CloudflareRouteHandler[];
      expressHandlers: readonly ExpressRouteHandler[];
      requiredServices: readonly RouteServiceKey[];
      importGuard: RouterModuleImportGuard;
    };
```

The module builder should reject duplicate module IDs, duplicate route IDs,
route definitions without handlers for enabled runtimes, and handlers that
request services outside `requiredServices`.

Target assembly shape:

```ts
const router = createCloudflareRouter({
  services,
  modules: [
    seamsAuthRoutes(),
    seamsSessionRoutes(),
    ...(idpEnabled ? [seamsIdpRoutes()] : []),
    ...(vaultEnabled ? [vaultCapabilityRoutes()] : []),
    ...(nearMpcEnabled ? [nearEd25519MpcRoutes()] : []),
    ...(evmMpcEnabled ? [evmEcdsaMpcRoutes()] : []),
  ],
});
```

### Runtime Adapter Decision

Cloudflare Workers are the primary runtime target for this refactor. The current
Express router stays only as a thin adapter over the same route modules. Do not
maintain duplicated Express route behavior or separate Express-only route
definitions.

Decision:

- route definitions, auth policy, service-port requirements, and capability
  metadata are runtime-neutral;
- Cloudflare and Express adapters register handlers from the same
  `RouterApiModule` list;
- Cloudflare is the release gate for Centaur/cloud deployment;
- Express parity means same route table, same route policy, same request parser,
  and same response envelope through an Express adapter;
- if Express cannot consume the module contract cleanly, remove the Express
  router during this breaking refactor rather than preserving duplicate route
  implementations.

Validation should compare Cloudflare and Express route manifests for every
enabled product shape while keeping Cloudflare bundle/import guards as the
deployment-critical checks.

### Route Auth Policy Planes

`packages/sdk-server-ts/src/router/routeAuthPolicy.ts` has
`console`, `api_credentials`, `user_session`, `threshold_session`, and `public`
planes. The target route policy should distinguish management access, normal
session access, and exact sensitive-operation grants. Threshold-session details
belong to MPC routes and lanes.

Management-plane decision:

- keep management auth as first-class route policy planes;
- rename `console` to `management_console`;
- rename `api_credentials` to `management_api_key`;
- resolve both management planes to tenant-scoped principals before route
  handlers run;
- use `management_console` for dashboard/admin configuration routes such as team
  membership, policy editing, capability provisioning, approval decisions, API
  key management, audit views, and IdP configuration;
- use `management_api_key` for programmatic administration and automation;
- use `seams_session` for product routes that need an authenticated principal
  without an exact sensitive operation;
- use `sensitive_operation` for vault reveal/export/proxy-use, MPC signing, key
  export, break-glass reveal, and IdP high-risk scope issuance;
- keep `public` only for bootstrap, challenge, callback, and health routes that
  verify their own request-bound artifact.

Management planes can create policies, approvals, capabilities, vault metadata,
and principals according to RBAC and scopes. They cannot reveal secrets, inject
secrets, export keys, sign transactions, or issue high-risk IdP scopes unless
the route also requires a `sensitive_operation` grant. API keys resolve to
service-account principals by default, and their scopes are management scopes,
not operation grants.

### API Credential Scope Taxonomy

`packages/shared-ts/src/console/apiKeyScopes.ts` is currently wallet-only:
`accounts.create`, `wallets.read`, `wallets.auth_methods.create`, and
`wallets.signers.create`. Replace those with management scopes that match the
auth-first model.

Scope decisions:

- API credential scopes authorize management-plane operations only;
- API credential scopes never reveal vault secrets, inject credentials, export
  keys, sign transactions, or issue high-risk IdP scopes by themselves;
- API credentials resolve to service-account principals and inherit tenant,
  project, and environment scope from the credential record;
- sensitive operation access for service accounts or agents still flows through
  `SensitiveOperationGrant` and capability policy;
- scope parsing happens at the request boundary, then core code receives a typed
  `ManagementApiKeyPrincipal`;
- old wallet-only scope names are removed once route definitions move to the new
  taxonomy.

Initial scope families:

```text
auth.accounts.create
auth.factors.manage
auth.sessions.revoke
principals.read
principals.manage
memberships.read
memberships.manage
capabilities.read
capabilities.provision
capabilities.policy.manage
vault.metadata.read
vault.metadata.write
vault.policy.manage
vault.proxy.configure
idp.config.read
idp.config.manage
idp.relying_parties.manage
mpc.capabilities.provision
mpc.capabilities.read
audit.read
api_keys.manage
```

Keep runtime-use operations out of API credential scopes:

```text
vault.reveal
vault.export
vault.proxy.use
mpc.sign
mpc.key_export
idp.high_risk_scope.issue
```

Those belong to sensitive-operation kinds and stay outside management API-key
scopes.

Route policy refactor move:

- replace `console` with `management_console`;
- replace `api_credentials` with `management_api_key`;
- replace `user_session` with `seams_session`;
- replace `threshold_session` with `sensitive_operation`;
- add `managementOperationKind` and required tenant/project/environment scope to
  management route policies;
- put capability kind, operation kind, and required grant semantics in route
  policy;
- keep threshold session claims inside MPC capability request parsing;
- make `RoutePrincipal` carry normalized management, session, public, or
  sensitive-operation context.

Target route auth shape:

```ts
type RouteAuthPolicy =
  | {
      plane: "management_console";
      operationKind: ManagementOperationKind;
      roles: readonly TenantRole[];
      scope: ManagementResourceScope;
    }
  | {
      plane: "management_api_key";
      operationKind: ManagementOperationKind;
      scopes: readonly ApiCredentialScope[];
      scope: ManagementResourceScope;
    }
  | { plane: "seams_session" }
  | {
      plane: "sensitive_operation";
      capabilityKind: ProtectedCapabilityKind;
      operationKind: SensitiveOperationKind;
      grantUse: "consume" | "inspect";
    }
  | { plane: "public"; proof: PublicProofType; rationale: string };
```

```ts
type RoutePrincipal =
  | {
      plane: "management_console";
      tenantId: TenantId;
      principalId: PrincipalId;
      roles: readonly TenantRole[];
      scope: ManagementResourceScope;
    }
  | {
      plane: "management_api_key";
      tenantId: TenantId;
      principalId: PrincipalId;
      credentialId: ApiCredentialId;
      scopes: readonly ApiCredentialScope[];
      scope: ManagementResourceScope;
    }
  | {
      plane: "seams_session";
      session: Extract<SeamsSession, { kind: "active" }>;
    }
  | {
      plane: "sensitive_operation";
      grant: Extract<SensitiveOperationGrant, { kind: "active" }>;
    }
  | { plane: "public"; proof: PublicProof };
```

MPC signing endpoints become sensitive-operation routes whose handler parses an
MPC lane. Vault proxy use, reveal, export, permission changes, and IdP
high-risk scope issuance use the same route policy plane with different
capability and operation kinds.

## Auth Provider Decision

Better Auth is useful for:

- plugin ergonomics;
- server and client plugin pairs;
- auth method modularity;
- schema-per-plugin design;
- organization, session, API-key, and admin product patterns.

Use Better Auth where customers want standard app auth and organization
management. Use `seams-auth` where customers want a first-party Seams auth stack.
Use Seams authorization for high-assurance cryptographic auth factors that
Better Auth does not provide, such as MPC signer proofs derived from wallet or
signer capabilities.

Seams authorization remains first-party because the core security model must
support:

- MPC-backed liveness and presence checks;
- MPC signer proofs as derived auth factors;
- operation digest binding before grant issuance;
- exact capability lanes for vault, Ed25519 MPC, ECDSA MPC, and key export;
- tenant-defined high-assurance policies;
- server-side grant minting that fails closed;
- audit evidence tied to capability ID, principal, lane, factor, and digest;
- Cloudflare Worker boundaries and bundle guarantees;
- future vault-specific authorization modes.

External auth providers should feed normalized session and factor evidence into
Seams authorization. Seams authorization decides whether to issue a
`StepUpAuthorization` or `SensitiveOperationGrant`.

## Development Auth Provider Decision

Use Better Auth first during development to avoid blocking the modular
authorization refactor on a full `seams-auth` implementation.

Better Auth should provide:

- user account and session plumbing;
- cookie/session lifecycle;
- passkey registration and login;
- Email OTP and 2FA delivery mechanics;
- organization and API-key scaffolding where useful;
- development ergonomics for client and server auth flows.

Seams should own from the start:

- `SeamsSession` normalization;
- operation digest construction;
- operation-bound step-up challenges;
- passkey assertions bound to Seams operation digests;
- MPC signer proof challenges bound to Seams operation digests;
- confirmer modal payloads;
- `StepUpAuthorization`;
- `SensitiveOperationGrant`;
- MPC threshold-session minting;
- vault access grants;
- audit envelopes for sensitive operations.

The Better Auth integration should therefore be an adapter and plugin bridge:

```text
Better Auth session
  -> betterAuthSessionProvider(auth)
  -> SeamsSession
  -> Seams operation-bound step-up
  -> StepUpAuthorization
  -> SensitiveOperationGrant
  -> capability operation
```

### Seams Passkey Step-Up Plugin

Standard passkey login proves account control. Seams passkey step-up must prove
presence for one exact sensitive operation.

Implement a custom Better Auth plugin endpoint for Seams-specific passkey
challenges. This plugin should reuse Better Auth's session context and route
mounting, while delegating challenge construction, digest binding, verification,
and grant issuance to Seams authorization.

Required endpoints:

```text
POST /seams/step-up/passkey/challenge
POST /seams/step-up/passkey/verify
```

Challenge endpoint responsibilities:

- require a valid Better Auth session;
- normalize the session into `SeamsSession`;
- accept a typed `SensitiveOperationIntent`;
- construct the canonical operation digest inside Seams authorization;
- create a WebAuthn challenge bound to tenant, principal, session, capability,
  operation kind, lane digest, intent digest, origin, RP ID, and expiry;
- return public challenge options plus confirmer modal metadata.

Verify endpoint responsibilities:

- require the same active Better Auth session;
- parse the WebAuthn assertion at the request boundary;
- verify origin, RP ID, challenge, credential ID, user presence, and user
  verification policy;
- verify the challenge maps to the same tenant, principal, session, operation
  digest, and capability lane;
- create `StepUpAuthorization`;
- mint a short-lived `SensitiveOperationGrant` when policy allows;
- return only grant metadata required by the capability caller.

Security rules:

- Better Auth passkey registration and login can manage account-level passkeys.
- Seams operation-bound passkey challenges must use Seams challenge records.
- Better Auth hooks and plugin endpoints cannot mint Seams grants directly.
- WebAuthn challenge records must be single-use and short-lived.
- Challenge verification must fail when the operation digest, session, tenant,
  RP ID, origin, or credential binding changes.
- Confirmer modal display data must be derived from the typed operation intent
  after boundary parsing.

## Product Shapes

| Product shape | Provisioned pieces |
| --- | --- |
| Vault-only | `AuthAccount`, auth factors, `SeamsSession`, `vault_access` |
| Wallet-only | `AuthAccount`, auth factors, `SeamsSession`, MPC signing capabilities |
| Full platform | `AuthAccount`, auth factors, `SeamsSession`, vault and MPC capabilities |
| Enterprise vault | `AuthAccount`, auth factors, vault access, optional MPC policy, customer KMS or sidecar |
| Identity provider | `AuthAccount`, auth factors, `SeamsSession`, IdP relying-party registrations |

## Required Auth Features

### Multi-Tenancy

Every auth, authorization, capability, policy, and audit record must be scoped
to a tenant or organization. Core logic should require `tenantId` on all
identity, session, factor, policy, grant, and capability inputs.

Tenant isolation requirements:

- tenant-scoped principal IDs;
- tenant-scoped auth provider configuration;
- tenant-scoped SSO provider configuration;
- tenant-scoped session and factor records;
- tenant-scoped role and team membership claims;
- tenant-scoped capability policies;
- no cross-tenant lookup without an explicit platform-admin boundary.

### Multi-Session

Users can have multiple active sessions across browsers, devices, and
integrations. `SeamsSession` should represent one active login context, not the
entire user account.

Session requirements:

- multiple sessions per principal;
- device-aware session records;
- per-session revocation;
- global principal logout;
- tenant-wide forced logout;
- session rotation and refresh;
- session-bound step-up evidence;
- audit fields for device ID, user agent hash, IP hash, and auth provider.

### Session Exchange

Session exchange is the boundary that converts provider-specific login evidence
into a `SeamsSession`. It should be specified separately from step-up and
sensitive-operation grants because it is the root login path for Better Auth,
Seams Auth, enterprise SSO, embedded wallet login, Slack-linked login helpers,
and future providers.

Exchange responsibilities:

- verify provider-specific session evidence at the provider adapter boundary;
- map provider subjects into tenant-scoped principals;
- create missing principals through explicit JIT provisioning policy;
- bind a session to tenant, principal, provider, device, origin, and expiry;
- store refresh-token hashes and token-family state when refresh is enabled;
- rotate or revoke one session without invalidating other active sessions;
- emit session lifecycle audit events;
- return typed failures for unknown provider, tenant mismatch, subject
  collision, disabled factor, revoked device, expired proof, replay, origin
  mismatch, and denied JIT provisioning.

Exchange commands:

```ts
type SessionExchangeCommand =
  | {
      kind: "better_auth_session";
      tenantId: TenantId;
      providerId: AuthProviderId;
      externalSessionId: ExternalSessionId;
      evidenceDigest: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    }
  | {
      kind: "seams_factor_assertion";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorKind: Extract<AuthFactorKind, "passkey" | "email_otp" | "slack_otp">;
      assertionDigest: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    }
  | {
      kind: "enterprise_oidc_callback";
      tenantId: TenantId;
      providerId: AuthProviderId;
      authorizationCodeDigest: DigestB64u;
      stateDigest: DigestB64u;
      nonceDigest: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    }
  | {
      kind: "enterprise_saml_assertion";
      tenantId: TenantId;
      providerId: AuthProviderId;
      assertionDigest: DigestB64u;
      relayStateDigest: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    }
  | {
      kind: "wallet_login_proof";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorId: AuthFactorId;
      proofDigest: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    }
  | {
      kind: "refresh";
      tenantId: TenantId;
      sessionId: SeamsSessionId;
      refreshTokenId: SessionRefreshTokenId;
      refreshTokenHash: DigestB64u;
      device: SessionDeviceEvidence;
      origin: HttpsOrigin;
    };

type SessionExchangeResult =
  | {
      kind: "created";
      session: Extract<SeamsSession, { kind: "active" }>;
      delivery: SessionDelivery;
      providerIdentityId: ProviderIdentityId;
    }
  | {
      kind: "refreshed";
      previousSessionId: SeamsSessionId;
      session: Extract<SeamsSession, { kind: "active" }>;
      delivery: SessionDelivery;
    }
  | {
      kind: "denied";
      failure: SessionExchangeFailure;
    };

type SessionDeviceEvidence = {
  tenantId: TenantId;
  deviceId: DeviceId;
  userAgentHash: DigestB64u;
  ipHash: DigestB64u;
};

type SessionDelivery =
  | {
      kind: "browser_cookie";
      sessionCookieName: string;
      csrfTokenHash: DigestB64u;
      refreshTokenId: SessionRefreshTokenId;
    }
  | {
      kind: "bearer_token";
      accessTokenId: SessionAccessTokenId;
      refreshTokenId: SessionRefreshTokenId;
    };

type SessionExchangeFailure =
  | { kind: "provider_not_enabled"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "tenant_mismatch"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "subject_collision"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "jit_provisioning_denied"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "factor_disabled"; tenantId: TenantId; factorKind: AuthFactorKind }
  | { kind: "device_revoked"; tenantId: TenantId; deviceId: DeviceId }
  | { kind: "origin_mismatch"; tenantId: TenantId; origin: HttpsOrigin }
  | { kind: "proof_expired"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "proof_replayed"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "refresh_family_revoked"; tenantId: TenantId; refreshTokenId: SessionRefreshTokenId };
```

Default exchange behavior:

- `betterAuthSessionProvider(auth)` verifies the Better Auth session and emits
  `AuthProviderSessionEvidence`; Seams owns the normalized session record.
- Seams Auth native factors can exchange verified login assertions directly.
- OIDC and SAML adapters verify protocol artifacts, then emit normalized
  provider identity evidence.
- Embedded wallet login creates a `SeamsSession` without provisioning signer
  capabilities.
- Refresh rotates refresh-token family state and records a session event.
- Revocation operates on one session by default. Tenant forced logout and
  principal-wide logout are explicit commands.
- Session exchange cannot mint `SensitiveOperationGrant` records, provision
  capabilities, or satisfy operation step-up.

### Enterprise SSO

Enterprise customers must be able to use their existing identity providers to
log into Seams. Initial provider families:

- OIDC;
- SAML.

Expected provider examples:

- Okta;
- Google Workspace;
- Microsoft Entra ID;
- OneLogin;
- JumpCloud.

SSO requirements:

- tenant-scoped provider configuration;
- provider metadata import and rotation;
- claim mapping to `principalId`, email, display name, groups, and roles;
- JIT user provisioning;
- optional SCIM later for lifecycle sync;
- IdP-initiated and SP-initiated flows where supported;
- group and role mapping into Seams team/RBAC records;
- SSO session evidence parsed into `AuthProviderSessionEvidence`;
- step-up policy compatibility with SSO sessions plus Seams-native factors.

### Seams IdP Mode

Seams should also act as an identity provider for other applications. This is
the inverse direction from enterprise SSO:

- enterprise SSO lets Okta, Google Workspace, Microsoft Entra ID, OneLogin, or
  JumpCloud log users into Seams;
- Seams IdP mode lets Seams log users into customer applications.

Initial IdP protocol support should prioritize OIDC Provider behavior. SAML IdP
support can follow if enterprise customers need legacy service-provider
integration.

IdP mode requirements:

- tenant-scoped relying-party application registration;
- tenant-scoped issuer and discovery metadata;
- OIDC authorization-code flow with PKCE;
- refresh-token rotation and revocation;
- JWKS publication with key rotation;
- claim mapping from Seams principals, organizations, roles, and groups;
- application assignment policies;
- per-application token lifetime and scope policy;
- optional step-up before issuing high-risk scopes;
- audit events for authorization code issuance, token issuance, token refresh,
  token revocation, and client configuration changes.

Embedded wallet login should be modeled as an auth factor that can create a
`SeamsSession`. Wallet-owned MPC signer material remains capability-owned and
loads only when a policy requires MPC-backed presence or signing. External
relying-party applications receive identity tokens or assertions. Seams
`SensitiveOperationGrant` records remain internal to Seams authorization.

## Vocabulary

| Current term | Target term |
| --- | --- |
| signing session | `SeamsSession` |
| signing grant | `SensitiveOperationGrant` |
| signing budget | `SensitiveOperationBudget` |
| selected signing lane | capability-specific lane |
| signing auth method | `AuthFactor` |
| signer material | capability-owned runtime material |
| wallet registration | auth account registration plus optional capability provisioning |

Use `MpcSigningSession` only inside the MPC capability modules, where threshold
runtime state is actually present.

## Layering Rules

1. `seams-authorization` cannot import vault, Ed25519 MPC, ECDSA MPC, signer
   WASM, HSS, or chain-specific code.
2. Capability modules can import `seams-authorization`.
3. App assembly code can import selected capabilities and wire them to routes.
4. Tenant capability state lives in persistence, not in legacy flags.
5. Route handlers fail closed when a required capability is missing.
6. Compatibility code belongs only at request and persistence boundaries, with a
   named deletion condition.
7. Build a constrained first-party auth plugin surface for `seams-auth`. Support
   Better Auth through a session-provider adapter.
8. Capabilities reference registered auth factor kinds through operation-level
   policies. They do not instantiate auth plugins directly.
9. Auth providers can create sessions and verify factors. Only Seams
   authorization can mint `SensitiveOperationGrant` records.
10. `seams-auth` persistence goes through an explicit database adapter. Raw
    database rows are normalized once at the adapter boundary.

## Configuration Shape

Use an auth provider plus capability-specific operation policies.

First-party `seams-auth` should expose a Better Auth-style setup API. The
top-level API should feel like application auth configuration, while internally
normalizing every enabled mechanism into an `AuthPlugin` and `AuthFactorKind`.
The `database` option is required for production deployments.

```ts
import { seamsAuth } from "@seams/auth";
import { d1Adapter } from "@seams/auth/adapters/d1";

export const auth = seamsAuth({
  database: d1Adapter(env.SIGNER_DB),
  appName: "Seams",
  baseURL: "https://auth.example.com",
  emailAndPassword: {
    enabled: true,
  },
  passkey: {
    enabled: true,
    rpId: "example.com",
  },
  emailOTP: {
    enabled: true,
    sendVerificationOTP: sendEmailOtp,
  },
  slackOTP: {
    enabled: true,
    sendVerificationOTP: sendSlackOtp,
  },
  walletLogin: {
    enabled: true,
  },
  socialProviders: {
    github: {
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
    },
  },
  enterpriseSSO: {
    oidc: [
      {
        providerId: "okta",
        issuer: env.OKTA_ISSUER,
        clientId: env.OKTA_CLIENT_ID,
        clientSecret: env.OKTA_CLIENT_SECRET,
        claimMapping: {
          subject: "sub",
          email: "email",
          groups: "groups",
        },
      },
    ],
    saml: [
      {
        providerId: "entra-saml",
        metadataUrl: env.ENTRA_SAML_METADATA_URL,
        claimMapping: {
          subject: "nameID",
          email: "email",
          groups: "groups",
        },
      },
    ],
  },
  identityProvider: {
    enabled: true,
    oidc: {
      issuer: "https://auth.example.com",
      jwksKeyRef: env.SEAMS_IDP_JWKS_KEY_REF,
      clients: [
        {
          clientId: "centaur-cloud",
          displayName: "Centaur Cloud",
          redirectUris: ["https://centaur.example.com/oauth/callback"],
          allowedScopes: ["openid", "profile", "email", "seams:roles"],
        },
      ],
    },
  },
  organization: {
    enabled: true,
  },
  apiKey: {
    enabled: true,
  },
});
```

Database adapters should cover the deployment shapes we expect:

```ts
seamsAuth({ database: d1Adapter(env.SIGNER_DB) });
seamsAuth({ database: postgresAdapter(pool) });
seamsAuth({ database: prismaAdapter(prisma) });
seamsAuth({ database: drizzleAdapter(db) });
```

The adapter contract should be narrow and explicit:

```ts
type SeamsAuthDatabaseAdapter = {
  kind: "seams_auth_database_adapter";
  createTransaction<T>(run: (tx: SeamsAuthTransaction) => Promise<T>): Promise<T>;
  migrate?: (plan: SeamsAuthMigrationPlan) => Promise<SeamsAuthMigrationResult>;
};
```

All auth-provider records stay in the configured database:

- auth accounts;
- auth factors;
- provider sessions;
- step-up challenges;
- OTP challenges and rate limits;
- passkey credentials;
- provider identity links;
- IdP relying-party applications;
- IdP authorization codes, refresh tokens, signing-key references, and token
  audit events;
- audit pointers and evidence digests.

`seams-auth` then plugs into Seams authorization:

```ts
export const seams = createSeamsAuthorization({
  sessionProvider: seamsAuthSessionProvider(auth),
  capabilities: [
    vaultAccessCapability({
      operationPolicies: {
        proxyUse: requireSession(),
        revealSecret: requireAnyFactor(["passkey", "email_otp", "slack_otp"]),
        exportSecret: requireAnyFactor(["passkey"]),
        changePermissions: requireAnyFactor(["passkey"]),
        breakGlassReveal: requireApprovalAndFactor(["passkey"]),
      },
    }),
    nearEd25519MpcCapability({
      operationPolicies: {
        signTransaction: requireAnyFactor(["passkey", "email_otp"]),
        exportKey: requireAnyFactor(["passkey"]),
      },
    }),
    evmEcdsaMpcCapability({
      operationPolicies: {
        signTransaction: requireAnyFactor(["passkey", "email_otp"]),
        exportKey: requireAnyFactor(["passkey"]),
      },
    }),
  ],
});
```

Low-level auth plugins remain available for internal package assembly and tests:

```ts
const auth = seamsAuth({
  database: d1Adapter(env.SIGNER_DB),
  plugins: [
    passkeyFactor(),
    emailOtpFactor(),
    slackOtpFactor(),
  ],
});
```

Better Auth provider:

```ts
const seamsStepUpBridge = createSeamsStepUpBridge();

const auth = betterAuth({
  database: prismaAdapter(prisma),
  plugins: [
    passkey(),
    emailOTP(),
    organization(),
    apiKey(),
    seamsSlackOtp(),
    seamsPasskeyStepUp({
      stepUpBridge: seamsStepUpBridge,
    }),
  ],
});

const seams = createSeamsAuthorization({
  sessionProvider: betterAuthSessionProvider(auth),
  stepUpBridge: seamsStepUpBridge,
  capabilities: [
    vaultAccessCapability(),
    nearEd25519MpcCapability(),
    evmEcdsaMpcCapability(),
  ],
});
```

The embedded defaults should be conservative:

| Capability operation | Default auth policy |
| --- | --- |
| Vault proxy use | active session plus RBAC |
| Vault reveal | passkey, Email OTP, or Slack OTP step-up |
| Vault export | passkey step-up |
| Vault permission change | passkey step-up |
| Vault break-glass reveal | approval plus passkey step-up |
| MPC transaction signing | passkey or Email OTP step-up |
| MPC key export | passkey step-up |
| MPC auth proof | inherited signer capability policy |
| High-assurance vault export | passkey plus MPC auth proof |

Tenant policy can make defaults stricter. It should not silently weaken the
compiled capability defaults.

## Target Domain Types

```ts
type AuthAccount = {
  tenantId: TenantId;
  principalId: PrincipalId;
  status: "active" | "suspended" | "deleted";
  recoveryPolicyId: RecoveryPolicyId;
  createdAt: IsoTimestamp;
};

type AuthFactor =
  | { kind: "passkey"; tenantId: TenantId; principalId: PrincipalId; credentialId: PasskeyCredentialId }
  | { kind: "email_otp"; tenantId: TenantId; principalId: PrincipalId; email: EmailAddress }
  | { kind: "slack_otp"; tenantId: TenantId; principalId: PrincipalId; slackTeamId: SlackTeamId; slackUserId: SlackUserId }
  | { kind: "wallet_login"; tenantId: TenantId; principalId: PrincipalId; walletAccountId: EmbeddedWalletAccountId }
  | { kind: "mpc_signer_proof"; tenantId: TenantId; principalId: PrincipalId; signerCapabilityId: CapabilityId; inheritedPolicyId: PolicyId }
  | { kind: "recovery_code"; tenantId: TenantId; principalId: PrincipalId; recoverySetId: RecoverySetId };

type AuthFactorKind = AuthFactor["kind"];

type AuthTenant = {
  tenantId: TenantId;
  status: "active" | "suspended" | "deleted";
  displayName: string;
  createdAt: IsoTimestamp;
};

type AuthPrincipal =
  | {
      kind: "human";
      tenantId: TenantId;
      principalId: PrincipalId;
      email: EmailAddress;
      displayName: string;
      status: "active" | "suspended" | "deleted";
    }
  | {
      kind: "agent";
      tenantId: TenantId;
      principalId: PrincipalId;
      displayName: string;
      status: "active" | "suspended" | "deleted";
    }
  | {
      kind: "service";
      tenantId: TenantId;
      principalId: PrincipalId;
      displayName: string;
      status: "active" | "suspended" | "deleted";
    };

type AuthPlugin =
  | {
      kind: "passkey_plugin";
      tenantId: TenantId;
      factorKind: "passkey";
      schema: PluginSchema;
      routes: AuthRoute[];
      clientModule: LazyClientModule;
    }
  | {
      kind: "email_otp_plugin";
      tenantId: TenantId;
      factorKind: "email_otp";
      schema: PluginSchema;
      routes: AuthRoute[];
      clientModule: LazyClientModule;
    }
  | {
      kind: "slack_otp_plugin";
      tenantId: TenantId;
      factorKind: "slack_otp";
      schema: PluginSchema;
      routes: AuthRoute[];
      clientModule: LazyClientModule;
    }
  | {
      kind: "wallet_login_plugin";
      tenantId: TenantId;
      factorKind: "wallet_login";
      schema: PluginSchema;
      routes: AuthRoute[];
      clientModule: LazyClientModule;
    }
  | {
      kind: "recovery_code_plugin";
      tenantId: TenantId;
      factorKind: "recovery_code";
      schema: PluginSchema;
      routes: AuthRoute[];
      clientModule: LazyClientModule;
    };

type AuthProvider =
  | {
      kind: "seams_auth_provider";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
    }
  | {
      kind: "better_auth_provider";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
      betterAuthInstanceId: ExternalAuthInstanceId;
    }
  | {
      kind: "external_oidc_provider";
      providerId: AuthProviderId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
      issuer: OidcIssuer;
      tenantId: TenantId;
      claimMapping: SsoClaimMapping;
    }
  | {
      kind: "external_saml_provider";
      providerId: AuthProviderId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
      tenantId: TenantId;
      entityId: SamlEntityId;
      claimMapping: SsoClaimMapping;
    };

type AuthProviderSessionEvidence =
  | {
      kind: "provider_session";
      providerId: AuthProviderId;
      tenantId: TenantId;
      principalId: PrincipalId;
      externalSessionId: ExternalSessionId;
      sessionSubject: ExternalSessionSubject;
      factorKinds: NonEmptyArray<AuthFactorKind>;
      deviceId: DeviceId;
      evidenceDigest: DigestB64u;
      expiresAt: IsoTimestamp;
    }
  | {
      kind: "provider_step_up";
      providerId: AuthProviderId;
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      factorKind: AuthFactorKind;
      deviceId: DeviceId;
      evidenceDigest: DigestB64u;
      expiresAt: IsoTimestamp;
    };

type MpcSignerProof =
  | {
      kind: "near_ed25519_mpc_signer_proof";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      signerCapabilityId: CapabilityId;
      inheritedPolicyId: PolicyId;
      challengeDigest: DigestB64u;
      proofDigest: DigestB64u;
      deviceId: DeviceId;
      expiresAt: IsoTimestamp;
    }
  | {
      kind: "evm_ecdsa_mpc_signer_proof";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      signerCapabilityId: CapabilityId;
      inheritedPolicyId: PolicyId;
      challengeDigest: DigestB64u;
      proofDigest: DigestB64u;
      deviceId: DeviceId;
      expiresAt: IsoTimestamp;
    };

type IdpRelyingParty =
  | {
      kind: "oidc_relying_party";
      tenantId: TenantId;
      relyingPartyId: IdpRelyingPartyId;
      clientId: OidcClientId;
      displayName: string;
      redirectUris: NonEmptyArray<HttpsUrl>;
      allowedScopes: NonEmptyArray<OidcScope>;
      claimPolicyId: ClaimPolicyId;
      tokenPolicyId: TokenPolicyId;
      status: "active" | "suspended" | "deleted";
    }
  | {
      kind: "saml_service_provider";
      tenantId: TenantId;
      relyingPartyId: IdpRelyingPartyId;
      entityId: SamlEntityId;
      assertionConsumerServiceUrls: NonEmptyArray<HttpsUrl>;
      claimPolicyId: ClaimPolicyId;
      assertionPolicyId: AssertionPolicyId;
      status: "active" | "suspended" | "deleted";
    };

type IdpTokenIssueRequest =
  | {
      kind: "oidc_authorization_code";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      relyingPartyId: IdpRelyingPartyId;
      redirectUri: HttpsUrl;
      scopes: NonEmptyArray<OidcScope>;
      nonce: OidcNonce;
      codeChallenge: PkceCodeChallenge;
    }
  | {
      kind: "oidc_refresh";
      tenantId: TenantId;
      principalId: PrincipalId;
      relyingPartyId: IdpRelyingPartyId;
      refreshTokenId: IdpRefreshTokenId;
      scopes: NonEmptyArray<OidcScope>;
    };

type SeamsSession =
  | {
      kind: "active";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
      authFactorId: AuthFactorId;
      deviceId: DeviceId;
      expiresAt: IsoTimestamp;
    }
  | {
      kind: "revoked";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
      authFactorId: AuthFactorId;
      deviceId: DeviceId;
      revokedAt: IsoTimestamp;
    }
  | {
      kind: "expired";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
      authFactorId: AuthFactorId;
      deviceId: DeviceId;
      expiredAt: IsoTimestamp;
    };

type StepUpAuthorization =
  | {
      kind: "passkey_step_up";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
      authFactorId: AuthFactorId;
      deviceId: DeviceId;
      stepUpId: StepUpId;
      expiresAt: IsoTimestamp;
    }
  | {
      kind: "otp_step_up";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
      authFactorId: AuthFactorId;
      deviceId: DeviceId;
      stepUpId: StepUpId;
      factor: Extract<AuthFactor, { kind: "email_otp" | "slack_otp" }>;
      expiresAt: IsoTimestamp;
    };
```

Auth policies reference auth factor kinds registered by the selected auth
provider:

```ts
type CapabilityOperationAuthPolicy =
  | {
      kind: "session_only";
      tenantId: TenantId;
      policyId: PolicyId;
    }
  | {
      kind: "step_up_any_factor";
      tenantId: TenantId;
      policyId: PolicyId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
    }
  | {
      kind: "approval_and_step_up";
      tenantId: TenantId;
      policyId: PolicyId;
      approvalPolicyId: ApprovalPolicyId;
      factorKinds: NonEmptyArray<AuthFactorKind>;
    };

type CapabilityOperationPolicyMap =
  | {
      kind: "vault_access_policy_map";
      proxyUse: CapabilityOperationAuthPolicy;
      revealSecret: CapabilityOperationAuthPolicy;
      exportSecret: CapabilityOperationAuthPolicy;
      changePermissions: CapabilityOperationAuthPolicy;
      breakGlassReveal: CapabilityOperationAuthPolicy;
    }
  | {
      kind: "near_ed25519_mpc_policy_map";
      signTransaction: CapabilityOperationAuthPolicy;
      produceAuthProof: CapabilityOperationAuthPolicy;
      exportKey: CapabilityOperationAuthPolicy;
    }
  | {
      kind: "evm_ecdsa_mpc_policy_map";
      signTransaction: CapabilityOperationAuthPolicy;
      produceAuthProof: CapabilityOperationAuthPolicy;
      exportKey: CapabilityOperationAuthPolicy;
    };
```

### MPC Signer Proof As Derived Auth

`mpc_signer_proof` is a derived auth factor backed by an enabled MPC capability.
It is stronger than ordinary app-session auth because the proof can bind user
presence, registered device state, threshold participation, and a typed Seams
operation digest.

The proof inherits the auth policy of the signer capability operation that
produces it:

```text
MPC capability produceAuthProof policy
  -> passkey, Email OTP, wallet login, or tenant-defined step-up
  -> MPC signer signs typed Seams auth challenge
  -> MpcSignerProof
  -> mpc_signer_proof factor satisfied
```

This is a Seams-specific high-assurance primitive. Better Auth can provide the
session and standard auth factors that feed the inherited policy, while Seams
authorization owns the MPC proof challenge, digest binding, capability lookup,
threshold signing path, and grant issuance.

Evaluation rules:

- policy branches that require `mpc_signer_proof` must name or resolve an MPC
  signer capability;
- the signer capability must exist, be active, and belong to the same tenant and
  principal;
- the signer capability must support `produceAuthProof`;
- the `produceAuthProof` operation runs the signer capability's inherited auth
  policy;
- the proof challenge must bind tenant, principal, session, signer capability,
  target operation, lane digest, intent digest, device ID, nonce, and expiry;
- missing or inactive MPC capability returns `capability_not_enabled` or
  `capability_not_active`;
- no fallback to passkey, OTP, or session auth occurs unless the policy defines
  an explicit alternative branch;
- `mpc_signer_proof` cannot authorize producing another proof for the same
  signer by default.

Capabilities are attached independently:

```ts
type ProtectedCapability =
  | {
      kind: "vault_access";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      defaultPolicyId: PolicyId;
      operationPolicies: Extract<
        CapabilityOperationPolicyMap,
        { kind: "vault_access_policy_map" }
      >;
    }
  | {
      kind: "near_ed25519_mpc_signing";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      signerId: NearEd25519SignerId;
      operationPolicies: Extract<
        CapabilityOperationPolicyMap,
        { kind: "near_ed25519_mpc_policy_map" }
      >;
    }
  | {
      kind: "evm_ecdsa_mpc_signing";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      signerId: EvmEcdsaSignerId;
      operationPolicies: Extract<
        CapabilityOperationPolicyMap,
        { kind: "evm_ecdsa_mpc_policy_map" }
      >;
    };
```

Sensitive operations are exact and capability-specific:

```ts
type SensitiveOperationIntent =
  | {
      kind: "vault_access";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      lane: VaultAccessLane;
      intent: VaultAccessIntent;
      policy: SensitiveOperationPolicy;
    }
  | {
      kind: "near_ed25519_mpc_sign";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      lane: NearEd25519MpcLane;
      intent: NearEd25519SigningIntent;
      policy: SensitiveOperationPolicy;
    }
  | {
      kind: "evm_ecdsa_mpc_sign";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      lane: EvmEcdsaMpcLane;
      intent: EvmEcdsaSigningIntent;
      policy: SensitiveOperationPolicy;
    }
  | {
      kind: "mpc_key_export";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityId: CapabilityId;
      lane: MpcKeyExportLane;
      intent: MpcKeyExportIntent;
      policy: SensitiveOperationPolicy;
    };

type SensitiveOperationGrant =
  | {
      kind: "active";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      grantId: SensitiveOperationGrantId;
      capabilityId: CapabilityId;
      operationKind: SensitiveOperationKind;
      laneDigest: DigestB64u;
      intentDigest: DigestB64u;
      policyId: PolicyId;
      remainingUses: PositiveInt;
      expiresAt: IsoTimestamp;
    }
  | {
      kind: "consumed";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      grantId: SensitiveOperationGrantId;
      capabilityId: CapabilityId;
      operationKind: SensitiveOperationKind;
      laneDigest: DigestB64u;
      intentDigest: DigestB64u;
      policyId: PolicyId;
      consumedAt: IsoTimestamp;
    }
  | {
      kind: "expired";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      grantId: SensitiveOperationGrantId;
      capabilityId: CapabilityId;
      operationKind: SensitiveOperationKind;
      laneDigest: DigestB64u;
      intentDigest: DigestB64u;
      policyId: PolicyId;
      expiredAt: IsoTimestamp;
    };

type MpcSignerProofFailure =
  | {
      kind: "capability_not_enabled";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityKind: "near_ed25519_mpc_signing" | "evm_ecdsa_mpc_signing";
    }
  | {
      kind: "capability_not_active";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
    }
  | {
      kind: "capability_principal_mismatch";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
    }
  | {
      kind: "operation_not_supported";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
      operationKind: "produceAuthProof";
    };
```

## Capability Boundaries

### `seams-authorization`

Owns:

- principals and auth accounts;
- auth factors;
- auth plugin registration;
- `SeamsSession`;
- step-up method selection;
- sensitive-operation policies;
- canonical operation digest envelope;
- short-lived operation grants;
- replay and budget accounting;
- audit envelopes.
- auth provider evidence parsing.

Does not own:

- Better Auth storage schema;
- Better Auth route handlers;
- vault item schema;
- secret unwrap or injection;
- MPC threshold sessions;
- signer WASM;
- HSS export;
- chain-specific transaction display.

### `capability-vault`

Owns:

- vault items, versions, fields, attachments, and wrapped keys;
- team RBAC and membership access mode;
- `VaultAccessLane`;
- `VaultAccessIntent`;
- Secret Broker and Egress Gateway integration;
- reveal, rotate, delegate, and proxy-only use policies;
- default operation policy map.

Uses `seams-authorization` for:

- auth session checks;
- step-up;
- sensitive-operation grant minting;
- audit envelope generation.

### `capability-near-ed25519-mpc`

Owns:

- NEAR Ed25519 signer identity;
- Ed25519 threshold signing lanes;
- NEAR transaction and NEP-413 display semantics;
- Ed25519 signing runtime material;
- Ed25519 export behavior where supported;
- default operation policy map.

Uses `seams-authorization` for session, step-up, budget, grants, and audit.

### `capability-evm-ecdsa-mpc`

Owns:

- EVM-family ECDSA signer identity;
- `ThresholdEcdsaChainTarget`;
- ECDSA threshold-session runtime;
- HSS prepare/finalize;
- signer WASM loading;
- ECDSA key export;
- EVM-family transaction display and nonce/budget coupling;
- default operation policy map.

Uses `seams-authorization` for session, step-up, budget, grants, and audit.

## Lazy Loading Rules

Registration:

- Always create `AuthAccount`.
- Register auth providers and auth plugins per tenant.
- Register IdP relying-party applications only for tenants with IdP mode
  enabled.
- Create only requested `ProtectedCapability` records.
- Vault-only registration creates no Ed25519 or ECDSA signer records.
- Wallet registration creates signer capabilities explicitly.
- Capability provisioning validates that every referenced auth factor kind is
  registered.

Frontend:

- Load auth UI for every account.
- Load auth provider UI by registered tenant auth factor kind.
- Load IdP admin UI only for tenants with IdP mode enabled.
- Load vault UI only for tenants with `vault_access`.
- Load wallet UI only for tenants with MPC signing capabilities.
- Load generic confirmation UI without importing MPC signing runtime.
- Load signer WASM only from MPC capability workers.
- Keep vault-only and IdP-only browser bundles free of signer WASM, HSS,
  threshold-session stores, chain display adapters, and wallet UI modules.
- Treat `passkey-confirm.worker.ts` and `UiConfirmManager.ts` as split targets:
  generic auth/confirmation behavior moves to an auth confirmation worker, while
  threshold warm-session material and signer WASM stay in MPC capability workers.

Worker/runtime:

- Auth routes are mounted from registered tenant auth providers.
- IdP routes are mounted only for tenants with IdP mode enabled.
- Route-level assembly imports only enabled capability handlers.
- Vault Worker paths cannot import signer WASM or HSS modules.
- IdP Worker paths cannot import vault or MPC capability modules.
- MPC Worker paths can import chain and threshold modules.
- Capability absence returns a typed authorization denial.

Packages:

```text
packages/seams-authorization/
packages/seams-auth/
packages/seams-auth-better-auth/
packages/seams-auth-idp/
packages/capability-vault/
packages/capability-near-ed25519-mpc/
packages/capability-evm-ecdsa-mpc/
packages/capability-assembly/
```

`capability-assembly` is the only package that wires multiple capabilities into
one app/runtime. Keep shared utilities out of assembly.

`packages/seams-authorization/` owns `SeamsSession`, step-up, grant domain,
policy evaluators, and audit envelope builders.

`packages/seams-auth/` owns the first-party auth plugin registry and session
provider implementation.

`packages/seams-auth-better-auth/` owns Better Auth adapters that convert Better
Auth sessions and step-up proofs into Seams auth provider evidence.

`packages/seams-auth-idp/` owns optional IdP endpoints, relying-party
registration, OIDC Provider metadata, authorization-code issuance, token
issuance, refresh-token rotation, JWKS publication, and SAML IdP support if it
is added.

## Persistence Schema Defaults

These defaults make the auth/capability model concrete enough for migrations,
adapters, and tests. The internal domain type uses `tenantId`. The first D1
adapter may map existing console `org_id` into `tenantId` at the persistence
boundary. New tables should store `namespace` plus `tenant_id` so all rows can
support multiple deployment namespaces and multiple tenants.

Default storage rules:

- Use TEXT IDs with ULID or UUIDv7-style generation. Avoid integer IDs except
  fixed protocol counters such as threshold share IDs.
- Use `created_at_ms`, `updated_at_ms`, `expires_at_ms`, `revoked_at_ms`, and
  `consumed_at_ms` millisecond timestamps to match existing D1 migrations.
- Put `namespace` and `tenant_id` first in primary keys and indexes.
- Store lifecycle as explicit enum columns with CHECK constraints. Core code
  should parse those strings into discriminated unions at the adapter boundary.
- Store query-critical fields as columns. Use JSON columns only for provider
  config, display metadata, policy documents, and encrypted/opaque envelopes.
- Add `CHECK (json_valid(...))` for JSON columns and digest-length checks for
  digest columns in D1 migrations.
- Store raw grant tokens, refresh tokens, OTPs, auth headers, vault secrets, and
  signer material as hashes, sealed envelopes, or external secret references.
- Keep compatibility mapping at the adapter boundary. Core logic should never
  accept rows shaped like old wallet/session records.
- Default tenant scope is the console organization. Add `project_id` and
  `environment_id` only on resource rows that must inherit project/environment
  policy.
- Treat humans, agents, service accounts, and system actors as principals. Use
  membership and access-mode rows to express what each principal can do.

Shared auth and authorization tables:

```text
auth_tenants(
  namespace,
  tenant_id,
  lifecycle_kind,
  display_name,
  created_at_ms,
  updated_at_ms
)

auth_principals(
  namespace,
  tenant_id,
  principal_id,
  principal_kind,       -- human | agent | service_account | system
  lifecycle_kind,       -- invited | active | suspended | removed
  email_normalized,
  display_name,
  created_at_ms,
  updated_at_ms
)

auth_tenant_memberships(
  namespace,
  tenant_id,
  membership_id,
  principal_id,
  member_access_kind,   -- direct_member | delegate_member
  roles_json,
  lifecycle_kind,
  invited_by_principal_id,
  created_at_ms,
  updated_at_ms
)

auth_accounts(
  namespace,
  tenant_id,
  principal_id,
  lifecycle_kind,
  recovery_policy_id,
  created_at_ms,
  updated_at_ms
)

auth_factors(
  namespace,
  tenant_id,
  factor_id,
  principal_id,
  factor_kind,          -- passkey | email_otp | slack_otp | wallet_login | mpc_signer_proof | recovery_code
  factor_ref_json,
  lifecycle_kind,
  created_at_ms,
  updated_at_ms
)

auth_devices(
  namespace,
  tenant_id,
  device_id,
  principal_id,
  device_kind,
  device_fingerprint_digest,
  user_agent_hash,
  ip_hash,
  lifecycle_kind,
  created_at_ms,
  last_seen_at_ms,
  revoked_at_ms
)

auth_providers(
  namespace,
  tenant_id,
  provider_id,
  provider_kind,        -- seams_auth | better_auth | oidc | saml | wallet
  lifecycle_kind,
  factor_kinds_json,
  provider_config_json,
  config_digest,
  created_at_ms,
  updated_at_ms
)

auth_provider_identities(
  namespace,
  tenant_id,
  provider_identity_id,
  provider_id,
  provider_subject,
  principal_id,
  email_normalized,
  claims_digest,
  lifecycle_kind,
  created_at_ms,
  updated_at_ms
)

auth_sso_group_mappings(
  namespace,
  tenant_id,
  provider_id,
  external_group_id,
  external_group_name,
  role_refs_json,
  lifecycle_kind,
  created_at_ms,
  updated_at_ms
)

seams_sessions(
  namespace,
  tenant_id,
  session_id,
  principal_id,
  provider_id,
  device_id,
  assurance_level,
  lifecycle_kind,       -- active | revoked | expired
  created_at_ms,
  expires_at_ms,
  revoked_at_ms
)

seams_session_refresh_tokens(
  namespace,
  tenant_id,
  refresh_token_id,
  session_id,
  principal_id,
  token_family_id,
  refresh_token_hash,
  lifecycle_kind,       -- active | rotated | revoked | expired
  created_at_ms,
  expires_at_ms,
  rotated_at_ms,
  revoked_at_ms
)

seams_session_events(
  namespace,
  tenant_id,
  event_id,
  session_id,
  principal_id,
  event_kind,
  event_digest,
  created_at_ms
)

step_up_challenges(
  namespace,
  tenant_id,
  challenge_id,
  session_id,
  principal_id,
  factor_kind,
  capability_kind,
  operation_kind,
  lane_digest,
  intent_digest,
  challenge_digest,
  lifecycle_kind,       -- issued | verified | expired | revoked
  created_at_ms,
  expires_at_ms,
  verified_at_ms
)

step_up_authorizations(
  namespace,
  tenant_id,
  step_up_id,
  challenge_id,
  session_id,
  principal_id,
  factor_id,
  device_id,
  operation_digest,
  lifecycle_kind,       -- active | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms
)

operation_policies(
  namespace,
  tenant_id,
  policy_id,
  capability_kind,
  operation_kind,
  policy_kind,          -- session_only | step_up_any_factor | approval_and_step_up | mpc_signer_proof
  policy_json,
  lifecycle_kind,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

protected_capabilities(
  namespace,
  tenant_id,
  capability_id,
  capability_kind,      -- vault_access | near_ed25519_mpc_signing | evm_ecdsa_mpc_signing
  lifecycle_kind,
  default_policy_id,
  operation_policy_map_json,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

principal_capability_bindings(
  namespace,
  tenant_id,
  binding_id,
  capability_id,
  principal_id,
  binding_kind,         -- owner | admin | direct_member | delegate_member
  lifecycle_kind,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

sensitive_operation_grants(
  namespace,
  tenant_id,
  grant_id,
  grant_token_hash,
  principal_id,
  session_id,
  capability_id,
  operation_kind,
  lane_digest,
  intent_digest,
  policy_id,
  remaining_uses,
  lifecycle_kind,       -- active | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms
)

sensitive_operation_grant_uses(
  namespace,
  tenant_id,
  use_id,
  grant_id,
  principal_id,
  capability_id,
  operation_kind,
  result_kind,
  operation_digest,
  created_at_ms
)

authorization_audit_events(
  namespace,
  tenant_id,
  event_id,
  principal_id,
  actor_principal_kind,
  session_id,
  capability_id,
  operation_kind,
  lane_digest,
  intent_digest,
  factor_kinds_json,
  result_kind,
  event_digest,
  created_at_ms
)
```

IdP tables stay in `seams-auth-idp`:

```text
idp_relying_parties(...)
idp_signing_keys(...)
idp_authorization_codes(...)
idp_refresh_tokens(...)
idp_token_events(...)
```

Vault tables stay in `capability-vault`:

```text
vaults(
  namespace,
  tenant_id,
  vault_id,
  capability_id,
  display_name,
  lifecycle_kind,
  metadata_privacy_kind, -- standard | encrypted_metadata
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

vault_items(
  namespace,
  tenant_id,
  vault_id,
  item_id,
  item_kind,             -- login | api_key | token | note | ssh_key | custom
  lifecycle_kind,
  plaintext_label,
  search_metadata_json,
  current_version_id,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

vault_item_versions(
  namespace,
  tenant_id,
  vault_id,
  item_id,
  version_id,
  envelope_version,
  sealed_item_json,
  key_ref,
  aad_digest,
  ciphertext_digest,
  created_by_principal_id,
  created_at_ms
)

vault_proxy_bindings(
  namespace,
  tenant_id,
  binding_id,
  vault_id,
  item_id,
  allowed_host,
  allowed_method_kinds_json,
  injection_template_json,
  lifecycle_kind,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

vault_break_glass_requests(
  namespace,
  tenant_id,
  request_id,
  vault_id,
  item_id,
  requested_by_principal_id,
  approval_id,
  lifecycle_kind,
  reason_digest,
  created_at_ms,
  resolved_at_ms
)
```

Default vault item model:

- Store a versioned, sealed canonical item document in `sealed_item_json`.
- The canonical document contains typed fields, sections, file references,
  notes, OTP config, rotation hints, and provider-specific metadata.
- Keep only `item_kind`, `plaintext_label`, and minimal search metadata outside
  the sealed envelope by default.
- Allow `metadata_privacy_kind = encrypted_metadata` for tenants that want
  labels and search metadata inside the encrypted envelope.
- Use `vault_proxy_bindings` for cloud injection policy. Delegate members can
  receive proxy-use grants for these bindings, while reveal/export grants require
  `direct_member` or stronger policy.

MPC capability tables stay in their modules:

- Ed25519 signer tables under `capability-near-ed25519-mpc`.
- ECDSA signer, HSS, threshold-session, and export tables under
  `capability-evm-ecdsa-mpc`.

Existing console tables need either migrations or replacement views for the new
domain:

- team membership must accept human, agent, service-account, and system
  principals;
- approvals must add vault reveal, vault export, vault permission change,
  break-glass, and capability provisioning operation types;
- audit must add auth, capability, vault, IdP, and agent actor categories;
- API credential scopes must replace wallet-only scopes with the auth-first
  management scope taxonomy.

These tables are logical schema requirements. Concrete adapters may map them to
D1, PostgreSQL, Prisma, Drizzle, SQLite, or another supported database, provided
the adapter preserves boundary parser guarantees and tenant-scoped uniqueness.

## Security Model

Auth factors prove who is present.

Capabilities define what can be done.

Operation policies define which auth factors can authorize each capability
operation.

Sensitive-operation grants authorize one exact action.

Vault access default:

```text
SeamsSession + operation policy + RBAC + short-lived grant + audit
```

MPC signing default:

```text
SeamsSession + operation policy + MPC capability lane + threshold signing runtime
```

IdP token issuance default:

```text
SeamsSession + relying-party policy + claim policy + signed identity token + audit
```

High-assurance vault mode can require `mpc_signer_proof` when the tenant has an
MPC capability. Preventing unilateral server decrypt still depends on key
custody, such as customer KMS or sidecar unwrap.
