# Modular Auth And Capability Refactor SPEC

Date created: June 28, 2026

Status: planning.

Companion doc: [Implementation plan](./refactor-90-modular-auth-capabilities-plan.md).

## Goal

Split the current signing-session architecture into a small shared auth/session
core plus optional protected capability modules.

The shared layer should gate capability operations for multiple capabilities:

- vault access;
- NEAR Ed25519 MPC signing;
- EVM-family ECDSA MPC signing.

Vault-only customers should provision an auth account and vault access without
loading MPC signer material, signer WASM, HSS export logic, wallet UI, or
threshold-session setup.

Auth methods should be modular. Passkeys, Email OTP, Slack OTP, recovery codes,
Better Auth, and future SSO providers can all feed normalized session evidence into
Seams. Capabilities sit downstream from auth and bind operation-level policies
to normalized session evidence and assurance levels.

Build Seams authorization as first-party security infrastructure. `seams-auth`
is the first-party auth provider. Better Auth can also be used through a
session-provider adapter. The system of record for grant evidence,
capability grants, capability grant policies, and audit envelopes lives
inside Seams.

`seams-auth` must store authentication data in the customer's configured
database by default. This preserves data residency, compliance control, pricing
predictability, and deployer ownership of auth records.

`seams-auth` must support multi-tenant organizations, multiple active sessions
per user across devices, and enterprise SSO through OIDC providers such as Okta,
Google Workspace, Microsoft Entra ID, OneLogin, and JumpCloud. SAML can be added
later when enterprise demand justifies the extra protocol surface.

`seams-auth` must also support identity-provider mode for applications that want
Seams to be the login authority. In this mode, Seams authenticates the principal
and issues identity assertions to configured relying-party applications.

## Core Decision

Split auth into two layers:

1. Auth providers prove identity, session state, and auth factors.
2. Seams authorization evaluates capability grant policy and mints exact
   capability grants.

`seams-auth` is the built-in auth provider. Better Auth is a supported upstream
provider through `betterAuthSessionProvider(auth)`.

Rename the parent concept from `signing-session` to `SeamsSession`.

`SeamsSession` owns identity, auth factors, and session state. Seams
authorization owns grant evidence, capability grants, grant-use limits, and audit envelopes.
MPC signing is a capability that uses this shared layer. Vault access is another
capability that uses the same shared layer.

```text
Auth account
  -> auth provider
  -> normalized auth factors
  -> SeamsSession
  -> GrantEvidence
  -> CapabilityGrant

Capability instances
  -> vault_access
  -> near_ed25519_mpc_signing
  -> evm_ecdsa_mpc_signing
```

Auth providers define mechanisms. Capabilities define resources. Capability
grant policies bind grant evidence to capability operations.

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
| Auth account and sessions | session and authorization modules |
| WebAuthn, Email OTP, Slack OTP, wallet login factors | auth factor modules |
| Identity links, SSO claims, IdP relying parties | session, authorization, and IdP modules |
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
- keep passkey, Email OTP, Slack OTP, wallet login, and recovery code as local
  auth factor kinds;
- create `SessionEvidenceKind` for session evidence and provider assurance;
- create `GrantEvidenceKind` for evidence that can satisfy capability grant
  policies;
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

type ProviderSessionEvidenceKind = "oidc_session";

type ProviderAssuranceEvidenceKind =
  | "provider_mfa"
  | "provider_phishing_resistant"
  | "provider_device_trust";

type ProviderEvidenceKind =
  | ProviderSessionEvidenceKind
  | ProviderAssuranceEvidenceKind;

type SessionEvidenceKind =
  | AuthFactorKind
  | ProviderEvidenceKind;

type InteractiveGrantEvidenceKind =
  | "passkey_assertion"
  | "email_otp"
  | "slack_otp"
  | "wallet_login";

type GrantEvidenceKind =
  | "seams_session"
  | InteractiveGrantEvidenceKind
  | ProviderEvidenceKind
  | "service_account_api_key"
  | "approval_decision"
  | "mpc_signer_proof";

type MpcCapabilityAuthFactorKind = Extract<
  AuthFactorKind,
  "passkey" | "email_otp"
>;
```

Wallet-login evidence is session/auth-factor evidence. MPC signing policies
accept only digest-bound native grant evidence (`passkey_assertion`,
`email_otp`) or derived `mpc_signer_proof`; wallet-login evidence never gates
signing.

### Wallet Session Restoration Boundary

Page refresh and iframe startup currently need to rebuild wallet-session UI from
durable local records after volatile runtime signing records disappear. The
resolver for that flow must compose the same branch-specific
`WalletUnlockSubject` model used by unlock. It must not create a parallel
NEAR-only session subject.

Refactor move:

- parse raw `walletId`, last-used account hints, and profile rows once at the
  session-read boundary;
- resolve durable wallet identity into `WalletUnlockSubjectSet`;
- compute wallet-session display state from branch subjects plus sealed/session
  records;
- surface missing, corrupt, or ambiguous durable identity as typed
  `unresolvable` results;
- keep provenance (`runtime_session_record`, `profile_projection`,
  `host_last_used_profile`) as diagnostics only;
- represent restorable sealed sessions as `active_restorable`, then let signing
  or export prepare perform exact material restore and demote to re-auth on
  typed restore failure.

Target shape:

```ts
type WalletUnlockSubject =
  | {
      kind: "near_ed25519_wallet";
      walletId: WalletId;
      nearAccountId: NearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      signerSlot: SignerSlot;
    }
  | {
      kind: "evm_family_ecdsa_wallet";
      walletId: WalletId;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    };

type WalletUnlockSubjectSet = {
  kind: "wallet_unlock_subject_set";
  walletId: WalletId;
  subjects: NonEmptyArray<WalletUnlockSubject>;
};

type WalletIdentitySource =
  | "runtime_session_record"
  | "profile_projection"
  | "host_last_used_profile";

type WalletIdentityResolveFailure =
  | "missing_wallet_profile"
  | "ambiguous_wallet_profile"
  | "missing_requested_capability_subject"
  | "invalid_wallet_profile";

type WalletSessionReadResolution =
  | { kind: "no_session_request" }
  | {
      kind: "resolved";
      walletId: WalletId;
      subjectSet: WalletUnlockSubjectSet;
      source: WalletIdentitySource;
    }
  | {
      kind: "no_session_for_wallet";
      walletId: WalletId;
      reason: "missing_requested_capability_subject";
      source: WalletIdentitySource;
    }
  | {
      kind: "unresolvable";
      walletId: WalletId;
      reason: WalletIdentityResolveFailure;
    };

type WalletSessionDisplayState =
  | { kind: "locked" }
  | { kind: "active_warm"; subjectSet: WalletUnlockSubjectSet }
  | { kind: "active_restorable"; subjectSet: WalletUnlockSubjectSet }
  | { kind: "expired"; subjectSet: WalletUnlockSubjectSet }
  | { kind: "exhausted"; subjectSet: WalletUnlockSubjectSet }
  | { kind: "unavailable"; subjectSet: WalletUnlockSubjectSet };
```

`WalletUnlockSubjectSet` is the only wallet/capability subject shape consumed
below the session-read boundary. NEAR account identity exists only on the
`near_ed25519_wallet` branch. ECDSA-only restoration must not import NEAR
account validators or fabricate a NEAR account subject. Auth-method display
must come from wallet-auth-method bindings or session evidence, never from
`publicKey` heuristics.

### Signing-Centered Grant-Evidence UI

`packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts` currently
uses `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`,
`thresholdSessionId`, and `signingGrantId`. That makes the browser confirmation
system hard to reuse for vault access and IdP high-risk scope issuance.

Refactor move:

- rename shared client confirmation concepts to `CapabilityGrantPlan` and
  `CapabilityGrantChallenge`;
- keep `thresholdSessionId` only inside MPC capability operation lanes and MPC UI
  adapters;
- replace `signingGrantId` in shared UI payloads with
  `capabilityGrantId`;
- move wallet-specific display data behind a capability display adapter;
- let vault, IdP, and MPC modules provide operation-specific prompt metadata.

Target UI shape:

```ts
type CapabilityGrantPlan =
  | {
      kind: "active_grant";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      capabilityId: CapabilityId;
      operationKind: CapabilityOperationKind;
      grantId: CapabilityGrantId;
      expiresAtMs: number;
      remainingUses: PositiveInt;
    }
  | {
      kind: "grant_evidence_required";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
      laneDigest: DigestB64u;
      intentDigest: DigestB64u;
      displayDigest: DigestB64u;
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
module manifest should own route definitions, required service ports, capability
metadata, and import-guard expectations. Runtime-specific module wrappers should
own handler factories.

Refactor move:

- extend `RouterApiModule` from route-extension wrapper into the canonical route
  manifest contract;
- replace the static handler array with runtime-specific
  `RuntimeRouterApiModule` instances;
- let app assembly choose enabled modules from tenant capability config;
- mount IdP routes only when IdP mode is enabled;
- mount vault routes only when `vault_access` is enabled;
- mount MPC routes only when the relevant MPC capability is enabled;
- add import guards proving vault and IdP route modules do not import threshold,
  HSS, signer WASM, or chain modules.

Target module shape:

```ts
type RouterApiModuleManifest =
  | {
      kind: "router_api_module_manifest";
      moduleId: RouterApiModuleId;
      capabilityKind: CapabilityKind | "seams_auth" | "session" | "management";
      routeDefinitions: readonly RouterApiRouteDefinition[];
      requiredServices: readonly RouteServiceKey[];
      importGuard: RouterModuleImportGuard;
    };

type RuntimeRouterApiModule<TRuntime extends RouteRuntimeKind> =
  | {
      kind: "runtime_router_api_module";
      manifest: RouterApiModuleManifest;
      runtime: TRuntime;
      loadHandlers: RuntimeHandlerFactory<TRuntime>;
    };
```

The manifest must be runtime-neutral. Cloudflare and Node handler factories live
in runtime-specific files so Worker bundles do not import Node-only code.
The module builder should reject duplicate module IDs, duplicate route IDs,
route definitions without handlers for enabled runtimes, and handlers that
request services outside `requiredServices`.

Target assembly shape:

```ts
const modules = buildCloudflareRouteModules({
  idpEnabled,
  vaultEnabled,
  nearMpcEnabled,
  evmMpcEnabled,
});

const router = createCloudflareRouter({
  services,
  modules,
});
```

Builder implementation target:

```ts
type CloudflareRouteModuleFlags = {
  idpEnabled: boolean;
  vaultEnabled: boolean;
  nearMpcEnabled: boolean;
  evmMpcEnabled: boolean;
};

function buildCloudflareRouteModules(
  input: CloudflareRouteModuleFlags,
): RuntimeRouterApiModule<'cloudflare'>[] {
  const optionalModules: RuntimeRouterApiModule<'cloudflare'>[] = [];

  if (input.idpEnabled) optionalModules.push(seamsIdpCloudflareRoutes());
  if (input.vaultEnabled) optionalModules.push(vaultCapabilityCloudflareRoutes());
  if (input.nearMpcEnabled) optionalModules.push(nearEd25519MpcCloudflareRoutes());
  if (input.evmMpcEnabled) optionalModules.push(evmEcdsaMpcCloudflareRoutes());

  return [
    seamsAuthCloudflareRoutes(),
    seamsSessionCloudflareRoutes(),
    ...optionalModules,
  ];
}
```

### Runtime Adapter Decision

Cloudflare Workers are the primary runtime target for this refactor. The Node
web-server consumes the same route modules through a thin adapter. Express is an
on-demand adapter contract over the same handlers if a customer requests Express
hosting.

Capability modularity has two levels:

- **deployment-level modularity:** separate Worker entrypoints or deploy bundles
  can omit vault, MPC, IdP, or other capability handler factories entirely;
- **tenant-level modularity:** one multi-tenant Worker can enable or disable a
  capability per tenant, but any capability present in that Worker entrypoint is
  still part of the deployed bundle.

Decision:

- route definitions, auth policy, service-port requirements, and capability
  metadata are runtime-neutral;
- Cloudflare and Node adapters share manifests and load runtime-specific
  handler factories from separate modules;
- Cloudflare is the release gate for Centaur/cloud deployment;
- Express adapter parity, when introduced, means same route table, same route
  policy, same request parser, and same response envelope through a thin
  adapter.

Validation should compare Cloudflare and Node route manifests for every enabled
product shape while keeping Cloudflare bundle/import guards as the
deployment-critical checks. An Express adapter, if introduced, must pass the
same manifest contract tests.

### Route Auth Policy Planes

`packages/sdk-server-ts/src/router/routeAuthPolicy.ts` has
`console`, `api_credentials`, `user_session`, `threshold_session`, and `public`
planes. The target route policy should distinguish management access, normal
session access, and exact capability grants. Threshold-session details belong to
MPC routes and capability operation lanes.

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
- use `session_principal` for product routes that need an authenticated principal
  without an exact capability operation;
- use `capability_grant` for vault reveal/export/proxy-use, MPC signing, key
  export, break-glass reveal, and IdP high-risk scope issuance;
- keep `public` only for bootstrap, challenge, callback, and health routes that
  verify their own request-bound artifact.

Management planes can create policies, approvals, capabilities, vault metadata,
and principals according to RBAC and scopes. They cannot reveal secrets, inject
secrets, export keys, sign transactions, or issue high-risk IdP scopes unless
the route also requires `capability_grant` context. API keys resolve to
service-account principals by default, and their scopes are management scopes,
not capability grants.

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
- capability operation access for service accounts or agents still flows through
  `CapabilityGrant` and capability grant policy;
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
vault.proxy_use
near.sign_transaction
evm.sign_transaction
idp.high_risk_scope.issue
```

Those belong to capability operation kinds and stay outside management API-key
scopes.

### Grant Evidence For Automation

Management API keys can configure capabilities and policies. They cannot perform
runtime use by themselves. Service accounts, CI jobs, rotations, vault proxy
use, and signing bots must present grant evidence, satisfy policy, and receive a
short-lived `CapabilityGrant`.

Universal capability grant shape:

```text
principal
  + grant evidence
  + capability binding
  + operation envelope
  + capability grant policy
  -> CapabilityGrant
```

Phase-one automation should support only `service_account_api_key` evidence.
OIDC workload federation, mTLS client certificate proof, KMS-bound proof, and
customer workload identity adapters are future evidence providers that can feed
the same grant issuer.

Grant evidence rules:

- `service_account_api_key` evidence resolves to a tenant-scoped
  service-account principal;
- the principal must have a `CapabilityBinding` for the target
  capability;
- authorization resolves policy server-side from capability config,
  environment, principal binding, operation kind, and grant evidence;
- issued grants are short-lived, operation-bound, use-limited, and audited;
- a service-account API key can request an capability grant only when policy names
  that key, service account, operation, resource scope, and environment as
  allowed.

Route policy refactor move:

- replace `console` with `management_console`;
- replace `api_credentials` with `management_api_key`;
- replace `user_session` with `session_principal`;
- replace `threshold_session` with `capability_grant`;
- add `managementOperationKind` and required tenant/project/environment scope to
  management route policies;
- put capability kind, operation kind, and required grant semantics in route
  policy;
- keep threshold session claims inside MPC capability request parsing;
- make `RoutePrincipal` carry normalized management, session, public, or
  capability-grant context.

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
  | { plane: "session_principal" }
  | {
      plane: "capability_grant";
      capabilityKind: CapabilityKind;
      operationKind: CapabilityOperationKind;
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
      plane: "session_principal";
      session: ActiveSeamsSessionRecord;
    }
  | {
      plane: "capability_grant";
      grant: Extract<CapabilityGrant, { kind: "active" }>;
    }
  | { plane: "public"; proof: PublicProof };
```

MPC signing endpoints become capability-grant routes whose handler parses an
MPC operation lane and intent. Vault proxy use, reveal, export, permission
changes, and IdP high-risk scope issuance use the same route policy plane with
different capability and operation kinds.

## Auth Provider Decision

Better Auth is useful for:

- plugin ergonomics;
- server and client plugin pairs;
- auth factor modularity;
- schema-per-plugin design;
- organization, session, API-key, and admin product patterns.

The split is by evidence grade, permanently (plan Decided Point 12):

- **Better Auth is the permanent, optional commodity-auth provider:**
  email+password, social login, organizations, enterprise SSO, admin/API-key
  product patterns. Seams never rebuilds these natively.
- **Seams-native factor modules are exactly those that produce MPC-grade,
  operation-digest-bound evidence or drive the Seams confirmation UI** —
  passkey and Email OTP for signing-grade flows, plus Slack OTP when a tenant
  policy accepts Slack OTP as operation-bound grant evidence. They are never
  ported into Better Auth plugins.
- Both normalize into `SeamsSession` through the same exchange boundary.
  Better Auth is optional at assembly: a signing-only tenant runs native
  factors alone.
- **Providers are interchangeable behind one session-provider port.** Better
  Auth and the Seams-native session provider are two implementations of the
  same contract: swapping is a config/assembly change only, no code outside
  the provider adapter depends on provider specifics, grant-evidence
  endpoints are provider-neutral Seams routes with Better Auth mounting as a
  thin bridge, and one provider conformance suite runs against both. Feature
  sets may differ (commodity breadth is Better Auth's); the exchange
  boundary, authorization, capabilities, and UI behave identically over
  either.
- **MPC signing works over either provider, but provider evidence is never
  the MPC factor.** Capability grant policies for MPC signing lanes accept
  only digest-bound native grant evidence (`passkey_assertion`, `email_otp`)
  or `mpc_signer_proof`; provider session/assurance evidence — including a
  Better Auth passkey login — can never satisfy them. Three structural
  reasons: the wallet authority is the credential enrolled through the Seams
  registration ceremony (a provider-registered passkey is a different,
  unbound credential); signing assertions must bind lane/intent/display
  digests, which login-shaped provider challenges do not; and the native
  factors gate key material cryptographically (worker-material restore
  authorization, Email OTP unlock proof and seal), which a session-minting
  provider cannot substitute.
- **Credential adoption (one passkey, two verifiers):** an existing
  provider-registered passkey may be adopted into wallet authority through
  the Seams add-auth-method enrollment ceremony — Seams verifies an assertion
  against its own challenge and binds the credential ID to the wallet. After
  adoption, Better Auth verifies the credential for login and Seams verifies
  it for signing; provider verification code is never in the signing path.
  The native Email OTP factor may likewise share the provider-verified email
  identity (`provider` + `providerUserId`) while the signing-grade OTP
  challenge stays Seams-run.
- Litmus test for any future factor: digest-bound/MPC-grade evidence or Seams
  confirm UI required → native module; otherwise → Better Auth.

Use Seams authorization for high-assurance cryptographic session evidence that
Better Auth does not provide, such as MPC signer proofs derived from wallet or
signer capabilities.

Seams authorization remains first-party because the core security model must
support:

- MPC-backed liveness and presence checks;
- MPC signer proofs as derived grant evidence;
- lane, intent, and display digest binding before capability grant minting;
- exact lane, intent, and display digests for vault, Ed25519 MPC, ECDSA MPC,
  and key export;
- tenant-defined high-assurance policies;
- server-side capability grant minting that fails closed;
- audit evidence tied to capability ID, principal, lane, evidence, and digest;
- Cloudflare Worker boundaries and bundle guarantees;
- future vault-specific authorization modes.

External auth providers should feed normalized session evidence into
Seams authorization. Seams authorization normalizes grant evidence and decides
whether to issue a `CapabilityGrant`.

## Development Auth Provider Decision

Amended July 3, 2026: v1 ships on the Seams-native session provider — the
existing passkey and Email OTP stack — behind the session-provider port. The
Better Auth adapter is a later compatibility milestone (plan Phase P1B),
gated on the same provider conformance suite the native provider passes.
The description below records what the Better Auth adapter provides when it
lands; it is not the v1 development path.

Better Auth should provide:

- user account and session plumbing;
- cookie/session lifecycle;
- commodity factors where a tenant wants them (email+password, social login);
- organization and API-key scaffolding where useful;
- development ergonomics for client and server auth flows.

Better Auth does not provide wallet-grade or Seams-operation-bound factors. The
existing Seams-native passkey and Email OTP factor modules stay first-party even
during development: their signing-grade flows can bind registration or unlock
ceremonies, their assertions bind to operation digests, and the Seams UI
components are built against them. Slack OTP is native whenever it is accepted
as operation-bound vault grant evidence. These modules plug into the same
session exchange as peer evidence sources beside the Better Auth provider.

Seams should own from the start:

- `SeamsSession` normalization;
- operation lane, intent, and display digest construction;
- operation-bound grant challenges;
- passkey assertions bound to Seams lane, intent, and display digests;
- MPC signer proof challenges bound to Seams lane, intent, and display digests;
- confirmer modal payloads;
- `GrantEvidence`;
- `CapabilityGrant`;
- MPC threshold-session minting;
- vault access grants;
- audit envelopes for capability operations.

The Better Auth integration should therefore be an adapter and plugin bridge:

```text
Better Auth session
  -> betterAuthSessionProvider(auth)
  -> SeamsSession
  -> Seams operation-bound grant evidence
  -> CapabilityGrant
  -> capability operation
```

### Seams Passkey Grant Evidence Plugin

Standard passkey login proves account control. Seams passkey grant evidence must
prove presence for one exact capability operation.

The challenge/verify endpoints are provider-neutral Seams manifest routes
owned by Seams authorization (interchangeability clause: they must work
unchanged over either session provider). The Better Auth plugin is a thin
mounting bridge over those routes — it reuses Better Auth's session context
and route mounting while delegating challenge construction, digest binding,
verification, and capability grant to Seams authorization. When the
Seams-native provider is configured instead, the same routes mount directly
from the manifest with the native session context.

Required endpoints:

```text
POST /seams/grant-evidence/passkey/challenge
POST /seams/grant-evidence/passkey/verify
```

Challenge endpoint responsibilities:

- require an active session from the configured session provider;
- normalize the session into `SeamsSession`;
- accept a capability-local operation request and normalize it at the capability
  route boundary;
- construct the generic `CapabilityOperationEnvelope` inside Seams
  authorization;
- create a WebAuthn challenge bound to tenant, principal, session, capability,
  operation kind, lane digest, intent digest, display digest, origin, RP ID,
  and expiry;
- return public challenge options plus confirmer modal metadata.

Verify endpoint responsibilities:

- require the same active `SeamsSession`;
- parse the WebAuthn assertion at the request boundary;
- verify origin, RP ID, challenge, credential ID, user presence, and user
  verification policy;
- verify the challenge maps to the same tenant, principal, session, operation
  kind, lane digest, intent digest, display digest, and capability ID;
- create `GrantEvidence` with `evidenceKind: "passkey_assertion"`;
- mint a short-lived `CapabilityGrant` when policy allows;
- return only grant metadata required by the capability caller.

Security rules:

- Better Auth passkey registration and login can manage account-level passkeys.
- Seams operation-bound passkey challenges must use Seams grant challenge
  records.
- Better Auth hooks and plugin endpoints cannot mint Seams grants directly.
- WebAuthn challenge records must be single-use and short-lived.
- Challenge verification must fail when the operation kind, lane digest, intent
  digest, display digest, session, tenant, RP ID, origin, or credential binding
  changes.
- Confirmer modal display data must be derived from capability-owned typed
  request data after boundary parsing.

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
- tenant-scoped capability grant policies;
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
- session-bound grant evidence;
- audit fields for device ID, user agent hash, IP hash, and auth provider.

### Session Exchange

Session exchange is the boundary that converts provider-specific login evidence
into a `SeamsSession`. It should be specified separately from grant evidence and
capability grants because it is the root login path for Better Auth,
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
      factorKind: Extract<AuthFactorKind, "passkey" | "email_otp" | "slack_otp" | "recovery_code">;
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
      session: ActiveSeamsSessionRecord;
      delivery: SessionDelivery;
      providerIdentityId: ProviderIdentityId;
    }
  | {
      kind: "refreshed";
      previousSessionId: SeamsSessionId;
      session: ActiveSeamsSessionRecord;
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

Session handle rules:

- Bearer `SeamsSession` values are bearer authority. SDKs must never log them,
  store them outside the selected session store, or persist them in diagnostics.
- Browser-cookie delivery stores the session token only in an HttpOnly cookie.
  The SDK handle wraps delivery mode plus CSRF binding metadata, not the token.
- Hosted wallet iframe deployments cannot rely on unrestricted third-party
  cookies. Cross-origin iframe mode must use a first-party storage/access flow
  or an explicit postMessage/token-exchange boundary that resolves to the same
  `SeamsSessionRecord` server-side.

Default exchange behavior:

- `betterAuthSessionProvider(auth)` verifies the Better Auth session and emits
  `SessionProviderEvidence`; Seams owns the normalized session record.
- Seams Auth native factors can exchange verified login assertions directly.
- OIDC adapters verify protocol artifacts, then emit normalized provider
  identity evidence.
- Embedded wallet login creates a `SeamsSession` without provisioning signer
  capabilities.
- Refresh rotates refresh-token family state and records a session event.
- Revocation operates on one session by default. Tenant forced logout and
  principal-wide logout are explicit commands.
- Session exchange cannot mint `CapabilityGrant` records, provision
  capabilities, or satisfy grant evidence requirements by itself.

Device identity is minted and managed by the `session/` module. Session exchange
accepts a boundary-normalized `SessionDeviceEvidence`, looks up or creates the
`auth_devices` row for the principal, rejects revoked devices, and stores the
resulting `deviceId` on sessions, challenges, grant evidence, MPC signer
proofs, and audit events. Core authorization and capability code require
`DeviceId`; they never fingerprint a device directly.

### Enterprise SSO

Enterprise customers must be able to use their existing identity providers to
log into Seams. Initial provider support is OIDC.

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
- authorization-code flow with PKCE and provider callback validation;
- group and role mapping into Seams team/RBAC records;
- SSO session evidence parsed into `SessionProviderEvidence`;
- capability grant policy compatibility with SSO sessions plus Seams-native
  evidence.

Deferred SAML support should be added as a separate provider adapter once the
OIDC path is stable.

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
- optional grant evidence before issuing high-risk scopes;
- audit events for authorization code issuance, token issuance, token refresh,
  token revocation, and client configuration changes.

Embedded wallet login should be modeled as an auth factor that can create a
`SeamsSession`. Wallet-owned MPC signer material remains capability-owned and
loads only when a policy requires MPC-backed presence or signing. External
relying-party applications receive identity tokens or assertions. Seams
`CapabilityGrant` records remain internal to Seams authorization.

## Vocabulary

Type-sketch amendments applied July 3, 2026:

- Internal modules use `AuthFactorModule`; the public browser config keeps the
  customer-facing `authMethods` key.
- Evidence kinds are composed from family unions (`AuthFactorKind`, provider
  evidence, interactive grant evidence, and derived grant evidence).
- `SeamsSession` is exposed publicly as an opaque branded handle. Internal code
  uses `SeamsSessionRecord` and `ActiveSeamsSessionRecord`.
- Repeated status and digest clusters use `RecordStatus` and
  `OperationDigestSet`.
- Deferred workload evidence kinds stay out of `GrantEvidenceKind` until their
  provider phase lands.
- Audit envelope writing lives in `seams-authorization`; there is no separate
  `audit-core` package.

| Current term | Target term |
| --- | --- |
| signing session | `SeamsSession` |
| signing grant | `CapabilityGrant` |
| signing budget | capability grant use limits (`CapabilityGrantPolicy.maxUses` plus active grant `remainingUses`) |
| capability-specific signing scope | capability-local lane |
| signing auth method | `AuthFactor` |
| signer material | capability-owned runtime material |
| wallet registration | auth account registration plus optional capability provisioning |

Use `MpcSigningSession` only inside the MPC capability modules, where threshold
runtime state is actually present.

`CapabilityLane` means a capability-local authorization path such as
`vault.proxy_use`, `vault.reveal`, `near.sign_transaction`, or
`evm.sign_transaction`. It determines the policy family and is bound as
`laneDigest`.

`CapabilityIntent` means the exact semantic request inside a lane, such as the
transaction, vault secret use, export request, or permission change. It is bound
as `intentDigest`.

`CapabilityDisplay` means the canonical prompt and audit display derived from a
parsed intent. It is bound as `displayDigest`.

### Digest Canonicalization

`authorization/digests` is the authoritative owner for lane, intent, display,
challenge, evidence-set, and audit digest construction. Capability modules
produce typed lane/intent/display objects, then call this module for canonical
bytes and digest labels.

Canonical bytes:

- UTF-8 JSON with explicit domain labels such as
  `seams.capability.intent.v1`;
- stable lexicographic ordering for object keys;
- original order preserved for arrays;
- no `undefined`, sparse arrays, non-finite numbers, functions, symbols, or raw
  class instances;
- branded ID strings and integer counters encoded as strings when precision
  matters across TypeScript and Rust;
- every digest input includes `tenantId`, `capabilityKind`, `operationKind`,
  and a schema version.

A3 owns TypeScript fixtures plus Rust parity vectors before any capability
depends on a digest. A capability can add a new lane or intent only by adding
vectors for its canonical bytes and digest output.

## Layering Rules

1. `seams-authorization` cannot import vault, Ed25519 MPC, ECDSA MPC, signer
   WASM, HSS, or chain-specific code.
2. Capability modules can import `seams-authorization`.
3. App assembly code can import selected capabilities and wire them to routes.
4. Tenant capability state lives in persistence, not in legacy flags.
5. Route handlers fail closed when a required capability is missing.
6. Compatibility code belongs only at request and persistence boundaries, with a
   named deletion condition.
7. Build a constrained first-party auth factor module surface. Support
   Better Auth through a session-provider adapter.
8. Capabilities reference registered grant evidence kinds through operation-level
   policies. They do not instantiate auth factor modules directly.
9. Auth providers can create sessions and verify factors. Only Seams
   authorization can mint `CapabilityGrant` records.
10. `seams-auth` persistence goes through an explicit database adapter. Raw
    database rows are normalized once at the adapter boundary.

## Configuration Shape

Use an auth provider plus capability-specific grant policies.

`seamsAuth(...)` is a composition layer, not a Better Auth reimplementation
(plan Decided Point 12). It wires the Seams-native factor modules (passkey,
Email OTP, Slack OTP when enabled for operation-bound evidence, and recovery
codes) plus an optional Better Auth instance and the session exchange. In
the sketch below, `emailAndPassword`, `socialProviders`, `enterpriseSSO`, and
`organization` are reachable only through the optional Better Auth provider
composition — they are not implemented natively, and the native surface does
not grow commodity-auth options. The top-level API should feel like
application auth configuration, while internally normalizing every enabled
mechanism into an `AuthFactorModule`, `AuthFactorKind`,
`SessionEvidenceKind`, and `GrantEvidenceKind`. The `database` option is
required for production deployments.

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
- grant challenges;
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
        proxyUse: requireAnyGrantEvidence(["seams_session", "service_account_api_key"]),
        revealSecret: requireAnyGrantEvidence([
          "passkey_assertion",
          "email_otp",
          "slack_otp",
        ]),
        exportSecret: requireAnyGrantEvidence(["passkey_assertion"]),
        rotateSecret: requireAnyGrantEvidence([
          "passkey_assertion",
          "service_account_api_key",
        ]),
        changePermissions: requireAnyGrantEvidence(["passkey_assertion"]),
        breakGlassReveal: requireGrantEvidence([
          "approval_decision",
          "passkey_assertion",
        ]),
      },
    }),
    nearEd25519MpcCapability({
      operationPolicies: {
        signTransaction: requireAnyGrantEvidence(["passkey_assertion", "email_otp"]),
        exportKey: requireAnyGrantEvidence(["passkey_assertion"]),
      },
    }),
    evmEcdsaMpcCapability({
      operationPolicies: {
        signTransaction: requireAnyGrantEvidence(["passkey_assertion", "email_otp"]),
        exportKey: requireAnyGrantEvidence(["passkey_assertion"]),
      },
    }),
  ],
});
```

Browser SDK runtime selection:

```ts
import {
  createSeamsConfig,
  hostedWalletIframe,
  passkeyAuth,
  nearEd25519MpcSigning,
  evmFamilyEcdsaMpcSigning,
} from "@seams/sdk";

const config = createSeamsConfig({
  environmentId: "env_...",
  publishableKey: "pk_...",
  walletRuntime: hostedWalletIframe({
    origin: "https://wallet.seams.sh",
    rpId: "example.com",
  }),
  authMethods: [
    passkeyAuth(),
  ],
  capabilities: [
    nearEd25519MpcSigning(),
    evmFamilyEcdsaMpcSigning(),
  ],
});
```

The browser runtime surface is SDK configuration, independent of Vite, Next, and
framework build hooks. `hostedWalletIframe(...)` selects the runtime that owns
wallet UI, workers, and WASM. Browser capability builders such as
`nearEd25519MpcSigning()` and `evmFamilyEcdsaMpcSigning()` declare that they need
that runtime in browser builds. Passkeys and Email OTP are auth factors; they do
not belong in wallet runtime config.

Browser config only selects SDK modules and UI/runtime loading. Server tenant
runtime config is authoritative for enabled auth factors, capabilities, and
policies:

```ts
type TenantRuntimeConfig = {
  tenantId: TenantId;
  authMethods: readonly AuthFactorKind[];
  capabilities: readonly CapabilityKind[];
  policies: readonly CapabilityPolicyRef[];
};
```

`publishableKey` and `environmentId` are public lookup inputs. Session exchange
and capability initialization resolve them through the server tenant-runtime
config boundary into `tenantId`, `projectId`, and `environmentId`, then core
logic receives only the normalized IDs. A publishable key that resolves to a
different tenant or environment than the request body fails before session
creation or capability initialization.

Auth-only applications can omit the wallet runtime:

```ts
const config = createSeamsConfig({
  environmentId: "env_...",
  publishableKey: "pk_...",
  authMethods: [passkeyAuth()],
});
```

Target normalized browser shape:

```ts
type BrowserWalletRuntimeSelection =
  | { kind: "none" }
  | {
      kind: "hosted_wallet_iframe";
      origin: WalletOrigin;
      servicePath: WalletServicePath;
      sdkBasePath: WalletSdkBasePath;
      rpId?: WebAuthnRpId;
      walletHostVariant: WalletHostVariant;
    };

type BrowserCapabilitySelection = {
  capabilityKind: Extract<
    CapabilityKind,
    "near_ed25519_mpc_signing" | "evm_ecdsa_mpc_signing"
  >;
  walletRuntime: "hosted_wallet_iframe";
};

type BrowserAuthFactorSelection = {
  factorKind: Extract<AuthFactorKind, "passkey" | "email_otp">;
};
```

Rules:

- Parse raw config inputs once in `createSeamsConfig(...)`.
- Allow at most one wallet runtime selection.
- Reject duplicate auth factor kinds and duplicate capability kinds.
- Reject browser MPC signing capabilities unless `hostedWalletIframe(...)` is
  present.
- Keep passkey auth independent from wallet iframe when the application only
  needs auth.
- Keep passkey and OTP in `authMethods`, not wallet runtime config.
- Keep wallet static asset delivery in
  [Refactor 86](./refactor-86-static-wallet-assets.md). This spec owns the SDK
  runtime selection shape.

Low-level auth factor modules remain available for internal package assembly and
tests:

```ts
const auth = seamsAuth({
  database: d1Adapter(env.SIGNER_DB),
  authMethods: [
    passkeyFactor(),
    emailOtpFactor(),
    slackOtpFactor(),
  ],
});
```

Better Auth provider:

```ts
const seamsGrantEvidenceBridge = createSeamsGrantEvidenceBridge();

const auth = betterAuth({
  database: prismaAdapter(prisma),
  plugins: [
    passkey(),
    emailOTP(),
    organization(),
    apiKey(),
    seamsPasskeyGrantEvidence({
      grantEvidenceBridge: seamsGrantEvidenceBridge,
    }),
  ],
});

const seams = createSeamsAuthorization({
  sessionProvider: betterAuthSessionProvider(auth),
  grantEvidenceBridge: seamsGrantEvidenceBridge,
  capabilities: [
    vaultAccessCapability(),
    nearEd25519MpcCapability(),
    evmEcdsaMpcCapability(),
  ],
});
```

The embedded defaults should be conservative:

| Capability operation | Default capability grant policy |
| --- | --- |
| Vault proxy use | active session plus RBAC, or service-account API-key evidence plus an explicit proxy-use policy |
| Vault reveal | passkey assertion, Email OTP, or Slack OTP evidence |
| Vault export | passkey assertion evidence |
| Vault rotation | passkey assertion evidence, or service-account API-key evidence plus an explicit rotation policy |
| Vault permission change | passkey assertion evidence |
| Vault break-glass reveal | approval plus passkey assertion evidence |
| MPC transaction signing (`near.sign_transaction`, `evm.sign_transaction`) | passkey assertion or Email OTP evidence |
| MPC signer-proof production (`mpc.produce_signer_proof`) | inherited signer capability grant policy |
| Vault export with high-assurance policy | passkey assertion plus MPC signer proof evidence |

Tenant policy can make defaults stricter. It should not silently weaken the
compiled capability defaults.

## Target Domain Types

Amended July 3, 2026: capability kinds and operation kinds are closed unions in
a leaf module (`authorization/capabilityKinds`) that both `seams-authorization`
and capability modules import. Capability packages still register operation
descriptors and handlers at app assembly time, keyed by these closed kinds, but
the kind vocabulary itself is compile-time closed and exhaustiveness-checked.
There is no runtime kind registry. If third-party capability extensibility ever
becomes real, reopen via module augmentation or a generic parameter then.

```ts
type CapabilityKind =
  | "vault_access"
  | "near_ed25519_mpc_signing"
  | "evm_ecdsa_mpc_signing";

type CapabilityOperationKind =
  | "vault.proxy_use"
  | "vault.reveal"
  | "vault.export"
  | "vault.rotate"
  | "vault.permission_change"
  | "vault.break_glass_reveal"
  | "near.sign_transaction"
  | "evm.sign_transaction"
  | "mpc.produce_signer_proof";

type RecordStatus = "active" | "suspended" | "deleted";

type OperationDigestSet = {
  laneDigest: DigestB64u;
  intentDigest: DigestB64u;
  displayDigest: DigestB64u;
};

type AuthAccount = {
  tenantId: TenantId;
  principalId: PrincipalId;
  status: RecordStatus;
  recoveryPolicyId: RecoveryPolicyId;
  createdAt: IsoTimestamp;
};

type AuthFactor =
  | { kind: "passkey"; tenantId: TenantId; principalId: PrincipalId; credentialId: PasskeyCredentialId }
  | { kind: "email_otp"; tenantId: TenantId; principalId: PrincipalId; provider: EmailOtpProvider; providerUserId: EmailOtpProviderUserId }
  | { kind: "slack_otp"; tenantId: TenantId; principalId: PrincipalId; slackTeamId: SlackTeamId; slackUserId: SlackUserId }
  | { kind: "wallet_login"; tenantId: TenantId; principalId: PrincipalId; walletAccountId: EmbeddedWalletAccountId }
  | { kind: "recovery_code"; tenantId: TenantId; principalId: PrincipalId; recoverySetId: RecoverySetId };

type AuthFactorKind = AuthFactor["kind"];

type ProviderSessionEvidenceKind = "oidc_session";

type ProviderAssuranceEvidenceKind =
  | "provider_mfa"
  | "provider_phishing_resistant"
  | "provider_device_trust";

type ProviderEvidenceKind =
  | ProviderSessionEvidenceKind
  | ProviderAssuranceEvidenceKind;

type SessionEvidenceKind =
  | AuthFactorKind
  | ProviderEvidenceKind;

type InteractiveGrantEvidenceKind =
  | "passkey_assertion"
  | "email_otp"
  | "slack_otp"
  | "wallet_login";

type SessionGrantEvidenceKind = "seams_session";
type ServiceAccountGrantEvidenceKind = "service_account_api_key";
type ApprovalGrantEvidenceKind = "approval_decision";
type MpcGrantEvidenceKind = "mpc_signer_proof";

type GrantEvidenceKind =
  | SessionGrantEvidenceKind
  | InteractiveGrantEvidenceKind
  | ProviderEvidenceKind
  | ServiceAccountGrantEvidenceKind
  | ApprovalGrantEvidenceKind
  | MpcGrantEvidenceKind;

type AssuranceLevel =
  | "session"
  | "interactive_assertion"
  | "provider_mfa"
  | "phishing_resistant"
  | "high_assurance";

type SessionEvidenceBase = {
  tenantId: TenantId;
  principalId: PrincipalId;
  evidenceDigest: DigestB64u;
  assertedAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
};

type SessionEvidenceRef =
  | (SessionEvidenceBase & {
      kind: "auth_factor_evidence";
      factorId: AuthFactorId;
      evidenceKind: AuthFactorKind;
    })
  | (SessionEvidenceBase & {
      kind: "provider_session_evidence";
      providerId: AuthProviderId;
      evidenceKind: ProviderSessionEvidenceKind;
    })
  | (SessionEvidenceBase & {
      kind: "provider_assurance_evidence";
      providerId: AuthProviderId;
      evidenceKind: ProviderAssuranceEvidenceKind;
    });

type AuthTenant = {
  tenantId: TenantId;
  status: RecordStatus;
  displayName: string;
  createdAt: IsoTimestamp;
};

type NonHumanPrincipalKind = "agent" | "service_account" | "system";

type AuthPrincipal =
  | {
      kind: "human";
      tenantId: TenantId;
      principalId: PrincipalId;
      email: EmailAddress;
      displayName: string;
      status: RecordStatus;
    }
  | {
      kind: NonHumanPrincipalKind;
      tenantId: TenantId;
      principalId: PrincipalId;
      displayName: string;
      status: RecordStatus;
    };

type PrincipalKind = AuthPrincipal["kind"];

type AuthFactorModule = {
  factorKind: AuthFactorKind;
  schema: AuthFactorSchema;
  routes: AuthRoute[];
  clientModule: LazyClientModule;
};

type TenantAuthFactorEnablement = {
  tenantId: TenantId;
  factorKind: AuthFactorKind;
  configDigest: DigestB64u;
  status: RecordStatus;
};

type AuthProvider =
  | {
      kind: "seams_auth_provider";
      tenantId: TenantId;
      providerId: AuthProviderId;
      evidenceKinds: NonEmptyArray<SessionEvidenceKind>;
    }
  | {
      kind: "better_auth_provider";
      tenantId: TenantId;
      providerId: AuthProviderId;
      evidenceKinds: NonEmptyArray<SessionEvidenceKind>;
      betterAuthInstanceId: ExternalAuthInstanceId;
    }
  | {
      kind: "external_oidc_provider";
      providerId: AuthProviderId;
      evidenceKinds: NonEmptyArray<SessionEvidenceKind>;
      issuer: OidcIssuer;
      tenantId: TenantId;
      claimMapping: SsoClaimMapping;
    };

type SessionProviderEvidence =
  {
    kind: "provider_session";
    providerId: AuthProviderId;
    tenantId: TenantId;
    principalId: PrincipalId;
    externalSessionId: ExternalSessionId;
    sessionSubject: ExternalSessionSubject;
    sessionEvidence: NonEmptyArray<SessionEvidenceRef>;
    assuranceLevel: AssuranceLevel;
    deviceId: DeviceId;
    evidenceDigest: DigestB64u;
    expiresAt: IsoTimestamp;
  };

type MpcCapabilityKind = Extract<
  CapabilityKind,
  "near_ed25519_mpc_signing" | "evm_ecdsa_mpc_signing"
>;

type MpcSignerProof = {
  signerKind: MpcCapabilityKind;
  tenantId: TenantId;
  principalId: PrincipalId;
  sessionId: SeamsSessionId;
  signerCapabilityId: CapabilityId;
  inheritedPolicyId: PolicyId;
  challengeDigest: DigestB64u;
  operationDigests: OperationDigestSet;
  proofDigest: DigestB64u;
  deviceId: DeviceId;
  expiresAt: IsoTimestamp;
};

type IdpRelyingParty = {
  tenantId: TenantId;
  relyingPartyId: IdpRelyingPartyId;
  clientId: OidcClientId;
  displayName: string;
  redirectUris: NonEmptyArray<HttpsUrl>;
  allowedScopes: NonEmptyArray<OidcScope>;
  claimPolicyId: ClaimPolicyId;
  tokenPolicyId: TokenPolicyId;
  status: RecordStatus;
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

// Public opaque handle. In bearer-token delivery it wraps the access token and
// resolves server-side to a SeamsSessionId. In browser-cookie delivery it is an
// SDK-local handle to the HttpOnly cookie plus CSRF binding metadata; the SDK
// never reads the session token.
type SeamsSession = Brand<string, "SeamsSession">;

type SeamsSessionState =
  | { kind: "active"; expiresAt: IsoTimestamp }
  | { kind: "revoked"; revokedAt: IsoTimestamp }
  | { kind: "expired"; expiredAt: IsoTimestamp };

type SeamsSessionRecord = {
  tenantId: TenantId;
  principalId: PrincipalId;
  sessionId: SeamsSessionId;
  providerId: AuthProviderId;
  sessionEvidence: NonEmptyArray<SessionEvidenceRef>;
  assuranceLevel: AssuranceLevel;
  deviceId: DeviceId;
  state: SeamsSessionState;
};

type ActiveSeamsSessionRecord = SeamsSessionRecord & {
  state: Extract<SeamsSessionState, { kind: "active" }>;
};

type GrantEvidenceBase = {
  tenantId: TenantId;
  principalId: PrincipalId;
  evidenceKind: GrantEvidenceKind;
  evidenceDigest: DigestB64u;
  assertedAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
};

type GrantEvidenceRef =
  | (GrantEvidenceBase & {
      kind: "session_grant_evidence";
      evidenceKind: SessionGrantEvidenceKind;
      sessionId: SeamsSessionId;
    })
  | (GrantEvidenceBase & {
      kind: "interactive_challenge_grant_evidence";
      evidenceKind: InteractiveGrantEvidenceKind;
      sessionId: SeamsSessionId;
      challengeId: GrantChallengeId;
      operationDigests: OperationDigestSet;
      deviceId: DeviceId;
    })
  | (GrantEvidenceBase & {
      kind: "provider_assurance_grant_evidence";
      evidenceKind: ProviderEvidenceKind;
      sessionId: SeamsSessionId;
      providerId: AuthProviderId;
    })
  | (GrantEvidenceBase & {
      kind: "mpc_signer_grant_evidence";
      evidenceKind: MpcGrantEvidenceKind;
      sessionId: SeamsSessionId;
      signerKind: MpcCapabilityKind;
      signerCapabilityId: CapabilityId;
      inheritedPolicyId: PolicyId;
      challengeDigest: DigestB64u;
      operationDigests: OperationDigestSet;
      proofDigest: DigestB64u;
    })
  | (GrantEvidenceBase & {
      kind: "service_account_api_key_grant_evidence";
      evidenceKind: ServiceAccountGrantEvidenceKind;
      apiCredentialId: ApiCredentialId;
      apiScopeDigest: DigestB64u;
    })
  | (GrantEvidenceBase & {
      kind: "approval_decision_grant_evidence";
      evidenceKind: ApprovalGrantEvidenceKind;
      approvalId: ApprovalId;
      operationDigests: OperationDigestSet;
    });

type CapabilityGrantRequest = {
  tenantId: TenantId;
  principalId: PrincipalId;
  principalKind: PrincipalKind;
  evidence: NonEmptyArray<GrantEvidenceRef>;
  assuranceLevel: AssuranceLevel;
  evidenceSetDigest: DigestB64u;
};

type GrantEvidenceRequirement =
  | {
      kind: "any_of";
      evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
    }
  | {
      kind: "all_of";
      evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
    };

type CapabilityGrantPolicy = {
  tenantId: TenantId;
  policyId: PolicyId;
  capabilityKind: CapabilityKind;
  operationKind: CapabilityOperationKind;
  allowedPrincipalKinds: NonEmptyArray<PrincipalKind>;
  allowedBindingKinds: NonEmptyArray<CapabilityBindingKind>;
  requiredEvidence: NonEmptyArray<GrantEvidenceRequirement>;
  minAssuranceLevel: AssuranceLevel;
  maxTtlSeconds: PositiveInt;
  maxUses: PositiveInt;
};

type CapabilityOperationGrantPolicyBinding = {
  tenantId: TenantId;
  capabilityId: CapabilityId;
  capabilityKind: CapabilityKind;
  operationKind: CapabilityOperationKind;
  policyId: PolicyId;
};
```

### MPC Signer Proof As Grant Evidence

`mpc_signer_proof` is derived grant evidence backed by an enabled MPC capability.
It is stronger than ordinary app-session auth because the proof can bind user
presence, registered device state, threshold participation, and a typed Seams
lane/intent/display digest set.

The proof inherits the capability grant policy of the signer capability operation that
produces it:

```text
MPC capability mpc.produce_signer_proof policy
  -> passkey assertion, Email OTP, or tenant-defined native digest-bound evidence
  -> MPC signer signs typed Seams auth challenge
  -> MpcSignerProof
  -> mpc_signer_proof grant evidence
```

This is a Seams-specific high-assurance primitive. Better Auth can provide the
session and standard auth factors that feed grant evidence, while Seams
authorization owns the MPC proof challenge, digest binding, capability lookup,
threshold signing path, and capability grant.

Evaluation rules:

- capability grant policies that require `mpc_signer_proof` evidence must name or
  resolve an MPC signer capability;
- the signer capability must exist, be active, and have a valid
  `CapabilityBinding` for the requesting principal;
- the signer capability must support `mpc.produce_signer_proof`;
- the `mpc.produce_signer_proof` operation runs the signer capability's inherited
  capability grant policy;
- the proof challenge must bind tenant, principal, session, signer capability,
  target operation, lane digest, intent digest, display digest, device ID,
  nonce, and expiry;
- missing or inactive MPC capability returns `capability_not_enabled` or
  `capability_not_active`;
- no fallback to passkey, OTP, or session auth occurs unless the policy defines
  an explicit alternative branch;
- `mpc_signer_proof` cannot authorize producing another proof for the same
  signer by default.

Capabilities are resource-scoped. Principals gain access through explicit
bindings:

```ts
type ResourceScope =
  | {
      kind: "tenant";
      tenantId: TenantId;
    }
  | {
      kind: "project";
      tenantId: TenantId;
      projectId: ProjectId;
    }
  | {
      kind: "environment";
      tenantId: TenantId;
      projectId: ProjectId;
      environmentId: EnvironmentId;
    };

type CapabilityInstance = {
  tenantId: TenantId;
  capabilityId: CapabilityId;
  capabilityKind: CapabilityKind;
  resourceScope: ResourceScope;
  defaultPolicyId: PolicyId;
  configDigest: DigestB64u;
  status: RecordStatus;
};

type CapabilityBindingKind = "owner" | "admin" | "direct_member" | "delegate_member";

type CapabilityBinding = {
  tenantId: TenantId;
  bindingId: CapabilityBindingId;
  capabilityId: CapabilityId;
  principalId: PrincipalId;
  bindingKind: CapabilityBindingKind;
  status: RecordStatus;
};
```

Capability modules own rich operation lane, intent, and display types. They
normalize parsed requests into a generic envelope before asking
`seams-authorization` for a grant. Requests never carry `CapabilityGrantPolicy`;
authorization resolves the policy server-side and records the selected
`policyId`.

```ts
type CapabilityOperationEnvelope = {
  tenantId: TenantId;
  principalId: PrincipalId;
  capabilityKind: CapabilityKind;
  capabilityId: CapabilityId;
  operationKind: CapabilityOperationKind;
  operationDigests: OperationDigestSet;
};

type CapabilityGrantRecord = {
  tenantId: TenantId;
  requester: CapabilityGrantRequest;
  grantId: CapabilityGrantId;
  capabilityKind: CapabilityKind;
  capabilityId: CapabilityId;
  operationKind: CapabilityOperationKind;
  operationDigests: OperationDigestSet;
  policyId: PolicyId;
};

type CapabilityGrant =
  | (CapabilityGrantRecord & {
      kind: "active";
      remainingUses: PositiveInt;
      expiresAt: IsoTimestamp;
    })
  | (CapabilityGrantRecord & {
      kind: "consumed";
      consumedAt: IsoTimestamp;
    })
  | (CapabilityGrantRecord & {
      kind: "expired";
      expiredAt: IsoTimestamp;
    });

type MpcSignerProofFailure =
  | {
      kind: "capability_not_enabled";
      tenantId: TenantId;
      principalId: PrincipalId;
      capabilityKind: CapabilityKind;
    }
  | {
      kind: "capability_not_active";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
    }
  | {
      kind: "capability_binding_missing";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
    }
  | {
      kind: "operation_not_supported";
      tenantId: TenantId;
      principalId: PrincipalId;
      signerCapabilityId: CapabilityId;
      operationKind: "mpc.produce_signer_proof";
    };
```

Grant-use consumption is one-way. Handlers must complete cheap boundary parsing,
route policy checks, capability lookup, and replay checks before consuming a
use. Once the operation crosses the consume boundary, a later vault, network,
signing, or downstream failure records a failed `capability_grant_uses` row and
does not refund the use. Retrying a failed operation requires a remaining use on
the same grant or a fresh grant. This is the intentional replacement for the old
signing-budget reserve/commit/release lifecycle.

`capability_grant_uses.result_kind` distinguishes at least `succeeded`,
`failed_before_side_effect`, `failed_after_side_effect`, and `denied_replay` so
operators can audit failed consumed attempts without reconstructing them from
logs.

## Capability Boundaries

### `seams-authorization`

Owns:

- principals and auth accounts;
- auth factors;
- auth factor module registration;
- `SeamsSession`;
- grant evidence challenge selection;
- capability grant policies;
- generic operation envelopes;
- policy resolution from capability ID, operation kind, resource scope,
  principal binding, and grant evidence;
- short-lived capability grants;
- replay and grant-use accounting;
- audit envelopes;
- auth provider evidence parsing.

Does not own:

- Better Auth storage schema;
- Better Auth route handlers;
- capability-local operation lane, intent, or display structs;
- capability-local display rendering;
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
- `VaultAccessScope`;
- `VaultAccessPayload`;
- vault digest, display, and policy descriptors registered with
  `seams-authorization`;
- Secret Broker and Egress Gateway adapter contracts;
- a minimal local Worker-compatible broker/gateway adapter for Slice A
  proxy-use tests;
- reveal, rotate, delegate, and proxy-only use policies;
- capability-local default capability grant policy config.

Uses `seams-authorization` for:

- auth session checks;
- grant evidence verification;
- capability grant minting;
- server-side policy resolution;
- audit envelope generation.

Slice A requires `vault.proxy_use` to execute against the minimal local
broker/gateway adapter. Production Secret Broker and Egress Gateway Workers,
including the separate service-bound deployment split from
[centaur-secrets-vault.md](./centaur-secrets-vault.md), remain capability-vault
work after the grant model is proven.

### `capability-near-ed25519-mpc`

Owns:

- NEAR Ed25519 signer identity;
- Ed25519 threshold signing operation lanes;
- NEAR transaction and NEP-413 display semantics;
- Ed25519 signing runtime material;
- Ed25519 export behavior where supported;
- NEAR digest, display, and policy descriptors registered with
  `seams-authorization`;
- capability-local default capability grant policy config.

Uses `seams-authorization` for session, grant evidence, grant-use limits, grants, and
audit.

### `capability-evm-ecdsa-mpc`

Owns:

- EVM-family ECDSA signer identity;
- `ThresholdEcdsaChainTarget`;
- ECDSA threshold-session runtime;
- HSS prepare/finalize;
- signer WASM loading;
- ECDSA key export;
- EVM-family transaction display and nonce/grant-use coupling;
- EVM digest, display, and policy descriptors registered with
  `seams-authorization`;
- capability-local default capability grant policy config.

Uses `seams-authorization` for session, grant evidence, grant-use limits, grants, and
audit.

## Lazy Loading Rules

Registration:

- Always create `AuthAccount`.
- Register auth providers and auth factor modules per tenant.
- Register IdP relying-party applications only for tenants with IdP mode
  enabled.
- Create only requested `CapabilityInstance` records.
- Vault-only registration creates no Ed25519 or ECDSA signer records.
- Wallet registration creates signer capabilities explicitly.
- Capability provisioning validates that every referenced grant evidence kind is
  registered or resolvable through the selected provider.

Frontend:

- Load auth UI for every account.
- Load auth provider UI by registered tenant auth factor and grant evidence kind.
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

Source boundaries:

```text
authFactor/
  passkey
  emailOtp
  slackOtp
  walletLogin
  recoveryCode
session/
  seamsSession
  providerSessionAdapters
authorization/
  capabilityKinds
  grantEvidence
  capabilityGrants
  policies
  audit
capability/
  vault
  nearEd25519Mpc
  evmEcdsaMpc
idp/
  oidcProvider
  relyingParties
router/
  routeModules
  cloudflareAdapter
  nodeAdapter
  (expressAdapter)
sdkWeb/
  config
  walletRuntime/hostedIframe
  authFactorUi
  capabilityUi
```

Internal module/folder names are authoritative for this refactor. Package names
such as `seams-auth-idp` and `capability-vault` are future extraction labels
until these boundaries are stable.

`session/` owns `SeamsSession` and provider session normalization.

`authFactor/` owns first-party auth factor modules such as passkey, Email OTP,
Slack OTP, wallet login, and recovery codes.

`authorization/` owns grant evidence, grant domain, policy evaluators, and audit
envelope builders.

`session/providerSessionAdapters/betterAuth` owns Better Auth adapters that convert
Better Auth sessions and operation-bound assertions into Seams grant evidence.

`idp/` owns optional IdP endpoints, relying-party registration, OIDC
Provider metadata, authorization-code issuance, token issuance, refresh-token
rotation, JWKS publication, and SAML IdP support if it is added.

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
  factor_kind,          -- passkey | email_otp | slack_otp | wallet_login | recovery_code
  factor_ref_json,      -- email_otp stores provider + providerUserId; email is display/profile metadata
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
  provider_kind,        -- seams_auth | better_auth | oidc | wallet
  lifecycle_kind,
  evidence_kinds_json,
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
  session_evidence_digest,
  lifecycle_kind,       -- active | revoked | expired
  created_at_ms,
  expires_at_ms,
  revoked_at_ms
)

seams_session_evidence(
  namespace,
  tenant_id,
  evidence_id,
  session_id,
  principal_id,
  evidence_kind,
  evidence_source_kind, -- auth_factor | provider_session | provider_assurance
  evidence_ref_id,
  evidence_digest,
  asserted_at_ms,
  expires_at_ms
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

grant_challenges(
  namespace,
  tenant_id,
  challenge_id,
  session_id,
  principal_id,
  grant_evidence_kinds_json,
  capability_kind,
  operation_kind,
  lane_digest,
  intent_digest,
  display_digest,
  challenge_digest,
  lifecycle_kind,       -- issued | verified | expired | revoked
  created_at_ms,
  expires_at_ms,
  verified_at_ms
)

grant_evidence(
  namespace,
  tenant_id,
  evidence_id,
  challenge_id,
  session_id,
  principal_id,
  principal_kind,
  evidence_kind,
  evidence_ref_kind,    -- session | auth_factor | provider | mpc_signer | api_credential | approval | external_workload
  evidence_ref_id,
  api_credential_id,
  approval_id,
  lane_digest,
  intent_digest,
  display_digest,
  evidence_digest,
  assurance_level,
  device_id,
  lifecycle_kind,       -- active | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms
)

capability_grant_policies(
  namespace,
  tenant_id,
  policy_id,
  capability_kind,
  operation_kind,
  policy_kind,          -- capability_grant_policy
  policy_json,
  lifecycle_kind,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

capability_instances(
  namespace,
  tenant_id,
  capability_id,
  capability_kind,      -- registered kind, e.g. vault_access or near_ed25519_mpc_signing
  resource_scope_kind,  -- tenant | project | environment
  project_id,
  environment_id,
  lifecycle_kind,
  default_policy_id,
  config_digest,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

capability_operation_grant_policy_bindings(
  namespace,
  tenant_id,
  capability_id,
  capability_kind,
  operation_kind,
  policy_id,
  lifecycle_kind,
  created_by_principal_id,
  created_at_ms,
  updated_at_ms
)

capability_bindings(
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

capability_grants(
  namespace,
  tenant_id,
  grant_id,
  grant_token_hash,
  principal_id,
  principal_kind,
  evidence_set_digest,
  capability_kind,
  capability_id,
  operation_kind,
  lane_digest,
  intent_digest,
  display_digest,
  policy_id,
  remaining_uses,
  lifecycle_kind,       -- active | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms
)

capability_grant_uses(
  namespace,
  tenant_id,
  use_id,
  grant_id,
  principal_id,
  evidence_set_digest,
  capability_id,
  operation_kind,
  result_kind,
  lane_digest,
  intent_digest,
  display_digest,
  created_at_ms
)

authorization_audit_events(
  namespace,
  tenant_id,
  event_id,
  principal_id,
  actor_principal_kind,
  session_id,
  device_id,
  capability_id,
  operation_kind,
  lane_digest,
  intent_digest,
  display_digest,
  evidence_kinds_json,
  result_kind,
  event_digest,
  created_at_ms
)
```

Retention and abuse controls:

- A1 adds expiry indexes for challenges, evidence rows, refresh tokens, and
  capability grants.
- A3 owns a pruning job interface for expired grant challenges, expired or
  consumed grant evidence, expired grants, revoked refresh-token families after
  the retention window, and old audit-export scratch rows.
- A2 and A6 add rate-limit ports for session exchange, OTP challenge minting,
  WebAuthn grant-evidence challenge minting, and verification attempts. A7 adds
  the same controls for service-account grant requests.
- Default adapters must expose a D1-compatible scheduled cleanup path; hosts can
  wire it to Cloudflare cron, a Node scheduler, or an explicit admin task.

IdP tables stay with the `idp/` module:

```text
idp_relying_parties(...)
idp_signing_keys(...)
idp_authorization_codes(...)
idp_refresh_tokens(...)
idp_token_events(...)
```

Vault tables stay with the `capability/vault` module:

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

Capability grant policies define which auth factors can authorize each capability
operation.

Capability grants authorize one exact capability operation.

Vault access default:

```text
SeamsSession + capability grant policy + RBAC + short-lived grant + audit
```

MPC signing default:

```text
SeamsSession + capability grant policy + MPC operation lane + threshold signing runtime
```

IdP token issuance default:

```text
SeamsSession + relying-party policy + claim policy + signed identity token + audit
```

High-assurance vault mode can require `mpc_signer_proof` when the tenant has an
MPC capability. Preventing unilateral server decrypt still depends on key
custody, such as customer KMS or sidecar unwrap.
