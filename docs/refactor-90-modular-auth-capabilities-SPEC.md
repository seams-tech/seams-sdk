# Modular Auth And Capability Refactor SPEC

Date created: June 28, 2026
Architecture hardening: July 10, 2026
MPC preparation generalization: July 10, 2026
MPC lifecycle convergence: July 16, 2026
ECDSA state and persistence convergence: July 18, 2026

Status: planning.

Companion doc: [Implementation plan](./refactor-90-modular-auth-capabilities-plan.md).

Scope amendment: July 22, 2026 — the implementation plan was reduced to the
minimal authorization proving slice and the two current MPC capabilities.
Service accounts, Better Auth, IdP functionality, Slack OTP evidence, full vault
product workflows, general route-module registries, and speculative package
splits are follow-on work. Sections that describe those future product shapes
are design context rather than Refactor 90 acceptance criteria.

## Normative Invariant Index

The implementation plan cites these IDs instead of restating their full rules.
Code, boundary parsers, and tests remain the executable expression of each
invariant.

- **R90-INV-001 — Boundary normalization.** Raw request, persistence, token,
  worker, and UI data is validated once at its owning boundary. Core functions
  accept only precise internal states.
- **R90-INV-002 — Canonical material ownership.** Each MPC protocol has one
  durable material owner and one volatile runtime owner. Registration, unlock,
  refresh, recovery, signing, and export cannot publish parallel active records.
- **R90-INV-003 — Entry-point-neutral hydration.** Registration, wallet unlock,
  and page refresh are provenance only. Canonical state selects
  `use_live_runtime`, `rehydrate_active_session`,
  `reauthorize_public_anchor`, or `blocked`.
- **R90-INV-004 — Recovery server idempotency.** Every consuming recovery call
  is independently idempotent and queryable by exact `recoveryId`. A reload from
  a prepared journal queries server state before retrying or finalizing an
  effect.
- **R90-INV-005 — Atomic local finalization.** The final IndexedDB transaction
  writes replacement material and lifecycle facts, retires or removes the old
  source, and deletes the recovery or activation journal atomically. Journal
  absence is terminal only after that transaction commits.
- **R90-INV-006 — Durable facts only.** Journals contain server uncertainty and
  receipts required for local durable convergence. Runtime publication, handle
  disposal, candidate disposal, and zeroization are process-local worker facts
  and are never journal states.
- **R90-INV-007 — Cancellation does not resurrect work.** A prepared recovery
  records `continue | cancel_requested`. Reload reconciles a cancellation and
  never silently resumes the abandoned parent operation.
- **R90-INV-008 — Exact material serialization.** One queue serializes material
  use per exact owner and checks the current generation/fence. There is no
  public affine lease-token lifecycle.
- **R90-INV-009 — Exact operation claim.** The stable operation fingerprint
  excludes rotating authorization, quota, session, and runtime identities. One
  absent-claim transaction consumes the exact grant and applicable quota and
  creates the claim and audit linkage. Operation descriptors declare quota
  applicability: normal signing consumes one wallet-quota use beside its grant;
  key export declares no quota use and consumes only its exact grant. Quota
  exhaustion never blocks export, and export never spends signing quota.
- **R90-INV-010 — Supersession invalidates preparation.** Authority or lifecycle
  replacement returns `superseded`; callers discard the prepared lane and
  resolve current canonical state again.
- **R90-INV-011 — Readback is verification, not lifecycle.** A high-value local
  commit may be read immediately through the canonical parser after transaction
  completion. Readback never creates a durable pending state.
- **R90-INV-012 — Enforcement matches failure mode.** Types reject invalid core
  construction, boundary tests reject hostile raw data, guards enforce
  dependency/artifact boundaries, integration tests prove cross-store effects,
  and E2E tests prove selected user-visible transitions.

## Phased Invariant Verification Checklist

This checklist tracks conformance evidence for the normative invariants. The
implementation plan owns task status. Check an item here only when the invariant
is expressed in code and its cheapest effective verification passes; link the
evidence from the progress journal.

### Foundations A-B

- [ ] `R90-INV-001` — hydration and ECDSA persistence boundaries parse raw
  records once and expose only precise internal branches.
- [ ] `R90-INV-002` — Near and ECDSA each have one durable material owner and one
  volatile runtime owner.
- [ ] `R90-INV-003` — registration, unlock, and refresh equivalence tests select
  the same hydration outcome from equivalent canonical observations.
- [ ] `R90-INV-005` — ECDSA activation finalization atomically writes material,
  manifest, replacement retirement, and journal deletion.
- [ ] `R90-INV-006` — ECDSA journal types contain no runtime-publication,
  disposal, zeroization, or other volatile facts.
- [ ] `R90-INV-011` — ECDSA post-commit verification creates no durable
  readback/publication state.
- [ ] `R90-INV-012` — Foundation type fixtures, parser tests, persistence tests,
  and generic-module guards each cover their assigned failure mode once.

### Slice A — authorization proving vertical

- [ ] `R90-INV-001` — session, evidence, grant, claim, vault, and audit requests
  and rows normalize at their owning boundaries.
- [ ] `R90-INV-009` — the minimal vault operation uses a stable fingerprint and
  one atomic absent-claim grant-use transaction.
- [ ] `R90-INV-012` — the real minimal vault vertical proves session → Passkey
  evidence → grant → operation → audit without future-provider scaffolding.

### Slice B — MPC migration

- [ ] `R90-INV-002` — registration, unlock, refresh, recovery, signing, and
  export cannot publish or select a parallel active material record.
- [ ] `R90-INV-003` — both MPC modules use the canonical hydration outcomes and
  contain no entry-point-selected material branch.
- [ ] `R90-INV-004` — Near admission, acquisition, and promotion are independently
  idempotent and queryable by exact recovery ID, including injected crash cases.
- [ ] `R90-INV-005` — Near finalization atomically swaps or retires material,
  persists lifecycle facts, and deletes the journal.
- [ ] `R90-INV-006` — Near durable journals contain only server uncertainty and
  the promotion receipt required for local convergence.
- [ ] `R90-INV-007` — cancel/crash/reload tests prove `cancel_requested` never
  resumes the abandoned parent operation.
- [ ] `R90-INV-008` — concurrent recovery, signing, refresh, and export serialize
  by exact owner and reject stale generations/fences.
- [ ] `R90-INV-009` — MPC absent-claim transactions consume the exact grant and
  applicable quota once; existing claims consume neither again.
- [ ] `R90-INV-010` — authority/lifecycle replacement returns `superseded` and
  every SDK/UI adapter discards and re-resolves the stale lane.
- [ ] `R90-INV-011` — Near post-commit verification creates no durable readback
  stage.
- [ ] `R90-INV-012` — type, parser, guard, integration, concurrency, and E2E
  checks follow the one-enforcement-per-failure-mode rule.

### Final conformance

- [ ] Every invariant has implementation and validation evidence in the journal.
- [ ] No unchecked invariant is represented as complete in the implementation
  plan.
- [ ] Follow-on capability/provider designs extend the closed unions only when
  they enter implementation scope.

## Goal

Split the current signing-session architecture into a small shared auth/session
core plus optional protected capability modules.

The shared layer should gate capability operations for multiple capabilities:

- vault access;
- NEAR Ed25519 MPC signing;
- EVM-family ECDSA MPC signing;
- high-risk IdP scope issuance.

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

Split auth into four ownership layers:

1. Identity and auth-factor modules own principals, enrollments, and exact
   factor/provider verification.
2. The session module normalizes verified evidence into an audience- and
   device-bound `SeamsSession`.
3. Seams authorization evaluates verified evidence sets and capability grant
   policy, then mints exact capability grants.
4. Capability modules consume grants and own operation-specific side effects.

`seams-auth` is the built-in auth provider. Better Auth is a supported upstream
provider through `betterAuthSessionProvider(auth)`.

Rename the parent concept from `signing-session` to `SeamsSession`.

`identity/` owns principals and auth accounts, `authFactor/` owns enrollments,
and `session/` owns session state. Seams authorization owns grant evidence,
capability grants, grant-use limits, and audit envelopes.
MPC signing is a capability that uses this shared layer. Vault access is another
capability that uses the same shared layer.

```text
Auth account
  -> exact factor enrollment or provider identity
  -> SeamsSession
  -> VerifiedGrantEvidenceSet
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
  identity: SeamsIdentityPort;
  session: SeamsSessionPort;
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
| Tenants, principals, auth accounts, and provider identity links | identity module |
| Sessions, devices, audiences, and refresh families | session module |
| WebAuthn, Email OTP, Slack OTP, wallet login factors | auth factor modules |
| SSO claims and provider-session normalization | session module |
| IdP relying parties and token protocol state | IdP module |
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

- `AuthFactorIdentity` defines pure factor identity; `AuthFactorRecord` defines
  one durable enrollment.
- `SessionEvidenceKind` contains factor evidence plus provider session and
  provider assurance evidence.
- `GrantEvidenceKind` contains Seams-session evidence, operation-bound
  interactive evidence, provider assurance, service-account credentials,
  approvals, and MPC signer proofs.
- `ProviderSessionEvidenceKind` is deliberately excluded from
  `GrantEvidenceKind`.
- MPC signing policies accept only `passkey_assertion`, `email_otp`, or
  `mpc_signer_proof` unless an explicit future policy expansion is reviewed.

The canonical definitions live in [Target Domain Types](#target-domain-types);
this incompatibility section does not duplicate them.

Wallet-login evidence is session/auth-factor evidence. MPC signing policies
accept only digest-bound native grant evidence (`passkey_assertion`,
`email_otp`) or derived `mpc_signer_proof`; wallet-login evidence never gates
signing.

Provider login sessions always normalize into `SeamsSession` before grant
evaluation. `provider_session` is session evidence, not grant evidence.
Provider assurance can become grant evidence only through the
`provider_assurance_grant_evidence` branch after the provider adapter verifies
the assurance assertion and binds it to the active Seams session.

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
- compute wallet-session display state from the `SeamsSession` lifecycle and
  public wallet identity;
- surface missing, corrupt, or ambiguous durable identity as typed
  `unresolvable` results;
- keep provenance (`runtime_session_record`, `profile_projection`,
  `host_last_used_profile`) as diagnostics only;
- resolve every MPC capability independently through
  `MpcCapabilityHydrationPlan`. Sealed-active material, public reauthorization,
  expiry, exhaustion, and missing live runtime are capability states and never
  session/login display states.

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
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
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
  | { kind: "active"; subjectSet: WalletUnlockSubjectSet }
  | {
      kind: "unavailable";
      walletId: WalletId;
      reason: WalletIdentityResolveFailure;
    };
```

`WalletUnlockSubjectSet` is the only wallet/capability subject shape consumed
below the session-read boundary. NEAR account identity exists only on the
`near_ed25519_wallet` branch. ECDSA-only restoration must not import NEAR
account validators or fabricate a NEAR account subject. Auth-method display
must come from wallet-auth-method bindings or session evidence, never from
`publicKey` heuristics. `WalletSessionDisplayState` cannot authorize signing,
material recovery, or export. Those decisions consume the capability-local
hydration plan defined below.

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
      operation: CapabilityOperationRef;
      grantId: CapabilityGrantId;
      expiresAtMs: number;
      remainingUses: PositiveInt;
    }
  | {
      kind: "grant_evidence_required";
      tenantId: TenantId;
      principalId: PrincipalId;
      sessionId: SeamsSessionId;
      capabilityId: CapabilityId;
      operation: CapabilityOperationRef;
      evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
      operationDigests: OperationDigestSet;
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
- let deployment assembly choose the modules compiled into a host, then enforce
  tenant capability enablement inside the request boundary;
- mount IdP routes only when IdP mode is enabled;
- mount vault routes only when `vault_access` is enabled;
- mount MPC routes only when the relevant MPC capability is enabled;
- add import guards proving vault and IdP route modules do not import threshold,
  HSS, signer WASM, or chain modules.

Target module shape:

```ts
type RouterModuleOwner =
  | {
      kind: "platform";
      moduleKind: "seams_auth" | "session" | "management";
    }
  | {
      kind: "capability";
      capabilityKind: CapabilityKind;
    };

type RouterApiModuleManifest = {
  moduleId: RouterApiModuleId;
  owner: RouterModuleOwner;
  routeDefinitions: readonly RouterApiRouteDefinition[];
  requiredServices: readonly RouteServiceKey[];
  importGuard: RouterModuleImportGuard;
};

type RuntimeRouterApiModule<TRuntime extends RouteRuntimeKind> = {
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
  platformModules: ["seams_auth", "session", "management"],
  capabilityKinds: deploymentCapabilityKinds,
});

const router = createCloudflareRouter({
  services,
  modules,
});
```

Builder implementation target:

```ts
type CloudflareDeploymentModuleSelection = {
  platformModules: NonEmptyArray<"seams_auth" | "session" | "management">;
  capabilityKinds: readonly CapabilityKind[];
};

function buildCloudflareRouteModules(
  input: CloudflareDeploymentModuleSelection,
): RuntimeRouterApiModule<'cloudflare'>[] {
  return buildRuntimeModulesFromDeploymentSelection(input);
}
```

`CloudflareDeploymentModuleSelection` is deployment-scoped and is evaluated
once while assembling a Worker bundle. `TenantRuntimeConfig` is request-scoped
and can only disable a deployed capability for a tenant. Tenant configuration
never dynamically changes the route table or causes per-request imports. A
tenant request for an undeployed or disabled capability fails through the typed
capability-availability boundary before its handler runs.

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

`packages/console-shared-ts/src/apiKeyScopes.ts` is currently wallet-only:
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

> Follow-on context (July 22 scope amendment): service-account evidence is not a
> Refactor 90 acceptance surface.

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
      operation: CapabilityOperationRef;
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

> Partially follow-on (July 22 scope amendment): the provider-neutral session
> port is a Refactor 90 surface; Better Auth integration itself is follow-on
> work.

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

> Follow-on context (July 22 scope amendment): the Better Auth mounting bridge
> is not a Refactor 90 acceptance surface.

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
      kind: "provider_session";
      evidence: SessionProviderEvidence;
      requestContext: SessionExchangeRequestContext;
    }
  | {
      kind: "seams_factor_assertion";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorId: AuthFactorId;
      assertionDigest: DigestB64u;
      requestContext: SessionExchangeRequestContext;
    }
  | {
      kind: "wallet_login_proof";
      tenantId: TenantId;
      providerId: AuthProviderId;
      factorId: AuthFactorId;
      proofDigest: DigestB64u;
      requestContext: SessionExchangeRequestContext;
    }
  | {
      kind: "refresh";
      tenantId: TenantId;
      sessionId: SeamsSessionId;
      refreshTokenId: SessionRefreshTokenId;
      refreshTokenHash: DigestB64u;
      requestContext: SessionExchangeRequestContext;
    };

type SessionExchangeResult =
  | {
      kind: "created";
      session: ActiveSeamsSessionRecord;
      delivery: SessionDelivery;
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

type SessionDeviceClaim =
  | {
      kind: "new_device";
      registrationNonce: DeviceRegistrationNonce;
    }
  | {
      kind: "existing_device";
      deviceId: DeviceId;
      deviceCredentialDigest: DigestB64u;
    };

declare const sessionExchangeRequestContextBrand: unique symbol;

type SessionExchangeRequestContext = {
  readonly [sessionExchangeRequestContextBrand]: true;
  audience: SessionAudience;
  deviceClaim: SessionDeviceClaim;
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
      session: SeamsSession;
      accessTokenId: SessionAccessTokenId;
      refreshTokenId: SessionRefreshTokenId;
    }
  | {
      kind: "hosted_wallet_exchange_code";
      exchangeCode: HostedWalletSessionExchangeCode;
      appOrigin: HttpsOrigin;
      walletOrigin: WalletOrigin;
      nonce: HostedWalletSessionExchangeNonce;
      expiresAt: IsoTimestamp;
    };

type SessionExchangeFailure =
  | { kind: "provider_not_enabled"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "tenant_mismatch"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "subject_collision"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "jit_provisioning_denied"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "factor_disabled"; tenantId: TenantId; factorKind: AuthFactorKind }
  | { kind: "factor_identity_mismatch"; tenantId: TenantId; factorId: AuthFactorId }
  | { kind: "device_revoked"; tenantId: TenantId; deviceId: DeviceId }
  | { kind: "origin_mismatch"; tenantId: TenantId; origin: HttpsOrigin }
  | { kind: "audience_mismatch"; tenantId: TenantId; audience: SessionAudience }
  | { kind: "proof_expired"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "proof_replayed"; tenantId: TenantId; providerId: AuthProviderId }
  | { kind: "refresh_family_revoked"; tenantId: TenantId; refreshTokenId: SessionRefreshTokenId };
```

Session handle rules:

- Bearer `SeamsSession` values are bearer authority. SDKs must never log them,
  store them outside the selected session store, or persist them in diagnostics.
- Browser-cookie delivery stores the session token only in an HttpOnly cookie.
  The SDK handle wraps delivery mode plus CSRF binding metadata, not the token.
- Hosted wallet iframe deployments use the explicit
  `hosted_wallet_exchange_code` flow. The parent sends only the one-time,
  origin-bound exchange code and nonce over the authenticated iframe channel.
  The iframe redeems the code directly with the session service for a
  wallet-audience bearer session; the parent never sends a bearer token through
  `postMessage`, and the flow does not depend on third-party cookies.
- Hosted-wallet exchange codes are single-use, short-lived, bound to tenant,
  source session, app origin, wallet origin, and nonce, and recorded as consumed
  atomically with wallet-audience session creation.

Default exchange behavior:

- `betterAuthSessionProvider(auth)` verifies the Better Auth session and emits
  principal-unbound `SessionProviderEvidence`; the identity module resolves the
  tenant/provider subject to a principal before the session module constructs
  `SessionEvidenceRef` values and the normalized session record.
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
- Session construction resolves evidence records by ID and rejects mixed tenant,
  principal, provider, subject, audience, or device facts before constructing
  `ActiveSeamsSessionRecord`.

Device identity is minted and managed by the `session/` module. The HTTP/runtime
adapter derives user-agent and IP hashes from trusted request metadata and
parses the signed device claim once into `SessionExchangeRequestContext`.
Session exchange validates an existing device credential or creates a new
`auth_devices` row, rejects revoked devices, and stores the resulting `deviceId`
on sessions, challenges, grant evidence, MPC signer proofs, and audit events.
Core authorization and capability code require `DeviceId`; they never accept a
client-selected device ID or fingerprint a device directly.

### Enterprise SSO

> Follow-on context (July 22 scope amendment): not a Refactor 90 acceptance
> surface.

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

> Follow-on context (July 22 scope amendment): not a Refactor 90 acceptance
> surface.

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

- Internal modules use `AuthFactorManifest`, `ServerAuthFactorModule`, and
  `BrowserAuthFactorModule`; the public browser config keeps the customer-facing
  `authMethods` key.
- Evidence kinds are composed from family unions (`AuthFactorKind`, provider
  evidence, interactive grant evidence, and derived grant evidence).
- `SeamsSession` is exposed publicly as an opaque branded handle. Internal code
  uses `SeamsSessionRecord` and `ActiveSeamsSessionRecord`.
- Records use entity-specific lifecycle unions. Exact repeated digest clusters
  use `OperationDigestSet`.
- Capability kind and operation kind travel as correlated
  `CapabilityOperationRef` values.
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
| signing auth method | `AuthFactorIdentity` plus durable `AuthFactorRecord` |
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

Phase 12 owns TypeScript fixtures plus Rust parity vectors before any capability
depends on a digest. A capability can add a new lane or intent only by adding
vectors for its canonical bytes and digest output.

## Layering Rules

1. `seams-authorization` cannot import vault, Ed25519 MPC, ECDSA MPC, signer
   WASM, HSS, or chain-specific code.
2. `identity`, `authFactor`, and `session` own their records and expose narrow
   ports. `seams-authorization` consumes active session/evidence projections; it
   cannot import provider adapters or mutate identity/factor/session lifecycle.
3. Capability modules can import `seams-authorization`.
4. App assembly code can import selected capabilities and wire them to routes.
5. Tenant capability state lives in persistence, not in legacy flags.
6. Route handlers fail closed when a required capability is missing.
7. Compatibility code belongs only at request and persistence boundaries, with a
   named deletion condition.
8. Build a constrained first-party auth factor module surface. Support
   Better Auth through a session-provider adapter.
9. Capabilities reference registered grant evidence kinds through operation-level
   policies. They do not instantiate auth factor modules directly.
10. Auth providers verify provider artifacts and factor modules verify factor
    assertions. The session module alone creates sessions, and Seams
    authorization alone mints `CapabilityGrant` records.
11. `seams-auth` persistence goes through an explicit database adapter. Raw
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
mechanism into an `AuthFactorManifest`, runtime-specific auth-factor module,
`AuthFactorKind`,
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
  identity: IdentityStorePort;
  authFactors: AuthFactorStorePort;
  sessions: SessionStorePort;
  authorization: AuthorizationStorePort;
  migrate?: (plan: SeamsAuthMigrationPlan) => Promise<SeamsAuthMigrationResult>;
};
```

Core modules never receive a raw transaction or query object. Store ports expose
domain commands such as `replaceAuthFactor`, `consumeHostedWalletExchangeCode`,
`claimCapabilityGrantUse`, and `completeCapabilityGrantUse`. Each adapter
implements those commands atomically using its native primitive: D1 batch/CAS,
or a database transaction on PostgreSQL/Prisma/Drizzle. The conformance suite
tests command semantics, not a shared transaction API that some runtimes cannot
provide.
Optional modules such as IdP and vault receive their own store adapters at
module assembly and are absent from auth-only deployments.

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
  authFactors: readonly AuthFactorKind[];
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
  authFactors: [
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
| Vault proxy use | active session plus RBAC and an exact one-use grant |
| Vault reveal | operation-bound passkey assertion evidence |
| NEAR signing (`near.sign_transaction`, `near.sign_delegate_action`, `near.sign_nep413_message`) | passkey assertion or Email OTP evidence |
| NEAR export (`near.export_key`) | passkey assertion evidence |
| EVM transaction signing (`evm.sign_transaction`) | passkey assertion or Email OTP evidence |
| EVM export (`evm.export_key`) | passkey assertion evidence |

Tenant policy can make defaults stricter. It should not silently weaken the
compiled capability defaults.

## Target Domain Types

Amended July 3 and July 10, 2026: capability kinds and operation kinds are closed unions in
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

type VaultOperationKind =
  | "vault.proxy_use"
  | "vault.reveal";

type NearEd25519MpcOperationKind =
  | "near.sign_transaction"
  | "near.sign_delegate_action"
  | "near.sign_nep413_message"
  | "near.export_key";

type EvmEcdsaMpcOperationKind =
  | "evm.sign_transaction"
  | "evm.export_key";

type CapabilityOperationKind =
  | VaultOperationKind
  | NearEd25519MpcOperationKind
  | EvmEcdsaMpcOperationKind;

type CapabilityOperationKindByCapability = {
  vault_access: VaultOperationKind;
  near_ed25519_mpc_signing: NearEd25519MpcOperationKind;
  evm_ecdsa_mpc_signing: EvmEcdsaMpcOperationKind;
};

type CapabilityOperationRef = {
  [K in CapabilityKind]: {
    capabilityKind: K;
    operationKind: CapabilityOperationKindByCapability[K];
  };
}[CapabilityKind];

type AdministrativeRecordState =
  | { kind: "active"; activatedAt: IsoTimestamp }
  | { kind: "suspended"; suspendedAt: IsoTimestamp }
  | { kind: "deleted"; deletedAt: IsoTimestamp };

type PrincipalState =
  | { kind: "invited"; invitedAt: IsoTimestamp }
  | { kind: "active"; activatedAt: IsoTimestamp }
  | { kind: "suspended"; suspendedAt: IsoTimestamp }
  | { kind: "removed"; removedAt: IsoTimestamp };

type AuthFactorState =
  | { kind: "active"; activatedAt: IsoTimestamp }
  | { kind: "suspended"; suspendedAt: IsoTimestamp }
  | { kind: "revoked"; revokedAt: IsoTimestamp }
  | {
      kind: "replaced";
      replacedAt: IsoTimestamp;
      replacementFactorId: AuthFactorId;
    };

type OperationDigestSet = {
  laneDigest: DigestB64u;
  intentDigest: DigestB64u;
  displayDigest: DigestB64u;
};

type CapabilityOperationFingerprintDigest = Brand<
  string,
  "CapabilityOperationFingerprintDigest"
>;

type AuthAccount = {
  tenantId: TenantId;
  principalId: PrincipalId;
  state: AdministrativeRecordState;
  recoveryPolicyId: RecoveryPolicyId;
  createdAt: IsoTimestamp;
};

type AuthFactorIdentity =
  | { kind: "passkey"; credentialId: PasskeyCredentialId }
  | {
      kind: "email_otp";
      provider: EmailOtpProvider;
      providerUserId: EmailOtpProviderUserId;
    }
  | { kind: "wallet_login"; walletAccountId: EmbeddedWalletAccountId }
  | { kind: "recovery_code"; recoverySetId: RecoverySetId };

type AuthFactorKind = AuthFactorIdentity["kind"];

type AuthFactorRecord = {
  tenantId: TenantId;
  principalId: PrincipalId;
  factorId: AuthFactorId;
  identity: AuthFactorIdentity;
  state: AuthFactorState;
  enrolledAt: IsoTimestamp;
};

type ActiveAuthFactorRecord = AuthFactorRecord & {
  state: Extract<AuthFactorState, { kind: "active" }>;
};

type WalletAuthAuthorityBindingState =
  | { kind: "active"; activatedAt: IsoTimestamp }
  | {
      kind: "replaced";
      replacedAt: IsoTimestamp;
      replacementBindingId: WalletAuthMethodId;
    }
  | { kind: "revoked"; revokedAt: IsoTimestamp };

type WalletAuthAuthorityRecord = {
  tenantId: TenantId;
  principalId: PrincipalId;
  factorId: AuthFactorId;
  authority: WalletAuthAuthority;
  state: WalletAuthAuthorityBindingState;
};

type WalletAuthAuthorityRef = {
  walletId: WalletId;
  bindingId: WalletAuthMethodId;
  factorId: AuthFactorId;
  authorityDigest: WalletAuthorityBindingDigest;
};

type ProviderSessionEvidenceKind = "provider_session";

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
  | "email_otp";

type SessionGrantEvidenceKind = "seams_session";

type GrantEvidenceKind =
  | SessionGrantEvidenceKind
  | InteractiveGrantEvidenceKind;

type AssuranceProperty =
  | "authenticated_session"
  | "recent_interaction"
  | "multi_factor"
  | "phishing_resistant"
  | "device_bound";

type AssuranceProfile = {
  properties: NonEmptyArray<AssuranceProperty>;
  assessedAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
};

type AssuranceRequirement = {
  kind: "all_properties";
  properties: NonEmptyArray<AssuranceProperty>;
};

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
  state: AdministrativeRecordState;
  displayName: string;
  createdAt: IsoTimestamp;
};

type NonHumanPrincipalKind = "agent" | "service_account" | "system";

type PrincipalKind = "human" | NonHumanPrincipalKind;

type AuthPrincipal = {
  kind: PrincipalKind;
  tenantId: TenantId;
  principalId: PrincipalId;
  displayName: string;
  state: PrincipalState;
  createdAt: IsoTimestamp;
};

type AuthFactorManifest = {
  factorKind: AuthFactorKind;
  schema: AuthFactorSchema;
  sessionEvidenceKinds: readonly SessionEvidenceKind[];
  grantEvidenceKinds: readonly GrantEvidenceKind[];
  routeDefinitions: readonly RouterApiRouteDefinition[];
};

type ServerAuthFactorModule<TRuntime extends RouteRuntimeKind> = {
  manifest: AuthFactorManifest;
  runtime: TRuntime;
  loadHandlers: RuntimeHandlerFactory<TRuntime>;
};

type BrowserAuthFactorModule = {
  factorKind: AuthFactorKind;
  loadClient: LazyClientModule;
};

type TenantAuthFactorEnablement = {
  tenantId: TenantId;
  factorKind: AuthFactorKind;
  configDigest: DigestB64u;
  state: AdministrativeRecordState;
  createdAt: IsoTimestamp;
};

type AuthProviderBase = {
  tenantId: TenantId;
  providerId: AuthProviderId;
  evidenceKinds: NonEmptyArray<SessionEvidenceKind>;
  configDigest: DigestB64u;
  state: AdministrativeRecordState;
  createdAt: IsoTimestamp;
};

type AuthProvider =
  | (AuthProviderBase & {
      kind: "seams_auth_provider";
    })
  | (AuthProviderBase & {
      kind: "better_auth_provider";
      betterAuthInstanceId: ExternalAuthInstanceId;
    })
  | (AuthProviderBase & {
      kind: "external_oidc_provider";
      issuer: OidcIssuer;
      claimMapping: SsoClaimMapping;
    });

declare const sessionProviderEvidenceBrand: unique symbol;

type SessionProviderEvidence = {
  readonly [sessionProviderEvidenceBrand]: true;
  providerId: AuthProviderId;
  tenantId: TenantId;
  externalSessionId: ExternalSessionId;
  sessionSubject: ExternalSessionSubject;
  evidenceKinds: NonEmptyArray<ProviderEvidenceKind>;
  assurance: AssuranceProfile;
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
  targetCapabilityId: CapabilityId;
  targetOperation: CapabilityOperationRef;
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
  state: AdministrativeRecordState;
  createdAt: IsoTimestamp;
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

type SessionSubjectRef =
  | {
      kind: "provider_identity";
      providerIdentityId: ProviderIdentityId;
    }
  | {
      kind: "auth_factor";
      factorId: AuthFactorId;
    };

type SessionAudience =
  | {
      kind: "first_party_web";
      origin: HttpsOrigin;
    }
  | {
      kind: "hosted_wallet_iframe";
      appOrigin: HttpsOrigin;
      walletOrigin: WalletOrigin;
    }
  | {
      kind: "api_client";
      clientId: SessionClientId;
    };

type HostedWalletSessionExchangeRecordBase = {
  tenantId: TenantId;
  exchangeCodeId: HostedWalletSessionExchangeCodeId;
  sourceSessionId: SeamsSessionId;
  appOrigin: HttpsOrigin;
  walletOrigin: WalletOrigin;
  nonceDigest: DigestB64u;
  expiresAt: IsoTimestamp;
};

type HostedWalletSessionExchangeRecord =
  | (HostedWalletSessionExchangeRecordBase & {
      kind: "issued";
      issuedAt: IsoTimestamp;
    })
  | (HostedWalletSessionExchangeRecordBase & {
      kind: "consumed";
      targetSessionId: SeamsSessionId;
      consumedAt: IsoTimestamp;
    })
  | (HostedWalletSessionExchangeRecordBase & {
      kind: "expired";
      expiredAt: IsoTimestamp;
    })
  | (HostedWalletSessionExchangeRecordBase & {
      kind: "revoked";
      revokedAt: IsoTimestamp;
    });

type SeamsSessionState =
  | { kind: "active"; expiresAt: IsoTimestamp }
  | { kind: "revoked"; revokedAt: IsoTimestamp }
  | { kind: "expired"; expiredAt: IsoTimestamp };

type SeamsSessionRecord = {
  tenantId: TenantId;
  principalId: PrincipalId;
  sessionId: SeamsSessionId;
  providerId: AuthProviderId;
  subject: SessionSubjectRef;
  sessionEvidence: NonEmptyArray<SessionEvidenceRef>;
  assurance: AssuranceProfile;
  deviceId: DeviceId;
  audience: SessionAudience;
  state: SeamsSessionState;
  createdAt: IsoTimestamp;
};

type ActiveSeamsSessionRecord = SeamsSessionRecord & {
  state: Extract<SeamsSessionState, { kind: "active" }>;
};

type GrantEvidenceBase = {
  tenantId: TenantId;
  principalId: PrincipalId;
  evidenceId: GrantEvidenceId;
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
    });

type GrantEvidenceContext = {
  kind: "interactive_session";
  sessionId: SeamsSessionId;
  deviceId: DeviceId;
};

declare const verifiedGrantEvidenceSetBrand: unique symbol;

type VerifiedGrantEvidenceSet = {
  readonly [verifiedGrantEvidenceSetBrand]: true;
  tenantId: TenantId;
  evidenceSetId: GrantEvidenceSetId;
  principalId: PrincipalId;
  principalKind: PrincipalKind;
  context: GrantEvidenceContext;
  evidenceIds: NonEmptyArray<GrantEvidenceId>;
  evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
  operation: CapabilityOperationRef;
  operationDigests: OperationDigestSet;
  assurance: AssuranceProfile;
  evidenceSetDigest: DigestB64u;
  expiresAt: IsoTimestamp;
};

declare const capabilityGrantRequestBrand: unique symbol;

type CapabilityGrantRequest = {
  readonly [capabilityGrantRequestBrand]: true;
  operation: CapabilityOperationEnvelope;
  bindingId: CapabilityBindingId;
  evidenceSet: VerifiedGrantEvidenceSet;
};

type GrantEvidenceRequirement = {
  mode: "all" | "any";
  evidenceKinds: NonEmptyArray<GrantEvidenceKind>;
};

type CapabilityGrantPolicy = {
  tenantId: TenantId;
  policyId: PolicyId;
  operation: CapabilityOperationRef;
  allowedPrincipalKinds: NonEmptyArray<PrincipalKind>;
  allowedBindingKinds: NonEmptyArray<CapabilityBindingKind>;
  requiredEvidence: GrantEvidenceRequirement;
  requiredAssurance: AssuranceRequirement;
  maxTtlSeconds: PositiveInt;
  maxUses: PositiveInt;
  state: AdministrativeRecordState;
  createdByPrincipalId: PrincipalId;
  createdAt: IsoTimestamp;
};

type CapabilityOperationGrantPolicyBinding = {
  tenantId: TenantId;
  capabilityId: CapabilityId;
  operation: CapabilityOperationRef;
  policyId: PolicyId;
  state: AdministrativeRecordState;
  createdByPrincipalId: PrincipalId;
  createdAt: IsoTimestamp;
};
```

`AuthFactorIdentity` is pure matching identity. `AuthFactorRecord` is one durable
enrollment, and `WalletAuthAuthorityRecord` is one wallet-bound verifier
authority referencing that exact enrollment. Re-enrollment creates a new
`factorId` and wallet-auth binding; equality of credential/provider identity
alone never reactivates records tied to a replaced binding. Signing, export,
recovery, restore, and admission lanes carry `WalletAuthAuthorityRef`, never raw
credential IDs, provider subjects, or display data.

`VerifiedGrantEvidenceSet` is the only evidence collection accepted by grant
issuance. Its builder loads evidence records by ID and rejects mixed tenant,
principal, session, device, capability operation, or operation-digest facts.
For interactive sets, every session-bound evidence row must resolve to the same
active session and device. For non-interactive sets, every evidence provider
must explicitly support non-interactive use. Diagnostics and raw arrays of
`GrantEvidenceRef` never influence authorization directly.
`CapabilityGrantRequest` is built only after the active capability binding,
operation envelope, and verified evidence set agree on tenant, principal,
capability kind, operation kind, and operation digests.

### Canonical MPC Hydration And ECDSA Capability State

Registration, wallet unlock, and page refresh are entry-point provenance. They
do not select material, recovery, authorization, or signing behavior. Every MPC
capability resolves current canonical persistence and runtime facts into the same
closed hydration plan:

```ts
type CapabilityInstanceRef = Brand<string, "CapabilityInstanceRef">;
type MpcMaterialOwnerRef = Brand<string, "MpcMaterialOwnerRef">;
type MpcCapabilityRuntimeRef = Brand<string, "MpcCapabilityRuntimeRef">;
type ActiveMpcMaterialSessionRef = Brand<string, "ActiveMpcMaterialSessionRef">;
type RestorableMpcMaterialRef = Brand<string, "RestorableMpcMaterialRef">;
type NearEd25519YaoSealedActiveClientRef =
  Brand<string, "NearEd25519YaoSealedActiveClientRef">;
type NearEd25519YaoSealedRootRecoveryRef =
  Brand<string, "NearEd25519YaoSealedRootRecoveryRef">;
type EcdsaRoleLocalDurableMaterialRef =
  Brand<string, "EcdsaRoleLocalDurableMaterialRef">;
type MpcKeyBindingRef = Brand<string, "MpcKeyBindingRef">;
type MpcLifecycleBindingRef = Brand<string, "MpcLifecycleBindingRef">;
type MpcReauthorizationPolicyRef =
  Brand<string, "MpcReauthorizationPolicyRef">;
type MpcRegisteredPublicKeyBindingRef =
  Brand<string, "MpcRegisteredPublicKeyBindingRef">;

type MpcCapabilityHydrationEntryPoint =
  | "post_registration"
  | "post_wallet_unlock"
  | "post_page_refresh";

type MpcCapabilityPublicReauthAnchor = {
  kind: "mpc_capability_public_reauth_anchor";
  capability: CapabilityInstanceRef;
  materialOwner: MpcMaterialOwnerRef;
  authority: WalletAuthAuthorityRef;
  keyBinding: MpcKeyBindingRef;
  lifecycleBinding: MpcLifecycleBindingRef;
  reauthorizationPolicy: MpcReauthorizationPolicyRef;
  registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
  secretMaterial?: never;
  sealedMaterial?: never;
  bearerSessionCredential?: never;
  runtime?: never;
  activeMaterialSession?: never;
  operationGrant?: never;
  quotaState?: never;
  nonceState?: never;
};

type MpcCapabilityHydrationPlan =
  | {
      kind: "use_live_runtime";
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      runtime: MpcCapabilityRuntimeRef;
      activeMaterialSession: ActiveMpcMaterialSessionRef;
      sealedMaterial?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    }
  | {
      kind: "rehydrate_active_session";
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      activeMaterialSession: ActiveMpcMaterialSessionRef;
      sealedMaterial: RestorableMpcMaterialRef;
      runtime?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    }
  | {
      kind: "reauthorize_public_anchor";
      capability: CapabilityInstanceRef;
      materialOwner: MpcMaterialOwnerRef;
      authority: WalletAuthAuthorityRef;
      retirement: "expired" | "exhausted";
      publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
      runtime?: never;
      activeMaterialSession?: never;
      sealedMaterial?: never;
    }
  | {
      kind: "blocked";
      capability: CapabilityInstanceRef | null;
      reason:
        | "missing_capability"
        | "missing_material"
        | "revoked"
        | "replaced"
        | "authority_ambiguous"
        | "binding_mismatch"
        | "exact_record_conflict"
        | "corrupt"
        | "persistence_unavailable";
      materialOwner?: never;
      authority?: never;
      runtime?: never;
      activeMaterialSession?: never;
      sealedMaterial?: never;
      retirement?: never;
      publicReauthAnchor?: never;
    };

type MpcCapabilityHydrationResolution = {
  provenance: {
    entryPoint: MpcCapabilityHydrationEntryPoint;
  };
  plan: MpcCapabilityHydrationPlan;
};
```

`RestorableMpcMaterialRef` is proof that the protocol adapter resolved exact
durable material for the current active material session and an exact currently
available material-unlock source. An adapter with an unavailable unlock source
returns its typed material-unlock requirement and cannot construct
`rehydrate_active_session`. The Near Ed25519
adapter derives it from an authenticated
`NearEd25519YaoSealedActiveClientRef`; the rehydration effect imports that
activated Client locally and makes zero Deriver A/B calls. The ECDSA adapter
derives it from an exact encrypted `EcdsaRoleLocalDurableMaterialRef`.
`NearEd25519YaoSealedRootRecoveryRef` is a separate recovery input used for
device linking and explicit same-root recovery. Export uses its separately
authorized one-use material-acquisition lifecycle. The root-recovery ref cannot
construct `rehydrate_active_session`.

The shared leaf contract owns only the four decisions and branded proofs.
Protocol adapters own persistence parsing, cryptographic envelope validation,
and exact observation unions. Narrow proof constructors accept normalized
evidence; they do not infer authority, lifecycle, or policy from optional
legacy records, source labels, or diagnostics.

The public anchor is stable reauthorization input. Its policy reference names
the capability's reauthorization policy and is never an operation grant. Core
material, signing, and export functions receive `plan`, while diagnostics and
tests may also receive `provenance`.

Near same-root recovery persists only cross-boundary facts:

```ts
type NearEd25519YaoRecoveryId = Brand<string, "NearEd25519YaoRecoveryId">;
type NearEd25519YaoRecoveryCorrelation =
  Brand<string, "NearEd25519YaoRecoveryCorrelation">;
type NearEd25519YaoMaterialRecoverySourceRef =
  Brand<string, "NearEd25519YaoMaterialRecoverySourceRef">;
type NearEd25519YaoPromotionReceipt =
  Brand<string, "NearEd25519YaoPromotionReceipt">;
type NearEd25519YaoLocalFinalizationCommand =
  Brand<string, "NearEd25519YaoLocalFinalizationCommand">;

type NearEd25519YaoRecoveryCommitJournal =
  | {
      kind: "prepared";
      recoveryId: NearEd25519YaoRecoveryId;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      source: NearEd25519YaoMaterialRecoverySourceRef;
      correlation: NearEd25519YaoRecoveryCorrelation;
      disposition: "continue" | "cancel_requested";
    }
  | {
      kind: "promotion_committed";
      recoveryId: NearEd25519YaoRecoveryId;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      promotionReceipt: NearEd25519YaoPromotionReceipt;
      finalization: NearEd25519YaoLocalFinalizationCommand;
    };

type CapabilityPreparationResult<
  Ready,
  Resume,
  Requirement,
  Replacement,
  Failure,
> =
  | { kind: "ready"; value: Ready }
  | { kind: "pending"; resume: Resume }
  | { kind: "authorization_required"; requirement: Requirement }
  | { kind: "superseded"; replacement: Replacement }
  | { kind: "failed"; failure: Failure };
```

`prepared` is written before the first consuming server call and therefore
already represents uncertainty after reload. Admission, acquisition, and
promotion are independently idempotent and queryable by `recoveryId`
(R90-INV-004). A cancellation changes `disposition` with compare-and-swap;
reload reconciles it and cannot silently execute the abandoned parent operation
(R90-INV-007).

After promotion, one IndexedDB transaction persists the replacement seal or
volatile-retention record, retires or removes the prior source, persists the
current lifecycle receipt, and deletes the journal (R90-INV-005). Runtime
publication and secret cleanup remain process-local (R90-INV-006). An optional
post-commit read through the canonical parser does not create another journal
branch (R90-INV-011). `superseded` invalidates the prepared lane and forces exact
current-state resolution (R90-INV-010).

ECDSA persists one capability manifest. It replaces the current
`ThresholdEcdsaSessionRecordCore` family of records.

```ts
type EvmFamilyEcdsaSignerId = Brand<string, "EvmFamilyEcdsaSignerId">;
type ThresholdEcdsaSessionId = Brand<string, "ThresholdEcdsaSessionId">;
type EcdsaServerGeneration = Brand<string, "EcdsaServerGeneration">;
type EcdsaCapabilityManifestId =
  Brand<string, "EcdsaCapabilityManifestId">;
type EcdsaCapabilityManifestRevision =
  Brand<number, "EcdsaCapabilityManifestRevision">;
type EcdsaRoleLocalBindingDigest =
  Brand<string, "EcdsaRoleLocalBindingDigest">;
type EcdsaCiphertextDigest = Brand<string, "EcdsaCiphertextDigest">;
type EcdsaActivationDigest = Brand<string, "EcdsaActivationDigest">;
type EcdsaLifecycleId = Brand<string, "EcdsaLifecycleId">;
type EcdsaServerActivationReceipt =
  Brand<string, "EcdsaServerActivationReceipt">;
type EcdsaRuntimeValidationProof =
  Brand<string, "EcdsaRuntimeValidationProof">;
type CorrelationId = Brand<string, "CorrelationId">;
type SpendableMpcWalletSigningQuotaRef =
  Brand<string, "SpendableMpcWalletSigningQuotaRef">;
type VerifiedCapabilityOperationAuthorizationRef =
  Brand<string, "VerifiedCapabilityOperationAuthorizationRef">;

type EcdsaCapabilityScope =
  | {
      kind: "evm_family";
      targetMemberships: NonEmptyArray<ThresholdEcdsaChainTarget>;
      exactTarget?: never;
    }
  | {
      kind: "exact_target";
      exactTarget: ThresholdEcdsaChainTarget;
      targetMemberships?: never;
    };

type EcdsaRoleLocalMaterialBinding = {
  keyHandle: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  participantIds: NonEmptyArray<EcdsaParticipantId>;
  relayerKeyId: EcdsaRelayerKeyId;
};

type RegisteredEvmFamilySigner = {
  kind: "registered_evm_family_signer";
  capability: CapabilityInstanceRef;
  signerId: EvmFamilyEcdsaSignerId;
  walletId: WalletId;
  authority: WalletAuthAuthorityRef;
  scope: EcdsaCapabilityScope;
  materialOwner: MpcMaterialOwnerRef;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  registeredPublicFacts: VerifiedEcdsaPublicFacts;
  activeSession?: never;
  durableMaterial?: never;
  runtime?: never;
  operationGrant?: never;
  quotaState?: never;
  nonceState?: never;
  bearerSessionCredential?: never;
};

type ActiveEcdsaMaterialSession = {
  kind: "active_ecdsa_material_session";
  thresholdSessionId: ThresholdEcdsaSessionId;
  serverGeneration: EcdsaServerGeneration;
  lifecycleBinding: MpcLifecycleBindingRef;
  retention: "session_retained";
  thresholdSessionExpiresAt: IsoTimestamp;
  recoveryPolicy: {
    kind: "recoverable";
    remainingRecoveryUses: PositiveInt;
    recoveryExpiresAt: IsoTimestamp;
  };
  operationGrant?: never;
  quotaState?: never;
  nonceState?: never;
  bearerSessionCredential?: never;
};

type DurableEcdsaMaterialBinding = {
  kind: "durable_ecdsa_material";
  materialOwner: MpcMaterialOwnerRef;
  roleLocalBinding: EcdsaRoleLocalMaterialBinding;
  durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  bindingDigest: EcdsaRoleLocalBindingDigest;
  lifecycleId: EcdsaLifecycleId;
  ciphertextDigest: EcdsaCiphertextDigest;
  activationDigest: EcdsaActivationDigest;
  activatedAt: IsoTimestamp;
  materialExpiresAt: IsoTimestamp;
  runtime?: never;
};

type ActiveEcdsaCapabilityManifest = {
  kind: "active_ecdsa_capability_manifest";
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  signer: RegisteredEvmFamilySigner;
  activeSession: ActiveEcdsaMaterialSession;
  durableMaterial: DurableEcdsaMaterialBinding;
  serverActivationReceipt: EcdsaServerActivationReceipt;
  committedAt: IsoTimestamp;
  publicReauthAnchor?: never;
  retirement?: never;
  runtime?: never;
  operationGrant?: never;
  quotaState?: never;
  nonceState?: never;
  bearerSessionCredential?: never;
  provenance?: never;
  diagnostics?: never;
};

type RetiredEcdsaCapabilityManifestCommon = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  signer: RegisteredEvmFamilySigner;
  retiredAt: IsoTimestamp;
  activeSession?: never;
  durableMaterial?: never;
  serverActivationReceipt?: never;
  runtime?: never;
  operationGrant?: never;
  quotaState?: never;
  nonceState?: never;
  bearerSessionCredential?: never;
};

type RetiredEcdsaCapabilityManifest =
  RetiredEcdsaCapabilityManifestCommon &
    (
      | {
          kind: "reauthorizable_ecdsa_capability_manifest";
          retirement: "expired" | "exhausted";
          publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
        }
      | {
          kind: "terminal_ecdsa_capability_manifest";
          retirement: "revoked" | "replaced";
          publicReauthAnchor?: never;
        }
    );

type EcdsaCapabilityManifest =
  | ActiveEcdsaCapabilityManifest
  | RetiredEcdsaCapabilityManifest;

type ActiveEcdsaCapabilityRef = {
  kind: "active_ecdsa_capability_ref";
  capability: CapabilityInstanceRef;
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  signerId: EvmFamilyEcdsaSignerId;
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
  thresholdSessionId: ThresholdEcdsaSessionId;
  serverGeneration: EcdsaServerGeneration;
};

type EcdsaRuntimeObservation =
  | {
      kind: "absent";
      capability: CapabilityInstanceRef;
      manifestRevision: EcdsaCapabilityManifestRevision;
      materialOwner?: never;
      runtime?: never;
      durableMaterialRef?: never;
      bindingDigest?: never;
      validationProof?: never;
      failure?: never;
    }
  | {
      kind: "live";
      capability: CapabilityInstanceRef;
      manifestRevision: EcdsaCapabilityManifestRevision;
      materialOwner: MpcMaterialOwnerRef;
      durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
      bindingDigest: EcdsaRoleLocalBindingDigest;
      runtime: MpcCapabilityRuntimeRef;
      validationProof: EcdsaRuntimeValidationProof;
      failure?: never;
    }
  | {
      kind: "invalid";
      capability: CapabilityInstanceRef;
      manifestRevision: EcdsaCapabilityManifestRevision;
      failure:
        | "unknown_runtime_handle"
        | "manifest_revision_mismatch"
        | "material_ref_mismatch"
        | "binding_digest_mismatch";
      materialOwner?: never;
      durableMaterialRef?: never;
      bindingDigest?: never;
      runtime?: never;
      validationProof?: never;
    };

type EcdsaCapabilityManifestLookup =
  | { kind: "active"; manifest: ActiveEcdsaCapabilityManifest }
  | { kind: "retired"; manifest: RetiredEcdsaCapabilityManifest }
  | { kind: "missing"; capability: CapabilityInstanceRef }
  | {
      kind: "exact_binding_mismatch";
      capability: CapabilityInstanceRef;
      failureDigest: DigestB64u;
    }
  | {
      kind: "exact_record_conflict";
      capability: CapabilityInstanceRef;
      conflictDigest: DigestB64u;
    }
  | {
      kind: "corrupt";
      capability: CapabilityInstanceRef;
      corruptionDigest: DigestB64u;
    }
  | {
      kind: "persistence_unavailable";
      capability: CapabilityInstanceRef;
      retryCorrelation: CorrelationId;
    };
```

An active manifest always carries exact durable material identity. Volatile
runtime loss has one legal downgrade: `live -> durable`. A reauthorizable
retired manifest carries public reauthorization facts; a terminal retired
manifest carries the revocation or replacement tombstone. Neither carries
active or recoverable material.
Missing, mismatch, conflict, corruption, and unavailable storage remain distinct
terminal parser results until an explicit recovery or maintenance action handles
them.

Registration, unlock, and reauthorization publish active manifests through one
activation journal:

```ts
type EcdsaManifestRevisionExpectation =
  | { kind: "no_current_manifest" }
  | {
      kind: "exact_revision";
      manifestRevision: EcdsaCapabilityManifestRevision;
    };

type EcdsaActivationJournalCommon = {
  journalId: CorrelationId;
  capability: CapabilityInstanceRef;
  signerId: EvmFamilyEcdsaSignerId;
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
  expectedManifest: EcdsaManifestRevisionExpectation;
  activationRequestDigest: DigestB64u;
  candidateMaterial: DurableEcdsaMaterialBinding;
  createdAt: IsoTimestamp;
};

type EcdsaCapabilityActivationCommitJournal =
  EcdsaActivationJournalCommon &
    (
      | {
          kind: "activation_prepared";
          serverGeneration?: never;
          serverActivationReceipt?: never;
        }
      | {
          kind: "server_activation_committed";
          serverGeneration: EcdsaServerGeneration;
          serverActivationReceipt: EcdsaServerActivationReceipt;
        }
    );
```

The journal is persisted before the first consuming server effect. Server
activation is idempotent and queryable by `journalId`. After server activation,
one IndexedDB transaction writes encrypted material, writes the active manifest,
retires the replaced manifest when applicable, and deletes the journal. This is
the local commit boundary required by R90-INV-005. Runtime publication follows
from canonical durable state and is validated against the manifest revision,
durable material ref, and binding digest. A high-value commit may be read through
the canonical parser after transaction completion; no readback or runtime-
publication journal state exists. Reload reconciles a pending journal before
ordinary capability discovery. A partial commit cannot construct
`use_live_runtime`, `rehydrate_active_session`, or an operation lane.

Exact operation selection begins from the active capability ref and keeps
operation authorization and quota independent from material identity:

```ts
type MpcOperationQuotaBinding =
  | {
      kind: "required";
      quota: SpendableMpcWalletSigningQuotaRef;
    }
  | {
      kind: "none";
      quota?: never;
    };

type EcdsaOperationTarget =
  | {
      kind: "transaction_target";
      chainTarget: ThresholdEcdsaChainTarget;
      materialOwner?: never;
    }
  | {
      kind: "material_owner";
      materialOwner: MpcMaterialOwnerRef;
      chainTarget?: never;
    };

declare const exactEcdsaOperationLaneBrand: unique symbol;

type ExactEcdsaOperationLane = {
  readonly [exactEcdsaOperationLaneBrand]: true;
  capability: ActiveEcdsaCapabilityRef;
  operation: CapabilityOperationEnvelope;
  target: EcdsaOperationTarget;
  authorization: VerifiedCapabilityOperationAuthorizationRef;
  quota: MpcOperationQuotaBinding;
  runtime?: never;
  bearerSessionCredential?: never;
  nonceState?: never;
};
```

The operation-descriptor builder correlates operation kind, target kind, and
quota requirement before branding the lane. The same branded lane travels
through recovery, authorization, quota claim, nonce preparation, signing or
export, and finalization. Shared EVM-family projection may reuse only signer,
scope, authority, material-owner, and durable material facts allowed by the
manifest. It cannot project a threshold session, operation grant, quota use,
bearer credential, nonce, or runtime handle.

Core ECDSA types have no optional identity, authority, session, material,
recovery, persistence, signing, export, or lifecycle fields. Discriminated
branches use required fields plus `never` exclusions. Boundary builders and
parsers are the only constructors for branded values. The implementation
deletes `ThresholdEcdsaSessionRecordCore`, its normalized variants, optional-field
state inference, source-priority ranking, newest-record selection, and
flow-specific registration/unlock/refresh records when this model lands.

### Auth-Agnostic EVM ECDSA Preparation

Auth factors do not define ECDSA transaction lanes or signer-material lifecycle
states. Passkey, Email OTP, and future factors resolve to distinct
`WalletAuthAuthorityRef` values and produce grant evidence through factor
adapters. The EVM ECDSA capability consumes those normalized references and
grants without branching on factor kind.

Transaction targeting and signer-material ownership are separate identities.
This is required because EVM and Tempo transaction lanes can use the same
EVM-family signer material while retaining distinct operation targets.
`ExactEcdsaMaterialIdentity` composes the final canonical material identity from
Phase 5; it does not revive provisioning-only key-slot IDs or duplicate wallet
identity already carried by `WalletAuthAuthorityRef`.

```ts
type MpcMaterialUseState =
  | { kind: "session_retained" }
  | {
      kind: "single_use_pending";
      operationFingerprintDigest: CapabilityOperationFingerprintDigest;
    }
  | { kind: "single_use_consumed"; consumedAt: IsoTimestamp };

type SignableMpcMaterialUseState = Extract<
  MpcMaterialUseState,
  { kind: "session_retained" | "single_use_pending" }
>;

type RecoverableMpcMaterialUseState = Extract<
  MpcMaterialUseState,
  { kind: "session_retained" }
>;

type MpcMaterialRecoveryId = Brand<string, "MpcMaterialRecoveryId">;

type WalletAuthoritySelectionPolicy =
  | { kind: "any_authority" }
  | {
      kind: "exact_authority";
      authorityRef: WalletAuthAuthorityRef;
    };

type ExactEcdsaMaterialIdentity = {
  kind: "exact_ecdsa_material";
  authorityRef: WalletAuthAuthorityRef;
  materialBinding: EcdsaRoleLocalMaterialBinding;
};

type EvmEcdsaTransactionOperationEnvelope = CapabilityOperationEnvelope & {
  operation: {
    capabilityKind: "evm_ecdsa_mpc_signing";
    operationKind: "evm.sign_transaction";
  };
};

declare const evmEcdsaTransactionSelectionRequestBrand: unique symbol;

type EvmEcdsaTransactionSelectionRequest = {
  readonly [evmEcdsaTransactionSelectionRequestBrand]: true;
  operation: EvmEcdsaTransactionOperationEnvelope;
  transactionTarget: ThresholdEcdsaChainTarget;
};

type EvmEcdsaTransactionLane<
  Use extends MpcMaterialUseState = MpcMaterialUseState,
> = {
  kind: "evm_ecdsa_transaction_lane";
  operation: EvmEcdsaTransactionOperationEnvelope;
  transactionTarget: ThresholdEcdsaChainTarget;
  materialOwner: ExactEcdsaMaterialIdentity;
  materialUse: Use;
};

declare const authorizedEvmEcdsaOperationBrand: unique symbol;

type AuthorizedEvmEcdsaOperation = {
  readonly [authorizedEvmEcdsaOperationBrand]: true;
  operation: EvmEcdsaTransactionOperationEnvelope;
  grant: Extract<CapabilityGrant, { kind: "active" }>;
};

declare const claimedEvmEcdsaOperationBrand: unique symbol;

type ClaimedEvmEcdsaOperation = {
  readonly [claimedEvmEcdsaOperationBrand]: true;
  authorization: AuthorizedEvmEcdsaOperation;
  grantUse: Extract<CapabilityGrantUse, { kind: "claimed" }>;
};

declare const boundReadyEcdsaMaterialBrand: unique symbol;

type BoundReadyEcdsaSigningMaterial<
  Use extends SignableMpcMaterialUseState = SignableMpcMaterialUseState,
> = {
  readonly [boundReadyEcdsaMaterialBrand]: true;
  materialOwner: ExactEcdsaMaterialIdentity;
  materialUse: Use;
  materialHandle: EcdsaRoleLocalMaterialHandle;
};

declare const committedEvmEcdsaCapabilityBrand: unique symbol;

type CommittedEvmEcdsaSigningCapability = {
  readonly [committedEvmEcdsaCapabilityBrand]: true;
  lane: EvmEcdsaTransactionLane<SignableMpcMaterialUseState>;
  authorization: AuthorizedEvmEcdsaOperation;
  material: BoundReadyEcdsaSigningMaterial<SignableMpcMaterialUseState>;
};

declare const verifiedExactEcdsaRecoveryBrand: unique symbol;

type VerifiedExactEcdsaMaterialRecovery = {
  readonly [verifiedExactEcdsaRecoveryBrand]: true;
  materialOwner: ExactEcdsaMaterialIdentity;
  materialUse: RecoverableMpcMaterialUseState;
  authorization: AuthorizedEvmEcdsaOperation;
  recoveryId: MpcMaterialRecoveryId;
  recoveryBindingDigest: DigestB64u;
};

type MpcMaterialUnlockAuthorizationRequirement = {
  kind: "material_unlock";
  recovery: VerifiedExactEcdsaMaterialRecovery;
};

declare const verifiedMpcMaterialUnlockBrand: unique symbol;

type VerifiedMpcMaterialUnlockAuthorization = {
  readonly [verifiedMpcMaterialUnlockBrand]: true;
  recoveryId: MpcMaterialRecoveryId;
  recoveryBindingDigest: DigestB64u;
};

type ExactEcdsaMaterialRecoveryAttempt =
  | {
      kind: "session_authorized_recovery";
      recovery: VerifiedExactEcdsaMaterialRecovery;
    }
  | {
      kind: "material_unlock_authorized_recovery";
      recovery: VerifiedExactEcdsaMaterialRecovery;
      unlockAuthorization: VerifiedMpcMaterialUnlockAuthorization;
    };

declare const replacementEvmEcdsaLaneBrand: unique symbol;

type ReplacementEvmEcdsaLane = {
  readonly [replacementEvmEcdsaLaneBrand]: true;
  anchor: EvmEcdsaReauthorizationAnchor;
  lane: EvmEcdsaTransactionLane;
};

declare const evmEcdsaReauthorizationAnchorBrand: unique symbol;

type EvmEcdsaReauthorizationAnchor = {
  readonly [evmEcdsaReauthorizationAnchorBrand]: true;
  kind: "evm_ecdsa_reauthorization_anchor";
  previousLane: EvmEcdsaTransactionLane;
};

declare const evmEcdsaOperationGrantRequirementBrand: unique symbol;

type EvmEcdsaOperationGrantRequirement = {
  readonly [evmEcdsaOperationGrantRequirementBrand]: true;
  kind: "operation_grant";
  operation: EvmEcdsaTransactionOperationEnvelope;
  plan: Extract<CapabilityGrantPlan, { kind: "grant_evidence_required" }>;
};

type EvmEcdsaAuthorizationRequirement =
  | EvmEcdsaOperationGrantRequirement
  | MpcMaterialUnlockAuthorizationRequirement
  | {
      kind: "threshold_session_replacement";
      anchor: EvmEcdsaReauthorizationAnchor;
    };

type EvmEcdsaAuthorizationSuccessFor<
  Requirement extends EvmEcdsaAuthorizationRequirement,
> = Requirement extends { kind: "operation_grant" }
  ? { kind: "operation_authorized"; authorization: AuthorizedEvmEcdsaOperation }
  : Requirement extends { kind: "material_unlock" }
    ? {
        kind: "material_unlock_authorized";
        recovery: Extract<
          ExactEcdsaMaterialRecoveryAttempt,
          { kind: "material_unlock_authorized_recovery" }
        >;
      }
    : Requirement extends { kind: "threshold_session_replacement" }
      ? { kind: "replacement_lane"; replacement: ReplacementEvmEcdsaLane }
      : never;

type EvmEcdsaAuthorizationResultFor<
  Requirement extends EvmEcdsaAuthorizationRequirement,
> =
  | EvmEcdsaAuthorizationSuccessFor<Requirement>
  | { kind: "denied"; failure: EvmEcdsaPreparationFailure };

type EvmEcdsaPreparationFailure =
  | { kind: "material_missing" }
  | { kind: "material_identity_mismatch" }
  | { kind: "material_ambiguous" }
  | { kind: "material_corrupt" }
  | { kind: "authority_inactive" }
  | { kind: "authorization_denied" }
  | { kind: "no_progress_after_action" };

type EvmEcdsaLaneSelectionFailure =
  | { kind: "lane_missing" }
  | { kind: "authority_ambiguous" }
  | { kind: "lane_identity_conflict" };

type EvmEcdsaLaneSelectionResult =
  | { kind: "selected"; lane: EvmEcdsaTransactionLane }
  | { kind: "blocked"; failure: EvmEcdsaLaneSelectionFailure };

type EvmEcdsaSigningPreparation =
  | {
      kind: "ready";
      committed: CommittedEvmEcdsaSigningCapability;
    }
  | {
      kind: "recovery_required";
      lane: EvmEcdsaTransactionLane<RecoverableMpcMaterialUseState>;
      recovery: ExactEcdsaMaterialRecoveryAttempt;
    }
  | {
      kind: "authorization_required";
      lane: EvmEcdsaTransactionLane;
      requirement: EvmEcdsaAuthorizationRequirement;
    }
  | {
      kind: "blocked";
      lane: EvmEcdsaTransactionLane;
      failure: EvmEcdsaPreparationFailure;
    };

type ExactEcdsaMaterialRecoveryResult =
  | {
      kind: "recovered";
      material: BoundReadyEcdsaSigningMaterial<RecoverableMpcMaterialUseState>;
    }
  | {
      kind: "already_ready";
      material: BoundReadyEcdsaSigningMaterial<RecoverableMpcMaterialUseState>;
    }
  | {
      kind: "requires_authorization";
      requirement: MpcMaterialUnlockAuthorizationRequirement;
    }
  | { kind: "unavailable" }
  | { kind: "rejected"; failure: EvmEcdsaPreparationFailure };

type EvmEcdsaPreparationPort = {
  selectExact(args: {
    request: EvmEcdsaTransactionSelectionRequest;
    authorityPolicy: WalletAuthoritySelectionPolicy;
  }): Promise<EvmEcdsaLaneSelectionResult>;
  resolveExact(
    lane: EvmEcdsaTransactionLane,
  ): Promise<EvmEcdsaSigningPreparation>;
  recoverExact(
    recovery: ExactEcdsaMaterialRecoveryAttempt,
  ): Promise<ExactEcdsaMaterialRecoveryResult>;
  authorize<Requirement extends EvmEcdsaAuthorizationRequirement>(
    requirement: Requirement,
  ): Promise<EvmEcdsaAuthorizationResultFor<Requirement>>;
};
```

Only boundary builders can create the branded authorization, claimed-use,
ready-material, committed-capability, unlock-authorization, recovery, and
replacement-lane types, as well as transaction-selection and operation-grant
requirements. They compare canonical material-owner keys, authority digests,
parsed transaction targets and intents, transaction envelopes, operation
digests, fingerprints, use state, and grant facts before construction. The EVM
operation-grant requirement proves its evidence plan names the same EVM
transaction operation and digest set as its envelope. `any_authority` with more
than one eligible exact authority returns a lane-selection
`authority_ambiguous` failure before an exact lane exists; selection never uses
diagnostics or factor-kind priority to break the tie.

Resolution first proves an active wallet authority and an authorized,
operation-bound active capability grant. It inspects signer material only after
those checks. `recovery_required` therefore contains a branded recovery
capability bound to the exact material owner, active authorization,
session-retained use state, and recovery binding digest. Inventory labels such
as `restorable` or `deferred` cannot construct it. Grant-use claim occurs after
preparation reaches `ready` and immediately before signing; failed material
recovery does not consume an operation use.

The recovery binding digest covers the exact material owner, authority ref,
canonical Phase 5 material binding, recovery ID, and authorized capability
operation. A transaction target is authorized by its own operation envelope;
recovery remains material-owner scoped so multiple authorized EVM-family targets
can share one restore safely.

Session-retained sealed material can recover. Pending single-use material is
ready only while hot and only for its bound operation fingerprint. Cold pending
single-use material requires threshold-session replacement; consumed
single-use material cannot become ready or recoverable. Recovery results never
construct authorization policy. They return a typed authorization requirement,
and the authorization boundary constructs any challenge or grant-evidence plan.
Successful material-unlock authorization returns an upgraded recovery attempt
bound to the original recovery ID and binding digest; the coordinator supplies
that attempt to `recoverExact`. Recovery can return only session-retained ready
material.

Operation authorization and material-unlock authorization are distinct. The
operation grant follows capability policy and may use any evidence set that
policy accepts. Material unlock is bound to the exact
`WalletAuthAuthorityRef`. Threshold-session replacement uses a reauthorization
anchor and returns a branded replacement lane correlated to that anchor; the
coordinator does not re-resolve an obsolete lane whose threshold-session
identity changed. The generic authorization result is conditional on requirement
kind, so an operation-grant request cannot return a replacement lane and a
material-unlock request cannot return an unrelated operation authorization.

The preparation coordinator executes each operation-bound authorization action
at most once per operation fingerprint and returns `no_progress_after_action`
if the same action repeats. Exact recovery is idempotent and singleflight by
material-owner identity key plus recovery ID, because EVM and Tempo operations
can concurrently reference the same material owner.

Factor-specific interaction and material-unlock protocols stay behind auth
factor and material adapters. WebAuthn assertion belongs to the Passkey factor
adapter; OTP challenge, resend, and code completion belong to the Email OTP
factor adapter. PRF-derived unlock, worker material, sealed restore, and
consumption belong to material adapters. Generic material and persistence types
own retention and use state. Persistence boundaries normalize current
cross-curve companion envelopes into separate exact Ed25519 and ECDSA recovery
references; one capability recovery cannot restore or commit the companion
capability as a hidden side effect. Generic EVM ECDSA selection, preparation,
restore coordination, and committed-lane construction contain no factor-kind
control flow.

`GrantEvidenceRequirement` is deliberately flat. `all` requires every named
evidence kind and `any` requires at least one. Evidence kinds are canonicalized
as a sorted unique nonempty set before persistence or evaluation. A real policy
that cannot be expressed by this model is the trigger for a separate policy-
language design; Refactor 90 does not add a recursive Boolean expression tree.
Assurance remains property-based, and the profile expiry cannot exceed the
earliest evidence/session expiry that supports it.

### MPC Signer Proof As Grant Evidence

> Follow-on context (July 22 scope amendment): the producer is undecided.
> Refactor 90 keeps `mpc_signer_proof` policy evaluation failing closed and
> implements no producer.

`mpc_signer_proof` is follow-on work. Refactor 90 does not add it to the closed
capability-operation or evidence unions and does not implement a producer.
Raw policies or requests that name it fail closed as unsupported. Its owning
capability, challenge binding, recursion policy, and evidence semantics require a
separate design before the leaf unions are intentionally extended.

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
  state: AdministrativeRecordState;
  createdByPrincipalId: PrincipalId;
  createdAt: IsoTimestamp;
};

type CapabilityBindingKind = "owner" | "admin" | "direct_member" | "delegate_member";

type CapabilityBinding = {
  tenantId: TenantId;
  bindingId: CapabilityBindingId;
  capabilityId: CapabilityId;
  principalId: PrincipalId;
  bindingKind: CapabilityBindingKind;
  state: AdministrativeRecordState;
  createdByPrincipalId: PrincipalId;
  createdAt: IsoTimestamp;
};
```

Capability modules own rich operation lane, intent, and display types. They
normalize parsed requests into a generic envelope before asking
`seams-authorization` for a grant. Requests never carry `CapabilityGrantPolicy`;
authorization resolves the policy server-side and records the selected
`policyId`.

```ts
declare const capabilityOperationEnvelopeBrand: unique symbol;

type CapabilityOperationEnvelope = {
  readonly [capabilityOperationEnvelopeBrand]: true;
  tenantId: TenantId;
  principalId: PrincipalId;
  capabilityId: CapabilityId;
  operation: CapabilityOperationRef;
  operationId: CapabilityOperationId;
  operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  operationDigests: OperationDigestSet;
};

type CapabilityGrantRecord = {
  tenantId: TenantId;
  principalId: PrincipalId;
  principalKind: PrincipalKind;
  grantId: CapabilityGrantId;
  capabilityId: CapabilityId;
  bindingId: CapabilityBindingId;
  operation: CapabilityOperationRef;
  operationDigests: OperationDigestSet;
  evidenceSetId: GrantEvidenceSetId;
  evidenceIds: NonEmptyArray<GrantEvidenceId>;
  evidenceSetDigest: DigestB64u;
  assurance: AssuranceProfile;
  policyId: PolicyId;
  createdAt: IsoTimestamp;
  expiresAt: IsoTimestamp;
};

type CapabilityGrant =
  | (CapabilityGrantRecord & {
      kind: "active";
      remainingUses: PositiveInt;
    })
  | (CapabilityGrantRecord & {
      kind: "consumed";
      consumedAt: IsoTimestamp;
    })
  | (CapabilityGrantRecord & {
      kind: "expired";
      expiredAt: IsoTimestamp;
    })
  | (CapabilityGrantRecord & {
      kind: "revoked";
      revokedAt: IsoTimestamp;
      revokedByPrincipalId: PrincipalId;
    });

type CompletedCapabilityGrantUseResult =
  | "succeeded"
  | "failed_before_side_effect"
  | "failed_after_side_effect";

type CapabilityOperationResultRef = {
  resultDigest: DigestB64u;
  resultStorageRef: CapabilityOperationResultStorageRef;
};

type CapabilityGrantUseBase = {
  tenantId: TenantId;
  useId: CapabilityGrantUseId;
  grantId: CapabilityGrantId;
  principalId: PrincipalId;
  evidenceSetDigest: DigestB64u;
  capabilityId: CapabilityId;
  operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  operation: CapabilityOperationRef;
  operationDigests: OperationDigestSet;
};

type CapabilityGrantUse =
  | (CapabilityGrantUseBase & {
      kind: "claimed";
      claimedAt: IsoTimestamp;
    })
  | (CapabilityGrantUseBase & {
      kind: "completed";
      result: CompletedCapabilityGrantUseResult;
      resultRef: CapabilityOperationResultRef;
      completedAt: IsoTimestamp;
    });

```

Grant-use consumption is one-way. Handlers must complete cheap boundary parsing,
route policy checks, capability lookup, and replay checks before consuming a
use. Once the operation crosses the consume boundary, a later vault, network,
signing, or downstream failure records a failed `capability_grant_uses` row and
does not refund the use. Repeating the same operation fingerprint returns its
recorded result. A deliberate retry uses a new operation ID/fingerprint and
requires a remaining use on the same grant or a fresh grant. This is the
intentional replacement for the old signing-budget reserve/commit/release
lifecycle.

`capability_grant_uses.result_kind` distinguishes at least `succeeded`,
`failed_before_side_effect`, and `failed_after_side_effect` so operators can
audit failed consumed attempts without reconstructing them from logs. Rejected
replay attempts that never claimed a use are authorization audit events, not
grant-use rows.

## Capability Boundaries

### `identity`

Owns tenant-scoped principals, auth accounts, provider-identity links, principal
lifecycle, and recovery-policy references. Human email addresses are verified
contact/provider-identity data; they are not required principal identity fields.

### `authFactor`

Owns `AuthFactorIdentity`, `AuthFactorRecord`, factor lifecycle, factor manifests,
and runtime-specific factor modules. It emits exact factor evidence containing
`factorId`; it does not mint sessions or capability grants.

### `session`

Owns provider-session normalization, device resolution, session audience
binding, `SeamsSession`, refresh-token families, hosted-wallet exchange codes,
and session lifecycle. It consumes verified provider/factor evidence and does
not mint capability grants.

### `seams-authorization`

Owns:

- grant evidence challenge selection;
- capability grant policies;
- generic operation envelopes;
- policy resolution from capability ID, operation kind, resource scope,
  principal binding, and grant evidence;
- short-lived capability grants;
- replay and grant-use accounting;
- audit envelopes.

Does not own:

- Better Auth storage schema;
- Better Auth route handlers;
- principal, factor, device, or session lifecycle;
- provider-specific session evidence parsing;
- capability-local operation lane, intent, or display structs;
- capability-local display rendering;
- vault item schema;
- secret unwrap or injection;
- MPC threshold sessions;
- signer WASM;
- HSS export;
- chain-specific transaction display.

### `capability-vault`

> Refactor 90 implements only the minimal proxy/reveal vertical from this
> section; the remaining vault product surface is follow-on context (July 22
> scope amendment).

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

### `capability-mpc-wallet-authority`

Owns wallet-auth authority records, authority refs/digests, factor-enrollment
binding, re-enrollment/revocation lifecycle, and the shared boundary consumed by
both MPC capabilities. It imports auth-factor identity types but no chain,
threshold runtime, signer WASM, HSS, or operation-lane code.

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

### `capability-idp-access`

> Follow-on context (July 22 scope amendment): not a Refactor 90 acceptance
> surface.

Owns the `idp_access` capability descriptor,
`idp.high_risk_scope.issue` operation envelope/display semantics, and default
grant policy. The `idp/` protocol module still owns relying-party registration,
authorization codes, token issuance, refresh, JWKS, and claim mapping. The IdP
module consumes an active `idp_access` grant only when the requested scope is
classified high risk.

## Lazy Loading Rules

Registration:

- Always create `AuthAccount`.
- Register auth providers and auth factor modules per tenant.
- Register IdP relying-party applications only for tenants with IdP mode
  enabled.
- Provision `idp_access` only for tenants that enable IdP mode; high-risk scope
  policies bind to that capability instance.
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

- Deployment assembly mounts route modules from the deployment capability set.
- Request admission verifies tenant auth-provider and capability enablement
  before invoking a deployed module.
- IdP handlers are compiled only into deployments that include `idp_access` and
  deny requests for tenants that have not enabled it.
- Route-level assembly imports only deployment-enabled capability handlers.
- Vault Worker paths cannot import signer WASM or HSS modules.
- IdP Worker paths cannot import vault or MPC capability modules.
- MPC Worker paths can import chain and threshold modules.
- Capability absence returns a typed authorization denial.

Source boundaries:

```text
identity/
  tenants
  principals
  authAccounts
  providerIdentities
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
  mpcWalletAuthority
  vault
  nearEd25519Mpc
  evmEcdsaMpc
  idpAccess
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

`identity/` owns tenants, principals, auth accounts, and provider identity
links.

`session/` owns `SeamsSession`, device/audience binding, refresh, hosted-wallet
exchange codes, and provider session normalization.

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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
)

auth_principals(
  namespace,
  tenant_id,
  principal_id,
  principal_kind,       -- human | agent | service_account | system
  lifecycle_kind,       -- invited | active | suspended | removed
  display_name,
  created_at_ms,
  updated_at_ms,
  invited_at_ms,
  activated_at_ms,
  suspended_at_ms,
  removed_at_ms
)

auth_principal_contacts(
  namespace,
  tenant_id,
  contact_id,
  principal_id,
  contact_kind,         -- email | phone
  contact_value_normalized,
  verification_kind,    -- unverified | provider_verified | seams_verified
  lifecycle_kind,
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
)

auth_factors(
  namespace,
  tenant_id,
  factor_id,
  principal_id,
  factor_kind,          -- passkey | email_otp | slack_otp | wallet_login | recovery_code
  factor_ref_json,      -- email_otp stores provider + providerUserId; email is display/profile metadata
  factor_identity_digest,
  lifecycle_kind,       -- active | suspended | revoked | replaced
  replacement_factor_id,
  created_at_ms,
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  revoked_at_ms,
  replaced_at_ms
)

tenant_auth_factor_enablements(
  namespace,
  tenant_id,
  factor_kind,
  config_digest,
  lifecycle_kind,       -- active | suspended | deleted
  created_at_ms,
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
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
  subject_kind,         -- provider_identity | auth_factor
  subject_ref_id,
  device_id,
  audience_kind,        -- first_party_web | hosted_wallet_iframe | api_client
  audience_json,
  audience_digest,
  assurance_profile_json,
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

hosted_wallet_session_exchange_codes(
  namespace,
  tenant_id,
  exchange_code_id,
  exchange_code_hash,
  source_session_id,
  target_session_id,
  app_origin,
  wallet_origin,
  nonce_digest,
  lifecycle_kind,       -- issued | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms,
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
  evidence_ref_kind,    -- session | auth_factor | provider | mpc_signer | api_credential | approval
  evidence_ref_id,
  api_credential_id,
  approval_id,
  lane_digest,
  intent_digest,
  display_digest,
  evidence_digest,
  assurance_profile_json,
  device_id,
  lifecycle_kind,       -- active | consumed | expired | revoked
  created_at_ms,
  expires_at_ms,
  consumed_at_ms,
  revoked_at_ms
)

grant_evidence_sets(
  namespace,
  tenant_id,
  evidence_set_id,
  principal_id,
  principal_kind,
  context_kind,         -- interactive_session | non_interactive
  session_id,
  device_id,
  capability_kind,
  operation_kind,
  lane_digest,
  intent_digest,
  display_digest,
  assurance_profile_json,
  evidence_set_digest,
  created_at_ms,
  expires_at_ms
)

grant_evidence_set_members(
  namespace,
  tenant_id,
  evidence_set_id,
  evidence_id,
  evidence_position,
  created_at_ms
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
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
  updated_at_ms,
  activated_at_ms,
  suspended_at_ms,
  deleted_at_ms
)

capability_grants(
  namespace,
  tenant_id,
  grant_id,
  grant_token_hash,
  principal_id,
  principal_kind,
  binding_id,
  evidence_set_id,
  evidence_set_digest,
  assurance_profile_json,
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
  consumed_at_ms,
  revoked_by_principal_id,
  revoked_at_ms
)

capability_grant_uses(
  namespace,
  tenant_id,
  use_id,
  grant_id,
  principal_id,
  operation_fingerprint_digest,
  evidence_set_digest,
  capability_kind,
  capability_id,
  operation_kind,
  lifecycle_kind,       -- claimed | completed
  result_kind,          -- pending | succeeded | failed_before_side_effect | failed_after_side_effect
  result_digest,
  result_ref_json,
  lane_digest,
  intent_digest,
  display_digest,
  created_at_ms,
  completed_at_ms
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

Required relational invariants:

- `factor_identity_digest` uses the canonical, domain-separated
  `seams:auth-factor-identity:v1` encoding of `AuthFactorIdentity`. Tenant scope
  is carried by the unique index; display email, RP configuration, and wallet
  binding data are excluded from the factor-identity preimage;
- provider subjects are unique by
  `(namespace, tenant_id, provider_id, provider_subject)`;
- active factor identities are unique by
  `(namespace, tenant_id, factor_identity_digest)` through a partial unique
  index; re-enrollment first transitions the prior factor to `replaced`, then
  creates the new active factor and records `replacement_factor_id` in one
  transaction;
- tenant auth-factor enablement is unique by
  `(namespace, tenant_id, factor_kind)`;
- session subject references, device IDs, capability bindings, evidence IDs,
  policy IDs, and capability IDs have tenant-scoped foreign keys;
- hosted-wallet exchange-code hashes are unique and can transition from
  `issued` to `consumed` only once;
- every persisted `(capability_kind, operation_kind)` pair satisfies the
  `CapabilityOperationKindByCapability` mapping. D1 uses an explicit CHECK
  constraint; other adapters must enforce an equivalent constraint;
- active capability-operation policy bindings are unique by
  `(namespace, tenant_id, capability_id, operation_kind)`;
- evidence-set membership is unique by both `(evidence_set_id, evidence_id)` and
  `(evidence_set_id, evidence_position)`;
- grant token hashes are unique, and grant records reference an immutable
  evidence set whose principal, operation, and digest facts match the grant;
- grant-use claims are unique by
  `(namespace, tenant_id, grant_id, operation_fingerprint_digest)`.
- lifecycle CHECK constraints correlate branch fields: active grants have a
  positive balance, consumed grants have zero balance and `consumed_at_ms`,
  revoked grants have revocation actor/time, claimed uses have `pending` with no
  result reference, and completed uses have a terminal result plus result
  digest/reference.

Atomic grant-use algorithm:

1. Parse the request into a `CapabilityOperationEnvelope`. The capability module
   computes `operationFingerprintDigest` from a versioned canonical preimage
   containing tenant, grant, capability, correlated operation, operation ID,
   and lane/intent/display digests.
2. In one transaction, insert a `claimed` grant-use row and decrement
   `remaining_uses` with a compare-and-swap that requires an active, unexpired
   grant with a positive balance and matching operation/digests. A failed CAS
   rolls back the claim and returns the typed exhausted/expired/mismatch result.
3. A duplicate fingerprint loads the existing row. A completed row returns its
   prior result as an idempotent replay; a claimed row returns
   `operation_in_progress`. Neither path consumes another use.
4. Different fingerprints consume independently and serialize through the same
   grant row. Once the claim transaction commits, downstream failure never
   refunds the use.
5. Completion transitions the use row from `claimed` to `completed` exactly
   once and records `succeeded`, `failed_before_side_effect`, or
   `failed_after_side_effect` plus an integrity-bound operation-result reference.
   Replay denial is written to the authorization audit log without another grant
   decrement. Idempotent retries return the result through that reference after
   validating its digest.

Every database adapter must pass the same concurrent-consumption conformance
suite. An adapter that cannot provide the claim-plus-decrement transaction
cannot implement capability grants.

`CapabilityOperationResultRef` points to capability-local idempotency state.
Vault plaintext, raw exported keys, bearer tokens, and unsealed signer material
never appear in `result_ref_json`; sensitive replayable results stay sealed or
are re-fetched through the capability's protected result store. Result
retention cannot outlive the grant-use audit retention without an explicit
capability policy.

Retention and abuse controls:

- Phase 10 adds expiry indexes for challenges, evidence rows, refresh tokens, and
  capability grants.
- Phase 12 owns a pruning job interface for expired grant challenges, expired or
  consumed grant evidence, expired grants, revoked refresh-token families after
  the retention window, and old audit-export scratch rows.
- Phase 11 and Phase 14 add rate-limit ports for session exchange, OTP challenge
  minting, WebAuthn grant-evidence challenge minting, and verification attempts.
  Phase 15 adds the same controls for service-account grant requests.
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
- ECDSA signer, Router A/B derivation, threshold-session, and export tables under
  `capability-evm-ecdsa-mpc`.
- Shared wallet-authority bindings used by both MPC capabilities have this
  logical shape:

```text
mpc_wallet_auth_authorities(
  namespace,
  tenant_id,
  wallet_id,
  wallet_auth_method_id,
  principal_id,
  factor_id,
  authority_digest,
  verifier_kind,
  verifier_ref_json,
  lifecycle_kind,       -- active | replaced | revoked
  replacement_wallet_auth_method_id,
  created_at_ms,
  updated_at_ms,
  replaced_at_ms,
  revoked_at_ms
)
```

Active wallet-authority bindings are unique by wallet and authority digest.
Signing-lane, sealed-session, recovery, export, and admission records reference
`wallet_auth_method_id` plus `authority_digest`; they never reconstruct an
authority from provider subjects or credential fields.

The ECDSA server adapter owns registered capability authority and the current
server generation. D1 and DO may divide durable registration facts from
threshold-session coordination internally, but their verified activation receipt
is one boundary result with this logical identity:

```text
mpc_ecdsa_capability_generations(
  namespace,
  tenant_id,
  capability_id,
  signer_id,
  wallet_id,
  wallet_auth_method_id,
  authority_digest,
  threshold_session_id,
  server_generation,
  lifecycle_kind,             -- active | expired | exhausted | revoked | replaced
  scope_digest,
  registered_public_key_digest,
  material_binding_digest,
  activation_correlation_id,
  activation_receipt,
  activated_at_ms,
  retired_at_ms
)
```

The active tuple is unique by namespace, tenant, capability, signer, and exact
authority. Activation and replacement are compare-and-swap operations over the
expected server generation and idempotent by `activation_correlation_id`.
Conflict, missing authority, retired authority, and unavailable server storage
are distinct boundary results. The server does not report browser material as
live or restorable.

Browser ECDSA persistence uses one capability database and one owning adapter
with these object stores:

```text
ecdsa_capability_manifests
  key: [capability_ref, authority_ref]
  value: ActiveEcdsaCapabilityManifest | RetiredEcdsaCapabilityManifest

ecdsa_role_local_material
  key: durable_material_ref
  value: {
    binding_digest,
    lifecycle_id,
    ciphertext_digest,
    activation_digest,
    activated_at,
    material_expires_at,
    iv,
    ciphertext
  }

ecdsa_activation_commit_journals
  key: journal_id
  value: EcdsaCapabilityActivationCommitJournal

ecdsa_material_sealing_keys
  key: key_id
  value: non_extractable CryptoKey
```

The encrypted material row, active manifest row, retirement of a replaced
manifest, and activation-journal deletion commit in one IndexedDB transaction.
The manifest's `durableMaterialRef`, binding digest, lifecycle ID, ciphertext
digest, activation digest, and expiry must equal the authenticated material
header parsed through the same adapter. A missing row is `missing`; a different
exact binding is `exact_binding_mismatch`; duplicate current manifests are
`exact_record_conflict`; invalid authenticated data is `corrupt`; I/O failure is
`persistence_unavailable`.

The activation journal is written before the first consuming server effect and
is reconciled before ordinary manifest discovery after reload. Its server receipt
advances monotonically. Runtime publication follows canonical durable state and
never participates in the IndexedDB transaction. An immediate post-commit read
may verify the high-value write through the same parser, but it is not durable
lifecycle state. Browser/worker memory cannot make a partially committed
manifest ready.

These records exclude operation grants, wallet quotas, nonce state, bearer
credentials, provider subjects, provenance source, diagnostics, and live worker
handles. Those domains join only after exact manifest and runtime resolution.
The migration rejects and clears obsolete ECDSA session-record stores at this
boundary. There is no dual-schema reader and no current-record selection by
timestamp or source priority.

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

Security invariants:

- factor identity is matching data; only an active `factorId` enrollment and,
  for MPC wallets, an active wallet-auth-method binding can authorize;
- provider login sessions normalize into audience/device-bound
  `SeamsSession`; they are never treated as digest-bound factor assertions;
- capability kind and operation kind are parsed as one correlated
  `CapabilityOperationRef`;
- grant policy receives only branded `CapabilityGrantRequest` values built from
  an active capability binding, exact operation envelope, and
  `VerifiedGrantEvidenceSet`;
- grant use is claimed and decremented atomically by canonical operation
  fingerprint; repeated fingerprints cannot repeat side effects or consume
  another use;
- deployment availability and tenant enablement are both required before a
  capability handler can execute.

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
