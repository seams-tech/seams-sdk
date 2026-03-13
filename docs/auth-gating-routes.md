# Auth Gating And Metering Plan For Server Routes And APIs

This document is the proposed source of truth for route-level auth policy across the relay server and console server surfaces.

It exists to answer three questions clearly:

- which auth plane applies to each route family
- which scopes or roles, if any, each route family should require
- which route families should be billed or metered

This plan intentionally separates console route access from machine API access auth. They are different systems and must stay different.

## Problem statement

The current route surface mixes three distinct concerns:

- console user access through console sessions and org RBAC
- machine access through publishable keys, secret keys, and bootstrap tokens
- end-user wallet access through app sessions, threshold sessions, and cryptographic protocol state

That split exists in code today, but it is not enforced consistently enough:

- the secret-key scope list is ahead of the actual machine route surface
- some console mutation routes are only session-gated and skip RBAC
- some low-level signing and protocol routes do not have an explicit documented reason for being auth-free
- adjacent wallet execution routes still need an explicit auth classification
- billing and metering policy is still implicit for some routes that can spend relayer funds

## Decision

We will adopt an explicit auth-plane model and classify every server route into exactly one primary auth plane, plus one explicit billing or metering stance.

Primary auth planes:

1. Console session + RBAC
2. Machine API key or bootstrap credential
3. End-user app or threshold session
4. Internal service-to-service or cryptographic proof route
5. Explicit public route

Rules:

- `/console/*` routes must never use API-key scopes.
- machine `/v1/*` or relay routes must never depend on console session cookies.
- low-level threshold protocol routes must not be retrofitted with console RBAC or generic API-key scopes.
- if backend wallet signing is needed, we add a dedicated machine endpoint rather than exposing low-level threshold protocol routes to secret keys.
- `/console/*` routes are auth-gated by team-member permissions and are never customer-billed.
- auth-free proof or protocol routes are allowed only when that is deliberate and documented.
- any route that can spend relayer funds must state whether it is metered.
- breaking changes are acceptable; we will remove stale scopes and stale auth paths instead of preserving them behind flags.

## Goals

- make route auth classification explicit and testable
- remove unused or misleading secret-key scopes
- close console mutation routes that are missing RBAC
- make wallet-signing and protocol route expectations explicit
- keep Express and Cloudflare behavior in parity where both exist
- leave no ambiguous side-effecting route without a documented auth gate
- leave no relayer-spending route without a documented billing or metering rule

## Non-goals

- preserving legacy scope names or legacy auth behavior for compatibility
- adding feature flags or shadow auth paths
- collapsing console RBAC and machine API scopes into one system
- exposing low-level MPC protocol routes directly as general-purpose machine APIs

## Canonical auth planes

### 1. Console session + RBAC

Use for human operators in the dashboard and console APIs.

Required properties:

- authenticated via console session claims
- org-scoped
- optionally role-gated by route family
- never authenticated by secret key or publishable key

Canonical entry points today:

- console auth parsing in `server/src/router/console.ts`
- `requireConsoleAuth()` and role helpers in `server/src/router/express/createConsoleRouter.ts`

### 2. Machine API key or bootstrap credential

Use for server-to-server or browser-to-relay API access.

Required properties:

- authenticated via publishable key, secret key, or explicit bootstrap token
- evaluated against environment, origin, IP allowlist, quota, or payment policy as appropriate
- scopes apply only here
- never used for `/console/*`

### 3. End-user app or threshold session

Use for authenticated user wallet operations.

Required properties:

- authenticated via `app_session_v1` or threshold session JWT
- bound to user identity and relayer/session state
- not interchangeable with machine API keys

### 4. Internal service-to-service or cryptographic proof route

Use for routes that are not console routes and are not general customer machine APIs.

Examples:

- internal smart-account provisioning hooks
- private worker or coordinator ingress
- explicit webhook ingress from trusted providers

Required properties:

- internal routes must not rely on path naming alone
- they must require an internal auth mechanism such as HMAC, mTLS, or signed one-time continuation tokens
- public cryptographic proof routes must document the proof that substitutes for a session

### 5. Explicit public route

Use only when a route is intentionally unauthenticated.

Examples:

- health
- readiness
- discovery
- login bootstrap or challenge issuance

Required properties:

- public status must be deliberate and documented
- the route must not cause privileged side effects unless it validates an explicit proof artifact

## Metering policy

Metering is independent from auth.

Rules:

- `/console/*` routes are never customer-billed or usage-metered for relay execution.
- high-level machine execution routes that can spend relayer funds must declare a billing or metering rule.
- low-level threshold protocol routes are not billed or metered directly at the route layer.
- public bootstrap, challenge, recovery, and passkey routes are not billed or metered unless we explicitly turn them into paid execution surfaces later.

## Architecture decisions

We should not keep adding one-off auth checks inside handlers.

The target architecture is:

- one declarative route-definition layer shared by Express and Cloudflare
- one central policy-enforcement layer that resolves auth, service dependencies, and metering
- thin transport adapters for Express and Cloudflare
- business handlers that receive a prevalidated route context instead of reading headers directly

### Decision 1: define routes as typed policy objects

Each route should be declared once as data, with path, auth plane, metering stance, and handler metadata.

Target files:

- `server/src/router/routeDefinitions.ts`
- `server/src/router/routeAuthPolicy.ts`
- `server/src/router/routeMeteringPolicy.ts`

Example:

```ts
export type RouteDefinition = {
  id: string;
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  auth: RouteAuthPolicy;
  metering: RouteMeteringPolicy;
  requiredServices?: RouteServiceKey[];
  handler: RouteHandler;
};

export type RouteAuthPolicy =
  | { plane: 'console'; roles?: ConsoleRouteRole[] }
  | {
      plane: 'machine';
      credentials: Array<'publishable_key' | 'secret_key' | 'bootstrap_token'>;
      scopes?: string[];
      environmentBinding?: 'required' | 'optional';
      originBinding?: 'required' | 'optional';
    }
  | { plane: 'app_session' }
  | { plane: 'threshold_session' }
  | {
      plane: 'public';
      proof?: 'webauthn' | 'threshold_protocol_state' | 'signed_payload';
      rationale: string;
    }
  | { plane: 'internal'; mechanism: 'hmac' | 'mtls' | 'signed_token' };

export type RouteMeteringPolicy =
  | { kind: 'none' }
  | { kind: 'event'; action: 'wallet_created' }
  | { kind: 'gas'; ledger: 'evm' | 'near_delegate' };
```

### Decision 2: handlers must receive resolved auth context, not parse auth themselves

Today some handlers do header parsing, auth branching, and metering inline. For example, `POST /registration/bootstrap` does that directly in [createAccountAndRegisterUser.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/createAccountAndRegisterUser.ts#L21). We should move that logic into a shared route executor.

Target files:

- `server/src/router/enforceRoutePolicy.ts`
- `server/src/router/routeExecutionContext.ts`

Example:

```ts
export type RoutePrincipal =
  | { kind: 'console'; claims: ConsoleAuthClaims }
  | { kind: 'machine'; principal: RelayApiKeyPrincipal }
  | { kind: 'app_session'; claims: SessionClaims }
  | { kind: 'threshold_session'; claims: ThresholdSessionClaims }
  | { kind: 'public' }
  | { kind: 'internal'; service: string };

export type RouteExecutionContext = {
  principal: RoutePrincipal;
  services: RouteServices;
  logger: NormalizedRouterLogger;
  headers: Record<string, string | string[] | undefined>;
  sourceIp?: string;
};

export type RouteHandler = (input: {
  request: RouteRequest;
  context: RouteExecutionContext;
}) => Promise<RouteResponse>;
```

Rule:

- route handlers may validate business inputs and proof payloads
- route handlers may not do primary auth-plane selection or direct header credential parsing

### Decision 3: compile the same route definition into both transports

Express and Cloudflare should not separately encode the auth decision for the same route family.

Target files:

- `server/src/router/express/registerExpressRoute.ts`
- `server/src/router/cloudflare/registerCloudflareRoute.ts`

Example:

```ts
export function registerExpressRoute(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
  def: RouteDefinition,
): void {
  router[def.method.toLowerCase() as 'get'](def.path, async (req, res) => {
    const execution = await enforceRoutePolicy({
      route: def,
      transport: 'express',
      headers: req.headers as Record<string, string | string[] | undefined>,
      body: req.body,
      ctx,
      sourceIp: req.ip,
    });
    if (!execution.ok) {
      res.status(execution.status).json(execution.body);
      return;
    }

    const response = await def.handler({
      request: execution.request,
      context: execution.context,
    });

    await applyRouteMetering({
      route: def,
      execution: execution.context,
      response,
    });

    res.status(response.status).json(response.body);
  });
}
```

### Decision 4: make metering a first-class post-handler hook

Metering should not be embedded ad hoc inside route bodies. It should run from a route policy so routes like `signedDelegatePath` can be billed consistently.

Today `POST /registration/bootstrap` records usage inline in [createAccountAndRegisterUser.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/createAccountAndRegisterUser.ts#L129). That should move behind a shared metering hook.

Target files:

- `server/src/router/applyRouteMetering.ts`
- `server/src/router/routeMeteringPolicy.ts`

Example:

```ts
await applyRouteMetering({
  route,
  execution,
  response,
  usage: {
    walletId: response.body.walletId,
    gasUsed: response.body.gasUsed,
    transactionHash: response.body.relayerTxHash,
  },
});
```

### Decision 5: route definitions should carry proof metadata for auth-free routes

For auth-free routes, the policy must still explain why they are safe.

That applies to:

- `/threshold-*/sign/*`
- `/threshold-*/internal/cosign/*`
- `/threshold-ed25519/keygen`
- `/session/exchange`
- `/wallet/unlock/*`

Example:

```ts
export const thresholdEcdsaSignInitRoute: RouteDefinition = {
  id: 'threshold_ecdsa_sign_init',
  method: 'POST',
  path: '/threshold-ecdsa/sign/init',
  auth: {
    plane: 'public',
    proof: 'threshold_protocol_state',
    rationale:
      'The protocol transcript, client share possession, and passkey-backed authorize flow are the effective gate.',
  },
  metering: { kind: 'none' },
  requiredServices: ['authService'],
  handler: handleThresholdEcdsaSignInit,
};
```

### Decision 6: console RBAC should be expressed as route policy, not scattered helper calls

We already have reusable helpers like `requireConsoleAuth()` in [createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts#L648). The next step is to move the RBAC requirement into the route definition and keep the helper inside the policy enforcer.

Example:

```ts
export const consoleApiKeysCreateRoute: RouteDefinition = {
  id: 'console_api_keys_create',
  method: 'POST',
  path: '/console/api-keys',
  auth: {
    plane: 'console',
    roles: ['owner', 'admin', 'security_admin'],
  },
  metering: { kind: 'none' },
  requiredServices: ['apiKeys', 'orgProjectEnv'],
  handler: handleConsoleApiKeysCreate,
};
```

### Decision 7: machine route policy should declare accepted credential types explicitly

This matters for routes like `POST /registration/bootstrap`, which currently branches between secret keys and bootstrap tokens inline.

Example:

```ts
export const registrationBootstrapRoute: RouteDefinition = {
  id: 'registration_bootstrap',
  method: 'POST',
  path: '/registration/bootstrap',
  auth: {
    plane: 'machine',
    credentials: ['secret_key', 'bootstrap_token'],
    scopes: ['accounts.create'],
    environmentBinding: 'required',
  },
  metering: { kind: 'event', action: 'wallet_created' },
  requiredServices: ['authService', 'apiKeyAuth', 'bootstrapTokenStore'],
  handler: handleRegistrationBootstrap,
};
```

### Decision 8: route inventory tests should derive from the definitions, not handwritten route lists

The route definition table should drive:

- auth policy validation
- metering validation
- Express registration
- Cloudflare registration
- parity tests

Rule:

- if a route exists in a transport but not in `routeDefinitions.ts`, that is a test failure

## Current route inventory and target gating and metering

### Console routes

All `/console/*` routes should be console-session authenticated unless they are an explicit health or provider-webhook exception.
All `/console/*` routes are unmetered and should follow the team-member permissions model.

Allowed unauthenticated exceptions:

- `/console/healthz`
- `/console/readyz`
- `/console/billing/stripe/webhook`

All other `/console/*` routes should remain in the console auth plane.

#### Target console RBAC matrix

| Route family | Target gate | Notes |
| --- | --- | --- |
| Account/session/profile/org context reads | Console session only | Human dashboard context reads |
| Onboarding telemetry reads | `admin` or `ops` | Already modeled |
| Org/project/environment mutation | `owner` or `admin` | Already modeled |
| Team member and RBAC mutation | `owner` or `admin` | Already modeled |
| Approval queue mutation | `owner`, `admin`, or `security_admin` | Already modeled |
| Policy mutation | `owner`, `admin`, or `security_admin` | Already modeled |
| API key mutation | `owner`, `admin`, or `security_admin` | Already modeled |
| Smart-wallet config mutation | `owner`, `admin`, or `security_admin` | Already modeled |
| Runtime snapshot publish | `owner`, `admin`, or `security_admin` | Already modeled |
| Webhook endpoint mutation and replay | `owner`, `admin`, or `security_admin` | Should use console config mutation guard or dedicated webhook guard |
| Observability reads | `owner`, `admin`, `security_admin`, `ops`, or `support` | Already modeled |
| Invoice generation | `admin` or `ops` | Already modeled |
| Billing adjustments | `admin` | Already modeled |
| Billing usage event writes | internal billing role, or remove from console plane | Current route is too open |
| Enterprise isolation actions | `owner` or `admin` | Already modeled |
| Key export approval | `admin` | Already modeled |
| Key export request creation | explicit decision required | Sensitive route; decide whether request creation is broad or privileged |

### Machine API routes

These are the routes that should use API-key auth or bootstrap credentials.

#### Current real machine routes

| Route | Target auth | Target scope | Notes |
| --- | --- | --- | --- |
| `POST /registration/bootstrap` | secret key or bootstrap token | `accounts.create` | Existing scoped secret-key route |
| `POST /v1/registration/bootstrap-grants` | publishable key | none | Capability is controlled by publishable key, origin, environment, quota, and payment policy |
| `POST /sponsorships/evm/call` | publishable key | none | Capability is controlled by publishable key, origin, environment, and active sponsorship policy |
| `POST <signedDelegatePath>` | publishable key | none | When configured, treat as an auth-gated relay execution route and meter based on exact gas used or equivalent relayer spend |

#### Planned machine routes if backend wallet APIs are needed

These do not all exist today. The point is to create explicit machine endpoints instead of abusing console routes or low-level protocol routes.

| Proposed route family | Target auth | Target scope | Notes |
| --- | --- | --- | --- |
| `POST /v1/accounts/sync` | secret key | `accounts.sync` | New machine route; do not map this scope to current `/sync-account/*` WebAuthn routes |
| `GET /v1/wallets` / `GET /v1/wallets/:id` | secret key | `wallets.read` | New machine read surface; do not map to `/console/wallets*` |
| `POST /v1/wallets/:id/sign` | secret key | `wallets.sign` | New high-level backend signing endpoint |
| `GET /v1/billing/*` | secret key | `billing.read` | Only if non-console machine billing reads are actually needed |

### End-user wallet and session routes

These should stay out of the machine API scope system.

#### App session routes

Use `app_session_v1`:

- `/auth/identities`
- `/auth/link`
- `/auth/unlink`
- `/near/public-keys`
- `/webauthn/authenticators`
- `/session/revoke`
- `/session/refresh`
- `/wallet/state`
- `/wallet/lock`

These are end-user session routes, not console routes and not secret-key routes.

#### Public proof or challenge routes

These can remain public only because they validate a challenge, attestation, or recovery proof:

- `/auth/passkey/*`
- `/email-recovery/prepare`
- `/session/exchange`
- `/wallet/unlock/challenge`
- `/wallet/unlock/verify`
- `/sync-account/options`
- `/sync-account/verify`
- `/threshold-ed25519/keygen`
- `/threshold-ed25519/session`
- `/threshold-ecdsa/bootstrap`

Required rule:

- every public route here must document the proof it validates and the side effects it can trigger
- these routes are auth-free and unmetered for now

#### Explicitly public operational ingress for now

These remain auth-free and unmetered for now even though they are not console routes and are not standard machine APIs:

- `/link-device/session`
- `/link-device/session/:sessionId`
- `/link-device/session/claim`
- `/link-device/prepare`
- `/recover-email`

Required rule:

- if these routes start incurring relayer gas or other billable execution cost later, revisit both auth and metering together

#### Threshold session routes

Use threshold session JWTs:

- `/threshold-ed25519/authorize`
- `/threshold-ecdsa/authorize`
- `/threshold-ecdsa/presign/init`
- `/threshold-ecdsa/presign/step`

These are part of end-user signing flows and must not use console RBAC or secret-key scopes.

### Low-level threshold continuation routes

These remain intentionally auth-free and unmetered.

Routes in this category:

- `/threshold-ed25519/sign/init`
- `/threshold-ed25519/sign/finalize`
- `/threshold-ed25519/internal/cosign/init`
- `/threshold-ed25519/internal/cosign/finalize`
- `/threshold-ecdsa/sign/init`
- `/threshold-ecdsa/sign/finalize`
- `/threshold-ecdsa/internal/cosign/init`
- `/threshold-ecdsa/internal/cosign/finalize`

Target policy:

- do not add console auth, generic API-key auth, or customer billing to these routes
- rely on threshold protocol state, client-share possession, passkey or assertion proofs, and session-bound transcripts as the effective gate
- document explicitly that the lack of route auth is intentional
- add validation coverage for replay, cross-session misuse, and malformed protocol state where the protocol itself is expected to reject the request
- if any route in this family later becomes truly internal-only, move it to a separate internal route family instead of relying on the current naming

### Adjacent wallet execution surfaces

These need explicit implementation work:

- `ctx.signedDelegatePath`
- `smartAccountDeploy` internal hook

Target policy:

- `ctx.signedDelegatePath` is a machine execution route, not a public proof route
- `ctx.signedDelegatePath` must be API-auth-gated and billed or metered based on actual gas used or equivalent relayer spend
- `ctx.signedDelegatePath` should not use console RBAC and does not need a machine scope unless we later expose a broader dedicated wallet execution API
- `smartAccountDeploy` remains internal-only and should be invoked from registration or provisioning flows, not exposed as a public route

## Scope taxonomy

We should clean up scope naming as part of this effort instead of preserving the current mixed format.

Target machine scope set:

- `accounts.create`
- `accounts.sync`
- `wallets.read`
- `wallets.sign`
- `billing.read`

Scopes to delete unless a real machine route is added:

- `sessions.refresh`

Rules:

- dot notation only
- no route may reference a scope that is not backed by a real machine endpoint
- no console route may mention a machine scope in docs, UI copy, or code

## Current gaps to fix first

1. Secret-key UI and storage advertise scopes that do not correspond to real machine routes.
2. Webhook endpoint mutation and replay routes are missing console RBAC.
3. Billing usage event writes are exposed as a generic console route instead of a privileged or internal route.
4. Low-level threshold continuation and cosign routes need explicit documentation and tests for their intentional auth-free, unmetered design.
5. Registration-triggered smart-account deployment for EVM and Tempo is not yet wired to the internal deploy hook.
6. Sensitive route families are classified by convention in code rather than by one explicit policy manifest.

## Implementation plan

### Phase 1. Create one canonical route definition and auth policy layer

Add a single source of truth for route classification and transport registration.

Deliverables:

- add `server/src/router/routeDefinitions.ts`
- add `server/src/router/routeAuthPolicy.ts`
- add `server/src/router/routeMeteringPolicy.ts`
- add `server/src/router/routeExecutionContext.ts`
- add `server/src/router/express/registerExpressRoute.ts`
- add `server/src/router/cloudflare/registerCloudflareRoute.ts`
- define each route family with:
  - route pattern
  - auth plane
  - required role or scope, if any
  - billing or metering stance
  - explicit public or internal designation
- add helpers or tests so Express and Cloudflare route implementations are checked against the policy

Required outcome:

- no new route may be added without a route definition entry

### Phase 2. Clean up machine scope taxonomy

Remove misleading secret-key scopes and align the UI with the real route surface.

Deliverables:

- update API key scope definitions in `examples/tatchi-site/src/pages/dashboard/routes/api-keys/page.tsx`
- update machine scope enforcement in:
  - `server/src/console/apiKeys/service.ts`
  - `server/src/console/apiKeys/postgres.ts`
  - `server/src/router/relay.ts`
- delete scope names that do not map to real machine routes
- convert colon-style scope names to dot notation

Required outcome:

- the scope picker only shows scopes that back real machine endpoints

### Phase 3. Fix console RBAC gaps

Close the current console mutation gaps.

Deliverables:

- gate webhook mutations and replay with `requireConsoleConfigMutationRole()` or a new dedicated helper
- reclassify `POST /console/billing/usage/events` as either:
  - an internal route outside `/console/*`, or
  - a console route with an explicit billing operator role guard
- make a deliberate decision on whether key export request creation is:
  - available to any console member, or
  - restricted to a security-oriented role

Files likely touched:

- `server/src/router/express/createConsoleRouter.ts`
- `server/src/router/cloudflare/createCloudflareConsoleRouter.ts` if matching console routes exist there
- related tests under `tests/relayer` and `tests/e2e`

Required outcome:

- no side-effecting console route is protected by session auth alone unless that is explicitly intended and documented
- no `/console/*` route is treated as billable machine traffic

### Phase 4. Document and validate low-level threshold routes

Make the auth-free protocol model explicit instead of retrofitting generic route auth onto it.

Deliverables:

- document that `sign/init`, `sign/finalize`, and `internal/cosign/*` are intentionally auth-free and unmetered
- document which threshold routes are:
  - public proof/bootstrap routes
  - threshold-session routes
  - low-level protocol continuation routes
- add replay, malformed-state, and cross-session misuse tests
- remove or rename misleading route comments if they imply an auth boundary that does not exist

Required outcome:

- low-level threshold routes have an explicit documented reason for being auth-free

### Phase 5. Add explicit high-level machine wallet APIs if needed

If backend systems need wallet reads or signing, create dedicated machine endpoints instead of reusing console or threshold routes.

Deliverables:

- define route shapes under `/v1/*`
- bind them to secret-key scopes
- keep all policy evaluation, auditability, and environment checks at the high-level route

Possible endpoints:

- `POST /v1/accounts/sync`
- `GET /v1/wallets`
- `GET /v1/wallets/:id`
- `POST /v1/wallets/:id/sign`
- `GET /v1/billing/*`

Required outcome:

- machine capabilities are explicit and narrow

### Phase 6. Implement adjacent wallet execution route policy

Finish the auth story for the remaining ambiguous wallet-adjacent routes.

Deliverables:

- gate `signedDelegatePath` with relay API auth
- meter `signedDelegatePath` based on exact gas used or equivalent relayer spend
- decide whether `signedDelegatePath` uses publishable-key policy only or additionally supports another non-console API credential
- decide where registration or provisioning invokes the internal `smartAccountDeploy` hook for EVM and Tempo chains
- document the chosen route policy and add route tests

Required outcome:

- there are no privileged wallet execution routes with an implicit or undocumented auth story

### Phase 7. Add policy tests and regression coverage

The auth policy should be enforced by tests, not memory.

Deliverables:

- route-policy tests that enumerate registered routes and assert:
  - all routes are classified
  - all `/console/*` routes are console-authenticated except explicit exceptions
  - all console mutation routes have an RBAC helper unless explicitly allowed
  - only machine routes use scopes
  - public routes are intentionally allowlisted
- Express and Cloudflare parity tests where both surfaces exist

### Phase 8. Update docs and delete stale auth language

Remove stale documentation and misleading UI copy.

Deliverables:

- update `docs/saas/api-keys.md`
- update any dashboard copy that still describes console APIs as machine-scope targets
- update auth comments in route files
- delete legacy scope names and route comments once the new model lands

Required outcome:

- the code, docs, and UI all describe the same auth model

## Phased Todo List

### Phase 1: Route definition and policy layer

- [x] Add `server/src/router/routeDefinitions.ts`.
- [x] Add `server/src/router/routeAuthPolicy.ts`.
- [x] Add `server/src/router/routeMeteringPolicy.ts`.
- [x] Add `server/src/router/routeExecutionContext.ts`.
- [x] Add `server/src/router/relayRouteSurface.ts`.
- [x] Add `server/src/router/express/registerExpressRoute.ts`.
- [x] Add `server/src/router/cloudflare/registerCloudflareRoute.ts`.
- [x] Enumerate every route family with one primary auth plane.
- [x] Mark every route family as console, machine, end-user session, internal, or explicit public.
- [x] Record required role, scope, proof type, billing stance, or explicit exception for each route family.
- [x] Add a guardrail test so new routes cannot land without a policy entry.

### Phase 2: Machine scope cleanup

- [x] Remove secret-key scope options that do not back real machine endpoints.
- [x] Rename colon-style scopes to dot notation.
- [x] Keep `accounts.create` for `POST /registration/bootstrap`.
- [x] Delete `sessions.refresh` from machine scopes unless a real machine route is added for it.
- [x] Update API key docs and dashboard copy to reflect the reduced scope set.

### Phase 3: Console RBAC hardening

- [x] Gate webhook create, update, delete, and replay behind a console mutation role.
- [x] Reclassify `POST /console/billing/usage/events` as internal-only or add an explicit billing operator role guard.
- [x] Decide whether key export request creation is broad or privileged.
- [x] Audit remaining side-effecting `/console/*` routes for session-only protection.
- [x] Add regression coverage for every fixed console RBAC gap.
- [ ] Confirm `/console/*` routes stay unmetered and do not emit customer billing usage.

### Phase 4: Threshold route documentation and validation

- [x] Document `/threshold-*/sign/*` and `/threshold-*/internal/cosign/*` as intentionally auth-free protocol routes.
- [x] Document which threshold routes are public proof routes, threshold-session routes, and low-level continuation routes.
- [ ] Add replay and malformed-state coverage for low-level signing continuations.
- [ ] Add cross-session misuse coverage for cosign and continuation routes.
- [ ] Remove or rewrite misleading comments that imply an internal auth boundary where none exists.

### Phase 5: High-level machine wallet APIs

- [ ] Decide whether backend wallet read APIs are a supported product surface.
- [ ] Decide whether backend signing by secret key is a supported product surface.
- [ ] If yes, add explicit `/v1/*` machine endpoints instead of reusing console or threshold routes.
- [ ] Bind new machine wallet routes to `wallets.read`, `wallets.sign`, and any needed account or billing scopes.
- [ ] Add audit and policy enforcement at the high-level machine route, not only inside the MPC protocol.

### Phase 6: Adjacent wallet execution route policy

- [x] Gate `signedDelegatePath` with non-console API auth.
- [ ] Meter `signedDelegatePath` on actual gas used or equivalent relayer spend.
- [ ] Decide whether `signedDelegatePath` stays publishable-key-only or also supports another API credential model.
- [ ] Wire EVM and Tempo registration or provisioning flows to the internal `smartAccountDeploy` hook.
- [ ] Document the chosen auth and metering policy for each adjacent execution route.
- [ ] Move any privileged route that lacks a real proof behind a stronger auth plane.
- [ ] Add route-level tests for the chosen classification.

### Phase 7: Route-policy tests and parity coverage

- [x] Add route-policy tests that enumerate registered Express routes.
- [x] Assert that all `/console/*` routes are console-authenticated except explicit allowlisted exceptions.
- [ ] Assert that only machine routes reference scopes.
- [ ] Assert that public routes are intentionally allowlisted.
- [x] Add Cloudflare parity coverage for shared route families.

### Phase 8: Docs and legacy cleanup

- [x] Update `docs/saas/api-keys.md` to match the new auth model.
- [x] Remove stale dashboard copy that describes console APIs as machine-scope targets.
- [ ] Remove stale route comments and legacy scope references from server code.
- [x] Delete tests that assert obsolete scope names or obsolete route auth behavior.
- [ ] Re-read the route surface after cleanup and confirm the docs still match reality.

## Detailed Todo Breakdown

### Phase 1 detailed tasks: Route definition and policy layer

- [x] Add `RouteMethod`, `RouteDefinition`, `RouteAuthPolicy`, `RouteMeteringPolicy`, `RoutePrincipal`, and `RouteServiceKey` types.
- [x] Add a `defineRoute()` helper that validates route IDs, methods, and policy shape at definition time.
- [x] Add a route registry for relay routes and a separate route registry for console routes.
- [ ] Give every route family a stable `id` so tests and metering can reference it without depending on a path string.
- [x] Support configured paths such as `signedDelegatePath` without making route IDs dynamic.
- [x] Add `requiredServices` to route definitions so missing runtime dependencies return a standard `501` response.
- [x] Add a shared `RouteExecutionContext` type that is transport-agnostic.
- [x] Add a shared relay route-surface resolver so Express and Cloudflare derive the same configured route definitions.
- [x] Attach configured relay route definitions to the live Express and Cloudflare router factories.
- [x] Add a shared route-response shape so Express and Cloudflare return the same auth and missing-service errors.
- [x] Migrate `POST /registration/bootstrap` to a shared route handler that uses `enforceRoutePolicy()` and `applyRouteMetering()`.
- [x] Migrate `POST /v1/registration/bootstrap-grants` to a shared route handler that uses route definitions and shared publishable-key policy enforcement.
- [x] Add a uniqueness test for route IDs and a completeness test for route definitions.

### Phase 2 detailed tasks: Machine scope cleanup

- [x] Update the API key dashboard scope picker to read from the canonical machine scope list instead of a local ad hoc array.
- [x] Rename any remaining colon-style scope names in server code, tests, fixtures, and docs.
- [x] Remove dead scopes from the persisted API key model and scope validators.
- [x] Update machine route definitions to reference only real scopes.
- [x] Confirm `accounts.create` remains the only currently enforced secret-key scope unless new machine routes land.
- [x] Add tests that fail if a machine route references an unknown scope.
- [x] Add tests that fail if a listed scope does not map to any machine route definition.
- [x] Tighten API key services, relay auth types, and persisted scope parsing so secret-key scopes are canonical `MachineApiKeyScope[]` end-to-end.

### Phase 3 detailed tasks: Console RBAC hardening

- [x] Convert webhook create, update, delete, and replay routes to policy-defined console roles.
- [x] Move `POST /console/billing/usage/events` behind an explicit internal or operator-only policy.
- [x] Decide and encode policy for key export request creation.
- [x] Convert onboarding organization and project setup routes to policy-defined console roles.
- [x] Convert org/project/environment mutation routes to policy-defined console roles.
- [x] Convert team member mutation routes to policy-defined console roles.
- [x] Convert approval queue mutation routes to policy-defined console roles.
- [x] Convert policy create, update, assignment, and publish routes to policy-defined console roles.
- [x] Convert audit export creation and enterprise isolation trigger routes to policy-defined console roles.
- [x] Convert invoice generation and platform billing adjustment routes to policy-defined console roles.
- [ ] Audit console read routes that may need dedicated read roles instead of membership-only access.
- [ ] Centralize console role-to-response mapping so authorization failures are uniform.
- [x] Remove inline role checks from migrated console handlers once the route policy enforcer owns them.
- [x] Move onboarding telemetry and observability read-role checks onto the shared console route policy layer.
- [x] Move account settings routes and policy simulation onto the shared console route policy layer with explicit route definitions.
- [x] Move ops cockpit summary and Stripe checkout/reconcile routes onto the shared console route policy layer with explicit route definitions.
- [x] Add regression tests for webhook RBAC, billing write gating, and key export request creation.
- [x] Redesign export governance to use current key export request entities instead of legacy API-key scope heuristics.

### Phase 4 detailed tasks: Threshold route documentation and validation

- [x] Add route definitions for every threshold route, including explicit `public` proof metadata for auth-free continuations.
- [x] Document the proof rationale for `/threshold-*/sign/*` and `/threshold-*/internal/cosign/*` in the route definition itself.
- [x] Ensure threshold continuation routes declare `metering: { kind: 'none' }`.
- [ ] Add protocol misuse tests for replay, wrong-session continuation, and malformed transcript input.
- [ ] Remove comments or helper names that imply internal auth where the route is intentionally public.
- [ ] Add tests that fail if any threshold continuation route accidentally gets machine scope or console auth attached.

### Phase 5 detailed tasks: High-level machine wallet APIs

- [ ] Decide whether `wallets.read` should exist in the product surface.
- [ ] Decide whether `wallets.sign` should exist in the product surface.
- [ ] If yes, add route definitions, request schemas, response schemas, and metering policy for each new `/v1/*` wallet route.
- [ ] Add audit-event emission for every high-level machine wallet mutation route.
- [ ] Ensure high-level wallet routes call into application services instead of exposing low-level MPC steps directly.
- [ ] Add tests for scope enforcement, environment binding, IP/origin rules where applicable, and audit emission.

### Phase 6 detailed tasks: Adjacent wallet execution route policy

- [x] Add a route definition for `signedDelegatePath` with `machine` auth and `gas` metering.
- [x] Route `signedDelegatePath` through shared publishable-key auth enforcement in both Express and Cloudflare.
- [ ] Decide whether `signedDelegatePath` accepts only publishable keys or also a second API credential type.
- [ ] Add a reusable gas-metering abstraction that can record both `evm_call` and `near_delegate` spend.
- [ ] Ensure `signedDelegatePath` emits consistent billing records even for reverted or partially failed execution.
- [ ] Wire EVM and Tempo account registration or provisioning flows to the internal `smartAccountDeploy` hook.
- [ ] Keep `smartAccountDeploy` out of the public route registry entirely.
- [x] Add Express and Cloudflare parity tests for `signedDelegatePath` auth behavior.
- [ ] Extend `signedDelegatePath` parity tests to cover gas metering behavior.

### Phase 7 detailed tasks: Route-policy tests and parity coverage

- [x] Add a test that enumerates the Express router and fails if any route lacks a definition entry.
- [x] Add a seeded console-route-surface guardrail that asserts policy-defined `/console/*` routes stay `plane: 'console'` and `metering: { kind: 'none' }`.
- [x] Add a matching Cloudflare test for shared route families.
- [x] Add a test that every `/console/*` route resolves to `console` auth except explicit allowlisted exceptions.
- [x] Add a test that every non-allowlisted live `/console/*` route has `metering: { kind: 'none' }`.
- [x] Add canonical route definitions for stable console read surfaces to shrink the live exception allowlist.
- [x] Add canonical route definitions for account settings and policy simulation to keep the live exception allowlist focused on truly special-case routes.
- [x] Reduce the live console exception allowlist to only health probes and the Stripe webhook ingress.
- [x] Add a test that every `machine` route declares accepted credential types.
- [x] Add a test that every `public` route includes proof metadata or explicit rationale.
- [x] Add a test that every route definition points only to declared `requiredServices`.

### Phase 8 detailed tasks: Docs and legacy cleanup

- [ ] Update docs to describe route definitions as the canonical source of auth policy.
- [ ] Remove stale comments that instruct developers to add auth inside handlers.
- [ ] Delete direct per-handler header parsing where the route executor now resolves auth.
- [x] Delete transport-specific publishable-key parsing and auth duplication from `POST /v1/registration/bootstrap-grants`.
- [x] Delete transport-specific auth duplication from `POST <signedDelegatePath>`.
- [ ] Delete transport-specific auth duplication that is replaced by shared route definitions.
- [ ] Re-run the route inventory after cleanup and confirm there are no orphaned route modules.
- [ ] Reconcile examples in docs with the final file names and type names used in the implementation.

## Validation checklist

- every route has a canonical route definition entry
- every console mutation route has a role gate or an explicit exception
- every secret-key scope maps to at least one real machine endpoint
- no console route references machine scopes
- no machine route depends on console session cookies
- no billable route is missing an explicit billing or metering rule
- wallet-signing continuation routes reject replay or malformed-state cases expected by the protocol
- `/console/*` routes remain unmetered
- Express and Cloudflare behavior match for shared route families

## Recommended implementation order

1. Phase 1: route definition and policy layer
2. Phase 3: console RBAC gaps
3. Phase 2: machine scope cleanup
4. Phase 4: low-level threshold route documentation and validation
5. Phase 6: implement adjacent wallet execution route policy
6. Phase 5: add high-level machine wallet APIs if needed
7. Phase 7 and Phase 8: tests and docs cleanup

## Open decisions

These need explicit product and security decisions during implementation:

- should key export request creation be broad or privileged
- should billing usage event ingestion be a console route at all
- do we want backend wallet signing as a supported machine capability
- if backend wallet signing is supported, what policy and audit model must sit above the MPC protocol
- should `signedDelegatePath` be publishable-key-only or accept an additional non-console API credential
- where should EVM and Tempo registration trigger the internal `smartAccountDeploy` hook

## Progress tracker

- [ ] Phase 1 complete
- [ ] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete
- [ ] Phase 7 complete
- [ ] Phase 8 complete
