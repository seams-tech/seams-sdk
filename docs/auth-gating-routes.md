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
2. API credential
3. End-user app session
4. Threshold signing session
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

### 2. API credential

Use for server-to-server or browser-to-relay API access.

Required properties:

- authenticated via publishable key, secret key, or explicit bootstrap token
- evaluated against environment, origin, IP allowlist, quota, or payment policy as appropriate
- scopes apply only here
- never used for `/console/*`

### 3. End-user app session

Use for authenticated user wallet operations.

Required properties:

- authenticated via `app_session_v1`
- bound to user identity and relayer/session state
- not interchangeable with API credentials

### 4. Threshold signing session

Use for threshold authorization and continuation routes that are authenticated by threshold session claims.

- authenticated via threshold session JWTs or equivalent threshold signing session claims
- scoped to the threshold signing flow, not reused as a general user session

### 5. Explicit public route

Use only when a route is intentionally unauthenticated.

Examples:

- health
- readiness
- discovery
- login bootstrap or challenge issuance

Required properties:

- public status must be deliberate and documented
- proof-gated public routes must record the proof type that substitutes for a session
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
- shared route handlers and auth helpers that receive a prevalidated route context instead of re-parsing credentials in each transport

### Decision 1: define routes as typed policy objects

Each route should be declared once as data, with path, auth plane, metering stance, required services, and a human-readable summary.

Target files:

- `server/src/router/routeDefinitions.ts`
- `server/src/router/routeAuthPolicy.ts`
- `server/src/router/routeMeteringPolicy.ts`

Example:

```ts
export interface RouteDefinition {
  id: string;
  surface: 'console' | 'relay';
  method: RouteMethod;
  path: string;
  aliases?: readonly string[];
  auth: RouteAuthPolicy;
  metering: RouteMeteringPolicy;
  requiredServices?: readonly RouteServiceKey[];
  summary: string;
}

export type RouteAuthPolicy =
  | { plane: 'console'; roles?: ConsoleRouteRole[] }
  | {
      plane: 'api_credentials';
      credentials: ApiCredentialType[];
      scopes?: ApiCredentialRouteScope[];
      environmentBinding?: 'required' | 'optional';
      originBinding?: 'required' | 'optional';
      ipBinding?: 'required' | 'optional';
    }
  | { plane: 'user_session' }
  | { plane: 'threshold_session'; scheme?: 'any' | 'ecdsa' | 'ed25519' }
  | {
      plane: 'public';
      proof?: PublicProofType;
      rationale: string;
    };

export type RouteMeteringPolicy =
  | { kind: 'none' }
  | { kind: 'event'; action: 'wallet_created' }
  | { kind: 'gas'; ledger: 'evm' | 'near_delegate' };

const registrationBootstrapRoute = defineRoute({
  id: 'registration_bootstrap',
  surface: 'relay',
  method: 'POST',
  path: '/registration/bootstrap',
  summary: 'Create and register a user account',
  auth: {
    plane: 'api_credentials',
    credentials: ['secret_key', 'bootstrap_token'],
    scopes: ['accounts.create'],
    environmentBinding: 'required',
  },
  metering: { kind: 'event', action: 'wallet_created' },
  requiredServices: ['authService'],
});
```

### Decision 2: handlers must receive resolved auth context, not parse auth themselves

The transport wrappers should not each parse `Authorization`, environment headers, or origin/auth binding rules. Shared helpers like [relayApiCredentialAuth.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiCredentialAuth.ts) should own that once per auth plane, and the business handler should consume the resolved principal.

Target files:

- `server/src/router/enforceRoutePolicy.ts`
- `server/src/router/routeExecutionContext.ts`

Example:

```ts
export type RoutePrincipal =
  | { kind: 'console'; claims: ConsoleAuthClaims }
  | {
      kind: 'api_credentials';
      principal: RelayApiKeyPrincipal;
      credentialType: ApiCredentialType;
    }
  | { kind: 'user_session'; claims: SessionClaims }
  | { kind: 'threshold_session'; claims: ThresholdSessionClaims }
  | { kind: 'public' };

export interface RouteExecutionContext<TServices extends RouteServices = RouteServices> {
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  principal: RoutePrincipal;
  services: TServices;
  sourceIp?: string;
}

const resolved = await enforceRoutePolicy({
  headers,
  logger,
  request: { body, headers },
  route,
  services,
  resolvers: {
    apiCredentials: async () =>
      await resolvePublishableKeyApiCredentialAuth({
        environmentId,
        headers,
        origin,
        publishableKeyAuth,
        route,
        missingEnvironmentMessage: 'Environment header is required',
        missingOriginMessage: 'Origin header is required',
        missingPublishableKeyMessage: 'Missing publishable key',
        routeAuthNotConfiguredMessage: 'Route requires API credential auth policy',
      }),
  },
});
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
registerExpressRoute({
  router,
  route,
  context: ctx,
  handler: async ({ context, req, res, route }) => {
    const response = await handleRelayBootstrapGrant({
      body: req.body,
      headers: req.headers as Record<string, string | string[] | undefined>,
      logger: context.logger,
      origin: String(req.headers.origin || '').trim() || undefined,
      route,
      services: {
        bootstrapGrantBroker: context.opts.bootstrapGrantBroker,
      },
    });
    sendExpressRouteResponse(res, response);
  },
});

const handleBootstrapGrant = registerCloudflareRoute(route, async ({ context, route }) => {
  if (context.method !== route.method || context.pathname !== route.path) return null;
  const response = await handleRelayBootstrapGrant({
    body: await readJson(context.request),
    headers: Object.fromEntries(context.request.headers.entries()),
    logger: context.logger,
    origin: String(context.request.headers.get('origin') || '').trim() || undefined,
    route,
    services: {
      bootstrapGrantBroker: context.opts.bootstrapGrantBroker,
    },
  });
  return toFetchRouteResponse(response);
});
```

### Decision 4: make metering a first-class post-handler hook

Metering should not be embedded ad hoc inside route bodies. It should run from a route policy so routes like `signedDelegatePath` can be billed consistently.

The route handler can attach usage metadata, and the post-handler metering layer can dispatch to the right event or gas ledger recorder.

Target files:

- `server/src/router/applyRouteMetering.ts`
- `server/src/router/routeMeteringPolicy.ts`

Example:

```ts
await applyRouteMetering({
  route,
  context,
  response,
  handlers: {
    event: async ({ action, context, response, route }) => {
      if (action !== 'wallet_created') return;
      await usageMeter.recordEvent({
        orgId: context.principal.principal.orgId,
        environmentId: context.principal.principal.environmentId,
        apiKeyId: context.principal.principal.apiKeyId,
        endpoint: `${route.method} ${route.path}`,
        walletId: String(response.usage?.walletId || ''),
        action: 'wallet_created',
      });
    },
  },
});
```

### Decision 5: route definitions should carry proof metadata for auth-free routes

For auth-free routes, the policy must still explain why they are safe.

That applies to:

- `/threshold-*/sign/*`
- `/threshold-*/internal/cosign/*`
- `/threshold-ed25519/session`
- `/threshold-ed25519/hss/*`
- `/registration/threshold-ed25519/hss/*`
- `/session/exchange`
- `/wallet/unlock/*`

Example:

```ts
const thresholdEcdsaSignInitRoute = defineRoute({
  id: 'threshold_ecdsa_sign_init',
  surface: 'relay',
  method: 'POST',
  path: '/threshold-ecdsa/sign/init',
  summary: 'Begin threshold ECDSA signing continuation',
  auth: {
    plane: 'public',
    proof: 'threshold_protocol_state',
    rationale:
      'The protocol transcript, client share possession, and passkey-backed authorize flow are the effective gate.',
  },
  metering: { kind: 'none' },
  requiredServices: ['authService'],
});
```

### Decision 6: console RBAC should be expressed as route policy, not scattered helper calls

We already have reusable helpers like `requireConsoleAuth()` in [createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts#L648). The next step is to move the RBAC requirement into the route definition and keep the helper inside the policy enforcer.

Example:

```ts
const consoleApiKeysCreateRoute = defineRoute({
  id: 'console_api_keys_create',
  surface: 'console',
  method: 'POST',
  path: '/console/api-keys',
  summary: 'Create a console API key',
  auth: {
    plane: 'console',
    roles: ['owner', 'admin', 'security_admin'],
  },
  metering: { kind: 'none' },
  requiredServices: ['apiKeys'],
});
```

### Decision 7: API credential route policy should declare accepted credential types explicitly

This matters for routes like `POST /registration/bootstrap`, which currently branches between secret keys and bootstrap tokens inline.

Example:

```ts
const registrationBootstrapRoute = defineRoute({
  id: 'registration_bootstrap',
  surface: 'relay',
  method: 'POST',
  path: '/registration/bootstrap',
  summary: 'Create and register a user account',
  auth: {
    plane: 'api_credentials',
    credentials: ['secret_key', 'bootstrap_token'],
    scopes: ['accounts.create'],
    environmentBinding: 'required',
  },
  metering: { kind: 'event', action: 'wallet_created' },
  requiredServices: ['authService'],
});
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

### Current route access matrix

| Route family                            | Representative routes                                                                                                                                                                  | Auth plane          | Gate                                                                                  | Metering | Current stance                                                                       |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------ |
| Relay diagnostics and discovery         | `GET /healthz`, `GET /readyz`, `GET /.well-known/webauthn`, threshold health probes                                                                                                    | `public`            | intentionally open                                                                    | none     | correct                                                                              |
| Public proof bootstrap routes           | `POST /auth/:provider/:action`, `POST /session/exchange`, `POST /wallet/unlock/*`, `POST /sync-account/*`, `POST /threshold-ed25519/session`, `POST /threshold-ecdsa/hss/*`            | `public`            | cryptographic proof, challenge, or attestation inside the flow                        | none     | correct                                                                              |
| Public operational ingress              | `GET/POST /link-device/session*`, `POST /link-device/prepare`, `POST /recover-email`                                                                                                   | `public`            | intentionally auth-free for now                                                       | none     | acceptable for now; later review if they start consuming gas or privileged resources |
| End-user session routes                 | `/auth/identities`, `/auth/link`, `/auth/unlink`, `/near/public-keys`, `/webauthn/authenticators`, `/session/revoke`, `/session/refresh`, `/wallet/state`, `/wallet/lock`              | `user_session`      | authenticated end-user app session                                                    | none     | correct                                                                              |
| Threshold-session routes                | `/threshold-ed25519/authorize`, `/threshold-ed25519/hss/*`, `/threshold-ecdsa/authorize`, `/threshold-ecdsa/presign/*`                                                                 | `threshold_session` | threshold session claims                                                              | none     | correct                                                                              |
| Low-level threshold continuation routes | `/threshold-*/sign/*`, `/threshold-*/internal/cosign/*`                                                                                                                                | `public`            | protocol state, client-share possession, passkey/assertion proofs, transcript binding | none     | intentionally auth-free; keep proof-gated, not route-auth-gated                      |
| Registration bootstrap                  | `POST /registration/bootstrap`                                                                                                                                                         | `api_credentials`   | `secret_key` with `accounts.create`, or `bootstrap_token`                             | event    | correct                                                                              |
| Registration bootstrap HSS sidecars     | `POST /registration/threshold-ed25519/hss/*`                                                                                                                                           | `api_credentials`   | `secret_key` with `accounts.create`, or `bootstrap_token`                             | none     | correct                                                                              |
| Publishable bootstrap grants            | `POST /v1/registration/bootstrap-grants`                                                                                                                                               | `api_credentials`   | `publishable_key` plus origin and environment binding                                 | none     | correct                                                                              |
| API wallet reads                        | `GET /v1/wallets`, `GET /v1/wallets/search`, `GET /v1/wallets/:id`                                                                                                                     | `api_credentials`   | `secret_key` with `wallets.read`                                                      | none     | correct                                                                              |
| Relay execution spending routes         | `POST /sponsorships/evm/call`, `POST <signedDelegatePath>`                                                                                                                             | `api_credentials`   | `publishable_key` plus origin and environment binding                                 | gas      | correct                                                                              |
| Console public exceptions               | `/console/healthz`, `/console/readyz`, `/console/billing/stripe/webhook`                                                                                                               | `public`            | explicit exception                                                                    | none     | correct                                                                              |
| Console context and account routes      | `/console/session`, `/console/account/*`, `/console/org`, `/console/projects`, `/console/environments`                                                                                 | `console`           | console session                                                                       | none     | correct                                                                              |
| Console reads with role gates           | ops cockpit, audit, wallets, observability, billing reads                                                                                                                              | `console`           | console session plus role requirements                                                | none     | correct                                                                              |
| Console mutations with role gates       | onboarding create, project/environment mutation, members, approvals, policies, webhooks, API keys, runtime snapshots, smart-wallet config, key exports, billing writes and adjustments | `console`           | console session plus role requirements                                                | none     | correct                                                                              |

### Console routes

All `/console/*` routes should be console-session authenticated unless they are an explicit health or provider-webhook exception.
All `/console/*` routes are unmetered and should follow the team-member permissions model.

Allowed unauthenticated exceptions:

- `/console/healthz`
- `/console/readyz`
- `/console/billing/stripe/webhook`

All other `/console/*` routes should remain in the console auth plane.

The canonical source of route auth and metering policy is [routeDefinitions.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeDefinitions.ts). Router handlers should enforce those policies through the shared route-policy helpers, not invent route-local auth decisions.

#### Target console RBAC matrix

| Route family                              | Target gate                                             | Notes                                                                                      |
| ----------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Account/session/profile/org context reads | Console session only                                    | Human dashboard context reads                                                              |
| Onboarding telemetry reads                | `admin` or `ops`                                        | Already modeled                                                                            |
| Ops cockpit reads                         | `owner`, `admin`, `security_admin`, or `ops`            | Already modeled; onboarding telemetry stays partial for `owner` / `security_admin` viewers |
| Audit reads                               | `owner`, `admin`, `security_admin`, or `ops`            | Already modeled                                                                            |
| Wallet reads                              | `owner`, `admin`, `security_admin`, `ops`, or `support` | Already modeled                                                                            |
| Billing reads                             | `owner`, `admin`, `billing_admin`, or `ops`             | Already modeled                                                                            |
| Org/project/environment mutation          | `owner` or `admin`                                      | Already modeled                                                                            |
| Team member and RBAC mutation             | `owner` or `admin`                                      | Already modeled                                                                            |
| Approval queue mutation                   | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| Policy mutation                           | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| API key mutation                          | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| Smart-wallet config mutation              | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| Runtime snapshot publish                  | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| Webhook endpoint mutation and replay      | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |
| Observability reads                       | `owner`, `admin`, `security_admin`, `ops`, or `support` | Already modeled                                                                            |
| Invoice generation                        | `admin` or `ops`                                        | Already modeled                                                                            |
| Billing adjustments                       | `platform_admin`                                        | Already modeled                                                                            |
| Billing usage event writes                | `admin` or `ops`                                        | Already modeled                                                                            |
| Enterprise isolation actions              | `owner` or `admin`                                      | Already modeled                                                                            |
| Key export approval                       | `admin`                                                 | Already modeled                                                                            |
| Key export request creation               | `owner`, `admin`, or `security_admin`                   | Already modeled                                                                            |

### API credential routes

These are the routes that should use API-key auth or bootstrap credentials.

#### Current real API credential routes

| Route                                                                | Target auth                   | Target scope      | Notes                                                                                                                       |
| -------------------------------------------------------------------- | ----------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `POST /registration/bootstrap`                                       | secret key or bootstrap token | `accounts.create` | Existing scoped secret-key route                                                                                            |
| `POST /registration/threshold-ed25519/hss/*`                         | secret key or bootstrap token | `accounts.create` | Registration-only single-key HSS prepare/finalize sidecars used before atomic account creation                              |
| `POST /v1/registration/bootstrap-grants`                             | publishable key               | none              | Capability is controlled by publishable key, origin, environment, quota, and payment policy                                 |
| `GET /v1/wallets` / `GET /v1/wallets/search` / `GET /v1/wallets/:id` | secret key                    | `wallets.read`    | Machine wallet read surface; environment scope comes from the authenticated key and does not reuse `/console/wallets*`      |
| `POST /sponsorships/evm/call`                                        | publishable key               | none              | Capability is controlled by publishable key, origin, environment, and active sponsorship policy                             |
| `POST <signedDelegatePath>`                                          | publishable key               | none              | When configured, treat as an auth-gated relay execution route and meter based on exact gas used or equivalent relayer spend |

#### Possible future machine routes if product scope expands

These do not exist today. The point is to create explicit machine endpoints instead of abusing console routes or low-level protocol routes.

| Proposed route family    | Target auth | Target scope    | Notes                                                                                 |
| ------------------------ | ----------- | --------------- | ------------------------------------------------------------------------------------- |
| `POST /v1/accounts/sync` | secret key  | `accounts.sync` | New machine route; do not map this scope to current `/sync-account/*` WebAuthn routes |
| `GET /v1/billing/*`      | secret key  | `billing.read`  | Only if non-console machine billing reads are actually needed                         |

Current decision:

- do not add a secret-key-backed wallet signing route in the current product surface
- wallet execution remains either:
  - end-user app-session or threshold-session driven, or
  - the dedicated publishable-key `signedDelegatePath` execution surface

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
- `/registration/threshold-ed25519/hss/prepare`
- `/registration/threshold-ed25519/hss/finalize`
- `/threshold-ed25519/session`
- `/threshold-ecdsa/hss/prepare`
- `/threshold-ecdsa/hss/respond`
- `/threshold-ecdsa/hss/finalize`

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
- `/threshold-ed25519/hss/prepare`
- `/threshold-ed25519/hss/finalize`
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

Target policy:

- `ctx.signedDelegatePath` is a machine execution route, not a public proof route
- `ctx.signedDelegatePath` must be API-auth-gated and billed or metered based on actual gas used or equivalent relayer spend
- `ctx.signedDelegatePath` should not use console RBAC and does not need a machine scope unless we later expose a broader dedicated wallet execution API
- `smartAccountDeploy` remains internal-only and stays out of the public route registry
- future rollout decisions for `smartAccountDeploy` are deferred to [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md)

## Scope taxonomy

We should clean up scope naming as part of this effort instead of preserving the current mixed format.

Current supported machine scope set:

- `accounts.create`
- `wallets.read`

Possible future scope candidates only if real machine routes are added:

- `accounts.sync`
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
5. High-level machine wallet signing must stay out of scope unless we first define a policy and audit model above MPC.
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

- update API key scope definitions in `examples/seams-site/src/pages/dashboard/routes/api-keys/page.tsx`
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

Current scope:

- `GET /v1/wallets`
- `GET /v1/wallets/search`
- `GET /v1/wallets/:id`

Explicitly out of scope for now:

- any secret-key-backed `/v1/wallets/:id/sign` route
- any route that exposes low-level threshold signing steps to machine credentials

Possible future endpoints only if product scope expands:

- `POST /v1/accounts/sync`
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
- [x] Confirm `/console/*` routes stay unmetered and do not emit customer billing usage.

### Phase 4: Threshold route documentation and validation

- [x] Document `/threshold-*/sign/*` and `/threshold-*/internal/cosign/*` as intentionally auth-free protocol routes.
- [x] Document which threshold routes are public proof routes, threshold-session routes, and low-level continuation routes.
- [x] Add replay and malformed-state coverage for low-level signing continuations.
- [x] Add cross-session misuse coverage for cosign and continuation routes.
- [x] Remove or rewrite misleading comments that imply an internal auth boundary where none exists.

### Phase 5: High-level machine wallet APIs

- [x] Decide whether backend wallet read APIs are a supported product surface.
- [x] Decide whether backend signing by secret key is a supported product surface. Current decision: no.
- [x] If yes, add explicit `/v1/*` machine endpoints instead of reusing console or threshold routes.
- [x] Bind the live machine wallet routes to `wallets.read` and keep unsupported signing scopes out of the product surface.
- [x] Keep audit-emitting wallet mutation work out of scope until a future high-level machine mutation route is intentionally introduced.

### Phase 6: Adjacent wallet execution route policy

- [x] Gate `signedDelegatePath` with non-console API auth.
- [x] Meter `signedDelegatePath` on actual gas used or equivalent relayer spend.
- [x] Keep `signedDelegatePath` publishable-key-only for now; treat any future x402 support as a payment layer, not a second API credential model.
- [x] Keep `smartAccountDeploy` out of the public route registry entirely.
- [x] Move deferred `smartAccountDeploy` product questions to [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md).
- [x] Document the chosen auth and metering policy for each adjacent execution route.
- [x] Confirm the remaining proofless public relay routes are limited to explicit allowlisted discovery or operational-ingress surfaces and remain unmetered.
- [x] Add route-level tests for the chosen classification.

### Phase 7: Route-policy tests and parity coverage

- [x] Add route-policy tests that enumerate registered Express routes.
- [x] Assert that all `/console/*` routes are console-authenticated except explicit allowlisted exceptions.
- [x] Assert that only machine routes reference scopes.
- [x] Assert that public routes are intentionally allowlisted.
- [x] Add Cloudflare parity coverage for shared route families.

### Phase 8: Docs and legacy cleanup

- [x] Update `docs/saas/api-keys.md` to match the new auth model.
- [x] Remove stale dashboard copy that describes console APIs as machine-scope targets.
- [x] Remove stale route comments and legacy scope references from server code.
- [x] Delete tests that assert obsolete scope names or obsolete route auth behavior.
- [x] Re-read the route surface after cleanup and confirm the docs still match reality.

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
- [x] Confirm the live secret-key scope set is `accounts.create` and `wallets.read`, and block any new scope until a real machine route lands.
- [x] Add tests that fail if a machine route references an unknown scope.
- [x] Add tests that fail if a listed scope does not map to any machine route definition.
- [x] Tighten API key services, relay auth types, and persisted scope parsing so secret-key scopes are canonical `ApiCredentialScope[]` end-to-end.

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
- [x] Audit console read routes that may need dedicated read roles instead of membership-only access.
- [x] Centralize console role-to-response mapping so authorization failures are uniform.
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
- [x] Add protocol misuse tests for replay, wrong-session continuation, and malformed transcript input.
- [x] Add protocol misuse tests for cross-session cosign misuse.
- [x] Remove comments or helper names that imply internal auth where the route is intentionally public.
- [x] Add tests that fail if any threshold continuation route accidentally gets machine scope or console auth attached.

Current coverage includes:

- [threshold-ed25519.scope.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/threshold-ed25519.scope.test.ts) for one-shot `mpcSessionId`, one-shot `signingSessionId`, digest mismatch, and malformed finalize inputs.
- [thresholdEd25519.frostTamper.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/thresholdEd25519.frostTamper.test.ts) for tampered continuation transcripts.
- [threshold-ecdsa.signature-harness.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/threshold-ecdsa.signature-harness.test.ts) and [thresholdEcdsa.presignDistributed.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts) for stale-session and cross-instance continuation misuse.
- [thresholdEd25519.relayerCosigners.stub.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.relayerCosigners.stub.test.ts) for Ed25519 relayer-cosigner cross-session `coordinatorGrant` misuse against a live internal cosign session.

### Phase 5 detailed tasks: High-level machine wallet APIs

- [x] Decide whether `wallets.read` should exist in the product surface.
- [x] Decide whether `wallets.sign` should exist in the product surface. Current decision: no.
- [x] Add route definitions, request schemas, response schemas, and metering policy for the supported `/v1/*` wallet read routes.
- [x] Bind the supported wallet read routes to `wallets.read` and reject unsupported signing scopes from API-key management.
- [x] Ensure high-level wallet routes call into application services instead of exposing low-level MPC steps directly.
- [x] Add tests for scope enforcement, environment binding, and IP rules where applicable.
- [x] Defer audit emission until or unless high-level machine wallet mutation routes are introduced.

### Phase 6 detailed tasks: Adjacent wallet execution route policy

- [x] Add a route definition for `signedDelegatePath` with `machine` auth and `gas` metering.
- [x] Route `signedDelegatePath` through shared publishable-key auth enforcement in both Express and Cloudflare.
- [x] Keep `signedDelegatePath` publishable-key-only; revisit x402 as payment support rather than a new API credential.
- [x] Add a reusable gas-metering abstraction that can record both `evm_call` and `near_delegate` spend.
- [x] Ensure `signedDelegatePath` emits consistent billing records even for reverted or partially failed execution.
- [x] Keep `smartAccountDeploy` out of the public route registry entirely.
- [x] Move deferred `smartAccountDeploy` rollout questions to [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md).
- [x] Confirm the only proofless public relay routes left are health or readiness probes, well-known discovery, `link-device/*`, and `/recover-email`, and that they remain `metering: { kind: 'none' }`.
- [x] Add Express and Cloudflare parity tests for `signedDelegatePath` auth behavior.
- [x] Extend `signedDelegatePath` parity tests to cover gas metering behavior.

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

- [x] Update docs to describe route definitions as the canonical source of auth policy.
- [x] Remove stale comments that instruct developers to add auth inside handlers.
- [x] Delete direct per-handler header parsing where the route executor now resolves auth.
- [x] Delete transport-specific publishable-key parsing and auth duplication from `POST /v1/registration/bootstrap-grants`.
- [x] Delete transport-specific auth duplication from `POST <signedDelegatePath>`.
- [x] Delete transport-specific auth duplication that is replaced by shared route definitions.
- [x] Re-run the route inventory after cleanup and confirm there are no orphaned route modules.
- [x] Reconcile examples in docs with the final file names and type names used in the implementation.

Route inventory rerun on 2026-03-14:

- relay route-module scan found `17/17` Express relay route modules referenced by [createRelayRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createRelayRouter.ts)
- relay route-module scan found `17/17` Cloudflare relay route modules referenced by [createCloudflareRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareRouter.ts)
- live route-surface guardrails passed for [router.relayRouteSurface.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/router.relayRouteSurface.unit.test.ts) and [router.consoleRouteSurface.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/router.consoleRouteSurface.unit.test.ts)
- proofless public relay routes are now constrained by test to the explicit allowlist of health or readiness probes, well-known discovery, `link-device/*`, and `/recover-email`, and all remain `metering: { kind: 'none' }`

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

- should billing usage event ingestion be a console route at all
- when to add x402-style paid execution to `signedDelegatePath` without changing its publishable-key auth model
- should any `smartAccountDeploy` trigger happen outside recovery or first-use flows, or should initial registration stay gas-free for EVM

## Audit review (2026-03-18)

Findings from a security review of the API surface, auth gating, and spending paths. Ordered by severity.

### CRITICAL: Race condition in prepaid balance reservation

**Location:** `server/src/console/billingPrepaidReservations/postgres.ts`

The balance check (`reservedMinor + estimatedSpendMinor > postedBalanceMinor`) and the subsequent `INSERT INTO console_billing_prepaid_reservations` are not atomic. Concurrent requests can each pass the balance check before either reservation row is created, allowing total reservations to exceed the actual posted balance.

**Exploitation:** Two concurrent sponsored calls each read the same summary state, both pass the availability check, both insert reservations. Total reserved can exceed the posted balance by up to `N * estimatedSpendMinor` where `N` is the number of concurrent requests in the race window.

**Recommendation:** Use `SELECT ... FOR UPDATE` on the balance summary row, or use a serializable transaction that covers both the read and the insert.

### CRITICAL: `/link-device/session/:sessionId` enumeration

**Location:** `server/src/router/cloudflare/routes/linkDevice.ts`, `server/src/router/express/routes/linkDevice.ts`

This unauthenticated `GET` endpoint returns session data for any valid `sessionId`. There is no rate limiting, no authentication, and no visible entropy guarantee on session IDs. If session IDs have insufficient entropy or are sequential, an attacker can enumerate active device-linking sessions.

**Recommendation:** Ensure session IDs have at least 128 bits of cryptographic randomness. Add per-IP rate limiting. Consider requiring a short-lived proof or HMAC to access session state.

### HIGH: No global rate limiting beyond bootstrap grants

Only bootstrap grant issuance has rate and quota limits (60 per minute, 1000 total per publishable key per bucket). All other public endpoints lack per-IP or per-endpoint throttling. This includes:

- gas-spending routes (`/sponsorships/evm/call`, `signedDelegatePath`)
- threshold signing routes (CPU-intensive MPC operations)
- wallet unlock challenge and verify
- link-device endpoints

**Exploitation:** Resource exhaustion, brute-force on challenge/verification endpoints, spam on operational ingress routes.

**Recommendation:** Add per-IP and per-publishable-key rate limiting at the transport layer or a shared middleware for all public and API-credential routes.

### HIGH: Pricing service failure causes silent fallback to estimated spend

**Location:** `server/src/sponsorship/prepaidBalance.ts`, `server/src/sponsorship/spendCaps.ts`

When `finalizeSponsoredExecutionSpend()` throws any error, the settlement code falls back to `estimatedSpendMinor`. If the pricing service is temporarily unreachable, all settlements revert to estimates, which may be systematically higher or lower than actual spend.

**Exploitation:** Difficult to exploit directly (requires pricing service disruption), but a sustained pricing outage silently shifts all billing to estimates with no alert or circuit breaker.

**Recommendation:** Add a circuit breaker or alert when the pricing fallback fires. Bound the fallback amount to a server-side maximum derived from policy gas limits and current gas prices. Consider failing closed (rejecting the settlement) rather than falling back silently when the pricing service is down.

### HIGH: Origin header trust on `/wallet/unlock/verify`

**Location:** `server/src/router/cloudflare/routes/sessions.ts`, `server/src/router/express/routes/sessions.ts`

The `/wallet/unlock/verify` endpoint passes `expected_origin` from the request `Origin` header to the WebAuthn verification function. In non-browser contexts, the `Origin` header is attacker-controlled. While WebAuthn's `clientDataJSON` embeds the true origin, the server-side check must compare against the embedded origin, not the request header.

**Recommendation:** Verify that the WebAuthn verification implementation compares the `origin` field inside `clientDataJSON` against the server's configured allowed origins, and does not rely on the request `Origin` header as the source of truth.

### HIGH: Concurrent spend cap bypass (TOCTOU)

**Location:** `server/src/sponsorship/spendCaps.ts`

Spend cap reservation uses a reserve-then-execute-then-settle pattern. If the underlying `spendCaps.reserve()` does not lock the aggregate counter atomically, concurrent requests can each read the same remaining capacity and both pass. This is the same class of time-of-check-to-time-of-use bug as the prepaid balance race condition.

**Recommendation:** Ensure the spend cap reservation uses an atomic compare-and-increment or row-level locking on the aggregate spend counter.

### MEDIUM: Inflated `estimatedSpendMinor` blocks legitimate callers

**Location:** `server/src/router/relaySponsoredEvmCall.ts`

An attacker using a valid publishable key can submit sponsored calls that trigger large estimated spend reservations. Even if actual execution costs are small, the inflated reservation reduces available balance for other callers until settlement releases the excess.

**Recommendation:** Bound estimated spend to a server-side maximum derived from the matched policy's gas limits and current gas prices, rather than accepting the pricing service estimate without an upper bound check.

### MEDIUM: Non-atomic billing ledger and reservation settlement

**Location:** `server/src/router/sponsorshipExecution.ts`

The reservation settlement and billing ledger debit are logically coupled. If `recordSponsoredExecutionDebitTx()` fails after the reservation is marked `SETTLED`, the prepaid balance is reduced but no billing record exists, creating accounting inconsistencies.

**Recommendation:** Wrap the reservation settlement and billing ledger insert in a single database transaction with proper rollback.

### MEDIUM: Cloudflare vs Express path matching parity gap

**Location:** `server/src/router/cloudflare/registerCloudflareRoute.ts` vs `server/src/router/express/registerExpressRoute.ts`

Express uses parameterized path patterns (`:id`), while Cloudflare uses exact string matching via a `Set`. Routes with path parameters (e.g., `/v1/wallets/:id`) may behave differently across transports. This could create routes that are reachable in Express but silently 404 in Cloudflare.

**Recommendation:** Add parity tests that confirm every parameterized route is reachable in both transports with representative path values.

### LOW: Idempotency key does not include policy context

Idempotency keys for signed delegates are scoped to `(apiKeyId, hash)` but do not include the policy ID or expected amount. A replay with the same hash against a different policy context could produce unexpected billing behavior.

### LOW: No input size limits on threshold signing payloads

Base64-encoded cryptographic inputs are passed to WASM without visible size bounds. Extremely large payloads could cause memory pressure or WASM out-of-memory conditions.

### LOW: Silent route-not-found in Cloudflare router

When no Cloudflare handler matches a request, the router returns 404 without logging. Misconfigured routes silently fail rather than alerting.

### INFORMATIONAL: Email recovery header extraction (mitigated)

`parseRecoverEmailRequest()` extracts `accountId` from user-controlled email headers (`x-near-account-id`). This is mitigated because the email DKIM signature is verified onchain before any keys are added to any wallet account. The server endpoint is a relay; the onchain verifier is the trust boundary.

## Progress tracker

- [x] Phase 1 complete
- [x] Phase 2 complete
- [x] Phase 3 complete
- [x] Phase 4 complete
- [x] Phase 5 complete
- [x] Phase 6 complete
- [x] Phase 7 complete
- [x] Phase 8 complete
