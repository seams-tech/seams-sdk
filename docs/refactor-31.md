# Refactor 31: Rename Route Auth Planes

## Goal

Rename the route auth-plane taxonomy to better match product language, while keeping route behavior unchanged.

This refactor is about naming and policy-model cleanup, not about changing which routes are protected or how billing works.

## Target auth planes

Replace the current canonical names with:

- `console`: console session auth; `/console/*` is unmetered.
- `api_credentials`: API credentials; currently `publishable_key`, `secret_key`, or `bootstrap_token`.
- `user_session`: end-user app session.
- `threshold_session`: threshold signing session claims.
- `public`: no route auth; gated by proof inside the flow or intentionally public by design.

## Decisions

- Rename `machine` -> `api_credentials`.
- Rename `app_session` -> `user_session`.
- Keep `console`, `threshold_session`, and `public`.
- Remove `internal` from the route-policy taxonomy entirely because no live route currently uses it.
- Do not keep legacy aliases in the route-policy type layer. Breaking changes are acceptable.
- Do not rename JWT/session claim kinds such as `app_session_v1` or `threshold_session_v1`. Those are protocol/session token names, not route auth-plane names.
- Keep `public` as the single bucket for both:
  - proof-gated routes
  - intentionally open routes
  The distinction remains encoded by `proof` and `rationale`, not by introducing another top-level plane.

## Why this is better

- `api_credentials` is clearer than `machine`.
- `user_session` is clearer than `app_session`.
- Removing unused `internal` shrinks the policy surface and removes dead vocabulary.
- We preserve the important distinction between end-user app sessions and threshold signing sessions.

## Non-goals

- changing route access behavior
- changing route billing or metering policy
- changing route paths
- changing JWT claim versions or session token formats
- keeping both old and new auth-plane names around

## Scope

Primary code and doc targets:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeAuthPolicy.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeDefinitions.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/enforceRoutePolicy.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiCredentialAuth.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiWallets.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayBootstrapGrant.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayRegistrationBootstrap.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/shared/src/console/apiKeyScopes.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/apiKeys/service.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/apiKeys/types.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/apiKeys/postgres.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/apiKeys/requests.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/api-keys/page.tsx`
- `/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/api-keys/consoleApiKeysApi.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/router.routeDefinitions.unit.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/router.relayRouteSurface.unit.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/relay-api-keys.test.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/docs/auth-gating-routes.md`

Secondary cleanup targets:

- focused relayer tests that assert route policy wording
- any docs that describe route auth planes directly
- helper names or error messages that still say `machine auth` when they really mean API credential auth

## Before / after model

### Current

```ts
type RouteAuthPlane =
  | 'console'
  | 'machine'
  | 'app_session'
  | 'threshold_session'
  | 'public'
  | 'internal';
```

### Target

```ts
type RouteAuthPlane =
  | 'console'
  | 'api_credentials'
  | 'user_session'
  | 'threshold_session'
  | 'public';
```

## Proposed code-level changes

### 1. Rename route auth policy variants

Update the route-policy union in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeAuthPolicy.ts`:

- `plane: 'machine'` -> `plane: 'api_credentials'`
- `plane: 'app_session'` -> `plane: 'user_session'`
- delete `plane: 'internal'`

Update the matching principal union:

- `kind: 'machine'` -> `kind: 'api_credentials'`
- `kind: 'app_session'` -> `kind: 'user_session'`
- delete `kind: 'internal'`

### 2. Rename supporting types to match

Rename supporting type names so the codebase does not keep stale terminology:

- `MachineCredentialType` -> `ApiCredentialType`
- `MachineRouteScope` -> `ApiCredentialRouteScope`
- `MACHINE_CREDENTIAL_TYPES` -> `API_CREDENTIAL_TYPES`
- `MACHINE_ROUTE_SCOPES` -> `API_CREDENTIAL_ROUTE_SCOPES`

If any helper type still embeds `machine` only because of the old plane name, rename it too.

### 3. Rename route-definition helpers

Update helper function names in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeDefinitions.ts`:

- `machineRoute()` -> `apiCredentialRoute()`
- `appSessionRoute()` -> `userSessionRoute()`

Then update every route definition callsite accordingly.

### 4. Rename route IDs and summaries that still embed the old taxonomy

Route IDs are internal registry identifiers. They should follow the new language too.

Examples:

- `machine_wallets_list` -> `api_wallets_list`
- `machine_wallets_search` -> `api_wallets_search`
- `machine_wallets_get` -> `api_wallets_get`

Also update route summaries or failure messages that currently say `machine auth` when the real meaning is `API credential auth`.

### 5. Rename helper modules that expose stale terminology

Because we do not want legacy naming to linger:

- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayMachineAuth.ts`
  -> `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiCredentialAuth.ts`
- `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayMachineWallets.ts`
  -> `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiWallets.ts`

Then update imports in relay route handlers and tests.

Note: this is a rename/cleanup refactor, so the old files should not remain as wrappers.

### 6. Rename shared scope catalog terminology

The shared secret-key scope catalog should use the same vocabulary:

- `MachineApiKeyScope` -> `ApiCredentialScope`
- `isMachineApiKeyScope()` -> `isApiCredentialScope()`
- `MACHINE_API_KEY_SCOPES` -> `API_CREDENTIAL_SCOPES`
- `MACHINE_API_KEY_SCOPE_OPTIONS` -> `API_CREDENTIAL_SCOPE_OPTIONS`

That rename should flow through server API-key types/services, relay auth types, dashboard API-key UI, and focused tests.

## Phase plan

### Phase 1: Type-layer rename

- [x] Update `RouteAuthPlane` in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeAuthPolicy.ts`.
- [x] Update `RouteAuthPolicy` discriminants from `machine` to `api_credentials`.
- [x] Update `RouteAuthPolicy` discriminants from `app_session` to `user_session`.
- [x] Remove the unused `internal` route-policy branch.
- [x] Update `RoutePrincipal` discriminants to match.
- [x] Rename supporting credential/scope types and constants away from `machine`.

Exit criteria:

- the route-policy type layer compiles with no `machine`, `app_session`, or `internal` route-plane variants left

### Phase 2: Route-definition rename

- [x] Rename `machineRoute()` helper to `apiCredentialRoute()`.
- [x] Rename `appSessionRoute()` helper to `userSessionRoute()`.
- [x] Update all relay route definitions to use the new `plane` names.
- [x] Rename route IDs that embed `machine`.
- [x] Update route-definition normalization code to use the renamed types/constants.

Exit criteria:

- `routeDefinitions.ts` contains only the new plane names
- route IDs no longer use stale `machine_*` naming where it refers to auth-plane taxonomy

### Phase 3: Enforcement-layer rename

- [x] Update `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/enforceRoutePolicy.ts` to switch on the new plane names.
- [x] Rename `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayMachineAuth.ts` to `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayApiCredentialAuth.ts` and update its exported APIs.
- [x] Rename other relay helpers/modules that still encode stale plane naming.
- [x] Update all imports, error messages, and internal helper names.

Exit criteria:

- there is no active route-enforcement code referring to `machine auth` or `app session` as plane names

### Phase 4: Tests

- [x] Update route-definition unit tests for the new plane names.
- [x] Update relay route-surface tests for renamed route IDs if needed.
- [x] Update focused relayer tests that assert route policy wording.
- [x] Add a grep-based guard or unit assertion that route-plane names are limited to:
  - `console`
  - `api_credentials`
  - `user_session`
  - `threshold_session`
  - `public`

Exit criteria:

- tests pass with the new taxonomy
- no assertions still expect the old names

### Phase 5: Docs cleanup

- [x] Update `/Users/pta/Dev/rust/simple-threshold-signer/docs/auth-gating-routes.md` to use the new canonical plane names consistently.
- [x] Update any architecture examples in docs to match the final code.
- [x] Update any route summaries or design notes that still explain `machine` or `app_session` as plane names.
- [x] Leave `app_session_v1` references alone where they refer to the JWT/session claim kind rather than the route plane.

Exit criteria:

- product/design docs use one consistent route-plane vocabulary
- no mixed old/new terminology remains in the main auth-gating docs

## Search checklist

Before closing the refactor, verify these searches return only intentional results:

- [x] `rg -n \"plane: 'machine'|kind: 'machine'|\\bmachine auth\\b\" /Users/pta/Dev/rust/simple-threshold-signer`
- [x] `rg -n \"plane: 'app_session'|kind: 'app_session'\" /Users/pta/Dev/rust/simple-threshold-signer`
- [x] `rg -n \"plane: 'internal'|kind: 'internal'\" /Users/pta/Dev/rust/simple-threshold-signer`
- [x] `rg -n \"RouteAuthPlane\" /Users/pta/Dev/rust/simple-threshold-signer`

Expected survivors:

- `app_session_v1` token references
- the route-policy type definition in `/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeAuthPolicy.ts`
- historical prose that explicitly documents the rename, if any

## Validation

Minimum validation after implementation:

- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server exec tsc --noEmit`
- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/tests exec playwright test ./unit/router.routeDefinitions.unit.test.ts ./unit/router.relayRouteSurface.unit.test.ts --reporter=line`
- [x] run focused relayer tests that cover:
  - registration bootstrap
  - bootstrap grants
  - sponsored EVM call
  - signed delegate
  - API credential wallet routes

Completed focused verification:

- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/sdk build`
- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/tests exec playwright test ./relayer/relay-api-keys.test.ts -c playwright.relayer.config.ts --reporter=line`
- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/tests exec playwright test ./relayer/bootstrap-grants.test.ts -c playwright.relayer.config.ts --reporter=line`
- [x] `pnpm -C /Users/pta/Dev/rust/simple-threshold-signer/tests exec playwright test ./unit/router.routeDefinitions.unit.test.ts ./unit/router.relayRouteSurface.unit.test.ts --reporter=line`

## Risks

- renaming route IDs may require updating test fixtures and any internal dashboards/scripts that refer to those IDs
- mixed terminology can linger in helper names even after the main type rename unless we do a full grep cleanup
- deleting `internal` is safe only because no current route definitions use it; if that changes before the refactor lands, revisit this decision

## Final state

At the end of this refactor:

- route auth planes are:
  - `console`
  - `api_credentials`
  - `user_session`
  - `threshold_session`
  - `public`
- no route-policy type, helper, or primary doc still uses the old `machine` or `app_session` plane names
- no unused `internal` route plane remains in the codebase
- helper modules and route IDs now use `api_credentials` / `user_session` terminology instead of `machine` / `app_session`
- the shared secret-key scope catalog now uses `ApiCredentialScope` naming end to end
