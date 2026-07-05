# Refactor 87: Signer Core / Console Module Separation

Date created: July 4, 2026

Status: planning.

Dated progress entries and validation evidence go to a companion journal file
(`refactor-87-journal.md`, created on first entry), not this plan.

## Goal

Separate `@seams/sdk-server` into two modules with independent folder
structures and build outputs, so the signer core can later be released and
open sourced while the console stays closed source and private:

- **Signer core** — the minimum MPC signer surface for the ed25519 and ecdsa
  threshold signers to work: threshold signing runtime, key shares and session
  sealing, registration/auth ceremonies, webauthn/identity/email-OTP stores,
  nonce handling, wasm crypto, `SIGNER_DB` adapters and migrations, and the
  signer Router API.
- **Console** — everything dashboard-shaped: gas sponsorship, policy controls,
  API keys, org/project/environment management, team RBAC, billing, webhooks,
  approvals, audit, observability, key exports, runtime snapshots, onboarding,
  `CONSOLE_DB` adapters and migrations, and the console router.

The dependency direction is one-way: **console may depend on signer core;
signer core must never depend on console.** That direction is what makes the
open-source split possible — the closed console package consumes the published
open signer package like any other customer of it.

Client packages are already on the right side of the line: `@seams/sdk`
(sdk-web) has zero console imports today and needs no work in this plan.

## Why now

Refactor 82 already partitioned the hard layers for tenancy reasons:
`CONSOLE_DB` vs `SIGNER_DB` bindings, `migrations/d1-console` vs
`migrations/d1-signer`, no shared tables, signing paths that never read
console tables, and "console routes cannot access signer KEKs." What remains
is code-level coupling concentrated in the router layer, the package barrel,
and two misplaced modules. Every phase here is mechanical; none touches
signing math, ceremony logic, or storage schemas.

## Current coupling inventory

What is already clean (verified July 4, 2026 by import-graph scan):

- `src/core`, `src/threshold`, `src/wasm`, `src/storage`, `src/delegateAction`,
  `src/email-recovery`: zero imports from `src/console`.
- Signer D1 adapters (`d1ThresholdSigningRuntime`, `d1WalletRegistrationService`,
  `d1WebAuthn*`, `d1EmailOtp*`, `d1Identity*`, `d1RegistrationCeremony*`,
  `d1NearPublicKeyStore`, `d1SessionService`): no console imports, no
  `CONSOLE_DB` access.
- The threshold signing routes do no billing, spend-cap, or console-policy
  calls at sign time. `runtimePolicyScope` / `sessionPolicy` in those routes
  are threshold-signing concepts, not console policies.
- `console → core` imports exist only for `core/logger` and
  `normalizeCorsOrigin` — the allowed direction.

Concrete blockers, each owned by a phase below:

| # | Coupling | Location |
|---|----------|----------|
| B1 | `src/sponsorship` (17 files, ~3.6k lines) has value imports into console but lives outside it | `sponsorship/spendCaps.ts:6`, `sponsorship/prepaidBalance.ts:6`, `sponsorship/evm.ts:2`, plus type imports across `sponsorship/*` |
| B2 | Signer router statically wires console-adjacent handlers into one array | `router/cloudflare/createCloudflareRouter.ts:116-184` (`handleBootstrapGrant`, `handleApiWallets`, `handleSponsoredEvmCall`, `handleSignedDelegate` beside `handleThresholdEd25519`/`Ecdsa`); mirrored in `router/express/createRouterApiRouter.ts:92-95` |
| B3 | Console-aware auth value-imports console | `router/routerApiKeyAuth.ts` (console/apiKeys, ipAllowlist), `router/routerApiCredentialAuth.ts:3` (bootstrapTokens/secret), `router/bootstrapGrantBroker.ts:6` (apiKeys) |
| B4 | Sponsored-call execution/billing glue value-imports console | `router/sponsorshipExecution.ts`, `router/sponsorshipBillingEvents.ts:2`, `router/routerApiSponsoredEvmCall.ts`, `router/routerApiWallets.ts:3` |
| B5 | `RouterApiOptions` types reference 11 `Console*Service` types | `router/routerApi.ts:18-28`; also `router/commonRouterUtils.ts:15` (`ConsoleOrgProjectEnvService` for managed-mode scope resolution), type-only refs in `routerApiSignedDelegate.ts`, `walletRegistrationRoutes.ts:49-50`, `sponsorshipRuntime.ts`, `sponsorshipSpendCapObservability.ts:7` |
| B6 | Main barrel exports both worlds | `src/index.ts:261-266` (`export *` from five `console/*` paths and `./sponsorship`); `package.json` has no signer-only or console-only subpath |
| B7 | Mixed Worker Env types | `router/cloudflare/cloudflare.types.ts` bundles `CONSOLE_DB` + `SIGNER_DB` + `THRESHOLD_STORE` in one Env; `RouterApiCloudflareWorkerEnv` mixes billing/webhook/snapshot vars with relayer/signer vars |
| B8 | Needless directory coupling | `router/cloudflare/routes/thresholdEcdsa.ts:43` imports a console-free crypto leaf from `sponsorship/evmWorkerSignerWasm`; the express variant already uses `core/ThresholdService/ethSignerWasm` |
| B9 | Shared constants for console features live in the shared package | `packages/shared-ts/src/console/` (apiKeyScopes, gasSponsorshipChains, gasSponsorshipSpendCapTargets, organizationIdentity, webhookEventCategories) — imported by `router/routerApi.ts:36` among others |
| B10 | Dev/staging composition harnesses boot both worlds | `router/cloudflare/d1LocalDevWorker.ts`, `d1RouterApiStagingWorker.ts`, `d1StagingSession.ts` (uses `ConsoleTeamRbacService`) |

## Target shape

Two modules, staged as folders first and packages second:

- `@seams/sdk-server` keeps its name and becomes the signer core (the
  open-sourceable unit): `core`, `threshold`, `wasm`, `storage`,
  `delegateAction`, `email-recovery`, the signer Router API, signer D1
  adapters, `migrations/d1-signer`.
- `@seams-internal/console-server` (new workspace package, name TBD in Phase 0)
  owns `console`, `sponsorship`, the console routers, console D1 adapters,
  `migrations/d1-console`, and console shared constants. It depends on
  `@seams/sdk-server`.
- Composition roots (local dev worker, staging workers, deployed Cloudflare
  bundles) import both and wire them together. They live with the console
  package or under `apps/`, never inside the signer core.

Extension mechanism instead of static wiring: the signer router factories
accept injected route groups and auth providers
(`routeExtensions: RouterRouteExtension[]`, `credentialAuthProviders: [...]`)
with runtime behavior identical to today's null-safe optional handlers. The
console package exports `consoleRouteExtensions(...)` /
`consoleCredentialAuth(...)` implementing signer-core-owned port interfaces.

## Design rules

- Signer core defines ports; console implements them. Any signer-core code
  path that can optionally consult console (managed-mode scope resolution,
  API-key auth, bootstrap tokens, sponsored-call metering) does so through an
  interface declared in signer core, injected at composition time, and
  null-safe when absent — matching today's runtime behavior.
- No `import type` exemption: type-only imports of `console/*` from signer
  core break `tsc` after the split just the same. The import guard treats
  them identically.
- Self-hosted signer core must be a complete product: registration, auth
  ceremonies, sessions, ed25519/ecdsa threshold signing, recovery — all
  functional with zero console services configured. This is already true at
  runtime; the split makes it true at build time.
- Append-only D1 migrations continue unchanged; this plan moves no tables and
  changes no schemas.

## Phases

- [ ] Phase 0: Decisions and enforcement baseline.
  - Decide the console package name and whether it lives under `packages/`
    (recommended: `packages/console-server-ts`, name
    `@seams-internal/console-server`).
  - Add a CI import guard that fails on any `console/*` or `sponsorship/*`
    import (value or type) from `src/{core,threshold,wasm,storage,
    delegateAction,email-recovery}` and from an explicit signer-router file
    list. Seed an allowlist with the B1–B10 inventory above and burn it down
    per phase; the guard blocks new coupling immediately. Follow the pattern
    of the existing runtime import scan from Refactor 82 (the one that rejects
    Postgres storage and mixed console barrels).
- [ ] Phase 1: Quick wins with no behavior change.
  - B8: repoint `router/cloudflare/routes/thresholdEcdsa.ts:43` to
    `core/ThresholdService/ethSignerWasm`, matching the express variant.
  - B1 (location only): move `src/sponsorship` to `src/console/sponsorship`
    (or a sibling folder slated for the console package). Its console imports
    become intra-console; its one crypto leaf used by signer code is gone
    after B8.
- [ ] Phase 2: Invert the auth and scope-resolution dependencies (B3, B5).
  - Declare signer-core ports: `ProjectEnvironmentResolver` (replacing the
    `ConsoleOrgProjectEnvService` type in `commonRouterUtils.ts:15`),
    `ApiCredentialAuthenticator`, `BootstrapTokenVerifier`.
  - Move the console-backed implementations (`routerApiKeyAuth`,
    `routerApiCredentialAuth`, `bootstrapGrantBroker`) to console-owned files
    that implement those ports.
  - Split `RouterApiOptions` (`routerApi.ts:18-28`): core options carry only
    ports and signer services; a console-side
    `ConsoleRouterApiExtensions` type carries the 11 `Console*Service`
    fields. `@shared/console/apiKeyScopes` usage in signer core is replaced by
    a scope-string type owned by the port.
- [ ] Phase 3: Split the route surface (B2, B4).
  - Add `routeExtensions` injection to `createCloudflareRouter` and the
    express `createRouterApiRouter`; move `handleBootstrapGrant`,
    `handleApiWallets`, `handleSponsoredEvmCall`, and the console-metered
    parts of `handleSignedDelegate` (plus `sponsorshipExecution`,
    `sponsorshipBillingEvents`, `sponsorshipRuntime`,
    `sponsorshipSpendCapObservability`, `routerApiSponsoredEvmCall`,
    `routerApiWallets`) into console-owned route extension modules.
  - `handleSignedDelegate`'s signer-only path (delegate action relay without
    console billing) stays in core; metering hooks become an injected
    observer port.
  - Contract: with no extensions injected, the signer router serves exactly
    the self-hosted route surface it serves today when those options are
    absent. Route-surface parity is asserted by test, not by inspection.
- [ ] Phase 4: Split entry points and Env types (B6, B7).
  - Trim `src/index.ts:261-266`; console/sponsorship exports move to the
    console module's own barrel. Until the physical package split, expose
    them via a `./console` subpath export so existing consumers migrate with
    a one-line import change.
  - Split `cloudflare.types.ts`: a signer Env (`SIGNER_DB`,
    `THRESHOLD_STORE`, relayer/signer vars) owned by signer core; a console
    Env (`CONSOLE_DB`, billing/webhook/snapshot vars) owned by console; the
    combined shape becomes an intersection type defined at the composition
    root.
- [ ] Phase 5: Move shared console constants (B9).
  - Relocate `packages/shared-ts/src/console/` into the console module (or a
    console-owned shared subpath). After Phase 2 nothing in signer core
    imports it; the guard enforces that stays true. `shared-ts` keeps only
    signer/wallet-neutral types.
- [ ] Phase 6: Physical package split.
  - Create the console workspace package; `git mv` the console folders,
    console routers, console D1 adapters, `migrations/d1-console`, and
    console smoke scripts into it. Wire `tsconfig` project references,
    build, and typecheck per package.
  - Move the composition harnesses (B10: `d1LocalDevWorker`,
    `d1RouterApiStagingWorker`, `d1StagingSession`) and deployed Worker
    bundles to the console package or `apps/`, importing both packages.
  - Split `package.json` scripts: `migrate:*`/`smoke:*` for signer stay in
    `@seams/sdk-server`; console equivalents move with the console package.
- [ ] Phase 7: Open-source readiness pass on the signer package (parked until
  a release decision).
  - License, secrets/history scan, README for self-hosted deployment, and a
    public-API review of everything the signer barrel exports.

## Sequencing gates

- Phases 0 and 1 can start now; they touch files no in-flight plan owns and
  change no behavior.
- Phases 2–4 touch the Router API surface that Refactors 82B and 83 are
  actively modifying. They start only after those tracks stabilize, and land
  under the Refactor 88 `test:intended` gate so route-surface regressions
  fail contracts immediately.
- Phase 6 lands only after Phases 2–5 have burned the import-guard allowlist
  to empty — the package split must be a `git mv`, not a debugging exercise.

## Validation

- CI import guard (Phase 0) green with an empty allowlist by end of Phase 5.
- Deletion test, automated in CI after Phase 6: build and typecheck
  `@seams/sdk-server` with the console package absent from the workspace.
- Existing per-database migrate/smoke scripts pass unchanged in their new
  homes (`d1-signer` under signer core, `d1-console` under console).
- Route-surface parity test (Phase 3): the signer router with no extensions
  serves the same routes as today's unconfigured self-hosted mode; the
  composed router serves the same surface as today's fully configured mode.
- `test:intended` and the browser passkey smokes stay green across every
  phase — signing, registration, unlock, and recovery flows never regress.

## Risks

- The `handleSignedDelegate` split (Phase 3) is the only place where signer
  and console logic interleave inside one handler; the metering-observer port
  needs care to keep billing events identical. Mitigate with a
  before/after billing-event fixture test.
- Hidden type-only coupling tends to surface late; running `tsc` against a
  console-less workspace (the deletion test) early — even before Phase 6, via
  a scripted temporary exclusion — catches stragglers cheaply.
- Refactor 90's modular auth capabilities may reshape the auth ports drawn in
  Phase 2; declare the port interfaces minimal (resolver + authenticator
  functions, not service objects) so both plans can evolve them without
  conflict.
