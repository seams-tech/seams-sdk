# Refactor 87: Signer Core / Console Module Separation

Date created: July 4, 2026

Status: in progress.

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
| B1 | Resolved July 8, 2026: sponsorship now lives under `src/console/sponsorship`, so its console imports are intra-console | `console/sponsorship/*` |
| B2 | Resolved July 8, 2026: managed bootstrap grants, API-wallet reads, sponsored EVM calls, and signed-delegate execution now mount through console-owned route extensions | `console/router/routeExtensions.ts` |
| B3 | Resolved July 8, 2026: signer-router auth files now depend on signer-owned credential/bootstrap ports; console-backed adapters live under `src/console/router` | `router/apiCredentialPorts.ts`, `console/router/routerApiKeyAuth.ts`, `console/router/bootstrapGrantBroker.ts`, `console/router/bootstrapTokenVerifier.ts` |
| B4 | Resolved July 8, 2026: API-wallet, sponsored EVM, signed-delegate implementation, and shared sponsorship helper modules live under `console/router`; signed-delegate route ownership moved to the console route extension | `console/router/routeExtensions.ts`, `console/router/routerApiSignedDelegate.ts` |
| B5 | Resolved July 8, 2026: `RouterApiOptions` now carries signer-owned ports and route extensions; console sponsorship services live in console route-extension options, and Router API lifecycle webhooks use a signer-owned emitter port | `router/routerApi.ts`, `console/router/routeExtensions.ts` |
| B6 | Main barrel exports both worlds | `src/index.ts:261-266` (`export *` from five `console/*` paths and `./console/sponsorship`); `package.json` has no signer-only or console-only subpath |
| B7 | Mixed Worker Env types | `router/cloudflare/cloudflare.types.ts` bundles `CONSOLE_DB` + `SIGNER_DB` + `THRESHOLD_STORE` in one Env; `RouterApiCloudflareWorkerEnv` mixes billing/webhook/snapshot vars with relayer/signer vars |
| B8 | Needless directory coupling | `router/cloudflare/routes/thresholdEcdsa.ts:43` imports a console-free crypto leaf from `sponsorship/evmWorkerSignerWasm`; the express variant already uses `core/ThresholdService/ethSignerWasm` |
| B9 | Shared constants for console features live in the shared package; the signer auth scope constants are now owned by `router/apiCredentialPorts.ts` | `packages/shared-ts/src/console/` (gasSponsorshipChains, gasSponsorshipSpendCapTargets, organizationIdentity, webhookEventCategories, and console API-key helpers still used by console code) |
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

- [x] Phase 0: Decisions and enforcement baseline.
  - [x] Decide the console package name and whether it lives under `packages/`
    (recommended: `packages/console-server-ts`, name
    `@seams-internal/console-server`).
  - [x] Add a CI import guard that fails on any `console/*` or `sponsorship/*`
    import (value or type) from `src/{core,threshold,wasm,storage,
    delegateAction,email-recovery}` and from an explicit signer-router file
    list. Seed an allowlist with the B1–B10 inventory above and burn it down
    per phase; the guard blocks new coupling immediately. Follow the pattern
    of the existing runtime import scan from Refactor 82 (the one that rejects
    Postgres storage and mixed console barrels).
- [x] Phase 1: Quick wins with no behavior change.
  - [x] B8: repoint `router/cloudflare/routes/thresholdEcdsa.ts:43` to
    `core/ThresholdService/ethSignerWasm`, matching the express variant.
  - [x] B1 (location only): move `src/sponsorship` to `src/console/sponsorship`
    (or a sibling folder slated for the console package). Its console imports
    become intra-console; its one crypto leaf used by signer code is gone
    after B8.
- [x] Phase 2: Invert the auth and scope-resolution dependencies (B3, B5).
  - [x] Declare signer-core ports: `ProjectEnvironmentResolver` (replacing the
    `ConsoleOrgProjectEnvService` type in `commonRouterUtils.ts:15`),
    `ApiCredentialAuthenticator`, `BootstrapTokenVerifier`.
  - [x] Move the console-backed API-key auth, publishable-key auth, billing
    usage meter, bootstrap-token verifier, and bootstrap-grant broker to
    console-owned files that implement those ports.
  - [x] Finish splitting `RouterApiOptions` (`routerApi.ts:18-28`): core options carry only
    ports and signer services; console-side
    `ConsoleRouterApiRouteExtensionsOptions` carries the remaining `Console*Service`
    fields. `@shared/console/apiKeyScopes` usage in signer core is replaced by
    a scope-string type owned by the port.
  - [x] Move managed bootstrap-grant and API-wallet service ownership off
    `RouterApiOptions` and into console-owned route extension closures.
- [x] Phase 3: Split the route surface (B2, B4).
  - [x] Use the existing `routeExtensions` injection in `createCloudflareRouter`
    and the fetch-backed express `createRouterApiRouter` to move
    `handleBootstrapGrant` and `handleApiWallets` into a console-owned route
    extension module.
  - [x] Move `handleSponsoredEvmCall` and `routerApiSponsoredEvmCall` into
    `console/router` and mount sponsored EVM through the console route
    extension.
  - [x] Move `sponsorshipExecution`, `sponsorshipBillingEvents`,
    `sponsorshipRuntime`, and `sponsorshipSpendCapObservability` into
    console-owned route helper modules.
  - [x] Move the console-metered signed-delegate implementation module into
    `console/router`.
  - [x] Move `handleSignedDelegate` route ownership and remaining route/runtime
    helpers into console-owned route extension modules.
  - The signer-owned `delegateAction` execution primitive stays in core; console
    metering composes through the signed-delegate route extension.
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

- Any future signer-only signed-delegate relay needs a narrow observer port so
  billing events remain identical when console metering is composed in.
  Mitigate with a before/after billing-event fixture test.
- Hidden type-only coupling tends to surface late; running `tsc` against a
  console-less workspace (the deletion test) early — even before Phase 6, via
  a scripted temporary exclusion — catches stragglers cheaply.
- Refactor 90's modular auth capabilities may reshape the auth ports drawn in
  Phase 2; declare the port interfaces minimal (resolver + authenticator
  functions, not service objects) so both plans can evolve them without
  conflict.
