# Refactor 97 — Router Folder Organisation

## Status

Implemented and integrated through Phases 1–6 on `codex/r97-folder-hierarchy`
at the current branch HEAD.

### Implementation record

- Integrated branch/HEAD: `codex/r97-folder-hierarchy` (current HEAD).
- No R97 structural symlinks or fallback paths remain.
- Server package typecheck, console-server typecheck, and unit typecheck pass.
- Package export contract passes 12/12; export server passes 17/17; route
  surface passes 11/11, including Cloudflare metadata, eager validation, and
  runtime forwarding coverage.
- R97 contract, recovery, and vault tests pass 33/33.
- ECDSA derivation guard passes.
- The resolved Express runtime graph reports zero Cloudflare runtime or
  persistence edges.
- Static local-router resolver reports zero unresolved imports.
- The full source-guard chain stops on existing sdk-web auth-method fallback
  findings and the existing ECDSA identity guard finding; both are outside
  R97.

This refactor changes **no behaviour**. Phase 1 and Phase 2 are small
boundary extractions that remove dependency inversions. Phases 3–4 are
move-only directory shards. Phases 5–6 repair public, production, test, and
guard paths. Runtime, schema, and wire behaviour are unchanged. Package export
keys and adaptor entry functions remain stable; Cloudflare-named shared Fetch
extension types are intentionally replaced by Fetch-owned types.

## Problem

`packages/wallet-server/src/router` currently has 143 TypeScript files:

- 71 files are flat at the router root (68 modules plus three public adaptor
  entry points).
- `cloudflare/` has 53 direct files, 13 route files, and one nested Durable
  Object file (67 files recursively).
- `ror/` has five files and is already a coherent provider folder.

The architecture is visible only through prefixes and imports. There are 23
`routerAbEd25519Yao*` modules, four `emailOtp*` modules, and eight request
validation modules at the root. The Cloudflare directory contains 47 D1
implementations, including 13 `d1EmailOtp*` files, beside Fetch routing and
Durable Object code.

The import graph shows the intended layers:

```
public adaptors (Express, Cloudflare, ROR)
  └─ shared Fetch transport and route handlers
       └─ host-neutral framework, auth, and lifecycle domains
            └─ Cloudflare D1 and Durable Object implementations
```

Specific defects:

1. Prefixes are standing in for folders. The 23 Ed25519/Yao modules and the
   lifecycle validation modules have no structural ownership boundary.
2. `cloudflare/http.ts` is Fetch-standard (`json`, CORS, `readJson`, response
   helpers) rather than Cloudflare-specific. It has 22 importers, including
   seven host-neutral Yao modules.
3. There are 15 core-to-`cloudflare/` imports (inventory below). Until those
   ports are extracted, a directory layout would misstate dependency
   direction.
4. `walletRegistrationRoutes.ts` is the host-neutral service (2,653 lines),
   while `cloudflare/routes/walletRegistration.ts` is a 129-line Fetch
   boundary handler that parses, validates, and invokes it. Their matching
   basenames obscure ownership.
5. D1 records, stores, services, and boundaries are a useful convention, but
   47 implementations are flat beside the host router.
6. `routerAbNormalSigningAdmissionCore` still embeds a Cloudflare D1 store,
   its options, and its factory; `routerAbNormalSigningAdmissionStore.ts` only
   re-exports that mixed module. The product partitioned-state module likewise
   embeds a D1 factory and options.
7. Express delegates to a shared Fetch router named and located as a
   Cloudflare implementation. That router also imports the standard-Fetch
   signing-session seal handler from a file named `transport/cloudflare.ts`.
   These names hide the existing portable boundary and make the Express
   dependency graph appear Cloudflare-specific.

## Target structure

The three public adaptors stay at the router root. The shared Fetch router and
route handlers move to `transport/fetch/`; Express calls that transport
directly. Cloudflare keeps a small runtime wrapper that converts Worker
`(request, env, ctx)` calls into the Fetch transport's explicit inline or
background-execution state. Worker bindings remain in the Cloudflare
composition root because the shared router does not consume them.
Concrete D1 and Durable Object implementations remain under `cloudflare/`.
Generic Fetch helpers used by host-neutral request boundaries live in
`framework/http.ts`.

```
router/
  express-adaptor.ts
  cloudflare-adaptor.ts
  ror-adaptor.ts

  framework/                   # host-neutral route machinery and contracts
    http.ts                    # moved from cloudflare/http.ts
    apiCredentialPorts.ts      # host-neutral credential contracts/constants
    authServicePort.ts         # cross-domain service composition contract
    ror/                       # ROR provider internals moved from router/ror
  auth/                        # credential and wallet-session boundaries
  domains/                     # host-neutral lifecycle and protocol code
    walletRegistration/
    walletUnlock/
    emailOtp/
    emailRecovery/
    syncAccount/
    ed25519Yao/
      registration/
      capabilityLifecycle/
      recovery/
      export/
      session/
    ecdsa/
    signingOperations/

  transport/
    fetch/                     # shared Request/Response router
      createFetchRouter.ts
      fetchRouter.types.ts
      routes/

  cloudflare/
    runtime/                   # Worker wrapper, Worker types, email handling
    d1/                        # D1 records/stores/services/boundaries
      emailOtp/ registration/ session/ identity/ oidc/ webauthn/
      auth/ wallet/ authorization/ ed25519Yao/ near/ signingAdmission/
      versionedJson/
    durableObjects/            # thresholdStore and versioned JSON DO adapter
```

### Layering rule

- `framework/` contains host-neutral runtime machinery and injected contracts.
  Its runtime imports stay within `framework/` and shared/core utilities; its
  domain references are type-only public contracts. It never imports
  Cloudflare implementations.
- `auth/` and `domains/` may import `framework/`, `../core`, and shared
  protocol types at runtime or as types. They never import `cloudflare/`.
- `cloudflare/d1/` and `cloudflare/durableObjects/` implement ports from the
  host-neutral layers. They never import `transport/fetch/` handlers.
- `transport/fetch/` imports the host-neutral layers and receives its
  `RouterApiServiceBag` from the deployment composition root. It never imports
  `cloudflare/`.
- `cloudflare/runtime/` may import `transport/fetch/` to adapt Worker runtime
  calls. Cloudflare persistence never imports the transport.
- Root adaptors are public assembly points and may import any router layer.

`routerApiWebhooks` stays in `framework/`: it is an injected, host-neutral
event emitter used by multiple lifecycle routes, rather than Email OTP or
wallet persistence logic. D1 implementations remain entirely under
`cloudflare/d1/`; domain handlers do not move into D1 folders.

This is a dependency rule, not a new source-text guard. If enforcement is
needed after the moves, use a resolved import-graph check in the existing
architecture checks.

### Deployment portability invariant

R97 preserves the adaptor architecture; it does not implement a second
persistence stack:

- `express-adaptor.ts`, `cloudflare-adaptor.ts`, and `ror-adaptor.ts` remain
  stable public entry points.
- Express continues to translate Node requests to standard Fetch
  `Request`/`Response` objects and invokes `transport/fetch/createFetchRouter`
  with an injected `RouterApiServiceBag`. It requires no Worker binding, D1
  database, or Durable Object namespace.
- Cloudflare composition may supply D1 and Durable Object implementations for
  the same host-neutral service ports. A VM composition may instead supply
  Postgres-backed implementations.
- `framework/`, `auth/`, and `domains/` contain no concrete D1, Durable Object,
  Hyperdrive, or Postgres client dependency. Persistence implementations stay
  outside those layers.

The current storage model already represents Postgres targets, but the
repository does not contain a complete Postgres implementation of the router
service bag. AWS VM and Postgres delivery therefore remains separate work.
R97 must leave a direct path for that work and must not claim to provide it.

## Inversion inventory

The current 15 core-to-`cloudflare/` imports are:

| # | Current edge | Disposition |
| - | ------------ | ----------- |
| 1–7 | `routerAbEd25519Yao{Export, ExportRequestScopedCloudflare, Recovery, RecoveryRequestScopedCloudflare, RecoveryWalletSessionAuthorization, Registration, RegistrationRequestScopedCloudflare}` → `cloudflare/http` | Phase 1: move the Fetch helpers to `framework/http.ts`. |
| 8–11 | `routerAbEd25519Yao{RegistrationExecutionRecord, RegistrationSideEffectBoundary, ProductRegistrationPartitionedStateStore, ProductRegistrationPersistence}` → `cloudflare/versionedJsonRecordStore` | Phase 2: extract host-neutral versioned-JSON port types; the Durable Object implementation moves to `cloudflare/durableObjects/`. |
| 12 | `routerAbEd25519YaoProductRegistrationPartitionedStateStore` → `cloudflare/d1VersionedJsonRecordStore` (value import for the D1 factory, plus D1 option types) | Phase 2: move `createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1` and its D1 options into `cloudflare/d1/ed25519Yao/`; the domain module keeps only host-neutral partitioning and store ports. |
| 13–14 | `authServicePort` and `walletRegistrationRoutes` → `cloudflare/d1WalletRegistrationSetup` (type-only) | Phase 2: move the setup/respond/activate/near-provisioning input types to `domains/walletRegistration/`; D1 setup imports the domain types. |
| 15 | `routerAbEd25519YaoExport` → `cloudflare/d1WalletAuthMethodBoundary` (value import for WebAuthn credential codecs) | Phase 2: extract the codecs to `auth/`; keep the D1 boundary in `cloudflare/d1/wallet/`. |

One additional portability defect is removed in Phase 2:
`express-adaptor` currently delegates to
`cloudflare/createCloudflareRouter`. After the Fetch transport extraction it
imports `transport/fetch/createFetchRouter` directly; only
`cloudflare/runtime/createCloudflareRouter` adapts Worker runtime arguments to
that shared transport. The shared signing-session seal handler moves from
`threshold/session/signingSessionSeal/transport/cloudflare.ts` to
`threshold/session/signingSessionSeal/transport/fetch.ts` in the same
extraction, so the Fetch router has no Cloudflare-named transitive boundary.

## Execution plan

### Readiness verdict

**Architecture ready; execution gated on baseline classification.** The audit
at `c0bcbc6e9` confirms the target hierarchy and the move maps below against
the current tree. The checkout has documentation edits from other work; it
has no SDK source diff. Preserve those edits and create implementation
worktrees only after this plan lands as a plan-only checkpoint whose SDK
source tree still matches `c0bcbc6e9`.

The 2026-08-05 preflight evidence is:

- `pnpm -C packages/wallet-server type-check` passes.
- The focused Phase 1–2 set has 108 tests: 107 pass, with the pre-existing
  `cloudflareD1RouterApiWalletAuthMethods.unit.test.ts:549` strict ECDSA
  add-signer lifecycle failure (`add-signer ceremony not found`).
- `packageExports.contract.unit.test.ts` passes 12/12.
- `pnpm test:source-guards` reaches the guards and reports two pre-existing
  standalone failures: `check-auth-method-domain-boundaries` finds the two
  conditional auth fallbacks in `registration.ts` (lines 3631 and 4847), and
  `check-signing-engine-ecdsa-identity-boundaries` reports the missing
  `walletSession` on `PMSignTempoPayload`.

The two guard failures and the one focused-test failure are baseline findings.
The integrator records and classifies them before R97 work; no R97 agent fixes
them. Readiness becomes execution-ready when the full baseline commands have
been run and any additional failure is absent or assigned a separate owner.

### Agent and worktree policy

Use five isolated worktrees and branches: one integrator (`I`) and four
workers (`A`–`D`). No agent edits another agent's worktree, and no agent uses
the dirty documentation checkout for implementation. The integrator owns
merge commits, the frozen destination manifest, and every integrated gate. A
shard may be red while it intentionally leaves stale paths for the
path-repair wave; only the integrated checkpoints are gates.

Ownership is fixed for the whole stack:

| Agent | Foundation extraction (serial) | Rename wave (parallel) | Path-repair wave (parallel) |
| --- | --- | --- | --- |
| `I` integrator | Applies and gates each extraction; owns shared importers when a hotspot overlaps | Merges `A` → `B` → `C` → `D`; does not rename files in a worker lane | Merges all repair lanes, runs the resolved import-graph audit, and owns every integrated gate |
| `A` | Fetch helpers, shared Fetch transport (including the signing-session seal Fetch adapter), and WebAuthn codecs | `framework/`, `auth/`, and `framework/ror/` | SDK production import specifiers, excluding hubs owned by `D` |
| `B` | Wallet-registration input types | `domains/walletRegistration`, `walletUnlock`, `emailOtp`, `emailRecovery`, `syncAccount`, and `ecdsa` | Test/helper source paths and `@server/router/...` aliases |
| `C` | Normal-signing D1 split | `domains/ed25519Yao/**` and `domains/signingOperations/**` | Retained source guards and path checks |
| `D` | Versioned-JSON ports and Yao partitioned-state D1 split | `cloudflare/runtime/**`, `cloudflare/d1/**`, and `cloudflare/durableObjects/**` | `cloud-host.ts`, the three adaptors, `src/index.ts`, package export metadata, and the package-export assertion |

The foundation tasks are applied serially because their importer hotspots
overlap. Workers can prepare each patch in its own worktree; only the
integrator applies one patch at a time to the integration branch. This keeps
the first green checkpoint coherent. The rename and repair waves use true
parallel worktrees because their destinations and edit surfaces are disjoint.

### Dependency DAG, parallel waves, and merge order

```text
G0 preflight
  └─ F1 Fetch helpers → F2 shared Fetch transport → F3 WebAuthn codecs
       → F4 wallet inputs → F5 normal-signing D1
       → F6 versioned-JSON/Yao D1 → G1 foundation gate
            └─ (R-A || R-B || R-C || R-D) move-only rename shards
                 → M2 merged structural checkpoint
                      └─ (Q-A || Q-B || Q-C || Q-D) path-repair shards
                           → M3 integrated repair checkpoint → G3 final gates
```

Wave 0 (`G0`) is the integrator's clean-checkout and baseline preflight. Wave
1 (`F1`–`F6`) performs the Phase 1–2 extractions in the ownership table and
lands them before any directory rename. Each extraction includes the importer
updates required to keep the foundation green, with no unrelated renames.
The integrator tags `G1` only after the SDK type-check and focused extraction
tests pass relative to the recorded baseline.

Wave 2 starts all four rename worktrees from the exact `G1` commit. Rename
commits contain `git mv`, directory creation, and no import, export, or logic
edits. Every destination is taken from the move maps below. Individual shards
are expected to be red because path repair is intentionally deferred. The
integrator merges the shards in deterministic order `A`, `B`, `C`, `D`,
recording `M2` before opening repair worktrees.

Wave 3 starts four repair worktrees from `M2`. `A` repairs SDK production
imports, `B` repairs tests and helpers, `C` repairs retained guards, and `D`
repairs public barrels, adaptors, and package surfaces. The integrator merges
`D` first, followed by `A`, `B`, and `C`, then runs the resolved import-graph
audit before recording `M3`. No repair lane changes runtime behavior or
introduces an alias.

### Conflict boundaries

- Foundation ownership stops at the destination and its direct importers. The
  integrator owns `cloud-host.ts`, the three adaptors, `src/index.ts`, package
  metadata, and `packageExports.contract.unit.test.ts` while applying the
  serial foundation patches; Agent `D` owns those hubs in Wave 3.
- Rename workers touch only their destination directories. They do not edit
  import specifiers, barrels, tests, guards, or bundler configuration. A
  `git diff --name-status` review must show move-only commits.
- Wave 3 production repair excludes the public hubs. Test/helper repair owns
  `tests/**` except `tests/scripts/**`; guard repair owns only the relevant
  `tests/scripts/*.mjs` files. Historical docs and unrelated refactor docs are
  outside every lane.
- The `check-wallet-scoped-lookup-boundaries.mjs` recursion change belongs to
  the guard lane. The integrator owns the resolved import-graph report after
  merging all repair lanes; graph violations return to the lane that owns the
  offending import.

### Frozen foundation destinations

These Phase 1–2 destinations are agreed before any worktree is created:

| Boundary | Destination |
| --- | --- |
| Fetch helpers | `framework/http.ts` |
| Shared Fetch router | `transport/fetch/createFetchRouter.ts` |
| Fetch router state/context | `transport/fetch/fetchRouter.types.ts` |
| Signing-session seal Fetch adapter | `threshold/session/signingSessionSeal/transport/fetch.ts` |
| Cloudflare Worker wrapper | `cloudflare/runtime/createCloudflareRouter.ts` |
| Versioned-JSON ports | `framework/versionedJsonRecordStore.ts` |
| Wallet-registration inputs | `domains/walletRegistration/walletRegistrationInputs.ts` |
| WebAuthn credential codecs | `auth/webAuthnCredentialCodecs.ts` |
| Normal-signing D1 admission | `cloudflare/d1/signingAdmission/d1RouterAbNormalSigningAdmissionStore.ts` |
| Yao partitioned-state D1 factory/options | `cloudflare/d1/ed25519Yao/d1Ed25519YaoProductRegistrationPartitionedStateStore.ts` |

No compatibility barrel is created for a moved or deleted module. The
normal-signing domain keeps its port, in-memory store, and adapter; the D1
implementation owns the destination above. The D1 WebAuthn service imports
`auth/webAuthnCredentialCodecs` directly after extraction.

## Phases

Each phase is one commit or a small reviewable stack. Rename-only phases must
contain no logic edits; extraction phases must not mix unrelated renames.

### Phase 0 — Baseline

- Confirm the current 94C/post-90 source tree is the starting point; do not
  wait for a superseded branch or restore deleted routing paths.
- Land this document as a plan-only checkpoint, then create the integration
  and worker worktrees from that exact commit. Confirm the SDK and test source
  trees have no implementation diff in any worktree.
- Record `pnpm -C packages/wallet-server type-check`,
  `pnpm -C tests type-check:unit`, `pnpm check`, `pnpm test:unit`, and
  `pnpm test:source-guards` before moving anything. Root `pnpm check` does not
  replace the explicit SDK-server type-check.
- Classify the three known baseline findings under `AGENTS.md`. Repair a
  production regression in a separate change before `G0`; record a valid
  baseline exception with its owner. No R97 worker repairs unrelated behavior
  while performing this behavior-free refactor.

### Phase 1 — Fetch helpers out of `cloudflare/`

Move `cloudflare/http.ts` to `framework/http.ts` without changing its
contents. Update exactly 22 source importers: 15 Cloudflare files (the
router, self-hosted worker, and 13 route handlers) plus seven Yao modules. The
public-surface lane separately updates the `cloud-host.ts` re-export path.
This phase removes the seven core upward edges and can land independently.

### Phase 2 — Host-neutral ports and codecs

Extract the following boundaries:

1. Extract the shared Fetch transport into `transport/fetch/`:
   - move the route dispatcher and all 13 route-handler modules out of
     `cloudflare/`;
   - move
     `threshold/session/signingSessionSeal/transport/cloudflare.ts` to
     `threshold/session/signingSessionSeal/transport/fetch.ts`, rename
     `CloudflareSigningSessionSealContext` to
     `FetchSigningSessionSealContext`, and update its public barrel and router
     importer;
   - replace `CloudflareRouterApiContext` with `FetchRouterApiContext` and a
     required `FetchRouterRuntime` union with `inline` and `background`
     branches. Only `background` carries a required `waitUntil` callback;
   - rename the shared extension contract from
     `cloudflare_route_extension` / `handleCloudflareRoute` /
     `RouterApiCloudflareRouteExtensionInput` to
     `fetch_route_extension` / `handleFetchRoute` /
     `RouterApiFetchRouteExtensionInput`, with transport discriminator
     `fetch`. The extension input receives the required Fetch runtime union;
     remove the optional `env` and `cfCtx` fields because no current extension
     consumes them;
   - make `express-adaptor.ts` call `createFetchRouter` with the `inline`
     runtime branch. Keep `cloudflare/runtime/createCloudflareRouter.ts` as a
     small Worker adapter that supplies the `background` branch from Worker
     `ctx.waitUntil`; Express supplies `inline`.

   Rename all implementations and tests directly. Do not retain Cloudflare-
   named aliases for this shared contract. The recover-email handler may use
   background execution only from the runtime branch that carries
   `waitUntil`; inline Express execution stays synchronous.
2. Shared versioned-JSON value/read/put/port types into
   `framework/versionedJsonRecordStore.ts`. The Cloudflare Durable Object and
   D1 implementations import those types; the ports do not import either host.
3. `WalletRegistrationSetupInput`, `WalletRegistrationRespondInput`,
   `WalletRegistrationActivateInput`, and
   `WalletRegistrationNearProvisioningInput` into
   `domains/walletRegistration/walletRegistrationInputs.ts`.
4. WebAuthn credential ID/client-data codecs used by export into
   `auth/webAuthnCredentialCodecs.ts`; update `d1WebAuthnAuthService.ts` to
   import that module directly, with no compatibility re-export.
5. Move the Cloudflare D1 implementation, options, and factory for normal-signing
   admission out of `routerAbNormalSigningAdmissionCore` into
   `cloudflare/d1/signingAdmission/d1RouterAbNormalSigningAdmissionStore.ts`.
   Leave the domain port, in-memory store, and admission adapter in the core
   module. Delete the old thin `routerAbNormalSigningAdmissionStore.ts` barrel
   and update every importer to the owning domain or D1 module; do not retain a
   compatibility re-export.
6. Move `createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1`
   and `RouterAbEd25519YaoProductRegistrationPartitionedStateD1OptionsV1` into
   `cloudflare/d1/ed25519Yao/d1Ed25519YaoProductRegistrationPartitionedStateStore.ts`.
   The domain partitioned-state module keeps the host-neutral record store,
   codecs, and state transitions.

After this phase, Express and all host-neutral layers have no runtime edge into
`cloudflare/`.

### Phase 3 — Regroup the root modules (`git mv` only)

Create `framework/`, `auth/`, and `domains/`, move `ror/` to
`framework/ror/`, and apply the top-level move map below. Move every
`.typecheck.ts` twin with its owning module. Keep basenames unchanged and leave
all import/export repair to Phases 5–6.

### Phase 4 — Split Cloudflare responsibilities (`git mv` only)

Move the remaining Cloudflare files into `cloudflare/runtime`,
`cloudflare/d1`, and `cloudflare/durableObjects` per the host move map. The
shared route handlers have already moved to `transport/fetch/routes/` in
Phase 2. Do not create a second `hosts/` level or edit imports in this
move-only phase.

### Phase 5 — Public surfaces and package paths

Adaptors and package export keys stay at their current public paths. Update
their internal imports, the stable `cloud-host.ts` re-export list, and the
root `src/index.ts` barrel for `framework/ror/`. Update the one source path in
`tests/unit/packageExports.contract.unit.test.ts` for
`cloudflare/runtime/cloudflare.types.ts`;
its three adaptor declaration paths remain unchanged.

### Phase 6 — Guard and test path repair

The current SDK path inventory is 80 matching lines (50 unique SDK path
literals) across 15 `tests/scripts/*.mjs` files. Repoint a check when it
protects a live invariant; retire it when it only freezes the old flat source
shape, following [refactor-88B](./refactor-88B-clean-source-guards.md). Do not
add a new source-text guard for this move. Update direct test/helper imports
after the move-only Phases 3–4 and public Phase 5; this includes 78 files with
direct SDK source paths and 10 files (12 import lines) using `@server/router/...`
aliases.

The `check-wallet-scoped-lookup-boundaries.mjs` guard currently reads only
direct `cloudflare/` files. After the D1 moves, make its traversal recursive or
retire it with evidence that the invariant is covered elsewhere; a silent
zero-file scan is invalid. Update its hardcoded `d1WebAuthnRecords` and
`d1NearPublicKeyStore` paths. Inventory the move with:

```sh
rg --glob '*.{ts,tsx,mjs}' 'packages/wallet-server/src/router/' tests packages
rg '@server/router/' tests
```

Historical documents do not require path rewrites. `rolldown` already discovers
`src` recursively and has explicit adaptor inputs; `tsconfig.build.json`
already covers `src/**/*`, so no bundler or TypeScript config-path edits are
expected.

### Phase 7 (optional, separate change) — Basename cleanup

After the directory moves have settled, consider shortening names such as
`routerAbEd25519YaoRegistrationIntentAuthorization.ts` inside the already
scoped Yao directories. Keep this separate from the move stack and skip it if
the churn is not worth the readability gain.

## Move map — router root

| Destination | Current files |
| ----------- | ------------- |
| `framework/` | `apiCredentialPorts`, `applyRouteMetering`, `authServicePort`, `enforceRoutePolicy`, `logger`, `modules`, `routeAuthPolicy`, `routeDefinitions` (+typecheck), `routeExecutionContext`, `routeExtensions`, `routeMeteringPolicy`, `routeRequestValidation`, `routeResponses`, `routerApi` (+`routerApiOptions.typecheck`), `routerApiRouteSurface`, `routerApiWebhooks`, `routerCommand.typecheck`, `runtimeSnapshotConsumer`, and `ror/`; `http` is added by Phase 1 |
| `auth/` | `authRequestValidation`, `commonRouterUtils`, `routerApiCredentialAuth`, `routerApiKeyAuth`, `sessionExchangeRequestValidation`, `verifiedWalletSessionAuth` (+typecheck), `walletSessionFailure`; `webAuthnCredentialCodecs` is added in Phase 2 |
| `domains/walletRegistration/` | `walletRegistrationRoutes`, `walletRegistrationSetupPayload`; `walletRegistrationInputs` is added in Phase 2 |
| `domains/walletUnlock/` | `walletUnlockRequestedCapabilitiesValidation`, `walletUnlockRouteHandlers` |
| `domains/emailOtp/` | `emailOtpExportPolicy`, `emailOtpRequestValidation`, `emailOtpRouteHandlers`, `emailOtpSessionRouteHelpers` |
| `domains/emailRecovery/` | `emailRecoveryRequestValidation`, `recoveryExecutionTracking` |
| `domains/syncAccount/` | `syncAccountRequestValidation` |
| `domains/ed25519Yao/registration/` | `routerAbEd25519YaoHttpRegistrationBackend`, `routerAbEd25519YaoRegistration`, `routerAbEd25519YaoRegistrationExecutionRecord`, `routerAbEd25519YaoRegistrationIntentAuthorization`, `routerAbEd25519YaoRegistrationRequestScopedCloudflare`, `routerAbEd25519YaoRegistrationSideEffectBoundary` (+typecheck), `routerAbEd25519YaoRegistrationTwoPhaseRunner` |
| `domains/ed25519Yao/capabilityLifecycle/` | `routerAbEd25519YaoProductRegistration` (+typecheck), `routerAbEd25519YaoProductRegistrationPartitionedStateStore`, `routerAbEd25519YaoProductRegistrationPartitioning`, `routerAbEd25519YaoProductRegistrationPersistence`, `routerAbEd25519YaoProductRegistrationRequestScopedRunner`, `routerAbEd25519YaoProductRegistrationRequestScopedRuntime` |
| `domains/ed25519Yao/recovery/` | `routerAbEd25519YaoRecovery` (+`RecoveryActivation.typecheck`), `routerAbEd25519YaoRecoveryRequestScopedCloudflare`, `routerAbEd25519YaoRecoveryWalletSessionAuthorization` |
| `domains/ed25519Yao/export/` | `routerAbEd25519YaoExport`, `routerAbEd25519YaoExportRequestScopedCloudflare` |
| `domains/ed25519Yao/session/` | `routerAbEd25519YaoWalletSession` (+typecheck), `thresholdEd25519RequestValidation` |
| `domains/ecdsa/` | `routerAbEcdsaStrictRegistration`, `thresholdEcdsaRequestValidation` |
| `domains/signingOperations/` | `routerAbNormalSigningAdmissionCore`, `routerAbPrivateSigningWorker`; `routerAbNormalSigningAdmissionStore` is deleted in Phase 2 |
| root (unchanged) | `express-adaptor`, `cloudflare-adaptor`, `ror-adaptor` |

## Move map — shared Fetch transport

| Destination | Current files or symbols |
| ----------- | ------------------------ |
| `transport/fetch/createFetchRouter.ts` | Router implementation from `cloudflare/createCloudflareRouter`; rename `createCloudflareRouter` to `createFetchRouter` and `CloudflareRouterApiContext` to `FetchRouterApiContext` |
| `transport/fetch/fetchRouter.types.ts` | Host-neutral Fetch handler and required runtime-state union extracted from `cloudflare.types` and the current router context |
| `transport/fetch/routes/` | `auth`, `emailRecovery`, `health`, `nearPublicKeys`, `normalSigningRouterProxy`, `recoverEmail`, `sessions`, `syncAccount`, `thresholdEcdsa`, `thresholdEd25519`, `walletRegistration`, `webauthnAuthenticators`, `wellKnown` |
| `threshold/session/signingSessionSeal/transport/fetch.ts` | Standard-Fetch signing-session seal handler from `transport/cloudflare.ts`; rename its context to `FetchSigningSessionSealContext` |

`routeExtensions`, its Yao/vault implementations, public barrels, and tests
rename the Cloudflare-specific extension discriminator, input, and handler to
their Fetch equivalents in Phase 2. The old names are deleted.

## Move map — `cloudflare/`

| Destination | Current files |
| ----------- | ------------- |
| `runtime/` | `cloudflare.types`, the new `createCloudflareRouter` Worker wrapper, `createSelfHostedCloudflareSigningWorker`, `email` |
| `d1/emailOtp/` | `d1EmailOtpChallengeIssuer`, `d1EmailOtpChallengeService`, `d1EmailOtpChallengeStore`, `d1EmailOtpChallengeVerifier`, `d1EmailOtpDeliveryRuntime`, `d1EmailOtpEnrollmentStore`, `d1EmailOtpGrantStore`, `d1EmailOtpRateLimitStore`, `d1EmailOtpRecords`, `d1EmailOtpRecoveryEscrowStore`, `d1EmailOtpRecoveryService`, `d1EmailOtpRegistrationEnrollmentFinalizer`, `d1EmailOtpServerSealRuntime`, `d1GoogleEmailOtpRegistrationAttemptStore`, `d1GoogleEmailOtpRegistrationRecords`, `d1GoogleEmailOtpSessionResolver` |
| `d1/registration/` | `d1EvmFamilyEcdsaRegistrationBranch`, `d1RegistrationCeremonyRecordStore`, `d1RegistrationCeremonyRecords`, `d1RegistrationCeremonyStore`, `d1RegistrationIntentService`, `d1WalletRegistrationCommitStore`, `d1WalletRegistrationService`, `d1WalletRegistrationSetup` |
| `d1/session/` | `d1SessionRecords`, `d1SessionService`, `d1SessionStore` |
| `d1/identity/` | `d1IdentityRecords`, `d1IdentityService` |
| `d1/oidc/` | `d1OidcBoundary`, `d1OidcVerificationService` |
| `d1/webauthn/` | `d1WebAuthnAuthService`, `d1WebAuthnRecords`, `d1WebAuthnStore` |
| `d1/auth/` | `d1RouterApiAuthBoundary`, `d1RouterApiAuthConfig`, `d1RouterApiAuthService` |
| `d1/wallet/` | `d1WalletAddSignerService` (+typecheck), `d1WalletAuthMethodBoundary`, `d1WalletAuthMethodService` |
| `d1/authorization/` | `d1AuthorizationStore`, `d1VaultProxyStore` |
| `d1/ed25519Yao/` | `d1Ed25519YaoCapabilityPersistence`, `d1Ed25519YaoWalletSigner`, and `d1Ed25519YaoProductRegistrationPartitionedStateStore` (Phase 2 factory/options) |
| `d1/near/` | `d1NearPublicKeyStore` |
| `d1/signingAdmission/` | `d1RouterAbNormalSigningAdmissionStore` (Phase 2 implementation, options, and factory) |
| `d1/versionedJson/` | `d1VersionedJsonRecordStore` |
| `durableObjects/` | `versionedJsonRecordStore`, `durableObjects/thresholdStore` (the latter keeps its existing basename) |

The removed `d1RegistrationSharedSigningBudget`, `d1RegistrationCeremonyDo`,
`registerCloudflareRoute`, and `routerAbEcdsaDerivationRefreshPort` are not
move targets. They are absent from the current tree and must not be restored
for this reorganisation.

## Blast radius

- `packages/wallet-server/src/cloud-host.ts` has 36 router re-export paths;
  `cloudflare-adaptor.ts` has 15 Cloudflare import paths; `src/index.ts` has
  five router import paths. Update these mechanically, including the deleted
  normal-signing barrel and the moved ROR provider.
- Phase 1 has exactly 22 `http.ts` importers: the Cloudflare router,
  self-hosted worker, 13 route handlers, and seven Yao modules; the
  `cloud-host.ts` re-export is also updated in the public-surface lane.
- The Fetch extraction renames the public route-extension discriminator,
  input type, and handler across four current extension implementations,
  their public barrels, and their tests. `createCloudflareRouter` remains a
  Cloudflare-adaptor entry function backed by `createFetchRouter`; Express
  imports only the latter.
- The same extraction renames the signing-session seal transport file and its
  internal context from Cloudflare to Fetch. Its exported handler name and
  runtime behavior stay unchanged.
- The package export keys remain `./router/express`, `./router/cloudflare`,
  and `./router/ror`; their adaptor declaration paths do not change.
- `tests/unit/packageExports.contract.unit.test.ts` has three adaptor export
  assertions plus one `cloudflare.types.ts` source-path assertion, updated to
  `cloudflare/runtime/cloudflare.types.ts`.
- `rolldown` recursively discovers `src` and receives explicit adaptor inputs;
  `tsconfig.build.json` covers `src/**/*`. No bundler or TypeScript config
  path edits are expected.
- `packages/console-server-ts` consumes only `@seams/wallet-server/cloud-host`
  and has no source-path dependency on this layout.

## Validation gates

### G0 — Preflight baseline

The integrator records the commit, environment, command, and result for:

```sh
git rev-parse --short HEAD
git status --short
pnpm check
pnpm test:unit
pnpm test:source-guards
pnpm -C packages/wallet-server type-check
pnpm -C packages/wallet-server build
pnpm -C tests type-check:unit
```

The explicit SDK commands are required because root `pnpm check` does not run
the `sdk-server-ts` package type-check. The known guard and focused-test
failures listed in the readiness verdict are carried as baseline findings.
Any new failure blocks the next wave until it is classified.

### G1 — Extraction foundation

After each serial extraction, run the narrow focused set. The final `G1` gate
requires all of these tests to pass relative to G0:

```sh
pnpm -C tests exec playwright test -c playwright.unit.config.ts \
  ./unit/cloudflareVersionedJsonRecordStore.unit.test.ts \
  ./unit/cloudflareD1VersionedJsonRecordStore.unit.test.ts \
  ./unit/routerAbEd25519YaoProductRegistrationPartitionedStateStore.unit.test.ts \
  ./unit/routerAbNormalSigningAdmissionStore.unit.test.ts \
  ./unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts \
  ./unit/d1WalletRegistrationCommitStore.unit.test.ts \
  ./unit/walletRegistrationSetupRoute.unit.test.ts \
  ./unit/walletRegistrationRespondRoute.unit.test.ts \
  ./unit/walletRegistrationActivateRoute.unit.test.ts \
  ./unit/routerAbEd25519YaoExport.server.unit.test.ts \
  ./unit/routerAbEd25519YaoRecoveryRequestScoped.unit.test.ts \
  ./unit/routerAbEd25519YaoRegistrationBridge.unit.test.ts \
  ./unit/router.routerApiRouteSurface.unit.test.ts \
  --reporter=line
pnpm -C packages/wallet-server type-check
```

The extraction gate also confirms that Express and `transport/fetch/**` have no
runtime edge into `cloudflare/`, that no source imports
`signingSessionSeal/transport/cloudflare`, and that the deleted normal-signing
barrel has no importer. `packageExports.contract.unit.test.ts` remains a
public-surface gate and is run in G2.

### G2 — Integrated move and repair checkpoint

After the four move-only shards are merged and the four repair lanes are
merged, run:

```sh
pnpm -C packages/wallet-server type-check
pnpm -C packages/wallet-server build
pnpm check
pnpm test:unit
pnpm -C tests exec playwright test -c playwright.unit.config.ts \
  ./unit/packageExports.contract.unit.test.ts --reporter=line
```

The package-export test must retain all 12 assertions, including the stable
`./router/ror` export and ROR adaptor. The only source-path assertion change
is the `cloudflare.types.ts` location. The resolved import graph must show
that `cloudflare/d1/**` and `cloudflare/durableObjects/**` do not import
`transport/fetch/**`, that `transport/fetch/**` does not import `cloudflare/**`,
and that the Express adaptor's runtime graph does not reach any Cloudflare
runtime or persistence implementation. Run
`router.routerApiRouteSurface.unit.test.ts` against the Express and Fetch
surfaces as the transport-parity smoke test.

### G3 — Guard and lifecycle closeout

Run `pnpm test:source-guards` after Phase 6. Every retained path must point to
a live module, and the wallet-scoped lookup guard must recurse through D1
subdirectories or have an evidence-backed replacement. Run
`pnpm test:intended` once as lifecycle insurance; it is not a behavior-change
gate.

### Failure classification and rollback

Stop the active wave on a new failure and compare it with G0. Classify it as
one of the following before changing code:

- Baseline or infrastructure failure: record it and keep R97 behavior-free.
- Mechanical path failure: repair it in the owning Wave 3 lane, then rerun the
  narrow gate.
- A guard that only freezes the retired flat layout: retire or repoint it under
  [refactor-88B](./refactor-88B-clean-source-guards.md). A guard that protects a
  live invariant remains required.
- Behavior, schema, wire, or public-surface change: revert the offending shard
  commit to the last integrated checkpoint and re-plan that extraction; do not
  add a compatibility alias.

The integrator rolls back with `git revert` of the offending shard commit,
retains the last green checkpoint for diagnosis, and reruns the smallest
affected gate. A port extraction that cannot remain host-neutral is paused and
reclassified before any rename work begins. Phase 7 basename cleanup stays a
separate change.

## Non-goals

- No behavior, schema, wire-format, persistence ownership, or public export-key
  changes.
- No changes to the `d1Xxx{Records,Store,Service,Boundary}` naming convention.
- No new compatibility paths, aliases, legacy flags, or source-text guards.
- No `src/router` ↔ `src/core` boundary changes; this reorganises modules
  within the router package only.
- No Postgres store implementation, AWS deployment manifest, or VM process
  manager is added by R97.
