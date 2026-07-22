# Refactor 69C Cleanup 2: Runtime Export And Package Boundary Slimming

Date created: June 18, 2026

Status: complete for the current branch package/runtime scope. Runtime value
exports, hard server-dependency removal from browser installs, and
branch-specific runtime dependency narrowing for this branch are implemented.
The current branch publishes server APIs from `@seams/sdk-server`; the old
optional-peer `@seams/sdk/server` subpaths are deleted.

Primary source of truth:

- [refactor-69C-cleanup-reduce-bloat.md](./refactor-69C-cleanup-reduce-bloat.md)
- [router-ab/protocol.md](./router-ab/protocol.md)
- [audit/router-a-b-diff-review-inventory.md](./audit/router-a-b-diff-review-inventory.md)

## Goal

Finish the package/runtime cleanup discovered during the Refactor 69C diff
audit. The current implementation deleted the tiny private
`packages/sdk-runtime-ts` package and folded its files into
`packages/sdk-web/src/core/runtime`, which is the right direction for reducing
internal package bloat. The follow-up work is to preserve the intended public
runtime export, reduce the larger browser-package dependency bloat, and make the
runtime boundary honest.

## Guardrails

- Keep `packages/sdk-runtime-ts` deleted.
- Keep `packages/shared-ts` as the cross-package shared source boundary.
- Keep `packages/sdk-server-ts` as the public `@seams/sdk-server` source and
  package boundary.
- Do not introduce compatibility aliases for `@seams-internal/runtime`.
- Keep compatibility handling at package import/request boundaries only.
- Do not move signing, replay, quota, budget, Wallet Session, or Router A/B
  protocol semantics as part of this package cleanup.

## Current Findings

### P2: Public Runtime Subpath Lost Value Exports

Status: resolved locally on June 18, 2026. `@seams/sdk/runtime` now exports
`createSigningRuntime` and `createSigningRuntimeStatePorts` from
`packages/sdk-web/src/runtime.ts`, and the runtime-entry bundle check imports
the built package subpath to verify those value exports.

Impact:

- This was a package-fold regression risk: consumers could import the public
  runtime subpath and receive an empty or type-only JS module.
- Keep the focused runtime export smoke test so the public contract cannot drift
  back to type-only exports.

Implemented fix:

- `packages/sdk-web/src/runtime.ts` exports the intended runtime values.
- `packages/sdk-web/scripts/checks/assert-runtime-entry-bundles.mjs` checks the
  built `@seams/sdk/runtime` value exports.
- `packages/sdk-web/src/runtime.typecheck.ts` covers the public runtime types and
  constructors.

Implementation checklist:

- [x] Export the intended runtime values from `packages/sdk-web/src/runtime.ts`,
      or delete the public `./runtime` export.
- [x] Add a unit/build smoke test for `@seams/sdk/runtime` value exports.
- [x] Add a type fixture for `SigningRuntime`, `SigningRuntimeDeps`,
      `SigningRuntimeConfig`, and the runtime state-port types.
- [x] Add a source guard that fails if `@seams-internal/runtime` or
      `packages/sdk-runtime-ts` is reintroduced.
- [x] Update `docs/refactor-69C-cleanup-reduce-bloat.md` if the final
      public contract differs from the current merged 69B section.

## Phase 1: Keep The Runtime Package Fold Clean

The fold should reduce package count without creating a new half-public runtime
surface.

Tasks:

- [x] Remove stale docs that imply `sdk-runtime-ts` remains an independent
      package.
- [x] Keep `packages/sdk-web/rolldown.config.ts` aliases pointed at
      `src/core/runtime`.
- [x] Keep root workspace/package guards proving `packages/sdk-runtime-ts` is
      absent.
- [x] Verify `src/core/runtime` stays under `sdk-web` ownership until a real
      package split is justified.
- [x] Keep `createBrowserSigningRuntime` as the browser assembly entrypoint and
      keep direct runtime service access out of public `SeamsWeb` surfaces.

Validation:

- [x] `rtk rg "@seams-internal/runtime|\\.\\./sdk-runtime-ts|RUNTIME_SRC_ROOT_ABS" packages tests apps`
- [x] `rtk rg "sdk-runtime-ts.*independent|independent.*sdk-runtime-ts" docs --glob '!docs/refactor-69C-cleanup-reduce-bloat.md' --glob '!docs/refactor-69D-cleanup-2.md' --glob '!docs/audit/router-a-b-diff-review-inventory.md'`
- [x] `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/refactor67ReorgFolders.guard.unit.test.ts ./unit/refactor51bPlatformBoundaries.guard.unit.test.ts ./unit/refactor54Simplify.guard.unit.test.ts --reporter=line`

## Phase 2: Split Browser And Server Package Dependency Surfaces

`packages/sdk-web` now owns browser/runtime/react exports only. The server
source package publishes as `@seams/sdk-server`, owns server dependencies, and
exports the root server API, router adapters, Postgres storage helpers, and
server WASM signer subpath. The old `@seams/sdk/server` subpaths are deleted.

Tasks:

- [x] Decide the public package shape for this branch:
      keep `@seams/sdk` browser-first and create a separate server package, or
      keep one published package with truly optional server dependency loading.
- [x] Record the target public server package split and its sequencing:
      implement it after the Router A/B signing/session cleanup stabilizes.

Server-package split tasks:

- [x] Make `packages/sdk-server-ts` publish as `@seams/sdk-server`. Candidate
      shape:
      `@seams/sdk` for browser/runtime/react exports and `@seams/sdk-server` for
      root server APIs, router adapters, Postgres stores, and server WebAuthn
      helpers.
- [x] If the server package split is deferred, move `pg` and
      `@simplewebauthn/server` out of hard browser dependencies and enforce
      dynamic import failure messages at server-only boundaries.
- [x] Move server export maps from `packages/sdk-web/package.json` to the server
      package when the split lands.
- [x] Delete the old `@seams/sdk/server` subpaths when `@seams/sdk-server`
      lands. Breaking changes are acceptable during development.
- [x] Move server dependencies from optional peers in `@seams/sdk` to normal
      dependencies or peers in `@seams/sdk-server`.
- [x] Update app and test imports from `@seams/sdk/server` to
      `@seams/sdk-server`.
- [x] Add package export guard coverage proving `pg` and
      `@simplewebauthn/server` stay out of hard browser dependencies.
- [x] Add browser-only package install/import smoke tests proving an install
      without `pg`, `@simplewebauthn/server`, Express, or Node-only builtins can
      import browser/runtime subpaths.
- [x] Replace current-branch server subpath smoke tests with package split
      smokes proving `@seams/sdk/server` no longer resolves.
- [x] Add `@seams/sdk-server` package smoke tests when the separate public
      server package split lands. Required clean-room smokes: browser install of
      `@seams/sdk` has no server dependencies, and server install of
      `@seams/sdk-server` imports routers, storage, and WebAuthn server paths.

Validation:

- [x] `rtk pnpm -C packages/sdk-web build:rolldown`
      Passed again on June 20, 2026 after removing web-package server build
      entries.
- [x] `rtk pnpm -C packages/sdk-web type-check`
- [x] `rtk pnpm -C packages/sdk-server-ts build`
- [x] `rtk pnpm -C packages/sdk-server-ts type-check`
- [x] Package export guard coverage without hard `pg` and
      `@simplewebauthn/server`.
- [x] Browser-only package install/import smoke test without `pg`,
      `@simplewebauthn/server`, Express, or Node-only builtins.
- [x] Package split smoke test proves `@seams/sdk/server` no longer resolves and
      `@seams/sdk-server` imports root server APIs, router adapters, and
      Postgres storage helpers.

## Phase 3: Make `core/runtime` An Honest Boundary

The folded runtime still imports heavily from `@/...`, worker-manager types,
signing-engine persistence records, and browser assembly ports. This is
acceptable as an internal `sdk-web` composition root, but it should not be
described as a reusable platform-neutral runtime until the boundary is narrower.

Runtime import inventory, June 18, 2026:

| Import source                                                                 | Category            | Current decision                                                                         |
| ----------------------------------------------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `@/core/platform`                                                             | `platform_port`     | Owns `RuntimePorts` and the narrowed ECDSA relayer client port used by runtime assembly. |
| `@/core/types/seams`                                                          | `web_internal`      | SDK-web config shape; keep in `sdk-web` until package config boundaries are split.       |
| `@/core/signingEngine/interfaces/signing`                                     | `state_port`        | Export artifact state is runtime-owned SDK-web state.                                    |
| `@/core/signingEngine/session/persistence/records`                            | `state_port`        | Runtime state ports reference persisted ECDSA session records at the sdk-web boundary.   |
| `@/core/signingEngine/useCases/provisionEcdsa`                                | `runtime_service`   | Provisioning remains a runtime service exposed through `SigningRuntimeServices`.         |
| `@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap` | `runtime_service`   | Registration bootstrap is a runtime service dependency.                                  |
| `@/core/signingEngine/workerManager/executeWorkerOperation`                   | `platform_port`     | Worker execution remains a sdk-web worker port.                                          |
| `@/core/signingEngine/interfaces/operationDeps`                               | `signing_flow_port` | Registration and NEAR signing deps are flow-level ports, not a reusable package API.     |
| `@/core/signingEngine/flows/registration/services/ecdsaWalletRecords`         | `runtime_service`   | Wallet-record access stays a runtime registration service.                               |
| `@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence`     | `state_port`        | Bootstrap persistence stays a runtime state port.                                        |
| `@/core/signingEngine/session/passkey/warmSessionMaterialWriter`              | `web_internal`      | Passkey warm-session material writing is sdk-web/browser-owned.                          |
| `@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions`  | `runtime_service`   | Registration session coordination stays a runtime service.                               |
| `@/core/signingEngine/session/passkey/warmSessionHydration`                   | `runtime_service`   | Warm-session hydration is a runtime service.                                             |
| `@/core/signingEngine/useCases/nearKeyOperations`                             | `runtime_service`   | NEAR key operations expose both a service and a required port.                           |
| `@/core/signingEngine/flows/registration/services/registrationAccounts`       | `runtime_service`   | Registration account lifecycle stays a runtime service.                                  |
| `@/core/signingEngine/flows/signNear/signNear`                                | `signing_flow_port` | Public NEAR signing request/result types are flow-level runtime ports.                   |
| `@/core/signingEngine/flows/signEvmFamily/signEvmFamily`                      | `signing_flow_port` | EVM-family signing and Tempo nonce reporting are flow-level runtime ports.               |
| `@/core/signingEngine/chains/evm/types`                                       | `signing_flow_port` | EVM signing request is a flow input shape owned by sdk-web.                              |
| `@/core/signingEngine/chains/evm/evmAdapter`                                  | `signing_flow_port` | EVM signed result is a flow output shape owned by sdk-web.                               |
| `@/core/signingEngine/chains/tempo/types`                                     | `signing_flow_port` | Tempo signing request is a flow input shape owned by sdk-web.                            |
| `@/core/signingEngine/chains/tempo/tempoAdapter`                              | `signing_flow_port` | Tempo signed result is a flow output shape owned by sdk-web.                             |
| `@/core/types/signer-worker`                                                  | `web_internal`      | Confirmation config still comes from sdk-web worker/public event types.                  |
| `@/core/types/sdkSentEvents`                                                  | `signing_flow_port` | Signing flow events are sdk-web flow telemetry.                                          |
| `@/core/signingEngine/interfaces/ecdsaChainTarget`                            | `signing_flow_port` | Chain target and wallet-session refs remain signing-flow ports.                          |

Inventory result:

- `core/runtime` is an sdk-web composition root, not an independent runtime
  package boundary.
- No additional shared primitive/domain type moves are justified by this
  inventory. Existing `shared-ts` moves stay limited to types already needed by
  more than one package.
- Web-only worker, passkey, confirmation, and chain-flow types stay in
  `sdk-web`; adding another package would hide the ownership boundary without
  removing invalid states.

Tasks:

- [x] Update docs to describe `packages/sdk-web/src/core/runtime` as the
      `sdk-web` TypeScript composition root.
- [x] Inventory every import in `packages/sdk-web/src/core/runtime/types.ts` and
      classify it as:
      `platform_port`, `runtime_service`, `signing_flow_port`, `state_port`, or
      `web_internal`.
- [x] Move genuinely shared primitive/domain types to `packages/shared-ts` only
      when at least two packages need them; this inventory did not identify new
      shared type moves.
- [x] Keep web-only ports and worker types in `sdk-web`; avoid creating a new
      package for them.
- [x] Replace broad `SigningRuntimeDeps` fields with narrower branch-specific
      deps only where it reduces invalid construction.
      Completed on June 18, 2026: removed the exported empty
      `SigningRuntimeUiPorts = Record<never, never>` alias and replaced the
      `ui` dependency branch with concrete `SigningRuntimeUiDeps` /
      `SigningRuntimeWarmSessionUiPorts` types. The rest of the
      `SigningRuntimeDeps` inventory already maps to concrete platform,
      signing-flow, state, registration, worker, and relayer branches; no
      further narrowing was found that would reduce invalid construction without
      moving Router A/B or signing semantics into this package cleanup.
- [x] Add source guards so `core/runtime` does not import React, DOM globals,
      iframe host modules, IndexedDB browser adapters, or server-only packages.

Validation:

- [x] `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/signingRuntime.construction.unit.test.ts --reporter=line`
      Passed again on June 18, 2026 with
      `./unit/refactor51bPackageExports.unit.test.ts` after the runtime UI deps
      narrowing.
- [x] `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/refactor51bPlatformBoundaries.guard.unit.test.ts ./unit/refactor54Simplify.guard.unit.test.ts --reporter=line`
- [x] `rtk pnpm -C packages/sdk-web type-check`
      Passed again on June 18, 2026 after the runtime UI deps narrowing.

## Completion Criteria

- [x] `packages/sdk-runtime-ts` is gone and guarded against reintroduction.
- [x] `@seams/sdk/runtime` has an explicit public contract backed by tests.
- [x] Browser package installs do not hard-require server-only dependencies.
- [x] The remaining server-subpath coupling is documented as an explicit
      packaging follow-up with a split plan.
- [x] `core/runtime` documentation matches its actual ownership and import
      graph.
- [x] Runtime/package cleanup does not change Router A/B signing behavior,
      Wallet Session semantics, replay protection, quota/budget behavior, or
      cryptographic protocol code.
      Completed on June 18, 2026: the branch-specific runtime deps slice only
      changed the public TypeScript runtime dependency type surface and focused
      runtime type fixtures; it did not touch Router A/B signing, Wallet Session,
      replay, quota/budget, or crypto protocol code.
