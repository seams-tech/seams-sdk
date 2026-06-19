# Refactor 67: Reorganize Folders For Cross-Platform Products

Date created: 2026-06-10
Status: implemented, with runtime package extraction later folded back
Owner: SDK architecture

## Purpose

Refactor 51b made the SDK architecture cross-platform internally: `SeamsWeb`
owns browser behavior, `SigningRuntime` owns platform-neutral TypeScript
runtime services, and iOS or embedded implementations receive platform
capabilities through ports.

This plan makes the repository layout match that architecture. The target is a
repo where engineers can find the web client, web server, iOS client, embedded
client, TypeScript SDK packages, Rust crates, and shared protocol code without
having to remember that `client/` currently contains several different
responsibilities.

## Implementation Status

Implemented on 2026-06-10:

- moved the web SDK package from `sdk/` to `packages/sdk-web/`;
- moved browser SDK source from `client/src/` to `packages/sdk-web/src/`;
- moved shared TypeScript source from `shared/` to `packages/shared-ts/`;
- moved server library source from `server/` to `packages/sdk-server-ts/`;
- moved deployable apps from `examples/seams-site`, `examples/relay-server`,
  and `examples/seams-docs` to `apps/web-client`, `apps/web-server`, and
  `apps/docs`;
- moved `core/runtime/**` into `packages/sdk-web/src/core/runtime`;
- created `clients/ios/` and `crates/seams-embedded/` implementation roots;
- updated workspace metadata, root scripts, package paths, build paths,
  TypeScript configs, tests, and app imports for the new roots;
- added `tests/unit/refactor67ReorgFolders.guard.unit.test.ts` to reject old
  implementation roots and deployable app imports through package source paths.

The separate runtime package extraction was folded back because the runtime
source remained small and coupled to existing web SDK core modules. A future
runtime package should be created only when the neutral dependency closure can
stand on its own.

Validation completed on 2026-06-10 after generated WASM artifacts were
restored:

- `pnpm build:sdk`
- `pnpm type-check:relay-server`
- `pnpm -C apps/web-server build`
- `pnpm run server` starts Postgres through Docker compose and binds
  `http://127.0.0.1:8444`; the verification run was stopped with `SIGTERM`
  after startup completed.
- `pnpm site` starts Caddy, the web client Vite dev server, and the docs
  VitePress dev server; the verification run was stopped with `SIGTERM` after
  startup completed.

Additional targeted validation completed during the implementation:

- `pnpm -C packages/shared-ts type-check`
- `pnpm -C apps/docs type-check`
- `pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/refactor67ReorgFolders.guard.unit.test.ts --reporter=line`
- `node packages/sdk-web/scripts/codegen/generate-w3a-components-css.mjs`
- `node packages/sdk-web/scripts/checks/assert-palette-css.mjs packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/css/w3a-components.css`
- `cargo metadata --manifest-path crates/seams-embedded/Cargo.toml --format-version 1 --no-deps`
- `swift test --package-path clients/ios`

## Decision

A direct `client/` to `client-web/` rename is rejected for the first migration
step.

The current `client/` root contains browser-owned code and platform-neutral
code:

- `client/src/SeamsWeb/**` is browser SDK facade code.
- `client/src/react/**`, `client/src/plugins/**`, browser IndexedDB, wallet
  iframe, and DOM UI modules are web-owned.
- `client/src/core/runtime/**` and the neutral parts of
  `client/src/core/platform/**` are cross-platform TypeScript runtime code.
- `client/src/core/platform/ios/README.md` and
  `client/src/core/platform/embedded/README.md` are adapter contracts for future
  non-web implementations.

Renaming the whole folder to `client-web/` would make runtime contracts look
browser-owned. The migration must first separate source ownership, then delete
the old mixed root.

## Current State

| Area | Current location | Problem |
| --- | --- | --- |
| Browser SDK facade | `client/src/SeamsWeb/` | Correct internal boundary, wrong top-level root. |
| React/browser SDK code | `client/src/react/`, `client/src/plugins/`, `client/src/theme/` | Lives beside runtime code under `client/`. |
| Platform-neutral runtime | `client/src/core/runtime/` | Lives under a folder that reads as app-client code. |
| Platform ports | `client/src/core/platform/` | Mixed neutral ports, browser adapter, and native notes. |
| SDK package/build | `sdk/` | Package metadata points at `../client/src` and emits `dist/types/client/src/...`. |
| Server library | `server/src/` | Published through `@seams/sdk/server`, but top-level relation to SDK packages is unclear. |
| Web client app | `examples/seams-site/` | This is a deployable app, not an SDK package. |
| Web server app | `examples/relay-server/` | This is a deployable server app, not the server library. |
| iOS client | Adapter contract only | Needs a native root before implementation starts. |
| Embedded client | `crates/signer-embedded-linux/` plus adapter notes | Needs an SDK facade decision separate from browser TypeScript. |

## Target Top-Level Layout

Use this layout unless a later phase updates this table first.

```text
apps/
  web-client/
  web-server/
  docs/

packages/
  sdk-web/
  sdk-server-ts/
  shared-ts/

clients/
  ios/

crates/
  signer-core/
  seams-embedded/
  signer-embedded-linux/
  ecdsa-hss/
  ed25519-hss/
  threshold-prf/

wasm/
benchmarks/
tests/
docs/
examples/
```

### Area Ownership

| Area | Target location | Notes |
| --- | --- | --- |
| Web SDK package | `packages/sdk-web/` | Owns `SeamsWeb`, React exports, browser plugins, browser platform adapter, IndexedDB, wallet iframe, browser UI, and web build scripts. The npm package may remain `@seams/sdk` during the source move. |
| Runtime TS directory | `packages/sdk-web/src/core/runtime/` | Owns platform-neutral TypeScript runtime composition. It must have no DOM, React, browser storage, wallet iframe, or server route dependencies. |
| Server TS package | `packages/sdk-server-ts/` | Owns server routes, WebAuthn verifier policy, route adapters, storage adapters, and server wasm bindings currently under `server/src`. |
| Shared TS package | `packages/shared-ts/` | Owns protocol/domain TypeScript shared by web SDK, runtime, server, and tests. This can start as a move of `shared/src`. |
| Web client app | `apps/web-client/` | Owns the browser app or site currently represented by `examples/seams-site`. It imports package exports instead of relative source roots. |
| Web server app | `apps/web-server/` | Owns the deployable relay/server app currently represented by `examples/relay-server`. It imports server package exports instead of `server/src`. |
| Docs app | `apps/docs/` | Optional move for `examples/seams-docs`; keep in `examples/` until the app boundary is useful. |
| iOS client | `clients/ios/` | Swift Package Manager root. Owns `SeamsIos`, AuthenticationServices adapter code, Keychain storage, native signer-core bindings, and native replay fixtures. |
| Embedded client | `crates/seams-embedded/` | Rust SDK facade for embedded deployments. Owns `SeamsEmbedded`, Rust signer-core integration, embedded persistence, local secret source adapters, and replay fixtures. |
| Linux embedded adapter | `crates/signer-embedded-linux/` | Linux-specific adapter or test target used by `crates/seams-embedded`. |
| Examples | `examples/` | Keep small integration examples and deployment templates that are not primary apps. |

## Package Boundary Rules

1. `packages/sdk-web` may import `packages/shared-ts`, browser-compatible wasm
   outputs, and browser-only dependencies.
2. `packages/sdk-web` must not import `packages/sdk-server-ts` or server app
   code.
3. `packages/sdk-web/src/core/runtime` may import `packages/shared-ts`,
   generated signer-core schemas, and type-only dependency packages.
4. `packages/sdk-web/src/core/runtime` must not import React, DOM UI modules,
   IndexedDB, browser platform adapters, wallet iframe code, server routes,
   Node database clients, or deployable apps.
5. `packages/sdk-server-ts` may import `packages/shared-ts`, generated schemas,
   server dependencies, and signer-core wasm/server bindings.
6. `packages/sdk-server-ts` must not import `SeamsWeb`, React, wallet iframe
   modules, browser storage, or web app code.
7. `apps/web-client` and `apps/web-server` must consume package exports. They
   must not import implementation files through relative paths such as
   `../../client/src` or `../../server/src`.
8. `clients/ios` must not import npm package implementation files for runtime
   behavior. It may consume committed language-neutral fixtures and generated
   schema artifacts.
9. `crates/seams-embedded` must not depend on npm package exports for runtime
   behavior. It should reuse Rust crates, generated fixtures, and local platform
   adapters.

## Target Source Layout

### `packages/sdk-web`

```text
packages/sdk-web/
  package.json
  src/
    index.ts
    advanced.ts
    threshold.ts
    SeamsWeb/
    react/
    plugins/
    theme/
    browser/
    walletIframe/
  scripts/
  rolldown.config.ts
  build-paths.ts
  tsconfig.json
  tsconfig.build.json
  tsconfig.client-types.json
```

`packages/sdk-web/src/SeamsWeb` remains the public browser facade root. Browser
platform adapters currently under `client/src/core/platform/browser` move under
the web package because they are implementation details of the browser package.

### `packages/sdk-web/src/core/runtime`

```text
packages/sdk-web/src/core/runtime/
  index.ts
  createSigningRuntime.ts
  types.ts
  runtimeConfig.typecheck.ts
```

This directory exposes only neutral contracts and services. If a module needs
`window`, `document`, `navigator`, `IndexedDBManager`, React, wallet iframe
routing, browser workers, `pg`, or Express, it belongs somewhere else.

### `packages/sdk-server-ts`

```text
packages/sdk-server-ts/
  package.json
  src/
    index.ts
    router/
    console/
    core/
    storage/
    threshold/
    wasm/
  tsconfig.json
```

The package owns server library exports. The deployable relay service lives in
`apps/web-server`.

### `apps/web-client`

```text
apps/web-client/
  package.json
  src/
  public/
  vite.config.ts
```

Move `examples/seams-site` here only after the web package exports are stable
enough for the app to avoid relative source imports.

### `apps/web-server`

```text
apps/web-server/
  package.json
  src/
  migrations/
  scripts/
```

Move `examples/relay-server` here after `packages/sdk-server-ts` exposes the
route and server helpers it needs.

### `clients/ios`

```text
clients/ios/
  Package.swift
  Sources/
    SeamsIOS/
  Tests/
    SeamsIOSTests/
  Fixtures/
    signer-core-replay/
  README.md
```

This root owns native iOS implementation work. The `SeamsIos` facade should map
native AuthenticationServices, Keychain, HTTP, clock, random, and signer-core
bindings into the same platform concepts established by Refactor 51b.

### `crates/seams-embedded`

```text
crates/seams-embedded/
  Cargo.toml
  src/
  tests/
  fixtures/
```

This crate owns the embedded Rust SDK facade. It can depend on
`crates/signer-core` and platform adapter crates. It should not route through
TypeScript package exports.

## Migration Strategy

Move package roots in dependency order. The first phases add guardrails and
neutral package boundaries. Later phases move web and server package source.
The final phase deletes the old mixed roots.

## Phase 0: Inventory And Naming Lock

Goals:

- inventory every build, test, package export, docs, and source import that
  refers to `client/src`, `server/src`, `shared/src`, or `sdk/`;
- lock the target root names before code movement starts;
- prevent new path debt while the reorg is in progress.

Tasks:

- [ ] Add `docs/refactor-67-inventory.md` with rows for:
  - [ ] `sdk/build-paths.ts`;
  - [ ] `sdk/build-paths.sh`;
  - [ ] `sdk/rolldown.config.ts`;
  - [ ] `sdk/package.json` exports and `typesVersions`;
  - [ ] `sdk/tsconfig*.json`;
  - [ ] root `package.json` scripts;
  - [ ] `pnpm-workspace.yaml`;
  - [ ] tests that import `../../client/src` or `../../server/src`;
  - [ ] docs that document physical paths;
  - [ ] examples that import implementation files.
- [ ] Record the source owner for each `client/src` subtree:
  - [ ] web package;
  - [ ] runtime package;
  - [ ] server package;
  - [ ] shared package;
  - [ ] test fixture only;
  - [ ] delete.
- [ ] Add a source guard that rejects new `client/src` imports from deployable
      apps after the inventory lands.
- [ ] Add a source guard that rejects new `server/src` imports from deployable
      apps after the inventory lands.
- [ ] Add a temporary path register in this document for aliases and package
      paths that are allowed only during the migration.

Acceptance:

- The inventory can explain where every major current source directory will
  move or why it will stay.
- No new deployable app code imports old implementation roots directly.
- The target names in this plan are treated as canonical unless a later commit
  edits this plan first.

Validation:

- `rtk rg "../client/src|client/src|../server/src|server/src|../shared/src|shared/src|sdk/" package.json pnpm-workspace.yaml sdk tests client server shared examples docs`
- `pnpm -C tests run test:source-guards`

## Phase 1: Introduce Package Roots Without Moving Behavior

Goals:

- create the future package directories in a low-risk way;
- document package boundaries close to the code;
- prepare TypeScript path aliases and workspace entries.

Tasks:

- [ ] Add `packages/README.md` with the package boundary summary.
- [ ] Add placeholder roots:
  - [ ] `packages/sdk-web/README.md`;
  - [ ] `packages/sdk-server-ts/README.md`;
  - [ ] `packages/shared-ts/README.md`.
- [ ] Add future workspace package rows to `pnpm-workspace.yaml` only when each
      root contains a real `package.json`.
- [ ] Add or reserve aliases for:
  - [ ] `@seams-internal/sdk-web/*`;
  - [ ] `@seams-internal/server/*`;
  - [ ] `@seams-internal/shared/*`.
- [ ] Keep existing public package exports unchanged in this phase.

Acceptance:

- New directories exist with ownership docs.
- No runtime or package export behavior changes.
- The repo can still build using the current `sdk/`, `client/`, `server/`, and
  `shared/` roots.

Validation:

- Documentation-only or metadata-only checks for this phase.
- `pnpm -C sdk type-check` if TypeScript aliases or workspace metadata changed.

## Phase 2: Keep Platform-Neutral Runtime Under Web Source

Goals:

- move neutral runtime code out of `client/`;
- keep `packages/sdk-web/src/core/runtime` as the owner of cross-platform
  TypeScript runtime composition until a real standalone package exists;
- keep browser adapters in the web package.

Tasks:

- [ ] Move neutral runtime modules from `client/src/core/runtime/**` to
      `packages/sdk-web/src/core/runtime/**`.
- [ ] Keep neutral platform modules in `packages/sdk-web/src/core/platform/**`
      until they can move without broad signing-engine churn.
- [ ] Move generated signer-core TypeScript schemas only when the destination
      has a real independent owner.
- [ ] Update imports in web, server, tests, and build scripts to use
      `@/core/runtime/*`.
- [ ] Keep `client/src/runtime.ts` as a temporary forwarding file only until the
      web package move. The forwarding file must be listed in the temporary path
      register.
- [ ] Add guards that reject React, DOM globals, IndexedDB, wallet iframe, and
      browser adapter imports from `packages/sdk-web/src/core/runtime/**`.
- [ ] Add guards that reject `packages/sdk-web/src/core/runtime` importing
      server routes, Node database clients, or deployable apps.

Acceptance:

- Runtime source has a stable owner under `packages/sdk-web/src/core/runtime`.
- `SigningRuntime` can still be constructed by browser tests with browser
  platform ports.
- Native and embedded adapter contracts do not point at deleted `client/`
  paths.

Validation:

- `pnpm -C sdk type-check`
- `pnpm -C tests run test:source-guards`
- `pnpm -C tests run test:unit -- ./unit/signingRuntime.construction.unit.test.ts`
- `pnpm -C tests run test:unit -- ./unit/platformAdapter.conformance.unit.test.ts`

## Phase 3: Move The Web SDK Package

Goals:

- move browser-owned SDK code from `client/` and `sdk/` into
  `packages/sdk-web`;
- keep `SeamsWeb` as the public browser facade;
- remove `dist/types/client/src/...` from package metadata.

Tasks:

- [ ] Move `sdk/package.json`, `sdk/scripts/**`, `sdk/rolldown.config.ts`,
      `sdk/build-paths.ts`, `sdk/build-paths.sh`, and `sdk/tsconfig*.json` to
      `packages/sdk-web/`.
- [ ] Move browser SDK source to `packages/sdk-web/src/**`:
  - [ ] `client/src/index.ts`;
  - [ ] `client/src/advanced.ts`;
  - [ ] `client/src/threshold.ts`;
  - [ ] `client/src/SeamsWeb/**`;
  - [ ] `client/src/react/**`;
  - [ ] `client/src/plugins/**`;
  - [ ] `client/src/theme/**`;
  - [ ] browser adapters and IndexedDB modules;
  - [ ] wallet iframe and browser UI modules.
- [ ] Move any remaining browser-owned signing assembly from `client/src/core/**`
      after confirming it is excluded from the runtime package.
- [ ] Update `rolldown.config.ts` entrypoints from `../client/src` to
      `src` and runtime package imports.
- [ ] Update package exports so type paths point at `dist/types/src/...` or a
      stable package-local type path.
- [ ] Update root scripts from `pnpm -C sdk ...` to
      `pnpm -C packages/sdk-web ...`.
- [ ] Update `pnpm-workspace.yaml`.
- [ ] Add guards that reject new `client/src` imports from
      `packages/sdk-web/src/**`.
- [ ] Delete obsolete forwarding files created for the web move in the same
      phase once all call sites are updated.

Acceptance:

- The web SDK builds from `packages/sdk-web`.
- Public imports continue to expose `SeamsWeb`, React, runtime, plugins, and
  wallet iframe exports according to the package contract.
- `sdk/` is either deleted or contains only a temporary README pointing at
  `packages/sdk-web`, listed in the temporary path register.
- `client/` contains no web-owned source after this phase.

Validation:

- `pnpm -C packages/sdk-web type-check`
- `pnpm -C packages/sdk-web build`
- `pnpm -C tests run test:source-guards`
- package export smoke tests
- wallet iframe unit tests

## Phase 4: Move Server Library And Web Server App

Goals:

- separate server library exports from the deployable server app;
- keep server verification and route code out of browser packages;
- give the web server a first-class app root.

Tasks:

- [ ] Move `server/src/**` to `packages/sdk-server-ts/src/**`.
- [ ] Add `packages/sdk-server-ts/package.json` and package-local tsconfig.
- [ ] Move server package exports from `packages/sdk-web/package.json` to the
      server package when the package split is accepted.
- [ ] If a single npm package remains required temporarily, keep server exports
      in `packages/sdk-web/package.json` as forwarding build entries and list
      them in the temporary path register.
- [ ] Move `examples/relay-server` to `apps/web-server`.
- [ ] Update app imports to use `packages/sdk-server-ts` exports.
- [ ] Add guards that reject `SeamsWeb`, React, wallet iframe, browser platform
      adapters, and browser storage imports from `packages/sdk-server-ts`.
- [ ] Add guards that reject deployable server app code importing package
      implementation files through relative paths.

Acceptance:

- Server library source lives under `packages/sdk-server-ts`.
- The deployable web server lives under `apps/web-server`.
- Server tests and route verification policy tests run from the new package
  paths.

Validation:

- `pnpm -C packages/sdk-server-ts type-check`
- `pnpm -C apps/web-server type-check`
- `pnpm -C tests run test:relayer`
- `pnpm -C tests run test:source-guards`

## Phase 5: Move Web Client App

Goals:

- make the web client a first-class app;
- stop treating the primary app as an example;
- keep examples for small integration templates.

Tasks:

- [ ] Move `examples/seams-site` to `apps/web-client`.
- [ ] Update workspace entries and root scripts:
  - [ ] `site`;
  - [ ] `caddy`;
  - [ ] web app build or preview scripts.
- [ ] Update app imports to use package exports.
- [ ] Move app-specific public assets with the app.
- [ ] Keep SDK distribution assets under `packages/sdk-web`.
- [ ] Decide whether `examples/seams-docs` stays in `examples/` or moves to
      `apps/docs`. Update this plan before moving it.

Acceptance:

- The web client runs from `apps/web-client`.
- The web client imports no source implementation files through relative paths.
- `examples/` contains integration examples and deployment templates only.

Validation:

- `pnpm -C apps/web-client type-check`
- `pnpm -C apps/web-client build`
- focused browser smoke or existing app e2e tests

## Phase 6: Add Native Client Roots

Goals:

- give iOS and embedded work stable roots before implementation;
- move native adapter contracts out of browser package paths;
- align native fixtures with signer-core and runtime contracts.

Tasks:

- [ ] Create `clients/ios/README.md` from the current iOS adapter contract.
- [ ] Create `clients/ios/Package.swift` once implementation starts.
- [ ] Add `clients/ios/Fixtures/signer-core-replay/` for native replay
      fixtures.
- [ ] Move iOS RP ID and Associated Domains docs from
      `client/src/core/platform/ios/README.md` to `clients/ios/README.md`.
- [ ] Create `crates/seams-embedded/README.md` from the current embedded adapter
      contract.
- [ ] Create `crates/seams-embedded/Cargo.toml` when the facade crate starts.
- [ ] Move embedded adapter notes from
      `client/src/core/platform/embedded/README.md` to
      `crates/seams-embedded/README.md`.
- [ ] Decide whether `crates/signer-embedded-linux` becomes an adapter crate,
      an example target, or is folded into `crates/seams-embedded`.
- [ ] Add guards that reject npm package implementation imports from native
      roots.

Acceptance:

- iOS implementation work has a Swift package root.
- Embedded implementation work has a Rust crate root or a documented crate
  creation trigger.
- Native docs reference runtime contracts without living under browser package
  source paths.

Validation:

- `cargo metadata` after `crates/seams-embedded/Cargo.toml` exists.
- Swift package checks once `Package.swift` exists.
- `pnpm -C tests run test:source-guards`

## Phase 7: Rehome Tests By Boundary

Goals:

- make tests follow package and app ownership;
- preserve broad integration tests while narrowing source imports;
- delete tests that only protect old physical paths.

Tasks:

- [ ] Keep the top-level `tests/` package during the first moves.
- [ ] Add package-aware test directories:
  - [ ] `tests/unit/sdk-web/`;
  - [ ] `tests/unit/sdk-server-ts/`;
  - [ ] `tests/integration/web-client/`;
  - [ ] `tests/integration/web-server/`;
  - [ ] `tests/native-replay/`.
- [ ] Update fixtures that import `../../client/src` to import package source
      through test aliases or public package entrypoints.
- [ ] Delete tests that only assert old `client/`, `sdk/`, or `server/` path
      names.
- [ ] Preserve tests that assert real architecture boundaries under their new
      paths.

Acceptance:

- Tests read naturally by package or app boundary.
- Source guard tests protect the new root layout.
- Old-path-only assertions are deleted.

Validation:

- `pnpm -C tests run test:unit`
- `pnpm -C tests run test:source-guards`
- focused e2e suites for any app moves

## Phase 8: Delete Legacy Roots

Goals:

- remove the old mixed roots;
- make path regressions obvious;
- finish the folder reorg without compatibility shims.

Tasks:

- [ ] Delete `client/` after all source has moved or been deleted.
- [ ] Delete `sdk/` after the web package move is complete.
- [ ] Delete `server/` after server package and app moves are complete.
- [ ] Delete temporary forwarding files and aliases listed in the temporary path
      register.
- [ ] Update docs that mention old physical paths.
- [ ] Add guards that fail if `client/src`, `sdk/`, or `server/src` are
      recreated for implementation code.
- [ ] Update root `README` or architecture docs with the new layout.

Acceptance:

- `rtk rg "client/src|../client|server/src|../server|pnpm -C sdk|dist/types/client/src" package.json pnpm-workspace.yaml packages apps clients crates tests docs` returns only historical refactor docs or explicit migration history.
- No package export points at old source-root type paths.
- No temporary path register entries remain active.

Validation:

- `pnpm -C packages/sdk-web build`
- `pnpm -C packages/sdk-web type-check`
- `pnpm -C packages/sdk-server-ts type-check`
- `pnpm -C apps/web-client build`
- `pnpm -C apps/web-server type-check`
- `pnpm -C tests run test:source-guards`
- targeted unit and e2e suites affected by moved paths

## Temporary Path Register

Every temporary path must have an owner phase and a deletion trigger before it
is introduced.

| Temporary path or alias | Owner phase | Deletion trigger | Guard |
| --- | --- | --- | --- |
| `@/* -> client/src/*` | Phase 3 | `packages/sdk-web/src/**` imports no `client/src` files | source guard |
| `client/src/runtime.ts` forwarding export | Phase 2 | web package imports runtime package entrypoint directly | source guard |
| `sdk/` root | Phase 3 | `packages/sdk-web` owns package metadata and build scripts | source guard |
| `server/src` root | Phase 4 | `packages/sdk-server-ts` owns server package source | source guard |
| `shared/src` root | Phase 4 or earlier | `packages/shared-ts` owns shared TypeScript source | source guard |

## Guard Tests

Add or update guards for:

- no new deployable app imports from `client/src`, `server/src`, `shared/src`,
  or package implementation files;
- no React, DOM globals, browser storage, browser platform adapter, or wallet
  iframe imports from `packages/sdk-web/src/core/runtime/**`;
- no server route, Express, `pg`, Node database, or deployable app imports from
  `packages/sdk-web/src/core/runtime/**`;
- no server package imports from `packages/sdk-web/src/**`;
- no `SeamsWeb`, React, wallet iframe, browser adapter, or browser storage
  imports from `packages/sdk-server-ts/src/**`;
- no npm package implementation imports from `clients/ios/**` or
  `crates/seams-embedded/**`;
- no package export type path containing `dist/types/client/src`;
- no implementation code under deleted roots after Phase 8.

## Package Export Policy

During the source move, public package names are a separate decision from source
folder names.

Recommended migration:

1. Keep `@seams/sdk` as the web SDK package name while moving source into
   `packages/sdk-web`.
2. Keep `@seams/sdk/runtime` as a web package export. Create a separate runtime
   package only when it has an independent dependency closure.
3. Keep `@seams/sdk/server` as a web package export only until the server
   package split is accepted.
4. Add new published package names in a later plan if product packaging needs
   them. Source boundaries should land first.

## Review Checklist

Before merging a phase:

- Does this move reduce the responsibilities hidden under `client/`, `sdk/`, or
  `server/`?
- Does the moved code land in the package, app, client, or crate that owns its
  runtime behavior?
- Are browser-only dependencies kept out of runtime, server, iOS, and embedded
  roots?
- Are deployable apps consuming package exports instead of implementation files?
- Did this phase delete obsolete aliases, forwarding files, docs, tests, and
  old-path guards made stale by the move?
- Are temporary paths listed with an owner phase, deletion trigger, and guard?
- Did validation match the risk of the phase?

## Final Target State

- `packages/sdk-web` is the browser TypeScript SDK source root.
- `packages/sdk-web/src/core/runtime` owns platform-neutral TypeScript runtime
  composition.
- `packages/sdk-server-ts` owns server library exports.
- `apps/web-client` owns the deployable web client.
- `apps/web-server` owns the deployable web server.
- `clients/ios` owns the native iOS client.
- `crates/seams-embedded` owns the embedded Rust client.
- `client/`, `sdk/`, and `server/` no longer contain implementation source.
- Source guards enforce the new boundaries.
