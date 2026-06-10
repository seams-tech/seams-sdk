# Refactor 67 Inventory

Date created: 2026-06-10
Status: implemented inventory

This inventory records the physical source moves completed for the
cross-platform folder reorganization.

## Root Moves

| Previous root | New root | Owner |
| --- | --- | --- |
| `sdk/` | `packages/sdk-web/` | Web SDK package, build scripts, package metadata, distribution config. |
| `client/src/` | `packages/sdk-web/src/` | Browser SDK source, React exports, plugins, theme, wallet iframe, browser UI, signing engine source still owned by web SDK. |
| `client/src/core/runtime/` | `packages/sdk-runtime-ts/src/runtime/` | Extracted platform-neutral runtime entrypoint and runtime config/types. |
| `server/src/` | `packages/sdk-server-ts/src/` | Server library, route adapters, console services, storage, threshold server code. |
| `shared/src/` | `packages/shared-ts/src/` | Shared protocol, console, threshold, and utility TypeScript. |
| `examples/seams-site/` | `apps/web-client/` | Deployable web client. |
| `examples/relay-server/` | `apps/web-server/` | Deployable web server. |
| `examples/seams-docs/` | `apps/docs/` | Docs app. |
| `client/src/core/platform/ios/README.md` | `clients/ios/README.md` | iOS client root documentation. |
| `client/src/core/platform/embedded/README.md` | `crates/seams-embedded/README.md` | Embedded client root documentation. |

## Package Roots

| Package root | Package name | Notes |
| --- | --- | --- |
| `packages/sdk-web` | `@seams/sdk` | Public npm package remains the web SDK package for this migration. Server exports are still surfaced through this package. |
| `packages/sdk-runtime-ts` | `@seams-internal/sdk-runtime-ts` | Workspace-private runtime package. Current extraction covers `runtime/**`; deeper neutral signing/platform extraction remains follow-up work. |
| `packages/sdk-server-ts` | `@seams-internal/sdk-server-ts` | Workspace-private server library source package. |
| `packages/shared-ts` | `@seams-internal/shared-ts` | Workspace-private shared TypeScript package with package exports for `console/*`, `threshold/*`, and `utils/*`. |

## Build And Workspace Files

| File | Reorg action |
| --- | --- |
| `pnpm-workspace.yaml` | Added `packages/*` and `apps/*` roots; removed old `sdk` and app example roots. |
| `package.json` | Updated SDK, site, server, docs, and source-check scripts to the new package/app roots. |
| `packages/sdk-web/package.json` | Updated type paths from `dist/types/client/src` and `dist/types/server/src` to package-rooted type paths. |
| `packages/sdk-web/build-paths.ts` | Updated source, wasm, server, shared, and app paths for the new layout. |
| `packages/sdk-web/build-paths.sh` | Updated shell build paths for the new layout. |
| `packages/sdk-web/rolldown.config.ts` | Updated entries and aliases from old source roots to package roots. |
| `packages/sdk-web/tsconfig*.json` | Updated aliases, includes, excludes, and declaration roots. |
| `apps/web-client/tsconfig.json` | Updated SDK type paths to the new `sdk-web` type output root. |
| `tests/tsconfig.playwright.json` | Updated test aliases to the new package roots. |

## App Import Cleanup

Deployable app code now imports shared package code through
`@seams-internal/shared-ts/*` package exports instead of relative paths into
`packages/shared-ts/src`.

The reorg guard rejects new app imports that reach into package implementation
source through relative `../../packages/*/src` paths.

## Native Roots

| Root | Contents |
| --- | --- |
| `clients/ios` | `Package.swift`, `Sources/SeamsIOS`, `Tests/SeamsIOSTests`, signer-core replay fixture root, iOS adapter README. |
| `crates/seams-embedded` | `Cargo.toml`, `src/lib.rs`, tests/fixtures roots, embedded adapter README. |

## Validation Notes

Validation completed on 2026-06-10:

- `pnpm build:sdk`
- `pnpm type-check:relay-server`
- `pnpm -C apps/web-server build`
- `pnpm run server` starts Postgres through Docker compose and binds
  `http://127.0.0.1:8444`; the verification run was stopped after startup.
- `pnpm site` starts Caddy, the web client Vite dev server, and the docs
  VitePress dev server; the verification run was stopped after startup.
- `pnpm -C packages/shared-ts type-check`
- `pnpm -C apps/docs type-check`
- `pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/refactor67ReorgFolders.guard.unit.test.ts --reporter=line`
- `node packages/sdk-web/scripts/codegen/generate-w3a-components-css.mjs`
- `node packages/sdk-web/scripts/checks/assert-palette-css.mjs packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/css/w3a-components.css`
- `cargo metadata --manifest-path crates/seams-embedded/Cargo.toml --format-version 1 --no-deps`
- `swift test --package-path clients/ios`
