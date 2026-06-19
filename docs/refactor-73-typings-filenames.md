# Refactor 73: Type File Naming For Agent Searchability

Date created: June 19, 2026

Status: planned.

## Goal

Use a consistent `.types.ts` suffix for source-owned type-only modules so
coding agents and humans can quickly find existing domain typings before adding
new ones.

The practical problem is duplicate type definitions in a large codebase. When
an agent misses the relevant existing type, it may create a near-copy with a
slightly different shape. Those copies then need conversion and validation at
boundaries, which adds code bloat and weakens the domain model.

## Naming Convention

- `*.types.ts`: type-only modules. These files should export `type` and
  `interface` declarations, and use `import type`.
- `*.typecheck.ts`: compile-time fixtures for invalid-state rejection,
  `@ts-expect-error`, and type-level guarantees.
- `index.ts`: barrels that re-export a directory's public surface.
- Regular implementation files may export local helper types when the type is
  private to that implementation.

Avoid new `*.typings.ts` files. Rename existing `*.typings.ts` files to
`*.types.ts`.

## Agent Search Contract

Before adding a domain type, search the type surfaces first:

```sh
rg --files packages/sdk-web/src packages/sdk-server-ts/src packages/shared-ts/src tests \
  | rg '(^|/)types/|\.types\.ts$|\.typecheck\.ts$|(^|/)types\.ts$'
```

Then search the specific domain terms:

```sh
rg "LoginHooksOptions|WalletIframeUnlockRequest|SigningSessionStatus|WalletEmailOtpLoginOperation" \
  packages/sdk-web/src packages/sdk-server-ts/src packages/shared-ts/src tests \
  -g '*.types.ts' -g 'types.ts' -g '*.typecheck.ts'
```

Replace the terms with the target domain words for the current refactor.

## Scope

Rename dedicated type modules across:

- `packages/sdk-web/src`
- `packages/sdk-server-ts/src`
- `packages/shared-ts/src`
- `tests`

Do not rename files that contain runtime behavior just because they export
some helper types. Split those only when the type surface is shared enough to
justify a separate file.

## Current Baseline

Observed naming families:

- Current `*.typings.ts`: `packages/sdk-web/src/core/types/login.typings.ts`.
- Existing compliant `*.types.ts` examples:
  - `packages/sdk-web/src/core/indexedDB/keyMaterial.types.ts`
  - `packages/sdk-web/src/core/indexedDB/passkeyClientDB.types.ts`
- Current `types.ts` examples:
  - `packages/sdk-web/src/core/types/seams.ts`
  - `packages/sdk-web/src/core/types/sdkSentEvents.ts`
  - `packages/sdk-web/src/SeamsWeb/publicApi/types.ts`
  - `packages/sdk-web/src/SeamsWeb/signingSurface/types.ts`
  - `packages/sdk-web/src/react/types.ts`
  - many `packages/sdk-server-ts/src/console/*/types.ts` files

## Implementation Plan

### Phase 1: Mechanical `.typings.ts` Cleanup

- Rename `packages/sdk-web/src/core/types/login.typings.ts` to
  `packages/sdk-web/src/core/types/login.types.ts`.
- Rename `packages/sdk-web/src/core/types/login.typings.typecheck.ts` to
  `packages/sdk-web/src/core/types/login.types.typecheck.ts`.
- Update imports and exports.
- Run SDK web type-check and the focused wallet iframe unlock unit test.

### Phase 2: Type-Only `types.ts` Inventory

Create an inventory of `types.ts` files and classify each as:

- type-only public surface: rename to a domain-specific `*.types.ts`.
- directory barrel: replace with `index.ts` when practical.
- mixed runtime and type module: leave in place or split only when the shared
  type surface is causing duplication.

Use this command as the starting point:

```sh
rg --files packages/sdk-web/src packages/sdk-server-ts/src packages/shared-ts/src tests \
  | rg '(^|/)types\.ts$'
```

### Phase 3: Rename High-Value Shared Typing Surfaces

Start with files agents are most likely to miss:

- SDK public API and hook options.
- Wallet iframe message payloads.
- signing session, budget, restore, and lane state.
- Email OTP and passkey auth domain types.
- shared server/client protocol and boundary input types.

Keep each PR or commit scoped to one ownership area.

### Phase 4: Add Source Guards

Add a small guard test that fails on:

- new `*.typings.ts` files.
- new type-only `types.ts` files outside approved barrels.
- runtime exports from `*.types.ts`, except `export type` and interfaces.

Use existing guard-test patterns. Avoid new lint dependencies.

### Phase 5: Update Contributor Docs

Update the repo guidance so future agents know:

- search `*.types.ts` before creating new domain types.
- add `*.typecheck.ts` fixtures for strict domain-state guarantees.
- keep boundary parsers close to raw inputs and normalize into existing domain
  types immediately.

## Validation

For each rename slice:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test -c playwright.unit.config.ts <focused-test> --reporter=line
```

Use broader tests only when the rename touches package exports, generated
types, public API barrels, or runtime bundling.

## Done Criteria

- No `*.typings.ts` files remain.
- Shared type-only modules use `.types.ts`.
- `*.typecheck.ts` files remain compile-time fixtures.
- Agents can find the relevant domain type with one filename search and one
  domain-term search.
- No duplicate compatibility types are introduced during the rename.
