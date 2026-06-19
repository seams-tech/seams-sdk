# Refactor 73: Type File Naming For Agent Searchability

Date created: June 19, 2026

Status: in progress.

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

This refactor is mechanical. Do not combine these renames with semantic changes
to signing, auth, restore, budget, protocol, or lifecycle state. If a file needs
semantic cleanup, do that in the owning refactor first, then return here for the
filename cleanup.

## Guard Rules

`*.types.ts` files may contain:

- `import type ...`
- `export type ...`
- `export interface ...`
- comments
- JSDoc on exported types/interfaces

`*.types.ts` files must not contain runtime exports:

- `export const`
- `export let`
- `export var`
- `export function`
- `export class`
- `export enum`
- side-effect imports
- executable statements

If an existing type-only module needs a runtime validator, split it into:

- `domain.types.ts` for types
- `domain.ts` or `domainParser.ts` for runtime parsing/validation
- `domain.typecheck.ts` for compile-time invalid-state fixtures

Companion fixture convention:

- `foo.types.ts` pairs with `foo.types.typecheck.ts` when the fixture only
  exercises that type module.
- `foo.typecheck.ts` remains valid for broader compile-time fixtures that cover
  an implementation module or directory-level domain.

Approved `types.ts` allowlist:

- public API barrels that are intentionally imported as `.../types`
- directory-level `types.ts` files that still mix too much public API surface to
  rename safely in one mechanical pass
- generated or external-contract files if changing the filename would break an
  external import path

Every allowed `types.ts` file should be listed in the Phase 2 inventory with one
of: `public-barrel`, `mixed-runtime`, `external-contract`, or
`rename-later:<target>`.

## Current Baseline

Observed naming families before Phase 1:

- Renamed `*.typings.ts`: `packages/sdk-web/src/core/types/login.typings.ts`
  is now `packages/sdk-web/src/core/types/login.types.ts`.
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

Status: complete.

- [x] Rename `packages/sdk-web/src/core/types/login.typings.ts` to
  `packages/sdk-web/src/core/types/login.types.ts`.
- [x] Rename `packages/sdk-web/src/core/types/login.typings.typecheck.ts` to
  `packages/sdk-web/src/core/types/login.types.typecheck.ts`.
- [x] Update imports and exports.
- [x] Run SDK web type-check and focused tests:
  - `pnpm -C packages/sdk-web type-check`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/walletIframeUnlockOptions.unit.test.ts --reporter=line`
    because `unit/walletIframeUnlock.unit.test.ts` does not exist, and this is
    the nearest wallet iframe unlock option fixture
    that imports the renamed login types

### Phase 2: Type-Only `types.ts` Inventory

Status: complete.

Created an inventory of `types.ts` files and classified each as:

- type-only public surface: rename to a domain-specific `*.types.ts`.
- directory barrel: replace with `index.ts` when practical.
- mixed runtime and type module: leave in place or split only when the shared
  type surface is causing duplication.

Use this command as the starting point:

```sh
rg --files packages/sdk-web/src packages/sdk-server-ts/src packages/shared-ts/src tests \
  | rg '(^|/)types\.ts$'
```

Inventory captured on June 19, 2026:

| File | Classification |
| --- | --- |
| `packages/sdk-server-ts/src/console/account/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/apiKeys/types.ts` | `mixed-runtime` |
| `packages/sdk-server-ts/src/console/approvals/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/audit/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/auditExports/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/billing/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/billingPrepaidReservations/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/bootstrapTokens/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/enterpriseIsolation/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/gasSponsorship/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/keyExports/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/observability/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/onboarding/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/orgProjectEnv/types.ts` | `mixed-runtime` |
| `packages/sdk-server-ts/src/console/policies/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/runtimeSnapshots/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/sponsoredCalls/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/sponsorshipSpendCaps/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/teamRbac/types.ts` | `mixed-runtime` |
| `packages/sdk-server-ts/src/console/wallets/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/console/webhooks/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/core/ThresholdService/schemes/types.ts` | `rename-later:thresholdServiceSchemes.types.ts` |
| `packages/sdk-server-ts/src/core/types.ts` | `mixed-runtime` |
| `packages/sdk-server-ts/src/email-recovery/types.ts` | `external-contract` |
| `packages/sdk-server-ts/src/router/cloudflare/types.ts` | `rename-later:cloudflare.types.ts` |
| `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts` | `rename-later:signingSessionSeal.types.ts` |
| `packages/sdk-web/src/SeamsWeb/publicApi/types.ts` | `public-barrel` |
| `packages/sdk-web/src/SeamsWeb/signingSurface/types.ts` | `public-barrel` |
| `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/types.ts` | `rename-later:walletIframeHandler.types.ts` |
| `packages/sdk-web/src/core/accountData/near/types.ts` | `rename-later:nearAccountData.types.ts` |
| `packages/sdk-web/src/core/platform/types.ts` | `rename-later:platform.types.ts` |
| `packages/sdk-web/src/core/runtime/types.ts` | `rename-later:runtime.types.ts` |
| `packages/sdk-web/src/core/signingEngine/chains/evm/types.ts` | `rename-later:evmSigning.types.ts` |
| `packages/sdk-web/src/core/signingEngine/chains/tempo/types.ts` | `rename-later:tempoSigning.types.ts` |
| `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/core/signingEngine/session/operationState/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/types.ts` | `rename-later:sealedRecovery.types.ts` |
| `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/core/signingEngine/uiConfirm/types.ts` | `rename-later:uiConfirm.types.ts` |
| `packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/TxTree/renderers/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/react/components/AccountMenuButton/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/react/components/PasskeyAuthMenu/types.ts` | `mixed-runtime` |
| `packages/sdk-web/src/react/types.ts` | `public-barrel` |
| `tests/setup/types.ts` | `external-contract` |

### Phase 3: Rename High-Value Shared Typing Surfaces

Status: scoped to owner-specific follow-up slices.

Start with files agents are most likely to miss:

- SDK public API and hook options.
- Wallet iframe message payloads.
- signing session, budget, restore, and lane state.
- Email OTP and passkey auth domain types.
- shared server/client protocol and boundary input types.

Keep each PR or commit scoped to one ownership area.

Current result: the active `.typings.ts` module was renamed in Phase 1. The
remaining `types.ts` files are explicit public barrels, external contracts,
mixed runtime/type modules, or `rename-later:<target>` rows in the Phase 2
inventory. Each `rename-later` row should be handled by its owning area with
imports and focused validation in the same commit.

### Phase 4: Add Source Guards

Status: complete.

Added `tests/unit/refactor73TypeFilename.guard.unit.test.ts`, which fails on:

- new `*.typings.ts` files.
- new `types.ts` files outside the approved inventory.
- runtime exports from `*.types.ts`, except `export type` and interfaces.
- private top-level runtime declarations in `*.types.ts`.
- side-effect imports from `*.types.ts`.
- broad runtime barrels re-exporting `*.types.ts` as values.

Validation:

```sh
pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/refactor73TypeFilename.guard.unit.test.ts --reporter=line
```

### Phase 5: Update Contributor Docs

Status: complete.

Updated `README.md` so future agents know:

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
