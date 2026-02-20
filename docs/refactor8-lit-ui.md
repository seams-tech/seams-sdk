# Refactor 8: touchConfirm Lit UI (In-Place Cleanup)

Status: In progress
Last updated: 2026-02-20

## Current Progress

- [x] `ui/index.ts` barrel removed (no side-effectful UI re-export surface).
- [x] `confirm-ui.ts` no longer performs duplicate custom-element definition.
- [x] Initial in-file cleanup completed for portal logic, host prop updates, and intent-digest guard.

## 0. Constraints

- [ ] Keep the existing folder structure largely intact:
  - [ ] `client/src/core/signingEngine/touchConfirm/ui/`
  - [ ] `ui/lit-components/`
  - [ ] `ui/lit-components/ExportPrivateKey/`
- [ ] Prefer in-file cleanup; do not split logic into additional files for this refactor.
- [ ] No legacy aliases, no duplicate implementations, no compatibility code left behind.

## 1. Goals

- [ ] Make each file internally ordered and predictable (imports/constants/types/main implementation/exports).
- [ ] Eliminate random side effects in shared entrypoints.
- [ ] Deduplicate logic currently implemented in multiple files (digest validation, protocol types, style gating).
- [ ] Keep behavior stable while reducing maintenance cost.

## 2. File Organization Standard (Apply Everywhere)

- [ ] Imports grouped in order: external, internal absolute, internal relative, type-only.
- [ ] Constants immediately after imports.
- [ ] Types/interfaces before implementation.
- [ ] Shared utility logic in-file before main classes/functions that use it.
- [ ] Main class/function implementation next.
- [ ] Exports last.
- [ ] No bottom-of-file surprise imports.
- [ ] No mixed module patterns (e.g. default IIFE export plus named exports).

## 3. In-Place Cleanup Plan

### 3.1 `ui` public API hygiene

- [x] Remove wildcard barrel exposure from `ui/index.ts`.
- [x] Stop re-exporting side-effectful modules (`lit-components/ExportPrivateKey/iframe-host` should not be in public barrel).
- [x] Remove `ui/index.ts` to force explicit imports from source modules.

### 3.2 `ui/confirm-ui.ts` cleanup (same location)

- [x] Remove duplicate registration of `w3a-tx-confirmer` from `confirm-ui.ts`.
- [x] Keep one source of truth for `WALLET_UI_OPENED/CLOSED` posting.
- [x] Remove `any` casts for known host props where possible.

### 3.3 `ui/confirm-ui-types.ts` cleanup

- [x] Keep only required exported types.
- [x] Drop redundant `Theme` enum if string union `ThemeName` is sufficient.
- [ ] Ensure types are colocated and not redefined in component files.

### 3.4 `ui/registry.ts` and tag loading

- [x] Define a complete tag->loader map for all dynamically created elements.
- [x] Use one code path for ensure-before-create behavior.
- [ ] Remove ad-hoc local define fallbacks in callsites once loader map is complete.

### 3.5 Export private key flow (same structure, dedupe internals)

- [ ] Keep protocol types co-located in an existing ExportPrivateKey file (no new protocol file).
- [ ] Consume one shared protocol source in:
  - [ ] `ui/lit-components/ExportPrivateKey/iframe-host.ts`
  - [ ] `ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts`
- [ ] Centralize message validation logic instead of copy/pasted checks.
- [ ] Add origin/source checks where runtime constraints permit.

### 3.6 `ui/lit-components/IframeTxConfirmer/*` cleanup

- [ ] Deduplicate:
  - [ ] timeout handling (`MODAL_TIMEOUT`)
  - [ ] theme sync to `document.documentElement`
  - [ ] keyboard ESC handling
  - [ ] canonical confirm/cancel dispatch shape
- [ ] Ensure intent digest logic uses one shared path from `ui/confirm-ui-intent-digest.ts`.

### 3.7 `ui/lit-components/Drawer/index.ts` cleanup

- [ ] Keep file path unchanged.
- [ ] Consolidate complex internals inside `Drawer/index.ts` with clearly separated in-file sections.
- [ ] Remove unused imports (`css`) and stale state fields.
- [ ] Keep one registration pattern (no default-export IIFE registration).

### 3.8 `ui/lit-components/TxTree/*` cleanup

- [ ] Remove legacy `tx-tree` alias registration; keep only canonical `w3a-tx-tree`.
- [ ] Remove unused function params and dead comments in `tx-tree-utils.ts`.
- [ ] Keep tree rendering pure and keep formatting logic in dedicated in-file sections.

### 3.9 `ui/lit-components/css/*` and style gating dedupe

- [ ] Centralize the repeated `_stylesReady/_stylePromises/_stylesAwaiting` pattern in an existing file (no new style-gate file).
- [ ] Update components to use that shared style-gate path.
- [ ] Remove unused fallback logic (if any) in `css-loader.ts` after migration.

### 3.10 Misc small component cleanup

- [ ] Normalize registration style across:
  - [ ] `PasskeyHaloLoading/index.ts`
  - [ ] `HaloBorder/index.ts`
  - [ ] `common/PadlockIcon.ts`
  - [ ] `ExportPrivateKey/viewer.ts`
- [ ] Keep all custom-element registration in one predictable block per file.

## 4. TODO Execution Checklist

### 4.1 API and side-effect cleanup

- [x] Remove `ui/index.ts` barrel.
- [x] Remove side-effect exports from UI entrypoints.


### 4.3 Apply logic consolidation

- [x] Rewire `confirm-ui.ts` to consolidated local logic.
- [ ] Rewire wrapper/modal/drawer confirmer files to shared in-file logic paths.
- [ ] Rewire export iframe host/bootstrap to shared protocol.
- [ ] Rewire components to shared style-gate path (defined in an existing file).

### 4.4 Legacy/dead code deletion

- [x] Delete duplicate digest implementations.
- [ ] Delete legacy `tx-tree` alias define.
- [ ] Delete unused imports/fields/comments found during cleanup.

### 4.5 Verification

- [x] `pnpm -C sdk type-check`
- [ ] `pnpm -C sdk build`
- [x] Run touchConfirm unit tests (or nearest existing target).
- [ ] Manual QA:
  - [ ] modal confirm flow
  - [ ] drawer confirm flow
  - [ ] export private key flow
  - [ ] concurrent confirmer stacking behavior

Notes:
- `pnpm -C sdk build` now passes.

## 5. Done Criteria

- [ ] Folder structure is still largely unchanged.
- [ ] Files follow consistent internal ordering.
- [ ] No duplicate digest/protocol/style-gate logic remains.
- [ ] Public API barrels are side-effect free.
- [ ] No legacy alias tags or compatibility duplicates remain.
- [ ] Build/type-check/tests pass.
