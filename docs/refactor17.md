# Refactor 17: TouchConfirm Boundary Lockdown (Single Runtime Bridge)

Status: Planned  
Severity: High (architecture boundary drift / confirmation surface sprawl)  
Last updated: 2026-02-23

## 1. Problem Statement

`TouchConfirmManager` is still referenced directly across multiple JS main-thread modules (orchestration + API wiring).  
This creates two risks:

1. Boundary drift: confirmation orchestration can leak back into business logic modules.
2. Regression risk: direct manager access makes it easy to reintroduce shortcut paths that bypass intended worker-owned flow boundaries.

Refactor 10 fixed export-flow shortcuts, but the broader surface still allows direct manager usage.  
This refactor standardizes one rule:

- `TouchConfirmManager` is an internal implementation detail behind one runtime bridge module.

## 2. Scope and Decisions

1. Introduce one canonical runtime bridge module that owns direct `TouchConfirmManager` calls.
2. Keep manager construction in bootstrap, but do not expose manager instance beyond bridge wiring.
3. Replace broad `touchConfirmManager` dependency injection with narrow, purpose-specific ports.
4. Remove compatibility aliases and legacy duplicate paths as modules are migrated.
5. Preserve current behavior; this is boundary/ownership hardening, not product behavior change.

## 3. Invariants

- Only bridge module(s) may invoke `TouchConfirmManager` methods directly.
- Non-bridge modules must depend on narrow ports/functions, never on `TouchConfirmManager` type.
- No direct import of `createTouchConfirmManager` outside manager assembly.
- No direct access in app/business modules to:
  - `requestUserConfirmation`
  - `orchestrateSigningConfirmation`
  - `exportPrivateKeysWithUi`
  - `requestRegistrationCredentialConfirmation`
  - PRF session cache methods (`put/peek/dispense/clear`)
- No dual path: once a callsite is migrated, remove old manager-based path immediately.

## 4. Target Architecture

## 4.1 Single Bridge Module

Create a canonical bridge module (suggested path):

- `client/src/core/signingEngine/bootstrap/touchConfirmBridge.ts`

Responsibilities:

1. Hold the only direct reference to `TouchConfirmManager` outside manager assembly.
2. Expose narrow ports for each use-case cluster.
3. Translate runtime concerns (timeouts/progress/options) without leaking manager type.

## 4.2 Narrow Port Surface

Replace generic manager injection with explicit ports, for example:

1. `SigningConfirmationPort` for near/evm/tempo confirmation orchestration.
2. `RegistrationConfirmationPort` for registration confirmation flow.
3. `ExportConfirmationPort` for `ExportPrivateKeysWithUi` worker operation.
4. `ThresholdPrfSessionCachePort` for PRF.first warm-session cache primitives.

## 4.3 Runtime DI Rule

`SigningRuntimeDeps` and downstream API/orchestration deps must accept only narrow ports.  
No `touchConfirmManager` property in broad runtime interfaces.

## 5. Implementation Plan

## Phase 0: Baseline Inventory and Cut Lines

- [ ] Capture current direct usage map with `rg` for:
  - `touchConfirmManager`
  - `TouchConfirmManager`
  - `createTouchConfirmManager`
- [ ] Define allowlist files for temporary direct usage during migration.
- [ ] Confirm export path remains on narrow worker-op callback (already landed in Refactor 10 follow-up).

Suggested files:

- `client/src/core/signingEngine/**`
- `sdk/scripts/lib/worker-runtime-boundaries.mjs`

## Phase 1: Introduce Bridge and Ports

- [ ] Add `touchConfirmBridge.ts` with explicit port interfaces + factory.
- [ ] Move direct manager calls behind bridge methods.
- [ ] Export only bridge contracts from bootstrap/runtime DI entrypoints.

Suggested files:

- `client/src/core/signingEngine/bootstrap/touchConfirmBridge.ts` (new)
- `client/src/core/signingEngine/bootstrap/managerAssembly.ts`
- `client/src/core/signingEngine/touchConfirm/types.ts` (if contract extraction is needed)

## Phase 2: Migrate Dependency Injection

- [ ] Remove broad `touchConfirmManager` from generic runtime deps.
- [ ] Inject narrow bridge ports into orchestration dependency bundle.
- [ ] Keep compile breakage intentional to force complete migration (no back-compat shim).

Suggested files:

- `client/src/core/signingEngine/interfaces/runtime.ts`
- `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
- `client/src/core/signingEngine/workerManager/index.ts`

## Phase 3: Migrate Call Sites (No Dual Paths)

- [ ] Near signing flows (`transactions`, `delegate`, `nep413`) use bridge ports only.
- [ ] EVM/Tempo signing flows use bridge ports only.
- [ ] Registration/session lifecycle modules use bridge ports only.
- [ ] Remove direct manager-type imports from migrated modules.

Likely files:

- `client/src/core/signingEngine/orchestration/near/*.ts`
- `client/src/core/signingEngine/orchestration/evm/*.ts`
- `client/src/core/signingEngine/orchestration/tempo/*.ts`
- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/signingEngine/api/registration/*.ts`
- `client/src/core/signingEngine/api/session/*.ts`

## Phase 4: Enforcement Guardrails (CI)

- [ ] Add/extend static boundary check to fail when forbidden direct usage appears outside allowlist.
- [ ] Check patterns:
  - direct import/use of `TouchConfirmManager`
  - direct `touchConfirmManager.` callsites
  - direct import/use of `createTouchConfirmManager` outside manager assembly
- [ ] Keep checks strict and fail-closed (no warning-only mode).

Suggested files:

- `sdk/scripts/lib/worker-runtime-boundaries.mjs`
- `sdk/scripts/checks/check-worker-runtime-boundaries.mjs`
- `package.json` (if check wiring updates are needed)

## Phase 5: Tests and Verification

- [ ] Unit: bridge routes each operation to manager correctly.
- [ ] Unit: orchestration modules compile/run with bridge ports and without manager type.
- [ ] Unit: export hardening tests remain green.
- [ ] Architecture check: no direct manager usage outside allowlist.
- [ ] Regression run:
  - `pnpm test:unit`
  - `pnpm test:wallet-iframe`
  - `pnpm -s check:signing-architecture`
  - `pnpm -C sdk type-check`

Suggested tests:

- `tests/unit/touchConfirm.workerRouter.unit.test.ts`
- `tests/unit/privateKeyExportRecovery.hardening.unit.test.ts`
- `tests/unit/*near*`
- `tests/unit/*evm*`
- `tests/unit/*tempo*`

## 6. Risks and Mitigations

1. Large compile break blast radius during DI migration.  
Mitigation: phase by dependency bundles, land small vertical slices.

2. Hidden behavior changes while renaming deps.  
Mitigation: no logic changes in same commits; keep refactor commits mechanical.

3. Temporary dual-path temptation.  
Mitigation: explicit “no dual path” rule + immediate deletion of replaced path.

4. Incomplete enforcement lets regressions back in.  
Mitigation: CI check is required in `check:signing-architecture`.

## 7. Done Criteria

- [ ] No non-bridge module directly references `TouchConfirmManager`.
- [ ] No non-bridge module directly calls manager methods.
- [ ] `SigningRuntimeDeps` no longer exposes broad `touchConfirmManager`.
- [ ] Static boundary checks enforce the rule and are green.
- [ ] Unit + integration suites are green with no behavior regressions.

## 8. Phased TODO List

## Immediate

- [ ] Add bridge module + narrow contracts.
- [ ] Migrate runtime DI for export/registration/session first.
- [ ] Remove direct manager dependency from `SigningRuntimeDeps`.

## Next

- [ ] Migrate near/evm/tempo orchestration call sites.
- [ ] Delete leftover manager-type imports in migrated files.
- [ ] Land strict CI guardrails for forbidden direct usage.

## Finalize

- [ ] Run full regression suite + architecture checks.
- [ ] Refresh architecture docs with final allowed direct-usage allowlist (should be bridge + assembly only).
- [ ] Treat any new direct manager callsite as release-blocking regression.
