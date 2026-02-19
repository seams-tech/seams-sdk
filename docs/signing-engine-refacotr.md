# Signing Engine Refactor Plan

Status: Draft  
Last updated: 2026-02-19

## Objective

Restructure signing code around a single conceptual model:

`TatchiPasskey -> SigningEngine -> orchestration -> chainAdaptors/signers`

with this target layout:

```txt
client/src/core/
  signingEngine/
    index.ts
    SigningEngine.ts
    interfaces/
    orchestration/
    chainAdaptors/
    signers/
      algorithms/
      wasm/
      webauthn/
    workers/
    threshold/
    secureConfirm/
```

## Why Refactor

Current code is functionally rich but hard to reason about because dependency direction is not obvious:

- `client/src/core/signingEngine/*` submodules are strongly coupled in a cycle.
- Top-level `core/*` also has cross-module cycles.
- Callers need deep imports instead of one stable signing entrypoint.

The refactor makes ownership explicit:

- `SigningEngine` is the only top-level runtime facade for signing flows.
- `orchestration` is visibly above adaptors/signers.
- interfaces are centralized and reused across modules.

## Scope

In scope:

- Move `client/src/core/signingEngine/*` to `client/src/core/signingEngine/*`.
- Introduce `client/src/core/signingEngine/index.ts`.
- Introduce `client/src/core/signingEngine/SigningEngine.ts`.
- Merge `client/src/core/signingEngine/api/WebAuthnManager.ts` into `SigningEngine` as the canonical signing composition root.
- Rename/organize internals to match the new hierarchy.
- Remove old paths without compatibility re-exports.

Out of scope:

- Protocol/wire format changes.
- Crypto algorithm behavior changes.
- UI redesign.

## Constraints

- No legacy shim exports.
- No duplicate implementations.
- Keep behavior parity for NEAR, Tempo, and EVM signing flows.
- Preserve existing worker contracts and secure-confirm semantics.

## Target Boundaries

Dependency rules after refactor:

1. `interfaces/*` imports nothing from `signingEngine/*` runtime modules.
2. `signers/*`, `chainAdaptors/*`, `workers/*`, `threshold/*`, `secureConfirm/*` may import `interfaces/*`.
3. `orchestration/*` may import `interfaces/*` + lower modules.
4. Lower modules must not import `orchestration/*`.
5. Product modules (`TatchiPasskey`, `WalletIframe`) depend on `signingEngine`, not the reverse.

## Public API

`client/src/core/signingEngine/index.ts`:

- exports the `SigningEngine` facade
- exports public types from `signingEngine/interfaces`
- avoids deep-path imports for external callers

`client/src/core/signingEngine/SigningEngine.ts`:

- is the former `WebAuthnManager` composition root, migrated/renamed
- composes orchestration dependencies
- exposes chain/domain operations (near/tempo/evm and session activation)
- keeps orchestration internals private

## Move Map

Primary moves:

- `client/src/core/signingEngine/orchestration/* -> client/src/core/signingEngine/orchestration/*`
- `client/src/core/signingEngine/chainAdaptors/* -> client/src/core/signingEngine/chainAdaptors/*`
- `client/src/core/signingEngine/algorithms/* -> client/src/core/signingEngine/signers/algorithms/*`
- WebAuthn signer-specific pieces into `client/src/core/signingEngine/signers/webauthn/*`
- wasm signer helpers into `client/src/core/signingEngine/signers/wasm/*`
- `client/src/core/signingEngine/workers/* -> client/src/core/signingEngine/workers/*`
- `client/src/core/signingEngine/threshold/* -> client/src/core/signingEngine/threshold/*`
- `client/src/core/signingEngine/secureConfirm/* -> client/src/core/signingEngine/secureConfirm/*`

Type/interface extraction:

- Move shared signing contracts from former orchestration/types into `signingEngine/interfaces/*`.
- Move runtime dependency interfaces currently buried under chain adaptors into `signingEngine/interfaces/*`.

## Phased Execution

### Phase 0: Baseline and Safety

- Run:
  - `pnpm -s type-check:sdk`
  - `pnpm -s check:signing-architecture`
  - `pnpm -s test:unit`
- Capture baseline failures before refactor changes.

Deliverable:

- Known baseline for type/lint/tests.

### Phase 1: Introduce New Root and Interfaces

- Create:
  - `client/src/core/signingEngine/index.ts`
  - `client/src/core/signingEngine/SigningEngine.ts`
  - `client/src/core/signingEngine/interfaces/*`
- Move shared contracts first (no behavior changes yet).

Deliverable:

- Stable signingEngine entrypoint and interfaces package.

### Phase 2: Move Orchestration

- Move `client/src/core/signingEngine/orchestration/*` to `client/src/core/signingEngine/orchestration/*`.
- Repoint internal imports to `signingEngine/interfaces/*`.
- Keep behavior unchanged.

Deliverable:

- Orchestration fully under `signingEngine/orchestration`.

### Phase 3: Move Execution Modules

- Move chain modules:
  - `chainAdaptors/*`
  - `algorithms/*` to `signers/algorithms/*`
  - wasm signer helpers to `signers/wasm/*`
  - webauthn signer helpers to `signers/webauthn/*`
- Move `workers/*`, `threshold/*`, `secureConfirm/*` under `signingEngine/*`.

Deliverable:

- End-state folder hierarchy exists with updated imports.

### Phase 4: Introduce SigningEngine Facade

- Merge `WebAuthnManager` implementation into `SigningEngine`:
  - move bootstrap wiring from `client/src/core/signingEngine/api/WebAuthnManager.ts`
  - move/retain surface composition (`signingActions`, `thresholdSession`, etc.) under `SigningEngine`
  - update callsites to construct/use `SigningEngine`
- Remove `WebAuthnManager` after migration (no compatibility wrapper).
- Replace direct deep imports in higher-level modules with `signingEngine` entrypoint usage where appropriate.

Deliverable:

- Clear runtime call path: `TatchiPasskey -> SigningEngine`.

### Phase 5: Remove Legacy Paths

- Delete `client/src/core/signingEngine/*` old structure once all imports are migrated.
- No compatibility re-exports.

Deliverable:

- Single canonical location for signing code.

### Phase 6: Boundary Enforcement

- Update architecture checks to reflect new paths and rules.
- Add explicit forbidden import checks:
  - lower modules importing `orchestration/*`
  - product modules imported by `signingEngine/*`
  - deep imports bypassing `signingEngine/index.ts` for public consumers

Deliverable:

- Boundaries enforced by CI checks.

## Validation Gates

Run after each major phase:

- `pnpm -s type-check:sdk`
- `pnpm -s check:signing-architecture`
- `pnpm -s test:unit`
- `pnpm -s test:signers:gates`
- `pnpm -s build:sdk`

Run at finalization:

- `pnpm -s check`

## Success Criteria

- `client/src/core/signingEngine/index.ts` exists and is the canonical entrypoint.
- `SigningEngine` facade exists, and `WebAuthnManager` has been removed/absorbed.
- Old `client/src/core/signingEngine/*` paths are removed.
- No behavior regressions in unit/signer architecture checks.
- Folder hierarchy communicates dependency direction without deep tribal knowledge.
