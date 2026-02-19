# Refactor 5 TODO: Unify NEAR with Multichain Signing Pipeline

Status: Draft
Last updated: 2026-02-19

## Goal

Use one signing architecture for all chains:

`chainAdaptor -> intent/sign requests -> executeSigningIntent -> signer backend -> chain finalization`

NEAR should follow the same model as EVM/Tempo. Remove NEAR-only architecture branches as each phase completes.

## Definition of Done

- [ ] NEAR no longer uses `execute()` closure requests.
- [ ] NEAR, EVM, and Tempo all enter through the same orchestration pattern.
- [ ] `signers/wasm` includes a NEAR wasm wrapper for deterministic signer primitives.
- [ ] Worker operation contracts use one consistent typed op-map style across chains.
- [ ] NEAR legacy transport/key-ops wrappers are deleted after migration.
- [ ] No compatibility shims or dual paths remain.

## Phase 1: Type and Intent Model Unification

- [ ] Replace `NearEd25519ExecutionRequest` in `client/src/core/signingEngine/interfaces/near.ts` with a sign-request model aligned to other chains.
- [ ] Keep NEAR request kinds explicit (`transactionsWithActions`, `delegateAction`, `nep413`) but remove executable closures from types.
- [ ] Update `NearEd25519SignOutput` typing to map 1:1 from request kind to result kind.
- [ ] Remove dead/legacy NEAR intent type aliases once callers are migrated.

## Phase 2: Engine and Orchestration Convergence

- [ ] Refactor `client/src/core/signingEngine/signers/algorithms/ed25519.ts` to consume NEAR sign requests directly (no `req.execute()`).
- [ ] Refactor `client/src/core/signingEngine/orchestration/near/nearSigningFlow/index.ts` to only resolve signing inputs and call `executeSigningIntent`.
- [ ] Ensure NEAR request resolution mirrors Tempo/EVM flow shape.
- [ ] Delete now-redundant NEAR flow glue introduced only to support `execute()` closures.

## Phase 3: Introduce `nearSignerWasm`

- [ ] Add `client/src/core/signingEngine/signers/wasm/nearSignerWasm.ts`.
- [ ] Move deterministic NEAR signer-specific primitives into `nearSignerWasm`.
- [ ] Export `nearSignerWasm` from `client/src/core/signingEngine/signers/wasm/index.ts`.
- [ ] Keep orchestration/session/auth logic out of wasm wrappers.

## Phase 4: Worker Contract Unification

- [ ] Unify operation typing in `client/src/core/signingEngine/workers/signerWorkerManager/backends/types.ts` so NEAR follows the same op-map contract style as EVM/Tempo.
- [ ] Simplify `client/src/core/signingEngine/workers/signerWorkerManager/index.ts` request routing to one consistent pattern.
- [ ] Update `client/src/core/signingEngine/workers/operations/executeSignerWorkerOperation.ts` to use the unified contract.
- [ ] Remove NEAR-only wrappers when superseded:
- [ ] `client/src/core/signingEngine/workers/signerWorkerManager/backends/nearWorkerBackend.ts`
- [ ] `client/src/core/signingEngine/workers/signerWorkerManager/nearKeyOpsService.ts`
- [ ] `client/src/core/signingEngine/workers/signerWorkerManager/nearKeyOps/*` (only those replaced by unified ops)

## Phase 5: Vertical Migration by Flow

- [ ] Migrate `client/src/core/signingEngine/orchestration/near/nep413Flow/index.ts` to the unified request model.
- [ ] Migrate `client/src/core/signingEngine/orchestration/near/delegateFlow/index.ts` to the unified request model.
- [ ] Migrate `client/src/core/signingEngine/orchestration/near/transactionsFlow/index.ts` to the unified request model.
- [ ] After each migrated flow, delete legacy branch code immediately.

## Phase 6: API Surface Cleanup

- [ ] Ensure `SigningEngine` public methods expose consistent chain intent entrypoints and no NEAR special-case API shape.
- [ ] Remove deep imports that bypass the unified orchestration entrypoints.
- [ ] Confirm `TatchiPasskey` callers depend on `SigningEngine` public API only.

## Phase 7: Boundary and Architecture Guards

- [ ] Update architecture checks to forbid lower-level modules from importing orchestration internals.
- [ ] Add checks to prevent reintroduction of NEAR execution-closure request types.
- [ ] Add checks to prevent reintroduction of duplicate legacy NEAR signing paths.

## Validation Gates (Run Every Phase)

- [ ] `pnpm -s type-check:sdk`
- [ ] `pnpm -s check:signing-architecture`
- [ ] `pnpm -s test:unit`
- [ ] `pnpm -s build:sdk`

## Final Cleanup Checklist

- [ ] Remove dead exports and unused NEAR legacy symbols.
- [ ] Remove outdated docs that describe old NEAR flow architecture.
- [ ] Verify there is exactly one canonical signing path per chain and the same architecture across chains.
