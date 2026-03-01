# Refactor 24: EVM Finalization Reliability Hardening

## Goal
Eliminate remaining "waiting for finalization" freezes and reduce ambiguous EVM pending outcomes with small, high-impact reliability changes.

## Why
Recent fixes closed major dropped/replaced detection gaps, but we still need stronger end-to-end correctness around:
1. Rapid concurrent user actions across Tempo + ARC flows.
2. Ambiguous timeout outcomes that require nonce-lane reconciliation.
3. Fee staleness between periodic refresh and click time.
4. Branch-level observability to distinguish real chain/RPC behavior from client handling regressions.

## Scope
In scope:
1. Finalization handling in demo EVM flows (Tempo + ARC).
2. EVM nonce-lane recovery behavior for timeout outcomes.
3. Fee-cap refresh behavior at sign time.
4. Targeted telemetry and tests.

Out of scope:
1. Protocol-level mempool behavior changes.
2. Deep nonce-manager redesign.
3. Broad UI redesign.

## Hard Invariants
1. Any broadcasted transaction attempt must reach a terminal UI outcome (`success`, `dropped`, `replaced`, `underpriced`, `timeout`, `aborted`) without indefinite loading.
2. Timeout outcomes must trigger explicit nonce-lane recovery, not passive waiting.
3. Sign actions must use fresh fee caps sampled at click time, not only interval-cached values.
4. Finalization telemetry must include deterministic branch/reason fields so outcomes are diagnosable.

## Implementation Plan

## Phase 1: Finalization + Recovery Path Tightening
1. Centralize finalization error handling so both Tempo and ARC flows always execute the same recovery path.
2. Make timeout handling explicit and guaranteed to call nonce-lane reconciliation.
3. Keep dropped/replaced mapping deterministic from `finalizationBranch` and `error.reason`.

## Phase 2: Click-Time Fee Freshness
1. Add immediate fee-cap refresh right before building/signing EIP-1559 requests.
2. Keep interval refresh for UI defaults, but prefer click-time values for submitted requests.
3. Preserve fallback behavior when fee fetch fails (do not block signing path).

## Phase 3: Structured Finalization Telemetry
1. Emit a small structured event per attempt.
2. Include `chain`, `chainId`, `sender`, `nonce`, `txHash`, `branch`, `reason`, `errorCode`.
3. Hook both Tempo and ARC demo flows into the same reporter.
4. Keep event payload minimal and deterministic.

## Phase 4: Reliability Test Coverage
1. Add an unresolved nonce-gap e2e scenario where finalization does not resolve via receipt and recovery must run.
2. Add a rapid alternating Tempo/ARC e2e stress scenario asserting both loading states clear.
3. Keep/extend unit coverage for dropped vs replaced vs timeout classification.

## Phase 5: Cleanup + Docs
1. Remove duplicate per-flow recovery snippets after centralization.
2. Update dropped-tx operational docs with timeout recovery and telemetry fields.
3. Record validation evidence and residual risks in this doc.

## Phased TODO List

### Phase 1
- [x] Introduce shared finalization failure handler used by Tempo + ARC demo signing actions.
- [x] Ensure timeout failures always run `reconcileNonceLane` before surfacing terminal error.
- [x] Verify no callsite can leave loading state without terminal toast/update.

### Phase 2
- [x] Add click-time `resolveEip1559FeeCaps` refresh in Tempo sign flow.
- [x] Add click-time `resolveEip1559FeeCaps` refresh in ARC sign flow.
- [x] Keep non-blocking fallback to last-known/default fee caps on RPC fetch failure.

### Phase 3
- [x] Define structured finalization telemetry type.
- [x] Emit one telemetry event per terminal branch for Tempo.
- [x] Emit one telemetry event per terminal branch for ARC.
- [x] Include `branch` + `reason` parity with `waitForTransactionReceipt` error model.

### Phase 4
- [x] Add e2e: unresolved nonce-gap recovery scenario.
- [x] Add e2e: rapid alternating Tempo/ARC signing stress scenario.
- [x] Add/adjust unit assertions for timeout -> reconcile behavior.

### Phase 5
- [x] Remove duplicated flow-specific recovery code.
- [x] Update `docs/dropped-tx.md` with timeout reconciliation notes.
- [x] Add final validation snapshot to this document.

## File Targets
1. `examples/tatchi-site/src/flows/demo/demoEvmHelpers.ts`
2. `examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx`
3. `examples/tatchi-site/src/flows/demo/hooks/useDemoArcSigningActions.tsx`
4. `examples/tatchi-site/src/flows/demo/hooks/useDemoTempoFeeTokenActions.tsx`
5. `examples/tatchi-site/src/flows/demo/hooks/demoEvmTransactionHandling.ts`
6. `examples/tatchi-site/src/flows/demo/hooks/reportTempoBroadcastFailure.ts`
7. `examples/tatchi-site/src/flows/demo/hooks/reportEvmFinalizationDebugEvent.ts`
8. `tests/unit/demoEvmTransactionHandling.unit.test.ts`
9. `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
10. `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
11. `tests/unit/evmPublicClient.waitForReceipt.unit.test.ts`
12. `tests/unit/reportTempoBroadcastFailure.unit.test.ts`
13. `docs/dropped-tx.md`

## Validation Checklist
1. `pnpm -C sdk run build`
2. `pnpm -C tests exec playwright test ./unit/evmPublicClient.waitForReceipt.unit.test.ts --reporter=line`
3. `pnpm -C tests exec playwright test ./unit/reportTempoBroadcastFailure.unit.test.ts --reporter=line`
4. `pnpm -C tests exec playwright test ./e2e/thresholdEcdsa.tempoSigning.test.ts --reporter=line`
5. `pnpm -C tests exec playwright test ./e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts --reporter=line`

## Validation Snapshot
1. `pnpm -C sdk exec tsc --noEmit -p tsconfig.build.json` ✅
2. `pnpm -C examples/tatchi-site exec tsc --noEmit` ✅
3. `pnpm -C sdk run build` ✅
4. `pnpm -C tests exec playwright test ./unit/demoEvmTransactionHandling.unit.test.ts --reporter=line` ✅
5. `pnpm -C tests exec playwright test ./unit/reportTempoBroadcastFailure.unit.test.ts --reporter=line` ✅
6. `pnpm -C tests exec playwright test ./unit/evmPublicClient.waitForReceipt.unit.test.ts --reporter=line` ✅
7. `pnpm -C tests exec playwright test ./e2e/thresholdEcdsa.tempoSigning.test.ts --reporter=line` ✅
8. `pnpm -C tests exec playwright test ./e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts --reporter=line` ✅

## Residual Risk
1. Mempool/RPC divergence remains an external condition; the client now exits deterministically via dropped/replaced/underpriced/timeout but cannot force chain inclusion.
2. Nonce-lane recovery reporting after terminal errors now runs off the UI critical path to prevent spinner deadlocks; reconciliation still executes, but completion is asynchronous relative to toast/button reset.

## Merge Gates
1. No remaining path where broadcasted tx attempts can leave spinner indefinitely.
2. Timeout outcomes consistently trigger nonce-lane recovery.
3. Both Tempo + ARC use click-time fee caps when signing.
4. Structured branch telemetry is emitted and visible in demo debugging.
5. New e2e stress scenario passes consistently in CI.
