# Refactor25 Plan: Internalize Demo EVM/Tempo Transaction Lifecycle Into SDK

Status: Ready for implementation  
Severity: High (transaction correctness + UX consistency)  
Last updated: 2026-03-01

## 1. Direct Answer

Yes. The transaction-processing pipeline currently implemented in `examples/tatchi-site/src/flows/demo/*` should be internalized into the SDK.

The SDK should own the canonical `sign -> broadcast -> report -> finalize -> reconcile` lifecycle so apps only provide request construction and app-specific post-finalization checks.

## 2. Problem Statement

Today, demo flow code owns critical lifecycle logic:

1. Raw transaction broadcast.
2. Finalization polling and dropped/replaced handling.
3. Nonce lane reporting (`reportBroadcastAccepted`, `reportBroadcastRejected`, `reportFinalized`, `reportDroppedOrReplaced`, `reconcileNonceLane`).
4. Payload integrity checks and retry/error classification.

This duplicates logic that should be shared across all consumers and increases bug risk (including stale payload/surprising-finalization outcomes).

## 3. Scope and Decisions

1. Add a high-level SDK transaction lifecycle API for EVM-family chains (Tempo + ARC/EVM).
2. Keep low-level APIs available for advanced callers, but migrate first-party demo flows to the high-level API.
3. No legacy parallel codepaths in demo flows after migration.
4. No compatibility flags or deprecated aliases.
5. Preserve existing nonce manager behavior and event semantics, but move orchestration ownership into SDK.

## 4. Target Architecture

## 4.1 New SDK capability (high-level)

Add a high-level method on `TempoSignerCapability` for full lifecycle execution.

Proposed shape:

```ts
executeEvmFamilyTransaction(args: {
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  finalization?: {
    timeoutMs?: number;
    pollIntervalMs?: number;
  };
  payloadExpectation?: {
    to?: `0x${string}`;
    input?: `0x${string}`;
  };
  postFinalizationCheck?: () => Promise<void>;
  options?: {
    shouldAbort?: () => boolean;
    onEvent?: (event: LifecycleEvent) => void;
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
}): Promise<{
  txHash: `0x${string}`;
  signedResult: TempoSignedResult | EvmSignedResult;
}>;
```

Notes:

1. `postFinalizationCheck` remains app-owned (example: expected greeting convergence).
2. SDK owns lifecycle/reporting/error mapping and must emit canonical error codes.

## 4.2 Canonical error contract

Normalize lifecycle failures into stable codes, including:

1. `tx_payload_mismatch`
2. `post_finalization_state_mismatch`
3. `tx_dropped_or_replaced`
4. `nonce_lane_blocked`
5. `nonce_conflict_retryable`
6. `aborted`

## 4.3 Ownership boundary

SDK-owned:

1. Signing orchestration and nonce-lifecycle reporting.
2. Broadcast/finalization and dropped/replaced classification.
3. Payload verification helpers.

App-owned:

1. Building chain-specific calldata.
2. UI toasts/loading states.
3. Domain state checks after finalization (optional callback).

## 5. Phased TODO List

## Phase 0: Baseline and guardrails

- [ ] Freeze current behavior with focused regression tests for stale/finalized payload mismatch.
- [ ] Add temporary instrumentation assertions ensuring report calls happen in legal order.
- [ ] Document event/error contract in SDK docs before migration.

Tests:

- [ ] `tests/unit/demoEvmFinalizationDebugEvent.unit.test.ts` includes mismatch + state-convergence cases.
- [ ] `tests/unit/demoThresholdHooks.actions.unit.test.ts` baseline assertions saved before refactor.

## Phase 1: Extract shared lifecycle primitives into SDK

- [ ] Move generic helpers from demo into SDK-level modules:
  `sendRawEvmTransaction`, `waitForEvmTransactionFinalization`, `readEvmTransactionByHash`, payload verifier.
- [ ] Keep helper names/domain clean; remove demo-prefixed duplicates where replaced.
- [ ] Ensure helper interfaces are chain-family generic (tempo + evm).

Candidate files:

- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/rpcClients/evm/*` (new/expanded)
- `client/src/core/TatchiPasskey/tempo/index.ts`

Tests:

- [ ] New unit suite for payload verification and finalization classification in SDK.
- [ ] Existing nonce lifecycle tests still pass:
  `tests/unit/tempo.broadcastNonceLifecycle.unit.test.ts`
  `tests/unit/evmNonceLifecycleMetrics.unit.test.ts`

## Phase 2: Implement high-level SDK transaction lifecycle API

- [ ] Add public types/method signatures in:
  `client/src/core/TatchiPasskey/interfaces.ts`
  `client/src/core/types/tatchi.ts`
  `client/src/index.ts`.
- [ ] Implement method in `client/src/core/TatchiPasskey/tempo/index.ts`.
- [ ] Enforce canonical lifecycle sequence:
  sign -> broadcast -> reportAccepted -> waitFinalization -> verifyPayload -> reportFinalized.
- [ ] On failure, enforce single canonical branch:
  reportRejected OR reportDroppedOrReplaced OR reconcileNonceLane (as appropriate).

Tests:

- [ ] Unit tests for success path.
- [ ] Unit tests for broadcast rejection.
- [ ] Unit tests for dropped/replaced branch.
- [ ] Unit tests for payload mismatch branch.
- [ ] Unit tests for post-finalization check failure branch.

## Phase 3: Migrate demo flows to new SDK API

- [ ] Replace manual lifecycle code in:
  `examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx`
  `examples/tatchi-site/src/flows/demo/hooks/useDemoArcSigningActions.tsx`
  with SDK high-level call.
- [ ] Keep request builders and UI-level post-finalization greeting expectations in demo.
- [ ] Remove manual report helpers in demo once no longer used.

Candidate removals (if unused after migration):

- `examples/tatchi-site/src/flows/demo/hooks/demoEvmTransactionHandling.ts`
- `examples/tatchi-site/src/flows/demo/hooks/reportTempoBroadcastFailure.ts`
- duplicate lifecycle helpers in `examples/tatchi-site/src/flows/demo/demoEvmHelpers.ts`

Tests:

- [ ] Update and pass `tests/unit/demoThresholdHooks.actions.unit.test.ts`.
- [ ] Keep `tests/unit/demoEvmFinalizationDebugEvent.unit.test.ts` green with new integration points.

## Phase 4: Delete legacy duplicates and harden contracts

- [ ] Remove old demo-only lifecycle utilities fully.
- [ ] Remove dead imports and stale symbols in demo hooks.
- [ ] Add static guards (grep/lint/test) preventing reintroduction of duplicate lifecycle implementations under `flows/demo`.

Tests:

- [ ] Targeted unit suite rerun for impacted modules.
- [ ] `pnpm -C tests run test:signers:gates` passes.

## Phase 5: End-to-end regression pass

- [ ] Validate Tempo and ARC demo signing flows with real RPC in e2e.
- [ ] Validate session refresh + retry behavior does not replay stale request payload.
- [ ] Validate dropped/replaced user-visible behavior and error messages.

Tests:

- [ ] `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
- [ ] `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
- [ ] Add/extend a dedicated e2e for "stuck old tx then retry" regression.

## 6. Acceptance Criteria

1. Demo hooks no longer own broadcast/finalization/report orchestration logic.
2. SDK has one canonical high-level lifecycle implementation.
3. No duplicate legacy transaction lifecycle code remains in `flows/demo`.
4. Payload mismatch and stale-state mismatch are surfaced as explicit SDK errors.
5. Unit + e2e suites for Tempo/ARC lifecycle behavior pass.

## 7. Test Execution Checklist

Run at minimum:

1. `pnpm -C tests playwright test ./unit/demoEvmFinalizationDebugEvent.unit.test.ts --reporter=line`
2. `pnpm -C tests playwright test ./unit/demoThresholdHooks.actions.unit.test.ts --reporter=line`
3. `pnpm -C tests playwright test ./unit/tempo.broadcastNonceLifecycle.unit.test.ts --reporter=line`
4. `pnpm -C tests playwright test ./unit/evmNonceLifecycleMetrics.unit.test.ts --reporter=line`
5. `pnpm -C tests playwright test ./e2e/thresholdEcdsa.tempoSigning.test.ts --reporter=line`

## 8. Implementation Notes

1. Prefer moving code, not copying code.
2. If a helper becomes SDK-owned, delete the demo-local variant in the same PR unless still required by another in-flight phase.
3. Breaking changes are acceptable; avoid compatibility shims that preserve old duplicate paths.
