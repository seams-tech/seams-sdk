# Signing Session Architecture

Date created: 2026-04-23

## Objective

Keep transaction signing on one selected lane from readiness through auth, signing,
budget accounting, and cleanup.

The architecture should make these invariants explicit:

1. Lane resolution happens before planning.
2. The planner only plans for a concrete lane.
3. Operation identity is separate from lane identity.
4. No auth side effect starts before the tx confirmer owns the flow.
5. Budget accounting uses the confirmed operation id, not a pre-confirm planner artifact.

## Current Flow

`SigningSessionCoordinator` is the chain-facing transaction signing boundary. It
resolves or receives the selected lane, reads warm-session readiness, calls the
pure planner, drives the execution machine, delegates side effects to executors,
and finalizes budget plus cleanup.

```ts
const laneResult = await signingSessionCoordinator.resolveLane(operationRequest);
if (laneResult.kind === 'blocked') return laneResult;

const readiness = await signingSessionCoordinator.readWarmSessionReadiness(laneResult.lane);
const plan = signingSessionCoordinator.plan({
  lane: laneResult.lane,
  readiness,
  forceFreshAuth,
  sensitiveOperationPolicy,
});

const machine = signingSessionCoordinator.createExecutionMachine({
  plan,
  operation: operationContext,
});

const result = await signingSessionCoordinator.execute({
  machine,
  operationContext,
});

await signingSessionCoordinator.finalize({
  lane: laneResult.lane,
  plan,
  result,
  operationContext,
});
```

## Core Types

### Lane Resolution

```ts
type SigningLaneResolutionResult =
  | {
      kind: 'resolved';
      lane: SigningLaneContext;
    }
  | {
      kind: 'blocked';
      reason: 'missing_lane' | 'auth_unavailable' | 'policy_blocked';
      accountId?: AccountId;
      authMethod?: SigningAuthMethod;
      chainFamily?: SigningChainFamily;
    };
```

### Lane Identity

```ts
type SigningLaneContext = {
  accountId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ed25519' | 'ecdsa';
  keyKind: 'threshold_ed25519' | 'threshold_ecdsa_secp256k1' | 'webauthn_p256';
  chainFamily: 'near' | 'tempo' | 'evm';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId?: ThresholdSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  sessionOrigin:
    | 'login'
    | 'registration'
    | 'manual_bootstrap'
    | 'manual_connect'
    | 'bootstrap'
    | 'per_operation'
    | 'sealed_restore';
  storageSource:
    | 'login'
    | 'registration'
    | 'manual-bootstrap'
    | 'manual-connect'
    | 'bootstrap'
    | 'email_otp';
  retention: 'session' | 'single_use';
  activeSignerSlot?: number;
  signingRootId?: string;
  signingRootVersion?: string;
};
```

### Operation Identity

```ts
type SigningOperationContext = {
  operationId: SigningOperationId;
  intent: 'transaction_sign';
};
```

### Planner Output

```ts
type SigningSessionPlan =
  | {
      kind: 'warm_session';
      lane: SigningLaneContext;
      keyRef: SigningKeyRefIntent;
    }
  | {
      kind: 'email_otp_reauth';
      lane: SigningLaneContext;
      challenge: EmailOtpChallengePlan;
    }
  | {
      kind: 'passkey_reauth';
      lane: SigningLaneContext;
      reconnect: PasskeyReconnectPlan;
    }
  | {
      kind: 'not_ready';
      lane: SigningLaneContext;
      reason: SigningSessionNotReadyReason;
    };
```

## Execution Model

The current `SigningExecutionMachine` is an ordering machine, not yet a fully
typed result-carrying state machine.

That is intentional for now:

1. The planner owns readiness and reauth choice.
2. The execution machine owns legal command order and transition tracing.
3. Command executors own side effects.
4. Finalizers own cleanup decisions that require the confirmed operation id.

Commands can carry `operation` so post-confirm work does not need to mutate or
rebind the selected lane:

```ts
type SigningExecutionCommand =
  | { kind: 'showConfirmation'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'requestOtp'; plan: Extract<SigningSessionPlan, { kind: 'email_otp_reauth' }>; operation?: SigningOperationContext }
  | { kind: 'requestPasskey'; plan: Extract<SigningSessionPlan, { kind: 'passkey_reauth' }>; operation?: SigningOperationContext }
  | { kind: 'reconnectThreshold'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'prepareNonce'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'reserveBudget'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'sign'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'spendBudget'; plan: SigningSessionPlan; operation?: SigningOperationContext }
  | { kind: 'cleanup'; plan: SigningSessionPlan; operation?: SigningOperationContext };
```

## Budget Accounting

Budget spend construction does not belong in the planner.

It happens at the execution boundary from the confirmed operation id and selected
lane:

```ts
const spend = buildWalletSigningSpendPlan(operationContext, lane, {
  thresholdSessionId,
  backingMaterialSessionId,
});

await walletSigningBudgetLedger.reserve({ spend });
await signer.sign(...);
await walletSigningBudgetLedger.recordSuccess({ spend });
```

This keeps the planner pure and ensures budget accounting uses the confirmed
operation id.

Current guarantees:

1. Budget is reserved before threshold signing starts.
2. Distinct in-process operations cannot race through the same last remaining
   wallet signing-session use.
3. Successful spends are idempotent by `operationId`.
4. Zero-spend outcomes release reservations and do not consume budget.
5. The selected lane carries wallet/session identity.
6. The spend record carries operation identity.

The current reservation boundary is local to the shared budget ledger instance.
Cross-tab or cross-device atomicity belongs server-side, where the authoritative
wallet signing-session budget is consumed.

## Open Direction

The main open architecture choice is whether to keep the execution machine as an
ordering machine or upgrade it into a typed result-carrying state machine.

Until that change is justified, the current model is:

1. `SigningSessionCoordinator`
2. warm-session readiness/store services
3. pure planner
4. ordering machine
5. command executors
6. budget and cleanup finalization

## Related Docs

The migration and phased checklist history now lives in
[docs/signing-session-coordinator.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/signing-session-coordinator.md).
