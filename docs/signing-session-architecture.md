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
6. Sealed-refresh restore is a write-side operation, not a read-side side
   effect. Status, snapshot, capability, budget, and lane-resolution reads must
   not unseal, bootstrap, call server seal endpoints, or mutate durable restore
   state.

The restore refactor plan lives in
[`docs/signing-session-restore-refactor.md`](signing-session-restore-refactor.md).
It is now archival. The restore migration is complete; this document is the
current architecture spec for signing-session restore and transaction lane
selection.

## Current Flow

Transaction signing uses prepared identity boundaries. Each command-side flow
restores durable sealed material before lane selection, reads a side-effect-free
snapshot, resolves one concrete lane, and carries that prepared identity through
auth, budget, signing, finalization, and cleanup.

The lane-resolution entrypoints are:

1. Tempo and ARC/EVM ECDSA transaction signing:
   `prepareEvmFamilyEcdsaSigningSession(...)`.
2. NEAR Ed25519 transaction signing:
   `prepareNearEd25519TransactionSigningSession(...)`.
3. ECDSA key export:
   exact-purpose restore with `reason: 'export'` before local metadata
   selection.

There is no read-side restore path. Wallet-session status polling, snapshot
composition, budget reads, and capability reads cannot unseal, call server-seal
endpoints, or mutate durable restore state.

```ts
const prepared = await prepareEvmFamilyEcdsaSigningSession({
  deps,
  nearAccountId,
  chain,
  diagnostics,
});

const readiness = await readReadinessForPreparedLane(prepared.signingLane);
const { signingSessionPlan } = await signingSessionCoordinator.resolveAuthPlanFromReadiness({
  lane: prepared.signingLane,
  readiness,
  forceFreshAuth,
});

const machine = signingSessionCoordinator.createExecutionMachine({
  plan: signingSessionPlan,
  operation: operationContext,
});

const result = await executeSigning({
  plan: signingSessionPlan,
  operation: operationContext,
  prepared,
});

await signingSessionCoordinator.finalize({
  lane: prepared.signingLane,
  plan: signingSessionPlan,
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
  thresholdSessionId: ThresholdSessionId;
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
  | {
      kind: 'requestOtp';
      plan: Extract<SigningSessionPlan, { kind: 'email_otp_reauth' }>;
      operation?: SigningOperationContext;
    }
  | {
      kind: 'requestPasskey';
      plan: Extract<SigningSessionPlan, { kind: 'passkey_reauth' }>;
      operation?: SigningOperationContext;
    }
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
