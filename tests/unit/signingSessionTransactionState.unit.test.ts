import { expect, test } from '@playwright/test';
import {
  admitTransactionBudget,
  receiveTransactionIntent,
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  prepareTransactionSigningOperation,
  recordExactRestoreAttempt,
  recordTransactionBudgetAdmission,
  recordTransactionSnapshot,
  selectTransactionLane,
  selectTransactionLaneFromSnapshot,
  signPreparedTransactionOperation,
  finalizeSignedTransactionOperation,
  type TransactionSigningIntent,
} from '@/core/signingEngine/session/signingSession/transactionState';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/signingSession/lanes';
import {
  SigningSessionIds,
  type SigningOperationId,
} from '@/core/signingEngine/session/signingSession/types';
import type { SigningSessionSnapshot } from '@/core/signingEngine/session/snapshotReader';

const nearIntent = (
  authMethod: 'email_otp' | 'passkey',
  kind: 'explicit' | 'account_class' = 'account_class',
): TransactionSigningIntent => ({
  walletId: 'alice.testnet',
  curve: 'ed25519',
  chain: 'near',
  authSelectionPolicy: { kind, authMethod },
  operationUsesNeeded: 1,
});

const ecdsaIntent = (
  authMethod: 'email_otp' | 'passkey',
  chain: 'tempo' | 'evm' = 'evm',
  kind: 'explicit' | 'account_class' = 'account_class',
): TransactionSigningIntent => ({
  walletId: 'alice.testnet',
  curve: 'ecdsa',
  chain,
  authSelectionPolicy: { kind, authMethod },
  operationUsesNeeded: 1,
});

const emptySnapshot = (): SigningSessionSnapshot => ({
  walletId: 'alice.testnet' as any,
  generation: 1,
  lanes: {
    ed25519: {
      near: { curve: 'ed25519', chain: 'near', state: 'missing' },
    },
    ecdsa: {
      tempo: { curve: 'ecdsa', chain: 'tempo', state: 'missing' },
      evm: { curve: 'ecdsa', chain: 'evm', state: 'missing' },
    },
  },
  candidates: {
    ed25519: {
      near: [],
    },
    ecdsa: {
      tempo: [],
      evm: [],
    },
  },
});

function ed25519Candidate(args: {
  authMethod: 'email_otp' | 'passkey';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  state?: 'ready' | 'restorable';
  source?: 'runtime_session_record' | 'durable_sealed_record' | 'runtime_and_durable';
  updatedAtMs?: number;
}) {
  return {
    authMethod: args.authMethod,
    curve: 'ed25519' as const,
    chain: 'near' as const,
    state: args.state || 'restorable',
    source: args.source || 'durable_sealed_record',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    ...(args.updatedAtMs !== undefined ? { updatedAtMs: args.updatedAtMs } : {}),
  };
}

function ecdsaCandidate(args: {
  authMethod: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  state?: 'ready' | 'restorable';
  source?: 'runtime_session_record' | 'durable_sealed_record' | 'runtime_and_durable';
  updatedAtMs?: number;
}) {
  return {
    authMethod: args.authMethod,
    curve: 'ecdsa' as const,
    chain: args.chain || 'evm',
    state: args.state || 'restorable',
    source: args.source || 'durable_sealed_record',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    ...(args.updatedAtMs !== undefined ? { updatedAtMs: args.updatedAtMs } : {}),
  };
}

test.describe('transaction signing state selector', () => {
  test('selects a concrete NEAR Ed25519 candidate by account-class policy', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
      }),
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey',
        walletSigningSessionId: 'wss-passkey',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('email_otp'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.authMethod).toBe('email_otp');
    expect(selection.lane.thresholdSessionId).toBe('tsess-otp');
    expect(selection.lane.walletSigningSessionId).toBe('wss-otp');
  });

  test('linked-auth explicit OTP selection does not choose passkey', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey',
        walletSigningSessionId: 'wss-passkey',
        state: 'ready',
      }),
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
        state: 'ready',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('email_otp', 'explicit'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.authMethod).toBe('email_otp');
    expect(selection.lane.thresholdSessionId).toBe('tsess-otp');
  });

  test('linked-auth explicit passkey selection does not choose OTP', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
        state: 'ready',
      }),
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey',
        walletSigningSessionId: 'wss-passkey',
        state: 'ready',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('passkey', 'explicit'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.authMethod).toBe('passkey');
    expect(selection.lane.thresholdSessionId).toBe('tsess-passkey');
  });

  test('anchors current OTP runtime lane before passkey account metadata', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey-durable',
        walletSigningSessionId: 'wss-passkey-durable',
      }),
    ];
    const currentRuntimeLane = ed25519Candidate({
      authMethod: 'email_otp',
      thresholdSessionId: 'tsess-current-otp',
      walletSigningSessionId: 'wss-current-otp',
      state: 'ready',
      source: 'runtime_session_record',
    });

    const selection = selectTransactionLane({
      intent: nearIntent('passkey'),
      snapshot,
      currentRuntimeLane,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.authMethod).toBe('email_otp');
    expect(selection.lane.thresholdSessionId).toBe('tsess-current-otp');
  });

  test('does not fall back to another durable candidate when runtime lane is concrete', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey-durable',
        walletSigningSessionId: 'wss-passkey-durable',
      }),
    ];
    const currentRuntimeLane = ed25519Candidate({
      authMethod: 'email_otp',
      thresholdSessionId: 'tsess-current-otp',
      walletSigningSessionId: 'wss-current-otp',
      state: 'ready',
      source: 'runtime_session_record',
    });

    const selection = selectTransactionLane({
      intent: nearIntent('passkey'),
      snapshot,
      currentRuntimeLane,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.thresholdSessionId).not.toBe('tsess-passkey-durable');
    expect(selection.lane.thresholdSessionId).toBe('tsess-current-otp');
  });

  test('reports incomplete runtime lane instead of falling back to durable candidates', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-passkey-durable',
        walletSigningSessionId: 'wss-passkey-durable',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('passkey'),
      snapshot,
      currentRuntimeLane: {
        authMethod: 'email_otp',
        curve: 'ed25519',
        chain: 'near',
        state: 'ready',
        source: 'runtime_session_record',
        thresholdSessionId: 'tsess-incomplete-runtime',
      } as any,
    });

    expect(selection).toEqual({
      ok: false,
      failure: { kind: 'incomplete_candidate', missing: ['walletSigningSessionId'] },
    });
  });

  test('explicit auth choice fails instead of probing the other auth method', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('passkey', 'explicit'),
      snapshot,
    });

    expect(selection).toEqual({
      ok: false,
      failure: { kind: 'no_candidate', authMethod: 'passkey' },
    });
  });

  test('passkey Ed25519 intent does not select an OTP durable candidate', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp-only',
        walletSigningSessionId: 'wss-otp-only',
      }),
    ];

    const selection = selectTransactionLane({
      intent: nearIntent('passkey'),
      snapshot,
    });

    expect(selection).toEqual({
      ok: false,
      failure: { kind: 'no_candidate', authMethod: 'passkey' },
    });
  });

  test('selects a concrete EVM ECDSA candidate by account-class policy', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ecdsa.evm = [
      ecdsaCandidate({
        authMethod: 'passkey',
        thresholdSessionId: 'tsess-ecdsa-passkey',
        walletSigningSessionId: 'wss-ecdsa-passkey',
      }),
      ecdsaCandidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-ecdsa-otp',
        walletSigningSessionId: 'wss-ecdsa-otp',
      }),
    ];

    const selection = selectTransactionLane({
      intent: ecdsaIntent('email_otp', 'evm'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: 'evm',
      thresholdSessionId: 'tsess-ecdsa-otp',
      walletSigningSessionId: 'wss-ecdsa-otp',
    });
  });

  test('selects same-auth ECDSA candidates by readiness and unique newest metadata', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ecdsa.tempo = [
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-z-restorable',
        walletSigningSessionId: 'wss-z-restorable',
      }),
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-b-ready',
        walletSigningSessionId: 'wss-b-ready',
        state: 'ready',
        updatedAtMs: 20,
      }),
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-a-ready',
        walletSigningSessionId: 'wss-a-ready',
        state: 'ready',
        updatedAtMs: 10,
      }),
    ];

    const selection = selectTransactionLane({
      intent: ecdsaIntent('passkey', 'tempo'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.thresholdSessionId).toBe('tsess-b-ready');
  });

  test('returns ambiguous_candidates for indistinguishable same-auth lanes', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ecdsa.tempo = [
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-a-ready',
        walletSigningSessionId: 'wss-a-ready',
        state: 'ready',
      }),
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-b-ready',
        walletSigningSessionId: 'wss-b-ready',
        state: 'ready',
      }),
    ];

    const selection = selectTransactionLane({
      intent: ecdsaIntent('passkey', 'tempo'),
      snapshot,
    });

    expect(selection).toEqual({
      ok: false,
      failure: { kind: 'ambiguous_candidates', allowedAuthMethods: ['passkey'] },
    });
  });

  test('moves from intent to snapshot to selected lane with explicit state tags', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
      }),
    ];

    const intent = receiveTransactionIntent(nearIntent('email_otp'));
    const snapshotState = recordTransactionSnapshot(intent, { snapshot });
    const selected = selectTransactionLaneFromSnapshot(snapshotState);

    expect(intent.tag).toBe('IntentReceived');
    expect(snapshotState.tag).toBe('SnapshotRead');
    expect(selected.tag).toBe('LaneSelected');
    if (selected.tag !== 'LaneSelected') throw new Error('expected selected lane');
    expect(selected.lane.thresholdSessionId).toBe('tsess-otp');
  });

  test('records exact restore and readiness as follow-on state transitions', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
      }),
    ];

    const intent = receiveTransactionIntent(nearIntent('email_otp'));
    const snapshotState = recordTransactionSnapshot(intent, { snapshot });
    const selected = selectTransactionLaneFromSnapshot(snapshotState);
    if (selected.tag !== 'LaneSelected') throw new Error('expected selected lane');

    const restored = recordExactRestoreAttempt(selected, { restored: true });
    const readiness = classifyTransactionReadiness(restored, {
      status: 'ready',
      remainingUses: 1,
      expiresAtMs: 123,
    });

    expect(restored.tag).toBe('ExactRestoreAttempted');
    expect(restored.lane.thresholdSessionId).toBe(selected.lane.thresholdSessionId);
    expect(readiness.tag).toBe('ReadinessClassified');
    expect(readiness.readiness).toEqual({
      status: 'ready',
      remainingUses: 1,
      expiresAtMs: 123,
    });
  });

  test('moves ready operation into an explicit budget-admitted state', () => {
    const snapshot = emptySnapshot();
    snapshot.candidates.ed25519.near = [
      ed25519Candidate({
        authMethod: 'email_otp',
        thresholdSessionId: 'tsess-otp',
        walletSigningSessionId: 'wss-otp',
      }),
    ];

    const intent = receiveTransactionIntent(nearIntent('email_otp'));
    const snapshotState = recordTransactionSnapshot(intent, { snapshot });
    const selected = selectTransactionLaneFromSnapshot(snapshotState);
    if (selected.tag !== 'LaneSelected') throw new Error('expected selected lane');
    const readiness = classifyTransactionReadiness(recordExactRestoreAttempt(selected, { restored: true }), {
      status: 'ready',
      remainingUses: 1,
      expiresAtMs: 123,
    });

    const prepared = prepareTransactionOperationFromReadiness(readiness);
    const admitted = admitTransactionBudget(prepared, {
      budgetIdentity: {
        walletSigningSessionId: 'wss-otp',
        projectionVersion: 'budget-rev-1',
        status: {
          status: 'active',
          projectionVersion: 'budget-rev-1',
          remainingUses: 1,
          expiresAtMs: 123,
        },
      } as any,
    });
    const admittedState = recordTransactionBudgetAdmission(admitted);

    expect(prepared.lane.thresholdSessionId).toBe('tsess-otp');
    expect(admitted.budgetAdmission.budgetIdentity.projectionVersion).toBe('budget-rev-1');
    expect(admittedState.tag).toBe('BudgetAdmitted');
    expect(admittedState.operation.lane).toEqual(prepared.lane);
  });

  test('prepares a transaction operation through the shared transaction boundary', async () => {
    const accountId = 'alice.testnet';
    const walletSigningSessionId =
      SigningSessionIds.walletSigningSession('wss-shared-prepare');
    const thresholdSessionId =
      SigningSessionIds.thresholdEd25519Session('tsess-shared-prepare');
    const transactionLane = {
      accountId: accountId as any,
      authMethod: 'email_otp' as const,
      curve: 'ed25519' as const,
      chain: 'near' as const,
      walletSigningSessionId,
      thresholdSessionId,
    };
    const signingLane = buildNearTransactionSigningLane({
      accountId: accountId as any,
      authMethod: 'email_otp',
      walletSigningSessionId,
      thresholdSessionId,
    });

    const prepared = await prepareTransactionSigningOperation({
      intent: nearIntent('email_otp'),
      coordinator: {
        resolveAuthPlanFromReadiness: async ({ lane, readiness, expiresAtMs, remainingUses }) => ({
          signingSessionPlan: {
            kind: 'warm_session',
            lane,
            keyRef: {
              kind: 'cached',
              thresholdSessionId,
            },
          } as any,
          readiness,
          expiresAtMs: Number(expiresAtMs) || 123,
          remainingUses: Number(remainingUses) || 1,
        }),
        prepareBudgetIdentity: async () => ({
          walletSigningSessionId,
          projectionVersion: 'budget-rev-shared-prepare',
          status: {
            status: 'active',
            projectionVersion: 'budget-rev-shared-prepare',
            remainingUses: 1,
            expiresAtMs: 123,
          } as any,
        }),
      },
      prepareBudgetIdentity: true,
      operation: {
        operationId: SigningSessionIds.signingOperation(
          'op-shared-prepare',
        ) as SigningOperationId,
        intent: 'transaction_sign',
      },
      lifecycleAdapter: {
        prepare: async () => ({
          lane: signingLane,
          transactionLane,
          readiness: {
            readiness: {
              status: 'ready',
              thresholdSessionId,
            },
            expiresAtMs: 123,
            remainingUses: 1,
            usesNeeded: 1,
          },
          snapshotGeneration: 7,
          metadata: { source: 'test' },
        }),
      },
    });

    expect(prepared.transactionOperation).toMatchObject({
      lane: transactionLane,
      readiness: { status: 'ready', remainingUses: 1, expiresAtMs: 123 },
    });
    expect(prepared.thresholdOperation.metadata.transactionOperation).toBe(
      prepared.transactionOperation,
    );
    expect(prepared.budget.kind).toBe('admitted');
    expect(
      prepared.budget.kind === 'admitted'
        ? prepared.budget.operation.budgetAdmission.budgetIdentity.projectionVersion
        : undefined,
    ).toBe('budget-rev-shared-prepare');
    expect(prepared.budget.kind === 'admitted' ? prepared.budget.state.tag : undefined).toBe(
      'BudgetAdmitted',
    );
  });

  test('signs and finalizes only after budget admission', async () => {
    const prepared = {
      intent: nearIntent('email_otp'),
      lane: {
        accountId: 'alice.testnet' as any,
        authMethod: 'email_otp' as const,
        curve: 'ed25519' as const,
        chain: 'near' as const,
        walletSigningSessionId: SigningSessionIds.walletSigningSession('wss-signed-op'),
        thresholdSessionId: SigningSessionIds.thresholdEd25519Session('tsess-signed-op'),
      },
      readiness: { status: 'ready' as const, remainingUses: 1, expiresAtMs: 123 },
    };
    const admitted = admitTransactionBudget(prepared, {
      budgetIdentity: {
        walletSigningSessionId: 'wss-signed-op',
        projectionVersion: 'budget-rev-signed-op',
        status: {
          status: 'active',
          projectionVersion: 'budget-rev-signed-op',
          remainingUses: 1,
          expiresAtMs: 123,
        },
      } as any,
    });
    const finalized: string[] = [];

    const signed = await signPreparedTransactionOperation(admitted, { payload: 'tx' }, {
      sign: async (operation, payload) => ({
        thresholdSessionId: String(operation.lane.thresholdSessionId),
        payload,
      }),
    });
    await finalizeSignedTransactionOperation(signed, {
      recordSuccess: (operation) => {
        finalized.push(String(operation.lane.thresholdSessionId));
      },
    });

    expect(signed.result).toEqual({
      thresholdSessionId: 'tsess-signed-op',
      payload: { payload: 'tx' },
    });
    expect(finalized).toEqual(['tsess-signed-op']);
  });
});
