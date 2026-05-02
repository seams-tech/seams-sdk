import { expect, test } from '@playwright/test';
import {
  admitTransactionBudget,
  receiveTransactionIntent,
  classifyTransactionReadiness,
  prepareTransactionOperationFromReadiness,
  recordExactRestoreAttempt,
  recordTransactionBudgetAdmission,
  recordTransactionSnapshot,
  selectTransactionLane,
  selectTransactionLaneFromSnapshot,
  type TransactionSigningIntent,
} from '@/core/signingEngine/session/signingSession/transactionState';
import type { SigningSessionSnapshot } from '@/core/signingEngine/session/snapshotReader';

const nearIntent = (
  authMethod: 'email_otp' | 'passkey',
  kind: 'explicit' | 'account_class' | 'current_lane' = 'account_class',
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
  kind: 'explicit' | 'account_class' | 'current_lane' = 'account_class',
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
}) {
  return {
    authMethod: args.authMethod,
    curve: 'ed25519' as const,
    chain: 'near' as const,
    state: args.state || 'restorable',
    source: args.source || 'durable_sealed_record',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
  };
}

function ecdsaCandidate(args: {
  authMethod: 'email_otp' | 'passkey';
  chain?: 'tempo' | 'evm';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  state?: 'ready' | 'restorable';
  source?: 'runtime_session_record' | 'durable_sealed_record' | 'runtime_and_durable';
}) {
  return {
    authMethod: args.authMethod,
    curve: 'ecdsa' as const,
    chain: args.chain || 'evm',
    state: args.state || 'restorable',
    source: args.source || 'durable_sealed_record',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
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

  test('selects ECDSA candidates deterministically by ready state and stable identity', () => {
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
      }),
      ecdsaCandidate({
        authMethod: 'passkey',
        chain: 'tempo',
        thresholdSessionId: 'tsess-a-ready',
        walletSigningSessionId: 'wss-a-ready',
        state: 'ready',
      }),
    ];

    const selection = selectTransactionLane({
      intent: ecdsaIntent('passkey', 'tempo'),
      snapshot,
    });

    expect(selection.ok).toBe(true);
    if (!selection.ok) throw new Error('expected selection');
    expect(selection.lane.thresholdSessionId).toBe('tsess-a-ready');
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
});
