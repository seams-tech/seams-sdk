import { expect, test } from '@playwright/test';
import {
  receiveTransactionIntent,
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
});
