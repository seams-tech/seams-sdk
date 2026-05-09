import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import { sealedRecordRecoverabilityState } from './policy';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionPurpose,
  RestorePersistedSessionWorkItem,
} from './types';

export function buildRestoreWorkItemForRecord(
  input: RestorePersistedSessionForSigningInput,
  record: SigningSessionSealedStoreRecord,
): RestorePersistedSessionWorkItem | null {
  const thresholdSessionId = String(record.thresholdSessionIds[input.curve] || '').trim();
  const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId) return null;
  if (sealedRecordRecoverabilityState({ record }) !== 'recoverable') return null;
  if (record.authMethod !== input.authMethod) return null;
  if (walletSigningSessionId !== input.walletSigningSessionId) return null;
  if (thresholdSessionId !== input.thresholdSessionId) return null;
  if (
    input.curve === 'ecdsa' &&
    (!record.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, input.chainTarget))
  ) {
    return null;
  }
  return {
    record,
    purpose:
      input.curve === 'ecdsa'
        ? {
            walletId: input.walletId,
            authMethod: input.authMethod,
            curve: 'ecdsa',
            chainTarget: input.chainTarget,
            walletSigningSessionId,
            thresholdSessionId,
            reason: input.reason,
          }
        : {
            walletId: input.walletId,
            authMethod: input.authMethod,
            curve: 'ed25519',
            chain: 'near',
            walletSigningSessionId,
            thresholdSessionId,
            reason: input.reason,
          },
  };
}

export function buildRestoreWorkItemsForAccountRecord(args: {
  walletId: string;
  record: SigningSessionSealedStoreRecord;
  reason: Extract<RestorePersistedSessionPurpose['reason'], 'session_status'>;
  requestedCurve: 'ed25519' | 'ecdsa';
  requestedChainTarget?: ThresholdEcdsaChainTarget;
}): RestorePersistedSessionWorkItem[] {
  const walletSigningSessionId = String(args.record.walletSigningSessionId || '').trim();
  if (!walletSigningSessionId) return [];
  if (sealedRecordRecoverabilityState({ record: args.record }) !== 'recoverable') return [];
  if (args.requestedCurve === 'ed25519') {
    const thresholdSessionId = String(args.record.thresholdSessionIds.ed25519 || '').trim();
    if (!thresholdSessionId) return [];
    return [
      {
        record: args.record,
        purpose: {
          walletId: args.walletId,
          authMethod: args.record.authMethod,
          curve: 'ed25519',
          chain: 'near',
          walletSigningSessionId,
          thresholdSessionId,
          reason: args.reason,
        },
      },
    ];
  }
  const thresholdSessionId = String(args.record.thresholdSessionIds.ecdsa || '').trim();
  if (!thresholdSessionId || !args.requestedChainTarget) return [];
  if (
    !args.record.ecdsaRestore?.chainTarget ||
    !thresholdEcdsaChainTargetsEqual(
      args.record.ecdsaRestore.chainTarget,
      args.requestedChainTarget,
    )
  ) {
    return [];
  }
  return [
    {
      record: args.record,
      purpose: {
        walletId: args.walletId,
        authMethod: args.record.authMethod,
        curve: 'ecdsa',
        chainTarget: args.requestedChainTarget,
        walletSigningSessionId,
        thresholdSessionId,
        reason: args.reason,
      },
    },
  ];
}
