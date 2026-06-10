import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { RawSigningSessionSealedStoreRecord, SealedRecoveryRecord } from './recoveryRecord';
import { normalizeSealedRecoveryRecord, type RejectedSealedRecoveryRecord } from './recoveryRecord';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionPurpose,
  RestorePersistedSessionWorkItem,
} from './types';

export type RestoreWorkItemLookupResult =
  | {
      kind: 'matched';
      workItem: RestorePersistedSessionWorkItem;
    }
  | {
      kind: 'rejected';
      rejection: RejectedSealedRecoveryRecord;
    }
  | {
      kind: 'not_applicable';
    };

function exactPurposeForAcceptedRecord(
  input: RestorePersistedSessionForSigningInput,
  record: SealedRecoveryRecord,
): RestorePersistedSessionWorkItem | null {
  if (record.authMethod !== input.authMethod) return null;
  let exactRecord: SealedRecoveryRecord | null = null;
  let thresholdSessionId: string | null = null;
  let walletSigningSessionId: string | null = null;

  if (input.curve === 'ecdsa') {
    if (record.curve === 'ecdsa') {
      if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, input.chainTarget)) return null;
      exactRecord = record;
      thresholdSessionId = record.thresholdSessionId;
      walletSigningSessionId = record.walletSigningSessionId;
    } else if (
      record.curve === 'ed25519' &&
      record.authMethod === 'email_otp' &&
      record.companionEcdsaRecovery &&
      thresholdEcdsaChainTargetsEqual(record.companionEcdsaRecovery.chainTarget, input.chainTarget)
    ) {
      exactRecord = record.companionEcdsaRecovery;
      thresholdSessionId = record.companionEcdsaRecovery.thresholdSessionId;
      walletSigningSessionId = record.companionEcdsaRecovery.walletSigningSessionId;
    } else {
      return null;
    }
  } else if (record.curve === 'ed25519') {
    exactRecord = record;
    thresholdSessionId = record.thresholdSessionId;
    walletSigningSessionId = record.walletSigningSessionId;
  } else if (
    record.curve === 'ecdsa' &&
    record.authMethod === 'email_otp' &&
    record.companionEd25519Recovery
  ) {
    exactRecord = record;
    thresholdSessionId = record.companionEd25519Recovery.thresholdSessionId;
    walletSigningSessionId = record.walletSigningSessionId;
  } else {
    return null;
  }

  if (!exactRecord || !thresholdSessionId || !walletSigningSessionId) return null;
  if (walletSigningSessionId !== input.walletSigningSessionId) return null;
  if (thresholdSessionId !== input.thresholdSessionId) return null;
  return {
    record: exactRecord,
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

export function buildRestoreWorkItemLookupResult(
  input: RestorePersistedSessionForSigningInput,
  record: RawSigningSessionSealedStoreRecord,
): RestoreWorkItemLookupResult {
  const normalized = normalizeSealedRecoveryRecord(record);
  if (normalized.kind === 'rejected') {
    return {
      kind: 'rejected',
      rejection: normalized.rejection,
    };
  }
  const workItem = exactPurposeForAcceptedRecord(input, normalized.record);
  return workItem
    ? {
        kind: 'matched',
        workItem,
      }
    : {
        kind: 'not_applicable',
      };
}

function listedPurposeForAcceptedRecord(args: {
  walletId: string;
  record: SealedRecoveryRecord;
  reason: Extract<RestorePersistedSessionPurpose['reason'], 'session_status'>;
  requestedCurve: 'ed25519' | 'ecdsa';
  requestedChainTarget?: ThresholdEcdsaChainTarget;
}): RestorePersistedSessionWorkItem[] {
  const acceptedRecord = args.record;
  if (args.requestedCurve === 'ed25519') {
    const ed25519Record =
      acceptedRecord.curve === 'ed25519'
        ? acceptedRecord
        : acceptedRecord.curve === 'ecdsa' &&
            acceptedRecord.authMethod === 'email_otp' &&
            acceptedRecord.companionEd25519Recovery
          ? acceptedRecord
          : null;
    if (!ed25519Record) return [];
    const walletSigningSessionId = ed25519Record.walletSigningSessionId;
    const thresholdSessionId = (() => {
      if (ed25519Record.curve === 'ed25519') return ed25519Record.thresholdSessionId;
      const companionEd25519Recovery = ed25519Record.companionEd25519Recovery;
      return companionEd25519Recovery ? companionEd25519Recovery.thresholdSessionId : null;
    })();
    if (!thresholdSessionId) return [];
    return [
      {
        record: ed25519Record,
        purpose: {
          walletId: args.walletId,
          authMethod: ed25519Record.authMethod,
          curve: 'ed25519',
          chain: 'near',
          walletSigningSessionId,
          thresholdSessionId,
          reason: args.reason,
        },
      },
    ];
  }
  if (!args.requestedChainTarget) return [];
  const ecdsaRecord =
    acceptedRecord.curve === 'ecdsa'
      ? thresholdEcdsaChainTargetsEqual(acceptedRecord.chainTarget, args.requestedChainTarget)
        ? acceptedRecord
        : null
      : acceptedRecord.curve === 'ed25519' &&
          acceptedRecord.authMethod === 'email_otp' &&
          acceptedRecord.companionEcdsaRecovery &&
          thresholdEcdsaChainTargetsEqual(
            acceptedRecord.companionEcdsaRecovery.chainTarget,
            args.requestedChainTarget,
          )
        ? acceptedRecord.companionEcdsaRecovery
        : null;
  if (!ecdsaRecord) {
    return [];
  }
  const walletSigningSessionId = ecdsaRecord.walletSigningSessionId;
  return [
    {
      record: ecdsaRecord,
      purpose: {
        walletId: args.walletId,
        authMethod: ecdsaRecord.authMethod,
        curve: 'ecdsa',
        chainTarget: args.requestedChainTarget,
        walletSigningSessionId,
        thresholdSessionId: ecdsaRecord.thresholdSessionId,
        reason: args.reason,
      },
    },
  ];
}

export function buildRestoreWorkItemLookupResultsForListedRecord(args: {
  walletId: string;
  record: RawSigningSessionSealedStoreRecord;
  reason: Extract<RestorePersistedSessionPurpose['reason'], 'session_status'>;
  requestedCurve: 'ed25519' | 'ecdsa';
  requestedChainTarget?: ThresholdEcdsaChainTarget;
}): RestoreWorkItemLookupResult[] {
  const normalized = normalizeSealedRecoveryRecord(args.record);
  if (normalized.kind === 'rejected') {
    return [
      {
        kind: 'rejected',
        rejection: normalized.rejection,
      },
    ];
  }
  const workItems = listedPurposeForAcceptedRecord({
    walletId: args.walletId,
    record: normalized.record,
    reason: args.reason,
    requestedCurve: args.requestedCurve,
    ...(args.requestedChainTarget ? { requestedChainTarget: args.requestedChainTarget } : {}),
  });
  return workItems.length
    ? workItems.map((workItem) => ({
        kind: 'matched' as const,
        workItem,
      }))
    : [{ kind: 'not_applicable' }];
}
