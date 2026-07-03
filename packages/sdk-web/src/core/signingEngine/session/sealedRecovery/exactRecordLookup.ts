import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { RawSigningSessionSealedStoreRecord, SealedRecoveryRecord } from './recoveryRecord';
import {
  ed25519SealedRecoveryMaterialIdentity,
  normalizeSealedRecoveryRecord,
  type RejectedSealedRecoveryRecord,
} from './recoveryRecord';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionPurpose,
  RestorePersistedSessionWorkItem,
} from './sealedRecovery.types';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';

type EcdsaRestoreRecord = Extract<SealedRecoveryRecord, { curve: 'ecdsa' }>;
type Ed25519RestoreRecord = Extract<SealedRecoveryRecord, { curve: 'ed25519' }>;

function sameString(left: unknown, right: unknown): boolean {
  return String(left ?? '').trim() === String(right ?? '').trim();
}

function sameStringLower(left: unknown, right: unknown): boolean {
  return String(left ?? '').trim().toLowerCase() === String(right ?? '').trim().toLowerCase();
}

function sameParticipantIds(left: readonly unknown[], right: readonly unknown[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((participantId, index) => Number(participantId) === Number(right[index]));
}

function ecdsaRestoreRecordMatchesLaneIdentity(
  record: EcdsaRestoreRecord,
  lane: ExactEcdsaSigningLaneIdentity,
): boolean {
  const signer = lane.signer;
  if (!sameString(record.walletId, signer.walletId)) return false;
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, signer.chainTarget)) return false;
  if (!sameString(record.keyHandle, signer.keyHandle)) return false;
  if (!sameString(record.ecdsaThresholdKeyId, signer.key.ecdsaThresholdKeyId)) return false;
  if (!sameString(record.signingRootId, signer.key.signingRootId)) return false;
  if (!sameString(record.signingRootVersion, signer.key.signingRootVersion)) return false;
  if (!sameStringLower(record.ethereumAddress, signer.key.thresholdOwnerAddress)) return false;
  if (!sameParticipantIds(record.participantIds, signer.key.participantIds)) return false;
  if (record.authMethod !== lane.auth.kind) return false;
  if (record.authMethod === 'passkey') {
    return (
      lane.auth.kind === 'passkey' &&
      sameString(record.authority.verifier.rpId, lane.auth.rpId) &&
      sameString(record.authority.factor.credentialIdB64u, lane.auth.credentialIdB64u)
    );
  }
  return (
    lane.auth.kind === 'email_otp' &&
    sameString(record.authority.factor.providerUserId, lane.auth.providerSubjectId)
  );
}

function ed25519RestoreRecordMatchesLaneIdentity(
  record: Ed25519RestoreRecord,
  lane: ExactEd25519SigningLaneIdentity,
): boolean {
  const signer = lane.signer;
  if (!sameString(record.walletId, signer.account.wallet.walletId)) return false;
  if (!sameString(record.nearAccountId, signer.account.nearAccountId)) return false;
  if (!sameString(record.nearEd25519SigningKeyId, signer.nearEd25519SigningKeyId)) return false;
  if (record.authMethod !== lane.auth.kind) return false;
  if (record.authMethod === 'passkey') {
    return (
      lane.auth.kind === 'passkey' &&
      sameString(record.authority.verifier.rpId, lane.auth.rpId) &&
      sameString(record.authority.factor.credentialIdB64u, lane.auth.credentialIdB64u)
    );
  }
  return (
    lane.auth.kind === 'email_otp' &&
    sameString(record.authority.factor.providerUserId, lane.auth.providerSubjectId)
  );
}

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
  let signingGrantId: string | null = null;

  if (input.curve === 'ecdsa') {
    if (record.curve === 'ecdsa') {
      if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, input.chainTarget)) return null;
      exactRecord = record;
      thresholdSessionId = record.thresholdSessionId;
      signingGrantId = record.signingGrantId;
    } else if (
      record.curve === 'ed25519' &&
      record.authMethod === 'email_otp' &&
      record.companionEcdsaRecovery &&
      thresholdEcdsaChainTargetsEqual(record.companionEcdsaRecovery.chainTarget, input.chainTarget)
    ) {
      exactRecord = record.companionEcdsaRecovery;
      thresholdSessionId = record.companionEcdsaRecovery.thresholdSessionId;
      signingGrantId = record.companionEcdsaRecovery.signingGrantId;
    } else {
      return null;
    }
  } else if (record.curve === 'ed25519') {
    exactRecord = record;
    thresholdSessionId = record.thresholdSessionId;
    signingGrantId = record.signingGrantId;
  } else if (
    record.curve === 'ecdsa' &&
    record.authMethod === 'email_otp' &&
    record.companionEd25519Recovery
  ) {
    exactRecord = record.companionEd25519Recovery;
    thresholdSessionId = record.companionEd25519Recovery.thresholdSessionId;
    signingGrantId = record.signingGrantId;
  } else {
    return null;
  }

  if (!exactRecord || !thresholdSessionId || !signingGrantId) return null;
  if (signingGrantId !== input.signingGrantId) return null;
  if (thresholdSessionId !== input.thresholdSessionId) return null;
  if (input.curve === 'ecdsa') {
    if (exactRecord.curve !== 'ecdsa') return null;
    if (!ecdsaRestoreRecordMatchesLaneIdentity(exactRecord, input.materialRestoreIdentity.lane)) {
      return null;
    }
    if (
      String(exactRecord.ecdsaThresholdKeyId || '').trim() !==
      String(input.materialRestoreIdentity.ecdsaThresholdKeyId)
    ) {
      return null;
    }
    if (
      String(exactRecord.walletId || '').trim() !==
      String(input.materialRestoreIdentity.lane.signer.walletId)
    ) {
      return null;
    }
    if (
      String(exactRecord.keyHandle || '').trim() !==
      String(input.materialRestoreIdentity.lane.signer.keyHandle)
    ) {
      return null;
    }
  } else {
    if (exactRecord.curve !== 'ed25519') return null;
    if (!ed25519RestoreRecordMatchesLaneIdentity(exactRecord, input.materialRestoreIdentity.lane)) {
      return null;
    }
    const materialIdentity = ed25519SealedRecoveryMaterialIdentity(exactRecord);
    if (
      String(materialIdentity.bindingDigest).trim() !==
      String(input.materialRestoreIdentity.materialBindingDigest)
    ) {
      return null;
    }
    if (
      String(materialIdentity.materialKeyId).trim() !==
      String(input.materialRestoreIdentity.materialKeyId)
    ) {
      return null;
    }
    if (
      String(exactRecord.walletId || '').trim() !==
      String(input.materialRestoreIdentity.lane.signer.account.wallet.walletId)
    ) {
      return null;
    }
    if (
      String(exactRecord.nearAccountId || '').trim() !==
      String(input.materialRestoreIdentity.lane.signer.account.nearAccountId)
    ) {
      return null;
    }
    if (
      String(exactRecord.nearEd25519SigningKeyId || '').trim() !==
      String(input.materialRestoreIdentity.lane.signer.nearEd25519SigningKeyId)
    ) {
      return null;
    }
  }
  return {
    record: exactRecord,
    purpose:
      input.curve === 'ecdsa'
        ? {
            walletId: input.walletId,
            authMethod: input.authMethod,
            curve: 'ecdsa',
            chainTarget: input.chainTarget,
            signingGrantId,
            thresholdSessionId,
            reason: input.reason,
          }
        : {
            walletId: input.walletId,
            authMethod: input.authMethod,
            curve: 'ed25519',
            chain: 'near',
            signingGrantId,
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
    const signingGrantId = ed25519Record.signingGrantId;
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
          signingGrantId,
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
  const signingGrantId = ecdsaRecord.signingGrantId;
  return [
    {
      record: ecdsaRecord,
      purpose: {
        walletId: args.walletId,
        authMethod: ecdsaRecord.authMethod,
        curve: 'ecdsa',
        chainTarget: args.requestedChainTarget,
        signingGrantId,
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
