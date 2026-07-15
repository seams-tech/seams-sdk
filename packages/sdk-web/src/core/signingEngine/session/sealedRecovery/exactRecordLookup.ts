import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { RawSigningSessionSealedStoreRecord, SealedRecoveryRecord } from './recoveryRecord';
import { normalizeSealedRecoveryRecord, type RejectedSealedRecoveryRecord } from './recoveryRecord';
import type {
  RestorePersistedSessionForSigningInput,
  RestorePersistedSessionPurpose,
  RestorePersistedSessionWorkItem,
} from './sealedRecovery.types';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';

type EcdsaRestoreRecord = Extract<SealedRecoveryRecord, { curve: 'ecdsa' }>;

function sameString(left: unknown, right: unknown): boolean {
  return String(left ?? '').trim() === String(right ?? '').trim();
}

function sameStringLower(left: unknown, right: unknown): boolean {
  return (
    String(left ?? '')
      .trim()
      .toLowerCase() ===
    String(right ?? '')
      .trim()
      .toLowerCase()
  );
}

function sameParticipantIds(left: readonly unknown[], right: readonly unknown[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((participantId, index) => Number(participantId) === Number(right[index]));
}

function ecdsaRestoreRecordLaneIdentityMismatchReasons(
  record: EcdsaRestoreRecord,
  lane: ExactEcdsaSigningLaneIdentity,
): string[] {
  const reasons: string[] = [];
  const signer = lane.signer;
  if (!sameString(record.walletId, signer.walletId)) reasons.push('wallet_id');
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, signer.chainTarget)) {
    reasons.push('chain_target');
  }
  if (!sameString(record.keyHandle, signer.keyHandle)) reasons.push('key_handle');
  if (!sameString(record.ecdsaThresholdKeyId, signer.key.ecdsaThresholdKeyId)) {
    reasons.push('ecdsa_threshold_key_id');
  }
  if (!sameString(record.signingRootId, signer.key.signingRootId)) {
    reasons.push('signing_root_id');
  }
  if (!sameString(record.signingRootVersion, signer.key.signingRootVersion)) {
    reasons.push('signing_root_version');
  }
  if (!sameStringLower(record.ethereumAddress, signer.key.thresholdOwnerAddress)) {
    reasons.push('threshold_owner_address');
  }
  if (!sameParticipantIds(record.participantIds, signer.key.participantIds)) {
    reasons.push('participant_ids');
  }
  if (record.authMethod !== lane.auth.kind) reasons.push('auth_method');
  if (record.authMethod === 'passkey') {
    if (lane.auth.kind !== 'passkey') {
      reasons.push('passkey_auth_branch');
      return reasons;
    }
    if (!sameString(record.authority.verifier.rpId, lane.auth.rpId)) reasons.push('rp_id');
    if (!sameString(record.authority.factor.credentialIdB64u, lane.auth.credentialIdB64u)) {
      reasons.push('credential_id');
    }
    return reasons;
  }
  if (lane.auth.kind !== 'email_otp') {
    reasons.push('email_otp_auth_branch');
    return reasons;
  }
  if (!sameString(record.authority.factor.providerUserId, lane.auth.providerSubjectId)) {
    reasons.push('provider_subject_id');
  }
  return reasons;
}

function logEcdsaRestoreIdentityMismatch(args: {
  record: EcdsaRestoreRecord;
  lane: ExactEcdsaSigningLaneIdentity;
  reasons: readonly string[];
}): void {
  console.warn(
    '[SigningSessionRestore] ECDSA restore identity mismatch',
    JSON.stringify(
      {
        reasons: args.reasons,
        record: {
          authMethod: args.record.authMethod,
          walletId: args.record.walletId,
          source: args.record.source,
          chainTarget: thresholdEcdsaChainTargetKey(args.record.chainTarget),
          keyHandle: args.record.keyHandle,
          ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
          signingRootId: args.record.signingRootId,
          signingRootVersion: args.record.signingRootVersion,
          ethereumAddress: args.record.ethereumAddress,
          participantIds: args.record.participantIds,
        },
        lane: {
          authMethod: args.lane.auth.kind,
          walletId: args.lane.signer.walletId,
          chainTarget: thresholdEcdsaChainTargetKey(args.lane.signer.chainTarget),
          keyHandle: args.lane.signer.keyHandle,
          ecdsaThresholdKeyId: args.lane.signer.key.ecdsaThresholdKeyId,
          signingRootId: args.lane.signer.key.signingRootId,
          signingRootVersion: args.lane.signer.key.signingRootVersion,
          thresholdOwnerAddress: args.lane.signer.key.thresholdOwnerAddress,
          participantIds: args.lane.signer.key.participantIds,
        },
      },
      null,
      2,
    ),
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
  if (
    record.authMethod !== input.authMethod ||
    !thresholdEcdsaChainTargetsEqual(record.chainTarget, input.chainTarget) ||
    record.signingGrantId !== input.signingGrantId ||
    record.thresholdSessionId !== input.thresholdSessionId
  ) {
    return null;
  }
  const lane = input.materialRestoreIdentity.lane;
  const mismatchReasons = ecdsaRestoreRecordLaneIdentityMismatchReasons(record, lane);
  if (mismatchReasons.length > 0) {
    logEcdsaRestoreIdentityMismatch({ record, lane, reasons: mismatchReasons });
    return null;
  }
  if (
    !sameString(record.ecdsaThresholdKeyId, input.materialRestoreIdentity.ecdsaThresholdKeyId) ||
    !sameString(record.walletId, lane.signer.walletId) ||
    !sameString(record.keyHandle, lane.signer.keyHandle)
  ) {
    return null;
  }
  return {
    record,
    purpose: {
      walletId: input.walletId,
      authMethod: input.authMethod,
      curve: 'ecdsa',
      chainTarget: input.chainTarget,
      signingGrantId: record.signingGrantId,
      thresholdSessionId: record.thresholdSessionId,
      reason: input.reason,
    },
  };
}

export function buildRestoreWorkItemLookupResult(
  input: RestorePersistedSessionForSigningInput,
  record: RawSigningSessionSealedStoreRecord,
): RestoreWorkItemLookupResult {
  const normalized = normalizeSealedRecoveryRecord(record, {
    allowExpired: false,
    allowExhausted: false,
  });
  if (normalized.kind === 'rejected') {
    return { kind: 'rejected', rejection: normalized.rejection };
  }
  const workItem = exactPurposeForAcceptedRecord(input, normalized.record);
  return workItem ? { kind: 'matched', workItem } : { kind: 'not_applicable' };
}

function listedPurposeForAcceptedRecord(args: {
  walletId: string;
  record: SealedRecoveryRecord;
  reason: Extract<RestorePersistedSessionPurpose['reason'], 'session_status'>;
  requestedChainTarget: ThresholdEcdsaChainTarget;
}): RestorePersistedSessionWorkItem[] {
  if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.requestedChainTarget)) {
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
        signingGrantId: args.record.signingGrantId,
        thresholdSessionId: args.record.thresholdSessionId,
        reason: args.reason,
      },
    },
  ];
}

export function buildRestoreWorkItemLookupResultsForListedRecord(args: {
  walletId: string;
  record: RawSigningSessionSealedStoreRecord;
  reason: Extract<RestorePersistedSessionPurpose['reason'], 'session_status'>;
  requestedChainTarget: ThresholdEcdsaChainTarget;
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
    requestedChainTarget: args.requestedChainTarget,
  });
  return workItems.length
    ? workItems.map((workItem) => ({
        kind: 'matched' as const,
        workItem,
      }))
    : [{ kind: 'not_applicable' }];
}
