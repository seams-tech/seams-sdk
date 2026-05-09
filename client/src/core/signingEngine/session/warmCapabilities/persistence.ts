import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '../persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import { publishResolvedIdentity } from '../persistence/sealedSessionStore';

export type PersistWarmSessionEd25519CapabilityArgs = {
  nearAccountId: AccountId | string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionKind?: ThresholdSessionKind;
  sessionId: string;
  walletSigningSessionId?: string;
  expiresAtMs: number;
  remainingUses: number;
  jwt?: string;
  xClientBaseB64u?: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
};

export function persistWarmSessionEd25519Capability(
  args: PersistWarmSessionEd25519CapabilityArgs,
): ThresholdEd25519SessionRecord {
  const sessionId = String(args.sessionId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const remainingUses = normalizePositiveInteger(args.remainingUses) ?? 0;
  if (!sessionId) {
    throw new Error('Missing sessionId for warm threshold-ed25519 capability');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Invalid expiresAtMs for warm threshold-ed25519 capability');
  }
  if (remainingUses <= 0) {
    throw new Error('Invalid remainingUses for warm threshold-ed25519 capability');
  }

  const existingRecord = getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(existingRecord?.participantIds);
  if (!participantIds) {
    throw new Error('Missing participantIds for warm threshold-ed25519 capability');
  }

  const jwt = String(args.jwt || '').trim();
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(jwt) ||
    existingRecord?.runtimePolicyScope;
  const xClientBaseB64u =
    String(args.xClientBaseB64u || '').trim() ||
    String(existingRecord?.xClientBaseB64u || '').trim();

  const record = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: args.nearAccountId,
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
    thresholdSessionKind: args.sessionKind === 'cookie' ? 'cookie' : 'jwt',
    thresholdSessionId: sessionId,
    ...(String(args.walletSigningSessionId || existingRecord?.walletSigningSessionId || '').trim()
      ? {
          walletSigningSessionId: String(
            args.walletSigningSessionId || existingRecord?.walletSigningSessionId || '',
          ).trim(),
        }
      : {}),
    ...(jwt ? { thresholdSessionAuthToken: jwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
  if (!record) {
    throw new Error('Failed to persist warm threshold-ed25519 capability');
  }
  if (record.walletSigningSessionId) {
    publishResolvedIdentity({
      walletId: record.nearAccountId,
      authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionId: record.thresholdSessionId,
    });
  }
  return record;
}
