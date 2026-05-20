import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizeThresholdSessionKind } from '../../threshold/sessionPolicy';
import type {
  SigningSessionStatus,
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/seams';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  getThresholdEcdsaClientPresignaturePoolDepth,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  type ThresholdEcdsaClientPresignatureRefillScheduleResult,
} from '../../threshold/ecdsa/presignPool';
import type { SignerWorkerManagerContext } from '../../workerManager/SignerWorkerManager';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  LOGIN_PREFILL_MIN_REMAINING_USES,
  LOGIN_PREFILL_TARGET_DEPTH,
  LOGIN_PREFILL_TRIGGER_DEPTH,
} from '@/core/config/defaultConfigs';
import { tryBuildEcdsaSessionIdentity } from './ecdsaProvisionPlan';

export type ThresholdEcdsaLoginPrefillSkippedReason =
  | 'pool_disabled'
  | 'pool_already_warm'
  | 'missing_threshold_session_id'
  | 'missing_threshold_session_auth_token'
  | 'invalid_key_ref'
  | 'warm_session_not_active'
  | 'threshold_session_mismatch'
  | 'low_remaining_uses'
  | 'refill_not_scheduled';

export type ThresholdEcdsaLoginPrefillResult =
  | {
      status: 'scheduled';
      reason: 'scheduled';
      thresholdSessionId: string;
      remainingUsesBeforeDispense: number;
      remainingUsesAfterDispense: number;
      schedule: ThresholdEcdsaClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'skipped';
      reason: 'invalid_key_ref' | 'missing_threshold_session_id';
      thresholdSessionId: null;
      details: string | null;
    }
  | {
      status: 'skipped';
      reason: 'missing_threshold_session_auth_token' | 'warm_session_not_active';
      thresholdSessionId: string;
    }
  | {
      status: 'skipped';
      reason: 'threshold_session_mismatch';
      thresholdSessionId: string;
      details: string;
    }
  | {
      status: 'skipped';
      reason: 'low_remaining_uses';
      thresholdSessionId: string;
      remainingUses: number;
    }
  | {
      status: 'skipped';
      reason: 'refill_not_scheduled';
      thresholdSessionId: string;
      remainingUses: number;
      schedule: ThresholdEcdsaClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'skipped';
      reason: 'pool_disabled' | 'pool_already_warm';
      thresholdSessionId: string;
    }
  | {
      status: 'failed';
      reason: 'unexpected_error';
      thresholdSessionId: string | null;
      error: string;
    };

export type ThresholdEcdsaLoginPrefillDeps = {
  getWarmThresholdEcdsaSessionStatus: (
    walletId: WalletId,
    thresholdSessionId: string,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => Promise<SigningSessionStatus | null>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  resolveClientSigningShare32: (keyRef: ThresholdEcdsaSecp256k1KeyRef) => Promise<Uint8Array>;
  thresholdEcdsaPresignPoolPolicy?:
    | ThresholdEcdsaPresignPoolPolicyInput
    | ThresholdEcdsaPresignPoolPolicy;
};

function isWarmSessionActive(
  status: SigningSessionStatus | null,
): status is SigningSessionStatus & { status: 'active'; remainingUses: number } {
  return Boolean(
    status && status.status === 'active' && Number.isFinite(Number(status.remainingUses)),
  );
}

export async function scheduleThresholdEcdsaLoginPresignPrefill(
  deps: ThresholdEcdsaLoginPrefillDeps,
  args: {
    walletId: WalletId;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    chainTarget: ThresholdEcdsaChainTarget;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  let thresholdSessionId: string | undefined;
  try {
    const walletId = args.walletId;
    const keyRef = args.thresholdEcdsaKeyRef;
    if (!keyRef || keyRef.type !== 'threshold-ecdsa-secp256k1') {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
        thresholdSessionId: null,
        details: null,
      };
    }

    const relayerUrl = String(keyRef.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
    const clientVerifyingShareB64u = String(
      keyRef.backendBinding?.clientVerifyingShareB64u || '',
    ).trim();
    const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
    if (!relayerUrl || !relayerKeyId || !clientVerifyingShareB64u || !participantIds) {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
        thresholdSessionId: null,
        details: null,
      };
    }

    const identity = tryBuildEcdsaSessionIdentity(keyRef);
    thresholdSessionId = identity?.thresholdSessionId;
    if (!thresholdSessionId || !identity) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_id',
        thresholdSessionId: null,
        details: null,
      };
    }

    const sessionKind = normalizeThresholdSessionKind(keyRef.thresholdSessionKind);
    const thresholdSessionAuthToken = String(keyRef.thresholdSessionAuthToken || '').trim();
    if (sessionKind === 'jwt' && !thresholdSessionAuthToken) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_auth_token',
        thresholdSessionId,
      };
    }

    const policy = resolveThresholdEcdsaPresignPoolPolicy(deps.thresholdEcdsaPresignPoolPolicy);
    if (!policy.enabled) {
      return {
        status: 'skipped',
        reason: 'pool_disabled',
        thresholdSessionId,
      };
    }

    const existingDepth = getThresholdEcdsaClientPresignaturePoolDepth({
      relayerUrl,
      ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
      participantIds,
    });
    if (existingDepth >= LOGIN_PREFILL_TARGET_DEPTH) {
      return {
        status: 'skipped',
        reason: 'pool_already_warm',
        thresholdSessionId,
      };
    }

    const warmStatus = await deps.getWarmThresholdEcdsaSessionStatus(
      walletId,
      thresholdSessionId,
      args.chainTarget,
    );
    if (!isWarmSessionActive(warmStatus)) {
      return {
        status: 'skipped',
        reason: 'warm_session_not_active',
        thresholdSessionId,
      };
    }
    if (String(warmStatus.sessionId || '').trim() !== identity.thresholdSessionId) {
      return {
        status: 'skipped',
        reason: 'threshold_session_mismatch',
        thresholdSessionId,
        details: `active=${warmStatus.sessionId}`,
      };
    }

    const minimumUses = Math.max(
      LOGIN_PREFILL_MIN_REMAINING_USES,
      Math.floor(Number(args.minRemainingUsesBeforePrefill ?? LOGIN_PREFILL_MIN_REMAINING_USES)),
    );
    const remainingUsesBefore = Math.floor(Number(warmStatus.remainingUses) || 0);
    if (remainingUsesBefore < minimumUses) {
      return {
        status: 'skipped',
        reason: 'low_remaining_uses',
        thresholdSessionId,
        remainingUses: remainingUsesBefore,
      };
    }

    let clientSigningShare32: Uint8Array | null = null;
    const remainingUsesAfterDispense = remainingUsesBefore;
    try {
      clientSigningShare32 = await deps.resolveClientSigningShare32(keyRef);
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message || error || '').trim();
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
        thresholdSessionId: null,
        details: message || 'missing ECDSA signing material',
      };
    }

    try {
      const schedule = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl,
        ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
        relayerKeyId,
        clientVerifyingShareB64u,
        participantIds,
        clientSigningShare32: clientSigningShare32.slice(),
        thresholdEcdsaPublicKeyB64u: keyRef.thresholdEcdsaPublicKeyB64u,
        relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
        sessionKind,
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
        workerCtx: deps.getSignerWorkerContext(),
        poolPolicy: policy,
        targetDepth: LOGIN_PREFILL_TARGET_DEPTH,
        triggerIfDepthAtOrBelow: LOGIN_PREFILL_TRIGGER_DEPTH,
      });

      if (!schedule.scheduled) {
      return {
        status: 'skipped',
        reason: 'refill_not_scheduled',
        thresholdSessionId,
        remainingUses: remainingUsesAfterDispense,
          schedule,
        };
      }

      return {
        status: 'scheduled',
        reason: 'scheduled',
        thresholdSessionId,
        remainingUsesBeforeDispense: remainingUsesBefore,
        remainingUsesAfterDispense,
        schedule,
      };
    } finally {
      clientSigningShare32.fill(0);
    }
  } catch (error: unknown) {
    return {
      status: 'failed',
      reason: 'unexpected_error',
      thresholdSessionId: thresholdSessionId || null,
      error: String((error as { message?: unknown })?.message || error || 'unexpected error'),
    };
  }
}
