import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/base64';
import { normalizeInteger } from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  normalizeThresholdEcdsaSessionKind,
  type ThresholdEcdsaSessionKind as EcdsaSessionKind,
} from './normalization';
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
} from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import type { SignerWorkerManagerContext } from '../../workerManager';
import {
  LOGIN_PREFILL_MIN_REMAINING_USES,
  LOGIN_PREFILL_TARGET_DEPTH,
  LOGIN_PREFILL_TRIGGER_DEPTH,
} from '@/core/config/defaultConfigs';

export type ThresholdEcdsaLoginPrefillSkippedReason =
  | 'pool_disabled'
  | 'pool_already_warm'
  | 'missing_threshold_session_id'
  | 'missing_threshold_session_jwt'
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
      reason: ThresholdEcdsaLoginPrefillSkippedReason;
      thresholdSessionId?: string;
      remainingUses?: number;
      details?: string;
      schedule?: ThresholdEcdsaClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'failed';
      reason: 'unexpected_error';
      thresholdSessionId?: string;
      error: string;
    };

export type ThresholdEcdsaLoginPrefillDeps = {
  getWarmThresholdEcdsaSessionStatus: (
    nearAccountId: AccountId | string,
    thresholdSessionId: string,
    chain: 'tempo' | 'evm',
  ) => Promise<SigningSessionStatus | null>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  thresholdEcdsaPresignPoolPolicy?:
    | ThresholdEcdsaPresignPoolPolicyInput
    | ThresholdEcdsaPresignPoolPolicy;
};

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function isWarmSessionActive(
  status: SigningSessionStatus | null,
): status is SigningSessionStatus & { status: 'active'; remainingUses: number } {
  return Boolean(
    status && status.status === 'active' && Number.isFinite(Number(status.remainingUses)),
  );
}

function resolveEmailOtpShareHandleSessionId(keyRef: ThresholdEcdsaSecp256k1KeyRef): string {
  const handle = keyRef.backendBinding?.clientAdditiveShareHandle;
  if (handle?.kind !== 'email_otp_worker_session') return '';
  return String(handle.sessionId || '').trim();
}

async function claimEmailOtpWorkerEcdsaSigningShare(args: {
  deps: ThresholdEcdsaLoginPrefillDeps;
  sessionId: string;
}): Promise<Uint8Array> {
  const result = await args.deps.getSignerWorkerContext().requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'claimEmailOtpEcdsaSigningShare',
      timeoutMs: 5_000,
      payload: { sessionId: args.sessionId },
    },
  });
  if (!result.ok) {
    throw new Error(
      result.message ||
        result.code ||
        'Email OTP ECDSA signing material is unavailable; verify Email OTP again',
    );
  }
  const clientSigningShare32 = new Uint8Array(result.clientSigningShare32);
  if (clientSigningShare32.length !== 32) {
    zeroizeBytes(clientSigningShare32);
    throw new Error('Email OTP ECDSA signing material must contain 32 bytes');
  }
  return clientSigningShare32;
}

export async function scheduleThresholdEcdsaLoginPresignPrefill(
  deps: ThresholdEcdsaLoginPrefillDeps,
  args: {
    nearAccountId: AccountId | string;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    chain: 'tempo' | 'evm';
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  let thresholdSessionId: string | undefined;
  try {
    const chain = args.chain;
    const nearAccountId = toAccountId(args.nearAccountId);
    const keyRef = args.thresholdEcdsaKeyRef;
    if (!keyRef || keyRef.type !== 'threshold-ecdsa-secp256k1') {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
      };
    }

    const relayerUrl = String(keyRef.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
    const clientVerifyingShareB64u = String(
      keyRef.backendBinding?.clientVerifyingShareB64u || '',
    ).trim();
    const clientAdditiveShare32B64u = String(
      keyRef.backendBinding?.clientAdditiveShare32B64u || '',
    ).trim();
    const emailOtpWorkerShareSessionId = resolveEmailOtpShareHandleSessionId(keyRef);
    const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
    if (!relayerUrl || !relayerKeyId || !clientVerifyingShareB64u || !participantIds) {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
      };
    }

    thresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
    if (!thresholdSessionId) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_id',
      };
    }

    const sessionKind = normalizeThresholdEcdsaSessionKind(keyRef.thresholdSessionKind);
    const thresholdSessionJwt = String(keyRef.thresholdSessionJwt || '').trim();
    if (sessionKind === 'jwt' && !thresholdSessionJwt) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_jwt',
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
      nearAccountId,
      thresholdSessionId,
      chain,
    );
    if (!isWarmSessionActive(warmStatus)) {
      return {
        status: 'skipped',
        reason: 'warm_session_not_active',
        thresholdSessionId,
      };
    }
    if (String(warmStatus.sessionId || '').trim() !== thresholdSessionId) {
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
    const remainingUsesBefore = normalizeInteger(warmStatus.remainingUses);
    if (remainingUsesBefore == null || remainingUsesBefore < minimumUses) {
      return {
        status: 'skipped',
        reason: 'low_remaining_uses',
        thresholdSessionId,
        remainingUses: remainingUsesBefore ?? undefined,
      };
    }

    let clientSigningShare32: Uint8Array | null = null;
    const remainingUsesAfterDispense = remainingUsesBefore;
    if (!clientAdditiveShare32B64u && !emailOtpWorkerShareSessionId) {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
        thresholdSessionId,
        details: 'missing ECDSA signing material',
      };
    }
    if (emailOtpWorkerShareSessionId) {
      clientSigningShare32 = await claimEmailOtpWorkerEcdsaSigningShare({
        deps,
        sessionId: emailOtpWorkerShareSessionId,
      });
    } else {
      try {
        clientSigningShare32 = base64UrlDecode(clientAdditiveShare32B64u);
      } catch {
        return {
          status: 'skipped',
          reason: 'invalid_key_ref',
          thresholdSessionId,
          details: 'clientAdditiveShare32B64u must be valid base64url',
        };
      }
      if (clientSigningShare32.length !== 32) {
        return {
          status: 'skipped',
          reason: 'invalid_key_ref',
          thresholdSessionId,
          details: 'clientAdditiveShare32B64u must decode to 32 bytes',
        };
      }
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
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
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
      zeroizeBytes(clientSigningShare32);
    }
  } catch (error: unknown) {
    return {
      status: 'failed',
      reason: 'unexpected_error',
      ...(thresholdSessionId ? { thresholdSessionId } : {}),
      error: String((error as { message?: unknown })?.message || error || 'unexpected error'),
    };
  }
}
