import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  SigningSessionStatus,
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/tatchi';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  getThresholdEcdsaClientPresignaturePoolDepth,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  type ThresholdEcdsaClientPresignatureRefillScheduleResult,
} from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../signers/wasm/ethSignerWasm';
import type { ThresholdPrfCacheDispenseResult } from '../../touchConfirm';
import type { SignerWorkerManagerContext } from '../../workerManager';

type EcdsaSessionKind = 'jwt' | 'cookie';

const LOGIN_PREFILL_TARGET_DEPTH = 1;
const LOGIN_PREFILL_TRIGGER_DEPTH = 0;
const LOGIN_PREFILL_MIN_REMAINING_USES = 2;

export type ThresholdEcdsaLoginPrefillSkippedReason =
  | 'pool_disabled'
  | 'pool_already_warm'
  | 'missing_threshold_session_id'
  | 'missing_threshold_session_jwt'
  | 'invalid_key_ref'
  | 'warm_session_not_active'
  | 'threshold_session_mismatch'
  | 'low_remaining_uses'
  | 'prf_unavailable'
  | 'derived_share_mismatch'
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
      reason: 'derive_failed' | 'unexpected_error';
      thresholdSessionId?: string;
      error: string;
    };

export type ThresholdEcdsaLoginPrefillDeps = {
  getWarmSigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
  dispensePrfFirstForThresholdSession: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<ThresholdPrfCacheDispenseResult>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  thresholdEcdsaPresignPoolPolicy?:
    | ThresholdEcdsaPresignPoolPolicyInput
    | ThresholdEcdsaPresignPoolPolicy;
};

function normalizeSessionKind(value: unknown): EcdsaSessionKind {
  return String(value || '').trim().toLowerCase() === 'cookie' ? 'cookie' : 'jwt';
}

function normalizeRemainingUses(value: unknown): number | null {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.floor(n);
}

function isWarmSessionActive(
  status: SigningSessionStatus | null,
): status is SigningSessionStatus & { status: 'active'; remainingUses: number } {
  return Boolean(
    status
      && status.status === 'active'
      && Number.isFinite(Number(status.remainingUses)),
  );
}

export async function scheduleThresholdEcdsaLoginPresignPrefill(
  deps: ThresholdEcdsaLoginPrefillDeps,
  args: {
    nearAccountId: AccountId | string;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  let thresholdSessionId: string | undefined;
  try {
    const nearAccountId = toAccountId(args.nearAccountId);
    const keyRef = args.thresholdEcdsaKeyRef;
    if (!keyRef || keyRef.type !== 'threshold-ecdsa-secp256k1') {
      return {
        status: 'skipped',
        reason: 'invalid_key_ref',
      };
    }

    const relayerUrl = String(keyRef.relayerUrl || '').trim().replace(/\/+$/g, '');
    const relayerKeyId = String(keyRef.relayerKeyId || '').trim();
    const clientVerifyingShareB64u = String(keyRef.clientVerifyingShareB64u || '').trim();
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

    const sessionKind = normalizeSessionKind(keyRef.thresholdSessionKind);
    const thresholdSessionJwt = String(keyRef.thresholdSessionJwt || '').trim();
    if (sessionKind === 'jwt' && !thresholdSessionJwt) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_jwt',
        thresholdSessionId,
      };
    }

    const policy = resolveThresholdEcdsaPresignPoolPolicy(
      deps.thresholdEcdsaPresignPoolPolicy,
    );
    if (!policy.enabled) {
      return {
        status: 'skipped',
        reason: 'pool_disabled',
        thresholdSessionId,
      };
    }

    const existingDepth = getThresholdEcdsaClientPresignaturePoolDepth({
      relayerUrl,
      relayerKeyId,
      clientVerifyingShareB64u,
      participantIds,
    });
    if (existingDepth >= LOGIN_PREFILL_TARGET_DEPTH) {
      return {
        status: 'skipped',
        reason: 'pool_already_warm',
        thresholdSessionId,
      };
    }

    const warmStatus = await deps.getWarmSigningSessionStatus(nearAccountId);
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
    const remainingUsesBefore = normalizeRemainingUses(warmStatus.remainingUses);
    if (remainingUsesBefore == null || remainingUsesBefore < minimumUses) {
      return {
        status: 'skipped',
        reason: 'low_remaining_uses',
        thresholdSessionId,
        remainingUses: remainingUsesBefore ?? undefined,
      };
    }

    const dispensed = await deps.dispensePrfFirstForThresholdSession({
      sessionId: thresholdSessionId,
      uses: 1,
    });
    if (!dispensed.ok) {
      return {
        status: 'skipped',
        reason: 'prf_unavailable',
        thresholdSessionId,
        details: `${dispensed.code}:${dispensed.message}`,
      };
    }

    let derived: Awaited<ReturnType<typeof deriveThresholdSecp256k1ClientShareWasm>>;
    try {
      derived = await deriveThresholdSecp256k1ClientShareWasm({
        prfFirstB64u: dispensed.prfFirstB64u,
        userId: nearAccountId,
        workerCtx: deps.getSignerWorkerContext(),
      });
    } catch (error: unknown) {
      return {
        status: 'failed',
        reason: 'derive_failed',
        thresholdSessionId,
        error: String((error as { message?: unknown })?.message || error || 'derive failed'),
      };
    }

    if (derived.clientVerifyingShareB64u !== clientVerifyingShareB64u) {
      return {
        status: 'skipped',
        reason: 'derived_share_mismatch',
        thresholdSessionId,
      };
    }

    const schedule = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl,
      relayerKeyId,
      clientVerifyingShareB64u,
      participantIds,
      clientSigningShare32: derived.clientSigningShare32,
      groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
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
        remainingUses: normalizeRemainingUses(dispensed.remainingUses) ?? undefined,
        schedule,
      };
    }

    return {
      status: 'scheduled',
      reason: 'scheduled',
      thresholdSessionId,
      remainingUsesBeforeDispense: remainingUsesBefore,
      remainingUsesAfterDispense: Math.max(0, Math.floor(Number(dispensed.remainingUses) || 0)),
      schedule,
    };
  } catch (error: unknown) {
    return {
      status: 'failed',
      reason: 'unexpected_error',
      ...(thresholdSessionId ? { thresholdSessionId } : {}),
      error: String((error as { message?: unknown })?.message || error || 'unexpected error'),
    };
  }
}
