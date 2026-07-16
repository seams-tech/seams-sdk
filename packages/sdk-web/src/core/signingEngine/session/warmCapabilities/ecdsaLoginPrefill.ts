import { parseThresholdSecp256k1Ecdsa2pParticipantIdsV1 } from '@shared/threshold/secp256k1';
import type {
  SigningSessionStatus,
  RouterAbEcdsaDerivationPresignaturePoolPolicy,
  RouterAbEcdsaDerivationPresignaturePoolPolicyInput,
} from '@/core/types/seams';
import {
  getRouterAbEcdsaDerivationClientPresignaturePoolDepth,
  resolveRouterAbEcdsaDerivationPresignaturePoolPolicy,
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill,
  type RouterAbEcdsaDerivationClientSigningMaterialSource,
  type RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult,
} from '../../routerAb/ecdsaDerivation/presignaturePool';
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
import {
  resolveRouterAbEcdsaWalletSessionAuthFromRecord,
} from './routerAbEcdsaWalletSessionAuth';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaThresholdKeyId,
} from '../keyMaterialBrands';

export type RouterAbEcdsaDerivationLoginPresignaturePrefillSkippedReason =
  | 'pool_disabled'
  | 'pool_already_warm'
  | 'missing_threshold_session_id'
  | 'missing_wallet_session_jwt'
  | 'invalid_session_record'
  | 'warm_session_not_active'
  | 'warm_session_expiry_unavailable'
  | 'threshold_session_mismatch'
  | 'low_remaining_uses'
  | 'missing_router_ab_ecdsa_derivation_state'
  | 'refill_not_scheduled';

export type RouterAbEcdsaDerivationLoginPresignaturePrefillResult =
  | {
      status: 'scheduled';
      reason: 'scheduled';
      thresholdSessionId: string;
      remainingUsesBeforeDispense: number;
      remainingUsesAfterDispense: number;
      schedule: RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult;
    }
  | {
      status: 'skipped';
      reason: 'invalid_session_record' | 'missing_threshold_session_id';
      thresholdSessionId: null;
      details: string | null;
    }
  | {
      status: 'skipped';
      reason:
        | 'missing_wallet_session_jwt'
        | 'warm_session_not_active'
        | 'warm_session_expiry_unavailable'
        | 'missing_router_ab_ecdsa_derivation_state';
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
      schedule: RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult;
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

export type RouterAbEcdsaDerivationLoginPresignaturePrefillDeps = {
  getWarmThresholdEcdsaSessionStatus: (
    walletId: WalletId,
    thresholdSessionId: string,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => Promise<SigningSessionStatus | null>;
  getSignerWorkerContext: () => SignerWorkerManagerContext;
  resolveClientSigningMaterialSource: (
    record: ThresholdEcdsaSessionRecord,
  ) => RouterAbEcdsaDerivationClientSigningMaterialSource;
  routerAbEcdsaDerivationPresignaturePoolPolicy?:
    | RouterAbEcdsaDerivationPresignaturePoolPolicyInput
    | RouterAbEcdsaDerivationPresignaturePoolPolicy;
};

function isWarmSessionActive(
  status: SigningSessionStatus | null,
): status is SigningSessionStatus & { status: 'active'; remainingUses: number } {
  return Boolean(
    status && status.status === 'active' && Number.isFinite(Number(status.remainingUses)),
  );
}

function activeSessionExpiresAtMs(status: SigningSessionStatus): number | null {
  const expiresAtMs = Math.floor(Number(status.expiresAtMs));
  return Number.isSafeInteger(expiresAtMs) && expiresAtMs > Date.now() ? expiresAtMs : null;
}

export async function scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(
  deps: RouterAbEcdsaDerivationLoginPresignaturePrefillDeps,
  args: {
    walletId: WalletId;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    chainTarget: ThresholdEcdsaChainTarget;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
  let thresholdSessionId: string | undefined;
  try {
    const walletId = args.walletId;
    const record = args.thresholdEcdsaSessionRecord;

    const relayerUrl = String(record.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    const clientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
    const participantIds = parseThresholdSecp256k1Ecdsa2pParticipantIdsV1(record.participantIds);
    if (!relayerUrl || !clientVerifyingShareB64u || !participantIds.ok) {
      return {
        status: 'skipped',
        reason: 'invalid_session_record',
        thresholdSessionId: null,
        details: null,
      };
    }

    const identity = tryBuildEcdsaSessionIdentity(record);
    thresholdSessionId = identity?.thresholdSessionId;
    if (!thresholdSessionId || !identity) {
      return {
        status: 'skipped',
        reason: 'missing_threshold_session_id',
        thresholdSessionId: null,
        details: null,
      };
    }

    const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
    if (walletSessionAuth.kind !== 'ready') {
      return {
        status: 'skipped',
        reason: 'missing_wallet_session_jwt',
        thresholdSessionId,
      };
    }
    const walletSessionJwt = walletSessionAuth.walletSessionJwt;

    const policy = resolveRouterAbEcdsaDerivationPresignaturePoolPolicy(deps.routerAbEcdsaDerivationPresignaturePoolPolicy);
    if (!policy.enabled) {
      return {
        status: 'skipped',
        reason: 'pool_disabled',
        thresholdSessionId,
      };
    }

    if (!record.routerAbEcdsaDerivationNormalSigning || Math.floor(Number(record.expiresAtMs)) <= Date.now()) {
      return {
        status: 'skipped',
        reason: 'missing_router_ab_ecdsa_derivation_state',
        thresholdSessionId,
      };
    }

    const existingDepth = getRouterAbEcdsaDerivationClientPresignaturePoolDepth({
      relayerUrl,
      scope: record.routerAbEcdsaDerivationNormalSigning.scope,
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

    const warmSessionExpiresAtMs = activeSessionExpiresAtMs(warmStatus);
    if (warmSessionExpiresAtMs === null) {
      return {
        status: 'skipped',
        reason: 'warm_session_expiry_unavailable',
        thresholdSessionId,
      };
    }

    const routerAbPoolFillExpiresAtMs = Math.min(
      Math.floor(Number(record.expiresAtMs)),
      warmSessionExpiresAtMs,
      Date.now() + 60_000,
    );
    if (routerAbPoolFillExpiresAtMs <= Date.now()) {
      return {
        status: 'skipped',
        reason: 'warm_session_expiry_unavailable',
        thresholdSessionId,
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

    const routerAbEcdsaDerivationPoolFill = {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool' as const,
      scope: record.routerAbEcdsaDerivationNormalSigning.scope,
      expiresAtMs: routerAbPoolFillExpiresAtMs,
    };

    const remainingUsesAfterDispense = remainingUsesBefore;
    const clientSigningMaterial = deps.resolveClientSigningMaterialSource(record);

    const schedule = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl,
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(clientVerifyingShareB64u),
      clientSigningMaterial,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
      credential: { kind: 'jwt', walletSessionJwt },
      routerAbEcdsaDerivationPoolFill,
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
  } catch (error: unknown) {
    return {
      status: 'failed',
      reason: 'unexpected_error',
      thresholdSessionId: thresholdSessionId || null,
      error: String((error as { message?: unknown })?.message || error || 'unexpected error'),
    };
  }
}
