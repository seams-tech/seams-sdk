import type { KeyRef, SignRequest, SignatureBytes, Signer } from '../../interfaces/signing';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/tatchi';
import { deriveThresholdSecp256k1ClientShareWasm } from '../wasm/ethSignerWasm';
import { authorizeEcdsaWithSession } from '../../threshold/workflows/authorizeEcdsa';
import {
  getThresholdEcdsaClientPresignaturePoolDepth,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  signThresholdEcdsaDigestWithPool,
} from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import type { ThresholdEcdsaClientPresignatureRefillScheduleResult } from '../../orchestration/walletOrigin/thresholdEcdsaCoordinator';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import { emitThresholdSessionMetric } from '../../api/thresholdLifecycle/thresholdSessionMetrics';

type EcdsaSessionKind = 'jwt' | 'cookie';
type EcdsaSessionChain = 'tempo' | 'evm';

function inferThresholdEcdsaSessionChainFromLabel(labelRaw: unknown): EcdsaSessionChain | null {
  const label = String(labelRaw || '')
    .trim()
    .toLowerCase();
  if (!label) return null;
  if (label === 'tempo' || label.startsWith('tempo:')) return 'tempo';
  if (label === 'evm' || label.startsWith('evm:')) return 'evm';
  return null;
}

export type ThresholdEcdsaCommitQueueEnqueueFn = <T>(args: {
  nearAccountId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<T>;
}) => Promise<T>;

export type ThresholdEcdsaPrfFirstDispenseFn = (args: {
  sessionId: string;
  uses?: number;
}) => Promise<
  | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
  | { ok: false; code: string; message: string }
>;

export type ThresholdEcdsaPresignRefillScheduledEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: ThresholdEcdsaClientPresignatureRefillScheduleResult;
};

export class Secp256k1Engine implements Signer {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;
  private readonly enqueueThresholdEcdsaCommit?: ThresholdEcdsaCommitQueueEnqueueFn;
  private readonly thresholdEcdsaPresignPoolPolicy: ThresholdEcdsaPresignPoolPolicy;
  private readonly onThresholdEcdsaPresignRefillScheduled?: (
    event: ThresholdEcdsaPresignRefillScheduledEvent,
  ) => void;
  private readonly shouldAbort?: () => boolean;
  private readonly workerCtx: WorkerOperationContext;

  constructor(opts: {
    getRpId?: () => string | null;
    dispenseThresholdEcdsaPrfFirstForSession?: ThresholdEcdsaPrfFirstDispenseFn;
    enqueueThresholdEcdsaCommit?: ThresholdEcdsaCommitQueueEnqueueFn;
    thresholdEcdsaPresignPoolPolicy?:
      | ThresholdEcdsaPresignPoolPolicyInput
      | ThresholdEcdsaPresignPoolPolicy;
    onThresholdEcdsaPresignRefillScheduled?: (
      event: ThresholdEcdsaPresignRefillScheduledEvent,
    ) => void;
    shouldAbort?: () => boolean;
    workerCtx: WorkerOperationContext;
  }) {
    this.getRpId = opts.getRpId;
    this.dispenseThresholdEcdsaPrfFirstForSession = opts.dispenseThresholdEcdsaPrfFirstForSession;
    this.enqueueThresholdEcdsaCommit = opts.enqueueThresholdEcdsaCommit;
    this.thresholdEcdsaPresignPoolPolicy = resolveThresholdEcdsaPresignPoolPolicy(
      opts.thresholdEcdsaPresignPoolPolicy,
    );
    this.onThresholdEcdsaPresignRefillScheduled = opts.onThresholdEcdsaPresignRefillScheduled;
    this.shouldAbort = opts.shouldAbort;
    this.workerCtx = opts.workerCtx;
  }

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'digest' || req.algorithm !== 'secp256k1') {
      throw new Error('[Secp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[Secp256k1Engine] digest32 must be 32 bytes');
    }

    if (keyRef.type !== 'threshold-ecdsa-secp256k1') {
      throw new Error(
        '[Secp256k1Engine] runtime signing requires threshold-ecdsa-secp256k1 keyRef',
      );
    }
    const keyRefThresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
    if (!keyRefThresholdSessionId) {
      throw new Error(
        '[multichain] Missing threshold-ecdsa sessionId on keyRef; reconnect threshold session via bootstrapEcdsaSession',
      );
    }

    const runCommit = async (): Promise<SignatureBytes> => {
      if (this.shouldAbort?.()) {
        const aborted = new Error('Request cancelled') as Error & { code: 'cancelled' };
        aborted.code = 'cancelled';
        throw aborted;
      }

      const rpId = String(this.getRpId?.() || '').trim();
      if (!rpId) {
        throw new Error('[multichain] Missing rpId for threshold-ecdsa signing');
      }
      const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
      if (!participantIds) {
        throw new Error(
          '[multichain] Missing threshold-ecdsa participantIds; reconnect threshold session',
        );
      }

      const resolvedAuthMaterial = resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
        thresholdSessionId: keyRefThresholdSessionId,
        nearAccountIdFallback: keyRef.userId,
      });
      const canonicalRecord = resolvedAuthMaterial?.record || null;
      const hasCanonicalRecord = !!canonicalRecord;
      const requestChain = inferThresholdEcdsaSessionChainFromLabel(req.label);
      const canonicalRecordMatchesKeyRefLane =
        !!canonicalRecord &&
        String(canonicalRecord.nearAccountId || '') === String(keyRef.userId || '') &&
        (!requestChain || canonicalRecord.chain === requestChain) &&
        String(canonicalRecord.relayerUrl || '') === String(keyRef.relayerUrl || '') &&
        String(canonicalRecord.relayerKeyId || '') === String(keyRef.relayerKeyId || '') &&
        String(canonicalRecord.clientVerifyingShareB64u || '') ===
          String(keyRef.clientVerifyingShareB64u || '');

      if (canonicalRecordMatchesKeyRefLane) {
        emitThresholdSessionMetric({
          metric: 'cache_hit',
          curve: 'ecdsa',
          source: 'canonical-session-record',
          sessionId: keyRefThresholdSessionId,
        });
      } else if (hasCanonicalRecord) {
        emitThresholdSessionMetric({
          metric: 'rehydrate_fail',
          curve: 'ecdsa',
          source: 'canonical-session-record',
          sessionId: keyRefThresholdSessionId,
          reason: 'canonical_record_lane_mismatch_ignored',
        });
      } else {
        emitThresholdSessionMetric({
          metric: 'rehydrate_fail',
          curve: 'ecdsa',
          source: 'canonical-session-record',
          sessionId: keyRefThresholdSessionId,
          reason: 'canonical_record_missing_keyref_fallback',
        });
      }

      const keyRefSessionKind = keyRef.thresholdSessionKind;
      const recordSessionKind: EcdsaSessionKind = canonicalRecord?.thresholdSessionKind || 'jwt';
      if (
        canonicalRecordMatchesKeyRefLane &&
        keyRefSessionKind &&
        keyRefSessionKind !== recordSessionKind
      ) {
        emitThresholdSessionMetric({
          metric: 'session_mismatch',
          curve: 'ecdsa',
          source: 'session-kind',
          sessionId: keyRefThresholdSessionId,
          reason: 'keyref_vs_record_session_kind',
        });
        throw new Error(
          '[multichain] threshold-ecdsa session kind mismatch; reconnect threshold session',
        );
      }
      const sessionKind: EcdsaSessionKind = keyRefSessionKind || recordSessionKind || 'jwt';

      const recordSessionId = String(
        (canonicalRecordMatchesKeyRefLane
          ? canonicalRecord?.thresholdSessionId
          : keyRefThresholdSessionId) || keyRefThresholdSessionId,
      ).trim();
      if (
        canonicalRecordMatchesKeyRefLane &&
        (!recordSessionId || recordSessionId !== keyRefThresholdSessionId)
      ) {
        emitThresholdSessionMetric({
          metric: 'session_mismatch',
          curve: 'ecdsa',
          source: 'session-id',
          sessionId: keyRefThresholdSessionId,
          reason: 'keyref_vs_record_session_id',
        });
        throw new Error(
          '[multichain] threshold-ecdsa sessionId mismatch; reconnect threshold session via bootstrapEcdsaSession',
        );
      }

      const keyRefJwt = String(keyRef.thresholdSessionJwt || '').trim();
      const recordJwt = String(
        canonicalRecordMatchesKeyRefLane ? canonicalRecord?.thresholdSessionJwt || '' : '',
      ).trim();
      const resolvedJwt = String(
        canonicalRecordMatchesKeyRefLane ||
          resolvedAuthMaterial?.thresholdSessionJwtSource === 'ed25519'
          ? resolvedAuthMaterial?.thresholdSessionJwt || ''
          : '',
      ).trim();
      if (resolvedAuthMaterial?.thresholdSessionJwtSource === 'ed25519' && resolvedJwt) {
        emitThresholdSessionMetric({
          metric: 'rehydrate_hit',
          curve: 'ecdsa',
          source: 'session-jwt',
          sessionId: keyRefThresholdSessionId,
          reason: 'ed25519_fallback',
        });
      }
      const thresholdSessionJwt = keyRefJwt || resolvedJwt || undefined;

      if (sessionKind === 'jwt' && !thresholdSessionJwt) {
        emitThresholdSessionMetric({
          metric: 'rehydrate_fail',
          curve: 'ecdsa',
          source: 'session-jwt',
          sessionId: keyRefThresholdSessionId,
          reason: 'jwt_unavailable',
        });
        throw new Error(
          '[multichain] threshold-ecdsa session token unavailable; reconnect threshold session via bootstrapEcdsaSession',
        );
      }
      if (sessionKind === 'jwt') {
        if (canonicalRecordMatchesKeyRefLane && keyRefJwt && recordJwt && keyRefJwt !== recordJwt) {
          emitThresholdSessionMetric({
            metric: 'session_mismatch',
            curve: 'ecdsa',
            source: 'session-jwt',
            sessionId: keyRefThresholdSessionId,
            reason: 'keyref_vs_record_jwt',
          });
          throw new Error(
            '[multichain] threshold-ecdsa keyRef JWT does not match session record; reconnect threshold session',
          );
        }
      }

      const purpose = String(req.label || 'secp256k1');
      const authorized = await authorizeEcdsaWithSession({
        relayerUrl: keyRef.relayerUrl,
        relayerKeyId: keyRef.relayerKeyId,
        clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
        purpose,
        signingDigest32: req.digest32,
        sessionKind,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
      });
      if (!authorized.ok || !authorized.mpcSessionId) {
        throw new Error(
          authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed',
        );
      }
      const effectiveThresholdEcdsaPresignPoolPolicy = resolveThresholdEcdsaPresignPoolPolicy({
        ...this.thresholdEcdsaPresignPoolPolicy,
        ...(authorized.presignPoolPolicy || {}),
      });

      if (!this.dispenseThresholdEcdsaPrfFirstForSession) {
        throw new Error('[multichain] Missing PRF.first dispenser for threshold-ecdsa signing');
      }

      const dispensed = await this.dispenseThresholdEcdsaPrfFirstForSession({
        sessionId: keyRefThresholdSessionId,
        uses: 1,
      });
      if (!dispensed.ok) {
        throw new Error(
          dispensed.message ||
            dispensed.code ||
            '[multichain] failed to load PRF.first for threshold-ecdsa signing',
        );
      }

      const derived = await deriveThresholdSecp256k1ClientShareWasm({
        prfFirstB64u: dispensed.prfFirstB64u,
        userId: keyRef.userId,
        workerCtx: this.workerCtx,
      });
      if (derived.clientVerifyingShareB64u !== keyRef.clientVerifyingShareB64u) {
        throw new Error(
          '[multichain] Derived client share does not match keyRef.clientVerifyingShareB64u',
        );
      }

      const refillBaseArgs = {
        relayerUrl: keyRef.relayerUrl,
        relayerKeyId: keyRef.relayerKeyId,
        clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
        participantIds,
        clientSigningShare32: derived.clientSigningShare32,
        groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
        relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
        sessionKind,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
        workerCtx: this.workerCtx,
      };
      const presignPoolDepthAtCommitStart = getThresholdEcdsaClientPresignaturePoolDepth({
        relayerUrl: keyRef.relayerUrl,
        relayerKeyId: keyRef.relayerKeyId,
        clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
        participantIds,
      });
      const presignRefillScheduledAtCommitStart =
        presignPoolDepthAtCommitStart > 0
          ? scheduleThresholdEcdsaClientPresignaturePoolRefill({
              ...refillBaseArgs,
              poolPolicy: effectiveThresholdEcdsaPresignPoolPolicy,
              targetDepth: effectiveThresholdEcdsaPresignPoolPolicy.targetDepth,
              triggerIfDepthAtOrBelow: effectiveThresholdEcdsaPresignPoolPolicy.lowWatermark,
            })
          : {
              scheduled: false,
              reason: 'cold_start_pool_empty' as const,
              depth: presignPoolDepthAtCommitStart,
              targetDepth: effectiveThresholdEcdsaPresignPoolPolicy.targetDepth,
            };
      try {
        this.onThresholdEcdsaPresignRefillScheduled?.({
          trigger: 'commit_start',
          result: presignRefillScheduledAtCommitStart,
        });
      } catch {}

      const signed = await signThresholdEcdsaDigestWithPool({
        relayerUrl: keyRef.relayerUrl,
        relayerKeyId: keyRef.relayerKeyId,
        clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
        mpcSessionId: authorized.mpcSessionId,
        signingDigest32: req.digest32,
        clientSigningShare32: derived.clientSigningShare32,
        participantIds,
        groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
        relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
        sessionKind,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
        workerCtx: this.workerCtx,
      });
      if (!signed.ok) {
        throw new Error(
          signed.message || signed.code || '[multichain] threshold-ecdsa signing failed',
        );
      }

      const presignRefillScheduledPostSign = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        ...refillBaseArgs,
        poolPolicy: effectiveThresholdEcdsaPresignPoolPolicy,
        targetDepth: effectiveThresholdEcdsaPresignPoolPolicy.targetDepth,
        triggerIfDepthAtOrBelow: Math.max(
          0,
          effectiveThresholdEcdsaPresignPoolPolicy.targetDepth - 1,
        ),
      });
      try {
        this.onThresholdEcdsaPresignRefillScheduled?.({
          trigger: 'post_sign_success',
          result: presignRefillScheduledPostSign,
        });
      } catch {}

      return signed.signature65;
    };

    if (this.enqueueThresholdEcdsaCommit) {
      return await this.enqueueThresholdEcdsaCommit({
        nearAccountId: keyRef.userId,
        thresholdSessionId: keyRefThresholdSessionId,
        shouldAbort: this.shouldAbort,
        task: runCommit,
      });
    }

    return await runCommit();
  }
}
