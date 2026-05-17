import type { KeyRef, SignRequest, SignatureBytes, Signer } from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import type {
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/seams';
import { base64UrlDecode } from '@shared/utils/base64';
import { authorizeEcdsaWithSession } from '../../../threshold/ecdsa/authorize';
import {
  getThresholdEcdsaClientPresignaturePoolDepth,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  signThresholdEcdsaDigestWithPool,
  clearThresholdEcdsaClientPresignaturesForLane,
} from '../../../threshold/ecdsa/presignPool';
import type { ThresholdEcdsaClientPresignatureRefillScheduleResult } from '../../../threshold/ecdsa/presignPool';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { createWarmSessionCapabilityReader } from '../../../session/warmCapabilities/capabilityReader';
import {
  deleteDurableSealedSessionRecord,
  updateExactSealedSessionPolicy,
} from '../../../session/persistence/sealedSessionStore';
import { createDeleteDurableSealedSessionCommand } from '../../../session/persistence/durableSealedSessionCommands';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdSessionKind } from '../../../threshold/sessionPolicy';
type EcdsaSessionChain = 'tempo' | 'evm';

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function resolveEmailOtpShareHandleSessionId(keyRef: KeyRef): string {
  if (keyRef.type !== 'threshold-ecdsa-secp256k1') return '';
  const handle = keyRef.backendBinding?.clientAdditiveShareHandle;
  if (handle?.kind !== 'email_otp_worker_session') return '';
  return String(handle.sessionId || '').trim();
}

function inferThresholdEcdsaSessionChainFromLabel(labelRaw: unknown): EcdsaSessionChain | null {
  const label = String(labelRaw || '')
    .trim()
    .toLowerCase();
  if (!label) return null;
  if (label === 'tempo' || label.startsWith('tempo:')) return 'tempo';
  if (label === 'evm' || label.startsWith('evm:')) return 'evm';
  return null;
}

async function claimEmailOtpWorkerEcdsaSigningShare(args: {
  workerCtx: WorkerOperationContext;
  sessionId: string;
  sealedThresholdSessionId: string;
  chain: EcdsaSessionChain;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<{ clientSigningShare32: Uint8Array; remainingUses: number; expiresAtMs: number }> {
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    throw new Error(
      '[multichain] Missing Email OTP signing share handle; reconnect threshold session',
    );
  }
  const result = await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'claimEmailOtpEcdsaSigningShare',
      timeoutMs: 5_000,
      payload: { sessionId },
    },
  });
  if (!result.ok) {
    if (result.code === 'expired' || result.code === 'exhausted' || result.code === 'not_found') {
      const sealedThresholdSessionId = String(args.sealedThresholdSessionId || '').trim();
      await deleteDurableSealedSessionRecord(
        createDeleteDurableSealedSessionCommand({
          durableRecord: {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            thresholdSessionId: sealedThresholdSessionId || sessionId,
            chainTarget: args.chainTarget,
          },
          deleteReason:
            result.code === 'not_found'
              ? 'invalid_persisted_record'
              : result.code,
          preserveResolvedIdentity: result.code !== 'not_found',
        }),
      ).catch(() => undefined);
    }
    throw new Error(
      result.message ||
        result.code ||
        '[multichain] Email OTP ECDSA signing material is unavailable; verify Email OTP again',
    );
  }
  const clientSigningShare32 = new Uint8Array(result.clientSigningShare32);
  if (clientSigningShare32.length !== 32) {
    zeroizeBytes(clientSigningShare32);
    throw new Error(
      '[multichain] Email OTP ECDSA signing material must decode to 32 bytes; verify Email OTP again',
    );
  }
  return {
    clientSigningShare32,
    remainingUses: Math.max(0, Math.floor(Number(result.remainingUses) || 0)),
    expiresAtMs: Math.max(0, Math.floor(Number(result.expiresAtMs) || 0)),
  };
}

async function updateEmailOtpSealedRecordPolicyAfterEcdsaClaim(args: {
  thresholdSessionId: string;
  chain: EcdsaSessionChain;
  chainTarget: ThresholdEcdsaChainTarget;
  remainingUses: number;
  expiresAtMs: number;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  if (args.remainingUses <= 0 || args.expiresAtMs <= Date.now()) {
    await deleteDurableSealedSessionRecord(
      createDeleteDurableSealedSessionCommand({
        durableRecord: {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          thresholdSessionId,
          chainTarget: args.chainTarget,
        },
        deleteReason: args.remainingUses <= 0 ? 'exhausted' : 'expired',
        preserveResolvedIdentity: true,
      }),
    ).catch(() => undefined);
    return;
  }
  await updateExactSealedSessionPolicy({
    thresholdSessionId,
    filter: {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: args.chainTarget,
    },
    remainingUses: args.remainingUses,
    expiresAtMs: args.expiresAtMs,
    updatedAtMs: Date.now(),
  }).catch(() => undefined);
}

async function clearEmailOtpWorkerSessionBestEffort(args: {
  workerCtx: WorkerOperationContext;
  sessionId: string;
}): Promise<void> {
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) return;
  await args.workerCtx
    .requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'clearEmailOtpWarmSessionMaterial',
        timeoutMs: 5_000,
        payload: { sessionId },
      },
    })
    .catch(() => undefined);
}

export type ThresholdEcdsaCommitQueueEnqueueFn = <T>(args: {
  walletId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<T>;
}) => Promise<T>;

export type ThresholdEcdsaPresignRefillScheduledEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: ThresholdEcdsaClientPresignatureRefillScheduleResult;
};

export class Secp256k1Engine implements Signer {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly enqueueThresholdEcdsaCommit?: ThresholdEcdsaCommitQueueEnqueueFn;
  private readonly thresholdEcdsaPresignPoolPolicy: ThresholdEcdsaPresignPoolPolicy;
  private readonly onThresholdEcdsaPresignRefillScheduled?: (
    event: ThresholdEcdsaPresignRefillScheduledEvent,
  ) => void;
  private readonly shouldAbort?: () => boolean;
  private readonly workerCtx: WorkerOperationContext;

  constructor(opts: {
    getRpId?: () => string | null;
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
      const relayerKeyId = String(keyRef.backendBinding?.relayerKeyId || '').trim();
      if (!relayerKeyId) {
        throw new Error(
          '[multichain] Missing backend relayerKeyId for threshold-ecdsa signing; reconnect threshold session',
        );
      }
      const clientVerifyingShareB64u = String(
        keyRef.backendBinding?.clientVerifyingShareB64u || '',
      ).trim();
      if (!clientVerifyingShareB64u) {
        throw new Error(
          '[multichain] Missing backend clientVerifyingShareB64u for threshold-ecdsa signing; reconnect threshold session',
        );
      }

      const resolvedAuthMaterial =
        createWarmSessionCapabilityReader({}).resolveEcdsaAuthByThresholdSessionId(
          keyRefThresholdSessionId,
        );
      const canonicalRecord = resolvedAuthMaterial?.record || null;
      const requestChain = inferThresholdEcdsaSessionChainFromLabel(req.label);
      const canonicalRecordMatchesKeyRefLane =
        !!canonicalRecord &&
        String(canonicalRecord.walletId || '') === String(keyRef.userId || '') &&
        (!requestChain || canonicalRecord.chainTarget.kind === requestChain) &&
        String(canonicalRecord.ecdsaThresholdKeyId || '') ===
          String(keyRef.ecdsaThresholdKeyId || '') &&
        String(canonicalRecord.relayerUrl || '') === String(keyRef.relayerUrl || '') &&
        String(canonicalRecord.relayerKeyId || '') === relayerKeyId &&
        String(canonicalRecord.clientVerifyingShareB64u || '') === clientVerifyingShareB64u;

      const keyRefSessionKind = keyRef.thresholdSessionKind;
      const recordSessionKind: ThresholdSessionKind =
        canonicalRecord?.thresholdSessionKind || 'jwt';
      if (
        canonicalRecordMatchesKeyRefLane &&
        keyRefSessionKind &&
        keyRefSessionKind !== recordSessionKind
      ) {
        throw new Error(
          '[multichain] threshold-ecdsa session kind mismatch; reconnect threshold session',
        );
      }
      const sessionKind: ThresholdSessionKind = keyRefSessionKind || recordSessionKind || 'jwt';

      const recordSessionId = String(
        (canonicalRecordMatchesKeyRefLane
          ? canonicalRecord?.thresholdSessionId
          : keyRefThresholdSessionId) || keyRefThresholdSessionId,
      ).trim();
      if (
        canonicalRecordMatchesKeyRefLane &&
        (!recordSessionId || recordSessionId !== keyRefThresholdSessionId)
      ) {
        throw new Error(
          '[multichain] threshold-ecdsa sessionId mismatch; reconnect threshold session via bootstrapEcdsaSession',
        );
      }
      if (
        canonicalRecordMatchesKeyRefLane &&
        canonicalRecord?.source === 'email_otp' &&
        canonicalRecord.emailOtpAuthContext?.retention === 'single_use' &&
        Number(canonicalRecord.emailOtpAuthContext.consumedAtMs) > 0
      ) {
        throw new Error(
          `[SigningEngine] ${requestChain || canonicalRecord.chainTarget.kind} signing requires fresh Email OTP verification with per_operation policy`,
        );
      }

      const keyRefAuthToken = String(keyRef.thresholdSessionAuthToken || '').trim();
      const recordAuthToken = String(
        canonicalRecordMatchesKeyRefLane ? canonicalRecord?.thresholdSessionAuthToken || '' : '',
      ).trim();
      const resolvedAuthToken = String(
        canonicalRecordMatchesKeyRefLane ? resolvedAuthMaterial?.thresholdSessionAuthToken || '' : '',
      ).trim();
      const thresholdSessionAuthToken = resolvedAuthToken || recordAuthToken || keyRefAuthToken || undefined;

      if (sessionKind === 'jwt' && !thresholdSessionAuthToken) {
        throw new Error(
          '[multichain] threshold-ecdsa session token unavailable; reconnect threshold session via bootstrapEcdsaSession',
        );
      }
      if (sessionKind === 'jwt') {
        if (canonicalRecordMatchesKeyRefLane && keyRefAuthToken && recordAuthToken && keyRefAuthToken !== recordAuthToken) {
          console.debug(
            '[multichain] using current threshold-ecdsa session record auth token over stale keyRef auth token',
            {
              thresholdSessionId: keyRefThresholdSessionId,
            },
          );
        }
      }

      const purpose = String(req.label || 'secp256k1');
      const authorized = await authorizeEcdsaWithSession({
        relayerUrl: keyRef.relayerUrl,
        ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
        purpose,
        signingDigest32: req.digest32,
        sessionKind,
        ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
      });
      if (!authorized.ok || !authorized.mpcSessionId) {
        throw new Error(
          authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed',
        );
      }
      const emailOtpWorkerShareSessionId = resolveEmailOtpShareHandleSessionId(keyRef);
      const emailOtpWorkerShareChain = requestChain || canonicalRecord?.chainTarget.kind || null;
      const usesEmailOtpWorkerSession = !!emailOtpWorkerShareSessionId;
      let emailOtpWorkerShareExhausted = false;
      const isSingleUseEmailOtpSession =
        canonicalRecordMatchesKeyRefLane &&
        canonicalRecord?.source === 'email_otp' &&
        canonicalRecord.emailOtpAuthContext?.retention === 'single_use';
      const authorizedPresignPoolPolicy = resolveThresholdEcdsaPresignPoolPolicy({
        ...this.thresholdEcdsaPresignPoolPolicy,
        ...(authorized.presignPoolPolicy || {}),
      });
      const effectiveThresholdEcdsaPresignPoolPolicy = usesEmailOtpWorkerSession
        ? { ...authorizedPresignPoolPolicy, enabled: false }
        : authorizedPresignPoolPolicy;

      let clientSigningShare32: Uint8Array | null = null;
      try {
        if (emailOtpWorkerShareSessionId) {
          if (!emailOtpWorkerShareChain) {
            throw new Error(
              '[multichain] Missing Email OTP ECDSA chain for signing-session policy update',
            );
          }
          const claimedShare = await claimEmailOtpWorkerEcdsaSigningShare({
            workerCtx: this.workerCtx,
            sessionId: emailOtpWorkerShareSessionId,
            sealedThresholdSessionId: keyRefThresholdSessionId,
            chain: emailOtpWorkerShareChain,
            chainTarget: keyRef.chainTarget,
          });
          clientSigningShare32 = claimedShare.clientSigningShare32;
          emailOtpWorkerShareExhausted =
            claimedShare.remainingUses <= 0 || claimedShare.expiresAtMs <= Date.now();
          await updateEmailOtpSealedRecordPolicyAfterEcdsaClaim({
            thresholdSessionId: keyRefThresholdSessionId,
            chain: emailOtpWorkerShareChain,
            chainTarget: keyRef.chainTarget,
            remainingUses: claimedShare.remainingUses,
            expiresAtMs: claimedShare.expiresAtMs,
          });
        } else {
          const clientAdditiveShare32B64u = String(
            keyRef.backendBinding?.clientAdditiveShare32B64u || '',
          ).trim();
          if (!clientAdditiveShare32B64u) {
            throw new Error(
              '[multichain] Missing threshold ECDSA signing material; reconnect threshold session',
            );
          }
          try {
            clientSigningShare32 = base64UrlDecode(clientAdditiveShare32B64u);
          } catch {
            throw new Error(
              '[multichain] backend clientAdditiveShare32B64u must be valid base64url; reconnect threshold session',
            );
          }
          if (clientSigningShare32.length !== 32) {
            throw new Error(
              '[multichain] backend clientAdditiveShare32B64u must decode to 32 bytes; reconnect threshold session',
            );
          }
        }

        const refillBaseArgs = {
          relayerUrl: keyRef.relayerUrl,
          ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
          relayerKeyId,
          clientVerifyingShareB64u,
          participantIds,
          thresholdEcdsaPublicKeyB64u: keyRef.thresholdEcdsaPublicKeyB64u,
          relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
          sessionKind,
          ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
          workerCtx: this.workerCtx,
        };
        if (usesEmailOtpWorkerSession) {
          clearThresholdEcdsaClientPresignaturesForLane({
            relayerUrl: keyRef.relayerUrl,
            ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
            participantIds,
          });
        }
        const presignPoolDepthAtCommitStart = getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: keyRef.relayerUrl,
          ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
          participantIds,
        });
        const presignRefillScheduledAtCommitStart =
          presignPoolDepthAtCommitStart > 0
            ? scheduleThresholdEcdsaClientPresignaturePoolRefill({
                ...refillBaseArgs,
                clientSigningShare32: clientSigningShare32.slice(),
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
          ecdsaThresholdKeyId: String(keyRef.ecdsaThresholdKeyId || '').trim(),
          relayerKeyId,
          clientVerifyingShareB64u,
          mpcSessionId: authorized.mpcSessionId,
          signingDigest32: req.digest32,
          clientSigningShare32: clientSigningShare32.slice(),
          participantIds,
          thresholdEcdsaPublicKeyB64u: keyRef.thresholdEcdsaPublicKeyB64u,
          relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
          sessionKind,
          ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
          workerCtx: this.workerCtx,
        });
        if (!signed.ok) {
          throw new Error(
            signed.message || signed.code || '[multichain] threshold-ecdsa signing failed',
          );
        }

        const presignRefillScheduledPostSign = scheduleThresholdEcdsaClientPresignaturePoolRefill({
          ...refillBaseArgs,
          clientSigningShare32: clientSigningShare32.slice(),
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
      } finally {
        zeroizeBytes(clientSigningShare32);
        if (
          emailOtpWorkerShareSessionId &&
          (isSingleUseEmailOtpSession || emailOtpWorkerShareExhausted)
        ) {
          await clearEmailOtpWorkerSessionBestEffort({
            workerCtx: this.workerCtx,
            sessionId: emailOtpWorkerShareSessionId,
          });
        }
      }
    };

    if (this.enqueueThresholdEcdsaCommit) {
      return await this.enqueueThresholdEcdsaCommit({
        walletId: keyRef.userId,
        thresholdSessionId: keyRefThresholdSessionId,
        shouldAbort: this.shouldAbort,
        task: runCommit,
      });
    }

    return await runCommit();
  }
}
