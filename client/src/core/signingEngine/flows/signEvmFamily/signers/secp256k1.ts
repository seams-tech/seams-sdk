import type {
  SignRequest,
  SignatureBytes,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/seams';
import { base64UrlDecode } from '@shared/utils/base64';
import { authorizeEcdsaWithSession } from '../../../threshold/ecdsa/authorize';
import {
  clearThresholdEcdsaClientPresignaturesForLane,
  getThresholdEcdsaClientPresignaturePoolDepth,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  signThresholdEcdsaDigestWithPool,
} from '../../../threshold/ecdsa/presignPool';
import type { ThresholdEcdsaClientPresignatureRefillScheduleResult } from '../../../threshold/ecdsa/presignPool';
import { createWarmSessionCapabilityReader } from '../../../session/warmCapabilities/capabilityReader';
import {
  deleteDurableSealedSessionRecord,
  updateExactSealedSessionPolicy,
} from '../../../session/persistence/sealedSessionStore';
import { createDeleteDurableSealedSessionCommand } from '../../../session/persistence/durableSealedSessionCommands';
import {
  buildReadyEcdsaSignerSession,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildUnavailableReadyThresholdEcdsaSessionPolicy,
  resolveThresholdEcdsaKeyIdFromKeyRef,
  resolveThresholdEcdsaKeyIdFromRecord,
  toVerifiedEcdsaPublicFactsFromKeyRef,
  type ReadyEcdsaSignerSession,
  type ReadyThresholdEcdsaSessionPolicy,
} from '../../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdSessionKind } from '../../../threshold/sessionPolicy';
type EcdsaSessionChain = 'tempo' | 'evm';
type Secp256k1DigestSignRequest = Extract<SignRequest, { kind: 'digest' }> & {
  algorithm: 'secp256k1';
};
export type ReadySecp256k1SigningMaterial = {
  kind: 'ready_secp256k1_signing_material';
  walletId: string;
  signerSession: ReadyEcdsaSignerSession;
  singleUseEmailOtpSession: boolean;
};

export type ReadySecp256k1Signer = {
  readonly algorithm: 'secp256k1';
  signReady: (req: SignRequest, material: ReadySecp256k1SigningMaterial) => Promise<SignatureBytes>;
};

export function buildReadySecp256k1SigningMaterial(args: {
  walletId: unknown;
  signerSession: ReadyEcdsaSignerSession;
  singleUseEmailOtpSession: boolean;
}): ReadySecp256k1SigningMaterial {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[multichain] Missing wallet id for ready secp256k1 signing material');
  }
  return {
    kind: 'ready_secp256k1_signing_material',
    walletId,
    signerSession: args.signerSession,
    singleUseEmailOtpSession: args.singleUseEmailOtpSession,
  };
}

type Secp256k1KeyRefFallbackQueueIdentity = {
  walletId: string;
  thresholdSessionId: string;
};

function isSecp256k1DigestSignRequest(req: SignRequest): req is Secp256k1DigestSignRequest {
  return req.kind === 'digest' && req.algorithm === 'secp256k1';
}

function buildSecp256k1KeyRefFallbackQueueIdentity(
  keyRef: ThresholdEcdsaSecp256k1KeyRef,
): Secp256k1KeyRefFallbackQueueIdentity {
  const walletId = String(keyRef.userId || '').trim();
  if (!walletId) {
    throw new Error('[multichain] Missing wallet id on threshold-ecdsa keyRef');
  }
  const thresholdSessionId = String(keyRef.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error(
      '[multichain] Missing threshold-ecdsa sessionId on keyRef; reconnect threshold session via bootstrapEcdsaSession',
    );
  }
  return { walletId, thresholdSessionId };
}

function readySignerSessionKind(signerSession: ReadyEcdsaSignerSession): ThresholdSessionKind {
  switch (signerSession.transport.auth.kind) {
    case 'jwt_threshold_session_auth':
      return 'jwt';
    case 'cookie_threshold_session_auth':
      return 'cookie';
  }
}

function readySignerSessionAuthToken(signerSession: ReadyEcdsaSignerSession): string | undefined {
  switch (signerSession.transport.auth.kind) {
    case 'jwt_threshold_session_auth':
      return signerSession.transport.auth.thresholdSessionAuthToken;
    case 'cookie_threshold_session_auth':
      return undefined;
  }
}

function readySignerSessionEmailOtpWorkerShareChain(
  signerSession: ReadyEcdsaSignerSession,
): EcdsaSessionChain | null {
  switch (signerSession.clientShare.kind) {
    case 'inline_client_share':
      return null;
    case 'email_otp_worker_share':
      return signerSession.clientShare.handle.laneIdentity.chainTarget.kind;
  }
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
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

async function buildReadySecp256k1SigningMaterialFromKeyRefFallback(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  queueIdentity: Secp256k1KeyRefFallbackQueueIdentity;
  requestLabel: unknown;
  rpId: unknown;
}): Promise<ReadySecp256k1SigningMaterial> {
  const rpId = String(args.rpId || '').trim();
  if (!rpId) {
    throw new Error('[multichain] Missing rpId for threshold-ecdsa signing');
  }
  const keyRef = args.keyRef;
  const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });

  const resolvedAuthMaterial = createWarmSessionCapabilityReader(
    {},
  ).resolveEcdsaAuthByThresholdSessionId(args.queueIdentity.thresholdSessionId);
  const canonicalRecord = resolvedAuthMaterial?.record || null;
  const canonicalRecordThresholdKeyId = canonicalRecord
    ? String(
        resolveThresholdEcdsaKeyIdFromRecord({
          record: canonicalRecord,
        }),
      )
    : '';
  const keyRefThresholdKeyId = String(resolveThresholdEcdsaKeyIdFromKeyRef({ keyRef }));
  const requestChain = inferThresholdEcdsaSessionChainFromLabel(args.requestLabel);
  const canonicalRecordMatchesKeyRefLane =
    !!canonicalRecord &&
    String(canonicalRecord.walletId || '') === args.queueIdentity.walletId &&
    (!requestChain || canonicalRecord.chainTarget.kind === requestChain) &&
    canonicalRecordThresholdKeyId === keyRefThresholdKeyId &&
    String(canonicalRecord.relayerUrl || '') === String(keyRef.relayerUrl || '');

  const keyRefSessionKind = keyRef.thresholdSessionKind;
  const recordSessionKind: ThresholdSessionKind = canonicalRecord?.thresholdSessionKind || 'jwt';
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
      : args.queueIdentity.thresholdSessionId) || args.queueIdentity.thresholdSessionId,
  ).trim();
  if (
    canonicalRecordMatchesKeyRefLane &&
    (!recordSessionId || recordSessionId !== args.queueIdentity.thresholdSessionId)
  ) {
    throw new Error(
      '[multichain] threshold-ecdsa sessionId mismatch; reconnect threshold session via bootstrapEcdsaSession',
    );
  }
  const keyRefAuthToken = String(keyRef.thresholdSessionAuthToken || '').trim();
  const recordAuthToken = String(
    canonicalRecordMatchesKeyRefLane ? canonicalRecord?.thresholdSessionAuthToken || '' : '',
  ).trim();
  const resolvedAuthToken = String(
    canonicalRecordMatchesKeyRefLane ? resolvedAuthMaterial?.thresholdSessionAuthToken || '' : '',
  ).trim();
  const thresholdSessionAuthToken =
    resolvedAuthToken || recordAuthToken || keyRefAuthToken || undefined;

  if (sessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      '[multichain] threshold-ecdsa session token unavailable; reconnect threshold session via bootstrapEcdsaSession',
    );
  }
  if (
    sessionKind === 'jwt' &&
    canonicalRecordMatchesKeyRefLane &&
    keyRefAuthToken &&
    recordAuthToken &&
    keyRefAuthToken !== recordAuthToken
  ) {
    console.debug(
      '[multichain] using current threshold-ecdsa session record auth token over stale keyRef auth token',
      {
        thresholdSessionId: args.queueIdentity.thresholdSessionId,
      },
    );
  }
  const sessionPolicy: ReadyThresholdEcdsaSessionPolicy =
    canonicalRecordMatchesKeyRefLane && canonicalRecord
      ? buildKnownReadyThresholdEcdsaSessionPolicy({
          remainingUses: canonicalRecord.remainingUses,
          expiresAtMs: canonicalRecord.expiresAtMs,
        })
      : buildUnavailableReadyThresholdEcdsaSessionPolicy({
          source: 'key_ref_fallback',
        });
  const signerSession =
    sessionKind === 'jwt'
      ? buildReadyEcdsaSignerSession({
          keyRef,
          publicFacts,
          sessionPolicy,
          thresholdSessionKind: 'jwt',
          thresholdSessionAuthToken,
        })
      : buildReadyEcdsaSignerSession({
          keyRef,
          publicFacts,
          sessionPolicy,
          thresholdSessionKind: 'cookie',
        });
  const signerTransport = signerSession.transport;
  const canonicalRecordMatchesSignerTransport =
    canonicalRecordMatchesKeyRefLane &&
    String(canonicalRecord?.relayerUrl || '') === signerTransport.relayerUrl &&
    canonicalRecordThresholdKeyId === String(signerTransport.ecdsaThresholdKeyId) &&
    String(canonicalRecord?.relayerKeyId || '') === signerTransport.relayerKeyId &&
    String(canonicalRecord?.clientVerifyingShareB64u || '') ===
      signerTransport.clientVerifyingShareB64u;
  if (
    canonicalRecordMatchesSignerTransport &&
    canonicalRecord?.source === 'email_otp' &&
    canonicalRecord.emailOtpAuthContext?.retention === 'single_use' &&
    Number(canonicalRecord.emailOtpAuthContext.consumedAtMs) > 0
  ) {
    throw new Error(
      `[SigningEngine] ${requestChain || canonicalRecord.chainTarget.kind} signing requires fresh Email OTP verification with per_operation policy`,
    );
  }

  return buildReadySecp256k1SigningMaterial({
    walletId: args.queueIdentity.walletId,
    signerSession,
    singleUseEmailOtpSession:
      canonicalRecordMatchesSignerTransport &&
      canonicalRecord?.source === 'email_otp' &&
      canonicalRecord.emailOtpAuthContext?.retention === 'single_use',
  });
}

export async function buildReadySecp256k1SigningMaterialFromKeyRef(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  requestLabel: unknown;
  rpId: unknown;
}): Promise<ReadySecp256k1SigningMaterial> {
  return await buildReadySecp256k1SigningMaterialFromKeyRefFallback({
    keyRef: args.keyRef,
    queueIdentity: buildSecp256k1KeyRefFallbackQueueIdentity(args.keyRef),
    requestLabel: args.requestLabel,
    rpId: args.rpId,
  });
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
          deleteReason: result.code === 'not_found' ? 'invalid_persisted_record' : result.code,
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
  walletId: WalletId;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<T>;
}) => Promise<T>;

export type ThresholdEcdsaPresignRefillScheduledEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: ThresholdEcdsaClientPresignatureRefillScheduleResult;
};

export class Secp256k1Engine {
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

  private async signReadySecp256k1Digest(
    req: Secp256k1DigestSignRequest,
    material: ReadySecp256k1SigningMaterial,
  ): Promise<SignatureBytes> {
    const signerSession = material.signerSession;
    const publicFacts = signerSession.publicFacts;
    const participantIds = publicFacts.participantIds.map((participantId) => Number(participantId));
    const signerTransport = signerSession.transport;
    const sessionKind = readySignerSessionKind(signerSession);
    const signerTransportAuthToken = readySignerSessionAuthToken(signerSession);

    const purpose = String(req.label || 'secp256k1');
    const authorized = await authorizeEcdsaWithSession({
      relayerUrl: signerTransport.relayerUrl,
      keyHandle: String(publicFacts.keyHandle),
      purpose,
      signingDigest32: req.digest32,
      sessionKind,
      ...(signerTransportAuthToken ? { thresholdSessionAuthToken: signerTransportAuthToken } : {}),
    });
    if (!authorized.ok || !authorized.mpcSessionId) {
      throw new Error(
        authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed',
      );
    }
    const emailOtpWorkerShareSessionId =
      signerSession.clientShare.kind === 'email_otp_worker_share'
        ? signerSession.clientShare.handle.sessionId
        : '';
    const emailOtpWorkerShareChain = readySignerSessionEmailOtpWorkerShareChain(signerSession);
    const usesEmailOtpWorkerSession = !!emailOtpWorkerShareSessionId;
    let emailOtpWorkerShareExhausted = false;
    const authorizedPresignPoolPolicy = resolveThresholdEcdsaPresignPoolPolicy({
      ...this.thresholdEcdsaPresignPoolPolicy,
      ...(authorized.presignPoolPolicy || {}),
    });
    const effectiveThresholdEcdsaPresignPoolPolicy = usesEmailOtpWorkerSession
      ? { ...authorizedPresignPoolPolicy, enabled: false }
      : authorizedPresignPoolPolicy;

    let clientSigningShare32: Uint8Array | null = null;
    try {
      if (signerSession.clientShare.kind === 'email_otp_worker_share') {
        if (!emailOtpWorkerShareChain) {
          throw new Error(
            '[multichain] Missing Email OTP ECDSA chain for signing-session policy update',
          );
        }
        const claimedShare = await claimEmailOtpWorkerEcdsaSigningShare({
          workerCtx: this.workerCtx,
          sessionId: signerSession.clientShare.handle.sessionId,
          sealedThresholdSessionId: String(signerSession.session.thresholdSessionId),
          chain: emailOtpWorkerShareChain,
          chainTarget: signerSession.clientShare.handle.laneIdentity.chainTarget,
        });
        clientSigningShare32 = claimedShare.clientSigningShare32;
        emailOtpWorkerShareExhausted =
          claimedShare.remainingUses <= 0 || claimedShare.expiresAtMs <= Date.now();
        await updateEmailOtpSealedRecordPolicyAfterEcdsaClaim({
          thresholdSessionId: String(signerSession.session.thresholdSessionId),
          chain: emailOtpWorkerShareChain,
          chainTarget: signerSession.clientShare.handle.laneIdentity.chainTarget,
          remainingUses: claimedShare.remainingUses,
          expiresAtMs: claimedShare.expiresAtMs,
        });
      } else {
        try {
          clientSigningShare32 = base64UrlDecode(
            signerSession.clientShare.clientAdditiveShare32B64u,
          );
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
        relayerUrl: signerTransport.relayerUrl,
        keyHandle: String(publicFacts.keyHandle),
        ecdsaThresholdKeyId: String(signerTransport.ecdsaThresholdKeyId),
        relayerKeyId: signerTransport.relayerKeyId,
        clientVerifyingShareB64u: signerTransport.clientVerifyingShareB64u,
        participantIds,
        thresholdEcdsaPublicKeyB64u: publicFacts.publicKeyB64u,
        relayerVerifyingShareB64u: signerTransport.relayerVerifyingShareB64u,
        sessionKind,
        ...(signerTransportAuthToken
          ? { thresholdSessionAuthToken: signerTransportAuthToken }
          : {}),
        workerCtx: this.workerCtx,
      };
      if (usesEmailOtpWorkerSession) {
        clearThresholdEcdsaClientPresignaturesForLane({
          relayerUrl: signerTransport.relayerUrl,
          ecdsaThresholdKeyId: String(signerTransport.ecdsaThresholdKeyId),
          participantIds,
        });
      }
      const presignPoolDepthAtCommitStart = getThresholdEcdsaClientPresignaturePoolDepth({
        relayerUrl: signerTransport.relayerUrl,
        ecdsaThresholdKeyId: String(signerTransport.ecdsaThresholdKeyId),
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
        relayerUrl: signerTransport.relayerUrl,
        keyHandle: String(publicFacts.keyHandle),
        ecdsaThresholdKeyId: String(signerTransport.ecdsaThresholdKeyId),
        relayerKeyId: signerTransport.relayerKeyId,
        clientVerifyingShareB64u: signerTransport.clientVerifyingShareB64u,
        mpcSessionId: authorized.mpcSessionId,
        signingDigest32: req.digest32,
        clientSigningShare32: clientSigningShare32.slice(),
        participantIds,
        thresholdEcdsaPublicKeyB64u: publicFacts.publicKeyB64u,
        relayerVerifyingShareB64u: signerTransport.relayerVerifyingShareB64u,
        sessionKind,
        ...(signerTransportAuthToken
          ? { thresholdSessionAuthToken: signerTransportAuthToken }
          : {}),
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
        (material.singleUseEmailOtpSession || emailOtpWorkerShareExhausted)
      ) {
        await clearEmailOtpWorkerSessionBestEffort({
          workerCtx: this.workerCtx,
          sessionId: emailOtpWorkerShareSessionId,
        });
      }
    }
  }

  async signReady(
    req: SignRequest,
    material: ReadySecp256k1SigningMaterial,
  ): Promise<SignatureBytes> {
    if (!isSecp256k1DigestSignRequest(req)) {
      throw new Error('[Secp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[Secp256k1Engine] digest32 must be 32 bytes');
    }
    const runCommit = async (): Promise<SignatureBytes> => {
      if (this.shouldAbort?.()) {
        const aborted = new Error('Request cancelled') as Error & { code: 'cancelled' };
        aborted.code = 'cancelled';
        throw aborted;
      }
      return await this.signReadySecp256k1Digest(req, material);
    };
    if (this.enqueueThresholdEcdsaCommit) {
      return await this.enqueueThresholdEcdsaCommit({
        walletId: toWalletId(material.walletId),
        thresholdSessionId: String(material.signerSession.session.thresholdSessionId),
        shouldAbort: this.shouldAbort,
        task: runCommit,
      });
    }
    return await runCommit();
  }
}
