import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import {
  deleteDurableSealedSessionRecord,
  updateExactSealedSessionPolicy,
} from '../../../session/persistence/sealedSessionStore';
import { createDeleteDurableSealedSessionCommand } from '../../../session/persistence/durableSealedSessionCommands';
import type {
  ReadyEcdsaSignerSession,
} from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
} from '../../../threshold/crypto/hssClientSignerWasm';
import type { RouterAbEcdsaHssClientSigningMaterialSource } from '../../../routerAb/ecdsaHss/presignaturePool';
import {
  abortRouterAbEcdsaHssClientPresignSession,
  computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle,
  initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare,
  stepRouterAbEcdsaHssClientPresignSession,
} from '../../../routerAb/ecdsaHss/clientSigningMaterialBoundary';

type EcdsaSessionChain = 'tempo' | 'evm';

export type SignableReadyEcdsaSignerSession = ReadyEcdsaSignerSession & {
  clientShare: ReadyEcdsaSignerSession['clientShare'];
};

export type LoadedRouterAbEcdsaHssSigningMaterialSource = {
  signerSession: SignableReadyEcdsaSignerSession;
  clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource;
  cleanupAfterSign: (args: { singleUseEmailOtpSession: boolean }) => Promise<void>;
};

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function readySignerSessionEmailOtpWorkerShareChain(
  signerSession: SignableReadyEcdsaSignerSession,
): EcdsaSessionChain | null {
  switch (signerSession.clientShare.kind) {
    case 'role_local_worker_share':
      return null;
    case 'email_otp_worker_share':
      return signerSession.clientShare.handle.laneIdentity.chainTarget.kind;
  }
}

async function claimEmailOtpWorkerEcdsaSigningShare(args: {
  workerCtx: WorkerOperationContext;
  sessionId: string;
  sealedThresholdSessionId: string;
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
  chainTarget: ThresholdEcdsaChainTarget;
  remainingUses: number;
  expiresAtMs: number;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
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

export async function loadRouterAbEcdsaHssSigningMaterialSource(args: {
  signerSession: ReadyEcdsaSignerSession;
  workerCtx: WorkerOperationContext;
}): Promise<LoadedRouterAbEcdsaHssSigningMaterialSource> {
  const signerSession: SignableReadyEcdsaSignerSession = args.signerSession;
  const emailOtpWorkerShareSessionId =
    signerSession.clientShare.kind === 'email_otp_worker_share'
      ? signerSession.clientShare.handle.sessionId
      : '';
  const emailOtpWorkerShareChain = readySignerSessionEmailOtpWorkerShareChain(signerSession);
  let emailOtpWorkerShareExhausted = false;

  return {
    signerSession,
    clientSigningMaterial: {
      kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1',
      initClientPresignSession: async (input) => {
        let clientSigningShare32: Uint8Array | null = null;
        try {
          if (signerSession.clientShare.kind === 'email_otp_worker_share') {
            if (!emailOtpWorkerShareChain) {
              throw new Error(
                '[multichain] Missing Email OTP ECDSA chain for signing-session policy update',
              );
            }
            const claimedShare = await claimEmailOtpWorkerEcdsaSigningShare({
              workerCtx: args.workerCtx,
              sessionId: signerSession.clientShare.handle.sessionId,
              sealedThresholdSessionId: String(signerSession.session.thresholdSessionId),
              chainTarget: signerSession.clientShare.handle.laneIdentity.chainTarget,
            });
            clientSigningShare32 = claimedShare.clientSigningShare32;
            emailOtpWorkerShareExhausted =
              claimedShare.remainingUses <= 0 || claimedShare.expiresAtMs <= Date.now();
            await updateEmailOtpSealedRecordPolicyAfterEcdsaClaim({
              thresholdSessionId: String(signerSession.session.thresholdSessionId),
              chainTarget: signerSession.clientShare.handle.laneIdentity.chainTarget,
              remainingUses: claimedShare.remainingUses,
              expiresAtMs: claimedShare.expiresAtMs,
            });
          } else if (signerSession.clientShare.kind === 'role_local_worker_share') {
            return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
              materialHandle: signerSession.clientShare.handle.materialHandle,
              expectedBindingDigest: signerSession.clientShare.handle.bindingDigest,
              ...input,
            });
          } else {
            throw new Error('[multichain] threshold-ecdsa signer session is missing signing material');
          }

          const initialized = await initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare({
            clientSigningShare32,
            ...input,
          });
          clientSigningShare32 = null;
          return initialized;
        } finally {
          zeroizeBytes(clientSigningShare32);
        }
      },
      stepClientPresignSession: async (input) =>
        signerSession.clientShare.kind === 'role_local_worker_share'
          ? await thresholdEcdsaRoleLocalPresignSessionStepWasm(input)
          : await stepRouterAbEcdsaHssClientPresignSession(input),
      abortClientPresignSession: async (input) =>
        signerSession.clientShare.kind === 'role_local_worker_share'
          ? await thresholdEcdsaRoleLocalPresignSessionAbortWasm(input)
          : await abortRouterAbEcdsaHssClientPresignSession(input),
      computeSignatureShareFromPresignatureHandle: async (input) =>
        signerSession.clientShare.kind === 'role_local_worker_share'
          ? await thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm(input)
          : await computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle(input),
    },
    cleanupAfterSign: async (cleanupArgs) => {
      if (
        emailOtpWorkerShareSessionId &&
        (cleanupArgs.singleUseEmailOtpSession || emailOtpWorkerShareExhausted)
      ) {
        await clearEmailOtpWorkerSessionBestEffort({
          workerCtx: args.workerCtx,
          sessionId: emailOtpWorkerShareSessionId,
        });
      }
    },
  };
}
