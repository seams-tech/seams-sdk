import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import { updateExactSealedSessionPolicy } from '../../../session/persistence/sealedSessionStore';
import type {
  ReadyEcdsaSignerSession,
  ThresholdEcdsaRoleLocalWorkerShare,
} from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  storeEcdsaRoleLocalSigningMaterialWasm,
  thresholdEcdsaRoleLocalAdmitPresignatureWasm,
  thresholdEcdsaRoleLocalDestroyPresignatureWasm,
  thresholdEcdsaRoleLocalReservePresignatureWasm,
  thresholdEcdsaRoleLocalCommitPresignatureWasm,
  thresholdEcdsaEmailOtpPresignSessionInitWasm,
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
} from '../../../threshold/crypto/ecdsaDerivationClientWasm';
import type { RouterAbEcdsaDerivationClientSigningMaterialSource } from '../../../routerAb/ecdsaDerivation/presignaturePool';

type EcdsaSessionChain = 'tempo' | 'evm';

export type SignableReadyEcdsaSignerSession = ReadyEcdsaSignerSession & {
  clientShare: ReadyEcdsaSignerSession['clientShare'];
};

export type LoadedRouterAbEcdsaDerivationSigningMaterialSource = {
  signerSession: SignableReadyEcdsaSignerSession;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  cleanupAfterSign: (args: { singleUseEmailOtpSession: boolean }) => Promise<void>;
};

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

async function ensureRoleLocalSigningMaterialLoaded(args: {
  workerCtx: WorkerOperationContext;
  clientShare: ThresholdEcdsaRoleLocalWorkerShare;
}): Promise<void> {
  const material = args.clientShare.material;
  if (material.kind === 'worker_loaded') return;
  const stored = await storeEcdsaRoleLocalSigningMaterialWasm({
    materialHandle: args.clientShare.handle.materialHandle,
    bindingDigest: args.clientShare.handle.bindingDigest,
    stateBlob: material.stateBlob,
    workerCtx: args.workerCtx,
  });
  if (
    stored.materialHandle !== args.clientShare.handle.materialHandle ||
    stored.bindingDigest !== args.clientShare.handle.bindingDigest
  ) {
    throw new Error('[multichain] ECDSA role-local worker material handle mismatch');
  }
}

export async function loadRouterAbEcdsaDerivationSigningMaterialSource(args: {
  signerSession: ReadyEcdsaSignerSession;
  workerCtx: WorkerOperationContext;
}): Promise<LoadedRouterAbEcdsaDerivationSigningMaterialSource> {
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
      kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
      initClientPresignSession: async (input) => {
        if (signerSession.clientShare.kind === 'email_otp_worker_share') {
          if (!emailOtpWorkerShareChain) {
            throw new Error(
              '[multichain] Missing Email OTP ECDSA chain for signing-session policy update',
            );
          }
          const initialized = await thresholdEcdsaEmailOtpPresignSessionInitWasm({
            emailOtpSessionId: signerSession.clientShare.handle.sessionId,
            ...input,
          });
          emailOtpWorkerShareExhausted =
            initialized.remainingUses <= 0 || initialized.expiresAtMs <= Date.now();
          await updateEmailOtpSealedRecordPolicyAfterEcdsaClaim({
            thresholdSessionId: String(signerSession.session.thresholdSessionId),
            chainTarget: signerSession.clientShare.handle.laneIdentity.chainTarget,
            remainingUses: initialized.remainingUses,
            expiresAtMs: initialized.expiresAtMs,
          });
          return initialized.progress;
        }
        await ensureRoleLocalSigningMaterialLoaded({
          workerCtx: args.workerCtx,
          clientShare: signerSession.clientShare,
        });
        return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
          materialHandle: signerSession.clientShare.handle.materialHandle,
          expectedBindingDigest: signerSession.clientShare.handle.bindingDigest,
          ...input,
        });
      },
      stepClientPresignSession: thresholdEcdsaRoleLocalPresignSessionStepWasm,
      abortClientPresignSession: thresholdEcdsaRoleLocalPresignSessionAbortWasm,
      admitClientPresignature: thresholdEcdsaRoleLocalAdmitPresignatureWasm,
      destroyClientPresignature: thresholdEcdsaRoleLocalDestroyPresignatureWasm,
      reserveClientPresignature: thresholdEcdsaRoleLocalReservePresignatureWasm,
      commitClientPresignature: thresholdEcdsaRoleLocalCommitPresignatureWasm,
      computeSignatureShareFromPresignatureHandle:
        thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
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
