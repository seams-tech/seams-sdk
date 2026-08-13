import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import type {
  HydratedEcdsaSignerMaterial,
  ThresholdEcdsaRoleLocalWorkerShare,
} from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  storeEcdsaRoleLocalSigningMaterialWasm,
  thresholdEcdsaRoleLocalAdmitPresignatureWasm,
  thresholdEcdsaRoleLocalDestroyPresignatureWasm,
  thresholdEcdsaRoleLocalReservePresignatureWasm,
  thresholdEcdsaRoleLocalCommitPresignatureWasm,
  thresholdEcdsaRoleLocalListAvailablePresignaturesWasm,
  thresholdEcdsaRoleLocalRetirePresignaturePoolWasm,
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
} from '../../../threshold/crypto/ecdsaDerivationClientWasm';
import type { RouterAbEcdsaDerivationClientSigningMaterialSource } from '../../../routerAb/ecdsaDerivation/presignaturePool';

export type LoadedRouterAbEcdsaDerivationSigningMaterialSource = {
  signerSession: HydratedEcdsaSignerMaterial;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  cleanupAfterSign: (args: { singleUseEmailOtpSession: boolean }) => Promise<void>;
};

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
  signerSession: HydratedEcdsaSignerMaterial;
  workerCtx: WorkerOperationContext;
}): Promise<LoadedRouterAbEcdsaDerivationSigningMaterialSource> {
  const signerSession = args.signerSession;

  return {
    signerSession,
    clientSigningMaterial: {
      kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
      initClientPresignSession: async (input) => {
        await ensureRoleLocalSigningMaterialLoaded({
          workerCtx: args.workerCtx,
          clientShare: signerSession.clientShare,
        });
        return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
          materialHandle: signerSession.clientShare.handle.materialHandle,
          material:
            signerSession.clientShare.material.kind === 'worker_loaded'
              ? {
                  kind: 'persisted',
                  materialRef: signerSession.clientShare.material.materialRef,
                }
              : {
                  kind: 'runtime_loaded',
                  expectedBindingDigest: signerSession.clientShare.handle.bindingDigest,
                },
          ...input,
        });
      },
      stepClientPresignSession: thresholdEcdsaRoleLocalPresignSessionStepWasm,
      abortClientPresignSession: thresholdEcdsaRoleLocalPresignSessionAbortWasm,
      admitClientPresignature: thresholdEcdsaRoleLocalAdmitPresignatureWasm,
      destroyClientPresignature: thresholdEcdsaRoleLocalDestroyPresignatureWasm,
      reserveClientPresignature: thresholdEcdsaRoleLocalReservePresignatureWasm,
      commitClientPresignature: thresholdEcdsaRoleLocalCommitPresignatureWasm,
      listAvailableClientPresignatures: thresholdEcdsaRoleLocalListAvailablePresignaturesWasm,
      retireClientPresignaturePool: thresholdEcdsaRoleLocalRetirePresignaturePoolWasm,
      computeSignatureShareFromPresignatureHandle:
        thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
    },
    cleanupAfterSign: async () => undefined,
  };
}
