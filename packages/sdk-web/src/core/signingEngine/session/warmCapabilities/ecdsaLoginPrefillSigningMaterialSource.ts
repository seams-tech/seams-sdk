import {
  requirePersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import {
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
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import type { RouterAbEcdsaDerivationClientSigningMaterialSource } from '../../routerAb/ecdsaDerivation/presignaturePool';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
} from '../material/ecdsaRoleLocalMaterialResolver';

function requireResolvedLoginPrefillMaterial(
  resolution: EcdsaRoleLocalMaterialResolution,
): Extract<EcdsaRoleLocalMaterialResolution, { kind: 'rehydrated' }> {
  switch (resolution.kind) {
    case 'rehydrated':
      return resolution;
    case 'device_link_required':
      throw new Error('ECDSA login prefill requires local role-local material');
    case 'corrupt':
      throw new Error(
        `ECDSA login prefill role-local material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA login prefill material state: ${String(exhaustive)}`);
    }
  }
}

export function createEcdsaLoginPrefillClientSigningMaterialSource(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaDerivationClientSigningMaterialSource {
  return {
    kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
    initClientPresignSession: async (input) => {
      const persistedMaterial = requirePersistedEcdsaRoleLocalMaterial(record);
      const resolution = await resolveEcdsaRoleLocalMaterial({
        purpose: 'wallet_unlock',
        source: ecdsaRoleLocalPersistedMaterialSource(persistedMaterial),
        workerCtx: input.workerCtx,
      });
      const resolvedMaterial = requireResolvedLoginPrefillMaterial(resolution);
      if (!markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
        throw new Error('ECDSA login prefill could not validate runtime role-local material');
      }
      return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
        materialHandle: resolvedMaterial.liveHandle.materialHandle,
        material: {
          kind: 'persisted',
          materialRef: resolvedMaterial.materialRef,
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
  };
}
