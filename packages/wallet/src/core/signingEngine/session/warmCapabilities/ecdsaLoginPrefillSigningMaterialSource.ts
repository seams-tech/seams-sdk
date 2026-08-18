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
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
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

export function createEcdsaLoginPrefillClientSigningMaterialSource(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): RouterAbEcdsaDerivationClientSigningMaterialSource {
  return {
    kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
    initClientPresignSession: async (input) => {
      const resolution = await resolveEcdsaRoleLocalMaterial({
        purpose: 'wallet_unlock',
        // Material identity is the manifest's half of the split: authority,
        // activation and public facts all come from the selected capability.
        source: ecdsaRoleLocalPersistedMaterialSource({
          authority: args.manifest.signer.authority,
          materialActivation: args.manifest.durableMaterial.materialActivation,
          publicFacts: args.manifest.durableMaterial.roleLocalPublicFacts,
        }),
        workerCtx: input.workerCtx,
      });
      const resolvedMaterial = requireResolvedLoginPrefillMaterial(resolution);
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
