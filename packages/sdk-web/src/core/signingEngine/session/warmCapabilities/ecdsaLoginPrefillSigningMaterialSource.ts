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
import {
  markResolvedEcdsaRoleLocalMaterialRuntimeValidated,
  type RouterAbEcdsaDerivationSigningWalletSession,
} from '../routerAbSigningWalletSession';
import { buildRouterAbEcdsaDerivationSigningMaterialRef } from '../../routerAb/ecdsaDerivation/signingMaterialRef';
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

/** The signing session the runtime-validation fence is keyed by, built from the
 * exact sealed runtime and the active authorization rather than parsed out of a
 * composite record. Mirrors how the signing path composes the same session from
 * already-resolved facts. */
function loginPrefillSigningWalletSession(args: {
  runtime: ExactEcdsaSealedRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): RouterAbEcdsaDerivationSigningWalletSession {
  const runtimePolicyScope = args.runtime.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('ECDSA login prefill requires a sealed runtime policy scope');
  }
  const walletSessionJwt = args.authorization.walletSessionJwt;
  return {
    curve: 'ecdsa',
    auth: {
      kind: 'wallet_session_jwt',
      walletSessionJwt,
      credential: { kind: 'jwt', walletSessionJwt },
    },
    thresholdSessionId: args.runtime.sealedRecord.thresholdSessionId,
    remainingUses: args.runtime.remainingUses,
    expiresAtMs: args.runtime.expiresAtMs,
    signingMaterial: buildRouterAbEcdsaDerivationSigningMaterialRef({
      routerAbState: args.runtime.normalSigning,
    }),
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: args.runtime.normalSigning,
  };
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
      if (
        !markResolvedEcdsaRoleLocalMaterialRuntimeValidated({
          material: resolvedMaterial,
          session: loginPrefillSigningWalletSession(args),
          keyHandle: args.runtime.keyHandle,
          chainTarget: args.runtime.chainTarget,
          participantIds: args.runtime.participantIds,
        })
      ) {
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
