import { alphabetizeStringify } from '@shared/utils/digests';
import type { ThresholdEcdsaRoleLocalWorkerShareHandle } from '../../interfaces/signing';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { ReadyEcdsaSignerSession } from './evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaKeyHandle,
  type EcdsaRelayerKeyId,
  type EcdsaThresholdKeyId,
} from '../keyMaterialBrands';

export type BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: EcdsaKeyHandle;
  routerAbStateSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};

export function buildEcdsaRoleLocalSigningMaterialHandle(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): ThresholdEcdsaRoleLocalWorkerShareHandle {
  const thresholdSessionId = String(input.thresholdSessionId || '').trim();
  const signingGrantId = String(input.signingGrantId || '').trim();
  const keyHandle = parseEcdsaKeyHandle(input.keyHandle);
  const routerAbStateSessionId = String(input.routerAbStateSessionId || '').trim();
  if (!thresholdSessionId || !signingGrantId || !keyHandle || !routerAbStateSessionId) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material handle identity is incomplete');
  }
  const bindingDigest = alphabetizeStringify({
    kind: 'router_ab_ecdsa_role_local_signing_material_binding_v1',
    chainTarget: input.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
      input.clientVerifyingShareB64u,
    ),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    keyHandle,
    participantIds: input.participantIds.map((participantId) => Number(participantId)),
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
    routerAbStateSessionId,
    thresholdSessionId,
    signingGrantId,
  });
  return {
    kind: 'role_local_worker_session',
    materialHandle: `router-ab-ecdsa-role-local:${thresholdSessionId}:${keyHandle}:${routerAbStateSessionId}`,
    bindingDigest,
  };
}

export function ecdsaRoleLocalSigningMaterialHandleFromReadySignerSession(
  signerSession: ReadyEcdsaSignerSession,
): ThresholdEcdsaRoleLocalWorkerShareHandle {
  return buildEcdsaRoleLocalSigningMaterialHandle({
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    signingGrantId: String(signerSession.session.signingGrantId),
    keyHandle: parseEcdsaKeyHandle(signerSession.publicFacts.keyHandle),
    routerAbStateSessionId: String(
      signerSession.routerAbEcdsaHssNormalSigning.walletSessionSessionId,
    ),
    chainTarget: signerSession.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
      signerSession.transport.signingMaterial.clientVerifier33B64u,
    ),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
      signerSession.transport.signingMaterial.ecdsaThresholdKeyId,
    ),
    participantIds: signerSession.publicFacts.participantIds.map((participantId) =>
      Number(participantId),
    ),
    relayerKeyId: parseEcdsaRelayerKeyId(signerSession.transport.relayerKeyId),
  });
}
