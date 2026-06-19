import { alphabetizeStringify } from '@shared/utils/digests';
import type { ThresholdEcdsaRoleLocalWorkerShareHandle } from '../../interfaces/signing';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { ReadyEcdsaSignerSession } from './evmFamilyEcdsaIdentity';

export type BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  keyHandle: string;
  routerAbStateSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  clientVerifyingShareB64u: string;
  ecdsaThresholdKeyId: string;
  participantIds: readonly number[];
  relayerKeyId: string;
};

export function buildEcdsaRoleLocalSigningMaterialHandle(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): ThresholdEcdsaRoleLocalWorkerShareHandle {
  const thresholdSessionId = String(input.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(input.walletSigningSessionId || '').trim();
  const keyHandle = String(input.keyHandle || '').trim();
  const routerAbStateSessionId = String(input.routerAbStateSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId || !keyHandle || !routerAbStateSessionId) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material handle identity is incomplete');
  }
  const bindingDigest = alphabetizeStringify({
    kind: 'router_ab_ecdsa_role_local_signing_material_binding_v1',
    chainTarget: input.chainTarget,
    clientVerifyingShareB64u: String(input.clientVerifyingShareB64u || '').trim(),
    ecdsaThresholdKeyId: String(input.ecdsaThresholdKeyId || '').trim(),
    keyHandle,
    participantIds: input.participantIds.map((participantId) => Number(participantId)),
    relayerKeyId: String(input.relayerKeyId || '').trim(),
    routerAbStateSessionId,
    thresholdSessionId,
    walletSigningSessionId,
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
    walletSigningSessionId: String(signerSession.session.walletSigningSessionId),
    keyHandle: String(signerSession.publicFacts.keyHandle),
    routerAbStateSessionId: String(
      signerSession.routerAbEcdsaHssNormalSigning.walletSessionSessionId,
    ),
    chainTarget: signerSession.chainTarget,
    clientVerifyingShareB64u: signerSession.transport.clientVerifyingShareB64u,
    ecdsaThresholdKeyId: String(signerSession.transport.ecdsaThresholdKeyId),
    participantIds: signerSession.publicFacts.participantIds.map((participantId) =>
      Number(participantId),
    ),
    relayerKeyId: signerSession.transport.relayerKeyId,
  });
}
