import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { sha256 } from '@noble/hashes/sha2.js';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { ReadyEcdsaSignerSession } from './evmFamilyEcdsaIdentity';
import {
  SigningSessionIds,
  type SigningGrantId,
  type ThresholdEcdsaSessionId,
} from '../operationState/types';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaKeyHandle,
  type EcdsaRelayerKeyId,
  type EcdsaRoleLocalWorkerHandle,
  type EcdsaThresholdKeyId,
} from '../keyMaterialBrands';
import { parseEcdsaActiveStateId, type EcdsaActiveStateId } from '@shared/utils/domainIds';

export type BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: EcdsaKeyHandle;
  activeStateId: EcdsaActiveStateId;
  chainTarget: ThresholdEcdsaChainTarget;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};

type EcdsaRoleLocalMaterialBinding = {
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly signingGrantId: SigningGrantId;
  readonly keyHandle: EcdsaKeyHandle;
  readonly activeStateId: EcdsaActiveStateId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly participantIds: readonly number[];
  readonly relayerKeyId: EcdsaRelayerKeyId;
};

function requireEcdsaActiveStateId(value: unknown): EcdsaActiveStateId {
  const parsed = parseEcdsaActiveStateId(value);
  if (!parsed.ok) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material requires activeStateId');
  }
  return parsed.value;
}

function normalizeEcdsaRoleLocalMaterialBinding(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): EcdsaRoleLocalMaterialBinding {
  return {
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
    signingGrantId: SigningSessionIds.signingGrant(input.signingGrantId),
    keyHandle: parseEcdsaKeyHandle(input.keyHandle),
    activeStateId: requireEcdsaActiveStateId(input.activeStateId),
    chainTarget: input.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(input.clientVerifyingShareB64u),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    participantIds: input.participantIds.map((participantId) => Number(participantId)),
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
  };
}

function buildEcdsaRoleLocalSigningMaterialHandleFromBinding(
  binding: EcdsaRoleLocalMaterialBinding,
): EcdsaRoleLocalWorkerHandle {
  const activeStateId = requireEcdsaActiveStateId(binding.activeStateId);
  const bindingDigest = parseEcdsaRoleLocalBindingDigest(
    alphabetizeStringify({
      kind: 'router_ab_ecdsa_role_local_signing_material_binding_v1',
      chainTarget: binding.chainTarget,
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
        binding.clientVerifyingShareB64u,
      ),
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(binding.ecdsaThresholdKeyId),
      keyHandle: parseEcdsaKeyHandle(binding.keyHandle),
      participantIds: binding.participantIds.map((participantId) => Number(participantId)),
      relayerKeyId: parseEcdsaRelayerKeyId(binding.relayerKeyId),
      activeStateId,
      signingGrantId: SigningSessionIds.signingGrant(binding.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(binding.thresholdSessionId),
    }),
  );
  const bindingDigestHashB64u = base64UrlEncode(sha256(new TextEncoder().encode(bindingDigest)));
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(
    `router-ab-ecdsa-role-local:${binding.thresholdSessionId}:${binding.keyHandle}:${activeStateId}:${bindingDigestHashB64u}`,
  );
  return {
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle,
    bindingDigest,
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(materialHandle),
  };
}

export function buildEcdsaRoleLocalSigningMaterialHandle(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): EcdsaRoleLocalWorkerHandle {
  return buildEcdsaRoleLocalSigningMaterialHandleFromBinding(
    normalizeEcdsaRoleLocalMaterialBinding(input),
  );
}

export function ecdsaRoleLocalSigningMaterialHandleFromReadySignerSession(
  signerSession: ReadyEcdsaSignerSession,
): EcdsaRoleLocalWorkerHandle {
  return buildEcdsaRoleLocalSigningMaterialHandle({
    thresholdSessionId: String(signerSession.session.thresholdSessionId),
    signingGrantId: String(signerSession.session.signingGrantId),
    keyHandle: parseEcdsaKeyHandle(signerSession.publicFacts.keyHandle),
    activeStateId: signerSession.routerAbEcdsaDerivationNormalSigning.activeStateId,
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
