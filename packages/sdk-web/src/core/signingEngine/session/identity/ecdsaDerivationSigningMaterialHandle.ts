import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { sha256 } from '@noble/hashes/sha2.js';
import type { ThresholdEcdsaRoleLocalWorkerShareHandle } from '../../interfaces/signing';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { ReadyEcdsaSignerSession } from './evmFamilyEcdsaIdentity';
import { SigningSessionIds, type SigningGrantId, type ThresholdEcdsaSessionId } from '../operationState/types';
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
  type EcdsaRoleLocalBindingDigest,
  type EcdsaRoleLocalMaterialHandle,
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

export type EcdsaRoleLocalMaterialBinding = {
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly signingGrantId: SigningGrantId;
  readonly keyHandle: EcdsaKeyHandle;
  readonly routerAbStateSessionId: string;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly participantIds: readonly number[];
  readonly relayerKeyId: EcdsaRelayerKeyId;
};

export type EcdsaRoleLocalMaterialIdentity = {
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
  readonly materialHandle: EcdsaRoleLocalMaterialHandle;
};

function requireRouterAbStateSessionId(value: unknown): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material requires routerAbStateSessionId');
  }
  return normalized;
}

function normalizeEcdsaRoleLocalMaterialBinding(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): EcdsaRoleLocalMaterialBinding {
  return {
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(input.thresholdSessionId),
    signingGrantId: SigningSessionIds.signingGrant(input.signingGrantId),
    keyHandle: parseEcdsaKeyHandle(input.keyHandle),
    routerAbStateSessionId: requireRouterAbStateSessionId(input.routerAbStateSessionId),
    chainTarget: input.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
      input.clientVerifyingShareB64u,
    ),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    participantIds: input.participantIds.map((participantId) => Number(participantId)),
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
  };
}

export function buildEcdsaRoleLocalMaterialIdentity(
  binding: EcdsaRoleLocalMaterialBinding,
): EcdsaRoleLocalMaterialIdentity {
  const routerAbStateSessionId = requireRouterAbStateSessionId(binding.routerAbStateSessionId);
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
      routerAbStateSessionId,
      signingGrantId: SigningSessionIds.signingGrant(binding.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(binding.thresholdSessionId),
    }),
  );
  const bindingDigestHashB64u = base64UrlEncode(
    sha256(new TextEncoder().encode(bindingDigest)),
  );
  return {
    bindingDigest,
    materialHandle: parseEcdsaRoleLocalMaterialHandle(
      `router-ab-ecdsa-role-local:${binding.thresholdSessionId}:${binding.keyHandle}:${routerAbStateSessionId}:${bindingDigestHashB64u}`,
    ),
  };
}

export function buildEcdsaRoleLocalSigningMaterialHandle(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): ThresholdEcdsaRoleLocalWorkerShareHandle {
  const identity = buildEcdsaRoleLocalMaterialIdentity(
    normalizeEcdsaRoleLocalMaterialBinding(input),
  );
  return {
    kind: 'role_local_worker_session',
    materialHandle: identity.materialHandle,
    bindingDigest: identity.bindingDigest,
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(identity.materialHandle),
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
      signerSession.routerAbEcdsaDerivationNormalSigning.walletSessionSessionId,
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
