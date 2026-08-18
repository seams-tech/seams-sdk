import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingPublicKey33B64u,
  type EcdsaKeyHandle,
  type EcdsaRelayerKeyId,
  type EcdsaRoleLocalWorkerHandle,
  type EcdsaThresholdKeyId,
} from '../keyMaterialBrands';

export type BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  keyHandle: EcdsaKeyHandle;
  clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly [number, ...number[]];
  relayerKeyId: EcdsaRelayerKeyId;
  evmFamilySigningKeySlotId?: never;
  chainTarget?: never;
  walletId?: never;
  thresholdSessionId?: never;
  activeStateId?: never;
  capabilityGrantId?: never;
  mpcWalletSigningQuotaId?: never;
  remainingUses?: never;
  expiresAtMs?: never;
};

type EcdsaRoleLocalMaterialBinding = {
  readonly keyHandle: EcdsaKeyHandle;
  readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly participantIds: readonly [number, ...number[]];
  readonly relayerKeyId: EcdsaRelayerKeyId;
};

function parseEcdsaParticipantIds(
  value: readonly [number, ...number[]],
): readonly [number, ...number[]] {
  if (!value.length) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material requires participantIds');
  }
  const participantIds = [...new Set(value.map((participantId) => Number(participantId)))].sort(
    (left, right) => left - right,
  );
  if (
    participantIds.length !== value.length ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId < 1,
    )
  ) {
    throw new Error(
      '[evm-family-ecdsa] ECDSA role-local material participantIds must be unique positive integers',
    );
  }
  const [firstParticipantId, ...remainingParticipantIds] = participantIds;
  if (firstParticipantId === undefined) {
    throw new Error('[evm-family-ecdsa] ECDSA role-local material requires participantIds');
  }
  return [firstParticipantId, ...remainingParticipantIds];
}

function normalizeEcdsaRoleLocalMaterialBinding(
  input: BuildEcdsaRoleLocalSigningMaterialHandleInput,
): EcdsaRoleLocalMaterialBinding {
  return {
    keyHandle: parseEcdsaKeyHandle(input.keyHandle),
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      input.clientVerifyingPublicKey33B64u,
    ),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId),
    participantIds: parseEcdsaParticipantIds(input.participantIds),
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
  };
}

function buildEcdsaRoleLocalSigningMaterialHandleFromBinding(
  binding: EcdsaRoleLocalMaterialBinding,
): EcdsaRoleLocalWorkerHandle {
  const bindingDigest = parseEcdsaRoleLocalBindingDigest(
    alphabetizeStringify({
      kind: 'router_ab_ecdsa_role_local_signing_material_binding_v2',
      clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
        binding.clientVerifyingPublicKey33B64u,
      ),
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(binding.ecdsaThresholdKeyId),
      keyHandle: parseEcdsaKeyHandle(binding.keyHandle),
      participantIds: binding.participantIds.map((participantId) => Number(participantId)),
      relayerKeyId: parseEcdsaRelayerKeyId(binding.relayerKeyId),
    }),
  );
  const bindingDigestHashB64u = base64UrlEncode(sha256(new TextEncoder().encode(bindingDigest)));
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(
    `router-ab-ecdsa-role-local:${binding.keyHandle}:${binding.ecdsaThresholdKeyId}:${bindingDigestHashB64u}`,
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
