import type { KeyMaterialRecord } from '../../../packages/wallet/src/core/indexedDB/keyMaterial.types';
import type { RouterAbMpcMaterialActivationRefWire } from '../../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';

function requireFixtureRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is unavailable`);
  }
  return value as Record<string, unknown>;
}

export function buildActiveClientKeyMaterialRecord(
  source: KeyMaterialRecord,
  materialActivation: RouterAbMpcMaterialActivationRefWire,
): KeyMaterialRecord {
  const envelope = source.payloadEnvelope;
  if (!envelope) throw new Error('recovery source fixture requires a payload envelope');
  const sourceBinding = requireFixtureRecord(
    source.payload?.binding,
    'recovery source fixture binding',
  );

  return {
    profileId: source.profileId,
    signerSlot: source.signerSlot,
    chainIdKey: source.chainIdKey,
    accountAddress: source.accountAddress,
    keyKind: 'router_ab_ed25519_yao_active_client_v1',
    algorithm: source.algorithm,
    publicKey: source.publicKey,
    signerId: source.signerId,
    wrapKeySalt: source.wrapKeySalt,
    payload: {
      ...source.payload,
      binding: {
        ...sourceBinding,
        materialActivation: {
          kind: materialActivation.kind,
          activationId: materialActivation.activation_id,
          capability: materialActivation.capability,
          materialOwner: materialActivation.material_owner,
          keyBinding: materialActivation.key_binding,
          lifecycleBinding: materialActivation.lifecycle_binding,
          signingWorker: materialActivation.signing_worker,
        },
      },
    },
    payloadEnvelope: {
      encVersion: envelope.encVersion,
      alg: envelope.alg,
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
      tag: envelope.tag,
      aad: {
        profileId: envelope.aad.profileId,
        signerSlot: envelope.aad.signerSlot,
        chainIdKey: envelope.aad.chainIdKey,
        keyKind: 'router_ab_ed25519_yao_active_client_v1',
        schemaVersion: envelope.aad.schemaVersion,
        signerId: envelope.aad.signerId,
        accountAddress: envelope.aad.accountAddress,
      },
    },
    timestamp: source.timestamp,
    schemaVersion: source.schemaVersion,
  };
}
