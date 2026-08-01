import type { KeyMaterialRecord } from '../../../packages/sdk-web/src/core/indexedDB/keyMaterial.types';

export function buildActiveClientKeyMaterialRecord(source: KeyMaterialRecord): KeyMaterialRecord {
  const envelope = source.payloadEnvelope;
  if (!envelope) throw new Error('recovery source fixture requires a payload envelope');

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
    payload: source.payload,
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
