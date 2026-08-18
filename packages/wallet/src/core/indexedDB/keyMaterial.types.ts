export type KeyMaterialAlgorithm = 'ed25519' | 'secp256k1' | 'webauthn-p256' | string;

export type KeyMaterialKind = 'threshold_share_v1' | string;

export interface KeyMaterialPayloadEnvelopeAAD {
  profileId: string;
  signerSlot: number;
  chainIdKey: string;
  keyKind: string;
  schemaVersion: number;
  signerId: string;
  accountAddress: string;
}

export interface KeyMaterialPayloadEnvelope {
  encVersion: number;
  alg: string;
  nonce: string;
  ciphertext: string;
  tag?: string;
  aad: KeyMaterialPayloadEnvelopeAAD;
}

export interface KeyMaterialRecord {
  profileId: string;
  signerSlot: number;
  chainIdKey: string;
  accountAddress: string;
  keyKind: KeyMaterialKind;
  algorithm: KeyMaterialAlgorithm;
  publicKey: string;
  signerId: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  payloadEnvelope?: KeyMaterialPayloadEnvelope;
  timestamp: number;
  schemaVersion: number;
}
