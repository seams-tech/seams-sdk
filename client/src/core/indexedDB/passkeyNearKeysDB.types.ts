import { type ThresholdEd25519ParticipantV1 } from '@shared/threshold/participants';

export type ClientShareDerivation = 'prf_first_v1';

export type PasskeyNearKeyMaterialKind = 'threshold_ed25519_v1';

export interface BasePasskeyNearKeyMaterial {
  nearAccountId: string;
  deviceNumber: number; // 1-indexed device number
  kind: PasskeyNearKeyMaterialKind;
  /** NEAR ed25519 public key (e.g. `ed25519:...`) */
  publicKey: string;
  timestamp: number;
}

export interface ThresholdEd25519_V1Material extends BasePasskeyNearKeyMaterial {
  kind: 'threshold_ed25519_v1';
  relayerKeyId: string;
  keyVersion: string;
  /**
   * Versioned participant list for future n-party support.
   * In 2P, participants are `{id:1, role:'client'}` and `{id:2, role:'relayer', ...}`.
   */
  participants: ThresholdEd25519ParticipantV1[];
}

export type PasskeyNearKeyMaterial = ThresholdEd25519_V1Material;

export type PasskeyChainIdKeyAlgorithm = 'ed25519' | 'secp256k1' | 'webauthn-p256' | string;

export type PasskeyChainIdKeyKind = 'threshold_share_v1' | string;

export interface PasskeyChainIdKeyPayloadEnvelopeAAD {
  profileId: string;
  deviceNumber: number;
  chainIdKey: string;
  keyKind: string;
  schemaVersion: number;
  signerId?: string;
  accountAddress?: string;
}

export interface PasskeyChainIdKeyPayloadEnvelope {
  encVersion: number;
  alg: string;
  nonce: string;
  ciphertext: string;
  tag?: string;
  aad: PasskeyChainIdKeyPayloadEnvelopeAAD;
}

export interface PasskeyChainIdKeyMaterial {
  profileId: string;
  deviceNumber: number;
  chainIdKey: string;
  keyKind: PasskeyChainIdKeyKind;
  algorithm: PasskeyChainIdKeyAlgorithm;
  publicKey: string;
  signerId?: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  payloadEnvelope?: PasskeyChainIdKeyPayloadEnvelope;
  timestamp: number;
  schemaVersion: number;
}
