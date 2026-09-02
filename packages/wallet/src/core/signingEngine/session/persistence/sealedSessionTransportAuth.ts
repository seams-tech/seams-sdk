import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';

export type EcdsaSealTransportAuthMaterial = {
  curve: 'ecdsa';
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  walletSessionToken?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
};
