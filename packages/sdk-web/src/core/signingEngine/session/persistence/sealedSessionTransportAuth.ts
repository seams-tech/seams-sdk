import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';

export type WalletSessionJwtAuthSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdSessionSealTransportAuthMaterial =
  | {
      curve: 'ed25519';
      walletId?: string;
      relayerUrl: string;
      signingGrantId?: string;
      walletSessionJwt?: string;
      walletSessionJwtSource: WalletSessionJwtAuthSource;
      signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
      groupId?: string;
    }
  | {
      curve: 'ecdsa';
      walletId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      relayerUrl: string;
      signingGrantId?: string;
      walletSessionJwt?: string;
      walletSessionJwtSource: WalletSessionJwtAuthSource;
      signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
      groupId?: string;
    };
