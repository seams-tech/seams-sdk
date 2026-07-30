import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import {
  SIGNER_AUTH_METHODS,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
import {
  resolveAccountAuthMetadataForSignerAuthMethod,
  type AccountAuthMetadata,
} from '../../interfaces/accountAuthMetadata';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';

export type EvmFamilyAccountMetadataDeps = {
  walletSignerStore: EvmFamilyWalletSignerStorePort;
};

export type EvmFamilyWalletSignerStorePort = {
  getActiveWalletSignerForChainTarget: (args: {
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }) => Promise<AccountSignerRecord | null>;
  listActiveWalletSigners: (args: {
    walletId: string;
    signerFamily: 'ecdsa';
  }) => Promise<AccountSignerRecord[]>;
};

export async function resolveEvmFamilyTransactionWalletAuth(args: {
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
  signerAuthMethod?: SignerAuthMethod;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: SIGNER_AUTH_METHODS.passkey,
    });
  }

  if (args.signerAuthMethod !== undefined) {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: args.signerAuthMethod,
    });
  }

  throw new Error('[SigningEngine][ecdsa] signer auth method is unavailable');
}
