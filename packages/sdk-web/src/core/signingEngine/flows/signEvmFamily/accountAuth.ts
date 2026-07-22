import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import {
  SIGNER_AUTH_METHODS,
  type SignerAuthMethod,
} from '@shared/utils/signerDomain';
import {
  resolveAccountAuthMetadataForSignerAuthMethod,
  signerAuthMethodFromUnknown,
  type AccountAuthMetadata,
} from '../../interfaces/accountAuthMetadata';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../interfaces/ecdsaChainTarget';

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
  deps: EvmFamilyAccountMetadataDeps;
  walletId: string;
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
  chainTarget?: ThresholdEcdsaChainTarget;
  sessionAuthMethod?: SignerAuthMethod;
  isEmailOtpThresholdContext?: boolean;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: SIGNER_AUTH_METHODS.passkey,
    });
  }

  const walletId = toWalletId(args.walletId);
  const exactSigner = args.chainTarget
    ? await args.deps.walletSignerStore
        .getActiveWalletSignerForChainTarget({
          walletId,
          chainTarget: args.chainTarget,
        })
    : null;
  const exactSignerAuthMethod = signerAuthMethodFromUnknown(exactSigner?.signerAuthMethod);
  if (exactSignerAuthMethod !== null) {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: exactSignerAuthMethod,
    });
  }

  if (!args.chainTarget) {
    const activeSigners = await args.deps.walletSignerStore
      .listActiveWalletSigners({ walletId, signerFamily: 'ecdsa' })
      .catch(() => []);
    const authMethods = new Set<SignerAuthMethod>(
      activeSigners
        .map((signer) => signerAuthMethodFromUnknown(signer.signerAuthMethod))
        .filter((authMethod): authMethod is SignerAuthMethod => authMethod !== null),
    );
    if (authMethods.size === 1) {
      return resolveAccountAuthMetadataForSignerAuthMethod({
        authMethod: [...authMethods][0],
      });
    }
  }

  if (args.isEmailOtpThresholdContext === true) {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    });
  }

  if (args.sessionAuthMethod !== undefined) {
    return resolveAccountAuthMetadataForSignerAuthMethod({
      authMethod: args.sessionAuthMethod,
    });
  }

  throw new Error('[SigningEngine][ecdsa] signer auth method is unavailable');
}
