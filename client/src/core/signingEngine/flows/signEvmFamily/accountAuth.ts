import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  resolveAccountAuthMetadataForSignerSource,
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

function signerSourceFromAuthMethod(value: unknown): string {
  if (value === SIGNER_AUTH_METHODS.emailOtp) return SIGNER_AUTH_METHODS.emailOtp;
  if (value === SIGNER_AUTH_METHODS.passkey) return SIGNER_AUTH_METHODS.passkey;
  return '';
}

export async function resolveEvmFamilyTransactionWalletAuth(args: {
  deps: EvmFamilyAccountMetadataDeps;
  walletId: string;
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
  chainTarget?: ThresholdEcdsaChainTarget;
  sessionSource?: string;
  isEmailOtpThresholdContext?: boolean;
}): Promise<AccountAuthMetadata> {
  if (args.senderSignatureAlgorithm === 'webauthnP256') {
    return resolveAccountAuthMetadataForSignerSource();
  }

  const walletId = toWalletId(args.walletId);
  const exactSigner = args.chainTarget
    ? await args.deps.walletSignerStore
        .getActiveWalletSignerForChainTarget({
          walletId,
          chainTarget: args.chainTarget,
        })
    : null;
  const exactSignerAuthMethod = signerSourceFromAuthMethod(exactSigner?.signerAuthMethod);
  if (exactSignerAuthMethod) {
    return resolveAccountAuthMetadataForSignerSource({
      source: exactSignerAuthMethod,
    });
  }

  if (!args.chainTarget) {
    const activeSigners = await args.deps.walletSignerStore
      .listActiveWalletSigners({ walletId, signerFamily: 'ecdsa' })
      .catch(() => []);
    const sources = new Set(
      activeSigners
        .map((signer) => signerSourceFromAuthMethod(signer.signerAuthMethod))
        .filter(Boolean),
    );
    if (sources.size === 1) {
      return resolveAccountAuthMetadataForSignerSource({
        source: [...sources][0],
      });
    }
  }

  if (args.isEmailOtpThresholdContext === true) {
    return resolveAccountAuthMetadataForSignerSource({
      source: SIGNER_AUTH_METHODS.emailOtp,
    });
  }

  return resolveAccountAuthMetadataForSignerSource({
    source: args.sessionSource,
  });
}
