import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { resolveEvmFamilyTransactionWalletAuth } from '@/core/signingEngine/flows/signEvmFamily/accountAuth';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});

test.describe('EVM-family account auth resolution', () => {
  test('uses exact wallet signer auth method for concrete ECDSA chain target', async () => {
    const auth = await resolveEvmFamilyTransactionWalletAuth({
      deps: {
        walletSignerStore: {
          getActiveWalletSignerForChainTarget: async () => ({
            signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
          }),
          listActiveWalletSigners: async () => [],
        } as never,
      },
      walletId: 'wallet-1',
      senderSignatureAlgorithm: 'secp256k1',
      chainTarget,
    });

    expect(auth.primaryAuthMethod).toBe('email_otp');
  });

  test('does not hide ambiguous exact wallet signer errors behind auth hints', async () => {
    await expect(
      resolveEvmFamilyTransactionWalletAuth({
        deps: {
          walletSignerStore: {
            getActiveWalletSignerForChainTarget: async () => {
              throw new Error('ambiguous active ECDSA wallet signer');
            },
            listActiveWalletSigners: async () => [],
          } as never,
        },
        walletId: 'wallet-1',
        senderSignatureAlgorithm: 'secp256k1',
        chainTarget,
        isEmailOtpThresholdContext: true,
      }),
    ).rejects.toThrow(/ambiguous active ECDSA wallet signer/);
  });
});
