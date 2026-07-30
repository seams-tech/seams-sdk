import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { resolveEvmFamilyTransactionWalletAuth } from '@/core/signingEngine/flows/signEvmFamily/accountAuth';

test.describe('EVM-family account auth resolution', () => {
  test('uses the exact selected capability auth method', async () => {
    const auth = await resolveEvmFamilyTransactionWalletAuth({
      senderSignatureAlgorithm: 'secp256k1',
      signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
    });

    expect(auth.primaryAuthMethod).toBe('email_otp');
  });

  test('rejects threshold signing without an exact capability auth method', async () => {
    await expect(
      resolveEvmFamilyTransactionWalletAuth({
        senderSignatureAlgorithm: 'secp256k1',
      }),
    ).rejects.toThrow(/signer auth method is unavailable/);
  });
});
