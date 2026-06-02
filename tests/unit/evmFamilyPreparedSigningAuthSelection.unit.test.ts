import { expect, test } from '@playwright/test';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyTransactionSigningIntent,
  resolveEvmFamilyTransactionAuthSelectionPolicy,
} from '@/core/signingEngine/flows/signEvmFamily/preparedSigning';

const walletId = toWalletId('wallet.testnet');
const signingTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});

test.describe('EVM-family prepared signing auth selection', () => {
  test('keeps initial transaction intent auth-neutral', () => {
    const intent = buildEvmFamilyTransactionSigningIntent({
      walletId,
      signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: resolveEvmFamilyTransactionAuthSelectionPolicy({}),
    });

    expect(intent).toMatchObject({
      walletId,
      curve: 'ecdsa',
      chain: 'evm',
      chainTarget: signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: { kind: 'any' },
    });
  });

  test('derives account-class policy from the selected candidate auth method', () => {
    expect(
      resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod: 'email_otp',
      }),
    ).toEqual({
      kind: 'account_class',
      authMethod: 'email_otp',
    });
    expect(
      resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod: 'passkey',
      }),
    ).toEqual({
      kind: 'account_class',
      authMethod: 'passkey',
    });
  });
});
