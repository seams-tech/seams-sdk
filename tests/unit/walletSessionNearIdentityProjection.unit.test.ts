import { expect, test } from '@playwright/test';
import { selectNearOperationalPublicKeyForLogin } from '@/SeamsWeb/operations/auth/login';
import type { WalletSession } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { buildReactLoggedInLoginStateFromSession } from '@/react/context/reactLoginStateBuilders';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import { walletIdFromString } from '@shared/utils/registrationIntent';

const WALLET_ID = walletIdFromString('frost-vermillion-k7p9m2');
const NEAR_ACCOUNT_ID = toAccountId('frost-vermillion-k7p9m2.testnet');
const NEAR_PUBLIC_KEY = 'ed25519:mixed-wallet-public-key';

function mixedWalletSession(publicKey: string): WalletSession {
  const currentAuthMethod = buildNoCurrentWalletAuthMethod();
  return {
    login: {
      isLoggedIn: true,
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      publicKey,
      userData: null,
      currentAuthMethod,
      authMethods: [],
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
      thresholdEcdsaPublicKeyB64u: 'mixed-wallet-ecdsa-public-key',
    },
    signingSession: {
      sessionId: 'mixed-wallet-ecdsa-session',
      status: 'active',
      remainingUses: 3,
    },
    currentAuthMethod,
    authMethods: [],
    authMethod: null,
    retention: null,
    nonceDiagnostics: null,
  };
}

test('persisted Ed25519 public identity is independent of signing-lane readiness', () => {
  expect(
    selectNearOperationalPublicKeyForLogin({
      operationalPublicKey: NEAR_PUBLIC_KEY,
    }),
  ).toBe(NEAR_PUBLIC_KEY);
});

test('React projection retains NEAR identity for a mixed wallet session', () => {
  const projected = buildReactLoggedInLoginStateFromSession(mixedWalletSession(NEAR_PUBLIC_KEY));

  expect(projected).toMatchObject({
    isLoggedIn: true,
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearPublicKey: NEAR_PUBLIC_KEY,
    thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
  });
});
