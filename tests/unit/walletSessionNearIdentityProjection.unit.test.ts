import { expect, test } from '@playwright/test';
import { selectNearOperationalPublicKeyForLogin } from '@/SeamsWeb/operations/auth/login';
import type { WalletSession } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import { buildReactLoggedInLoginStateFromSession } from '@/react/context/reactLoginStateBuilders';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  activeLinkedDeviceWalletSessionFixture,
  activeWalletSessionFixture,
} from './helpers/walletSessionReadProjection.fixtures';

const WALLET_ID = walletIdFromString('frost-vermillion-k7p9m2');
const NEAR_ACCOUNT_ID = toAccountId('frost-vermillion-k7p9m2.testnet');
const NEAR_PUBLIC_KEY = 'ed25519:mixed-wallet-public-key';

function mixedWalletSession(publicKey: string): WalletSession {
  return activeWalletSessionFixture({
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearOperationalPublicKey: publicKey,
    thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
    thresholdEcdsaPublicKeyB64u: 'mixed-wallet-ecdsa-public-key',
    walletSessionId: 'mixed-wallet-session',
  });
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

test('React projection treats a linked-device session as logged in without owner auth', () => {
  const projected = buildReactLoggedInLoginStateFromSession(
    activeLinkedDeviceWalletSessionFixture({
      walletId: String(WALLET_ID),
      nearAccountId: String(NEAR_ACCOUNT_ID),
      nearOperationalPublicKey: NEAR_PUBLIC_KEY,
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
      thresholdEcdsaPublicKeyB64u: 'mixed-wallet-ecdsa-public-key',
    }),
  );

  expect(projected).toMatchObject({
    isLoggedIn: true,
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearPublicKey: NEAR_PUBLIC_KEY,
    currentAuthMethod: { kind: 'none' },
    authMethods: [],
  });
});
