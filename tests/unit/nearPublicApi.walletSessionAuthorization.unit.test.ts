import { expect, test } from '@playwright/test';
import { fundImplicitNearAccountFromCurrentSession } from '@/SeamsWeb/publicApi/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import {
  buildActiveWalletSessionAuthorizationProjection,
  walletSessionAuthorizations,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { buildWalletAuthAuthorityRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const WALLET_ID = toWalletId('wallet-near-public-funding');
const NEAR_ACCOUNT_ID = toAccountId('a'.repeat(64));
const WALLET_SESSION_TOKEN = 'opaque-wallet-session-token:near-public-funding';

function buildActiveAuthorization(expiresAtMs: number) {
  const walletSessionId = parseWalletSessionId('wallet-session-near-public-funding');
  const authorizationId = parseWalletSessionAuthorizationId(
    'wallet-session-authorization:near-public-funding',
  );
  const quotaId = parseMpcWalletSigningQuotaId('quota-near-public-funding');
  const thresholdSessionId = parseThresholdEd25519SessionId('threshold-near-public-funding');
  if (!walletSessionId.ok || !authorizationId.ok || !quotaId.ok || !thresholdSessionId.ok) {
    throw new Error('Failed to build Wallet Session authorization fixture');
  }
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: WALLET_ID,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: authorizationId.value,
        walletSessionToken: WALLET_SESSION_TOKEN,
        thresholdSessionId: thresholdSessionId.value,
      },
    },
    authMethod: 'passkey',
    authority: buildWalletAuthAuthorityRefFixture({
      walletId: String(WALLET_ID),
      label: 'near-public-funding',
    }),
    expiresAtMs,
  });
}

function fundingConfigs() {
  return {
    ...PASSKEY_MANAGER_DEFAULT_CONFIGS,
    network: {
      ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network,
      relayer: {
        ...PASSKEY_MANAGER_DEFAULT_CONFIGS.network.relayer,
        url: 'https://relay.example.test',
      },
    },
  };
}

test('implicit NEAR funding reads the canonical Wallet Session authorization projection', async () => {
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  const originalFetch = globalThis.fetch;
  const authorizationHeaders: string[] = [];
  walletSessionAuthorizations.readActiveForWallet = async () => ({
    kind: 'found',
    projection: buildActiveAuthorization(Date.now() + 60_000),
  });
  globalThis.fetch = async (_input, init) => {
    authorizationHeaders.push(String(new Headers(init?.headers).get('authorization') || ''));
    return new Response(
      JSON.stringify({
        ok: true,
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        fundedAmountYocto: '1',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  try {
    const result = await fundImplicitNearAccountFromCurrentSession({
      configs: fundingConfigs(),
      walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
      nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
      nearPublicKey: 'ed25519:near-public-funding-key',
    });

    expect(result.ok).toBe(true);
    expect(authorizationHeaders).toEqual([`Bearer ${WALLET_SESSION_TOKEN}`]);
  } finally {
    walletSessionAuthorizations.readActiveForWallet = originalRead;
    globalThis.fetch = originalFetch;
  }
});

test('implicit NEAR funding rejects absent or expired authorization before fetch', async () => {
  const originalRead = walletSessionAuthorizations.readActiveForWallet;
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error('fetch must not run');
  };

  try {
    walletSessionAuthorizations.readActiveForWallet = async () => ({ kind: 'missing' });
    await expect(
      fundImplicitNearAccountFromCurrentSession({
        configs: fundingConfigs(),
        walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
        nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
        nearPublicKey: 'ed25519:near-public-funding-key',
      }),
    ).rejects.toThrow('Current Ed25519 wallet session is required');

    walletSessionAuthorizations.readActiveForWallet = async () => ({
      kind: 'found',
      projection: buildActiveAuthorization(Date.now() - 1),
    });
    await expect(
      fundImplicitNearAccountFromCurrentSession({
        configs: fundingConfigs(),
        walletSession: { walletId: WALLET_ID, walletSessionUserId: 'near-public-funding' },
        nearAccount: { kind: 'implicit', accountId: NEAR_ACCOUNT_ID },
        nearPublicKey: 'ed25519:near-public-funding-key',
      }),
    ).rejects.toThrow('Current Ed25519 wallet session is required');
    expect(fetchCalls).toBe(0);
  } finally {
    walletSessionAuthorizations.readActiveForWallet = originalRead;
    globalThis.fetch = originalFetch;
  }
});
