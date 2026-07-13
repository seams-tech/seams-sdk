import { expect, test } from '@playwright/test';
import { fundImplicitNearAccountAfterFreshAuth } from '@/core/signingEngine/flows/signNear/implicitAccountFunding';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';

test('implicit NEAR funding uses refreshed Wallet Session authority', async () => {
  const originalFetch = globalThis.fetch;
  const authorizationHeaders: string[] = [];
  globalThis.fetch = async (_input, init) => {
    authorizationHeaders.push(String(new Headers(init?.headers).get('authorization') || ''));
    return new Response(
      JSON.stringify({
        ok: true,
        walletId: 'wallet-fresh-auth',
        nearAccountId: 'a'.repeat(64),
        fundedAmountYocto: '1',
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  try {
    const operationId = SigningSessionIds.signingOperation('near-funding-operation');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'near-funding-fingerprint',
    );
    const result = await fundImplicitNearAccountAfterFreshAuth({
      ctx: {
        relayerUrl: 'https://relay.example.test',
        chains: [{ network: 'near-testnet' }],
        nearClient: {},
        nonceCoordinator: {
          reserveNearContext: async () => ({
            context: {
              accessKeyInfo: { nonce: 10 },
              nextNonce: '11',
              txBlockHeight: '100',
              txBlockHash: 'block-hash',
            },
            leases: [
              {
                leaseId: 'near-lease-1',
                operationId,
                operationFingerprint,
                nonce: '11',
                lane: {
                  family: 'near',
                  networkKey: 'near-testnet',
                  walletId: 'wallet-fresh-auth',
                  nearAccountId: 'a'.repeat(64),
                  publicKey: 'ed25519:fresh-auth-public-key',
                },
                state: 'reserved',
                reservedAtMs: Date.now(),
                expiresAtMs: Date.now() + 60_000,
              },
            ],
          }),
        },
      } as any,
      walletId: 'wallet-fresh-auth',
      nearAccountId: toAccountId('a'.repeat(64)),
      nearPublicKeyStr: 'ed25519:fresh-auth-public-key',
      walletSessionState: {
        walletSessionAuth: {
          kind: 'wallet_session_jwt',
          walletSessionJwt: 'fresh-wallet-session-jwt',
        },
      },
      signingOperation: {
        operationId,
        operationFingerprint,
        intent: SigningOperationIntent.TransactionSign,
      },
      signatureUses: 1,
    });

    expect(authorizationHeaders).toEqual(['Bearer fresh-wallet-session-jwt']);
    expect(result.transactionContext.nextNonce).toBe('11');
    expect(result.nonceLeases).toEqual([
      {
        leaseId: 'near-lease-1',
        operationId: 'near-funding-operation',
        operationFingerprint: 'near-funding-fingerprint',
        nonce: '11',
      },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
