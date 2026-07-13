import { expect, test } from '@playwright/test';
import { resolveConfirmedNearTransactionContext } from '@/core/signingEngine/flows/signNear/implicitAccountFunding';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

test('post-reauth implicit NEAR funding uses subject-bound refreshed authority', async () => {
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
    const walletId = toWalletId('wallet-fresh-auth');
    const nearAccountId = toAccountId('a'.repeat(64));
    const nearPublicKeyStr = 'ed25519:fresh-auth-public-key';
    const operationId = SigningSessionIds.signingOperation('near-funding-operation');
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      'near-funding-fingerprint',
    );
    const operation = {
      operationId,
      operationFingerprint,
      intent: SigningOperationIntent.TransactionSign,
      accountId: nearAccountId,
    };
    const result = await resolveConfirmedNearTransactionContext({
      confirmation: {
        sessionId: 'threshold-session-fresh',
        intentDigest: 'intent-fresh',
        readiness: {
          kind: 'funding_required',
          request: {
            subject: { walletId, nearAccountId, nearPublicKeyStr },
            operation,
            signatureUses: 1,
          },
        },
      },
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
                  walletId,
                  nearAccountId,
                  publicKey: nearPublicKeyStr,
                },
                state: 'reserved',
                reservedAtMs: Date.now(),
                expiresAtMs: Date.now() + 60_000,
              },
            ],
          }),
        },
      } as any,
      nearPublicKeyStr,
      walletSessionState: {
        thresholdSessionId: 'threshold-session-fresh',
        walletSessionAuth: {
          kind: 'wallet_session_jwt',
          walletSessionJwt: 'fresh-wallet-session-jwt',
        },
        signingLane: {
          identity: {
            thresholdSessionId: 'threshold-session-fresh',
            signer: {
              account: {
                wallet: { walletId },
                nearAccountId,
              },
            },
          },
        },
      } as any,
      authorization: { kind: 'passkey' } as any,
      signingOperation: operation,
      signatureUses: 1,
    });

    expect(authorizationHeaders).toEqual(['Bearer fresh-wallet-session-jwt']);
    expect(result.kind).toBe('context_ready');
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
