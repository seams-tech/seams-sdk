import { expect, test } from '@playwright/test';
import { orchestrateSigningConfirmation } from '@/core/signingEngine/touchConfirm/handlers/flowOrchestrator';
import {
  PENDING_INTENT_DIGEST,
  clearIntentDigestPreparation,
  consumeIntentDigestPreparation,
} from '@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry';

test.describe('touchConfirm orchestration manager bridge', () => {
  test('uses ctx.touchConfirm.requestUserConfirmation', async () => {
    let managerCalls = 0;

    const result = await orchestrateSigningConfirmation({
      ctx: {
        touchConfirm: {
          requestUserConfirmation: async (request: {
            requestId: string;
            intentDigest?: string;
          }) => {
            managerCalls += 1;
            return {
              requestId: request.requestId,
              confirmed: true,
              intentDigest: request.intentDigest,
            };
          },
        },
      } as any,
      sessionId: 'session-fallback',
      chain: 'near',
      kind: 'intentDigest',
      signerAccountId: 'alice.testnet',
      challengeB64u: 'AQ',
      intentDigest: 'intent-fallback',
    });

    expect(managerCalls).toBe(1);
    expect(result.intentDigest).toBe('intent-fallback');
  });

  test('throws when manager request bridge is unavailable', async () => {
    await expect(
      orchestrateSigningConfirmation({
        ctx: {} as any,
        sessionId: 'session-missing',
        chain: 'near',
        kind: 'intentDigest',
        signerAccountId: 'alice.testnet',
        challengeB64u: 'AQ',
        intentDigest: 'intent-missing',
      }),
    ).rejects.toThrow('UserConfirm manager request bridge is unavailable');
  });

  test('near warmSession transaction uses placeholder digest and prepares real digest in background', async () => {
    const sessionId = 'session-near-warm';
    let capturedRequest: any;

    try {
      const result = await orchestrateSigningConfirmation({
        ctx: {
          touchConfirm: {
            requestUserConfirmation: async (request: any) => {
              capturedRequest = request;
              const preparation = consumeIntentDigestPreparation(request.requestId);
              expect(preparation).toBeTruthy();
              const prepared = await preparation!;
              return {
                requestId: request.requestId,
                confirmed: true,
                intentDigest: prepared.intentDigest,
                transactionContext: {
                  nearPublicKeyStr: 'pk',
                  accessKeyInfo: { nonce: 1 },
                  nextNonce: '2',
                  txBlockHeight: '100',
                  txBlockHash: 'hash100',
                },
              };
            },
          },
        } as any,
        sessionId,
        chain: 'near',
        kind: 'transaction',
        signingAuthMode: 'warmSession',
        txSigningRequests: [
          {
            receiverId: 'receiver.testnet',
            actions: [{ action_type: 2, method_name: 'ping', args: '', gas: '1', deposit: '0' }],
          } as any,
        ],
        rpcCall: {
          nearRpcUrl: 'https://rpc.testnet.near.org',
          nearAccountId: 'alice.testnet',
        } as any,
      });

      expect(capturedRequest?.payload?.intentDigest).toBe(PENDING_INTENT_DIGEST);
      expect(capturedRequest?.summary?.intentDigest).toBeUndefined();
      expect(result.intentDigest).toBeTruthy();
      expect(result.intentDigest).not.toBe(PENDING_INTENT_DIGEST);
    } finally {
      clearIntentDigestPreparation(sessionId);
    }
  });
});
