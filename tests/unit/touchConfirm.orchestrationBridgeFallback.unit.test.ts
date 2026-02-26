import { expect, test } from '@playwright/test';
import { orchestrateSigningConfirmation } from '@/core/signingEngine/touchConfirm/handlers/flowOrchestrator';

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
});
