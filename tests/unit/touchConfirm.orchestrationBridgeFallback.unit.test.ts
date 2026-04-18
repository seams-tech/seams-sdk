import { expect, test } from '@playwright/test';
import { orchestrateSigningConfirmation } from '@/core/signingEngine/touchConfirm/handlers/flowOrchestrator';
import {
  PENDING_INTENT_DIGEST,
  clearIntentDigestPreparation,
  consumeIntentDigestPreparation,
} from '@/core/signingEngine/touchConfirm/intentDigestPreparationRegistry';
import {
  getEmailOtpPrompt,
  getSigningAuthMode,
} from '@/core/signingEngine/touchConfirm/handlers/flows/adapters/request';
import type { SigningAuthPlan } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';

const passkeyPlan: SigningAuthPlan = {
  kind: 'passkeyReauth',
  method: 'passkey',
};

function warmSessionPlan(sessionId: string): SigningAuthPlan {
  return {
    kind: 'warmSession',
    method: 'passkey',
    accountId: 'alice.testnet',
    intent: 'transaction_sign',
    curve: 'ed25519',
    sessionId,
    retention: 'session',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 1,
  };
}

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
      signingAuthPlan: passkeyPlan,
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
        signingAuthPlan: passkeyPlan,
      }),
    ).rejects.toThrow('UserConfirm manager request bridge is unavailable');
  });

  test('forwards signing auth plans as canonical auth input', async () => {
    let capturedRequest: any;

    await orchestrateSigningConfirmation({
      ctx: {
        touchConfirm: {
          requestUserConfirmation: async (request: any) => {
            capturedRequest = request;
            return {
              requestId: request.requestId,
              confirmed: true,
              intentDigest: request.intentDigest,
            };
          },
        },
      } as any,
      sessionId: 'session-email-otp-plan',
      chain: 'evm',
      kind: 'intentDigest',
      signerAccountId: 'alice.testnet',
      challengeB64u: 'AQ',
      intentDigest: 'intent-email-otp-plan',
      signingAuthPlan: {
        kind: 'emailOtpReauth',
        method: 'email_otp',
        emailOtpPrompt: {
          challengeId: 'email-otp-plan-challenge',
          emailHint: 'a***e@example.com',
        },
      },
    });

    expect(capturedRequest?.payload?.signingAuthPlan?.kind).toBe('emailOtpReauth');
    expect(getSigningAuthMode(capturedRequest)).toBe('emailOtp');
    expect(getEmailOtpPrompt(capturedRequest)?.challengeId).toBe('email-otp-plan-challenge');
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
        signingAuthPlan: warmSessionPlan('threshold-session-warm'),
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
        nearPublicKeyStr: 'ed25519:warm-session-key',
      });

      expect(capturedRequest?.payload?.intentDigest).toBe(PENDING_INTENT_DIGEST);
      expect(capturedRequest?.payload?.nearPublicKeyStr).toBe('ed25519:warm-session-key');
      expect(capturedRequest?.summary?.intentDigest).toBeUndefined();
      expect(result.intentDigest).toBeTruthy();
      expect(result.intentDigest).not.toBe(PENDING_INTENT_DIGEST);
    } finally {
      clearIntentDigestPreparation(sessionId);
    }
  });

  test('near warmSession transaction can be driven by signingAuthPlan without legacy mode', async () => {
    const sessionId = 'session-near-warm-plan';
    let capturedRequest: any;

    try {
      await orchestrateSigningConfirmation({
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
        signingAuthPlan: warmSessionPlan('threshold-session-1'),
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
        nearPublicKeyStr: 'ed25519:warm-session-key',
      });

      expect(capturedRequest?.payload?.intentDigest).toBe(PENDING_INTENT_DIGEST);
      expect(capturedRequest?.payload?.signingAuthMode).toBeUndefined();
      expect(capturedRequest?.payload?.signingAuthPlan?.kind).toBe('warmSession');
    } finally {
      clearIntentDigestPreparation(sessionId);
    }
  });

  test('near warmSession delegate keeps request-scoped public key', async () => {
    let capturedRequest: any;

    const result = await orchestrateSigningConfirmation({
      ctx: {
        touchConfirm: {
          requestUserConfirmation: async (request: any) => {
            capturedRequest = request;
            return {
              requestId: request.requestId,
              confirmed: true,
              intentDigest: request.intentDigest,
              transactionContext: {
                nearPublicKeyStr: 'ed25519:delegate-key',
                accessKeyInfo: { nonce: 5 },
                nextNonce: '6',
                txBlockHeight: '200',
                txBlockHash: 'hash200',
              },
            };
          },
        },
      } as any,
      sessionId: 'session-near-delegate',
      chain: 'near',
      kind: 'delegate',
      signingAuthPlan: warmSessionPlan('threshold-session-delegate'),
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:delegate-key',
      delegate: {
        senderId: 'alice.testnet',
        receiverId: 'receiver.testnet',
        actions: [{ action_type: 2, method_name: 'ping', args: '', gas: '1', deposit: '0' }] as any,
        nonce: '7',
        maxBlockHeight: '999',
      },
      rpcCall: {
        nearRpcUrl: 'https://rpc.testnet.near.org',
        nearAccountId: 'alice.testnet',
      } as any,
    });

    expect(capturedRequest?.payload?.nearPublicKeyStr).toBe('ed25519:delegate-key');
    expect(result.transactionContext?.nearPublicKeyStr).toBe('ed25519:delegate-key');
  });

  test('near warmSession nep413 keeps request-scoped public key', async () => {
    let capturedRequest: any;

    const result = await orchestrateSigningConfirmation({
      ctx: {
        touchConfirm: {
          requestUserConfirmation: async (request: any) => {
            capturedRequest = request;
            return {
              requestId: request.requestId,
              confirmed: true,
              intentDigest: request.intentDigest,
              transactionContext: {
                nearPublicKeyStr: 'ed25519:nep413-key',
                accessKeyInfo: { nonce: 8 },
                nextNonce: '9',
                txBlockHeight: '300',
                txBlockHash: 'hash300',
              },
            };
          },
        },
      } as any,
      sessionId: 'session-nep413',
      chain: 'near',
      kind: 'nep413',
      signingAuthPlan: warmSessionPlan('threshold-session-nep413'),
      nearAccountId: 'alice.testnet',
      nearPublicKeyStr: 'ed25519:nep413-key',
      message: 'hello threshold nep413',
      recipient: 'receiver.testnet',
    });

    expect(capturedRequest?.payload?.nearPublicKeyStr).toBe('ed25519:nep413-key');
    expect(result.transactionContext?.nearPublicKeyStr).toBe('ed25519:nep413-key');
  });
});
