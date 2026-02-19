import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/core/WalletIframe/host/wallet-iframe-handlers';
import { resolveWalletBoundaryErrorCode } from '@/core/WalletIframe/host/canonicalSignerErrorCode';
import type { ChildToParentEnvelope } from '@/core/WalletIframe/shared/messages';

function makeTempoRequest(requestId: string): any {
  return {
    type: 'PM_SIGN_TEMPO',
    requestId,
    payload: {
      nearAccountId: 'alice.testnet',
      request: {
        chain: 'tempo',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {},
      },
      options: {},
    },
  };
}

test.describe('wallet iframe host PM_SIGN_TEMPO cancellation guards', () => {
  test('returns early when request is already cancelled before signing starts', async () => {
    const posts: ChildToParentEnvelope[] = [];
    let signCalls = 0;
    let cancelChecks = 0;

    const handlers = createWalletIframeHandlers({
      getTatchiPasskey: () => ({
        tempo: {
          signTempo: async () => {
            signCalls += 1;
            return { chain: 'tempo', kind: 'eip1559', txHashHex: '0x1', rawTxHex: '0x2' } as any;
          },
        },
      } as any),
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => true,
      respondIfCancelled: () => {
        cancelChecks += 1;
        return true;
      },
    });

    await handlers.PM_SIGN_TEMPO!(makeTempoRequest('req-cancelled') as any);

    expect(cancelChecks).toBe(1);
    expect(signCalls).toBe(0);
    expect(posts.length).toBe(0);
  });

  test('forwards shouldAbort probe into signTempo call', async () => {
    const posts: ChildToParentEnvelope[] = [];
    let cancelled = false;
    let signCalls = 0;

    const handlers = createWalletIframeHandlers({
      getTatchiPasskey: () => ({
        tempo: {
          signTempo: async (args: any) => {
            signCalls += 1;
            const shouldAbort = args?.options?.shouldAbort;
            expect(typeof shouldAbort).toBe('function');
            expect(shouldAbort()).toBe(false);
            cancelled = true;
            expect(shouldAbort()).toBe(true);
            cancelled = false;
            return { chain: 'tempo', kind: 'eip1559', txHashHex: '0x1', rawTxHex: '0x2' } as any;
          },
        },
      } as any),
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => cancelled,
      respondIfCancelled: () => cancelled,
    });

    await handlers.PM_SIGN_TEMPO!(makeTempoRequest('req-active') as any);

    expect(signCalls).toBe(1);
    expect(posts.some((msg) => msg.type === 'PM_RESULT')).toBe(true);
  });
});

test.describe('wallet iframe host canonical signer error mapping', () => {
  test('normalizes legacy CANCELLED into canonical cancelled', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'CANCELLED',
      message: 'Request cancelled',
    });
    expect(code).toBe('cancelled');
  });

  test('maps threshold in-flight message to signing_in_progress', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: '[SigningEngine] threshold ECDSA signing already in progress for alice.testnet',
    });
    expect(code).toBe('signing_in_progress');
  });

  test('maps deployment failure message to deployment_failed', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: '[SigningEngine] smart-account deployment must succeed before first EVM send: gateway timeout',
    });
    expect(code).toBe('deployment_failed');
  });

  test('maps deployment_in_progress variants to canonical code', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'DEPLOYMENT-IN-PROGRESS',
      message: 'smart-account deployment already in progress',
    });
    expect(code).toBe('deployment_in_progress');
  });

  test('maps threshold session auth errors to session_not_ready', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      message: 'relayer threshold session expired',
    });
    expect(code).toBe('session_not_ready');
  });

  test('prevents unknown signer-boundary code leakage', async () => {
    const code = resolveWalletBoundaryErrorCode({
      requestType: 'PM_SIGN_TEMPO',
      rawCode: 'SOME_INTERNAL_RUNTIME_ERROR',
      message: 'unexpected runtime path',
    });
    expect(code).toBe('session_not_ready');
  });
});
