import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { prefillThresholdEcdsaPresignPoolDomain } from '@/core/SeamsPasskey/authSessions';

test.describe('prefillThresholdEcdsaPresignPoolDomain', () => {
  test('local mode resolves canonical keyRef and schedules prefill', async () => {
    const calls: Array<{ nearAccountId: string; chain?: 'tempo' | 'evm'; source?: 'login' }> = [];
    const scheduleCalls: any[] = [];
    const result = { status: 'scheduled', reason: 'scheduled' } as const;

    const out = await prefillThresholdEcdsaPresignPoolDomain(
      {
        getContext: () => ({}) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be used in local mode');
          },
        } as any,
        signingEngine: {
          getThresholdEcdsaKeyRefForLookup: (args: {
            nearAccountId: string;
            chain?: 'tempo' | 'evm';
            source?: 'login';
          }) => {
            calls.push(args);
            return {
              type: 'threshold-ecdsa-secp256k1',
              userId: args.nearAccountId,
              relayerUrl: 'https://relay.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
              thresholdSessionJwt: 'jwt-1',
              participantIds: [1, 2],
            } as any;
          },
          scheduleThresholdEcdsaLoginPresignPrefill: async (args: any) => {
            scheduleCalls.push(args);
            return result;
          },
        } as any,
        nearClient: {} as any,
        initWalletIframe: async () => undefined,
      },
      {
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
      },
    );

    expect(out).toEqual(result);
    expect(calls).toEqual([
      { nearAccountId: toAccountId('alice.testnet'), chain: 'tempo', source: 'login' },
    ]);
    expect(scheduleCalls).toHaveLength(1);
    expect(scheduleCalls[0]?.nearAccountId).toBe(toAccountId('alice.testnet'));
    expect(scheduleCalls[0]?.thresholdEcdsaKeyRef?.thresholdSessionId).toBe('session-1');
  });

  test('iframe mode forwards prefill request to router', async () => {
    const routerCalls: any[] = [];
    const result = { status: 'skipped', reason: 'pool_already_warm' } as const;

    const out = await prefillThresholdEcdsaPresignPoolDomain(
      {
        getContext: () => ({}) as any,
        walletIframe: {
          shouldUseWalletIframe: () => true,
          requireRouter: async () =>
            ({
              prefillThresholdEcdsaPresignPool: async (args: any) => {
                routerCalls.push(args);
                return result;
              },
            }) as any,
        } as any,
        signingEngine: {} as any,
        nearClient: {} as any,
        initWalletIframe: async () => undefined,
      },
      {
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        waitForPoolReady: true,
        poolReadyTimeoutMs: 5_000,
      },
    );

    expect(out).toEqual(result);
    expect(routerCalls).toEqual([
      {
        nearAccountId: 'alice.testnet',
        options: {
          chain: 'evm',
          waitForPoolReady: true,
          poolReadyTimeoutMs: 5_000,
        },
      },
    ]);
  });
});
