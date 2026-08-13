import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import {
  activeHostedWalletAppSessionJwt,
  redeemHostedWalletSeamsSession,
} from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { routeWalletHostRequest } from '@/SeamsWeb/walletIframe/host/requestRouter';
import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';

type RecoveryCodeStatusRequest = Extract<
  ParentToChildEnvelope,
  { type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS' }
>;
type RegisterWalletRequest = Extract<ParentToChildEnvelope, { type: 'PM_REGISTER_WALLET' }>;

function handlerDeps(input: { seamsWeb: unknown; posts: ChildToParentEnvelope[] }) {
  return {
    getSeamsWeb: () => input.seamsWeb as any,
    post: (msg: ChildToParentEnvelope) => input.posts.push(msg),
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
}

test.describe('wallet iframe Email OTP recovery-code RPC', () => {
  test('rejects legacy fields in the hosted-wallet session exchange response', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          session: {},
          jwt: 'legacy-token',
          session_id: 'legacy-session',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    try {
      await expect(
        redeemHostedWalletSeamsSession(
          {
            exchangeCode: 'exchange-1',
            nonce: 'nonce-1',
            relayUrl: 'https://relay.example.test',
          },
          'https://relay.example.test',
        ),
      ).rejects.toThrow(/Unsupported hosted-wallet redemption response field: session_id/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('routes recovery-code status to the Email OTP runtime', () => {
    const statusRoute = routeWalletHostRequest({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      requestId: 'status-1',
      payload: { walletId: 'alice.testnet' },
    } satisfies ParentToChildEnvelope);

    expect(statusRoute.kind).toBe('email_otp');
    expect(
      routeWalletHostRequest({
        type: 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION',
        requestId: 'redeem-1',
        payload: {
          exchangeCode: 'exchange-1',
          nonce: 'nonce-1',
          relayUrl: 'https://relay.example.test',
        },
      } satisfies ParentToChildEnvelope).kind,
    ).toBe('email_otp');
  });

  test('redeems one-time authority in the wallet origin and never accepts a posted bearer', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const calls: unknown[] = [];
    const unlockCalls: unknown[] = [];
    const registrationCalls: unknown[] = [];
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const jwt = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
      kind: 'app_session_v1',
      tenantId: 'tenant-1',
      sub: 'alice',
      seamsSessionId: 'session-wallet-1',
      deviceId: 'device-1',
      sessionAudience: {
        kind: 'hosted_wallet_iframe',
        appOrigin: 'https://app.example.test',
        walletOrigin: 'https://wallet.example.test',
      },
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.signature`;
    const walletOrigin = 'https://wallet.example.test';
    const originalWindow = Reflect.get(globalThis, 'window');
    Reflect.set(globalThis, 'window', { location: { origin: walletOrigin } });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      requests.push({ url: String(url), init });
      return new Response(
        JSON.stringify({
          ok: true,
          session: {
            kind: 'app_session_v1',
            userId: 'alice',
            tenantId: 'tenant-1',
            seamsSessionId: 'session-wallet-1',
            deviceId: 'device-1',
            audience: {
              kind: 'hosted_wallet_iframe',
              appOrigin: 'https://app.example.test',
              walletOrigin,
            },
            expiresAtMs: Date.now() + 60_000,
          },
          jwt,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    };
    const handlers = createWalletIframeHandlers(
      handlerDeps({
        posts,
        seamsWeb: {
          configs: {
            network: {
              relayer: { url: 'https://relay.example.test' },
            },
          },
          auth: {
            unlock: async (...args: unknown[]) => {
              unlockCalls.push(args);
              return { success: false, error: 'captured' };
            },
          },
          registration: {
            registerWallet: async (args: unknown) => {
              registrationCalls.push(args);
              return { success: false, error: 'captured' };
            },
          },
          recovery: {
            getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
              calls.push(args);
              return { status: 'ready', walletId: 'alice.testnet' };
            },
          },
        },
      }),
    );

    try {
      await handlers.PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION!({
        type: 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION',
        requestId: 'redeem-1',
        payload: {
          exchangeCode: 'exchange-1',
          nonce: 'nonce-1',
          relayUrl: 'https://relay.example.test',
        },
      });
      await handlers.PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS!({
        type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
        requestId: 'status-1',
        payload: {
          walletId: ' alice.testnet ',
          relayUrl: ' https://relay.example.test ',
        },
      } satisfies RecoveryCodeStatusRequest);

      expect(requests).toHaveLength(1);
      expect(requests[0]?.init?.headers).toEqual({ 'Content-Type': 'application/json' });
      expect(JSON.parse(String(requests[0]?.init?.body))).toEqual({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code_redeem',
          exchange_code: 'exchange-1',
          nonce: 'nonce-1',
        },
      });
      expect(calls).toEqual([
        {
          walletId: 'alice.testnet',
          relayUrl: 'https://relay.example.test',
          appSessionJwt: jwt,
        },
      ]);
      const registrationPayload = {
        authMethod: {
          kind: 'email_otp' as const,
          proofKind: 'otp_challenge' as const,
          email: 'alice@example.test',
          otpCode: '123456',
          challengeId: 'challenge-1',
        },
        wallet: { kind: 'server_allocated' as const },
        signerSelection: { kind: 'signer_set' as const, signers: [] },
      };
      await handlers.PM_REGISTER_WALLET!({
        type: 'PM_REGISTER_WALLET',
        requestId: 'registration-1',
        payload: registrationPayload,
      });
      expect(registrationCalls).toEqual([
        expect.objectContaining({
          authMethod: {
            ...registrationPayload.authMethod,
            appSessionJwt: jwt,
          },
        }),
      ]);
      await expect(
        handlers.PM_REGISTER_WALLET!({
          type: 'PM_REGISTER_WALLET',
          requestId: 'registration-with-bearer',
          payload: {
            ...registrationPayload,
            authMethod: {
              ...registrationPayload.authMethod,
              appSessionJwt: 'parent-bearer',
            },
          },
        } as RegisterWalletRequest),
      ).rejects.toThrow(/must not carry appSessionJwt/);
      const unlockPayload = {
        kind: 'custom_options' as const,
        walletId: 'alice.testnet',
        options: {
          kind: 'pm_unlock_options_v1' as const,
          signerSlot: { kind: 'default' as const },
          session: { kind: 'default' as const },
          signingSession: { kind: 'default' as const },
          unlockSelection: { kind: 'default' as const },
          ecdsaKeyFactsInventory: {
            kind: 'value' as const,
            value: { mode: 'app_session' as const },
          },
        },
      };
      await handlers.PM_UNLOCK!({
        type: 'PM_UNLOCK',
        requestId: 'unlock-1',
        payload: unlockPayload,
      });
      expect(unlockCalls).toEqual([
        [
          'alice.testnet',
          expect.objectContaining({
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
            ecdsaKeyFactsInventory: {
              mode: 'app_session',
              appSessionJwt: jwt,
            },
          }),
        ],
      ]);
      await expect(
        handlers.PM_UNLOCK!({
          type: 'PM_UNLOCK',
          requestId: 'unlock-with-bearer',
          payload: {
            ...unlockPayload,
            options: {
              ...unlockPayload.options,
              ecdsaKeyFactsInventory: {
                kind: 'value',
                value: { mode: 'app_session', appSessionJwt: 'parent-bearer' },
              },
            },
          },
        }),
      ).rejects.toThrow(/must not carry appSessionJwt/);
      await expect(
        handlers.PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS!({
          type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
          requestId: 'status-with-bearer',
          payload: {
            walletId: 'alice.testnet',
            appSessionJwt: 'parent-bearer',
          },
        } as RecoveryCodeStatusRequest),
      ).rejects.toThrow(/must not carry appSessionJwt/);
      expect(activeHostedWalletAppSessionJwt('https://another-relay.example.test')).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
      if (originalWindow === undefined) {
        Reflect.deleteProperty(globalThis, 'window');
      } else {
        Reflect.set(globalThis, 'window', originalWindow);
      }
    }
  });
});
