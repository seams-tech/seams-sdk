import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import {
  activeHostedWalletSessionOperationCredential,
  clearHostedWalletSessions,
  recordAdoptedWalletIframeParentOrigin,
  redeemHostedWalletSeamsSession,
} from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { routeWalletHostRequest } from '@/SeamsWeb/walletIframe/host/requestRouter';
import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';
import {
  buildPMRedeemHostedWalletSeamsSessionPayload,
  parsePMRedeemHostedWalletSeamsSessionPayload,
} from '@/SeamsWeb/walletIframe/shared/messages';

type RecoveryCodeStatusRequest = Extract<
  ParentToChildEnvelope,
  { type: 'PM_GET_WALLET_RECOVERY_CODE_STATUS' }
>;
type RegisterWalletRequest = Extract<ParentToChildEnvelope, { type: 'PM_REGISTER_WALLET' }>;

const RELAY_URL = 'https://relay.example.test';
const APP_ORIGIN = 'https://app.example.test';
const WALLET_ORIGIN = 'https://wallet.example.test';
const HOSTED_OPERATION_CREDENTIAL = `wsh_${'c'.repeat(43)}`;

function redemptionRequest() {
  return buildPMRedeemHostedWalletSeamsSessionPayload({
    exchangeCode: 'exchange-1',
    nonce: 'nonce-1',
    appOrigin: APP_ORIGIN,
    walletOrigin: WALLET_ORIGIN,
    relayUrl: RELAY_URL,
  });
}

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
  test('parses only the exact curve-free hosted-wallet redemption message', () => {
    expect(parsePMRedeemHostedWalletSeamsSessionPayload(redemptionRequest())).toEqual(
      redemptionRequest(),
    );
    expect(() =>
      parsePMRedeemHostedWalletSeamsSessionPayload({
        ...redemptionRequest(),
        curve: 'ecdsa',
      }),
    ).toThrow(/payload fields are invalid/);
    expect(() =>
      parsePMRedeemHostedWalletSeamsSessionPayload({
        ...redemptionRequest(),
        walletSessionToken: 'wst_legacy',
      }),
    ).toThrow(/payload fields are invalid/);
  });

  test('rejects redemption before fetch when appOrigin differs from the adopted parent', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const originalFetch = globalThis.fetch;
    let fetchCount = 0;
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });
    recordAdoptedWalletIframeParentOrigin('https://other-app.example.test');
    globalThis.fetch = async () => {
      fetchCount += 1;
      throw new Error('fetch must not run');
    };
    try {
      await expect(
        redeemHostedWalletSeamsSession(redemptionRequest(), RELAY_URL),
      ).rejects.toThrow(/appOrigin does not match the adopted iframe parent/);
      expect(fetchCount).toBe(0);
    } finally {
      clearHostedWalletSessions();
      globalThis.fetch = originalFetch;
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('rejects unsupported fields in the hosted-wallet session exchange response', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const originalFetch = globalThis.fetch;
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });
    recordAdoptedWalletIframeParentOrigin(APP_ORIGIN);
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSessionId: 'wallet-session-1',
          operationCredential: {
            kind: 'opaque_hosted_wallet_session_operation_credential_v1',
            token: HOSTED_OPERATION_CREDENTIAL,
            walletSessionId: 'wallet-session-1',
          },
          expiresAtMs: Date.now() + 60_000,
          session_id: 'legacy-session',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    try {
      await expect(
        redeemHostedWalletSeamsSession(redemptionRequest(), RELAY_URL),
      ).rejects.toThrow(/hosted-wallet session redemption response fields are invalid/);
    } finally {
      clearHostedWalletSessions();
      globalThis.fetch = originalFetch;
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('rejects a hosted credential for a different parent Wallet Session', async () => {
    const originalWindow = Reflect.get(globalThis, 'window');
    const originalFetch = globalThis.fetch;
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });
    recordAdoptedWalletIframeParentOrigin(APP_ORIGIN);
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ok: true,
          walletSessionId: 'wallet-session-1',
          operationCredential: {
            kind: 'opaque_hosted_wallet_session_operation_credential_v1',
            token: HOSTED_OPERATION_CREDENTIAL,
            walletSessionId: 'wallet-session-2',
          },
          expiresAtMs: Date.now() + 60_000,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    try {
      await expect(
        redeemHostedWalletSeamsSession(redemptionRequest(), RELAY_URL),
      ).rejects.toThrow(/does not identify its parent Wallet Session/);
      expect(activeHostedWalletSessionOperationCredential(RELAY_URL)).toBeUndefined();
    } finally {
      clearHostedWalletSessions();
      globalThis.fetch = originalFetch;
      if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
      else Reflect.set(globalThis, 'window', originalWindow);
    }
  });

  test('routes wallet recovery-code status to the Email OTP runtime', () => {
    const statusRoute = routeWalletHostRequest({
      type: 'PM_GET_WALLET_RECOVERY_CODE_STATUS',
      requestId: 'status-1',
      payload: { walletId: 'alice.testnet' },
    } satisfies ParentToChildEnvelope);

    expect(statusRoute.kind).toBe('email_otp');
    expect(
      routeWalletHostRequest({
        type: 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION',
        requestId: 'redeem-1',
        payload: redemptionRequest(),
      } satisfies ParentToChildEnvelope).kind,
    ).toBe('email_otp');
  });

  test('redeems one-time authority in the wallet origin and never accepts a posted wallet session token', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const calls: unknown[] = [];
    const registrationCalls: unknown[] = [];
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const originalWindow = Reflect.get(globalThis, 'window');
    Reflect.set(globalThis, 'window', { location: { origin: WALLET_ORIGIN } });
    recordAdoptedWalletIframeParentOrigin(APP_ORIGIN);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      requests.push({ url: String(url), init });
      return new Response(
        JSON.stringify({
          ok: true,
          walletSessionId: 'wallet-session-1',
          operationCredential: {
            kind: 'opaque_hosted_wallet_session_operation_credential_v1',
            token: HOSTED_OPERATION_CREDENTIAL,
            walletSessionId: 'wallet-session-1',
          },
          expiresAtMs: Date.now() + 60_000,
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
              relayer: { url: RELAY_URL },
            },
          },
          registration: {
            registerWallet: async (args: unknown) => {
              registrationCalls.push(args);
              return { success: false, error: 'captured' };
            },
          },
          recovery: {
            getWalletRecoveryCodeStatus: async (args: unknown) => {
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
        payload: redemptionRequest(),
      });

      expect(requests).toHaveLength(1);
      expect(requests[0]?.url).toBe(`${RELAY_URL}/wallet/session/exchange/redeem`);
      expect(requests[0]?.init?.headers).toEqual({ 'Content-Type': 'application/json' });
      expect(JSON.parse(String(requests[0]?.init?.body))).toEqual({
        exchangeCode: 'exchange-1',
        nonce: 'nonce-1',
        appOrigin: APP_ORIGIN,
        walletOrigin: WALLET_ORIGIN,
      });

      // The child credential stays in the wallet origin; the parent only learns the expiry.
      expect(activeHostedWalletSessionOperationCredential(RELAY_URL)).toEqual({
        kind: 'opaque_hosted_wallet_session_operation_credential_v1',
        token: HOSTED_OPERATION_CREDENTIAL,
        walletSessionId: 'wallet-session-1',
      });
      const redeemResult = posts.find((post) => post.requestId === 'redeem-1');
      expect(JSON.stringify(redeemResult)).not.toContain(HOSTED_OPERATION_CREDENTIAL);

      await handlers.PM_GET_WALLET_RECOVERY_CODE_STATUS!({
        type: 'PM_GET_WALLET_RECOVERY_CODE_STATUS',
        requestId: 'status-1',
        payload: { walletId: ' alice.testnet ' },
      } satisfies RecoveryCodeStatusRequest);
      expect(calls).toEqual([{ walletId: 'alice.testnet' }]);

      await expect(
        handlers.PM_GET_WALLET_RECOVERY_CODE_STATUS!({
          type: 'PM_GET_WALLET_RECOVERY_CODE_STATUS',
          requestId: 'status-with-bearer',
          payload: {
            walletId: 'alice.testnet',
            walletSessionToken: 'wst_parent-supplied-token',
          },
        } as RecoveryCodeStatusRequest),
      ).rejects.toThrow(/must not carry walletSessionToken/);

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
        requestId: 'registration-with-bearer',
        payload: {
          ...registrationPayload,
          authMethod: {
            ...registrationPayload.authMethod,
            walletSessionToken: 'wst_parent-supplied-token',
          },
        },
      } as RegisterWalletRequest);

      // Registration maps the auth method onto its exact union, so a posted bearer never lands.
      expect(registrationCalls).toHaveLength(1);
      expect(JSON.stringify(registrationCalls[0])).not.toContain('wst_parent-supplied-token');

      recordAdoptedWalletIframeParentOrigin('https://replacement-app.example.test');
      expect(activeHostedWalletSessionOperationCredential(RELAY_URL)).toBeUndefined();
    } finally {
      clearHostedWalletSessions();
      globalThis.fetch = originalFetch;
      if (originalWindow === undefined) {
        Reflect.deleteProperty(globalThis, 'window');
      } else {
        Reflect.set(globalThis, 'window', originalWindow);
      }
    }
  });
});
