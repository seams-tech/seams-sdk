import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import { routeWalletHostRequest } from '@/SeamsWeb/walletIframe/host/requestRouter';
import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';

type RecoveryCodeStatusRequest = Extract<
  ParentToChildEnvelope,
  { type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS' }
>;

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
  test('routes recovery-code status to the Email OTP runtime', () => {
    const statusRoute = routeWalletHostRequest({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      requestId: 'status-1',
      payload: { walletId: 'alice.testnet' },
    } satisfies ParentToChildEnvelope);

    expect(statusRoute.kind).toBe('email_otp');
  });

  test('normalizes recovery-code status payload before delegating to pm.recovery', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const calls: unknown[] = [];
    const handlers = createWalletIframeHandlers(
      handlerDeps({
        posts,
        seamsWeb: {
          recovery: {
            getEmailOtpRecoveryCodeStatus: async (args: unknown) => {
              calls.push(args);
              return { status: 'ready', walletId: 'alice.testnet' };
            },
          },
        },
      }),
    );

    await handlers.PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS!({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      requestId: 'status-1',
      payload: {
        walletId: ' alice.testnet ',
        relayUrl: ' https://relay.example.test ',
        appSessionJwt: ' jwt-1 ',
      },
    } satisfies RecoveryCodeStatusRequest);

    expect(calls).toEqual([
      {
        walletId: 'alice.testnet',
        relayUrl: 'https://relay.example.test',
        appSessionJwt: 'jwt-1',
      },
    ]);
    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'status-1',
        payload: expect.objectContaining({ ok: true }),
      }),
    ]);
  });

});
