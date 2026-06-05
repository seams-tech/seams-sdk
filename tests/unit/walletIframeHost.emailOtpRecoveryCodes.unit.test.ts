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
type RecoveryCodeAcknowledgeRequest = Extract<
  ParentToChildEnvelope,
  { type: 'PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP' }
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
  test('routes recovery-code status and acknowledgement to the Email OTP runtime', () => {
    const statusRoute = routeWalletHostRequest({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      requestId: 'status-1',
      payload: { walletId: 'alice.testnet' },
    } satisfies ParentToChildEnvelope);
    const acknowledgeRoute = routeWalletHostRequest({
      type: 'PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP',
      requestId: 'ack-1',
      payload: {
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-1',
      },
    } satisfies ParentToChildEnvelope);

    expect(statusRoute.kind).toBe('email_otp');
    expect(acknowledgeRoute.kind).toBe('email_otp');
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

  test('normalizes recovery-code acknowledgement payload before delegating to pm.recovery', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const calls: unknown[] = [];
    const handlers = createWalletIframeHandlers(
      handlerDeps({
        posts,
        seamsWeb: {
          recovery: {
            acknowledgeEmailOtpRecoveryCodeBackup: async (args: unknown) => {
              calls.push(args);
              return { status: 'active', walletId: 'alice.testnet' };
            },
          },
        },
      }),
    );

    await handlers.PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP!({
      type: 'PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP',
      requestId: 'ack-1',
      payload: {
        walletId: ' alice.testnet ',
        enrollmentId: ' enrollment-1 ',
        enrollmentSealKeyVersion: ' seal-1 ',
        relayUrl: ' https://relay.example.test ',
        appSessionJwt: ' jwt-1 ',
      },
    } satisfies RecoveryCodeAcknowledgeRequest);

    expect(calls).toEqual([
      {
        walletId: 'alice.testnet',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-1',
        relayUrl: 'https://relay.example.test',
        appSessionJwt: 'jwt-1',
      },
    ]);
    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'ack-1',
        payload: expect.objectContaining({ ok: true }),
      }),
    ]);
  });

  test('rejects recovery-code acknowledgement payloads missing required identity fields', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      handlerDeps({
        posts,
        seamsWeb: {
          recovery: {
            acknowledgeEmailOtpRecoveryCodeBackup: async () => {
              throw new Error('should not delegate invalid payload');
            },
          },
        },
      }),
    );

    await expect(
      handlers.PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP!({
        type: 'PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP',
        requestId: 'ack-invalid',
        payload: {
          walletId: 'alice.testnet',
          enrollmentId: 'enrollment-1',
        },
      } as any),
    ).rejects.toThrow('Missing enrollmentSealKeyVersion');
    expect(posts).toEqual([]);
  });
});
