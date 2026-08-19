import { expect, test } from '@playwright/test';
import { createDeviceLinkWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/handlers/deviceLink';
import type { HandlerDeps } from '@/SeamsWeb/walletIframe/host/handlers/walletIframeHandler.types';
import type { LinkedDeviceTargetFactorActivationV1 } from '@/core/types/linkDevice';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

type DeviceLinkCallbacksV1 = {
  readonly onTargetFactorRequired: (activation: LinkedDeviceTargetFactorActivationV1) => void;
};

function buildEmailOtpActivationV1(calls: {
  send: number;
  resend: number;
  submit: string[];
}): Extract<
  LinkedDeviceTargetFactorActivationV1,
  { readonly kind: 'linked_device_target_email_otp_activation_v1' }
> {
  return {
    kind: 'linked_device_target_email_otp_activation_v1',
    state: {
      kind: 'code_input',
      maskedEmailHint: 'a***@example.test',
      expiresAtMs: 10_000,
      resendAvailableAtMs: 2_000,
    },
    sendCode: async () => {
      calls.send += 1;
    },
    resendCode: async () => {
      calls.resend += 1;
    },
    submitCode: async (otpCode) => {
      calls.submit.push(otpCode);
    },
  };
}

test('iframe device-link transport forwards Email OTP activation and exact actions', async () => {
  const fixture = buildR103DeviceLinkFixture({ targetFactor: { kind: 'email_otp' } });
  const progress: unknown[] = [];
  const calls = { send: 0, resend: 0, submit: [] as string[] };
  let callbacks: DeviceLinkCallbacksV1 | null = null;
  const deps: HandlerDeps = {
    getSeamsWeb: () =>
      ({
        devices: {
          startDevice2LinkingFlow: async (input: { options: DeviceLinkCallbacksV1 }) => {
            callbacks = input.options;
            return { qrData: fixture.payload, qrCodeDataURL: 'data:image/png;base64,AA' };
          },
          cancelDeviceLinking: async () => undefined,
        },
      }) as unknown as ReturnType<HandlerDeps['getSeamsWeb']>,
    post: () => undefined,
    postProgress: (_requestId, payload) => {
      progress.push(payload);
    },
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
  const handlers = createDeviceLinkWalletIframeHandlers(deps);
  await handlers.PM_START_DEVICE2_LINKING_FLOW?.({
    type: 'PM_START_DEVICE2_LINKING_FLOW',
    requestId: 'link-request-1',
    payload: { targetFactor: { kind: 'email_otp' } },
  });
  if (!callbacks) throw new Error('device-link callbacks were not installed');
  callbacks.onTargetFactorRequired(buildEmailOtpActivationV1(calls));

  expect(progress.at(-1)).toEqual({
    event: 'wallet_device_link_target_factor_activation_v1',
    activationId: 'link-request-1',
    activation: {
      kind: 'linked_device_target_email_otp_activation_v1',
      state: {
        kind: 'code_input',
        maskedEmailHint: 'a***@example.test',
        expiresAtMs: 10_000,
        resendAvailableAtMs: 2_000,
      },
    },
  });

  await handlers.PM_DEVICE_LINK_TARGET_FACTOR_ACTION?.({
    type: 'PM_DEVICE_LINK_TARGET_FACTOR_ACTION',
    requestId: 'action-1',
    payload: {
      activationId: 'link-request-1',
      action: { kind: 'send_email_otp' },
    },
  });
  await handlers.PM_DEVICE_LINK_TARGET_FACTOR_ACTION?.({
    type: 'PM_DEVICE_LINK_TARGET_FACTOR_ACTION',
    requestId: 'action-2',
    payload: {
      activationId: 'link-request-1',
      action: { kind: 'resend_email_otp' },
    },
  });
  await handlers.PM_DEVICE_LINK_TARGET_FACTOR_ACTION?.({
    type: 'PM_DEVICE_LINK_TARGET_FACTOR_ACTION',
    requestId: 'action-3',
    payload: {
      activationId: 'link-request-1',
      action: { kind: 'submit_email_otp', otpCode: '123456' },
    },
  });

  expect(calls).toEqual({ send: 1, resend: 1, submit: ['123456'] });
});

test('iframe device-link transport rejects an action for another activation', async () => {
  const fixture = buildR103DeviceLinkFixture();
  let callbacks: DeviceLinkCallbacksV1 | null = null;
  const deps: HandlerDeps = {
    getSeamsWeb: () =>
      ({
        devices: {
          startDevice2LinkingFlow: async (input: { options: DeviceLinkCallbacksV1 }) => {
            callbacks = input.options;
            return { qrData: fixture.payload, qrCodeDataURL: 'data:image/png;base64,AA' };
          },
          cancelDeviceLinking: async () => undefined,
        },
      }) as unknown as ReturnType<HandlerDeps['getSeamsWeb']>,
    post: () => undefined,
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
  const handlers = createDeviceLinkWalletIframeHandlers(deps);
  await handlers.PM_START_DEVICE2_LINKING_FLOW?.({
    type: 'PM_START_DEVICE2_LINKING_FLOW',
    requestId: 'link-request-1',
    payload: { targetFactor: { kind: 'passkey_prf' } },
  });
  if (!callbacks) throw new Error('device-link callbacks were not installed');
  callbacks.onTargetFactorRequired({
    kind: 'linked_device_target_passkey_activation_v1',
    createPasskey: async () => undefined,
  });

  await expect(
    handlers.PM_DEVICE_LINK_TARGET_FACTOR_ACTION?.({
      type: 'PM_DEVICE_LINK_TARGET_FACTOR_ACTION',
      requestId: 'action-1',
      payload: {
        activationId: 'another-link-request',
        action: { kind: 'create_passkey' },
      },
    }),
  ).rejects.toThrow('target-factor activation is unavailable');
});
