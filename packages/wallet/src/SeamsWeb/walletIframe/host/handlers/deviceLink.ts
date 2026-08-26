import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOk, respondOkResult, withProgress } from './shared';
import {
  LinkedDeviceEmailOtpBaseFactorChoiceV1,
  parseLinkedDeviceListRequestV1,
  parseLinkedDeviceListResultV1,
  parseLinkedDeviceRevokeRequestV1,
  parseLinkedDeviceRevokeResultV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { LinkedDeviceTargetFactorActivationV1 } from '@/core/types/linkDevice';
import { classifyLinkDeviceFlowEvent, type LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  DeviceLinkEmailOtpBaseFactorActionPayloadV1,
  DeviceLinkTargetFactorActionV1,
  DeviceLinkTargetFactorActivationProgressV1,
} from '../../shared/messages';
import {
  parseDeviceLinkEmailOtpBaseFactorActionPayloadV1,
  parseDeviceLinkTargetFactorActionPayloadV1,
} from '../../shared/messages';

type ActiveDeviceLinkTargetFactorV1 = {
  readonly activationId: string;
  readonly activation: LinkedDeviceTargetFactorActivationV1;
};

type ActiveDeviceLinkTargetFactorStoreV1 = {
  current: ActiveDeviceLinkTargetFactorV1 | null;
};

type PendingEmailOtpBaseFactorSelectionV1 = {
  readonly choices: readonly [
    LinkedDeviceEmailOtpBaseFactorChoiceV1,
    ...LinkedDeviceEmailOtpBaseFactorChoiceV1[],
  ];
  readonly resolve: (
    baseWalletAuthMethodId: LinkedDeviceEmailOtpBaseFactorChoiceV1['baseWalletAuthMethodId'],
  ) => void;
  readonly reject: (reason?: unknown) => void;
};

type PendingEmailOtpBaseFactorSelectionStoreV1 = Map<string, PendingEmailOtpBaseFactorSelectionV1>;

function waitForEmailOtpBaseFactorSelectionV1(
  store: PendingEmailOtpBaseFactorSelectionStoreV1,
  deps: Pick<HandlerDeps, 'postProgress'>,
  requestId: string | undefined,
  choices: readonly [
    LinkedDeviceEmailOtpBaseFactorChoiceV1,
    ...LinkedDeviceEmailOtpBaseFactorChoiceV1[],
  ],
): Promise<LinkedDeviceEmailOtpBaseFactorChoiceV1['baseWalletAuthMethodId']> {
  if (!requestId) return Promise.reject(new Error('Device-link request id is required'));
  const previous = store.get(requestId);
  previous?.reject(new Error('A newer Email OTP method selection is required'));
  return new Promise((resolve, reject) => {
    store.set(requestId, { choices, resolve, reject });
    deps.postProgress(requestId, {
      event: 'wallet_device_link_email_otp_base_factor_selection_required_v1',
      choices,
    });
  });
}

function cancelPendingEmailOtpBaseFactorSelectionV1(
  store: PendingEmailOtpBaseFactorSelectionStoreV1,
  requestId: string | undefined,
  reason: Error,
): void {
  if (!requestId) return;
  const pending = store.get(requestId);
  if (!pending) return;
  store.delete(requestId);
  pending.reject(reason);
}

function resolveEmailOtpBaseFactorSelectionV1(
  store: PendingEmailOtpBaseFactorSelectionStoreV1,
  payload: DeviceLinkEmailOtpBaseFactorActionPayloadV1,
): void {
  const pending = store.get(payload.scanRequestId);
  if (!pending) throw new Error('Email OTP method selection is unavailable');
  switch (payload.action.kind) {
    case 'cancel':
      store.delete(payload.scanRequestId);
      pending.reject(new Error('Device linking was cancelled'));
      return;
    case 'select': {
      const selectedBaseWalletAuthMethodId = payload.action.baseWalletAuthMethodId;
      if (
        !pending.choices.some(
          (choice) => choice.baseWalletAuthMethodId === selectedBaseWalletAuthMethodId,
        )
      ) {
        throw new Error('The selected Email OTP method is unavailable for this linked device');
      }
      store.delete(payload.scanRequestId);
      pending.resolve(selectedBaseWalletAuthMethodId);
      return;
    }
    default:
      payload.action satisfies never;
      throw new Error('Unsupported Email OTP method selection action');
  }
}

function targetFactorProgressV1(
  active: ActiveDeviceLinkTargetFactorV1,
): DeviceLinkTargetFactorActivationProgressV1 {
  switch (active.activation.kind) {
    case 'linked_device_target_passkey_activation_v1':
      return {
        event: 'wallet_device_link_target_factor_activation_v1',
        activationId: active.activationId,
        activation: { kind: active.activation.kind },
      };
    case 'linked_device_target_email_otp_activation_v1':
      return {
        event: 'wallet_device_link_target_factor_activation_v1',
        activationId: active.activationId,
        activation: {
          kind: active.activation.kind,
          state: active.activation.state,
        },
      };
    default:
      active.activation satisfies never;
      throw new Error('Unsupported linked-device target-factor activation');
  }
}

async function performTargetFactorActionV1(input: {
  readonly active: ActiveDeviceLinkTargetFactorV1;
  readonly action: DeviceLinkTargetFactorActionV1;
}): Promise<void> {
  switch (input.action.kind) {
    case 'create_passkey':
      if (input.active.activation.kind !== 'linked_device_target_passkey_activation_v1') {
        throw new Error('linked-device Passkey activation is unavailable');
      }
      await input.active.activation.createPasskey();
      return;
    case 'send_email_otp':
      if (input.active.activation.kind !== 'linked_device_target_email_otp_activation_v1') {
        throw new Error('linked-device Email OTP activation is unavailable');
      }
      await input.active.activation.sendCode();
      return;
    case 'resend_email_otp':
      if (input.active.activation.kind !== 'linked_device_target_email_otp_activation_v1') {
        throw new Error('linked-device Email OTP activation is unavailable');
      }
      await input.active.activation.resendCode();
      return;
    case 'submit_email_otp':
      if (input.active.activation.kind !== 'linked_device_target_email_otp_activation_v1') {
        throw new Error('linked-device Email OTP activation is unavailable');
      }
      await input.active.activation.submitCode(input.action.otpCode);
      return;
    default:
      input.action satisfies never;
      throw new Error('Unsupported linked-device target-factor action');
  }
}

function publishTargetFactorActivationV1(
  store: ActiveDeviceLinkTargetFactorStoreV1,
  deps: Pick<HandlerDeps, 'postProgress'>,
  requestId: string | undefined,
  activationId: string,
  activation: LinkedDeviceTargetFactorActivationV1,
): void {
  store.current = { activationId, activation };
  deps.postProgress(requestId, targetFactorProgressV1(store.current));
}

function forwardDeviceLinkEventV1(
  store: ActiveDeviceLinkTargetFactorStoreV1,
  deps: Pick<HandlerDeps, 'postProgress'>,
  requestId: string | undefined,
  event: LinkDeviceFlowEvent,
): void {
  deps.postProgress(requestId, event);
  const outcome = classifyLinkDeviceFlowEvent(event);
  if (
    outcome.kind === 'active' ||
    outcome.kind === 'failed' ||
    outcome.kind === 'invalid_active' ||
    outcome.kind === 'cancelled'
  ) {
    store.current = null;
  }
}

export function createDeviceLinkWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  const activeTargetFactor: ActiveDeviceLinkTargetFactorStoreV1 = { current: null };
  const pendingEmailOtpBaseFactorSelections: PendingEmailOtpBaseFactorSelectionStoreV1 = new Map();
  return {
    PM_START_DEVICE2_LINKING_FLOW: async (req: Req<'PM_START_DEVICE2_LINKING_FLOW'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_START_DEVICE2_LINKING_FLOW requires a payload');
      const { targetFactor, ui, cameraId, options } = payload;
      if (deps.respondIfCancelled(req.requestId)) return;
      const activationId = String(req.requestId || '').trim();
      if (!activationId) throw new Error('Device-link target-factor activation id is required');
      const result = await pm.devices.startDevice2LinkingFlow({
        targetFactor,
        ...(ui ? { ui } : {}),
        ...(cameraId ? { cameraId } : {}),
        options: {
          ...(options || {}),
          onEvent: forwardDeviceLinkEventV1.bind(null, activeTargetFactor, deps, req.requestId),
          onTargetFactorRequired: publishTargetFactorActivationV1.bind(
            null,
            activeTargetFactor,
            deps,
            req.requestId,
            activationId,
          ),
        },
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, result);
    },

    PM_DEVICE_LINK_TARGET_FACTOR_ACTION: async (
      req: Req<'PM_DEVICE_LINK_TARGET_FACTOR_ACTION'>,
    ) => {
      const payload = parseDeviceLinkTargetFactorActionPayloadV1(req.payload);
      if (!payload) throw new Error('PM_DEVICE_LINK_TARGET_FACTOR_ACTION payload is invalid');
      const active = activeTargetFactor.current;
      if (!active || active.activationId !== payload.activationId) {
        throw new Error('linked-device target-factor activation is unavailable');
      }
      await performTargetFactorActionV1({ active, action: payload.action });
      respondOk(deps, req.requestId);
    },

    PM_DEVICE_LINK_EMAIL_OTP_BASE_FACTOR_ACTION: async (
      req: Req<'PM_DEVICE_LINK_EMAIL_OTP_BASE_FACTOR_ACTION'>,
    ) => {
      const payload = parseDeviceLinkEmailOtpBaseFactorActionPayloadV1(req.payload);
      if (!payload) throw new Error('Email OTP method selection payload is invalid');
      resolveEmailOtpBaseFactorSelectionV1(pendingEmailOtpBaseFactorSelections, payload);
      respondOk(deps, req.requestId);
    },

    PM_CANCEL_DEVICE_LINKING: async (req: Req<'PM_CANCEL_DEVICE_LINKING'>) => {
      const pm = deps.getSeamsWeb();
      if (deps.respondIfCancelled(req.requestId)) return;
      await pm.devices.cancelDeviceLinking();
      activeTargetFactor.current = null;
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOk(deps, req.requestId);
    },

    PM_SCAN_AND_LINK_DEVICE: async (req: Req<'PM_SCAN_AND_LINK_DEVICE'>) => {
      const pm = deps.getSeamsWeb();
      const { qrData, options } = req.payload!;
      if (deps.respondIfCancelled(req.requestId)) return;
      try {
        const result = await pm.devices.scanAndLinkDevice(
          parseQrLinkedDeviceSessionPayloadV5(qrData),
          {
            ...withProgress(deps, req.requestId, options || {}),
            onEmailOtpBaseFactorRequired: (choices) =>
              waitForEmailOtpBaseFactorSelectionV1(
                pendingEmailOtpBaseFactorSelections,
                deps,
                req.requestId,
                choices,
              ),
          },
        );
        if (deps.respondIfCancelled(req.requestId)) return;
        respondOkResult(deps, req.requestId, result);
      } finally {
        cancelPendingEmailOtpBaseFactorSelectionV1(
          pendingEmailOtpBaseFactorSelections,
          req.requestId,
          new Error('Device-link request ended before Email OTP method selection completed'),
        );
      }
    },

    PM_HAS_PASSKEY: async (req: Req<'PM_HAS_PASSKEY'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId } = req.payload!;
      const result = await pm.auth.hasPasskeyCredential(walletId);
      respondOkResult(deps, req.requestId, result);
    },

    PM_LIST_LINKED_DEVICES: async (req: Req<'PM_LIST_LINKED_DEVICES'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_LIST_LINKED_DEVICES requires a payload');
      const request = parseLinkedDeviceListRequestV1({
        kind: 'linked_device_list_request_v1',
        walletId: payload.walletId,
        limit: payload.limit,
        cursor: payload.cursor,
      });
      const result = await pm.devices.listLinkedDevices({
        walletId: String(request.walletId),
        limit: request.limit,
        cursor: request.cursor,
      });
      respondOkResult(deps, req.requestId, parseLinkedDeviceListResultV1(result));
    },

    PM_REVOKE_LINKED_DEVICE: async (req: Req<'PM_REVOKE_LINKED_DEVICE'>) => {
      const pm = deps.getSeamsWeb();
      const payload = req.payload;
      if (!payload) throw new Error('PM_REVOKE_LINKED_DEVICE requires a payload');
      if (deps.respondIfCancelled(req.requestId)) return;
      const request = parseLinkedDeviceRevokeRequestV1({
        kind: 'linked_device_revoke_request_v1',
        walletId: payload.walletId,
        walletAuthMethodId: payload.walletAuthMethodId,
        requestedAtMs: payload.requestedAtMs,
      });
      const result = await pm.devices.revokeLinkedDevice({
        walletId: String(request.walletId),
        walletAuthMethodId: String(request.walletAuthMethodId),
        requestedAtMs: request.requestedAtMs,
        sourceProof: payload.sourceProof,
      });
      if (deps.respondIfCancelled(req.requestId)) return;
      respondOkResult(deps, req.requestId, parseLinkedDeviceRevokeResultV1(result));
    },
  };
}
