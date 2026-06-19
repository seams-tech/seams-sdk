import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type {
  LoginUnlockPayloadOption,
  PMUnlockPayload,
  WalletIframeUnlockRequest,
} from '@/core/types/login.types';

export function walletIframeUnlockRequestFromLoginHooks(args: {
  nearAccountId: string;
  options: LoginHooksOptions | undefined;
}): WalletIframeUnlockRequest {
  if (!args.options) return { kind: 'default_options', nearAccountId: args.nearAccountId };
  return {
    kind: 'custom_options',
    nearAccountId: args.nearAccountId,
    options: args.options,
  };
}

export function buildPMUnlockPayload(request: WalletIframeUnlockRequest): PMUnlockPayload {
  switch (request.kind) {
    case 'default_options':
      return {
        kind: 'default_options',
        nearAccountId: request.nearAccountId,
      };
    case 'custom_options':
      return {
        kind: 'custom_options',
        nearAccountId: request.nearAccountId,
        options: {
          kind: 'pm_unlock_options_v1',
          signerSlot: optionFromValue(request.options.signerSlot),
          session: optionFromValue(request.options.session),
          signingSession: optionFromValue(request.options.signingSession),
          unlockSelection: optionFromValue(request.options.unlockSelection),
          ecdsaKeyFactsInventory: optionFromValue(request.options.ecdsaKeyFactsInventory),
        },
      };
  }
}

export function requirePMUnlockPayload(payload: PMUnlockPayload | undefined): PMUnlockPayload {
  if (!payload) throw new Error('PM_UNLOCK payload is required');
  return payload;
}

export function pmUnlockPayloadToLoginHooksOptions(payload: PMUnlockPayload): LoginHooksOptions {
  switch (payload.kind) {
    case 'default_options':
      return {};
    case 'custom_options':
      return {
        ...optionToObject('signerSlot', payload.options.signerSlot),
        ...optionToObject('session', payload.options.session),
        ...optionToObject('signingSession', payload.options.signingSession),
        ...optionToObject('unlockSelection', payload.options.unlockSelection),
        ...optionToObject('ecdsaKeyFactsInventory', payload.options.ecdsaKeyFactsInventory),
      };
  }
}

function optionFromValue<T>(value: T | undefined): LoginUnlockPayloadOption<T> {
  return value === undefined ? { kind: 'default' } : { kind: 'value', value };
}

function optionToObject<K extends keyof LoginHooksOptions>(
  key: K,
  option: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions[K]>>,
): Pick<LoginHooksOptions, K> | Record<string, never> {
  switch (option.kind) {
    case 'default':
      return {};
    case 'value':
      return { [key]: option.value } as Pick<LoginHooksOptions, K>;
  }
}
