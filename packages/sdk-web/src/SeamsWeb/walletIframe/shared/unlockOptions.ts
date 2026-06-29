import type { LoginHooksOptions } from '@/core/types/sdkSentEvents';
import type {
  LoginUnlockRequest,
  LoginUnlockPayloadOption,
  PMUnlockPayload,
} from '@/core/types/login.types';

export function walletIframeUnlockRequestFromLoginHooks(args: {
  walletId: string;
  options: LoginHooksOptions | undefined;
}): LoginUnlockRequest {
  if (!args.options) return { kind: 'default_options', walletId: args.walletId };
  return {
    kind: 'custom_options',
    walletId: args.walletId,
    options: args.options,
  };
}

export function buildPMUnlockPayload(request: LoginUnlockRequest): PMUnlockPayload {
  switch (request.kind) {
    case 'default_options':
      return {
        kind: 'default_options',
        walletId: request.walletId,
      };
    case 'custom_options':
      return {
        kind: 'custom_options',
        walletId: request.walletId,
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
