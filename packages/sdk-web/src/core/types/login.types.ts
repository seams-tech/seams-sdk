import type { LoginHooksOptions } from './sdkSentEvents';

export type LoginUnlockPayloadOption<T> =
  | {
      kind: 'default';
    }
  | {
      kind: 'value';
      value: T;
    };

export type PMUnlockOptions = {
  kind: 'pm_unlock_options_v1';
  signerSlot: LoginUnlockPayloadOption<number>;
  session: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions['session']>>;
  signingSession: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions['signingSession']>>;
  unlockSelection: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions['unlockSelection']>>;
  ecdsaKeyFactsInventory: LoginUnlockPayloadOption<
    NonNullable<LoginHooksOptions['ecdsaKeyFactsInventory']>
  >;
};

export type PMUnlockPayload =
  | {
      kind: 'default_options';
      walletId: string;
    }
  | {
      kind: 'custom_options';
      walletId: string;
      options: PMUnlockOptions;
    };

export type WalletIframeUnlockRequest =
  | {
      kind: 'default_options';
      walletId: string;
    }
  | {
      kind: 'custom_options';
      walletId: string;
      options: LoginHooksOptions;
    };
