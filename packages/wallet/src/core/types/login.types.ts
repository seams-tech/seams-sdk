import type { LoginHooksOptions } from './sdkSentEvents';

export type LoginUnlockPayloadOption<T> =
  | {
      kind: 'default';
    }
  | {
      kind: 'value';
      value: T;
  };

export type PMUnlockEcdsaKeyFactsInventory =
  | {
      mode: 'opaque_wallet_session';
      curve: 'ecdsa_secp256k1';
    }
  | {
      mode: 'webauthn';
    };

export type PMUnlockOptions = {
  kind: 'pm_unlock_options_v1';
  signerSlot: LoginUnlockPayloadOption<number>;
  signingSession: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions['signingSession']>>;
  unlockSelection: LoginUnlockPayloadOption<NonNullable<LoginHooksOptions['unlockSelection']>>;
  ecdsaKeyFactsInventory: LoginUnlockPayloadOption<PMUnlockEcdsaKeyFactsInventory>;
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

export type LoginUnlockRequest =
  | {
      kind: 'default_options';
      walletId: string;
    }
  | {
      kind: 'custom_options';
      walletId: string;
      options: LoginHooksOptions;
    };
