import type { PMUnlockOptions, PMUnlockPayload } from './login.types';

const validUnlockOptions = {
  kind: 'pm_unlock_options_v1',
  signerSlot: { kind: 'default' },
  signingSession: { kind: 'default' },
  unlockSelection: { kind: 'value', value: { mode: 'ecdsa_only', ecdsa: true } },
  ecdsaKeyFactsInventory: { kind: 'value', value: { mode: 'webauthn' } },
} satisfies PMUnlockOptions;
void validUnlockOptions;

const validOpaqueUnlockOptions = {
  kind: 'pm_unlock_options_v1',
  signerSlot: { kind: 'default' },
  signingSession: { kind: 'default' },
  unlockSelection: { kind: 'value', value: { mode: 'ecdsa_only', ecdsa: true } },
  ecdsaKeyFactsInventory: {
    kind: 'value',
    value: { mode: 'wallet_session_operation_credential_v1' },
  },
} satisfies PMUnlockOptions;
void validOpaqueUnlockOptions;

const unlockOptionsMissingInventory = {
  kind: 'pm_unlock_options_v1',
  signerSlot: { kind: 'default' },
  signingSession: { kind: 'default' },
  unlockSelection: { kind: 'default' },
};
// @ts-expect-error PM_UNLOCK options require an explicit inventory branch
unlockOptionsMissingInventory satisfies PMUnlockOptions;

const unlockPayloadMissingOptions = {
  kind: 'custom_options',
  nearAccountId: 'alice.testnet',
};
// @ts-expect-error custom PM_UNLOCK payloads require options
unlockPayloadMissingOptions satisfies PMUnlockPayload;
