import { expect, test } from '@playwright/test';
import {
  buildPMUnlockPayload,
  pmUnlockPayloadToLoginHooksOptions,
} from '@/SeamsWeb/walletIframe/shared/unlockOptions';

test('wallet iframe PM_UNLOCK forwards explicit unlock options', () => {
  const payload = buildPMUnlockPayload({
    kind: 'custom_options',
    nearAccountId: 'alice.testnet',
    options: {
      signerSlot: 2,
      session: {
        kind: 'jwt',
        relayUrl: 'https://relay.example.test',
        route: '/session/exchange',
      },
      signingSession: {
        ttlMs: 90_000,
        remainingUses: 2,
      },
      unlockSelection: {
        mode: 'ecdsa_only',
        ecdsa: true,
      },
      ecdsaKeyFactsInventory: {
        mode: 'app_session',
        appSessionJwt: 'app-session-jwt',
        policyTtlMs: 45_000,
      },
    },
  });

  expect(payload).toEqual({
    kind: 'custom_options',
    nearAccountId: 'alice.testnet',
    options: {
      kind: 'pm_unlock_options_v1',
      signerSlot: { kind: 'value', value: 2 },
      session: {
        kind: 'value',
        value: {
          kind: 'jwt',
          relayUrl: 'https://relay.example.test',
          route: '/session/exchange',
        },
      },
      signingSession: { kind: 'value', value: { ttlMs: 90_000, remainingUses: 2 } },
      unlockSelection: { kind: 'value', value: { mode: 'ecdsa_only', ecdsa: true } },
      ecdsaKeyFactsInventory: {
        kind: 'value',
        value: {
          mode: 'app_session',
          appSessionJwt: 'app-session-jwt',
          policyTtlMs: 45_000,
        },
      },
    },
  });

  expect(pmUnlockPayloadToLoginHooksOptions(payload)).toEqual({
    signerSlot: 2,
    session: {
      kind: 'jwt',
      relayUrl: 'https://relay.example.test',
      route: '/session/exchange',
    },
    signingSession: {
      ttlMs: 90_000,
      remainingUses: 2,
    },
    unlockSelection: {
      mode: 'ecdsa_only',
      ecdsa: true,
    },
    ecdsaKeyFactsInventory: {
      mode: 'app_session',
      appSessionJwt: 'app-session-jwt',
      policyTtlMs: 45_000,
    },
  });
});
