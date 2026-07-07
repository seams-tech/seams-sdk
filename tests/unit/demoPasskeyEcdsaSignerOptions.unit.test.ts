import { expect, test } from '@playwright/test';

import { demoPasskeyEcdsaSignerOptions } from '../../apps/seams-site/src/flows/demo/demoPasskeyEcdsaSignerOptions';

test('demo passkey registration enables Tempo and EVM ECDSA provisioning', () => {
  const defaults = {
    tempo: {
      enabled: false,
      signingSession: {
        kind: 'jwt' as const,
        ttlMs: 60_000,
        remainingUses: 2,
      },
    },
    evm: {
      enabled: false,
      signingSession: {
        kind: 'cookie' as const,
        ttlMs: 120_000,
        remainingUses: 3,
      },
    },
  };

  expect(demoPasskeyEcdsaSignerOptions(defaults)).toEqual({
    tempo: {
      enabled: true,
      signingSession: defaults.tempo.signingSession,
    },
    evm: {
      enabled: true,
      signingSession: defaults.evm.signingSession,
    },
  });
});
