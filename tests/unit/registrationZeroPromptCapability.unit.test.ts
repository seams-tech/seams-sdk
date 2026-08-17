import { expect, test } from '@playwright/test';
import {
  establishPasskeyRegistrationCustodyTransferCapability,
} from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import type { RegistrationWebContext } from '../../packages/sdk-web/src/SeamsWeb/signingSurface/types';
import { buildWalletCustodyCommitPayloadFixture } from './helpers/passkeyCustodyEnvelope.fixtures';

test('establishes the zero-prompt capability after passkey ECDSA registration', async () => {
  type EstablishInput = Parameters<
    RegistrationWebContext['signingEngine']['establishUnlockedWalletCustodyTransferCapabilityV1']
  >[0];
  let received: EstablishInput | null = null;
  const signingEngine: Pick<
    RegistrationWebContext['signingEngine'],
    'establishUnlockedWalletCustodyTransferCapabilityV1'
  > = {
    establishUnlockedWalletCustodyTransferCapabilityV1: async (input) => {
      received = input;
    },
  };
  const expiresAtMs = Date.now() + 60_000;

  await establishPasskeyRegistrationCustodyTransferCapability({
    signingEngine,
    commit: buildWalletCustodyCommitPayloadFixture({ walletId: 'alice.testnet' }),
    passkeyPrfFirstB64u: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA',
    walletId: 'alice.testnet',
    walletSessionId: 'wallet-session:registration',
    expiresAtMs,
  });

  if (!received) throw new Error('registration did not establish a custody capability');
  expect(received.walletId).toBe('alice.testnet');
  expect(received.walletSessionId).toBe('wallet-session:registration');
  expect(received.expiresAtMs).toBe(expiresAtMs);
  expect(received.existingEnvelope.walletId).toBe('alice.testnet');
  expect(received.existingEnvelope.factor.kind).toBe('passkey');
});
