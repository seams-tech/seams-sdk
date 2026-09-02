import { expect, test } from '@playwright/test';
import { establishPasskeyRegistrationEd25519ExportRootCapability } from '../../packages/wallet/src/SeamsWeb/operations/registration/registration';
import type { RegistrationWebContext } from '../../packages/wallet/src/SeamsWeb/signingSurface/types';
import { buildWalletCustodyCommitPayloadFixture } from './helpers/passkeyCustodyEnvelope.fixtures';

test('establishes the zero-prompt Ed25519 export-root capability after passkey registration', async () => {
  type EstablishInput = Parameters<
    RegistrationWebContext['signingEngine']['establishUnlockedWalletEd25519ExportRootCapabilityV1']
  >[0];
  let received: EstablishInput | null = null;
  const signingEngine: Pick<
    RegistrationWebContext['signingEngine'],
    'establishUnlockedWalletEd25519ExportRootCapabilityV1'
  > = {
    establishUnlockedWalletEd25519ExportRootCapabilityV1: async (input) => {
      received = input;
    },
  };
  const expiresAtMs = Date.now() + 60_000;

  await establishPasskeyRegistrationEd25519ExportRootCapability({
    signingEngine,
    commit: buildWalletCustodyCommitPayloadFixture({ walletId: 'alice.testnet' }),
    passkeyPrfFirstB64u: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA',
    walletId: 'alice.testnet',
    walletAuthMethodId: 'wallet-auth-method:registration',
    walletSessionId: 'wallet-session:registration',
    expiresAtMs,
  });

  if (!received) throw new Error('registration did not establish an export-root capability');
  expect(received.walletId).toBe('alice.testnet');
  expect(received.walletAuthMethodId).toBe('wallet-auth-method:registration');
  expect(received.walletSessionId).toBe('wallet-session:registration');
  expect(received.expiresAtMs).toBe(expiresAtMs);
  expect(received.existingEnvelope.walletId).toBe('alice.testnet');
  expect(received.existingEnvelope.factor.kind).toBe('passkey');
});
