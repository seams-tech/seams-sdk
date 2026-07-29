import { expect, test } from '@playwright/test';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { deriveEcdsaPostRegistrationSigningGrantId } from '../../packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

function requireMintId(value: string) {
  const parsed = parseReusableWalletSessionMintId(value);
  if (!parsed.ok) throw new Error('Wallet Session mint fixture is invalid');
  return parsed.value;
}

test('derives a stable signing grant distinct from the Wallet Session mint identity', async () => {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'mint-grant.testnet',
    chain: 'evm',
  });
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding || binding.materialKind !== 'role_local_worker_handle') {
    throw new Error('expected passkey ECDSA role-local fixture');
  }
  const mintId = requireMintId('wallet-session-mint-stable');
  const input = {
    mintId,
    walletId: walletIdFromString(String(binding.publicFacts.walletId)),
    publicCapability: binding.publicFacts.publicCapability,
  };

  const first = await deriveEcdsaPostRegistrationSigningGrantId(input);
  const retry = await deriveEcdsaPostRegistrationSigningGrantId(input);
  const otherMint = await deriveEcdsaPostRegistrationSigningGrantId({
    ...input,
    mintId: requireMintId('wallet-session-mint-other'),
  });

  expect(first).toBe(retry);
  expect(first).not.toBe(mintId);
  expect(otherMint).not.toBe(first);
});
