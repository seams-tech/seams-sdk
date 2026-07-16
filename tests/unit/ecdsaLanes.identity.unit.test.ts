import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildEvmTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  updateResolvedEvmFamilyEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/flows/signEvmFamily/ecdsaLanes';

const walletId = toWalletId('ecdsa-lanes.testnet');
const signingRootId = 'project:dev';
const signingRootVersion = 'default';
const chainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const;
const auth = {
  kind: 'passkey',
  rpId: toRpId('localhost'),
  credentialIdB64u: 'ecdsa-lanes-credential',
} as const;
const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId,
    signingRootVersion,
  }),
  ecdsaThresholdKeyId: 'ederivation-ecdsa-lanes',
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'12'.repeat(20)}`,
});
const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-ecdsa-lanes');

test('updating a resolved ECDSA lane updates the exact lane identity and projections together', () => {
  const initialLane = buildEvmTransactionSigningLane({
    key,
    keyHandle,
    walletId,
    auth,
    chainTarget,
    signingGrantId: 'grant-old',
    thresholdSessionId: 'threshold-old',
  });
  const resolved = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: initialLane,
    chain: 'evm',
    context: 'ecdsa lane identity unit',
  });

  const updated = updateResolvedEvmFamilyEcdsaSigningLaneIdentity({
    lane: resolved,
    chain: 'evm',
    signingGrantId: 'grant-new',
    thresholdSessionId: 'threshold-new',
    context: 'ecdsa lane identity unit',
  });

  expect(String(updated.signingGrantId)).toBe('grant-new');
  expect(String(updated.thresholdSessionId)).toBe('threshold-new');
  expect(String(updated.identity.signingGrantId)).toBe('grant-new');
  expect(String(updated.identity.thresholdSessionId)).toBe('threshold-new');
  expect(updated.identity.signer.key).toBe(key);
  expect(updated.identity.signer.keyHandle).toBe(keyHandle);
});
