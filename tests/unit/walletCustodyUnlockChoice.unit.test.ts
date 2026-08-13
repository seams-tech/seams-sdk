import { expect, test } from '@playwright/test';
import { openOrRejoinWalletCustodyEd25519V1 } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/openCustodyCache';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

/**
 * Which branch an unlock takes, and what it does with the factor secret.
 *
 * The open path is exercised where it belongs — against the wasm module, in
 * the ceremony's own tests. What is worth pinning here is the choice: that a
 * missing row and an unusable row both lead to a rejoin while staying
 * distinguishable, and that the factor secret is not left in a live buffer on
 * the branch where nothing downstream consumes it.
 */

const B64U_32 = 'A'.repeat(43);

const activation = {
  materialActivation: buildMpcMaterialActivationRefFixture('activation-1', 'alice.testnet'),
  lifecycleId: 'lifecycle-1',
  signingRootVersion: '2',
  signingRootId: 'signing-root-1',
  signerSetId: 'signer-set-1',
  thresholdSessionId: 'threshold-session-1',
  activationTranscriptB64u: B64U_32,
  activationCapabilityBindingB64u: B64U_32,
} as never;

const envelope = {
  bindingJson: '{}',
  nonceB64u: 'B'.repeat(16),
  ciphertextB64u: 'C'.repeat(64),
  aadHashB64u: B64U_32,
  ciphertextDigestB64u: B64U_32,
};

test('an absent cache asks for a rejoin and says so plainly', async () => {
  const secret = new Uint8Array([1, 2, 3, 4]);
  const result = await openOrRejoinWalletCustodyEd25519V1({
    loadCachedMaterial: async () => ({ kind: 'absent' }),
    activation,
    envelope,
    ownedFactorSecret: secret,
  });
  expect(result.kind).toBe('rejoin_required');
  if (result.kind !== 'rejoin_required') return;
  expect(result.reason).toContain('no cached custody material');
});

test('an unusable row also rejoins, but keeps its own reason', async () => {
  // Flattening this into the absent message would hide a stale row that will
  // keep failing behind a message that reads like a fresh device.
  const result = await openOrRejoinWalletCustodyEd25519V1({
    loadCachedMaterial: async () => ({
      kind: 'unusable',
      reason: 'cached custody material was sealed under another key',
    }),
    activation,
    envelope,
    ownedFactorSecret: new Uint8Array([1, 2, 3, 4]),
  });
  expect(result.kind).toBe('rejoin_required');
  if (result.kind !== 'rejoin_required') return;
  expect(result.reason).toBe('cached custody material was sealed under another key');
});

test('the factor secret is zeroed on the branch that never reaches wasm', async () => {
  // The callee that normally zeroes it is not reached here, so this path has
  // to do it: a secret that opened nothing should not outlive the attempt.
  const secret = new Uint8Array([9, 9, 9, 9]);
  await openOrRejoinWalletCustodyEd25519V1({
    loadCachedMaterial: async () => ({ kind: 'absent' }),
    activation,
    envelope,
    ownedFactorSecret: secret,
  });
  expect(Array.from(secret)).toEqual([0, 0, 0, 0]);
});
