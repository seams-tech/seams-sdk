import { expect, test } from '@playwright/test';
import { walletCustodyActiveClientMetadataV1 } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/openCustodyCache';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

/**
 * Where each half of the active-client metadata comes from.
 *
 * The record contributes key identity; the session contributes permission.
 * That split is the invariant: a cached row that carried its own material
 * activation would be a second source for state Refactor 90 owns, and it
 * would outlive the operation it was minted for — the row survives across
 * sessions and the authorization it described does not.
 *
 * So these tests assert *provenance*, not just shape.
 */

const B64U_32 = 'A'.repeat(43);

const material = {
  binding: {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: B64U_32,
    registeredPublicKeyB64u: B64U_32,
    participantIds: [1, 2],
    stateEpoch: '7',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    signerSlot: 3,
    signingWorkerId: 'signing-worker-1',
    signingWorkerVerifyingShareB64u: B64U_32,
  },
  sealed: { ciphertextB64u: 'B'.repeat(64), nonceB64u: 'C'.repeat(16) },
} as never;

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

test('key identity comes from the cached record', () => {
  const metadata = walletCustodyActiveClientMetadataV1({ material, activation });
  expect(metadata.scope.account_id).toBe('alice.testnet');
  expect(metadata.scope.signing_worker_id).toBe('signing-worker-1');
  expect(metadata.applicationBinding.near_ed25519_signing_key_id).toBe('near-ed25519-key-1');
  expect(metadata.applicationBinding.key_creation_signer_slot).toBe(3);
  expect(metadata.stateEpoch).toBe(7n);
  expect(metadata.participantIds).toEqual([1, 2]);
});

test('permission comes from the session, never the record', () => {
  const metadata = walletCustodyActiveClientMetadataV1({ material, activation });
  // Each of these would be a second owner for Refactor 90 state if it were
  // read from the cached row instead.
  expect(metadata.materialActivation).toBe(activation.materialActivation);
  expect(metadata.scope.lifecycle_id).toBe('lifecycle-1');
  expect(metadata.scope.threshold_session_id).toBe('threshold-session-1');
  expect(metadata.scope.signer_set_id).toBe('signer-set-1');
  expect(metadata.scope.root_share_epoch).toBe('2');
  expect(metadata.applicationBinding.signing_root_id).toBe('signing-root-1');
});

test('a second session produces different permission over the same key', () => {
  // The same cached row, re-used under a new activation. If any permission
  // field tracked the row, this would come back with the first session's.
  const second = walletCustodyActiveClientMetadataV1({
    material,
    activation: {
      ...(activation as object),
      materialActivation: buildMpcMaterialActivationRefFixture('activation-2', 'alice.testnet'),
      lifecycleId: 'lifecycle-2',
      thresholdSessionId: 'threshold-session-2',
    } as never,
  });
  expect(second.scope.lifecycle_id).toBe('lifecycle-2');
  expect(second.scope.threshold_session_id).toBe('threshold-session-2');
  // ...while the key identity is unchanged.
  expect(second.applicationBinding.near_ed25519_signing_key_id).toBe('near-ed25519-key-1');
  expect(second.stateEpoch).toBe(7n);
});
