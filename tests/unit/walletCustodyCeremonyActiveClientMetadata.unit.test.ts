import { expect, test } from '@playwright/test';
import { walletCustodyEd25519ActiveClientMetadataV1 } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/ceremonyActiveClientMetadata';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

/**
 * Rebuilding the active-client metadata for a key set the ceremony registered.
 *
 * The PRF path read this off the live client it kept. A ceremony keeps none, so
 * the metadata is rebuilt from the admission request the run registered under
 * and the Router's activation result. The property that matters: every identity
 * comes from the Router's receipt, not from this side — `materialActivation`
 * especially, since minting one locally would be a second owner for state
 * Refactor 90 owns.
 */

function fixture() {
  const built = buildEd25519YaoCapabilityFixture({
    walletId: walletIdFromString('alice.testnet'),
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    signingWorkerId: 'signing-worker-1',
    participantIds: [1, 2],
    runtimePolicyScope: {
      namespace: 'ns',
      orgId: 'org',
      projectId: 'project',
      envId: 'env',
      signingRootVersion: 'root-v1',
    },
    seed: 77,
  });
  if (built.capability.version !== 'wallet_ed25519_yao_registration_capability_v1') {
    throw new Error('fixture must build a registration capability');
  }
  return built.capability;
}

test('every identity comes from the Router receipt', () => {
  const capability = fixture();
  const metadata = walletCustodyEd25519ActiveClientMetadataV1({
    admissionRequest: capability.admissionRequest,
    activationResultJson: JSON.stringify(capability.activationResult),
  });

  const receipt = capability.activationResult.public_receipt;
  expect([...metadata.registeredPublicKey]).toEqual(receipt.registered_public_key);
  expect([...metadata.signingWorkerVerifyingShare]).toEqual(receipt.signing_worker_verifying_share);
  expect([...metadata.transcript]).toEqual(receipt.transcript);
  expect(metadata.stateEpoch).toBe(BigInt(receipt.state_epoch));
  expect(metadata.activeCapabilityBinding).toEqual(capability.activationResult.binding.session_id);
  // The Refactor 90 identity, minted by the Router and never here.
  expect(metadata.materialActivation.activationId).toBe(receipt.material_activation.activation_id);
});

test('the scope and application binding are the ones this run registered under', () => {
  const capability = fixture();
  const metadata = walletCustodyEd25519ActiveClientMetadataV1({
    admissionRequest: capability.admissionRequest,
    activationResultJson: JSON.stringify(capability.activationResult),
  });

  expect(metadata.scope).toEqual(capability.admissionRequest.scope);
  expect(metadata.applicationBinding).toEqual(capability.admissionRequest.application_binding);
  expect(metadata.participantIds).toEqual([1, 2]);
});

test('a result for another lifecycle is refused before anything is built from it', () => {
  /* Without this, a wallet would take metadata describing someone else's key
     and every record built below would carry it. */
  const capability = fixture();
  const foreign = {
    ...capability.activationResult,
    binding: {
      ...capability.activationResult.binding,
      lifecycle: {
        ...capability.activationResult.binding.lifecycle,
        lifecycle_id: 'another-ceremony',
      },
    },
  };

  expect(() =>
    walletCustodyEd25519ActiveClientMetadataV1({
      admissionRequest: capability.admissionRequest,
      activationResultJson: JSON.stringify(foreign),
    }),
  ).toThrow(/another lifecycle/);
});

test('a malformed result is refused rather than partially read', () => {
  const capability = fixture();
  for (const json of ['not json', '{}', '{"binding":{}}']) {
    expect(() =>
      walletCustodyEd25519ActiveClientMetadataV1({
        admissionRequest: capability.admissionRequest,
        activationResultJson: json,
      }),
    ).toThrow();
  }
});
