import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceEcdsaNormalSigningScopeV1,
  parseLinkedDeviceEcdsaNormalSigningScopeV1,
} from '../../packages/shared-ts/src/signing-lanes/linkedEcdsaScope';

const digest = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const point = 'Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY';

function validScopeRecord(): Record<string, unknown> {
  return {
    kind: 'linked_device_ecdsa_normal_signing_scope_v1',
    keyFamily: 'ecdsa_secp256k1',
    laneKind: 'linked_device',
    walletId: 'wallet:r102',
    walletKeyId: 'wallet-key:r102',
    enrollmentId: 'enrollment:r102',
    operationId: 'operation:r102',
    laneId: 'lane:r102',
    laneShareEpoch: 'epoch:r102',
    revocationEpoch: 0,
    targetMaterialActivationId: 'target-activation:r102',
    materialActivation: {
      kind: 'mpc_material_activation_ref',
      activationId: 'target-activation:r102',
      capability: 'capability:r102',
      materialOwner: 'wallet:r102',
      keyBinding: 'key-binding:r102',
      lifecycleBinding: 'lifecycle-binding:r102',
      signingWorker: 'signing-worker:r102',
    },
    ecdsaThresholdKeyId: 'threshold-key-r102',
    thresholdPublicKey33B64u: point,
    evmAddress: '0x0000000000000000000000000000000000000001',
    publicIdentityDigestB64u: digest,
    targetHolderPublicCommitmentB64u: point,
    targetServerPublicCommitmentB64u: point,
    holderParticipantId: 'holder-r102',
    signingWorkerParticipantId: 'worker-r102',
    holderParticipantBindingDigestB64u: digest,
    signingWorkerParticipantBindingDigestB64u: digest,
    holderRecipientKeyDigestB64u: digest,
    serverRecipientKeyDigestB64u: digest,
    signingWorkerRecipientKeyId: 'worker-key-r102',
    transcriptHashB64u: digest,
    protocolCommitReceiptDigestB64u: digest,
  };
}

test('parses the exact linked ECDSA lane scope and rebuilds it', () => {
  const parsed = parseLinkedDeviceEcdsaNormalSigningScopeV1(validScopeRecord());
  const rebuilt = buildLinkedDeviceEcdsaNormalSigningScopeV1(parsed);

  expect(rebuilt).toEqual(parsed);
  expect(rebuilt).not.toHaveProperty('signingRootId');
  expect(rebuilt).not.toHaveProperty('publicIdentity');
});

test('rejects owner-root and owner public-identity fields at the wire boundary', () => {
  const withRoot = { ...validScopeRecord(), signingRootId: 'owner-root:r102' };
  const withPublicIdentity = {
    ...validScopeRecord(),
    publicIdentity: { threshold_public_key33_b64u: point },
  };

  expect(() => parseLinkedDeviceEcdsaNormalSigningScopeV1(withRoot)).toThrow('fields are invalid');
  expect(() => parseLinkedDeviceEcdsaNormalSigningScopeV1(withPublicIdentity)).toThrow(
    'fields are invalid',
  );
});

test('rejects activation substitution and non-linked discriminators', () => {
  const activationMismatch = {
    ...validScopeRecord(),
    targetMaterialActivationId: 'target-activation:other',
  };
  const wrongCurve = { ...validScopeRecord(), keyFamily: 'ed25519' };

  expect(() => parseLinkedDeviceEcdsaNormalSigningScopeV1(activationMismatch)).toThrow(
    'activation id does not match material activation',
  );
  expect(() => parseLinkedDeviceEcdsaNormalSigningScopeV1(wrongCurve)).toThrow(
    'discriminator is invalid',
  );
});
