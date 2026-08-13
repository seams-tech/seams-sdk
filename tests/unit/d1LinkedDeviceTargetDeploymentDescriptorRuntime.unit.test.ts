import { expect, test } from '@playwright/test';
import {
  assertLinkedDeviceTargetSigningWorkerBindingV1,
  buildLinkedDeviceTargetSigningWorkerV1,
  createLinkedDeviceTargetDeploymentDescriptorSignerV1,
  createLinkedDeviceTargetDeploymentDescriptorVerifierV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetDeploymentDescriptorRuntime';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import { buildSigningWorkerParticipantRecordWithDigestV1 } from '../../packages/shared-ts/src/signing-lanes/participantDigest';
import {
  buildSigningWorkerRecipientIdentityV1,
  parseHpkePublicKeyB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
} from '../../packages/shared-ts/src/signing-lanes/participants';

const SECRET = 'descriptor-runtime-secret-with-at-least-32-bytes';
const WORKER_FIELDS = {
  participantId: 'signing-worker:gateway',
  recipientKeyId: 'signing-worker-recipient:gateway',
  hpkePublicKeyB64u: base64UrlEncode(new Uint8Array([1, 2, 3, 4])),
  hpkePublicKeyDigestB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
} as const;

async function workerConfig() {
  const value = <T>(
    result:
      | { readonly ok: true; readonly value: T }
      | { readonly ok: false; readonly error: { readonly message: string } },
  ): T => {
    if (!result.ok) throw new Error(result.error.message);
    return result.value;
  };
  const result = await buildSigningWorkerParticipantRecordWithDigestV1({
    participantId: value(parseSigningWorkerParticipantId(WORKER_FIELDS.participantId)),
    recipient: buildSigningWorkerRecipientIdentityV1({
      recipientKeyId: value(parseSigningWorkerRecipientKeyId(WORKER_FIELDS.recipientKeyId)),
      hpkePublicKeyB64u: value(parseHpkePublicKeyB64u(WORKER_FIELDS.hpkePublicKeyB64u)),
      hpkePublicKeyDigestB64u: value(
        parseSigningWorkerRecipientKeyDigestB64u(WORKER_FIELDS.hpkePublicKeyDigestB64u),
      ),
    }),
  });
  return { ...WORKER_FIELDS, participantBindingDigestB64u: result.participantBindingDigestB64u };
}

test('builds the target worker binding from explicit fields and authenticates HMAC descriptors', async () => {
  const config = await workerConfig();
  const targetSigningWorker = buildLinkedDeviceTargetSigningWorkerV1(config);
  expect(targetSigningWorker.participantId).toBe(config.participantId);
  expect(targetSigningWorker.recipientKeyId).toBe(config.recipientKeyId);
  expect(targetSigningWorker.participantBindingDigestB64u).toHaveLength(43);
  await expect(
    assertLinkedDeviceTargetSigningWorkerBindingV1({
      ...targetSigningWorker,
      hpkePublicKeyDigestB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    }),
  ).rejects.toThrow('hpkePublicKeyDigestB64u does not match its key');

  const unsigned = new TextEncoder().encode('descriptor-runtime-payload');
  const descriptorDigestB64u = parseDigestB64u(base64UrlEncode(await sha256Bytes(unsigned)));
  const signer = createLinkedDeviceTargetDeploymentDescriptorSignerV1({
    descriptorHmacSecret: SECRET,
  });
  const verifier = createLinkedDeviceTargetDeploymentDescriptorVerifierV1({
    descriptorHmacSecret: SECRET,
  });
  const signatureB64u = await signer.signTargetDeploymentDescriptorV1({
    encodedPayload: unsigned,
    descriptorDigestB64u,
    request: {
      kind: 'linked_device_target_deployment_descriptor_request_v1',
      linkSessionId: 'link-session:runtime',
      walletId: 'wallet:runtime',
      walletKeyId: 'wallet-key:runtime',
      enrollmentId: 'linked-enrollment:runtime',
      deviceId: 'linked-device:runtime',
      operationId: 'linked-device-target:runtime',
      childIndex: 0,
      keyFamily: 'ed25519',
      targetLaneId: 'signing-lane:runtime',
      targetLaneShareEpoch: 'epoch:1',
      targetMaterialActivationId: 'linked-device-target-material:runtime',
      targetHolderParticipantId: 'holder:runtime',
      targetPreparationDigestB64u: descriptorDigestB64u,
      registrationDigestB64u: descriptorDigestB64u,
      credentialIdB64u: base64UrlEncode(new Uint8Array([8])),
    },
  });
  expect(signatureB64u).toHaveLength(86);
  expect(
    await verifier.verifyTargetDeploymentDescriptorV1({
      descriptor: {
        signingKeyId: signer.signingKeyId,
      } as never,
      encodedPayload: unsigned,
      descriptorDigestB64u,
    }),
  ).toBe(false);
});

test('requires a dedicated descriptor secret with sufficient entropy', () => {
  expect(() =>
    createLinkedDeviceTargetDeploymentDescriptorSignerV1({ descriptorHmacSecret: '' }),
  ).toThrow('descriptorHmacSecret is required');
  expect(() =>
    createLinkedDeviceTargetDeploymentDescriptorVerifierV1({ descriptorHmacSecret: 'short' }),
  ).toThrow('descriptorHmacSecret must be at least 32 UTF-8 bytes');
});
