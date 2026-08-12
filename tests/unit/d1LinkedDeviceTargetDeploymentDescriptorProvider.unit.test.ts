import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../packages/shared-ts/src/utils/digests';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseLinkedDeviceTargetDeploymentDescriptorRequestV1,
  parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1,
} from '../../packages/shared-ts/src/device-linking/targetDeploymentDescriptor';
import { D1LinkedDeviceTargetDeploymentDescriptorProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetDeploymentDescriptorProvider';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  buildR103DeviceLinkFixture,
  buildR103MixedPlannerFixture,
  buildR103TargetCredentialFixture,
} from './helpers/deviceLinkContracts.fixtures';
import { buildR102LaneJob } from './helpers/r102LaneGateway.fixtures';
import type {
  LinkedDeviceTargetDeploymentDescriptorRequestV1,
  LinkedDeviceTargetDeploymentDescriptorSignerV1,
  LinkedDeviceTargetDeploymentDescriptorVerifierV1,
} from '../../packages/shared-ts/src/device-linking/targetDeploymentDescriptor';

const scope = {
  namespace: 'signer',
  orgId: 'org_target_descriptor',
  projectId: 'project_target_descriptor',
  envId: 'env_target_descriptor',
} as const;

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});

test('allocates and replays one authenticated descriptor without re-running capability allocation', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = buildR103DeviceLinkFixture();
  const target = await buildR103TargetCredentialFixture(fixture);
  const preparationChild = target.preparation.orderedChildren[0];
  if (!preparationChild) throw new Error('fixture target child is missing');
  const registrationDigestB64u = parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(target.registration))),
  );
  const request = parseLinkedDeviceTargetDeploymentDescriptorRequestV1({
    kind: 'linked_device_target_deployment_descriptor_request_v1',
    linkSessionId: fixture.approval.linkSessionId,
    walletId: fixture.approval.walletId,
    walletKeyId: preparationChild.walletKeyId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    operationId: preparationChild.operationId,
    childIndex: 0,
    keyFamily: preparationChild.keyFamily,
    targetLaneId: preparationChild.targetLaneId,
    targetLaneShareEpoch: preparationChild.targetLaneShareEpoch,
    targetMaterialActivationId: preparationChild.targetMaterialActivationId,
    targetHolderParticipantId: preparationChild.targetHolderParticipantId,
    targetPreparationDigestB64u: await digestJson(target.preparation),
    registrationDigestB64u,
    credentialIdB64u: target.registration.webauthnRegistration.credentialIdB64u,
  });
  const targetWorker = buildR102LaneJob('descriptor-worker').targetSigningWorker;
  const signingKeyId = parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1({
    kind: 'linked_device_target_deployment_descriptor_v1',
    descriptorId: 'descriptor-id',
    signingKeyId: 'descriptor-signing-key',
    request,
    keyFamily: 'ed25519',
    targetHolderParticipantId: request.targetHolderParticipantId,
    targetSigningWorker: targetWorker,
    issuedAtMs: 3_010,
    expiresAtMs: 4_000,
    yaoSuiteId: 'yao-suite-descriptor',
    circuitDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(4))),
  }).signingKeyId;
  let signCount = 0;
  let verifyCount = 0;
  let allocateCount = 0;
  const signer: LinkedDeviceTargetDeploymentDescriptorSignerV1 = {
    signingKeyId,
    async signTargetDeploymentDescriptorV1() {
      signCount += 1;
      return base64UrlEncode(new Uint8Array(64).fill(7));
    },
  };
  const verifier: LinkedDeviceTargetDeploymentDescriptorVerifierV1 = {
    async verifyTargetDeploymentDescriptorV1() {
      verifyCount += 1;
      return true;
    },
  };
  const provider = new D1LinkedDeviceTargetDeploymentDescriptorProviderV1({
    database: temporary.database,
    scope,
    targetSigningWorker: targetWorker,
    descriptorSigner: signer,
    descriptorVerifier: verifier,
    ecdsaCapabilityAllocator: {
      async allocateEcdsaTargetCapabilityV1() {
        allocateCount += 1;
        throw new Error('ECDSA allocator should not be called for Ed25519');
      },
    },
    ed25519: {
      yaoSuiteId: 'yao-suite-descriptor',
      circuitDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(4))),
    },
  });
  const first = await provider.resolveTargetDeploymentDescriptorV1({
    request,
    issuedAtMs: 3_010,
    expiresAtMs: 4_000,
  });
  const replay = await provider.resolveTargetDeploymentDescriptorV1({
    request,
    issuedAtMs: 3_011,
    expiresAtMs: 4_000,
  });
  expect(replay).toEqual(first);
  expect(first.request).toEqual(request);
  expect(signCount).toBe(1);
  expect(allocateCount).toBe(0);
  expect(verifyCount).toBe(2);
});

test('allocates ECDSA capability and rejects a tampered persisted signature', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const fixture = await buildR103MixedPlannerFixture();
  const target = fixture.targetCredential;
  const preparationChild = target.preparation.orderedChildren[1];
  const ecdsaJob = fixture.sourceJobs[1];
  if (!preparationChild || ecdsaJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('ECDSA fixture child is missing');
  const registrationDigestB64u = parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(target.registration))),
  );
  const request = parseLinkedDeviceTargetDeploymentDescriptorRequestV1({
    kind: 'linked_device_target_deployment_descriptor_request_v1',
    linkSessionId: fixture.deviceLink.approval.linkSessionId,
    walletId: fixture.deviceLink.approval.walletId,
    walletKeyId: preparationChild.walletKeyId,
    enrollmentId: fixture.deviceLink.approval.enrollmentId,
    deviceId: fixture.deviceLink.approval.deviceId,
    operationId: preparationChild.operationId,
    childIndex: 1,
    keyFamily: 'ecdsa_secp256k1',
    targetLaneId: preparationChild.targetLaneId,
    targetLaneShareEpoch: preparationChild.targetLaneShareEpoch,
    targetMaterialActivationId: preparationChild.targetMaterialActivationId,
    targetHolderParticipantId: preparationChild.targetHolderParticipantId,
    targetPreparationDigestB64u: await digestJson(target.preparation),
    registrationDigestB64u,
    credentialIdB64u: target.registration.webauthnRegistration.credentialIdB64u,
  });
  const validSignature = base64UrlEncode(new Uint8Array(64).fill(8));
  let allocateCount = 0;
  const provider = new D1LinkedDeviceTargetDeploymentDescriptorProviderV1({
    database: temporary.database,
    scope,
    targetSigningWorker: ecdsaJob.targetSigningWorker,
    descriptorSigner: {
      signingKeyId: 'descriptor-signing-key-ecdsa',
      async signTargetDeploymentDescriptorV1() {
        return validSignature;
      },
    },
    descriptorVerifier: {
      async verifyTargetDeploymentDescriptorV1(input) {
        return input.descriptor.signatureB64u === validSignature;
      },
    },
    ecdsaCapabilityAllocator: {
      async allocateEcdsaTargetCapabilityV1() {
        allocateCount += 1;
        return {
          targetCapability: ecdsaJob.targetCapability,
          reshareChannelBindingDigestB64u: parseDigestB64u(
            base64UrlEncode(new Uint8Array(32).fill(12)),
          ),
        };
      },
    },
    ed25519: {
      yaoSuiteId: 'yao-suite-descriptor',
      circuitDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(4))),
    },
  });
  const descriptor = await provider.resolveTargetDeploymentDescriptorV1({
    request,
    issuedAtMs: 3_010,
    expiresAtMs: 4_000,
  });
  expect(descriptor.keyFamily).toBe('ecdsa_secp256k1');
  expect(descriptor.targetCapability).toEqual(ecdsaJob.targetCapability);
  expect(descriptor.reshareChannelBindingDigestB64u).toBe(
    base64UrlEncode(new Uint8Array(32).fill(12)),
  );
  expect(allocateCount).toBe(1);
  await temporary.database
    .prepare(
      `UPDATE linked_device_target_deployment_descriptors
          SET descriptor_json = json_set(descriptor_json, '$.signatureB64u', ?)
        WHERE link_session_id = ? AND child_index = ?`,
    )
    .bind(base64UrlEncode(new Uint8Array(64).fill(9)), String(request.linkSessionId), request.childIndex)
    .run();
  await expect(
    provider.resolveTargetDeploymentDescriptorV1({
      request,
      issuedAtMs: 3_011,
      expiresAtMs: 4_000,
    }),
  ).rejects.toThrow('signature is invalid');
});

async function digestJson(value: unknown) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}
