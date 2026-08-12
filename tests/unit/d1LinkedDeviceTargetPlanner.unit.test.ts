import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RotatableSigningLaneJobV1 } from '@shared/signing-lanes/rotation';
import type { LinkedDeviceTargetDeploymentDescriptorRequestV1 } from '@shared/device-linking/targetDeploymentDescriptor';
import {
  buildLinkedDeviceTargetDeploymentDescriptorV1,
  buildLinkedDeviceTargetDeploymentDescriptorRequestV1,
} from '@shared/device-linking/targetDeploymentDescriptor';
import { D1LinkedDeviceTargetPlannerV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetPlanner';
import type { VerifiedLinkedDeviceWebAuthnCredentialV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import {
  buildR103MixedPlannerFixture,
  buildR103ActiveExecutionFixture,
  buildR103ProvisioningFixture,
} from './helpers/deviceLinkContracts.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function registrationDigestV1(registration: unknown) {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `seams/r103/target-credential/v1\u0000${alphabetizeStringify(registration)}`,
      ),
    ),
  );
}

async function targetDescriptorProviderV1(sourceJobs: readonly RotatableSigningLaneJobV1[]) {
  return {
    async resolveTargetDeploymentDescriptorV1(input: {
      request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
      issuedAtMs: number;
      expiresAtMs: number;
    }) {
      const request = buildLinkedDeviceTargetDeploymentDescriptorRequestV1(input.request);
      const sourceJob = sourceJobs[request.childIndex];
      if (!sourceJob || sourceJob.keyFamily !== request.keyFamily) {
        throw new Error(`descriptor fixture child ${request.childIndex} is missing`);
      }
      const unsigned =
        request.keyFamily === 'ed25519'
          ? {
              kind: 'linked_device_target_deployment_descriptor_v1' as const,
              descriptorId: `descriptor-${request.childIndex}`,
              signingKeyId: 'descriptor-test-key',
              request,
              keyFamily: 'ed25519' as const,
              targetHolderParticipantId: request.targetHolderParticipantId,
              targetSigningWorker: sourceJob.targetSigningWorker,
              issuedAtMs: input.issuedAtMs,
              expiresAtMs: input.expiresAtMs,
              yaoSuiteId: sourceJob.yaoSuiteId,
              circuitDigestB64u: sourceJob.circuitDigestB64u,
            }
          : {
              kind: 'linked_device_target_deployment_descriptor_v1' as const,
              descriptorId: `descriptor-${request.childIndex}`,
              signingKeyId: 'descriptor-test-key',
              request,
              keyFamily: 'ecdsa_secp256k1' as const,
              targetHolderParticipantId: request.targetHolderParticipantId,
              targetSigningWorker: sourceJob.targetSigningWorker,
              issuedAtMs: input.issuedAtMs,
              expiresAtMs: input.expiresAtMs,
              targetCapability: sourceJob.targetCapability,
              reshareChannelBindingDigestB64u: sourceJob.reshareChannelBindingDigestB64u,
            };
      return buildLinkedDeviceTargetDeploymentDescriptorV1({
        ...unsigned,
        signatureB64u: base64UrlEncode(new Uint8Array(64).fill(7)),
      });
    },
  };
}

test('creates exact R102 target jobs from owner source resolution', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const provisioning = buildR103ProvisioningFixture(fixture.deviceLink);
  const sourceJob = provisioning.deliveries.orderedChildren[0]?.job;
  if (!sourceJob) throw new Error('R103 fixture did not contain a source job');
  const authorizedOperationId = required(
    parseAuthorizedOperationId(String(fixture.deviceLink.approval.operationId)),
  );
  const planner = new D1LinkedDeviceTargetPlannerV1({
    rpId: required(parseWebAuthnRpId('wallet.example.test')),
    targetDeploymentDescriptorProvider: await targetDescriptorProviderV1([sourceJob, sourceJob]),
    resolveOwnerSourceChildV1: async () => ({
      keyFamily: 'ed25519',
      walletKeyId: sourceJob.walletKeyId,
      source: sourceJob.source,
      authorization: {
        authorizedOperationId,
        idempotencyKey: fixture.deviceLink.approval.idempotencyKey,
        linkedDevicePermissionDigestB64u: fixture.deviceLink.approval.policyDigestB64u,
      },
      registeredPublicKeyB64u: sourceJob.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: sourceJob.nearEd25519SigningKeyId,
      keyCreationSignerSlot: sourceJob.keyCreationSignerSlot,
      stableContextBindingB64u: sourceJob.stableContextBindingB64u,
    }),
  });
  const credential: VerifiedLinkedDeviceWebAuthnCredentialV1 = {
    credentialIdB64u: fixture.targetCredential.registration.webauthnRegistration.credentialIdB64u,
    credentialPublicKeyB64u: 'AQ',
    counter: 0,
  };
  const committed = await planner.commitVerifiedTargetV1({
    preparation: fixture.targetCredential.preparation,
    registration: fixture.targetCredential.registration,
    credential,
    registrationDigestB64u: await registrationDigestV1(fixture.targetCredential.registration),
    requestedAtMs: 4_000,
  });
  expect(committed.targetReady.children).toHaveLength(1);
  expect(committed.targetReady.children[0]?.target.laneId).toBe(
    fixture.targetCredential.preparation.orderedChildren[0]?.targetLaneId,
  );
  expect(committed.targetReady.manifest.orderedChildren[0]?.operationId).toBe(
    fixture.targetCredential.preparation.orderedChildren[0]?.operationId,
  );
  expect(committed.keyManifestDigestB64u).toBeTruthy();
});

test('rejects target commit when the authenticated descriptor is missing', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const provisioning = buildR103ProvisioningFixture(fixture.deviceLink);
  const sourceJob = provisioning.deliveries.orderedChildren[0]?.job;
  if (!sourceJob) throw new Error('R103 fixture did not contain a source job');
  const authorizedOperationId = required(
    parseAuthorizedOperationId(String(fixture.deviceLink.approval.operationId)),
  );
  const planner = new D1LinkedDeviceTargetPlannerV1({
    rpId: required(parseWebAuthnRpId('wallet.example.test')),
    targetDeploymentDescriptorProvider: {
      async resolveTargetDeploymentDescriptorV1() {
        throw new Error('target deployment descriptor is unavailable');
      },
    },
    resolveOwnerSourceChildV1: async () => ({
      keyFamily: 'ed25519',
      walletKeyId: sourceJob.walletKeyId,
      source: sourceJob.source,
      authorization: {
        authorizedOperationId,
        idempotencyKey: fixture.deviceLink.approval.idempotencyKey,
        linkedDevicePermissionDigestB64u: fixture.deviceLink.approval.policyDigestB64u,
      },
      registeredPublicKeyB64u: sourceJob.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: sourceJob.nearEd25519SigningKeyId,
      keyCreationSignerSlot: sourceJob.keyCreationSignerSlot,
      stableContextBindingB64u: sourceJob.stableContextBindingB64u,
    }),
  });
  const credential: VerifiedLinkedDeviceWebAuthnCredentialV1 = {
    credentialIdB64u: fixture.targetCredential.registration.webauthnRegistration.credentialIdB64u,
    credentialPublicKeyB64u: 'AQ',
    counter: 0,
  };
  await expect(
    planner.commitVerifiedTargetV1({
      preparation: fixture.targetCredential.preparation,
      registration: fixture.targetCredential.registration,
      credential,
      registrationDigestB64u: await registrationDigestV1(fixture.targetCredential.registration),
      requestedAtMs: 4_000,
    }),
  ).rejects.toThrow('target deployment descriptor is unavailable');
});

test('creates exact mixed Ed25519 and ECDSA target jobs from source-only owner facts', async () => {
  const fixture = await buildR103MixedPlannerFixture();
  const authorizedOperationId = required(
    parseAuthorizedOperationId(String(fixture.deviceLink.approval.operationId)),
  );
  const planner = new D1LinkedDeviceTargetPlannerV1({
    rpId: required(parseWebAuthnRpId('wallet.example.test')),
    targetDeploymentDescriptorProvider: await targetDescriptorProviderV1(fixture.sourceJobs),
    resolveOwnerSourceChildV1: async (input) => {
      if (input.kind === 'preparation') {
        throw new Error('mixed planner test only resolves source facts at commit');
      }
      const sourceJob = fixture.sourceJobs[input.childIndex];
      const preparationChild = input.preparation.orderedChildren[input.childIndex];
      if (!sourceJob || !preparationChild) {
        throw new Error(`mixed planner fixture child ${input.childIndex} is missing`);
      }
      const authorization = {
        authorizedOperationId,
        idempotencyKey: fixture.deviceLink.approval.idempotencyKey,
        linkedDevicePermissionDigestB64u: fixture.deviceLink.approval.policyDigestB64u,
      };
      if (sourceJob.keyFamily === 'ed25519') {
        return {
          keyFamily: 'ed25519' as const,
          walletKeyId: sourceJob.walletKeyId,
          source: sourceJob.source,
          authorization,
          registeredPublicKeyB64u: sourceJob.registeredPublicKeyB64u,
          nearEd25519SigningKeyId: sourceJob.nearEd25519SigningKeyId,
          keyCreationSignerSlot: sourceJob.keyCreationSignerSlot,
          stableContextBindingB64u: sourceJob.stableContextBindingB64u,
        };
      }
      return {
        keyFamily: 'ecdsa_secp256k1' as const,
        walletKeyId: sourceJob.walletKeyId,
        source: sourceJob.source,
        authorization,
        evmFamilySigningKeySlotId: sourceJob.evmFamilySigningKeySlotId,
        thresholdPublicKey33B64u: sourceJob.thresholdPublicKey33B64u,
        evmAddress: sourceJob.evmAddress,
        sourceCapability: sourceJob.sourceCapability,
        sourceHolderVerifyingShare33B64u: sourceJob.sourceHolderVerifyingShare33B64u,
        sourceServerVerifyingShare33B64u: sourceJob.sourceServerVerifyingShare33B64u,
      };
    },
  });
  const credential: VerifiedLinkedDeviceWebAuthnCredentialV1 = {
    credentialIdB64u: fixture.targetCredential.registration.webauthnRegistration.credentialIdB64u,
    credentialPublicKeyB64u: 'AQ',
    counter: 0,
  };
  const committed = await planner.commitVerifiedTargetV1({
    preparation: fixture.targetCredential.preparation,
    registration: fixture.targetCredential.registration,
    credential,
    registrationDigestB64u: await registrationDigestV1(fixture.targetCredential.registration),
    requestedAtMs: 4_000,
  });
  const [ed25519, ecdsa] = committed.targetReady.children;
  expect(ed25519?.keyFamily).toBe('ed25519');
  expect(ecdsa?.keyFamily).toBe('ecdsa_secp256k1');
  if (
    !ed25519 ||
    !ecdsa ||
    ed25519.keyFamily !== 'ed25519' ||
    ecdsa.keyFamily !== 'ecdsa_secp256k1'
  ) {
    throw new Error('mixed planner fixture did not produce both curve jobs');
  }
  expect(ed25519.targetSigningWorker).toEqual(fixture.sourceJobs[0].targetSigningWorker);
  expect(ecdsa.targetSigningWorker).toEqual(fixture.sourceJobs[1].targetSigningWorker);
  expect(ecdsa.targetCapability).toEqual(fixture.sourceJobs[1].targetCapability);
  expect(ecdsa.targetCapability.orderedThresholdSessions).toHaveLength(1);
  expect(committed.targetReady.manifest.orderedChildren.map((child) => child.keyFamily)).toEqual([
    'ed25519',
    'ecdsa_secp256k1',
  ]);
});
