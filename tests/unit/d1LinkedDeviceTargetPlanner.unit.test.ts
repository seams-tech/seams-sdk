import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
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
    resolveOwnerSourceChildV1: async () => ({
      keyFamily: 'ed25519',
      walletKeyId: sourceJob.walletKeyId,
      source: sourceJob.source,
      targetHolderParticipantId: sourceJob.targetHolder.participantId,
      targetSigningWorker: sourceJob.targetSigningWorker,
      authorization: {
        authorizedOperationId,
        idempotencyKey: fixture.deviceLink.approval.idempotencyKey,
        linkedDevicePermissionDigestB64u: fixture.deviceLink.approval.policyDigestB64u,
      },
      registeredPublicKeyB64u: sourceJob.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: sourceJob.nearEd25519SigningKeyId,
      keyCreationSignerSlot: sourceJob.keyCreationSignerSlot,
      stableContextBindingB64u: sourceJob.stableContextBindingB64u,
      yaoSuiteId: sourceJob.yaoSuiteId,
      circuitDigestB64u: sourceJob.circuitDigestB64u,
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

test('rejects target commit when the source resolver has no target enrichment', async () => {
  const fixture = await buildR103ActiveExecutionFixture();
  const provisioning = buildR103ProvisioningFixture(fixture.deviceLink);
  const sourceJob = provisioning.deliveries.orderedChildren[0]?.job;
  if (!sourceJob) throw new Error('R103 fixture did not contain a source job');
  const authorizedOperationId = required(
    parseAuthorizedOperationId(String(fixture.deviceLink.approval.operationId)),
  );
  const planner = new D1LinkedDeviceTargetPlannerV1({
    rpId: required(parseWebAuthnRpId('wallet.example.test')),
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
      yaoSuiteId: sourceJob.yaoSuiteId,
      circuitDigestB64u: sourceJob.circuitDigestB64u,
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
      requestedAtMs: 4_000,
    }),
  ).rejects.toThrow('target resolution 0 is not enriched');
});

test('creates exact mixed Ed25519 and ECDSA target jobs from source-only owner facts', async () => {
  const fixture = await buildR103MixedPlannerFixture();
  const authorizedOperationId = required(
    parseAuthorizedOperationId(String(fixture.deviceLink.approval.operationId)),
  );
  const planner = new D1LinkedDeviceTargetPlannerV1({
    rpId: required(parseWebAuthnRpId('wallet.example.test')),
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
          targetHolderParticipantId: preparationChild.targetHolderParticipantId,
          targetSigningWorker: sourceJob.targetSigningWorker,
          authorization,
          registeredPublicKeyB64u: sourceJob.registeredPublicKeyB64u,
          nearEd25519SigningKeyId: sourceJob.nearEd25519SigningKeyId,
          keyCreationSignerSlot: sourceJob.keyCreationSignerSlot,
          stableContextBindingB64u: sourceJob.stableContextBindingB64u,
          yaoSuiteId: sourceJob.yaoSuiteId,
          circuitDigestB64u: sourceJob.circuitDigestB64u,
        };
      }
      return {
        keyFamily: 'ecdsa_secp256k1' as const,
        walletKeyId: sourceJob.walletKeyId,
        source: sourceJob.source,
        targetHolderParticipantId: preparationChild.targetHolderParticipantId,
        targetSigningWorker: sourceJob.targetSigningWorker,
        targetCapability: sourceJob.targetCapability,
        authorization,
        evmFamilySigningKeySlotId: sourceJob.evmFamilySigningKeySlotId,
        thresholdPublicKey33B64u: sourceJob.thresholdPublicKey33B64u,
        evmAddress: sourceJob.evmAddress,
        sourceCapability: sourceJob.sourceCapability,
        sourceHolderVerifyingShare33B64u: sourceJob.sourceHolderVerifyingShare33B64u,
        sourceServerVerifyingShare33B64u: sourceJob.sourceServerVerifyingShare33B64u,
        reshareChannelBindingDigestB64u: sourceJob.reshareChannelBindingDigestB64u,
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
