import { expect, test } from '@playwright/test';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { D1LinkedDeviceTargetPlannerV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetPlanner';
import type { VerifiedLinkedDeviceWebAuthnCredentialV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import {
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
