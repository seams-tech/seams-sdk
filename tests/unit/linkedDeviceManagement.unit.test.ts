import { expect, test } from '@playwright/test';
import {
  buildLinkedDeviceSessionClaimV1,
  parseLinkedDeviceSummaryV1,
} from '../../packages/shared-ts/src/device-linking/parsers';
import {
  computeLinkedDeviceApprovalDigestV1,
  computeLinkedDeviceSessionClaimDigestV1,
} from '../../packages/shared-ts/src/device-linking/digests';
import {
  buildLaneEnrollmentManifestV1,
  buildRevokeLaneEnrollmentV1,
  buildRevokeSigningLaneV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseAuthorizedOperationId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseTenantId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseLaneEnrollmentId } from '../../packages/shared-ts/src/signing-lanes/ids';
import {
  parseMpcMaterialActivationId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import type { LaneAggregateRevocationRequestV1 } from '../../packages/sdk-server-ts/src/core/signingLanes/LaneAggregateRevocationApplicationService';
import {
  LinkedDeviceManagementServiceV1,
  type LinkedDeviceManagementTargetV1,
} from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceManagement';
import { parseLinkedDeviceSessionRecordV1 } from '../../packages/sdk-server-ts/src/core/deviceLinking/linkedDeviceSession';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';

const DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));

test('lists wallet-scoped linked devices only after owner authorization', async () => {
  const target = await buildManagementTarget();
  const calls: string[] = [];
  const service = new LinkedDeviceManagementServiceV1({
    authorization: {
      authorizeLinkedDeviceManagementV1: async (input) => {
        calls.push(input.operation);
        return { kind: 'authorized' };
      },
    },
    projection: {
      listLinkedDevicesV1: async (walletId) =>
        walletId === target.summary.walletId ? [target.summary] : [],
      getLinkedDeviceV1: async () => target,
    },
    preparation: neverPreparation(),
    aggregateRevocation: neverAggregate(),
    walletSessionRevocation: neverWalletSessionRevocation(),
    localStateInvalidation: neverLocalInvalidation(),
  });

  const result = await service.listLinkedDevicesV1(
    { kind: 'linked_device_list_request_v1', walletId: target.summary.walletId },
    4_000,
  );
  expect(result).toEqual({ devices: [target.summary] });
  expect(calls).toEqual(['list']);
});

test('refuses a public revoke plan whose lane command does not bind the requested wallet', async () => {
  const target = await buildManagementTarget();
  const walletId = target.summary.walletId;
  const laneEnrollmentId = parseLaneEnrollmentId(String(target.summary.enrollmentId)).value;
  const operationId = target.enrollment.value.manifest.orderedChildren[0]?.operationId;
  if (!operationId) throw new Error('fixture manifest child is missing');
  const command = buildRevokeLaneEnrollmentV1({
    enrollmentId: laneEnrollmentId,
    walletId: parseWalletId('wallet:other').value,
    manifestDigestB64u: DIGEST,
    reason: 'user_revoked',
    requestedAtMs: 4_000,
  });
  const child = target.enrollment.value.manifest.orderedChildren[0];
  const childCommand = buildRevokeSigningLaneV1({
    walletId,
    walletKeyId: child.walletKeyId,
    laneId: child.targetLaneId,
    laneShareEpoch: child.targetLaneShareEpoch,
    expectedRevocationEpoch: 0,
    reason: 'user_revoked',
    retirementCorrelationId: parseCorrelationId('correlation:management'),
    retirementRequestDigestB64u: DIGEST,
    retirementEffectBindingDigestB64u: DIGEST,
    requestedAtMs: 4_000,
  });
  const aggregate: LaneAggregateRevocationRequestV1 = {
    command,
    orderedChildren: [{ curve: 'ed25519_yao', command: childCommand }],
  };
  let aggregateCalls = 0;
  const service = new LinkedDeviceManagementServiceV1({
    authorization: authorizedManagement(),
    projection: {
      listLinkedDevicesV1: async () => [target.summary],
      getLinkedDeviceV1: async () => target,
    },
    preparation: {
      prepareLinkedDeviceRevocationV1: async () => ({
        kind: 'prepared',
        plan: {
          target,
          aggregate,
          walletSessions: [
            {
              tenantId: parseTenantId('tenant:management').value,
              deviceId: target.summary.deviceId,
              authorizationId: parseLinkedDeviceWalletSessionAuthorizationId(
                'authorization:management',
              ).value,
              walletSessionId: parseWalletSessionId('wallet-session:management').value,
              quotaId: parseMpcWalletSigningQuotaId('wallet-quota:management').value,
            },
          ],
          revocationEpoch: 1,
        },
      }),
    },
    aggregateRevocation: {
      revokeLaneEnrollmentV1: async () => {
        aggregateCalls += 1;
        throw new Error('aggregate should not run for a mismatched plan');
      },
    },
    walletSessionRevocation: neverWalletSessionRevocation(),
    localStateInvalidation: neverLocalInvalidation(),
  });

  await expect(
    service.revokeLinkedDeviceV1({
      kind: 'linked_device_revoke_request_v1',
      walletId,
      deviceId: target.summary.deviceId,
      requestedAtMs: 4_000,
    }),
  ).rejects.toThrow('linked-device revocation plan does not match its target');
  expect(aggregateCalls).toBe(0);
});

test('fences every linked Wallet Session before retiring child lanes', async () => {
  const target = await buildManagementTarget();
  const walletId = target.summary.walletId;
  const child = target.enrollment.value.manifest.orderedChildren[0];
  if (!child) throw new Error('fixture manifest child is missing');
  const command = buildRevokeLaneEnrollmentV1({
    enrollmentId: parseLaneEnrollmentId(String(target.summary.enrollmentId)).value,
    walletId,
    manifestDigestB64u: target.summary.keyManifestDigestB64u,
    reason: 'user_revoked',
    requestedAtMs: 4_000,
  });
  const aggregate: LaneAggregateRevocationRequestV1 = {
    command,
    orderedChildren: [
      {
        curve: child.keyFamily === 'ed25519' ? 'ed25519_yao' : 'ecdsa_additive',
        command: buildRevokeSigningLaneV1({
          walletId,
          walletKeyId: child.walletKeyId,
          laneId: child.targetLaneId,
          laneShareEpoch: child.targetLaneShareEpoch,
          expectedRevocationEpoch: 0,
          reason: 'user_revoked',
          retirementCorrelationId: parseCorrelationId('correlation:management-fence'),
          retirementRequestDigestB64u: DIGEST,
          retirementEffectBindingDigestB64u: DIGEST,
          requestedAtMs: 4_000,
        }),
      },
    ],
  };
  const order: string[] = [];
  const revokedAuthorizationIds: string[] = [];
  const service = new LinkedDeviceManagementServiceV1({
    authorization: authorizedManagement(),
    projection: {
      listLinkedDevicesV1: async () => [target.summary],
      getLinkedDeviceV1: async () => target,
    },
    preparation: {
      prepareLinkedDeviceRevocationV1: async () => ({
        kind: 'prepared',
        plan: {
          target,
          aggregate,
          walletSessions: [
            {
              tenantId: parseTenantId('tenant:management').value,
              deviceId: target.summary.deviceId,
              authorizationId: parseLinkedDeviceWalletSessionAuthorizationId(
                'authorization:management:first',
              ).value,
              walletSessionId: parseWalletSessionId('wallet-session:management:first').value,
              quotaId: parseMpcWalletSigningQuotaId('wallet-quota:management:first').value,
            },
            {
              tenantId: parseTenantId('tenant:management').value,
              deviceId: target.summary.deviceId,
              authorizationId: parseLinkedDeviceWalletSessionAuthorizationId(
                'authorization:management:renewed',
              ).value,
              walletSessionId: parseWalletSessionId('wallet-session:management:renewed').value,
              quotaId: parseMpcWalletSigningQuotaId('wallet-quota:management:renewed').value,
            },
          ],
          revocationEpoch: 1,
        },
      }),
    },
    walletSessionRevocation: {
      revokeLinkedDeviceWalletSessionV1: async ({ target: walletSession }) => {
        order.push('wallet_session');
        revokedAuthorizationIds.push(String(walletSession.authorizationId));
        return { kind: 'applied' };
      },
    },
    aggregateRevocation: {
      revokeLaneEnrollmentV1: async () => {
        order.push('aggregate');
        return {
          kind: 'lane_enrollment_revocation_result_v1',
          outcome: 'conflict',
          enrollmentId: command.enrollmentId,
          expectedVersion: 1,
          actualVersion: 2,
          requestedCommandDigestB64u: DIGEST,
          storedCommandDigestB64u: DIGEST,
        };
      },
    },
    localStateInvalidation: neverLocalInvalidation(),
  });

  const result = await service.revokeLinkedDeviceV1({
    kind: 'linked_device_revoke_request_v1',
    walletId,
    deviceId: target.summary.deviceId,
    requestedAtMs: 4_000,
  });

  expect(result).toEqual({ kind: 'conflict' });
  expect(order).toEqual(['wallet_session', 'wallet_session', 'aggregate']);
  expect(revokedAuthorizationIds).toEqual([
    'authorization:management:first',
    'authorization:management:renewed',
  ]);
});

function authorizedManagement() {
  return {
    authorizeLinkedDeviceManagementV1: async () => ({ kind: 'authorized' as const }),
  };
}

function neverPreparation() {
  return {
    prepareLinkedDeviceRevocationV1: async () => {
      throw new Error('unexpected revocation preparation');
    },
  };
}

function neverAggregate() {
  return {
    revokeLaneEnrollmentV1: async () => {
      throw new Error('unexpected aggregate revocation');
    },
  };
}

function neverWalletSessionRevocation() {
  return {
    revokeLinkedDeviceWalletSessionV1: async () => {
      throw new Error('unexpected Wallet Session revocation');
    },
  };
}

function neverLocalInvalidation() {
  return {
    invalidateLinkedDeviceStateV1: async () => {
      throw new Error('unexpected local invalidation');
    },
  };
}

async function buildManagementTarget(): Promise<LinkedDeviceManagementTargetV1> {
  const fixture = buildR103DeviceLinkFixture();
  const claim = buildLinkedDeviceSessionClaimV1({
    linkSessionId: fixture.payload.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
    deviceId: fixture.approval.deviceId,
    devicePublicKeyB64u: fixture.payload.devicePublicKeyB64u,
    claimedAtMs: 2_001,
    claimExpiresAtMs: 9_000,
  });
  const claimDigestB64u = parseDigestB64u(await computeLinkedDeviceSessionClaimDigestV1(claim));
  const approvalDigestB64u = parseDigestB64u(
    await computeLinkedDeviceApprovalDigestV1(fixture.approval),
  );
  const session = parseLinkedDeviceSessionRecordV1({
    version: 'linked_device_session_v1',
    linkSessionId: fixture.payload.linkSessionId,
    qrPayload: fixture.payload,
    state: {
      state: 'awaiting_target_passkey',
      linkSessionId: fixture.payload.linkSessionId,
      walletId: fixture.approval.walletId,
      enrollmentId: fixture.approval.enrollmentId,
      credentialDeadlineMs: 12_000,
    },
    revision: 3,
    claimTranscript: { digestB64u: claimDigestB64u, value: claim },
    approvalTranscript: { digestB64u: approvalDigestB64u, value: fixture.approval },
    createdAtMs: 2_000,
    updatedAtMs: 2_002,
  });
  const binding = fixture.approval.orderedKeyBindings[0];
  if (!binding) throw new Error('fixture key binding is missing');
  const laneEnrollmentId = parseLaneEnrollmentId(String(fixture.approval.enrollmentId)).value;
  const manifest = buildLaneEnrollmentManifestV1({
    enrollmentId: laneEnrollmentId,
    walletId: fixture.approval.walletId,
    authorization: {
      kind: 'linked_device_enrollment',
      authorizedOperationId: parseAuthorizedOperationId('authorized-operation:management').value,
      linkedDeviceEnrollmentId: fixture.approval.enrollmentId,
      linkedDevicePermissionDigestB64u: fixture.approval.policyDigestB64u,
    },
    orderedChildren: [
      {
        operationId: fixture.approval.operationId,
        walletKeyId: binding.walletKeyId,
        keyFamily: binding.keyFamily,
        sourceLaneId: binding.sourceLaneId,
        sourceLaneShareEpoch: binding.sourceLaneShareEpoch,
        sourceRevocationEpoch: binding.sourceRevocationEpoch,
        sourceMaterialActivation: fixture.receipt.orderedChildReceipts[0].materialActivation,
        targetLaneId: binding.targetLaneId,
        targetLaneShareEpoch: binding.targetLaneShareEpoch,
        targetMaterialActivationId: parseMpcMaterialActivationId('activation:management').value,
        holderParticipantBindingDigestB64u: DIGEST,
        signingWorkerParticipantBindingDigestB64u: DIGEST,
      },
    ],
    createdAtMs: 2_000,
    expiresAtMs: 20_000,
  });
  const summary = parseLinkedDeviceSummaryV1({
    deviceId: fixture.approval.deviceId,
    enrollmentId: fixture.approval.enrollmentId,
    walletId: fixture.approval.walletId,
    label: 'Test device',
    platform: 'test',
    permission: fixture.approval.permission,
    keyManifestDigestB64u: fixture.approval.policyDigestB64u,
    coveredWalletKeys: [binding.walletKeyId],
    state: 'provisioning',
    createdAtMs: 2_000,
    lastActivityAtMs: 2_002,
    revocationEpoch: 0,
  });
  return {
    summary,
    session,
    enrollment: {
      version: 1,
      commandDigestB64u: String(DIGEST),
      value: {
        manifest,
        lifecycle: {
          state: 'active',
          manifestDigestB64u: String(DIGEST),
          aggregateReceiptDigestB64u: String(DIGEST),
          activatedAtMs: 2_001,
        },
      },
    },
    products: [],
  };
}
