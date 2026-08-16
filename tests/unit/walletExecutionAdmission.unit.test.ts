import { expect, test } from '@playwright/test';
import {
  prepareLinkedDeviceWalletExecution,
  prepareOwnerWalletExecution,
} from '../../packages/sdk-server-ts/src/router/domains/signingOperations/walletExecutionAdmission';
import {
  proxyNormalSigningRequestToMpcRouter,
  proxyLinkedDeviceLaneAdmittedNormalSigningRequest,
  proxyOwnerLaneAdmittedNormalSigningRequest,
} from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/normalSigningRouterProxy';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseSigningLaneId } from '../../packages/shared-ts/src/signing-lanes/ids';
import {
  buildCompletedAuthorizedOperationFixture,
  buildReusableAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import { buildLinkedDeviceWalletExecutionFixture } from './helpers/linkedDeviceWalletExecution.fixtures';
import { buildOwnerWalletExecutionEvidenceFixture } from './helpers/walletExecutionLane.fixtures';

test.describe('R101 wallet execution admission', () => {
  test('prepares only a claimed operation bound to the exact active owner lane', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    const result = await prepareOwnerWalletExecution({
      authorizedOperation: authorization.authorizedOperation,
      evidence,
    });

    expect(result).toMatchObject({
      kind: 'prepared',
      execution: {
        kind: 'prepared_owner_wallet_execution',
        lane: { laneId: evidence.lane.laneId },
        authorization: {
          authorizedOperationId: authorization.authorizedOperation.authorizedOperationId,
          operationFingerprintDigest: authorization.authorizedOperation.operationFingerprintDigest,
          capabilityId: authorization.authorizedOperation.operation.capabilityId,
        },
      },
    });
  });

  test('prepares a linked-device operation only with exact active enrollment and local presence', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const result = await prepareLinkedDeviceWalletExecution({
      authorizedOperation: fixture.authorizedOperation,
      evidence: {
        ...fixture.projection,
        expectedMaterialActivation: fixture.projection.materialActivation,
      },
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
    });

    expect(result).toMatchObject({
      kind: 'prepared',
      execution: {
        kind: 'prepared_linked_device_wallet_execution',
        laneKind: 'linked_device',
        linkedDeviceEnrollmentId: fixture.authorization.enrollmentId,
        lane: { laneId: fixture.projection.lane.laneId },
        authorization: {
          authorizedOperationId: fixture.authorizedOperation.authorizedOperationId,
          capabilityId: fixture.authorizedOperation.operation.capabilityId,
        },
      },
    });
  });

  test('refuses a substituted linked-device grant before private work', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const result = await prepareLinkedDeviceWalletExecution({
      authorizedOperation: fixture.authorizedOperation,
      evidence: {
        ...fixture.projection,
        authorization: {
          ...fixture.authorization,
          authorizationGrantRef: {
            ...fixture.authorization.authorizationGrantRef,
            authorizationId: 'authorization:substituted',
          },
        },
        expectedMaterialActivation: fixture.projection.materialActivation,
      },
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'authorization_grant_mismatch' });
  });

  test('refuses a revoked linked-device enrollment before private work', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const result = await prepareLinkedDeviceWalletExecution({
      authorizedOperation: fixture.authorizedOperation,
      evidence: {
        ...fixture.projection,
        enrollment: { ...fixture.projection.enrollment, revocationEpoch: 1 },
        expectedMaterialActivation: fixture.projection.materialActivation,
      },
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'revocation_epoch_mismatch' });
  });

  test('refuses local presence for a different intent', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const result = await prepareLinkedDeviceWalletExecution({
      authorizedOperation: fixture.authorizedOperation,
      evidence: {
        ...fixture.projection,
        expectedMaterialActivation: fixture.projection.materialActivation,
      },
      localPresence: {
        kind: 'verified_assertion',
        evidence: {
          ...fixture.localPresence,
          intentDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(10))),
        },
      },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'local_presence_mismatch' });
  });

  test('refuses a substituted rotatable material source', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const substitutedLaneIdResult = parseSigningLaneId('lane:substituted');
    if (!substitutedLaneIdResult.ok) throw new Error(substitutedLaneIdResult.error.message);
    const result = await prepareLinkedDeviceWalletExecution({
      authorizedOperation: fixture.authorizedOperation,
      evidence: {
        ...fixture.projection,
        materialSource: {
          ...fixture.projection.materialSource,
          lookup: {
            ...fixture.projection.materialSource.lookup,
            identity: {
              ...fixture.projection.materialSource.lookup.identity,
              targetLaneId: substitutedLaneIdResult.value,
            },
          },
        },
        expectedMaterialActivation: fixture.projection.materialActivation,
      },
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'material_activation_mismatch' });
  });

  test('refuses stale material activation before dispatch', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    const result = await prepareOwnerWalletExecution({
      authorizedOperation: authorization.authorizedOperation,
      evidence: {
        ...evidence,
        expectedMaterialActivation: {
          ...evidence.expectedMaterialActivation,
          activationId: 'activation:stale',
        },
      },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'material_activation_mismatch' });
  });

  test('refuses an operation after completion', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const completed = await buildCompletedAuthorizedOperationFixture(authorization);
    const result = await prepareOwnerWalletExecution({
      authorizedOperation: completed,
      evidence: await buildOwnerWalletExecutionEvidenceFixture(),
    });

    expect(result).toEqual({ kind: 'refused', reason: 'operation_not_claimed' });
  });

  test('performs zero Router calls when the current owner lane is unavailable', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    if (
      evidence.lane.laneKind !== 'owner_passkey' &&
      evidence.lane.laneKind !== 'owner_email_otp'
    ) {
      throw new Error('owner auth lane fixture is required');
    }
    let routerCalls = 0;
    const response = await proxyOwnerLaneAdmittedNormalSigningRequest({
      request: new Request('https://wallet.example.test/sign', { method: 'POST' }),
      proxy: {
        internalServiceAuthSecret: 'test-router-secret',
        fetch: async () => {
          routerCalls += 1;
          return new Response('{}');
        },
      },
      body: {},
      authorizedOperation: authorization.authorizedOperation,
      walletId: evidence.walletId,
      expectedMaterialActivation: routerAbMpcMaterialActivationRefToWire(
        evidence.materialActivation,
      ),
      authorization: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: evidence.lane.walletAuthMethodId,
      },
      walletRegistration: {
        resolveActiveOwnerWalletExecutionLane: async () => ({
          kind: 'refused',
          reason: 'auth_method_inactive',
        }),
      },
    });

    expect(response.status).toBe(403);
    expect(routerCalls).toBe(0);
  });

  test('forwards an admitted linked-device lane through the rotatable material source proxy', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    let routerBody: Record<string, unknown> | null = null;
    const response = await proxyLinkedDeviceLaneAdmittedNormalSigningRequest({
      request: new Request('https://wallet.example.test/sign', { method: 'POST' }),
      proxy: {
        internalServiceAuthSecret: 'test-router-secret',
        fetch: async (request) => {
          routerBody = (await request.clone().json()) as Record<string, unknown>;
          return new Response('{"ok":true}', { status: 200 });
        },
      },
      body: { intent: 'linked-device' },
      authorizedOperation: fixture.authorizedOperation,
      walletId: fixture.projection.walletKey.walletId,
      enrollmentId: fixture.projection.enrollment.enrollmentId,
      deviceId: fixture.projection.enrollment.deviceId,
      walletKeyId: fixture.projection.lane.walletKeyId,
      laneId: fixture.projection.lane.laneId,
      laneShareEpoch: fixture.projection.lane.laneShareEpoch,
      laneRevocationEpoch: fixture.projection.lane.lifecycle.revocationEpoch,
      expectedMaterialActivation: routerAbMpcMaterialActivationRefToWire(
        fixture.projection.materialActivation,
      ),
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
      linkedDeviceExecution: {
        resolveActiveLinkedDeviceExecutionV1: async () => ({
          kind: 'projected' as const,
          projection: fixture.projection,
        }),
      },
    });

    expect(response.status).toBe(200);
    expect(routerBody).toMatchObject({
      intent: 'linked-device',
      material_source: { kind: 'rotatable_lane' },
    });
  });

  test('removes the gateway bearer token from linked-device Router admission', async () => {
    let routerAuthorization: string | null = 'unobserved';
    const response = await proxyNormalSigningRequestToMpcRouter({
      request: new Request('https://wallet.example.test/sign', {
        method: 'POST',
        headers: { authorization: 'Bearer gateway-only-wallet-session' },
      }),
      proxy: {
        internalServiceAuthSecret: 'test-router-secret',
        fetch: async (request) => {
          routerAuthorization = request.headers.get('authorization');
          return new Response('{"ok":true}', { status: 200 });
        },
      },
      body: {
        authorized_operation: {
          binding: { kind: 'gateway_linked_device_wallet_session' },
        },
      },
    });

    expect(response.status).toBe(200);
    expect(routerAuthorization).toBeNull();
  });

  test('refuses a resolver projection for a substituted lane coordinate before Router dispatch', async () => {
    const fixture = await buildLinkedDeviceWalletExecutionFixture();
    const substitutedLaneIdResult = parseSigningLaneId('lane:substituted-projection');
    if (!substitutedLaneIdResult.ok) throw new Error(substitutedLaneIdResult.error.message);
    let routerCalls = 0;
    const response = await proxyLinkedDeviceLaneAdmittedNormalSigningRequest({
      request: new Request('https://wallet.example.test/sign', { method: 'POST' }),
      proxy: {
        internalServiceAuthSecret: 'test-router-secret',
        fetch: async () => {
          routerCalls += 1;
          return new Response('{}', { status: 200 });
        },
      },
      body: { intent: 'linked-device' },
      authorizedOperation: fixture.authorizedOperation,
      walletId: fixture.projection.walletKey.walletId,
      enrollmentId: fixture.projection.enrollment.enrollmentId,
      deviceId: fixture.projection.enrollment.deviceId,
      walletKeyId: fixture.projection.lane.walletKeyId,
      laneId: fixture.projection.lane.laneId,
      laneShareEpoch: fixture.projection.lane.laneShareEpoch,
      laneRevocationEpoch: fixture.projection.lane.lifecycle.revocationEpoch,
      expectedMaterialActivation: routerAbMpcMaterialActivationRefToWire(
        fixture.projection.materialActivation,
      ),
      localPresence: { kind: 'verified_assertion', evidence: fixture.localPresence },
      linkedDeviceExecution: {
        resolveActiveLinkedDeviceExecutionV1: async () => ({
          kind: 'projected' as const,
          projection: {
            ...fixture.projection,
            lane: { ...fixture.projection.lane, laneId: substitutedLaneIdResult.value },
          },
        }),
      },
    });

    expect(response.status).toBe(403);
    expect(routerCalls).toBe(0);
  });
});
