import { expect, test } from '@playwright/test';
import type { LaneEnrollmentGatewayV1 } from '../../packages/shared-ts/src/signing-lanes';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildR102LaneEnrollmentFixture,
  buildR102LaneJob,
} from './helpers/r102LaneGateway.fixtures';
import {
  createD1LinkedDeviceLaneGatewayRouteServiceV1,
  type D1LinkedDeviceLaneProtocolCommitterV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/signingLanes/d1LinkedDeviceLaneOwnerAuthorization';
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization';

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: { readonly message: string } }): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function ownerFor(walletIdRaw: string): DeviceLinkingOwnerWalletSessionContextV1 {
  const walletId = required(parseWalletId(walletIdRaw));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u('credential-route-test'));
  return {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session-route-test')),
    authorizationId: required(parseWalletSessionAuthorizationId('wallet-authorization-route-test')),
    expiresAtMs: 100_000,
    curve: 'ed25519',
    authority: {
      walletId,
      factor: { kind: 'passkey', credentialIdB64u },
      verifier: { kind: 'webauthn', rpId },
      bindingId: required(parseWalletAuthMethodId(`passkey:${rpId}:${credentialIdB64u}`)),
    },
    authorityScope: { kind: 'passkey_rp', rpId },
  };
}

function rejectingGateway(calls: string[]): LaneEnrollmentGatewayV1 {
  const rejected = async (): Promise<never> => {
    throw new Error('prepare-dispatched');
  };
  return {
    prepareLaneEnrollmentV1: async () => {
      calls.push('prepare');
      return await rejected();
    },
    resumeLaneProtocolOperationV1: rejected,
    recordLaneProtocolCommitV1: rejected,
    recordLaneHolderDeliveryV1: rejected,
    activateLaneServerMaterialV1: rejected,
    commitLaneEnrollmentActivationV1: rejected,
    fenceSigningLaneRevocationV1: rejected,
    completeSigningLaneRevocationV1: rejected,
  };
}

function rejectingCommitter(calls: string[]): D1LinkedDeviceLaneProtocolCommitterV1 {
  return {
    executeAndRecordEd25519YaoLaneV1: async () => {
      calls.push('protocol');
      throw new Error('protocol-dispatched');
    },
    executeAndRecordEcdsaAdditiveLaneV1: async () => {
      calls.push('protocol');
      throw new Error('protocol-dispatched');
    },
  };
}

test('dispatches prepare, protocol commit, and ceremony binding only after source authorization', async () => {
  const fixture = buildR102LaneEnrollmentFixture();
  const job = fixture.children[0];
  const owner = ownerFor(job.walletId);
  const calls: string[] = [];
  const service = createD1LinkedDeviceLaneGatewayRouteServiceV1({
    authenticateOwnerRequestV1: async () => ({
      kind: 'denied',
      code: 'unauthorized',
      message: 'test authenticator is not used by this direct service test',
    }),
    gateway: rejectingGateway(calls),
    protocolCommitter: rejectingCommitter(calls),
    ownerProjection: {
      async assertActiveOwnerSourceLaneV1(input) {
        calls.push(`guard:${input.job.operationId}`);
        if (String(input.job.operationId).endsWith('reject')) {
          throw new Error('source-lane-rejected');
        }
      },
    },
    resolveCeremonyBindingV1: async ({ operationId }) => {
      calls.push(`ceremony:${operationId}`);
      throw new Error('ceremony-dispatched');
    },
  });

  await expect(
    service.executeOwnerAuthorizedRequestV1({
      owner,
      request: { action: 'prepare', body: fixture },
    }),
  ).rejects.toThrow('prepare-dispatched');
  expect(calls).toContain('prepare');
  expect(calls.filter((entry) => entry.startsWith('guard:'))).toHaveLength(2);

  calls.length = 0;
  await expect(
    service.executeOwnerAuthorizedRequestV1({
      owner,
      request: {
        action: 'protocol-commit',
        body: {
          curve: 'ed25519_yao',
          job,
          requestJson: '{}',
          expectedVersion: 1,
        },
      },
    }),
  ).rejects.toThrow('protocol-dispatched');
  expect(calls).toEqual([`guard:${job.operationId}`, 'protocol']);

  calls.length = 0;
  await expect(
    service.executeOwnerAuthorizedRequestV1({
      owner,
      request: {
        action: 'ceremony-binding',
        body: { operationId: job.operationId },
      },
    }),
  ).rejects.toThrow('ceremony-dispatched');
  expect(calls).toEqual([`ceremony:${job.operationId}`]);

  const rejectedJob = buildR102LaneJob('reject');
  await expect(
    service.executeOwnerAuthorizedRequestV1({
      owner,
      request: {
        action: 'protocol-commit',
        body: {
          curve: 'ed25519_yao',
          job: rejectedJob,
          requestJson: '{}',
          expectedVersion: 1,
        },
      },
    }),
  ).rejects.toThrow('source-lane-rejected');
  expect(calls).not.toContain('protocol');
});
