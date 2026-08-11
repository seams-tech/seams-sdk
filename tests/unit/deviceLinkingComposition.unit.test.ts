import { expect, test } from '@playwright/test';
import type { AuthenticatorPort } from '../../packages/sdk-web/src/core/platform';
import type { HttpTransport } from '../../packages/sdk-web/src/core/platform/http';
import type { LaneOperationSourcePortsV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/operations/ports';
import type { LaneSealedHolderMaterialRepositoryV1 } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import {
  createDeviceLinkingFlowPortsV1,
  type DeviceLinkingFlowPortsAssemblyOptionsV1,
} from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingComposition';
import type { DeviceLinkingOwnerAuthorizationPortV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingPorts';
import type {
  LinkSessionOwnerApprovalUpdatesPortV1,
  LinkSessionOwnerAuthenticatedRequestPortV1,
} from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingOwnerTransport';

class IdleWorkerEndpoint {
  addEventListener(): void {}
  removeEventListener(): void {}
  postMessage(): void {}
  terminate(): void {}
}

const unsupported = async (): Promise<never> => {
  throw new Error('source preparation is outside this composition test');
};

function sourceLanePorts(): LaneOperationSourcePortsV1 {
  return {
    nowMs: () => 1,
    reconcileEcdsaActivationJournalV1: unsupported,
    gateway: {
      prepareLaneEnrollmentV1: unsupported,
      resumeLaneProtocolOperationV1: unsupported,
      recordLaneProtocolCommitV1: unsupported,
      recordLaneHolderDeliveryV1: unsupported,
      activateLaneServerMaterialV1: unsupported,
      commitLaneEnrollmentActivationV1: unsupported,
      fenceSigningLaneRevocationV1: unsupported,
      completeSigningLaneRevocationV1: unsupported,
    },
    wasm: {
      ecdsa: { prepareEcdsaAdditiveLaneHolderRoundV1: unsupported },
      ed25519Yao: { prepare: unsupported, complete: unsupported },
    },
    protocolCommitter: {
      executeAndRecordEcdsaAdditiveLaneV1: unsupported,
      executeAndRecordEd25519YaoLaneV1: unsupported,
    },
  };
}

function repository(): LaneSealedHolderMaterialRepositoryV1 {
  return {
    put: unsupported,
    get: unsupported,
    listForEnrollmentV1: unsupported,
    delete: unsupported,
  };
}

function ownerAuthorization(): DeviceLinkingOwnerAuthorizationPortV1 {
  return { authenticateOwnerForLinkingV1: unsupported };
}

function ownerRequest(): LinkSessionOwnerAuthenticatedRequestPortV1 {
  return { requestOwnerV1: unsupported };
}

function approvalUpdates(): LinkSessionOwnerApprovalUpdatesPortV1 {
  return { getApprovalV1: unsupported, subscribeApprovalV1: unsupported };
}

function assemblyOptions(): DeviceLinkingFlowPortsAssemblyOptionsV1 {
  const authenticator: AuthenticatorPort = {
    kind: 'authenticator',
    run: unsupported,
  };
  const http: HttpTransport = {
    kind: 'http_transport',
    request: unsupported,
  };
  return {
    authenticator,
    http,
    relayerUrl: 'https://relay.example.test',
    ownerRequest: ownerRequest(),
    ownerApprovalUpdates: approvalUpdates(),
    ownerAuthorization: ownerAuthorization(),
    repository: repository(),
    sourceLanePorts: sourceLanePorts(),
    workerEndpoint: new IdleWorkerEndpoint(),
    nowMs: () => 1,
    pollIntervalMs: 1_000,
  };
}

test('composes direct device-linking ports only from explicit trust-boundary providers', () => {
  const ports = createDeviceLinkingFlowPortsV1(assemblyOptions());

  expect(ports.transport).toBeDefined();
  expect(ports.keyMaterial).toBeDefined();
  expect(ports.targetCredential).toBeDefined();
  expect(ports.laneProvisioning).toBeDefined();
  expect(ports.sourcePreparation).toBeDefined();
  expect(JSON.stringify(ports)).not.toContain('privateKey');
  expect(JSON.stringify(ports)).not.toContain('prf');
});
