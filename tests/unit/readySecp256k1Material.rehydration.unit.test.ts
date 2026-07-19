import { expect, test } from '@playwright/test';
import { buildReadySecp256k1SigningMaterialFromRecord } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
import {
  clearAllThresholdEcdsaSessionRecords,
  getInMemoryEcdsaRoleLocalHandle,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import {
  parseEcdsaRoleLocalWorkerHandle,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

type RehydrationFixture = {
  record: ThresholdEcdsaSessionRecord;
  store: ThresholdEcdsaSessionStoreDeps;
  roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
};

function createRehydrationFixture(): RehydrationFixture {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'rehydration.testnet',
    chain: 'evm',
    expiresAtMs: Date.now() + 120_000,
  });
  const initialBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (initialBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('expected ready role-local fixture material');
  }
  const readyRecord = initialBinding.ecdsaRoleLocalReadyRecord;
  const roleLocalMaterial = parseEcdsaRoleLocalWorkerHandle({
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle: 'router-ab-ecdsa-registration:rehydration-fixture',
    bindingDigest: readyRecord.publicFacts.contextBinding32B64u,
    durableMaterialRef: 'router-ab-ecdsa-registration:rehydration-fixture',
  });
  const workerBootstrap: ThresholdEcdsaSessionBootstrapResult = {
    ...bootstrap,
    thresholdEcdsaKeyRef: {
      ...bootstrap.thresholdEcdsaKeyRef,
      backendBinding: {
        materialKind: 'role_local_worker_handle',
        relayerKeyId: initialBinding.relayerKeyId,
        clientVerifyingShareB64u: initialBinding.clientVerifyingShareB64u,
        roleLocalMaterialHandle: roleLocalMaterial,
        publicFacts: readyRecord.publicFacts,
        authMethod: readyRecord.authMethod,
      },
    },
  };
  const store: ThresholdEcdsaSessionStoreDeps = {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
  const record = upsertThresholdEcdsaSessionFromBootstrap(store, {
    walletId: workerBootstrap.thresholdEcdsaKeyRef.userId,
    chainTarget: workerBootstrap.thresholdEcdsaKeyRef.chainTarget!,
    bootstrap: workerBootstrap,
    source: 'login',
  });
  clearAllThresholdEcdsaSessionRecords(store);
  return { record, store, roleLocalMaterial };
}

function successfulRehydrationWorkerContext(args: {
  expected: EcdsaRoleLocalWorkerHandle;
  requests: unknown[];
}): WorkerOperationContext {
  return {
    requestWorkerOperation: async (request) => {
      args.requests.push(request);
      return {
        type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          kind: 'ecdsa_role_local_signing_material_rehydrated_v1',
          roleLocalMaterial: args.expected,
        },
      } as never;
    },
  };
}

test.describe('ready secp256k1 durable role-local material rehydration', () => {
  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords({
      recordsByLane: new Map(),
      exportArtifactsByLane: new Map(),
    });
  });

  test('rehydrates the sealed worker material before constructing signing material', async () => {
    const fixture = createRehydrationFixture();
    const requests: unknown[] = [];

    const material = await buildReadySecp256k1SigningMaterialFromRecord({
      record: fixture.record,
      requestLabel: 'evm',
      evmFamilySigningKeySlotId: fixture.record.evmFamilySigningKeySlotId,
      hydrationEntryPoint: 'post_page_refresh',
      workerCtx: successfulRehydrationWorkerContext({
        expected: fixture.roleLocalMaterial,
        requests,
      }),
    });

    expect(requests).toEqual([
      {
        kind: 'ecdsaDerivationClient',
        request: {
          type: EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial,
          timeoutMs: 20_000,
          payload: {
            kind: 'rehydrate_ecdsa_role_local_signing_material_v1',
            roleLocalMaterial: fixture.roleLocalMaterial,
          },
        },
      },
    ]);
    expect(getInMemoryEcdsaRoleLocalHandle(fixture.record)).toEqual(fixture.roleLocalMaterial);
    expect(material.signerSession.clientShare).toMatchObject({
      kind: 'role_local_worker_share',
      handle: fixture.roleLocalMaterial,
    });
  });

  test('rejects a worker response that changes the durable material identity', async () => {
    const fixture = createRehydrationFixture();
    const substituted = parseEcdsaRoleLocalWorkerHandle({
      ...fixture.roleLocalMaterial,
      materialHandle: 'router-ab-ecdsa-registration:substituted',
    });

    await expect(
      buildReadySecp256k1SigningMaterialFromRecord({
        record: fixture.record,
        requestLabel: 'evm',
        evmFamilySigningKeySlotId: fixture.record.evmFamilySigningKeySlotId,
        hydrationEntryPoint: 'post_page_refresh',
        workerCtx: successfulRehydrationWorkerContext({
          expected: substituted,
          requests: [],
        }),
      }),
    ).rejects.toThrow('ECDSA role-local signing material hydration changed its identity');
    expect(getInMemoryEcdsaRoleLocalHandle(fixture.record)).toBeNull();
  });
});
