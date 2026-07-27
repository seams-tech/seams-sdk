import { expect, test } from '@playwright/test';
import { buildReadySecp256k1SigningMaterialFromRecord } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
import {
  clearAllThresholdEcdsaSessionRecords,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildPersistedEcdsaRoleLocalMaterial,
  getLiveEcdsaRoleLocalMaterial,
} from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import {
  parseEcdsaRoleLocalWorkerHandle,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { buildPasskeyEcdsaSessionRecordFixture } from './helpers/signingSessionRecord.fixtures';

type RehydrationFixture = {
  record: ThresholdEcdsaSessionRecord;
  store: ThresholdEcdsaSessionStoreDeps;
  roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
};

function createRehydrationFixture(): RehydrationFixture {
  const durableMaterialRef = 'router-ab-ecdsa-registration:rehydration-fixture';
  const record = buildPasskeyEcdsaSessionRecordFixture({
    walletId: 'rehydration.testnet',
    chain: 'evm',
    expiresAtMs: Date.now() + 120_000,
    roleLocalDurableMaterialRef: durableMaterialRef,
  });
  const roleLocalMaterial = parseEcdsaRoleLocalWorkerHandle({
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle: `${durableMaterialRef}:live`,
    bindingDigest: record.ecdsaRoleLocalPublicFacts.contextBinding32B64u,
    durableMaterialRef,
  });
  const store: ThresholdEcdsaSessionStoreDeps = {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
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
          ok: true,
          liveHandle: args.expected,
        },
      } as never;
    },
  };
}

function liveMaterialForRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaRoleLocalWorkerHandle | null {
  if (!record.roleLocalMaterialRef) return null;
  return getLiveEcdsaRoleLocalMaterial(
    buildPersistedEcdsaRoleLocalMaterial({
      materialRef: record.roleLocalMaterialRef,
      publicFacts: record.ecdsaRoleLocalPublicFacts,
    }),
  );
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
            materialRef: fixture.record.roleLocalMaterialRef,
          },
        },
      },
    ]);
    expect(liveMaterialForRecord(fixture.record)).toEqual(fixture.roleLocalMaterial);
    expect(material.signerSession.clientShare).toMatchObject({
      kind: 'role_local_worker_share',
      handle: fixture.roleLocalMaterial,
    });
  });

  test('rejects a worker response that changes the durable material identity', async () => {
    const fixture = createRehydrationFixture();
    const substituted = parseEcdsaRoleLocalWorkerHandle({
      ...fixture.roleLocalMaterial,
      durableMaterialRef: 'router-ab-ecdsa-registration:substituted',
    });

    await expect(
      buildReadySecp256k1SigningMaterialFromRecord({
        record: fixture.record,
        requestLabel: 'evm',
        evmFamilySigningKeySlotId: fixture.record.evmFamilySigningKeySlotId,
        workerCtx: successfulRehydrationWorkerContext({
          expected: substituted,
          requests: [],
        }),
      }),
    ).rejects.toThrow('ECDSA role-local signing material hydration changed its identity');
    expect(liveMaterialForRecord(fixture.record)).toBeNull();
  });
});
