import { expect, test } from '@playwright/test';
import { resolveReadySecp256k1SigningMaterialFromRecord } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
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
  type EcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { buildPasskeyEcdsaSessionRecordFixture } from './helpers/signingSessionRecord.fixtures';
import {
  buildEcdsaRoleLocalPersistedMaterialRefFixture,
  buildMpcMaterialActivationRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import { buildEvmFamilyEcdsaKeyIdentityFromRecord } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildEvmFamilyEcdsaSignerBinding } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';

type RehydrationFixture = {
  record: ThresholdEcdsaSessionRecord;
  store: ThresholdEcdsaSessionStoreDeps;
  roleLocalMaterial: EcdsaRoleLocalWorkerHandle;
  materialRef: EcdsaRoleLocalPersistedMaterialRef;
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
  const materialRef = buildEcdsaRoleLocalPersistedMaterialRefFixture({
    durableMaterialRef,
    bindingDigest: record.ecdsaRoleLocalPublicFacts.contextBinding32B64u,
    materialOwner: record.walletId,
  });
  clearAllThresholdEcdsaSessionRecords(store);
  return { record, store, roleLocalMaterial, materialRef };
}

function successfulRehydrationWorkerContext(args: {
  expected: EcdsaRoleLocalWorkerHandle;
  materialRef: EcdsaRoleLocalPersistedMaterialRef;
  requests: unknown[];
}): WorkerOperationContext {
  return {
    requestWorkerOperation: async (request) => {
      args.requests.push(request);
      return {
        type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          kind: 'ecdsa_role_local_signing_material_opened_v1',
          ok: true,
          liveHandle: args.expected,
          materialRef: args.materialRef,
        },
      } as never;
    },
  };
}

function liveMaterialForRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaRoleLocalWorkerHandle | null {
  return getLiveEcdsaRoleLocalMaterial(
    buildPersistedEcdsaRoleLocalMaterial({
      authority: record.authority,
      materialActivation: record.materialActivation,
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

    const resolution = await resolveReadySecp256k1SigningMaterialFromRecord({
      record: fixture.record,
      requestLabel: 'evm',
      materialActivation: fixture.record.materialActivation,
      workerCtx: successfulRehydrationWorkerContext({
        expected: fixture.roleLocalMaterial,
        materialRef: fixture.materialRef,
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
            kind: 'open_ecdsa_role_local_signing_material_v1',
            authority: fixture.record.authority,
            materialActivation: fixture.record.materialActivation,
          },
        },
      },
    ]);
    expect(liveMaterialForRecord(fixture.record)).toEqual(fixture.roleLocalMaterial);
    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') return;
    expect(resolution.material.signerSession.clientShare).toMatchObject({
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
      resolveReadySecp256k1SigningMaterialFromRecord({
        record: fixture.record,
        requestLabel: 'evm',
        materialActivation: fixture.record.materialActivation,
        workerCtx: successfulRehydrationWorkerContext({
          expected: substituted,
          materialRef: fixture.materialRef,
          requests: [],
        }),
      }),
    ).rejects.toThrow('ECDSA role-local signing material hydration changed its identity');
    expect(liveMaterialForRecord(fixture.record)).toBeNull();
  });

  test('classifies an exact material activation mismatch without entering authorization flow', async () => {
    const fixture = createRehydrationFixture();
    const mismatchedActivation = buildMpcMaterialActivationRefFixture(
      'rehydration-mismatch',
      fixture.record.walletId,
    );
    const result = await resolveReadySecp256k1SigningMaterialFromRecord({
      record: fixture.record,
      requestLabel: 'evm',
      materialActivation: mismatchedActivation,
      workerCtx: {
        requestWorkerOperation: async () => {
          throw new Error('worker must not open mismatched material');
        },
      },
    });

    expect(result).toEqual({
      kind: 'unavailable',
      reason: 'material_activation_mismatch',
    });
  });

  test('rejects a signer binding whose material owner is another wallet', () => {
    const fixture = createRehydrationFixture();
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record: fixture.record });
    const otherWalletActivation = buildMpcMaterialActivationRefFixture(
      'other-wallet',
      'other-wallet.testnet',
    );

    expect(() =>
      buildEvmFamilyEcdsaSignerBinding({
        walletId: fixture.record.walletId,
        chainTarget: fixture.record.chainTarget,
        keyHandle: fixture.record.keyHandle,
        key,
        materialActivation: otherWalletActivation,
      }),
    ).toThrow('exact ECDSA lane material owner mismatch');
  });
});
