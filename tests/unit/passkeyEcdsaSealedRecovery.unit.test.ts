import { expect, test } from '@playwright/test';

import type { WarmSessionSealTransportInput } from '../../packages/wallet/src/core/types/secure-confirm-worker';
import { resolveExactEcdsaSealedRuntime } from '../../packages/wallet/src/core/signingEngine/session/material/ecdsaSealedRuntime';
import { restorePasskeyEcdsaSealedRecordForWallet } from '../../packages/wallet/src/core/signingEngine/session/passkey/ecdsaRecovery';
import { toWalletId } from '../../packages/wallet/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeSealedRecoveryRecord,
  type PasskeyEcdsaSealedRecoveryRecord,
} from '../../packages/wallet/src/core/signingEngine/session/sealedRecovery/recoveryRecord';
import { walletAuthAuthorityRef } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildPasskeyEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

async function passkeyTransport(
  record: PasskeyEcdsaSealedRecoveryRecord,
): Promise<WarmSessionSealTransportInput> {
  return {
    curve: 'ecdsa',
    authMethod: 'passkey',
    walletId: record.walletId,
    walletSessionJwt: 'wallet-session-test-jwt',
    relayerUrl: record.relayerUrl,
    chainTarget: record.chainTarget,
    groupId: record.groupId,
    ecdsaRestore: {
      source: record.source,
      chainTarget: record.chainTarget,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      keyHandle: record.keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      ethereumAddress: record.ethereumAddress,
      relayerKeyId: record.relayerKeyId,
      clientVerifyingShareB64u: record.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      participantIds: [...record.participantIds],
      runtimePolicyScope: record.runtimePolicyScope,
      routerAbEcdsaDerivationNormalSigning: record.routerAbEcdsaDerivationNormalSigning,
      publicCapability: record.publicCapability,
      authority: await walletAuthAuthorityRef({ authority: record.authority }),
      roleLocalMaterialRef: record.roleLocalMaterialRef,
      rpId: record.authority.verifier.rpId,
      credentialIdB64u: record.authority.factor.credentialIdB64u,
    },
  };
}

async function recoveryFixture(remainingUses: number) {
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('passkey');
  const rawRecord = buildPasskeyEcdsaSealedRuntimeRecordFixture({
    manifest: fixture.manifest,
    remainingUses,
  });
  const normalized = normalizeSealedRecoveryRecord(rawRecord);
  if (normalized.kind !== 'accepted' || normalized.record.authMethod !== 'passkey') {
    throw new Error('passkey ECDSA recovery fixture must normalize to a passkey record');
  }
  const record = normalized.record;
  const resolver = async () =>
    resolveExactEcdsaSealedRuntime({
      manifest: fixture.manifest,
      walletId: toWalletId(record.walletId),
      chainTarget: record.chainTarget,
      sealedRecords: [rawRecord],
    });
  return {
    fixture,
    rawRecord,
    record,
    resolver,
    purpose: {
      walletId: record.walletId,
      authMethod: 'passkey' as const,
      curve: 'ecdsa' as const,
      chainTarget: record.chainTarget,
      materialActivation: record.roleLocalMaterialRef.materialActivation,
      thresholdSessionId: record.thresholdSessionId,
      reason: 'transaction' as const,
    },
    transport: await passkeyTransport(record),
  };
}

function requireFixtureGroupId(record: PasskeyEcdsaSealedRecoveryRecord): string {
  const groupId = String(record.groupId || '').trim();
  if (!groupId) throw new Error('passkey ECDSA recovery fixture requires a group id');
  return groupId;
}

test.describe('Passkey ECDSA sealed recovery exact-owner fence', () => {
  test('preserves a validated zero allowance during worker rehydrate', async () => {
    const fixture = await recoveryFixture(0);
    const rehydrateInputs: Array<{ remainingUses: number }> = [];
    const policyWrites: unknown[] = [];
    const restoredStatuses: unknown[] = [];

    const result = await restorePasskeyEcdsaSealedRecordForWallet({
      record: fixture.record,
      purpose: fixture.purpose,
      transport: fixture.transport,
      groupId: requireFixtureGroupId(fixture.record),
      rehydrateWarmSessionMaterial: async (input) => {
        rehydrateInputs.push({ remainingUses: input.remainingUses });
        return { ok: true, remainingUses: 0, expiresAtMs: Date.now() + 60_000 };
      },
      deletePersistedRecord: async () => undefined,
      recordSessionMaterialRestored: async (status) => {
        restoredStatuses.push(status);
      },
      readWarmSessionStatusFromWorker: async () => ({
        ok: true,
        remainingUses: 0,
        expiresAtMs: Date.now() + 60_000,
      }),
      resolveCurrentEcdsaCapabilityRuntime: fixture.resolver,
      updatePersistedPolicy: async (policy) => {
        policyWrites.push(policy);
      },
    });

    expect(result).toMatchObject({ ok: true, remainingUses: 0 });
    expect(rehydrateInputs).toEqual([{ remainingUses: 0 }]);
    expect(policyWrites).toHaveLength(1);
    expect(restoredStatuses).toHaveLength(1);
  });

  test('returns superseded before worker rehydrate with no side effects', async () => {
    const fixture = await recoveryFixture(2);
    const workerCalls: unknown[] = [];
    const durableWrites: unknown[] = [];
    const result = await restorePasskeyEcdsaSealedRecordForWallet({
      record: fixture.record,
      purpose: fixture.purpose,
      transport: fixture.transport,
      groupId: requireFixtureGroupId(fixture.record),
      rehydrateWarmSessionMaterial: async () => {
        workerCalls.push(true);
        return { ok: true, remainingUses: 1, expiresAtMs: Date.now() + 60_000 };
      },
      deletePersistedRecord: async () => durableWrites.push('delete'),
      recordSessionMaterialRestored: async () => durableWrites.push('record'),
      readWarmSessionStatusFromWorker: async () => ({
        ok: true,
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      resolveCurrentEcdsaCapabilityRuntime: async () => ({
        kind: 'blocked',
        reason: 'missing_capability',
      }),
      updatePersistedPolicy: async () => durableWrites.push('policy'),
    });

    expect(result).toMatchObject({ ok: false, code: 'superseded' });
    expect(workerCalls).toHaveLength(0);
    expect(durableWrites).toHaveLength(0);
  });

  test('returns superseded before durable writes after a replacement race', async () => {
    const fixture = await recoveryFixture(2);
    const workerCalls: unknown[] = [];
    const durableWrites: unknown[] = [];
    let resolverCalls = 0;
    const result = await restorePasskeyEcdsaSealedRecordForWallet({
      record: fixture.record,
      purpose: fixture.purpose,
      transport: fixture.transport,
      groupId: requireFixtureGroupId(fixture.record),
      rehydrateWarmSessionMaterial: async () => {
        workerCalls.push(true);
        return { ok: true, remainingUses: 1, expiresAtMs: Date.now() + 60_000 };
      },
      deletePersistedRecord: async () => durableWrites.push('delete'),
      recordSessionMaterialRestored: async () => durableWrites.push('record'),
      readWarmSessionStatusFromWorker: async () => ({
        ok: true,
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      }),
      resolveCurrentEcdsaCapabilityRuntime: async (input) => {
        resolverCalls += 1;
        if (resolverCalls === 1) return await fixture.resolver();
        return { kind: 'blocked', reason: 'missing_capability' };
      },
      updatePersistedPolicy: async () => durableWrites.push('policy'),
    });

    expect(result).toMatchObject({ ok: false, code: 'superseded' });
    expect(workerCalls).toHaveLength(1);
    expect(durableWrites).toHaveLength(0);
    expect(resolverCalls).toBe(2);
  });
});
