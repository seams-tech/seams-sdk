import { expect, test } from '@playwright/test';
import { scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  ecdsaCapabilityActivationLookupFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { parseWalletAuthorityId } from '@shared/utils/domainIds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';

// The non-iframe prefill path now takes canonical state: the active manifest
// selects the capability and the exact sealed runtime supplies session-scoped
// facts. Nothing on this path reads the composite session record, and a prefill
// that cannot run returns a typed skip rather than throwing, because it is an
// optimisation triggered by unlock and must never fail the unlock.

function resolvedRuntime(manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest) {
  const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const walletId = toWalletId(String(manifest.signer.walletId));
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId,
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`sealed runtime fixture did not resolve: ${resolution.reason}`);
  }
  return { manifest, walletId, runtime: resolution.runtime, record };
}

function prefillDeps(
  overrides: {
    resolveActiveWalletAuthority?: Parameters<
      typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill
    >[0]['resolveActiveWalletAuthority'];
    readExactWalletSessionWithOperationCredential?: Parameters<
      typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill
    >[0]['readExactWalletSessionWithOperationCredential'];
    poolEnabled?: boolean;
  } = {},
) {
  const materialSourceCalls: number[] = [];
  return {
    materialSourceCalls,
    deps: {
      resolveActiveWalletAuthority: overrides.resolveActiveWalletAuthority ?? (async () => null),
      readExactWalletSessionWithOperationCredential:
        overrides.readExactWalletSessionWithOperationCredential ??
        (async () => {
          throw new Error('exact Wallet Session read must not run in this test');
        }),
      getSignerWorkerContext: () => {
        throw new Error('prefill must not reach the signer worker in this test');
      },
      resolveClientSigningMaterialSource: () => {
        materialSourceCalls.push(1);
        throw new Error('prefill must not build material before its guards pass');
      },
      routerAbEcdsaDerivationPresignaturePoolPolicy:
        overrides.poolEnabled === false ? { enabled: false } : undefined,
    } as Parameters<typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill>[0],
  };
}

function activeAuthorityForManifest(manifest: ReturnType<typeof resolvedRuntime>['manifest']) {
  const authorityId = parseWalletAuthorityId('authority:ecdsa-login-prefill');
  if (!authorityId.ok) throw new Error(authorityId.error.message);
  return {
    walletId: manifest.signer.walletId,
    authorityId: authorityId.value,
    walletAuthMethodId: manifest.signer.authority.walletAuthMethodId,
    authorityDigestB64u: parseDigestB64u('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    authorityRevocationEpoch: 0,
  };
}

test.describe('ECDSA login presignature prefill canonical input', () => {
  test('an unavailable active authority is a typed skip that never builds material', async () => {
    const { manifest, walletId, runtime, record } = resolvedRuntime();
    const { deps, materialSourceCalls } = prefillDeps();

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result.status).toBe('skipped');
    if (result.status !== 'skipped') return;
    expect(result.reason).toBe('exact_wallet_session_unavailable');
    expect(result.thresholdSessionId).toBe(runtime.sealedRecord.thresholdSessionId);
    expect(materialSourceCalls).toHaveLength(0);
  });

  test('reads the exact Wallet Session for the resolved authority and method', async () => {
    const { manifest, walletId, runtime, record } = resolvedRuntime();
    const activeAuthority = activeAuthorityForManifest(manifest);
    const exactReadInputs: Array<{
      walletId: typeof activeAuthority.walletId;
      authorityId: typeof activeAuthority.authorityId;
      authMethodId: typeof activeAuthority.walletAuthMethodId;
    }> = [];
    const { deps, materialSourceCalls } = prefillDeps({
      resolveActiveWalletAuthority: async () => activeAuthority,
      readExactWalletSessionWithOperationCredential: async (input) => {
        exactReadInputs.push(input);
        return { kind: 'missing' };
      },
    });

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result.status).toBe('skipped');
    if (result.status !== 'skipped') return;
    expect(result.reason).toBe('exact_wallet_session_unavailable');
    expect(exactReadInputs).toEqual([
      {
        walletId,
        authorityId: activeAuthority.authorityId,
        authMethodId: manifest.signer.authority.walletAuthMethodId,
      },
    ]);
    expect(materialSourceCalls).toHaveLength(0);
  });

  test('a corrupt exact Wallet Session read remains a typed skip', async () => {
    const { manifest, walletId, runtime, record } = resolvedRuntime();
    const { deps, materialSourceCalls } = prefillDeps({
      resolveActiveWalletAuthority: async () => activeAuthorityForManifest(manifest),
      readExactWalletSessionWithOperationCredential: async () => {
        throw new Error('stored exact state is corrupt');
      },
    });

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result).toMatchObject({
      status: 'skipped',
      reason: 'exact_wallet_session_unavailable',
      thresholdSessionId: runtime.sealedRecord.thresholdSessionId,
    });
    expect(materialSourceCalls).toHaveLength(0);
  });

  test('accepts the exact active session through the pool-policy gate', async () => {
    const manifest = ecdsaCapabilityActivationLookupFixture().manifest;
    const authorityFixture = await buildLinkedDeviceManagementAuthorityFixture({
      label: 'ecdsa-login-prefill',
      permissions: buildFullOwnerPermissionsV1(),
      provenance: 'wallet_registration',
      keyFamily: 'ecdsa_secp256k1',
      materialActivation: manifest.activation.materialActivation,
      identity: {
        walletId: String(manifest.signer.walletId),
        authorityId: 'authority:ecdsa-login-prefill',
        walletAuthMethodId: String(manifest.signer.authority.walletAuthMethodId),
        rpId: 'prefill.example.test',
      },
      expiresAtMs: Date.now() + 60_000,
    });
    const { walletId, runtime, record } = resolvedRuntime(manifest);
    const { deps, materialSourceCalls } = prefillDeps({
      poolEnabled: false,
      resolveActiveWalletAuthority: async () => ({
        walletId,
        authorityId: authorityFixture.authority.authorityId,
        walletAuthMethodId: authorityFixture.authMethod.walletAuthMethodId,
        authorityDigestB64u: authorityFixture.authority.authorityDigestB64u,
        authorityRevocationEpoch: authorityFixture.authority.revocationEpoch,
      }),
      readExactWalletSessionWithOperationCredential: async () => ({
        kind: 'found',
        record: authorityFixture.activeWalletSession,
        operationCredential: authorityFixture.operationCredential,
      }),
    });

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result).toMatchObject({
      status: 'skipped',
      reason: 'pool_disabled',
      thresholdSessionId: runtime.sealedRecord.thresholdSessionId,
    });
    expect(materialSourceCalls).toHaveLength(0);
  });

  test('an expired sealed runtime skips rather than scheduling a refill', async () => {
    const { manifest, walletId, record } = resolvedRuntime();
    const expiredRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      expiresAtMs: Date.now() - 1_000,
    });
    const expired = resolveExactEcdsaSealedRuntime({
      manifest,
      walletId,
      chainTarget: record.ecdsaRestore.chainTarget,
      sealedRecords: [expiredRecord],
    });
    expect(expired.kind).toBe('resolved');
    if (expired.kind !== 'resolved') return;

    const { deps, materialSourceCalls } = prefillDeps();
    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime: expired.runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result.status).toBe('skipped');
    expect(materialSourceCalls).toHaveLength(0);
  });
});
