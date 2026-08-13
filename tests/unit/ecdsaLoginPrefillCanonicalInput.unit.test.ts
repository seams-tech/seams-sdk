import { expect, test } from '@playwright/test';
import { scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

// The non-iframe prefill path now takes canonical state: the active manifest
// selects the capability and the exact sealed runtime supplies session-scoped
// facts. Nothing on this path reads the composite session record, and a prefill
// that cannot run returns a typed skip rather than throwing, because it is an
// optimisation triggered by unlock and must never fail the unlock.

function resolvedRuntime() {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
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
    getWarmThresholdEcdsaSessionStatus?: Parameters<
      typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill
    >[0]['getWarmThresholdEcdsaSessionStatus'];
    poolEnabled?: boolean;
  } = {},
) {
  const materialSourceCalls: number[] = [];
  return {
    materialSourceCalls,
    deps: {
      getWarmThresholdEcdsaSessionStatus:
        overrides.getWarmThresholdEcdsaSessionStatus ?? (async () => null),
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

test.describe('ECDSA login presignature prefill canonical input', () => {
  test('an inactive authorization is a typed skip that never builds material', async () => {
    const { manifest, walletId, runtime, record } = resolvedRuntime();
    const { deps, materialSourceCalls } = prefillDeps();

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    // Authorization is resolved independently and checked before pool policy
    // and warm status, so with no active Wallet Session this is the first gate.
    expect(result.status).toBe('skipped');
    if (result.status !== 'skipped') return;
    expect(result.reason).toBe('missing_wallet_session_jwt');
    // The threshold-session id is reported as runtime state carried on the
    // resolved runtime, never looked up from a session record.
    expect(result.thresholdSessionId).toBe(runtime.sealedRecord.thresholdSessionId);
    expect(materialSourceCalls).toHaveLength(0);
  });

  test('skips when the warm session is not active, without building material', async () => {
    const { manifest, walletId, runtime, record } = resolvedRuntime();
    const { deps, materialSourceCalls } = prefillDeps({
      getWarmThresholdEcdsaSessionStatus: async () => null,
    });

    const result = await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(deps, {
      walletId,
      manifest,
      runtime,
      chainTarget: record.ecdsaRestore.chainTarget,
    });

    expect(result.status).toBe('skipped');
    if (result.status !== 'skipped') return;
    // Either the wallet-session authorization or the warm status is missing in
    // this environment; both are typed skips, not throws.
    expect(['missing_wallet_session_jwt', 'warm_session_not_active']).toContain(result.reason);
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
