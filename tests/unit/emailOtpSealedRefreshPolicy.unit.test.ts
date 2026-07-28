import { expect, test } from '@playwright/test';
import { EmailOtpSealedRefreshPolicy } from '@/core/signingEngine/session/emailOtp/sealedRefreshPolicy';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

// Refactor 92: expiry and exhaustion are authorization states. They compose
// with an unchanged material hydration result and cannot remove its activation,
// so sealed material survives both and stays available for rehydration after
// re-authorization. Only invalid persisted state may delete it.

function sealedRuntime() {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`sealed runtime fixture did not resolve: ${resolution.reason}`);
  }
  return resolution.runtime;
}

function policyHarness() {
  const runtime = sealedRuntime();
  const deletes: unknown[] = [];
  const policyWrites: Array<{ remainingUses?: number; expiresAtMs?: number }> = [];
  let cacheClears = 0;
  const policy = new EmailOtpSealedRefreshPolicy({
    resolveSealedRuntimeForSession: async () => runtime,
    deleteDurableSealedSessionRecord: (async (command: unknown) => {
      deletes.push(command);
    }) as never,
    updateExactSealedSessionPolicy: (async (input: {
      remainingUses?: number;
      expiresAtMs?: number;
    }) => {
      policyWrites.push({ remainingUses: input.remainingUses, expiresAtMs: input.expiresAtMs });
    }) as never,
    readExactSealedSession: (async () => null) as never,
    clearEcdsaRestoreCaches: () => {
      cacheClears += 1;
    },
  });
  return { policy, runtime, deletes, policyWrites, cacheClears: () => cacheClears };
}

test.describe('Email OTP sealed refresh policy', () => {
  test('an active use writes reduced allowance to the exact sealed record', async () => {
    const { policy, runtime, policyWrites, deletes } = policyHarness();

    await policy.recordSessionUseConsumed(runtime.sealedRecord.thresholdSessionId, {
      ok: true,
      remainingUses: 2,
      expiresAtMs: Date.now() + 60_000,
    } as never);

    expect(policyWrites).toHaveLength(1);
    expect(policyWrites[0]!.remainingUses).toBe(2);
    expect(deletes).toHaveLength(0);
  });

  test('expiry preserves sealed material and never deletes the record', async () => {
    const { policy, runtime, deletes, policyWrites } = policyHarness();

    await policy.recordSessionUseConsumed(runtime.sealedRecord.thresholdSessionId, {
      ok: false,
      code: 'expired',
    } as never);

    // Authorization and restore caches are invalidated; the sealed secret and
    // its activation are untouched.
    expect(deletes).toHaveLength(0);
    expect(policyWrites).toHaveLength(0);
  });

  test('exhaustion preserves sealed material and never deletes the record', async () => {
    const { policy, runtime, deletes, policyWrites } = policyHarness();

    await policy.recordSessionUseConsumed(runtime.sealedRecord.thresholdSessionId, {
      ok: false,
      code: 'exhausted',
    } as never);

    expect(deletes).toHaveLength(0);
    expect(policyWrites).toHaveLength(0);
  });

  test('invalid persisted state is the only reason that deletes sealed material', async () => {
    const { policy, runtime, deletes } = policyHarness();

    await policy.deleteEmailOtpDurableSealedSessionRecord({
      sessionId: runtime.sealedRecord.thresholdSessionId,
      deleteReason: 'invalid_persisted_record',
    });

    expect(deletes).toHaveLength(1);
    // The delete addresses the exact record the session resolved to.
    const command = deletes[0] as { durableRecord?: { thresholdSessionId?: string } };
    expect(command.durableRecord?.thresholdSessionId).toBe(
      runtime.sealedRecord.thresholdSessionId,
    );
  });
});
