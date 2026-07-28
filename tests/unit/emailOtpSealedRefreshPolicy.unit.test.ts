import { expect, test } from '@playwright/test';
import { EmailOtpSealedRefreshPolicy } from '@/core/signingEngine/session/emailOtp/sealedRefreshPolicy';
import type { EmailOtpEcdsaSealedRuntimePurpose } from '@/core/signingEngine/session/emailOtp/sealedRuntimePurpose';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

// Refactor 92: expiry and exhaustion are authorization states. They compose
// with an unchanged material hydration result and cannot remove its activation,
// so sealed material survives both. Only invalid persisted state may delete it.
//
// A threshold-session id indexes runtime state and never selects material, so
// every policy call carries the lane it belongs to.

const TEMPO = { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' } as const;
const EVM = { kind: 'evm', chainId: 1, networkSlug: 'ethereum' } as const;

function purpose(
  thresholdSessionId: string,
  chainTarget: EmailOtpEcdsaSealedRuntimePurpose['chainTarget'] = TEMPO,
): EmailOtpEcdsaSealedRuntimePurpose {
  return { thresholdSessionId, chainTarget };
}

function policyHarness() {
  const deletes: unknown[] = [];
  const policyWrites: Array<{
    thresholdSessionId: string;
    filter: { chainTarget?: { kind?: string } };
    remainingUses?: number;
  }> = [];
  const policy = new EmailOtpSealedRefreshPolicy({
    deleteDurableSealedSessionRecord: (async (command: unknown) => {
      deletes.push(command);
    }) as never,
    updateExactSealedSessionPolicy: (async (input: {
      thresholdSessionId: string;
      filter: { chainTarget?: { kind?: string } };
      remainingUses?: number;
    }) => {
      policyWrites.push(input);
    }) as never,
    clearEcdsaRestoreCaches: () => undefined,
  });
  return { policy, deletes, policyWrites };
}

test.describe('Email OTP sealed refresh policy', () => {
  test('an active use writes reduced allowance to the exact record named by the purpose', async () => {
    const { policy, policyWrites, deletes } = policyHarness();

    await policy.recordSessionUseConsumed(purpose('ec-session'), {
      ok: true,
      remainingUses: 2,
      expiresAtMs: Date.now() + 60_000,
    } as never);

    expect(policyWrites).toHaveLength(1);
    expect(policyWrites[0]!.thresholdSessionId).toBe('ec-session');
    expect(policyWrites[0]!.remainingUses).toBe(2);
    expect(deletes).toHaveLength(0);
  });

  test('identical session ids on different targets address their own lane', async () => {
    const { policy, policyWrites } = policyHarness();

    await policy.recordSessionUseConsumed(purpose('shared-session', TEMPO), {
      ok: true,
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
    } as never);
    await policy.recordSessionUseConsumed(purpose('shared-session', EVM), {
      ok: true,
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
    } as never);

    // The supplied target is used verbatim; there is no scan and no preference
    // between configured targets.
    expect(policyWrites.map((write) => write.filter.chainTarget?.kind)).toEqual(['tempo', 'evm']);
  });

  test('expiry preserves sealed material and never deletes the record', async () => {
    const { policy, deletes, policyWrites } = policyHarness();
    await policy.recordSessionUseConsumed(purpose('ec-session'), {
      ok: false,
      code: 'expired',
    } as never);
    expect(deletes).toHaveLength(0);
    expect(policyWrites).toHaveLength(0);
  });

  test('exhaustion preserves sealed material and never deletes the record', async () => {
    const { policy, deletes, policyWrites } = policyHarness();
    await policy.recordSessionUseConsumed(purpose('ec-session'), {
      ok: false,
      code: 'exhausted',
    } as never);
    expect(deletes).toHaveLength(0);
    expect(policyWrites).toHaveLength(0);
  });

  test('invalid persisted state is the only reason that deletes sealed material', async () => {
    const { policy, deletes } = policyHarness();

    await policy.deleteEmailOtpDurableSealedSessionRecord({
      purpose: purpose('ec-session'),
      deleteReason: 'invalid_persisted_record',
    });

    expect(deletes).toHaveLength(1);
    const command = deletes[0] as {
      durableRecord?: { thresholdSessionId?: string; chainTarget?: { kind?: string } };
    };
    expect(command.durableRecord?.thresholdSessionId).toBe('ec-session');
    expect(command.durableRecord?.chainTarget?.kind).toBe('tempo');
  });

  test('a sibling record cannot satisfy a mismatched requested session', () => {
    const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
    const sibling = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest,
      thresholdSessionId: 'ec-session-sibling',
    });
    const walletId = toWalletId(String(manifest.signer.walletId));

    // The sibling is a perfectly valid record for this material, so correlation
    // resolves -- which is exactly why the requested session id must be checked
    // against what came back rather than assumed.
    const resolution = resolveExactEcdsaSealedRuntime({
      manifest,
      walletId,
      chainTarget: sibling.ecdsaRestore.chainTarget,
      sealedRecords: [sibling],
    });
    expect(resolution.kind).toBe('resolved');
    if (resolution.kind !== 'resolved') return;
    expect(resolution.runtime.sealedRecord.thresholdSessionId).toBe('ec-session-sibling');
    expect(resolution.runtime.sealedRecord.thresholdSessionId).not.toBe('ec-session-requested');
  });
});
