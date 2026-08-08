import type { EmailOtpEcdsaSealedRuntimePurpose } from './sealedRuntimePurpose';
import type { EmailOtpWarmMaterialTarget } from '@/core/signingEngine/workerManager/workerTypes';
import type {
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';

export async function readEmailOtpWarmSessionStatusOnly(args: {
  target: EmailOtpWarmMaterialTarget;
  readWarmSessionStatusFromWorker: (target: EmailOtpWarmMaterialTarget) => Promise<WarmSessionStatusResult>;
}): Promise<WarmSessionStatusResult> {
  const target = normalizedWarmMaterialTarget(args.target);
  if (!target) {
    return { ok: false, code: 'invalid_args', message: 'Missing thresholdSessionId' };
  }
  return await args.readWarmSessionStatusFromWorker(target).catch((error) => ({
    ok: false as const,
    code: 'worker_error',
    message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
  }));
}

export async function consumeEmailOtpWarmSessionUses(args: {
  target: EmailOtpWarmMaterialTarget;
  uses?: number;
  consumeWarmSessionUsesFromWorker: (args: {
    target: EmailOtpWarmMaterialTarget;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  ecdsaPurpose: EmailOtpEcdsaSealedRuntimePurpose | null;
  tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (
    purpose: EmailOtpEcdsaSealedRuntimePurpose,
  ) => Promise<WarmSessionStatusResult | null>;
  recordSessionUseConsumed: (
    purpose: EmailOtpEcdsaSealedRuntimePurpose,
    result: WarmSessionStatusResult,
  ) => Promise<void>;
  recordSessionMaterialRestored: (
    purpose: EmailOtpEcdsaSealedRuntimePurpose,
    result: WarmSessionStatusResult,
  ) => Promise<void>;
}): Promise<WarmSessionStatusResult> {
  const target = normalizedWarmMaterialTarget(args.target);
  if (!target) {
    return { ok: false, code: 'invalid_args', message: 'Missing thresholdSessionId' };
  }
  try {
    const result = await args.consumeWarmSessionUsesFromWorker({
      target,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
    });
    if (
      !result.ok &&
      result.code === 'not_found' &&
      args.ecdsaPurpose
    ) {
      const restored = await args.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
        args.ecdsaPurpose,
      );
      if (restored?.ok) {
        const retry = await args.consumeWarmSessionUsesFromWorker({
          target,
          ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        });
        if (args.ecdsaPurpose) await args.recordSessionUseConsumed(args.ecdsaPurpose, retry);
        return retry;
      }
      if (restored) {
        if (args.ecdsaPurpose) await args.recordSessionMaterialRestored(args.ecdsaPurpose, restored);
      }
      return result;
    }
    if (args.ecdsaPurpose) await args.recordSessionUseConsumed(args.ecdsaPurpose, result);
    return result;
  } catch (error) {
    return {
      ok: false,
      code: 'worker_error',
      message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
    };
  }
}

export async function clearEmailOtpWarmSessionMaterial(args: {
  target: EmailOtpWarmMaterialTarget;
  clearVolatileWarmSessionMaterialFromWorker: (target: EmailOtpWarmMaterialTarget) => Promise<void>;
}): Promise<void> {
  const target = normalizedWarmMaterialTarget(args.target);
  if (!target) return;
  await args.clearVolatileWarmSessionMaterialFromWorker(target).catch(() => undefined);
}

function normalizedWarmMaterialTarget(
  target: EmailOtpWarmMaterialTarget,
): EmailOtpWarmMaterialTarget | null {
  const thresholdSessionId = String(target.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  return target.kind === 'ecdsa'
    ? { kind: 'ecdsa', thresholdSessionId }
    : {
        kind: 'ed25519_yao',
        thresholdSessionId,
        materialActivation: target.materialActivation,
      };
}
