import type { EmailOtpEcdsaSealedRuntimePurpose } from './sealedRuntimePurpose';
import type {
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';

export async function readEmailOtpWarmSessionStatusOnly(args: {
  sessionId: string;
  readWarmSessionStatusFromWorker: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): Promise<WarmSessionStatusResult> {
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  return await args.readWarmSessionStatusFromWorker(normalizedSessionId).catch((error) => ({
    ok: false as const,
    code: 'worker_error',
    message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
  }));
}

export async function consumeEmailOtpWarmSessionUses(args: {
  sessionId: string;
  uses?: number;
  consumeWarmSessionUsesFromWorker: (args: {
    sessionId: string;
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
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  try {
    const result = await args.consumeWarmSessionUsesFromWorker({
      sessionId: normalizedSessionId,
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
          sessionId: normalizedSessionId,
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
  sessionId: string;
  clearVolatileWarmSessionMaterialFromWorker: (sessionId: string) => Promise<void>;
}): Promise<void> {
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) return;
  await args.clearVolatileWarmSessionMaterialFromWorker(normalizedSessionId).catch(() => undefined);
}
