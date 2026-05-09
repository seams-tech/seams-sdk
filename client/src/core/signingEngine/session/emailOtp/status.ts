import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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

export async function claimEmailOtpWarmSessionMaterial(args: {
  sessionId: string;
  uses?: number;
  consume?: boolean;
  claimWarmSessionMaterialFromWorker: (args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
  }) => Promise<WarmSessionClaimResult>;
  shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId: string) => boolean;
  tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (
    sessionId: string,
  ) => Promise<WarmSessionStatusResult | null>;
  recordSessionMaterialClaimed: (
    sessionId: string,
    result: WarmSessionClaimResult,
  ) => Promise<void>;
  recordSessionMaterialRestored: (
    sessionId: string,
    result: WarmSessionStatusResult,
  ) => Promise<void>;
}): Promise<WarmSessionClaimResult> {
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }
  try {
    const result = await args.claimWarmSessionMaterialFromWorker({
      sessionId: normalizedSessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    });
    if (
      !result.ok &&
      result.code === 'not_found' &&
      args.shouldAttemptEcdsaSealedRestoreForSessionId(normalizedSessionId)
    ) {
      const restored =
        await args.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(normalizedSessionId);
      if (restored?.ok) {
        const retry = await args.claimWarmSessionMaterialFromWorker({
          sessionId: normalizedSessionId,
          ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
        });
        await args.recordSessionMaterialClaimed(normalizedSessionId, retry);
        return retry;
      }
      if (restored) {
        await args.recordSessionMaterialRestored(normalizedSessionId, restored);
      }
      return result;
    }
    await args.recordSessionMaterialClaimed(normalizedSessionId, result);
    return result;
  } catch (error) {
    return {
      ok: false,
      code: 'worker_error',
      message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
    };
  }
}

export async function consumeEmailOtpWarmSessionUses(args: {
  sessionId: string;
  uses?: number;
  consumeWarmSessionUsesFromWorker: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId: string) => boolean;
  tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (
    sessionId: string,
  ) => Promise<WarmSessionStatusResult | null>;
  recordSessionUseConsumed: (
    sessionId: string,
    result: WarmSessionStatusResult,
  ) => Promise<void>;
  recordSessionMaterialRestored: (
    sessionId: string,
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
      args.shouldAttemptEcdsaSealedRestoreForSessionId(normalizedSessionId)
    ) {
      const restored =
        await args.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(normalizedSessionId);
      if (restored?.ok) {
        const retry = await args.consumeWarmSessionUsesFromWorker({
          sessionId: normalizedSessionId,
          ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        });
        await args.recordSessionUseConsumed(normalizedSessionId, retry);
        return retry;
      }
      if (restored) {
        await args.recordSessionMaterialRestored(normalizedSessionId, restored);
      }
      return result;
    }
    await args.recordSessionUseConsumed(normalizedSessionId, result);
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
  clearWarmSessionMaterialFromWorker: (sessionId: string) => Promise<void>;
  cleanupSigningSession: (args: {
    sessionId: string;
    chainTarget?: ThresholdEcdsaChainTarget;
    reason: 'explicit_clear' | 'expired' | 'exhausted' | 'invalid_persisted_record';
  }) => Promise<void>;
}): Promise<void> {
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) return;
  await args.clearWarmSessionMaterialFromWorker(normalizedSessionId).catch(() => undefined);
  await args.cleanupSigningSession({
    sessionId: normalizedSessionId,
    reason: 'explicit_clear',
  });
}
