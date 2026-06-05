import type { TempoSignerCapability } from '@/web/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly } from '@/core/types/seams';

export function toSerializableTempoError(
  error: unknown,
): { code?: string; message?: string; details?: unknown } | undefined {
  if (error == null) return undefined;
  if (typeof error === 'string') return { message: error };
  if (error instanceof Error) {
    const code = 'code' in error ? String((error as { code?: unknown }).code || '').trim() : '';
    return {
      ...(code ? { code } : {}),
      message: String(error.message || ''),
    };
  }
  if (typeof error === 'object') {
    const value = error as { code?: unknown; message?: unknown; details?: unknown };
    const code = String(value.code || '').trim();
    const message = String(value.message || '').trim();
    return {
      ...(code ? { code } : {}),
      ...(message ? { message } : {}),
      ...(value.details !== undefined ? { details: value.details } : {}),
    };
  }
  return { message: String(error) };
}

export function buildTempoBootstrapArgs(
  configs: SeamsConfigsReadonly,
  args: Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0],
): Parameters<TempoSignerCapability['bootstrapEcdsaSession']>[0] {
  const managedRegistration = configs.registration.mode === 'managed' ? configs.registration : null;
  const runtimeScopeBootstrap =
    args.runtimeScopeBootstrap ||
    (managedRegistration
      ? {
          environmentId: managedRegistration.environmentId,
          publishableKey: managedRegistration.publishableKey,
        }
      : undefined);
  const chainTarget = args.chainTarget;
  if (chainTarget.kind !== 'tempo') {
    throw new Error('[SeamsWeb][tempo] bootstrapEcdsaSession requires a Tempo chainTarget');
  }
  return {
    ...args,
    ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
  };
}
