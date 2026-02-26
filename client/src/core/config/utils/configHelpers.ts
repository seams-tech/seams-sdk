import type { ThemePaletteName } from '../../types/tatchi';
import type { RegistrationSignerOptions } from '../../types/registrationSignerOptions';

export function coercePositiveIntInRange(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  const rounded = Math.trunc(value);
  if (rounded < min) return min;
  if (rounded > max) return max;
  return rounded;
}

export function coerceOptionalPositiveInt(value: unknown, fallback?: number): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.trunc(value);
  }
  if (typeof fallback === 'number' && Number.isFinite(fallback) && fallback > 0) {
    return Math.trunc(fallback);
  }
  return undefined;
}

export function coerceBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function coerceThemePaletteName(value: unknown): ThemePaletteName | undefined {
  return value === 'default' ? value : undefined;
}

export function toStringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

export function cloneRegistrationSignerOptions(
  value: RegistrationSignerOptions,
): RegistrationSignerOptions {
  return {
    tempo: {
      ...value.tempo,
      participantIds: Array.isArray(value.tempo.participantIds)
        ? [...value.tempo.participantIds]
        : [],
      ...(value.tempo.smartAccount ? { smartAccount: { ...value.tempo.smartAccount } } : {}),
    },
    evm: {
      ...value.evm,
      participantIds: Array.isArray(value.evm.participantIds)
        ? [...value.evm.participantIds]
        : [],
      ...(value.evm.smartAccount ? { smartAccount: { ...value.evm.smartAccount } } : {}),
    },
  };
}
