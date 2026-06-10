export function normalizeRequiredString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[NonceCoordinator] ${label} is required`);
  }
  return normalized;
}

export function normalizeBigint(value: unknown, label: string): bigint {
  try {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    const normalized = String(value || '').trim();
    if (/^\d+$/.test(normalized)) return BigInt(normalized);
  } catch {}
  throw new Error(`[NonceCoordinator] invalid ${label}`);
}

export function normalizePositiveInteger(value: unknown, fallback: number): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function normalizeMetricReason(value: unknown, fallback: string): string {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return normalized || fallback;
}

export function maxBigint(...values: bigint[]): bigint {
  if (values.length === 0) return 0n;
  return values.reduce((max, value) => (max > value ? max : value));
}

export function minBigint(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}
