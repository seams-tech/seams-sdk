export type SignerSlot = number & { readonly __brand: 'SignerSlot' };

export function parseSignerSlot(
  value: unknown,
  options: { min?: number } = {},
): SignerSlot | null {
  const signerSlot = Number(value);
  const minRaw = options.min;
  const min = Number.isSafeInteger(minRaw) && Number(minRaw) >= 1 ? Number(minRaw) : 1;
  if (!Number.isSafeInteger(signerSlot) || signerSlot < min) {
    return null;
  }
  return signerSlot as SignerSlot;
}

export function coerceSignerSlot(
  value: unknown,
  options: { min?: number; fallback?: number } = {},
): number {
  const minRaw = options.min;
  const min = Number.isSafeInteger(minRaw) && Number(minRaw) >= 1 ? Number(minRaw) : 1;
  const fallbackRaw = Number(options.fallback ?? min);
  const fallback = Number.isFinite(fallbackRaw) && fallbackRaw >= min ? Math.floor(fallbackRaw) : min;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= min ? Math.floor(parsed) : fallback;
}
