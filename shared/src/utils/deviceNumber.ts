export function parseDeviceNumber(value: unknown, options: { min?: number } = {}): number | null {
  const deviceNumber = Number(value);
  const minRaw = options.min;
  const min = Number.isSafeInteger(minRaw) && Number(minRaw) >= 1 ? Number(minRaw) : 1;
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < min) {
    return null;
  }
  return deviceNumber;
}

export function coerceDeviceNumber(
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
