export function normalizeSmartAccountDeploymentAttempts(
  value: unknown,
  fallback: number,
): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  const rounded = Math.trunc(value);
  if (rounded < 1) return 1;
  if (rounded > 5) return 5;
  return rounded;
}
