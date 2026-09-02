export function toOptionalEvmAddress(value: unknown): `0x${string}` | undefined {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) return undefined;
  return normalized as `0x${string}`;
}
