const SELECTOR_HEX_RE = /^0x[0-9a-f]{8}$/;

export function normalizeHexData(value: unknown, options: { lowercase?: boolean } = {}): string {
  const raw = String(value || '').trim();
  if (!raw) return '0x';
  const prefixed = /^0x/i.test(raw) ? `0x${raw.slice(2)}` : `0x${raw}`;
  const normalized = prefixed === '0x' ? '0x' : prefixed;
  return options.lowercase ? normalized.toLowerCase() : normalized;
}

export function normalizeHexSelector(value: unknown): string | undefined {
  const normalized = normalizeHexData(value, { lowercase: true });
  if (!SELECTOR_HEX_RE.test(normalized)) return undefined;
  return normalized;
}

export function deriveSelectorFromHexData(dataHex: unknown): string | undefined {
  const normalized = normalizeHexData(dataHex, { lowercase: true });
  if (!normalized.startsWith('0x') || normalized.length < 10) return undefined;
  return normalizeHexSelector(normalized.slice(0, 10));
}
