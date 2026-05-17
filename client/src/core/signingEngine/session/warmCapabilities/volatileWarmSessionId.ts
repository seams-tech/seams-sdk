declare const volatileWarmSessionIdBrand: unique symbol;

export type VolatileWarmSessionId = string & {
  readonly [volatileWarmSessionIdBrand]: 'VolatileWarmSessionId';
};

export function parseVolatileWarmSessionId(value: unknown): VolatileWarmSessionId | null {
  const normalized = String(value ?? '').trim();
  return normalized ? (normalized as VolatileWarmSessionId) : null;
}
