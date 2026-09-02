import { toOptionalTrimmedString } from '@shared/utils/validation';

export type NonDurableObjectThresholdStoreKind =
  | 'in-memory'
  | 'upstash-redis-rest'
  | 'redis-tcp';

export function readNonDurableObjectThresholdStoreKind(
  config: Record<string, unknown>,
  storeLabel: string,
): NonDurableObjectThresholdStoreKind | null {
  const kind = toOptionalTrimmedString(config.kind);
  if (!kind) return null;
  if (kind === 'in-memory' || kind === 'upstash-redis-rest' || kind === 'redis-tcp') {
    return kind;
  }
  throw new Error(`[${storeLabel}] Unknown threshold store kind: ${kind}`);
}
