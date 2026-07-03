import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AuthServiceConfig } from '../types';
import { coerceThresholdNodeRole } from '../ThresholdService/config';

function thresholdStoreKind(cfg: NonNullable<AuthServiceConfig['thresholdStore']>): string {
  if ('kind' in cfg) {
    switch (cfg.kind) {
      case 'upstash-redis-rest':
        return 'upstash';
      case 'redis-tcp':
        return 'redis';
      case 'cloudflare-do':
        return 'cloudflare-do';
      case 'in-memory':
        return 'in-memory';
    }
  }
  const upstashUrl = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_TOKEN);
  const redisUrl = toOptionalTrimmedString(cfg.REDIS_URL);
  if (upstashUrl || upstashToken) return 'upstash';
  if (redisUrl) return 'redis';
  return 'in-memory';
}

export function summarizeThresholdStoreConfig(cfg: AuthServiceConfig['thresholdStore']): string {
  if (!cfg) return 'thresholdStore: not configured';

  const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
  const store = thresholdStoreKind(cfg);
  const hasSigningRootSecretShares = Boolean(
    cfg.signingRootShareResolver ||
      cfg.signingRootShareResolverAdapters ||
      (cfg.signingRootSharePolicy &&
        cfg.signingRootShareStore &&
        cfg.signingRootShareDecryptAdapter),
  );
  const parts = [
    `thresholdStore: configured`,
    `nodeRole=${nodeRole}`,
    `store=${store}`,
    `signingRootSecretShares=${hasSigningRootSecretShares ? 'configured' : 'not_configured'}`,
  ];
  return parts.join(' ');
}
