import type { CloudflareDurableObjectNamespaceLike, ThresholdStoreConfigInput } from '../../types';

declare const thresholdStore: CloudflareDurableObjectNamespaceLike;

const inMemoryThresholdStore: ThresholdStoreConfigInput = { kind: 'in-memory' };
const upstashThresholdStore: ThresholdStoreConfigInput = {
  kind: 'upstash-redis-rest',
  url: 'https://upstash.example.invalid',
  token: 'token',
};
const redisThresholdStore: ThresholdStoreConfigInput = {
  kind: 'redis-tcp',
  redisUrl: 'redis://example.invalid:6379',
};
const durableObjectThresholdStore: ThresholdStoreConfigInput = {
  kind: 'cloudflare-do',
  namespace: thresholdStore,
};
const envThresholdStore: ThresholdStoreConfigInput = {
  UPSTASH_REDIS_REST_URL: 'https://upstash.example.invalid',
  UPSTASH_REDIS_REST_TOKEN: 'token',
};

const explicitPostgresThresholdStore: ThresholdStoreConfigInput = {
  // @ts-expect-error Threshold stores no longer expose a partial Postgres backend.
  kind: 'postgres',
  postgresUrl: 'postgres://example.invalid/seams',
};

const envPostgresThresholdStore: ThresholdStoreConfigInput = {
  // @ts-expect-error POSTGRES_URL is not a threshold-store env selector.
  POSTGRES_URL: 'postgres://example.invalid/seams',
};

void inMemoryThresholdStore;
void upstashThresholdStore;
void redisThresholdStore;
void durableObjectThresholdStore;
void envThresholdStore;
void explicitPostgresThresholdStore;
void envPostgresThresholdStore;
