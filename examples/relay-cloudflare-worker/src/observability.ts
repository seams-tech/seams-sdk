import {
  createPostgresConsoleObservabilityIngestionService,
  type ConsoleObservabilityIngestionService,
} from '@seams/sdk/server/router/cloudflare';

export interface WorkerObservabilityEnv {
  BILLING_POSTGRES_URL?: string;
  BILLING_NAMESPACE?: string;
  WEBHOOK_RETRY_POSTGRES_URL?: string;
  WEBHOOK_RETRY_NAMESPACE?: string;
}

export function resolveWorkerCronObservabilityConfig(env: WorkerObservabilityEnv): {
  postgresUrl?: string;
  namespace?: string;
} {
  const postgresUrl =
    String(env.WEBHOOK_RETRY_POSTGRES_URL || '').trim() ||
    String(env.BILLING_POSTGRES_URL || '').trim();
  const namespace =
    String(env.WEBHOOK_RETRY_NAMESPACE || '').trim() ||
    String(env.BILLING_NAMESPACE || '').trim() ||
    'console-default';
  return {
    ...(postgresUrl ? { postgresUrl } : {}),
    namespace,
  };
}

export async function createWorkerCronObservabilityIngestion(
  env: WorkerObservabilityEnv,
): Promise<ConsoleObservabilityIngestionService | null> {
  const resolved = resolveWorkerCronObservabilityConfig(env);
  if (!resolved.postgresUrl) return null;
  return createPostgresConsoleObservabilityIngestionService({
    postgresUrl: resolved.postgresUrl,
    namespace: resolved.namespace,
    logger: console as any,
  });
}
