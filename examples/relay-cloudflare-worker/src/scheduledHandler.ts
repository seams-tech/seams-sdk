import type { AuthService } from '@seams/sdk-server';
import {
  createCloudflareCron,
  type CfExecutionContext as Ctx,
  type CfScheduledEvent,
  type RelayCloudflareWorkerEnv,
} from '@seams/sdk-server/router/cloudflare';
import type { ConsoleObservabilityIngestionService } from '@seams/sdk-server/router/express';
import { createWorkerCronOptions, type WorkerCronConfigEnv } from './cronConfig';
import { resolveWorkerCronFeatureFlags } from './cronFlags';
import { collectWorkerCronConfigIssues } from './cronValidation';

export interface WorkerScheduledEnv extends RelayCloudflareWorkerEnv, WorkerCronConfigEnv {
  BILLING_FINALIZATION_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  WEBHOOK_RETRY_ENABLED?: string;
}

export interface WorkerRuntimeSnapshotOutboxSink {
  applyOutboxEvent(event: { payload: Record<string, unknown> }): void;
}

export interface WorkerScheduledHandlerDependencies<Env extends WorkerScheduledEnv> {
  createAuthService: (env: Env) => AuthService;
  createObservabilityIngestion?:
    | ((
        env: Env,
      ) =>
        | Promise<ConsoleObservabilityIngestionService | null>
        | ConsoleObservabilityIngestionService
        | null)
    | null;
  outboxSink: WorkerRuntimeSnapshotOutboxSink;
  createCron?: typeof createCloudflareCron;
  logger?: {
    warn: (message: string, meta?: unknown) => void;
  };
}

export function createWorkerScheduledHandler<Env extends WorkerScheduledEnv>(
  deps: WorkerScheduledHandlerDependencies<Env>,
) {
  const createCron = deps.createCron || createCloudflareCron;
  const logger = deps.logger || {
    warn(message: string, meta?: unknown) {
      console.warn(message, meta);
    },
  };
  return async (event: CfScheduledEvent, env: Env, ctx: Ctx): Promise<void> => {
    const authService = deps.createAuthService(env);
    const observabilityIngestion = deps.createObservabilityIngestion
      ? await deps.createObservabilityIngestion(env)
      : null;
    const cronFlags = resolveWorkerCronFeatureFlags(env);
    const issues = collectWorkerCronConfigIssues(env, cronFlags);
    for (const issue of issues) {
      logger.warn('[cron][worker-config] configuration issue detected', issue);
    }
    const cron = createCron(
      authService,
      createWorkerCronOptions(
        env,
        cronFlags,
        deps.outboxSink,
        observabilityIngestion,
      ),
    );
    await cron(event, env, ctx);
  };
}
