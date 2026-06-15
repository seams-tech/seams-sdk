export interface WorkerCronFeatureFlags {
  billingFinalizationEnabled: boolean;
  runtimeSnapshotOutboxEnabled: boolean;
  webhookRetryEnabled: boolean;
  cronEnabled: boolean;
}

interface WorkerCronFeatureFlagInputs {
  BILLING_FINALIZATION_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  WEBHOOK_RETRY_ENABLED?: string;
}

function envFlag(input: string | undefined): boolean {
  return String(input || '').trim() === '1';
}

export function resolveWorkerCronFeatureFlags(
  env: WorkerCronFeatureFlagInputs,
): WorkerCronFeatureFlags {
  const billingFinalizationEnabled = envFlag(env.BILLING_FINALIZATION_ENABLED);
  const runtimeSnapshotOutboxEnabled = envFlag(env.RUNTIME_SNAPSHOT_OUTBOX_ENABLED);
  const webhookRetryEnabled = envFlag(env.WEBHOOK_RETRY_ENABLED);

  return {
    billingFinalizationEnabled,
    runtimeSnapshotOutboxEnabled,
    webhookRetryEnabled,
    cronEnabled: billingFinalizationEnabled || runtimeSnapshotOutboxEnabled || webhookRetryEnabled,
  };
}
