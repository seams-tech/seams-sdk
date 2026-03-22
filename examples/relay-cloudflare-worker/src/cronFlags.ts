export interface WorkerCronFeatureFlags {
  rotateEnabled: boolean;
  billingFinalizationEnabled: boolean;
  runtimeSnapshotOutboxEnabled: boolean;
  webhookRetryEnabled: boolean;
  recoveryAuthorityContinuationEnabled: boolean;
  cronEnabled: boolean;
}

interface WorkerCronFeatureFlagInputs {
  ENABLE_ROTATION?: string;
  BILLING_FINALIZATION_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  WEBHOOK_RETRY_ENABLED?: string;
  RECOVERY_AUTHORITY_CONTINUATION_ENABLED?: string;
}

function envFlag(input: string | undefined): boolean {
  return String(input || '').trim() === '1';
}

export function resolveWorkerCronFeatureFlags(
  env: WorkerCronFeatureFlagInputs,
): WorkerCronFeatureFlags {
  const rotateEnabled = envFlag(env.ENABLE_ROTATION);
  const billingFinalizationEnabled = envFlag(env.BILLING_FINALIZATION_ENABLED);
  const runtimeSnapshotOutboxEnabled = envFlag(env.RUNTIME_SNAPSHOT_OUTBOX_ENABLED);
  const webhookRetryEnabled = envFlag(env.WEBHOOK_RETRY_ENABLED);
  const recoveryAuthorityContinuationEnabled = envFlag(
    env.RECOVERY_AUTHORITY_CONTINUATION_ENABLED,
  );

  return {
    rotateEnabled,
    billingFinalizationEnabled,
    runtimeSnapshotOutboxEnabled,
    webhookRetryEnabled,
    recoveryAuthorityContinuationEnabled,
    cronEnabled:
      rotateEnabled ||
      billingFinalizationEnabled ||
      runtimeSnapshotOutboxEnabled ||
      webhookRetryEnabled ||
      recoveryAuthorityContinuationEnabled,
  };
}
