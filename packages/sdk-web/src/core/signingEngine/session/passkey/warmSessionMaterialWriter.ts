import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';

export type WarmSessionMaterialWriteDiagnosticBucket =
  | 'worker_ready'
  | 'worker_put'
  | 'sealed_record_persist'
  | 'sealed_record_resolve_transport'
  | 'sealed_record_existing_read'
  | 'sealed_record_policy_read'
  | 'sealed_record_apply_server_seal'
  | 'sealed_record_apply_runtime_setup'
  | 'sealed_record_apply_client_seal'
  | 'sealed_record_apply_server_route'
  | 'sealed_record_apply_client_unseal'
  | 'sealed_record_apply_policy_update'
  | 'sealed_record_register'
  | 'sealed_record_verify_read';

export type WarmSessionMaterialWriteDiagnostics = {
  recordDuration(bucket: WarmSessionMaterialWriteDiagnosticBucket, durationMs: number): void;
};

export interface WarmSessionMaterialWriter {
  putWarmSessionMaterial(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
    diagnostics?: WarmSessionMaterialWriteDiagnostics;
  }): Promise<void>;
}
