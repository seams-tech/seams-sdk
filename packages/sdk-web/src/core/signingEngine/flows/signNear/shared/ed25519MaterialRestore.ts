export const ED25519_MATERIAL_RESTORE_REQUIRED_ERROR =
  '[SigningEngine][near] material_restore_required';

export type Ed25519MaterialRestoreRequiredReason =
  | 'missing_worker_material'
  | 'pending_material'
  | 'worker_material_unavailable';

export function ed25519MaterialRestoreRequiredError(args: {
  operation: 'near_transaction' | 'nep413_message' | 'delegate_action' | 'passkey_reconnect';
  thresholdSessionId: string;
  reason: Ed25519MaterialRestoreRequiredReason;
}): Error {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  return new Error(
    `${ED25519_MATERIAL_RESTORE_REQUIRED_ERROR}: ${args.operation}:${args.reason}` +
      (thresholdSessionId ? `:${thresholdSessionId}` : ''),
  );
}

export function throwEd25519MaterialRestoreRequired(args: {
  operation: 'near_transaction' | 'nep413_message' | 'delegate_action' | 'passkey_reconnect';
  thresholdSessionId: string;
  reason: Ed25519MaterialRestoreRequiredReason;
}): never {
  throw ed25519MaterialRestoreRequiredError(args);
}
