export const ED25519_MATERIAL_RESTORE_REQUIRED_ERROR =
  '[SigningEngine][near] material_restore_required';
export const ED25519_MATERIAL_UNSEAL_AUTHORIZATION_REQUIRED_ERROR =
  '[SigningEngine][near] material_unseal_authorization_required';

export type Ed25519MaterialRestoreRequiredReason =
  | 'missing_worker_material'
  | 'pending_material'
  | 'restore_available'
  | 'worker_material_unavailable';

export type Ed25519MaterialRestoreOperation =
  | 'near_transaction'
  | 'nep413_message'
  | 'delegate_action'
  | 'wallet_unlock'
  | 'passkey_reconnect';

export function ed25519MaterialRestoreRequiredError(args: {
  operation: Ed25519MaterialRestoreOperation;
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
  operation: Ed25519MaterialRestoreOperation;
  thresholdSessionId: string;
  reason: Ed25519MaterialRestoreRequiredReason;
}): never {
  throw ed25519MaterialRestoreRequiredError(args);
}

export function ed25519MaterialUnsealAuthorizationRequiredError(args: {
  operation: Ed25519MaterialRestoreOperation;
  thresholdSessionId: string;
}): Error {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  return new Error(
    `${ED25519_MATERIAL_UNSEAL_AUTHORIZATION_REQUIRED_ERROR}: ${args.operation}` +
      (thresholdSessionId ? `:${thresholdSessionId}` : ''),
  );
}

export function isEd25519MaterialUnsealAuthorizationRequiredError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.startsWith(ED25519_MATERIAL_UNSEAL_AUTHORIZATION_REQUIRED_ERROR);
}
