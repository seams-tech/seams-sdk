import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';

export type SealedRecoverySecretKind = 'signing_session_secret32';

export type SealedRecordRecoveryPolicy = {
  authMethod: SigningSessionSealedStoreRecord['authMethod'];
  curve: SigningSessionSealedStoreRecord['curve'];
  secretKind: SealedRecoverySecretKind;
};

export function matchesSealedRecordRecoveryPolicy(
  record: SigningSessionSealedStoreRecord,
  policy: SealedRecordRecoveryPolicy,
): boolean {
  return (
    record.authMethod === policy.authMethod &&
    record.curve === policy.curve &&
    record.secretKind === policy.secretKind
  );
}

export function assertSealedRecordRecoveryPolicy(args: {
  record: SigningSessionSealedStoreRecord;
  policy: SealedRecordRecoveryPolicy;
  errorPrefix: string;
}): void {
  if (matchesSealedRecordRecoveryPolicy(args.record, args.policy)) return;
  throw new Error(
    `${args.errorPrefix} policy mismatch (authMethod=${args.record.authMethod}, curve=${args.record.curve}, secretKind=${args.record.secretKind})`,
  );
}

export function sealedRecordRecoverabilityState(args: {
  record: SigningSessionSealedStoreRecord;
  nowMs?: number;
}): 'recoverable' | 'expired' | 'exhausted' {
  const nowMs = Math.floor(Number(args.nowMs) || Date.now());
  if (Math.floor(Number(args.record.expiresAtMs) || 0) <= nowMs) return 'expired';
  if (
    args.record.authMethod !== 'passkey' &&
    Math.floor(Number(args.record.remainingUses) || 0) <= 0
  ) {
    return 'exhausted';
  }
  return 'recoverable';
}

export function assertSealedRecordRecoverable(args: {
  record: SigningSessionSealedStoreRecord;
  errorPrefix: string;
  nowMs?: number;
}): void {
  const state = sealedRecordRecoverabilityState(args);
  if (state === 'recoverable') return;
  throw new Error(`${args.errorPrefix} ${state} sealed record`);
}

export function assertSealedRecordRestoreIdentity(args: {
  record: SigningSessionSealedStoreRecord;
  curve: SigningSessionSealedStoreRecord['curve'];
  thresholdSessionId: string;
  walletSigningSessionId: string;
  errorPrefix: string;
}): void {
  const expectedThresholdSessionId = String(args.thresholdSessionId || '').trim();
  const expectedWalletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!expectedThresholdSessionId || !expectedWalletSigningSessionId) {
    throw new Error(`${args.errorPrefix} missing restore identity`);
  }
  const recordThresholdSessionId = String(args.record.thresholdSessionIds[args.curve] || '').trim();
  if (recordThresholdSessionId !== expectedThresholdSessionId) {
    throw new Error(`${args.errorPrefix} threshold-session id mismatch`);
  }
  if (String(args.record.walletSigningSessionId || '').trim() !== expectedWalletSigningSessionId) {
    throw new Error(`${args.errorPrefix} wallet signing-session id mismatch`);
  }
}
