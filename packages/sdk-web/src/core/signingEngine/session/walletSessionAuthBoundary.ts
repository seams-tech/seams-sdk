import type { ThresholdEd25519SessionRecord } from './persistence/records';

export type PersistedEd25519WalletSessionAuth =
  {
    kind: 'wallet_session_jwt';
    walletSessionJwt: string;
  };

export function walletSessionAuthFromPersistedEd25519Record(
  record: ThresholdEd25519SessionRecord,
): PersistedEd25519WalletSessionAuth | null {
  if (record.thresholdSessionKind !== 'jwt') return null;
  const walletSessionJwt = String(record.walletSessionJwt || '').trim();
  return walletSessionJwt
    ? {
        kind: 'wallet_session_jwt',
        walletSessionJwt,
      }
    : null;
}

export function walletSessionJwtFromPersistedEd25519Record(
  record: ThresholdEd25519SessionRecord | null | undefined,
): string {
  if (!record || record.thresholdSessionKind !== 'jwt') return '';
  return String(record.walletSessionJwt || '').trim();
}
