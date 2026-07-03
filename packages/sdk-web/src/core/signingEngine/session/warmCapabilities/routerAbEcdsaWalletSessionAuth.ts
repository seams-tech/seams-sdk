import type { ThresholdEcdsaSessionRecord } from '../persistence/records';

export type RouterAbEcdsaWalletSessionAuthReady = {
  kind: 'ready';
  walletSessionJwt: string;
  source: 'record';
};

export type RouterAbEcdsaWalletSessionAuthUnavailable = {
  kind: 'unavailable';
  reason: 'cookie_session' | 'missing_wallet_session_jwt';
  walletSessionJwt?: never;
  source?: never;
};

export type RouterAbEcdsaWalletSessionAuthResolution =
  | RouterAbEcdsaWalletSessionAuthReady
  | RouterAbEcdsaWalletSessionAuthUnavailable;

export function resolveRouterAbEcdsaWalletSessionAuthFromRecord(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaWalletSessionAuthResolution {
  if (record.thresholdSessionKind !== 'jwt') {
    return { kind: 'unavailable', reason: 'cookie_session' };
  }

  const recordWalletSessionJwt = String(record.walletSessionJwt || '').trim();
  if (recordWalletSessionJwt) {
    return {
      kind: 'ready',
      walletSessionJwt: recordWalletSessionJwt,
      source: 'record',
    };
  }

  return { kind: 'unavailable', reason: 'missing_wallet_session_jwt' };
}
