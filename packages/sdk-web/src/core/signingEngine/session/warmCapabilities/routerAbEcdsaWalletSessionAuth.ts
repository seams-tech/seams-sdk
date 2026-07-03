import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  tryBuildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
} from './ecdsaProvisionPlan';

export type RouterAbEcdsaWalletSessionAuthority = {
  kind: 'ready';
  identity: EcdsaSessionIdentity;
  walletSessionJwt: string;
  source: 'record';
};

export type RouterAbEcdsaWalletSessionAuthUnavailable = {
  kind: 'unavailable';
  reason: 'cookie_session' | 'missing_session_identity' | 'missing_wallet_session_jwt';
  identity?: never;
  walletSessionJwt?: never;
  source?: never;
};

export type RouterAbEcdsaWalletSessionAuthResolution =
  | RouterAbEcdsaWalletSessionAuthority
  | RouterAbEcdsaWalletSessionAuthUnavailable;

export function resolveRouterAbEcdsaWalletSessionAuthFromRecord(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaWalletSessionAuthResolution {
  if (record.thresholdSessionKind !== 'jwt') {
    return { kind: 'unavailable', reason: 'cookie_session' };
  }

  const identity = tryBuildEcdsaSessionIdentity(record);
  if (!identity) {
    return { kind: 'unavailable', reason: 'missing_session_identity' };
  }

  const recordWalletSessionJwt = String(record.walletSessionJwt || '').trim();
  if (recordWalletSessionJwt) {
    return {
      kind: 'ready',
      identity,
      walletSessionJwt: recordWalletSessionJwt,
      source: 'record',
    };
  }

  return { kind: 'unavailable', reason: 'missing_wallet_session_jwt' };
}
