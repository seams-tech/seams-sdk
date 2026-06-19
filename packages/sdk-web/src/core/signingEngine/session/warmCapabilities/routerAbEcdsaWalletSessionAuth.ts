import { resolveThresholdEcdsaKeyIdFromRecord } from '../identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import { thresholdEcdsaChainTargetsEqual } from '../../interfaces/ecdsaChainTarget';
import { createWarmSessionCapabilityReader } from './capabilityReader';

export type RouterAbEcdsaWalletSessionAuthReady = {
  kind: 'ready';
  walletSessionJwt: string;
  source: 'warm_capability' | 'record';
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

  const resolvedAuthMaterial =
    createWarmSessionCapabilityReader().resolveEcdsaAuthByThresholdSessionId(
      record.thresholdSessionId,
    );
  const resolvedRecord = resolvedAuthMaterial?.record || null;
  const resolvedRecordMatches =
    !!resolvedRecord &&
    String(resolvedRecord.walletId || '') === String(record.walletId || '') &&
    String(resolveThresholdEcdsaKeyIdFromRecord({ record: resolvedRecord })) ===
      String(resolveThresholdEcdsaKeyIdFromRecord({ record })) &&
    thresholdEcdsaChainTargetsEqual(resolvedRecord.chainTarget, record.chainTarget) &&
    String(resolvedRecord.thresholdSessionId || '') === String(record.thresholdSessionId || '') &&
    String(resolvedRecord.signingGrantId || '') ===
      String(record.signingGrantId || '');
  const resolvedWalletSessionJwt = String(
    resolvedRecordMatches ? resolvedAuthMaterial?.walletSessionJwt || '' : '',
  ).trim();
  if (resolvedWalletSessionJwt) {
    return {
      kind: 'ready',
      walletSessionJwt: resolvedWalletSessionJwt,
      source: 'warm_capability',
    };
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
