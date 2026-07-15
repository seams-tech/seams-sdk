import type { SigningSessionStatus, WalletAuthMethod } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import {
  parseRouterAbEd25519WalletSessionAuthorityFromRecord,
  resolveRouterAbEd25519SigningRootFromRecord,
  type RouterAbEd25519WalletSessionAuthorityFailureReason,
} from '../routerAbSigningWalletSession';

export type WarmEd25519PrfClaimReady = {
  kind: 'hot_prf_claim';
  sessionId: string;
  remainingUses: number;
  availableUses: number;
  expiresAtMs: number;
};

export type WarmEd25519SigningSessionAuthorization = {
  kind: 'warm_ed25519_signing_session_authorized';
  curve: 'ed25519';
  authMethod: WalletAuthMethod;
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  thresholdSessionKind: 'jwt';
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionJwt: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
  remainingUses: number;
  availableUses: number;
  expiresAtMs: number;
  prfClaim: WarmEd25519PrfClaimReady;
};

export type WarmEd25519SigningSessionAuthorizationFailureReason =
  | 'missing_record'
  | 'wallet_mismatch'
  | 'account_mismatch'
  | 'key_scope_mismatch'
  | 'auth_method_mismatch'
  | 'cookie_session'
  | 'missing_wallet_session_jwt'
  | 'missing_threshold_session_id'
  | 'missing_signing_grant_id'
  | 'missing_runtime_policy_scope'
  | 'missing_signing_root'
  | 'signing_root_mismatch'
  | 'missing_router_ab_state'
  | 'missing_signing_worker_id'
  | 'invalid_budget'
  | 'expired'
  | 'prf_claim_missing'
  | 'prf_claim_session_mismatch'
  | 'prf_claim_not_active'
  | 'prf_claim_exhausted'
  | 'session_identity_invalid';

export type WarmEd25519SigningSessionAuthorizationResult =
  | { ok: true; value: WarmEd25519SigningSessionAuthorization }
  | {
      ok: false;
      reason: WarmEd25519SigningSessionAuthorizationFailureReason;
      details: Record<string, unknown>;
    };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function authMethodForEd25519Record(record: ThresholdEd25519SessionRecord): WalletAuthMethod {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function warmAuthorizationSigningRootFailureReason(
  reason: string,
): WarmEd25519SigningSessionAuthorizationFailureReason {
  switch (reason) {
    case 'missing_runtime_policy_scope':
    case 'missing_signing_root':
    case 'signing_root_mismatch':
      return reason;
    default:
      return 'session_identity_invalid';
  }
}

function warmAuthorizationWalletSessionFailureReason(
  reason: RouterAbEd25519WalletSessionAuthorityFailureReason,
): WarmEd25519SigningSessionAuthorizationFailureReason {
  switch (reason) {
    case 'missing_record':
      return 'missing_record';
    case 'cookie_session':
    case 'missing_wallet_session_jwt':
    case 'missing_threshold_session_id':
    case 'missing_signing_grant_id':
      return reason;
    case 'wallet_binding_mismatch':
      return 'session_identity_invalid';
  }
}

function warmAuthorizationWalletSessionFailureDetails(args: {
  record: ThresholdEd25519SessionRecord;
  reason: RouterAbEd25519WalletSessionAuthorityFailureReason;
}): Record<string, unknown> {
  const thresholdSessionId = nonEmptyString(args.record.thresholdSessionId);
  switch (args.reason) {
    case 'cookie_session':
      return { thresholdSessionKind: args.record.thresholdSessionKind };
    case 'missing_signing_grant_id':
    case 'missing_wallet_session_jwt':
    case 'wallet_binding_mismatch':
      return thresholdSessionId
        ? { thresholdSessionId, authorityReason: args.reason }
        : { authorityReason: args.reason };
    case 'missing_record':
    case 'missing_threshold_session_id':
      return {};
  }
}

function activePrfClaimFromStatus(args: {
  status: SigningSessionStatus | null | undefined;
  thresholdSessionId: string;
}): WarmEd25519PrfClaimReady | WarmEd25519SigningSessionAuthorizationFailureReason {
  const status = args.status;
  if (!status) return 'prf_claim_missing';
  if (nonEmptyString(status.sessionId) !== args.thresholdSessionId) {
    return 'prf_claim_session_mismatch';
  }
  if (status.status !== 'active') return 'prf_claim_not_active';
  const remainingUses = positiveInteger(status.remainingUses);
  const expiresAtMs = positiveInteger(status.expiresAtMs);
  const statusAvailableUses =
    status.availableUses === undefined ? remainingUses : positiveInteger(status.availableUses);
  const availableUses = Math.min(remainingUses, statusAvailableUses);
  if (!remainingUses || !availableUses) return 'prf_claim_exhausted';
  if (!expiresAtMs) return 'prf_claim_not_active';
  return {
    kind: 'hot_prf_claim',
    sessionId: args.thresholdSessionId,
    remainingUses,
    availableUses,
    expiresAtMs,
  };
}

export function parseWarmEd25519SigningSessionAuthorizationFromRecord(args: {
  record: ThresholdEd25519SessionRecord | null | undefined;
  walletId: string;
  nearAccountId: AccountId | string;
  nearEd25519SigningKeyId: string;
  authMethod: WalletAuthMethod;
  signingSessionStatus: SigningSessionStatus | null | undefined;
  nowMs?: number;
}): WarmEd25519SigningSessionAuthorizationResult {
  const record = args.record;
  if (!record) return { ok: false, reason: 'missing_record', details: {} };

  const expectedWalletId = nonEmptyString(args.walletId);
  if (nonEmptyString(record.walletId) !== expectedWalletId) {
    return {
      ok: false,
      reason: 'wallet_mismatch',
      details: { expectedWalletId, recordWalletId: record.walletId },
    };
  }

  const expectedNearAccountId = nonEmptyString(args.nearAccountId);
  if (nonEmptyString(record.nearAccountId) !== expectedNearAccountId) {
    return {
      ok: false,
      reason: 'account_mismatch',
      details: { expectedNearAccountId, recordNearAccountId: record.nearAccountId },
    };
  }

  const expectedNearEd25519SigningKeyId = nonEmptyString(args.nearEd25519SigningKeyId);
  if (nonEmptyString(record.nearEd25519SigningKeyId) !== expectedNearEd25519SigningKeyId) {
    return {
      ok: false,
      reason: 'key_scope_mismatch',
      details: {
        expectedNearEd25519SigningKeyId,
        recordNearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      },
    };
  }

  const authMethod = authMethodForEd25519Record(record);
  if (authMethod !== args.authMethod) {
    return {
      ok: false,
      reason: 'auth_method_mismatch',
      details: { expectedAuthMethod: args.authMethod, recordAuthMethod: authMethod },
    };
  }

  const walletSessionAuthority = parseRouterAbEd25519WalletSessionAuthorityFromRecord(record);
  if (!walletSessionAuthority.ok) {
    return {
      ok: false,
      reason: warmAuthorizationWalletSessionFailureReason(walletSessionAuthority.reason),
      details: warmAuthorizationWalletSessionFailureDetails({
        record,
        reason: walletSessionAuthority.reason,
      }),
    };
  }
  const { thresholdSessionId, signingGrantId } = walletSessionAuthority.value;
  const walletSessionJwt = walletSessionAuthority.value.auth.walletSessionJwt;

  if (!record.runtimePolicyScope) {
    return { ok: false, reason: 'missing_runtime_policy_scope', details: { thresholdSessionId } };
  }
  const signingRoot = resolveRouterAbEd25519SigningRootFromRecord(record);
  if (!signingRoot.ok) {
    return {
      ok: false,
      reason: warmAuthorizationSigningRootFailureReason(signingRoot.reason),
      details: { thresholdSessionId },
    };
  }

  const routerAbNormalSigning = record.routerAbNormalSigning;
  const signingWorkerId = nonEmptyString(routerAbNormalSigning.signingWorkerId);
  if (!signingWorkerId) {
    return { ok: false, reason: 'missing_signing_worker_id', details: { thresholdSessionId } };
  }

  const remainingUses = positiveInteger(record.remainingUses);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (!remainingUses || !expiresAtMs) {
    return { ok: false, reason: 'invalid_budget', details: { thresholdSessionId } };
  }
  if (expiresAtMs <= (args.nowMs ?? Date.now())) {
    return { ok: false, reason: 'expired', details: { thresholdSessionId, expiresAtMs } };
  }

  const prfClaim = activePrfClaimFromStatus({
    status: args.signingSessionStatus,
    thresholdSessionId,
  });
  if (typeof prfClaim === 'string') {
    return { ok: false, reason: prfClaim, details: { thresholdSessionId } };
  }

  return {
    ok: true,
    value: {
      kind: 'warm_ed25519_signing_session_authorized',
      curve: 'ed25519',
      authMethod,
      walletId: record.walletId,
      nearAccountId: record.nearAccountId,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      rpId: record.rpId,
      relayerUrl: record.relayerUrl,
      relayerKeyId: record.relayerKeyId,
      participantIds: record.participantIds,
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt,
      runtimePolicyScope: record.runtimePolicyScope,
      signingRootId: signingRoot.value.signingRootId,
      signingRootVersion: signingRoot.value.signingRootVersion,
      routerAbNormalSigning,
      signingWorkerId,
      remainingUses,
      availableUses: prfClaim.availableUses,
      expiresAtMs,
      prfClaim,
    },
  };
}
