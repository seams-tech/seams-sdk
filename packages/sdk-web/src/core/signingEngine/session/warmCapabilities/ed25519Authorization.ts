import type { SigningSessionStatus, WalletAuthMethod } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import { availableUsesForBudgetAdmission } from '../budget/budget';
import { resolveRouterAbEd25519SigningRootFromRecord } from '../routerAbSigningWalletSession';

export type WarmEd25519SigningSessionMaterialState =
  | { materialState: 'material_ready' }
  | { materialState: 'material_pending' };

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
  nearAccountId: AccountId;
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
  ed25519WorkerMaterialHandle?: never;
  ed25519WorkerMaterialBindingDigest?: never;
  clientVerifyingShareB64u?: never;
  xClientBaseB64u?: never;
} & WarmEd25519SigningSessionMaterialState;

export type WarmEd25519SigningSessionAuthorizationFailureReason =
  | 'missing_record'
  | 'account_mismatch'
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
  | 'material_identity_invalid';

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
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function authMethodForEd25519Record(record: ThresholdEd25519SessionRecord): WalletAuthMethod {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function materialStateForEd25519Record(
  record: ThresholdEd25519SessionRecord,
): WarmEd25519SigningSessionMaterialState {
  const hasHandle = Boolean(nonEmptyString(record.ed25519WorkerMaterialHandle));
  const hasBindingDigest = Boolean(nonEmptyString(record.ed25519WorkerMaterialBindingDigest));
  const hasClientVerifier = Boolean(nonEmptyString(record.clientVerifyingShareB64u));
  return hasHandle && hasBindingDigest && hasClientVerifier
    ? { materialState: 'material_ready' }
    : { materialState: 'material_pending' };
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
      return 'material_identity_invalid';
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
  const availableUses = availableUsesForBudgetAdmission(status);
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
  nearAccountId: AccountId | string;
  authMethod: WalletAuthMethod;
  signingSessionStatus: SigningSessionStatus | null | undefined;
  nowMs?: number;
}): WarmEd25519SigningSessionAuthorizationResult {
  const record = args.record;
  if (!record) return { ok: false, reason: 'missing_record', details: {} };

  const expectedNearAccountId = nonEmptyString(args.nearAccountId);
  if (nonEmptyString(record.nearAccountId) !== expectedNearAccountId) {
    return {
      ok: false,
      reason: 'account_mismatch',
      details: { expectedNearAccountId, recordNearAccountId: record.nearAccountId },
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

  if (record.thresholdSessionKind !== 'jwt') {
    return { ok: false, reason: 'cookie_session', details: { thresholdSessionKind: record.thresholdSessionKind } };
  }

  const thresholdSessionId = nonEmptyString(record.thresholdSessionId);
  if (!thresholdSessionId) return { ok: false, reason: 'missing_threshold_session_id', details: {} };

  const signingGrantId = nonEmptyString(record.signingGrantId);
  if (!signingGrantId) {
    return { ok: false, reason: 'missing_signing_grant_id', details: { thresholdSessionId } };
  }

  const walletSessionJwt = nonEmptyString(record.walletSessionJwt);
  if (!walletSessionJwt) {
    return { ok: false, reason: 'missing_wallet_session_jwt', details: { thresholdSessionId } };
  }

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
  if (!routerAbNormalSigning) {
    return { ok: false, reason: 'missing_router_ab_state', details: { thresholdSessionId } };
  }
  const signingWorkerId = nonEmptyString(routerAbNormalSigning.signingWorkerId);
  if (!signingWorkerId) {
    return { ok: false, reason: 'missing_signing_worker_id', details: { thresholdSessionId } };
  }

  const remainingUses = positiveInteger(record.remainingUses);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (!remainingUses) return { ok: false, reason: 'invalid_budget', details: { thresholdSessionId } };
  if (!expiresAtMs || expiresAtMs <= (args.nowMs ?? Date.now())) {
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
      nearAccountId: record.nearAccountId,
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
      ...materialStateForEd25519Record(record),
    },
  };
}
