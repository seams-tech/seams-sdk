import type { SigningSessionStatus } from '@/core/types/seams';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { SelectedEd25519SigningSessionPlanningLane } from '../operationState/types';
import type { ReusableWalletSessionStatus } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type Ed25519WalletSessionStatusOwner = {
  curve: 'ed25519';
  walletId: WalletId;
  accountId?: never;
};

export type WalletSessionStatusOwner = Ed25519WalletSessionStatusOwner;

/** The only identity accepted by the canonical Wallet Session status route. */
export type WalletSessionStatusIdentity = {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type SigningSessionStatusCheck = {
  kind: 'wallet_session_status_check';
  owner: WalletSessionStatusOwner;
  authorization: WalletSessionStatusIdentity;
};

export type SigningSessionStatusReader = (
  args: SigningSessionStatusCheck,
) => Promise<SigningSessionStatus | null>;

export type WalletSigningSessionStatusDeps = {
  getAvailableStatus: SigningSessionStatusReader;
};

export function normalizeSessionStatusRequired(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[WalletSessionStatus] ${label} is required`);
  }
  return normalized;
}

export function parseWalletSessionStatusIdentity(value: {
  walletSessionId: unknown;
  quotaId: unknown;
}): WalletSessionStatusIdentity | null {
  const walletSessionId = parseWalletSessionId(value.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(value.quotaId);
  if (!walletSessionId.ok || !quotaId.ok) return null;
  return {
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
}

export function buildWalletSessionStatusCheck(args: {
  owner: WalletSessionStatusOwner;
  authorization: WalletSessionStatusIdentity;
}): SigningSessionStatusCheck {
  const authorization = parseWalletSessionStatusIdentity(args.authorization);
  if (!authorization) {
    throw new Error('[WalletSessionStatus] canonical Wallet Session identity is invalid');
  }
  return {
    kind: 'wallet_session_status_check',
    owner: args.owner,
    authorization,
  };
}

export function ed25519WalletSessionStatusOwner(
  walletId: WalletId | string,
): Ed25519WalletSessionStatusOwner {
  return { curve: 'ed25519', walletId: toWalletId(walletId) };
}

export function walletSessionStatusOwnerForLane(
  lane: SelectedEd25519SigningSessionPlanningLane,
): WalletSessionStatusOwner {
  return ed25519WalletSessionStatusOwner(lane.identity.signer.account.wallet.walletId);
}

export function walletSessionStatusOwnerId(owner: WalletSessionStatusOwner): WalletId {
  return owner.walletId;
}

export function walletSessionStatusOwnerKey(owner: WalletSessionStatusOwner): string {
  return `${owner.curve}:${walletSessionStatusOwnerId(owner)}`;
}

export function walletSessionStatusIdentityKey(identity: WalletSessionStatusIdentity): string {
  return `${identity.walletSessionId}:${identity.quotaId}`;
}

export function signingSessionStatusFromWalletSessionStatus(
  status: ReusableWalletSessionStatus,
): SigningSessionStatus {
  const sessionId = String(status.walletSessionId);
  switch (status.status) {
    case 'active':
      return {
        sessionId,
        status: 'active',
        remainingUses: status.remainingUses,
        expiresAtMs: status.expiresAtMs,
      };
    case 'exhausted':
      return {
        sessionId,
        status: 'exhausted',
        remainingUses: 0,
        expiresAtMs: status.expiresAtMs,
      };
    case 'expired':
      return {
        sessionId,
        status: 'expired',
        expiresAtMs: status.expiresAtMs,
      };
    case 'missing':
    case 'superseded':
      return {
        sessionId,
        status: 'not_found',
        statusCode: status.status,
      };
    // The authorization exists but no longer resolves: its authority, method,
    // or capability is gone. That is definitive, not unknown.
    case 'authority_unavailable':
    case 'method_unavailable':
    case 'capability_unavailable':
      return {
        sessionId,
        status: 'unavailable',
        statusCode: status.status,
        expiresAtMs: status.expiresAtMs,
      };
    case 'invalid':
      return {
        sessionId,
        status: 'status_unknown',
        statusCode: 'invalid_wallet_session_status',
      };
    default:
      status satisfies never;
      throw new Error('[WalletSessionStatus] unsupported canonical status');
  }
}

export function unknownSigningSessionStatus(args: {
  walletSessionId: WalletSessionId | string;
  reason: string;
}): SigningSessionStatus & { status: 'status_unknown' } {
  return {
    sessionId: String(args.walletSessionId),
    status: 'status_unknown',
    statusCode: args.reason,
  };
}

export async function getWalletSessionStatus(
  deps: WalletSigningSessionStatusDeps,
  args: SigningSessionStatusCheck,
): Promise<SigningSessionStatus | null> {
  return await deps.getAvailableStatus(args).catch(() => null);
}

export function mergeWalletSigningSessionStatus<TStatus extends SigningSessionStatus>(
  status: TStatus,
  sessionStatus: SigningSessionStatus | null,
): TStatus {
  if (!sessionStatus) return status;
  if (sessionStatus.status === 'status_unknown') return status;
  if (sessionStatus.status !== 'active') {
    return {
      ...status,
      ...sessionStatus,
      sessionId: status.sessionId,
    };
  }
  const sessionRemainingUses = Math.max(0, Math.floor(Number(sessionStatus.remainingUses) || 0));
  const statusExpiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
  const sessionExpiresAtMs = Math.floor(Number(sessionStatus.expiresAtMs) || 0);
  return {
    ...status,
    status: 'active',
    remainingUses: sessionRemainingUses,
    expiresAtMs:
      statusExpiresAtMs > 0 && sessionExpiresAtMs > 0
        ? Math.min(statusExpiresAtMs, sessionExpiresAtMs)
        : statusExpiresAtMs || sessionExpiresAtMs,
    ...(sessionStatus.authMethod ? { authMethod: sessionStatus.authMethod } : {}),
    ...(sessionStatus.retention ? { retention: sessionStatus.retention } : {}),
  };
}

export function buildWalletSessionStatusCheckForSession(args: {
  owner: WalletSessionStatusOwner;
  authorization: WalletSessionStatusIdentity;
}): SigningSessionStatusCheck {
  return buildWalletSessionStatusCheck(args);
}
