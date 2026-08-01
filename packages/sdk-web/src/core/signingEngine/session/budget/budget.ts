import type { SigningSessionStatus } from '@/core/types/seams';
import type {
  BackingMaterialSessionId,
  SelectedEd25519SigningSessionPlanningLane,
  SigningGrantId,
  ThresholdSessionId,
} from '../operationState/types';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

/**
 * The client reads server-owned signing status and forwards consumption. It
 * does not reserve, project, or finalize quota locally.
 */

export type Ed25519WalletBudgetOwner = {
  curve: 'ed25519';
  walletId: WalletId;
  accountId?: never;
};

export type WalletBudgetOwner = Ed25519WalletBudgetOwner;

export type WalletBudgetStatusCheck = {
  kind: 'wallet_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds?: never;
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type BackingMaterialBudgetStatusCheck = {
  kind: 'backing_material_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds: readonly [
    BackingMaterialSessionId | string,
    ...(BackingMaterialSessionId | string)[],
  ];
  targetThresholdSessionIds?: never;
  trustedStatusAuth?: never;
};

export type ThresholdBudgetStatusCheck = {
  kind: 'threshold_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  targetBackingMaterialSessionIds?: never;
  trustedStatusAuth?: never;
};

export type SigningSessionBudgetStatusAuth = {
  relayerUrl: string;
  thresholdSessionId: string;
  walletSessionJwt: string;
};

export type AuthenticatedThresholdBudgetStatusCheck = {
  kind: 'authenticated_threshold_budget_status_check';
  owner: WalletBudgetOwner;
  walletId?: never;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly [
    ThresholdSessionId | string,
    ...(ThresholdSessionId | string)[],
  ];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
  targetBackingMaterialSessionIds?: never;
};

export type SigningSessionBudgetStatusCheck =
  | WalletBudgetStatusCheck
  | BackingMaterialBudgetStatusCheck
  | ThresholdBudgetStatusCheck
  | AuthenticatedThresholdBudgetStatusCheck;

export type SigningSessionBudgetStatusReader = (
  args: SigningSessionBudgetStatusCheck,
) => Promise<SigningSessionStatus | null>;

export function committedUsesForBudgetAdmission(status: SigningSessionStatus): number {
  if (status.status !== 'active') return 0;
  return Math.max(0, Math.floor(Number(status.remainingUses) || 0));
}

export function normalizeRequired(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningSessionBudget] ${label} is required`);
  }
  return normalized;
}

export function normalizeStringList(values: readonly string[] | undefined): string[] | undefined {
  const normalized = (values || []).map((value) => String(value || '').trim()).filter(Boolean);
  return normalized.length ? normalized : undefined;
}

export function buildWalletBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
}): WalletBudgetStatusCheck {
  return {
    kind: 'wallet_budget_status_check',
    owner: args.owner,
    signingGrantId: normalizeRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
  };
}

export function buildBackingMaterialBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
  targetBackingMaterialSessionIds: readonly (BackingMaterialSessionId | string)[];
}): BackingMaterialBudgetStatusCheck {
  const targetBackingMaterialSessionIds = normalizeStringList(
    args.targetBackingMaterialSessionIds,
  ) as BackingMaterialSessionId[] | undefined;
  if (!targetBackingMaterialSessionIds?.length) {
    throw new Error('[SigningSessionBudget] targetBackingMaterialSessionIds are required');
  }
  return {
    kind: 'backing_material_budget_status_check',
    owner: args.owner,
    signingGrantId: normalizeRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
    targetBackingMaterialSessionIds: [
      targetBackingMaterialSessionIds[0],
      ...targetBackingMaterialSessionIds.slice(1),
    ],
  };
}

export function buildThresholdBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
}): ThresholdBudgetStatusCheck {
  const targetThresholdSessionIds = normalizeStringList(args.targetThresholdSessionIds) as
    | ThresholdSessionId[]
    | undefined;
  if (!targetThresholdSessionIds?.length) {
    throw new Error('[SigningSessionBudget] targetThresholdSessionIds are required');
  }
  return {
    kind: 'threshold_budget_status_check',
    owner: args.owner,
    signingGrantId: normalizeRequired(args.signingGrantId, 'signingGrantId') as SigningGrantId,
    targetThresholdSessionIds: [
      targetThresholdSessionIds[0],
      ...targetThresholdSessionIds.slice(1),
    ],
  };
}

export function buildAuthenticatedThresholdBudgetStatusCheck(args: {
  owner: WalletBudgetOwner;
  signingGrantId: SigningGrantId | string;
  targetThresholdSessionIds: readonly (ThresholdSessionId | string)[];
  trustedStatusAuth: SigningSessionBudgetStatusAuth;
}): AuthenticatedThresholdBudgetStatusCheck {
  const thresholdCheck = buildThresholdBudgetStatusCheck(args);
  return {
    kind: 'authenticated_threshold_budget_status_check',
    owner: thresholdCheck.owner,
    signingGrantId: thresholdCheck.signingGrantId,
    targetThresholdSessionIds: thresholdCheck.targetThresholdSessionIds,
    trustedStatusAuth: args.trustedStatusAuth,
  };
}

export function ed25519WalletBudgetOwner(walletId: WalletId | string): Ed25519WalletBudgetOwner {
  return { curve: 'ed25519', walletId: toWalletId(walletId) };
}

export function walletBudgetOwnerForLane(
  lane: SelectedEd25519SigningSessionPlanningLane,
): WalletBudgetOwner {
  return ed25519WalletBudgetOwner(lane.identity.signer.account.wallet.walletId);
}

export function walletBudgetOwnerId(owner: WalletBudgetOwner): WalletId {
  return owner.walletId;
}

export function walletBudgetOwnerKey(owner: WalletBudgetOwner): string {
  return `${owner.curve}:${walletBudgetOwnerId(owner)}`;
}

export function thresholdSessionIdsForBudgetStatusCheck(
  args: SigningSessionBudgetStatusCheck,
): string[] {
  return args.kind === 'threshold_budget_status_check' ||
    args.kind === 'authenticated_threshold_budget_status_check'
    ? [...args.targetThresholdSessionIds].map((value) => normalizeRequired(value, 'thresholdSessionId'))
    : [];
}
