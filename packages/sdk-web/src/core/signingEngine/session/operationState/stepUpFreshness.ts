import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { EmailOtpSessionRefreshResult } from '../emailOtp/appSessionJwtCache';
import type { PositiveRemainingUses } from '../budget/policy';
import {
  exactSigningLaneIdentityKey,
  thresholdSessionIdsFromExactSigningLaneIdentity,
  type ExactSigningLaneIdentity,
  type ExactSigningLaneIdentityKey,
  type NonEmptyThresholdSessionIds,
} from '../identity/exactSigningLaneIdentity';
import type {
  SigningAuthMethod,
  SigningCurve,
  SigningOperationFingerprint,
  SigningOperationId,
  SigningGrantId,
} from './types';

export type SigningStatusProvenance =
  | {
      kind: 'trusted_server_budget_status';
      projectionVersion: string;
      observedAtMs: number;
    }
  | {
      kind: 'restored_sealed_record_status';
      recordVersion: string;
      updatedAtMs: number;
    }
  | {
      kind: 'email_otp_refresh_boundary';
      httpStatus: 401 | 403;
      observedAtMs: number;
    };

export type StepUpProjectionState =
  | {
      kind: 'known';
      version: string;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'restored_record_has_no_projection'
        | 'email_otp_refresh_rejected'
        | 'budget_status_unavailable';
    };

export type KnownStepUpProjectionState = Extract<StepUpProjectionState, { kind: 'known' }>;

export type StepUpExpiryState =
  | {
      kind: 'known';
      expiresAtMs: number;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'restored_record_has_no_expiry'
        | 'email_otp_refresh_rejected'
        | 'budget_status_unavailable';
    };

export type FreshStepUpRequired = {
  kind: 'fresh_step_up_required';
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  signingGrantId: SigningGrantId;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  provenance: SigningStatusProvenance;
  reason:
    | 'wallet_budget_exhausted'
    | 'threshold_session_exhausted'
    | 'threshold_session_expired'
    | 'email_otp_refresh_rejected';
};

export type FreshStepUpSatisfied = {
  kind: 'fresh_step_up_satisfied';
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  signingGrantId: SigningGrantId;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  remainingUses: PositiveRemainingUses;
  provenance: SigningStatusProvenance;
};

export type FreshStepUpSatisfiedForAdmission = Omit<FreshStepUpSatisfied, 'kind' | 'projection'> & {
  kind: 'fresh_step_up_satisfied_for_admission';
  projection: KnownStepUpProjectionState;
};

export type StepUpFreshnessState =
  | FreshStepUpRequired
  | FreshStepUpSatisfied
  | FreshStepUpSatisfiedForAdmission;

export type StepUpFreshnessDiagnostics = {
  kind: StepUpFreshnessState['kind'];
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  signingGrantId: SigningGrantId;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  provenance: SigningStatusProvenance;
  reason?: FreshStepUpRequired['reason'];
  remainingUses?: PositiveRemainingUses;
};

type StepUpFreshnessBaseInput = {
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  provenance: SigningStatusProvenance;
};

type StepUpFreshnessIdentityInput = Pick<
  StepUpFreshnessBaseInput,
  'walletId' | 'operationId' | 'operationFingerprint' | 'laneIdentity'
>;

export type BuildStepUpFreshnessFromTrustedBudgetStatusInput = StepUpFreshnessIdentityInput & {
  status: SigningSessionStatus;
  observedAtMs: number;
};

export type BuildStepUpFreshnessFromRestoredSealedRecordInput = StepUpFreshnessIdentityInput & {
  recordVersion: string;
  updatedAtMs: number;
  remainingUses?: number | null;
  expiresAtMs?: number | null;
  nowMs?: number;
};

function positiveRemainingUses(value: number): PositiveRemainingUses {
  const remainingUses = Math.floor(Number(value) || 0);
  if (remainingUses <= 0) {
    throw new Error('[StepUpFreshness] remainingUses must be positive');
  }
  return remainingUses as PositiveRemainingUses;
}

function validateBase(input: StepUpFreshnessBaseInput): {
  laneIdentityKey: ExactSigningLaneIdentityKey;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
} {
  const laneIdentityKey = exactSigningLaneIdentityKey(input.laneIdentity);
  const laneWalletId =
    input.laneIdentity.curve === 'ecdsa'
      ? String(input.laneIdentity.walletId)
      : String(input.laneIdentity.accountId);
  if (String(input.walletId) !== laneWalletId) {
    throw new Error('[StepUpFreshness] walletId does not match exact lane identity');
  }
  return {
    laneIdentityKey,
    thresholdSessionIds: thresholdSessionIdsFromExactSigningLaneIdentity(input.laneIdentity),
  };
}

export function buildFreshStepUpRequired(
  input: StepUpFreshnessBaseInput & {
    reason: FreshStepUpRequired['reason'];
  },
): FreshStepUpRequired {
  const validated = validateBase(input);
  return {
    kind: 'fresh_step_up_required',
    walletId: input.walletId,
    operationId: input.operationId,
    operationFingerprint: input.operationFingerprint,
    authMethod: input.laneIdentity.authMethod,
    curve: input.laneIdentity.curve,
    laneIdentity: input.laneIdentity,
    laneIdentityKey: validated.laneIdentityKey,
    signingGrantId: input.laneIdentity.signingGrantId,
    thresholdSessionIds: validated.thresholdSessionIds,
    projection: input.projection,
    expiry: input.expiry,
    provenance: input.provenance,
    reason: input.reason,
  };
}

export function buildFreshStepUpSatisfied(
  input: StepUpFreshnessBaseInput & {
    remainingUses: number;
  },
): FreshStepUpSatisfied {
  const validated = validateBase(input);
  return {
    kind: 'fresh_step_up_satisfied',
    walletId: input.walletId,
    operationId: input.operationId,
    operationFingerprint: input.operationFingerprint,
    authMethod: input.laneIdentity.authMethod,
    curve: input.laneIdentity.curve,
    laneIdentity: input.laneIdentity,
    laneIdentityKey: validated.laneIdentityKey,
    signingGrantId: input.laneIdentity.signingGrantId,
    thresholdSessionIds: validated.thresholdSessionIds,
    projection: input.projection,
    expiry: input.expiry,
    remainingUses: positiveRemainingUses(input.remainingUses),
    provenance: input.provenance,
  };
}

export function buildFreshStepUpSatisfiedForAdmission(
  state: FreshStepUpSatisfied,
): FreshStepUpSatisfiedForAdmission {
  if (state.projection.kind !== 'known') {
    throw new Error('[StepUpFreshness] admission requires a known projection');
  }
  return {
    ...state,
    kind: 'fresh_step_up_satisfied_for_admission',
    projection: state.projection,
  };
}

export function assertFreshnessMatchesLane(args: {
  freshness: StepUpFreshnessState;
  laneIdentity: ExactSigningLaneIdentity;
}): void {
  const laneIdentityKey = exactSigningLaneIdentityKey(args.laneIdentity);
  if (args.freshness.laneIdentityKey === laneIdentityKey) return;
  throw new Error('[StepUpFreshness] freshness does not match exact lane identity');
}

export function stepUpFreshnessDiagnostics(
  freshness: StepUpFreshnessState,
): StepUpFreshnessDiagnostics {
  const base = {
    kind: freshness.kind,
    walletId: freshness.walletId,
    operationId: freshness.operationId,
    operationFingerprint: freshness.operationFingerprint,
    authMethod: freshness.authMethod,
    curve: freshness.curve,
    laneIdentityKey: freshness.laneIdentityKey,
    signingGrantId: freshness.signingGrantId,
    thresholdSessionIds: freshness.thresholdSessionIds,
    projection: freshness.projection,
    expiry: freshness.expiry,
    provenance: freshness.provenance,
  };
  switch (freshness.kind) {
    case 'fresh_step_up_required':
      return {
        ...base,
        reason: freshness.reason,
      };
    case 'fresh_step_up_satisfied':
    case 'fresh_step_up_satisfied_for_admission':
      return {
        ...base,
        remainingUses: freshness.remainingUses,
      };
  }
}

export function buildStepUpFreshnessFromTrustedBudgetStatus(
  input: BuildStepUpFreshnessFromTrustedBudgetStatusInput,
): StepUpFreshnessState {
  const projection = trustedStatusProjection(input.status);
  const expiry = trustedStatusExpiry(input.status);
  const provenance: SigningStatusProvenance = {
    kind: 'trusted_server_budget_status',
    projectionVersion:
      projection.kind === 'known' ? projection.version : String(input.status.projectionVersion || ''),
    observedAtMs: input.observedAtMs,
  };
  const remainingUses = Math.floor(Number(input.status.remainingUses) || 0);
  if (input.status.status === 'active' && remainingUses > 0) {
    return buildFreshStepUpSatisfied({
      ...input,
      projection,
      expiry,
      provenance,
      remainingUses,
    });
  }
  return buildFreshStepUpRequired({
    ...input,
    projection,
    expiry,
    provenance,
    reason:
      input.status.status === 'expired'
        ? 'threshold_session_expired'
        : input.status.status === 'exhausted'
          ? 'threshold_session_exhausted'
          : 'wallet_budget_exhausted',
  });
}

export function buildStepUpFreshnessFromRestoredSealedRecord(
  input: BuildStepUpFreshnessFromRestoredSealedRecordInput,
): StepUpFreshnessState {
  const remainingUses = Math.floor(Number(input.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(input.expiresAtMs) || 0);
  const expiry: StepUpExpiryState =
    expiresAtMs > 0
      ? { kind: 'known', expiresAtMs }
      : { kind: 'unavailable', reason: 'restored_record_has_no_expiry' };
  const projection: StepUpProjectionState = {
    kind: 'unavailable',
    reason: 'restored_record_has_no_projection',
  };
  const provenance: SigningStatusProvenance = {
    kind: 'restored_sealed_record_status',
    recordVersion: input.recordVersion,
    updatedAtMs: input.updatedAtMs,
  };
  if (remainingUses > 0 && (expiresAtMs <= 0 || expiresAtMs > (input.nowMs ?? Date.now()))) {
    return buildFreshStepUpSatisfied({
      ...input,
      projection,
      expiry,
      provenance,
      remainingUses,
    });
  }
  return buildFreshStepUpRequired({
    ...input,
    projection,
    expiry,
    provenance,
    reason:
      expiresAtMs > 0 && expiresAtMs <= (input.nowMs ?? Date.now())
        ? 'threshold_session_expired'
        : 'threshold_session_exhausted',
  });
}

export function buildFreshStepUpRequiredFromEmailOtpRefreshRejection(
  rejection: Extract<EmailOtpSessionRefreshResult, { kind: 'email_otp_refresh_rejected' }>,
): FreshStepUpRequired {
  return buildFreshStepUpRequired({
    walletId: rejection.identity.walletId,
    operationId: rejection.identity.operationId,
    operationFingerprint: rejection.identity.operationFingerprint,
    laneIdentity: rejection.identity.laneIdentity,
    projection: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
    expiry: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
    provenance: {
      kind: 'email_otp_refresh_boundary',
      httpStatus: rejection.httpStatus,
      observedAtMs: Date.now(),
    },
    reason: 'email_otp_refresh_rejected',
  });
}

function trustedStatusProjection(status: SigningSessionStatus): StepUpProjectionState {
  const version = String(status.projectionVersion || '').trim();
  return version
    ? { kind: 'known', version }
    : { kind: 'unavailable', reason: 'budget_status_unavailable' };
}

function trustedStatusExpiry(status: SigningSessionStatus): StepUpExpiryState {
  const expiresAtMs = Math.floor(Number(status.expiresAtMs) || 0);
  return expiresAtMs > 0
    ? { kind: 'known', expiresAtMs }
    : { kind: 'unavailable', reason: 'budget_status_unavailable' };
}
