import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention, WalletAuthMethod } from '@/core/types/tatchi';
import type {
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../../orchestration/thresholdActivation';

export type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

export type WalletSigningSessionId = Brand<string, 'WalletSigningSessionId'>;
export type ThresholdEd25519SessionId = Brand<string, 'ThresholdEd25519SessionId'>;
export type ThresholdEcdsaSessionId = Brand<string, 'ThresholdEcdsaSessionId'>;
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;
export type BackingMaterialSessionId = Brand<string, 'BackingMaterialSessionId'>;
export type EmailOtpChallengeId = Brand<string, 'EmailOtpChallengeId'>;
export type SigningOperationId = Brand<string, 'SigningOperationId'>;
export type SigningOperationFingerprint = Brand<string, 'SigningOperationFingerprint'>;

export type SigningCurve = 'ed25519' | 'ecdsa';
export type SigningChainFamily = 'near' | ThresholdEcdsaActivationChain;
export type SigningAuthMethod = Extract<WalletAuthMethod, 'email_otp' | 'passkey'>;
export type SigningKeyKind = 'threshold_ed25519' | 'threshold_ecdsa_secp256k1' | 'webauthn_p256';
export type SigningSessionOrigin =
  | 'login'
  | 'registration'
  | 'manual_bootstrap'
  | 'manual_connect'
  | 'bootstrap'
  | 'per_operation'
  | 'sealed_restore';
export type SigningSessionStorageSource =
  | ThresholdEd25519SessionStoreSource
  | ThresholdEcdsaSessionStoreSource;
export const SigningOperationIntent = {
  TransactionSign: 'transaction_sign',
} as const;
export type SigningOperationIntent =
  (typeof SigningOperationIntent)[keyof typeof SigningOperationIntent];

export type SigningLaneContext = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  keyKind: SigningKeyKind;
  chainFamily: SigningChainFamily;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId?: ThresholdSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  sessionOrigin: SigningSessionOrigin;
  storageSource: SigningSessionStorageSource;
  retention: SigningSessionRetention;
  activeSignerSlot?: number;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type SigningSessionRequestIdentity = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  chainFamily: SigningChainFamily;
  walletSigningSessionId?: WalletSigningSessionId;
  thresholdSessionId?: ThresholdSessionId;
};

export type SelectedSigningLaneIdentity = {
  accountId: AccountId;
  authMethod: SigningAuthMethod;
  curve: SigningCurve;
  chainFamily: SigningChainFamily;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
};

export type SelectedSigningLaneContext = SigningLaneContext & SelectedSigningLaneIdentity;

export type ResolvedSigningSessionIdentity = SelectedSigningLaneIdentity & {
  keyKind: SigningKeyKind;
  sessionOrigin: SigningSessionOrigin;
  storageSource: SigningSessionStorageSource;
  retention: SigningSessionRetention;
  backingMaterialSessionId?: BackingMaterialSessionId;
  signingRootId?: string;
  signingRootVersion?: string;
};

export type ResolvedEd25519SigningSessionIdentity = ResolvedSigningSessionIdentity & {
  curve: 'ed25519';
  keyKind: 'threshold_ed25519';
  chainFamily: 'near';
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type ResolvedEcdsaSigningSessionIdentity = ResolvedSigningSessionIdentity & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: ThresholdEcdsaActivationChain;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type SigningOperationContext = {
  operationId: SigningOperationId;
  intent: SigningOperationIntent;
  operationFingerprint?: SigningOperationFingerprint;
};

export type SigningLaneResolutionBlockedReason =
  | 'missing_lane'
  | 'auth_unavailable'
  | 'policy_blocked';

export type SigningLaneResolutionResult =
  | {
      kind: 'resolved';
      lane: SigningLaneContext;
    }
  | {
      kind: 'blocked';
      reason: SigningLaneResolutionBlockedReason;
      accountId?: AccountId;
      authMethod?: SigningAuthMethod;
      chainFamily?: SigningChainFamily;
    };

export const SigningKeyRefIntentKind = {
  Cached: 'cached',
  Reauth: 'reauth',
} as const;

export type SigningKeyRefIntentKind =
  (typeof SigningKeyRefIntentKind)[keyof typeof SigningKeyRefIntentKind];

export type SigningKeyRefIntent =
  | {
      kind: typeof SigningKeyRefIntentKind.Cached;
      thresholdSessionId: ThresholdSessionId;
    }
  | {
      kind: typeof SigningKeyRefIntentKind.Reauth;
      authMethod: SigningAuthMethod;
    };

export type WalletSigningSpendPlan = {
  operationId: SigningOperationId;
  operationFingerprint?: SigningOperationFingerprint;
  nearAccountId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  lane: SigningLaneContext;
  thresholdSessionIds: ThresholdSessionId[];
  backingMaterialSessionIds: BackingMaterialSessionId[];
  uses: 1;
  reason: SigningOperationIntent;
};

export type EmailOtpChallengePlan = {
  challengeId?: EmailOtpChallengeId;
  chainFamily: SigningChainFamily;
  lane: SigningLaneContext;
};

export type PasskeyReconnectPlan = {
  lane: SigningLaneContext;
  thresholdSessionId?: ThresholdSessionId;
};

export type SigningSessionNotReadyReason =
  | 'missing_session'
  | 'expired'
  | 'exhausted'
  | 'auth_unavailable'
  | 'status_unavailable'
  | 'policy_blocked';

export const SigningSessionPlanKind = {
  WarmSession: 'warm_session',
  EmailOtpReauth: 'email_otp_reauth',
  PasskeyReauth: 'passkey_reauth',
  NotReady: 'not_ready',
} as const;

export type SigningSessionPlanKind =
  (typeof SigningSessionPlanKind)[keyof typeof SigningSessionPlanKind];

export type SigningSessionPlan =
  | {
      kind: typeof SigningSessionPlanKind.WarmSession;
      lane: SigningLaneContext;
      keyRef: SigningKeyRefIntent;
    }
  | {
      kind: typeof SigningSessionPlanKind.EmailOtpReauth;
      lane: SigningLaneContext;
      challenge: EmailOtpChallengePlan;
    }
  | {
      kind: typeof SigningSessionPlanKind.PasskeyReauth;
      lane: SigningLaneContext;
      reconnect: PasskeyReconnectPlan;
    }
  | {
      kind: typeof SigningSessionPlanKind.NotReady;
      lane: SigningLaneContext;
      reason: SigningSessionNotReadyReason;
    };

export type SigningLaneSummary = Pick<
  SigningLaneContext,
  | 'accountId'
  | 'authMethod'
  | 'curve'
  | 'keyKind'
  | 'chainFamily'
  | 'sessionOrigin'
  | 'storageSource'
  | 'retention'
>;

export type SigningPlanSummary = {
  kind: SigningSessionPlan['kind'];
  lane: SigningLaneSummary;
};

function toRequiredBrandedString<TBrand extends string>(
  value: unknown,
  label: string,
): Brand<string, TBrand> {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningSession] ${label} is required`);
  }
  return normalized as Brand<string, TBrand>;
}

export const SigningSessionIds = {
  walletSigningSession(value: unknown): WalletSigningSessionId {
    return toRequiredBrandedString(value, 'walletSigningSessionId');
  },
  thresholdEd25519Session(value: unknown): ThresholdEd25519SessionId {
    return toRequiredBrandedString(value, 'thresholdEd25519SessionId');
  },
  thresholdEcdsaSession(value: unknown): ThresholdEcdsaSessionId {
    return toRequiredBrandedString(value, 'thresholdEcdsaSessionId');
  },
  backingMaterialSession(value: unknown): BackingMaterialSessionId {
    return toRequiredBrandedString(value, 'backingMaterialSessionId');
  },
  emailOtpChallenge(value: unknown): EmailOtpChallengeId {
    return toRequiredBrandedString(value, 'emailOtpChallengeId');
  },
  signingOperation(value: unknown): SigningOperationId {
    return toRequiredBrandedString(value, 'signingOperationId');
  },
  signingOperationFingerprint(value: unknown): SigningOperationFingerprint {
    return toRequiredBrandedString(value, 'signingOperationFingerprint');
  },
} as const;

export function summarizeSigningLane(lane: SigningLaneContext): SigningLaneSummary {
  return {
    accountId: lane.accountId,
    authMethod: lane.authMethod,
    curve: lane.curve,
    keyKind: lane.keyKind,
    chainFamily: lane.chainFamily,
    sessionOrigin: lane.sessionOrigin,
    storageSource: lane.storageSource,
    retention: lane.retention,
  };
}

export function normalizeWalletSigningSpendPlan(
  input: WalletSigningSpendPlan,
): WalletSigningSpendPlan {
  if (!input || typeof input !== 'object') {
    throw new Error('[SigningSession] wallet signing spend plan is required');
  }
  const lane = input.lane;
  if (!lane || typeof lane !== 'object') {
    throw new Error('[SigningSession] wallet signing spend plan lane is required');
  }
  const operationId = SigningSessionIds.signingOperation(input.operationId);
  const operationFingerprint =
    input.operationFingerprint != null
      ? SigningSessionIds.signingOperationFingerprint(input.operationFingerprint)
      : undefined;
  const nearAccountId = toAccountId(input.nearAccountId || lane.accountId);
  const laneAccountId = toAccountId(lane.accountId);
  if (String(nearAccountId) !== String(laneAccountId)) {
    throw new Error('[SigningSession] wallet signing spend account does not match lane');
  }
  const walletSigningSessionId = SigningSessionIds.walletSigningSession(
    input.walletSigningSessionId || lane.walletSigningSessionId,
  );
  const laneWalletSigningSessionId = SigningSessionIds.walletSigningSession(
    lane.walletSigningSessionId,
  );
  if (walletSigningSessionId !== laneWalletSigningSessionId) {
    throw new Error(
      '[SigningSession] wallet signing spend walletSigningSessionId does not match lane',
    );
  }
  if (input.uses !== 1) {
    throw new Error('[SigningSession] wallet signing spend uses must be 1');
  }
  if (input.reason !== SigningOperationIntent.TransactionSign) {
    throw new Error('[SigningSession] wallet signing spend reason is invalid');
  }
  return {
    ...input,
    operationId,
    ...(operationFingerprint ? { operationFingerprint } : {}),
    nearAccountId,
    walletSigningSessionId,
    lane: {
      ...lane,
      accountId: nearAccountId,
      walletSigningSessionId,
    },
    thresholdSessionIds: uniqueBrandedStrings(
      input.thresholdSessionIds,
      (value) => toRequiredBrandedString(value, 'thresholdSessionId') as ThresholdSessionId,
      'thresholdSessionIds',
    ),
    backingMaterialSessionIds: uniqueBrandedStrings(
      input.backingMaterialSessionIds,
      SigningSessionIds.backingMaterialSession,
      'backingMaterialSessionIds',
    ),
    uses: 1,
    reason: SigningOperationIntent.TransactionSign,
  };
}

function uniqueBrandedStrings<TValue extends string>(
  values: readonly TValue[],
  normalize: (value: unknown) => TValue,
  label: string,
): TValue[] {
  if (!Array.isArray(values)) {
    throw new Error(`[SigningSession] wallet signing spend ${label} must be an array`);
  }
  const seen = new Set<string>();
  const out: TValue[] = [];
  for (const value of values) {
    const normalized = normalize(value);
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

export function summarizeSigningSessionPlan(plan: SigningSessionPlan): SigningPlanSummary {
  return {
    kind: plan.kind,
    lane: summarizeSigningLane(plan.lane),
  };
}
