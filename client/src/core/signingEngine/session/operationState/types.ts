import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention, WalletAuthMethod } from '@/core/types/seams';
import type {
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  parseEmailOtpChallengeId,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseThresholdSessionId,
  parseWalletSigningSessionId,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import type {
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  ThresholdSessionId,
  WalletSigningSessionId,
  EmailOtpChallengeId,
} from '@shared/utils/domainIds';

export type {
  EmailOtpChallengeId,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  ThresholdSessionId,
  WalletSigningSessionId,
} from '@shared/utils/domainIds';

export type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

export type BackingMaterialSessionId = Brand<string, 'BackingMaterialSessionId'>;
export type SigningOperationId = Brand<string, 'SigningOperationId'>;
export type SigningOperationFingerprint = Brand<string, 'SigningOperationFingerprint'>;

export type SigningCurve = 'ed25519' | 'ecdsa';
export type SigningChainFamily = 'near' | ThresholdEcdsaChainTarget['kind'];
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

type BaseSigningSessionPlanningLane = {
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
};

export type Ed25519SigningSessionPlanningLane = BaseSigningSessionPlanningLane & {
  curve: 'ed25519';
  keyKind: 'threshold_ed25519';
  chainFamily: 'near';
  accountId: AccountId;
  walletId?: never;
  chainTarget?: never;
  subjectId?: never;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  thresholdSessionId?: ThresholdEd25519SessionId;
};

export type EcdsaSigningSessionPlanningLane = BaseSigningSessionPlanningLane & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  key: EvmFamilyEcdsaKeyIdentity;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  walletId: AccountId;
  accountId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type SigningSessionPlanningLane =
  | Ed25519SigningSessionPlanningLane
  | EcdsaSigningSessionPlanningLane;

type BaseSelectedSigningLaneIdentity = {
  authMethod: SigningAuthMethod;
  walletSigningSessionId: WalletSigningSessionId;
};

export type SelectedEd25519SigningLaneIdentity = BaseSelectedSigningLaneIdentity & {
  curve: 'ed25519';
  chainFamily: 'near';
  accountId: AccountId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type SelectedEcdsaSigningLaneIdentity = BaseSelectedSigningLaneIdentity & {
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: AccountId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type SelectedSigningLaneIdentity =
  | SelectedEd25519SigningLaneIdentity
  | SelectedEcdsaSigningLaneIdentity;

export type SelectedEd25519SigningSessionPlanningLane =
  Ed25519SigningSessionPlanningLane & SelectedEd25519SigningLaneIdentity;

export type SelectedEcdsaSigningSessionPlanningLane =
  EcdsaSigningSessionPlanningLane & SelectedEcdsaSigningLaneIdentity;

export type SelectedSigningSessionPlanningLane =
  | SelectedEd25519SigningSessionPlanningLane
  | SelectedEcdsaSigningSessionPlanningLane;

type BaseResolvedSigningSessionIdentity = BaseSelectedSigningLaneIdentity & {
  keyKind: SigningKeyKind;
  sessionOrigin: SigningSessionOrigin;
  storageSource: SigningSessionStorageSource;
  retention: SigningSessionRetention;
  backingMaterialSessionId?: BackingMaterialSessionId;
};

export type ResolvedEd25519SigningSessionIdentity = BaseResolvedSigningSessionIdentity & {
  curve: 'ed25519';
  keyKind: 'threshold_ed25519';
  chainFamily: 'near';
  accountId: AccountId;
  thresholdSessionId: ThresholdEd25519SessionId;
  signingRootId?: never;
  signingRootVersion?: never;
};

export type ResolvedEcdsaSigningSessionIdentity = BaseResolvedSigningSessionIdentity & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

export type ResolvedSigningSessionIdentity =
  | ResolvedEd25519SigningSessionIdentity
  | ResolvedEcdsaSigningSessionIdentity;

export type SigningOperationContext = {
  operationId: SigningOperationId;
  intent: SigningOperationIntent;
  operationFingerprint?: SigningOperationFingerprint;
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

export type Ed25519WalletSigningSpendPlan = {
  operationId: SigningOperationId;
  operationFingerprint?: SigningOperationFingerprint;
  walletId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  lane: SelectedEd25519SigningSessionPlanningLane;
  thresholdSessionIds: readonly ThresholdEd25519SessionId[];
  backingMaterialSessionIds: readonly BackingMaterialSessionId[];
  uses: number;
  reason: SigningOperationIntent;
};

export type EcdsaWalletSigningSpendPlan = {
  operationId: SigningOperationId;
  operationFingerprint?: SigningOperationFingerprint;
  walletId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  lane: SelectedEcdsaSigningSessionPlanningLane;
  ecdsaKey: EvmFamilyEcdsaKeyIdentity;
  thresholdSessionIds: readonly ThresholdEcdsaSessionId[];
  backingMaterialSessionIds: readonly BackingMaterialSessionId[];
  uses: number;
  reason: SigningOperationIntent;
};

export type WalletSigningSpendPlan =
  | Ed25519WalletSigningSpendPlan
  | EcdsaWalletSigningSpendPlan;

export type EmailOtpChallengePlan = {
  challengeId?: EmailOtpChallengeId;
  chainFamily: SigningChainFamily;
  lane: SelectedSigningSessionPlanningLane;
};

export type PasskeyReconnectPlan = {
  lane: SelectedSigningSessionPlanningLane;
  thresholdSessionId: ThresholdSessionId;
};

export type SigningSessionNotReadyReason =
  | 'missing_session'
  | 'expired'
  | 'exhausted'
  | 'budget_unknown'
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
      lane: SelectedSigningSessionPlanningLane;
      keyRef: SigningKeyRefIntent;
    }
  | {
      kind: typeof SigningSessionPlanKind.EmailOtpReauth;
      lane: SelectedSigningSessionPlanningLane;
      challenge: EmailOtpChallengePlan;
    }
  | {
      kind: typeof SigningSessionPlanKind.PasskeyReauth;
      lane: SelectedSigningSessionPlanningLane;
      reconnect: PasskeyReconnectPlan;
    }
  | {
      kind: typeof SigningSessionPlanKind.NotReady;
      lane: SelectedSigningSessionPlanningLane;
      reason: SigningSessionNotReadyReason;
    };

type BaseSigningLaneSummary = Pick<
  SigningSessionPlanningLane,
  'authMethod' | 'curve' | 'keyKind' | 'chainFamily' | 'sessionOrigin' | 'storageSource' | 'retention'
>;

export type Ed25519SigningLaneSummary = BaseSigningLaneSummary & {
  curve: 'ed25519';
  accountId: AccountId;
};

export type EcdsaSigningLaneSummary = BaseSigningLaneSummary & {
  curve: 'ecdsa';
  walletId: AccountId;
};

export type SigningLaneSummary = Ed25519SigningLaneSummary | EcdsaSigningLaneSummary;

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

function requireDomainId<T>(result: DomainIdParseResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`[SigningSession] ${result.error.message || `${label} is required`}`);
  }
  return result.value;
}

export const SigningSessionIds = {
  walletSigningSession(value: unknown): WalletSigningSessionId {
    return requireDomainId(parseWalletSigningSessionId(value), 'walletSigningSessionId');
  },
  thresholdEd25519Session(value: unknown): ThresholdEd25519SessionId {
    return requireDomainId(parseThresholdEd25519SessionId(value), 'thresholdEd25519SessionId');
  },
  thresholdEcdsaSession(value: unknown): ThresholdEcdsaSessionId {
    return requireDomainId(parseThresholdEcdsaSessionId(value), 'thresholdEcdsaSessionId');
  },
  backingMaterialSession(value: unknown): BackingMaterialSessionId {
    return toRequiredBrandedString(value, 'backingMaterialSessionId');
  },
  emailOtpChallenge(value: unknown): EmailOtpChallengeId {
    return requireDomainId(parseEmailOtpChallengeId(value), 'emailOtpChallengeId');
  },
  signingOperation(value: unknown): SigningOperationId {
    return toRequiredBrandedString(value, 'signingOperationId');
  },
  signingOperationFingerprint(value: unknown): SigningOperationFingerprint {
    return toRequiredBrandedString(value, 'signingOperationFingerprint');
  },
} as const;

export function summarizeSigningLane(lane: SigningSessionPlanningLane): SigningLaneSummary {
  const summary = {
    authMethod: lane.authMethod,
    curve: lane.curve,
    keyKind: lane.keyKind,
    chainFamily: lane.chainFamily,
    sessionOrigin: lane.sessionOrigin,
    storageSource: lane.storageSource,
    retention: lane.retention,
  } as const;
  return lane.curve === 'ecdsa'
    ? {
        ...summary,
        curve: 'ecdsa',
        walletId: lane.walletId,
      }
    : {
        ...summary,
        curve: 'ed25519',
        accountId: lane.accountId,
      };
}

function normalizeLaneIdentityField(value: unknown): string {
  return value == null ? '' : String(value).trim();
}

export function findSigningLaneIdentityMismatch(
  a: SigningSessionPlanningLane,
  b: SigningSessionPlanningLane,
): string | null {
  const fields: Array<keyof SigningSessionPlanningLane> = [
    'authMethod',
    'curve',
    'keyKind',
    'chainFamily',
    'walletSigningSessionId',
    'thresholdSessionId',
    'backingMaterialSessionId',
    'sessionOrigin',
    'storageSource',
    'retention',
    'activeSignerSlot',
  ];
  if (a.curve === 'ecdsa' && b.curve === 'ecdsa') {
    if (normalizeLaneIdentityField(a.walletId) !== normalizeLaneIdentityField(b.walletId)) {
      return 'walletId';
    }
  } else if (a.curve === 'ed25519' && b.curve === 'ed25519') {
    if (normalizeLaneIdentityField(a.accountId) !== normalizeLaneIdentityField(b.accountId)) {
      return 'accountId';
    }
  }
  for (const field of fields) {
    if (normalizeLaneIdentityField(a[field]) !== normalizeLaneIdentityField(b[field])) {
      return String(field);
    }
  }
  return null;
}

export function assertSameSigningLaneIdentity(args: {
  expected: SigningSessionPlanningLane;
  actual: SigningSessionPlanningLane;
  context: string;
}): void {
  const mismatch = findSigningLaneIdentityMismatch(args.expected, args.actual);
  if (!mismatch) return;
  throw new Error(
    `[SigningSession] signing lane identity changed before ${args.context}: ${mismatch}`,
  );
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
  const laneWalletId = toAccountId(lane.curve === 'ecdsa' ? lane.walletId : lane.accountId);
  const walletId = toAccountId(input.walletId || laneWalletId);
  if (String(walletId) !== String(laneWalletId)) {
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
  const uses = Math.floor(Number(input.uses) || 0);
  if (!Number.isFinite(uses) || uses <= 0) {
    throw new Error('[SigningSession] wallet signing spend uses must be a positive integer');
  }
  if (input.reason !== SigningOperationIntent.TransactionSign) {
    throw new Error('[SigningSession] wallet signing spend reason is invalid');
  }
  const normalizedLane: SelectedSigningSessionPlanningLane =
    lane.curve === 'ecdsa'
      ? {
          ...lane,
          walletId,
          walletSigningSessionId,
        }
      : {
          ...lane,
          accountId: walletId,
          walletSigningSessionId,
        };
  const ecdsaKey =
    normalizedLane.curve === 'ecdsa'
      ? normalizeEcdsaSpendKey(input, normalizedLane)
      : undefined;
  return {
    ...input,
    operationId,
    ...(operationFingerprint ? { operationFingerprint } : {}),
    walletId,
    walletSigningSessionId,
    lane: normalizedLane,
    ...(ecdsaKey ? { ecdsaKey } : {}),
    thresholdSessionIds: uniqueBrandedStrings(
      input.thresholdSessionIds,
      (value) => requireDomainId(parseThresholdSessionId(value), 'thresholdSessionId'),
      'thresholdSessionIds',
    ),
    backingMaterialSessionIds: uniqueBrandedStrings(
      input.backingMaterialSessionIds,
      SigningSessionIds.backingMaterialSession,
      'backingMaterialSessionIds',
    ),
    uses,
    reason: SigningOperationIntent.TransactionSign,
  } as WalletSigningSpendPlan;
}

function normalizeEcdsaSpendKey(
  input: WalletSigningSpendPlan,
  lane: SelectedEcdsaSigningSessionPlanningLane,
): EvmFamilyEcdsaKeyIdentity {
  const key = (input as { ecdsaKey?: EvmFamilyEcdsaKeyIdentity }).ecdsaKey;
  if (!key) {
    throw new Error('[SigningSession] ECDSA wallet signing spend requires shared key identity');
  }
  const mismatches: string[] = [];
  if (String(key.walletId) !== String(lane.walletId)) mismatches.push('walletId');
  if (String(key.ecdsaThresholdKeyId) !== String(lane.key.ecdsaThresholdKeyId)) {
    mismatches.push('ecdsaThresholdKeyId');
  }
  if (String(key.signingRootId) !== String(lane.key.signingRootId)) {
    mismatches.push('signingRootId');
  }
  if (String(key.signingRootVersion) !== String(lane.key.signingRootVersion)) {
    mismatches.push('signingRootVersion');
  }
  if (mismatches.length) {
    throw new Error(
      `[SigningSession] ECDSA wallet signing spend key does not match lane: ${mismatches.join(',')}`,
    );
  }
  return key;
}

function uniqueBrandedStrings<TValue extends string>(
  values: readonly unknown[],
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
