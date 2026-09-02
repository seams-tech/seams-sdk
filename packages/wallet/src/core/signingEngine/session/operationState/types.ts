import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/seams';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type {
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
  ExactSigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import {
  deferredEd25519MaterialIdentityKey,
  exactSigningLaneIdentityKey,
} from '../identity/exactSigningLaneIdentity';
import {
  signingLaneAuthMethod,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import {
  parseEmailOtpChallengeId,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import type {
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  ThresholdSessionId,
  EmailOtpChallengeId,
} from '@shared/utils/domainIds';

export type {
  EmailOtpChallengeId,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  ThresholdSessionId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type AuthorizationParseResult,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';

export type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

export type SigningOperationId = Brand<string, 'SigningOperationId'>;
export type SigningOperationFingerprint = Brand<string, 'SigningOperationFingerprint'>;

export type SigningCurve = 'ed25519' | 'ecdsa';
export type SigningChainFamily = 'near' | ThresholdEcdsaChainTarget['kind'];
export type SigningKeyKind = 'threshold_ed25519' | 'threshold_ecdsa_secp256k1' | 'webauthn_p256';
export type SigningSessionOrigin =
  | 'login'
  | 'registration'
  | 'add_signer'
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
  auth: SigningLaneAuthBinding;
  curve: SigningCurve;
  keyKind: SigningKeyKind;
  chainFamily: SigningChainFamily;
  sessionOrigin: SigningSessionOrigin;
  storageSource: SigningSessionStorageSource;
  retention: SigningSessionRetention;
};

export type Ed25519SigningSessionPlanningLane = BaseSigningSessionPlanningLane & {
    identity: ExactEd25519SigningLaneIdentity;
    curve: 'ed25519';
    keyKind: 'threshold_ed25519';
    chainFamily: 'near';
    walletSessionId: WalletSessionId;
    quotaId: MpcWalletSigningQuotaId;
    thresholdSessionId: ThresholdEd25519SessionId;
  };

export type DeferredEd25519MaterialIdentity = {
  readonly kind: 'deferred_ed25519_material_identity';
  readonly signer: NearEd25519SignerBinding;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

/** A material candidate before operation-step-up has issued a grant. This
 * lane is deliberately excluded from reusable-session and budget paths. */
export type DeferredEd25519SigningSessionPlanningLane = BaseSigningSessionPlanningLane & {
    identity: DeferredEd25519MaterialIdentity;
    auth: SigningLaneAuthBinding;
    curve: 'ed25519';
    keyKind: 'threshold_ed25519';
    chainFamily: 'near';
    sessionOrigin: 'per_operation';
    storageSource: 'sealed_restore';
    retention: 'single_use';
    materialActivation: MpcMaterialActivationRef;
    walletSessionId?: never;
    quotaId?: never;
    thresholdSessionId: ThresholdEd25519SessionId;
  };

export type EcdsaSigningSessionPlanningLane = BaseSigningSessionPlanningLane & {
    identity: ExactEcdsaSigningLaneIdentity;
    curve: 'ecdsa';
    keyKind: 'threshold_ecdsa_secp256k1';
    chainFamily: ThresholdEcdsaChainTarget['kind'];
    materialActivation: MpcMaterialActivationRef;
    authorization: ExactEvmFamilyWalletSessionAuthorization;
    thresholdSessionId?: never;
  };

export type SigningSessionPlanningLane =
  | Ed25519SigningSessionPlanningLane
  | DeferredEd25519SigningSessionPlanningLane
  | EcdsaSigningSessionPlanningLane;

type BaseSelectedSigningLaneIdentity<
  TIdentity extends ExactSigningLaneIdentity = ExactSigningLaneIdentity,
> = {
  identity: TIdentity;
  auth: SigningLaneAuthBinding;
};

export type SelectedEd25519SigningLaneIdentity =
  BaseSelectedSigningLaneIdentity<ExactEd25519SigningLaneIdentity> & {
  identity: ExactEd25519SigningLaneIdentity;
  curve: 'ed25519';
  chainFamily: 'near';
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type SelectedEcdsaSigningLaneIdentity =
  BaseSelectedSigningLaneIdentity<ExactEcdsaSigningLaneIdentity> & {
  identity: ExactEcdsaSigningLaneIdentity;
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  materialActivation: MpcMaterialActivationRef;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  thresholdSessionId?: never;
};

export type SelectedSigningLaneIdentity =
  | SelectedEd25519SigningLaneIdentity
  | SelectedEcdsaSigningLaneIdentity;

export type SelectedEd25519SigningSessionPlanningLane = Ed25519SigningSessionPlanningLane &
  SelectedEd25519SigningLaneIdentity;

export type SelectedEcdsaSigningSessionPlanningLane = EcdsaSigningSessionPlanningLane &
  SelectedEcdsaSigningLaneIdentity;

export type SelectedSigningSessionPlanningLane =
  | SelectedEd25519SigningSessionPlanningLane
  | SelectedEcdsaSigningSessionPlanningLane;

type BaseResolvedSigningSessionIdentity<
  TIdentity extends ExactSigningLaneIdentity = ExactSigningLaneIdentity,
> = BaseSelectedSigningLaneIdentity<TIdentity> & {
  keyKind: SigningKeyKind;
  sessionOrigin: SigningSessionOrigin;
  storageSource: SigningSessionStorageSource;
  retention: SigningSessionRetention;
};

export type ResolvedEd25519SigningSessionIdentity =
  BaseResolvedSigningSessionIdentity<ExactEd25519SigningLaneIdentity> & {
  curve: 'ed25519';
  keyKind: 'threshold_ed25519';
  chainFamily: 'near';
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

export type ResolvedEcdsaSigningSessionIdentity =
  BaseResolvedSigningSessionIdentity<ExactEcdsaSigningLaneIdentity> & {
  curve: 'ecdsa';
  keyKind: 'threshold_ecdsa_secp256k1';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  materialActivation: MpcMaterialActivationRef;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
  thresholdSessionId?: never;
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

export type Ed25519SigningKeyRefIntent =
  | {
      kind: typeof SigningKeyRefIntentKind.Cached;
      curve: 'ed25519';
      thresholdSessionId: ThresholdEd25519SessionId;
      materialActivation?: never;
      authorization?: never;
    }
  | {
      kind: typeof SigningKeyRefIntentKind.Reauth;
      curve: 'ed25519';
      authMethod: SignerAuthMethod;
      thresholdSessionId?: never;
      materialActivation?: never;
      authorization?: never;
    };

export type EcdsaSigningKeyRefIntent =
  | {
      kind: typeof SigningKeyRefIntentKind.Cached;
      curve: 'ecdsa';
      materialActivation: MpcMaterialActivationRef;
      authorization: ExactEvmFamilyWalletSessionAuthorization;
      thresholdSessionId?: never;
    }
  | {
      kind: typeof SigningKeyRefIntentKind.Reauth;
      curve: 'ecdsa';
      authMethod: SignerAuthMethod;
      thresholdSessionId?: never;
      materialActivation?: never;
      authorization?: never;
    };

export type SigningKeyRefIntent = Ed25519SigningKeyRefIntent | EcdsaSigningKeyRefIntent;

export type EmailOtpChallengePlan = {
  challengeId?: EmailOtpChallengeId;
  chainFamily: SigningChainFamily;
  lane: SelectedSigningSessionPlanningLane;
};

export type PasskeyReconnectPlan =
  | {
      lane: SelectedEd25519SigningSessionPlanningLane;
      curve: 'ed25519';
      thresholdSessionId: ThresholdEd25519SessionId;
      materialActivation?: never;
      authorization?: never;
    }
  | {
      lane: SelectedEcdsaSigningSessionPlanningLane;
      curve: 'ecdsa';
      materialActivation: MpcMaterialActivationRef;
      authorization: ExactEvmFamilyWalletSessionAuthorization;
      thresholdSessionId?: never;
    };

export type SigningSessionNotReadyReason =
  | 'missing_session'
  | 'expired'
  | 'exhausted'
  | 'status_unknown'
  | 'auth_unavailable'
  | 'status_unavailable'
  | 'policy_blocked';

export const SigningSessionPlanKind = {
  WarmSession: 'warm_session',
  EmailOtpReauth: 'email_otp_reauth',
  PasskeyReauth: 'passkey_reauth',
  NotReady: 'not_ready',
  OperationStepUp: 'operation_step_up',
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
    }
  | {
      kind: typeof SigningSessionPlanKind.OperationStepUp;
      lane: DeferredEd25519SigningSessionPlanningLane;
    };

type BaseSigningLaneSummary = Pick<
  SigningSessionPlanningLane,
  'curve' | 'keyKind' | 'chainFamily' | 'sessionOrigin' | 'storageSource' | 'retention'
> & {
  authMethod: SignerAuthMethod;
};

export type Ed25519SigningLaneSummary = BaseSigningLaneSummary & {
  curve: 'ed25519';
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  accountId?: never;
};

export type EcdsaSigningLaneSummary = BaseSigningLaneSummary & {
  curve: 'ecdsa';
  walletId: WalletId;
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

function requireAuthorizationId<T>(result: AuthorizationParseResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`[SigningSession] ${result.error.message || `${label} is required`}`);
  }
  return result.value;
}

export const SigningSessionIds = {
  walletSession(value: unknown): WalletSessionId {
    return requireAuthorizationId(parseWalletSessionId(value), 'walletSessionId');
  },
  walletSessionQuota(value: unknown): MpcWalletSigningQuotaId {
    return requireAuthorizationId(parseMpcWalletSigningQuotaId(value), 'quotaId');
  },
  thresholdEd25519Session(value: unknown): ThresholdEd25519SessionId {
    return requireDomainId(parseThresholdEd25519SessionId(value), 'thresholdEd25519SessionId');
  },
  thresholdEcdsaSession(value: unknown): ThresholdEcdsaSessionId {
    return requireDomainId(parseThresholdEcdsaSessionId(value), 'thresholdEcdsaSessionId');
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
  const signer = lane.identity.signer;
  const summary = {
    authMethod: signingLaneAuthMethod(lane.auth),
    curve: lane.curve,
    keyKind: lane.keyKind,
    chainFamily: lane.chainFamily,
    sessionOrigin: lane.sessionOrigin,
    storageSource: lane.storageSource,
    retention: lane.retention,
  } as const;
  switch (signer.kind) {
    case 'evm_family_ecdsa_signer':
      return {
        ...summary,
        curve: 'ecdsa',
        walletId: signer.walletId,
};
    case 'near_ed25519_signer':
      return {
        ...summary,
        curve: 'ed25519',
        walletId: signer.account.wallet.walletId,
        nearAccountId: signer.account.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
      };
  }
}

function normalizeLaneIdentityField(value: unknown): string {
  return value == null ? '' : String(value).trim();
}

export function findSigningLaneIdentityMismatch(
  a: SigningSessionPlanningLane,
  b: SigningSessionPlanningLane,
): string | null {
  const leftKey =
    a.identity.kind === 'deferred_ed25519_material_identity'
      ? deferredEd25519MaterialIdentityKey(a.identity)
      : exactSigningLaneIdentityKey(a.identity);
  const rightKey =
    b.identity.kind === 'deferred_ed25519_material_identity'
      ? deferredEd25519MaterialIdentityKey(b.identity)
      : exactSigningLaneIdentityKey(b.identity);
  if (leftKey !== rightKey) {
    return 'identity';
  }
  const fields: Array<keyof SigningSessionPlanningLane> = [
    'keyKind',
    'sessionOrigin',
    'storageSource',
    'retention',
  ];
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

export function summarizeSigningSessionPlan(plan: SigningSessionPlan): SigningPlanSummary {
  return {
    kind: plan.kind,
    lane: summarizeSigningLane(plan.lane),
  };
}
