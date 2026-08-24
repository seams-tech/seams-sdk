import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import {
  buildEmailOtpWalletAuthAuthority,
  emailOtpWalletAuthAuthorityEmailHashHex,
  emailOtpWalletAuthAuthorityProvider,
  emailOtpWalletAuthAuthorityProviderUserId,
  type EmailOtpProvider,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningSessionIds,
  type SigningCurve,
  type ThresholdEd25519SessionId,
  type ThresholdSessionId,
} from '../operationState/types';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import {
  toEvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type ResolvedEvmFamilyEcdsaKey,
} from './evmFamilyEcdsaIdentity';
import { signingLaneAuthMethod, type SigningLaneAuthBinding } from './signingLaneAuthBinding';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEcdsaSigningLaneIdentity,
  type ExactEd25519SigningLaneIdentity,
  type ExactSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type { ActiveWalletAuthorityEcdsaRuntimeV1 } from '../material/activeWalletAuthorityEcdsaRuntime';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';

export type { SigningCurve };
export type { EcdsaThresholdKeyId };
export type SigningRootId = string & { readonly __brand?: 'SigningRootId' };
export type SigningRootVersion = string & { readonly __brand?: 'SigningRootVersion' };

export type ThresholdEcdsaSessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-bootstrap'
  | 'email_otp';

export const THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES = [
  'login',
  'registration',
  'manual-bootstrap',
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export const THRESHOLD_ECDSA_SESSION_STORE_SOURCES = [
  'email_otp',
  ...THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES,
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export type ThresholdEd25519SessionStoreSource =
  | 'login'
  | 'registration'
  | 'add-signer'
  | 'manual-connect'
  | 'bootstrap'
  | 'email_otp'
  | 'sealed_restore';

export type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  authMethod: 'email_otp';
  authority: EmailOtpWalletAuthAuthority;
  use: EmailOtpAuthUse;
};

export type EmailOtpAuthUse =
  | {
      kind: 'session';
      reason: 'login' | 'sign';
    }
  | {
      kind: 'single_use_pending';
    }
  | {
      kind: 'single_use_consumed';
      consumedAtMs: number;
    };

export type ThresholdEcdsaEmailOtpSessionAuthContext = ThresholdEcdsaEmailOtpAuthContext & {
  use: Extract<EmailOtpAuthUse, { kind: 'session' }>;
};

export type ThresholdEcdsaEmailOtpPendingSingleUseAuthContext =
  ThresholdEcdsaEmailOtpAuthContext & {
    use: Extract<EmailOtpAuthUse, { kind: 'single_use_pending' }>;
  };

export type ThresholdEcdsaEmailOtpConsumedSingleUseAuthContext =
  ThresholdEcdsaEmailOtpAuthContext & {
    use: Extract<EmailOtpAuthUse, { kind: 'single_use_consumed' }>;
  };

export function emailOtpAuthContextProviderUserId(
  context: ThresholdEcdsaEmailOtpAuthContext,
): string {
  return String(emailOtpWalletAuthAuthorityProviderUserId(context.authority));
}

export function emailOtpAuthContextProvider(
  context: ThresholdEcdsaEmailOtpAuthContext,
): EmailOtpProvider {
  return emailOtpWalletAuthAuthorityProvider(context.authority);
}

export function emailOtpAuthContextEmailHashHex(
  context: ThresholdEcdsaEmailOtpAuthContext,
): string {
  return emailOtpWalletAuthAuthorityEmailHashHex(context.authority);
}

export function emailOtpAuthContextReason(
  context: ThresholdEcdsaEmailOtpAuthContext,
): 'login' | 'sign' {
  switch (context.use.kind) {
    case 'session':
      return context.use.reason;
    case 'single_use_pending':
    case 'single_use_consumed':
      return 'sign';
  }
  context.use satisfies never;
  throw new Error('[SigningSession] unsupported Email OTP auth use');
}

export function emailOtpAuthContextRetention(
  context: ThresholdEcdsaEmailOtpAuthContext,
): 'session' | 'single_use' {
  switch (context.use.kind) {
    case 'session':
      return 'session';
    case 'single_use_pending':
    case 'single_use_consumed':
      return 'single_use';
  }
  context.use satisfies never;
  throw new Error('[SigningSession] unsupported Email OTP auth use');
}

export function emailOtpAuthContextConsumedAtMs(
  context: ThresholdEcdsaEmailOtpAuthContext,
): number | null {
  return context.use.kind === 'single_use_consumed' ? context.use.consumedAtMs : null;
}

export function isEmailOtpSessionAuthContext(
  context: ThresholdEcdsaEmailOtpAuthContext,
): context is ThresholdEcdsaEmailOtpSessionAuthContext {
  return context.use.kind === 'session';
}

export function isEmailOtpPendingSingleUseAuthContext(
  context: ThresholdEcdsaEmailOtpAuthContext,
): context is ThresholdEcdsaEmailOtpPendingSingleUseAuthContext {
  return context.use.kind === 'single_use_pending';
}

export function isEmailOtpConsumedSingleUseAuthContext(
  context: ThresholdEcdsaEmailOtpAuthContext,
): context is ThresholdEcdsaEmailOtpConsumedSingleUseAuthContext {
  return context.use.kind === 'single_use_consumed';
}

type BuildEmailOtpSessionAuthContextArgs = {
  policy: EmailOtpAuthPolicy;
  reason: 'login' | 'sign';
  retention: 'session';
  authority: EmailOtpWalletAuthAuthority;
  consumedAtMs?: never;
};

type BuildEmailOtpPendingSingleUseAuthContextArgs = {
  policy: EmailOtpAuthPolicy;
  retention: 'single_use';
  authority: EmailOtpWalletAuthAuthority;
  reason?: never;
  consumedAtMs?: never;
};

type BuildEmailOtpConsumedSingleUseAuthContextArgs = {
  policy: EmailOtpAuthPolicy;
  retention: 'single_use';
  authority: EmailOtpWalletAuthAuthority;
  reason?: never;
  consumedAtMs: number;
};

type BuildEmailOtpAuthContextArgs =
  | BuildEmailOtpSessionAuthContextArgs
  | BuildEmailOtpPendingSingleUseAuthContextArgs
  | BuildEmailOtpConsumedSingleUseAuthContextArgs;

type BuildEmailOtpAuthContextForWalletAuthMethodArgs = {
  policy: EmailOtpAuthPolicy;
  walletId: unknown;
  emailHashHex: unknown;
  provider: EmailOtpProvider;
  providerUserId: unknown;
} & (
  | {
      retention: 'session';
      reason: 'login' | 'sign';
      consumedAtMs?: never;
    }
  | {
      retention: 'single_use';
      reason?: never;
      consumedAtMs?: number;
  }
);

type BuildEmailOtpAuthContextFromExactAuthorityArgs = {
  policy: EmailOtpAuthPolicy;
  authority: EmailOtpWalletAuthAuthority;
} & (
  | {
      retention: 'session';
      reason: 'login' | 'sign';
      consumedAtMs?: never;
    }
  | {
      retention: 'single_use';
      reason?: never;
      consumedAtMs?: number;
    }
);

export function buildEmailOtpAuthContext(
  args: BuildEmailOtpSessionAuthContextArgs,
): ThresholdEcdsaEmailOtpSessionAuthContext;
export function buildEmailOtpAuthContext(
  args: BuildEmailOtpPendingSingleUseAuthContextArgs,
): ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
export function buildEmailOtpAuthContext(
  args: BuildEmailOtpConsumedSingleUseAuthContextArgs,
): ThresholdEcdsaEmailOtpConsumedSingleUseAuthContext;
export function buildEmailOtpAuthContext(
  args: BuildEmailOtpAuthContextArgs,
): ThresholdEcdsaEmailOtpAuthContext;
export function buildEmailOtpAuthContext(
  args: BuildEmailOtpAuthContextArgs,
): ThresholdEcdsaEmailOtpAuthContext {
  if (args.policy === 'per_operation' && args.retention !== 'single_use') {
    throw new Error('Invalid Email OTP auth context: per-operation sessions must be single-use');
  }
  if (args.retention === 'single_use' && Object.prototype.hasOwnProperty.call(args, 'reason')) {
    throw new Error('Invalid Email OTP auth context: single-use sessions must not carry reason');
  }
  const consumedAtMs = Math.floor(Number(args.consumedAtMs) || 0);
  const use: EmailOtpAuthUse =
    args.retention === 'session'
      ? { kind: 'session', reason: args.reason }
      : consumedAtMs > 0
        ? { kind: 'single_use_consumed', consumedAtMs }
        : { kind: 'single_use_pending' };
  return {
    policy: args.policy,
    authMethod: 'email_otp',
    authority: args.authority,
    use,
  };
}

export function buildEmailOtpAuthContextForWalletAuthMethod(args: {
  policy: EmailOtpAuthPolicy;
  authority: EmailOtpWalletAuthAuthority;
  reason: 'login' | 'sign';
  retention: 'session';
  consumedAtMs?: never;
}): ThresholdEcdsaEmailOtpSessionAuthContext;
export function buildEmailOtpAuthContextForWalletAuthMethod(args: {
  policy: EmailOtpAuthPolicy;
  authority: EmailOtpWalletAuthAuthority;
  retention: 'single_use';
  reason?: never;
  consumedAtMs?: never;
}): ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
export function buildEmailOtpAuthContextForWalletAuthMethod(args: {
  policy: EmailOtpAuthPolicy;
  authority: EmailOtpWalletAuthAuthority;
  retention: 'single_use';
  reason?: never;
  consumedAtMs: number;
}): ThresholdEcdsaEmailOtpConsumedSingleUseAuthContext;
export function buildEmailOtpAuthContextForWalletAuthMethod(
  args: BuildEmailOtpAuthContextFromExactAuthorityArgs,
): ThresholdEcdsaEmailOtpAuthContext;
export function buildEmailOtpAuthContextForWalletAuthMethod(
  args: BuildEmailOtpAuthContextFromExactAuthorityArgs,
): ThresholdEcdsaEmailOtpAuthContext {
  const authority = args.authority;
  if (args.retention === 'session') {
    return buildEmailOtpAuthContext({
      policy: args.policy,
      reason: args.reason,
      retention: 'session',
      authority,
    });
  }
  if (Object.prototype.hasOwnProperty.call(args, 'reason')) {
    throw new Error('Invalid Email OTP auth context: single-use sessions must not carry reason');
  }
  const consumedAtMs = Math.floor(Number(args.consumedAtMs) || 0);
  if (consumedAtMs > 0) {
    return buildEmailOtpAuthContext({
      policy: args.policy,
      retention: 'single_use',
      authority,
      consumedAtMs,
    });
  }
  return buildEmailOtpAuthContext({
    policy: args.policy,
    retention: 'single_use',
    authority,
  });
}

export function buildEmailOtpAuthContextForCanonicalWallet(args: {
  policy: EmailOtpAuthPolicy;
  walletId: unknown;
  emailHashHex: unknown;
  reason: 'login' | 'sign';
  retention: 'session';
  provider: EmailOtpProvider;
  providerUserId: unknown;
  consumedAtMs?: never;
}): ThresholdEcdsaEmailOtpSessionAuthContext;
export function buildEmailOtpAuthContextForCanonicalWallet(args: {
  policy: EmailOtpAuthPolicy;
  walletId: unknown;
  emailHashHex: unknown;
  retention: 'single_use';
  provider: EmailOtpProvider;
  providerUserId: unknown;
  reason?: never;
  consumedAtMs?: never;
}): ThresholdEcdsaEmailOtpPendingSingleUseAuthContext;
export function buildEmailOtpAuthContextForCanonicalWallet(args: {
  policy: EmailOtpAuthPolicy;
  walletId: unknown;
  emailHashHex: unknown;
  retention: 'single_use';
  provider: EmailOtpProvider;
  providerUserId: unknown;
  reason?: never;
  consumedAtMs: number;
}): ThresholdEcdsaEmailOtpConsumedSingleUseAuthContext;
export function buildEmailOtpAuthContextForCanonicalWallet(
  args: BuildEmailOtpAuthContextForWalletAuthMethodArgs,
): ThresholdEcdsaEmailOtpAuthContext;
export function buildEmailOtpAuthContextForCanonicalWallet(
  args: BuildEmailOtpAuthContextForWalletAuthMethodArgs,
): ThresholdEcdsaEmailOtpAuthContext {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: args.walletId,
    provider: args.provider,
    providerUserId: args.providerUserId,
    emailHashHex: args.emailHashHex,
  });
  if (args.retention === 'session') {
    return buildEmailOtpAuthContext({
      policy: args.policy,
      reason: args.reason,
      retention: 'session',
      authority,
    });
  }
  if (Object.prototype.hasOwnProperty.call(args, 'reason')) {
    throw new Error('Invalid Email OTP auth context: single-use sessions must not carry reason');
  }
  const consumedAtMs = Math.floor(Number(args.consumedAtMs) || 0);
  if (consumedAtMs > 0) {
    return buildEmailOtpAuthContext({
      policy: args.policy,
      retention: 'single_use',
      authority,
      consumedAtMs,
    });
  }
  return buildEmailOtpAuthContext({
    policy: args.policy,
    retention: 'single_use',
    authority,
  });
}

type CommonSelectedLane = {
  kind: 'selected_lane';
  identity: ExactSigningLaneIdentity;
  auth: SigningLaneAuthBinding;
  curve: SigningCurve;
};

export type BaseSelectedLane = CommonSelectedLane & {
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdSessionId: ThresholdSessionId;
};

export type SelectedEd25519Lane = BaseSelectedLane & {
  identity: ExactEd25519SigningLaneIdentity;
  curve: 'ed25519';
  chain: 'near';
  thresholdSessionId: ThresholdEd25519SessionId;
  accountId?: never;
};

export type SelectedEcdsaLane = CommonSelectedLane & {
  identity: ExactEcdsaSigningLaneIdentity;
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  materialActivation: MpcMaterialActivationRef;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
};

export type SelectedLane = SelectedEd25519Lane | SelectedEcdsaLane;

export type SelectedEd25519LaneInput = {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: unknown;
  auth: SigningLaneAuthBinding;
  walletSessionId: unknown;
  quotaId: unknown;
  thresholdSessionId: unknown;
};

export type SelectedEcdsaLaneInput = {
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
  keyHandle: unknown;
  walletId: WalletId;
  auth: SigningLaneAuthBinding;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
  chainTarget: ThresholdEcdsaChainTarget;
};

export function selectedEd25519Lane(input: SelectedEd25519LaneInput): SelectedEd25519Lane {
  const signerSlot = parseSignerSlot(input.signerSlot);
  if (signerSlot == null) {
    throw new Error('[SigningSession] selected Ed25519 lane requires signerSlot >= 1');
  }
  const walletSessionId = SigningSessionIds.walletSession(input.walletSessionId);
  const quotaId = SigningSessionIds.walletSessionQuota(input.quotaId);
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(input.thresholdSessionId);
  const identity = exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      signerSlot,
    }),
    auth: input.auth,
    walletSessionId,
    quotaId,
    thresholdSessionId,
  });
  return {
    kind: 'selected_lane',
    identity,
    auth: input.auth,
    curve: 'ed25519',
    chain: 'near',
    walletSessionId,
    quotaId,
    thresholdSessionId,
  };
}

export function selectedEcdsaLane(input: SelectedEcdsaLaneInput): SelectedEcdsaLane {
  if (!input.key) {
    throw new Error('[SigningSession] selected ECDSA lane requires shared key identity');
  }
  const keyHandle = toEvmFamilyEcdsaKeyHandle(input.keyHandle);
  if (String(input.key.walletId) !== String(input.walletId)) {
    throw new Error('[SigningSession] selected ECDSA lane wallet mismatch');
  }
  const identity = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: input.walletId,
      chainTarget: input.chainTarget,
      keyHandle,
      key: input.key,
      materialActivation: input.materialActivation,
    }),
    auth: input.auth,
  });
  return {
    kind: 'selected_lane',
    identity,
    auth: input.auth,
    curve: 'ecdsa',
    chain: input.chainTarget.kind,
    materialActivation: input.materialActivation,
    authorization: input.authorization,
  };
}

export type LaneCandidateState = 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';

/** Shared Refactor 92 classification of a session's runtime allowance and
 * expiry. Expiry is checked before exhaustion so an expired session is never
 * reported as merely out of uses. */
export function laneCandidateStateFromRuntimePolicy(args: {
  remainingUses: number;
  expiresAtMs: number;
  nowMs?: number;
}): LaneCandidateState {
  const nowMs = Math.floor(Number(args.nowMs) || Date.now());
  if (args.expiresAtMs <= nowMs) return 'expired';
  if (args.remainingUses <= 0) return 'exhausted';
  return 'ready';
}

export type LaneCandidateSource =
  | 'canonical_capability'
  | 'active_wallet_authority'
  | 'durable_sealed_record'
  | 'public_capability_reference'
  | 'active_execution_bundle'
  | 'runtime_session_record'
  | 'unknown';

type CommonLaneCandidate = {
  kind: 'lane_candidate';
  auth: SigningLaneAuthBinding;
  curve: SigningCurve;
  state: LaneCandidateState;
  source: LaneCandidateSource;
};

export type BaseLaneCandidate = CommonLaneCandidate & {
  thresholdSessionId: string;
  remainingUses: number | null;
  expiresAtMs: number | null;
  updatedAtMs: number | null;
};

type BaseEd25519LaneCandidate = BaseLaneCandidate & {
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  materialActivation: MpcMaterialActivationRef;
  accountId?: never;
  curve: 'ed25519';
  chain: 'near';
};

export type Ed25519LaneCandidate = BaseEd25519LaneCandidate &
  (
    | {
        authorizationState: 'authorized';
        authorization: ActiveWalletSessionAuthorizationProjection;
      }
    | {
        authorizationState: 'authorization_required';
        authorization?: never;
        state: 'deferred';
      }
  );

type BaseEcdsaLaneCandidate = CommonLaneCandidate & {
  curve: 'ecdsa';
  chain: 'evm' | 'tempo';
  walletId: WalletId;
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
  resolvedKey?: ResolvedEvmFamilyEcdsaKey;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  chainTarget: ThresholdEcdsaChainTarget;
} & (
    | ({
        source: 'canonical_capability';
        sourceChainTarget?: never;
      } & (
        | {
            authorizationState: 'authorized';
            authorization: ActiveEvmFamilyWalletSessionAuthorization;
          }
        | {
            authorizationState: 'authorization_required';
            authorization?: never;
            state: 'deferred';
          }
      ))
    | {
        source: 'active_wallet_authority';
        sourceChainTarget?: never;
        runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
        authorizationState: 'authorization_required';
        authorization?: never;
        state: 'deferred';
      }
  );

export type EcdsaLaneCandidate = BaseEcdsaLaneCandidate;

export type AuthorizedEcdsaLaneCandidate = Extract<
  EcdsaLaneCandidate,
  { authorizationState: 'authorized' }
>;

export type AuthorizationRequiredEcdsaLaneCandidate = Extract<
  EcdsaLaneCandidate,
  { authorizationState: 'authorization_required' }
>;

export type LaneCandidate = Ed25519LaneCandidate | EcdsaLaneCandidate;

export function laneCandidateAuthMethod(candidate: LaneCandidate): SignerAuthMethod {
  return signingLaneAuthMethod(candidate.auth);
}
