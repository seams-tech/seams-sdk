import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletEmailOtpOperation } from '@shared/utils/emailOtpDomain';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';

export type AuthorizingSigningGrantId = string & {
  readonly __brand: 'AuthorizingSigningGrantId';
};

export type MintedSigningGrantId = string & {
  readonly __brand: 'MintedSigningGrantId';
};

export type EmailOtpAuthLane =
  | { kind: 'app_session'; jwt: string }
  | EmailOtpSigningSessionAuthLane
  | { kind: 'cookie' };

export type EmailOtpSigningSessionAuthLane =
  | {
      kind: 'signing_session';
      jwt: string;
      thresholdSessionId: string;
      authorizingSigningGrantId: AuthorizingSigningGrantId;
      curve: 'ed25519';
    }
  | {
      kind: 'signing_session';
      jwt: string;
      thresholdSessionId: string;
      authorizingSigningGrantId: AuthorizingSigningGrantId;
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type EmailOtpRouteFamily = 'login' | 'registration' | 'signing_session';

export type EmailOtpRoutePlan = {
  routeFamily: EmailOtpRouteFamily;
  authLane: EmailOtpAuthLane;
  operation: WalletEmailOtpOperation;
};

export type ResolveEmailOtpAuthLaneArgs = {
  sessionKind?: 'jwt' | 'cookie';
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  thresholdSessionId?: string;
  authorizingSigningGrantId?: string;
  curve?: 'ed25519' | 'ecdsa';
  chainTarget?: ThresholdEcdsaChainTarget;
};

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

export function toAuthorizingSigningGrantId(
  value: unknown,
): AuthorizingSigningGrantId {
  const normalized = nonEmptyString(value);
  if (!normalized) {
    throw new Error('Email OTP auth lane requires authorizing signing grant identity');
  }
  return normalized as AuthorizingSigningGrantId;
}

export function toMintedSigningGrantId(value: unknown): MintedSigningGrantId {
  const normalized = nonEmptyString(value);
  if (!normalized) {
    throw new Error('Email OTP minting requires signing grant identity');
  }
  return normalized as MintedSigningGrantId;
}

function buildEmailOtpSigningSessionAuthLane(args: {
  jwt: unknown;
  thresholdSessionId: unknown;
  authorizingSigningGrantId: unknown;
  curve: unknown;
  chainTarget?: ThresholdEcdsaChainTarget;
}): EmailOtpSigningSessionAuthLane | undefined {
  const jwt = nonEmptyString(args.jwt);
  const thresholdSessionId = nonEmptyString(args.thresholdSessionId);
  const authorizingSigningGrantId = nonEmptyString(
    args.authorizingSigningGrantId,
  );
  if (!jwt || !thresholdSessionId || !authorizingSigningGrantId) {
    console.warn('[EmailOtpAuthLane] rejected incomplete signing-session auth lane', {
      hasAuthToken: !!jwt,
      thresholdSessionId,
      authorizingSigningGrantId,
      curve: args.curve,
      chainTarget: args.chainTarget,
    });
    return undefined;
  }
  if (args.curve === 'ed25519') {
    return {
      kind: 'signing_session',
      jwt,
      thresholdSessionId,
      authorizingSigningGrantId: toAuthorizingSigningGrantId(
        authorizingSigningGrantId,
      ),
      curve: 'ed25519',
    };
  }
  if (args.curve === 'ecdsa' && args.chainTarget) {
    return {
      kind: 'signing_session',
      jwt,
      thresholdSessionId,
      authorizingSigningGrantId: toAuthorizingSigningGrantId(
        authorizingSigningGrantId,
      ),
      curve: 'ecdsa',
      chainTarget: args.chainTarget,
    };
  }
  console.warn(
    '[EmailOtpAuthLane] rejected signing-session auth lane with invalid curve or chain target',
    {
      thresholdSessionId,
      authorizingSigningGrantId,
      curve: args.curve,
      chainTarget: args.chainTarget,
    },
  );
  return undefined;
}

export function resolveEmailOtpAuthLane(
  args: ResolveEmailOtpAuthLaneArgs,
): EmailOtpAuthLane | undefined {
  if (args.sessionKind === 'cookie') return { kind: 'cookie' };

  if (args.routeAuth?.kind === 'app_session') {
    const jwt = nonEmptyString(args.routeAuth.jwt);
    return jwt ? { kind: 'app_session', jwt } : undefined;
  }

  if (args.routeAuth?.kind === 'wallet_session') {
    return buildEmailOtpSigningSessionAuthLane({
      jwt: args.routeAuth.jwt,
      thresholdSessionId: args.thresholdSessionId,
      authorizingSigningGrantId: args.authorizingSigningGrantId,
      curve: args.curve,
      chainTarget: args.chainTarget,
    });
  }

  const appSessionJwt = nonEmptyString(args.appSessionJwt);
  return appSessionJwt ? { kind: 'app_session', jwt: appSessionJwt } : undefined;
}

export function authLaneToRouteAuth(lane: EmailOtpAuthLane): AppOrWalletSessionAuth | undefined {
  if (lane.kind === 'cookie') return undefined;
  if (lane.kind === 'app_session') return { kind: 'app_session', jwt: lane.jwt };
  return { kind: 'wallet_session', jwt: lane.jwt };
}

export function authLaneAppSessionJwt(lane: EmailOtpAuthLane): string {
  return lane.kind === 'app_session' ? lane.jwt : '';
}

export function buildEmailOtpRoutePlan(args: {
  routeFamily: EmailOtpRouteFamily;
  authLane?: EmailOtpAuthLane;
  operation?: WalletEmailOtpOperation;
}): EmailOtpRoutePlan {
  const authLane = args.authLane;
  if (!authLane) {
    throw new Error(`Email OTP ${args.routeFamily} route requires an auth lane`);
  }
  if (args.routeFamily === 'signing_session' && authLane.kind !== 'signing_session') {
    throw new Error('Email OTP signing-session routes require signing-session auth');
  }
  if (
    (args.routeFamily === 'login' || args.routeFamily === 'registration') &&
    authLane.kind === 'signing_session'
  ) {
    throw new Error(`Email OTP ${args.routeFamily} routes cannot use signing-session auth`);
  }
  return {
    routeFamily: args.routeFamily,
    authLane,
    operation: args.operation || WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  };
}

export function routeFamilyForAuthLane(args: {
  authLane: EmailOtpAuthLane;
  freshRouteFamily: Extract<EmailOtpRouteFamily, 'login' | 'registration'>;
}): EmailOtpRouteFamily {
  return args.authLane.kind === 'signing_session' ? 'signing_session' : args.freshRouteFamily;
}

export function emailOtpRoutePath(
  plan: EmailOtpRoutePlan,
  action: 'challenge' | 'verify' | 'verifyAndUnseal' | 'unseal' | 'seal' | 'finalize',
): string {
  if (plan.routeFamily === 'signing_session') {
    if (action === 'challenge') return '/wallet/email-otp/signing-session/challenge';
    if (action === 'verify') return '/wallet/email-otp/signing-session/verify';
    if (action === 'unseal') return '/wallet/email-otp/signing-session/unseal';
  }
  if (plan.routeFamily === 'registration') {
    if (action === 'challenge') return '/wallet/email-otp/registration/challenge';
    if (action === 'seal') return '/wallet/email-otp/registration/seal';
    if (action === 'finalize') return '/wallet/email-otp/registration/finalize';
  }
  if (plan.routeFamily === 'login') {
    if (action === 'challenge') return '/wallet/email-otp/login/challenge';
    if (action === 'verify') return '/wallet/email-otp/login/verify';
    if (action === 'verifyAndUnseal') return '/wallet/email-otp/login/verify-and-unseal';
    if (action === 'unseal') return '/wallet/email-otp/unseal';
  }
  throw new Error(`Email OTP ${plan.routeFamily} route does not support ${action}`);
}

export function normalizeEmailOtpRoutePlan(value: unknown): EmailOtpRoutePlan | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const input = value as {
    routeFamily?: unknown;
    operation?: unknown;
    authLane?: {
      kind?: unknown;
      jwt?: unknown;
      thresholdSessionId?: unknown;
      authorizingSigningGrantId?: unknown;
      curve?: unknown;
      chainTarget?: ThresholdEcdsaChainTarget;
    };
  };
  const routeFamily = nonEmptyString(input.routeFamily);
  if (!['login', 'registration', 'signing_session'].includes(routeFamily)) return undefined;
  const laneKind = nonEmptyString(input.authLane?.kind);
  let authLane: EmailOtpAuthLane | undefined;
  if (laneKind === 'cookie') {
    authLane = { kind: 'cookie' };
  } else if (laneKind === 'app_session') {
    const jwt = nonEmptyString(input.authLane?.jwt);
    if (jwt) authLane = { kind: 'app_session', jwt };
  } else if (laneKind === 'signing_session') {
    authLane = buildEmailOtpSigningSessionAuthLane({
      jwt: input.authLane?.jwt,
      thresholdSessionId: input.authLane?.thresholdSessionId,
      authorizingSigningGrantId: input.authLane?.authorizingSigningGrantId,
      curve: input.authLane?.curve,
      chainTarget: input.authLane?.chainTarget,
    });
  }
  return buildEmailOtpRoutePlan({
    routeFamily: routeFamily as EmailOtpRouteFamily,
    authLane,
    operation: nonEmptyString(input.operation) as WalletEmailOtpOperation,
  });
}
