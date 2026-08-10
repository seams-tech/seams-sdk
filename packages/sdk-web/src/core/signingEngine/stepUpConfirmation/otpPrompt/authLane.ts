import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isWalletEmailOtpLoginOperation,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import { isPlainObject } from '@shared/utils/validation';

export type EmailOtpAuthLane =
  | { kind: 'app_session'; jwt: string }
  | EmailOtpSigningSessionAuthLane
  | { kind: 'cookie' };

export type EmailOtpSigningSessionAuthLane =
  | {
      kind: 'signing_session';
      jwt: string;
      curve: 'ed25519';
    }
  | {
      kind: 'signing_session';
      jwt: string;
      thresholdSessionId: string;
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type EmailOtpRouteFamily = 'login' | 'registration' | 'signing_session';

type EmailOtpFreshAuthLane = Extract<EmailOtpAuthLane, { kind: 'app_session' | 'cookie' }>;

export type EmailOtpRoutePlan =
  | {
      routeFamily: 'login';
      authLane: EmailOtpFreshAuthLane;
      operation: WalletEmailOtpLoginOperation;
    }
  | {
      routeFamily: 'registration';
      authLane: EmailOtpFreshAuthLane;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      routeFamily: 'signing_session';
      authLane: EmailOtpSigningSessionAuthLane;
      operation:
        | typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION
        | typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
    };

export type ResolveEmailOtpAuthLaneArgs = {
  sessionKind?: 'jwt' | 'cookie';
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  thresholdSessionId?: string;
  curve?: 'ed25519' | 'ecdsa';
  chainTarget?: ThresholdEcdsaChainTarget;
};

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function buildEmailOtpSigningSessionAuthLane(args: {
  jwt: unknown;
  thresholdSessionId: unknown;
  curve: unknown;
  chainTarget?: unknown;
}): EmailOtpSigningSessionAuthLane | undefined {
  const jwt = nonEmptyString(args.jwt);
  const thresholdSessionId = nonEmptyString(args.thresholdSessionId);
  if (!jwt) {
    console.warn('[EmailOtpAuthLane] rejected incomplete signing-session auth lane', {
      hasAuthToken: !!jwt,
      thresholdSessionId,
      curve: args.curve,
      chainTarget: args.chainTarget,
    });
    return undefined;
  }
  if (args.curve === 'ed25519') {
    return {
      kind: 'signing_session',
      jwt,
      curve: 'ed25519',
    };
  }
  if (args.curve === 'ecdsa' && isPlainObject(args.chainTarget) && thresholdSessionId) {
    let chainTarget: ThresholdEcdsaChainTarget;
    try {
      chainTarget = thresholdEcdsaChainTargetFromRequest({
        kind: args.chainTarget.kind,
        namespace: args.chainTarget.namespace,
        chainId: args.chainTarget.chainId,
        networkSlug: args.chainTarget.networkSlug,
      });
    } catch {
      return undefined;
    }
    return {
      kind: 'signing_session',
      jwt,
      thresholdSessionId,
      curve: 'ecdsa',
      chainTarget,
    };
  }
  console.warn(
    '[EmailOtpAuthLane] rejected signing-session auth lane with invalid curve or chain target',
    {
      thresholdSessionId,
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

export function requireEmailOtpAuthLane(
  lane: EmailOtpAuthLane | undefined,
  context: string,
): EmailOtpAuthLane {
  if (!lane) {
    throw new Error(`Email OTP ${context} requires an auth lane`);
  }
  return lane;
}

export function buildEmailOtpRoutePlan(args: {
  routeFamily: EmailOtpRouteFamily;
  authLane: EmailOtpAuthLane;
  operation: WalletEmailOtpOperation;
}): EmailOtpRoutePlan {
  const authLane = requireEmailOtpAuthLane(args.authLane, `${args.routeFamily} route`);
  switch (args.routeFamily) {
    case 'registration':
      if (authLane.kind === 'signing_session') {
        throw new Error('Email OTP registration routes cannot use signing-session auth');
      }
      if (args.operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
        throw new Error('Email OTP registration routes require registration operation');
      }
      return { routeFamily: 'registration', authLane, operation: args.operation };
    case 'login':
      if (authLane.kind === 'signing_session') {
        throw new Error('Email OTP login routes cannot use signing-session auth');
      }
      if (!isWalletEmailOtpLoginOperation(args.operation)) {
        throw new Error('Email OTP login routes require a login operation');
      }
      return { routeFamily: 'login', authLane, operation: args.operation };
    case 'signing_session':
      if (authLane.kind !== 'signing_session') {
        throw new Error('Email OTP signing-session routes require signing-session auth');
      }
      if (
        args.operation !== WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION &&
        args.operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION
      ) {
        throw new Error('Email OTP signing-session routes require signing or export operation');
      }
      return { routeFamily: 'signing_session', authLane, operation: args.operation };
  }
  args.routeFamily satisfies never;
  throw new Error('Unsupported Email OTP route family');
}

export function routeFamilyForAuthLane(args: {
  authLane: EmailOtpAuthLane;
  freshRouteFamily: Extract<EmailOtpRouteFamily, 'login' | 'registration'>;
}): EmailOtpRouteFamily {
  return args.authLane.kind === 'signing_session' ? 'signing_session' : args.freshRouteFamily;
}

export function emailOtpRoutePath(
  plan: EmailOtpRoutePlan,
  action: 'challenge' | 'verify' | 'seal' | 'finalize',
): string {
  if (plan.routeFamily === 'signing_session') {
    if (action === 'challenge') return '/wallet/email-otp/signing-session/challenge';
    if (action === 'verify') return '/wallet/email-otp/signing-session/verify';
  }
  if (plan.routeFamily === 'registration') {
    if (action === 'challenge') return '/wallet/email-otp/registration/challenge';
    if (action === 'seal') return '/wallet/email-otp/registration/seal';
    if (action === 'finalize') return '/wallet/email-otp/registration/finalize';
  }
  if (plan.routeFamily === 'login') {
    if (action === 'challenge') return '/wallet/email-otp/login/challenge';
    if (action === 'verify') return '/wallet/email-otp/login/verify';
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
      curve?: unknown;
      chainTarget?: ThresholdEcdsaChainTarget;
    };
  };
  const routeFamily = nonEmptyString(input.routeFamily);
  if (!['login', 'registration', 'signing_session'].includes(routeFamily)) return undefined;
  const operation = nonEmptyString(input.operation);
  if (
    !isWalletEmailOtpLoginOperation(operation) &&
    operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION
  ) {
    return undefined;
  }
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
      curve: input.authLane?.curve,
      chainTarget: input.authLane?.chainTarget,
    });
  }
  if (!authLane) return undefined;
  try {
    return buildEmailOtpRoutePlan({
      routeFamily: routeFamily as EmailOtpRouteFamily,
      authLane,
      operation,
    });
  } catch {
    return undefined;
  }
}
