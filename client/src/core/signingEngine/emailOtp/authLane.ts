import type { ThresholdEcdsaActivationChain } from '@/core/signingEngine/orchestration/thresholdActivation';
import type { WalletEmailOtpOperation } from '@shared/utils/emailOtpDomain';
import {
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';

export type EmailOtpAuthLane =
  | { kind: 'app_session'; jwt: string }
  | {
      kind: 'signing_session';
      jwt: string;
      thresholdSessionId: string;
      walletSigningSessionId?: string;
      curve?: 'ed25519' | 'ecdsa';
      chain?: ThresholdEcdsaActivationChain;
    }
  | { kind: 'cookie' };

export type EmailOtpRouteFamily = 'login' | 'registration' | 'signing_session';

export type EmailOtpRoutePlan = {
  routeFamily: EmailOtpRouteFamily;
  authLane: EmailOtpAuthLane;
  operation: WalletEmailOtpOperation;
};

export type ResolveEmailOtpAuthLaneArgs = {
  sessionKind?: 'jwt' | 'cookie';
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  curve?: 'ed25519' | 'ecdsa';
  chain?: ThresholdEcdsaActivationChain;
};

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

export function resolveEmailOtpAuthLane(
  args: ResolveEmailOtpAuthLaneArgs,
): EmailOtpAuthLane | undefined {
  if (args.sessionKind === 'cookie') return { kind: 'cookie' };

  if (args.routeAuth?.kind === 'app_session') {
    const jwt = nonEmptyString(args.routeAuth.jwt);
    return jwt ? { kind: 'app_session', jwt } : undefined;
  }

  if (args.routeAuth?.kind === 'threshold_session') {
    const jwt = nonEmptyString(args.routeAuth.jwt);
    if (!jwt) return undefined;
    return {
      kind: 'signing_session',
      jwt,
      thresholdSessionId: nonEmptyString(args.thresholdSessionId),
      ...(nonEmptyString(args.walletSigningSessionId)
        ? { walletSigningSessionId: nonEmptyString(args.walletSigningSessionId) }
        : {}),
      ...(args.curve ? { curve: args.curve } : {}),
      ...(args.chain ? { chain: args.chain } : {}),
    };
  }

  const appSessionJwt = nonEmptyString(args.appSessionJwt);
  return appSessionJwt ? { kind: 'app_session', jwt: appSessionJwt } : undefined;
}

export function authLaneToRouteAuth(
  lane: EmailOtpAuthLane | undefined,
): AppOrThresholdSessionAuth | undefined {
  if (!lane || lane.kind === 'cookie') return undefined;
  if (lane.kind === 'app_session') return { kind: 'app_session', jwt: lane.jwt };
  return { kind: 'threshold_session', jwt: lane.jwt };
}

export function authLaneAppSessionJwt(lane: EmailOtpAuthLane | undefined): string {
  return lane?.kind === 'app_session' ? lane.jwt : '';
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
  action: 'challenge' | 'verify' | 'unseal' | 'seal' | 'finalize',
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
      walletSigningSessionId?: unknown;
      curve?: unknown;
      chain?: unknown;
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
    const jwt = nonEmptyString(input.authLane?.jwt);
    if (jwt) {
      authLane = {
        kind: 'signing_session',
        jwt,
        thresholdSessionId: nonEmptyString(input.authLane?.thresholdSessionId),
        ...(nonEmptyString(input.authLane?.walletSigningSessionId)
          ? { walletSigningSessionId: nonEmptyString(input.authLane?.walletSigningSessionId) }
          : {}),
        ...(input.authLane?.curve === 'ed25519' || input.authLane?.curve === 'ecdsa'
          ? { curve: input.authLane.curve }
          : {}),
        ...(input.authLane?.chain === 'tempo' || input.authLane?.chain === 'evm'
          ? { chain: input.authLane.chain }
          : {}),
      };
    }
  }
  return buildEmailOtpRoutePlan({
    routeFamily: routeFamily as EmailOtpRouteFamily,
    authLane,
    operation: nonEmptyString(input.operation) as WalletEmailOtpOperation,
  });
}
