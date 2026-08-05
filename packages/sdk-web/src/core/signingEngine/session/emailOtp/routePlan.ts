import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type {
  WalletEmailOtpExportOperation,
  WalletEmailOtpLoginOperation,
  WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRoutePlan,
  routeFamilyForAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export type EmailOtpSigningSessionExpectedCurve = 'ed25519' | 'ecdsa' | 'unknown';

export type EmailOtpSigningSessionAuthStateFailure =
  | {
      kind: 'auth_lane_missing';
      source:
        | 'route_plan'
        | 'provided_route_auth'
        | 'evm_signing_refresh';
      expectedCurve: EmailOtpSigningSessionExpectedCurve;
    };

export class EmailOtpSigningSessionAuthStateError extends Error {
  readonly kind = 'email_otp_signing_session_auth_state_error';
  readonly failure: EmailOtpSigningSessionAuthStateFailure;

  constructor(failure: EmailOtpSigningSessionAuthStateFailure) {
    super(emailOtpSigningSessionAuthStateFailureMessage(failure));
    this.name = 'EmailOtpSigningSessionAuthStateError';
    this.failure = failure;
    Object.setPrototypeOf(this, EmailOtpSigningSessionAuthStateError.prototype);
  }
}

function emailOtpSigningSessionAuthStateFailureMessage(
  failure: EmailOtpSigningSessionAuthStateFailure,
): string {
  return `Email OTP ${failure.expectedCurve} signing-session auth lane is unavailable at ${failure.source}; unlock wallet again`;
}

export function throwEmailOtpSigningSessionAuthStateError(
  failure: EmailOtpSigningSessionAuthStateFailure,
): never {
  throw new EmailOtpSigningSessionAuthStateError(failure);
}

export type EmailOtpAppSessionRouteAuth = {
  kind: 'app_session';
  jwt: string;
  curve?: never;
  thresholdSessionId?: never;
  chainTarget?: never;
};

export type EmailOtpThresholdEd25519RouteAuth = {
  kind: 'threshold_ed25519_session';
  jwt: string;
  curve: 'ed25519';
  chainTarget?: never;
};

export type EmailOtpThresholdEcdsaRouteAuth = {
  kind: 'threshold_ecdsa_session';
  jwt: string;
  curve: 'ecdsa';
  // Session-scoped runtime state only. Operation authority is attached later.
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type EmailOtpEcdsaBootstrapRouteAuth =
  | EmailOtpAppSessionRouteAuth
  | EmailOtpThresholdEcdsaRouteAuth;

export type EmailOtpEcdsaBootstrapAuthorization =
  | {
      kind: 'route_plan_auth';
      routeAuth?: never;
    }
  | {
      kind: 'explicit_route_auth';
      routeAuth: EmailOtpEcdsaBootstrapRouteAuth;
    };

function assertNever(value: never): never {
  throw new Error(`Unexpected Email OTP route auth branch: ${String(value)}`);
}

export function buildFreshEmailOtpRoutePlan(args: {
  freshRouteFamily: 'login' | 'registration';
  authLane: EmailOtpAuthLane;
  operation?: WalletEmailOtpLoginOperation;
}): EmailOtpRoutePlan {
  const operation =
    args.freshRouteFamily === 'registration'
      ? WALLET_EMAIL_OTP_REGISTRATION_OPERATION
      : (args.operation ?? WALLET_EMAIL_OTP_UNLOCK_OPERATION);
  return buildEmailOtpRoutePlan({
    routeFamily: routeFamilyForAuthLane({
      authLane: args.authLane,
      freshRouteFamily: args.freshRouteFamily,
    }),
    authLane: args.authLane,
    operation,
  });
}

export function assertEmailOtpSigningSessionAuthLane(
  authLane: EmailOtpAuthLane | undefined,
): EmailOtpSigningSessionAuthLane {
  if (authLane?.kind !== 'signing_session') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'route_plan',
      expectedCurve: 'unknown',
    });
  }
  return authLane;
}

export function buildEmailOtpSigningSessionRoutePlan(args: {
  authLane: EmailOtpSigningSessionAuthLane;
  operation: EmailOtpSigningSessionChallengeOperation;
}): EmailOtpRoutePlan {
  return buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane: args.authLane,
    operation: args.operation,
  });
}

export function emailOtpEcdsaBootstrapRouteAuthFromAuthLane(
  authLane: EmailOtpAuthLane,
): EmailOtpEcdsaBootstrapRouteAuth | undefined {
  if (authLane.kind === 'app_session') {
    return {
      kind: 'app_session',
      jwt: authLane.jwt,
    };
  }
  if (authLane.kind === 'signing_session' && authLane.curve === 'ecdsa') {
    return {
      kind: 'threshold_ecdsa_session',
      jwt: authLane.jwt,
      curve: 'ecdsa',
      thresholdSessionId: authLane.thresholdSessionId,
      chainTarget: authLane.chainTarget,
    };
  }
  return undefined;
}

export function emailOtpEcdsaBootstrapRouteAuthFromRoutePlan(
  routePlan: EmailOtpRoutePlan,
): EmailOtpEcdsaBootstrapRouteAuth | undefined {
  return emailOtpEcdsaBootstrapRouteAuthFromAuthLane(routePlan.authLane);
}

export function emailOtpEcdsaBootstrapRouteAuthToTransport(
  auth: EmailOtpEcdsaBootstrapRouteAuth,
): AppOrWalletSessionAuth {
  switch (auth.kind) {
    case 'app_session':
      return { kind: 'app_session', jwt: auth.jwt };
    case 'threshold_ecdsa_session':
      return { kind: 'wallet_session', jwt: auth.jwt };
  }
  return assertNever(auth);
}
