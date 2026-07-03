import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type {
  WalletEmailOtpExportOperation,
  WalletEmailOtpLoginOperation,
  WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  routeFamilyForAuthLane,
  toMintedSigningGrantId,
  type AuthorizingSigningGrantId,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
  type MintedSigningGrantId,
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
        | 'record_backed_export'
        | 'evm_reauth_anchor'
        | 'evm_signing_refresh';
      expectedCurve: EmailOtpSigningSessionExpectedCurve;
    }
  | {
      kind: 'signing_grant_missing';
      source: 'record_backed_export';
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

function assertNeverEmailOtpSigningSessionAuthStateFailure(value: never): never {
  throw new Error(`[EmailOtpRoutePlan] unexpected signing-session auth failure: ${value}`);
}

function emailOtpSigningSessionAuthStateFailureMessage(
  failure: EmailOtpSigningSessionAuthStateFailure,
): string {
  switch (failure.kind) {
    case 'auth_lane_missing':
      return `Email OTP ${failure.expectedCurve} signing-session auth lane is unavailable at ${failure.source}; unlock wallet again`;
    case 'signing_grant_missing':
      return 'Email OTP signing-session grant is unavailable for record-backed export; unlock wallet again';
  }
  return assertNeverEmailOtpSigningSessionAuthStateFailure(failure);
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
  signingGrantId?: never;
  chainTarget?: never;
};

export type EmailOtpThresholdEd25519RouteAuth = {
  kind: 'threshold_ed25519_session';
  jwt: string;
  curve: 'ed25519';
  thresholdSessionId: string;
  signingGrantId: AuthorizingSigningGrantId;
  chainTarget?: never;
};

export type EmailOtpThresholdEcdsaRouteAuth = {
  kind: 'threshold_ecdsa_session';
  jwt: string;
  curve: 'ecdsa';
  thresholdSessionId: string;
  signingGrantId: AuthorizingSigningGrantId;
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
  return buildEmailOtpRoutePlan({
    routeFamily: routeFamilyForAuthLane({
      authLane: args.authLane,
      freshRouteFamily: args.freshRouteFamily,
    }),
    authLane: args.authLane,
    operation: args.operation,
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

export function routeAuthFromEmailOtpRoutePlan(
  routePlan: EmailOtpRoutePlan,
): AppOrWalletSessionAuth | undefined {
  return authLaneToRouteAuth(routePlan.authLane);
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
      signingGrantId: authLane.authorizingSigningGrantId,
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

export type EmailOtpEcdsaMintingSession =
  | {
      kind: 'per_operation';
      signingGrantId: MintedSigningGrantId;
      authorizingSigningGrantId?: AuthorizingSigningGrantId;
    }
  | {
      kind: 'session';
      signingGrantId: MintedSigningGrantId;
      authorizingSigningGrantId?: AuthorizingSigningGrantId;
    };

export function authorizingSigningGrantIdFromRoutePlan(
  routePlan: EmailOtpRoutePlan,
): AuthorizingSigningGrantId | undefined {
  return routePlan.authLane.kind === 'signing_session'
    ? routePlan.authLane.authorizingSigningGrantId
    : undefined;
}

export function assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession(args: {
  mintedSigningGrantId: MintedSigningGrantId;
  authorizingSigningGrantId?: AuthorizingSigningGrantId;
}): void {
  if (!args.authorizingSigningGrantId) return;
  if (String(args.mintedSigningGrantId) === String(args.authorizingSigningGrantId)) {
    throw new Error(
      'Email OTP per-operation ECDSA minting must create a fresh signing grant id',
    );
  }
}

export function buildPerOperationEmailOtpEcdsaMintingSession(args: {
  routePlan: EmailOtpRoutePlan;
  generateSigningGrantId: () => string;
}): Extract<EmailOtpEcdsaMintingSession, { kind: 'per_operation' }> {
  const mintedSigningGrantId = toMintedSigningGrantId(
    args.generateSigningGrantId(),
  );
  const authorizingSigningGrantId = authorizingSigningGrantIdFromRoutePlan(
    args.routePlan,
  );
  assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
    mintedSigningGrantId,
    ...(authorizingSigningGrantId ? { authorizingSigningGrantId } : {}),
  });
  return {
    kind: 'per_operation',
    signingGrantId: mintedSigningGrantId,
    ...(authorizingSigningGrantId ? { authorizingSigningGrantId } : {}),
  };
}

export function buildEmailOtpEcdsaMintingSession(args: {
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  routePlan: EmailOtpRoutePlan;
  generateSigningGrantId: () => string;
}): EmailOtpEcdsaMintingSession {
  if (args.emailOtpAuthPolicy === 'per_operation') {
    return buildPerOperationEmailOtpEcdsaMintingSession({
      routePlan: args.routePlan,
      generateSigningGrantId: args.generateSigningGrantId,
    });
  }
  const authorizingSigningGrantId = authorizingSigningGrantIdFromRoutePlan(
    args.routePlan,
  );
  return {
    kind: 'session',
    signingGrantId: toMintedSigningGrantId(args.generateSigningGrantId()),
    ...(authorizingSigningGrantId ? { authorizingSigningGrantId } : {}),
  };
}

export function walletSessionRouteAuthFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
): AppOrWalletSessionAuth | undefined {
  const jwt = String(bootstrap?.session?.jwt || '').trim();
  return jwt ? { kind: 'wallet_session', jwt } : undefined;
}

export function signingGrantIdFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
  defaultSigningGrantId: string,
): string {
  const keyRef = bootstrap ? bootstrap.thresholdEcdsaKeyRef : undefined;
  return (
    String(bootstrap?.session?.signingGrantId || '').trim() ||
    String(keyRef ? keyRef.signingGrantId : '').trim() ||
    String(defaultSigningGrantId || '').trim()
  );
}

export function ecdsaBootstrapWithSigningGrantId(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signingGrantId: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const signingGrantId = signingGrantIdFromEcdsaBootstrap(
    args.bootstrap,
    args.signingGrantId,
  );
  if (!signingGrantId) {
    throw new Error('Email OTP ECDSA bootstrap is missing signing grant identity');
  }
  return {
    ...args.bootstrap,
    thresholdEcdsaKeyRef: {
      ...args.bootstrap.thresholdEcdsaKeyRef,
      signingGrantId,
    },
    session: {
      ...args.bootstrap.session,
      signingGrantId,
    },
  };
}

export function thresholdSessionIdFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
): string {
  const keyRef = bootstrap ? bootstrap.thresholdEcdsaKeyRef : undefined;
  return (
    String(bootstrap?.session?.thresholdSessionId || '').trim() ||
    String(keyRef ? keyRef.thresholdSessionId : '').trim()
  );
}
