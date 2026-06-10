import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type {
  WalletEmailOtpExportOperation,
  WalletEmailOtpLoginOperation,
  WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  routeFamilyForAuthLane,
  toMintedWalletSigningSessionId,
  type AuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
  type MintedWalletSigningSessionId,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export const EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE =
  'Email OTP signing-session authority is unavailable; unlock wallet again';

export type EmailOtpAppSessionRouteAuth = {
  kind: 'app_session';
  jwt: string;
  curve?: never;
  thresholdSessionId?: never;
  walletSigningSessionId?: never;
  chainTarget?: never;
};

export type EmailOtpThresholdEd25519RouteAuth = {
  kind: 'threshold_ed25519_session';
  jwt: string;
  curve: 'ed25519';
  thresholdSessionId: string;
  walletSigningSessionId: AuthorizingWalletSigningSessionId;
  chainTarget?: never;
};

export type EmailOtpThresholdEcdsaRouteAuth = {
  kind: 'threshold_ecdsa_session';
  jwt: string;
  curve: 'ecdsa';
  thresholdSessionId: string;
  walletSigningSessionId: AuthorizingWalletSigningSessionId;
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
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
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
): AppOrThresholdSessionAuth | undefined {
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
      walletSigningSessionId: authLane.authorizingWalletSigningSessionId,
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
): AppOrThresholdSessionAuth {
  switch (auth.kind) {
    case 'app_session':
      return { kind: 'app_session', jwt: auth.jwt };
    case 'threshold_ecdsa_session':
      return { kind: 'threshold_session', jwt: auth.jwt };
  }
  return assertNever(auth);
}

export type EmailOtpEcdsaMintingSession =
  | {
      kind: 'per_operation';
      walletSigningSessionId: MintedWalletSigningSessionId;
      authorizingWalletSigningSessionId?: AuthorizingWalletSigningSessionId;
    }
  | {
      kind: 'session';
      walletSigningSessionId: MintedWalletSigningSessionId;
      authorizingWalletSigningSessionId?: AuthorizingWalletSigningSessionId;
    };

export function authorizingWalletSigningSessionIdFromRoutePlan(
  routePlan: EmailOtpRoutePlan,
): AuthorizingWalletSigningSessionId | undefined {
  return routePlan.authLane.kind === 'signing_session'
    ? routePlan.authLane.authorizingWalletSigningSessionId
    : undefined;
}

export function assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession(args: {
  mintedWalletSigningSessionId: MintedWalletSigningSessionId;
  authorizingWalletSigningSessionId?: AuthorizingWalletSigningSessionId;
}): void {
  if (!args.authorizingWalletSigningSessionId) return;
  if (String(args.mintedWalletSigningSessionId) === String(args.authorizingWalletSigningSessionId)) {
    throw new Error(
      'Email OTP per-operation ECDSA minting must create a fresh wallet signing-session id',
    );
  }
}

export function buildPerOperationEmailOtpEcdsaMintingSession(args: {
  routePlan: EmailOtpRoutePlan;
  generateWalletSigningSessionId: () => string;
}): Extract<EmailOtpEcdsaMintingSession, { kind: 'per_operation' }> {
  const mintedWalletSigningSessionId = toMintedWalletSigningSessionId(
    args.generateWalletSigningSessionId(),
  );
  const authorizingWalletSigningSessionId = authorizingWalletSigningSessionIdFromRoutePlan(
    args.routePlan,
  );
  assertPerOperationEmailOtpMintDoesNotReuseAuthorizingSession({
    mintedWalletSigningSessionId,
    ...(authorizingWalletSigningSessionId ? { authorizingWalletSigningSessionId } : {}),
  });
  return {
    kind: 'per_operation',
    walletSigningSessionId: mintedWalletSigningSessionId,
    ...(authorizingWalletSigningSessionId ? { authorizingWalletSigningSessionId } : {}),
  };
}

export function buildEmailOtpEcdsaMintingSession(args: {
  emailOtpAuthPolicy: EmailOtpAuthPolicy;
  routePlan: EmailOtpRoutePlan;
  generateWalletSigningSessionId: () => string;
}): EmailOtpEcdsaMintingSession {
  if (args.emailOtpAuthPolicy === 'per_operation') {
    return buildPerOperationEmailOtpEcdsaMintingSession({
      routePlan: args.routePlan,
      generateWalletSigningSessionId: args.generateWalletSigningSessionId,
    });
  }
  const authorizingWalletSigningSessionId = authorizingWalletSigningSessionIdFromRoutePlan(
    args.routePlan,
  );
  return {
    kind: 'session',
    walletSigningSessionId: toMintedWalletSigningSessionId(args.generateWalletSigningSessionId()),
    ...(authorizingWalletSigningSessionId ? { authorizingWalletSigningSessionId } : {}),
  };
}

export function thresholdSessionAuthFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
): AppOrThresholdSessionAuth | undefined {
  const jwt = String(bootstrap?.session?.jwt || '').trim();
  return jwt ? { kind: 'threshold_session', jwt } : undefined;
}

export function walletSigningSessionIdFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
  defaultWalletSigningSessionId: string,
): string {
  const keyRef = bootstrap ? bootstrap.thresholdEcdsaKeyRef : undefined;
  return (
    String(bootstrap?.session?.walletSigningSessionId || '').trim() ||
    String(keyRef ? keyRef.walletSigningSessionId : '').trim() ||
    String(defaultWalletSigningSessionId || '').trim()
  );
}

export function ecdsaBootstrapWithWalletSigningSessionId(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  walletSigningSessionId: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const walletSigningSessionId = walletSigningSessionIdFromEcdsaBootstrap(
    args.bootstrap,
    args.walletSigningSessionId,
  );
  if (!walletSigningSessionId) {
    throw new Error('Email OTP ECDSA bootstrap is missing wallet signing-session identity');
  }
  return {
    ...args.bootstrap,
    thresholdEcdsaKeyRef: {
      ...args.bootstrap.thresholdEcdsaKeyRef,
      walletSigningSessionId,
    },
    session: {
      ...args.bootstrap.session,
      walletSigningSessionId,
    },
  };
}

export function thresholdSessionIdFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
): string {
  const keyRef = bootstrap ? bootstrap.thresholdEcdsaKeyRef : undefined;
  return (
    String(bootstrap?.session?.sessionId || '').trim() ||
    String(keyRef ? keyRef.thresholdSessionId : '').trim()
  );
}
