import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type {
  WalletEmailOtpExportOperation,
  WalletEmailOtpLoginOperation,
  WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  authLaneToRouteAuth,
  buildEmailOtpRoutePlan,
  resolveEmailOtpAuthLane,
  routeFamilyForAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export const EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE =
  'Email OTP signing-session authority is unavailable; unlock wallet again';

export function buildFreshEmailOtpRoutePlan(args: {
  freshRouteFamily: 'login' | 'registration';
  routeAuth?: AppOrThresholdSessionAuth;
  appSessionJwt?: string;
  sessionKind?: 'jwt' | 'cookie';
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  curve?: 'ed25519' | 'ecdsa';
  chainTarget?: ThresholdEcdsaChainTarget;
  operation?: WalletEmailOtpLoginOperation;
}): EmailOtpRoutePlan {
  const authLane = resolveEmailOtpAuthLane({
    sessionKind: args.sessionKind,
    appSessionJwt: args.appSessionJwt,
    routeAuth: args.routeAuth,
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    curve: args.curve,
    chainTarget: args.chainTarget,
  });
  if (!authLane) {
    throw new Error(`Email OTP ${args.freshRouteFamily} requires route auth`);
  }
  return buildEmailOtpRoutePlan({
    routeFamily: routeFamilyForAuthLane({
      authLane,
      freshRouteFamily: args.freshRouteFamily,
    }),
    authLane,
    operation: args.operation,
  });
}

export function buildEmailOtpSigningSessionRoutePlan(args: {
  authLane?: EmailOtpAuthLane;
  routeAuth?: AppOrThresholdSessionAuth;
  thresholdSessionId?: string;
  walletSigningSessionId?: string;
  curve?: 'ed25519' | 'ecdsa';
  chainTarget?: ThresholdEcdsaChainTarget;
  operation: EmailOtpSigningSessionChallengeOperation;
}): EmailOtpRoutePlan {
  const authLane =
    args.authLane?.kind === 'signing_session'
      ? args.authLane
      : resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          thresholdSessionId: args.thresholdSessionId,
          walletSigningSessionId: args.walletSigningSessionId,
          curve: args.curve,
          chainTarget: args.chainTarget,
        });
  if (authLane?.kind !== 'signing_session') {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane,
    operation: args.operation,
  });
}

export function routeAuthFromEmailOtpRoutePlan(
  routePlan: EmailOtpRoutePlan,
): AppOrThresholdSessionAuth | undefined {
  return authLaneToRouteAuth(routePlan.authLane);
}

export function thresholdSessionAuthFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
): AppOrThresholdSessionAuth | undefined {
  const jwt = String(bootstrap?.session?.jwt || '').trim();
  return jwt ? { kind: 'threshold_session', jwt } : undefined;
}

export function walletSigningSessionIdFromEcdsaBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult | undefined,
  defaultWalletSigningSessionId?: string,
): string {
  return (
    String(bootstrap?.session?.walletSigningSessionId || '').trim() ||
    String(bootstrap?.thresholdEcdsaKeyRef?.walletSigningSessionId || '').trim() ||
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
  return (
    String(bootstrap?.session?.sessionId || '').trim() ||
    String(bootstrap?.thresholdEcdsaKeyRef?.thresholdSessionId || '').trim()
  );
}
