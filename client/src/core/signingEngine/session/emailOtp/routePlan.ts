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
  routeFamilyForAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export const EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE =
  'Email OTP signing-session authority is unavailable; unlock wallet again';

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
