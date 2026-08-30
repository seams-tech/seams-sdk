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
import {
  parseWalletSessionOperationCredentialV1,
  type WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import { isPlainObject } from '@shared/utils/validation';

export type EmailOtpAuthLane = EmailOtpSigningSessionAuthLane;

export type EmailOtpSigningSessionAuthLane =
  | {
      kind: 'signing_session';
      operationCredential: WalletSessionOperationCredentialV1;
      curve: 'ed25519';
    }
  | {
      kind: 'signing_session';
      operationCredential: WalletSessionOperationCredentialV1;
      thresholdSessionId: string;
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type EmailOtpRouteFamily = 'login' | 'registration' | 'signing_session';

export type EmailOtpRoutePlan =
  | {
      routeFamily: 'login';
      authLane?: never;
      operation: WalletEmailOtpLoginOperation;
    }
  | {
      routeFamily: 'registration';
      authLane?: never;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      routeFamily: 'signing_session';
      authLane: EmailOtpSigningSessionAuthLane;
      operation:
        | typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION
        | typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
    };

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function buildEmailOtpSigningSessionAuthLane(args: {
  operationCredential: unknown;
  thresholdSessionId: unknown;
  curve: unknown;
  chainTarget?: unknown;
}): EmailOtpSigningSessionAuthLane | undefined {
  let operationCredential: WalletSessionOperationCredentialV1;
  try {
    operationCredential = parseWalletSessionOperationCredentialV1(args.operationCredential);
  } catch {
    console.warn('[EmailOtpAuthLane] rejected invalid signing-session operation credential');
    return undefined;
  }
  const thresholdSessionId = nonEmptyString(args.thresholdSessionId);
  if (args.curve === 'ed25519') {
    return {
      kind: 'signing_session',
      operationCredential,
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
      operationCredential,
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

export function buildEmailOtpRoutePlan(args: {
  routeFamily: 'login';
  authLane?: never;
  operation: WalletEmailOtpLoginOperation;
} | {
  routeFamily: 'registration';
  authLane?: never;
  operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
} | {
  routeFamily: 'signing_session';
  authLane: EmailOtpSigningSessionAuthLane;
  operation:
    | typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION
    | typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
}): EmailOtpRoutePlan {
  switch (args.routeFamily) {
    case 'registration':
      if (args.operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
        throw new Error('Email OTP registration routes require registration operation');
      }
      return { routeFamily: 'registration', operation: args.operation };
    case 'login':
      if (!isWalletEmailOtpLoginOperation(args.operation)) {
        throw new Error('Email OTP login routes require a login operation');
      }
      return { routeFamily: 'login', operation: args.operation };
    case 'signing_session':
      if (
        args.operation !== WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION &&
        args.operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION
      ) {
        throw new Error('Email OTP signing-session routes require signing or export operation');
      }
      return { routeFamily: 'signing_session', authLane: args.authLane, operation: args.operation };
  }
  throw new Error('Unsupported Email OTP route family');
}

export function emailOtpRoutePath(
  plan: EmailOtpRoutePlan,
  action: 'challenge' | 'seal' | 'finalize',
): string {
  if (plan.routeFamily === 'signing_session') {
    if (action === 'challenge') return '/wallet/email-otp/challenge';
  }
  if (plan.routeFamily === 'registration') {
    if (action === 'challenge') return '/wallet/email-otp/registration/challenge';
    if (action === 'seal') return '/wallet/email-otp/registration/seal';
    if (action === 'finalize') return '/wallet/email-otp/registration/finalize';
  }
  if (plan.routeFamily === 'login') {
    if (action === 'challenge') return '/wallet/email-otp/challenge';
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
      operationCredential?: unknown;
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
  try {
    if (routeFamily === 'login') {
      if (!isWalletEmailOtpLoginOperation(operation)) return undefined;
      return buildEmailOtpRoutePlan({ routeFamily, operation });
    }
    if (routeFamily === 'registration') {
      if (operation !== WALLET_EMAIL_OTP_REGISTRATION_OPERATION) return undefined;
      return buildEmailOtpRoutePlan({ routeFamily, operation });
    }
    const authLane = buildEmailOtpSigningSessionAuthLane({
      operationCredential: input.authLane?.operationCredential,
      thresholdSessionId: input.authLane?.thresholdSessionId,
      curve: input.authLane?.curve,
      chainTarget: input.authLane?.chainTarget,
    });
    if (!authLane) return undefined;
    if (
      operation !== WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION &&
      operation !== WALLET_EMAIL_OTP_EXPORT_OPERATION
    ) {
      return undefined;
    }
    return buildEmailOtpRoutePlan({ routeFamily: 'signing_session', authLane, operation });
  } catch {
    return undefined;
  }
}
