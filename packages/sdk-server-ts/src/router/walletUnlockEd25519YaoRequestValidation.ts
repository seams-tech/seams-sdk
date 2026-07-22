import { isPlainObject } from '@shared/utils/validation';
import { findUnexpectedRouteKey } from './routeRequestValidation';

export const EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND =
  'exact_local_material_session_v1' as const;
export const EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND =
  'missing_ed25519_material_recovery_v1' as const;

type WalletUnlockEmailOtpSessionIntentBase = {
  readonly signerSlot: number;
  readonly remainingUses: number;
};

export type WalletUnlockEmailOtpSessionIntentV1 =
  | (WalletUnlockEmailOtpSessionIntentBase & {
      readonly kind: typeof EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND;
    })
  | (WalletUnlockEmailOtpSessionIntentBase & {
      readonly kind: typeof EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND;
    });

export type WalletUnlockEmailOtpSessionRequestV1 = {
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly sessionIntent: WalletUnlockEmailOtpSessionIntentV1;
};

type WalletUnlockEd25519YaoParseFailure = {
  readonly ok: false;
  readonly status: 400;
  readonly body: {
    readonly ok: false;
    readonly code: 'invalid_body';
    readonly message: string;
  };
};

export type WalletUnlockEd25519YaoParseResult =
  | { readonly ok: true; readonly request: null }
  | { readonly ok: true; readonly request: WalletUnlockEmailOtpSessionRequestV1 }
  | WalletUnlockEd25519YaoParseFailure;

const SESSION_INTENT_KEYS = ['kind', 'signerSlot', 'remainingUses'] as const;

function invalidWalletUnlockEd25519YaoRequest(message: string): WalletUnlockEd25519YaoParseFailure {
  return {
    ok: false,
    status: 400,
    body: { ok: false, code: 'invalid_body', message },
  };
}

function requiredTrimmedString(body: Record<string, unknown>, field: string): string | null {
  const value = body[field];
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function parsePositiveInteger(
  value: unknown,
  field: string,
): number | WalletUnlockEd25519YaoParseFailure {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return invalidWalletUnlockEd25519YaoRequest(`${field} must be a positive integer`);
  }
  return value;
}

function parseWalletUnlockEmailOtpSessionIntent(
  raw: unknown,
): WalletUnlockEmailOtpSessionIntentV1 | WalletUnlockEd25519YaoParseFailure {
  if (!isPlainObject(raw)) {
    return invalidWalletUnlockEd25519YaoRequest('sessionIntent is required for Email OTP unlock');
  }
  const unsupported = findUnexpectedRouteKey(raw, SESSION_INTENT_KEYS);
  if (unsupported) {
    return invalidWalletUnlockEd25519YaoRequest(
      `Unsupported sessionIntent field: ${unsupported}`,
    );
  }
  const signerSlot = parsePositiveInteger(raw.signerSlot, 'sessionIntent.signerSlot');
  if (typeof signerSlot !== 'number') return signerSlot;
  const remainingUses = parsePositiveInteger(raw.remainingUses, 'sessionIntent.remainingUses');
  if (typeof remainingUses !== 'number') return remainingUses;

  switch (raw.kind) {
    case EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND:
      return {
        kind: EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND,
        signerSlot,
        remainingUses,
      };
    case EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND:
      return {
        kind: EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND,
        signerSlot,
        remainingUses,
      };
    default:
      return invalidWalletUnlockEd25519YaoRequest('sessionIntent.kind is invalid');
  }
}

export function parseWalletUnlockEd25519YaoRequest(
  raw: unknown,
): WalletUnlockEd25519YaoParseResult {
  if (!isPlainObject(raw)) {
    return invalidWalletUnlockEd25519YaoRequest('Expected JSON object body');
  }
  if (raw.unlockBackend !== 'email_otp') {
    return { ok: true, request: null };
  }
  const walletId = requiredTrimmedString(raw, 'walletId');
  const orgId = requiredTrimmedString(raw, 'orgId');
  const challengeId = requiredTrimmedString(raw, 'challengeId');
  if (!walletId) return invalidWalletUnlockEd25519YaoRequest('walletId is required');
  if (!orgId) return invalidWalletUnlockEd25519YaoRequest('orgId is required');
  if (!challengeId) return invalidWalletUnlockEd25519YaoRequest('challengeId is required');
  if (raw.sessionIntent === undefined) return { ok: true, request: null };

  const sessionIntent = parseWalletUnlockEmailOtpSessionIntent(raw.sessionIntent);
  if ('ok' in sessionIntent) return sessionIntent;
  return {
    ok: true,
    request: {
      walletId,
      orgId,
      challengeId,
      sessionIntent,
    },
  };
}
