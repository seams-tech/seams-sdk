import { isPlainObject } from '@shared/utils/validation';
import { findUnexpectedRouteKey } from '../../framework/routeRequestValidation';

export const EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND = 'none' as const;
export const EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND = 'ed25519_yao' as const;

type WalletUnlockEmailOtpRequestedCapabilitiesBase = {
  readonly signerSlot: number;
  readonly remainingUses: number;
};

export type WalletUnlockEmailOtpRequestedCapabilitiesV1 =
  | { readonly kind: typeof EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND }
  | (WalletUnlockEmailOtpRequestedCapabilitiesBase & {
      readonly kind: typeof EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND;
    });

export type WalletUnlockEmailOtpRequestedCapabilitiesRequestV1 = {
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly requestedCapabilities: WalletUnlockEmailOtpRequestedCapabilitiesV1;
};

type WalletUnlockRequestedCapabilitiesParseFailure = {
  readonly ok: false;
  readonly status: 400;
  readonly body: {
    readonly ok: false;
    readonly code: 'invalid_body';
    readonly message: string;
  };
};

export type WalletUnlockRequestedCapabilitiesParseResult =
  | { readonly ok: true; readonly request: null }
  | { readonly ok: true; readonly request: WalletUnlockEmailOtpRequestedCapabilitiesRequestV1 }
  | WalletUnlockRequestedCapabilitiesParseFailure;

const REQUESTED_CAPABILITIES_KEYS = ['kind', 'signerSlot', 'remainingUses'] as const;

function invalidWalletUnlockRequestedCapabilitiesRequest(
  message: string,
): WalletUnlockRequestedCapabilitiesParseFailure {
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
): number | WalletUnlockRequestedCapabilitiesParseFailure {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    return invalidWalletUnlockRequestedCapabilitiesRequest(`${field} must be a positive integer`);
  }
  return value;
}

function parseWalletUnlockEmailOtpRequestedCapabilities(
  raw: unknown,
): WalletUnlockEmailOtpRequestedCapabilitiesV1 | WalletUnlockRequestedCapabilitiesParseFailure {
  if (!isPlainObject(raw)) {
    return invalidWalletUnlockRequestedCapabilitiesRequest(
      'requestedCapabilities is required for Email OTP unlock',
    );
  }
  const unsupported = findUnexpectedRouteKey(raw, REQUESTED_CAPABILITIES_KEYS);
  if (unsupported) {
    return invalidWalletUnlockRequestedCapabilitiesRequest(
      `Unsupported requestedCapabilities field: ${unsupported}`,
    );
  }
  switch (raw.kind) {
    case EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND:
      if (raw.signerSlot !== undefined || raw.remainingUses !== undefined) {
        return invalidWalletUnlockRequestedCapabilitiesRequest(
          'requestedCapabilities.none cannot include signerSlot or remainingUses',
        );
      }
      return { kind: EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND };
    case EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND: {
      const signerSlot = parsePositiveInteger(
        raw.signerSlot,
        'requestedCapabilities.signerSlot',
      );
      if (typeof signerSlot !== 'number') return signerSlot;
      const remainingUses = parsePositiveInteger(
        raw.remainingUses,
        'requestedCapabilities.remainingUses',
      );
      if (typeof remainingUses !== 'number') return remainingUses;
      return {
        kind: EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND,
        signerSlot,
        remainingUses,
      };
    }
    default:
      return invalidWalletUnlockRequestedCapabilitiesRequest('requestedCapabilities.kind is invalid');
  }
}

export function parseWalletUnlockRequestedCapabilitiesRequest(
  raw: unknown,
): WalletUnlockRequestedCapabilitiesParseResult {
  if (!isPlainObject(raw)) {
    return invalidWalletUnlockRequestedCapabilitiesRequest('Expected JSON object body');
  }
  if (raw.unlockBackend !== 'email_otp') {
    return { ok: true, request: null };
  }
  const walletId = requiredTrimmedString(raw, 'walletId');
  const orgId = requiredTrimmedString(raw, 'orgId');
  const challengeId = requiredTrimmedString(raw, 'challengeId');
  if (!walletId) return invalidWalletUnlockRequestedCapabilitiesRequest('walletId is required');
  if (!orgId) return invalidWalletUnlockRequestedCapabilitiesRequest('orgId is required');
  if (!challengeId) return invalidWalletUnlockRequestedCapabilitiesRequest('challengeId is required');
  const requestedCapabilities = parseWalletUnlockEmailOtpRequestedCapabilities(
    raw.requestedCapabilities,
  );
  if ('ok' in requestedCapabilities) return requestedCapabilities;
  return {
    ok: true,
    request: {
      walletId,
      orgId,
      challengeId,
      requestedCapabilities,
    },
  };
}
