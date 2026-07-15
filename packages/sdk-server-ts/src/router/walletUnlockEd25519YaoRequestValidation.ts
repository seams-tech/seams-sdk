import { isPlainObject } from '@shared/utils/validation';
import { findUnexpectedRouteKey } from './routeRequestValidation';

export const ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND =
  'router_ab_ed25519_yao_email_otp_recovery_v1' as const;

export type WalletUnlockEd25519YaoEmailOtpRecoveryRequestV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly signerSlot: number;
  readonly remainingUses: number;
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
  | {
      readonly ok: true;
      readonly request: WalletUnlockEd25519YaoEmailOtpRecoveryRequestV1;
    }
  | WalletUnlockEd25519YaoParseFailure;

const RECOVERY_KEYS = ['kind', 'signerSlot', 'remainingUses'] as const;

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

export function parseWalletUnlockEd25519YaoRequest(
  raw: unknown,
): WalletUnlockEd25519YaoParseResult {
  if (!isPlainObject(raw)) {
    return invalidWalletUnlockEd25519YaoRequest('Expected JSON object body');
  }
  if (!Object.prototype.hasOwnProperty.call(raw, 'ed25519YaoRecovery')) {
    return { ok: true, request: null };
  }
  if (raw.unlockBackend !== 'email_otp') {
    return invalidWalletUnlockEd25519YaoRequest(
      'ed25519YaoRecovery requires unlockBackend=email_otp',
    );
  }
  const walletId = requiredTrimmedString(raw, 'walletId');
  const orgId = requiredTrimmedString(raw, 'orgId');
  const challengeId = requiredTrimmedString(raw, 'challengeId');
  if (!walletId) return invalidWalletUnlockEd25519YaoRequest('walletId is required');
  if (!orgId) return invalidWalletUnlockEd25519YaoRequest('orgId is required');
  if (!challengeId) return invalidWalletUnlockEd25519YaoRequest('challengeId is required');

  const recovery = raw.ed25519YaoRecovery;
  if (!isPlainObject(recovery)) {
    return invalidWalletUnlockEd25519YaoRequest('ed25519YaoRecovery is required');
  }
  const unsupported = findUnexpectedRouteKey(recovery, RECOVERY_KEYS);
  if (unsupported) {
    return invalidWalletUnlockEd25519YaoRequest(
      `Unsupported ed25519YaoRecovery field: ${unsupported}`,
    );
  }
  if (recovery.kind !== ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND) {
    return invalidWalletUnlockEd25519YaoRequest('ed25519YaoRecovery.kind is invalid');
  }
  if (
    typeof recovery.signerSlot !== 'number' ||
    !Number.isSafeInteger(recovery.signerSlot) ||
    recovery.signerSlot < 1
  ) {
    return invalidWalletUnlockEd25519YaoRequest(
      'ed25519YaoRecovery.signerSlot must be a positive integer',
    );
  }
  if (
    typeof recovery.remainingUses !== 'number' ||
    !Number.isSafeInteger(recovery.remainingUses) ||
    recovery.remainingUses < 1
  ) {
    return invalidWalletUnlockEd25519YaoRequest(
      'ed25519YaoRecovery.remainingUses must be a positive integer',
    );
  }
  return {
    ok: true,
    request: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
      walletId,
      orgId,
      challengeId,
      signerSlot: recovery.signerSlot,
      remainingUses: recovery.remainingUses,
    },
  };
}
