import {
  EMAIL_OTP_CHANNEL,
  isWalletEmailOtpLoginOperation,
  isWalletUnlockBackend,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
  type WalletUnlockBackend,
} from '@shared/utils/emailOtpDomain';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';

export function parseWalletUnlockBackend(raw: unknown): WalletUnlockBackend | null {
  const value = toOptionalTrimmedString(raw)?.toLowerCase() || '';
  if (isWalletUnlockBackend(value)) return value;
  return null;
}

export function parseWalletEmailOtpChannel(raw: unknown): WalletEmailOtpChannel | null {
  const value = toOptionalTrimmedString(raw)?.toLowerCase() || '';
  if (value === EMAIL_OTP_CHANNEL) return value;
  return null;
}

export function parseWalletEmailOtpLoginOperation(raw: unknown):
  | { ok: true; operation: WalletEmailOtpLoginOperation }
  | { ok: false; code: 'invalid_body'; message: string } {
  const value = toOptionalTrimmedString(raw)?.toLowerCase() || '';
  if (!value || value === WALLET_EMAIL_OTP_UNLOCK_OPERATION) {
    return { ok: true, operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION };
  }
  if (isWalletEmailOtpLoginOperation(value)) {
    return { ok: true, operation: value };
  }
  return {
    ok: false,
    code: 'invalid_body',
    message: 'operation must be wallet_unlock, transaction_sign, or export_key',
  };
}
