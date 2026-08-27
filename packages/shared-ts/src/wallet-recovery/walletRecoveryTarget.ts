import { parseWebAuthnRpId, type WebAuthnRpId } from '../utils/domainIds';

export type WalletRecoveryTargetV1 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly googleProvider?: never;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly googleProvider: 'google';
      readonly rpId?: never;
    };

export function parseWalletRecoveryTargetV1(raw: unknown): WalletRecoveryTargetV1 {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('wallet recovery target must be an object');
  }
  const record = raw as Record<string, unknown>;
  const fields = Object.keys(record);
  switch (record.kind) {
    case 'passkey': {
      if (fields.length !== 2 || !fields.includes('rpId')) {
        throw new Error('Passkey recovery target fields are invalid');
      }
      const rpId = parseWebAuthnRpId(record.rpId);
      if (!rpId.ok) throw new Error('Passkey recovery target RP ID is invalid');
      return { kind: 'passkey', rpId: rpId.value };
    }
    case 'google_email_otp':
      if (
        fields.length !== 2 ||
        !fields.includes('googleProvider') ||
        record.googleProvider !== 'google'
      ) {
        throw new Error('Google Email OTP recovery target fields are invalid');
      }
      return { kind: 'google_email_otp', googleProvider: 'google' };
    default:
      throw new Error('wallet recovery target kind is unsupported');
  }
}
