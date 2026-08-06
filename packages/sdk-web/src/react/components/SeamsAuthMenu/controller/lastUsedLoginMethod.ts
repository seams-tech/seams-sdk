export type NoLastUsedLoginMethod = { kind: 'none' };

export type LastUsedLoginMethod =
  | NoLastUsedLoginMethod
  | { kind: 'passkey' }
  | { kind: 'email_otp' };

export const NO_LAST_USED_LOGIN_METHOD: NoLastUsedLoginMethod = { kind: 'none' };

export function parseLastUsedLoginMethod(raw: unknown): LastUsedLoginMethod {
  switch (raw) {
    case 'passkey':
      return { kind: 'passkey' };
    case 'email_otp':
      return { kind: 'email_otp' };
    default:
      return NO_LAST_USED_LOGIN_METHOD;
  }
}
