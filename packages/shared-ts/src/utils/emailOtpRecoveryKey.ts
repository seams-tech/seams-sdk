export const EMAIL_OTP_RECOVERY_KEY_COUNT = 10 as const;
export const EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH = 20 as const;
export const EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH = 32 as const;
export const EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT = 8 as const;
export const EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH = 4 as const;
export const EMAIL_OTP_RECOVERY_KEY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' as const;
declare const emailOtpRecoveryCodeBrand: unique symbol;

export type EmailOtpRecoveryCode = string & {
  readonly [emailOtpRecoveryCodeBrand]: 'EmailOtpRecoveryCode';
};

export type EmailOtpRecoveryCodeSet = readonly [
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
  EmailOtpRecoveryCode,
];

const RECOVERY_KEY_DECODE: Record<string, number> = Object.freeze(
  Array.from(EMAIL_OTP_RECOVERY_KEY_ALPHABET).reduce<Record<string, number>>((acc, char, index) => {
    acc[char] = index;
    return acc;
  }, {}),
);

function cryptoRandomBytes(length: number): Uint8Array {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required to generate Email OTP recovery keys');
  }
  return cryptoApi.getRandomValues(new Uint8Array(length));
}

function isDecimalOnly(value: string): boolean {
  if (!value) return false;
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x30 || code > 0x39) return false;
  }
  return true;
}

export function encodeEmailOtpRecoveryKeyBytes(bytes: Uint8Array): string {
  if (bytes.byteLength !== EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH) {
    throw new Error('Email OTP recovery key bytes must be exactly 20 bytes');
  }

  let bitBuffer = 0;
  let bitsAvailable = 0;
  let normalized = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    bitBuffer = (bitBuffer << 8) | bytes[i];
    bitsAvailable += 8;
    while (bitsAvailable >= 5) {
      bitsAvailable -= 5;
      normalized += EMAIL_OTP_RECOVERY_KEY_ALPHABET[(bitBuffer >> bitsAvailable) & 0x1f];
      bitBuffer &= (1 << bitsAvailable) - 1;
    }
  }
  return normalized;
}

export function formatEmailOtpRecoveryKey(normalizedKey: string): EmailOtpRecoveryCode {
  const normalized = normalizeEmailOtpRecoveryKey(normalizedKey);
  const groups: string[] = [];
  let offset = 0;
  for (let i = 0; i < EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT; i++) {
    groups.push(normalized.slice(offset, offset + EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH));
    offset += EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH;
  }
  return groups.join('-') as EmailOtpRecoveryCode;
}

export function buildEmailOtpRecoveryCodeSet(keys: readonly string[]): EmailOtpRecoveryCodeSet {
  if (keys.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
    throw new Error(`Email OTP recovery code set must contain ${EMAIL_OTP_RECOVERY_KEY_COUNT} keys`);
  }
  return [
    formatEmailOtpRecoveryKey(keys[0]),
    formatEmailOtpRecoveryKey(keys[1]),
    formatEmailOtpRecoveryKey(keys[2]),
    formatEmailOtpRecoveryKey(keys[3]),
    formatEmailOtpRecoveryKey(keys[4]),
    formatEmailOtpRecoveryKey(keys[5]),
    formatEmailOtpRecoveryKey(keys[6]),
    formatEmailOtpRecoveryKey(keys[7]),
    formatEmailOtpRecoveryKey(keys[8]),
    formatEmailOtpRecoveryKey(keys[9]),
  ];
}

export function normalizeEmailOtpRecoveryKey(input: string): string {
  const normalized = String(input || '')
    .replace(/[\s-]/g, '')
    .toUpperCase();

  if (normalized.length !== EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH) {
    throw new Error('Email OTP recovery key must be 32 Crockford Base32 characters');
  }
  if (isDecimalOnly(normalized)) {
    throw new Error('Email OTP recovery key must not be decimal-only');
  }

  for (let i = 0; i < normalized.length; i++) {
    const char = normalized[i];
    if (RECOVERY_KEY_DECODE[char] === undefined) {
      throw new Error('Email OTP recovery key contains unsupported characters');
    }
  }

  return normalized;
}

export function decodeEmailOtpRecoveryKey(input: string): Uint8Array {
  const normalized = normalizeEmailOtpRecoveryKey(input);
  const out = new Uint8Array(EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH);
  let bitBuffer = 0;
  let bitsAvailable = 0;
  let offset = 0;

  for (let i = 0; i < normalized.length; i++) {
    bitBuffer = (bitBuffer << 5) | RECOVERY_KEY_DECODE[normalized[i]];
    bitsAvailable += 5;
    if (bitsAvailable >= 8) {
      bitsAvailable -= 8;
      out[offset] = (bitBuffer >> bitsAvailable) & 0xff;
      bitBuffer &= (1 << bitsAvailable) - 1;
      offset += 1;
    }
  }

  return out;
}

export function generateEmailOtpRecoveryKey(): string {
  for (;;) {
    const normalized = encodeEmailOtpRecoveryKeyBytes(
      cryptoRandomBytes(EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH),
    );
    if (!isDecimalOnly(normalized)) return formatEmailOtpRecoveryKey(normalized);
  }
}

export function generateEmailOtpRecoveryKeySet(): EmailOtpRecoveryCodeSet {
  const keys: string[] = [];
  const seen = new Set<string>();
  while (keys.length < EMAIL_OTP_RECOVERY_KEY_COUNT) {
    const key = generateEmailOtpRecoveryKey();
    if (seen.has(key)) continue;
    seen.add(key);
    keys.push(key);
  }
  return buildEmailOtpRecoveryCodeSet(keys);
}
