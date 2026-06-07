import { encodeSigningSessionHkdfTuple } from './signingSessionSeal';
import { base64UrlEncode } from './encoders';

export const EMAIL_OTP_RECOVERY_KEY_COUNT = 10 as const;
export const EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH = 20 as const;
export const EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH = 32 as const;
export const EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT = 8 as const;
export const EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH = 4 as const;
export const EMAIL_OTP_RECOVERY_KEY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' as const;
export const EMAIL_OTP_RECOVERY_WRAP_KEY_LENGTH = 32 as const;
export const EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH = 12 as const;

export const EMAIL_OTP_RECOVERY_WRAP_ALG = 'chacha20poly1305-hkdf-sha256-v1' as const;
export const EMAIL_OTP_RECOVERY_WRAP_HKDF_SALT = 'seams/email-otp/recovery-wrap/v1' as const;
export const EMAIL_OTP_RECOVERY_KEY_ID_CONTEXT =
  'seams/email-otp/recovery-key-id/v1' as const;
export const EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_AAD_CONTEXT =
  'seams/email-otp/recovery-wrapped-enrollment/v1' as const;
export const EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND =
  'email_otp_device_enrollment_escrow' as const;
export const EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND =
  'recovery_wrapped_enrollment_escrow' as const;

declare const emailOtpRecoveryCodeBrand: unique symbol;

export type EmailOtpRecoveryCode = string & {
  readonly [emailOtpRecoveryCodeBrand]: 'EmailOtpRecoveryCode';
};

declare const emailOtpRecoveryKeyIdBrand: unique symbol;

export type DerivedEmailOtpRecoveryKeyId = string & {
  readonly [emailOtpRecoveryKeyIdBrand]: 'DerivedEmailOtpRecoveryKeyId';
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

export type EmailOtpRecoveryWrapBinding = {
  auth: {
    authMethod: 'google_sso_email_otp';
    walletId: string;
    userId: string;
    authSubjectId: string;
  };
  enrollment: {
    enrollmentId: string;
    enrollmentVersion: string;
    enrollmentSealKeyVersion: string;
  };
  signingRoot: {
    signingRootId: string;
    signingRootVersion: string;
  };
  recoveryKeyId: string;
};

export type EmailOtpRecoveryKeyIdBinding = Omit<EmailOtpRecoveryWrapBinding, 'recoveryKeyId'>;

export function buildEmailOtpRecoveryWrapBinding(args: {
  walletId: string;
  userId: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryKeyId: string;
}): EmailOtpRecoveryWrapBinding {
  return {
    auth: {
      authMethod: args.authMethod,
      walletId: args.walletId,
      userId: args.userId,
      authSubjectId: args.authSubjectId,
    },
    enrollment: {
      enrollmentId: args.enrollmentId,
      enrollmentVersion: args.enrollmentVersion,
      enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
    },
    signingRoot: {
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
    },
    recoveryKeyId: args.recoveryKeyId,
  };
}

export type EmailOtpRecoveryChaCha20Poly1305 = {
  encrypt(input: {
    key32: Uint8Array;
    nonce12: Uint8Array;
    aad: Uint8Array;
    plaintext: Uint8Array;
  }): Promise<Uint8Array>;
  decrypt(input: {
    key32: Uint8Array;
    nonce12: Uint8Array;
    aad: Uint8Array;
    ciphertext: Uint8Array;
  }): Promise<Uint8Array>;
};

export type EmailOtpRecoveryWrappedEncS = {
  alg: typeof EMAIL_OTP_RECOVERY_WRAP_ALG;
  nonce12: Uint8Array;
  ciphertext: Uint8Array;
};

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

function requireSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (
    !subtle ||
    typeof subtle.importKey !== 'function' ||
    typeof subtle.deriveBits !== 'function' ||
    typeof subtle.digest !== 'function'
  ) {
    throw new Error('crypto.subtle HKDF support is required for Email OTP recovery keys');
  }
  return subtle;
}

function trimString(value: unknown): string {
  return String(value || '').trim();
}

function copyBytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array`);
  }
  return new Uint8Array(value);
}

function requireByteLength(value: Uint8Array, expectedLength: number, label: string): Uint8Array {
  if (value.byteLength !== expectedLength) {
    throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  }
  return value;
}

function zeroizeBytes(value: Uint8Array | null | undefined): void {
  value?.fill(0);
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

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const subtle = requireSubtleCrypto();
  return new Uint8Array(await subtle.digest('SHA-256', input));
}

export function emailOtpRecoveryKeyIdFields(args: {
  recoveryKeyBytesB64u: string;
  binding: EmailOtpRecoveryKeyIdBinding;
}): string[] {
  return [
    EMAIL_OTP_RECOVERY_KEY_ID_CONTEXT,
    trimString(args.recoveryKeyBytesB64u),
    trimString(args.binding.auth.walletId),
    trimString(args.binding.auth.userId),
    trimString(args.binding.auth.authSubjectId),
    trimString(args.binding.auth.authMethod),
    trimString(args.binding.enrollment.enrollmentId),
    trimString(args.binding.enrollment.enrollmentVersion),
    trimString(args.binding.enrollment.enrollmentSealKeyVersion),
    trimString(args.binding.signingRoot.signingRootId),
    trimString(args.binding.signingRoot.signingRootVersion),
  ];
}

export async function deriveEmailOtpRecoveryKeyId(args: {
  recoveryKey: string;
  binding: EmailOtpRecoveryKeyIdBinding;
}): Promise<DerivedEmailOtpRecoveryKeyId> {
  const recoveryKeyBytes = decodeEmailOtpRecoveryKey(args.recoveryKey);
  const tuple = encodeSigningSessionHkdfTuple(
    emailOtpRecoveryKeyIdFields({
      recoveryKeyBytesB64u: base64UrlEncode(recoveryKeyBytes),
      binding: args.binding,
    }),
  );
  try {
    const digest = await sha256Bytes(tuple);
    return `email-otp-rkid-v1-${base64UrlEncode(digest)}` as DerivedEmailOtpRecoveryKeyId;
  } finally {
    zeroizeBytes(recoveryKeyBytes);
    zeroizeBytes(tuple);
  }
}

export function emailOtpRecoveryKekInfoFields(args: EmailOtpRecoveryWrapBinding): string[] {
  return [
    trimString(args.auth.walletId),
    trimString(args.auth.userId),
    trimString(args.auth.authSubjectId),
    trimString(args.enrollment.enrollmentId),
    trimString(args.enrollment.enrollmentVersion),
    trimString(args.recoveryKeyId),
  ];
}

export function emailOtpRecoveryWrappedEnrollmentAadFields(
  args: EmailOtpRecoveryWrapBinding,
): string[] {
  return [
    EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_AAD_CONTEXT,
    trimString(args.auth.walletId),
    trimString(args.auth.userId),
    trimString(args.auth.authSubjectId),
    trimString(args.auth.authMethod),
    trimString(args.enrollment.enrollmentId),
    trimString(args.enrollment.enrollmentVersion),
    trimString(args.enrollment.enrollmentSealKeyVersion),
    trimString(args.signingRoot.signingRootId),
    trimString(args.signingRoot.signingRootVersion),
    trimString(args.recoveryKeyId),
  ];
}

export function encodeEmailOtpRecoveryKekInfo(args: EmailOtpRecoveryWrapBinding): Uint8Array {
  return encodeSigningSessionHkdfTuple(emailOtpRecoveryKekInfoFields(args));
}

export function encodeEmailOtpRecoveryWrappedEnrollmentAad(
  args: EmailOtpRecoveryWrapBinding,
): Uint8Array {
  return encodeSigningSessionHkdfTuple(emailOtpRecoveryWrappedEnrollmentAadFields(args));
}

export async function deriveEmailOtpRecoveryKek32(args: {
  recoveryKey: string;
  binding: EmailOtpRecoveryWrapBinding;
}): Promise<Uint8Array> {
  const subtle = requireSubtleCrypto();
  const recoveryKeyBytes = decodeEmailOtpRecoveryKey(args.recoveryKey);
  const salt = new TextEncoder().encode(EMAIL_OTP_RECOVERY_WRAP_HKDF_SALT);
  const info = encodeEmailOtpRecoveryKekInfo(args.binding);
  try {
    const key = await subtle.importKey('raw', recoveryKeyBytes, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(
      await subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt,
          info,
        },
        key,
        EMAIL_OTP_RECOVERY_WRAP_KEY_LENGTH * 8,
      ),
    );
  } finally {
    zeroizeBytes(recoveryKeyBytes);
    zeroizeBytes(salt);
    zeroizeBytes(info);
  }
}

export async function wrapEmailOtpDeviceEnrollmentEscrow(args: {
  recoveryKey: string;
  binding: EmailOtpRecoveryWrapBinding;
  encS: Uint8Array;
  chacha20poly1305: EmailOtpRecoveryChaCha20Poly1305;
  nonce12?: Uint8Array;
}): Promise<EmailOtpRecoveryWrappedEncS> {
  const nonce12 = args.nonce12
    ? requireByteLength(
        copyBytes(args.nonce12, 'nonce12'),
        EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH,
        'nonce12',
      )
    : cryptoRandomBytes(EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH);
  let key32: Uint8Array | null = null;
  const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(args.binding);
  const plaintext = copyBytes(args.encS, 'encS');
  try {
    key32 = await deriveEmailOtpRecoveryKek32({
      recoveryKey: args.recoveryKey,
      binding: args.binding,
    });
    const ciphertext = await args.chacha20poly1305.encrypt({
      key32,
      nonce12,
      aad,
      plaintext,
    });
    return {
      alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
      nonce12,
      ciphertext,
    };
  } finally {
    zeroizeBytes(key32);
    zeroizeBytes(aad);
    zeroizeBytes(plaintext);
  }
}

export async function unwrapEmailOtpDeviceEnrollmentEscrow(args: {
  recoveryKey: string;
  binding: EmailOtpRecoveryWrapBinding;
  wrapped: EmailOtpRecoveryWrappedEncS;
  chacha20poly1305: EmailOtpRecoveryChaCha20Poly1305;
}): Promise<Uint8Array> {
  if (args.wrapped.alg !== EMAIL_OTP_RECOVERY_WRAP_ALG) {
    throw new Error('Unsupported Email OTP recovery wrapper algorithm');
  }
  const nonce12 = requireByteLength(
    copyBytes(args.wrapped.nonce12, 'wrapped.nonce12'),
    EMAIL_OTP_RECOVERY_WRAP_NONCE_LENGTH,
    'wrapped.nonce12',
  );
  const ciphertext = copyBytes(args.wrapped.ciphertext, 'wrapped.ciphertext');
  let key32: Uint8Array | null = null;
  const aad = encodeEmailOtpRecoveryWrappedEnrollmentAad(args.binding);
  try {
    key32 = await deriveEmailOtpRecoveryKek32({
      recoveryKey: args.recoveryKey,
      binding: args.binding,
    });
    try {
      return await args.chacha20poly1305.decrypt({
        key32,
        nonce12,
        aad,
        ciphertext,
      });
    } catch {
      throw new Error('Email OTP recovery unwrap failed');
    }
  } finally {
    zeroizeBytes(key32);
    zeroizeBytes(aad);
  }
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
