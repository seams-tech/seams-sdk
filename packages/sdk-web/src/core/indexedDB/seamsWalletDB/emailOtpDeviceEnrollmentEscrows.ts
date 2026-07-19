import { base64UrlDecode } from '@shared/utils/base64';
import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_STORES,
} from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION = 1 as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_NAME = SEAMS_WALLET_DB_NAME;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_VERSION = SEAMS_WALLET_DB_VERSION;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME =
  SEAMS_WALLET_STORES.emailOtpDeviceEnrollmentEscrows;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE = 'iframe_origin_indexeddb' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG = 'shamir3pass-v1' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND =
  'email_otp_device_enrollment_escrow_enc_s' as const;
const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_PAYLOAD_FIELD = 'escrow_record';

export type EmailOtpDeviceEnrollmentEscrowRecord = {
  v: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION;
  alg: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG;
  storageScope: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE;
  secretKind: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND;
  walletId: string;
  userId?: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  shamirPrimeB64u?: string;
  encSB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};

export type WriteEmailOtpDeviceEnrollmentEscrowRecordInput = Omit<
  EmailOtpDeviceEnrollmentEscrowRecord,
  'v' | 'alg' | 'storageScope' | 'secretKind' | 'authMethod' | 'issuedAtMs' | 'updatedAtMs'
> & {
  issuedAtMs?: number;
  updatedAtMs?: number;
};

const PLAINTEXT_OR_WRONG_STORE_FIELDS = [
  'S',
  'secretS',
  'plaintextS',
  'emailOtpSecretS',
  'clientSecret',
  'clientSecret32',
  'clientSecretB64u',
  'clientSecret32B64u',
  'signingSessionSecretB64u',
  'sealedSecretB64u',
  'walletSessionJwt',
  'recoveryKey',
  'recoveryKeys',
  'recoveryKek',
  'K_recovery_i',
] as const;

function isValidBase64UrlBytes(value: string): boolean {
  try {
    return base64UrlDecode(value).byteLength > 0;
  } catch {
    return false;
  }
}

export function normalizeEmailOtpDeviceEnrollmentEscrowRecord(
  value: unknown,
): EmailOtpDeviceEnrollmentEscrowRecord | null {
  const row =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (
    row &&
    EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_PAYLOAD_FIELD in row &&
    row[EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_PAYLOAD_FIELD]
  ) {
    value = row[EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_PAYLOAD_FIELD];
  }
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  for (const field of PLAINTEXT_OR_WRONG_STORE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) return null;
  }
  if (Number(obj.v) !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION) return null;
  if (String(obj.alg || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG) return null;
  if (String(obj.storageScope || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE) {
    return null;
  }
  if (String(obj.secretKind || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND) {
    return null;
  }
  if (String(obj.authMethod || '').trim() !== 'google_sso_email_otp') return null;

  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const userId = normalizeOptionalNonEmptyString(obj.userId);
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const enrollmentId = normalizeOptionalNonEmptyString(obj.enrollmentId);
  const enrollmentVersion = normalizeOptionalNonEmptyString(obj.enrollmentVersion);
  const enrollmentSealKeyVersion = normalizeOptionalNonEmptyString(obj.enrollmentSealKeyVersion);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  const encSB64u = normalizeOptionalNonEmptyString(obj.encSB64u);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (
    !walletId ||
    !authSubjectId ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !encSB64u
  ) {
    return null;
  }
  if (!isValidBase64UrlBytes(encSB64u)) return null;
  if (shamirPrimeB64u && !isValidBase64UrlBytes(shamirPrimeB64u)) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;

  return {
    v: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
    alg: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
    storageScope: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
    secretKind: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
    walletId,
    ...(userId ? { userId } : {}),
    authSubjectId,
    authMethod: 'google_sso_email_otp',
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    encSB64u,
    issuedAtMs,
    updatedAtMs,
  };
}

function emailOtpDeviceEnrollmentEscrowStorageRow(
  record: EmailOtpDeviceEnrollmentEscrowRecord,
): Record<string, unknown> {
  return {
    wallet_id: record.walletId,
    user_id: record.userId,
    auth_subject_id: record.authSubjectId,
    enrollment_id: record.enrollmentId,
    signing_root_id: record.signingRootId,
    signing_root_version: record.signingRootVersion,
    updated_at: record.updatedAtMs,
    [EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_PAYLOAD_FIELD]: record,
  };
}

export class EmailOtpDeviceEnrollmentEscrowRepository {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async read(args: {
    walletId: string;
    authSubjectId: string;
    enrollmentId: string;
  }): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    const authSubjectId = normalizeOptionalNonEmptyString(args.authSubjectId);
    const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
    if (!walletId || !authSubjectId || !enrollmentId) return null;
    const db = await this.manager.getDB();
    const value = await db.get(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, [
      walletId,
      authSubjectId,
      enrollmentId,
    ]);
    return normalizeEmailOtpDeviceEnrollmentEscrowRecord(value);
  }

  async readSingleForWallet(args: {
    walletId: string;
  }): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    if (!walletId) return null;
    const db = await this.manager.getDB();
    const values = await db.getAllFromIndex(
      EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME,
      SEAMS_WALLET_INDEXES.walletId,
      walletId,
    );
    const records = values
      .map((value) => normalizeEmailOtpDeviceEnrollmentEscrowRecord(value))
      .filter((record): record is EmailOtpDeviceEnrollmentEscrowRecord => !!record);
    return records.length === 1 ? records[0] : null;
  }

  async write(args: WriteEmailOtpDeviceEnrollmentEscrowRecordInput): Promise<void> {
    const nowMs = Date.now();
    const record = normalizeEmailOtpDeviceEnrollmentEscrowRecord({
      v: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
      alg: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
      storageScope: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
      secretKind: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
      walletId: args.walletId,
      userId: args.userId,
      authSubjectId: args.authSubjectId,
      authMethod: 'google_sso_email_otp',
      enrollmentId: args.enrollmentId,
      enrollmentVersion: args.enrollmentVersion,
      enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
      signingRootId: args.signingRootId,
      signingRootVersion: args.signingRootVersion,
      shamirPrimeB64u: args.shamirPrimeB64u,
      encSB64u: args.encSB64u,
      issuedAtMs: args.issuedAtMs ?? nowMs,
      updatedAtMs: args.updatedAtMs ?? nowMs,
    });
    if (!record) {
      throw new Error('Invalid Email OTP device enrollment escrow record');
    }

    await this.manager.runTransaction(
      [EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME);
        const existing = normalizeEmailOtpDeviceEnrollmentEscrowRecord(
          await store.get([record.walletId, record.authSubjectId, record.enrollmentId]),
        );
        if (existing && existing.encSB64u !== record.encSB64u) {
          throw new Error(
            'Email OTP device enrollment escrow already exists for this wallet and subject; refusing to replace active local material',
          );
        }
        await store.put(emailOtpDeviceEnrollmentEscrowStorageRow(record));
      },
    );
  }

  async delete(args: { walletId: string; authSubjectId: string; enrollmentId: string }): Promise<void> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    const authSubjectId = normalizeOptionalNonEmptyString(args.authSubjectId);
    const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
    if (!walletId || !authSubjectId || !enrollmentId) return;
    await this.manager.runTransaction(
      [EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx.store(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).delete([
          walletId,
          authSubjectId,
          enrollmentId,
        ]);
      },
    );
  }

  async clearAll(): Promise<void> {
    await this.manager.runTransaction(
      [EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx.store(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).clear();
      },
    );
  }
}

export const emailOtpDeviceEnrollmentEscrowRepository =
  new EmailOtpDeviceEnrollmentEscrowRepository();
